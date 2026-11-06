import hashlib
import json
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import requests

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

from backend.database import connect, get_crypto_watchlist
from backend.settings import DB_PATH
from src.notify import (
    is_telegram_configured,
    is_telegram_enabled,
    send_notification,
    send_telegram_message,
)

LOGGER = logging.getLogger(__name__)
SHUTDOWN = threading.Event()


def _request_shutdown(_signum: int, _frame: object) -> None:
    LOGGER.info("realtime_monitor_shutdown_signal_received")
    SHUTDOWN.set()


@dataclass
class RealtimeConfig:
    enabled: bool = False
    interval_seconds: int = 15
    window_minutes: int = 15
    alert_threshold_pct: float = 2.0
    cooldown_seconds: int = 900
    finnhub_api_key: str = ""
    db_path: Path = DB_PATH


def load_realtime_config(db_path: Path | None = None) -> RealtimeConfig:
    raw_enabled = os.getenv("REALTIME_MONITOR_ENABLED", "false").strip().casefold()
    enabled = raw_enabled in {"1", "true", "yes", "on"}

    try:
        interval = int(os.getenv("REALTIME_MONITOR_INTERVAL_SECONDS", "15"))
    except ValueError:
        interval = 15

    try:
        window = int(os.getenv("REALTIME_WINDOW_MINUTES", "15"))
    except ValueError:
        window = 15

    try:
        threshold = float(os.getenv("REALTIME_ALERT_THRESHOLD_PCT", "2.0"))
    except ValueError:
        threshold = 2.0

    try:
        cooldown = int(os.getenv("REALTIME_ALERT_COOLDOWN_SECONDS", "900"))
    except ValueError:
        cooldown = 900

    finnhub_key = os.getenv("FINNHUB_API_KEY", "").strip()

    return RealtimeConfig(
        enabled=enabled,
        interval_seconds=max(5, interval),
        window_minutes=max(1, window),
        alert_threshold_pct=threshold if threshold > 0 else 2.0,
        cooldown_seconds=max(0, cooldown),
        finnhub_api_key=finnhub_key,
        db_path=db_path or DB_PATH,
    )


class PriceProvider(Protocol):
    def fetch_prices(self, symbols: list[str], session: requests.Session) -> dict[str, float]: ...


class BinanceCryptoProvider:
    BINANCE_URL = "https://api.binance.com/api/v3/ticker/price"

    def fetch_prices(self, symbols: list[str], session: requests.Session) -> dict[str, float]:
        if not symbols:
            return {}
        prices: dict[str, float] = {}
        # Binance format: '["BTCUSDT","ETHUSDT"]'
        binance_symbols = [f"{s.upper()}USDT" for s in symbols]
        try:
            response = session.get(
                self.BINANCE_URL,
                params={"symbols": json.dumps(binance_symbols, separators=(",", ":"))},
                timeout=(3, 10),
            )
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list):
                mapping = {
                    item["symbol"]: float(item["price"])
                    for item in data
                    if "symbol" in item and "price" in item
                }
                for sym in symbols:
                    pair = f"{sym.upper()}USDT"
                    if pair in mapping and mapping[pair] > 0:
                        prices[sym.upper()] = mapping[pair]
        except Exception as exc:
            LOGGER.warning("binance_fetch_failed error=%s", type(exc).__name__)
        return prices


class FinnhubEquityProvider:
    FINNHUB_QUOTE_URL = "https://finnhub.io/api/v1/quote"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key.strip()

    def fetch_prices(self, symbols: list[str], session: requests.Session) -> dict[str, float]:
        if not self.api_key:
            LOGGER.debug("finnhub_skipped reason=missing_api_key")
            return {}
        prices: dict[str, float] = {}
        for s in symbols:
            try:
                response = session.get(
                    self.FINNHUB_QUOTE_URL,
                    params={"symbol": s.upper(), "token": self.api_key},
                    timeout=(3, 10),
                )
                response.raise_for_status()
                data = response.json()
                current = float(data.get("c", 0.0))
                if current > 0:
                    prices[s.upper()] = current
            except Exception as exc:
                LOGGER.warning("finnhub_fetch_failed symbol=%s error=%s", s, type(exc).__name__)
        return prices


@dataclass
class PricePoint:
    timestamp: float
    price: float


class RollingWindowDetector:
    def __init__(
        self,
        window_seconds: float = 900.0,
        threshold_pct: float = 2.0,
        cooldown_seconds: float = 900.0,
    ) -> None:
        self.window_seconds = window_seconds
        self.threshold_pct = threshold_pct
        self.cooldown_seconds = cooldown_seconds
        self.history: dict[str, list[PricePoint]] = {}
        self.last_alert_time: dict[str, float] = {}

    def record_and_evaluate(
        self,
        symbol: str,
        price: float,
        timestamp: float | None = None,
    ) -> dict[str, Any] | None:
        now = timestamp if timestamp is not None else time.time()
        if price <= 0:
            return None

        sym = symbol.upper()
        history = self.history.setdefault(sym, [])
        cutoff = now - self.window_seconds
        history = [p for p in history if p.timestamp >= cutoff]
        history.append(PricePoint(now, price))
        self.history[sym] = history

        if len(history) < 2:
            return None

        base_point = history[0]
        base_price = base_point.price
        if base_price <= 0:
            return None

        change_pct = round(((price - base_price) / base_price) * 100, 4)
        if abs(change_pct) < self.threshold_pct:
            return None

        if sym in self.last_alert_time and (now - self.last_alert_time[sym]) < self.cooldown_seconds:
            return None

        self.last_alert_time[sym] = now
        direction = "up" if change_pct > 0 else "down"
        elapsed_mins = max(1, round((now - base_point.timestamp) / 60))

        # Reset baseline for this symbol to current price to prevent re-alerting on minor fluctuations
        self.history[sym] = [PricePoint(now, price)]

        return {
            "symbol": sym,
            "current_price": price,
            "base_price": base_price,
            "change_pct": change_pct,
            "direction": direction,
            "window_minutes": elapsed_mins,
            "timestamp": now,
        }


def format_realtime_alert_message(alert: dict[str, Any]) -> tuple[str, str]:
    symbol = alert["symbol"]
    change_pct = alert["change_pct"]
    current_price = alert["current_price"]
    base_price = alert["base_price"]
    window_mins = alert["window_minutes"]
    direction = alert["direction"].upper()

    title = f"⚡ Real-time Market Move: {symbol}"
    message = (
        f"{symbol} moved {change_pct:+.2f}% in the last {window_mins}m ({direction}).\n"
        f"Current: ${current_price:,.2f} (from ${base_price:,.2f})\n"
        "Research alert only; not a trading instruction."
    )
    return title, message


def dispatch_realtime_alert(
    alert: dict[str, Any],
    *,
    session: requests.Session | None = None,
) -> tuple[bool, list[str]]:
    title, message = format_realtime_alert_message(alert)
    symbol = alert["symbol"]
    delivered_channels: list[str] = []

    # Send to Telegram
    if is_telegram_enabled() and is_telegram_configured():
        try:
            ok, err = send_telegram_message(title, message, session=session)
            if ok:
                delivered_channels.append("telegram")
            else:
                LOGGER.warning("realtime_telegram_alert_failed symbol=%s error=%s", symbol, err)
        except Exception as exc:
            LOGGER.warning(
                "realtime_telegram_alert_exception symbol=%s error=%s",
                symbol,
                type(exc).__name__,
            )

    # Send to ntfy
    ntfy_topic = os.getenv("NTFY_TOPIC", "").strip()
    ntfy_enabled = os.getenv("NTFY_ENABLED", "true").strip().casefold() not in {
        "0",
        "false",
        "no",
        "off",
    }
    if ntfy_topic and ntfy_enabled:
        try:
            sequence_id = hashlib.sha256(
                f"rt:{symbol}:{alert['timestamp']}".encode("utf-8")
            ).hexdigest()[:32]
            ok = send_notification(
                title,
                message,
                priority="urgent",
                sequence_id=sequence_id,
            )
            if ok:
                delivered_channels.append("ntfy")
            else:
                LOGGER.warning("realtime_ntfy_alert_failed symbol=%s", symbol)
        except Exception as exc:
            LOGGER.warning(
                "realtime_ntfy_alert_exception symbol=%s error=%s",
                symbol,
                type(exc).__name__,
            )

    return bool(delivered_channels), delivered_channels


def get_realtime_crypto_symbols(db_path: Path) -> list[str]:
    if not db_path.is_file():
        return ["BTC", "ETH"]
    try:
        items = get_crypto_watchlist(db_path)
        symbols = [item["symbol"].upper() for item in items]
        return symbols if symbols else ["BTC", "ETH"]
    except Exception:
        return ["BTC", "ETH"]


def get_realtime_equity_symbols(db_path: Path) -> list[str]:
    if not db_path.is_file():
        return ["AAPL"]
    try:
        connection = connect(db_path)
        try:
            rows = connection.execute(
                "SELECT symbol FROM assets WHERE asset_class = 'equity' ORDER BY symbol"
            ).fetchall()
            symbols = [row["symbol"].upper() for row in rows]
            return symbols if symbols else ["AAPL"]
        finally:
            connection.close()
    except Exception:
        return ["AAPL"]


def poll_once(
    detector: RollingWindowDetector,
    config: RealtimeConfig,
    session: requests.Session,
    *,
    crypto_provider: PriceProvider | None = None,
    equity_provider: PriceProvider | None = None,
) -> list[dict[str, Any]]:
    crypto_prov = crypto_provider or BinanceCryptoProvider()
    equity_prov = equity_provider or FinnhubEquityProvider(config.finnhub_api_key)

    crypto_symbols = get_realtime_crypto_symbols(config.db_path)
    equity_symbols = get_realtime_equity_symbols(config.db_path)

    prices: dict[str, float] = {}
    if crypto_symbols:
        prices.update(crypto_prov.fetch_prices(crypto_symbols, session))
    if equity_symbols and config.finnhub_api_key:
        prices.update(equity_prov.fetch_prices(equity_symbols, session))

    alerts: list[dict[str, Any]] = []
    now = time.time()
    for sym, price in prices.items():
        alert = detector.record_and_evaluate(sym, price, now)
        if alert:
            dispatch_realtime_alert(alert, session=session)
            alerts.append(alert)
            LOGGER.info(
                "realtime_alert_dispatched symbol=%s change_pct=%.2f%% price=%.2f",
                sym,
                alert["change_pct"],
                price,
            )

    return alerts


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_realtime_config()
    if not config.enabled:
        LOGGER.info("realtime_monitor_disabled via REALTIME_MONITOR_ENABLED=false; exiting")
        return

    lock_path = config.db_path.parent / "realtime-monitor.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    with lock_path.open("a", encoding="utf-8") as lock_file:
        if fcntl is not None:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                raise RuntimeError("Another realtime monitor process already holds the lock") from exc

        signal.signal(signal.SIGTERM, _request_shutdown)
        signal.signal(signal.SIGINT, _request_shutdown)

        detector = RollingWindowDetector(
            window_seconds=config.window_minutes * 60,
            threshold_pct=config.alert_threshold_pct,
            cooldown_seconds=config.cooldown_seconds,
        )

        LOGGER.info(
            "realtime_monitor_started interval_s=%d window_m=%d threshold_pct=%.1f%% cooldown_s=%d finnhub=%s",
            config.interval_seconds,
            config.window_minutes,
            config.alert_threshold_pct,
            config.cooldown_seconds,
            bool(config.finnhub_api_key),
        )

        session = requests.Session()
        try:
            while not SHUTDOWN.is_set():
                poll_once(detector, config, session)
                SHUTDOWN.wait(config.interval_seconds)
        finally:
            session.close()
            LOGGER.info("realtime_monitor_stopped")


if __name__ == "__main__":
    run()
