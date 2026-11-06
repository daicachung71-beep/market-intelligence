from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

from backend.realtime_monitor import (
    BinanceCryptoProvider,
    FinnhubEquityProvider,
    RealtimeConfig,
    RollingWindowDetector,
    dispatch_realtime_alert,
    load_realtime_config,
    poll_once,
    run,
)


def test_rolling_window_detector_calculates_moves_and_obeys_cooldown():
    # 15 min window (900s), 2.0% threshold, 900s cooldown
    detector = RollingWindowDetector(window_seconds=900, threshold_pct=2.0, cooldown_seconds=900)

    # First point at t=0: price 100
    assert detector.record_and_evaluate("BTC", 100.0, timestamp=0.0) is None

    # Small move at t=60: price 101 (+1%) -> below threshold
    assert detector.record_and_evaluate("BTC", 101.0, timestamp=60.0) is None

    # Large move at t=120: price 103 (+3% from 100) -> triggers alert
    alert = detector.record_and_evaluate("BTC", 103.0, timestamp=120.0)
    assert alert is not None
    assert alert["symbol"] == "BTC"
    assert alert["direction"] == "up"
    assert alert["change_pct"] == 3.0
    assert alert["current_price"] == 103.0
    assert alert["base_price"] == 100.0
    assert alert["window_minutes"] == 2

    # Immediately at t=180: price surges to 108 (+4.8% from 103 baseline) -> but within cooldown (60s < 900s)!
    cooldown_suppressed = detector.record_and_evaluate("BTC", 108.0, timestamp=180.0)
    assert cooldown_suppressed is None

    # After cooldown expires at t=1100 (1100 - 120 = 980s > 900s):
    # Establish new point
    detector.record_and_evaluate("BTC", 108.0, timestamp=1100.0)
    # Price drops to 104 (-3.7%) at t=1200
    drop_alert = detector.record_and_evaluate("BTC", 104.0, timestamp=1200.0)
    assert drop_alert is not None
    assert drop_alert["direction"] == "down"
    assert drop_alert["change_pct"] < -2.0


def test_rolling_window_prunes_stale_data():
    detector = RollingWindowDetector(window_seconds=300, threshold_pct=2.0, cooldown_seconds=60)

    # Point at t=0
    detector.record_and_evaluate("ETH", 100.0, timestamp=0.0)
    # Point at t=500 (stale point at t=0 pruned because 500 - 0 > 300)
    detector.record_and_evaluate("ETH", 101.0, timestamp=500.0)

    # Point at t=550 with price 101.5 (+0.5% from 101) -> not compared against t=0
    alert = detector.record_and_evaluate("ETH", 101.5, timestamp=550.0)
    assert alert is None


def test_binance_crypto_provider(monkeypatch):
    provider = BinanceCryptoProvider()

    def fake_get(url, **kwargs):
        assert kwargs["params"]["symbols"] == '["BTCUSDT","ETHUSDT"]'
        return SimpleNamespace(
            status_code=200,
            raise_for_status=lambda: None,
            json=lambda: [
                {"symbol": "BTCUSDT", "price": "67500.50"},
                {"symbol": "ETHUSDT", "price": "3520.10"},
            ],
        )

    session = MagicMock()
    session.get = fake_get

    prices = provider.fetch_prices(["BTC", "ETH"], session)
    assert prices == {"BTC": 67500.50, "ETH": 3520.10}

    # Error isolation
    def failing_get(url, **kwargs):
        raise requests.ConnectionError("offline")

    session.get = failing_get
    assert provider.fetch_prices(["BTC"], session) == {}


def test_finnhub_equity_provider_skips_when_no_key_and_fetches_when_present():
    # Without key: skips cleanly
    no_key_provider = FinnhubEquityProvider("")
    session = MagicMock()
    assert no_key_provider.fetch_prices(["AAPL"], session) == {}
    assert session.get.call_count == 0

    # With key: calls API and extracts "c"
    provider = FinnhubEquityProvider("test_api_key")

    def fake_quote(url, **kwargs):
        assert kwargs["params"]["token"] == "test_api_key"
        assert kwargs["params"]["symbol"] == "AAPL"
        return SimpleNamespace(
            status_code=200,
            raise_for_status=lambda: None,
            json=lambda: {"c": 265.40, "d": 2.5, "dp": 0.95},
        )

    session.get = fake_quote
    prices = provider.fetch_prices(["AAPL"], session)
    assert prices == {"AAPL": 265.40}


def test_dispatch_realtime_alert_to_telegram_and_ntfy(monkeypatch, capsys):
    monkeypatch.setenv("TELEGRAM_ENABLED", "true")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "secret-rt-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100777888")
    monkeypatch.setenv("NTFY_TOPIC", "rt-alerts-topic")

    captured_posts = []

    def fake_post(self, url, **kwargs):
        captured_posts.append({"url": url, "kwargs": kwargs})
        return SimpleNamespace(
            status_code=200,
            raise_for_status=lambda: None,
            json=lambda: {"ok": True},
        )

    monkeypatch.setattr(requests.Session, "post", fake_post)

    alert = {
        "symbol": "BTC",
        "current_price": 68500.0,
        "base_price": 66500.0,
        "change_pct": 3.01,
        "direction": "up",
        "window_minutes": 15,
        "timestamp": 1792180800.0,
    }

    ok, channels = dispatch_realtime_alert(alert)
    assert ok is True
    assert "telegram" in channels
    assert "ntfy" in channels

    tg_post = next(p for p in captured_posts if "api.telegram.org" in p["url"])
    ntfy_post = next(p for p in captured_posts if "ntfy.sh" in p["url"])

    assert "secret-rt-token" in tg_post["url"]
    assert "<b>⚡ Real-time Market Move: BTC</b>" in tg_post["kwargs"]["json"]["text"]
    assert "+3.01%" in tg_post["kwargs"]["json"]["text"]
    assert "$68,500.00" in tg_post["kwargs"]["json"]["text"]
    assert ntfy_post["url"].startswith("https://ntfy.sh/rt-alerts-topic")
    # Check no credential leakage
    assert "secret-rt-token" not in capsys.readouterr().out


def test_poll_once_triggers_alerts_and_finnhub_cooldown(tmp_path, monkeypatch):
    class FakeCryptoProvider:
        def fetch_prices(self, symbols, session):
            return {"BTC": 100.0, "ETH": 200.0}

    class FakeEquityProvider:
        def fetch_prices(self, symbols, session):
            return {"AAPL": 150.0}

    config = RealtimeConfig(
        enabled=True,
        interval_seconds=15,
        window_minutes=15,
        alert_threshold_pct=2.0,
        cooldown_seconds=900,
        finnhub_api_key="valid-key",
        db_path=tmp_path / "market.sqlite3",
    )

    detector = RollingWindowDetector(window_seconds=900, threshold_pct=2.0, cooldown_seconds=900)
    session = MagicMock()

    # Tick 1: sets baselines
    alerts1 = poll_once(
        detector,
        config,
        session,
        crypto_provider=FakeCryptoProvider(),
        equity_provider=FakeEquityProvider(),
    )
    assert alerts1 == []

    # Tick 2: BTC jumps to 105 (+5%)
    class FakeCryptoJumpProvider:
        def fetch_prices(self, symbols, session):
            return {"BTC": 105.0, "ETH": 200.5}

    alerts2 = poll_once(
        detector,
        config,
        session,
        crypto_provider=FakeCryptoJumpProvider(),
        equity_provider=FakeEquityProvider(),
    )
    assert len(alerts2) == 1
    assert alerts2[0]["symbol"] == "BTC"
    assert alerts2[0]["change_pct"] == 5.0


def test_realtime_config_loader(monkeypatch):
    monkeypatch.setenv("REALTIME_MONITOR_ENABLED", "true")
    monkeypatch.setenv("REALTIME_MONITOR_INTERVAL_SECONDS", "30")
    monkeypatch.setenv("REALTIME_WINDOW_MINUTES", "10")
    monkeypatch.setenv("REALTIME_ALERT_THRESHOLD_PCT", "3.5")
    monkeypatch.setenv("REALTIME_ALERT_COOLDOWN_SECONDS", "600")
    monkeypatch.setenv("FINNHUB_API_KEY", "custom_key")

    cfg = load_realtime_config()
    assert cfg.enabled is True
    assert cfg.interval_seconds == 30
    assert cfg.window_minutes == 10
    assert cfg.alert_threshold_pct == 3.5
    assert cfg.cooldown_seconds == 600
    assert cfg.finnhub_api_key == "custom_key"


def test_realtime_monitor_disabled_exits_cleanly(monkeypatch):
    monkeypatch.setenv("REALTIME_MONITOR_ENABLED", "false")
    # Should return without starting loop
    run()
