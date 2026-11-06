import argparse
try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from backend.auth import validate_username
from backend.database import (
    connect,
    get_alert_events,
    get_asset_summaries,
    get_collection_runs,
    get_news_articles,
    initialize_database,
)
from backend.settings import DB_PATH
from backend.social import get_collection_status, get_social_statistics

ROOT = Path(__file__).resolve().parents[1]
LOGGER = logging.getLogger(__name__)
COMMANDS = frozenset(
    {
        "/status",
        "/health",
        "/market",
        "/news",
        "/social",
        "/alerts",
        "/help",
        "/collect",
        "/backup",
        "/stop-monitor",
    }
)
MAX_MESSAGE_BYTES = 4096
MAX_POLL_BYTES = 12 * 1024 * 1024
COMMAND_WINDOW_SECONDS = 300
COMMAND_RATE_LIMIT = 10
COMMAND_JOB_TIMEOUT_SECONDS = 300
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
SIGNATURE_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$")
SHUTDOWN = threading.Event()


class CommandRejected(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class CommandExecutionError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CommandConfig:
    server: str
    topic: str
    response_topic: str
    secret: str


def _enabled(value: str | None) -> bool:
    return (value or "").strip().casefold() in {"1", "true", "yes", "on"}


def _validate_topic(topic: str) -> str:
    normalized = topic.strip()
    if not re.fullmatch(r"[-_A-Za-z0-9]{1,64}", normalized):
        raise ValueError("ntfy command topics must contain 1-64 letters, digits, hyphens or underscores")
    return normalized


def load_config(*, require_enabled: bool = True) -> CommandConfig:
    if require_enabled and not _enabled(os.getenv("NTFY_COMMAND_ENABLED")):
        raise ValueError("Set NTFY_COMMAND_ENABLED=true to start the command listener")
    server = (
        os.getenv("NTFY_BASE_URL", "").strip()
        or os.getenv("NTFY_SERVER", "https://ntfy.sh").strip()
    ).rstrip("/")
    parsed = urlsplit(server)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("NTFY command server must be an HTTPS URL without credentials or query")
    topic = _validate_topic(os.getenv("NTFY_COMMAND_TOPIC", ""))
    response_topic = _validate_topic(os.getenv("NTFY_COMMAND_RESPONSE_TOPIC", ""))
    if topic == response_topic:
        raise ValueError("Use separate ntfy command and response topics")
    secret = os.getenv("NTFY_COMMAND_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("NTFY_COMMAND_SECRET must contain at least 32 bytes")
    return CommandConfig(server, topic, response_topic, secret)


def _canonical_json(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _signature(payload: dict[str, object], secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        _canonical_json(payload),
        hashlib.sha256,
    )
    return digest.hexdigest()


def sign_command(
    command: str,
    actor: str,
    secret: str,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, object]:
    if command not in COMMANDS:
        raise ValueError("Command is not allowlisted")
    normalized_actor = validate_username(actor)
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("NTFY_COMMAND_SECRET must contain at least 32 bytes")
    payload: dict[str, object] = {
        "actor": normalized_actor,
        "command": command,
        "timestamp": int(time.time()) if timestamp is None else timestamp,
        "nonce": secrets.token_urlsafe(24) if nonce is None else nonce,
    }
    if not NONCE_PATTERN.fullmatch(str(payload["nonce"])):
        raise ValueError("Nonce must contain 20-128 URL-safe characters")
    payload["signature"] = _signature(payload, secret)
    return payload


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CommandRejected("duplicate_field")
        result[key] = value
    return result


def _verify_message(message: str, secret: str, now_epoch: int) -> dict[str, object]:
    if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise CommandRejected("message_too_large")
    try:
        payload = json.loads(message, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, UnicodeEncodeError) as exc:
        raise CommandRejected("invalid_json") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "actor",
        "command",
        "timestamp",
        "nonce",
        "signature",
    }:
        raise CommandRejected("invalid_envelope")
    actor = payload["actor"]
    command = payload["command"]
    timestamp = payload["timestamp"]
    nonce = payload["nonce"]
    signature = payload["signature"]
    if (
        not isinstance(actor, str)
        or not isinstance(command, str)
        or not isinstance(timestamp, int)
        or isinstance(timestamp, bool)
        or not isinstance(nonce, str)
        or not isinstance(signature, str)
        or not SIGNATURE_PATTERN.fullmatch(signature)
    ):
        raise CommandRejected("invalid_envelope")
    try:
        validate_username(actor)
    except ValueError as exc:
        raise CommandRejected("invalid_actor") from exc
    if not NONCE_PATTERN.fullmatch(nonce):
        raise CommandRejected("invalid_nonce")
    unsigned = {key: payload[key] for key in ("actor", "command", "timestamp", "nonce")}
    if not hmac.compare_digest(_signature(unsigned, secret), signature.casefold()):
        raise CommandRejected("invalid_signature")
    if abs(now_epoch - timestamp) > COMMAND_WINDOW_SECONDS:
        raise CommandRejected("stale_timestamp")
    return unsigned


def _active_admin(db_path: Path, actor: str) -> int | None:
    connection = connect(db_path)
    try:
        row = connection.execute(
            "SELECT id FROM auth_users "
            "WHERE username = ? COLLATE NOCASE AND role = 'ADMIN' AND active = 1",
            (actor,),
        ).fetchone()
        return int(row["id"]) if row else None
    finally:
        connection.close()


def _write_audit(
    db_path: Path,
    *,
    actor_user_id: int | None,
    command: str,
    nonce: str | None,
    status: str,
    error_code: str | None,
    result_summary: str | None,
    received_at: str,
    completed_at: str | None,
) -> int:
    connection = connect(db_path)
    try:
        cursor = connection.execute(
            "INSERT INTO ntfy_command_audit "
            "(actor_user_id, command, nonce, status, error_code, result_summary, "
            "received_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                actor_user_id,
                command,
                nonce,
                status,
                error_code,
                result_summary[:500] if result_summary else None,
                received_at,
                completed_at,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)
    finally:
        connection.close()


def _reserve_nonce(
    db_path: Path,
    actor_user_id: int,
    command: str,
    nonce: str,
    received_at: str,
) -> int | None:
    connection = connect(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        cutoff = datetime.fromtimestamp(
            time.time() - 86400,
            tz=timezone.utc,
        ).isoformat(timespec="seconds")
        connection.execute(
            "DELETE FROM ntfy_command_nonces WHERE received_at < ?",
            (cutoff,),
        )
        try:
            connection.execute(
                "INSERT INTO ntfy_command_nonces "
                "(nonce, actor_user_id, command, received_at) VALUES (?, ?, ?, ?)",
                (nonce, actor_user_id, command, received_at),
            )
        except sqlite3.IntegrityError:
            connection.rollback()
            return None
        cursor = connection.execute(
            "INSERT INTO ntfy_command_audit "
            "(actor_user_id, command, nonce, status, received_at) "
            "VALUES (?, ?, ?, 'running', ?)",
            (actor_user_id, command, nonce, received_at),
        )
        audit_id = int(cursor.lastrowid)
        connection.commit()
        return audit_id
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _finish_audit(
    db_path: Path,
    audit_id: int,
    *,
    status: str,
    result_summary: str | None = None,
    error_code: str | None = None,
) -> None:
    connection = connect(db_path)
    try:
        connection.execute(
            "UPDATE ntfy_command_audit SET status = ?, result_summary = ?, "
            "error_code = ?, completed_at = ? WHERE id = ?",
            (
                status,
                result_summary[:500] if result_summary else None,
                error_code,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                audit_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _health_result(db_path: Path) -> str:
    connection = connect(db_path)
    try:
        result = connection.execute("PRAGMA quick_check").fetchone()[0]
        if result != "ok":
            raise CommandExecutionError("database_check_failed")
        return "Database: connected and healthy."
    finally:
        connection.close()


def _status_result(db_path: Path) -> str:
    latest = get_collection_runs(db_path, limit=1)
    last_run = "no collection recorded"
    if latest:
        run = latest[0]
        last_run = (
            f"{run['provider']} {run['symbol']}: {run['status']} "
            f"at {run['completed_at']}"
        )
    return f"Command listener: online. {_health_result(db_path)} Last collection: {last_run}."


def _market_result(db_path: Path) -> str:
    assets = get_asset_summaries(db_path)
    if not assets:
        return "No tracked market assets are available."
    entries = []
    for asset in assets[:12]:
        price = asset.get("price")
        price_text = "no price" if price is None else f"{price:.6g} {asset['currency']}"
        change = asset.get("change_pct")
        change_text = "" if change is None else f" ({change:+.2f}%)"
        entries.append(f"{asset['symbol']}: {price_text}{change_text}, {asset['freshness']}")
    return "Market snapshot: " + "; ".join(entries)


def _news_result(db_path: Path) -> str:
    articles, count = get_news_articles(db_path, limit=3)
    if not articles:
        return "No collected news articles."
    headlines = [
        f"- {str(article['title'])[:140]} [{article['source']}]"
        for article in articles
    ]
    return f"Latest news ({count} stored):\n" + "\n".join(headlines)


def _social_result(db_path: Path) -> str:
    collection = get_collection_status(db_path)
    statistics = get_social_statistics(db_path)
    return (
        f"Social monitor: {collection.get('status', 'unknown')}; "
        f"last success: {collection.get('last_success_at') or 'not recorded'}; "
        f"posts: {statistics.get('posts', 0)}, events: {statistics.get('events', 0)}."
    )


def _alerts_result(db_path: Path) -> str:
    alerts = get_alert_events(db_path, limit=20)
    if not alerts:
        return "No price alerts recorded."
    lines = [
        f"- {item['symbol']} {item['change_pct']:+.2f}% at "
        f"{item['timestamp']} ({item['delivery_status']})"
        for item in alerts
    ]
    return "Recent price alerts:\n" + "\n".join(lines)


def _backup_database(db_path: Path, backup_dir: Path | None = None) -> dict[str, object]:
    target_dir = backup_dir or ROOT / "backups"
    if target_dir.exists() and target_dir.is_symlink():
        raise CommandExecutionError("backup_directory_is_symlink")
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not target_dir.is_dir():
        raise CommandExecutionError("backup_path_not_directory")
    os.chmod(target_dir, 0o700)
    if not db_path.is_file():
        raise CommandExecutionError("database_file_missing")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    filename = f"market_{timestamp}_{uuid.uuid4().hex[:8]}.sqlite3"
    destination = target_dir / filename
    temporary = target_dir / f".{filename}.tmp"
    source_uri = db_path.resolve().as_uri() + "?mode=ro"
    try:
        source = sqlite3.connect(source_uri, uri=True, timeout=10)
        try:
            target = sqlite3.connect(temporary, timeout=10)
            try:
                source.backup(target)
                target.commit()
            finally:
                target.close()
        finally:
            source.close()

        check = sqlite3.connect(temporary, timeout=10)
        try:
            integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            check.close()

        if integrity != "ok":
            raise CommandExecutionError("backup_integrity_check_failed")
        os.chmod(temporary, 0o600)
        try:
            os.link(temporary, destination)
            temporary.unlink()
        except OSError:
            os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)

    backups = sorted(
        (
            item
            for item in target_dir.glob("market_*.sqlite3")
            if item.is_file() and not item.is_symlink()
        ),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for old_backup in backups[10:]:
        old_backup.unlink()
    return {
        "file": filename,
        "bytes": destination.stat().st_size,
        "integrity": "ok",
        "retained": min(len(backups), 10),
    }


def _run_market_collection(db_path: Path, timeout: int = COMMAND_JOB_TIMEOUT_SECONDS) -> str:
    connection = connect(db_path)
    try:
        previous_id = int(connection.execute(
            "SELECT COALESCE(MAX(id), 0) FROM collection_runs"
        ).fetchone()[0])
    finally:
        connection.close()
    command = [sys.executable, "-m", "backend.run_collector"]
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError("collector_timeout") from exc
    if result.returncode != 0:
        raise CommandExecutionError("collector_failed")
    connection = connect(db_path)
    try:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS count FROM collection_runs WHERE id > ? GROUP BY status",
            (previous_id,),
        ).fetchall()
    finally:
        connection.close()
    totals = {str(row["status"]): int(row["count"]) for row in rows}
    return (
        "Market collection finished: "
        f"success={totals.get('success', 0)}, failed={totals.get('failed', 0)}, "
        f"skipped={totals.get('skipped', 0)}."
    )


def _stop_realtime_monitor() -> str:
    try:
        result = subprocess.run(
            ["systemctl", "--user", "disable", "--now", "market-realtime-monitor.service"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            timeout=60,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError("monitor_stop_timeout") from exc
    if result.returncode != 0:
        raise CommandExecutionError("monitor_stop_failed")
    return (
        "Real-time monitor stopped and disabled. "
        "To start it again locally: systemctl --user enable --now market-realtime-monitor.service"
    )


def _dispatch(command: str, db_path: Path) -> str:
    if command == "/status":
        return _status_result(db_path)
    if command == "/health":
        return _health_result(db_path)
    if command == "/market":
        return _market_result(db_path)
    if command == "/news":
        return _news_result(db_path)
    if command == "/social":
        return _social_result(db_path)
    if command == "/alerts":
        return _alerts_result(db_path)
    if command == "/help":
        return "Commands: " + ", ".join(sorted(COMMANDS))
    if command == "/collect":
        return _run_market_collection(db_path)
    if command == "/backup":
        result = _backup_database(db_path)
        return (
            f"Verified SQLite backup created: {result['file']} "
            f"({result['bytes']} bytes; integrity={result['integrity']}; "
            f"retained={result['retained']})."
        )
    if command == "/stop-monitor":
        return _stop_realtime_monitor()
    raise CommandExecutionError("command_not_allowlisted")


class CommandProcessor:
    def __init__(
        self,
        db_path: Path,
        config: CommandConfig,
        *,
        clock=time.time,
    ):
        self.db_path = db_path
        self.config = config
        self.clock = clock
        self.actor_requests: dict[int, deque[float]] = defaultdict(deque)

    def process(self, message: str) -> dict[str, object] | None:
        now_epoch = int(self.clock())
        try:
            envelope = _verify_message(message, self.config.secret, now_epoch)
        except CommandRejected as exc:
            LOGGER.warning("ntfy_command_rejected reason=%s", exc.code)
            return None

        actor_id = _active_admin(self.db_path, str(envelope["actor"]))
        received_at = datetime.fromtimestamp(
            now_epoch,
            tz=timezone.utc,
        ).isoformat(timespec="seconds")
        if actor_id is None:
            _write_audit(
                self.db_path,
                actor_user_id=None,
                command=str(envelope["command"])[:64],
                nonce=None,
                status="rejected",
                error_code="admin_required",
                result_summary=None,
                received_at=received_at,
                completed_at=received_at,
            )
            LOGGER.warning("ntfy_command_rejected reason=admin_required")
            return None

        command = str(envelope["command"])
        audit_id = _reserve_nonce(
            self.db_path,
            actor_id,
            command[:64],
            str(envelope["nonce"]),
            received_at,
        )
        if audit_id is None:
            _write_audit(
                self.db_path,
                actor_user_id=actor_id,
                command=command[:64],
                nonce=None,
                status="rejected",
                error_code="replay",
                result_summary=None,
                received_at=received_at,
                completed_at=received_at,
            )
            return self._signed_response(
                envelope,
                status="error",
                result="Command was already used; send a new nonce.",
            )

        bucket = self.actor_requests[actor_id]
        monotonic_now = time.monotonic()
        while bucket and monotonic_now - bucket[0] >= 60:
            bucket.popleft()
        if len(bucket) >= COMMAND_RATE_LIMIT:
            _finish_audit(
                self.db_path,
                audit_id,
                status="rejected",
                error_code="rate_limited",
            )
            return self._signed_response(
                envelope,
                status="error",
                result="Command rate limit exceeded; try again later.",
            )
        bucket.append(monotonic_now)

        if command not in COMMANDS:
            _finish_audit(
                self.db_path,
                audit_id,
                status="rejected",
                error_code="command_not_allowlisted",
            )
            return self._signed_response(
                envelope,
                status="error",
                result="Command is not allowlisted.",
            )

        try:
            result = _dispatch(command, self.db_path)
        except CommandExecutionError as exc:
            _finish_audit(
                self.db_path,
                audit_id,
                status="failed",
                error_code=exc.code,
            )
            return self._signed_response(
                envelope,
                status="error",
                result=f"Command failed: {exc.code}.",
            )
        except (OSError, sqlite3.Error, requests.RequestException) as exc:
            error_code = type(exc).__name__.casefold()
            _finish_audit(
                self.db_path,
                audit_id,
                status="failed",
                error_code=error_code,
            )
            return self._signed_response(
                envelope,
                status="error",
                result=f"Command failed: {error_code}.",
            )
        _finish_audit(
            self.db_path,
            audit_id,
            status="succeeded",
            result_summary=result,
        )
        return self._signed_response(envelope, status="ok", result=result)

    def _signed_response(
        self,
        envelope: dict[str, object],
        *,
        status: str,
        result: str,
    ) -> dict[str, object]:
        response: dict[str, object] = {
            "actor": envelope["actor"],
            "command": envelope["command"],
            "nonce": envelope["nonce"],
            "result": result,
            "status": status,
            "timestamp": int(self.clock()),
        }
        response["signature"] = _signature(response, self.config.secret)
        return response


def _session() -> requests.Session:
    retry = Retry(
        total=3,
        connect=3,
        read=0,
        status=3,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


def _read_poll_response(response: requests.Response) -> list[dict[str, Any]]:
    if response.status_code != 200:
        raise requests.HTTPError(f"ntfy poll returned HTTP {response.status_code}")
    if response.headers.get("X-Messages-Truncated") == "1":
        raise ValueError("ntfy poll response was truncated by the server")
    chunks = bytearray()
    for chunk in response.iter_content(chunk_size=65536):
        chunks.extend(chunk)
        if len(chunks) > MAX_POLL_BYTES:
            raise ValueError("ntfy poll response exceeded size limit")
    events: list[dict[str, Any]] = []
    for line in chunks.splitlines():
        if not line:
            continue
        event = json.loads(line)
        if isinstance(event, dict):
            events.append(event)
    return events


def _poll(
    session: requests.Session,
    config: CommandConfig,
    since: str,
) -> list[dict[str, Any]]:
    with session.get(
        f"{config.server}/{config.topic}/json",
        params={"poll": "1", "since": since},
        timeout=(5, 30),
        stream=True,
        allow_redirects=False,
    ) as response:
        return _read_poll_response(response)


def _publish(
    session: requests.Session,
    config: CommandConfig,
    payload: dict[str, object],
) -> None:
    response = session.post(
        f"{config.server}/{config.response_topic}",
        data=_canonical_json(payload),
        headers={"Content-Type": "application/json"},
        timeout=(5, 15),
        allow_redirects=False,
    )
    if not 200 <= response.status_code < 300:
        raise requests.HTTPError(f"ntfy response publish returned HTTP {response.status_code}")


def _event_message(event: dict[str, Any], topic: str) -> str | None:
    if event.get("event") != "message" or event.get("topic") != topic:
        return None
    message = event.get("message")
    if not isinstance(message, str):
        return None
    return message


def _request_shutdown(_signum: int, _frame: object) -> None:
    SHUTDOWN.set()


def run_listener() -> None:
    config = load_config()
    initialize_database(DB_PATH)
    lock_path = DB_PATH.parent / "ntfy-command-listener.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a", encoding="utf-8") as lock_file:
        if fcntl is not None:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                raise RuntimeError("Another ntfy command listener already holds the lock") from exc
        signal.signal(signal.SIGTERM, _request_shutdown)
        signal.signal(signal.SIGINT, _request_shutdown)
        processor = CommandProcessor(DB_PATH, config)
        client = _session()
        since = "latest"
        failures = 0
        LOGGER.info("ntfy_command_listener_started")
        try:
            while not SHUTDOWN.is_set():
                try:
                    events = _poll(client, config, since)
                    failures = 0
                    for event in events:
                        event_id = event.get("id")
                        if event_id is not None:
                            since = str(event_id)
                        message = _event_message(event, config.topic)
                        if message is None:
                            continue
                        signed_response = processor.process(message)
                        if signed_response is not None:
                            _publish(client, config, signed_response)
                except (requests.RequestException, OSError, sqlite3.Error, ValueError) as exc:
                    failures += 1
                    delay = min(60, 2 ** min(failures, 6))
                    LOGGER.error(
                        "ntfy_command_listener_error type=%s retry_seconds=%s",
                        type(exc).__name__,
                        delay,
                    )
                    SHUTDOWN.wait(delay)
        finally:
            client.close()
            LOGGER.info("ntfy_command_listener_stopped")


def _publish_signed_command(command: str, actor: str, config: CommandConfig) -> None:
    envelope = sign_command(command, actor, config.secret)
    response = requests.post(
        f"{config.server}/{config.topic}",
        data=_canonical_json(envelope),
        headers={"Content-Type": "application/json"},
        timeout=(5, 15),
        allow_redirects=False,
    )
    if not 200 <= response.status_code < 300:
        raise requests.HTTPError(f"ntfy command publish returned HTTP {response.status_code}")
    print(f"Published signed {command} request.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Authenticated ntfy command center")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("run", help="Run the independent command listener")
    sign_parser = commands.add_parser("sign", help="Print a signed allowlisted command envelope")
    sign_parser.add_argument("command", choices=sorted(COMMANDS))
    sign_parser.add_argument("--actor", required=True)
    publish_parser = commands.add_parser("publish", help="Publish a signed allowlisted command")
    publish_parser.add_argument("command", choices=sorted(COMMANDS))
    publish_parser.add_argument("--actor", required=True)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if args.action == "run":
        run_listener()
        return
    config = load_config(require_enabled=False)
    if args.action == "sign":
        print(json.dumps(sign_command(args.command, args.actor, config.secret)))
        return
    _publish_signed_command(args.command, args.actor, config)


if __name__ == "__main__":
    main()
