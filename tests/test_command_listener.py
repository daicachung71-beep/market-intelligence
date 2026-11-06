import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.auth import create_user
from backend.command_listener import (
    COMMANDS,
    CommandConfig,
    CommandExecutionError,
    CommandProcessor,
    _backup_database,
    _poll,
    _run_market_collection,
    _dispatch,
    _verify_message,
    sign_command,
)
from backend.database import connect, initialize_database
from tools.ntfy_command_sender import build_envelope

SECRET = "independent-command-signing-secret-of-at-least-32-bytes"


def _config() -> CommandConfig:
    return CommandConfig(
        server="https://ntfy.sh",
        topic="market-command-private",
        response_topic="market-response-private",
        secret=SECRET,
    )


def _signed_text(command: str, actor: str, now: int, nonce: str) -> str:
    return json.dumps(
        sign_command(command, actor, SECRET, timestamp=now, nonce=nonce),
        separators=(",", ":"),
    )


def test_command_listener_requires_admin_signature_and_consumes_nonce(tmp_path, monkeypatch):
    db_path = tmp_path / "market.sqlite3"
    initialize_database(db_path)
    admin = create_user(db_path, "command-admin", "a-very-long-command-test-password", "ADMIN")
    create_user(db_path, "read-only-user", "another-long-command-test-password", "READ_ONLY")
    now = 1_800_000_000
    processor = CommandProcessor(db_path, _config(), clock=lambda: now)
    monkeypatch.setattr(
        "backend.command_listener._dispatch",
        lambda command, _db_path: f"ran {command}",
    )

    nonce = "n" * 24
    message = _signed_text("/help", "command-admin", now, nonce)
    result = processor.process(message)
    assert result is not None
    assert result["status"] == "ok"
    assert result["result"] == "ran /help"
    response_signature = str(result.pop("signature"))
    expected_signature = hmac.new(
        SECRET.encode(),
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(response_signature, expected_signature)

    replay = processor.process(message)
    assert replay is not None
    assert replay["status"] == "error"
    assert "already used" in str(replay["result"])
    assert processor.process(_signed_text("/help", "read-only-user", now, "r" * 24)) is None

    tampered = sign_command("/help", "command-admin", SECRET, timestamp=now, nonce="t" * 24)
    tampered["command"] = "/backup"
    assert processor.process(json.dumps(tampered)) is None
    stale = _signed_text("/help", "command-admin", now - 301, "s" * 24)
    assert processor.process(stale) is None

    connection = connect(db_path)
    try:
        rows = connection.execute(
            "SELECT actor_user_id, command, status, error_code "
            "FROM ntfy_command_audit ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    assert [row["status"] for row in rows] == ["succeeded", "rejected", "rejected"]
    assert rows[0]["actor_user_id"] == admin["id"]
    assert rows[1]["error_code"] == "replay"
    assert rows[2]["error_code"] == "admin_required"


def test_command_rate_limit_and_allowlist(tmp_path, monkeypatch):
    db_path = tmp_path / "market.sqlite3"
    initialize_database(db_path)
    create_user(db_path, "command-admin", "a-very-long-command-test-password", "ADMIN")
    now = 1_800_000_000
    processor = CommandProcessor(db_path, _config(), clock=lambda: now)
    monkeypatch.setattr("backend.command_listener._dispatch", lambda *_args: "ok")

    results = [
        processor.process(
            _signed_text("/help", "command-admin", now, f"nonce-{index:020d}")
        )
        for index in range(11)
    ]
    assert all(result and result["status"] == "ok" for result in results[:10])
    assert results[10] is not None
    assert results[10]["status"] == "error"
    assert "rate limit" in str(results[10]["result"])

    assert "/start" not in COMMANDS
    with pytest.raises(ValueError, match="not allowlisted"):
        sign_command("/start", "command-admin", SECRET)
    assert "/stop-monitor" in COMMANDS


def test_phone_sender_uses_listener_signature_protocol():
    now = 1_800_000_000
    envelope = build_envelope("/status", "command-admin", SECRET, timestamp=now)
    verified = _verify_message(json.dumps(envelope), SECRET, now)
    assert verified["command"] == "/status"
    assert verified["actor"] == "command-admin"
    assert build_envelope(
        "/stop-monitor", "command-admin", SECRET, timestamp=now
    )["command"] == "/stop-monitor"


def test_stop_monitor_uses_only_fixed_systemd_user_command(monkeypatch):
    calls = []

    def run_fixed(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("backend.command_listener.subprocess.run", run_fixed)

    result = _dispatch("/stop-monitor", Path("unused"))

    assert "stopped and disabled" in result
    assert calls[0][0] == [
        "systemctl",
        "--user",
        "disable",
        "--now",
        "market-realtime-monitor.service",
    ]
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["stdin"] == subprocess.DEVNULL
    assert calls[0][1]["timeout"] == 60


def test_stop_monitor_reports_systemd_failure(monkeypatch):
    monkeypatch.setattr(
        "backend.command_listener.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )

    with pytest.raises(CommandExecutionError, match="monitor_stop_failed"):
        _dispatch("/stop-monitor", Path("unused"))


def test_poll_uses_ntfy_json_poll_protocol():
    class PollResponse:
        status_code = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_content(self, chunk_size):
            assert chunk_size == 65536
            yield b'{"id":"message-id","event":"message"}\n'

    class PollSession:
        def get(self, url, **kwargs):
            self.url = url
            self.kwargs = kwargs
            return PollResponse()

    session = PollSession()
    events = _poll(session, _config(), "latest")

    assert session.url == "https://ntfy.sh/market-command-private/json"
    assert session.kwargs["params"] == {"poll": "1", "since": "latest"}
    assert session.kwargs["allow_redirects"] is False
    assert events == [{"id": "message-id", "event": "message"}]


def test_database_backup_is_integrity_checked_private_and_rotated(tmp_path):
    db_path = tmp_path / "market.sqlite3"
    backup_dir = tmp_path / "backups"
    initialize_database(db_path)

    results = [
        _backup_database(db_path, backup_dir)
        for _ in range(11)
    ]

    backups = sorted(backup_dir.glob("market_*.sqlite3"))
    assert len(backups) == 10
    assert all(result["integrity"] == "ok" for result in results)
    assert all(result["bytes"] > 0 for result in results)
    if os.name != "nt":
        assert all(os.stat(path).st_mode & 0o077 == 0 for path in backups)
    assert not list(backup_dir.glob("*.tmp"))
    for path in backups:
        with sqlite3.connect(path) as connection:
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_read_only_commands_return_local_database_state(tmp_path):
    db_path = tmp_path / "market.sqlite3"
    initialize_database(db_path)

    assert "healthy" in _dispatch("/health", db_path)
    assert "Market snapshot" in _dispatch("/market", db_path)
    assert "No collected news" in _dispatch("/news", db_path)
    assert "Social monitor" in _dispatch("/social", db_path)
    assert "No price alerts" in _dispatch("/alerts", db_path)
    assert "Commands:" in _dispatch("/help", db_path)


def test_alerts_command_returns_more_than_five_recent_alerts(tmp_path):
    db_path = tmp_path / "market.sqlite3"
    initialize_database(db_path)
    connection = connect(db_path)
    try:
        connection.executemany(
            "INSERT INTO alert_events "
            "(event_key, symbol, interval, rule, timestamp, change_pct, delivery_status) "
            "VALUES (?, ?, '1h', 'test', ?, 5.0, 'sent')",
            [
                (f"BTC:1h:{index}", "BTC", f"2026-11-06T19:{index:02d}:00+00:00")
                for index in range(7)
            ],
        )
        connection.commit()
    finally:
        connection.close()

    result = _dispatch("/alerts", db_path)

    assert result.count("- BTC") == 7


def test_collector_job_uses_fixed_no_shell_command_and_timeout(tmp_path, monkeypatch):
    db_path = tmp_path / "market.sqlite3"
    initialize_database(db_path)
    calls = []

    def run_fixed(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("backend.command_listener.subprocess.run", run_fixed)
    result = _run_market_collection(db_path, timeout=7)
    assert result.startswith("Market collection finished")
    assert calls[0][0] == [sys.executable, "-m", "backend.run_collector"]
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 7
    assert calls[0][1]["stdin"] == subprocess.DEVNULL

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("collector", 7)

    monkeypatch.setattr("backend.command_listener.subprocess.run", timeout)
    with pytest.raises(CommandExecutionError, match="collector_timeout"):
        _run_market_collection(db_path, timeout=7)
