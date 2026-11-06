import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

COMMANDS = {
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
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,48}$")
TOPIC_PATTERN = re.compile(r"^[-_A-Za-z0-9]{1,64}$")


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def build_envelope(command: str, actor: str, secret: str, *, timestamp: int | None = None) -> dict[str, object]:
    if command not in COMMANDS:
        raise ValueError("Command is not allowlisted")
    if not USERNAME_PATTERN.fullmatch(actor):
        raise ValueError("Actor must be a valid Market Intelligence username")
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("NTFY_COMMAND_SECRET must contain at least 32 bytes")
    payload: dict[str, object] = {
        "actor": actor,
        "command": command,
        "timestamp": int(time.time()) if timestamp is None else timestamp,
        "nonce": secrets.token_urlsafe(24),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload["signature"] = hmac.new(
        secret.encode("utf-8"),
        canonical,
        hashlib.sha256,
    ).hexdigest()
    return payload


def publish(command: str, actor: str, environ: dict[str, str] | None = None) -> str:
    config = os.environ if environ is None else environ
    server = (
        config.get("NTFY_BASE_URL", "").strip()
        or config.get("NTFY_SERVER", "https://ntfy.sh").strip()
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
        raise ValueError("ntfy command server must use HTTPS and contain no credentials")
    topic = config.get("NTFY_COMMAND_TOPIC", "").strip()
    if not TOPIC_PATTERN.fullmatch(topic):
        raise ValueError("NTFY_COMMAND_TOPIC is invalid")
    envelope = build_envelope(
        command,
        actor,
        config.get("NTFY_COMMAND_SECRET", ""),
    )
    request = urllib.request.Request(
        f"{server}/{topic}",
        data=json.dumps(envelope, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(
        NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    with opener.open(request, timeout=15) as response:
        if not 200 <= response.status < 300:
            raise ValueError(f"ntfy returned HTTP {response.status}")
        body = response.read(65536)
    if not body:
        return "published"
    try:
        result = json.loads(body)
    except json.JSONDecodeError:
        return "published"
    message_id = result.get("id") if isinstance(result, dict) else None
    return str(message_id) if isinstance(message_id, str) else "published"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish a signed, allowlisted Market Intelligence ntfy command"
    )
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--actor", required=True, help="Active ADMIN username")
    args = parser.parse_args()
    try:
        message_id = publish(args.command, args.actor)
    except (OSError, ValueError, urllib.error.URLError, TimeoutError) as exc:
        print(f"Command publish failed ({type(exc).__name__}).", file=sys.stderr)
        return 1
    print(f"Published {args.command} request ({message_id}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
