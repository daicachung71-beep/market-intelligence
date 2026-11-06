# ntfy Command Center

The command listener is an optional, independent process. It is disabled by default and only controls the real-time monitor through the fixed `/stop-monitor` command; it cannot start or control other services. It accepts a fixed command allowlist, verifies an HMAC signature and timestamp, requires the named account to be an active `ADMIN`, consumes a persistent one-time nonce, and records an audit row before running a command. No message is passed to a shell.

## Configure

Set these values in the private `.env` file:

```dotenv
NTFY_COMMAND_ENABLED=true
NTFY_COMMAND_TOPIC=<private-command-topic>
NTFY_COMMAND_RESPONSE_TOPIC=<different-private-response-topic>
NTFY_COMMAND_SECRET=<random-secret-of-at-least-32-bytes>
```

Use separate, high-entropy topics and a separate signing key; do not reuse `AUTH_TOKEN_SECRET` or paste any of them into chat, screenshots, source control, or issue reports. For example, generate candidate values locally with `openssl rand -hex 24` and store them directly in `.env`, then run `chmod 600 .env`. The command listener requires an HTTPS ntfy server and uses `NTFY_BASE_URL`, falling back to `NTFY_SERVER` and then `https://ntfy.sh`.

The listener verifies that the `actor` is an active ADMIN in the local database. Create that account using the Phase 1 bootstrap instructions if needed. Install and start the independent user service only after configuration:

The unit template assumes the checkout is at `~/market-intelligence`, like the other units in `deploy/`. If it is elsewhere, update its `WorkingDirectory`, `EnvironmentFile`, `ExecStart`, and `ReadWritePaths` before installing it.

```bash
mkdir -p ~/market-intelligence/backups
chmod 700 ~/market-intelligence/backups
mkdir -p ~/.config/systemd/user
cp deploy/market-command-listener.service ~/.config/systemd/user/
cp deploy/market-realtime-monitor.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now market-realtime-monitor.service market-command-listener.service
systemctl --user status market-realtime-monitor.service market-command-listener.service
journalctl --user -u market-command-listener.service -n 100 --no-pager
```

Run `loginctl enable-linger "$USER"` on the VPS (or have its administrator do so) so the user systemd manager and both services start at boot and continue after logout. Keep the VPS powered on with network access; a VPS that is stopped, suspended, or unreachable cannot process commands. The listener service is not enabled automatically. It needs write access only to the SQLite data directory and `backups/`. Existing scheduled collection and remote `/collect` share a non-blocking lock so they cannot run concurrently.

## Commands

Read-only commands:

- `/status`: command listener, database and last market collection.
- `/health`: SQLite quick integrity check.
- `/market`: compact tracked-asset snapshot.
- `/news`: up to three most recent stored headlines.
- `/social`: social collection state and stored counts.
- `/alerts`: up to twenty recent price alerts. This only limits the history shown; it does not stop monitoring.
- `/stop-monitor`: stops and disables the real-time monitor so it will remain stopped after a reboot. To enable it again, run `systemctl --user enable --now market-realtime-monitor.service` on the VPS.
- `/help`: allowlisted commands.

Bounded jobs:

- `/collect`: runs only `python -m backend.run_collector`, with a fixed 300-second timeout and no caller-provided arguments. The existing provider adapters keep their own request timeouts and retry limits.
- `/backup`: creates an SQLite online backup in `backups/`, runs `PRAGMA integrity_check`, and retains the ten newest `market_*.sqlite3` snapshots. It does not back up `.env` or model artifacts.

No general `/start`, `/stop`, `/restart`, arbitrary command, command arguments, or host reboot operations are supported. `/stop-monitor` is the sole fixed service action; other lifecycle operations must be run locally through systemd.

## Send from a phone

`tools/ntfy_command_sender.py` is a small Python-standard-library publisher that can be copied to a trusted Termux environment. It signs and publishes only the allowlisted commands. Configure the topic and server in the phone's private Termux environment; enter the signing secret interactively rather than putting it in shell history:

```bash
read -rsp 'Command signing secret: ' NTFY_COMMAND_SECRET
export NTFY_COMMAND_SECRET
export NTFY_COMMAND_TOPIC='<private-command-topic>'
export NTFY_SERVER='https://ntfy.sh'
python ntfy_command_sender.py /status --actor admin
unset NTFY_COMMAND_SECRET
```

Subscribe to the separate response topic in the ntfy app. Responses are HMAC-signed with the same secret. The request protocol covers the canonical JSON fields `actor`, `command`, `timestamp` (Unix seconds), and `nonce`; the listener accepts timestamps only within five minutes and rejects nonce reuse. A valid signature is required in addition to the ADMIN account check.

## Security and operations

ntfy over HTTPS protects data in transit but does not encrypt message contents end-to-end. Treat both topic names and the signing key as sensitive; anyone with the signing key can issue ADMIN commands, and command/status results may be visible to ntfy topic readers. Use a private ntfy server with access controls when topic confidentiality is required. Rotate the command key and topics if a phone is lost.

The listener rate-limits each ADMIN to ten commands per minute, processes at most twenty ntfy events per poll, bounds poll response size, rejects redirects, and retries network failures with capped backoff. Invalid signatures are rejected without publishing an error response. Authenticated requests and job outcomes are retained in `ntfy_command_audit` and are available to ADMIN accounts at `GET /api/auth/command-audit`. Tests use fake providers/HTTP and never send real ntfy messages.
