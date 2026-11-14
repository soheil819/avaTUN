# avaTUN Telegram management

The optional bot uses the panel's password-authenticated API and long polling.
It runs on the central panel server and controls all registered tunnel endpoints
through the same API used by the dashboard. Python 3.11 and the standard library
are sufficient. No inbound Telegram port or webhook is needed.

## Features

- Private inline menus for overview, server status, CPU/RAM/disk/swap and upload/download.
- Live server status widget with online state, tunnel count, installed version, service state, server details, and 15-second refresh.
- Live tunnel widget with status, protocol, peer addresses and latency, plus
  per-tunnel details and confirmed two-sided operations.
- Confirmed start/stop/restart of both tunnel endpoints. A partial failure names
  the failed endpoint. Ambiguous mutations are never retried automatically.
- Live diagnostics using each endpoint's status/probe API.
- HAProxy status widget and rules, primary/backup backend health, and confirmed
  enable/disable, edit, delete, or create flows. The guided bot form configures
  listener IP/port, destination port, balancing algorithm, PROXY protocol,
  health-check PROXY behavior, session shutdown, tunnel backends, their roles,
  and weights. The panel API validates and applies the final configuration.
  Disabling preserves the rule in the panel database for later re-enabling.
- Server/tunnel/panel outage alerts after 60 seconds, plus recovery notifications.
- Resource alerts above 90% for 120 seconds, clearing below 85%.
- Daily report at 09:00 Asia/Tehran by default, plus `/report` on demand.
- Numeric user allowlists, admin/viewer roles, operation audit and one-use
  confirmation buttons. Callback buttons expire after ten minutes or a restart.
- Admin-only `/update` checks GitHub and offers a confirmed background update;
  admins are also notified once when a newer version is found.
- Persistent polling offset, incidents and pending notifications in SQLite.
  A failed delivery does not prevent the bot from receiving new commands.

## Configuration

The installer copies the bot and systemd unit. On the first save in **Settings
→ Telegram bot**, enter the BotFather token and at least one Telegram admin ID.
The panel creates the initial config and a dedicated internal admin account
automatically; there is no separate bot-install step. Later saves can leave the
token field blank to retain the current token. Panel authorization still applies
in addition to the Telegram roles. The legacy `chat_id` configuration remains
supported with viewer access.

Create `/etc/avatun/telegram.json` on the central panel server:

```json
{
  "bot_token": "BOTFATHER_TOKEN",
  "admins": [123456789],
  "viewers": [],
  "panel_url": "http://127.0.0.1:8765",
  "panel_username": "telegram-bot",
  "panel_password": "DEDICATED_PANEL_ACCOUNT_PASSWORD",
  "timezone": "Asia/Tehran",
  "daily_report_hour": 9,
  "state_path": "/var/lib/tunnelmgr/telegram.sqlite3"
}
```

Administrators can change the BotFather token and Telegram administrator ID
list from **Settings → Telegram bot** in the web panel. The token is never sent
back to the browser; saving enables and restarts the bot service automatically.

User IDs must be positive numbers. Only private chats where the sender and chat
ID match an allowed user are accepted. Add a viewer to `viewers` to permit status
and reports without operational buttons. Alerts and scheduled reports go to admins.
Use HTTPS when connecting to a panel outside loopback. Tokens and passwords are
kept in this server config, never in Git or chat replies.

```sh
chown root:tunnelmgr /etc/avatun/telegram.json
chmod 640 /etc/avatun/telegram.json
sudo -u tunnelmgr python3 /opt/tunnelmgr/tunnelmgr/telegram_bot.py --check
systemctl daemon-reload
systemctl enable --now avatun-telegram
```

Send `/start` to the bot from your allowed Telegram account. Until that first
message, Telegram cannot deliver private notifications. An existing webhook must
be removed before polling is activated. The bot reports this configuration error
and does not delete an existing webhook automatically.

Available commands are `/start`, `/status`, `/servers` (live server widget), `/tunnels` (live tunnel widget),
`/tunnel_list`, `/hardware`, `/forwards` and `/haproxy`, `/report` and `/audit`
(admins). HAProxy configuration is administrator-only. Use `journalctl -u avatun-telegram`
for logs. Credentials are redacted from outgoing error messages and network
exceptions are logged by type only.

Run the regression checks with `python3 scripts/check-telegram.py`.

### HTML widget delivery

The bot calls the official `sendWidget` method in each allowed user's private
chat. It checks the HTML and compressed payload limits before sending. Layout
changes create a new widget because Telegram can only edit an existing widget's
data, not its HTML.

If Telegram replies `INPUT_MEDIA_WIDGET_NOT_ALLOWED`, the bot shows that reason
with an inline-keyboard menu. The rejection delays retries for five minutes for
that bot token and user only. The next menu request after the delay tries a
widget again; **تلاش دوباره برای ویجت** retries immediately. The legacy global
disable flag is ignored. This fallback does not mean widget delivery succeeded,
and changing the panel code cannot grant Telegram-side sending permissions.

Telegram API reference: https://core.telegram.org/bots/api
