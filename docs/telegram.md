# avaTUN Telegram management

The optional bot uses the panel's password-authenticated API and long polling.
It runs on the central panel server and controls all registered tunnel endpoints
through the same API used by the dashboard. Python 3.11 and the standard library
are sufficient. No inbound Telegram port or webhook is needed.

## Interface and behavior

The main interface uses Telegram's native HTML text and inline keyboards. It
edits a single console message when navigating, with a compact home, named
server/tunnel buttons, contextual actions, pagination, and back/home/refresh
controls. `/start` opens a fresh console and closes an unfinished form.

- **Servers:** connection, service/version, resource summary, and links to that
  server's tunnels and resource page.
- **Tunnels:** internal addresses, latency, MTU and endpoint state, followed by
  confirmed start/stop/restart actions for administrators.
- **Resources:** CPU, memory, disk, transfer rates, and sample age.
- **Forwarding:** choose any managed server, inspect its HAProxy rules, toggle,
  delete, or create/edit with a guided form. `/cancel` exits a form. Old form
  controls cannot change a newer draft.
- **Updates:** inspect the installed/GitHub version, request a check, then confirm
  installation of the specific commit shown.
- **Reports and audit:** 24-hour incidents, recent operations, and daily reports.

Callback buttons are bound to a user and stored in SQLite. Navigation lasts up
to 24 hours across restarts; operational confirmations expire after 3 minutes
and are consumed before execution. Confirmed operations run in background
workers so polling stays responsive. Partial endpoint failures are reported.
An interrupted mutation is never replayed automatically after a restart.

All displayed and entered decimal digits are converted to ASCII. Dynamic HTML
is escaped. Viewer accounts can inspect status/resources/reports; forwarding,
audit, settings and updates require an administrator.

Monitoring retains debounced server/tunnel/panel outages after 60 seconds,
resource alerts above 90% for 120 seconds (clearing below 85%), recovery messages,
and a daily report at 09:00 Asia/Tehran. Alerts remain separate messages and do
not replace the active console.

HTML widget delivery is an explicit experiment under **Settings**, also
reachable with `/widgets`. Normal navigation never calls `sendWidget`.

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

Commands: `/start`, `/status`, `/servers`, `/tunnels`, `/hardware`, `/report`,
`/help`, `/cancel`. Administrators also have `/forwards`, `/update`, `/audit`,
and `/settings`. Legacy `/tunnel_list` and `/haproxy` aliases still work.
Use `journalctl -u avatun-telegram` for logs. Credentials are redacted from
outgoing error messages and network exceptions are logged by type only.

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
