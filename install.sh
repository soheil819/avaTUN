#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root: sudo $0" >&2
    exit 1
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -f "$ROOT/tunnelmgr/tunnelctl.py" ] || [ ! -f "$ROOT/scripts/install-preview.sh" ] || \
   [ ! -f "$ROOT/vendor/backhaul/bin/backhaul" ] || [ ! -f "$ROOT/vendor/backhaul/SHA256SUMS" ]; then
    echo 'Run install.sh from a complete avaTUN source directory.' >&2
    exit 1
fi

if [ ! -r /etc/os-release ]; then
    echo 'Could not identify this Linux distribution.' >&2
    exit 1
fi
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu|linuxmint|pop) ;;
    *) echo 'Supported systems: Debian and Ubuntu (including compatible derivatives).' >&2; exit 1 ;;
esac
command -v apt-get >/dev/null 2>&1 || { echo 'apt-get is required.' >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl iproute2 openssl python3
python3 -c 'import sys; sys.version_info >= (3,11) or sys.exit("avaTUN requires Python 3.11 or newer")'
command -v systemctl >/dev/null 2>&1 || { echo 'systemd is required.' >&2; exit 1; }

# Install files and dependencies, but keep the public API stopped until its
# first administrator account has been created.
AVATUN_INSTALL_DEFER_START=1 sh "$ROOT/scripts/install-preview.sh"

runuser -u tunnelmgr -- env TUNNELMGR_HOME=/var/lib/tunnelmgr \
    /usr/bin/python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py init >/dev/null

ACCOUNT_COUNT=$(runuser -u tunnelmgr -- env TUNNELMGR_HOME=/var/lib/tunnelmgr \
    /usr/bin/python3 -c 'import sqlite3; c=sqlite3.connect("/var/lib/tunnelmgr/state.sqlite3"); print(c.execute("SELECT count(*) FROM accounts").fetchone()[0])')
ADMIN_USER=admin
ADMIN_PASSWORD=
if [ "$ACCOUNT_COUNT" -eq 0 ]; then
    ADMIN_PASSWORD=$(openssl rand -hex 18)
    printf '%s\n' "$ADMIN_PASSWORD" | runuser -u tunnelmgr -- env TUNNELMGR_HOME=/var/lib/tunnelmgr \
        /usr/bin/python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account create "$ADMIN_USER" --role admin --password-stdin >/dev/null
fi

systemctl daemon-reload
systemctl enable --now frr.service tunnelmgr-privd.service tunnelmgr.service
systemctl restart frr.service tunnelmgr-privd.service tunnelmgr.service
systemctl is-active --quiet tunnelmgr.service || {
    echo 'avaTUN service did not start; inspect: journalctl -u tunnelmgr.service -n 100 --no-pager' >&2
    exit 1
}

PANEL_HOST=${PANEL_HOST:-}
if [ -z "$PANEL_HOST" ]; then
    PANEL_HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')
fi
if [ -z "$PANEL_HOST" ]; then
    PANEL_HOST=$(hostname -f 2>/dev/null || hostname)
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 8765/tcp >/dev/null
fi

VERSION=$(sed -n 's/^APP_VERSION="\([^"]*\)"/\1/p' /opt/tunnelmgr/tunnelmgr/tunnelctl.py | head -n 1)
printf '\n%s\n' '============================================================'
printf 'avaTUN %s installed and running.\n' "${VERSION:-}"
printf 'Panel:    http://%s:8765\n' "$PANEL_HOST"
if [ -n "$ADMIN_PASSWORD" ]; then
    printf 'Username: %s\n' "$ADMIN_USER"
    printf 'Password: %s\n' "$ADMIN_PASSWORD"
else
    EXISTING_USERS=$(runuser -u tunnelmgr -- env TUNNELMGR_HOME=/var/lib/tunnelmgr \
        /usr/bin/python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py account list | \
        /usr/bin/python3 -c 'import json,sys; print(", ".join(x["name"] for x in json.load(sys.stdin)))')
    printf 'Existing accounts were preserved; username(s): %s (use current password).\n' "$EXISTING_USERS"
fi
printf '%s\n' '============================================================'
printf '%s\n' 'If your provider firewall is enabled, allow TCP port 8765 there as well.'
