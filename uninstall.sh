#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo 'Run as root: sudo ./uninstall.sh' >&2
    exit 1
fi

cat <<'NOTICE'
This removes the avaTUN panel, its Telegram bot, local tunnel interfaces and
avaTUN-owned configuration and state from this host.
It does not remove system packages, FRR, HAProxy, Certbot, firewall rules,
kernel modules, swap, remote-server installations, or unrelated services.
NOTICE
printf 'Type REMOVE AVATUN to continue: '
IFS= read -r answer
[ "$answer" = 'REMOVE AVATUN' ] || { echo 'Cancelled.'; exit 1; }

command -v systemctl >/dev/null 2>&1 || { echo 'systemd is required.' >&2; exit 1; }

# Stop only instances of avaTUN-owned systemd templates. These units own the
# virtual interfaces created by the panel; unrelated network devices remain.
for pattern in \
    'tunnelmgr-network@*.service' \
    'tunnelmgr-openvpn@*.service' \
    'tunnelmgr-openconnect@*.service' \
    'tunnelmgr-ocserv@*.service' \
    'tunnelmgr-mesh@*.service'; do
    systemctl list-units --all --plain --no-legend "$pattern" 2>/dev/null |
        awk '{print $1}' |
        while IFS= read -r unit; do
            case "$unit" in tunnelmgr-*@*.service) systemctl disable --now "$unit" >/dev/null 2>&1 || true ;; esac
        done
done

for unit in \
    avatun-telegram.service avatun-panel-tls.service \
    tunnelmgr.service tunnelmgr-privd.service tunnelmgr-xray.service \
    tunnelmgr-github-update.service tunnelmgr-github-update-check.service \
    tunnelmgr-github-update-check.timer; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
done

systemctl daemon-reload

# Remove only unit files installed under avaTUN's reserved unit-name prefix.
find /etc/systemd/system -maxdepth 1 -type f \
    \( -name 'tunnelmgr*.service' -o -name 'tunnelmgr*.timer' \
       -o -name 'avatun-*.service' \) -delete
systemctl daemon-reload

rm -rf -- \
    /opt/tunnelmgr \
    /etc/tunnelmgr \
    /etc/avatun \
    /var/lib/tunnelmgr \
    /var/backups/tunnelmgr

echo 'avaTUN panel files and owned services have been removed.'
echo 'Shared packages, system networking, firewall rules, swap, and the tunnelmgr system account were preserved.'
