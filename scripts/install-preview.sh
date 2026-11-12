#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v python3 >/dev/null
python3 -c 'import sys; assert sys.version_info >= (3,11)'

# Keep small-memory servers installable. Do not resize, replace, or disable
# existing swap; only add this managed 512 MiB file when no swap is active.
if ! awk 'NR > 1 { found=1 } END { exit !found }' /proc/swaps; then
    SWAP_FILE=/swapfile.avatun
    if [ -e "$SWAP_FILE" ]; then
        if swapon "$SWAP_FILE" 2>/dev/null; then
            :
        else
            echo "Swap is inactive and $SWAP_FILE already exists; refusing to overwrite it." >&2
            exit 1
        fi
    else
        ROOT_FS=$(findmnt -n -o FSTYPE --target / 2>/dev/null || true)
        if [ "$ROOT_FS" = btrfs ]; then
            : > "$SWAP_FILE"
            chattr +C "$SWAP_FILE"
            if ! dd if=/dev/zero of="$SWAP_FILE" bs=1M count=512 conv=fsync status=none; then
                rm -f "$SWAP_FILE"
                echo 'Could not allocate the 512 MiB Avatun swap file.' >&2
                exit 1
            fi
        elif command -v fallocate >/dev/null 2>&1 && fallocate -l 512M "$SWAP_FILE"; then
            :
        else
            rm -f "$SWAP_FILE"
            if ! dd if=/dev/zero of="$SWAP_FILE" bs=1M count=512 conv=fsync status=none; then
                rm -f "$SWAP_FILE"
                echo 'Could not allocate the 512 MiB Avatun swap file.' >&2
                exit 1
            fi
        fi
        chmod 0600 "$SWAP_FILE"
        if ! mkswap "$SWAP_FILE" >/dev/null; then
            rm -f "$SWAP_FILE"
            echo 'Could not format the 512 MiB Avatun swap file.' >&2
            exit 1
        fi
        if ! swapon "$SWAP_FILE"; then
            rm -f "$SWAP_FILE"
            echo 'Could not activate the 512 MiB Avatun swap file.' >&2
            exit 1
        fi
    fi
    if ! awk '$1 == "/swapfile.avatun" && $3 == "swap" { found=1 } END { exit !found }' /etc/fstab; then
        printf '%s\n' '/swapfile.avatun none swap sw 0 0' >> /etc/fstab
    fi
    echo 'Activated persistent 512 MiB swap at /swapfile.avatun.'
else
    echo 'Active swap detected; leaving the existing swap configuration unchanged.'
fi

PACKAGES=""
command -v haproxy >/dev/null 2>&1 || PACKAGES="$PACKAGES haproxy"
command -v wg >/dev/null 2>&1 || PACKAGES="$PACKAGES wireguard-tools"
command -v openvpn >/dev/null 2>&1 || PACKAGES="$PACKAGES openvpn"
command -v ocserv >/dev/null 2>&1 || PACKAGES="$PACKAGES ocserv"
command -v openconnect >/dev/null 2>&1 || PACKAGES="$PACKAGES openconnect"
command -v vtysh >/dev/null 2>&1 || PACKAGES="$PACKAGES frr"
command -v openssl >/dev/null 2>&1 || PACKAGES="$PACKAGES openssl"
command -v certbot >/dev/null 2>&1 || PACKAGES="$PACKAGES certbot"
if [ -n "$PACKAGES" ]; then
    command -v apt-get >/dev/null 2>&1 || { echo 'HAProxy, WireGuard, OpenVPN, OpenConnect, FRR and Certbot require a Debian/Ubuntu package manager' >&2; exit 1; }
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y $PACKAGES
fi
getent passwd tunnelmgr >/dev/null 2>&1 || useradd --system --home-dir /var/lib/tunnelmgr --create-home --shell /usr/sbin/nologin tunnelmgr
install -d -o root -g root -m 0755 /opt/tunnelmgr/tunnelmgr /opt/tunnelmgr/web /etc/systemd/system
install -d -o root -g root -m 0755 /opt/tunnelmgr/web/assets
install -d -o root -g root -m 0755 /opt/tunnelmgr/packaging/systemd
install -o root -g root -m 0644 "$ROOT/tunnelmgr/tunnelctl.py" /opt/tunnelmgr/tunnelmgr/tunnelctl.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/openconnect_runner.py" /opt/tunnelmgr/tunnelmgr/openconnect_runner.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/routing.py" /opt/tunnelmgr/tunnelmgr/routing.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/topology.py" /opt/tunnelmgr/tunnelmgr/topology.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/privd.py" /opt/tunnelmgr/tunnelmgr/privd.py
install -o root -g root -m 0644 "$ROOT/packaging/systemd/tunnelmgr-privd.service" /etc/systemd/system/tunnelmgr-privd.service
install -o root -g root -m 0644 "$ROOT"/packaging/systemd/*.service /opt/tunnelmgr/packaging/systemd/
install -o root -g root -m 0644 "$ROOT/web/index.html" /opt/tunnelmgr/web/index.html
install -o root -g root -m 0644 "$ROOT/web/assets/"* /opt/tunnelmgr/web/assets/
install -o root -g root -m 0644 "$ROOT/packaging/systemd/tunnelmgr.service" /etc/systemd/system/tunnelmgr.service
install -o root -g root -m 0644 "$ROOT/packaging/systemd/avatun-panel-tls.service" /etc/systemd/system/avatun-panel-tls.service
install -d -o tunnelmgr -g tunnelmgr -m 0700 /var/lib/tunnelmgr
install -d -o root -g root -m 0700 /etc/tunnelmgr/network
# Paths listed in tunnelmgr-privd.service ReadWritePaths must exist before systemd starts it.
install -d -o root -g root -m 0755 /etc/backhaul /var/lib/backhaul-manager /etc/swanctl/conf.d
install -d -o root -g root -m 0755 /var/lib/letsencrypt /var/log/letsencrypt /var/cache/letsencrypt
install -m 0644 "$ROOT/tunnelmgr/network.py" /opt/tunnelmgr/tunnelmgr/
install -m 0644 "$ROOT/packaging/systemd/tunnelmgr-network@.service" /etc/systemd/system/
install -m 0644 "$ROOT/packaging/systemd/tunnelmgr-openvpn@.service" /etc/systemd/system/
install -m 0644 "$ROOT/packaging/systemd/tunnelmgr-ocserv@.service" "$ROOT/packaging/systemd/tunnelmgr-openconnect@.service" /etc/systemd/system/
install -d -o root -g root -m 0700 /etc/tunnelmgr/openvpn
install -d -o root -g root -m 0700 /etc/tunnelmgr/openconnect
install -d -m 0700 /etc/tunnelmgr/mesh
install -d -m 0755 /opt/tunnelmgr/scripts
install -m 0755 "$ROOT/scripts/mesh-worker.py" "$ROOT/scripts/mesh-deploy.py" "$ROOT/scripts/install-preview.sh" /opt/tunnelmgr/scripts/
install -m 0644 "$ROOT/tunnelmgr/apply_profile.py" /opt/tunnelmgr/tunnelmgr/
install -m 0644 "$ROOT/packaging/systemd/tunnelmgr-mesh@.service" /etc/systemd/system/
install -m 0644 "$ROOT/tunnelmgr/profiles.py" /opt/tunnelmgr/tunnelmgr/
install -m 0644 "$ROOT/tunnelmgr/tls_manager.py" /opt/tunnelmgr/tunnelmgr/tls_manager.py
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/frr/daemons')
if p.exists():
    lines=p.read_text().splitlines()
    needed={'zebra','bgpd','ospfd'}
    found=set()
    out=[]
    for line in lines:
        key=line.split('=',1)[0] if '=' in line else ''
        if key in needed:
            out.append(key+'=yes');found.add(key)
        else:out.append(line)
    out.extend(x+'=yes' for x in sorted(needed-found))
    p.write_text('\n'.join(out)+'\n')
PY
systemctl daemon-reload
systemctl enable --now frr.service tunnelmgr-privd.service tunnelmgr.service

# Never take over an existing HAProxy configuration blindly. Validate the
# complete primary config before starting/reloading the service. An invalid
# pre-existing HAProxy config must not block the panel update or be rewritten.
if command -v haproxy >/dev/null 2>&1 && [ -r /etc/haproxy/haproxy.cfg ]; then
    if haproxy -c -f /etc/haproxy/haproxy.cfg; then
        systemctl enable haproxy.service
        if systemctl is-active --quiet haproxy.service; then
            systemctl reload haproxy.service
        else
            systemctl start haproxy.service
        fi
    else
        echo 'WARNING: Existing HAProxy configuration is invalid; leaving haproxy.service untouched. Fix its config and run: haproxy -c -f /etc/haproxy/haproxy.cfg' >&2
    fi
else
    echo 'WARNING: HAProxy config is missing; leaving haproxy.service untouched.' >&2
fi
systemctl restart frr.service tunnelmgr-privd.service tunnelmgr.service
systemctl --no-pager status tunnelmgr.service
