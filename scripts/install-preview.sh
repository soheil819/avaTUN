#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v python3 >/dev/null
python3 -c 'import sys; assert sys.version_info >= (3,11)'

install -d -o root -g root -m 0755 /usr/local/bin /etc/backhaul /var/lib/backhaul-manager
# Backhaul TUN is shipped as a manifest-verified amd64 core. Every installer
# run removes older installed Backhaul executables, then installs this trusted
# local build. Tunnel configs and manager state are retained.
if [ "$(uname -m)" = x86_64 ]; then
    active_backhaul_units=$(mktemp /run/avatun-backhaul-active.XXXXXX)
    trap 'rm -f "$active_backhaul_units"' EXIT HUP INT TERM
    for unit_file in /etc/systemd/system/backhaul-*.service /run/systemd/system/backhaul-*.service /usr/lib/systemd/system/backhaul-*.service /lib/systemd/system/backhaul-*.service; do
        [ -f "$unit_file" ] || continue
        unit=$(basename "$unit_file")
        exec_start=$(systemctl show "$unit" -p ExecStart --value 2>/dev/null || true)
        if systemctl is-active --quiet "$unit"; then
            case "$exec_start" in
                *"/usr/local/bin/backhaul"*) printf '%s\n' "$unit" >> "$active_backhaul_units" ;;
            esac
            systemctl stop "$unit" || true
        fi
        case "$exec_start" in
            *"/usr/local/bin/backhaul"*) ;;
            *) systemctl disable "$unit" >/dev/null 2>&1 || true ;;
        esac
    done
    pkill -x backhaul 2>/dev/null || true
    pkill -x backhaul_premium 2>/dev/null || true
    pkill -f '^/root/backhaul-core/backhaul_premium([[:space:]]|$)' 2>/dev/null || true
    python3 - <<'PY'
from pathlib import Path
for folder in ('/usr/local/bin','/usr/bin','/usr/local/sbin','/usr/sbin','/root/backhaul-core'):
    directory=Path(folder)
    if not directory.is_dir():continue
    for path in directory.glob('backhaul*'):
        try:
            if path.is_file() and not path.is_symlink() and path.open('rb').read(4)==b'\x7fELF':
                path.unlink()
        except OSError:
            raise
PY
    for old_core in /usr/local/bin/backhaul /usr/bin/backhaul /usr/local/sbin/backhaul /usr/sbin/backhaul /root/backhaul-core/backhaul_premium; do
        [ ! -f "$old_core" ] || rm -f -- "$old_core"
    done
    rm -f /usr/local/bin/backhaul-manager /usr/local/bin/backhaul-manager.py /usr/local/bin/backhaul.sh
    python3 "$ROOT/vendor/backhaul/scripts/backhaul-manager.py" install \
        --binary "$ROOT/vendor/backhaul/bin/backhaul" \
        --manifest "$ROOT/vendor/backhaul/SHA256SUMS" \
        --manifest-entry bin/backhaul
    if [ -s "$active_backhaul_units" ]; then
        while IFS= read -r unit; do
            [ -n "$unit" ] && systemctl restart "$unit"
        done < "$active_backhaul_units"
    fi
    echo 'Removed previous Backhaul cores and installed the bundled manifest-verified build.'
else
    echo "Backhaul TUN core is bundled for amd64; skipped on $(uname -m)."
fi

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
command -v curl >/dev/null 2>&1 || PACKAGES="$PACKAGES curl"
command -v ip >/dev/null 2>&1 || PACKAGES="$PACKAGES iproute2"
command -v haproxy >/dev/null 2>&1 || PACKAGES="$PACKAGES haproxy"
command -v wg >/dev/null 2>&1 || PACKAGES="$PACKAGES wireguard-tools"
command -v openvpn >/dev/null 2>&1 || PACKAGES="$PACKAGES openvpn"
command -v ocserv >/dev/null 2>&1 || PACKAGES="$PACKAGES ocserv"
command -v openconnect >/dev/null 2>&1 || PACKAGES="$PACKAGES openconnect"
command -v iperf3 >/dev/null 2>&1 || PACKAGES="$PACKAGES iperf3"
command -v swanctl >/dev/null 2>&1 || PACKAGES="$PACKAGES strongswan-swanctl"
CHARON_SYSTEMD_STATUS=$(dpkg-query -W -f='${Status}' charon-systemd 2>/dev/null || true)
case "$CHARON_SYSTEMD_STATUS" in 'install ok installed') ;; *) PACKAGES="$PACKAGES charon-systemd" ;; esac
# IKEv2 operations use swanctl's plugin loader as well as charon-systemd.
# Minimal images otherwise emit missing ctr/ccm/curl plugin warnings on every
# initiate; these bundles also make the same algorithms available to charon.
for package in libstrongswan-extra-plugins libcharon-extra-plugins; do
    PACKAGE_STATUS=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)
    case "$PACKAGE_STATUS" in 'install ok installed') ;; *) PACKAGES="$PACKAGES $package" ;; esac
done
command -v vtysh >/dev/null 2>&1 || PACKAGES="$PACKAGES frr"
command -v openssl >/dev/null 2>&1 || PACKAGES="$PACKAGES openssl"
command -v certbot >/dev/null 2>&1 || PACKAGES="$PACKAGES certbot"
command -v modprobe >/dev/null 2>&1 || PACKAGES="$PACKAGES kmod"
if [ -n "$PACKAGES" ]; then
    command -v apt-get >/dev/null 2>&1 || { echo 'HAProxy, WireGuard, OpenVPN, OpenConnect, FRR and Certbot require a Debian/Ubuntu package manager' >&2; exit 1; }
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y $PACKAGES
fi

# On hosts where /usr/lib/ipsec is linked into another StrongSwan installation,
# AppArmor sees the resolved path and may deny swanctl its libraries/plugins.
# Allow only the exact VICI/library/plugin files under that resolved directory.
if [ -f /etc/apparmor.d/usr.sbin.swanctl ] && command -v apparmor_parser >/dev/null 2>&1; then
    vici_path=$(readlink -f /usr/lib/ipsec/libvici.so.0 2>/dev/null || true)
    vici_dir=${vici_path%/*}
    if [ -n "$vici_path" ] && [ "$vici_dir" != /usr/lib/ipsec ]; then
        case "$vici_dir" in
            *[!A-Za-z0-9._/-]*) echo 'Unexpected StrongSwan library path; cannot update the swanctl AppArmor profile safely.' >&2; exit 1 ;;
            *)
                local_profile=/etc/apparmor.d/local/usr.sbin.swanctl
                install -d -o root -g root -m 0755 /etc/apparmor.d/local
                touch "$local_profile"
                for rule in "$vici_dir/libvici.so* mr," "$vici_dir/libstrongswan.so* mr," "$vici_dir/plugins/*.so mr,"; do
                    if ! grep -Fqx -- "$rule" "$local_profile"; then printf '%s\n' "$rule" >> "$local_profile"; fi
                done
                apparmor_parser -r /etc/apparmor.d/usr.sbin.swanctl
                ;;
        esac
    fi
fi

# swanctl requires VICI.  Prefer charon-systemd over the legacy starter, which
# may be installed and active without creating /var/run/charon.vici.
if systemctl list-unit-files --no-legend 2>/dev/null | awk '$1 == "strongswan.service" { found=1 } END { exit !found }'; then
    systemctl disable --now strongswan-starter.service >/dev/null 2>&1 || true
    systemctl enable --now strongswan.service
    if ! /usr/sbin/swanctl --version --daemon >/dev/null 2>&1; then
        systemctl restart strongswan.service
        swanctl_ready=0
        for attempt in $(seq 1 20); do
            if /usr/sbin/swanctl --version --daemon >/dev/null 2>&1; then swanctl_ready=1; break; fi
            sleep 0.5
        done
        [ "$swanctl_ready" -eq 1 ] || { echo 'StrongSwan VICI socket is unavailable; charon-systemd did not start correctly.' >&2; exit 1; }
    fi
else
    echo 'charon-systemd did not provide strongswan.service; swanctl/VICI IPsec cannot be enabled.' >&2
    exit 1
fi

# Preload and persist kernel modules used by the tunnel types exposed in the
# panel. Only record modules supported by the running kernel; kernels may build
# features in or ship them as loadable modules.
install -d -o root -g root -m 0755 /etc/modules-load.d
modules_file=/etc/modules-load.d/avatun-tunnels.conf
: > "$modules_file"
for module in tun wireguard ip_gre ipip geneve vxlan sit fou l2tp_core l2tp_eth l2tp_ip xfrm_user esp4 esp6 xfrm4_tunnel xfrm6_tunnel; do
    if modprobe --dry-run "$module" >/dev/null 2>&1; then
        printf '%s\n' "$module" >> "$modules_file"
        if ! modprobe "$module" >/dev/null 2>&1; then
            echo "Warning: kernel module $module could not be loaded now; it will be retried when its tunnel starts." >&2
        fi
    else
        echo "Warning: kernel module $module is unavailable for $(uname -r); related tunnel types may not start." >&2
    fi
done
chmod 0644 "$modules_file"
getent passwd tunnelmgr >/dev/null 2>&1 || useradd --system --home-dir /var/lib/tunnelmgr --create-home --shell /usr/sbin/nologin tunnelmgr
install -d -o root -g root -m 0755 /opt/tunnelmgr/tunnelmgr /opt/tunnelmgr/web /etc/systemd/system
install -d -o root -g root -m 0755 /opt/tunnelmgr/web/assets
install -d -o root -g root -m 0755 /opt/tunnelmgr/packaging/systemd
install -o root -g root -m 0644 "$ROOT/tunnelmgr/tunnelctl.py" /opt/tunnelmgr/tunnelmgr/tunnelctl.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/telegram_bot.py" /opt/tunnelmgr/tunnelmgr/telegram_bot.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/telegram_console.py" /opt/tunnelmgr/tunnelmgr/telegram_console.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/telegram_ui.py" /opt/tunnelmgr/tunnelmgr/telegram_ui.py
install -o root -g root -m 0644 "$ROOT/packaging/systemd/avatun-telegram.service" /etc/systemd/system/avatun-telegram.service
install -d -o root -g tunnelmgr -m 0750 /etc/avatun
install -o root -g root -m 0644 "$ROOT/tunnelmgr/openconnect_runner.py" /opt/tunnelmgr/tunnelmgr/openconnect_runner.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/routing.py" /opt/tunnelmgr/tunnelmgr/routing.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/topology.py" /opt/tunnelmgr/tunnelmgr/topology.py
install -o root -g root -m 0644 "$ROOT/tunnelmgr/privd.py" /opt/tunnelmgr/tunnelmgr/privd.py
install -o root -g root -m 0644 "$ROOT/packaging/systemd/tunnelmgr-privd.service" /etc/systemd/system/tunnelmgr-privd.service
install -o root -g root -m 0644 "$ROOT/packaging/systemd/tunnelmgr-github-update.service" "$ROOT/packaging/systemd/tunnelmgr-github-update-check.service" /etc/systemd/system/
install -o root -g root -m 0644 "$ROOT/packaging/systemd/tunnelmgr-github-update-check.timer" /etc/systemd/system/
install -o root -g root -m 0644 "$ROOT"/packaging/systemd/*.service /opt/tunnelmgr/packaging/systemd/
install -o root -g root -m 0644 "$ROOT"/packaging/systemd/*.timer /opt/tunnelmgr/packaging/systemd/
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
install -m 0755 "$ROOT/scripts/mesh-worker.py" "$ROOT/scripts/mesh-deploy.py" "$ROOT/scripts/github-update.py" "$ROOT/scripts/install-preview.sh" /opt/tunnelmgr/scripts/
install -d -o root -g root -m 0755 /opt/tunnelmgr/vendor/backhaul/bin /opt/tunnelmgr/vendor/backhaul/scripts
install -o root -g root -m 0755 "$ROOT/vendor/backhaul/bin/backhaul" /opt/tunnelmgr/vendor/backhaul/bin/backhaul
install -o root -g root -m 0755 "$ROOT/vendor/backhaul/scripts/backhaul-manager.py" /opt/tunnelmgr/vendor/backhaul/scripts/backhaul-manager.py
install -o root -g root -m 0644 "$ROOT/vendor/backhaul/SHA256SUMS" "$ROOT/vendor/backhaul/LICENSE" "$ROOT/vendor/backhaul/THIRD_PARTY.txt" /opt/tunnelmgr/vendor/backhaul/

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
if [ "${AVATUN_INSTALL_DEFER_START:-0}" = "1" ]; then
    systemctl enable frr.service tunnelmgr-privd.service tunnelmgr.service tunnelmgr-github-update-check.timer
    systemctl start tunnelmgr-github-update-check.timer
else
    systemctl enable --now frr.service tunnelmgr-privd.service tunnelmgr.service tunnelmgr-github-update-check.timer
fi

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
if [ "${AVATUN_INSTALL_DEFER_START:-0}" != "1" ]; then
    systemctl restart frr.service tunnelmgr-privd.service tunnelmgr.service
    if [ -f /etc/avatun/telegram.json ] && systemctl is-enabled --quiet avatun-telegram.service; then
        systemctl restart avatun-telegram.service
    fi
    systemctl --no-pager status tunnelmgr.service
fi
