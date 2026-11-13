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
command -v curl >/dev/null 2>&1 || PACKAGES="$PACKAGES curl"
command -v ip >/dev/null 2>&1 || PACKAGES="$PACKAGES iproute2"
command -v haproxy >/dev/null 2>&1 || PACKAGES="$PACKAGES haproxy"
command -v wg >/dev/null 2>&1 || PACKAGES="$PACKAGES wireguard-tools"
command -v openvpn >/dev/null 2>&1 || PACKAGES="$PACKAGES openvpn"
command -v ocserv >/dev/null 2>&1 || PACKAGES="$PACKAGES ocserv"
command -v openconnect >/dev/null 2>&1 || PACKAGES="$PACKAGES openconnect"
command -v swanctl >/dev/null 2>&1 || PACKAGES="$PACKAGES strongswan-swanctl"
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
install -o root -g root -m 0644 "$ROOT/tunnelmgr/telegram_bot.py" /opt/tunnelmgr/tunnelmgr/telegram_bot.py
install -o root -g root -m 0644 "$ROOT/packaging/systemd/avatun-telegram.service" /etc/systemd/system/avatun-telegram.service
install -d -o root -g tunnelmgr -m 0750 /etc/avatun
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
install -d -o root -g root -m 0755 /opt/tunnelmgr/vendor/backhaul/bin /opt/tunnelmgr/vendor/backhaul/scripts
install -o root -g root -m 0755 "$ROOT/vendor/backhaul/bin/backhaul" /opt/tunnelmgr/vendor/backhaul/bin/backhaul
install -o root -g root -m 0755 "$ROOT/vendor/backhaul/scripts/backhaul-manager.py" /opt/tunnelmgr/vendor/backhaul/scripts/backhaul-manager.py
install -o root -g root -m 0644 "$ROOT/vendor/backhaul/SHA256SUMS" "$ROOT/vendor/backhaul/LICENSE" "$ROOT/vendor/backhaul/THIRD_PARTY.txt" /opt/tunnelmgr/vendor/backhaul/

# Backhaul TUN is shipped as a verified amd64 core and manager. Preserve an
# existing core and tunnel files; repair a missing manager without replacing
# the core or touching any existing Backhaul tunnel.
if [ "$(uname -m)" = x86_64 ]; then
    if [ ! -e /usr/local/bin/backhaul-manager ] && [ ! -e /usr/local/bin/backhaul ]; then
        python3 /opt/tunnelmgr/vendor/backhaul/scripts/backhaul-manager.py install \
            --binary /opt/tunnelmgr/vendor/backhaul/bin/backhaul \
            --manifest /opt/tunnelmgr/vendor/backhaul/SHA256SUMS \
            --manifest-entry bin/backhaul
    elif [ -x /usr/local/bin/backhaul ] && [ ! -e /usr/local/bin/backhaul-manager ]; then
        # Older/partial installs can have the core but lack the command used by
        # tunnelmgr-privd. Install only missing manager files and leave the
        # existing core, state, configs, and units untouched.
        manager_tmp=$(mktemp /usr/local/bin/.backhaul-manager.XXXXXX)
        trap 'rm -f "$manager_tmp"' EXIT HUP INT TERM
        cat > "$manager_tmp" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/tunnelmgr/vendor/backhaul/scripts/backhaul-manager.py "$@"
EOF
        install -o root -g root -m 0755 "$manager_tmp" /usr/local/bin/backhaul-manager
        rm -f "$manager_tmp"
        trap - EXIT HUP INT TERM
        echo 'Repaired missing Backhaul manager; existing core and tunnel files were preserved.'
    elif [ ! -x /usr/local/bin/backhaul-manager ] || [ ! -x /usr/local/bin/backhaul ]; then
        echo 'WARNING: Existing Backhaul manager/core installation is partial; preserved existing files.' >&2
    elif [ ! -e /var/lib/backhaul-manager/state.json ]; then
        # Migrate only an exact bundled core with no pre-existing tunnel
        # configs or units. Record the old manager files so its guarded
        # installer can replace them without taking ownership of user tunnels.
        python3 - <<'PY' || echo 'WARNING: Existing Backhaul install is not an empty, verifiable setup; preserving it.' >&2
import hashlib, json, os, pathlib, re, subprocess, sys
base=pathlib.Path('/opt/tunnelmgr/vendor/backhaul')
binary=pathlib.Path('/usr/local/bin/backhaul')
state=pathlib.Path('/var/lib/backhaul-manager/state.json')
manifest=(base/'SHA256SUMS').read_text().splitlines()
matches=[line.split()[0].lower() for line in manifest if re.fullmatch(r'[0-9a-fA-F]{64}  bin/backhaul',line)]
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
if len(matches)!=1 or digest(binary)!=matches[0]:sys.exit(1)
configs=list(pathlib.Path('/etc/backhaul').glob('*.toml'))
units=list(pathlib.Path('/etc/systemd/system').glob('backhaul-*.service'))
if configs or units:sys.exit(1)
paths=('/usr/local/bin/backhaul-manager.py','/usr/local/bin/backhaul-manager','/usr/local/bin/backhaul.sh')
files={p:digest(pathlib.Path(p)) for p in paths if pathlib.Path(p).is_file() and not pathlib.Path(p).is_symlink()}
state.parent.mkdir(parents=True,exist_ok=True)
fd=os.open(state,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:
    json.dump({'schema':1,'core_sha256':matches[0],'tunnels':{},'manager_files':files},f,separators=(',',':'))
    f.write('\n');f.flush();os.fsync(f.fileno())
PY
        if [ -e /var/lib/backhaul-manager/state.json ]; then
            python3 /opt/tunnelmgr/vendor/backhaul/scripts/backhaul-manager.py install \
                --binary /opt/tunnelmgr/vendor/backhaul/bin/backhaul \
                --manifest /opt/tunnelmgr/vendor/backhaul/SHA256SUMS \
                --manifest-entry bin/backhaul
        fi
    fi

    # A prior installer or manual replacement may have left the installed
    # core different from the hash recorded by its own manager. Reconcile it
    # only when manager state exists, using the exact current digest as the
    # replacement guard and the bundled manifest as the trusted new build.
    if [ -x /usr/local/bin/backhaul ] && [ -x /usr/local/bin/backhaul-manager ] && [ -f /var/lib/backhaul-manager/state.json ]; then
        current_core_sha=$(python3 - <<'PY'
import hashlib, pathlib
p=pathlib.Path('/usr/local/bin/backhaul')
h=hashlib.sha256()
with p.open('rb') as f:
    for block in iter(lambda:f.read(1024*1024), b''):
        h.update(block)
print(h.hexdigest())
PY
)
        recorded_core_sha=$(python3 - <<'PY'
import json, pathlib
try:
    print(json.loads(pathlib.Path('/var/lib/backhaul-manager/state.json').read_text()).get('core_sha256', ''))
except Exception:
    raise SystemExit(1)
PY
)
        if [ -n "$recorded_core_sha" ] && [ "$current_core_sha" != "$recorded_core_sha" ]; then
            python3 /opt/tunnelmgr/vendor/backhaul/scripts/backhaul-manager.py install \
                --binary /opt/tunnelmgr/vendor/backhaul/bin/backhaul \
                --manifest /opt/tunnelmgr/vendor/backhaul/SHA256SUMS \
                --manifest-entry bin/backhaul \
                --replace-existing --previous-sha256 "$current_core_sha"
            echo 'Reconciled Backhaul core to the bundled verified build; managed tunnels were preserved.'
        fi
    fi
else
    echo "Backhaul TUN core is bundled for amd64; skipped on $(uname -m)."
fi
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
    systemctl enable frr.service tunnelmgr-privd.service tunnelmgr.service
else
    systemctl enable --now frr.service tunnelmgr-privd.service tunnelmgr.service
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
