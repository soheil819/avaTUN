#!/bin/sh
# Verified offline Backhaul installation by ir_spoof - https://t.me/ir_spoof
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.11 or newer is required; install it with your Linux distribution package manager.' >&2
    exit 1
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' || {
    printf '%s\n' 'Python 3.11 or newer is required.' >&2
    exit 1
}
if [ "$#" -eq 0 ]; then
    package_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
    exec python3 "$script_dir/backhaul-manager.py" install --binary "$package_dir/bin/backhaul" --manifest "$package_dir/SHA256SUMS" --manifest-entry bin/backhaul
fi
exec python3 "$script_dir/backhaul-manager.py" install "$@"
