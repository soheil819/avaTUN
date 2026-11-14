#!/bin/bash
# Independent offline Backhaul helper by ir_spoof - https://t.me/ir_spoof
# No upstream script evaluation, automatic downloads, IP lookup or licensing.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/backhaul-manager.py" "$@"
