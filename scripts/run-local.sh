#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$ROOT/tunnelmgr/tunnelctl.py" api --host 127.0.0.1 --port "${TUNNELMGR_PORT:-8765}"
