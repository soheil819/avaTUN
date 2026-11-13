#!/usr/bin/env bash
set -euo pipefail

for tool in curl tar; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Required command not found: $tool" >&2; exit 1; }
done
if [[ "$(id -u)" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || { echo 'Required command not found: sudo (run as root or install sudo).' >&2; exit 1; }
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/avatun-install.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$WORK/source"
curl --fail --location --silent --show-error \
    https://github.com/soheil819/avaTUN/archive/refs/heads/main.tar.gz \
    | tar -xz --strip-components=1 -C "$WORK/source"

if [[ "$(id -u)" -eq 0 ]]; then
    if [[ -n "${PANEL_HOST:-}" ]]; then
        PANEL_HOST="$PANEL_HOST" bash "$WORK/source/install.sh"
    else
        bash "$WORK/source/install.sh"
    fi
elif [[ -n "${PANEL_HOST:-}" ]]; then
    sudo env PANEL_HOST="$PANEL_HOST" bash "$WORK/source/install.sh"
else
    sudo bash "$WORK/source/install.sh"
fi
