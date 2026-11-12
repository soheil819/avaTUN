#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    echo 'Run this bootstrap as your regular user; it will request sudo only for installation.' >&2
    exit 1
fi
for tool in gh git sudo; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Required command not found: $tool" >&2; exit 1; }
done
gh auth status >/dev/null 2>&1 || {
    echo 'Authenticate GitHub CLI first: gh auth login (the avaTUN repository is private).' >&2
    exit 1
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/avatun-install.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
gh repo clone soheil819/avaTUN "$WORK/source"

if [[ -n "${PANEL_HOST:-}" ]]; then
    sudo env PANEL_HOST="$PANEL_HOST" bash "$WORK/source/install.sh"
else
    sudo bash "$WORK/source/install.sh"
fi
