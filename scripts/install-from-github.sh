#!/usr/bin/env bash
set -euo pipefail

REPOSITORY=soheil819/avaTUN
SIGNER_WORKFLOW=soheil819/avaTUN/.github/workflows/release-assets.yml
MIN_GH_VERSION=2.102.0

command -v gh >/dev/null 2>&1 || {
    echo 'Install GitHub CLI from https://github.com/cli/cli/blob/trunk/docs/install_linux.md, then run this installer again.' >&2
    exit 1
}
GH_VERSION=$(gh --version | sed -n '1s/^gh version \([0-9.]*\).*/\1/p')
python3 - "$GH_VERSION" "$MIN_GH_VERSION" <<'PY'
import sys
actual=tuple(map(int,sys.argv[1].split('.')))
required=tuple(map(int,sys.argv[2].split('.')))
if actual < required:raise SystemExit('GitHub CLI 2.102.0 or newer is required to verify release attestations.')
PY

TAG=$(gh release list --repo "$REPOSITORY" --json tagName,isDraft,isPrerelease \
    --jq '[.[] | select(.isDraft == false and .isPrerelease == false)][0].tagName')
[[ "$TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'No published stable avaTUN release was found.' >&2; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/avatun-install.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
ARCHIVE="$WORK/avaTUN-${TAG}.tar.gz"
gh release download "$TAG" --repo "$REPOSITORY" --pattern "avaTUN-${TAG}.tar.gz" --dir "$WORK"
gh attestation verify "$ARCHIVE" --repo "$REPOSITORY" \
    --signer-workflow "$SIGNER_WORKFLOW" --source-ref "refs/tags/$TAG"

mkdir -p "$WORK/source"
tar -xzf "$ARCHIVE" --strip-components=1 -C "$WORK/source"
[[ -f "$WORK/source/install.sh" ]] || { echo 'Verified release archive is missing install.sh.' >&2; exit 1; }
if [[ "$(id -u)" -eq 0 ]]; then
    bash "$WORK/source/install.sh"
else
    command -v sudo >/dev/null 2>&1 || { echo 'Required command not found: sudo (run as root or install sudo).' >&2; exit 1; }
    sudo bash "$WORK/source/install.sh"
fi
