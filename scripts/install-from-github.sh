#!/usr/bin/env bash
set -euo pipefail

REPOSITORY=soheil819/avaTUN
SIGNER_WORKFLOW=soheil819/avaTUN/.github/workflows/release-assets.yml
MIN_GH_VERSION=2.102.0

command -v gh >/dev/null 2>&1 || {
    echo 'Install GitHub CLI from https://github.com/cli/cli/blob/trunk/docs/install_linux.md, then run this installer again.' >&2
    exit 1
}
python3 -c 'import snappy' 2>/dev/null || {
    echo 'Install python3-snappy before verifying GitHub release attestations.' >&2
    exit 1
}
GH_VERSION=$(gh --version | sed -n '1s/^gh version \([0-9.]*\).*/\1/p')
python3 - "$GH_VERSION" "$MIN_GH_VERSION" <<'PY'
import sys
actual=tuple(map(int,sys.argv[1].split('.')))
required=tuple(map(int,sys.argv[2].split('.')))
if actual < required:raise SystemExit('GitHub CLI 2.102.0 or newer is required to verify release attestations.')
PY

WORK=$(mktemp -d "${TMPDIR:-/tmp}/avatun-install.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
ARCHIVE="$WORK/avaTUN-release.tar.gz"
BUNDLE="$WORK/attestations.jsonl"
TAG_FILE="$WORK/tag"
python3 - "$REPOSITORY" "$ARCHIVE" "$BUNDLE" "$TAG_FILE" <<'PY'
import hashlib,json,sys,urllib.parse,urllib.request
repo,archive,bundle_file,tag_file=sys.argv[1:]
api='https://api.github.com/repos/'+repo
headers={'Accept':'application/vnd.github+json','User-Agent':'avaTUN-installer','X-GitHub-Api-Version':'2026-03-10'}
def get(url,api_request=False):
    request=urllib.request.Request(url,headers=headers if api_request else {'User-Agent':'avaTUN-installer'})
    with urllib.request.urlopen(request,timeout=180) as response:return response.read()
release=json.loads(get(api+'/releases/latest',True))
tag=release.get('tag_name','')
import re
if release.get('draft') or release.get('prerelease') or not re.fullmatch(r'\d+\.\d+\.\d+',tag):
    raise SystemExit('No published stable avaTUN release was found.')
name='avaTUN-'+tag+'.tar.gz'
assets={x.get('name'):x.get('browser_download_url') for x in release.get('assets',[])}
url=assets.get(name,'')
if urllib.parse.urlsplit(url).scheme!='https' or urllib.parse.urlsplit(url).hostname!='github.com':
    raise SystemExit('Stable release archive is missing or has an unexpected download URL.')
data=get(url)
open(archive,'wb').write(data)
digest=hashlib.sha256(data).hexdigest()
metadata=json.loads(get(api+'/attestations/sha256:'+digest,True))
entries=metadata.get('attestations',[])
if not entries:raise SystemExit('GitHub returned no attestations for the release archive.')
bundles=[]
for entry in entries:
    item=entry.get('bundle')
    if item is None and entry.get('bundle_url'):
        bundle_url=entry['bundle_url'];parsed=urllib.parse.urlsplit(bundle_url)
        if parsed.scheme!='https' or not parsed.hostname or not parsed.hostname.endswith('.blob.core.windows.net') or parsed.username or parsed.password:
            raise SystemExit('GitHub returned an invalid attestation bundle URL.')
        try:
            import snappy
            item=json.loads(snappy.uncompress(get(bundle_url)))
        except Exception as error:raise SystemExit('Could not download or decompress GitHub attestation: '+str(error))
    if isinstance(item,dict):bundles.append(json.dumps(item,separators=(',',':')))
if not bundles:raise SystemExit('GitHub returned no usable release attestation bundles.')
open(bundle_file,'w').write('\n'.join(bundles)+'\n')
open(tag_file,'w').write(tag)
PY
TAG=$(cat "$TAG_FILE")
gh attestation verify "$ARCHIVE" --repo "$REPOSITORY" \
    --signer-workflow "$SIGNER_WORKFLOW" --source-ref "refs/tags/$TAG" --bundle "$BUNDLE"

mkdir -p "$WORK/source"
tar -xzf "$ARCHIVE" --strip-components=1 -C "$WORK/source"
[[ -f "$WORK/source/install.sh" ]] || { echo 'Verified release archive is missing install.sh.' >&2; exit 1; }
if [[ "$(id -u)" -eq 0 ]]; then
    bash "$WORK/source/install.sh"
else
    command -v sudo >/dev/null 2>&1 || { echo 'Required command not found: sudo (run as root or install sudo).' >&2; exit 1; }
    sudo bash "$WORK/source/install.sh"
fi
