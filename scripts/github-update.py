#!/usr/bin/env python3
"""Check and install verified avaTUN updates from the project GitHub branch."""
import argparse
import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

OWNER = 'soheil819'
REPOSITORY = 'avaTUN'
REF = 'main'
API = f'https://api.github.com/repos/{OWNER}/{REPOSITORY}'
RAW = f'https://raw.githubusercontent.com/{OWNER}/{REPOSITORY}'
STATUS = pathlib.Path('/var/lib/tunnelmgr/github-update.json')
INSTALLED_APP = pathlib.Path('/opt/tunnelmgr/tunnelmgr/tunnelctl.py')
USER_AGENT = 'avaTUN-update-checker'
VERSION_RE = re.compile(r'^APP_VERSION\s*=\s*[\'\"](\d+(?:\.\d+){2,3})[\'\"]', re.M)
SIGNER_WORKFLOW = f'{OWNER}/{REPOSITORY}/.github/workflows/release-assets.yml'
MIN_GH_VERSION = (2, 102, 0)


def version_tuple(value):
    match = re.fullmatch(r'(\d+(?:\.\d+){2,3})', str(value))
    if not match:
        raise ValueError('Invalid avaTUN version string.')
    return tuple(int(part) for part in match.group(1).split('.'))


def request(url, accept='application/vnd.github+json', timeout=20):
    headers={'Accept': accept, 'User-Agent': USER_AGENT}
    if urllib.parse.urlsplit(url).hostname=='api.github.com':
        headers['X-GitHub-Api-Version']='2026-03-10'
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def installed_version():
    source = INSTALLED_APP.read_text()
    match = VERSION_RE.search(source)
    if not match:
        raise ValueError('Installed avaTUN version could not be read.')
    return match.group(1)


def remote_release():
    ref = urllib.parse.quote(REF, safe='')
    commit_data = json.loads(request(f'{API}/commits/{ref}'))
    commit = commit_data.get('sha', '')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('GitHub returned an invalid commit ID.')
    source = request(f'{RAW}/{commit}/tunnelmgr/tunnelctl.py', 'text/plain').decode()
    match = VERSION_RE.search(source)
    if not match:
        raise ValueError('GitHub branch does not contain a readable avaTUN version.')
    return commit, match.group(1)


def release_archive(version, expected_commit):
    tag_url = f'{API}/git/ref/tags/{urllib.parse.quote(version, safe="")}'
    target = json.loads(request(tag_url)).get('object', {})
    for _ in range(4):
        if target.get('type') == 'commit':
            break
        if target.get('type') != 'tag' or not re.fullmatch(r'[0-9a-f]{40}', target.get('sha', '')):
            raise ValueError('GitHub release tag does not point to a commit.')
        target = json.loads(request(f'{API}/git/tags/{target["sha"]}')).get('object', {})
    if target.get('type') != 'commit' or target.get('sha') != expected_commit:
        raise ValueError('GitHub release tag does not match the checked main commit.')
    release = json.loads(request(f'{API}/releases/tags/{urllib.parse.quote(version, safe="")}'))
    if release.get('draft') or release.get('tag_name') != version:
        raise ValueError('A published GitHub release is not available for this version.')
    assets = {asset.get('name'): asset.get('browser_download_url') for asset in release.get('assets', [])}
    archive_url = assets.get(f'avaTUN-{version}.tar.gz')
    if not archive_url or not archive_url.startswith('https://github.com/'):
        raise ValueError('The signed GitHub release archive is not available yet.')
    return archive_url


def verify_release_archive(archive, version):
    gh = shutil.which('gh')
    if not gh:
        raise RuntimeError('GitHub CLI is required to verify the release attestation.')
    version_text = subprocess.run([gh, '--version'], capture_output=True, text=True, timeout=15)
    match = re.search(r'gh version (\d+)\.(\d+)\.(\d+)', version_text.stdout)
    if not match or tuple(map(int, match.groups())) < MIN_GH_VERSION:
        raise RuntimeError('GitHub CLI 2.102.0 or newer is required to verify release attestations.')
    digest=hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    metadata=json.loads(request(f'{API}/attestations/sha256:{digest.hexdigest()}'))
    entries=metadata.get('attestations',[])
    if not isinstance(entries,list) or not entries:
        raise RuntimeError('GitHub returned no attestations for the release archive.')
    bundles=[]
    for entry in entries:
        bundle=entry.get('bundle')
        if bundle is None and entry.get('bundle_url'):
            parsed=urllib.parse.urlsplit(entry['bundle_url'])
            if parsed.scheme!='https' or not parsed.hostname or not parsed.hostname.endswith('.blob.core.windows.net') or parsed.username or parsed.password:
                raise RuntimeError('GitHub returned an invalid attestation bundle URL.')
            try:
                import snappy
                bundle=json.loads(snappy.uncompress(request(entry['bundle_url'],'application/octet-stream',60)))
            except Exception as error:
                raise RuntimeError('Could not download or decompress the GitHub attestation bundle.') from error
        if isinstance(bundle,dict):bundles.append(json.dumps(bundle,separators=(',',':')))
    if not bundles:
        raise RuntimeError('GitHub returned no usable release attestation bundles.')
    bundle_path=archive.with_name(archive.name+'.attestations.jsonl')
    bundle_path.write_text('\n'.join(bundles)+'\n')
    result = subprocess.run([gh, 'attestation', 'verify', str(archive), '--repo',
                             f'{OWNER}/{REPOSITORY}', '--signer-workflow', SIGNER_WORKFLOW,
                             '--source-ref', f'refs/tags/{version}', '--bundle',str(bundle_path)],
                            capture_output=True, text=True, timeout=180)
    bundle_path.unlink(missing_ok=True)
    if result.returncode:
        detail=(result.stderr or result.stdout or 'GitHub artifact attestation verification failed.')[-900:]
        raise RuntimeError('Release attestation verification failed: '+detail)


def read_status():
    try:
        return json.loads(STATUS.read_text())
    except (OSError, ValueError):
        return {}


def write_status(data):
    STATUS.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = STATUS.with_name(STATUS.name + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, ensure_ascii=False, separators=(',', ':'))
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.chown(temp, os.geteuid(), pwd.getpwnam('tunnelmgr').pw_gid)
    except PermissionError:
        pass
    os.chmod(temp, 0o640)
    os.replace(temp, STATUS)


def check(save=True):
    previous = read_status()
    current = installed_version()
    try:
        commit, latest = remote_release()
        newer = version_tuple(latest) > version_tuple(current)
        archive_url = release_archive(latest, commit) if newer else None
        status = {
            'repository': f'{OWNER}/{REPOSITORY}', 'ref': REF,
            'current_version': current, 'latest_version': latest,
            'latest_commit': commit,
            'archive_url': archive_url,
            'commit_url': f'https://github.com/{OWNER}/{REPOSITORY}/commit/{commit}',
            'update_available': newer,
            'state': 'available' if newer else 'current',
            'checked_at': time.time(), 'error': None,
        }
    except Exception as error:
        status = {
            **previous, 'current_version': current, 'checked_at': time.time(),
            'state': 'error', 'error': f'{type(error).__name__}: {str(error)[:300]}',
        }
    if save:
        write_status(status)
    return status


def safe_extract(archive, destination):
    root = pathlib.Path(destination).resolve()
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        for member in members:
            name = pathlib.PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or member.issym() or member.islnk():
                raise ValueError('GitHub archive contains an unsafe path.')
        for member in members:
            target = (root / member.name).resolve()
            if target != root and root not in target.parents:
                raise ValueError('GitHub archive path leaves the update directory.')
        bundle.extractall(root)


def install():
    status = check(save=False)
    if status.get('state') == 'error':
        write_status(status)
        raise RuntimeError(status['error'])
    if not status.get('update_available'):
        status['state'] = 'current'
        write_status(status)
        print('No newer avaTUN version is available.')
        return

    status['state'] = 'installing'
    status['started_at'] = int(time.time())
    write_status(status)
    try:
        with tempfile.TemporaryDirectory(prefix='avatun-github-update-', dir=STATUS.parent) as tmp:
            work = pathlib.Path(tmp)
            archive = work / 'source.tar.gz'
            archive.write_bytes(request(status['archive_url'], 'application/octet-stream', timeout=180))
            verify_release_archive(archive, status['latest_version'])
            extract = work / 'source'
            extract.mkdir(mode=0o700)
            safe_extract(archive, extract)
            roots = [path for path in extract.iterdir() if path.is_dir()]
            source = next((path for path in roots if (path / 'scripts/update-release.sh').is_file()), None)
            if source is None:
                raise ValueError('GitHub archive is missing its update installer.')
            source_version = VERSION_RE.search((source / 'tunnelmgr/tunnelctl.py').read_text())
            if not source_version or source_version.group(1) != status['latest_version']:
                raise ValueError('Downloaded source version does not match the checked GitHub version.')
            update = subprocess.run(['/bin/sh', str(source / 'scripts/update-release.sh')],
                                    timeout=1100, capture_output=True, text=True)
            if update.returncode:
                detail=(update.stderr or update.stdout or 'Release installer returned an error.')[-900:]
                raise RuntimeError(detail)
        current = installed_version()
        status.update({'current_version': current, 'latest_version': current,
                       'update_available': False, 'state': 'updated',
                       'updated_at': int(time.time()), 'error': None})
        write_status(status)
        print(f'Updated avaTUN to {current}.')
    except Exception as error:
        status.update({'state': 'error', 'error': f'{type(error).__name__}: {str(error)[:300]}',
                       'failed_at': int(time.time())})
        write_status(status)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('check', 'install'))
    args = parser.parse_args()
    if args.action == 'check':
        print(json.dumps(check(), ensure_ascii=False))
    else:
        install()


if __name__ == '__main__':
    main()
