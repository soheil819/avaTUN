#!/usr/bin/env python3
"""Check and install verified avaTUN updates from the project GitHub branch."""
import argparse
import json
import os
import pathlib
import pwd
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

OWNER = 'soheil819'
REPOSITORY = 'avaTUN'
REF = 'codex/release-0.1.35'
API = f'https://api.github.com/repos/{OWNER}/{REPOSITORY}'
RAW = f'https://raw.githubusercontent.com/{OWNER}/{REPOSITORY}'
STATUS = pathlib.Path('/var/lib/tunnelmgr/github-update.json')
INSTALLED_APP = pathlib.Path('/opt/tunnelmgr/tunnelmgr/tunnelctl.py')
USER_AGENT = 'avaTUN-update-checker'
VERSION_RE = re.compile(r'^APP_VERSION\s*=\s*[\'\"](\d+\.\d+\.\d+)[\'\"]', re.M)


def version_tuple(value):
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', str(value))
    if not match:
        raise ValueError('Invalid avaTUN version string.')
    return tuple(int(part) for part in match.groups())


def request(url, accept='application/vnd.github+json', timeout=20):
    req = urllib.request.Request(url, headers={'Accept': accept, 'User-Agent': USER_AGENT})
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
        status = {
            'repository': f'{OWNER}/{REPOSITORY}', 'ref': REF,
            'current_version': current, 'latest_version': latest,
            'latest_commit': commit,
            'commit_url': f'https://github.com/{OWNER}/{REPOSITORY}/commit/{commit}',
            'update_available': version_tuple(latest) > version_tuple(current),
            'state': 'available' if version_tuple(latest) > version_tuple(current) else 'current',
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
    archive_url = f'https://codeload.github.com/{OWNER}/{REPOSITORY}/tar.gz/{status["latest_commit"]}'
    try:
        with tempfile.TemporaryDirectory(prefix='avatun-github-update-', dir=STATUS.parent) as tmp:
            work = pathlib.Path(tmp)
            archive = work / 'source.tar.gz'
            archive.write_bytes(request(archive_url, 'application/vnd.github+json', timeout=90))
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
