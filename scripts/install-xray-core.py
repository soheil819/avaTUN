#!/usr/bin/env python3
"""Install a pinned, avaTUN-owned Xray Core without touching host Xray installs."""
import hashlib
import os
import pathlib
import platform
import subprocess
import sys
import tempfile
import io
import urllib.request
import zipfile

VERSION = '26.11.9'
RELEASE = f'https://github.com/XTLS/Xray-core/releases/download/v{VERSION}'
ARCHES = {
    'x86_64': {
        'name': 'linux-amd64',
        'asset': 'Xray-linux-64.zip',
        'archive_sha256': 'b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82',
        'binary_sha256': 'e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d',
    },
    'aarch64': {
        'name': 'linux-arm64',
        'asset': 'Xray-linux-arm64-v8a.zip',
        'archive_sha256': '64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be',
        'binary_sha256': 'c2d1e66a130556d32089adcf38202fcb6f9027e41fb456cc2cda9a5fabdc093a',
    },
}
DEST = pathlib.Path('/opt/tunnelmgr/bin/xray')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def install():
    arch = ARCHES.get(platform.machine().lower())
    if not arch:
        raise RuntimeError(f'Automatic Xray Core installation is unsupported on {platform.machine()}.')
    DEST.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    bundle = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if bundle and bundle.is_dir():
        bundle = bundle / f"xray-core-{arch['name']}"
    if DEST.is_file() and sha256(DEST.read_bytes()) == arch['binary_sha256']:
        return f'Xray Core {VERSION} is already installed in the avaTUN-managed path.'

    if bundle and bundle.is_file():
        binary = bundle.read_bytes()
        if sha256(binary) != arch['binary_sha256']:
            raise RuntimeError('The bundled Xray Core failed SHA-256 verification.')
    else:
        request = urllib.request.Request(
            f"{RELEASE}/{arch['asset']}",
            headers={'User-Agent': 'avaTUN-Xray-Core-Installer'},
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                archive = response.read(64 * 1024 * 1024 + 1)
        except Exception as error:
            raise RuntimeError(f'Could not download the pinned Xray Core {VERSION} release: {error}') from error
        if len(archive) > 64 * 1024 * 1024 or sha256(archive) != arch['archive_sha256']:
            raise RuntimeError('The downloaded Xray Core archive failed SHA-256 verification.')
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as package:
                info = next((item for item in package.infolist() if pathlib.PurePosixPath(item.filename).name == 'xray' and not item.is_dir()), None)
                if info is None or info.file_size > 100 * 1024 * 1024:
                    raise RuntimeError('The pinned Xray Core archive does not contain a valid binary.')
                binary = package.read(info)
        except (zipfile.BadZipFile, KeyError) as error:
            raise RuntimeError('The pinned Xray Core archive is invalid.') from error
        if sha256(binary) != arch['binary_sha256']:
            raise RuntimeError('The extracted Xray Core binary failed SHA-256 verification.')

    fd, temporary = tempfile.mkstemp(prefix='.xray-', dir=DEST.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(binary)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o755)
        result = subprocess.run([temporary, 'version'], capture_output=True, text=True, timeout=15)
        if result.returncode or VERSION not in (result.stdout + result.stderr):
            raise RuntimeError('The installed Xray Core binary did not report the pinned version.')
        os.replace(temporary, DEST)
    finally:
        pathlib.Path(temporary).unlink(missing_ok=True)
    if os.geteuid() == 0:
        os.chown(DEST, 0, 0)
    return f'Installed isolated Xray Core {VERSION} at {DEST}; existing Xray/x-ui files and services were not changed.'


if __name__ == '__main__':
    try:
        print(install())
    except Exception as error:
        print(f'Xray Core installation failed: {error}', file=sys.stderr)
        raise SystemExit(1)
