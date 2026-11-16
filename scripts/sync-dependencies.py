#!/usr/bin/env python3
"""Match slave Debian package versions to the central avaTUN server."""
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile


PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*")
PACKAGE_VERSION = re.compile(r"[A-Za-z0-9.+:~_-]+")


def run(args, *, check=True, capture=False):
    result = subprocess.run(args, text=True, capture_output=capture)
    if check and result.returncode:
        message = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(message or f"Command failed: {args[0]}")
    return result


def installed_version(package):
    result = run(
        ["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}", package],
        check=False,
        capture=True,
    )
    if result.returncode:
        return None
    fields = result.stdout.strip().split("\t", 1)
    if len(fields) != 2 or not fields[0].startswith("ii"):
        return None
    return fields[1]


def available_versions(package):
    result = run(["/usr/bin/apt-cache", "madison", package], check=False, capture=True)
    versions = set()
    for line in result.stdout.splitlines():
        columns = line.split("|")
        if len(columns) >= 2:
            versions.add(columns[1].strip())
    return versions


def apt_candidate(package):
    result = run(["/usr/bin/apt-cache", "policy", package], check=False, capture=True)
    for line in result.stdout.splitlines():
        if line.strip().startswith("Candidate:"):
            candidate = line.split(":", 1)[1].strip()
            return None if candidate == "(none)" else candidate
    return None


def snapshot_haproxy():
    config = pathlib.Path("/etc/haproxy")
    if not config.exists() and not config.is_symlink():
        return None
    fd, backup = tempfile.mkstemp(prefix="avatun-haproxy-", suffix=".tar", dir="/var/tmp")
    os.close(fd)
    run(["/usr/bin/tar", "--acls", "--xattrs", "--numeric-owner", "-cpf", backup, "-C", "/", "etc/haproxy"])
    return backup


def restore_haproxy(backup):
    if not backup:
        return
    config = pathlib.Path("/etc/haproxy")
    if config.is_symlink() or config.is_file():
        config.unlink()
    elif config.exists():
        shutil.rmtree(config)
    run(["/usr/bin/tar", "--same-owner", "--same-permissions", "--acls", "--xattrs", "-xpf", backup, "-C", "/"])


def main(lock_path):
    if os.geteuid() != 0:
        raise RuntimeError("Dependency synchronization must run as root")
    manifest = json.loads(pathlib.Path(lock_path).read_text())
    if not isinstance(manifest, dict) or not isinstance(manifest.get("packages"), dict) or not manifest["packages"]:
        raise RuntimeError("The central server package lock is empty or invalid")
    lock = manifest["packages"]
    central_os = manifest.get("central_os") or {}
    slave_os = platform.freedesktop_os_release()
    central_codename = central_os.get("VERSION_CODENAME") or central_os.get("UBUNTU_CODENAME")
    slave_codename = slave_os.get("VERSION_CODENAME") or slave_os.get("UBUNTU_CODENAME")
    same_release = bool(
        central_os.get("ID")
        and central_os.get("ID") == slave_os.get("ID")
        and ((central_codename and central_codename == slave_codename)
             or (not central_codename and central_os.get("VERSION_ID") == slave_os.get("VERSION_ID")))
    )
    for package, version in lock.items():
        if not isinstance(package, str) or not PACKAGE_NAME.fullmatch(package):
            raise RuntimeError("The central server package lock contains an invalid package name")
        if not isinstance(version, str) or not PACKAGE_VERSION.fullmatch(version):
            raise RuntimeError(f"The central server package lock contains an invalid version for {package}")

    changes = []
    exact_count = 0
    compatible_count = 0
    for package, target in sorted(lock.items()):
        current = installed_version(package)
        central_version_available = target in available_versions(package)
        if same_release and (central_version_available or current == target):
            desired = target
            source = "central pin"
            exact_count += 1
        else:
            desired = apt_candidate(package)
            source = "slave repository candidate"
            compatible_count += 1
        if not desired:
            raise RuntimeError(f"No compatible apt version is available for {package} on this slave")
        if current != desired:
            if desired not in available_versions(package):
                raise RuntimeError(f"Selected apt version is unavailable for {package}={desired}")
            changes.append((package, current, desired, source))
    if not changes:
        print(f"All {len(lock)} managed Debian package versions match their targets ({exact_count} central pins, {compatible_count} slave-repository versions).")
        return

    haproxy_backup = snapshot_haproxy() if any(name == "haproxy" for name, _, _, _ in changes) else None
    specifications = [f"{name}={target}" for name, _, target, _ in changes]
    try:
        run([
            "/usr/bin/apt-get", "install", "--yes", "--allow-downgrades", "--no-install-recommends",
            "-o", "Dpkg::Options::=--force-confold", *specifications,
        ])
    except Exception:
        if haproxy_backup:
            try:
                restore_haproxy(haproxy_backup)
                pathlib.Path(haproxy_backup).unlink(missing_ok=True)
            except Exception as restore_error:
                raise RuntimeError(f"Package synchronization failed and HAProxy configuration restore failed; backup retained at {haproxy_backup}: {restore_error}")
        raise
    else:
        if haproxy_backup:
            try:
                restore_haproxy(haproxy_backup)
            except Exception as restore_error:
                raise RuntimeError(f"Could not restore the original HAProxy configuration; backup retained at {haproxy_backup}: {restore_error}")
            pathlib.Path(haproxy_backup).unlink(missing_ok=True)

    mismatches = [f"{name}={installed_version(name) or 'missing'} (wanted {target})" for name, _, target, _ in changes if installed_version(name) != target]
    if mismatches:
        raise RuntimeError("Package versions still differ after synchronization: " + ", ".join(mismatches))
    for name, current, target, source in changes:
        print(f"Updated {name}: {current or 'missing'} -> {target} ({source})")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise RuntimeError("Usage: sync-dependencies.py PACKAGE_LOCK.json")
        main(sys.argv[1])
    except Exception as error:
        print(f"Dependency synchronization failed: {error}", file=sys.stderr)
        raise SystemExit(1)
