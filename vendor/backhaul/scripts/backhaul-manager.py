#!/usr/bin/env python3
"""Offline independent Backhaul service manager by ir_spoof.

Attribution: https://t.me/ir_spoof
Adapted from the independently authored MIT Netrix manager by ir_spoof;
no obfuscated upstream install script is embedded or evaluated.
Python 3.11+ standard library only. No telemetry or automatic downloads.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request
from pathlib import Path, PurePosixPath

CHANNEL = "t.me/ir_spoof"
TRANSPORTS = ("tcp", "tcpmux", "xtcpmux", "ws", "wss", "wsmux", "wssmux", "xwsmux", "anytls", "tun")
IPX_PROFILES = ("icmp", "ipip", "udp", "tcp", "gre", "bip")
TLS_TRANSPORTS = ("wss", "wssmux", "anytls")
SECTIONS = ("listener", "dialer", "transport", "tun", "ipx", "mux", "security", "tls", "tuning", "accept_udp", "logging", "ports")
ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
SHA_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
KEY_RE = re.compile(r"[a-z][a-z0-9_]*\Z")
MAX_CONFIG_BYTES = 1024 * 1024


class ManagerError(RuntimeError):
    pass


class LocalHealthOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ManagerError("Local health redirects are not permitted.")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def tunnel_id(value: str) -> str:
    if not ID_RE.fullmatch(value):
        raise ManagerError("ID must be 1-48 lowercase letters/digits/underscores/hyphens and start with a letter or digit.")
    return value


def safe_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ManagerError("Expected an ordinary local file, not a link or directory.")


def safe_text(value: str) -> str:
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ManagerError("Configuration strings cannot contain control characters or invalid Unicode.")
    return value


def atomic_bytes(path: Path, content: bytes, mode: int) -> None:
    if path.is_symlink():
        raise ManagerError("Refusing to replace a symbolic link.")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".backhaul-", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            Path(temporary).unlink()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def toml_value(value: object) -> str:
    if isinstance(value, str):
        return '"' + safe_text(value).replace("\\", "\\\\").replace('"', '\\"') + '"'
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int and -(1 << 63) <= value < (1 << 63):
        return str(value)
    if isinstance(value, list) and all(type(item) in (str, int, bool) for item in value):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    raise ManagerError("Only simple TOML strings, integers, booleans and scalar arrays are supported.")


def config_bytes(config: dict) -> bytes:
    if not isinstance(config, dict) or set(config) - set(SECTIONS):
        raise ManagerError("Configuration must contain only recognized Backhaul TOML sections.")
    result = [f"# Independent reconstruction by ir_spoof - {CHANNEL}"]
    for section in SECTIONS:
        if section not in config:
            continue
        table = config[section]
        if not isinstance(table, dict):
            raise ManagerError("Each Backhaul section must be a table.")
        result.extend(("", f"[{section}]"))
        for key, value in table.items():
            if not isinstance(key, str) or not KEY_RE.fullmatch(key):
                raise ManagerError("Invalid configuration field name.")
            result.append(f"{key} = {toml_value(value)}")
    content = ("\n".join(result) + "\n").encode("utf-8")
    if len(content) > MAX_CONFIG_BYTES:
        raise ManagerError("Configuration is too large.")
    if tomllib.loads(content.decode("utf-8")) != config:
        raise ManagerError("Configuration did not round-trip through TOML safely.")
    return content


def read_config(path: Path) -> dict:
    safe_file(path)
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ManagerError("Configuration is too large.")
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ManagerError("Invalid TOML configuration.") from error
    config_bytes(value)
    return value


def expected_digest(binary: Path, sha256: str | None, manifest: Path | None, entry: str | None) -> str:
    if sha256:
        if not SHA_RE.fullmatch(sha256):
            raise ManagerError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
        return sha256.lower()
    if not manifest:
        raise ManagerError("Supply a trusted --sha256 HASH or a local --manifest FILE.")
    safe_file(manifest)
    if manifest.stat().st_size > MAX_CONFIG_BYTES:
        raise ManagerError("Checksum manifest is too large.")
    selected = entry or binary.name
    found = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+[* ]?(.+)", line)
        if match and match[2] == selected:
            found.append(match[1].lower())
    if len(found) != 1:
        raise ManagerError("Manifest must contain exactly one matching local core checksum entry.")
    return found[0]


def validate_elf(path: Path, machine: str | None = None) -> None:
    with path.open("rb") as handle:
        header = handle.read(64)
    expected = {"x86_64": 62, "amd64": 62, "aarch64": 183, "arm64": 183}.get((machine or platform.machine()).lower())
    if expected is None:
        raise ManagerError("Installer supports Linux amd64 or arm64; rebuild for this architecture.")
    if len(header) < 64 or header[:7] != b"\x7fELF\x02\x01\x01" or header[7] not in (0, 3):
        raise ManagerError("Core must be a 64-bit little-endian Linux ELF executable.")
    if int.from_bytes(header[18:20], "little") != expected or int.from_bytes(header[16:18], "little") not in (2, 3):
        raise ManagerError("Core architecture or executable type does not match this host.")


class Manager:
    """--root is an isolated filesystem simulation; it never calls host systemd."""

    def __init__(self, root: Path | None = None, test_core_command: list[str] | None = None):
        self.root = root.resolve() if root else None
        self.test_core_command = test_core_command
        if self.root is not None and self.root == Path(self.root.anchor):
            raise ManagerError("Simulation root must be a dedicated directory, never a filesystem root.")
        if test_core_command and not self.root:
            raise ManagerError("Test core commands require --root simulation.")

    def path(self, logical: str) -> Path:
        value = PurePosixPath(logical)
        if not value.is_absolute() or ".." in value.parts:
            raise ManagerError("Invalid managed path.")
        if not self.root and platform.system() != "Linux":
            raise ManagerError("Production manager requires Linux; use --root for a simulation.")
        candidate = self.root.joinpath(*value.parts[1:]) if self.root else Path(str(value))
        stop = self.root if self.root else Path(candidate.anchor)
        cursor = candidate
        while cursor != stop:
            if cursor.is_symlink():
                raise ManagerError("Managed paths must not pass through symbolic links.")
            cursor = cursor.parent
        return candidate

    @property
    def binary(self) -> Path:
        return self.path("/usr/local/bin/backhaul")

    @property
    def state_path(self) -> Path:
        return self.path("/var/lib/backhaul-manager/state.json")

    def config_path(self, name: str) -> Path:
        return self.path(f"/etc/backhaul/{tunnel_id(name)}.toml")

    def service_path(self, name: str) -> Path:
        return self.path(f"/etc/systemd/system/backhaul-{tunnel_id(name)}.service")

    def require_write(self) -> None:
        if self.root:
            self.root.mkdir(parents=True, exist_ok=True)
        elif platform.system() != "Linux" or os.geteuid() != 0:
            raise ManagerError("Production changes require Linux and sudo.")

    @contextlib.contextmanager
    def lock(self):
        self.require_write()
        target = self.path("/var/lib/backhaul-manager/lock")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open("a+b") as handle:
            if platform.system() == "Linux":
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    def state(self) -> dict:
        if not self.state_path.exists():
            return {"schema": 1, "tunnels": {}, "manager_files": {}}
        safe_file(self.state_path)
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as error:
            raise ManagerError("Invalid manager state; preserve it for local recovery.") from error
        if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("tunnels"), dict) or not isinstance(value.get("manager_files"), dict):
            raise ManagerError("Unsupported manager state.")
        for name in value["tunnels"]:
            tunnel_id(name)
        return value

    def save_state(self, value: dict) -> None:
        atomic_bytes(self.state_path, json_bytes(value), 0o600)

    def command(self, argv: list[str], timeout: int = 30, acceptable=(0,)) -> subprocess.CompletedProcess:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False)
        if result.returncode not in acceptable:
            raise ManagerError(f"Command failed with exit code {result.returncode}; inspect local logs for details.")
        return result

    def core_command(self, core: Path, args: list[str]) -> subprocess.CompletedProcess:
        argv = self.test_core_command + args if self.test_core_command else [str(core)] + args
        return self.command(argv, timeout=30)

    def verify_core(self, core: Path) -> str:
        safe_file(core)
        value = self.core_command(core, ["-version"]).stdout.strip()
        if "ir_spoof" not in value or len(value) > 300 or "\n" in value or "\r" in value:
            raise ManagerError("Only the independently rebuilt ir_spoof core is accepted.")
        return value

    def validate_config(self, path: Path, core: Path | None = None) -> None:
        read_config(path)
        selected = core or self.binary
        if core is None and self.state().get("core_sha256") != digest(selected):
            raise ManagerError("Installed core changed outside this manager; reinstall a trusted local build first.")
        self.verify_core(selected)
        self.core_command(selected, ["-c", str(path), "-check"])

    def service(self, action: str, name: str | None = None) -> bool:
        if action not in ("daemon-reload", "is-active", "start", "stop", "restart", "enable", "disable"):
            raise ManagerError("Unsupported service operation.")
        unit = f"backhaul-{tunnel_id(name)}.service" if name else None
        if self.root:
            target = self.path("/var/lib/backhaul-manager/simulation.json")
            data = json.loads(target.read_text()) if target.exists() else {"operations": [], "active": [], "enabled": []}
            if action == "is-active":
                return unit in data["active"]
            data["operations"].append({"action": action, "unit": unit})
            for category, additions, removals in (("active", ("start", "restart"), ("stop",)), ("enabled", ("enable",), ("disable",))):
                if action in additions and unit not in data[category]:
                    data[category].append(unit)
                if action in removals and unit in data[category]:
                    data[category].remove(unit)
            atomic_bytes(target, json_bytes(data), 0o600)
            return True
        result = self.command(["systemctl", action] + ([unit] if unit else []), timeout=40,
                              acceptable=(0, 3, 4) if action == "is-active" else (0,))
        return result.returncode == 0

    def start_service(self, name: str) -> None:
        self.service("start", name)
        if not self.root:
            # Type=simple acknowledges execution before early config/bind errors exit.
            # This is startup supervision, not a claim of peer connectivity.
            time.sleep(0.5)
            if not self.service("is-active", name):
                raise ManagerError("Service failed during startup; previous managed files will be preserved/restored.")

    def owned(self, name: str, state: dict, missing_ok: bool = False) -> dict:
        name = tunnel_id(name)
        record = state["tunnels"].get(name)
        if not isinstance(record, dict):
            raise ManagerError("This tunnel is not owned by this manager.")
        for target, key in ((self.service_path(name), "unit_sha256"), (self.config_path(name), "config_sha256")):
            if not target.exists():
                if missing_ok:
                    continue
                raise ManagerError("A managed tunnel file is missing; restore it before changing the service.")
            safe_file(target)
            if digest(target) != record.get(key):
                raise ManagerError("A tunnel file changed outside this manager; refusing to modify an unrecognized file.")
        return record

    def unit_bytes(self, name: str) -> bytes:
        name = tunnel_id(name)
        return (f"# Independent manager by ir_spoof - {CHANNEL}\n"
                "[Unit]\nDescription=Backhaul independent tunnel\nAfter=network-online.target\nWants=network-online.target\n\n"
                f"[Service]\nType=simple\nExecStart=/usr/local/bin/backhaul -c /etc/backhaul/{name}.toml\n"
                "Restart=on-failure\nRestartSec=5\nTimeoutStopSec=20\nKillMode=control-group\n"
                "UMask=0077\nLimitNOFILE=1048576\nTasksMax=4096\nLimitCORE=0\nNoNewPrivileges=true\n\n"
                "[Install]\nWantedBy=multi-user.target\n").encode("utf-8")

    def generate_secret(self, name: str, kind: str = "token") -> Path:
        name = tunnel_id(name)
        if kind not in ("token", "psk"):
            raise ManagerError("Secret kind must be token or psk.")
        with self.lock():
            target = self.path(f"/etc/backhaul/secrets/{name}.{kind}")
            if target.exists():
                raise ManagerError("Secret file already exists; privately reuse/transfer it instead of overwriting.")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            secret = secrets.token_hex(32) if kind == "token" else base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            atomic_bytes(target, (secret + "\n").encode("ascii"), 0o600)
            return target

    def create(self, name: str, config: dict, replace: bool = False, start: bool = False) -> None:
        name = tunnel_id(name)
        content = config_bytes(config)
        with self.lock():
            state = self.state()
            target, unit = self.config_path(name), self.service_path(name)
            existing = name in state["tunnels"]
            if existing:
                self.owned(name, state)
                if not replace or self.service("is-active", name):
                    raise ManagerError("Stop this manager-owned tunnel and use --replace before replacing it.")
            elif target.exists() or unit.exists():
                raise ManagerError("An unowned config or service uses this ID; choose another ID.")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix=".check-", dir=target.parent) as temporary:
                candidate = Path(temporary) / "config.toml"
                atomic_bytes(candidate, content, 0o600)
                self.validate_config(candidate)
            previous_state = copy.deepcopy(state)
            previous_config = target.read_bytes() if existing else None
            previous_unit = unit.read_bytes() if existing else None
            try:
                atomic_bytes(target, content, 0o600)
                atomic_bytes(unit, self.unit_bytes(name), 0o644)
                state["tunnels"][name] = {"config_sha256": digest(target), "unit_sha256": digest(unit)}
                self.save_state(state)
                self.service("daemon-reload")
                if start:
                    self.service("enable", name)
                    self.start_service(name)
            except Exception:
                if start:
                    for action in ("stop", "disable"):
                        with contextlib.suppress(Exception):
                            self.service(action, name)
                for path, previous, mode in ((target, previous_config, 0o600), (unit, previous_unit, 0o644)):
                    if previous is not None:
                        atomic_bytes(path, previous, mode)
                    else:
                        with contextlib.suppress(FileNotFoundError):
                            path.unlink()
                self.save_state(previous_state)
                with contextlib.suppress(Exception):
                    self.service("daemon-reload")
                raise

    def action(self, action: str, name: str) -> None:
        if action not in ("start", "stop", "restart", "delete"):
            raise ManagerError("Unsupported tunnel action.")
        with self.lock():
            state = self.state()
            self.owned(name, state, missing_ok=action == "delete")
            if action in ("start", "restart"):
                self.validate_config(self.config_path(name))
            if action == "delete":
                self.service("stop", name)
                self.service("disable", name)
                for target in (self.config_path(name), self.service_path(name)):
                    with contextlib.suppress(FileNotFoundError):
                        target.unlink()
                del state["tunnels"][name]
                self.save_state(state)
                self.service("daemon-reload")
            else:
                if action == "start":
                    self.service("enable", name)
                    self.start_service(name)
                elif action == "restart":
                    self.service("stop", name)
                    self.start_service(name)
                else:
                    self.service(action, name)

    def status(self, name: str | None = None) -> list[dict]:
        state = self.state()
        names = [tunnel_id(name)] if name else sorted(state["tunnels"])
        result = []
        for item in names:
            self.owned(item, state)
            result.append({"id": item, "active": self.service("is-active", item)})
        return result

    def manager_payloads(self) -> dict[str, bytes]:
        return {
            "/usr/local/bin/backhaul-manager.py": Path(__file__).read_bytes(),
            "/usr/local/bin/backhaul-manager": b'#!/bin/sh\n# Offline manager by ir_spoof - t.me/ir_spoof\nexec python3 /usr/local/bin/backhaul-manager.py "$@"\n',
            "/usr/local/bin/backhaul.sh": b'#!/bin/bash\n# Offline manager by ir_spoof - t.me/ir_spoof\nexec python3 /usr/local/bin/backhaul-manager.py "$@"\n',
        }

    def install(self, source: Path, expected: str, replace_existing: bool = False, previous_sha256: str | None = None) -> str:
        safe_file(source)
        if not SHA_RE.fullmatch(expected) or digest(source) != expected.lower():
            raise ManagerError("Local core SHA-256 does not match the expected trusted checksum.")
        expected = expected.lower()
        validate_elf(source)
        with self.lock():
            state = self.state()
            old_state = copy.deepcopy(state)
            target = self.binary
            if target.exists():
                safe_file(target)
                previous = digest(target)
                if state.get("core_sha256") != previous and not (replace_existing and previous_sha256 == previous):
                    raise ManagerError("Existing core is unowned; preserve it or explicitly supply its exact previous SHA-256.")
            payloads = self.manager_payloads()
            snapshots = {}
            for logical in payloads:
                path = self.path(logical)
                if path.exists():
                    safe_file(path)
                    if digest(path) != state["manager_files"].get(logical):
                        raise ManagerError("An existing manager file is not recognized; refusing to overwrite it.")
                    snapshots[logical] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                else:
                    snapshots[logical] = None
            active = []
            for name in state["tunnels"]:
                self.owned(name, state)
                if self.service("is-active", name):
                    active.append(name)
            candidate = self.path("/usr/local/bin/.backhaul-candidate")
            backup = self.path("/usr/local/bin/.backhaul-rollback")
            if candidate.exists() or backup.exists():
                raise ManagerError("An unfinished installation exists; inspect candidate/rollback files locally.")
            existed = target.exists()
            old_mode = stat.S_IMODE(target.stat().st_mode) if existed else 0o755
            stopped, replaced, managers_changed = [], False, []
            completed = restored = False
            try:
                atomic_bytes(candidate, source.read_bytes(), 0o755)
                if digest(candidate) != expected:
                    raise ManagerError("Core changed during copying; cancelled before installation.")
                version = self.verify_core(candidate)
                for name in state["tunnels"]:
                    self.validate_config(self.config_path(name), core=candidate)
                for name in active:
                    self.service("stop", name)
                    stopped.append(name)
                if existed:
                    atomic_bytes(backup, target.read_bytes(), old_mode)
                os.replace(candidate, target)
                replaced = True
                for logical, content in payloads.items():
                    atomic_bytes(self.path(logical), content, 0o755)
                    managers_changed.append(logical)
                    state["manager_files"][logical] = hashlib.sha256(content).hexdigest()
                for name in active:
                    self.start_service(name)
                state["core_sha256"], state["core_version"] = expected, version
                self.save_state(state)
                completed = True
                return version
            except Exception:
                if replaced:
                    for name in active:
                        with contextlib.suppress(Exception):
                            self.service("stop", name)
                    if existed and backup.exists():
                        os.replace(backup, target)
                        restored = True
                    elif not existed:
                        with contextlib.suppress(FileNotFoundError):
                            target.unlink()
                for logical in managers_changed:
                    prior = snapshots[logical]
                    if prior is None:
                        with contextlib.suppress(FileNotFoundError):
                            self.path(logical).unlink()
                    else:
                        atomic_bytes(self.path(logical), prior[0], prior[1])
                self.save_state(old_state)
                for name in stopped:
                    with contextlib.suppress(Exception):
                        self.start_service(name)
                raise
            finally:
                cleanup = [candidate]
                # A failed restore must retain the last known-good backup for local recovery.
                if not replaced or completed or restored:
                    cleanup.append(backup)
                for path in cleanup:
                    with contextlib.suppress(FileNotFoundError):
                        path.unlink()

    def change_source(self, name: str, local_ips: list[str] | None = None, spoof_source: str | None = None,
                      expected_peer_source: str | None = None, clear_bind: bool = False, clear_spoof: bool = False) -> None:
        if not (local_ips or spoof_source is not None or expected_peer_source is not None or clear_bind or clear_spoof):
            raise ManagerError("Choose an assigned local bind address or an explicit IPX spoof change.")
        if clear_bind and local_ips or clear_spoof and (spoof_source is not None or expected_peer_source is not None):
            raise ManagerError("Clear and set options cannot be combined for the same source setting.")
        with self.lock():
            state = self.state()
            self.owned(name, state)
            target = self.config_path(name)
            previous = target.read_bytes()
            old_state = copy.deepcopy(state)
            config = read_config(target)
            if local_ips or clear_bind:
                if "dialer" not in config or config.get("tun", {}).get("encapsulation") == "ipx":
                    raise ManagerError("Assigned local bind selection requires a non-IPX dialer.")
                for key in ("local_addr", "local_addrs"):
                    config["dialer"].pop(key, None)
                if local_ips:
                    values = [bind_address(value) for value in local_ips]
                    config["dialer"]["local_addr" if len(values) == 1 else "local_addrs"] = values[0] if len(values) == 1 else values
            if spoof_source is not None or expected_peer_source is not None or clear_spoof:
                if config.get("transport", {}).get("type") != "tun" or config.get("tun", {}).get("encapsulation") != "ipx" or "ipx" not in config:
                    raise ManagerError("Raw source spoof settings require an explicitly configured TUN/IPX tunnel.")
                if clear_spoof:
                    config["ipx"].pop("spoof_src_ip", None)
                    config["ipx"].pop("spoof_dst_ip", None)
                for key, value in (("spoof_src_ip", spoof_source), ("spoof_dst_ip", expected_peer_source)):
                    if value is not None:
                        config["ipx"][key] = literal_ip(value, ipv4=True)
            content = config_bytes(config)
            with tempfile.TemporaryDirectory(prefix=".check-", dir=target.parent) as folder:
                check = Path(folder) / "config.toml"
                atomic_bytes(check, content, 0o600)
                self.validate_config(check)
            active = self.service("is-active", name)
            stopped = False
            try:
                if active:
                    self.service("stop", name)
                    stopped = True
                atomic_bytes(target, content, 0o600)
                state["tunnels"][name]["config_sha256"] = digest(target)
                if active:
                    self.start_service(name)
                self.save_state(state)
            except Exception:
                if stopped:
                    with contextlib.suppress(Exception):
                        self.service("stop", name)
                atomic_bytes(target, previous, 0o600)
                self.save_state(old_state)
                if stopped:
                    with contextlib.suppress(Exception):
                        self.start_service(name)
                raise

    def health(self, name: str) -> dict:
        self.owned(name, self.state())
        config = read_config(self.config_path(name))
        port = config.get("tun", {}).get("health_port", 0)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ManagerError("This config has no valid local TUN health port.")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalHealthOnly())
        with opener.open(f"http://127.0.0.1:{port}/health", timeout=3) as response:
            content = response.read(MAX_CONFIG_BYTES + 1)
        if len(content) > MAX_CONFIG_BYTES:
            raise ManagerError("Local health response is too large.")
        try:
            value = json.loads(content)
        except ValueError as error:
            raise ManagerError("Invalid local health response.") from error
        if not isinstance(value, dict):
            raise ManagerError("Invalid local health response.")
        return value


def literal_ip(value: str, ipv4: bool = False) -> str:
    try:
        result = ipaddress.ip_address(value)
    except ValueError as error:
        raise ManagerError("Expected a literal IP address, never a lookup hostname.") from error
    if ipv4 and result.version != 4:
        raise ManagerError("IPX outer addresses must be IPv4.")
    if result.is_multicast or result.is_unspecified:
        raise ManagerError("Source addresses must be specific unicast IPs.")
    return str(result)


def bind_address(value: str) -> str:
    # Bare IPv4/IPv6, [IPv6]:port or IPv4:port. No DNS lookup occurs here.
    try:
        return literal_ip(value)
    except ManagerError:
        if value.startswith("[") and "]:" in value:
            host, port = value[1:].rsplit("]:", 1)
        elif value.count(":") == 1:
            host, port = value.rsplit(":", 1)
        else:
            raise ManagerError("Local bind must be a literal IP or IP:port; brackets are required for IPv6 ports.")
        host = literal_ip(host)
        if not port.isascii() or not port.isdigit() or not 0 <= int(port) <= 65535:
            raise ManagerError("Invalid local bind port.")
        return f"[{host}]:{int(port)}" if ":" in host else f"{host}:{int(port)}"


def read_secret(path: Path, kind: str) -> str:
    safe_file(path)
    if path.stat().st_size > 4096:
        raise ManagerError("Secret file is too large.")
    if platform.system() == "Linux" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ManagerError("Secret file must have mode 0600 or stricter.")
    try:
        value = path.read_text(encoding="ascii").strip()
    except UnicodeError as error:
        raise ManagerError("Secret must be ASCII text.") from error
    safe_text(value)
    if kind == "psk":
        try:
            if len(base64.b64decode(value, validate=True)) != 32:
                raise ValueError()
        except (ValueError, base64.binascii.Error) as error:
            raise ManagerError("IPX PSK must be base64 encoding exactly 32 random bytes.") from error
    elif not 16 <= len(value) <= 512:
        raise ManagerError("Token must contain 16-512 ASCII characters; use a generated random token.")
    return value


def ports(value: str) -> list[str]:
    result = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:[=:][0-9]+)?", item):
            raise ManagerError("Port maps use PORT, PORT=TARGET, FIRST-LAST or FIRST-LAST:TARGET.")
        if any(not 1 <= int(number) <= 65535 for number in re.findall(r"[0-9]+", item)):
            raise ManagerError("Mapped ports must be between 1 and 65535.")
        range_part = re.split(r"[=:]", item)[0]
        if "-" in range_part and int(range_part.split("-")[0]) > int(range_part.split("-")[1]):
            raise ManagerError("Port range is reversed.")
        result.append(item)
    return result


def build_config(args: argparse.Namespace) -> dict:
    if args.config:
        return read_config(Path(args.config))
    if args.mode not in ("server", "client") or not args.secret_file:
        raise ManagerError("Supply --config FILE or --mode server/client and a private --secret-file.")
    tun_carrier = getattr(args, "tun_carrier", "tcp") if args.transport == "tun" else args.transport
    is_ipx = args.transport == "tun" and args.encapsulation == "ipx"
    if args.encapsulation == "ipx" and args.transport != "tun":
        raise ManagerError("IPX encapsulation requires TUN transport.")
    if (args.spoof_source or args.expected_peer_source or args.local_ip or args.peer_ip or args.interface) and not is_ipx:
        raise ManagerError("Outer IP/interface and raw spoof settings apply only to TUN/IPX.")
    if args.source_bind and (args.mode != "client" or is_ipx):
        raise ManagerError("Assigned source binds apply only to non-IPX dialers.")
    if args.accept_udp and (args.mode != "server" or args.transport != "tcp"):
        raise ManagerError("UDP-over-TCP acceptance applies only to a TCP server.")
    if args.proxy_protocol and (args.mode != "server" or args.transport in ("tun", "ws")):
        raise ManagerError("PROXY protocol applies only to supported non-TUN server transports.")
    if args.edge and (args.mode != "client" or tun_carrier not in ("ws", "wss", "wsmux", "wssmux", "xwsmux")):
        raise ManagerError("Edge destination applies only to a WebSocket dialer.")
    if (args.cert or args.key or args.ca or args.sni) and tun_carrier not in TLS_TRANSPORTS:
        raise ManagerError("TLS options apply only to TLS transports.")
    if args.mode == "client" and (args.cert or args.key) or args.mode == "server" and args.ca:
        raise ManagerError("Use certificate/key on the TLS server and CA trust file on its client.")
    if args.mode != "server" and args.ports:
        raise ManagerError("Port mappings belong to the public server role.")
    if not 1 <= args.pool <= 4096:
        raise ManagerError("Connection pool must be between 1 and 4096.")
    secret = read_secret(Path(args.secret_file), "psk" if is_ipx else "token")
    config = {"transport": {"type": args.transport, "heartbeat_interval": 10, "heartbeat_timeout": 25},
              "security": {}, "tuning": {"auto_tuning": False, "tuning_profile": "balanced", "workers": 0},
              "logging": {"log_level": "info"}}
    if is_ipx:
        if not (args.local_ip and args.peer_ip and args.interface):
            raise ManagerError("IPX requires --local-ip, --peer-ip and --interface.")
        config["ipx"] = {"mode": args.mode, "profile": args.ipx_profile,
                         "listen_ip": literal_ip(args.local_ip, ipv4=True), "dst_ip": literal_ip(args.peer_ip, ipv4=True),
                         "interface": safe_text(args.interface)}
        config["security"] = {"enable_encryption": True, "algorithm": "aes-256-gcm", "psk": secret, "kdf_iterations": 100000}
        for key, value in (("spoof_src_ip", args.spoof_source), ("spoof_dst_ip", args.expected_peer_source)):
            if value:
                config["ipx"][key] = literal_ip(value, ipv4=True)
        if args.ipx_profile == "icmp":
            config["ipx"].update({"icmp_type": 0, "icmp_code": 0})
    else:
        config["security"] = {"token": secret}
        config["transport"].update({"nodelay": True, "keepalive_period": 40})
        if args.mode == "server":
            config["listener"] = {"bind_addr": safe_text(args.listen)}
            if args.accept_udp:
                if args.transport != "tcp":
                    raise ManagerError("--accept-udp applies only to TCP server transport.")
                config["transport"]["accept_udp"] = True
                config["accept_udp"] = {"ring_size": 64, "frame_size": 2048, "peer_idle_timeout_s": 120, "write_timeout_ms": 3}
            if args.proxy_protocol:
                config["transport"]["proxy_protocol"] = True
        else:
            if not args.peer:
                raise ManagerError("Client requires --peer HOST:PORT.")
            config["dialer"] = {"remote_addr": safe_text(args.peer), "dial_timeout": 10, "retry_interval": 3}
            if args.edge:
                config["dialer"]["edge_ip"] = safe_text(args.edge)
            if args.source_bind:
                values = [bind_address(value) for value in args.source_bind]
                config["dialer"]["local_addr" if len(values) == 1 else "local_addrs"] = values[0] if len(values) == 1 else values
            if args.transport != "tun":
                config["transport"]["connection_pool"] = args.pool
    if tun_carrier.endswith("mux"):
        config["mux"] = {"mux_version": 2, "mux_concurrency": 8, "mux_framesize": 32768,
                         "mux_recievebuffer": 4194304, "mux_streambuffer": 2097152}
    if args.transport == "tun":
        local = args.tun_local or ("10.200.0.1/30" if args.mode == "server" else "10.200.0.2/30")
        remote = args.tun_remote or ("10.200.0.2/30" if args.mode == "server" else "10.200.0.1/30")
        ipaddress.ip_interface(local)
        ipaddress.ip_interface(remote)
        config["tun"] = {"carrier": tun_carrier if not is_ipx else "", "encapsulation": args.encapsulation, "name": safe_text(args.tun_name), "local_addr": local,
                         "remote_addr": remote, "health_port": args.health_port, "mtu": args.tun_mtu or (1320 if is_ipx else 1500)}
    if tun_carrier in TLS_TRANSPORTS:
        config["tls"] = {"insecure_skip_verify": False}
        if args.sni:
            config["tls"]["sni"] = safe_text(args.sni)
        if args.mode == "server":
            if not (args.cert and args.key):
                raise ManagerError("TLS server requires existing --cert and --key files.")
            config["tls"].update({"tls_cert": safe_text(args.cert), "tls_key": safe_text(args.key)})
        elif args.ca:
            config["tls"]["ca_file"] = safe_text(args.ca)
    if args.mode == "server":
        config["ports"] = {"mapping": ports(args.ports)}
        if args.transport == "tun":
            config["ports"]["forwarder"] = "backhaul"
    config_bytes(config)
    return config


def prompt(label: str, default: str = "") -> str:
    return input(label + (f" [{default}]" if default else "") + ": ").strip() or default


def wizard(manager: Manager) -> None:
    print(f"Backhaul independent offline Linux manager - {CHANNEL}")
    print("Configure both endpoints with this independent rebuild; original-core interoperability is not assumed.")
    while True:
        print("\n1) Create  2) Status  3) Start  4) Stop  5) Restart  6) Delete  7) Local install  8) Change source  0) Exit")
        choice = prompt("Select", "0")
        if choice == "0":
            return
        try:
            if choice == "1":
                name = tunnel_id(prompt("Tunnel ID", "demo"))
                imported = prompt("Existing TOML file; empty for guided setup")
                if imported:
                    config = read_config(Path(imported))
                else:
                    role = prompt("Role server/client", "server")
                    transport = prompt("Transport " + "/".join(TRANSPORTS), "tcpmux")
                    if role not in ("server", "client") or transport not in TRANSPORTS:
                        raise ManagerError("Unknown role or transport.")
                    argv = ["create", name, "--mode", role, "--transport", transport]
                    encapsulation = prompt("TUN encapsulation tcp/ipx", "tcp") if transport == "tun" else "tcp"
                    if encapsulation not in ("tcp", "ipx"):
                        raise ManagerError("Unknown encapsulation.")
                    kind = "psk" if transport == "tun" and encapsulation == "ipx" else "token"
                    secret_path = prompt("Existing private shared secret file; empty creates a fresh local one")
                    if not secret_path:
                        secret_path = str(manager.generate_secret(name, kind))
                        print(f"Generated /etc/backhaul/secrets/{name}.{kind}; transfer privately to the peer. Secret is not displayed.")
                    argv += ["--secret-file", secret_path]
                    if kind == "psk":
                        argv += ["--encapsulation", "ipx", "--ipx-profile", prompt("IPX profile " + "/".join(IPX_PROFILES), "udp"),
                                 "--local-ip", prompt("Actual local outer IPv4"), "--peer-ip", prompt("Actual peer outer IPv4"),
                                 "--interface", prompt("Physical interface")]
                        spoof = prompt("Raw packet spoof source IPv4; empty disables, requires controlled routing")
                        expected = prompt("Expected peer spoof source IPv4; empty uses actual peer")
                        if spoof:
                            argv += ["--spoof-source", spoof]
                        if expected:
                            argv += ["--expected-peer-source", expected]
                    elif role == "server":
                        argv += ["--listen", prompt("Listen address", "0.0.0.0:8443")]
                    else:
                        argv += ["--peer", prompt("Server HOST:PORT")]
                        bound = prompt("Assigned local source IP; empty uses routing default")
                        if bound:
                            argv += ["--source-bind", bound]
                    if role == "server":
                        argv += ["--ports", prompt("Port maps, comma separated; empty for TUN only")]
                    if transport == "tun":
                        argv += ["--tun-name", prompt("TUN name", "backhaul0"),
                                 "--tun-local", prompt("Local TUN CIDR", "10.200.0.1/30" if role == "server" else "10.200.0.2/30"),
                                 "--tun-remote", prompt("Peer TUN CIDR", "10.200.0.2/30" if role == "server" else "10.200.0.1/30"),
                                 "--health-port", prompt("Loopback health port", "19080")]
                    if transport in TLS_TRANSPORTS:
                        argv += ["--sni", prompt("TLS name matching certificate")]
                        if role == "server":
                            argv += ["--cert", prompt("Existing certificate file"), "--key", prompt("Existing key file")]
                        else:
                            ca = prompt("CA/certificate trust file; empty uses system roots")
                            if ca:
                                argv += ["--ca", ca]
                    config = build_config(parser().parse_args(argv))
                manager.create(name, config, start=prompt("Start and enable after validation? y/n", "n").lower() == "y")
                print("Validated and installed; shared secrets were not displayed.")
            elif choice == "2":
                print(json.dumps(manager.status(), indent=2))
            elif choice in ("3", "4", "5", "6"):
                action = {"3": "start", "4": "stop", "5": "restart", "6": "delete"}[choice]
                name = tunnel_id(prompt("Tunnel ID"))
                if action == "delete" and prompt("Delete this owned service/config? y/n", "n") != "y":
                    continue
                manager.action(action, name)
                print("Completed.")
            elif choice == "7":
                binary = Path(prompt("Local independently rebuilt core"))
                manager.install(binary, expected_digest(binary, prompt("Trusted SHA-256"), None, None))
                print("Verified offline installation completed.")
            elif choice == "8":
                name = tunnel_id(prompt("Tunnel ID"))
                kind = prompt("Change assigned dialer bind or explicit IPX spoof? bind/spoof", "bind")
                if kind == "bind":
                    manager.change_source(name, local_ips=[prompt("Assigned local IP; connection startup verifies assignment")])
                elif kind == "spoof":
                    source = prompt("Raw source IPv4; empty keeps current")
                    peer = prompt("Expected peer raw source IPv4; empty keeps current")
                    manager.change_source(name, spoof_source=source or None, expected_peer_source=peer or None)
                else:
                    raise ManagerError("Unknown source operation.")
                print("Source configuration validated and updated; previously active service restarted.")
            else:
                print("Unknown option.")
        except (ManagerError, OSError, ValueError, subprocess.SubprocessError):
            print("Operation failed; inspect local configuration and service logs. Secrets are not printed.", file=sys.stderr)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=f"Offline independent Linux Backhaul manager - {CHANNEL}")
    result.add_argument("--root", type=Path, help="Simulation directory; never modifies host services")
    result.add_argument("--test-core-command", help=argparse.SUPPRESS)
    sub = result.add_subparsers(dest="command")
    install = sub.add_parser("install", help="Install a local independently rebuilt ELF with trusted checksum")
    install.add_argument("--binary", type=Path, required=True)
    check = install.add_mutually_exclusive_group(required=True)
    check.add_argument("--sha256")
    check.add_argument("--manifest", type=Path)
    install.add_argument("--manifest-entry")
    install.add_argument("--replace-existing", action="store_true")
    install.add_argument("--previous-sha256")
    create = sub.add_parser("create")
    create.add_argument("id", type=tunnel_id)
    create.add_argument("--config")
    create.add_argument("--mode", choices=("server", "client"))
    create.add_argument("--transport", choices=TRANSPORTS, default="tcpmux")
    create.add_argument("--listen", default="0.0.0.0:8443")
    create.add_argument("--peer")
    create.add_argument("--edge")
    create.add_argument("--pool", type=int, default=8)
    create.add_argument("--secret-file")
    create.add_argument("--ports", default="")
    create.add_argument("--accept-udp", action="store_true")
    create.add_argument("--proxy-protocol", action="store_true")
    create.add_argument("--source-bind", action="append")
    create.add_argument("--cert")
    create.add_argument("--key")
    create.add_argument("--ca")
    create.add_argument("--sni")
    create.add_argument("--encapsulation", choices=("tcp", "ipx"), default="tcp")
    create.add_argument("--tun-carrier", choices=tuple(x for x in TRANSPORTS if x != "tun"), default="tcp")
    create.add_argument("--tun-name", default="backhaul0")
    create.add_argument("--tun-local")
    create.add_argument("--tun-remote")
    create.add_argument("--tun-mtu", type=int)
    create.add_argument("--health-port", type=int, default=19080)
    create.add_argument("--ipx-profile", choices=IPX_PROFILES, default="udp")
    create.add_argument("--local-ip")
    create.add_argument("--peer-ip")
    create.add_argument("--interface")
    create.add_argument("--spoof-source")
    create.add_argument("--expected-peer-source")
    create.add_argument("--replace", action="store_true")
    create.add_argument("--start", action="store_true")
    for operation in ("start", "stop", "restart", "delete", "health"):
        action = sub.add_parser(operation)
        action.add_argument("id", type=tunnel_id)
        if operation == "delete":
            action.add_argument("--yes", required=True, action="store_true")
    status = sub.add_parser("status")
    status.add_argument("id", nargs="?", type=tunnel_id)
    secret = sub.add_parser("secret")
    secret.add_argument("id", type=tunnel_id)
    secret.add_argument("--kind", choices=("token", "psk"), default="token")
    check = sub.add_parser("check")
    check.add_argument("config", type=Path)
    check.add_argument("--binary", type=Path)
    source = sub.add_parser("change-source", help="Assigned local bind and explicit raw IPX spoof are separate settings")
    source.add_argument("id", type=tunnel_id)
    source.add_argument("--local-ip", action="append")
    source.add_argument("--spoof-source")
    source.add_argument("--expected-peer-source")
    source.add_argument("--clear-bind", action="store_true")
    source.add_argument("--clear-spoof", action="store_true")
    sub.add_parser("menu")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        manager = Manager(args.root, shlex.split(args.test_core_command) if args.test_core_command else None)
        if args.command == "install":
            manager.install(args.binary, expected_digest(args.binary, args.sha256, args.manifest, args.manifest_entry),
                            args.replace_existing, args.previous_sha256)
            print(f"Verified offline core and manager installed - {CHANNEL}")
        elif args.command == "create":
            manager.create(args.id, build_config(args), args.replace, args.start)
            print(f"Tunnel {args.id} validated and created - {CHANNEL}")
        elif args.command in ("start", "stop", "restart", "delete"):
            manager.action(args.command, args.id)
            print(f"Tunnel {args.id}: {args.command} completed.")
        elif args.command == "status":
            print(json.dumps(manager.status(args.id), indent=2))
        elif args.command == "secret":
            manager.generate_secret(args.id, args.kind)
            print(f"Generated /etc/backhaul/secrets/{args.id}.{args.kind}; transfer privately to the peer. Contents are not displayed.")
        elif args.command == "health":
            print(json.dumps(manager.health(args.id), indent=2))
        elif args.command == "check":
            manager.validate_config(args.config, args.binary)
            print("Configuration check passed.")
        elif args.command == "change-source":
            manager.change_source(args.id, args.local_ip, args.spoof_source, args.expected_peer_source, args.clear_bind, args.clear_spoof)
            print("Source configuration validated and updated; previously active service restarted.")
        else:
            wizard(manager)
        return 0
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except ManagerError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        # Arbitrary exceptions can include host paths, endpoints, config contents or secrets.
        print("Operation failed; inspect local service logs. No host path or configuration contents are printed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
