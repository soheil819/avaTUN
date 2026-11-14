#!/usr/bin/env python3
"""Meaningful offline manager safety regressions by ir_spoof - t.me/ir_spoof.

Uses only an independently written fake checker and --root simulation.
It never executes the supplied premium binary or modifies host services.
"""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import platform
import stat
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("backhaul_manager", Path(__file__).with_name("backhaul-manager.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

FAKE_CHECKER = '''# Independent test fixture by ir_spoof; t.me/ir_spoof
import pathlib, sys, tomllib
if sys.argv[1:] == ["-version"]:
    print("backhaul independent fixture ir_spoof")
    raise SystemExit(0)
if len(sys.argv) != 4 or sys.argv[1] != "-c" or sys.argv[3] != "-check":
    raise SystemExit(4)
config = tomllib.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if config.get("listener", {}).get("bind_addr") == "invalid":
    print("not-public-secret diagnostic", file=sys.stderr)
    raise SystemExit(2)
if config.get("transport", {}).get("type") not in ("tcp", "tcpmux", "xtcpmux", "ws", "wss", "wsmux", "wssmux", "xwsmux", "anytls", "tun"):
    raise SystemExit(3)
print("configuration checked")
'''


def elf_bytes(extra: bytes = b"first") -> bytes:
    result = bytearray(64)
    result[:7] = b"\x7fELF\x02\x01\x01"
    result[16:18] = (2).to_bytes(2, "little")
    result[18:20] = (183 if platform.machine().lower() in ("aarch64", "arm64") else 62).to_bytes(2, "little")
    return bytes(result) + extra


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="backhaul-manager-test-")
        self.addCleanup(self.folder.cleanup)
        self.base = Path(self.folder.name)
        self.root = self.base / "root"
        self.fake = self.base / "checker.py"
        self.fake.write_text(FAKE_CHECKER, encoding="utf-8")
        self.core = self.base / "core"
        self.core.write_bytes(elf_bytes())
        self.manager = M.Manager(self.root, [sys.executable, str(self.fake)])
        self.manager.install(self.core, M.digest(self.core))
        self.token = self.manager.generate_secret("peer", "token")
        self.psk = self.manager.generate_secret("peer", "psk")

    def config(self, role="server", transport="tcp", ipx=False):
        values = ["create", "demo", "--mode", role, "--transport", transport, "--secret-file", str(self.psk if ipx else self.token)]
        if role == "client":
            values += ["--peer", "127.0.0.1:18443"]
        else:
            values += ["--listen", "127.0.0.1:18443", "--ports", "18080=19090"]
        if transport in M.TLS_TRANSPORTS:
            values += ["--sni", "localhost"]
            values += ["--cert", "/etc/backhaul/cert.crt", "--key", "/etc/backhaul/cert.key"] if role == "server" else ["--ca", "/etc/backhaul/cert.crt"]
        if ipx:
            values += ["--encapsulation", "ipx", "--local-ip", "192.0.2.10", "--peer-ip", "192.0.2.20", "--interface", "lab0"]
        return M.build_config(M.parser().parse_args(values))

    def test_install_checks_checksum_before_changes(self):
        original = self.manager.binary.read_bytes()
        with self.assertRaises(M.ManagerError):
            self.manager.install(self.core, "0" * 64)
        self.assertEqual(self.manager.binary.read_bytes(), original)

    def test_simulation_never_targets_filesystem_root(self):
        with self.assertRaises(M.ManagerError):
            M.Manager(Path(self.base.anchor))

    def test_install_rejects_non_elf_and_wrong_architecture(self):
        self.core.write_bytes(b"not an executable")
        with self.assertRaises(M.ManagerError):
            self.manager.install(self.core, M.digest(self.core))
        altered = bytearray(elf_bytes())
        altered[18:20] = (65535).to_bytes(2, "little")
        self.core.write_bytes(altered)
        with self.assertRaises(M.ManagerError):
            self.manager.install(self.core, M.digest(self.core))

    def test_install_rejects_unknown_core_and_manager_files(self):
        original = self.manager.binary.read_bytes()
        self.manager.binary.write_bytes(b"unowned")
        with self.assertRaises(M.ManagerError):
            self.manager.install(self.core, M.digest(self.core))
        self.assertEqual(self.manager.binary.read_bytes(), b"unowned")
        self.manager.binary.write_bytes(original)
        launcher = self.manager.path("/usr/local/bin/backhaul-manager")
        launcher.write_text("unrelated tool", encoding="utf-8")
        with self.assertRaises(M.ManagerError):
            self.manager.install(self.core, M.digest(self.core))
        self.assertEqual(launcher.read_text(), "unrelated tool")

    def test_install_restart_failure_rolls_back_bytes_state_and_running_service(self):
        self.manager.create("demo", self.config(), start=True)
        previous_core = self.manager.binary.read_bytes()
        previous_state = self.manager.state_path.read_bytes()
        previous_launcher = self.manager.path("/usr/local/bin/backhaul-manager").read_bytes()
        self.core.write_bytes(elf_bytes(b"second"))
        real_service = self.manager.service
        failures = []
        def fail_new_start(action, name=None):
            if action == "start" and self.manager.binary.read_bytes() != previous_core:
                failures.append(name)
                raise M.ManagerError("simulated independent core startup failure")
            return real_service(action, name)
        with patch.object(self.manager, "service", side_effect=fail_new_start):
            with self.assertRaises(M.ManagerError):
                self.manager.install(self.core, M.digest(self.core))
        self.assertEqual(failures, ["demo"])
        self.assertEqual(self.manager.binary.read_bytes(), previous_core)
        self.assertEqual(self.manager.state_path.read_bytes(), previous_state)
        self.assertEqual(self.manager.path("/usr/local/bin/backhaul-manager").read_bytes(), previous_launcher)
        self.assertTrue(real_service("is-active", "demo"))
        self.assertFalse(self.manager.path("/usr/local/bin/.backhaul-rollback").exists())

    def test_install_failure_before_swap_does_not_stop_service(self):
        self.manager.create("demo", self.config(), start=True)
        prior = self.manager.binary.read_bytes()
        with patch.object(self.manager, "verify_core", side_effect=M.ManagerError("unrecognized build")):
            with self.assertRaises(M.ManagerError):
                self.manager.install(self.core, M.digest(self.core))
        self.assertEqual(self.manager.binary.read_bytes(), prior)
        self.assertTrue(self.manager.service("is-active", "demo"))

    def test_early_service_exit_is_reported_as_startup_failure(self):
        # Exercise production supervision without running systemd or changing files.
        manager = M.Manager()
        with patch.object(manager, "service", side_effect=[True, False]) as operation, patch.object(M.time, "sleep"):
            with self.assertRaises(M.ManagerError):
                manager.start_service("demo")
        self.assertEqual(operation.call_args_list[0].args, ("start", "demo"))
        self.assertEqual(operation.call_args_list[1].args, ("is-active", "demo"))

    def test_install_rollback_retains_backup_when_restore_fails(self):
        self.manager.create("demo", self.config(), start=True)
        previous = self.manager.binary.read_bytes()
        self.core.write_bytes(elf_bytes(b"second"))
        real_service, real_replace = self.manager.service, os.replace
        def fail_start(action, name=None):
            if action == "start":
                raise M.ManagerError("simulated startup failure")
            return real_service(action, name)
        def fail_restore(source, destination):
            if str(source).endswith(".backhaul-rollback"):
                raise OSError("simulated disk restore failure")
            return real_replace(source, destination)
        with patch.object(self.manager, "service", side_effect=fail_start), patch.object(M.os, "replace", side_effect=fail_restore):
            with self.assertRaises(OSError):
                self.manager.install(self.core, M.digest(self.core))
        self.assertEqual(self.manager.path("/usr/local/bin/.backhaul-rollback").read_bytes(), previous)

    def test_toml_shell_metacharacters_are_data_without_execution(self):
        config = self.config()
        marker = self.base / "INJECTION-MARKER"
        value = 'quoted"; $(touch ' + str(marker) + '); `touch NOPE`; \\ tail'
        config["security"]["token"] = value
        content = M.config_bytes(config)
        self.assertEqual(tomllib.loads(content.decode()), config)
        self.manager.create("demo", config)
        self.assertEqual(M.read_config(self.manager.config_path("demo"))["security"]["token"], value)
        self.assertFalse(marker.exists())
        self.assertNotIn("/bin/sh", self.manager.service_path("demo").read_text())

    def test_control_characters_and_table_injection_rejected(self):
        config = self.config()
        config["security"]["token"] = 'secret\n[listener]\nbind_addr="evil"'
        with self.assertRaises(M.ManagerError):
            M.config_bytes(config)
        for field in ('token]\n[evil', 'token;touch', 123):
            with self.subTest(field=field):
                with self.assertRaises(M.ManagerError):
                    M.config_bytes({"security": {field: "hello"}})

    def test_validation_failure_creates_no_config_or_service(self):
        config = self.config()
        config["listener"]["bind_addr"] = "invalid"
        with self.assertRaises(M.ManagerError):
            self.manager.create("demo", config, start=True)
        self.assertFalse(self.manager.config_path("demo").exists())
        self.assertFalse(self.manager.service_path("demo").exists())
        self.assertNotIn("demo", self.manager.state()["tunnels"])

    def test_modified_installed_core_is_never_executed(self):
        self.manager.binary.write_bytes(elf_bytes(b"unrecognized replacement"))
        with patch.object(self.manager, "core_command") as executed:
            with self.assertRaises(M.ManagerError):
                self.manager.create("demo", self.config())
            executed.assert_not_called()

    def test_create_start_failure_rolls_back_all_owned_files(self):
        service = self.manager.service
        def broken(action, name=None):
            if action == "start":
                raise M.ManagerError("startup failure")
            return service(action, name)
        with patch.object(self.manager, "service", side_effect=broken):
            with self.assertRaises(M.ManagerError):
                self.manager.create("demo", self.config(), start=True)
        self.assertFalse(self.manager.config_path("demo").exists())
        self.assertFalse(self.manager.service_path("demo").exists())
        self.assertNotIn("demo", self.manager.state()["tunnels"])

    def test_unowned_service_collision_never_changes_files(self):
        target = self.manager.service_path("demo")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("unrelated", encoding="utf-8")
        with self.assertRaises(M.ManagerError):
            self.manager.create("demo", self.config(), start=True)
        self.assertEqual(target.read_text(), "unrelated")
        self.assertFalse(self.manager.config_path("demo").exists())

    def test_modified_config_or_unit_never_deleted_or_restarted(self):
        self.manager.create("demo", self.config())
        for target in (self.manager.config_path("demo"), self.manager.service_path("demo")):
            previous = target.read_bytes()
            target.write_bytes(previous + b"# external\n")
            for action in ("start", "restart", "delete"):
                with self.subTest(path=target.name, action=action):
                    with self.assertRaises(M.ManagerError):
                        self.manager.action(action, "demo")
                    self.assertTrue(target.exists())
            target.write_bytes(previous)

    def test_delete_inactive_enabled_service_disables_and_preserves_sentinel(self):
        self.manager.create("demo", self.config(), start=True)
        self.manager.action("stop", "demo")
        sentinel = self.manager.path("/etc/systemd/system/unrelated.service")
        sentinel.write_text("keep", encoding="utf-8")
        self.manager.action("delete", "demo")
        data = json.loads(self.manager.path("/var/lib/backhaul-manager/simulation.json").read_text())
        self.assertNotIn("backhaul-demo.service", data["enabled"])
        self.assertNotIn("backhaul-demo.service", data["active"])
        self.assertEqual(sentinel.read_text(), "keep")
        self.assertNotIn("demo", self.manager.state()["tunnels"])

    def test_secrets_are_unique_correct_format_and_not_printed(self):
        first = M.read_secret(self.token, "token")
        second = self.manager.generate_secret("second", "token").read_text().strip()
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertEqual(len(base64.b64decode(self.psk.read_text().strip(), validate=True)), 32)
        with self.assertRaises(M.ManagerError):
            self.manager.generate_secret("peer", "psk")
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = M.main(["--root", str(self.root), "secret", "third", "--kind", "psk"])
        secret = self.manager.path("/etc/backhaul/secrets/third.psk").read_text().strip()
        self.assertEqual(code, 0)
        self.assertNotIn(secret, output.getvalue() + errors.getvalue())
        self.assertNotIn(str(self.root), output.getvalue() + errors.getvalue())

    @unittest.skipUnless(platform.system() == "Linux", "POSIX mode semantics require Linux")
    def test_secret_config_state_permissions_are_private(self):
        self.manager.create("demo", self.config())
        for target in (self.token, self.psk, self.manager.config_path("demo"), self.manager.state_path):
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.token.parent.stat().st_mode), 0o700)

    def test_all_advertised_transport_builders_and_secure_tls_defaults(self):
        for transport in M.TRANSPORTS:
            for role in ("server", "client"):
                with self.subTest(transport=transport, role=role):
                    config = self.config(role, transport)
                    self.assertEqual(tomllib.loads(M.config_bytes(config).decode()), config)
                    self.assertFalse(config["tuning"]["auto_tuning"])
                    self.assertEqual("ports" in config, role == "server")
                    if transport in M.TLS_TRANSPORTS:
                        self.assertIs(config["tls"]["insecure_skip_verify"], False)
                    self.assertNotIn("wire_mode", config["security"])
        for profile in M.IPX_PROFILES:
            for role in ("server", "client"):
                with self.subTest(ipx=profile, role=role):
                    config = self.config(role, "tun", ipx=True)
                    config["ipx"]["profile"] = profile
                    self.assertNotIn("listener", config)
                    self.assertNotIn("dialer", config)
                    self.assertTrue(config["security"]["enable_encryption"])
                    self.assertEqual(len(base64.b64decode(config["security"]["psk"])), 32)

    def test_inapplicable_source_and_transport_flags_are_not_silently_ignored(self):
        baseline = ["create", "demo", "--mode", "client", "--transport", "tcp", "--peer", "127.0.0.1:8443", "--secret-file", str(self.token)]
        for values in (["--spoof-source", "192.0.2.1"], ["--encapsulation", "ipx"], ["--accept-udp"],
                       ["--proxy-protocol"], ["--edge", "192.0.2.5"], ["--ca", "cert.crt"], ["--ports", "443"]):
            with self.subTest(values=values):
                with self.assertRaises(M.ManagerError):
                    M.build_config(M.parser().parse_args(baseline + values))

    def test_change_source_active_tunnel_updates_bound_ips_and_hash(self):
        self.manager.create("demo", self.config("client"), start=True)
        self.manager.change_source("demo", ["192.0.2.10", "[2001:db8::10]:0"])
        config = M.read_config(self.manager.config_path("demo"))
        self.assertEqual(config["dialer"]["local_addrs"], ["192.0.2.10", "[2001:db8::10]:0"])
        self.assertTrue(self.manager.service("is-active", "demo"))
        self.assertEqual(M.digest(self.manager.config_path("demo")), self.manager.state()["tunnels"]["demo"]["config_sha256"])
        self.manager.change_source("demo", clear_bind=True)
        self.assertNotIn("local_addrs", M.read_config(self.manager.config_path("demo"))["dialer"])

    def test_change_source_restart_failure_restores_file_state_and_service(self):
        self.manager.create("demo", self.config("client"), start=True)
        original = self.manager.config_path("demo").read_bytes()
        state = self.manager.state_path.read_bytes()
        real_service = self.manager.service
        failures = []
        def fail_candidate(action, name=None):
            if action == "start" and self.manager.config_path("demo").read_bytes() != original:
                failures.append(name)
                raise M.ManagerError("assigned address not available")
            return real_service(action, name)
        with patch.object(self.manager, "service", side_effect=fail_candidate):
            with self.assertRaises(M.ManagerError):
                self.manager.change_source("demo", ["192.0.2.99"])
        self.assertEqual(failures, ["demo"])
        self.assertEqual(self.manager.config_path("demo").read_bytes(), original)
        self.assertEqual(self.manager.state_path.read_bytes(), state)
        self.assertTrue(real_service("is-active", "demo"))

    def test_spoof_settings_are_explicit_and_distinct_from_bind(self):
        self.manager.create("demo", self.config("client"), start=True)
        before = self.manager.config_path("demo").read_bytes()
        with self.assertRaises(M.ManagerError):
            self.manager.change_source("demo", spoof_source="192.0.2.5")
        self.assertEqual(self.manager.config_path("demo").read_bytes(), before)
        self.manager.create("raw", self.config("server", "tun", ipx=True))
        self.manager.change_source("raw", spoof_source="198.51.100.10", expected_peer_source="198.51.100.20")
        config = M.read_config(self.manager.config_path("raw"))
        self.assertEqual(config["ipx"]["listen_ip"], "192.0.2.10")
        self.assertEqual(config["ipx"]["dst_ip"], "192.0.2.20")
        self.assertEqual(config["ipx"]["spoof_src_ip"], "198.51.100.10")
        self.assertEqual(config["ipx"]["spoof_dst_ip"], "198.51.100.20")
        self.manager.change_source("raw", clear_spoof=True)
        self.assertNotIn("spoof_src_ip", M.read_config(self.manager.config_path("raw"))["ipx"])

    def test_bad_source_names_and_invalid_ids_never_mutate(self):
        self.manager.create("demo", self.config("client"))
        prior = self.manager.config_path("demo").read_bytes()
        for value in ("example.com", "0.0.0.0", "192.0.2.1:99999", "$(touch no)", "224.0.0.1"):
            with self.subTest(value=value):
                with self.assertRaises(M.ManagerError):
                    self.manager.change_source("demo", [value])
                self.assertEqual(self.manager.config_path("demo").read_bytes(), prior)
        for name in ("../evil", "demo\nExecStart=", "-bad", ";touch", "a/b"):
            with self.assertRaises(M.ManagerError):
                M.tunnel_id(name)

    def test_health_disables_proxy_redirect_and_uses_only_loopback(self):
        self.manager.create("demo", self.config("server", "tun"))
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return b'{"sessions": 1}'
        class Opener:
            def open(self, url, timeout):
                self.assert_url = url
                if url != "http://127.0.0.1:19080/health" or timeout != 3:
                    raise AssertionError("unexpected endpoint")
                return Response()
        with patch.object(M.urllib.request, "build_opener", return_value=Opener()) as build:
            self.assertEqual(self.manager.health("demo"), {"sessions": 1})
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], M.LocalHealthOnly)
        with self.assertRaises(M.ManagerError):
            M.LocalHealthOnly().redirect_request(None, None, 302, "Found", None, "https://untrusted.invalid")

    def test_invalid_health_port_never_opens_network(self):
        self.manager.create("demo", self.config())
        with patch.object(M.urllib.request, "build_opener") as opened:
            with self.assertRaises(M.ManagerError):
                self.manager.health("demo")
            opened.assert_not_called()

    def test_child_stderr_is_not_leaked_to_cli(self):
        config = self.config()
        config["listener"]["bind_addr"] = "invalid"
        imported = self.base / "private-config.toml"
        imported.write_bytes(M.config_bytes(config))
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = M.main(["--root", str(self.root), "--test-core-command", shlex_join([sys.executable, str(self.fake)]),
                             "create", "demo", "--config", str(imported)])
        self.assertEqual(result, 1)
        self.assertNotIn("not-public-secret", errors.getvalue())
        self.assertNotIn(str(self.base), errors.getvalue())
        self.assertNotIn(self.token.read_text().strip(), errors.getvalue())

    @unittest.skipUnless(platform.system() == "Linux", "Safe symbolic link creation is checked in Linux")
    def test_managed_symlink_paths_rejected(self):
        other = self.base / "outside"
        other.mkdir()
        link = self.manager.path("/etc/backhaul/linked.toml")
        link.symlink_to(other / "file")
        with self.assertRaises(M.ManagerError):
            self.manager.config_path("linked")
        secret_dir = self.manager.path("/etc/backhaul/secrets")
        for target in secret_dir.iterdir():
            target.unlink()
        secret_dir.rmdir()
        secret_dir.symlink_to(other, target_is_directory=True)
        with self.assertRaises(M.ManagerError):
            self.manager.generate_secret("bad", "token")


def shlex_join(args):
    import shlex
    return shlex.join(args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
