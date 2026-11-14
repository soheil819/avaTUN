#!/usr/bin/env python3
"""Check managed HAProxy stats/exporter without using host configuration."""
import pathlib,sys,tempfile,types,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tunnelmgr'))
import haproxy_stats as stats
with patch('pwd.getpwnam',return_value=types.SimpleNamespace(pw_uid=0)):
    import privd


class StatsChecks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
        self.settings=self.root/'haproxy-stats.json'
        self.patch=patch.object(stats,'SETTINGS',self.settings);self.patch.start()

    def tearDown(self):self.patch.stop();self.tmp.cleanup()

    def test_contains_all_requested_statistics_and_exporter_options(self):
        text=stats.append_block('global\n  daemon\n')
        for option in ('frontend haproxy_stats','bind 0.0.0.0:18404','mode http','stats enable',
                       'stats uri /stats','stats refresh 5s','stats show-legends','stats show-node',
                       'stats auth admin:','http-request use-service prometheus-exporter if { path /metrics }'):
            self.assertIn(option,text)

    def test_reapplying_updates_one_block_and_preserves_user_config(self):
        original='global\n  daemon\nfrontend owned_by_user\n  bind 127.0.0.1:9000\n'
        once=stats.append_block(original);twice=stats.append_block(once)
        self.assertEqual(once,twice);self.assertEqual(1,twice.count('frontend haproxy_stats'))
        self.assertIn(original.rstrip(),twice)

    def test_credentials_are_persistent_private_runtime_data(self):
        first=stats.settings();self.assertEqual(first,stats.settings())
        self.assertEqual(0o600,self.settings.stat().st_mode&0o777)
        self.assertGreaterEqual(len(first['password']),24)

    def test_custom_runtime_credentials_are_used_exactly(self):
        self.settings.write_text('{"username":"admin","password":"test-runtime-password"}')
        self.assertIn('stats auth admin:test-runtime-password',stats.append_block('global\n'))

    def test_injected_credentials_are_rejected(self):
        self.settings.write_text('{"username":"admin","password":"bad\\nfrontend injection"}')
        with self.assertRaises(ValueError):stats.append_block('global\n')

    def test_unmanaged_stats_frontend_and_partial_markers_are_not_overwritten(self):
        for original in ('frontend haproxy_stats\n  bind :9999\n',stats.BEGIN+'\nunfinished'):
            with self.assertRaises(ValueError):stats.append_block(original)

    def test_statistics_remain_available_with_no_forwarding_rules(self):
        cfg=self.root/'haproxy.cfg';cfg.write_text('global\n  daemon\n')
        path=lambda value:cfg if str(value)=='/etc/haproxy/haproxy.cfg' else pathlib.Path(value)
        with patch.object(privd,'Path',side_effect=path),patch.object(privd.shutil,'which',return_value='/usr/sbin/haproxy'),patch.object(privd.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)),patch.object(privd,'haproxy_commit') as commit:
            result=privd.haproxy_apply({'action':'apply','rules':[]})
        self.assertTrue(result['active']);self.assertIn('frontend haproxy_stats',commit.call_args.args[0])

    def test_ensure_stats_preserves_existing_managed_forward_block(self):
        cfg=self.root/'haproxy.cfg'
        cfg.write_text('global\n  daemon\n# BEGIN TUNNELMGR FORWARDS\nfrontend tm_fwd_test\n  bind :2053\n# END TUNNELMGR FORWARDS\n')
        path=lambda value:cfg if str(value)=='/etc/haproxy/haproxy.cfg' else pathlib.Path(value)
        with patch.object(privd,'Path',side_effect=path),patch.object(privd.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)),patch.object(privd,'haproxy_commit') as commit:
            privd.haproxy_apply({'action':'ensure-stats'})
        text=commit.call_args.args[0]
        self.assertIn('frontend tm_fwd_test',text);self.assertIn('frontend haproxy_stats',text)


if __name__=='__main__':unittest.main(verbosity=2)
