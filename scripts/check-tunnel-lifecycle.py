#!/usr/bin/env python3
"""Verify two-sided teardown/recreate and rollback without touching host tunnels."""
import copy
import json
import pathlib
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tunnelmgr'))
import tunnelctl as t
import tunnel_lifecycle as lifecycle
import profiles
import network
with patch('pwd.getpwnam',return_value=types.SimpleNamespace(pw_uid=0)):
    import privd


class RebuildChecks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.events=[];self.fail=None
        self.old={sid:{'id':'demo','transport':'gre','mode':mode,'kind':'gre','interface':'old0',
                      'inner_local':local,'inner_peer':peer,'mtu':1400}
                  for sid,mode,local,peer in [('local','client','10.250.0.1/30','10.250.0.2/30'),('peer','server','10.250.0.2/30','10.250.0.1/30')]}
        self.live=copy.deepcopy(self.old)
        self.api=types.SimpleNamespace(ID=t.ID,BASE=pathlib.Path(self.tmp.name),NATIVE_PAIR_LOCK=threading.RLock(),
            server_rows=lambda:[{'id':'peer'}],normalize_rebuild_config=t.normalize_rebuild_config,
            tunnel_config=lambda ident:self.call('local','config'),
            validate_tunnel_config=lambda cfg:self.call('local','validate',cfg),
            remove_tunnel_endpoint=lambda ident:self.call('local','delete'),
            create_native=lambda cfg:self.call('local','create',cfg),
            create_instance=lambda cfg:self.call('local','create',cfg),
            find=lambda ident:{'id':ident} if 'local' in self.live else None,
            server_remote=self.remote)

    def tearDown(self):self.tmp.cleanup()

    def call(self,sid,op,cfg=None):
        self.events.append((sid,op,copy.deepcopy(cfg)))
        if self.fail:self.fail(sid,op,cfg)
        if op=='config':return copy.deepcopy(self.live[sid])
        if op=='validate':return {'ok':True}
        if op=='delete':
            self.assertTrue(list((self.api.BASE/'rebuild-journals').glob('*.json')))
            self.live.pop(sid,None);return {'ok':True}
        if op=='create':self.live[sid]=copy.deepcopy(cfg);return {'ok':True}
        if op=='list':return {'items':[{'id':'demo'}] if sid in self.live else []}
        raise AssertionError(op)

    def remote(self,server,payload):
        op=payload['op']
        return self.call(server['id'],payload['action'] if op=='operate' else op,payload.get('data'))

    def rebuild(self,configs=None):
        return lifecycle.rebuild(self.api,'demo',['local','peer'],configs,'update' if configs else 'restart')

    def test_restart_removes_both_before_creating_either_and_preserves_config(self):
        result=self.rebuild()
        self.assertEqual(['config','config','validate','validate','delete','delete','create','create'],[e[1] for e in self.events])
        self.assertEqual(['peer','local'],result['startup_order'])
        self.assertEqual(self.old,self.live)
        self.assertFalse(list((self.api.BASE/'rebuild-journals').glob('*.json')))

    def test_edit_uses_new_configs_only_after_both_ends_are_removed(self):
        new={sid:{**cfg,'interface':'new0','mtu':1300} for sid,cfg in self.old.items()}
        self.rebuild(new)
        self.assertEqual(new,self.live)
        first_create=next(i for i,x in enumerate(self.events) if x[1]=='create')
        self.assertEqual(2,sum(x[1]=='delete' for x in self.events[:first_create]))

    def test_unreachable_peer_never_stops_either_endpoint(self):
        self.fail=lambda sid,op,cfg:(_ for _ in ()).throw(RuntimeError('unreachable')) if sid=='peer' and op=='config' else None
        with self.assertRaisesRegex(RuntimeError,'unreachable'):self.rebuild()
        self.assertEqual(self.old,self.live)
        self.assertFalse(any(x[1]=='delete' for x in self.events))

    def test_invalid_second_config_never_stops_either_endpoint(self):
        self.fail=lambda sid,op,cfg:(_ for _ in ()).throw(ValueError('invalid')) if sid=='peer' and op=='validate' else None
        with self.assertRaisesRegex(ValueError,'invalid'):self.rebuild()
        self.assertEqual(self.old,self.live)

    def test_wrong_peer_addresses_are_rejected_before_teardown(self):
        new=copy.deepcopy(self.old);new['peer']['inner_peer']='10.251.1.1/30'
        with self.assertRaisesRegex(ValueError,'inverse'):self.rebuild(new)
        self.assertFalse(any(x[1]=='delete' for x in self.events))

    def test_failed_second_start_restores_both_old_configs(self):
        new={sid:{**cfg,'mtu':1300} for sid,cfg in self.old.items()}
        self.fail=lambda sid,op,cfg:(_ for _ in ()).throw(RuntimeError('start failed')) if op=='create' and sid=='local' and cfg['mtu']==1300 else None
        with self.assertRaisesRegex(RuntimeError,'هر دو سمت بازگردانده'):self.rebuild(new)
        self.assertEqual(self.old,self.live)

    def test_failed_cleanup_never_starts_new_configuration(self):
        count=[0]
        def fail(sid,op,cfg):
            if sid=='peer' and op=='delete' and not count[0]:count[0]+=1;raise RuntimeError('cleanup failed')
        self.fail=fail
        new={sid:{**cfg,'mtu':1300} for sid,cfg in self.old.items()}
        with self.assertRaisesRegex(RuntimeError,'cleanup failed'):self.rebuild(new)
        self.assertEqual(self.old,self.live)
        self.assertFalse(any(e[1]=='create' and e[2]['mtu']==1300 for e in self.events))

    def test_rollback_failure_keeps_private_recovery_journal(self):
        self.fail=lambda sid,op,cfg:(_ for _ in ()).throw(RuntimeError('start failed')) if op=='create' else None
        with self.assertRaisesRegex(RuntimeError,'بازگردانی ناقص'):self.rebuild()
        journal=next((self.api.BASE/'rebuild-journals').glob('*.json'))
        self.assertEqual(0o600,journal.stat().st_mode&0o777)
        saved=json.loads(journal.read_text());self.assertEqual(self.old,saved['previous'])

    def test_backhaul_reuses_secret_paths_and_ownership(self):
        self.old={sid:{'id':'demo','transport':'backhaul','mode':mode,'carrier':'tun','encapsulation':'ipx',
                  'secret_file':'/etc/backhaul/secrets/demo.psk','secret_managed':True,'manager':'Backhaul','tun_name':'bh9'}
                  for sid,mode in [('local','client'),('peer','server')]}
        self.live=copy.deepcopy(self.old);self.rebuild()
        for cfg in self.live.values():
            self.assertTrue(cfg['secret_managed'])
            self.assertEqual('/etc/backhaul/secrets/demo.psk',cfg['secret_file'])
            self.assertNotIn('manager',cfg)
        self.assertFalse(any(e[1]=='secret' for e in self.events))

    def test_duplicate_or_missing_endpoint_is_rejected(self):
        for ids in ([],['local'],['local','local'],['local','other'],['local',{}]):
            with self.assertRaises(ValueError):lifecycle.rebuild(self.api,'demo',ids)
        self.assertEqual([],self.events)


class ProfileCleanupChecks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.tmp.name)
        (self.base/'network').mkdir();self.path=self.base/'network/native-demo.json'
        self.cfg={'kind':'gre','interface':'tn9','inner_local':'10.250.0.1/30','inner_peer':'10.250.0.2/30','outer_local':'192.0.2.1','outer_peer':'192.0.2.2','mtu':1400}
        self.path.write_text(json.dumps(self.cfg));self.events=[]
        def path(value):return self.base if str(value)=='/etc/tunnelmgr' else pathlib.Path(value)
        self.patch=patch.object(profiles,'Path',side_effect=path);self.patch.start()

    def tearDown(self):self.patch.stop();self.tmp.cleanup()

    def test_delete_cleans_inactive_service_before_removing_config(self):
        def run(args,**kw):self.events.append(args);return types.SimpleNamespace(returncode=0,stdout='',stderr='')
        def cleanup(*args):
            self.assertTrue(self.path.exists());self.events.append('cleanup')
            self.assertEqual(('native-demo'),args[2])
        with patch.object(profiles.subprocess,'run',side_effect=run),patch.object(profiles,'apply',side_effect=cleanup),patch.object(profiles,'verify_tunnel_link'),patch.object(profiles,'remove_managed_link') as remove:
            self.assertTrue(profiles.manage({'group':'network','action':'delete'},'native-demo')['ok'])
        self.assertEqual(['systemctl','disable','--now','tunnelmgr-network@native-demo.service'],self.events[0])
        self.assertEqual('cleanup',self.events[1]);remove.assert_called_once_with('tn9','gre')
        self.assertFalse(self.path.exists())

    def test_stop_failure_preserves_old_profile_and_never_deletes_interface(self):
        with patch.object(profiles.subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stderr='stop failed')),patch.object(profiles,'apply') as apply,patch.object(profiles,'verify_tunnel_link'),patch.object(profiles,'remove_managed_link') as remove:
            with self.assertRaisesRegex(RuntimeError,'stop failed'):profiles.manage({'group':'network','action':'delete'},'native-demo')
        self.assertTrue(self.path.exists());apply.assert_not_called();remove.assert_not_called()

    def test_unverified_link_is_rejected_before_stopping_the_service(self):
        with patch.object(profiles,'verify_tunnel_link',side_effect=ValueError('physical interface')),patch.object(profiles.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'physical'):profiles.manage({'group':'network','action':'delete'},'native-demo')
        run.assert_not_called();self.assertTrue(self.path.exists())

    def test_ipsec_removes_the_host_address_not_the_original_subnet_mask(self):
        cfg={**self.cfg,'kind':'ipsec-ikev2'}
        with patch.object(network.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as run:
            network.apply(cfg,False,'native-demo')
        self.assertTrue(any(c.args[0]==['/usr/sbin/ip','address','del','10.250.0.1/32','dev','lo'] for c in run.call_args_list))

    def test_l2tp_missing_resources_are_idempotent_but_other_errors_are_not(self):
        with patch.object(network.subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stderr='RTNETLINK answers: No such device')):
            network.remove_l2tp('session','tunnel_id','1','session_id','2')
        with patch.object(network.subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stderr='Operation not permitted')):
            with self.assertRaisesRegex(RuntimeError,'permitted'):network.remove_l2tp('tunnel','tunnel_id','1')

    def test_l2tp_driver_is_verified_through_session_when_linkinfo_is_missing(self):
        exists=lambda p:str(p)=='/sys/class/net/l2x'
        results=[types.SimpleNamespace(returncode=0,stdout='[{"ifname":"l2x"}]'),
                 types.SimpleNamespace(returncode=0,stdout='[{"interface":"l2x","session_id":1}]')]
        with patch.object(pathlib.Path,'exists',autospec=True,side_effect=exists),patch.object(network.subprocess,'run',side_effect=results):
            network.verify_tunnel_link('l2x','l2tpv3')

    def test_auxiliary_vpn_stop_failure_is_not_ignored(self):
        results=[types.SimpleNamespace(returncode=1,stderr='stop failed'),
                 types.SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState=active')]
        with patch.object(network.subprocess,'run',side_effect=results):
            with self.assertRaisesRegex(RuntimeError,'stop failed'):network.stop_tunnel_unit('test-vpn.service')

    def test_never_created_auxiliary_vpn_unit_is_safe_to_clean(self):
        results=[types.SimpleNamespace(returncode=1,stderr='not found'),
                 types.SimpleNamespace(returncode=0,stdout='LoadState=not-found\nActiveState=inactive')]
        with patch.object(network.subprocess,'run',side_effect=results):network.stop_tunnel_unit('test-vpn.service')


class BackhaulCleanupChecks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
        def path(value):return pathlib.Path(value) if str(value).startswith(str(self.root)) else self.root/str(value).lstrip('/')
        self.patch=patch.object(privd,'Path',side_effect=path);self.patch.start()
        self.config=self.root/'etc/backhaul/demo.toml';self.unit=self.root/'etc/systemd/system/backhaul-demo.service'
        self.state=self.root/'var/lib/backhaul-manager/state.json'
        for f in (self.config,self.unit,self.state):f.parent.mkdir(parents=True,exist_ok=True)
        self.config.write_text('[tun]\nname = "bh9"\n');self.unit.write_text('managed')
        self.state.write_text(json.dumps({'tunnels':{'demo':{}}}))

    def tearDown(self):self.patch.stop();self.tmp.cleanup()

    def invoke(self,args,**kwargs):
        if args[0]=='delete':
            self.config.unlink();self.unit.unlink();self.state.write_text('{"tunnels":{}}')
        return types.SimpleNamespace(returncode=0,stdout='',stderr='')

    def test_unit_files_are_removed_before_interface_and_no_secret_is_deleted(self):
        def remove(name,kind):
            self.assertFalse(self.config.exists());self.assertFalse(self.unit.exists())
            self.assertEqual(('bh9','backhaul'),(name,kind))
        with patch.object(privd,'invoke',side_effect=self.invoke),patch.object(privd,'verify_tunnel_link'),patch.object(privd,'remove_managed_link',side_effect=remove):
            self.assertTrue(privd.delete_backhaul('demo')['ok'])
        self.assertFalse(list(self.root.glob('var/lib/backhaul-manager/removals/*.json')))

    def test_failed_interface_cleanup_is_retryable_after_unit_and_config_are_gone(self):
        with patch.object(privd,'invoke',side_effect=self.invoke),patch.object(privd,'verify_tunnel_link'),patch.object(privd,'remove_managed_link',side_effect=[RuntimeError('busy'),None]) as cleanup:
            with self.assertRaisesRegex(RuntimeError,'busy'):privd.delete_backhaul('demo')
            self.assertFalse(self.config.exists())
            self.assertTrue(privd.delete_backhaul('demo')['ok'])
        self.assertEqual(2,cleanup.call_count)

    def test_unowned_config_never_stops_service_or_removes_interface(self):
        with patch.object(privd,'invoke',return_value=types.SimpleNamespace(returncode=1,stdout='',stderr='unowned')) as invoke,patch.object(privd,'remove_managed_link') as remove:
            with self.assertRaisesRegex(RuntimeError,'unowned'):privd.delete_backhaul('demo')
        invoke.assert_called_once_with(['status','demo'],timeout=15)
        remove.assert_not_called();self.assertTrue(self.config.exists())

    def test_actual_owned_secret_is_preserved_without_returning_its_value(self):
        secret='test-actual-owned-backhaul-secret'
        self.config.write_text('[tun]\nname = "bh9"\n[security]\ntoken = "'+secret+'"\n')
        with patch.object(privd,'invoke',side_effect=self.invoke):result=privd.preserve_backhaul_secret('demo')
        path=pathlib.Path(result['secret_file'])
        self.assertEqual(secret,path.read_text().strip());self.assertEqual(0o600,path.stat().st_mode&0o777)
        self.assertNotIn(secret,json.dumps(result))


if __name__=='__main__':unittest.main(verbosity=2)
