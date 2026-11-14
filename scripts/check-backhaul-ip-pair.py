#!/usr/bin/env python3
import unittest,sys,copy,ipaddress
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tunnelmgr'))
import tunnelctl as t
class PairChecks(unittest.TestCase):
 def execute(self,fail=None,occupied=False):
  self.calls=[];self.created=[]
  configs={sid:{'mode':mode,'carrier':'tun','tun_carrier':'tcpmux','encapsulation':'tcp'} for sid,mode in [('local','client'),('peer','server')]}
  def remote(server,payload):
   self.calls.append(('peer',payload['op']))
   if payload['op']=='create':self.created.append(copy.deepcopy(payload['data']))
   return {'ok':True}
  def local(cfg):
   self.calls.append(('local','create'));self.created.append(copy.deepcopy(cfg))
   if fail:raise RuntimeError('local failed')
   return {}
  snap={'items':[{'id':'test'}] if occupied else [],'network':{'interfaces':['eth0'],'networks':['10.240.0.0/16','172.30.0.0/16','192.168.240.0/24']}}
  with patch.object(t,'server_rows',return_value=[{'id':'peer'}]),patch.object(t,'allocation_snapshot',return_value=snap),patch.object(t,'server_remote',side_effect=remote),patch.object(t,'validate_tunnel_config',side_effect=lambda cfg:self.calls.append(('local','validate'))),patch.object(t,'create_instance',side_effect=local),patch.object(t,'remove_tunnel_endpoint',side_effect=lambda ident:self.calls.append(('local','delete'))):
   return t.create_backhaul_pair({'id':'test','servers':['local','peer'],'configs':configs})
 def test_addresses_are_real_inverse_private_peers_and_avoid_routes(self):
  result=self.execute();a=result['configs']['local'];b=result['configs']['peer'];self.assertEqual(a['tun_local'],b['tun_remote']);self.assertEqual(a['tun_remote'],b['tun_local']);self.assertEqual(a['tun_name'],b['tun_name']);self.assertNotEqual(a['tun_name'],'eth0')
  net=ipaddress.ip_interface(a['tun_local']).network
  self.assertTrue(net.is_private)
  for old in ('10.240.0.0/16','172.30.0.0/16','192.168.240.0/24'):self.assertFalse(net.overlaps(ipaddress.ip_network(old)))
  self.assertLess(self.calls.index(('local','validate')),self.calls.index(('peer','create')))
  self.assertLess(self.calls.index(('peer','create')),self.calls.index(('local','create')))
 def test_existing_id_causes_no_remote_mutations(self):
  with self.assertRaisesRegex(ValueError,'already exists'):self.execute(occupied=True)
  self.assertEqual(self.calls,[])
 def test_second_endpoint_failure_removes_both_attempted_sides(self):
  with self.assertRaisesRegex(RuntimeError,'local failed'):self.execute(fail=True)
  self.assertEqual(self.calls[-2:],[('local','delete'),('peer','operate')])
if __name__=='__main__':unittest.main()
