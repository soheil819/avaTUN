#!/usr/bin/env python3
"""Check paired routing deployment, persistence, cleanup and remote worker syntax."""
import json
import pathlib
import shlex
import sqlite3
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tunnelmgr'))
import tunnelctl

local={'id':'link1','metadata':{'transport':'gre','tun_local':'10.0.0.1/30','tun_remote':'10.0.0.2/30','tun_name':'gre0','outer_local':'198.51.100.1'}}
remote_tunnel={'id':'link1','metadata':{'transport':'gre','tun_local':'10.0.0.2/30','tun_remote':'10.0.0.1/30','tun_name':'gre0','outer_local':'198.51.100.2'}}
remote_profiles=[];local_profiles=[]
def remote(server,payload):
    if payload['op']=='list':return {'items':[remote_tunnel]}
    if payload['op']=='routing-profile-create':remote_profiles.append(payload);return {'ok':True}
    if payload['op']=='routing-profile-delete':return {'ok':True}
    raise AssertionError(payload)
def privileged(req):
    if req.get('op')=='profile' and req.get('action')=='create':local_profiles.append(req['config'])
    return {'ok':True}

with tempfile.TemporaryDirectory(prefix='tm-routing-pair-') as tmp:
    with patch.object(tunnelctl,'BASE',pathlib.Path(tmp)),patch.object(tunnelctl,'DB',pathlib.Path(tmp)/'db.sqlite'), \
         patch.object(tunnelctl,'server_rows',return_value=[{'id':'fsn1','host':'198.51.100.2','user':'root','identity':'/unused'}]), \
         patch.object(tunnelctl,'rows',return_value=[local]),patch.object(tunnelctl,'server_remote',side_effect=remote),patch.object(tunnelctl,'privileged',side_effect=privileged):
        tunnelctl.db().close()
        result=tunnelctl.create_routing_pair({'id':'corp','protocol':'bgp','tunnel_id':'link1','server_a':'local','server_b':'fsn1','asn_a':65001,'asn_b':65002,'networks_a':'10.20.0.0/24','networks_b':'10.30.0.0/24'})
        assert result['ok'] and len(local_profiles)==1 and len(remote_profiles)==1
        assert local_profiles[0]['peer_ip']=='10.0.0.2' and remote_profiles[0]['config']['peer_ip']=='10.0.0.1'
        assert local_profiles[0]['networks']==['10.20.0.0/24'] and remote_profiles[0]['config']['networks']==['10.30.0.0/24']
        routed_rule=tunnelctl.normalize_forward({'id':'routed-web','listen_ip':'198.51.100.1','listen_port':443,'backend_port':443,'algorithm':'leastconn','backends':[{'tunnel_id':'link1','address':'10.30.0.25','weight':1}]},'local')
        assert routed_rule['backends'][0]['address']=='10.30.0.25'
        try:tunnelctl.normalize_forward({'id':'bad-web','listen_ip':'198.51.100.1','listen_port':8443,'backend_port':443,'algorithm':'leastconn','backends':[{'tunnel_id':'link1','address':'10.31.0.25','weight':1}]},'local')
        except ValueError as error:assert 'not advertised' in str(error)
        else:raise AssertionError('HAProxy accepted a backend outside the BGP peer prefixes')
        with patch.object(tunnelctl,'routing_status',return_value={'state':'up'}):
            assert tunnelctl.routing_rows()[0]['status_a']['state']=='up'
        assert tunnelctl.delete_routing_link('corp')['ok']

server={'id':'fsn1','host':'198.51.100.2','user':'root','identity':'/unused'}
with patch.object(tunnelctl.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'{}','')) as run:
    tunnelctl.server_remote(server,{'op':'routing-status','profile':'route-corp'})
    remote_shell=run.call_args.args[0][-1]
    code=shlex.split(remote_shell)[-1]
    compile(code,'remote-routing-worker','exec')
print('Paired route profiles, per-side prefixes, status/delete and remote worker syntax: PASS')
