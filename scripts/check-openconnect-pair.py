#!/usr/bin/env python3
"""Check OpenConnect pair certificates, fixed single-client /30 lease and HAProxy targeting."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"tunnelmgr"))
import tunnelctl
import profiles
import network

created=[]
def remote(server,payload):
    if payload['op']=='list':return {'items':[]}
    if payload['op']=='create':created.append((server['id'],payload['data']));return {'ok':True}
    raise AssertionError(payload)
def local(data):created.append(('local',data));return {'ok':True}

request={'id':'oc-check','server_a':'local','server_b':'fsn1','host_a':'198.51.100.1','host_b':'198.51.100.2',
         'inner_local':'10.247.0.2/30','inner_peer':'10.247.0.1/30','interface':'occa','peer_interface':'occb','port':4443,'mtu':1350,'direction':'direct'}
with patch.object(tunnelctl,'server_rows',return_value=[{'id':'fsn1','host':'198.51.100.2','user':'root','identity':'/unused'}]), \
     patch.object(tunnelctl,'rows',return_value=[]),patch.object(tunnelctl,'server_remote',side_effect=remote), \
     patch.object(tunnelctl,'create_native',side_effect=local),patch.object(tunnelctl.shutil,'which',return_value=shutil.which('openssl')):
    result=tunnelctl.create_openconnect_pair(request)

assert result['ok'] and result['transport']=='openconnect' and result['pool']=='10.247.0.0/30' and result['tcp_udp_port']==4443
assert [x[0] for x in created]==['local','fsn1']
client,server=[x[1] for x in created]
assert client['role']=='client' and server['role']=='server'
assert (client['inner_local'],client['inner_peer'])==('10.247.0.2/30','10.247.0.1/30')
assert (server['inner_local'],server['inner_peer'])==('10.247.0.1/30','10.247.0.2/30')
assert client['peer_common_name']==server['common_name'] and server['peer_common_name']==client['common_name']
profiles.validate('network',{'kind':'openconnect',**server})
profiles.validate('network',{'kind':'openconnect',**client})
server_config,user_config=network.openconnect_server_config(server,'occb','/etc/tunnelmgr/openconnect/oc-check','/etc/tunnelmgr/openconnect/oc-check/users','/run/tunnelmgr-ocserv-oc-check')
assert 'ipv4-netmask = 255.255.255.252' in server_config
assert 'ipv4-network = 10.247.0.0\nipv4-netmask = 255.255.255.252' in user_config
created.clear()
with patch.object(tunnelctl,'server_rows',return_value=[{'id':'fsn1','host':'198.51.100.2','user':'root','identity':'/unused'}]), \
     patch.object(tunnelctl,'rows',return_value=[]),patch.object(tunnelctl,'server_remote',side_effect=remote), \
     patch.object(tunnelctl,'create_native',side_effect=local),patch.object(tunnelctl.shutil,'which',return_value=shutil.which('openssl')):
    reverse=tunnelctl.create_openconnect_pair({**request,'id':'oc-reverse','direction':'reverse'})
assert reverse['ok'] and created[0][1]['role']=='server' and created[1][1]['role']=='client'
assert created[0][1]['inner_local']=='10.247.0.1/30' and created[1][1]['inner_local']=='10.247.0.2/30'
with tempfile.TemporaryDirectory(prefix='tm-openconnect-check-') as tmp:
    root=pathlib.Path(tmp);ca=root/'ca.crt';server_cert=root/'server.crt';client_cert=root/'client.crt'
    ca.write_text(server['ca_cert']);server_cert.write_text(server['cert']);client_cert.write_text(client['cert'])
    openssl=shutil.which('openssl')
    subprocess.run([openssl,'verify','-purpose','sslserver','-CAfile',str(ca),str(server_cert)],check=True,capture_output=True)
    subprocess.run([openssl,'verify','-purpose','sslclient','-CAfile',str(ca),str(client_cert)],check=True,capture_output=True)
with patch.object(tunnelctl,'rows',return_value=[{'id':'oc-check','metadata':{'transport':'openconnect','tun_remote':'10.247.0.0/31'}}]):
    rule=tunnelctl.normalize_forward({'id':'oc-web','listen_ip':'198.51.100.1','listen_port':443,'backend_port':443,'algorithm':'leastconn','backends':[{'tunnel_id':'oc-check','weight':1}]},'local')
assert rule['backends'][0]['address']=='10.247.0.0'
print('OpenConnect PKI, single-client /30 assignment, profile validation and HAProxy target: PASS')
