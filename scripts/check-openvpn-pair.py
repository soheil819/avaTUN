#!/usr/bin/env python3
"""Check OpenVPN pair PKI, peer roles, address reversal and HAProxy eligibility."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tunnelmgr"))
import tunnelctl

created=[]
def remote(server,payload):
    if payload["op"]=="list":return {"items":[]}
    if payload["op"]=="create":created.append((server["id"],payload["data"]));return {"ok":True}
    raise AssertionError(payload)
def local(data):created.append(("local",data));return {"ok":True}

with patch.object(tunnelctl,"server_rows",return_value=[{"id":"fsn1","host":"198.51.100.2","user":"root","identity":"/unused"}]), \
     patch.object(tunnelctl,"rows",return_value=[]), \
     patch.object(tunnelctl,"server_remote",side_effect=remote), \
     patch.object(tunnelctl,"create_native",side_effect=local), \
     patch.object(tunnelctl.shutil,"which",return_value=shutil.which("openssl")):
    result=tunnelctl.create_openvpn_pair({"id":"ovpn-check","server_a":"local","server_b":"fsn1","host_a":"198.51.100.1","host_b":"198.51.100.2","inner_local":"10.246.0.1/30","inner_peer":"10.246.0.2/30","interface":"ovpn-check-a","peer_interface":"ovpn-check-b","port":1194,"mtu":1400,"direction":"direct"})

assert result["ok"] and result["transport"]=="openvpn" and result["udp_port"]==1194
assert [item[0] for item in created]==["local","fsn1"]
a,b=[item[1] for item in created]
assert a["role"]=="client" and b["role"]=="server"
assert (a["inner_local"],a["inner_peer"])==("10.246.0.1/30","10.246.0.2/30")
assert (b["inner_local"],b["inner_peer"])==("10.246.0.2/30","10.246.0.1/30")
assert a["outer_peer"]=="198.51.100.2" and b["outer_peer"]=="198.51.100.1"
assert a["peer_common_name"]==b["common_name"] and b["peer_common_name"]==a["common_name"]
with patch.object(tunnelctl,"server_rows",return_value=[{"id":"fsn1","host":"198.51.100.2","user":"root","identity":"/unused"}]), \
     patch.object(tunnelctl,"rows",return_value=[{"id":"other","metadata":{"tun_local":"10.246.0.1/30"}}]), \
     patch.object(tunnelctl,"server_remote",side_effect=remote), \
     patch.object(tunnelctl.shutil,"which",return_value=shutil.which("openssl")):
    try:
        tunnelctl.create_openvpn_pair({"id":"ovpn-collision","server_a":"local","server_b":"fsn1","host_a":"198.51.100.1","host_b":"198.51.100.2","inner_local":"10.246.0.1/30","inner_peer":"10.246.0.2/30","port":1194,"direction":"direct"})
    except ValueError as error:
        assert "already belongs" in str(error)
    else:
        raise AssertionError("duplicate OpenVPN inner address was accepted")
with tempfile.TemporaryDirectory(prefix="tm-openvpn-check-") as tmp:
    root=pathlib.Path(tmp)
    ca=root/"ca.crt";server=root/"server.crt";client=root/"client.crt"
    ca.write_text(a["ca_cert"]);server.write_text(b["cert"]);client.write_text(a["cert"])
    subprocess.run([shutil.which("openssl"),"verify","-purpose","sslserver","-CAfile",str(ca),str(server)],check=True,capture_output=True)
    subprocess.run([shutil.which("openssl"),"verify","-purpose","sslclient","-CAfile",str(ca),str(client)],check=True,capture_output=True)
with patch.object(tunnelctl,"rows",return_value=[{"id":"ovpn-check","metadata":{"transport":"openvpn","tun_remote":"10.246.0.2/30"}}]):
    rule=tunnelctl.normalize_forward({"id":"ovpn-web","listen_ip":"198.51.100.1","listen_port":443,"backend_port":443,"algorithm":"leastconn","backends":[{"tunnel_id":"ovpn-check","weight":1}]},"local")
assert rule["backends"][0]["address"]=="10.246.0.2"
print("OpenVPN PKI, client/server pairing, peer addresses and port-forward backend: PASS")
