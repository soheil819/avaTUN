#!/usr/bin/env python3
"""Exercise WireGuard pair orchestration without touching host networking."""
import base64
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tunnelmgr"))
import tunnelctl


def key(seed):
    return base64.b64encode(bytes([seed]) * 32).decode()


class Result:
    def __init__(self, stdout): self.stdout=stdout


commands=[];created=[];counter=0
def fake_run(args, **kwargs):
    global counter
    if args[-1]=="genkey":
        counter+=1;return Result(key(counter))
    if args[-1]=="genpsk":return Result(key(99))
    if args[-1]=="pubkey":
        private=kwargs["input"].strip();return Result("pub-"+private)
    raise AssertionError(args)

def fake_remote(server,payload):
    if payload["op"]=="list":return {"items":[]}
    if payload["op"]=="create":created.append((server["id"],payload["data"]));return {"ok":True}
    raise AssertionError(payload)

def fake_local(data):created.append(("local",data));return {"ok":True}


with patch.object(tunnelctl,"server_rows",return_value=[{"id":"fsn1","host":"198.51.100.2","user":"root","identity":"/unused"}]), \
     patch.object(tunnelctl,"rows",return_value=[]), \
     patch.object(tunnelctl,"server_remote",side_effect=fake_remote), \
     patch.object(tunnelctl,"create_native",side_effect=fake_local), \
     patch.object(tunnelctl.shutil,"which",return_value="/usr/bin/wg"), \
     patch.object(tunnelctl.subprocess,"run",side_effect=fake_run):
    result=tunnelctl.create_wireguard_pair({"id":"wg-check","server_a":"local","server_b":"fsn1","host_a":"198.51.100.1","host_b":"198.51.100.2","inner_local":"10.245.0.1/30","inner_peer":"10.245.0.2/30","interface":"wg-check-a","peer_interface":"wg-check-b","port":51820,"mtu":1400,"keepalive":25})

assert result["ok"] and result["transport"]=="wireguard" and result["udp_port"]==51820
assert [x[0] for x in created]==["local","fsn1"]
a,b=[x[1] for x in created]
assert a["private_key"]==key(1) and b["private_key"]==key(2)
assert a["peer_public_key"]=="pub-"+key(2) and b["peer_public_key"]=="pub-"+key(1)
assert a["preshared_key"]==b["preshared_key"]==key(99)
assert (a["inner_local"],a["inner_peer"])==("10.245.0.1/30","10.245.0.2/30")
assert (b["inner_local"],b["inner_peer"])==("10.245.0.2/30","10.245.0.1/30")
assert a["outer_peer"]=="198.51.100.2" and b["outer_peer"]=="198.51.100.1"
with patch.object(tunnelctl,"rows",return_value=[{"id":"wg-check","metadata":{"transport":"wireguard","tun_remote":"10.245.0.2/30"}}]):
    rule=tunnelctl.normalize_forward({"id":"wg-web","listen_ip":"198.51.100.1","listen_port":443,"backend_port":443,"algorithm":"leastconn","backends":[{"tunnel_id":"wg-check","weight":1}]},"local")
assert rule["backends"][0]["address"]=="10.245.0.2"
print("WireGuard paired key exchange, peer reversal and endpoint wiring: PASS")
print("HAProxy backend resolution through WireGuard peer address: PASS")
