#!/usr/bin/env python3
"""Exercise native tunnel creation in disposable Linux network namespaces."""
import ipaddress
import json
import subprocess
import sys
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tunnelmgr"))
from network import apply

prefix = "tunnelcheck"

def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

try:
    command("modprobe", "fou")
    for node in ("a", "b"):
        command("ip", "netns", "add", prefix + node)
    command("ip", "-n", prefix+"a", "link", "add", "veth-a", "type", "veth", "peer", "name", "veth-b", "netns", prefix+"b")
    command("ip", "-n", prefix+"a", "addr", "add", "192.0.2.1/30", "dev", "veth-a")
    command("ip", "-n", prefix+"b", "addr", "add", "192.0.2.2/30", "dev", "veth-b")
    for node, dev in (("a", "veth-a"), ("b", "veth-b")):
        command("ip", "-n", prefix+node, "link", "set", "lo", "up")
        command("ip", "-n", prefix+node, "link", "set", dev, "up")

    cases = [
        ("gre", dict(inner_local="10.249.0.1/30", inner_peer="10.249.0.2/30")),
        ("gretap", dict(inner_local="10.249.0.1/30", inner_peer="10.249.0.2/30")),
        ("ipip", dict(inner_local="10.249.0.1/30", inner_peer="10.249.0.2/30")),
        ("geneve", dict(vni=123)), ("vxlan", dict(vni=123)),
        ("erspan", dict(erspan_index=7,erspan_key=11)),
        ("sit-6to4", {}),
        ("sit-isatap", dict(inner_local="2001:db8:1::1/64")),
        ("gre-fou", dict(inner_local="10.249.0.1/30", inner_peer="10.249.0.2/30", fou_port=5555)),
        ("ipip-fou", dict(inner_local="10.249.0.1/30", inner_peer="10.249.0.2/30", fou_port=5556)),
        ("sit-fou", dict(inner_local="10.249.0.1/30", inner_peer="10.249.0.2/30", fou_port=5557)),
        ("l2tpv3", dict(inner_local="10.249.0.1/30", tunnel_id=1001, peer_tunnel_id=2001, session_id=101, peer_session_id=201, encap='udp',udp_sport=5001,udp_dport=5002)),
    ]
    if shutil.which("wg"):
        def wgkey(*args, input=None):
            return subprocess.run(["wg",*args],input=input,capture_output=True,text=True,check=True).stdout.strip()
        priv_a,priv_b,psk=wgkey("genkey"),wgkey("genkey"),wgkey("genpsk")
        pub_a,pub_b=wgkey("pubkey",input=priv_a+"\n"),wgkey("pubkey",input=priv_b+"\n")
        cases.append(("wireguard",dict(private_key=priv_a,peer_public_key=pub_b,preshared_key=psk,listen_port=51820,endpoint_port=51820,keepalive=0)))
    for index, (kind, extra) in enumerate(cases):
        configs = []
        for node, local, peer in (("a", "192.0.2.1", "192.0.2.2"), ("b", "192.0.2.2", "192.0.2.1")):
            cfg = dict(kind=kind, interface="t%02d%s"%(index,node), outer_local=local, outer_peer=peer, mtu=1400, **extra)
            if kind=='wireguard':
                cfg['private_key'],cfg['peer_public_key']=(priv_a,pub_b) if node=='a' else (priv_b,pub_a)
                cfg['inner_local']="10.249.0.%s/30"%('1' if node=='a' else '2')
                cfg['inner_peer']="10.249.0.%s/30"%('2' if node=='a' else '1')
            if kind=='l2tpv3':
                cfg['inner_local']='10.249.0.%s/30'%('1' if node=='a' else '2')
                if node=='b':
                    cfg['tunnel_id'],cfg['peer_tunnel_id']=cfg['peer_tunnel_id'],cfg['tunnel_id']
                    cfg['session_id'],cfg['peer_session_id']=cfg['peer_session_id'],cfg['session_id']
            if "inner_local" in extra:
                if kind=='sit-isatap':cfg["inner_local"]="2001:db8:1::%s/64"%('1' if node=='a' else '2')
                else:
                    cfg["inner_local"] = "10.249.0.%s/30"% ("1" if node=="a" else "2")
                    cfg["inner_peer"] = "10.249.0.%s/30"% ("2" if node=="a" else "1")
            configs.append((node,cfg))
        if kind.endswith('-fou'):
            configs=configs[:1]
        for node,cfg in configs:
            subprocess.run(["ip","netns","exec",prefix+node,sys.executable,"-c",
              "import sys,json;sys.path.insert(0,sys.argv[1]);from network import apply;apply(json.loads(sys.argv[2]),True)",
              str(Path(__file__).resolve().parents[1]/"tunnelmgr"),json.dumps(cfg)],check=True)
        if kind=='wireguard':
            for node,peer in (("a","10.249.0.2"),("b","10.249.0.1")):
                subprocess.run(["ip","netns","exec",prefix+node,"ping","-n","-c","2","-W","2",peer],check=True,stdout=subprocess.DEVNULL)
        for node,cfg in reversed(configs):
            subprocess.run(["ip","netns","exec",prefix+node,sys.executable,"-c",
              "import sys,json;sys.path.insert(0,sys.argv[1]);from network import apply;apply(json.loads(sys.argv[2]),False)",
              str(Path(__file__).resolve().parents[1]/"tunnelmgr"),json.dumps(cfg)],check=True)
        print(kind+": create/delete ok")
finally:
    for node in ("a", "b"):
        subprocess.run(["ip","netns","del",prefix+node],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
