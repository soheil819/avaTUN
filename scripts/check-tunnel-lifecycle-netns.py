#!/usr/bin/env python3
"""Linux-only, root: rebuild test tunnels in disposable network namespaces."""
import json, pathlib, secrets, shutil, subprocess, sys
prefix='al'+secrets.token_hex(4);a=prefix+'a';b=prefix+'b';created=[];source=pathlib.Path(__file__).resolve().parents[1]/'tunnelmgr'
def run(*args,**kwargs):
    try:return subprocess.run(list(args),check=True,capture_output=True,text=True,**kwargs)
    except subprocess.CalledProcessError as error:
        print(error.stderr,flush=True);raise
def apply(ns,cfg,up):
    code="import sys,json;sys.path.insert(0,sys.argv[1]);from network import apply,remove_managed_link;c=json.loads(sys.argv[2]);apply(c,sys.argv[3]=='up','test');\nif sys.argv[3]=='down':remove_managed_link(c['interface'],c['kind'])"
    return run('ip','netns','exec',ns,'python3','-c',code,str(source),json.dumps(cfg),'up' if up else 'down')
try:
    for ns in (a,b):
        run('ip','netns','add',ns);created.append(ns);run('ip','-n',ns,'link','set','lo','up')
    run('ip','-n',a,'link','add','uplink','type','veth','peer','name','uplink','netns',b)
    for ns,addr in ((a,'192.0.2.1/30'),(b,'192.0.2.2/30')):
        run('ip','-n',ns,'address','add',addr,'dev','uplink');run('ip','-n',ns,'link','set','uplink','up')
    kinds=['gre','ipip','gre-fou','ipip-fou','l2tpv3']
    for module in ('ip_gre','ipip','fou','l2tp_eth','l2tp_netlink','wireguard'):
        subprocess.run(['modprobe',module],capture_output=True)
    keys={}
    if shutil.which('wg'):
        for ns in (a,b):
            key=run('wg','genkey').stdout.strip();keys[ns]=(key,run('wg','pubkey',input=key+'\n').stdout.strip())
        kinds.append('wireguard')
    for i,kind in enumerate(kinds):
        name='c'+prefix[2:]+str(i)
        cfgs=[]
        for ns,outer,peer,local,remote,other in ((a,'192.0.2.1','192.0.2.2','10.253.245.1/30','10.253.245.2/30',b),(b,'192.0.2.2','192.0.2.1','10.253.245.2/30','10.253.245.1/30',a)):
            cfg={'kind':kind,'interface':name,'outer_local':outer,'outer_peer':peer,'inner_local':local,'inner_peer':remote,'mtu':1400}
            if kind.endswith('-fou'):cfg['fou_port']=15555
            if kind=='l2tpv3':cfg.update(tunnel_id=101 if ns==a else 102,peer_tunnel_id=102 if ns==a else 101,session_id=201 if ns==a else 202,peer_session_id=202 if ns==a else 201,encap='udp',udp_sport=15556,udp_dport=15556)
            if kind=='wireguard':cfg.update(private_key=keys[ns][0],peer_public_key=keys[other][1],listen_port=15557,endpoint_port=15557,keepalive=1)
            cfgs.append((ns,cfg))
        for cycle in range(2):
            for ns,cfg in cfgs:apply(ns,cfg,True)
            run('ip','netns','exec',a,'ping','-n','-c','2','-W','2','10.253.245.2')
            for ns,cfg in cfgs:apply(ns,cfg,False);apply(ns,cfg,False)
        print(kind+': two rebuild cycles, ping and idempotent cleanup PASS',flush=True)
    bad={**cfgs[0][1],'kind':'gre','interface':'uplink'}
    try:apply(a,bad,False)
    except subprocess.CalledProcessError as error:
        assert 'Refusing to remove' in error.stderr
    else:raise AssertionError('The outer interface was not protected')
    run('ip','-n',a,'link','show','dev','uplink')
    print('outer interface ownership/type guard PASS',flush=True)
finally:
    for ns in created:subprocess.run(['ip','netns','del',ns],capture_output=True)
