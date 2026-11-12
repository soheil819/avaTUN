#!/usr/bin/env python3
"""Verify bidirectional traffic for Linux native tunnels in disposable netns."""
import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tunnelmgr'))
from network import apply

prefix='tmtraffic'+str(__import__('os').getpid())
nodes=('a','b')

def cmd(*args):
    return subprocess.run(args,check=True,text=True,capture_output=True).stdout

def ip(node,*args):
    return cmd('ip','netns','exec',prefix+node,'/usr/sbin/ip',*args)

def apply_in(node,cfg,up):
    cmd('ip','netns','exec',prefix+node,sys.executable,'-c',
        'import sys,json;sys.path.insert(0,sys.argv[1]);from network import apply;apply(json.loads(sys.argv[2]),sys.argv[3]=="up")',
        str(ROOT/'tunnelmgr'),json.dumps(cfg), 'up' if up else 'down')

def ping(node,dst,ipv6=False,source=None):
    args=['ping','-6' if ipv6 else '-4','-n','-q','-c','3','-W','2']
    if source:args+=['-I',source]
    args+=[dst]
    cmd('ip','netns','exec',prefix+node,*args)

def stats(node,dev):
    row=json.loads(ip(node,'-j','-s','link','show','dev',dev))[0]
    return row.get('stats64',row.get('stats',{}))

configs=[]
try:
    cmd('modprobe','fou')
    for n in nodes:cmd('ip','netns','add',prefix+n)
    cmd('ip','-n',prefix+'a','link','add','wan0','type','veth','peer','name','wan1','netns',prefix+'b')
    for n,dev,addr in [('a','wan0','192.0.2.1/30'),('b','wan1','192.0.2.2/30')]:
        cmd('ip','-n',prefix+n,'link','set','lo','up')
        cmd('ip','-n',prefix+n,'addr','add',addr,'dev',dev)
        cmd('ip','-n',prefix+n,'link','set',dev,'up')

    cases=[
        ('gre','ipv4',{}),('gre','ipv4',{'key':4291}),('ipip','ipv4',{}),
        ('gretap','ipv4',{}),('geneve','ipv4',{'vni':8101}),('vxlan','ipv4',{'vni':8102}),
        ('gre-fou','ipv4',{'fou_port':5501}),('ipip-fou','ipv4',{'fou_port':5502}),
        ('sit-fou','ipv6',{'fou_port':5503}),('l2tpv3','ipv4',{'tunnel_id':8101,'peer_tunnel_id':8102,'session_id':811,'peer_session_id':812,'encap':'udp','udp_sport':5811,'udp_dport':5812}),
        ('sit-6to4','6to4',{}),('sit-isatap','isatap',{}),
    ]
    if __import__('os').environ.get('ONLY'):
        cases=[case for case in cases if case[0]==__import__('os').environ['ONLY']]
    for idx,(kind,family,extra) in enumerate(cases):
        left='t%02da'%idx;right='t%02db'%idx
        a={'kind':kind,'interface':left,'outer_local':'192.0.2.1','outer_peer':'192.0.2.2','mtu':1400,**extra}
        b={'kind':kind,'interface':right,'outer_local':'192.0.2.2','outer_peer':'192.0.2.1','mtu':1400,**extra}
        if family=='ipv4':
            a.update(inner_local='10.250.%d.1/30'%idx,inner_peer='10.250.%d.2/30'%idx)
            b.update(inner_local='10.250.%d.2/30'%idx,inner_peer='10.250.%d.1/30'%idx)
        elif family=='ipv6':
            a.update(inner_local='2001:db8:55:%x::1/64'%idx,inner_peer='2001:db8:55:%x::2/64'%idx)
            b.update(inner_local='2001:db8:55:%x::2/64'%idx,inner_peer='2001:db8:55:%x::1/64'%idx)
        elif family=='6to4':
            a['inner_local']=a['inner_peer']=''
            b['inner_local']=b['inner_peer']=''
        elif family=='isatap':
            a.update(inner_local='2001:db8:55::5efe:c000:201/64',inner_peer='2001:db8:55::5efe:c000:202/64')
            b.update(inner_local='2001:db8:55::5efe:c000:202/64',inner_peer='2001:db8:55::5efe:c000:201/64')
        if kind=='l2tpv3':
            b.update(tunnel_id=extra['peer_tunnel_id'],peer_tunnel_id=extra['tunnel_id'],session_id=extra['peer_session_id'],peer_session_id=extra['session_id'])
            b.update(udp_sport=extra['udp_dport'],udp_dport=extra['udp_sport'])
        configs.append((kind,family,a,b))

    for kind,family,a,b in configs:
        if family=='6to4':
            # 6to4 derives each local address from its outer IPv4 endpoint.
            a.pop('inner_local');a.pop('inner_peer');b.pop('inner_local');b.pop('inner_peer')
        # FoU listeners are namespace-local, so both endpoints use the same UDP port.
        apply_in('a',a,True);apply_in('b',b,True)
        if family=='6to4':
            target='2002:c000:202::1';ping('a',target,ipv6=True)
        elif family=='isatap':
            dst='2001:db8:55::5efe:c000:202'
            print('ISATAP route:',ip('a','-6','route','get',dst).strip())
            print('ISATAP addresses:',ip('a','-6','addr','show','dev',a['interface']).strip())
            cmd('ip','netns','exec',prefix+'a','sleep','2')
            ping('a',dst,ipv6=True,source='2001:db8:55::5efe:c000:201')
        elif family=='ipv6':
            ping('a',a['inner_peer'].split('/')[0],ipv6=True,source=a['inner_local'].split('/')[0])
        else:
            ping('a',a['inner_peer'].split('/')[0],source=a['inner_local'].split('/')[0])
        apply_in('b',b,False);apply_in('a',a,False)
        print(kind+(' (GRE key)' if kind=='gre' and a.get('key') else '')+': bidirectional data path OK')

    # ERSPAN is one-way traffic mirroring, not a bidirectional IP tunnel.
    cmd('ip','-n',prefix+'a','link','add','src0','type','veth','peer','name','sink0')
    for dev,addr in [('src0','198.18.0.1/30'),('sink0','198.18.0.2/30')]:
        cmd('ip','-n',prefix+'a','addr','add',addr,'dev',dev);cmd('ip','-n',prefix+'a','link','set',dev,'up')
    ea={'kind':'erspan','interface':'erspanA','outer_local':'192.0.2.1','outer_peer':'192.0.2.2','erspan_index':17,'erspan_key':23,'mirror_interface':'src0','mtu':1400}
    eb={'kind':'erspan','interface':'erspanB','outer_local':'192.0.2.2','outer_peer':'192.0.2.1','erspan_index':17,'erspan_key':23,'mtu':1400}
    apply_in('a',ea,True);apply_in('b',eb,True)
    before=stats('b','erspanB').get('rx',{}).get('packets',0)
    ping('a','198.18.0.2',source='198.18.0.1')
    after=stats('b','erspanB').get('rx',{}).get('packets',0)
    if after<=before:raise RuntimeError('ERSPAN receiver saw no mirrored packets')
    apply_in('b',eb,False);apply_in('a',ea,False)
    print('erspan: mirrored packets received OK')
except Exception as e:
    print('traffic check failed:',e,file=sys.stderr)
    if isinstance(e,subprocess.CalledProcessError):print(e.stderr or e.stdout or '',file=sys.stderr)
    raise
finally:
    for kind,family,a,b in reversed(configs):
        for node,cfg in [('b',b),('a',a)]:
            try:apply_in(node,cfg,False)
            except Exception:pass
    for n in nodes:subprocess.run(['ip','netns','del',prefix+n],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
