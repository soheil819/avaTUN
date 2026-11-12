"""FRR BGP/OSPF configuration helpers for tunnel-bound IPv4 routing."""
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

RUN_DIR=pathlib.Path(os.environ.get('TUNNELMGR_RUNTIME_DIR','/run/tunnelmgr-netstate'))


def validate(cfg):
    protocol=cfg.get('protocol')
    if protocol not in ('bgp','ospf'):raise ValueError('routing protocol must be bgp or ospf')
    interface=cfg.get('interface','')
    if not re.fullmatch(r'[A-Za-z0-9_]{1,15}',interface):raise ValueError('invalid routing interface')
    local=ipaddress.IPv4Address(cfg.get('local_ip',''))
    peer=ipaddress.IPv4Address(cfg.get('peer_ip',''))
    if local==peer:raise ValueError('local and peer tunnel addresses must differ')
    if not local.is_private or not peer.is_private:raise ValueError('dynamic routing peers must use private tunnel addresses')
    ipaddress.IPv4Address(cfg.get('router_id',''))
    ipaddress.IPv4Address(cfg.get('peer_router_id',''))
    networks=cfg.get('networks')
    peer_networks=cfg.get('peer_networks')
    if not isinstance(networks,list) or not networks or len(networks)>32:raise ValueError('advertise at least one and at most 32 local prefixes')
    if not isinstance(peer_networks,list) or not peer_networks or len(peer_networks)>32:raise ValueError('provide at least one and at most 32 expected peer prefixes')
    for value in networks+peer_networks:
        net=ipaddress.IPv4Network(value,strict=True)
        if not any(net.subnet_of(ipaddress.IPv4Network(x)) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):raise ValueError('only RFC1918 prefixes may be exchanged by this panel')
    if protocol=='bgp':
        for field in ('local_asn','peer_asn'):
            if type(cfg.get(field)) is not int or not 1<=cfg[field]<=4294967295:raise ValueError('BGP ASNs must be between 1 and 4294967295')
    else:
        ipaddress.IPv4Address(cfg.get('area','0.0.0.0'))
    return True


def _names(cfg):
    tag=hashlib.sha256(cfg['id'].encode()).hexdigest()[:10].upper()
    sequence=10+(int(tag[:4],16)%5900)*10
    return 'TM'+tag+'I','TM'+tag+'O','TM-OSPF-REDIST',sequence


def commands(cfg,up):
    validate(cfg)
    protocol=cfg['protocol'];peer=cfg['peer_ip'];in_list,out_list,route_map,seqbase=_names(cfg)
    lines=['configure terminal']
    if protocol=='bgp':
        if up:
            for n,prefix in enumerate(cfg['peer_networks'],1):lines.append(f'ip prefix-list {in_list} seq {n*10} permit {prefix}')
            for n,prefix in enumerate(cfg['networks'],1):lines.append(f'ip prefix-list {out_list} seq {n*10} permit {prefix}')
            lines += [f'router bgp {cfg["local_asn"]}',f' bgp router-id {cfg["router_id"]}',f' neighbor {peer} remote-as {cfg["peer_asn"]}',f' neighbor {peer} description TunnelMgr-{cfg["id"]}',' address-family ipv4 unicast',f'  neighbor {peer} activate',f'  neighbor {peer} prefix-list {in_list} in',f'  neighbor {peer} prefix-list {out_list} out']
            lines += [f'  network {prefix}' for prefix in cfg['networks']]
            lines += [' exit-address-family','exit']
        else:
            lines += [f'router bgp {cfg["local_asn"]}',f' no neighbor {peer}',' address-family ipv4 unicast']
            lines += [f'  no network {prefix}' for prefix in cfg['networks']]
            lines += [' exit-address-family','exit',f'no ip prefix-list {in_list}',f'no ip prefix-list {out_list}']
    else:
        area=cfg.get('area','0.0.0.0')
        if up:
            for n,prefix in enumerate(cfg['peer_networks']):lines.append(f'ip prefix-list TM-OSPF-IN seq {seqbase+n} permit {prefix}')
            for n,prefix in enumerate(cfg['networks'],1):lines.append(f'ip prefix-list {out_list} seq {n*10} permit {prefix}')
            lines += [f'route-map {route_map} permit {seqbase}',f' match ip address prefix-list {out_list}',f'router ospf',f' router-id {cfg["router_id"]}',f' distribute-list prefix-list TM-OSPF-IN in',f' redistribute connected route-map {route_map}','exit',f'interface {cfg["interface"]}',f' ip ospf area {area}',' ip ospf network point-to-point','exit']
        else:
            lines += [f'interface {cfg["interface"]}',' no ip ospf area',' no ip ospf network point-to-point','exit']
            lines += [f'no route-map {route_map} permit {seqbase}',f'no ip prefix-list {out_list}']
            lines += [f'no ip prefix-list TM-OSPF-IN seq {seqbase+n}' for n in range(len(cfg['peer_networks']))]
    lines.append('end')
    return lines


def apply(cfg,up):
    validate(cfg)
    vtysh=shutil.which('vtysh')
    if not vtysh:raise RuntimeError('FRR vtysh is not installed')
    active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','frr.service'])
    if active.returncode:
        subprocess.run(['/usr/bin/systemctl','enable','--now','frr.service'],check=True,timeout=30)
    lines=commands(cfg,up)
    RUN_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile('w',encoding='utf-8',prefix='tunnelmgr-frr-',dir=RUN_DIR,delete=True) as f:
        f.write('\n'.join(lines)+'\n');f.flush()
        result=subprocess.run([vtysh,'-f',f.name],capture_output=True,text=True,timeout=25)
    if result.returncode:raise RuntimeError((result.stderr or result.stdout).strip()[-1200:] or 'FRR rejected the tunnel routing configuration')
    return {'ok':True,'output':(result.stdout+result.stderr).strip()}


def status(cfg):
    validate(cfg)
    vtysh=shutil.which('vtysh')
    if not vtysh:return {'state':'unavailable','error':'FRR vtysh is not installed'}
    if cfg['protocol']=='bgp':
        result=subprocess.run([vtysh,'-c','show bgp ipv4 unicast summary json'],capture_output=True,text=True,timeout=10)
        try:
            data=json.loads(result.stdout);peers=data.get('ipv4Unicast',data).get('peers',{});peer=peers.get(cfg['peer_ip'],{})
            state=peer.get('state') or peer.get('bgpState') or ''
            up=state.lower()=='established' or bool(peer.get('pfxRcd') is not None and peer.get('pfxRcd')!='')
            return {'state':'up' if up else 'down','peer_state':state or 'not-established','peer':cfg['peer_ip']}
        except Exception:
            result=subprocess.run([vtysh,'-c','show bgp ipv4 unicast summary'],capture_output=True,text=True,timeout=10)
            match=re.search(r'(?m)^\s*'+re.escape(cfg['peer_ip'])+r'\s+.*\bEstablished\b',result.stdout)
            return {'state':'up' if match else 'down','peer_state':'Established' if match else 'not-established','peer':cfg['peer_ip']}
    result=subprocess.run([vtysh,'-c','show ip ospf neighbor json'],capture_output=True,text=True,timeout=10)
    try:
        data=json.loads(result.stdout);items=data if isinstance(data,list) else data.get('neighbors',[])
        target_id=cfg['peer_router_id'];target_ip=cfg['peer_ip']
        matching=[x for x in items if str(x.get('address',x.get('neighborAddress','')))==target_ip or str(x.get('neighborId',x.get('routerId','')))==target_id]
        full=[x for x in (matching or items) if str(x.get('state','')).lower().startswith('full')]
        return {'state':'up' if full else 'down','peer_state':','.join(x.get('state','') for x in full) or 'not-full','peer':cfg['peer_ip']}
    except Exception:
        result=subprocess.run([vtysh,'-c','show ip ospf neighbor'],capture_output=True,text=True,timeout=10)
        match=re.search(r'(?im)^\s*'+re.escape(cfg['peer_router_id'])+r'\s+\d+\s+Full\S*\s+.*\s'+re.escape(cfg['peer_ip'])+r'\s+\S+\s*$',result.stdout)
        return {'state':'up' if match else 'down','peer_state':'Full' if match else 'not-full','peer':cfg['peer_ip']}
