"""Admin profile operations for the restricted local helper."""
import ipaddress
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

from network import apply, iface, private
from topology import mesh_plan
from routing import validate as validate_routing


def validate(group, cfg):
    if group == 'mesh':
        if set(cfg) - {'nodes','endpoints','topology','direction','hub','pool'}:
            raise ValueError('Unexpected mesh property')
        private(ipaddress.IPv4Network(cfg['pool']))
        plan = mesh_plan(**cfg)
        if not plan['ready_to_configure'] or set(cfg['nodes']) != set(cfg['endpoints']):
            raise ValueError('Every node needs a reachable SSH endpoint')
        return
    kind=cfg.get('kind')
    if kind not in ('gre','gretap','geneve','vxlan','ipip','sit-6to4','sit-isatap','erspan','gre-fou','ipip-fou','sit-fou','l2tpv3','ipsec-ikev2','ipsec-esp-udp','esp','wireguard','openvpn','openconnect','routing'):
        raise ValueError('Unsupported tunnel type')
    if kind=='routing':
        validate_routing(cfg)
        return
    iface(cfg['interface'])
    if kind=='openvpn':
        if cfg.get('role') not in ('server','client'):raise ValueError('OpenVPN role must be server or client')
        local=ipaddress.IPv4Interface(cfg['inner_local']);peer=ipaddress.IPv4Interface(cfg['inner_peer'])
        private(local.network)
        if local.network!=peer.network or local.ip==peer.ip:raise ValueError('OpenVPN peer addresses must be distinct hosts in one private subnet')
        ipaddress.IPv4Address(cfg['outer_local']);ipaddress.IPv4Address(cfg['outer_peer'])
        if not 1<=int(cfg.get('port',0))<=65535:raise ValueError('OpenVPN UDP port must be 1..65535')
        for field,marker in (('ca_cert','BEGIN CERTIFICATE'),('cert','BEGIN CERTIFICATE'),('private_key_pem','PRIVATE KEY')):
            if marker not in cfg.get(field,''):raise ValueError('OpenVPN certificate material is incomplete')
        for field in ('common_name','peer_common_name'):
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',cfg.get(field,'')):raise ValueError('invalid OpenVPN certificate name')
    elif kind=='openconnect':
        if cfg.get('role') not in ('server','client'):raise ValueError('OpenConnect role must be server or client')
        local=ipaddress.IPv4Interface(cfg['inner_local']);peer=ipaddress.IPv4Interface(cfg['inner_peer'])
        if local.network!=peer.network or local.ip==peer.ip or local.network.prefixlen not in (30,31):
            raise ValueError('OpenConnect requires the two distinct addresses of one /30 or /31 subnet')
        hosts={local.network.network_address,local.network.broadcast_address} if local.network.prefixlen==31 else {local.network.network_address+1,local.network.network_address+2}
        if {local.ip,peer.ip}!=hosts:raise ValueError('OpenConnect addresses must be the two point-to-point hosts of the pool')
        if not local.network.network_address.is_private:raise ValueError('OpenConnect pool must be private')
        ipaddress.IPv4Address(cfg['outer_local']);ipaddress.IPv4Address(cfg['outer_peer'])
        if not 1<=int(cfg.get('port',0))<=65535:raise ValueError('OpenConnect TCP/UDP port must be 1..65535')
        for field,marker in (('ca_cert','BEGIN CERTIFICATE'),('cert','BEGIN CERTIFICATE'),('private_key_pem','PRIVATE KEY')):
            if marker not in cfg.get(field,''):raise ValueError('OpenConnect certificate material is incomplete')
        for field in ('common_name','peer_common_name'):
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',cfg.get(field,'')):raise ValueError('invalid OpenConnect certificate name')
    elif kind=='wireguard':
        import base64
        for field in ('private_key','peer_public_key'):
            try:
                key=base64.b64decode(cfg.get(field,''),validate=True)
            except Exception as exc:raise ValueError('WireGuard keys must be base64-encoded 32-byte values') from exc
            if len(key)!=32:raise ValueError('WireGuard keys must be base64-encoded 32-byte values')
        local=ipaddress.ip_interface(cfg['inner_local']);peer=ipaddress.ip_interface(cfg['inner_peer'])
        if local.version!=peer.version or local.ip==peer.ip:raise ValueError('WireGuard peer addresses must be distinct and use the same IP version')
        if not 1<=int(cfg.get('listen_port',0))<=65535 or not 1<=int(cfg.get('endpoint_port',0))<=65535:raise ValueError('WireGuard UDP ports must be 1..65535')
        ipaddress.ip_address(cfg['outer_peer'])
        if cfg.get('preshared_key'):
            try:
                if len(base64.b64decode(cfg['preshared_key'],validate=True))!=32:raise ValueError()
            except Exception as exc:raise ValueError('WireGuard preshared key must be a base64-encoded 32-byte value') from exc
        if not 0<=int(cfg.get('keepalive',25))<=65535:raise ValueError('WireGuard keepalive must be 0..65535')
    elif kind=='esp':
        a,b=[ipaddress.IPv4Address(cfg[k]) for k in ('outer_local','outer_peer')]
        local,peer=[ipaddress.IPv4Interface(cfg[k]) for k in ('inner_local','inner_peer')]
        if a==b or local.ip==peer.ip:raise ValueError('ESP outer and inner endpoint pairs must differ')
        for k in ('spi','peer_spi'):
            if not 256<=int(cfg[k])<=4294967295:raise ValueError('ESP SPI must be 256..4294967295')
        if int(cfg['spi'])==int(cfg['peer_spi']):raise ValueError('ESP peer SPIs must differ')
        for k in ('enc_key','auth_key','peer_enc_key','peer_auth_key'):
            if not re.fullmatch(r'[0-9a-fA-F]{64}',cfg.get(k,'')):raise ValueError('ESP AES-256 and HMAC-SHA256 keys must each be 64 hex characters')
    elif kind in ('ipsec-ikev2','ipsec-esp-udp'):
        if cfg.get('role') not in ('server','client'):raise ValueError('Select server or client role')
        a,b=[ipaddress.IPv4Address(cfg[k]) for k in ('outer_local','outer_peer')]
        if a==b or len(cfg.get('psk',''))<16:raise ValueError('IPsec requires distinct outer IPs and a PSK of at least 16 characters')
        local,peer=[ipaddress.IPv4Interface(cfg[k]) for k in ('inner_local','inner_peer')]
        if local.ip==peer.ip:raise ValueError('IPsec inner addresses must differ')
        if not re.fullmatch(r'[A-Za-z0-9_.@+-]{1,128}',cfg.get('local_id',str(a))) or not re.fullmatch(r'[A-Za-z0-9_.@+-]{1,128}',cfg.get('remote_id',str(b))):raise ValueError('Invalid IKE identity')
    elif kind=='l2tpv3':
        for k in ('tunnel_id','peer_tunnel_id','session_id','peer_session_id'):
            if not 1<=int(cfg[k])<=4294967295:raise ValueError('L2TP identifiers must be 1..4294967295')
        if cfg['tunnel_id']==cfg['peer_tunnel_id'] or cfg['session_id']==cfg['peer_session_id']:raise ValueError('Peer and local identifiers must differ')
        if cfg.get('encap','udp') not in ('udp','ip'):raise ValueError('L2TPv3 encapsulation must be udp or ip')
        if cfg.get('encap','udp')=='udp' and any(not 1<=int(cfg[k])<=65535 for k in ('udp_sport','udp_dport')):raise ValueError('UDP ports must be 1..65535')
        local=ipaddress.IPv4Interface(cfg['inner_local']);private(local.network)
        a,b=[ipaddress.IPv4Address(cfg[k]) for k in ('outer_local','outer_peer')]
        if a==b:raise ValueError('Outer addresses must differ')
    elif kind in ('sit-6to4','sit-isatap'):
        ipaddress.IPv4Address(cfg['outer_local'])
        if kind=='sit-isatap':ipaddress.IPv6Interface(cfg['inner_local'])
    elif kind=='sit-fou':
        a,b=[ipaddress.IPv4Address(cfg[k]) for k in ('outer_local','outer_peer')]
        local,peer=[ipaddress.IPv6Interface(cfg[k]) for k in ('inner_local','inner_peer')]
        if a==b or local.ip==peer.ip or local.network!=peer.network:raise ValueError('SIT FoU requires distinct outer endpoints and peer IPv6 addresses in one prefix')
    else:
        a,b=[ipaddress.IPv4Address(cfg[k]) for k in ('outer_local','outer_peer')]
        if a==b:raise ValueError('Outer addresses must differ')
        if kind in ('gre','ipip','gretap','gre-fou','ipip-fou','l2tpv3'):
            local,peer=[ipaddress.IPv4Interface(cfg[k]) for k in ('inner_local','inner_peer')]
            private(local.network)
            if local.network.prefixlen!=30 or local.network!=peer.network or {local.ip,peer.ip}!=set(local.network.hosts()):raise ValueError('Use both host addresses of one private /30')
        if kind in ('geneve','vxlan') and not 1<=int(cfg['vni'])<=16777215:raise ValueError('VNI must be 1..16777215')
        if kind=='erspan' and (int(cfg['erspan_index'])<1 or not 0<=int(cfg['erspan_key'])<=4294967295):raise ValueError('ERSPAN index and key are invalid')
        if kind=='erspan' and cfg.get('mirror_interface'):iface(cfg['mirror_interface'])
        if kind in ('gre','gretap','gre-fou') and cfg.get('key') and not 0<=int(cfg['key'])<=4294967295:raise ValueError('GRE key must be a 32-bit value')
        if kind.endswith('-fou') and not 1<=int(cfg['fou_port'])<=65535:raise ValueError('FoU port must be 1..65535')
    if not 576<=int(cfg['mtu'])<=9000:raise ValueError('MTU must be 576..9000')


def manage(req, ident):
    group = req['group']
    if group not in ('mesh','network'):
        raise ValueError('Unknown profile type')
    directory = Path('/etc/tunnelmgr') / group
    path = directory / (ident+'.json')
    action = req['action']
    if action == 'list':
        return {'items': sorted(p.stem for p in directory.glob('*.json') if group=='mesh' or json.loads(p.read_text()).get('kind') in ('gre','ipip','gretap','geneve','vxlan','sit-6to4','sit-isatap','erspan','gre-fou','ipip-fou','sit-fou','l2tpv3','ipsec-ikev2','ipsec-esp-udp','esp','wireguard','openvpn','openconnect','routing'))}
    old = json.loads(path.read_text()) if path.exists() else None
    if old and group=='network' and old.get('kind') not in ('gre','ipip','gretap','geneve','vxlan','sit-6to4','sit-isatap','erspan','gre-fou','ipip-fou','sit-fou','l2tpv3','ipsec-ikev2','ipsec-esp-udp','esp','wireguard','openvpn','openconnect','routing'):
        raise ValueError('Reserved network profile')
    if action=='read' and old is not None:
        return {'config':old}
    unit = f'tunnelmgr-{group}@{ident}.service'
    if action in ('create','update'):
        cfg = req['config']
        validate(group,cfg)
        if action=='create' and old is not None:raise ValueError('Profile already exists')
        if action=='update' and (old is None or req.get('previous') != old):raise ValueError('Reload the profile before editing')
        state=subprocess.check_output(['systemctl','show','-p','ActiveState','--value',unit],text=True).strip()
        if state not in ('inactive','failed'):raise ValueError('Stop the service or wait for deployment before editing')
        with tempfile.NamedTemporaryFile('w',dir=directory,delete=False) as f:
            try:
                json.dump(cfg,f); f.flush(); os.fsync(f.fileno()); os.replace(f.name,path)
            finally:
                Path(f.name).unlink(missing_ok=True)
        return {'ok':True}
    if old and group=='network' and action in ('start','stop','restart','status'):
        cmd={'start':['enable','--now'],'stop':['disable','--now'],'restart':['restart'],'status':['show','-p','ActiveState','-p','Result']}[action]
        result=subprocess.run(['systemctl',*cmd,unit],capture_output=True,text=True,timeout=12)
        if result.returncode:
            if action=='start':
                try:apply(old,False)
                except Exception:pass
            raise ValueError(result.stderr.strip())
        return {'ok':True,'output':result.stdout.strip()}
    if old and group=='network' and action=='delete' and old.get('kind') in ('gre','ipip','gretap','geneve','vxlan','sit-6to4','sit-isatap','erspan','gre-fou','ipip-fou','sit-fou','l2tpv3','ipsec-ikev2','ipsec-esp-udp','esp','wireguard','openvpn','openconnect','routing'):
        subprocess.run(['systemctl','disable','--now',unit],capture_output=True,text=True,timeout=15)
        if old.get('kind') in ('ipsec-ikev2','ipsec-esp-udp'):
            safe=re.sub(r'[^a-zA-Z0-9_-]','_',old['interface'])
            Path('/etc/swanctl/conf.d/tunnelmgr-'+safe+'.conf').unlink(missing_ok=True)
            subprocess.run(['/usr/sbin/swanctl','--load-all'],capture_output=True,timeout=15)
        path.unlink()
        return {'ok':True}
    raise ValueError('Unknown profile or action')
