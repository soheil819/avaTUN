"""Apply static, administrator-owned Linux tunnel and mesh route profiles."""
import ipaddress as ip
import json
import os
import pathlib
import re
import subprocess
import sys
import zlib

def run(*args):
    subprocess.run(['/usr/sbin/ip', *args], check=True)

def run_tc(*args):
    subprocess.run(['/usr/sbin/tc', *args], check=True)

def remove_fou(kind, port):
    proto={'gre-fou':47,'ipip-fou':4,'sit-fou':41}[kind]
    subprocess.run(['/usr/sbin/ip','fou','del','port',str(int(port)),'ipproto',str(proto)],capture_output=True)

def shared_sit_name(local, peer):
    pair='|'.join(sorted((str(local),str(peer))))
    return iface('sit'+format(zlib.crc32(pair.encode()),'08x'))

def other_sit_profile_active(local, peer, current=None):
    pair=set((str(local),str(peer)))
    directory=pathlib.Path('/etc/tunnelmgr/network')
    for path in directory.glob('*.json'):
        if path.stem==current:continue
        try:profile=json.loads(path.read_text())
        except Exception:continue
        if profile.get('kind') not in ('sit-6to4','sit-isatap'):continue
        if set((str(profile.get('outer_local')),str(profile.get('outer_peer'))))!=pair:continue
        unit='tunnelmgr-network@'+path.stem+'.service'
        state=subprocess.run(['/usr/bin/systemctl','show','-p','ActiveState','--value',unit],capture_output=True,text=True,timeout=8).stdout.strip()
        if state in ('active','activating','deactivating'):return True
    return False

def iface(name):
    if not re.fullmatch(r'[A-Za-z0-9_]{1,15}', name): raise ValueError('invalid interface')
    return name

def openconnect_server_config(profile, name, base, users, runtime):
    """Build an ocserv config whose /30 has exactly one client lease."""
    import ipaddress
    net=ipaddress.IPv4Interface(profile['inner_local']).network
    per_user=f'ipv4-network = {net.network_address}\nipv4-netmask = {net.netmask}\n'
    lines=['auth = "certificate"','cert-user-oid = 2.5.4.3',f'ca-cert = {base}/ca.crt',f'server-cert = {base}/peer.crt',f'server-key = {base}/peer.key',f'device = {name}',f'tcp-port = {int(profile["port"])}',f'udp-port = {int(profile["port"])}',f'ipv4-network = {net.network_address}','ipv4-netmask = 255.255.255.252','predictable-ips = true',f'mtu = {int(profile.get("mtu",1350))}',f'config-per-user = {users}',f'socket-file = {runtime}/ocserv.sock',f'pid-file = {runtime}/ocserv.pid','try-mtu-discovery = false','use-occtl = false']
    return '\n'.join(lines)+'\n',per_user

def private(net):
    if not any(net.subnet_of(ip.IPv4Network(x)) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise ValueError('expected RFC1918 subnet')

def apply(profile, up, profile_name=None):
    kind=profile['kind']
    supported=('gre','gretap','geneve','vxlan','ipip','sit-6to4','sit-isatap','erspan','gre-fou','ipip-fou','sit-fou')
    if kind in supported:
        sit_shared=kind in ('sit-6to4','sit-isatap')
        if sit_shared:
            sit_local=ip.IPv4Address(profile['outer_local']);sit_peer=ip.IPv4Address(profile['outer_peer'])
            if sit_local==sit_peer:raise ValueError('SIT outer endpoints must differ')
            name=shared_sit_name(sit_local,sit_peer)
        else:name=iface(profile['interface'])
        created_sit=False
        mirror=iface(profile['mirror_interface']) if kind=='erspan' and profile.get('mirror_interface') else None
        pref=10000+(zlib.crc32((mirror+':'+name).encode())%50000) if mirror else None
        if not up:
            if mirror:subprocess.run(['/usr/sbin/tc','filter','del','dev',mirror,'egress','pref',str(pref)],capture_output=True)
            if sit_shared:
                address=('2002:%x:%x::1/16'%((int(sit_local)>>16)&65535,int(sit_local)&65535)) if kind=='sit-6to4' else profile['inner_local']
                subprocess.run(['/usr/sbin/ip','address','del',str(address),'dev',name],capture_output=True)
                if not other_sit_profile_active(sit_local,sit_peer,profile_name):
                    subprocess.run(['/usr/sbin/ip','tunnel','del',name],capture_output=True)
                    legacy=profile.get('interface')
                    if legacy and legacy!=name:subprocess.run(['/usr/sbin/ip','tunnel','del',legacy],capture_output=True)
                return
            subprocess.run(['/usr/sbin/ip','tunnel' if kind.startswith('sit-6to4') or kind=='sit-isatap' else 'link','del',name],capture_output=True)
            if kind.endswith('-fou'):remove_fou(kind,profile['fou_port'])
            return
        if kind=='sit-6to4':
            # 6to4 and ISATAP share the same point-to-point SIT interface;
            # their distinct IPv6 addresses/routes coexist on that link.
            src,dst=sit_local,sit_peer
            if not pathlib.Path('/sys/class/net',name).exists():
                run('tunnel','add',name,'mode','sit','local',str(src),'remote',str(dst));created_sit=True
            else:
                details=subprocess.run(['/usr/sbin/ip','tunnel','show',name],capture_output=True,text=True,check=True).stdout
                if str(src) not in details or str(dst) not in details:raise ValueError('shared SIT interface has different outer endpoints')
            address='2002:%x:%x::1/16'%((int(src)>>16)&65535,int(src)&65535)
        elif kind=='sit-isatap':
            src,dst=sit_local,sit_peer
            if not pathlib.Path('/sys/class/net',name).exists():
                run('tunnel','add',name,'mode','sit','local',str(src),'remote',str(dst));created_sit=True
            else:
                details=subprocess.run(['/usr/sbin/ip','tunnel','show',name],capture_output=True,text=True,check=True).stdout
                if str(src) not in details or str(dst) not in details:raise ValueError('shared SIT interface has different outer endpoints')
            address=profile['inner_local']
        else:
            src,dst=map(ip.IPv4Address,(profile['outer_local'],profile['outer_peer']))
            if src==dst:raise ValueError('identical outer endpoints')
            if kind.endswith('-fou'):
                proto={'gre-fou':47,'ipip-fou':4,'sit-fou':41}[kind]
                run('fou','add','port',str(int(profile['fou_port'])),'ipproto',str(proto))
            if kind in ('ipip','ipip-fou','sit-fou'):
                typ='ipip' if kind in ('ipip','ipip-fou') else 'sit'
                cmd=['link','add',name,'type',typ,'remote',str(dst),'local',str(src)]
                if kind.endswith('-fou'):cmd+=['encap','fou','encap-sport','auto','encap-dport',str(int(profile['fou_port']))]
                try:run(*cmd)
                except Exception:
                    if kind.endswith('-fou'):remove_fou(kind,profile['fou_port'])
                    raise
            else:
                typ={'gre':'gre','gretap':'gretap','gre-fou':'gre','geneve':'geneve','vxlan':'vxlan','erspan':'erspan'}[kind]
                cmd=['link','add',name,'type',typ]
                if kind=='geneve':cmd+=['id',str(int(profile['vni'])),'remote',str(dst),'dstport',str(int(profile.get('port',6081)))]
                elif kind=='vxlan':cmd+=['id',str(int(profile['vni'])),'local',str(src),'remote',str(dst),'dstport',str(int(profile.get('port',4789)))]
                else:cmd+=['local',str(src),'remote',str(dst)]
                if kind in ('gre','gretap','gre-fou') and profile.get('key'):cmd+=['key',str(int(profile['key']))]
                if kind=='gre-fou':cmd+=['encap','fou','encap-sport','auto','encap-dport',str(int(profile['fou_port']))]
                if kind=='erspan':cmd+=['seq','key',str(int(profile['erspan_key'])),'local',str(src),'remote',str(dst),'erspan_ver','1','erspan',str(int(profile['erspan_index']))]
                try:run(*cmd)
                except Exception:
                    if kind.endswith('-fou'):remove_fou(kind,profile['fou_port'])
                    raise
            address=profile.get('inner_local')
        if not address:
            run('link','set',name,'up')
            if not mirror:return
        if kind=='erspan' and mirror:
            try:
                qdisc=subprocess.run(['/usr/sbin/tc','qdisc','show','dev',mirror],check=True,capture_output=True,text=True).stdout
                if 'qdisc clsact ' not in qdisc:run_tc('qdisc','add','dev',mirror,'clsact')
                run_tc('filter','add','dev',mirror,'egress','pref',str(pref),'matchall','action','mirred','egress','mirror','dev',name)
            except Exception:
                subprocess.run(['/usr/sbin/tc','filter','del','dev',mirror,'egress','pref',str(pref)],capture_output=True)
                run('link','del',name)
                raise
            return
        try:
            run('address','replace' if sit_shared else 'add',str(address),'dev',name)
            run('link','set',name,'mtu',str(int(profile.get('mtu',1400))),'up')
        except Exception:
            subprocess.run(['/usr/sbin/ip','address','del',str(address),'dev',name],capture_output=True)
            if sit_shared:
                if created_sit and not other_sit_profile_active(sit_local,sit_peer,profile_name):subprocess.run(['/usr/sbin/ip','tunnel','del',name],capture_output=True)
            else:subprocess.run(['/usr/sbin/ip','link','del',name],capture_output=True)
            if kind.endswith('-fou'):remove_fou(kind,profile['fou_port'])
            raise
    elif kind=='wireguard':
        name=iface(profile['interface'])
        wg='/usr/bin/wg'
        if not os.path.exists(wg):raise ValueError('wireguard-tools is not installed')
        if not up:
            subprocess.run(['/usr/sbin/ip','link','del',name],capture_output=True)
            return
        private=pathlib.Path('/etc/wireguard')/('tunnelmgr-'+name+'.key')
        psk=pathlib.Path('/etc/wireguard')/('tunnelmgr-'+name+'.psk')
        private.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        def write_secret(path,value):
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w') as f:f.write(value+'\n')
        write_secret(private,profile['private_key'])
        try:
            run('link','add','dev',name,'type','wireguard')
            cmd=[wg,'set',name,'private-key',str(private),'listen-port',str(int(profile['listen_port']))]
            peer=['peer',profile['peer_public_key']]
            if profile.get('preshared_key'):
                write_secret(psk,profile['preshared_key']);peer+=['preshared-key',str(psk)]
            endpoint=str(profile['outer_peer'])
            if ':' in endpoint and not endpoint.startswith('['):endpoint='['+endpoint+']'
            peer_address=ip.ip_interface(profile['inner_peer']).ip
            peer_prefix='/32' if peer_address.version==4 else '/128'
            peer+=['endpoint',endpoint+':'+str(int(profile['endpoint_port'])),'allowed-ips',str(peer_address)+peer_prefix]
            if int(profile.get('keepalive',25)):peer+=['persistent-keepalive',str(int(profile.get('keepalive',25)))]
            subprocess.run(cmd+peer,check=True,timeout=15)
            run('address','add',str(profile['inner_local']),'dev',name)
            run('link','set',name,'mtu',str(int(profile.get('mtu',1400))),'up')
        except Exception:
            subprocess.run(['/usr/sbin/ip','link','del',name],capture_output=True)
            raise
        finally:
            private.unlink(missing_ok=True);psk.unlink(missing_ok=True)
    elif kind=='openvpn':
        name=iface(profile['interface']);ident=profile_name or name
        base=pathlib.Path('/etc/tunnelmgr/openvpn');base.mkdir(mode=0o700,parents=True,exist_ok=True)
        config=base/(ident+'.conf');ccd=base/('ccd-'+ident);unit='tunnelmgr-openvpn@'+ident+'.service'
        if not up:
            subprocess.run(['/usr/bin/systemctl','disable','--now',unit],capture_output=True,timeout=25)
            config.unlink(missing_ok=True)
            if ccd.is_dir():
                import shutil
                shutil.rmtree(ccd)
            return
        local=ip.IPv4Interface(profile['inner_local']).ip;peer=ip.IPv4Interface(profile['inner_peer']).ip
        role=profile['role'];cn=profile.get('peer_common_name','tunnelmgr-peer')
        lines=['dev '+name,'proto udp','port '+str(int(profile['port'])),'topology p2p','tun-mtu '+str(int(profile.get('mtu',1400))),'persist-key','persist-tun','keepalive 10 60','verb 3','auth SHA256','data-ciphers AES-256-GCM:AES-128-GCM','tls-version-min 1.2','remote-cert-tls '+('client' if role=='server' else 'server'),'verify-x509-name '+profile['peer_common_name']+' name']
        if role=='server':
            lines += ['mode server','tls-server','ifconfig '+str(local)+' '+str(peer),'push "topology p2p"','client-config-dir '+str(ccd)]
        else:
            endpoint=str(profile['outer_peer'])
            if ':' in endpoint and not endpoint.startswith('['):endpoint='['+endpoint+']'
            lines += ['client','tls-client','remote '+endpoint+' '+str(int(profile['port'])),'nobind']
        lines += ['<ca>',profile['ca_cert'].strip(),'</ca>','<cert>',profile['cert'].strip(),'</cert>','<key>',profile['private_key_pem'].strip(),'</key>']
        content='\n'.join(lines)+'\n'
        fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w') as f:f.write(content)
        if role=='server':
            ccd.mkdir(mode=0o700,parents=True,exist_ok=True)
            cfile=ccd/cn
            fd=os.open(cfile,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w') as f:f.write('ifconfig-push '+str(peer)+' '+str(local)+'\n')
        try:
            subprocess.run(['/usr/bin/systemctl','enable','--now',unit],check=True,capture_output=True,text=True,timeout=40)
        except Exception:
            config.unlink(missing_ok=True)
            if ccd.is_dir():
                import shutil
                shutil.rmtree(ccd)
            raise
    elif kind=='openconnect':
        import shutil
        import ipaddress
        name=iface(profile['interface']);ident=profile_name or name
        base=pathlib.Path('/etc/tunnelmgr/openconnect')/ident
        unit='tunnelmgr-'+('ocserv' if profile['role']=='server' else 'openconnect')+'@'+ident+'.service'
        if not up:
            subprocess.run(['/usr/bin/systemctl','disable','--now',unit],capture_output=True,timeout=30)
            shutil.rmtree(base,ignore_errors=True)
            if profile['role']=='server':shutil.rmtree('/run/tunnelmgr-ocserv-'+ident,ignore_errors=True)
            return
        base.mkdir(mode=0o700,parents=True,exist_ok=True)
        def secure_write(path,value):
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w') as f:f.write(value)
        secure_write(base/'ca.crt',profile['ca_cert'].strip()+'\n')
        secure_write(base/'peer.crt',profile['cert'].strip()+'\n')
        secure_write(base/'peer.key',profile['private_key_pem'].strip()+'\n')
        if profile['role']=='server':
            users=base/'users';users.mkdir(mode=0o700,exist_ok=True)
            runtime='/run/tunnelmgr-ocserv-'+ident
            pathlib.Path(runtime).mkdir(mode=0o755,parents=True,exist_ok=True)
            config,user_config=openconnect_server_config(profile,name,base,users,runtime)
            secure_write(users/profile['peer_common_name'],user_config)
            secure_write(base/'ocserv.conf',config)
        else:
            secure_write(base/'client.json',json.dumps({'server':profile['outer_peer'],'port':int(profile['port']),'interface':name,'cafile':str(base/'ca.crt'),'certificate':str(base/'peer.crt'),'key':str(base/'peer.key')})+'\n')
        try:
            subprocess.run(['/usr/bin/systemctl','enable','--now',unit],check=True,capture_output=True,text=True,timeout=50)
        except Exception:
            subprocess.run(['/usr/bin/systemctl','disable','--now',unit],capture_output=True,timeout=20)
            shutil.rmtree(base,ignore_errors=True)
            raise
    elif kind=='l2tpv3':
        name=iface(profile['interface']);tid=int(profile['tunnel_id']);ptid=int(profile['peer_tunnel_id']);sid=int(profile['session_id']);psid=int(profile['peer_session_id'])
        if not up:
            run('l2tp','del','session','tunnel_id',str(tid),'session_id',str(sid))
            run('l2tp','del','tunnel','tunnel_id',str(tid))
            return
        src,dst=map(ip.IPv4Address,(profile['outer_local'],profile['outer_peer']))
        args=['l2tp','add','tunnel','tunnel_id',str(tid),'peer_tunnel_id',str(ptid),'local',str(src),'remote',str(dst),'encap',profile.get('encap','udp')]
        if profile.get('encap','udp')=='udp':args+=['udp_sport',str(int(profile['udp_sport'])),'udp_dport',str(int(profile['udp_dport']))]
        run(*args)
        try:
            run('l2tp','add','session','tunnel_id',str(tid),'session_id',str(sid),'peer_session_id',str(psid),'name',name)
            run('address','add',profile['inner_local'],'dev',name);run('link','set',name,'mtu',str(int(profile.get('mtu',1400))),'up')
        except Exception:
            subprocess.run(['/usr/sbin/ip','l2tp','del','tunnel','tunnel_id',str(tid)],check=False);raise
    elif kind in ('ipsec-ikev2','ipsec-esp-udp'):
        name=iface(profile['interface']);safe=re.sub(r'[^a-zA-Z0-9_-]','_',name)
        conf=pathlib.Path('/etc/swanctl/conf.d/tunnelmgr-'+safe+'.conf')
        if not up:
            subprocess.run(['/usr/sbin/swanctl','--terminate','--ike',safe],capture_output=True,timeout=15)
            subprocess.run(['/usr/sbin/ip','address','del',profile['inner_local'],'dev','lo'],capture_output=True)
            return
        local=ip.IPv4Address(profile['inner_local'].split('/')[0]);peer=ip.IPv4Address(profile['inner_peer'].split('/')[0])
        li=str(profile.get('local_id') or profile['outer_local']);ri=str(profile.get('remote_id') or profile['outer_peer'])
        def q(v):return '"'+str(v).replace('\\','\\\\').replace('"','\\"')+'"'
        udp='encap = yes\n ' if kind=='ipsec-esp-udp' else ''
        text=f'''connections {{ {safe} {{ version = 2\n local_addrs = {profile['outer_local']}\n remote_addrs = {profile['outer_peer']}\n proposals = aes256-sha256-modp2048\n mobike = no\n {udp}local {{ auth = psk\n id = {q(li)} }}\n remote {{ auth = psk\n id = {q(ri)} }}\n children {{ {safe} {{ mode = tunnel\n local_ts = {local}/32\n remote_ts = {peer}/32\n esp_proposals = aes256-sha256\n start_action = {'start' if profile.get('role')=='client' else 'none'} }} }} }} }}\nsecrets {{ ike-{safe} {{ id-1 = {q(li)}\n id-2 = {q(ri)}\n secret = {q(profile['psk'])} }} }}\n'''
        conf.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd=os.open(conf,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w') as f:f.write(text)
        subprocess.run(['/usr/bin/systemctl','enable','--now','strongswan.service'],check=True,timeout=30)
        subprocess.run(['/usr/sbin/swanctl','--load-all'],check=True,timeout=20)
        subprocess.run(['/usr/sbin/ip','address','replace',str(local)+'/32','dev','lo'],check=True)
        if profile.get('role')=='client':subprocess.run(['/usr/sbin/swanctl','--initiate','--ike',safe,'--child',safe],check=True,timeout=45)
    elif kind=='esp':
        name=iface(profile['interface'])
        def secure_run(*args):
            result=subprocess.run(['/usr/sbin/ip',*args],capture_output=True,text=True)
            if result.returncode:raise RuntimeError('ESP XFRM operation failed: '+(result.stderr.strip() or 'ip failed'))
        src,dst=map(ip.IPv4Address,(profile['outer_local'],profile['outer_peer']))
        local=ip.IPv4Address(profile['inner_local'].split('/')[0]);peer=ip.IPv4Address(profile['inner_peer'].split('/')[0])
        tx_spi=int(profile['spi']);rx_spi=int(profile['peer_spi'])
        tx_enc,tx_auth=profile['enc_key'],profile['auth_key'];rx_enc,rx_auth=profile['peer_enc_key'],profile['peer_auth_key']
        if up:
            secure_run('xfrm','state','add','src',str(src),'dst',str(dst),'proto','esp','spi',hex(tx_spi),'reqid',str(tx_spi),'mode','tunnel','auth-trunc','hmac(sha256)','0x'+tx_auth,'128','enc','cbc(aes)','0x'+tx_enc)
            try:
                secure_run('xfrm','state','add','src',str(dst),'dst',str(src),'proto','esp','spi',hex(rx_spi),'reqid',str(tx_spi),'mode','tunnel','auth-trunc','hmac(sha256)','0x'+rx_auth,'128','enc','cbc(aes)','0x'+rx_enc)
                secure_run('xfrm','policy','add','src',str(local)+'/32','dst',str(peer)+'/32','dir','out','tmpl','src',str(src),'dst',str(dst),'proto','esp','reqid',str(tx_spi),'mode','tunnel')
                secure_run('xfrm','policy','add','src',str(peer)+'/32','dst',str(local)+'/32','dir','in','tmpl','src',str(dst),'dst',str(src),'proto','esp','reqid',str(tx_spi),'mode','tunnel')
            except Exception:
                subprocess.run(['/usr/sbin/ip','xfrm','policy','delete','src',str(local)+'/32','dst',str(peer)+'/32','dir','out'],check=False)
                subprocess.run(['/usr/sbin/ip','xfrm','policy','delete','src',str(peer)+'/32','dst',str(local)+'/32','dir','in'],check=False)
                subprocess.run(['/usr/sbin/ip','xfrm','state','delete','src',str(dst),'dst',str(src),'proto','esp','spi',hex(rx_spi)],check=False)
                subprocess.run(['/usr/sbin/ip','xfrm','state','delete','src',str(src),'dst',str(dst),'proto','esp','spi',hex(tx_spi)],check=False)
                raise
            try:
                subprocess.run(['/usr/sbin/ip','address','replace',str(local)+'/32','dev','lo'],check=True)
                # Select the ESP inner source on the peer host route. Without
                # this route Linux picks the public interface address, so the
                # XFRM selector (local/32 -> peer/32) never matches.
                outer_route=subprocess.run(['/usr/sbin/ip','-json','route','get',str(dst)],capture_output=True,text=True,check=True)
                outer_path=json.loads(outer_route.stdout)[0]
                route_args=['route','replace',str(peer)+'/32']
                if outer_path.get('gateway'):route_args+=['via',outer_path['gateway']]
                route_args+=['dev',iface(outer_path['dev']),'src',str(local)]
                secure_run(*route_args)
            except Exception:
                subprocess.run(['/usr/sbin/ip','route','del',str(peer)+'/32'],check=False)
                subprocess.run(['/usr/sbin/ip','xfrm','policy','delete','src',str(local)+'/32','dst',str(peer)+'/32','dir','out'],check=False)
                subprocess.run(['/usr/sbin/ip','xfrm','policy','delete','src',str(peer)+'/32','dst',str(local)+'/32','dir','in'],check=False)
                subprocess.run(['/usr/sbin/ip','xfrm','state','delete','src',str(dst),'dst',str(src),'proto','esp','spi',hex(rx_spi)],check=False)
                subprocess.run(['/usr/sbin/ip','xfrm','state','delete','src',str(src),'dst',str(dst),'proto','esp','spi',hex(tx_spi)],check=False)
                raise
        else:
            subprocess.run(['/usr/sbin/ip','route','del',str(peer)+'/32'],check=False)
            subprocess.run(['/usr/sbin/ip','xfrm','policy','delete','src',str(local)+'/32','dst',str(peer)+'/32','dir','out'],check=False)
            subprocess.run(['/usr/sbin/ip','xfrm','policy','delete','src',str(peer)+'/32','dst',str(local)+'/32','dir','in'],check=False)
            subprocess.run(['/usr/sbin/ip','xfrm','state','delete','src',str(src),'dst',str(dst),'proto','esp','spi',hex(tx_spi)],check=False)
            subprocess.run(['/usr/sbin/ip','xfrm','state','delete','src',str(dst),'dst',str(src),'proto','esp','spi',hex(rx_spi)],check=False)
            subprocess.run(['/usr/sbin/ip','address','del',str(local)+'/32','dev','lo'],check=False)
    elif kind=='forward':
        # One profile per interface; preserve the previous kernel value across stop.
        name=iface(profile['interface'])
        knob=pathlib.Path('/proc/sys/net/ipv4/conf',name,'forwarding')
        state=pathlib.Path('/run/tunnelmgr-netstate',name)
        state.parent.mkdir(mode=0o700,exist_ok=True)
        if up:
            with state.open('x') as f:f.write(knob.read_text())
            try:knob.write_text('1')
            except Exception:state.unlink();raise
        else:
            knob.write_text(state.read_text().strip());state.unlink()
    elif kind=='routes':
        routes=[]
        for row in profile['routes']:
            net=ip.IPv4Network(row['prefix']);private(net)
            gw=ip.IPv4Address(row['via']);private(ip.IPv4Network(f'{gw}/32'))
            routes.append((str(net),'via',str(gw),'dev',iface(row['interface']),'proto','186'))
        done=[]
        try:
            for route in routes:
                run('route','add' if up else 'del',*route);done.append(route)
        except Exception:
            for route in reversed(done):run('route','del' if up else 'add',*route)
            raise
    elif kind=='routing':
        import routing
        routing.apply(profile,up)
        if up:
            state=pathlib.Path('/run/tunnelmgr-netstate/ip_forward')
            state.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            knob=pathlib.Path('/proc/sys/net/ipv4/ip_forward')
            if not state.exists():
                fd=os.open(state,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'w') as f:f.write(knob.read_text().strip())
            knob.write_text('1')
        else:
            active=False
            for path in pathlib.Path('/etc/tunnelmgr/network').glob('*.json'):
                if path.stem==profile_name:continue
                try:other=json.loads(path.read_text())
                except Exception:continue
                if other.get('kind')!='routing':continue
                unit='tunnelmgr-network@'+path.stem+'.service'
                state=subprocess.run(['/usr/bin/systemctl','show','-p','ActiveState','--value',unit],capture_output=True,text=True,timeout=8).stdout.strip()
                if state in ('active','activating','deactivating'):active=True;break
            statefile=pathlib.Path('/run/tunnelmgr-netstate/ip_forward')
            if not active and statefile.exists():
                pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text(statefile.read_text().strip())
                statefile.unlink(missing_ok=True)
    else:raise ValueError('unknown kind')

if __name__=='__main__':
    action,name=sys.argv[1:]
    if action not in ('up','down') or not re.fullmatch(r'[a-z0-9_-]{1,48}',name):sys.exit('invalid arguments')
    apply(json.loads(pathlib.Path('/etc/tunnelmgr/network',name+'.json').read_text()), action=='up', name)
