#!/usr/bin/env python3
"""Restricted root helper for validated Backhaul TUN instances."""
from profiles import manage
import ipaddress, json, os, pwd, re, shutil, socket, struct, subprocess, time, sqlite3, csv
from pathlib import Path
SOCKET='/run/tunnelmgr/privd.sock'
ID=re.compile(r'^[a-z0-9][a-z0-9_-]{0,47}$')
NAME=re.compile(r'^[a-zA-Z0-9_]{1,15}$')
APP_UID=pwd.getpwnam('tunnelmgr').pw_uid
FIELDS={'mode','listen','peer','tun_name','tun_local','tun_remote','tun_mtu','health_port','secret_file','replace'}

def send(c,v):c.sendall((json.dumps(v)+'\n').encode())
def invoke(args,timeout=65):return subprocess.run(['/usr/local/bin/backhaul-manager',*args],text=True,capture_output=True,timeout=timeout)

HAPROXY_MARKER_START='# BEGIN TUNNELMGR FORWARDS'
HAPROXY_MARKER_END='# END TUNNELMGR FORWARDS'

def haproxy_without_managed_block(text):
    start=text.find(HAPROXY_MARKER_START);end=text.find(HAPROXY_MARKER_END)
    if (start<0)!=(end<0) or (start>=0 and end<start):
        raise ValueError('managed HAProxy block markers are incomplete; configuration left unchanged')
    if start<0:return text
    end += len(HAPROXY_MARKER_END)
    return (text[:start].rstrip()+('\n' if text[:start].strip() else '')+text[end:].lstrip())

def haproxy_commit(candidate,previous,active):
    cfg=Path('/etc/haproxy/haproxy.cfg');tmp=cfg.with_name('.haproxy.cfg.avatun.tmp')
    tmp.write_text(candidate);tmp.chmod(0o644)
    try:
        check=subprocess.run(['/usr/sbin/haproxy','-c','-f',str(tmp)],capture_output=True,text=True,timeout=20)
        if check.returncode:raise ValueError((check.stdout+check.stderr)[-1800:])
        enable=subprocess.run(['/usr/bin/systemctl','enable','haproxy.service'],capture_output=True,text=True,timeout=10)
        if enable.returncode:raise RuntimeError((enable.stdout+enable.stderr)[-1200:])
        os.replace(tmp,cfg)
        action='reload' if active else 'start'
        result=subprocess.run(['/usr/bin/systemctl',action,'haproxy.service'],capture_output=True,text=True,timeout=25)
        if result.returncode:
            restore=cfg.with_name('.haproxy.cfg.avatun.restore')
            restore.write_bytes(previous);restore.chmod(0o644);os.replace(restore,cfg)
            subprocess.run(['/usr/bin/systemctl',action,'haproxy.service'],capture_output=True,text=True,timeout=25)
            raise RuntimeError((result.stdout+result.stderr)[-1500:])
    finally:tmp.unlink(missing_ok=True)

def tunnel_create(req,ident):
    cfg=req.get('config')
    if not isinstance(cfg,dict) or set(cfg)-FIELDS:raise ValueError('invalid config fields')
    mode=cfg.get('mode')
    if mode not in ('server','client'):raise ValueError('mode must be server or client')
    secret=cfg.get('secret_file')
    if not isinstance(secret,str) or not secret.startswith('/etc/backhaul/secrets/') or '..' in secret.split('/'):
        raise ValueError('secret_file must point inside /etc/backhaul/secrets')
    local=ipaddress.ip_interface(cfg.get('tun_local',''))
    remote=ipaddress.ip_interface(cfg.get('tun_remote',''))
    if local.version!=remote.version or local.network!=remote.network or local.ip==remote.ip:raise ValueError('local and remote addresses must be distinct peers in the same subnet')
    if local.ip in (local.network.network_address,local.network.broadcast_address) or remote.ip in (remote.network.network_address,remote.network.broadcast_address):raise ValueError('both tunnel addresses must be usable host addresses')
    if not local.ip.is_private or not remote.ip.is_private:raise ValueError('use private internal tunnel IP addresses')
    name=cfg.get('tun_name','tun0')
    if not isinstance(name,str) or not NAME.fullmatch(name):raise ValueError('invalid Linux interface name')
    mtu=cfg.get('tun_mtu',1400)
    if not isinstance(mtu,int) or not 576<=mtu<=9000:raise ValueError('MTU must be 576..9000')
    health=cfg.get('health_port',19080)
    if not isinstance(health,int) or not 1<=health<=65535:raise ValueError('health port must be 1..65535')
    if cfg.get('replace') is not True:
        probe=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:probe.bind(('127.0.0.1',health))
        except OSError as e:raise ValueError(f'health port {health} is already in use; choose a unique port') from e
        finally:probe.close()
    args=['create',ident,'--mode',mode,'--transport','tun','--tun-name',name,'--tun-local',str(local),'--tun-remote',str(remote),'--tun-mtu',str(mtu),'--health-port',str(health),'--secret-file',secret]
    if mode=='server':
        listen=cfg.get('listen','0.0.0.0:18443')
        if not isinstance(listen,str) or len(listen)>128:raise ValueError('invalid listen address')
        args += ['--listen',listen]
    else:
        peer=cfg.get('peer')
        if not isinstance(peer,str) or len(peer)>255 or ':' not in peer:raise ValueError('client requires peer HOST:PORT')
        args += ['--peer',peer]
    if cfg.get('replace') is True:args.append('--replace')
    args.append('--start')
    p=invoke(args)
    if p.returncode:raise RuntimeError((p.stdout+p.stderr)[-3000:])
    return {'ok':True,'output':(p.stdout+p.stderr)[-4000:]}

def haproxy_apply(req):
    action=req.get('action','status')
    if action=='status':
        p=subprocess.run(['/usr/bin/systemctl','is-active','haproxy.service'],capture_output=True,text=True,timeout=8)
        active=p.stdout.strip()=='active';paths={}
        if active:
            try:
                client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(1.5);client.connect('/run/haproxy/admin.sock');client.sendall(b'show stat\n');data=b''
                while len(data)<2_000_000:
                    chunk=client.recv(65536)
                    if not chunk:break
                    data+=chunk
                    if data.endswith(b'\n\n'):break
                client.close();rows=list(csv.reader(data.decode(errors='replace').splitlines()))
                for row in rows[1:]:
                    if len(row)<18 or not row[0].startswith('tm_pool_') or row[1] in ('BACKEND','FRONTEND'):continue
                    match=re.fullmatch(r'path[0-9]+_(.+)',row[1])
                    if match:paths.setdefault(row[0][8:],{})[match[1]]=row[17]
            except Exception:paths={}
        return {'ok':p.returncode==0,'active':active,'status':p.stdout.strip() or p.stderr.strip(),'paths':paths}
    if action!='apply':raise ValueError('invalid HAProxy action')
    rules=req.get('rules')
    if not isinstance(rules,list) or len(rules)>100:raise ValueError('invalid HAProxy rule list')
    cfg=Path('/etc/haproxy/haproxy.cfg')
    if not shutil.which('haproxy'):raise ValueError('HAProxy is not installed on the panel server')
    if not cfg.is_file():raise ValueError('HAProxy configuration file is missing')
    previous=cfg.read_bytes();current=previous.decode()
    base=haproxy_without_managed_block(current)
    active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','haproxy.service']).returncode==0
    if not rules:
        if base!=current:haproxy_commit(base,previous,active)
        return {'ok':True,'active':False,'status':'no managed forwards'}
    if HAPROXY_MARKER_START in base or HAPROXY_MARKER_END in base:raise ValueError('nested managed markers found in HAProxy configuration')
    lines=[HAPROXY_MARKER_START,'','defaults','    log global','    mode tcp','    option tcplog','    timeout connect 5s','    timeout client 60s','    timeout server 60s']
    seen=set()
    for rule in rules:
        if not isinstance(rule,dict):raise ValueError('invalid port-forward rule')
        ident=rule.get('id','')
        if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError('invalid port-forward id')
        try:listen=ipaddress.ip_address(rule.get('listen_ip',''))
        except ValueError as e:raise ValueError('listen address must be an IP configured on this server') from e
        if not listen.is_unspecified:
            ipbin=shutil.which('ip')
            if not ipbin:raise ValueError('iproute2 is required to verify the listener address')
            addr_result=subprocess.run([ipbin,'-json','address','show'],capture_output=True,text=True,timeout=8)
            if addr_result.returncode:raise ValueError('could not inspect local IP addresses')
            local_addresses={a['local'] for iface in json.loads(addr_result.stdout) for item in iface.get('addr_info',[]) if (a:=item) and 'local' in a}
            if str(listen) not in local_addresses:raise ValueError('listener IP is not assigned to this server')
        port=rule.get('listen_port');backend_port=rule.get('backend_port')
        if type(port) is not int or not 1<=port<=65535 or type(backend_port) is not int or not 1<=backend_port<=65535:raise ValueError('ports must be 1..65535')
        endpoint=(str(listen),port)
        if endpoint in seen:raise ValueError('duplicate listener address and port')
        seen.add(endpoint)
        algorithm=rule.get('algorithm')
        if algorithm not in ('roundrobin','leastconn','source','first'):raise ValueError('invalid balancing algorithm')
        proxy_protocol=rule.get('proxy_protocol','none')
        if proxy_protocol not in ('none','send-proxy-v2'):raise ValueError('invalid PROXY protocol mode')
        check_send_proxy=rule.get('check_send_proxy',False);shutdown_sessions=rule.get('shutdown_sessions',False)
        if type(check_send_proxy) is not bool or type(shutdown_sessions) is not bool:raise ValueError('invalid HA health-check options')
        backends=rule.get('backends')
        if not isinstance(backends,list) or not 1<=len(backends)<=32:raise ValueError('select 1..32 healthy tunnel paths')
        if algorithm=='first' and sum(1 for b in backends if isinstance(b,dict) and b.get('role','primary')=='primary')!=1:raise ValueError('failover requires exactly one primary backend')
        bind=f'[{listen}]:{port}' if listen.version==6 else f'{listen}:{port}'
        lines += ['',f'frontend tm_fwd_{ident}','    mode tcp',f'    bind {bind}']
        if algorithm=='first':lines.append('    option clitcpka')
        lines += [f'    default_backend tm_pool_{ident}',f'backend tm_pool_{ident}','    mode tcp',f'    balance {algorithm}','    option tcp-check']
        if algorithm=='first':
            lines += ['    option redispatch 1','    option srvtcpka','    retries 1']
            default_server='    default-server inter 1200ms fastinter 600ms downinter 5s fall 2 rise 2'
            if check_send_proxy:default_server+=' check-send-proxy'
            lines.append(default_server)
        path_names=set();used_tunnels=set()
        for idx,backend in enumerate(backends,1):
            if not isinstance(backend,dict):raise ValueError('invalid backend entry')
            if backend.get('role','primary') not in ('primary','backup'):raise ValueError('invalid backend role')
            tunnel=backend.get('tunnel_id','')
            if not isinstance(tunnel,str) or not ID.fullmatch(tunnel):raise ValueError('invalid tunnel id in backend')
            if tunnel in used_tunnels:raise ValueError('duplicate tunnel path')
            used_tunnels.add(tunnel)
            try:address=ipaddress.ip_address(backend.get('address',''))
            except ValueError as e:raise ValueError('backend address must be an IP address') from e
            with sqlite3.connect('/var/lib/tunnelmgr/state.sqlite3') as database:
                row=database.execute('SELECT metadata FROM tunnels WHERE id=?',(tunnel,)).fetchone()
            if not row:raise ValueError('backend tunnel does not exist on this server')
            metadata=json.loads(row[0]);peer=metadata.get('tun_remote','')
            if not peer or str(ipaddress.ip_interface(peer).ip)!=str(address) or metadata.get('transport')=='erspan':raise ValueError('backend address does not match an eligible tunnel peer')
            weight=backend.get('weight',1)
            if type(weight) is not int or not 1<=weight<=256:raise ValueError('backend weight must be 1..256')
            name=f'path{idx}_{tunnel}'
            if name in path_names:raise ValueError('duplicate tunnel path')
            path_names.add(name)
            target=f'[{address}]:{backend_port}' if address.version==6 else f'{address}:{backend_port}'
            options=['check']
            if algorithm=='first' and backend.get('role')=='backup':options.append('backup')
            if proxy_protocol=='send-proxy-v2':options.append('send-proxy-v2')
            if algorithm!='first':options += ['inter','2s','fall','3','rise','2','weight',str(weight)]
            if shutdown_sessions:options += ['on-marked-down','shutdown-sessions']
            lines.append(f'    server {name} {target} '+' '.join(options))
    lines.append(HAPROXY_MARKER_END)
    content=base.rstrip()+'\n\n'+'\n'.join(lines)+'\n'
    haproxy_commit(content,previous,active)
    return {'ok':True,'active':True,'status':'active'}
def handle(c):
    try:
        _,uid,_=struct.unpack('3i',c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
        if uid!=APP_UID:return send(c,{'error':'peer not authorized'})
        raw=c.makefile("rb").readline(65537)
        if len(raw)>65536:return send(c,{'error':'request too large'})
        req=json.loads(raw);op=req.get('op');ident=req.get('id')
        if not isinstance(ident,str) or not ID.fullmatch(ident):return send(c,{'error':'invalid id'})
        if op=='probe':
            peer=ipaddress.ip_address(req.get('peer',''))
            iface=req.get('interface')
            local=req.get('local')
            if iface is not None and (not isinstance(iface,str) or not NAME.fullmatch(iface)):raise ValueError('invalid probe interface')
            if local is not None:local=str(ipaddress.ip_address(str(local).split('/',1)[0]))
            ping=shutil.which('ping') or '/usr/bin/ping'
            args=[ping,'-n','-c','1','-W','1']
            if peer.version==6:args.insert(1,'-6')
            if iface:args += ['-I',iface]
            elif local:args += ['-I',local]
            args.append(str(peer))
            result=subprocess.run(args,capture_output=True,text=True,timeout=3)
            match=re.search(r'time[=<]([0-9.]+)\s*ms',result.stdout)
            return send(c,{'state':'up' if result.returncode==0 else 'down','reachable':result.returncode==0,'rtt_ms':float(match.group(1)) if match else None,'checked_at':int(time.time()),'probe_error':None if result.returncode==0 else (result.stderr or result.stdout).strip()[-500:]})
        if op in ('interface-stats','send-erspan-probe'):
            interface=req.get('interface')
            if not isinstance(interface,str) or not NAME.fullmatch(interface):raise ValueError('invalid interface')
            device=Path('/sys/class/net')/interface
            if not device.is_dir():raise ValueError('interface is not present')
            stats=device/'statistics'
            if op=='interface-stats':
                return send(c,{'ok':True,'interface':interface,'rx_packets':int((stats/'rx_packets').read_text()),'rx_bytes':int((stats/'rx_bytes').read_text())})
            address=bytes.fromhex((device/'address').read_text().strip().replace(':',''))
            if len(address)!=6:raise ValueError('interface has no Ethernet address')
            frame=b'\xff'*6+address+b'\x88\xb5'+b'TUNNELMGR-ERSPAN-PROBE'+os.urandom(8)
            probe=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0003))
            try:
                probe.bind((interface,0));sent=probe.send(frame)
            finally:probe.close()
            return send(c,{'ok':sent==len(frame),'interface':interface,'bytes':sent,'checked_at':int(time.time())})
        if op=='secret':
            action=req.get('action');path=Path('/etc/backhaul/secrets')/(ident+'.token')
            if action=='create':
                value=req.get('value')
                if not isinstance(value,str) or not 16<=len(value)<=4096 or not re.fullmatch(r'[A-Za-z0-9_=-]+',value):raise ValueError('invalid shared secret')
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'w') as f:f.write(value+'\n')
                return send(c,{'ok':True,'path':str(path)})
            if action=='delete':
                path.unlink(missing_ok=True)
                return send(c,{'ok':True})
            raise ValueError('invalid secret action')
        if op=='profile':return send(c,manage(req,ident))
        if op in ('mesh-apply','mesh-status'):
            if not os.path.isfile('/etc/tunnelmgr/mesh/'+ident+'.json'):raise ValueError('unknown deployment profile')
            unit='tunnelmgr-mesh@'+ident+'.service'
            cmd=['start','--no-block',unit] if op=='mesh-apply' else ['show','-p','ActiveState','-p','Result','-p','ExecMainStatus',unit]
            result=subprocess.run(['/usr/bin/systemctl',*cmd],capture_output=True,text=True,timeout=8)
            return send(c,{'ok':result.returncode==0,'output':(result.stdout+result.stderr).strip()})
        if op=='create':return send(c,tunnel_create(req,ident))
        if op=='haproxy':return send(c,haproxy_apply(req))
        if op=='panel-tls':
            action=req.get('action')
            if action=='status':
                path=Path('/var/lib/tunnelmgr/panel-tls-status.json');request_path=Path('/etc/tunnelmgr/panel-tls-request.json')
                request=json.loads(request_path.read_text()) if request_path.is_file() else {}
                result=json.loads(path.read_text()) if path.is_file() else {'state':'unconfigured','port':8765}
                active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','avatun-panel-tls.service']).returncode==0
                if active and result.get('state') not in ('working','ready'):result={'state':'working','step':'starting','message':'در حال آماده‌سازی گواهی…',**{k:v for k,v in result.items() if k in ('domain','email','port')}}
                if not active and request and result.get('state') in ('unconfigured','working'):
                    outcome=subprocess.run(['/usr/bin/systemctl','show','avatun-panel-tls.service','-p','Result','--value'],capture_output=True,text=True,timeout=5).stdout.strip()
                    if outcome not in ('','success'):
                        journal=subprocess.run(['/usr/bin/journalctl','-u','avatun-panel-tls.service','-n','12','-o','cat','--no-pager'],capture_output=True,text=True,timeout=8).stdout.strip()[-1800:]
                        result={'state':'error','step':'failed','message':'سرویس صدور گواهی اجرا نشد: '+(journal or outcome),'domain':request.get('domain'),'email':request.get('email'),'port':request.get('port',8765)}
                for key in ('domain','email','port'):
                    if key not in result and key in request:result[key]=request[key]
                return send(c,{'ok':True,**result})
            if action=='apply':
                domain=req.get('domain');email=req.get('email');port=req.get('port')
                if not isinstance(domain,str) or len(domain)>253 or not re.fullmatch(r'(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain):raise ValueError('دامنه یا زیردامنه معتبر وارد کن.')
                if not isinstance(email,str) or len(email)>254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email):raise ValueError('ایمیل معتبر وارد کن.')
                if type(port) is not int or not 1024<=port<=65535 or port==443:raise ValueError('پورت آزاد بین ۱۰۲۴ تا ۶۵۵۳۵ انتخاب کن؛ ۴۴۳ برای سرویس‌ها رزرو است.')
                active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','avatun-panel-tls.service']).returncode==0
                if active:raise ValueError('درخواست صدور گواهی دیگری در حال اجراست؛ کمی صبر کن.')
                request=Path('/etc/tunnelmgr/panel-tls-request.json');request.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                tmp=request.with_suffix('.tmp');tmp.write_text(json.dumps({'domain':domain.lower(),'email':email,'port':port}));tmp.chmod(0o600);os.replace(tmp,request)
                subprocess.run(['/usr/bin/systemctl','start','--no-block','avatun-panel-tls.service'],check=True,capture_output=True,text=True,timeout=10)
                return send(c,{'ok':True,'state':'working','domain':domain.lower(),'port':port})
            raise ValueError('invalid panel TLS action')
        if op in ('start','stop','restart','health'):
            p=invoke([op,ident]);return send(c,{'ok':p.returncode==0,'output':(p.stdout+p.stderr)[-8000:]})
        if op=='delete':
            p=invoke(['delete',ident,'--yes']);return send(c,{'ok':p.returncode==0,'output':(p.stdout+p.stderr)[-8000:]})
        if op=='status':
            p=invoke(['status',ident],10)
            if p.returncode:return send(c,{'error':p.stderr[-2000:]})
            return send(c,{'status':json.loads(p.stdout)[0]})
        if op=='logs':
            p=subprocess.run(['/usr/bin/journalctl','--no-pager','-u',f'backhaul-{ident}.service','-n','100','-o','cat'],text=True,capture_output=True,timeout=10)
            return send(c,{'logs':p.stdout[-12000:]})
        return send(c,{'error':'operation not allowed'})
    except Exception as e:
        try:send(c,{'error':str(e)[:500]})
        except OSError:pass
    finally:c.close()
def main():
    os.makedirs('/run/tunnelmgr',mode=0o750,exist_ok=True)
    try:os.unlink(SOCKET)
    except FileNotFoundError:pass
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(SOCKET);os.chown(SOCKET,0,pwd.getpwnam('tunnelmgr').pw_gid);os.chmod(SOCKET,0o660);s.listen(32)
    while True:
        c,_=s.accept();handle(c)
if __name__=='__main__':main()
