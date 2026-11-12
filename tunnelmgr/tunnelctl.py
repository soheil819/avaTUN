#!/usr/bin/env python3
"""avaTUN API; delegates Backhaul operations to the installed Backhaul manager."""
from __future__ import annotations
import hashlib
import argparse, getpass, ipaddress, json, os, pathlib, re, secrets, shlex, shutil, sqlite3, subprocess, sys, time
import tarfile, tempfile
import ssl, socket, urllib.request
from concurrent.futures import ThreadPoolExecutor
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from topology import mesh_plan

APP_NAME="avatun"
APP_VERSION="0.1.29"
BASE=pathlib.Path(os.environ.get("TUNNELMGR_HOME",str(pathlib.Path.home()/".local/share/tunnelmgr")))
DB=BASE/"state.sqlite3"
MANAGER=os.environ.get("BACKHAUL_MANAGER","backhaul-manager")
ID=re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
SESSIONS={}
MONITOR_LOCK=threading.Lock();MONITOR_TUNNELS={};MONITOR_SERVERS=[];MONITOR_RESOURCES=[]
GEOIP_CACHE={}
FIELDS={"listen","peer","secret_file","tun_name","tun_local","tun_remote","tun_mtu","health_port","replace"}

def db():
    BASE.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(BASE,0o700)
    class ManagedConnection(sqlite3.Connection):
        def __exit__(self,exc_type,exc,tb):
            try:return super().__exit__(exc_type,exc,tb)
            finally:self.close()
    c=sqlite3.connect(DB,factory=ManagedConnection); c.row_factory=sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS tunnels(id TEXT PRIMARY KEY,kind TEXT NOT NULL,mode TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,metadata TEXT NOT NULL DEFAULT '{}')")
    legacy=c.execute("SELECT id,metadata FROM tunnels WHERE kind LIKE 'backhaul-%'").fetchall()
    for row in legacy:
        metadata=json.loads(row["metadata"] or "{}")
        if "manager" in metadata:metadata["manager"]="Backhaul"
        c.execute("UPDATE tunnels SET kind='backhaul',metadata=? WHERE id=?",(json.dumps(metadata),row["id"]))
    c.execute("CREATE TABLE IF NOT EXISTS accounts(name TEXT PRIMARY KEY,role TEXT NOT NULL,digest TEXT UNIQUE NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY,host TEXT NOT NULL,user TEXT NOT NULL,identity TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    server_columns={r[1] for r in c.execute("PRAGMA table_info(servers)")}
    if "proxy_server_id" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN proxy_server_id TEXT NOT NULL DEFAULT ''")
    if "location" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN location TEXT NOT NULL DEFAULT 'abroad'")
    if "auto_geoip" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN auto_geoip INTEGER NOT NULL DEFAULT 1")
    if "geoip_host" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN geoip_host TEXT NOT NULL DEFAULT ''")
    c.execute("CREATE TABLE IF NOT EXISTS port_forwards(id TEXT PRIMARY KEY,config TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS routing_links(id TEXT PRIMARY KEY,config TEXT NOT NULL)")
    c.commit(); return c

def password_digest(password, salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
    return salt.hex()+":"+digest.hex()

def verify_password(password, encoded):
    try:
        salt,expected=encoded.split(":",1)
        actual=password_digest(password,bytes.fromhex(salt)).split(":",1)[1]
        return secrets.compare_digest(actual,expected)
    except (ValueError,TypeError):return False

def account(args):
    with db() as c:
        if args.action=="list":
            print(json.dumps([dict(x) for x in c.execute("SELECT name,role FROM accounts ORDER BY name")]))
            return
        if not args.name or not ID.fullmatch(args.name):raise ValueError("invalid account name")
        if args.action=="revoke":
            if not c.execute("DELETE FROM accounts WHERE name=?",(args.name,)).rowcount:raise ValueError("unknown account")
            return
        password=args.password or (sys.stdin.readline().rstrip("\r\n") if getattr(args,"password_stdin",False) else getpass.getpass("New password (12+ characters): "))
        if len(password)<12:raise ValueError("password must contain at least 12 characters")
        if args.action=="password":
            if not c.execute("UPDATE accounts SET digest=? WHERE name=?",(password_digest(password),args.name)).rowcount:raise ValueError("unknown account")
        else:c.execute("INSERT INTO accounts VALUES(?,?,?)",(args.name,args.role,password_digest(password)))
        c.commit()
        print("account created")

def rows():
    with db() as c:return [dict(r)|{"metadata":json.loads(r["metadata"])} for r in c.execute("SELECT * FROM tunnels ORDER BY id")]
def find(ident):return next((x for x in rows() if x["id"]==ident),None)

def erspan_health(item):
    checked=int(time.time())
    try:
        config=tunnel_config(item['id']);mirror=config.get('mirror_interface')
        if not mirror:return {'state':'monitor-only','reachable':None,'checked_at':checked,'probe_error':'no mirror source is configured'}
        peer=item.get('metadata',{}).get('outer_peer')
        server=next((s for s in server_rows() if s.get('host','').strip('[]')==str(peer)),None)
        if not server:return {'state':'monitor-only','reachable':None,'checked_at':checked,'probe_error':'peer server is not registered'}
        remote=server_remote(server,{'op':'config','id':item['id']})
        receiver=remote.get('interface')
        if not receiver:return {'state':'down','reachable':False,'checked_at':checked,'probe_error':'peer ERSPAN interface is missing'}
        before=server_remote(server,{'op':'interface-stats','id':item['id'],'interface':receiver})
        sent=privileged({'op':'send-erspan-probe','id':item['id'],'interface':mirror})
        if not sent.get('ok'):raise RuntimeError(sent.get('error','could not send ERSPAN probe frame'))
        after=server_remote(server,{'op':'interface-stats','id':item['id'],'interface':receiver})
        delta=max(0,int(after.get('rx_packets',0))-int(before.get('rx_packets',0)))
        return {'state':'up' if delta else 'down','reachable':bool(delta),'checked_at':checked,'rtt_ms':None,'rx_packets':delta,'probe_error':None if delta else 'ERSPAN probe frame did not reach the peer'}
    except Exception as e:return {'state':'down','reachable':False,'checked_at':checked,'rtt_ms':None,'probe_error':str(e)[-500:]}

def tunnel_health(item):
    meta=item.get("metadata",{});peer=meta.get("tun_remote");iface=meta.get("tun_name")
    if meta.get('transport')=='erspan':return erspan_health(item)
    if not peer:return {"state":"monitor-only","reachable":None,"checked_at":int(time.time())}
    peer=peer.split("/",1)[0]
    local=meta.get("tun_local")
    if meta.get("transport") in ("ipsec-ikev2","ipsec-esp-udp","esp"):iface=None
    try:
        result=privileged({"op":"probe","id":item["id"],"peer":peer,"interface":None,"local":local})
        if result.get("error"):raise RuntimeError(result["error"])
        if result.get("state")!="up" and iface and local:
            fallback=privileged({"op":"probe","id":item["id"],"peer":peer,"interface":iface,"local":None})
            if fallback.get("state")=="up":return fallback
        return result
    except Exception as e:
        return {"state":"error","reachable":False,"error":str(e),"checked_at":int(time.time())}

def path_mtu_probe(host):
    """Measure route MTU with DF ping, falling back to the egress link MTU."""
    target=ipaddress.ip_address(str(host).strip("[]"));family="-6" if target.version==6 else "-4"
    route=subprocess.run(["/usr/sbin/ip",family,"-json","route","get",str(target)],capture_output=True,text=True,timeout=8)
    if route.returncode:raise RuntimeError("could not resolve route to tunnel peer")
    routes=json.loads(route.stdout or "[]")
    if not routes:raise RuntimeError("no route to tunnel peer")
    item=routes[0];route_mtu=int(item.get("mtu",0) or 0);dev=item.get("dev")
    if not route_mtu and dev:
        links=subprocess.run(["/usr/sbin/ip","-json","link","show","dev",dev],capture_output=True,text=True,timeout=8)
        if links.returncode==0:
            found=json.loads(links.stdout or "[]")
            if found:route_mtu=int(found[0].get("mtu",1500))
    route_mtu=max(576,min(9000,route_mtu or 1500));floor=1280 if target.version==6 else 576
    ping=shutil.which("ping")
    if not ping:return {"mtu":route_mtu,"method":"egress-interface","device":dev}
    header=48 if target.version==6 else 28;low=floor-header;high=route_mtu-header;best=-1
    while low<=high:
        payload=(low+high)//2;args=[ping,family,"-n","-c","1","-W","1","-M","do","-s",str(payload),str(target)]
        try:probe=subprocess.run(args,capture_output=True,text=True,timeout=3)
        except (OSError,subprocess.TimeoutExpired):break
        if probe.returncode==0:best=payload;low=payload+1
        else:high=payload-1
    if best<0:return {"mtu":route_mtu,"method":"egress-interface-fallback","device":dev}
    return {"mtu":best+header,"method":"df-ping","device":dev}

def recommended_tunnel_mtu(server_a,server_b,host_a,host_b,transport):
    overhead={"backhaul":80,"gre":24,"gretap":38,"geneve":50,"vxlan":50,"ipip":20,"sit-6to4":20,"sit-isatap":20,"gre-fou":52,"ipip-fou":48,"sit-fou":48,"l2tpv3":36,"ipsec-ikev2":56,"ipsec-esp-udp":82,"esp":60,"wireguard":60,"openvpn":60,"openconnect":60}
    if transport not in overhead:raise ValueError("unsupported tunnel type for MTU calculation")
    servers={s["id"]:s for s in server_rows()};
    if server_a!="local" and server_a not in servers or server_b!="local" and server_b not in servers:raise ValueError("MTU probe requires both registered tunnel endpoints")
    local_probe=path_mtu_probe(host_b) if server_a=="local" else server_remote(servers[server_a],{"op":"mtu-probe","host":host_b})
    peer_probe=path_mtu_probe(host_a) if server_b=="local" else server_remote(servers[server_b],{"op":"mtu-probe","host":host_a})
    effective=min(int(local_probe["mtu"]),int(peer_probe["mtu"]))-overhead[transport]
    min_mtu=1280 if transport in ("sit-6to4","sit-fou","sit-isatap") else 576
    if effective<min_mtu:raise ValueError(f"Measured path MTU is too small for {transport} after encapsulation overhead ({effective})")
    return {"mtu":min(9000,effective),"path_mtu_a":local_probe["mtu"],"path_mtu_b":peer_probe["mtu"],"overhead":overhead[transport],"method_a":local_probe.get("method"),"method_b":peer_probe.get("method")}

def ssh_argv(server):
    try:ipaddress.ip_address(server["host"].strip("[]"));host=f'[{server["host"].strip("[]")}]' if ":" in server["host"] else server["host"]
    except ValueError:host=server["host"]
    cmd=["ssh","-T","-o","StrictHostKeyChecking=accept-new","-o",f"UserKnownHostsFile={BASE/'known_hosts'}","-o","ConnectTimeout=12","-o","BatchMode=yes"]
    if server.get("identity"):cmd += ["-i",server["identity"],"-o","IdentitiesOnly=yes"]
    proxy_id=server.get("proxy_server_id")
    if proxy_id:
        proxy=next((s for s in server_rows() if s["id"]==proxy_id),None)
        if not proxy:raise ValueError(f"SSH proxy server {proxy_id} is missing")
        if proxy.get("proxy_server_id"):raise ValueError("SSH proxy chains are limited to one hop")
        try:ipaddress.ip_address(proxy["host"].strip("[]"));proxy_host=f'[{proxy["host"].strip("[]")}]' if ":" in proxy["host"] else proxy["host"]
        except ValueError:proxy_host=proxy["host"]
        jump=["ssh","-T","-o","StrictHostKeyChecking=accept-new","-o",f"UserKnownHostsFile={BASE/'known_hosts'}","-o","ConnectTimeout=12","-o","BatchMode=yes"]
        if proxy.get("identity"):jump += ["-i",proxy["identity"],"-o","IdentitiesOnly=yes"]
        jump += ["-W","%h:%p",f'{proxy["user"]}@{proxy_host}']
        cmd += ["-o","ProxyCommand="+shlex.join(jump)]
    return cmd+[f'{server["user"]}@{host}']

def password_ssh(server,remote,password):
    askdir=pathlib.Path(tempfile.mkdtemp(prefix="tunnelmgr-askpass-"))
    ask=askdir/"askpass"
    ask.write_text("#!/bin/sh\nprintf '%s\\n' \"$TUNNELMGR_SSH_PASSWORD\"\n");ask.chmod(0o700)
    env=os.environ.copy();env.update({"SSH_ASKPASS":str(ask),"SSH_ASKPASS_REQUIRE":"force","DISPLAY":"tunnelmgr:0","TUNNELMGR_SSH_PASSWORD":password})
    argv=ssh_argv(server)
    batch=argv.index("BatchMode=yes") if "BatchMode=yes" in argv else -1
    if batch>=0:argv[batch-1:batch+1]=[]
    argv += ["-o","BatchMode=no","-o","PreferredAuthentications=password,keyboard-interactive","-o","PubkeyAuthentication=no",remote]
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=25,env=env,stdin=subprocess.DEVNULL,start_new_session=True)
        if p.returncode:raise RuntimeError((p.stderr or p.stdout)[-1200:])
        return p.stdout
    finally:shutil.rmtree(askdir,ignore_errors=True)

def bootstrap_server(server,password):
    keydir=BASE/"ssh-keys";keydir.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(keydir,0o700)
    private=keydir/(server["id"]+".key");public=pathlib.Path(str(private)+".pub")
    if private.exists():raise ValueError("برای این شناسه کلید مدیریتی وجود دارد؛ ابتدا سرور قبلی را از فهرست حذف کنید")
    try:
        p=subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(private)],capture_output=True,text=True,timeout=15)
        if p.returncode:raise RuntimeError(p.stderr.strip() or "ساخت کلید SSH ناموفق بود")
        private.chmod(0o600);public.chmod(0o600)
        pub=public.read_text().strip();server={**server,"identity":str(private)}
        quoted=shlex.quote(pub)
        command=f"umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -qxF {quoted} ~/.ssh/authorized_keys || printf '%s\\n' {quoted} >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"
        password_ssh(server,command,password)
        return server
    except Exception:
        private.unlink(missing_ok=True);public.unlink(missing_ok=True);raise

def remove_bootstrap_key(server):
    identity=pathlib.Path(server.get("identity",""))
    try:identity.relative_to((BASE/"ssh-keys").resolve())
    except ValueError:return
    public=pathlib.Path(str(identity)+".pub")
    if not public.is_file():return
    quoted=shlex.quote(public.read_text().strip())
    remote=f"if [ -f ~/.ssh/authorized_keys ]; then grep -vxF {quoted} ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tunnelmgr.tmp || true; mv ~/.ssh/authorized_keys.tunnelmgr.tmp ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; fi"
    p=subprocess.run(ssh_argv(server)+[remote],capture_output=True,text=True,timeout=20)
    if p.returncode:raise RuntimeError((p.stderr or p.stdout)[-1000:])
    identity.unlink(missing_ok=True);public.unlink(missing_ok=True)

def server_rows():
    with db() as c:return [dict(r) for r in c.execute("SELECT * FROM servers ORDER BY id")]

def geoip_location(host):
    """Return a map location from the public address GeoIP currently sees."""
    host=str(host or "").strip().strip("[]")
    if not host:raise ValueError("IP یا نام میزبان برای GeoIP وارد نشده است")
    try:addresses=[ipaddress.ip_address(host)]
    except ValueError:
        try:addresses=list(dict.fromkeys(ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)))
        except Exception as e:raise ValueError("نام میزبان به IP تبدیل نشد؛ آدرس را بررسی کن") from e
    address=next((item for item in addresses if item.is_global),None)
    if address is None:raise ValueError("GeoIP فقط برای IP عمومی قابل استفاده است")
    key=str(address);cached=GEOIP_CACHE.get(key)
    if cached and cached["expires"]>time.time():return dict(cached["result"])
    providers=(f"https://ipwho.is/{key}",f"https://ipapi.co/{key}/json/")
    failures=[];data={}
    for url in providers:
        request=urllib.request.Request(url,headers={"User-Agent":"avaTUN/0.1 GeoIP"})
        try:
            with urllib.request.urlopen(request,timeout=5,context=ssl.create_default_context()) as response:data=json.loads(response.read(32768).decode("utf-8"))
            code=str(data.get("country_code") or "").upper()
            if data.get("success",True) and re.fullmatch(r"[A-Z]{2}",code):break
            failures.append(str(data.get("message") or "پاسخ نامعتبر GeoIP"))
        except Exception as e:failures.append(str(e))
    else:raise RuntimeError("سرویس‌های GeoIP کشور این IP را مشخص نکردند: "+" | ".join(failures))
    result={"location":"iran" if code=="IR" else "abroad","country_code":code,"country_name":str(data.get("country_name") or data.get("country") or code),"ip":key}
    GEOIP_CACHE[key]={"expires":time.time()+3600,"result":result}
    return dict(result)

def refresh_server_locations():
    for item in server_rows():
        if not item["auto_geoip"] or item["geoip_host"] == item["host"]:
            continue
        try:
            result = geoip_location(item["host"])
            with db() as connection:
                connection.execute(
                    "UPDATE servers SET location=?,geoip_host=? WHERE id=? AND host=? AND auto_geoip=1",
                    (result["location"], item["host"], item["id"], item["host"]),
                )
        except Exception as error:
            print(f"GeoIP {item['id']}: {error}", file=sys.stderr, flush=True)


def geoip_monitor_loop():
    while True:
        try:
            refresh_server_locations()
        except Exception as error:
            print(f"GeoIP monitor: {error}", file=sys.stderr, flush=True)
        time.sleep(60)


def resource_snapshot():
    cpu_fields=pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:]
    cpu_values=[int(x) for x in cpu_fields]
    cpu_total=sum(cpu_values);cpu_idle=cpu_values[3]+(cpu_values[4] if len(cpu_values)>4 else 0)
    mem={}
    for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
        key,_,value=line.partition(':')
        if value.strip():mem[key]=int(value.split()[0])*1024
    ram_total=mem.get('MemTotal',0);ram_available=mem.get('MemAvailable',mem.get('MemFree',0))
    swap_total=mem.get('SwapTotal',0);swap_free=mem.get('SwapFree',0)
    disk=shutil.disk_usage('/')
    net_rx=net_tx=0;net_interfaces=[]
    for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]:
        name,_,stats=line.partition(':');name=name.strip()
        if not name or name=='lo' or not (pathlib.Path('/sys/class/net')/name/'device').exists():continue
        values=[int(x) for x in stats.split()]
        if len(values)>=9:net_rx+=values[0];net_tx+=values[8];net_interfaces.append(name)
    percent=lambda used,total:round(100.0*used/total,1) if total else 0.0
    return {'cpu_percent':0.0,'cpu_total_ticks':cpu_total,'cpu_idle_ticks':cpu_idle,
            'memory_used_bytes':max(0,ram_total-ram_available),'memory_total_bytes':ram_total,
            'memory_percent':percent(max(0,ram_total-ram_available),ram_total),
            'swap_used_bytes':max(0,swap_total-swap_free),'swap_total_bytes':swap_total,
            'swap_percent':percent(max(0,swap_total-swap_free),swap_total),
            'disk_used_bytes':disk.used,'disk_total_bytes':disk.total,
            'disk_percent':percent(disk.used,disk.total),'disk_mount':'/',
            'net_rx_bytes':net_rx,'net_tx_bytes':net_tx,'net_interfaces':net_interfaces,
            'load_1m':os.getloadavg()[0] if hasattr(os,'getloadavg') else 0.0,
            'uptime_seconds':int(float(pathlib.Path('/proc/uptime').read_text().split()[0])),
            'checked_at':int(time.time())}

def server_probe(server):
    try:
        result=server_remote(server,{"op":"list"})
        return {"id":server["id"],"host":server["host"],"reachable":True,"services":result.get("services",[]),"tunnels":result.get("items",[]),"resources":result.get("resources"),"app_version":result.get("app_version","نامشخص")}
    except Exception as e:return {"id":server["id"],"host":server["host"],"reachable":False,"error":str(e)[-500:],"tunnels":[]}

def monitor_loop():
    global MONITOR_TUNNELS,MONITOR_SERVERS
    while True:
        try:
            current=rows()
            with ThreadPoolExecutor(max_workers=min(8,max(1,len(current)))) as pool:probes=list(pool.map(tunnel_health,current))
            local={item["id"]:probe for item,probe in zip(current,probes)}
            servers=server_rows()
            with ThreadPoolExecutor(max_workers=min(8,max(1,len(servers)))) as pool:remote=list(pool.map(server_probe,servers))
            services=[subprocess.run(['/usr/bin/systemctl','is-active',u],capture_output=True,text=True).stdout.strip() for u in ('tunnelmgr.service','tunnelmgr-privd.service')]
            local_status={'id':'local','name':'سرور مرکزی','host':'سرور پنل','reachable':True,'services':services,'tunnels':[],'app_version':APP_VERSION}
            with MONITOR_LOCK:MONITOR_TUNNELS,MONITOR_SERVERS=local,[local_status,*remote]
        except Exception as e:print(f"monitor: {e}",file=sys.stderr,flush=True)
        time.sleep(10)

def resource_monitor_loop():
    global MONITOR_RESOURCES
    previous={}
    while True:
        started=time.monotonic()
        try:
            servers=server_rows()
            with ThreadPoolExecutor(max_workers=min(8,max(1,len(servers)))) as pool:
                probes=list(pool.map(lambda server:(server,server_remote(server,{'op':'resources'})),servers))
            current=[{'id':'local','name':'سرور مرکزی','host':'سرور پنل','reachable':True,'resources':resource_snapshot()}]
            current.extend({'id':server['id'],'name':server['id'],'host':server['host'],'reachable':True,'resources':result} for server,result in probes)
            now=time.monotonic()
            for status in current:
                resources=status['resources'];prior=previous.get(status['id']);rx=resources.get('net_rx_bytes',0);tx=resources.get('net_tx_bytes',0)
                elapsed=max(.001,now-prior[0]) if prior else 0
                if prior:
                    total_delta=resources['cpu_total_ticks']-prior[3];idle_delta=resources['cpu_idle_ticks']-prior[4]
                    resources['cpu_percent']=round(max(0.0,min(100.0,100.0*(total_delta-idle_delta)/max(1,total_delta))),1)
                    resources['download_bytes_per_sec']=max(0,rx-prior[1])/elapsed
                    resources['upload_bytes_per_sec']=max(0,tx-prior[2])/elapsed
                else:resources['download_bytes_per_sec']=resources['upload_bytes_per_sec']=0.0
                previous[status['id']]=(now,rx,tx,resources['cpu_total_ticks'],resources['cpu_idle_ticks'])
            with MONITOR_LOCK:MONITOR_RESOURCES=current
        except Exception as e:print(f"resource monitor: {e}",file=sys.stderr,flush=True)
        time.sleep(max(0.2,2.0-(time.monotonic()-started)))

def server_remote(server,payload):
    import inspect
    code="import sys,json,subprocess,os,pathlib,shutil,time,ipaddress;sys.path.insert(0,'/opt/tunnelmgr/tunnelmgr');import tunnelctl as t;d=json.load(sys.stdin);op=d.get('op');out=None\nif op=='list':\n out=[]\n for x in t.rows():\n  try:\n   m=x['metadata'];native=m.get('native_profile');r=t.privileged({'op':'profile','group':'network','id':native,'action':'status'} if native else {'op':'status','id':x['id']});x['live']={'active':'ActiveState=active' in r.get('output','')} if native else r.get('status',{});x['health']=t.tunnel_health(x)\n  except Exception as e:x['live']={'active':False};x['health']={'state':'error','error':str(e)}\n  x['server_id']="+repr(server['id'])+";out.append(x)\n services=[subprocess.run(['/usr/bin/systemctl','is-active',u],capture_output=True,text=True).stdout.strip() for u in ('tunnelmgr.service','tunnelmgr-privd.service')];out={'items':out,'services':services}\nelif op=='resources':\n out=resource_snapshot()\nelif op=='interface-stats':\n out=t.privileged({'op':'interface-stats','id':d['id'],'interface':d['interface']})\nelif op=='mtu-probe':\n out=path_mtu_probe(d['host'])\nelif op=='create':\n out=t.create_instance(d['data']) if d['data'].get('transport')=='backhaul' else t.create_native(d['data'])\nelif op=='config':\n out=t.tunnel_config(d['id'])\nelif op=='update':\n out=t.update_tunnel(d['data'])\nelif op=='forward-apply':\n out=t.privileged({'op':'haproxy','id':'forwards','action':'apply','rules':d['rules']})\nelif op=='forward-status':\n out=t.privileged({'op':'haproxy','id':'forwards','action':'status'})\nelif op=='secret':\n out=t.privileged({'op':'secret','id':d['id'],'action':d['action'],'kind':d.get('kind','token'),'value':d.get('value')})\nelif op=='routing-profile-create':\n name=d['profile'];cfg=d['config'];out=t.privileged({'op':'profile','group':'network','id':name,'action':'create','config':cfg})\n if out.get('ok'):\n  out=t.privileged({'op':'profile','group':'network','id':name,'action':'start'})\n  if not out.get('ok'):t.privileged({'op':'profile','group':'network','id':name,'action':'delete'})\nelif op=='routing-profile-delete':\n p=t.privileged({'op':'profile','group':'network','id':d['profile'],'action':'read'});out=t.privileged({'op':'profile','group':'network','id':d['profile'],'action':'delete'}) if p.get('config') else {'ok':True,'already_removed':True}\nelif op=='routing-status':\n import routing as r\n p=t.privileged({'op':'profile','group':'network','id':d['profile'],'action':'read'});out=r.status(p['config']) if p.get('config') else {'state':'error','error':p.get('error','profile missing')}\nelif op=='operate':\n x=t.find(d['id'])\n if not x:raise ValueError('unknown tunnel')\n n=x['metadata'].get('native_profile');r=t.privileged({'op':'profile','group':'network','id':n,'action':d['action']} if n else {'op':d['action'],'id':d['id']})\n if d['action']=='delete' and r.get('ok'):\n  with t.db() as c:c.execute('DELETE FROM tunnels WHERE id=?',(d['id'],))\n out=r\nprint(json.dumps(out,ensure_ascii=False))"
    code=code.replace(";d=json.load(sys.stdin);op=", ";\n"+inspect.getsource(resource_snapshot)+"\n"+inspect.getsource(path_mtu_probe)+"\nd=json.load(sys.stdin);op=",1)
    code=code.replace("out={'items':out,'services':services}","out={'items':out,'services':services,'app_version':getattr(t,'APP_VERSION','نامشخص')}",1)
    guarded_code="import json\ntry:\n exec(compile("+repr(code)+", '<tunnelmgr-remote>', 'exec'))\nexcept Exception as exc:\n print(json.dumps({'error':str(exc)},ensure_ascii=False))"
    remote="runuser -u tunnelmgr -- env TUNNELMGR_HOME=/var/lib/tunnelmgr /usr/bin/python3 -c "+shlex.quote(guarded_code)
    proc=subprocess.run(ssh_argv(server)+[remote],input=json.dumps(payload),capture_output=True,text=True,timeout=90)
    if proc.returncode:raise RuntimeError((proc.stderr or proc.stdout)[-1600:])
    try:result=json.loads(proc.stdout)
    except json.JSONDecodeError as e:raise RuntimeError("invalid response from remote tunnel manager") from e
    if isinstance(result,dict) and result.get("error"):raise RuntimeError(result["error"])
    return result

def install_remote(server):
    root=pathlib.Path(__file__).resolve().parents[1]
    with tempfile.NamedTemporaryFile(suffix=".tgz") as bundle:
        with tarfile.open(bundle.name,"w:gz") as tf:
            for folder in ("tunnelmgr","web","packaging/systemd","vendor/backhaul"):
                for p in (root/folder).rglob("*"):
                    if p.is_file():tf.add(p,arcname=str(p.relative_to(root)))
            for name in ("install-preview.sh","mesh-deploy.py","mesh-worker.py"):
                p=root/"scripts"/name
                if p.is_file():tf.add(p,arcname=f"scripts/{name}")
        payload=pathlib.Path(bundle.name).read_bytes()
    remote="mkdir -p /tmp/tunnelmgr-bootstrap && tar -xzf - -C /tmp/tunnelmgr-bootstrap && sh /tmp/tunnelmgr-bootstrap/scripts/install-preview.sh"
    p=subprocess.run(ssh_argv(server)+[remote],input=payload,capture_output=True,timeout=180)
    if p.returncode:raise RuntimeError((p.stderr or p.stdout).decode(errors="replace")[-2000:])
    return {"ok":True,"output":p.stdout.decode(errors="replace")[-1500:]}
def save(ident,mode,metadata):
    with db() as c:c.execute("INSERT INTO tunnels(id,kind,mode,metadata) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET mode=excluded.mode,metadata=excluded.metadata",(ident,"backhaul",mode,json.dumps(metadata)))

def forward_rows():
    with db() as c:return [json.loads(r["config"]) for r in c.execute("SELECT config FROM port_forwards ORDER BY id")]

def normalize_forward(data,server_id):
    ident=data.get("id","")
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError("شناسهٔ پورت‌فوروارد نامعتبر است")
    if server_id!="local" and not any(s["id"]==server_id for s in server_rows()):raise ValueError("سرور شنود در فهرست مدیریت‌شده‌ها نیست")
    try:listen=str(ipaddress.ip_address(data.get("listen_ip","")))
    except ValueError as e:raise ValueError("آدرس شنود باید IP همین سرور باشد") from e
    listen_port=data.get("listen_port");backend_port=data.get("backend_port")
    if type(listen_port) is not int or not 1<=listen_port<=65535 or type(backend_port) is not int or not 1<=backend_port<=65535:raise ValueError("شمارهٔ پورت باید بین ۱ تا ۶۵۵۳۵ باشد")
    algorithm=data.get("algorithm","leastconn")
    if algorithm not in ("roundrobin","leastconn","source","first"):raise ValueError("الگوریتم پورت‌فوروارد نامعتبر است")
    proxy_protocol=data.get("proxy_protocol","none")
    if proxy_protocol not in ("none","send-proxy-v2"):raise ValueError("پروتکل PROXY نامعتبر است")
    check_send_proxy=data.get("check_send_proxy",False)
    shutdown_sessions=data.get("shutdown_sessions",False)
    if type(check_send_proxy) is not bool or type(shutdown_sessions) is not bool:raise ValueError("تنظیمات بررسی سلامت نامعتبر است")
    selected=data.get("backends")
    if not isinstance(selected,list) or not 1<=len(selected)<=32:raise ValueError("یک تا ۳۲ مسیر تونلی انتخاب کن")
    if server_id=="local":available=rows()
    else:
        server=next(s for s in server_rows() if s["id"]==server_id)
        result=server_remote(server,{"op":"list"});available=result.get("items",[])
    tunnel_map={item["id"]:item for item in available}
    backends=[]
    used=set()
    for entry in selected:
        if not isinstance(entry,dict):raise ValueError("مسیر تونلی نامعتبر است")
        tunnel_id=entry.get("tunnel_id")
        if not isinstance(tunnel_id,str) or not ID.fullmatch(tunnel_id):raise ValueError("شناسهٔ تونل نامعتبر است")
        if tunnel_id in used:raise ValueError("مسیر تونلی تکراری انتخاب شده است")
        used.add(tunnel_id)
        weight=entry.get("weight",1)
        if type(weight) is not int or not 1<=weight<=256:raise ValueError("وزن مسیر باید بین ۱ تا ۲۵۶ باشد")
        role=entry.get("role","primary")
        if role not in ("primary","backup"):raise ValueError("نقش مسیر باید primary یا backup باشد")
        item=tunnel_map.get(tunnel_id)
        if not item:raise ValueError(f"تونل {tunnel_id} روی سرور انتخاب‌شده پیدا نشد")
        meta=item.get("metadata",{});transport=meta.get("transport","")
        if transport=="erspan":raise ValueError("ERSPAN برای حمل ترافیک پورت‌فوروارد مناسب نیست")
        remote=meta.get("tun_remote")
        if not remote:raise ValueError(f"تونل {tunnel_id} آدرس داخلی peer ندارد")
        try:peer_address=ipaddress.ip_interface(remote).ip
        except ValueError as e:raise ValueError(f"IP داخلی peer در تونل {tunnel_id} نامعتبر است") from e
        requested=entry.get('address')
        if requested:
            try:address_ip=ipaddress.ip_address(requested)
            except ValueError as e:raise ValueError(f"IP مقصد برای تونل {tunnel_id} نامعتبر است") from e
            if address_ip.version!=peer_address.version:
                family="IPv4" if peer_address.version==4 else "IPv6"
                raise ValueError(f"IP مقصد برای تونل {tunnel_id} باید از نوع {family} باشد")
            if address_ip!=peer_address:
                routed=False
                with db() as c:route_rows=[json.loads(r['config']) for r in c.execute('SELECT config FROM routing_links')]
                for link in route_rows:
                    if link.get('tunnel_id')!=tunnel_id:continue
                    if server_id==link.get('server_a'):peer_config=link.get('config_b',{})
                    elif server_id==link.get('server_b'):peer_config=link.get('config_a',{})
                    else:continue
                    if any(address_ip in ipaddress.ip_network(prefix,strict=True) for prefix in peer_config.get('networks',[]) if ipaddress.ip_network(prefix,strict=True).version==address_ip.version):
                        routed=True;break
                if not routed:raise ValueError(f"{address_ip} is not advertised by the far end of an active BGP/OSPF link on tunnel {tunnel_id}")
            address=str(address_ip)
        else:address=str(peer_address)
        backends.append({"tunnel_id":tunnel_id,"address":address,"weight":weight,"role":role})
    if algorithm=="first" and sum(1 for backend in backends if backend["role"]=="primary")!=1:
        raise ValueError("در حالت Failover دقیقاً یک مسیر را Primary انتخاب کن؛ بقیه مسیرها Backup هستند")
    return {"id":ident,"server_id":server_id,"listen_ip":listen,"listen_port":listen_port,"backend_port":backend_port,"algorithm":algorithm,"proxy_protocol":proxy_protocol,"check_send_proxy":check_send_proxy,"shutdown_sessions":shutdown_sessions,"backends":backends}

def _prefixes(value):
    if isinstance(value,str):value=[x.strip() for x in value.split(',') if x.strip()]
    if not isinstance(value,list):raise ValueError('prefix list must be comma-separated IPv4 networks')
    result=[]
    for prefix in value:
        network=ipaddress.IPv4Network(prefix,strict=True)
        text=str(network)
        if text not in result:result.append(text)
    return result

def _routing_profile_apply(server_id,profile_id,config,action):
    if server_id=='local':
        if action=='delete':
            current=privileged({'op':'profile','group':'network','id':profile_id,'action':'read'})
            if not current.get('config'):return {'ok':True,'already_removed':True}
        result=privileged({'op':'profile','group':'network','id':profile_id,'action':action,'config':config})
        if not result.get('ok'):raise RuntimeError(result.get('error','could not configure routing profile'))
        if action=='create':
            result=privileged({'op':'profile','group':'network','id':profile_id,'action':'start'})
            if not result.get('ok'):
                privileged({'op':'profile','group':'network','id':profile_id,'action':'delete'})
                raise RuntimeError(result.get('error','could not start routing profile'))
        return result
    server=next((s for s in server_rows() if s['id']==server_id),None)
    if not server:raise ValueError('routing peer server is no longer registered')
    op='routing-profile-create' if action=='create' else 'routing-profile-delete'
    return server_remote(server,{'op':op,'profile':profile_id,'config':config})

def create_routing_pair(data):
    ident=data.get('id')
    if not isinstance(ident,str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,41}',ident):raise ValueError('routing ID must be 1..42 lowercase letters, digits, _ or -')
    with db() as c:
        if c.execute('SELECT 1 FROM routing_links WHERE id=?',(ident,)).fetchone():raise ValueError('routing ID already exists')
    a_id=data.get('server_a');b_id=data.get('server_b');tunnel_id=data.get('tunnel_id')
    if not isinstance(a_id,str) or not isinstance(b_id,str) or a_id==b_id:raise ValueError('select two different tunnel endpoints')
    servers={s['id']:s for s in server_rows()}
    if a_id!='local' and a_id not in servers:raise ValueError('server A is not managed')
    if b_id!='local' and b_id not in servers:raise ValueError('server B is not managed')
    if not isinstance(tunnel_id,str) or not ID.fullmatch(tunnel_id):raise ValueError('select an existing tunnel')
    endpoints={}
    for sid in (a_id,b_id):
        items=rows() if sid=='local' else server_remote(servers[sid],{'op':'list'}).get('items',[])
        item=next((x for x in items if x.get('id')==tunnel_id),None)
        if not item:raise ValueError(f'tunnel {tunnel_id} does not exist on {sid}')
        meta=item.get('metadata',{})
        if meta.get('transport')=='erspan':raise ValueError('ERSPAN has no IP link for BGP or OSPF')
        local=meta.get('tun_local');peer=meta.get('tun_remote');interface=meta.get('tun_name')
        if not local or not peer or not interface:raise ValueError(f'tunnel {tunnel_id} on {sid} has no routed IP interface')
        local_ip=ipaddress.IPv4Interface(local);peer_ip=ipaddress.IPv4Interface(peer)
        if local_ip.ip==peer_ip.ip:raise ValueError('tunnel local and peer IPs must differ')
        host=meta.get('outer_local') or (servers.get(sid,{}).get('host') if sid!='local' else None)
        try:router_id=str(ipaddress.IPv4Address(str(host).strip('[]')))
        except ValueError:router_id=str(local_ip.ip)
        endpoints[sid]={'local_ip':str(local_ip.ip),'peer_ip':str(peer_ip.ip),'interface':interface,'router_id':router_id}
    protocol=data.get('protocol')
    if protocol not in ('bgp','ospf'):raise ValueError('choose BGP or OSPF')
    networks_a=_prefixes(data.get('networks_a'));networks_b=_prefixes(data.get('networks_b'))
    if not networks_a or not networks_b:raise ValueError('enter at least one private network to advertise from each side')
    try:asn_a=int(data.get('asn_a',0));asn_b=int(data.get('asn_b',0))
    except (ValueError,TypeError) as exc:raise ValueError('BGP ASNs must be integers') from exc
    area=str(data.get('area','0.0.0.0'))
    import routing as routing_engine
    configs={}
    for sid,peer_sid,asn,peer_asn,advertise,expect in ((a_id,b_id,asn_a,asn_b,networks_a,networks_b),(b_id,a_id,asn_b,asn_a,networks_b,networks_a)):
        cfg={'kind':'routing','id':ident,'protocol':protocol,**endpoints[sid],'peer_router_id':endpoints[peer_sid]['router_id'],'networks':advertise,'peer_networks':expect}
        if protocol=='bgp':cfg.update(local_asn=asn,peer_asn=peer_asn)
        else:cfg['area']=area
        routing_engine.validate(cfg);configs[sid]=cfg
    profile_id='route-'+ident;created=[]
    try:
        for sid in (a_id,b_id):_routing_profile_apply(sid,profile_id,configs[sid],'create');created.append(sid)
    except Exception:
        for sid in reversed(created):
            try:_routing_profile_apply(sid,profile_id,configs[sid],'delete')
            except Exception:pass
        raise
    record={'id':ident,'protocol':protocol,'tunnel_id':tunnel_id,'server_a':a_id,'server_b':b_id,'config_a':configs[a_id],'config_b':configs[b_id]}
    try:
        with db() as c:c.execute('INSERT INTO routing_links(id,config) VALUES(?,?)',(ident,json.dumps(record)))
    except Exception:
        for sid in reversed(created):
            try:_routing_profile_apply(sid,profile_id,configs[sid],'delete')
            except Exception:pass
        raise
    return {'ok':True,'id':ident,'protocol':protocol,'tunnel_id':tunnel_id,'servers':[a_id,b_id]}

def routing_status(server_id,profile_id):
    try:
        if server_id=='local':
            result=privileged({'op':'profile','group':'network','id':profile_id,'action':'read'});cfg=result.get('config')
            if not cfg:raise RuntimeError(result.get('error','routing profile missing'))
            import routing as routing_engine
            return routing_engine.status(cfg)
        server=next(s for s in server_rows() if s['id']==server_id)
        return server_remote(server,{'op':'routing-status','profile':profile_id})
    except Exception as exc:return {'state':'error','error':str(exc)}

def routing_rows():
    with db() as c:records=[json.loads(x['config']) for x in c.execute('SELECT config FROM routing_links ORDER BY id')]
    result=[]
    for item in records:
        profile='route-'+item['id']
        a=routing_status(item['server_a'],profile);b=routing_status(item['server_b'],profile)
        item['status_a']=a;item['status_b']=b
        result.append(item)
    return result

def delete_routing_link(ident):
    with db() as c:
        row=c.execute('SELECT config FROM routing_links WHERE id=?',(ident,)).fetchone()
    if not row:raise ValueError('routing link not found')
    item=json.loads(row['config']);profile='route-'+ident;errors=[]
    for sid in (item['server_a'],item['server_b']):
        try:_routing_profile_apply(sid,profile,item['config_a'] if sid==item['server_a'] else item['config_b'],'delete')
        except Exception as exc:errors.append(f'{sid}: {exc}')
    if errors:raise RuntimeError('could not remove routing from all endpoints: '+'; '.join(errors))
    with db() as c:c.execute('DELETE FROM routing_links WHERE id=?',(ident,))
    return {'ok':True,'id':ident}

def apply_forward_set(server_id,rules):
    payload=[{k:v for k,v in rule.items() if k!="server_id"} for rule in rules]
    if server_id=="local":result=privileged({"op":"haproxy","id":"forwards","action":"apply","rules":payload})
    else:
        server=next((s for s in server_rows() if s["id"]==server_id),None)
        if not server:raise ValueError("سرور شنود در فهرست مدیریت‌شده‌ها نیست")
        result=server_remote(server,{"op":"forward-apply","rules":payload})
    if not result.get("ok"):raise RuntimeError(result.get("error",result.get("status","HAProxy apply failed")))
    return result

def forward_service_status(server_id):
    if server_id=="local":return privileged({"op":"haproxy","id":"forwards","action":"status"})
    server=next((s for s in server_rows() if s["id"]==server_id),None)
    if not server:return {"ok":False,"active":False,"status":"server not found","paths":{}}
    try:return server_remote(server,{"op":"forward-status"})
    except Exception as e:return {"ok":False,"active":False,"status":str(e),"paths":{}}
def run(args,capture=False):
    if any(x=="--root" or x.startswith("--root=") or x=="--test-core-command" for x in args):raise ValueError("simulation options blocked")
    return subprocess.run([MANAGER,*args],check=True,text=True,capture_output=capture,timeout=30)
def privileged(req,timeout=75):
    s=__import__("socket").socket(__import__("socket").AF_UNIX,__import__("socket").SOCK_STREAM)
    s.settimeout(timeout);s.connect("/run/tunnelmgr/privd.sock");s.sendall(json.dumps(req).encode()+b"\n");buf=b""
    while b"\n" not in buf and len(buf)<131072:
        part=s.recv(4096)
        if not part:break
        buf+=part
    s.close();return json.loads(buf.split(b"\n",1)[0])

def create_instance(data):
    if not isinstance(data,dict):raise ValueError("JSON object required")
    ident,mode=data.get("id"),data.get("mode")
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError("invalid instance id")
    if mode not in ("server","client"):raise ValueError("mode must be server or client")
    secret_managed=data.get("secret_managed") is True
    config={k:v for k,v in data.items() if k not in ("id","direction","server_id","transport","secret_managed")}
    carrier=config.get("carrier","tun")
    if carrier not in ("tcp","tcpmux","xtcpmux","ws","wss","wsmux","wssmux","xwsmux","anytls","tun"):raise ValueError("unsupported Backhaul carrier")
    if carrier=="tun" and config.get("encapsulation","tcp")=="tcp":
        if "tun_local" not in config or "tun_remote" not in config:raise ValueError("Backhaul TUN over TCP requires local and peer tunnel addresses")
        import ipaddress
        pair={str(ipaddress.ip_interface(config["tun_local"]).ip),str(ipaddress.ip_interface(config["tun_remote"]).ip)}
        for item in rows():
            if item["id"]==ident:continue
            for field in ("tun_local","tun_remote"):
                old=item["metadata"].get(field)
                if old and str(ipaddress.ip_interface(old).ip) in pair:raise ValueError("tunnel IP already assigned to another managed instance")
    result=privileged({"op":"create","id":ident,"config":config})
    if not result.get("ok"):raise RuntimeError(result.get("error",result.get("output","create failed")))
    metadata={k:v for k,v in config.items() if k!="secret_file"}
    if secret_managed:metadata["secret_managed"]=True
    save(ident,mode,{"manager":"Backhaul",**metadata})
    return {"id":ident,"kind":"backhaul","mode":mode,"carrier":carrier,"tun_local":config.get("tun_local"),"tun_remote":config.get("tun_remote")}

def create_native(data):
    ident=data.get("id")
    if not isinstance(ident,str) or not ID.fullmatch(ident) or len(ident)>41:raise ValueError("invalid native tunnel ID")
    kind=data.get("transport")
    allowed={"gre","gretap","geneve","vxlan","ipip","sit-6to4","sit-isatap","gre-fou","ipip-fou","sit-fou","l2tpv3","ipsec-ikev2","ipsec-esp-udp","esp","wireguard","openvpn"}
    if kind not in allowed:raise ValueError("unsupported transport")
    fields={"interface","outer_local","outer_peer","inner_local","inner_peer","key","vni","port","erspan_index","erspan_key","mirror_interface","fou_port","tunnel_id","peer_tunnel_id","session_id","peer_session_id","encap","udp_sport","udp_dport","role","local_id","remote_id","psk","spi","peer_spi","enc_key","auth_key","peer_enc_key","peer_auth_key","private_key","peer_public_key","preshared_key","listen_port","endpoint_port","keepalive","common_name","peer_common_name","ca_cert","cert","private_key_pem","mtu"}
    config={"kind":kind,**{k:v for k,v in data.items() if k in fields}}
    profile="native-"+ident
    result=privileged({"op":"profile","group":"network","id":profile,"action":"create","config":config})
    if not result.get("ok"):raise RuntimeError(result.get("error","native tunnel creation failed"))
    try:
        result=privileged({"op":"profile","group":"network","id":profile,"action":"start"})
        if not result.get("ok"):raise RuntimeError(result.get("error","start failed"))
        local=config.get("inner_local");peer=config.get("inner_peer")
        if kind=="sit-6to4":
            def six(ip):
                v=int(ipaddress.IPv4Address(ip));return "2002:%x:%x::1/16"%((v>>16)&65535,v&65535)
            local=six(config["outer_local"]);peer=six(config["outer_peer"])
        mode=data.get("mode","server")
        save(ident,mode,{"transport":kind,"tun_name":config["interface"],"tun_local":local,"tun_remote":peer,"outer_local":config.get("outer_local"),"outer_peer":config.get("outer_peer"),"mtu":config["mtu"],"native_profile":profile})
        return {"id":ident,"kind":kind,"mode":mode,"tun_local":local,"tun_remote":peer}
    except Exception:
        privileged({"op":"profile","group":"network","id":profile,"action":"delete"})
        raise

def create_wireguard_pair(data):
    """Create both WireGuard peers; private keys stay inside the server-to-server workflow."""
    ident=data.get("id")
    if not isinstance(ident,str) or not ID.fullmatch(ident) or len(ident)>41:raise ValueError("invalid tunnel id")
    a_id=data.get("server_a");b_id=data.get("server_b")
    if not isinstance(a_id,str) or not isinstance(b_id,str) or a_id==b_id:raise ValueError("choose two different servers")
    servers={s["id"]:s for s in server_rows()}
    if a_id!="local" and a_id not in servers:raise ValueError("server A is not managed")
    if b_id!="local" and b_id not in servers:raise ValueError("server B is not managed")
    hosts={"local":data.get("host_a") if a_id=="local" else data.get("host_b"),a_id:data.get("host_a"),b_id:data.get("host_b")}
    try:
        ipaddress.ip_address(hosts[a_id]);ipaddress.ip_address(hosts[b_id])
        local=ipaddress.ip_interface(data.get("inner_local",""));peer=ipaddress.ip_interface(data.get("inner_peer",""))
    except ValueError as exc:raise ValueError("WireGuard needs valid public endpoint and inner IP addresses") from exc
    if local.version!=peer.version or local.ip==peer.ip or local.network!=peer.network:raise ValueError("peer IPs must be distinct addresses in the same subnet")
    existing={}
    for sid in (a_id,b_id):
        items=rows() if sid=="local" else server_remote(servers[sid],{"op":"list"}).get("items",[])
        existing[sid]=items
        for item in items:
            meta=item.get("metadata",{})
            for field in ("tun_local","tun_remote"):
                old=meta.get(field)
                if old and ipaddress.ip_interface(old).ip in (local.ip,peer.ip):raise ValueError(f"WireGuard address already belongs to tunnel {item['id']} on {sid}")
    port=data.get("port",51820)
    if type(port) is not int or not 1<=port<=65535:raise ValueError("WireGuard UDP port must be 1..65535")
    mtu=data.get("mtu",1400)
    if type(mtu) is not int or not 576<=mtu<=9000:raise ValueError("MTU must be 576..9000")
    exists_a=any(x.get("id")==ident for x in existing[a_id]);exists_b=any(x.get("id")==ident for x in existing[b_id])
    if data.get("action")=="update":
        if not exists_a or not exists_b:raise ValueError("both WireGuard peers must exist before editing")
        old={a_id:(tunnel_config(ident) if a_id=="local" else server_remote(servers[a_id],{"op":"config","id":ident})),
             b_id:(tunnel_config(ident) if b_id=="local" else server_remote(servers[b_id],{"op":"config","id":ident}))}
        base={k:v for k,v in data.items() if k in ("mtu","keepalive")}
        config_a={**old[a_id],"id":ident,"transport":"wireguard","mode":"peer","interface":data.get("interface",old[a_id].get("interface","wg0")),"outer_peer":hosts[b_id],"inner_local":str(local),"inner_peer":str(peer),"listen_port":port,"endpoint_port":port,**base}
        config_b={**old[b_id],"id":ident,"transport":"wireguard","mode":"peer","interface":data.get("peer_interface",old[b_id].get("interface","wg1")),"outer_peer":hosts[a_id],"inner_local":str(peer),"inner_peer":str(local),"listen_port":port,"endpoint_port":port,**base}
        updates=[(a_id,config_a),(b_id,config_b)];done=[]
        try:
            for sid,cfg in updates:
                if sid=="local":update_tunnel(cfg)
                else:server_remote(servers[sid],{"op":"update","data":cfg})
                done.append(sid)
        except Exception:
            for sid in reversed(done):
                try:
                    if sid=="local":update_tunnel(old[sid])
                    else:server_remote(servers[sid],{"op":"update","data":old[sid]})
                except Exception:pass
            raise
        return {"ok":True,"id":ident,"transport":"wireguard","servers":[a_id,b_id],"updated":True,"udp_port":port}
    if exists_a or exists_b:raise ValueError("tunnel id already exists on one of the selected servers")
    wg=shutil.which("wg")
    if not wg:raise RuntimeError("wireguard-tools must be installed on the panel server")
    def output(*args):
        result=subprocess.run([wg,*args],capture_output=True,text=True,check=True,timeout=5)
        return result.stdout.strip()
    priv_a,priv_b=output("genkey"),output("genkey")
    pub_a=subprocess.run([wg,"pubkey"],input=priv_a+"\n",capture_output=True,text=True,check=True,timeout=5).stdout.strip()
    pub_b=subprocess.run([wg,"pubkey"],input=priv_b+"\n",capture_output=True,text=True,check=True,timeout=5).stdout.strip()
    psk=output("genpsk")
    base={k:v for k,v in data.items() if k in ("mtu","keepalive")}
    config_a={"id":ident,"transport":"wireguard","mode":"peer","interface":data.get("interface","wg0"),"outer_peer":hosts[b_id],"inner_local":str(local),"inner_peer":str(peer),"private_key":priv_a,"peer_public_key":pub_b,"preshared_key":psk,"listen_port":port,"endpoint_port":port,**base}
    config_b={"id":ident,"transport":"wireguard","mode":"peer","interface":data.get("peer_interface","wg1"),"outer_peer":hosts[a_id],"inner_local":str(peer),"inner_peer":str(local),"private_key":priv_b,"peer_public_key":pub_a,"preshared_key":psk,"listen_port":port,"endpoint_port":port,**base}
    endpoints=[(a_id,config_a),(b_id,config_b)]
    created=[]
    try:
        for sid,cfg in endpoints:
            if sid=="local":create_native(cfg)
            else:server_remote(servers[sid],{"op":"create","data":cfg})
            created.append(sid)
    except Exception:
        for sid in reversed(created):
            try:
                if sid=="local":
                    privileged({"op":"profile","group":"network","id":"native-"+ident,"action":"delete"})
                    with db() as c:c.execute("DELETE FROM tunnels WHERE id=?",(ident,))
                else:server_remote(servers[sid],{"op":"operate","id":ident,"action":"delete"})
            except Exception:pass
        raise
    return {"ok":True,"id":ident,"transport":"wireguard","servers":[a_id,b_id],"inner_local":str(local),"inner_peer":str(peer),"udp_port":port,"note":"Allow the selected UDP port in both host and provider firewalls."}

def create_openvpn_pair(data):
    """Create a TLS-authenticated OpenVPN P2P pair with controller-generated CA material."""
    ident=data.get("id");a_id=data.get("server_a");b_id=data.get("server_b")
    if not isinstance(ident,str) or not ID.fullmatch(ident) or len(ident)>41:raise ValueError("invalid tunnel id")
    if not isinstance(a_id,str) or not isinstance(b_id,str) or a_id==b_id:raise ValueError("choose two different servers")
    servers={s["id"]:s for s in server_rows()}
    if a_id!="local" and a_id not in servers:raise ValueError("server A is not managed")
    if b_id!="local" and b_id not in servers:raise ValueError("server B is not managed")
    host_a=data.get("host_a","").strip("[]");host_b=data.get("host_b","").strip("[]")
    try:
        ipaddress.IPv4Address(host_a);ipaddress.IPv4Address(host_b)
        local=ipaddress.IPv4Interface(data.get("inner_local",""));peer=ipaddress.IPv4Interface(data.get("inner_peer",""))
    except ValueError as exc:raise ValueError("OpenVPN requires IPv4 public endpoints and inner addresses") from exc
    if host_a==host_b:raise ValueError("OpenVPN endpoints must use two different public addresses")
    if local.network!=peer.network or local.ip==peer.ip or not local.network.is_private:raise ValueError("OpenVPN peer addresses must be distinct hosts in one private subnet")
    port=data.get("port",1194);mtu=data.get("mtu",1400)
    if type(port) is not int or not 1<=port<=65535:raise ValueError("OpenVPN UDP port must be 1..65535")
    if type(mtu) is not int or not 576<=mtu<=9000:raise ValueError("MTU must be 576..9000")
    existing={}
    for sid in (a_id,b_id):
        existing[sid]=rows() if sid=="local" else server_remote(servers[sid],{"op":"list"}).get("items",[])
    exists_a=any(x.get("id")==ident for x in existing[a_id]);exists_b=any(x.get("id")==ident for x in existing[b_id])
    updating=data.get("action")=="update"
    if updating and not (exists_a and exists_b):raise ValueError("both OpenVPN peers must exist before editing")
    if not updating and (exists_a or exists_b):raise ValueError("tunnel id already exists on one selected server")
    for sid in (a_id,b_id):
        for item in existing[sid]:
            if item.get("id")==ident:continue
            meta=item.get("metadata",{})
            for field in ("tun_local","tun_remote"):
                value=meta.get(field)
                if value:
                    try:used=ipaddress.ip_interface(value).ip
                    except ValueError:continue
                    if used in (local.ip,peer.ip):raise ValueError(f"OpenVPN address already belongs to tunnel {item['id']} on {sid}")
    direction=data.get("direction","direct")
    role_a="client" if direction=="direct" else "server";role_b="server" if role_a=="client" else "client"
    if updating:
        old={a_id:(tunnel_config(ident) if a_id=="local" else server_remote(servers[a_id],{"op":"config","id":ident})),
             b_id:(tunnel_config(ident) if b_id=="local" else server_remote(servers[b_id],{"op":"config","id":ident}))}
        role_material={role:{"cert":cfg.get("cert"),"private_key_pem":cfg.get("private_key_pem"),"common_name":cfg.get("common_name",f"tm-{ident}-{role}")} for role in ("server","client") for cfg in old.values() if cfg.get("role")==role}
        if set(role_material)!={"server","client"}:raise ValueError("both OpenVPN roles must be present to edit the pair")
        common={"ca_cert":next(iter(old.values())).get("ca_cert"),"mtu":mtu,"port":port}
    else:
        openssl=shutil.which("openssl")
        if not openssl:raise RuntimeError("openssl is required to create OpenVPN certificates")
        with tempfile.TemporaryDirectory(prefix="tunnelmgr-openvpn-") as tmp:
            directory=pathlib.Path(tmp);ca_key=directory/"ca.key";ca_cert=directory/"ca.crt"
            def run(*args):subprocess.run([openssl,*map(str,args)],capture_output=True,text=True,check=True,timeout=45)
            run("req","-x509","-newkey","rsa:2048","-nodes","-keyout",ca_key,"-out",ca_cert,"-days","3650","-subj",f"/CN=TunnelMgr-{ident}-CA")
            materials={"ca_cert":ca_cert.read_text()}
            for role,host,usage in (("server",host_a if role_a=="server" else host_b,"serverAuth"),("client",host_a if role_a=="client" else host_b,"clientAuth")):
                cn=f"tm-{ident}-{role}";keyfile=directory/(role+".key");reqfile=directory/(role+".csr");certfile=directory/(role+".crt");ext=directory/(role+".ext")
                ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=IP:{host}\n")
                run("req","-new","-newkey","rsa:2048","-nodes","-keyout",keyfile,"-out",reqfile,"-subj",f"/CN={cn}")
                run("x509","-req","-in",reqfile,"-CA",ca_cert,"-CAkey",ca_key,"-CAcreateserial","-out",certfile,"-days","1825","-sha256","-extfile",ext)
                materials[role+"_cert"]=certfile.read_text();materials[role+"_key"]=keyfile.read_text();materials[role+"_cn"]=cn
        role_material={"server":{"cert":materials["server_cert"],"private_key_pem":materials["server_key"],"common_name":materials["server_cn"]},
                       "client":{"cert":materials["client_cert"],"private_key_pem":materials["client_key"],"common_name":materials["client_cn"]}}
        common={"ca_cert":materials["ca_cert"],"mtu":mtu,"port":port}
    def endpoint(sid,role,local_ip,peer_ip,outer_local,outer_peer,interface,peer_role):
        own=role_material[role];remote=role_material[peer_role]
        return {"id":ident,"transport":"openvpn","mode":role,"kind":"openvpn","interface":interface,"role":role,"common_name":own["common_name"],
                "outer_local":outer_local,"outer_peer":outer_peer,"inner_local":str(local_ip),"inner_peer":str(peer_ip),
                "peer_common_name":remote["common_name"],
                "port":port,"mtu":mtu,"ca_cert":common["ca_cert"],"cert":own["cert"],"private_key_pem":own["private_key_pem"]}
    cfg_a=endpoint(a_id,role_a,local,peer,host_a,host_b,data.get("interface","tun0"),role_b)
    cfg_b=endpoint(b_id,role_b,peer,local,host_b,host_a,data.get("peer_interface","tun1"),role_a)
    actions=[(a_id,cfg_a),(b_id,cfg_b)];done=[]
    try:
        for sid,cfg in actions:
            if updating:
                if sid=="local":update_tunnel(cfg)
                else:server_remote(servers[sid],{"op":"update","data":cfg})
            else:
                if sid=="local":create_native(cfg)
                else:server_remote(servers[sid],{"op":"create","data":cfg})
            done.append(sid)
    except Exception:
        for sid in reversed(done):
            try:
                if updating:
                    if sid=="local":update_tunnel(old[sid])
                    else:server_remote(servers[sid],{"op":"update","data":old[sid]})
                elif sid=="local":
                    privileged({"op":"profile","group":"network","id":"native-"+ident,"action":"delete"})
                    with db() as c:c.execute("DELETE FROM tunnels WHERE id=?",(ident,))
                else:server_remote(servers[sid],{"op":"operate","id":ident,"action":"delete"})
            except Exception:pass
        raise
    return {"ok":True,"id":ident,"transport":"openvpn","servers":[a_id,b_id],"udp_port":port,"updated":updating}

def create_openconnect_pair(data):
    """Create an ocserv/OpenConnect site link with a deterministic /31 lease."""
    ident=data.get("id");a_id=data.get("server_a");b_id=data.get("server_b")
    if not isinstance(ident,str) or not ID.fullmatch(ident) or len(ident)>41:raise ValueError("invalid tunnel id")
    if not isinstance(a_id,str) or not isinstance(b_id,str) or a_id==b_id:raise ValueError("choose two different servers")
    servers={s["id"]:s for s in server_rows()}
    if a_id!="local" and a_id not in servers:raise ValueError("server A is not managed")
    if b_id!="local" and b_id not in servers:raise ValueError("server B is not managed")
    host_a=data.get("host_a","").strip("[]");host_b=data.get("host_b","").strip("[]")
    try:
        ipaddress.IPv4Address(host_a);ipaddress.IPv4Address(host_b)
        local=ipaddress.IPv4Interface(data.get("inner_local",""));peer=ipaddress.IPv4Interface(data.get("inner_peer",""))
    except ValueError as exc:raise ValueError("OpenConnect requires IPv4 public endpoints and inner addresses") from exc
    if host_a==host_b:raise ValueError("OpenConnect endpoints must use two different public addresses")
    if local.network!=peer.network or local.ip==peer.ip:
        raise ValueError("OpenConnect requires two distinct addresses in one private subnet")
    if local.network.prefixlen==31:allowed={local.network.network_address,local.network.broadcast_address}
    elif local.network.prefixlen==30:allowed={local.network.network_address+1,local.network.network_address+2}
    else:raise ValueError("OpenConnect supports a single-client /30 pool (or /31 on newer ocserv versions)")
    if {local.ip,peer.ip}!=allowed:raise ValueError("OpenConnect addresses must be the two point-to-point hosts of the pool")
    if not local.network.network_address.is_private:raise ValueError("OpenConnect pool must be private")
    port=data.get("port",443);mtu=data.get("mtu",1350)
    if type(port) is not int or not 1<=port<=65535:raise ValueError("OpenConnect TCP/UDP port must be 1..65535")
    if type(mtu) is not int or not 576<=mtu<=9000:raise ValueError("MTU must be 576..9000")
    existing={}
    for sid in (a_id,b_id):existing[sid]=rows() if sid=="local" else server_remote(servers[sid],{"op":"list"}).get("items",[])
    exists_a=any(x.get("id")==ident for x in existing[a_id]);exists_b=any(x.get("id")==ident for x in existing[b_id])
    updating=data.get("action")=="update"
    if updating and not (exists_a and exists_b):raise ValueError("both OpenConnect peers must exist before editing")
    if not updating and (exists_a or exists_b):raise ValueError("tunnel id already exists on one selected server")
    for sid in (a_id,b_id):
        for item in existing[sid]:
            if item.get("id")==ident:continue
            for field in ("tun_local","tun_remote"):
                value=item.get("metadata",{}).get(field)
                if value:
                    try:used=ipaddress.ip_interface(value).ip
                    except ValueError:continue
                    if used in (local.ip,peer.ip):raise ValueError(f"OpenConnect address already belongs to tunnel {item['id']} on {sid}")
    direction=data.get("direction","direct")
    if direction not in ("direct","reverse"):raise ValueError("direction must be direct or reverse")
    role_a="client" if direction=="direct" else "server";role_b="server" if role_a=="client" else "client"
    if updating:
        old={a_id:(tunnel_config(ident) if a_id=="local" else server_remote(servers[a_id],{"op":"config","id":ident})),
             b_id:(tunnel_config(ident) if b_id=="local" else server_remote(servers[b_id],{"op":"config","id":ident}))}
        roles={cfg.get("role"):cfg for cfg in old.values()}
        if set(roles)!={"server","client"}:raise ValueError("both OpenConnect roles must be present to edit the pair")
        ca_cert=roles["server"].get("ca_cert")
        if not ca_cert:raise ValueError("OpenConnect CA certificate is missing")
        materials={r:{"cert":cfg.get("cert"),"private_key_pem":cfg.get("private_key_pem"),"common_name":cfg.get("common_name")} for r,cfg in roles.items()}
    else:
        openssl=shutil.which("openssl")
        if not openssl:raise RuntimeError("openssl is required to create OpenConnect certificates")
        with tempfile.TemporaryDirectory(prefix="tunnelmgr-openconnect-") as tmp:
            directory=pathlib.Path(tmp);ca_key=directory/"ca.key";ca_cert_path=directory/"ca.crt"
            def run(*args):subprocess.run([openssl,*map(str,args)],capture_output=True,text=True,check=True,timeout=45)
            run("req","-x509","-newkey","rsa:2048","-nodes","-keyout",ca_key,"-out",ca_cert_path,"-days","3650","-subj",f"/CN=TunnelMgr-{ident}-CA")
            ca_cert=ca_cert_path.read_text();materials={}
            for role,host,usage in (("server",host_a if role_a=="server" else host_b,"serverAuth"),("client",host_a if role_a=="client" else host_b,"clientAuth")):
                cn=f"tm-{ident}-{role}";keyfile=directory/(role+".key");reqfile=directory/(role+".csr");certfile=directory/(role+".crt");ext=directory/(role+".ext")
                ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=IP:{host}\n")
                run("req","-new","-newkey","rsa:2048","-nodes","-keyout",keyfile,"-out",reqfile,"-subj",f"/CN={cn}")
                run("x509","-req","-in",reqfile,"-CA",ca_cert_path,"-CAkey",ca_key,"-CAcreateserial","-out",certfile,"-days","1825","-sha256","-extfile",ext)
                materials[role]={"cert":certfile.read_text(),"private_key_pem":keyfile.read_text(),"common_name":cn}
    network=local.network
    if network.prefixlen==31:server_ip=str(network.network_address);client_ip=str(network.broadcast_address)
    else:server_ip=str(network.network_address+1);client_ip=str(network.network_address+2)
    def endpoint(role,outer_local,outer_peer,interface):
        own=materials[role];other=materials["client" if role=="server" else "server"]
        ilocal,ipeer=(server_ip,client_ip) if role=="server" else (client_ip,server_ip)
        return {"id":ident,"transport":"openconnect","mode":role,"interface":interface,"role":role,"outer_local":outer_local,"outer_peer":outer_peer,
                "inner_local":ilocal+f"/{network.prefixlen}","inner_peer":ipeer+f"/{network.prefixlen}","port":port,"mtu":mtu,"ca_cert":ca_cert,
                "cert":own["cert"],"private_key_pem":own["private_key_pem"],"common_name":own["common_name"],"peer_common_name":other["common_name"]}
    cfg_a=endpoint(role_a,host_a,host_b,data.get("interface","oc0"));cfg_b=endpoint(role_b,host_b,host_a,data.get("peer_interface","oc1"))
    actions=[(a_id,cfg_a),(b_id,cfg_b)];done=[]
    try:
        for sid,cfg in actions:
            if updating:
                if sid=="local":update_tunnel(cfg)
                else:server_remote(servers[sid],{"op":"update","data":cfg})
            elif sid=="local":create_native(cfg)
            else:server_remote(servers[sid],{"op":"create","data":cfg})
            done.append(sid)
    except Exception:
        for sid in reversed(done):
            try:
                if updating:
                    if sid=="local":update_tunnel(old[sid])
                    else:server_remote(servers[sid],{"op":"update","data":old[sid]})
                elif sid=="local":
                    privileged({"op":"profile","group":"network","id":"native-"+ident,"action":"delete"})
                    with db() as c:c.execute("DELETE FROM tunnels WHERE id=?",(ident,))
                else:server_remote(servers[sid],{"op":"operate","id":ident,"action":"delete"})
            except Exception:pass
        raise
    return {"ok":True,"id":ident,"transport":"openconnect","servers":[a_id,b_id],"pool":str(network),"tcp_udp_port":port,"updated":updating}

def tunnel_config(ident):
    item=find(ident)
    if not item:raise ValueError("unknown tunnel")
    meta=item["metadata"]
    profile=meta.get("native_profile")
    if profile:
        result=privileged({"op":"profile","group":"network","id":profile,"action":"read"})
        if not result.get("config"):raise RuntimeError(result.get("error","could not read tunnel profile"))
        return {"id":ident,"transport":result["config"].get("kind"),"mode":item["mode"],**result["config"]}
    secret_kind="psk" if meta.get("encapsulation")=="ipx" else "token"
    return {"id":ident,"transport":"backhaul","mode":item["mode"],**meta,"secret_file":meta.get("secret_file",f"/etc/backhaul/secrets/{ident}.{secret_kind}"),"secret_managed":meta.get("secret_managed",False)}

def restart_ipsec_pair(ident):
    """Restart UDP-encapsulated IPsec peers responder-first to avoid a teardown race."""
    endpoints=[]
    local=find(ident)
    if local:
        endpoints.append(("local",local,tunnel_config(ident)))
    servers={s["id"]:s for s in server_rows()}
    for sid,srv in servers.items():
        remote_items=server_remote(srv,{"op":"list"}).get("items",[])
        remote=next((item for item in remote_items if item.get("id")==ident),None)
        if remote:
            endpoints.append((sid,remote,server_remote(srv,{"op":"config","id":ident})))
    endpoints=[e for e in endpoints if e[2].get("transport")=="ipsec-esp-udp"]
    if len(endpoints)<2:
        raise RuntimeError("Both IPsec-over-UDP peers must be reachable for a coordinated restart")
    srvmap=servers
    def operate(endpoint,action):
        sid,item,cfg=endpoint
        profile=item.get("metadata",{}).get("native_profile")
        if sid=="local":
            if not profile:raise RuntimeError("Local IPsec profile is missing")
            return privileged({"op":"profile","group":"network","id":profile,"action":action})
        return server_remote(srvmap[sid],{"op":"operate","id":ident,"action":action})
    with ThreadPoolExecutor(max_workers=len(endpoints)) as pool:
        stopped=list(pool.map(lambda endpoint:operate(endpoint,"stop"),endpoints))
    failures=[r.get("error","stop failed") for r in stopped if not r.get("ok")]
    if failures:raise RuntimeError("Could not stop both IPsec peers: "+"; ".join(failures))
    ordered=sorted(endpoints,key=lambda e:0 if e[2].get("role")=="server" else 1)
    started=[]
    for endpoint in ordered:
        result=operate(endpoint,"start")
        started.append(endpoint[0])
        if not result.get("ok"):
            raise RuntimeError("IPsec restart failed on "+endpoint[0]+": "+result.get("error","start failed"))
    return {"ok":True,"id":ident,"operation":"restart","servers":[e[0] for e in ordered],"startup_order":[e[2].get("role") for e in ordered]}

def update_tunnel(data):
    ident=data.get("id") if isinstance(data,dict) else None
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError("invalid tunnel id")
    old=find(ident)
    if not old:raise ValueError("unknown tunnel")
    old_profile=old["metadata"].get("native_profile")
    transport=data.get("transport")
    if transport=="backhaul":
        if old_profile:raise ValueError("Changing between Backhaul and native tunnel types is not supported in-place")
        mode=data.get("mode",old["mode"])
        if mode not in ("server","client"):raise ValueError("mode must be server or client")
        config={k:v for k,v in data.items() if k not in ("id","direction","server_id","transport","secret_managed","manager","native_profile")}
        config["replace"]=True
        result=privileged({"op":"create","id":ident,"config":config})
        if not result.get("ok"):raise RuntimeError(result.get("error",result.get("output","tunnel update failed")))
        metadata={k:v for k,v in config.items() if k not in ("secret_file","replace")}
        if old["metadata"].get("secret_managed"):metadata["secret_managed"]=True
        save(ident,mode,{"manager":"Backhaul",**metadata})
        return {"id":ident,"ok":True}
    if not old_profile:raise ValueError("Changing between Backhaul and native tunnel types is not supported in-place")
    profile=old_profile
    previous=privileged({"op":"profile","group":"network","id":profile,"action":"read"}).get("config")
    if not previous:raise RuntimeError("could not read current native tunnel profile")
    fields={"interface","outer_local","outer_peer","inner_local","inner_peer","key","vni","port","erspan_index","erspan_key","mirror_interface","fou_port","tunnel_id","peer_tunnel_id","session_id","peer_session_id","encap","udp_sport","udp_dport","role","local_id","remote_id","psk","spi","peer_spi","enc_key","auth_key","peer_enc_key","peer_auth_key","private_key","peer_public_key","preshared_key","listen_port","endpoint_port","keepalive","common_name","peer_common_name","ca_cert","cert","private_key_pem","mtu"}
    config={"kind":transport,**{k:v for k,v in data.items() if k in fields}}
    try:
        result=privileged({"op":"profile","group":"network","id":profile,"action":"stop"})
        if not result.get("ok"):raise RuntimeError(result.get("error","could not stop tunnel"))
        result=privileged({"op":"profile","group":"network","id":profile,"action":"update","previous":previous,"config":config})
        if not result.get("ok"):raise RuntimeError(result.get("error","could not update tunnel profile"))
        result=privileged({"op":"profile","group":"network","id":profile,"action":"start"})
        if not result.get("ok"):raise RuntimeError(result.get("error","could not restart tunnel"))
    except Exception:
        try:
            privileged({"op":"profile","group":"network","id":profile,"action":"stop"})
            current=privileged({"op":"profile","group":"network","id":profile,"action":"read"}).get("config")
            if current and current!=previous:
                privileged({"op":"profile","group":"network","id":profile,"action":"update","previous":current,"config":previous})
            privileged({"op":"profile","group":"network","id":profile,"action":"start"})
        except Exception:pass
        raise
    mode=data.get("mode",old["mode"])
    local=config.get("inner_local");peer=config.get("inner_peer")
    if transport=="sit-6to4":
        def six(ip):
            value=int(ipaddress.IPv4Address(ip));return "2002:%x:%x::1/16"%((value>>16)&65535,value&65535)
        local=six(config["outer_local"]);peer=six(config["outer_peer"])
    save(ident,mode,{"transport":transport,"tun_name":config.get("interface"),"tun_local":local,"tun_remote":peer,"outer_local":config.get("outer_local"),"outer_peer":config.get("outer_peer"),"mtu":config.get("mtu"),"native_profile":profile})
    return {"id":ident,"ok":True}

def _replace_host_value(value,old,new):
    if not isinstance(value,str):return value,False
    old=old.strip("[]");new=new.strip("[]")
    if value.strip("[]")==old:return new,True
    if value.startswith("[") and "]" in value:
        host,tail=value[1:].split("]",1)
        if host==old:return f"[{new}]{tail}",True
    if ":" in value:
        host,port=value.rsplit(":",1)
        if host==old and port.isdigit():return f"{new}:{port}",True
    return value,False

def _rewrite_tunnel_host(config,old,new):
    updated=dict(config);changed=False;local_changed=False;peer_changed=False
    for key in ("outer_local","outer_peer","peer","listen","endpoint"):
        if key in updated:
            value,did=_replace_host_value(updated[key],old,new)
            if did:
                updated[key]=value;changed=True
                if key=="outer_local":local_changed=True
                if key=="outer_peer":peer_changed=True
    if config.get("transport",config.get("kind"))=="sit-isatap":
        for field,outer,did in (("inner_local","outer_local",local_changed),("inner_peer","outer_peer",peer_changed)):
            value=updated.get(field)
            if did and isinstance(value,str) and "5efe:" in value.lower():
                try:
                    current=ipaddress.ip_interface(value);host=ipaddress.IPv4Address(updated[outer]);number=(int(current.ip)&~0xffffffff)|(0x5efe<<32)|int(host)
                    updated[field]=str(ipaddress.IPv6Interface((ipaddress.IPv6Address(number),current.network.prefixlen)));changed=True
                except (ValueError,KeyError):pass
    return updated,changed

def update_server_host(server_id,new_host,new_user=None,new_proxy_id=None,password="",new_location=None,auto_geoip=True):
    servers={s["id"]:s for s in server_rows()}
    current=servers.get(server_id)
    if not current:raise ValueError("server not found")
    old_host=current["host"]
    new_user=current["user"] if new_user is None else new_user
    new_proxy_id=current.get("proxy_server_id","") if new_proxy_id is None else new_proxy_id
    new_location=current.get("location","abroad") if new_location is None else new_location
    geoip_result=None;geoip_error=""
    if not isinstance(new_host,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}",new_host):raise ValueError("آدرس سرور نامعتبر است")
    if not isinstance(new_user,str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}",new_user):raise ValueError("نام کاربری SSH نامعتبر است")
    if not isinstance(new_proxy_id,str):raise ValueError("سرور پروکسی نامعتبر است")
    if new_location not in ("iran","abroad"):raise ValueError("موقعیت سرور باید ایران یا خارج باشد")
    if auto_geoip:
        try:
            geoip_result=geoip_location(new_host)
            new_location=geoip_result["location"]
        except Exception as e:geoip_error=str(e)
    if new_proxy_id:
        proxy=servers.get(new_proxy_id)
        if not proxy or new_proxy_id==server_id:raise ValueError("سرور پروکسی باید از فهرست انتخاب شود و با مقصد فرق کند")
        if proxy.get("proxy_server_id"):raise ValueError("زنجیرهٔ پروکسی SSH بیش از یک مرحله پشتیبانی نمی‌شود")
    candidate={**current,"host":new_host,"user":new_user,"proxy_server_id":new_proxy_id,"location":new_location}
    connection_unchanged=all(candidate.get(k)==current.get(k) for k in ("host","user","proxy_server_id"))
    unchanged=connection_unchanged and new_location==current.get("location","abroad") and bool(auto_geoip)==bool(current.get("auto_geoip",1)) and (not auto_geoip or current.get("geoip_host")==new_host)
    password=str(password or "")
    if len(password)>1024:raise ValueError("گذرواژه SSH بیش از حد طولانی است")
    if unchanged and not password:return {"ok":True,"location":new_location,"geoip":geoip_result,"geoip_error":geoip_error,"updated_tunnels":0,"updated_endpoints":0,"restarted_endpoints":0,"unchanged":True}
    if connection_unchanged and not password:
        with db() as c:c.execute("UPDATE servers SET location=?,auto_geoip=?,geoip_host=? WHERE id=?",(new_location,int(auto_geoip),new_host if geoip_result else "",server_id))
        return {"ok":True,"server":server_id,"location":new_location,"geoip":geoip_result,"geoip_error":geoip_error,"updated_tunnels":0,"updated_endpoints":0,"restarted_endpoints":0}
    if password:
        identity=pathlib.Path(current.get("identity", ""))
        public=pathlib.Path(str(identity)+".pub")
        if public.is_file():pub=public.read_text().strip()
        else:
            derive=subprocess.run(["ssh-keygen","-y","-f",str(identity)],capture_output=True,text=True,timeout=15)
            if derive.returncode:raise RuntimeError("کلید مدیریتی عمومی قابل‌خواندن نیست؛ کلید SSH را دوباره ثبت کن یا گذرواژه را خالی بگذار")
            pub=derive.stdout.strip()
        quoted=shlex.quote(pub)
        command=f"umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; grep -qxF {quoted} ~/.ssh/authorized_keys || printf '%s\\n' {quoted} >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"
        try:password_ssh(candidate,command,password)
        except Exception as e:raise RuntimeError("گذرواژهٔ SSH تأیید نشد یا نصب کلید مدیریتی روی حساب جدید ناموفق بود: "+str(e)) from e
    probe=subprocess.run(ssh_argv(candidate)+["true"],capture_output=True,text=True,timeout=25)
    if probe.returncode:raise RuntimeError("اتصال SSH با IP، کاربر و پراکسی جدید برقرار نشد؛ اطلاعات ذخیره نشدند: "+(probe.stderr or probe.stdout)[-800:])
    dependents=[s for s in servers.values() if s["id"]!=server_id and s.get("proxy_server_id")==server_id]
    previous_connection={k:current.get(k,"") for k in ("host","user","proxy_server_id","location","auto_geoip","geoip_host")}
    with db() as c:c.execute("UPDATE servers SET host=?,user=?,proxy_server_id=?,location=?,auto_geoip=?,geoip_host=? WHERE id=?",(new_host,new_user,new_proxy_id,new_location,int(auto_geoip),new_host if geoip_result else "",server_id))
    endpoints=[];applied=[]
    try:
        servers={s["id"]:s for s in server_rows()}
        for dependent in dependents:
            result=subprocess.run(ssh_argv(servers[dependent["id"]])+["true"],capture_output=True,text=True,timeout=25)
            if result.returncode:raise RuntimeError(f"تغییر اتصال {server_id} دسترسی سرور عبوری {dependent['id']} را قطع می‌کند: "+(result.stderr or result.stdout)[-600:])
        if new_host!=old_host:
            for item in rows():
                try:config=tunnel_config(item["id"])
                except Exception as e:raise RuntimeError(f"خواندن تنظیم تونل {item['id']} ناموفق بود: {e}")
                patched,changed=_rewrite_tunnel_host(config,old_host,new_host)
                if changed:endpoints.append(("local",None,item["id"],config,patched))
            for sid,srv in servers.items():
                try:
                    listing=server_remote(srv,{"op":"list"})
                    for item in listing.get("items",[]):
                        tid=item.get("id")
                        if not tid:continue
                        config=server_remote(srv,{"op":"config","id":tid})
                        patched,changed=_rewrite_tunnel_host(config,old_host,new_host)
                        if changed:endpoints.append((sid,srv,tid,config,patched))
                except Exception as e:
                    raise RuntimeError(f"وضعیت تونل‌های سرور {sid} بررسی نشد؛ برای جلوگیری از باقی‌ماندن IP قدیمی، تغییر اتصال برگردانده شد: {e}")
        for sid,srv,tid,before,after in endpoints:
            data={**after,"id":tid}
            if sid=="local":update_tunnel(data)
            else:server_remote(srv,{"op":"update","data":data})
            applied.append((sid,srv,tid,before))
    except Exception as error:
        rollback_errors=[]
        for sid,srv,tid,before in reversed(applied):
            try:
                if sid=="local":update_tunnel({**before,"id":tid})
                else:server_remote(srv,{"op":"update","data":{**before,"id":tid}})
            except Exception as rollback:rollback_errors.append(f"{sid}/{tid}: {rollback}")
        with db() as c:c.execute("UPDATE servers SET host=?,user=?,proxy_server_id=?,location=?,auto_geoip=?,geoip_host=? WHERE id=?",(previous_connection["host"],previous_connection["user"],previous_connection["proxy_server_id"],previous_connection["location"],previous_connection["auto_geoip"],previous_connection["geoip_host"],server_id))
        suffix=("؛ بازگردانی ناقص: "+" | ".join(rollback_errors)) if rollback_errors else ""
        raise RuntimeError("به‌روزرسانی اتصال سرور ناموفق شد؛ تغییر اتصال و تونل‌های انجام‌شده برگردانده شدند: "+str(error)+suffix)
    return {"ok":True,"server":server_id,"old_host":old_host,"host":new_host,"user":new_user,"proxy_server_id":new_proxy_id,"location":new_location,"geoip":geoip_result,"geoip_error":geoip_error,"updated_tunnels":len({x[2] for x in endpoints}),"updated_endpoints":len(endpoints),"restarted_endpoints":len(endpoints),"unavailable_servers":[]}

def server(host,port):
    try:ipaddress.ip_address(host)
    except ValueError as e:raise ValueError("bind host must be an IP address") from e
    class H(BaseHTTPRequestHandler):
        def setup(self):
            conn=self.request
            try:
                conn.settimeout(10);prefix=conn.recv(3,socket.MSG_PEEK|socket.MSG_WAITALL)
                if prefix.startswith(b'\x16\x03'):
                    cert=pathlib.Path('/etc/tunnelmgr/panel-tls/fullchain.pem');key=pathlib.Path('/etc/tunnelmgr/panel-tls/privkey.pem')
                    if not cert.is_file() or not key.is_file():raise OSError('TLS is not configured')
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
                    context.load_cert_chain(str(cert),str(key));self.request=context.wrap_socket(conn,server_side=True,do_handshake_on_connect=True)
                self.request.settimeout(None)
            except Exception:
                conn.close();raise
            super().setup()
        def send(self,status,obj,ctype="application/json; charset=utf-8"):
            b=obj if isinstance(obj,bytes) else json.dumps(obj,ensure_ascii=False).encode();self.send_response(status);self.send_header("Content-Type",ctype);self.send_header("Cache-Control","no-store");self.send_header("Content-Length",str(len(b)));self.send_header("X-Content-Type-Options","nosniff");self.end_headers();self.wfile.write(b)
        def body(self):
            n=int(self.headers.get("Content-Length","0"))
            if n<1 or n>65536:raise ValueError("body must be 1..65536 bytes")
            return json.loads(self.rfile.read(n))
        def role(self):
            from http.cookies import SimpleCookie
            cookie=SimpleCookie(self.headers.get("Cookie",""))
            morsel=cookie.get("tunnelmgr_session")
            if not morsel:return None
            value=morsel.value; entry=SESSIONS.get(value)
            if not entry:return None
            if entry[2]<time.time():SESSIONS.pop(value,None);return None
            return entry[1]
        def session(self):
            from http.cookies import SimpleCookie
            cookie=SimpleCookie(self.headers.get("Cookie",""));m=cookie.get("tunnelmgr_session")
            entry=SESSIONS.get(m.value) if m else None
            return entry if entry and entry[2]>=time.time() else None
        def do_GET(self):
            if self.path=="/":
                f=pathlib.Path(__file__).resolve().parents[1]/"web/index.html";return self.send(200,f.read_bytes(),"text/html; charset=utf-8")
            if self.path=="/assets/Yekan.woff2":
                f=pathlib.Path(__file__).resolve().parents[1]/"web/assets/Yekan.woff2";return self.send(200,f.read_bytes(),"font/woff2")
            if self.path in ("/assets/mesh-central.svg", "/assets/mesh-iran.svg", "/assets/mesh-abroad.svg"):
                f=pathlib.Path(__file__).resolve().parents[1]/"web"/self.path.lstrip("/");return self.send(200,f.read_bytes(),"image/svg+xml")
            if self.path=="/admin":
                self.send_response(302);self.send_header("Location","/#accounts");self.send_header("Content-Length","0");self.end_headers();return
            if self.path=="/health":return self.send(200,{"ok":True})
            if self.path=="/api/v1/auth/session":
                s=self.session();return self.send(200,{"ok":bool(s),"username":s[0] if s else None,"role":s[1] if s else None})
            role=self.role()
            if not role:return self.send(401,{"error":"sign in required"})
            if self.path=="/api/v1/settings/panel-tls":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:return self.send(200,privileged({'op':'panel-tls','id':'panel-tls','action':'status'}))
                except Exception as e:return self.send(502,{'error':str(e)})
            if self.path=="/api/v1/routing":
                if role not in ("admin","operator"):return self.send(403,{"error":"insufficient permissions"})
                return self.send(200,{"items":routing_rows()})
            if self.path.split("?",1)[0]=="/api/v1/forwards":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                from urllib.parse import parse_qs
                server_id=parse_qs(self.path.partition("?")[2]).get("server_id",["local"])[0]
                if server_id!="local" and not ID.fullmatch(server_id):return self.send(400,{"error":"invalid server id"})
                return self.send(200,{"items":forward_rows(),"service":forward_service_status(server_id)})
            if self.path=="/api/v1/tunnels":return self.send(200,{"items":rows()})
            if self.path=="/api/v1/servers":return self.send(200,{"items":[{k:v for k,v in s.items() if k!="identity"}|{"has_identity":bool(s.get("identity"))} for s in server_rows()]})
            if self.path=="/api/v1/servers/status":
                with MONITOR_LOCK:statuses=list(MONITOR_SERVERS)
                return self.send(200,{"items":statuses})
            if self.path=="/api/v1/servers/resources":
                with MONITOR_LOCK:resources=[dict(item) for item in MONITOR_RESOURCES]
                return self.send(200,{"items":resources})
            bits=self.path.strip("/").split("/")
            if len(bits)==7 and bits[:3]==["api","v1","servers"] and bits[4]=="tunnels" and bits[6]=="config":
                if self.role() not in ("admin","operator"):return self.send(403,{"error":"insufficient permissions"})
                srv=next((x for x in server_rows() if x["id"]==bits[3]),None)
                if not srv:return self.send(404,{"error":"server not found"})
                try:return self.send(200,server_remote(srv,{"op":"config","id":bits[5]}))
                except Exception as e:return self.send(400,{"error":str(e)})
            if len(bits)==5 and bits[:3]==["api","v1","tunnels"] and bits[4]=="config":
                if self.role() not in ("admin","operator"):return self.send(403,{"error":"insufficient permissions"})
                ident=bits[3]
                if not ID.fullmatch(ident):return self.send(400,{"error":"invalid id"})
                try:return self.send(200,tunnel_config(ident))
                except Exception as e:return self.send(404 if "unknown tunnel" in str(e) else 400,{"error":str(e)})
            if len(bits)==5 and bits[:3]==["api","v1","servers"] and bits[4]=="tunnels":
                srv=next((x for x in server_rows() if x["id"]==bits[3]),None)
                if not srv:return self.send(404,{"error":"server not found"})
                try:return self.send(200,{"items":server_remote(srv,{"op":"list"})})
                except Exception as e:return self.send(502,{"error":str(e)})
            if len(bits)==4 and bits[:3]==["api","v1","tunnels"]:
                ident=bits[3]
                if not ID.fullmatch(ident):return self.send(400,{"error":"invalid id"})
                item=find(ident)
                if not item:return self.send(404,{"error":"not found"})
                try:
                    native=item["metadata"].get("native_profile")
                    response=privileged({"op":"profile","group":"network","id":native,"action":"status"} if native else {"op":"status","id":ident})
                    if "error" in response:return self.send(502,{"error":response["error"],"item":item})
                    item["live"]={"active":"ActiveState=active" in response.get("output","")} if native else response["status"]
                    with MONITOR_LOCK:health=MONITOR_TUNNELS.get(ident)
                    item["health"]=health if health is not None else tunnel_health(item)
                    return self.send(200,item)
                except Exception as e:return self.send(502,{"error":str(e),"item":item})
            if len(bits)==5 and bits[:3]==["api","v1","tunnels"] and bits[4]=="logs":
                ident=bits[3]
                if not ID.fullmatch(ident):return self.send(400,{"error":"invalid id"})
                if not find(ident):return self.send(404,{"error":"not found"})
                try:
                    response=privileged({"op":"logs","id":ident})
                    if "error" in response:return self.send(502,response)
                    return self.send(200,{"id":ident,"logs":response.get("logs","")})
                except Exception as e:return self.send(502,{"error":str(e)})
            return self.send(404,{"error":"not found"})
        def do_POST(self):
            if self.path=="/api/v1/auth/login":
                try:
                    data=self.body();name=data.get("username","");password=data.get("password","")
                    with db() as c:row=c.execute("SELECT role,digest FROM accounts WHERE name=?",(name,)).fetchone()
                    if not row or not verify_password(password,row["digest"]):return self.send(401,{"error":"نام کاربری یا گذرواژه نادرست است"})
                    session=secrets.token_urlsafe(32);SESSIONS[session]=(name,row["role"],time.time()+12*3600)
                    self.send_response(200);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Cache-Control","no-store")
                    self.send_header("Set-Cookie",f"tunnelmgr_session={session}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200")
                    payload=json.dumps({"ok":True,"username":name,"role":row["role"]},ensure_ascii=False).encode();self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload);return
                except Exception as e:return self.send(400,{"error":str(e)})
            if self.path=="/api/v1/auth/logout":
                from http.cookies import SimpleCookie
                cookie=SimpleCookie(self.headers.get("Cookie",""));m=cookie.get("tunnelmgr_session")
                if m:SESSIONS.pop(m.value,None)
                self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Set-Cookie","tunnelmgr_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");self.send_header("Content-Length","11");self.end_headers();self.wfile.write(b'{"ok":true}');return
            role=self.role()
            if not role:return self.send(401,{"error":"unauthorized"})
            if self.path=="/api/v1/settings/panel-tls":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:
                    data=self.body();result=privileged({'op':'panel-tls','id':'panel-tls','action':'apply','domain':data.get('domain'),'email':data.get('email'),'port':data.get('port')},timeout=30)
                    if result.get('error'):return self.send(400,result)
                    return self.send(202,result)
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/forwards":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:
                    data=self.body();action=data.get("action");ident=data.get("id","");server_id=data.get("server_id","local")
                    if not isinstance(server_id,str) or (server_id!="local" and not ID.fullmatch(server_id)):raise ValueError("شناسهٔ سرور شنود نامعتبر است")
                    if server_id!="local" and not any(s["id"]==server_id for s in server_rows()):raise ValueError("سرور شنود در فهرست مدیریت‌شده‌ها نیست")
                    if action in ("create","update"):
                        config=normalize_forward(data,server_id)
                        current=forward_rows();exists=next((x for x in current if x["id"]==config["id"]),None)
                        if action=="create" and exists:raise ValueError("این شناسه از قبل ثبت شده است")
                        if action=="update" and (not exists or exists.get("server_id","local")!=server_id):raise ValueError("قانون پورت‌فوروارد روی این سرور پیدا نشد")
                        desired=[x for x in current if x.get("server_id","local")==server_id and x["id"]!=config["id"]]+[config]
                        apply_forward_set(server_id,desired)
                        with db() as c:c.execute("INSERT INTO port_forwards(id,config) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET config=excluded.config",(config["id"],json.dumps(config)))
                        return self.send(201 if action=="create" else 200,{"ok":True,"item":config})
                    if action=="delete":
                        if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError("شناسهٔ قانون نامعتبر است")
                        current=forward_rows();existing=next((x for x in current if x["id"]==ident),None)
                        if not existing or existing.get("server_id","local")!=server_id:raise ValueError("قانون پورت‌فوروارد روی این سرور پیدا نشد")
                        desired=[x for x in current if x.get("server_id","local")==server_id and x["id"]!=ident]
                        apply_forward_set(server_id,desired)
                        with db() as c:c.execute("DELETE FROM port_forwards WHERE id=?",(ident,))
                        return self.send(200,{"ok":True})
                    raise ValueError("عملیات پورت‌فوروارد نامعتبر است")
                except Exception as e:return self.send(400,{"error":str(e)})
            remote_update=re.fullmatch(r"/api/v1/servers/([a-z0-9][a-z0-9_-]{0,47})/tunnels/([a-z0-9][a-z0-9_-]{0,47})/update",self.path)
            if remote_update:
                if role not in ("admin","operator"):return self.send(403,{"error":"insufficient permissions"})
                srv=next((x for x in server_rows() if x["id"]==remote_update[1]),None)
                if not srv:return self.send(404,{"error":"server not found"})
                try:
                    data=self.body();data["id"]=remote_update[2]
                    return self.send(200,server_remote(srv,{"op":"update","data":data}))
                except Exception as e:return self.send(400,{"error":str(e)})
            local_update=re.fullmatch(r"/api/v1/tunnels/([a-z0-9][a-z0-9_-]{0,47})/update",self.path)
            if local_update:
                if role not in ("admin","operator"):return self.send(403,{"error":"insufficient permissions"})
                try:
                    data=self.body();data["id"]=local_update[1]
                    return self.send(200,update_tunnel(data))
                except Exception as e:return self.send(400,{"error":str(e)})
            remote_secret=re.fullmatch(r"/api/v1/servers/([a-z0-9][a-z0-9_-]{0,47})/secrets",self.path)
            if remote_secret:
                if role not in ("admin","operator"):return self.send(403,{"error":"insufficient permissions"})
                srv=next((x for x in server_rows() if x["id"]==remote_secret[1]),None)
                if not srv:return self.send(404,{"error":"server not found"})
                try:
                    data=self.body();ident=data.get("id","");action=data.get("action")
                    if not isinstance(ident,str) or not ID.fullmatch(ident) or action not in ("create","delete"):raise ValueError("invalid secret request")
                    kind=data.get("kind","token")
                    if kind not in ("token","psk"):raise ValueError("invalid secret kind")
                    result=server_remote(srv,{"op":"secret","id":ident,"action":action,"kind":kind,"value":data.get("value")})
                    return self.send(201 if action=="create" else 200,result)
                except Exception as e:return self.send(400,{"error":str(e)})
            remote_create=re.fullmatch(r"/api/v1/servers/([a-z0-9][a-z0-9_-]{0,47})/tunnels/(native|backhaul)",self.path)
            if remote_create:
                if role!="admin" and role!="operator":return self.send(403,{"error":"insufficient permissions"})
                srv=next((x for x in server_rows() if x["id"]==remote_create[1]),None)
                if not srv:return self.send(404,{"error":"server not found"})
                try:
                    data=self.body();data["transport"]="backhaul" if remote_create[2]=="backhaul" else data.get("transport")
                    result=server_remote(srv,{"op":"create","data":data});return self.send(201,result)
                except Exception as e:return self.send(400,{"error":str(e)})
            remote_op=re.fullmatch(r"/api/v1/servers/([a-z0-9][a-z0-9_-]{0,47})/tunnels/([a-z0-9_-]{1,48})/(start|stop|restart|health|delete)",self.path)
            if remote_op:
                if role not in ("admin","operator"):return self.send(403,{"error":"insufficient permissions"})
                srv=next((x for x in server_rows() if x["id"]==remote_op[1]),None)
                if not srv:return self.send(404,{"error":"server not found"})
                try:return self.send(200,server_remote(srv,{"op":"operate","id":remote_op[2],"action":remote_op[3]}))
                except Exception as e:return self.send(400,{"error":str(e)})
            if self.path=="/api/v1/servers":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:
                    data=self.body();action=data.get("action");ident=data.get("id","")
                    if action=="geoip":return self.send(200,{"ok":True,**geoip_location(data.get("host",""))})
                    if action in ("update-host","update-connection"):
                        if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError("شناسه سرور نامعتبر است")
                        host=data.get("host","")
                        if not isinstance(host,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}",host):raise ValueError("آدرس سرور نامعتبر است")
                        current=next((x for x in server_rows() if x["id"]==ident),None)
                        if not current:raise ValueError("سرور پیدا نشد")
                        user=data.get("user",current["user"]);proxy_id=data.get("proxy_server_id",current.get("proxy_server_id",""));password=data.get("ssh_password","");location=data.get("location",current.get("location","abroad"));auto_geoip=data.get("auto_geoip",bool(current.get("auto_geoip",1)))
                        if not isinstance(user,str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}",user):raise ValueError("نام کاربری SSH نامعتبر است")
                        if not isinstance(proxy_id,str):raise ValueError("سرور پروکسی نامعتبر است")
                        if not isinstance(password,str):raise ValueError("گذرواژه SSH نامعتبر است")
                        if not isinstance(auto_geoip,bool):raise ValueError("گزینهٔ GeoIP نامعتبر است")
                        return self.send(200,update_server_host(ident,host,user,proxy_id,password,location,auto_geoip))
                    if action=="add":
                        host=data.get("host","");user=data.get("user","root");identity=data.get("identity","");proxy_id=data.get("proxy_server_id","");location=data.get("location","abroad")
                        auto_geoip=data.get("auto_geoip",True)
                        if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError("شناسه سرور نامعتبر است")
                        if not isinstance(host,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}",host):raise ValueError("آدرس سرور نامعتبر است")
                        if not isinstance(user,str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}",user):raise ValueError("نام کاربری SSH نامعتبر است")
                        if not isinstance(proxy_id,str):raise ValueError("سرور پروکسی نامعتبر است")
                        if location not in ("iran","abroad"):raise ValueError("موقعیت سرور باید ایران یا خارج باشد")
                        if not isinstance(auto_geoip,bool):raise ValueError("گزینهٔ GeoIP نامعتبر است")
                        geoip_result=None;geoip_error=""
                        try:
                            if auto_geoip:
                                geoip_result=geoip_location(host)
                                location=geoip_result["location"]
                        except Exception as e:geoip_error=str(e)
                        if proxy_id:
                            proxy=next((x for x in server_rows() if x["id"]==proxy_id),None)
                            if not proxy or proxy_id==ident:raise ValueError("سرور پروکسی باید از قبل ثبت شده باشد و با مقصد فرق کند")
                            if proxy.get("proxy_server_id"):raise ValueError("سرور پروکسی انتخابی خودش نباید از پروکسی دیگری عبور کند")
                        with db() as c:
                            if c.execute("SELECT 1 FROM servers WHERE id=?",(ident,)).fetchone():raise ValueError("شناسه سرور تکراری است")
                        private_key=data.get("identity_key","")
                        if private_key:
                            if not isinstance(private_key,str) or len(private_key)>58000 or "PRIVATE KEY-----" not in private_key[:100]:raise ValueError("فایل کلید خصوصی SSH معتبر نیست")
                            keydir=BASE/"ssh-keys";keydir.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(keydir,0o700)
                            keypath=keydir/(ident+".key")
                            fd,tmp=tempfile.mkstemp(prefix=".key-",dir=keydir)
                            try:
                                os.fchmod(fd,0o600)
                                with os.fdopen(fd,"w") as f:f.write(private_key);f.flush();os.fsync(f.fileno())
                                os.replace(tmp,keypath)
                            finally:pathlib.Path(tmp).unlink(missing_ok=True)
                            identity=str(keypath)
                        else:identity=str(pathlib.Path(identity).expanduser().resolve()) if identity else ""
                        if identity:
                            keypath=pathlib.Path(identity)
                            if not keypath.is_file() or not os.access(keypath,os.R_OK):raise ValueError("فایل کلید SSH پیدا نشد یا قابل‌خواندن نیست")
                            try:keypath.relative_to(BASE.resolve())
                            except ValueError:raise ValueError(f"کلید خصوصی را داخل مسیر دادهٔ پنل قرار بده: {BASE}/ssh-keys")
                        elif data.get("ssh_password"):
                            srv=bootstrap_server({"id":ident,"host":host,"user":user,"identity":"","proxy_server_id":proxy_id},data["ssh_password"])
                            identity=srv["identity"]
                        else:raise ValueError("گذرواژهٔ SSH یا کلید خصوصی را وارد کن")
                        with db() as c:c.execute("INSERT INTO servers(id,host,user,identity,proxy_server_id,location,auto_geoip,geoip_host) VALUES(?,?,?,?,?,?,?,?)",(ident,host,user,identity,proxy_id,location,int(auto_geoip),host if geoip_result else ""))
                        if data.get("install"):
                            srv={"id":ident,"host":host,"user":user,"identity":identity,"proxy_server_id":proxy_id}
                            try:return self.send(201,{"ok":True,"server":ident,"location":location,"geoip":geoip_result,"geoip_error":geoip_error,"install":install_remote(srv)})
                            except Exception as e:return self.send(502,{"error":f"سرور ثبت شد اما نصب ناموفق بود: {e}"})
                        return self.send(201,{"ok":True,"server":ident,"location":location,"geoip":geoip_result,"geoip_error":geoip_error})
                    if action=="delete":
                        srv=next((x for x in server_rows() if x["id"]==ident),None)
                        if not srv:raise ValueError("سرور پیدا نشد")
                        dependents=[x["id"] for x in server_rows() if x.get("proxy_server_id")==ident]
                        if dependents:raise ValueError("ابتدا سرورهای عبوری را از پروکسی جدا کن: "+", ".join(dependents))
                        remove_bootstrap_key(srv)
                        with db() as c:removed=c.execute("DELETE FROM servers WHERE id=?",(ident,)).rowcount
                        if not removed:raise ValueError("سرور پیدا نشد")
                        return self.send(200,{"ok":True})
                    raise ValueError("عملیات سرور ناشناخته است")
                except sqlite3.IntegrityError:return self.send(409,{"error":"شناسه سرور تکراری است"})
                except Exception as e:return self.send(400,{"error":str(e)})
            server_action=re.fullmatch(r"/api/v1/servers/([a-z0-9][a-z0-9_-]{0,47})/(test|install)",self.path)
            if server_action:
                if role!="admin":return self.send(403,{"error":"admin role required"})
                srv=next((x for x in server_rows() if x["id"]==server_action[1]),None)
                if not srv:return self.send(404,{"error":"server not found"})
                try:
                    if server_action[2]=="test":
                        p=subprocess.run(ssh_argv(srv)+["true"],capture_output=True,text=True,timeout=20)
                        if p.returncode:raise RuntimeError((p.stderr or p.stdout)[-1200:])
                        return self.send(200,{"ok":True,"reachable":True})
                    return self.send(200,install_remote(srv))
                except Exception as e:return self.send(502,{"error":str(e)})
            operator_action=re.fullmatch(r"/api/v1/tunnels/[a-z0-9_-]+/(start|stop|restart|health|delete)",self.path)
            operator_create=self.path in ("/api/v1/tunnels/native","/api/v1/tunnels/backhaul","/api/v1/tunnels/secrets","/api/v1/tunnels/wireguard-pair","/api/v1/tunnels/openvpn-pair","/api/v1/tunnels/mtu-probe","/api/v1/routing") or bool(re.fullmatch(r"/api/v1/servers/[a-z0-9][a-z0-9_-]{0,47}/tunnels/(native|backhaul)",self.path))
            if role!="admin" and (self.path!="/api/v1/mesh/plan" and not (role=="operator" and (operator_action or operator_create))):
                return self.send(403,{"error":"insufficient permissions"})
            try:
                if self.path=="/api/v1/admin/accounts":
                    data=self.body()
                    action=data.get("action")
                    with db() as c:
                        if action=="list":return self.send(200,{"items":[dict(r) for r in c.execute("SELECT name,role FROM accounts ORDER BY name")]})
                        name=data.get("name","")
                        if not ID.fullmatch(name):raise ValueError("Invalid account name")
                        if action=="create" and data.get("role") in ("admin","viewer","operator"):
                            password=data.get("password","")
                            if len(password)<12:raise ValueError("password must contain at least 12 characters")
                            c.execute("INSERT INTO accounts VALUES(?,?,?)",(name,data["role"],password_digest(password)))
                            c.commit()
                            return self.send(201,{"ok":True})
                        if action=="password":
                            password=data.get("password","")
                            if len(password)<12:raise ValueError("password must contain at least 12 characters")
                            if not c.execute("UPDATE accounts SET digest=? WHERE name=?",(password_digest(password),name)).rowcount:raise ValueError("unknown account")
                            c.commit();return self.send(200,{"ok":True})
                        if action=="revoke" and c.execute("DELETE FROM accounts WHERE name=?",(name,)).rowcount:
                            c.commit()
                            return self.send(200,{"ok":True})
                        raise ValueError("Unknown account or action")
                if self.path=="/api/v1/admin/profiles":
                    req=self.body()
                    result=privileged({**req,"op":"profile"})
                    return self.send(400 if "error" in result else 200,result)
                match=re.fullmatch(r"/api/v1/mesh/(apply|status)/([a-z0-9][a-z0-9_-]{0,47})",self.path)
                if match:
                    result=privileged({"op":"mesh-"+match[1],"id":match[2]})
                    return self.send((202 if match[1]=="apply" else 200) if result.get("ok") else 400,result)
                if self.path=="/api/v1/mesh/plan":
                    plan=mesh_plan(**self.body())
                    return self.send(200,plan)
                if self.path=="/api/v1/tunnels/secrets":
                    data=self.body();ident=data.get("id","");action=data.get("action")
                    if not isinstance(ident,str) or not ID.fullmatch(ident) or action not in ("create","delete"):raise ValueError("invalid secret request")
                    kind=data.get("kind","token")
                    if kind not in ("token","psk"):raise ValueError("invalid secret kind")
                    result=privileged({"op":"secret","id":ident,"action":action,"kind":kind,"value":data.get("value")})
                    return self.send(201 if action=="create" else 200,result)
                if self.path=="/api/v1/tunnels/mtu-probe":
                    data=self.body()
                    return self.send(200,recommended_tunnel_mtu(data.get("server_a"),data.get("server_b"),data.get("host_a"),data.get("host_b"),data.get("transport")))
                if self.path=="/api/v1/tunnels/backhaul":return self.send(201,create_instance(self.body()))
                if self.path=="/api/v1/tunnels/native":return self.send(201,create_native(self.body()))
                if self.path=="/api/v1/tunnels/wireguard-pair":return self.send(201,create_wireguard_pair(self.body()))
                if self.path=="/api/v1/tunnels/openvpn-pair":return self.send(201,create_openvpn_pair(self.body()))
                if self.path=="/api/v1/tunnels/openconnect-pair":return self.send(410,{"error":"OpenConnect has been removed from tunnel creation"})
                if self.path=="/api/v1/routing":
                    data=self.body()
                    if data.get('action')=='delete':return self.send(200,delete_routing_link(data.get('id','')))
                    return self.send(201,create_routing_pair(data))
                bits=self.path.strip("/").split("/")
                if len(bits)==5 and bits[:3]==["api","v1","tunnels"] and bits[4] in ("start","stop","restart","health","delete"):
                    ident,op=bits[3],bits[4]
                    if not ID.fullmatch(ident):return self.send(400,{"error":"invalid id"})
                    if not find(ident):return self.send(404,{"error":"not found"})
                    item=find(ident)
                    native=item["metadata"].get("native_profile")
                    if op=="restart" and item["metadata"].get("transport")=="ipsec-esp-udp":
                        response=restart_ipsec_pair(ident)
                    else:
                        response=privileged({"op":"profile","group":"network","id":native,"action":{"status":"status"}.get(op,op)} if native else {"op":op,"id":ident})
                    if not response.get("ok",op=="status"):return self.send(400,response)
                    if op=="delete":
                        with db() as c:c.execute("DELETE FROM tunnels WHERE id=?",(ident,))
                    return self.send(200,{"ok":True,"id":ident,"operation":op,**response})
                return self.send(404,{"error":"not found"})
            except Exception as e:return self.send(400,{"error":str(e)})
        def log_message(self,fmt,*args):print("api:",fmt%args,file=sys.stderr)
    print(f"API on http://{host}:{port} (HTTPS on same port when configured); password authentication enabled",flush=True)
    db().close()
    threading.Thread(target=geoip_monitor_loop,name="geoip-monitor",daemon=True).start()
    threading.Thread(target=monitor_loop,name="tunnel-health-monitor",daemon=True).start()
    threading.Thread(target=resource_monitor_loop,name="resource-monitor",daemon=True).start()
    ThreadingHTTPServer((host,port),H).serve_forever()

def main():
    p=argparse.ArgumentParser(prog="tunnelctl");s=p.add_subparsers(dest="cmd",required=True)
    s.add_parser("init");s.add_parser("list");a=s.add_parser("api");a.add_argument("--host",default="127.0.0.1");a.add_argument("--port",type=int,default=8765)
    b=s.add_parser("backhaul");b.add_argument("args",nargs=argparse.REMAINDER)
    m=s.add_parser("mesh");ms=m.add_subparsers(dest="mesh_cmd",required=True);mp=ms.add_parser("plan");mp.add_argument("--nodes",required=True);mp.add_argument("--pool",default="10.240.0.0/16");mp.add_argument("--topology",choices=("full","hub"),default="full");mp.add_argument("--hub");mp.add_argument("--direction",choices=("direct","reverse"),default="direct");mp.add_argument("--public-nodes");mp.add_argument("--endpoints",help="comma-separated node=host entries")
    u=s.add_parser("account");u.add_argument("action",choices=("create","revoke","list","password"));u.add_argument("name",nargs="?");u.add_argument("--role",choices=("viewer","operator","admin"),default="viewer");u.add_argument("--password",help=argparse.SUPPRESS);u.add_argument("--password-stdin",action="store_true",help=argparse.SUPPRESS)
    n=p.parse_args()
    try:
        if n.cmd=="init":db().close();print(f"initialized {DB}; create the first user with: tunnelctl.py account create admin --role admin")
        elif n.cmd=="account":account(n)
        elif n.cmd=="list":print(json.dumps(rows(),separators=(",",":")))
        elif n.cmd=="api":server(n.host,n.port)
        elif n.cmd=="mesh":
            public=n.public_nodes.split(",") if n.public_nodes else None
            endpoints={}
            if n.endpoints:
                for pair in n.endpoints.split(","):
                    node,sep,host=pair.partition("=")
                    if not sep or not node or not host:raise ValueError("endpoints use node=host,node=host")
                    endpoints[node.strip()]=host.strip()
            print(json.dumps(mesh_plan(n.nodes.split(","),n.pool,n.topology,n.hub,n.direction,public,endpoints or None),indent=2))
        elif n.cmd=="backhaul":
            if n.args[:1]==["create"]:
                q=argparse.ArgumentParser(add_help=False);q.add_argument("id");q.add_argument("--mode",choices=("server","client"),required=True);ns,rest=q.parse_known_args(n.args[1:]);create_instance({"id":ns.id,"mode":ns.mode,**{}} if not rest else create_from_cli(ns,rest))
            else:
                run(n.args)
                if len(n.args)>1 and n.args[0]=="delete":
                    with db() as c:c.execute("DELETE FROM tunnels WHERE id=?",(n.args[1],))
    except Exception as e:print(f"tunnelctl: {e}",file=sys.stderr);return 1
    return 0

def create_from_cli(ns,rest):
    data={"id":ns.id,"mode":ns.mode};i=0
    while i<len(rest):
        flag=rest[i]
        if not flag.startswith("--"):raise ValueError("unexpected create argument")
        key=flag[2:].replace("-","_")
        if key not in FIELDS:raise ValueError(f"unsupported option {flag}")
        if key in ("accept_udp","proxy_protocol","replace","start"):data[key]=True;i+=1;continue
        if i+1>=len(rest):raise ValueError(f"missing value for {flag}")
        val=rest[i+1]
        if key in ("source_bind","local_ip"):
            data.setdefault(key,[]).append(val)
        else:data[key]=val
        i+=2
    return data
if __name__=="__main__":raise SystemExit(main())
