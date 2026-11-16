#!/usr/bin/env python3
"""avaTUN API; delegates Backhaul operations to the installed Backhaul manager."""
from __future__ import annotations
import hashlib
import base64, hmac, struct
import argparse, getpass, ipaddress, json, os, pathlib, re, secrets, shlex, shutil, sqlite3, subprocess, sys, time
import unicodedata
import tarfile, tempfile
import platform
import ssl, socket, urllib.request, urllib.parse, signal
from concurrent.futures import ThreadPoolExecutor
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from topology import mesh_plan
from telegram_miniapp import allowed_role as telegram_miniapp_role, load_config as load_telegram_miniapp_config, verify_init_data

APP_NAME="avatun"
APP_VERSION="1.0.0.13"
BASE=pathlib.Path(os.environ.get("TUNNELMGR_HOME",str(pathlib.Path.home()/".local/share/tunnelmgr")))
DB=BASE/"state.sqlite3"
MANAGER=os.environ.get("BACKHAUL_MANAGER","backhaul-manager")
ID=re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
SESSIONS={}
PENDING_LOGINS={}
MONITOR_LOCK=threading.Lock();MONITOR_TUNNELS={};MONITOR_SERVERS=[];MONITOR_RESOURCES=[]
GEOIP_CACHE={}
FORWARD_LOCK=threading.Lock()
PROXY_LOCK=threading.RLock()
NATIVE_PAIR_LOCK=threading.RLock()
SPEEDTEST_LOCK=threading.Lock()
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
    account_columns={r[1] for r in c.execute("PRAGMA table_info(accounts)")}
    for column,definition in (("totp_secret","TEXT NOT NULL DEFAULT ''"),("totp_pending","TEXT NOT NULL DEFAULT ''"),("totp_pending_at","INTEGER NOT NULL DEFAULT 0"),("totp_enabled","INTEGER NOT NULL DEFAULT 0"),("totp_last_step","INTEGER NOT NULL DEFAULT -1"),("recovery_codes","TEXT NOT NULL DEFAULT '[]'"),("theme_palette","TEXT NOT NULL DEFAULT 'teal'")):
        if column not in account_columns:c.execute(f"ALTER TABLE accounts ADD COLUMN {column} {definition}")
    c.execute("CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY,host TEXT NOT NULL,user TEXT NOT NULL,identity TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    server_columns={r[1] for r in c.execute("PRAGMA table_info(servers)")}
    if "proxy_server_id" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN proxy_server_id TEXT NOT NULL DEFAULT ''")
    if "proxy_line_id" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN proxy_line_id TEXT NOT NULL DEFAULT ''")
    if "location" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN location TEXT NOT NULL DEFAULT 'abroad'")
    if "auto_geoip" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN auto_geoip INTEGER NOT NULL DEFAULT 1")
    if "geoip_host" not in server_columns:c.execute("ALTER TABLE servers ADD COLUMN geoip_host TEXT NOT NULL DEFAULT ''")
    for column,definition in (("geo_country_code","TEXT"),("geo_country_name","TEXT"),("geo_city","TEXT"),("geo_latitude","REAL"),("geo_longitude","REAL")):
        if column not in server_columns:c.execute(f"ALTER TABLE servers ADD COLUMN {column} {definition}")
    c.execute("CREATE TABLE IF NOT EXISTS port_forwards(id TEXT PRIMARY KEY,config TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS proxy_lines(id TEXT PRIMARY KEY,metadata TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS proxy_forwards(id TEXT PRIMARY KEY,config TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS routing_links(id TEXT PRIMARY KEY,config TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS tunnel_speedtests(id TEXT PRIMARY KEY,result TEXT NOT NULL,checked_at INTEGER NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS traffic_counters(scope TEXT NOT NULL,entity_id TEXT NOT NULL,server_id TEXT NOT NULL,rx_raw INTEGER NOT NULL,tx_raw INTEGER NOT NULL,rx_total INTEGER NOT NULL,tx_total INTEGER NOT NULL,checked_at INTEGER NOT NULL,PRIMARY KEY(scope,entity_id))")
    c.execute("CREATE TABLE IF NOT EXISTS resource_report_settings(server_id TEXT PRIMARY KEY,telegram_enabled INTEGER NOT NULL DEFAULT 1,metrics TEXT NOT NULL DEFAULT '[\"cpu\",\"memory\",\"swap\",\"disk\",\"network\"]')")
    resource_columns={r[1] for r in c.execute("PRAGMA table_info(resource_report_settings)")}
    if "metrics" not in resource_columns:c.execute("ALTER TABLE resource_report_settings ADD COLUMN metrics TEXT NOT NULL DEFAULT '[\"cpu\",\"memory\",\"swap\",\"disk\",\"network\"]'")
    c.execute("INSERT OR IGNORE INTO resource_report_settings(server_id,telegram_enabled) VALUES('local',1)")
    for row in c.execute("SELECT id FROM servers"):
        c.execute("INSERT OR IGNORE INTO resource_report_settings(server_id,telegram_enabled) VALUES(?,1)",(row[0],))
    c.commit(); return c

def resource_report_settings():
    with db() as c:
        c.execute("INSERT OR IGNORE INTO resource_report_settings(server_id,telegram_enabled) VALUES('local',1)")
        for row in c.execute("SELECT id FROM servers"):
            c.execute("INSERT OR IGNORE INTO resource_report_settings(server_id,telegram_enabled) VALUES(?,1)",(row[0],))
        c.commit()
        return {row['server_id']:bool(row['telegram_enabled']) for row in c.execute("SELECT server_id,telegram_enabled FROM resource_report_settings")}

RESOURCE_REPORT_METRICS=('cpu','memory','swap','disk','network')

def normalize_resource_metrics(value):
    if isinstance(value,str):
        try:value=json.loads(value)
        except (TypeError,ValueError):value=[]
    if not isinstance(value,(list,tuple,set)):value=[]
    return [name for name in RESOURCE_REPORT_METRICS if name in {str(item) for item in value}]

def resource_report_metrics():
    with db() as c:
        c.execute("INSERT OR IGNORE INTO resource_report_settings(server_id,telegram_enabled) VALUES('local',1)")
        for row in c.execute("SELECT id FROM servers"):
            c.execute("INSERT OR IGNORE INTO resource_report_settings(server_id,telegram_enabled) VALUES(?,1)",(row[0],))
        c.commit()
        return {row['server_id']:normalize_resource_metrics(row['metrics']) for row in c.execute("SELECT server_id,metrics FROM resource_report_settings")}

def set_resource_report_enabled(server_id,enabled):
    if server_id!='local' and not any(row['id']==server_id for row in server_rows()):
        raise ValueError('سرور پیدا نشد')
    with db() as c:
        c.execute("INSERT INTO resource_report_settings(server_id,telegram_enabled) VALUES(?,?) ON CONFLICT(server_id) DO UPDATE SET telegram_enabled=excluded.telegram_enabled",(server_id,int(bool(enabled))))
        c.commit()
    return bool(enabled)

def set_resource_report_metrics(server_id,metrics):
    if server_id!='local' and not any(row['id']==server_id for row in server_rows()):
        raise ValueError('سرور پیدا نشد')
    selected=normalize_resource_metrics(metrics)
    with db() as c:
        c.execute("INSERT INTO resource_report_settings(server_id,telegram_enabled,metrics) VALUES(?,?,?) ON CONFLICT(server_id) DO UPDATE SET metrics=excluded.metrics",(server_id,1,json.dumps(selected,ensure_ascii=False)))
        c.commit()
    return selected

def account_theme(name):
    with db() as c:
        row=c.execute("SELECT theme_palette FROM accounts WHERE name=?",(name,)).fetchone()
    return (row['theme_palette'] if row and row['theme_palette'] else 'teal')

def set_account_theme(name,palette):
    allowed={'teal','blue','mint','amber','coral','rose','violet','ice'}
    if palette not in allowed:raise ValueError('تم رنگی نامعتبر است')
    with db() as c:
        if not c.execute("UPDATE accounts SET theme_palette=? WHERE name=?",(palette,name)).rowcount:raise ValueError('حساب کاربری پیدا نشد')
        c.commit()
    return palette

def github_update_status():
    path=pathlib.Path('/var/lib/tunnelmgr/github-update.json')
    try:data=json.loads(path.read_text()) if path.is_file() else {}
    except (OSError,ValueError):data={}
    if not data:
        data={'current_version':APP_VERSION,'latest_version':None,'update_available':False,
              'state':'checking','checked_at':None,'error':None}
    data['current_version']=APP_VERSION
    service=subprocess.run(['/usr/bin/systemctl','is-active','tunnelmgr-github-update.service'],capture_output=True,text=True,timeout=5).stdout.strip()
    if service in ('active','activating'):
        data['state']='installing'
    return data

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

def _mfa_fernet():
    from cryptography.fernet import Fernet
    key_path=BASE/'mfa.key'
    if not key_path.exists() and DB.is_file():
        try:
            with sqlite3.connect(DB.resolve().as_uri()+'?mode=ro',uri=True) as c:
                tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                columns={r[1] for r in c.execute('PRAGMA table_info(accounts)')} if 'accounts' in tables else set()
                if 'totp_enabled' in columns and c.execute('SELECT 1 FROM accounts WHERE totp_enabled=1 LIMIT 1').fetchone():
                    raise RuntimeError(f'{key_path} is missing while MFA is enabled; refusing to create a replacement key')
        except sqlite3.Error as e:
            raise RuntimeError(f'cannot verify MFA state before creating {key_path}') from e
    try:
        fd=os.open(key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except FileExistsError:pass
    else:
        try:
            os.write(fd,Fernet.generate_key());os.fsync(fd)
        finally:os.close(fd)
    os.chmod(key_path,0o600)
    return Fernet(key_path.read_bytes())

def _mfa_seal(secret):return _mfa_fernet().encrypt(secret.encode()).decode()
def _mfa_open(secret):
    if not secret:return ''
    try:return _mfa_fernet().decrypt(secret.encode()).decode()
    except Exception as e:raise ValueError(f'TOTP secret cannot be decrypted; preserve {BASE}/mfa.key') from e

def _totp(secret,step):
    key=base64.b32decode(secret.upper()+'='*((8-len(secret)%8)%8))
    digest=hmac.new(key,struct.pack('>Q',step),hashlib.sha1).digest();offset=digest[-1]&15
    return f'{(struct.unpack("!I",digest[offset:offset+4])[0]&0x7fffffff)%1000000:06d}'

def _totp_match(secret,code,last_step=-1,*,now=None):
    raw=str(code).strip()
    if any(not (ch.isdecimal() or ch in ' -') for ch in raw):return None
    digits=''.join(str(unicodedata.digit(ch)) for ch in raw if ch.isdecimal())
    if len(digits)!=6:return None
    step=int((time.time() if now is None else now)//30)
    replayed=False
    for candidate in (step,step-1,step+1):
        if hmac.compare_digest(_totp(secret,candidate),digits):
            if candidate>last_step:return candidate
            replayed=True
    return 'replay' if replayed else None

def _recovery_codes(count=10):
    codes=[]
    for _ in range(count):
        raw=secrets.token_hex(8).upper();codes.append('-'.join(raw[i:i+4] for i in range(0,16,4)))
    return codes,[hashlib.sha256(code.encode()).hexdigest() for code in codes]

def _recovery_consume(codes,value):
    normalized=str(value).strip().upper().replace('-','').replace(' ','')
    if len(normalized)!=16:return None
    digest=hashlib.sha256(('-'.join(normalized[i:i+4] for i in range(0,16,4))).encode()).hexdigest()
    for index,stored in enumerate(codes):
        if hmac.compare_digest(digest,stored):return codes[:index]+codes[index+1:]
    return None

def _qr_svg(uri):
    binary=shutil.which('qrencode')
    if not binary:raise RuntimeError('QR generator is not installed; update the panel installer first')
    result=subprocess.run([binary,'--type=SVG','--output=-'],input=uri,text=True,capture_output=True,timeout=10)
    if result.returncode or not result.stdout.lstrip().startswith('<?xml') and '<svg' not in result.stdout[:500]:raise RuntimeError((result.stderr or 'QR generation failed').strip())
    return base64.b64encode(result.stdout.encode()).decode()

def _new_session(name,role,mfa_verified=True):
    token=secrets.token_urlsafe(32);SESSIONS[token]={'name':name,'role':role,'expires':time.time()+(12*3600 if mfa_verified else 900),'mfa_verified':bool(mfa_verified)}
    return token

def account(args):
    with db() as c:
        if args.action=="list":
            print(json.dumps([dict(x) for x in c.execute("SELECT name,role,totp_enabled FROM accounts ORDER BY name")]))
            return
        if not args.name or not ID.fullmatch(args.name):raise ValueError("invalid account name")
        if args.action=="create" and c.execute("SELECT 1 FROM accounts WHERE name=?",(args.name,)).fetchone():
            raise ValueError(f"account '{args.name}' already exists; use 'account edit {args.name} --role ROLE' or 'account password {args.name}'")
        if args.action=="revoke":
            if not c.execute("DELETE FROM accounts WHERE name=?",(args.name,)).rowcount:raise ValueError("unknown account")
            for key,value in list(SESSIONS.items()):
                if value.get('name')==args.name:SESSIONS.pop(key,None)
            return
        if args.action=="mfa-reset":
            if not c.execute("UPDATE accounts SET totp_secret='',totp_pending='',totp_pending_at=0,totp_enabled=0,totp_last_step=-1,recovery_codes='[]' WHERE name=?",(args.name,)).rowcount:raise ValueError("unknown account")
            for key,value in list(SESSIONS.items()):
                if value.get('name')==args.name:SESSIONS.pop(key,None)
            return
        if args.action=="edit" and not c.execute("SELECT 1 FROM accounts WHERE name=?",(args.name,)).fetchone():
            raise ValueError("unknown account")
        password_requested=args.action=="password" or args.action=="create" or args.set_password or args.password is not None or args.password_stdin
        if args.action=="edit" and args.role is None and not password_requested:
            raise ValueError("no changes requested; use --role ROLE or --set-password")
        password=None
        if password_requested:
            password=args.password or (sys.stdin.readline().rstrip("\r\n") if args.password_stdin else getpass.getpass("New password (12+ characters): "))
            if len(password)<12:raise ValueError("password must contain at least 12 characters")
        if args.action=="password":
            if not c.execute("UPDATE accounts SET digest=? WHERE name=?",(password_digest(password),args.name)).rowcount:raise ValueError("unknown account")
            c.commit()
            print("password updated")
            return
        if args.action=="edit":
            updates=[];values=[]
            if args.role is not None:updates.append("role=?");values.append(args.role)
            if password is not None:updates.append("digest=?");values.append(password_digest(password))
            values.append(args.name)
            c.execute(f"UPDATE accounts SET {', '.join(updates)} WHERE name=?",values)
            c.commit()
            print("account updated")
            return
        try:c.execute("INSERT INTO accounts(name,role,digest) VALUES(?,?,?)",(args.name,args.role or "viewer",password_digest(password)))
        except sqlite3.IntegrityError as e:
            if "accounts.name" in str(e):raise ValueError(f"account '{args.name}' already exists; use 'account edit {args.name} --role ROLE' or 'account password {args.name}'") from None
            raise
        c.commit()
        print("account created")

def rows():
    with db() as c:return [dict(r)|{"metadata":json.loads(r["metadata"])} for r in c.execute("SELECT * FROM tunnels ORDER BY id")]
def find(ident):return next((x for x in rows() if x["id"]==ident),None)

def tunnel_speedtest_rows():
    with db() as c:return {row['id']:json.loads(row['result']) for row in c.execute('SELECT id,result FROM tunnel_speedtests')}

def save_tunnel_speedtest(ident,result):
    with db() as c:c.execute('INSERT INTO tunnel_speedtests(id,result,checked_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET result=excluded.result,checked_at=excluded.checked_at',(ident,json.dumps(result,ensure_ascii=False),int(result.get('checked_at',time.time()))))

def attach_speedtests(items):
    results=tunnel_speedtest_rows()
    return [dict(item,speedtest=results.get(item.get('id'))) for item in items]

def traffic_totals(scope,ident):
    with db() as c:
        row=c.execute('SELECT server_id,rx_total,tx_total,checked_at FROM traffic_counters WHERE scope=? AND entity_id=?',(scope,ident)).fetchone()
    if not row:return None
    return {'server_id':row['server_id'],'received_bytes':row['rx_total'],'sent_bytes':row['tx_total'],'total_bytes':row['rx_total']+row['tx_total'],'checked_at':row['checked_at']}

def record_traffic(scope,ident,server_id,rx_bytes,tx_bytes):
    rx_bytes=max(0,int(rx_bytes));tx_bytes=max(0,int(tx_bytes));now=int(time.time())
    with db() as c:
        row=c.execute('SELECT server_id,rx_raw,tx_raw,rx_total,tx_total FROM traffic_counters WHERE scope=? AND entity_id=?',(scope,ident)).fetchone()
        if row:
            if row['server_id']!=server_id:owner_mismatch=True
            else:owner_mismatch=False
            if owner_mismatch:rx_total=tx_total=None
            else:
                old_rx=int(row['rx_raw']);old_tx=int(row['tx_raw'])
                rx_total=int(row['rx_total'])+(rx_bytes-old_rx if rx_bytes>=old_rx else rx_bytes)
                tx_total=int(row['tx_total'])+(tx_bytes-old_tx if tx_bytes>=old_tx else tx_bytes)
        else:rx_total,tx_total=rx_bytes,tx_bytes
        if not row or not owner_mismatch:
            c.execute('INSERT INTO traffic_counters(scope,entity_id,server_id,rx_raw,tx_raw,rx_total,tx_total,checked_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(scope,entity_id) DO UPDATE SET rx_raw=excluded.rx_raw,tx_raw=excluded.tx_raw,rx_total=excluded.rx_total,tx_total=excluded.tx_total,checked_at=excluded.checked_at',(scope,ident,server_id,rx_bytes,tx_bytes,rx_total,tx_total,now))
        else:rx_total=tx_total=None
    if rx_total is None:return traffic_totals(scope,ident)
    return {'server_id':server_id,'received_bytes':rx_total,'sent_bytes':tx_total,'total_bytes':rx_total+tx_total,'checked_at':now}

def tunnel_counter(item):
    meta=item.get('metadata') or {};transport=meta.get('transport')
    if transport in ('ipsec-ikev2','ipsec-esp-udp','esp'):
        result=privileged({'op':'ipsec-stats','id':item['id'],'local':meta.get('outer_local'),'peer':meta.get('outer_peer')})
    else:
        interface=meta.get('tun_name') or meta.get('interface')
        if not isinstance(interface,str) or not interface:return None
        result=privileged({'op':'interface-stats','id':item['id'],'interface':interface})
    if result.get('error') or result.get('available') is False:return None
    try:return {'rx_bytes':max(0,int(result['rx_bytes'])),'tx_bytes':max(0,int(result['tx_bytes']))}
    except (KeyError,TypeError,ValueError):return None

def update_tunnel_traffic(local_items,remote_statuses):
    endpoints={}
    for item in local_items:
        raw=item.get('traffic_raw')
        if raw:endpoints.setdefault(item['id'],{})['local']=raw
    for status in remote_statuses:
        if status.get('reachable') is not True:continue
        for item in status.get('tunnels',[]):
            raw=item.get('traffic_raw')
            if isinstance(raw,dict) and not raw.get('error') and raw.get('available') is not False:
                try:endpoints.setdefault(item['id'],{})[status['id']]={'rx_bytes':max(0,int(raw['rx_bytes'])),'tx_bytes':max(0,int(raw['tx_bytes']))}
                except (KeyError,TypeError,ValueError):pass
    for ident,sources in endpoints.items():
        previous=traffic_totals('tunnel',ident)
        owner=previous.get('server_id') if previous else ('local' if 'local' in sources else sorted(sources)[0])
        raw=sources.get(owner)
        if raw:record_traffic('tunnel',ident,owner,raw['rx_bytes'],raw['tx_bytes'])

def update_forward_traffic(server_id,raw_forwards):
    if not isinstance(raw_forwards,dict):return
    for ident,raw in raw_forwards.items():
        if not ID.fullmatch(str(ident)) or not isinstance(raw,dict):continue
        try:record_traffic('forward:'+server_id,str(ident),server_id,raw['bytes_in'],raw['bytes_out'])
        except (KeyError,TypeError,ValueError):continue

def attach_forward_traffic(items):
    return [dict(item,traffic=traffic_totals('forward:'+str(item.get('server_id') or 'local'),item['id'])) for item in items]

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
    meta=item.get("metadata",{});ipx=meta.get('carrier')=='tun' and meta.get('encapsulation')=='ipx';peer=meta.get("tun_remote");iface=meta.get("tun_name")
    if meta.get('transport')=='erspan':return erspan_health(item)
    if ipx:return {"state":"monitor-only","reachable":None,"checked_at":int(time.time()),"probe_error":"waiting for the peer interface address probe"}
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

def ip_json(*args,attempts=3,timeout=8):
    ipbin=shutil.which('ip') or '/usr/sbin/ip'
    command=[ipbin,'-json',*args]
    for attempt in range(attempts):
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=timeout)
            if result.returncode==0:
                try:return json.loads(result.stdout or '[]')
                except ValueError as error:raise RuntimeError(f"ip {' '.join(args)} returned invalid JSON: {error}") from error
            detail=result.stderr.strip() or result.stdout.strip() or 'no diagnostic output'
            failure=f"ip {' '.join(args)} failed with exit status {result.returncode}: {detail}"
        except (OSError,subprocess.TimeoutExpired) as error:
            failure=f"ip {' '.join(args)} could not run: {error}"
        if attempt+1<attempts:time.sleep(.2)
    raise RuntimeError(failure)

def network_snapshot():
    addresses=ip_json('address','show')
    routes=ip_json('route','show','table','all')
    interfaces=set();networks=set()
    for link in addresses:
        name=link.get('ifname')
        if name:interfaces.add(name)
        for address in link.get('addr_info',[]):
            if address.get('family')!='inet' or not address.get('local'):continue
            try:networks.add(str(ipaddress.ip_network(f"{address['local']}/{int(address['prefixlen'])}",strict=False)))
            except (KeyError,TypeError,ValueError):continue
    for route in routes:
        destination=route.get('dst')
        if not destination or destination=='default':continue
        try:
            net=ipaddress.ip_network(destination,strict=False)
            if net.version==4 and net.prefixlen>0:networks.add(str(net))
        except ValueError:continue
    tcp_ports=set();tcp_inventory_ok=True
    for filename in ('/proc/net/tcp','/proc/net/tcp6'):
        try:
            for line in pathlib.Path(filename).read_text().splitlines()[1:]:
                columns=line.split()
                if len(columns)>3 and columns[3]=='0A':tcp_ports.add(int(columns[1].rsplit(':',1)[1],16))
        except OSError:tcp_inventory_ok=False
    udp_ports=set();udp_inventory_ok=True
    for filename in ('/proc/net/udp','/proc/net/udp6'):
        path=pathlib.Path(filename)
        if filename.endswith('/udp6') and not path.exists():continue
        try:
            for line in path.read_text().splitlines()[1:]:
                columns=line.split()
                if len(columns)>1 and ':' in columns[1]:udp_ports.add(int(columns[1].rsplit(':',1)[1],16))
        except OSError:udp_inventory_ok=False
    ephemeral_low,ephemeral_high=32768,60999
    try:
        ephemeral_low,ephemeral_high=map(int,pathlib.Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
    except (OSError,ValueError):udp_inventory_ok=False
    return {'interfaces':sorted(interfaces),'networks':sorted(networks),'udp_ports':sorted(udp_ports),'tcp_ports':sorted(tcp_ports),'tcp_inventory_ok':tcp_inventory_ok,
            'udp_ephemeral_range':[ephemeral_low,ephemeral_high],'udp_inventory_ok':udp_inventory_ok}

def interface_ip_addresses(interface):
    if not isinstance(interface,str) or not 1<=len(interface)<=15 or interface.startswith('-') or any(not (ch.isalnum() or ch in '_.-') for ch in interface):return []
    ipbin=shutil.which('ip') or '/usr/sbin/ip'
    try:
        result=subprocess.run([ipbin,'-json','address','show','dev',interface],capture_output=True,text=True,check=True,timeout=5)
        links=json.loads(result.stdout or '[]')
    except (OSError,subprocess.SubprocessError,ValueError):return []
    found=[]
    for link in links:
        for address in link.get('addr_info',[]):
            local=address.get('local')
            try:parsed=ipaddress.ip_address(local)
            except (TypeError,ValueError):continue
            if parsed.is_loopback or parsed.is_link_local:continue
            found.append({'local':str(parsed),'family':address.get('family'),'prefixlen':address.get('prefixlen'),'scope':address.get('scope')})
    return sorted(found,key=lambda item:(item.get('scope')!='global',item.get('family')!='inet',item['local']))

def tunnel_interface(item):
    """Get the managed link device, including legacy tun_name metadata."""
    meta=item.get('metadata') or {}
    # These transports install their inner address on loopback and have no
    # dedicated Linux link device to inspect or bind the probe to.
    if meta.get('transport') in ('ipsec-ikev2','ipsec-esp-udp','esp'):return None
    # Backhaul's `interface` option is an outer/IPX carrier setting; for its
    # virtual IP link the device is explicitly named by tun_name.
    if meta.get('manager')=='Backhaul':return meta.get('tun_name') if meta.get('carrier')=='tun' else None
    name=meta.get('interface') or meta.get('tun_name')
    return name if isinstance(name,str) and name else None

def _interface_ip(item):
    meta=item.get('metadata') or {}
    if meta.get('transport') in ('ipsec-ikev2','ipsec-esp-udp','esp'):
        try:return str(ipaddress.ip_interface(meta.get('tun_local','')).ip)
        except (TypeError,ValueError):return None
    name=tunnel_interface(item)
    if not name:return None
    addresses=item.get('interface_addresses')
    if addresses is None:addresses=item.get('tun_addresses')
    if addresses is None:addresses=interface_ip_addresses(name)
    for address in addresses:
        try:parsed=ipaddress.ip_address(address.get('local',''))
        except (AttributeError,TypeError,ValueError):continue
        if parsed.version==4:return str(parsed)
    return None

def iperf3_server_start(address,port):
    address=str(ipaddress.ip_address(address));port=int(port)
    if not 1024<=port<=65535:raise ValueError('iperf3 test port is outside the allowed range')
    binary=shutil.which('iperf3')
    if not binary:raise RuntimeError('iperf3 is not installed on this tunnel endpoint; update the server installer first')
    child=subprocess.Popen([binary,'-s','-1','-B',address,'-p',str(port)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
    time.sleep(.5)
    if child.poll() is not None:raise RuntimeError('iperf3 could not start its temporary listener')
    return child.pid

def iperf3_server_stop(pid):
    try:os.kill(int(pid),signal.SIGTERM)
    except ProcessLookupError:pass

def iperf3_client(address,port,reverse=False,source=None):
    address=str(ipaddress.ip_address(address));port=int(port)
    binary=shutil.which('iperf3')
    if not binary:raise RuntimeError('iperf3 is not installed on this tunnel endpoint; update the server installer first')
    args=[binary,'-c',address,'-p',str(port),'-t','3','--connect-timeout','3000','-J']
    if reverse:args.append('-R')
    if source:args.extend(['-B',str(ipaddress.ip_address(source))])
    result=subprocess.run(args,capture_output=True,text=True,timeout=12)
    if result.returncode:raise RuntimeError((result.stderr or result.stdout or 'iperf3 client failed').strip()[-500:])
    try:report=json.loads(result.stdout);end=report['end'];received=end.get('sum_received') or end.get('sum') or {}
    except (ValueError,KeyError,TypeError) as error:raise RuntimeError('iperf3 returned an unreadable throughput result') from error
    bps=float(received.get('bits_per_second',0))
    if bps<=0:raise RuntimeError('iperf3 completed without reporting received throughput')
    return round(bps/1_000_000,2)

def remote_iperf3(server,payload):
    code='''import json,ipaddress,os,shutil,signal,subprocess,sys,time\nd=json.load(sys.stdin);op=d.get("op");out={}\nif op=="start":\n addr=str(ipaddress.ip_address(d["address"]));port=int(d["port"]);binary=shutil.which("iperf3")\n if not binary:raise RuntimeError("iperf3 is not installed on this tunnel endpoint; update the server installer first")\n if not 1024<=port<=65535:raise ValueError("iperf3 test port is outside the allowed range")\n child=subprocess.Popen([binary,"-s","-1","-B",addr,"-p",str(port)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True);time.sleep(.5)\n if child.poll() is not None:raise RuntimeError("iperf3 could not start its temporary listener")\n out={"pid":child.pid}\nelif op=="stop":\n try:os.kill(int(d["pid"]),signal.SIGTERM)\n except ProcessLookupError:pass\n out={"ok":True}\nelif op=="client":\n addr=str(ipaddress.ip_address(d["address"]));port=int(d["port"]);binary=shutil.which("iperf3")\n if not binary:raise RuntimeError("iperf3 is not installed on this tunnel endpoint; update the server installer first")\n args=[binary,"-c",addr,"-p",str(port),"-t","3","--connect-timeout","3000","-J"]\n if d.get("reverse"):args.append("-R")\n if d.get("source"):args.extend(["-B",str(ipaddress.ip_address(d["source"]))])\n result=subprocess.run(args,capture_output=True,text=True,timeout=12)\n if result.returncode:raise RuntimeError((result.stderr or result.stdout or "iperf3 client failed").strip()[-500:])\n report=json.loads(result.stdout);end=report["end"];received=end.get("sum_received") or end.get("sum") or {};bps=float(received.get("bits_per_second",0))\n if bps<=0:raise RuntimeError("iperf3 completed without reporting received throughput")\n out={"mbps":round(bps/1000000,2)}\nelse:raise ValueError("unsupported iperf3 operation")\nprint(json.dumps(out))'''
    remote='runuser -u tunnelmgr -- /usr/bin/python3 -c '+shlex.quote(code)
    result=subprocess.run(ssh_argv(server)+[remote],input=json.dumps(payload),capture_output=True,text=True,timeout=25)
    if result.returncode:raise RuntimeError((result.stderr or result.stdout or 'remote iperf3 command failed')[-800:])
    try:data=json.loads(result.stdout)
    except ValueError as error:raise RuntimeError('remote iperf3 endpoint returned invalid data') from error
    if data.get('error'):raise RuntimeError(data['error'])
    return data

def tunnel_iperf_operation(server_id,servers,operation,**values):
    payload={'op':operation,**values}
    if server_id=='local':
        if operation=='start':return {'pid':iperf3_server_start(payload['address'],payload['port'])}
        if operation=='stop':iperf3_server_stop(payload['pid']);return {'ok':True}
        if operation=='client':return {'mbps':iperf3_client(payload['address'],payload['port'],payload.get('reverse',False),payload.get('source'))}
        raise ValueError('unsupported local iperf3 operation')
    return remote_iperf3(servers[server_id],payload)

def tunnel_speedtest(data):
    ident=data.get('id');a_id=data.get('server_a');b_id=data.get('server_b');checked=int(time.time())
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError('invalid tunnel id for speed test')
    if not isinstance(a_id,str) or not isinstance(b_id,str) or a_id==b_id:raise ValueError('speed test requires two different tunnel endpoints')
    servers={item['id']:item for item in server_rows()}
    for sid in (a_id,b_id):
        if sid!='local' and sid not in servers:raise ValueError('speed test endpoint is not managed')
    seen={};port=secrets.randbelow(18000)+44000
    def supports_speedtest(item):
        meta=item.get('metadata') or {}
        if meta.get('manager')=='Backhaul':return meta.get('carrier')=='tun'
        if meta.get('transport') in ('erspan','gretap','geneve','vxlan'):return False
        return bool(meta.get('tun_local'))
    def endpoint(sid):
        if sid in seen:return seen[sid]
        last=None
        for attempt in range(6):
            try:
                if sid=='local':item=find(ident)
                else:item=next((row for row in server_remote(servers[sid],{'op':'list'}).get('items',[]) if row.get('id')==ident),None)
                if not item:raise ValueError('tunnel is not registered on '+sid)
                if not supports_speedtest(item):seen[sid]=(item,None);return seen[sid]
                if sid=='local':
                    interface=tunnel_interface(item);item['interface_addresses']=interface_ip_addresses(interface) if interface else []
                address=_interface_ip(item)
                if address:seen[sid]=(item,address);return seen[sid]
                last=RuntimeError('could not read the internal IP from tunnel interface '+str(tunnel_interface(item)))
            except Exception as error:last=error
            if attempt<5:time.sleep(.8)
        raise RuntimeError(str(last or 'internal tunnel IP is unavailable'))
    running=[]
    def peer_reachable(sid,item,source_ip,peer_ip):
        meta=item.get('metadata') or {}
        transport=meta.get('transport')
        payload={'op':'probe','id':ident,'peer':peer_ip,'interface':tunnel_interface(item)}
        if transport in ('ipsec-ikev2','ipsec-esp-udp','esp'):
            payload.update(interface=None,local=source_ip)
        result=privileged(payload) if sid=='local' else server_remote(servers[sid],payload)
        return result.get('state')=='up'
    try:
        a_item,a_ip=endpoint(a_id);b_item,b_ip=endpoint(b_id)
        if not supports_speedtest(a_item) or not supports_speedtest(b_item):
            result={'state':'unsupported','a_server':a_id,'b_server':b_id,'a_local_ip':a_ip,'b_local_ip':b_ip,'checked_at':checked}
            save_tunnel_speedtest(ident,result)
            return result
        ready=False
        for attempt in range(8):
            if peer_reachable(a_id,a_item,a_ip,b_ip) and peer_reachable(b_id,b_item,b_ip,a_ip):
                ready=True
                break
            if attempt<7:time.sleep(1)
        if not ready:
            raise RuntimeError('Tunnel peers are not responding yet; wait a few seconds and retry the speed test.')
        def measure(source_id,dest_id,source_ip,dest_ip,reverse):
            chosen_port=port+int(reverse)
            last_error=None
            for attempt in range(3):
                pid=None
                try:
                    server=tunnel_iperf_operation(dest_id,servers,'start',address=dest_ip,port=chosen_port)
                    pid=server['pid'];running.append((dest_id,pid))
                    time.sleep(.25)
                    return float(tunnel_iperf_operation(source_id,servers,'client',address=dest_ip,port=chosen_port,reverse=reverse,source=source_ip)['mbps'])
                except RuntimeError as error:
                    last_error=error
                    text=str(error).lower()
                    retryable=any(token in text for token in ('without reporting received throughput','could not start its temporary listener','connection refused','unable to connect','connection timed out'))
                    if not retryable or attempt==2:raise
                finally:
                    if pid is not None:
                        try:
                            tunnel_iperf_operation(dest_id,servers,'stop',pid=pid)
                            running.remove((dest_id,pid))
                        except Exception:pass
                time.sleep(1.5*(attempt+1))
            raise RuntimeError(str(last_error or 'iperf3 could not measure tunnel throughput'))
        a_to_b=measure(a_id,b_id,a_ip,b_ip,False)
        b_to_a=measure(a_id,b_id,a_ip,b_ip,True)
        result={'state':'complete','a_server':a_id,'b_server':b_id,'a_local_ip':a_ip,'b_local_ip':b_ip,
                'a_to_b_mbps':a_to_b,'b_to_a_mbps':b_to_a,'checked_at':checked,'duration_seconds':8}
    except Exception as error:
        result={'state':'error','a_server':a_id,'b_server':b_id,'a_local_ip':seen.get(a_id,(None,None))[1],
                'b_local_ip':seen.get(b_id,(None,None))[1],'checked_at':checked,'error':str(error)[-500:]}
    finally:
        for sid,pid in reversed(running):
            try:tunnel_iperf_operation(sid,servers,'stop',pid=pid)
            except Exception:pass
    save_tunnel_speedtest(ident,result)
    return result

def probe_tunnel_links(local_items,remote_statuses,servers):
    endpoints=[]
    for item in local_items:
        interface=tunnel_interface(item)
        meta=item.get('metadata') or {};ipsec=meta.get('transport') in ('ipsec-ikev2','ipsec-esp-udp','esp')
        if interface or ipsec:
            item['interface_addresses']=interface_ip_addresses(interface) if interface else [];item['tun_addresses']=item['interface_addresses'];item['server_id']='local';endpoints.append(item)
    for status in remote_statuses:
        for item in status.get('tunnels',[]):
            meta=item.get('metadata') or {}
            if tunnel_interface(item) or meta.get('transport') in ('ipsec-ikev2','ipsec-esp-udp','esp'):endpoints.append(item)
    groups={}
    for item in endpoints:groups.setdefault(item.get('id'),[]).append(item)
    jobs=[]
    for ident,items in groups.items():
        pair=[]
        for item in items:
            sid=str(item.get('server_id') or 'local')
            if all(str(existing.get('server_id') or 'local')!=sid for existing in pair):pair.append(item)
        if len(pair)!=2:continue
        ips=[_interface_ip(item) for item in pair]
        for index,item in enumerate(pair):
            sid=str(item.get('server_id') or 'local');interface=tunnel_interface(item);own,peer=ips[index],ips[1-index]
            meta=item.get('metadata') or {};ipsec=meta.get('transport') in ('ipsec-ikev2','ipsec-esp-udp','esp')
            base={'tun_local_ip':own,'tun_peer_ip':peer,'interface_local_ip':own,'interface_peer_ip':peer,'probe_interface':interface or ('lo' if ipsec else None)}
            if not own or not peer:
                reason='could not read both configured IPsec inner addresses' if ipsec else f'could not read both peer IPs from interface {interface}'
                item['health']={'state':'monitor-only','reachable':None,'checked_at':int(time.time()),'probe_error':reason,**base};continue
            payload={'op':'probe','id':ident,'peer':peer,'interface':interface,'local':own if ipsec else None}
            jobs.append((item,sid,payload,base))
    def run_probe(job):
        item,sid,payload,base=job
        try:
            result=privileged(payload) if sid=='local' else server_remote(servers[sid],payload)
            return item,{**result,**base}
        except Exception as error:
            return item,{'state':'error','reachable':False,'checked_at':int(time.time()),'probe_error':str(error)[-500:],**base}
    with ThreadPoolExecutor(max_workers=min(8,max(1,len(jobs)))) as pool:
        for item,health in pool.map(run_probe,jobs):item['health']=health

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
    return {"mtu":min(1400,effective),"path_mtu_a":local_probe["mtu"],"path_mtu_b":peer_probe["mtu"],"overhead":overhead[transport],"method_a":local_probe.get("method"),"method_b":peer_probe.get("method")}

def ssh_argv(server):
    try:ipaddress.ip_address(server["host"].strip("[]"));host=f'[{server["host"].strip("[]")}]' if ":" in server["host"] else server["host"]
    except ValueError:host=server["host"]
    cmd=["ssh","-T","-o","StrictHostKeyChecking=accept-new","-o",f"UserKnownHostsFile={BASE/'known_hosts'}","-o","ConnectTimeout=12","-o","BatchMode=yes"]
    if server.get("identity"):cmd += ["-i",server["identity"],"-o","IdentitiesOnly=yes"]
    proxy_id=server.get("proxy_server_id")
    line_id=server.get("proxy_line_id") or ''
    if proxy_id and line_id:raise ValueError('choose either an SSH jump server or an Xray proxy line, not both')
    if line_id:
        line=proxy_line(line_id)
        helper=pathlib.Path(__file__).with_name('socks5_connect.py')
        proxy=[sys.executable,str(helper),str(line['socks_port']),'%h','%p']
        cmd += ['-o','ProxyCommand='+shlex.join(proxy)]
    if proxy_id:
        proxy=next((s for s in server_rows() if s["id"]==proxy_id),None)
        if not proxy:raise ValueError(f"SSH proxy server {proxy_id} is missing")
        if proxy.get("proxy_server_id") or proxy.get('proxy_line_id'):raise ValueError("SSH proxy chains are limited to one hop")
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

def geoip_location(host=None):
    """Return a map location from the public address GeoIP currently sees."""
    host=str(host or "").strip().strip("[]")
    if host:
        try:addresses=[ipaddress.ip_address(host)]
        except ValueError:
            try:addresses=list(dict.fromkeys(ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)))
            except Exception as e:raise ValueError("نام میزبان به IP تبدیل نشد؛ آدرس را بررسی کن") from e
        address=next((item for item in addresses if item.is_global),None)
        if address is None:raise ValueError("GeoIP فقط برای IP عمومی قابل استفاده است")
        key=str(address)
    else:key="@panel-egress"
    cached=GEOIP_CACHE.get(key)
    if cached and cached["expires"]>time.time():return dict(cached["result"])
    providers=(f"https://ipwho.is/{key}" if host else "https://ipwho.is/",f"https://ipapi.co/{key}/json/" if host else "https://ipapi.co/json/")
    failures=[];data={}
    for url in providers:
        request=urllib.request.Request(url,headers={"User-Agent":"avaTUN/0.1 GeoIP"})
        try:
            with urllib.request.urlopen(request,timeout=5,context=ssl.create_default_context()) as response:data=json.loads(response.read(32768).decode("utf-8"))
            code=str(data.get("country_code") or "").upper()
            latitude=float(data.get("latitude"));longitude=float(data.get("longitude"))
            if data.get("success",True) and re.fullmatch(r"[A-Z]{2}",code) and -90<=latitude<=90 and -180<=longitude<=180:break
            failures.append(str(data.get("message") or "پاسخ نامعتبر GeoIP"))
        except Exception as e:failures.append(str(e))
    else:raise RuntimeError("سرویس‌های GeoIP کشور این IP را مشخص نکردند: "+" | ".join(failures))
    result={"location":"iran" if code=="IR" else "abroad","country_code":code,"country_name":str(data.get("country_name") or data.get("country") or code),"city":str(data.get("city") or ""),"latitude":latitude,"longitude":longitude,"ip":str(data.get("ip") or key)}
    GEOIP_CACHE[key]={"expires":time.time()+3600,"result":result}
    return dict(result)

def refresh_server_locations():
    for item in server_rows():
        if not item["auto_geoip"] or (item["geoip_host"] == item["host"] and item.get("geo_latitude") is not None and item.get("geo_longitude") is not None):
            continue
        try:
            result = geoip_location(item["host"])
            with db() as connection:
                connection.execute(
                    "UPDATE servers SET location=?,geoip_host=?,geo_country_code=?,geo_country_name=?,geo_city=?,geo_latitude=?,geo_longitude=? WHERE id=? AND host=? AND auto_geoip=1",
                    (result["location"], item["host"], result["country_code"], result["country_name"], result["city"], result["latitude"], result["longitude"], item["id"], item["host"]),
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
        return {"id":server["id"],"host":server["host"],"reachable":True,"services":result.get("services",[]),"tunnels":result.get("items",[]),"resources":result.get("resources"),"forward_counters":result.get("forward_counters",{}),"app_version":result.get("app_version","نامشخص")}
    except Exception as e:return {"id":server["id"],"host":server["host"],"reachable":False,"error":str(e)[-500:],"tunnels":[]}

def monitor_loop():
    global MONITOR_TUNNELS,MONITOR_SERVERS
    while True:
        try:
            current=rows()
            for item in current:
                try:item['traffic_raw']=tunnel_counter(item)
                except Exception:item['traffic_raw']=None
            with ThreadPoolExecutor(max_workers=min(8,max(1,len(current)))) as pool:probes=list(pool.map(tunnel_health,current))
            for item,probe in zip(current,probes):item['health']=probe
            servers=server_rows()
            with ThreadPoolExecutor(max_workers=min(8,max(1,len(servers)))) as pool:remote=list(pool.map(server_probe,servers))
            probe_tunnel_links(current,remote,{server['id']:server for server in servers})
            update_tunnel_traffic(current,remote)
            local_forwards=privileged({'op':'haproxy','id':'forwards','action':'status'})
            update_forward_traffic('local',local_forwards.get('forwards',{}))
            for status in remote:update_forward_traffic(status['id'],status.get('forward_counters',{}))
            for status in remote:
                for item in status.get('tunnels',[]):
                    item.pop('traffic_raw',None);item['traffic']=traffic_totals('tunnel',item['id'])
            local={item["id"]:item.get('health',{}) for item in current}
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
            report_settings=resource_report_settings()
            report_metrics=resource_report_metrics()
            servers=server_rows()
            with ThreadPoolExecutor(max_workers=min(8,max(1,len(servers)))) as pool:
                probes=list(pool.map(lambda server:(server,server_remote(server,{'op':'resources'})),servers))
            current=[{'id':'local','name':'سرور مرکزی','host':'سرور پنل','reachable':True,'telegram_resources_enabled':report_settings.get('local',True),'telegram_resource_metrics':report_metrics.get('local',list(RESOURCE_REPORT_METRICS)),'resources':resource_snapshot()}]
            current.extend({'id':server['id'],'name':server['id'],'host':server['host'],'reachable':True,'telegram_resources_enabled':report_settings.get(server['id'],True),'telegram_resource_metrics':report_metrics.get(server['id'],list(RESOURCE_REPORT_METRICS)),'resources':result} for server,result in probes)
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
    code="import sys,json,subprocess,os,pathlib,shutil,time,ipaddress;sys.path.insert(0,'/opt/tunnelmgr/tunnelmgr');import tunnelctl as t;d=json.load(sys.stdin);op=d.get('op');out=None\nif op=='list':\n out=[]\n for x in t.rows():\n  try:\n   m=x['metadata'];native=m.get('native_profile');r=t.privileged({'op':'profile','group':'network','id':native,'action':'status'} if native else {'op':'status','id':x['id']});x['live']={'active':'ActiveState=active' in r.get('output','')} if native else r.get('status',{});ipsec=m.get('transport') in ('ipsec-ikev2','ipsec-esp-udp','esp');interface=m.get('tun_name') if m.get('manager')=='Backhaul' else (None if ipsec else (m.get('interface') or m.get('tun_name')));x['interface_addresses']=t.interface_ip_addresses(interface) if interface else [];x['tun_addresses']=x['interface_addresses'];x['health']={'state':'monitor-only','reachable':None,'checked_at':int(time.time()),'probe_error':'waiting for central TUN peer probe'} if m.get('carrier')=='tun' and m.get('encapsulation')=='ipx' else t.tunnel_health(x)\n  except Exception as e:x['live']={'active':False};x['health']={'state':'error','error':str(e)}\n  x['server_id']="+repr(server['id'])+";out.append(x)\n services=[subprocess.run(['/usr/bin/systemctl','is-active',u],capture_output=True,text=True).stdout.strip() for u in ('tunnelmgr.service','tunnelmgr-privd.service')];out={'items':out,'services':services}\nelif op=='probe':\n out=t.privileged({'op':'probe','id':d['id'],'peer':d['peer'],'interface':d.get('interface'),'local':d.get('local')})\nelif op=='resources':\n out=t.resource_snapshot()\nelif op=='network-info':\n out=t.network_snapshot()\nelif op=='allocation-snapshot':\n out={'items':t.rows(),'network':t.network_snapshot()}\n if d.get('include_network_profiles'):\n  out['network_profiles']=[]\n  listed=t.privileged({'op':'profile','group':'network','id':'inventory','action':'list'})\n  if listed.get('error') or not isinstance(listed.get('items'),list):raise RuntimeError('Could not safely inspect saved network profiles.')\n  for profile_id in listed.get('items',[]):\n   result=t.privileged({'op':'profile','group':'network','id':profile_id,'action':'read'})\n   if result.get('error'):raise RuntimeError('Could not safely inspect saved network profiles.')\n   config=result.get('config')\n   if not config:raise RuntimeError('A network profile changed during allocation; retry after it finishes.')\n   out['network_profiles'].append({'profile_id':profile_id,**{key:config[key] for key in ('kind','interface','vni','port','inner_local','inner_peer') if key in config}})\n if d.get('include_l2tp'):\n  out['l2tp_profiles']=[]\n  for item in out['items']:\n   meta=item.get('metadata') or {};profile=meta.get('native_profile')\n   if meta.get('transport')!='l2tpv3' or not profile:continue\n   result=t.privileged({'op':'profile','group':'network','id':profile,'action':'read'})\n   if not result.get('config'):raise RuntimeError(result.get('error','could not read managed L2TPv3 profile'))\n   out['l2tp_profiles'].append(result['config'])\nelif op=='native-config':\n x=t.find(d['id']);n=x['metadata'].get('native_profile') if x else None\n out=t.privileged({'op':'profile','group':'network','id':n,'action':'read'}) if n else {'error':'native tunnel is missing'}\nelif op=='interface-stats':\n out=t.privileged({'op':'interface-stats','id':d['id'],'interface':d['interface']})\nelif op=='mtu-probe':\n out=t.path_mtu_probe(d['host'])\nelif op=='create':\n out=t.create_instance(d['data']) if d['data'].get('transport')=='backhaul' else t.create_native(d['data'])\nelif op=='config':\n out=t.tunnel_config(d['id'])\nelif op=='validate':\n out=t.validate_tunnel_config(d['data'])\nelif op=='update':\n out=t.update_tunnel(d['data'])\nelif op=='forward-apply':\n out=t.privileged({'op':'haproxy','id':'forwards','action':'apply','rules':d['rules']})\nelif op=='xray-config':\n out=t.privileged({'op':'xray-config','id':'xray','action':d.get('action','apply'),'config':d.get('config')})\nelif op=='forward-status':\n out=t.privileged({'op':'haproxy','id':'forwards','action':'status'})\nelif op=='secret':\n out=t.privileged({'op':'secret','id':d['id'],'action':d['action'],'kind':d.get('kind','token'),'value':d.get('value')})\nelif op=='routing-profile-create':\n name=d['profile'];cfg=d['config'];out=t.privileged({'op':'profile','group':'network','id':name,'action':'create','config':cfg})\n if out.get('ok'):\n  out=t.privileged({'op':'profile','group':'network','id':name,'action':'start'})\n  if not out.get('ok'):t.privileged({'op':'profile','group':'network','id':name,'action':'delete'})\nelif op=='routing-profile-delete':\n p=t.privileged({'op':'profile','group':'network','id':d['profile'],'action':'read'});out=t.privileged({'op':'profile','group':'network','id':d['profile'],'action':'delete'}) if p.get('config') else {'ok':True,'already_removed':True}\nelif op=='routing-status':\n import routing as r\n p=t.privileged({'op':'profile','group':'network','id':d['profile'],'action':'read'});out=r.status(p['config']) if p.get('config') else {'state':'error','error':p.get('error','profile missing')}\nelif op=='operate':\n x=t.find(d['id'])\n if not x:raise ValueError('unknown tunnel')\n if d['action']=='delete':\n  out=t.remove_tunnel_endpoint(d['id'],delete_secret=True)\n else:\n  n=x['metadata'].get('native_profile');out=t.privileged({'op':'profile','group':'network','id':n,'action':d['action']} if n else {'op':d['action'],'id':d['id']})\nprint(json.dumps(out,ensure_ascii=False))"
    needle="  x['server_id']="+repr(server['id'])+";out.append(x)"
    replacement="  try:x['traffic_raw']=t.tunnel_counter(x)\n  except Exception:x['traffic_raw']=None\n  x['server_id']="+repr(server['id'])+";out.append(x)"
    code=code.replace(needle,replacement,1)
    code=code.replace("out={'items':out,'services':services}","out={'items':out,'services':services,'forward_counters':t.privileged({'op':'haproxy','id':'forwards','action':'status'}).get('forwards',{}),'app_version':getattr(t,'APP_VERSION','نامشخص')}",1)
    guarded_code="import json\ntry:\n exec(compile("+repr(code)+", '<tunnelmgr-remote>', 'exec'))\nexcept Exception as exc:\n print(json.dumps({'error':str(exc)},ensure_ascii=False))"
    remote="runuser -u tunnelmgr -- env TUNNELMGR_HOME=/var/lib/tunnelmgr /usr/bin/python3 -c "+shlex.quote(guarded_code)
    proc=subprocess.run(ssh_argv(server)+[remote],input=json.dumps(payload),capture_output=True,text=True,timeout=180)
    if proc.returncode:raise RuntimeError((proc.stderr or proc.stdout)[-1600:])
    try:result=json.loads(proc.stdout)
    except json.JSONDecodeError as e:raise RuntimeError("invalid response from remote tunnel manager") from e
    if isinstance(result,dict) and result.get("error"):raise RuntimeError(result["error"])
    return result

SLAVE_SYNC_PACKAGES=("ca-certificates","curl","python3","iproute2","haproxy","wireguard-tools","openvpn","ocserv","openconnect","iperf3","strongswan-swanctl","charon-systemd","libstrongswan-extra-plugins","libcharon-extra-plugins","frr","openssl","certbot","kmod","qrencode","gh","python3-cryptography","python3-snappy")

def slave_package_lock():
    lock={}
    for package in SLAVE_SYNC_PACKAGES:
        result=subprocess.run(['/usr/bin/dpkg-query','-W','-f=${db:Status-Abbrev}\\t${Version}',package],capture_output=True,text=True,timeout=10)
        fields=result.stdout.strip().split('\t',1)
        if result.returncode==0 and len(fields)==2 and fields[0].startswith('ii') and fields[1]:lock[package]=fields[1]
    if not lock:raise RuntimeError('Could not read installed Debian package versions on the central server')
    release=platform.freedesktop_os_release()
    return {'central_os':{key:release.get(key,'') for key in ('ID','VERSION_ID','VERSION_CODENAME','UBUNTU_CODENAME')},'packages':lock}

def install_remote(server):
    root=pathlib.Path(__file__).resolve().parents[1]
    remote_scripts=("install-preview.sh","install-xray-core.py","mesh-deploy.py","mesh-worker.py","github-update.py","sync-dependencies.py","tunnelmgr")
    missing=[name for name in remote_scripts if not (root/"scripts"/name).is_file()]
    if missing:raise RuntimeError("Central panel is missing remote installer files: "+", ".join(missing)+". Update the central panel, then retry.")
    stats=privileged({'op':'haproxy-stats','id':'forwards','action':'read'})
    if not stats.get('ok'):raise RuntimeError(stats.get('error','Could not read HAProxy statistics configuration'))
    with tempfile.NamedTemporaryFile(suffix=".tgz") as bundle:
        with tarfile.open(bundle.name,"w:gz") as tf:
            import io
            content=json.dumps(stats['config']).encode()
            member=tarfile.TarInfo('runtime/haproxy-stats.json');member.size=len(content);member.mode=0o600
            tf.addfile(member,io.BytesIO(content))
            package_lock=json.dumps(slave_package_lock(),sort_keys=True).encode()
            member=tarfile.TarInfo('runtime/slave-package-lock.json');member.size=len(package_lock);member.mode=0o600
            tf.addfile(member,io.BytesIO(package_lock))
            for folder in ("tunnelmgr","web","packaging/systemd","vendor/backhaul"):
                for p in (root/folder).rglob("*"):
                    if p.is_file():tf.add(p,arcname=str(p.relative_to(root)))
            for name in remote_scripts:
                p=root/"scripts"/name
                tf.add(p,arcname=f"scripts/{name}")
            xray=pathlib.Path('/opt/tunnelmgr/bin/xray')
            arch={'x86_64':'linux-amd64','aarch64':'linux-arm64'}.get(platform.machine().lower())
            if arch and xray.is_file():tf.add(xray,arcname=f'runtime/xray-core-{arch}')
        payload=pathlib.Path(bundle.name).read_bytes()
    remote="mkdir -p /tmp/tunnelmgr-bootstrap && tar -xzf - -C /tmp/tunnelmgr-bootstrap && sh /tmp/tunnelmgr-bootstrap/scripts/install-preview.sh"
    p=subprocess.run(ssh_argv(server)+[remote],input=payload,capture_output=True,timeout=600)
    if p.returncode:raise RuntimeError((p.stderr or p.stdout).decode(errors="replace")[-5000:])
    return {"ok":True,"app_version":APP_VERSION,"output":p.stdout.decode(errors="replace")[-5000:]}
def save(ident,mode,metadata):
    with db() as c:c.execute("INSERT INTO tunnels(id,kind,mode,metadata) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET mode=excluded.mode,metadata=excluded.metadata",(ident,"backhaul",mode,json.dumps(metadata)))

def forward_rows():
    with db() as c:return [json.loads(r["config"]) for r in c.execute("SELECT config FROM port_forwards ORDER BY id")]

def proxy_line_path(ident):
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError('invalid proxy line ID')
    return BASE/'proxy-lines'/(ident+'.json')

def proxy_lines():
    with db() as c:rows=[json.loads(r['metadata']) for r in c.execute('SELECT metadata FROM proxy_lines ORDER BY id')]
    result=[]
    for meta in rows:
        path=proxy_line_path(meta['id'])
        try:secret=json.loads(path.read_text())
        except Exception as error:raise RuntimeError(f"proxy line {meta['id']} configuration is unreadable") from error
        result.append({**meta,'outbound':secret['outbound']})
    return result

def proxy_line(ident):
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError('invalid proxy line ID')
    with db() as c:row=c.execute('SELECT metadata FROM proxy_lines WHERE id=?',(ident,)).fetchone()
    if not row:raise ValueError('proxy line not found')
    metadata=json.loads(row['metadata'])
    try:secret=json.loads(proxy_line_path(ident).read_text())
    except Exception as error:raise RuntimeError('proxy line private config is missing or unreadable') from error
    return {**metadata,'outbound':secret['outbound']}

def proxy_line_summaries():
    return [{key:line.get(key) for key in ('id','label','protocol','address','port','created_at','socks_port')} for line in proxy_lines()]

def proxy_forward_rows():
    with db() as c:return [json.loads(r['config']) for r in c.execute('SELECT config FROM proxy_forwards ORDER BY id')]

def _write_proxy_line(line):
    directory=BASE/'proxy-lines';directory.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(directory,0o700)
    path=proxy_line_path(line['id']);fd,tmp=tempfile.mkstemp(prefix='.line-',dir=directory)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as stream:json.dump({'outbound':line['outbound']},stream,separators=(',',':'));stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path);path.chmod(0o600)
    finally:pathlib.Path(tmp).unlink(missing_ok=True)

def _proxy_socks_port(ident):
    used={int(line['socks_port']) for line in proxy_lines()}
    start=20000+int(hashlib.sha256(ident.encode()).hexdigest()[:8],16)%10000
    for offset in range(10000):
        port=20000+(start-20000+offset)%10000
        if port not in used:return port
    raise ValueError('no local SOCKS listener port is available')

def _host_proxy_forwards(server_id,override=None):
    rows=proxy_forward_rows() if override is None else override
    return [item for item in rows if item.get('server_id','local')==server_id]

def proxy_host_config(server_id,forwards_override=None):
    forwards=_host_proxy_forwards(server_id,forwards_override)
    lines=proxy_lines()
    ssh_lines=[line['id'] for line in lines] if server_id=='local' else []
    if server_id!='local':
        required={item['line_id'] for item in forwards}
        lines=[line for line in lines if line['id'] in required]
    from xray_profiles import build_config
    return build_config(lines,ssh_lines,forwards)

def apply_proxy_host(server_id,forwards_override=None):
    forwards=_host_proxy_forwards(server_id,forwards_override)
    if server_id=='local':
        if not proxy_lines() and not forwards:return privileged({'op':'xray-config','id':'xray','action':'remove'})
        config=proxy_host_config(server_id,forwards_override)
        return privileged({'op':'xray-config','id':'xray','action':'apply','config':config})
    server=next((row for row in server_rows() if row['id']==server_id),None)
    if not server:raise ValueError('port-forward server is no longer registered')
    if not forwards:return server_remote(server,{'op':'xray-config','action':'remove'})
    config=proxy_host_config(server_id,forwards_override)
    return server_remote(server,{'op':'xray-config','action':'apply','config':config})

def save_proxy_forward(data,action):
    ident=data.get('id','');server_id=data.get('server_id','local');line_id=data.get('line_id','')
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError('شناسهٔ فوروارد نامعتبر است')
    if not isinstance(server_id,str) or (server_id!='local' and not any(row['id']==server_id for row in server_rows())):raise ValueError('سرور شنود در فهرست مدیریت‌شده‌ها نیست')
    if not isinstance(line_id,str) or not ID.fullmatch(line_id):raise ValueError('خط پروکسی را انتخاب کن')
    proxy_line(line_id)
    listen_ip=str(data.get('listen_ip','0.0.0.0')).strip()
    try:listen_ip=str(ipaddress.ip_address(listen_ip))
    except ValueError as error:raise ValueError('آدرس شنود باید IPv4 یا IPv6 باشد') from error
    listen_port=data.get('listen_port');target_port=data.get('target_port')
    if type(listen_port) is not int or not 1<=listen_port<=65535 or type(target_port) is not int or not 1<=target_port<=65535:raise ValueError('پورت‌ها باید بین ۱ تا ۶۵۵۳۵ باشند')
    target_host=str(data.get('target_host','')).strip()
    from xray_profiles import _safe_host
    target_host=_safe_host(target_host)
    network=data.get('network','tcp')
    if network not in ('tcp','udp'):raise ValueError('نوع اتصال باید TCP یا UDP باشد')
    item={'id':ident,'server_id':server_id,'line_id':line_id,'listen_ip':listen_ip,'listen_port':listen_port,'target_host':target_host,'target_port':target_port,'network':network,'enabled':True}
    with PROXY_LOCK:
        current=proxy_forward_rows();existing=next((row for row in current if row['id']==ident),None)
        if action=='create' and existing:raise ValueError('شناسهٔ فوروارد تکراری است')
        if action=='update' and (not existing or existing.get('server_id','local')!=server_id):raise ValueError('فوروارد روی این سرور پیدا نشد')
        if action not in ('create','update'):raise ValueError('عملیات فوروارد نامعتبر است')
        for row in current:
            if row['id']==ident:continue
            if row.get('server_id','local')==server_id and row.get('listen_port')==listen_port:
                raise ValueError('این پورت قبلاً برای خط پروکسی روی همین سرور استفاده شده است')
        for row in forward_rows():
            if row.get('server_id','local')==server_id and row.get('listen_port')==listen_port:
                raise ValueError('این پورت در HAProxy همین سرور استفاده شده است')
        desired=[row for row in current if row['id']!=ident]+[item]
        with db() as c:c.execute('INSERT INTO proxy_forwards(id,config) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET config=excluded.config',(ident,json.dumps(item)))
        try:
            service=apply_proxy_host(server_id,desired)
        except Exception:
            if existing:
                with db() as c:c.execute('UPDATE proxy_forwards SET config=? WHERE id=?',(json.dumps(existing),ident))
            else:
                with db() as c:c.execute('DELETE FROM proxy_forwards WHERE id=?',(ident,))
            try:apply_proxy_host(server_id,current)
            except Exception:pass
            raise
        return {'ok':True,'item':item,'service':service}

def delete_proxy_forward(ident,server_id):
    with PROXY_LOCK:
        current=proxy_forward_rows();existing=next((row for row in current if row['id']==ident and row.get('server_id','local')==server_id),None)
        if not existing:raise ValueError('فوروارد روی این سرور پیدا نشد')
        desired=[row for row in current if row['id']!=ident]
        with db() as c:c.execute('DELETE FROM proxy_forwards WHERE id=?',(ident,))
        try:service=apply_proxy_host(server_id,desired)
        except Exception:
            with db() as c:c.execute('INSERT INTO proxy_forwards(id,config) VALUES(?,?)',(ident,json.dumps(existing)))
            try:apply_proxy_host(server_id,current)
            except Exception:pass
            raise
        return {'ok':True,'service':service}

def create_proxy_line(ident,link):
    from xray_profiles import parse_link
    with PROXY_LOCK:
        with db() as c:
            if c.execute('SELECT 1 FROM proxy_lines WHERE id=?',(ident,)).fetchone():raise ValueError('proxy line ID already exists')
        line=parse_link(ident,link);line['socks_port']=_proxy_socks_port(ident);line['created_at']=int(time.time())
        metadata={key:line[key] for key in ('id','tag','protocol','address','port','label','socks_port','created_at')}
        _write_proxy_line(line)
        try:
            with db() as c:c.execute('INSERT INTO proxy_lines(id,metadata) VALUES(?,?)',(ident,json.dumps(metadata,ensure_ascii=False)))
            result=apply_proxy_host('local')
            if not result.get('ok'):raise RuntimeError(result.get('error','Xray did not accept the proxy line'))
        except Exception:
            with db() as c:c.execute('DELETE FROM proxy_lines WHERE id=?',(ident,))
            proxy_line_path(ident).unlink(missing_ok=True)
            try:apply_proxy_host('local')
            except Exception:pass
            raise
        return {'ok':True,'item':metadata,'service':result}

def delete_proxy_line(ident):
    with PROXY_LOCK:
        line=proxy_line(ident)
        users=[row['id'] for row in server_rows() if row.get('proxy_line_id')==ident]
        forwards=[row['id'] for row in proxy_forward_rows() if row.get('line_id')==ident]
        if users or forwards:
            detail=[]
            if users:detail.append('SSH سرورها: '+', '.join(users))
            if forwards:detail.append('فورواردها: '+', '.join(forwards))
            raise ValueError('ابتدا مسیرهای استفاده‌کننده از خط را جدا کن؛ '+'؛ '.join(detail))
        with db() as c:c.execute('DELETE FROM proxy_lines WHERE id=?',(ident,))
        proxy_line_path(ident).unlink(missing_ok=True)
        try:result=apply_proxy_host('local')
        except Exception:
            _write_proxy_line(line)
            with db() as c:c.execute('INSERT INTO proxy_lines(id,metadata) VALUES(?,?)',(ident,json.dumps({key:line[key] for key in ('id','tag','protocol','address','port','label','socks_port','created_at')},ensure_ascii=False)))
            raise
        return {'ok':True,'service':result}

def normalize_forward(data,server_id,allow_missing_backends=False):
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
        if not item:
            if allow_missing_backends:continue
            raise ValueError(f"تونل {tunnel_id} روی سرور انتخاب‌شده پیدا نشد")
        meta=item.get("metadata",{});transport=meta.get("transport","")
        if transport=="erspan":raise ValueError("ERSPAN برای حمل ترافیک پورت‌فوروارد مناسب نیست")
        remote=meta.get("tun_remote")
        ipx=meta.get('carrier')=='tun' and meta.get('encapsulation')=='ipx'
        if not remote and not ipx:raise ValueError(f"تونل {tunnel_id} آدرس داخلی peer ندارد")
        requested=entry.get('address')
        if ipx:
            if not requested:raise ValueError(f"برای مسیر IPX تونل {tunnel_id}، IP مقصد قابل‌دسترسی از رابط TUN را وارد کن")
            try:address_ip=ipaddress.ip_address(requested)
            except ValueError as e:raise ValueError(f"IP مقصد برای تونل {tunnel_id} نامعتبر است") from e
            address=str(address_ip)
        else:
            try:peer_address=ipaddress.ip_interface(remote).ip
            except ValueError as e:raise ValueError(f"IP داخلی peer در تونل {tunnel_id} نامعتبر است") from e
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
    if not backends:raise ValueError("هیچ مسیر تونلی معتبری باقی نمانده؛ قانون HAProxy را حذف یا مسیر تازه اضافه کن")
    if allow_missing_backends and algorithm=="first" and not any(backend["role"]=="primary" for backend in backends):
        backends[0]={**backends[0],"role":"primary"}
    if algorithm=="first" and sum(1 for backend in backends if backend["role"]=="primary")!=1:
        raise ValueError("در حالت Failover دقیقاً یک مسیر را Primary انتخاب کن؛ بقیه مسیرها Backup هستند")
    enabled=data.get("enabled",True)
    if type(enabled) is not bool:raise ValueError("وضعیت فعال بودن قانون نامعتبر است")
    return {"enabled":enabled,"id":ident,"server_id":server_id,"listen_ip":listen,"listen_port":listen_port,"backend_port":backend_port,"algorithm":algorithm,"proxy_protocol":proxy_protocol,"check_send_proxy":check_send_proxy,"shutdown_sessions":shutdown_sessions,"backends":backends}

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
    payload=[{k:v for k,v in rule.items() if k not in ("server_id","enabled")} for rule in rules if rule.get("enabled",True)]
    if server_id=="local":result=privileged({"op":"haproxy","id":"forwards","action":"apply","rules":payload})
    else:
        server=next((s for s in server_rows() if s["id"]==server_id),None)
        if not server:raise ValueError("سرور شنود در فهرست مدیریت‌شده‌ها نیست")
        result=server_remote(server,{"op":"forward-apply","rules":payload})
    if not result.get("ok"):raise RuntimeError(result.get("error",result.get("status","HAProxy apply failed")))
    return result

def _remove_forward_backends_locked(server_id,tunnel_ids):
    current=forward_rows();updated={};removed=[];removed_backends=0
    for rule in current:
        if rule.get("server_id","local")!=server_id:continue
        backends=rule.get("backends",[])
        remaining=[backend for backend in backends if backend.get("tunnel_id") not in tunnel_ids]
        dropped=len(backends)-len(remaining)
        if not dropped:continue
        removed_backends+=dropped
        if remaining:
            if rule.get("algorithm")=="first" and not any(backend.get("role","primary")=="primary" for backend in remaining):
                remaining[0]={**remaining[0],"role":"primary"}
            updated[rule["id"]]={**rule,"backends":remaining}
        else:removed.append(rule["id"])
    if not removed_backends:return {"removed_backends":0,"removed_rules":0}
    previous=[rule for rule in current if rule.get("server_id","local")==server_id]
    desired=[updated.get(rule["id"],rule) for rule in previous if rule["id"] not in removed]
    apply_forward_set(server_id,desired)
    try:
        with db() as connection:
            for ident,rule in updated.items():
                connection.execute("UPDATE port_forwards SET config=? WHERE id=?",(json.dumps(rule),ident))
            for ident in removed:
                connection.execute("DELETE FROM port_forwards WHERE id=?",(ident,))
    except Exception:
        try:apply_forward_set(server_id,previous)
        except Exception:pass
        raise
    return {"removed_backends":removed_backends,"removed_rules":len(removed)}

def remove_tunnel_from_forward_backends(server_id,tunnel_id):
    with FORWARD_LOCK:return _remove_forward_backends_locked(server_id,{tunnel_id})

def prune_missing_forward_backends_locked(server_id,available_tunnel_ids):
    available_tunnel_ids=set(available_tunnel_ids)
    stale={backend.get("tunnel_id") for rule in forward_rows() if rule.get("server_id","local")==server_id for backend in rule.get("backends",[]) if backend.get("tunnel_id") not in available_tunnel_ids}
    return _remove_forward_backends_locked(server_id,stale)

def set_forward_enabled(ident, server_id, enabled):
    if type(enabled) is not bool:
        raise ValueError("enabled must be a boolean")
    current = forward_rows()
    existing = next((item for item in current if item["id"] == ident and item.get("server_id", "local") == server_id), None)
    if not existing:
        raise ValueError("قانون پورت‌فوروارد روی این سرور پیدا نشد")
    updated = {**existing, "enabled": enabled}
    previous = [item for item in current if item.get("server_id", "local") == server_id]
    desired = [updated if item["id"] == ident else item for item in previous]
    apply_forward_set(server_id, desired)
    try:
        with db() as connection:
            connection.execute("UPDATE port_forwards SET config=? WHERE id=?", (json.dumps(updated), ident))
    except Exception:
        apply_forward_set(server_id, previous)
        raise
    return {"ok": True, "item": updated}


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
    if carrier=="tun" and config.get("encapsulation","tcp")=="tcp" and not all(config.get(field) for field in ("tun_local","tun_remote")):raise ValueError("Backhaul TUN over TCP requires local and peer tunnel addresses")
    if carrier=="tun" and all(config.get(field) for field in ("tun_local","tun_remote")):
        if config.get("encapsulation","tcp")=="tcp" and ("tun_local" not in config or "tun_remote" not in config):raise ValueError("Backhaul TUN over TCP requires local and peer tunnel addresses")
        import ipaddress
        pair={str(ipaddress.ip_interface(config["tun_local"]).ip),str(ipaddress.ip_interface(config["tun_remote"]).ip)}
        for item in rows():
            if item["id"]==ident:continue
            for field in ("tun_local","tun_remote"):
                old=item["metadata"].get(field)
                if old and str(ipaddress.ip_interface(old).ip) in pair:raise ValueError("tunnel IP already assigned to another managed instance")
    result=privileged({"op":"create","id":ident,"config":config})
    if not result.get("ok"):raise RuntimeError(result.get("error",result.get("output","create failed")))
    metadata={k:v for k,v in config.items() if k!='replace'}
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
        save(ident,mode,{"transport":kind,"interface":config["interface"],"tun_name":config["interface"],"tun_local":local,"tun_remote":peer,"outer_local":config.get("outer_local"),"outer_peer":config.get("outer_peer"),"mtu":config["mtu"],"native_profile":profile})
        return {"id":ident,"kind":kind,"mode":mode,"tun_local":local,"tun_remote":peer}
    except Exception:
        privileged({"op":"profile","group":"network","id":profile,"action":"delete"})
        raise

def allocation_snapshot(server_id,servers,include_l2tp=False,include_network_profiles=False):
    if server_id!='local':return server_remote(servers[server_id],{'op':'allocation-snapshot','include_l2tp':include_l2tp,'include_network_profiles':include_network_profiles})
    items=rows();snapshot={'items':items,'network':network_snapshot()}
    if include_network_profiles:
        snapshot['network_profiles']=[]
        listed=privileged({'op':'profile','group':'network','id':'inventory','action':'list'})
        if listed.get('error') or not isinstance(listed.get('items'),list):raise RuntimeError('Could not safely inspect saved network profiles on the local server.')
        for profile_id in listed.get('items',[]):
            result=privileged({'op':'profile','group':'network','id':profile_id,'action':'read'})
            if result.get('error'):raise RuntimeError('Could not safely inspect saved network profiles on the local server.')
            config=result.get('config')
            if not config:raise RuntimeError('A network profile changed during allocation; retry after it finishes.')
            snapshot['network_profiles'].append({'profile_id':profile_id,**{key:config[key] for key in ('kind','interface','vni','port','inner_local','inner_peer') if key in config}})
    if include_l2tp:
        snapshot['l2tp_profiles']=[]
        for item in items:
            metadata=item.get('metadata') or {};profile=metadata.get('native_profile')
            if metadata.get('transport')!='l2tpv3' or not profile:continue
            result=privileged({'op':'profile','group':'network','id':profile,'action':'read'})
            if not result.get('config'):raise RuntimeError(result.get('error','could not read managed L2TPv3 profile'))
            snapshot['l2tp_profiles'].append(result['config'])
    return snapshot

def available_udp_ports(server_id,ports,servers):
    """Ask the endpoint itself which candidate UDP ports can be bound now."""
    ports=sorted({int(port) for port in ports})
    if any(not 1024<=port<=65535 for port in ports):return set()
    if server_id!='local':
        code='import json,socket,sys; d=json.load(sys.stdin); ports=d["ports"]; available=[]\nfor p in ports:\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n try:\n  s.bind(("0.0.0.0",int(p))); available.append(int(p))\n except OSError:\n  pass\n finally:\n  s.close()\nprint(json.dumps({"available":available}))'
        command='runuser -u tunnelmgr -- /usr/bin/python3 -c '+shlex.quote(code)
        result=subprocess.run(ssh_argv(servers[server_id])+[command],input=json.dumps({'ports':ports}),capture_output=True,text=True,timeout=30)
        if result.returncode:
            raise RuntimeError('The central server could not verify UDP port availability on '+server_id+'. '+(result.stderr or result.stdout).strip()[-400:])
        try:available=json.loads(result.stdout).get('available')
        except (ValueError,AttributeError):available=None
        if not isinstance(available,list) or any(not isinstance(port,int) for port in available) or not set(available)<=set(ports):
            raise RuntimeError('The central server received an invalid UDP port check from '+server_id+'.')
        return set(available)
    available=set()
    for port in ports:
        probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            probe.bind(('0.0.0.0',port));available.add(port)
        except OSError:pass
        finally:probe.close()
    return available

def native_profile_config(server_id,ident,servers):
    if server_id=='local':
        item=find(ident)
        if not item:raise ValueError('native tunnel is missing on local server')
        profile=item.get('metadata',{}).get('native_profile')
        result=privileged({'op':'profile','group':'network','id':profile,'action':'read'}) if profile else {}
    else:
        result=server_remote(servers[server_id],{'op':'native-config','id':ident})
    config=result.get('config') if isinstance(result,dict) else None
    if not config:raise ValueError('could not read native tunnel config on '+server_id)
    return config

def allocate_pair_interface(snapshots,prefix='tn'):
    interfaces=set()
    for snapshot in snapshots:
        network=snapshot.get('network') or {}
        interfaces.update(str(name) for name in network.get('interfaces',[]))
        for item in snapshot.get('items',[]):
            metadata=item.get('metadata') or {}
            name=metadata.get('tun_name') or metadata.get('interface')
            if name:interfaces.add(str(name))
        for profile in snapshot.get('network_profiles',[]):
            name=profile.get('interface')
            if name:interfaces.add(str(name))
    for _ in range(128):
        candidate=prefix+secrets.token_hex(6)
        if len(candidate)<=15 and candidate not in interfaces:return candidate
    raise RuntimeError('Could not allocate a free tunnel interface name on both servers.')

def allocate_pair_resources(snapshots,prefix='tn'):
    networks=set()
    for snapshot in snapshots:
        network=snapshot.get('network') or {}
        for value in network.get('networks',[]):
            try:
                item=ipaddress.ip_network(value,strict=False)
                if item.version==4:networks.add(item)
            except ValueError:continue
        for item in snapshot.get('items',[]):
            metadata=item.get('metadata') or {}
            for field in ('tun_local','tun_remote'):
                value=metadata.get(field)
                if not value:continue
                try:
                    iface=ipaddress.ip_interface(value)
                    if iface.version==4:networks.add(iface.network)
                except ValueError:continue
        for profile in snapshot.get('network_profiles',[]):
            for field in ('inner_local','inner_peer'):
                value=profile.get(field)
                if not value:continue
                try:
                    iface=ipaddress.ip_interface(value)
                    if iface.version==4:networks.add(iface.network)
                except ValueError:continue
    interface=allocate_pair_interface(snapshots,prefix)
    pools=tuple(ipaddress.IPv4Network(value) for value in ('10.240.0.0/12','172.30.0.0/15','192.168.240.0/20'))
    subnet=None
    for _ in range(1024):
        pool=secrets.choice(pools);slots=int(pool.num_addresses)//4
        address=int(pool.network_address)+secrets.randbelow(slots)*4
        candidate=ipaddress.IPv4Network((address,30))
        if not any(candidate.overlaps(used) for used in networks):
            subnet=candidate;break
    if subnet is None:raise RuntimeError('No conflict-free private /30 subnet is available on the selected servers.')
    local=str(subnet.network_address+1)+'/'+str(subnet.prefixlen)
    peer=str(subnet.network_address+2)+'/'+str(subnet.prefixlen)
    return interface,local,peer

def allocate_backhaul_health_port(snapshot):
    network=snapshot.get('network') or {}
    if not network.get('tcp_inventory_ok'):raise RuntimeError('Could not inspect TCP listeners for a safe Backhaul health port.')
    used=set(int(port) for port in network.get('tcp_ports',[]))
    for item in snapshot.get('items',[]):
        meta=item.get('metadata') or {}
        if meta.get('manager')=='Backhaul' and meta.get('carrier')=='tun':used.add(int(meta.get('health_port') or 19080))
    for port in range(19080,20080):
        if port not in used:return port
    raise RuntimeError('No free Backhaul health port is available on the server.')

def allocate_vxlan_values(snapshots):
    """Pick one VNI and UDP destination port unused on both VXLAN/Geneve peers."""
    used_vni=set()
    used_ports=[]
    for snapshot in snapshots:
        network=snapshot.get('network') or {}
        if not network.get('udp_inventory_ok'):
            raise RuntimeError('Could not inspect UDP ports on both servers; automatic VXLAN/Geneve port allocation was stopped.')
        ports=set(int(port) for port in network.get('udp_ports',[]))
        for profile in snapshot.get('network_profiles',[]):
            if profile.get('kind') not in ('vxlan','geneve'):continue
            try:used_vni.add(int(profile.get('vni')))
            except (TypeError,ValueError):pass
            try:ports.add(int(profile.get('port') or (4789 if profile.get('kind')=='vxlan' else 6081)))
            except (TypeError,ValueError):pass
        used_ports.append(ports)
    vni=None
    # Randomize the starting point while checking every candidate once at most.
    start=secrets.randbelow(16777215)+1
    for offset in range(16777215):
        candidate=(start+offset-1)%16777215+1
        if candidate not in used_vni:
            vni=candidate;break
    if vni is None:raise RuntimeError('No unused VXLAN/Geneve VNI is available on the selected servers.')
    common=set.intersection(*(set(range(20000,65536))-ports for ports in used_ports))
    if 4789 not in used_ports[0] and 4789 not in used_ports[1]:
        port=4789
    elif common:
        # Prefer ports outside each host's ephemeral range when possible.
        safe=common
        for snapshot in snapshots:
            low,high=(snapshot.get('network') or {}).get('udp_ephemeral_range',[32768,60999])
            outside={value for value in safe if not int(low)<=value<=int(high)}
            if outside:safe=outside
        port=min(safe)
    else:raise RuntimeError('No UDP destination port is free on both selected servers.')
    return vni,port

def allocate_l2tp_values(snapshots,encap='udp',port_check=None):
    used_tunnel_ids=set();used_session_ids=set();used_ports=[]
    for snapshot in snapshots:
        network=snapshot.get('network') or {}
        if encap=='udp':
            if not network.get('udp_inventory_ok'):raise RuntimeError('Could not safely inspect UDP ports on both servers; L2TPv3 UDP allocation was stopped.')
            used_ports.append(set(int(port) for port in network.get('udp_ports',[])))
        for config in snapshot.get('l2tp_profiles',[]):
            for field in ('tunnel_id','peer_tunnel_id'):
                try:used_tunnel_ids.add(int(config[field]))
                except (KeyError,TypeError,ValueError):continue
            for field in ('session_id','peer_session_id'):
                try:used_session_ids.add(int(config[field]))
                except (KeyError,TypeError,ValueError):continue
            if encap=='udp':
                for field in ('udp_sport','udp_dport'):
                    try:used_ports[-1].add(int(config[field]))
                    except (KeyError,TypeError,ValueError):continue
    def unique_pair(used):
        pair=[]
        for _ in range(2):
            value=None
            for _ in range(256):
                candidate=secrets.randbelow(4294967295)+1
                if candidate not in used:
                    value=candidate;used.add(candidate);pair.append(candidate);break
            if value is None:raise RuntimeError('Could not allocate unused L2TPv3 identifiers.')
        return pair
    tunnel_a,tunnel_b=unique_pair(used_tunnel_ids);session_a,session_b=unique_pair(used_session_ids)
    if encap!='udp':return tunnel_a,tunnel_b,session_a,session_b,None,None
    def free_port(used,network,endpoint):
        low,high=network.get('udp_ephemeral_range',[32768,60999])
        preferred=[port for port in range(1024,65536) if port not in used and not int(low)<=port<=int(high)]
        fallback=[port for port in range(1024,65536) if port not in used]
        candidates=preferred or fallback
        # Randomly sample batches and ask the central allocator to bind-probe
        # them on the target endpoint, avoiding a new SSH connection per port.
        while candidates:
            batch=[candidates.pop(secrets.randbelow(len(candidates))) for _ in range(min(64,len(candidates)))]
            available=set(batch) if port_check is None else port_check(endpoint,batch)
            if available:
                value=secrets.choice(tuple(available));used.add(value);return value
        raise RuntimeError('The central server could not find and verify a free L2TPv3 UDP port on '+endpoint+'.')
    port_a=free_port(used_ports[0],snapshots[0].get('network') or {},0)
    port_b=free_port(used_ports[1],snapshots[1].get('network') or {},1)
    return tunnel_a,tunnel_b,session_a,session_b,port_a,port_b

def create_backhaul_pair(data):
    ident=data.get('id');ids=data.get('servers');configs=data.get('configs')
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError('invalid tunnel ID')
    if not isinstance(ids,list) or len(ids)!=2 or len(set(ids))!=2 or not isinstance(configs,dict) or set(configs)!=set(ids):raise ValueError('two endpoint configurations required')
    servers={s['id']:s for s in server_rows()}
    if any(sid!='local' and sid not in servers for sid in ids):raise ValueError('unknown managed server')
    with NATIVE_PAIR_LOCK:
        snapshots=[allocation_snapshot(sid,servers,include_network_profiles=True) for sid in ids]
        if any(item.get('id')==ident for snap in snapshots for item in snap.get('items',[])):raise ValueError('tunnel ID already exists')
        cfgs={sid:dict(configs[sid],id=ident,transport='backhaul') for sid in ids}
        a,b=[cfgs[sid] for sid in ids]
        if any(cfg.get('carrier')!='tun' for cfg in (a,b)):raise ValueError('IP tunnel pair requires TUN')
        if a.get('encapsulation','tcp')!=b.get('encapsulation','tcp') or a.get('tun_carrier','tcp')!=b.get('tun_carrier','tcp'):raise ValueError('peer carriers must match')
        if {a.get('mode'),b.get('mode')}!={'server','client'}:raise ValueError('one server and one client required')
        interface,local,peer=allocate_pair_resources(snapshots,prefix='bh')
        a.update(tun_name=interface,tun_local=local,tun_remote=peer,health_port=allocate_backhaul_health_port(snapshots[0]))
        b.update(tun_name=interface,tun_local=peer,tun_remote=local,health_port=allocate_backhaul_health_port(snapshots[1]))
        def call(sid,op):
            if sid=='local':
                if op=='validate':return validate_tunnel_config(cfgs[sid])
                if op=='create':return create_instance(cfgs[sid])
                return remove_tunnel_endpoint(ident,delete_secret=True)
            payload={'op':op,'id':ident,'data':cfgs[sid]} if op!='delete' else {'op':'operate','id':ident,'action':'delete'}
            result=server_remote(servers[sid],payload)
            if result.get('ok') is False:raise RuntimeError(result.get('error') or result.get('output') or 'endpoint operation failed')
            return result
        for sid in ids:call(sid,'validate')
        attempted=[]
        try:
            for sid in sorted(ids,key=lambda sid:cfgs[sid]['mode']=='client'):
                attempted.append(sid);call(sid,'create')
        except Exception as error:
            failures=[]
            for sid in reversed(attempted):
                try:
                    current=(find(ident) if sid=='local' else next((item for item in server_remote(servers[sid],{'op':'list'}).get('items',[]) if item.get('id')==ident),None))
                    if current:call(sid,'delete')
                except Exception as cleanup:failures.append(sid+': '+str(cleanup))
            if failures:raise RuntimeError(str(error)+'; cleanup failed: '+'; '.join(failures)) from error
            raise
        return {'id':ident,'configs':cfgs}

def create_native_pair(data):
    ident=data.get('id');kind=data.get('transport');a_id=data.get('server_a');b_id=data.get('server_b');action=data.get('action','create')
    if not isinstance(ident,str) or not ID.fullmatch(ident) or len(ident)>41:raise ValueError('invalid native tunnel ID')
    if not isinstance(a_id,str) or not isinstance(b_id,str) or a_id==b_id:raise ValueError('choose two different servers')
    allowed={'gre','gretap','geneve','vxlan','ipip','sit-6to4','sit-isatap','gre-fou','ipip-fou','sit-fou','l2tpv3','ipsec-ikev2','ipsec-esp-udp','esp'}
    if kind not in allowed:raise ValueError('unsupported native tunnel transport')
    if action not in ('create','update'):raise ValueError('unsupported native tunnel pair action')
    servers={item['id']:item for item in server_rows()}
    if a_id!='local' and a_id not in servers:raise ValueError('server A is not managed')
    if b_id!='local' and b_id not in servers:raise ValueError('server B is not managed')
    config_a=data.get('config_a');config_b=data.get('config_b')
    if not isinstance(config_a,dict) or not isinstance(config_b,dict):raise ValueError('both native tunnel endpoint configs are required')
    if config_a.get('id')!=ident or config_b.get('id')!=ident or config_a.get('transport')!=kind or config_b.get('transport')!=kind:
        raise ValueError('native tunnel endpoint configs do not match the requested tunnel')
    with NATIVE_PAIR_LOCK:
        snapshots={sid:allocation_snapshot(sid,servers,include_l2tp=kind=='l2tpv3',include_network_profiles=kind in ('geneve','vxlan')) for sid in (a_id,b_id)}
        existing={sid:next((item for item in snapshot.get('items',[]) if item.get('id')==ident),None) for sid,snapshot in snapshots.items()}
        if action=='create':
            for sid,item in existing.items():
                if item:raise ValueError('tunnel ID already exists on '+sid)
            if any(profile.get('profile_id')=='native-'+ident for snapshot in snapshots.values() for profile in snapshot.get('network_profiles',[])):
                raise ValueError('A saved network profile already uses this tunnel ID; remove or reconcile it before creating another.')
        else:
            if not all(existing.values()):raise ValueError('tunnel must exist on both selected servers before it can be updated')
            if any(not (item.get('metadata') or {}).get('native_profile') for item in existing.values()):
                raise ValueError('only native tunnel pairs can be updated through this action')
        previous={}
        if action=='update':
            previous={sid:{'id':ident,'transport':kind,'mode':existing[sid].get('mode','server'),**native_profile_config(sid,ident,servers)} for sid in (a_id,b_id)}
        config_a=dict(config_a);config_b=dict(config_b)
        address_kinds={'gre','gretap','ipip','gre-fou','ipip-fou','l2tpv3','ipsec-ikev2','ipsec-esp-udp','esp','geneve','vxlan'}
        if action=='create':
            interface,local,peer=allocate_pair_resources([snapshots[a_id],snapshots[b_id]])
            config_a['interface']=interface;config_b['interface']=interface
            if kind in address_kinds:
                config_a['inner_local']=local;config_a['inner_peer']=peer
                config_b['inner_local']=peer;config_b['inner_peer']=local
            if kind in ('geneve','vxlan'):
                vni,port=allocate_vxlan_values([snapshots[a_id],snapshots[b_id]])
                config_a['vni']=config_b['vni']=vni
                config_a['port']=config_b['port']=port
        else:
            # Recreate the devices, keeping their saved identity/addresses unless
            # the edit explicitly changes them. Routing and HAProxy reference them.
            for sid,cfg in ((a_id,config_a),(b_id,config_b)):
                cfg['interface']=cfg.get('interface') or previous[sid]['interface']
                if kind in address_kinds:
                    for field in ('inner_local','inner_peer'):cfg[field]=cfg.get(field) or previous[sid].get(field)
                if kind in ('geneve','vxlan'):
                    for field in ('vni','port'):cfg[field]=cfg.get(field) or previous[sid].get(field)
            interface=config_a['interface']
        if kind in ('ipsec-ikev2','ipsec-esp-udp'):
            configured_psks={cfg.get('psk') for cfg in (config_a,config_b) if cfg.get('psk')}
            if len(configured_psks)>1:raise ValueError('Both IPsec peers must use the same shared PSK.')
            psk=next(iter(configured_psks),None)
            if not psk and action=='update':
                psk=next((previous[sid].get('psk') for sid in (a_id,b_id) if previous[sid].get('psk')),None)
            if not psk:psk=secrets.token_urlsafe(48)
            config_a['psk']=config_b['psk']=psk
            for cfg in (config_a,config_b):
                outer_local=str(cfg.get('outer_local',''));outer_peer=str(cfg.get('outer_peer',''))
                # Outer-IP identities are ambiguous when several IKE tunnels
                # connect the same pair of servers.  strongSwan may select a
                # different connection's CHILD_SA selectors and answer
                # TS_UNACCEPTABLE.  Scope default identities to this tunnel;
                # retain explicitly customized identities.
                if not cfg.get('local_id') or cfg.get('local_id')==outer_local:
                    cfg['local_id']=f'{ident}@{outer_local}'
                if not cfg.get('remote_id') or cfg.get('remote_id')==outer_peer:
                    cfg['remote_id']=f'{ident}@{outer_peer}'
            if config_a['local_id']!=config_b['remote_id'] or config_a['remote_id']!=config_b['local_id']:
                raise ValueError('IPsec peer IKE identities must be inverse on the two tunnel endpoints.')
        if kind=='l2tpv3':
            encap=config_a.get('encap') or config_b.get('encap') or 'udp'
            if encap not in ('udp','ip'):raise ValueError('L2TPv3 encapsulation must be udp or ip.')
            if config_b.get('encap') and config_b['encap']!=encap:raise ValueError('Both L2TPv3 peers must use the same encapsulation.')
            config_a['encap']=config_b['encap']=encap
            if action=='create':
                tunnel_a,tunnel_b,session_a,session_b,port_a,port_b=allocate_l2tp_values(
                    [snapshots[a_id],snapshots[b_id]],encap,
                    lambda endpoint,ports:available_udp_ports((a_id,b_id)[endpoint],ports,servers))
                config_a.update({'tunnel_id':tunnel_a,'peer_tunnel_id':tunnel_b,'session_id':session_a,'peer_session_id':session_b})
                config_b.update({'tunnel_id':tunnel_b,'peer_tunnel_id':tunnel_a,'session_id':session_b,'peer_session_id':session_a})
                if encap=='udp':
                    config_a.update({'udp_sport':port_a,'udp_dport':port_b})
                    config_b.update({'udp_sport':port_b,'udp_dport':port_a})
            else:
                for field in ('tunnel_id','peer_tunnel_id','session_id','peer_session_id','udp_sport','udp_dport'):
                    if config_a.get(field) in (None,'') and previous[a_id].get(field) is not None:config_a[field]=previous[a_id][field]
                    if config_b.get(field) in (None,'') and previous[b_id].get(field) is not None:config_b[field]=previous[b_id][field]
        endpoints=((a_id,config_a),(b_id,config_b))
        if kind in ('ipsec-ikev2','ipsec-esp-udp'):
            # Install the responder's swanctl connection before the initiator
            # sends its first IKE_SA_INIT.  Otherwise the responder can reject
            # that packet with NO_PROPOSAL_CHOSEN because no matching IKE
            # config has been loaded yet.
            roles={config_a.get('role'),config_b.get('role')}
            if roles!={'client','server'}:
                raise ValueError('IPsec peers must have one client and one server role.')
            endpoints=tuple(sorted(endpoints,key=lambda endpoint:endpoint[1].get('role')=='client'))
        if action=='update':
            result=rebuild_tunnel_pair(ident,[a_id,b_id],dict(endpoints),'update')
            result.update(transport=kind,action='update',interface=interface,
                          inner_local=config_a.get('inner_local'),inner_peer=config_a.get('inner_peer'),
                          vni=config_a.get('vni'),port=config_a.get('port'))
            if kind=='l2tpv3' and config_a.get('encap')=='udp':result['udp_ports']=[config_a['udp_sport'],config_a['udp_dport']]
            return result
        attempted=[]
        try:
            for sid,config in endpoints:
                attempted.append(sid)
                if action=='create':
                    if sid=='local':create_native(config)
                    else:server_remote(servers[sid],{'op':'create','data':config})
                else:
                    request={**config,'id':ident,'transport':kind,'mode':existing[sid].get('mode','server')}
                    if sid=='local':update_tunnel(request)
                    else:server_remote(servers[sid],{'op':'update','data':request})
        except Exception:
            for sid in reversed(attempted):
                try:
                    if action=='update':
                        if sid=='local':update_tunnel(previous[sid])
                        else:server_remote(servers[sid],{'op':'update','data':previous[sid]})
                    elif sid=='local':
                        item=find(ident)
                        if item:
                            profile=item.get('metadata',{}).get('native_profile')
                            if profile:privileged({'op':'profile','group':'network','id':profile,'action':'delete'})
                            with db() as connection:connection.execute('DELETE FROM tunnels WHERE id=?',(ident,))
                    else:server_remote(servers[sid],{'op':'operate','id':ident,'action':'delete'})
                except Exception:pass
            raise
    result={'ok':True,'id':ident,'transport':kind,'servers':[a_id,b_id],'action':action,
            'interface':interface,'inner_local':config_a.get('inner_local'),
            'inner_peer':config_a.get('inner_peer'),'vni':config_a.get('vni'),'port':config_a.get('port')}
    if kind=='l2tpv3' and config_a.get('encap')=='udp':result['udp_ports']=[config_a['udp_sport'],config_a['udp_dport']]
    return result

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
    existing={};snapshots={};allocated_interface=None
    for sid in (a_id,b_id):
        if data.get("action")=="update":
            items=rows() if sid=="local" else server_remote(servers[sid],{"op":"list"}).get("items",[])
        else:
            snapshots[sid]=allocation_snapshot(sid,servers)
            items=snapshots[sid].get("items",[])
        existing[sid]=items
        for item in items:
            if data.get("action")=="update" and item.get("id")==ident:continue
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
        interface_a=old[a_id].get("interface")
        interface_b=old[b_id].get("interface")
        if not interface_a or not interface_b:raise ValueError("WireGuard peers have no saved tunnel interface")
        base={k:v for k,v in data.items() if k in ("mtu","keepalive")}
        config_a={**old[a_id],"id":ident,"transport":"wireguard","mode":"peer","interface":interface_a,"outer_peer":hosts[b_id],"inner_local":str(local),"inner_peer":str(peer),"listen_port":port,"endpoint_port":port,**base}
        config_b={**old[b_id],"id":ident,"transport":"wireguard","mode":"peer","interface":interface_b,"outer_peer":hosts[a_id],"inner_local":str(peer),"inner_peer":str(local),"listen_port":port,"endpoint_port":port,**base}
        result=rebuild_tunnel_pair(ident,[a_id,b_id],{a_id:config_a,b_id:config_b},'update')
        return {**result,'transport':'wireguard','updated':True,'udp_port':port}
    if exists_a or exists_b:raise ValueError("tunnel id already exists on one of the selected servers")
    allocated_interface=allocate_pair_interface([snapshots[a_id],snapshots[b_id]],prefix="wg")
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
    config_a={"id":ident,"transport":"wireguard","mode":"peer","interface":allocated_interface,"outer_peer":hosts[b_id],"inner_local":str(local),"inner_peer":str(peer),"private_key":priv_a,"peer_public_key":pub_b,"preshared_key":psk,"listen_port":port,"endpoint_port":port,**base}
    config_b={"id":ident,"transport":"wireguard","mode":"peer","interface":allocated_interface,"outer_peer":hosts[a_id],"inner_local":str(peer),"inner_peer":str(local),"private_key":priv_b,"peer_public_key":pub_a,"preshared_key":psk,"listen_port":port,"endpoint_port":port,**base}
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
    if updating:
        result=rebuild_tunnel_pair(ident,[a_id,b_id],{a_id:cfg_a,b_id:cfg_b},'update')
        return {**result,'transport':'openvpn','udp_port':port,'updated':True}
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
    secret_file=meta.get('secret_file')
    if not secret_file:
        saved=privileged({'op':'backhaul-secret-path','id':ident})
        if not saved.get('ok'):raise RuntimeError(saved.get('error','Could not preserve the owned Backhaul secret'))
        secret_file=saved['secret_file']
    return {"id":ident,"transport":"backhaul","mode":item["mode"],**meta,"secret_file":secret_file,"secret_managed":meta.get("secret_managed",False)}

def normalize_rebuild_config(ident,data,previous):
    if not isinstance(data,dict) or data.get('id',ident)!=ident:raise ValueError('Tunnel configuration ID does not match')
    transport=data.get('transport') or data.get('kind') or previous.get('transport')
    if (transport=='backhaul')!=(previous.get('transport')=='backhaul'):
        raise ValueError('Changing between Backhaul and native tunnel types is not supported')
    if transport=='backhaul':
        allowed={'mode','listen','peer','tun_name','tun_local','tun_remote','tun_mtu','health_port','secret_file','carrier','tun_carrier','ports','pool','accept_udp','proxy_protocol','edge','source_bind','cert','key','ca','sni','encapsulation','ipx_profile','local_ip','peer_ip','interface','spoof_source','expected_peer_source'}
        config={k:v for k,v in data.items() if k in allowed}
        config.setdefault('mode',previous.get('mode','server'))
        config.setdefault('secret_file',previous.get('secret_file'))
        if config.get('carrier','tun')=='tun' and config.get('encapsulation','tcp')=='ipx':
            for key in ('tun_local','tun_remote','health_port'):config.pop(key,None)
        return {'id':ident,'transport':transport,'secret_managed':previous.get('secret_managed',False),**config}
    return {**data,'id':ident,'transport':transport,'kind':transport,'mode':data.get('mode',previous.get('mode','server'))}

def validate_tunnel_config(data):
    supported={'backhaul','gre','gretap','geneve','vxlan','ipip','sit-6to4','sit-isatap','erspan','gre-fou','ipip-fou','sit-fou','l2tpv3','ipsec-ikev2','ipsec-esp-udp','esp','wireguard','openvpn'}
    if data.get('transport') not in supported:raise ValueError('This tunnel type does not support rebuilding')
    requested=[]
    for field in ('inner_local','inner_peer','tun_local','tun_remote'):
        if data.get(field):requested.append(ipaddress.ip_interface(data[field]).ip)
    for item in rows():
        if item['id']==data['id']:continue
        for field in ('tun_local','tun_remote'):
            value=item.get('metadata',{}).get(field)
            if value and ipaddress.ip_interface(value).ip in requested:
                raise ValueError('Internal address already belongs to tunnel '+item['id'])
    if data.get('transport')=='backhaul':
        config={k:v for k,v in data.items() if k not in ('id','transport','secret_managed')}
        result=privileged({'op':'validate-backhaul','id':data['id'],'config':{**config,'replace':True}})
    else:
        config={k:v for k,v in data.items() if k not in ('id','transport','mode','manager','native_profile')}
        result=privileged({'op':'profile','group':'network','id':'native-'+data['id'],'action':'validate','config':config})
    if not result.get('ok'):raise RuntimeError(result.get('error') or result.get('output') or 'Tunnel preflight failed')
    return result

def remove_tunnel_endpoint(ident,delete_secret=False):
    item=find(ident)
    if not item:return {'ok':True,'already_removed':True}
    metadata=item.get('metadata',{});profile=metadata.get('native_profile');request={'op':'profile','group':'network','id':profile,'action':'delete'} if profile else {'op':'delete','id':ident}
    if delete_secret and metadata.get('manager')=='Backhaul':
        secret_file=metadata.get('secret_file','');secret_kind='psk' if metadata.get('encapsulation')=='ipx' else 'token'
        if metadata.get('secret_managed') is True or secret_file==f'/etc/backhaul/secrets/{ident}.{secret_kind}':request['delete_secret_kind']=secret_kind
    result=privileged(request,timeout=150)
    if not result.get('ok'):raise RuntimeError(result.get('error') or result.get('output') or 'Tunnel cleanup failed')
    with db() as connection:connection.execute('DELETE FROM tunnels WHERE id=?',(ident,))
    return {'ok':True,'id':ident}

def rebuild_tunnel_pair(ident,server_ids=None,configs=None,operation='restart'):
    import tunnel_lifecycle
    if server_ids is None:
        with MONITOR_LOCK:statuses=list(MONITOR_SERVERS)
        server_ids=(['local'] if find(ident) else [])+[s['id'] for s in statuses if s.get('id')!='local' and any(t.get('id')==ident for t in s.get('tunnels',[]))]
    return tunnel_lifecycle.rebuild(sys.modules[__name__],ident,server_ids,configs,operation)

def restart_ipsec_pair(ident):
    return rebuild_tunnel_pair(ident)

def update_tunnel(data):
    ident=data.get('id') if isinstance(data,dict) else None
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError('invalid tunnel id')
    previous=tunnel_config(ident)
    config=normalize_rebuild_config(ident,data,previous)
    validate_tunnel_config(config)
    try:
        remove_tunnel_endpoint(ident)
        return create_instance(config) if config['transport']=='backhaul' else create_native(config)
    except Exception as error:
        try:
            remove_tunnel_endpoint(ident)
            old=normalize_rebuild_config(ident,previous,previous)
            create_instance(old) if old['transport']=='backhaul' else create_native(old)
        except Exception as rollback:
            raise RuntimeError(str(error)+' · بازگردانی سمت قبلی کامل نشد: '+str(rollback)) from error
        raise RuntimeError(str(error)+' · سمت قبلی بازگردانده شد.') from error

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

def update_server_host(server_id,new_host,new_user=None,new_proxy_id=None,password="",new_location=None,auto_geoip=True,new_proxy_line_id=None):
    servers={s["id"]:s for s in server_rows()}
    current=servers.get(server_id)
    if not current:raise ValueError("server not found")
    old_host=current["host"]
    new_user=current["user"] if new_user is None else new_user
    new_proxy_id=current.get("proxy_server_id","") if new_proxy_id is None else new_proxy_id
    new_proxy_line_id=current.get('proxy_line_id','') if new_proxy_line_id is None else new_proxy_line_id
    new_location=current.get("location","abroad") if new_location is None else new_location
    geoip_result=None;geoip_error=""
    if not isinstance(new_host,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}",new_host):raise ValueError("آدرس سرور نامعتبر است")
    if not isinstance(new_user,str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}",new_user):raise ValueError("نام کاربری SSH نامعتبر است")
    if not isinstance(new_proxy_id,str):raise ValueError("سرور پروکسی نامعتبر است")
    if not isinstance(new_proxy_line_id,str):raise ValueError('خط پروکسی نامعتبر است')
    if new_proxy_id and new_proxy_line_id:raise ValueError('برای SSH فقط یک مسیر پروکسی انتخاب کن')
    if new_proxy_line_id:
        proxy_line(new_proxy_line_id)
        state=privileged({'op':'xray-config','id':'xray','action':'status'})
        if not state.get('active'):raise ValueError('خط پروکسی روی سرور مرکزی فعال نیست')
    if new_location not in ("iran","abroad"):raise ValueError("موقعیت سرور باید ایران یا خارج باشد")
    if auto_geoip:
        try:
            geoip_result=geoip_location(new_host)
            new_location=geoip_result["location"]
        except Exception as e:geoip_error=str(e)
    if new_proxy_id:
        proxy=servers.get(new_proxy_id)
        if not proxy or new_proxy_id==server_id:raise ValueError("سرور پروکسی باید از فهرست انتخاب شود و با مقصد فرق کند")
        if proxy.get("proxy_server_id") or proxy.get('proxy_line_id'):raise ValueError("زنجیرهٔ پروکسی SSH بیش از یک مرحله پشتیبانی نمی‌شود")
    candidate={**current,"host":new_host,"user":new_user,"proxy_server_id":new_proxy_id,'proxy_line_id':new_proxy_line_id,"location":new_location}
    connection_unchanged=all(candidate.get(k)==current.get(k) for k in ("host","user","proxy_server_id","proxy_line_id"))
    unchanged=connection_unchanged and new_location==current.get("location","abroad") and bool(auto_geoip)==bool(current.get("auto_geoip",1)) and (not auto_geoip or (current.get("geoip_host")==new_host and current.get("geo_latitude") is not None and current.get("geo_longitude") is not None))
    geo_values=(geoip_result["country_code"],geoip_result["country_name"],geoip_result["city"],geoip_result["latitude"],geoip_result["longitude"]) if geoip_result else ((current.get("geo_country_code"),current.get("geo_country_name"),current.get("geo_city"),current.get("geo_latitude"),current.get("geo_longitude")) if new_host==old_host else (None,None,None,None,None))
    geoip_host=new_host if geoip_result else (current.get("geoip_host","") if new_host==old_host else "")
    password=str(password or "")
    if len(password)>1024:raise ValueError("گذرواژه SSH بیش از حد طولانی است")
    if unchanged and not password:return {"ok":True,"location":new_location,"geoip":geoip_result,"geoip_error":geoip_error,"updated_tunnels":0,"updated_endpoints":0,"restarted_endpoints":0,"unchanged":True}
    if connection_unchanged and not password:
        with db() as c:c.execute("UPDATE servers SET location=?,auto_geoip=?,geoip_host=?,geo_country_code=?,geo_country_name=?,geo_city=?,geo_latitude=?,geo_longitude=? WHERE id=?",(new_location,int(auto_geoip),geoip_host,*geo_values,server_id))
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
    previous_connection={k:current.get(k,"") for k in ("host","user","proxy_server_id","proxy_line_id","location","auto_geoip","geoip_host","geo_country_code","geo_country_name","geo_city","geo_latitude","geo_longitude")}
    with db() as c:c.execute("UPDATE servers SET host=?,user=?,proxy_server_id=?,proxy_line_id=?,location=?,auto_geoip=?,geoip_host=?,geo_country_code=?,geo_country_name=?,geo_city=?,geo_latitude=?,geo_longitude=? WHERE id=?",(new_host,new_user,new_proxy_id,new_proxy_line_id,new_location,int(auto_geoip),geoip_host,*geo_values,server_id))
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
        with db() as c:c.execute("UPDATE servers SET host=?,user=?,proxy_server_id=?,proxy_line_id=?,location=?,auto_geoip=?,geoip_host=?,geo_country_code=?,geo_country_name=?,geo_city=?,geo_latitude=?,geo_longitude=? WHERE id=?",(previous_connection["host"],previous_connection["user"],previous_connection["proxy_server_id"],previous_connection["proxy_line_id"],previous_connection["location"],previous_connection["auto_geoip"],previous_connection["geoip_host"],previous_connection["geo_country_code"],previous_connection["geo_country_name"],previous_connection["geo_city"],previous_connection["geo_latitude"],previous_connection["geo_longitude"],server_id))
        suffix=("؛ بازگردانی ناقص: "+" | ".join(rollback_errors)) if rollback_errors else ""
        raise RuntimeError("به‌روزرسانی اتصال سرور ناموفق شد؛ تغییر اتصال و تونل‌های انجام‌شده برگردانده شدند: "+str(error)+suffix)
    return {"ok":True,"server":server_id,"old_host":old_host,"host":new_host,"user":new_user,"proxy_server_id":new_proxy_id,'proxy_line_id':new_proxy_line_id,"location":new_location,"geoip":geoip_result,"geoip_error":geoip_error,"updated_tunnels":len({x[2] for x in endpoints}),"updated_endpoints":len(endpoints),"restarted_endpoints":len(endpoints),"unavailable_servers":[]}

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
            b=obj if isinstance(obj,bytes) else json.dumps(obj,ensure_ascii=False).encode();self.send_response(status);self.send_header("Content-Type",ctype);self.send_header("Cache-Control","no-store");self.send_header("Content-Length",str(len(b)));self.send_header("X-Content-Type-Options","nosniff")
            if self.is_secure():self.send_header("Strict-Transport-Security","max-age=15552000")
            self.end_headers();self.wfile.write(b)
        def is_secure(self):
            if isinstance(self.connection,ssl.SSLSocket):return True
            try:return ipaddress.ip_address(self.client_address[0]).is_loopback and self.headers.get('X-Forwarded-Proto','').lower()=='https'
            except ValueError:return False
        def parse_request(self):
            if not super().parse_request():return False
            if self.is_secure():return True
            try:
                peer=ipaddress.ip_address(self.client_address[0])
                # Local services (including the Telegram bot) call the panel
                # over loopback. SSH port forwards also terminate here, with
                # SSH providing transport encryption for the browser session.
                if peer.is_loopback:return True
                tls=json.loads(pathlib.Path('/var/lib/tunnelmgr/panel-tls-status.json').read_text())
                domain=tls.get('domain','');port=int(tls.get('port',0))
                cert=pathlib.Path('/etc/tunnelmgr/panel-tls/fullchain.pem');key=pathlib.Path('/etc/tunnelmgr/panel-tls/privkey.pem')
                if tls.get('state')!='ready' or not cert.is_file() or not key.is_file() or not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain) or not 1024<=port<=65535:return True
                target=self.path if self.path.startswith('/') and not self.path.startswith('//') and not any(ord(c)<32 for c in self.path) else '/'
                self.send_response(308,'Permanent Redirect');self.send_header('Location',f'https://{domain}:{port}{target}');self.send_header('Cache-Control','no-store');self.send_header('Content-Length','0');self.end_headers();self.close_connection=True
                return False
            except Exception:pass
            try:remote=not ipaddress.ip_address(self.client_address[0]).is_loopback
            except ValueError:remote=True
            if remote:
                host=self.headers.get('Host','').strip()
                if host and re.fullmatch(r'(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::\d{1,5})?',host):
                    target=self.path if self.path.startswith('/') and not self.path.startswith('//') and not any(ord(c)<32 for c in self.path) else '/'
                    self.send_response(308,'Permanent Redirect');self.send_header('Location',f'https://{host}{target}');self.send_header('Cache-Control','no-store');self.send_header('Content-Length','0');self.end_headers();self.close_connection=True
                    return False
            return True
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
            if entry['expires']<time.time():SESSIONS.pop(value,None);return None
            if entry.get('telegram_id') and entry.get('telegram_role') in ('admin','viewer'):
                try:
                    config=load_telegram_miniapp_config()
                    current=telegram_miniapp_role(config,entry['telegram_id'])
                except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError):
                    current=None
                if current!=entry['telegram_role']:
                    SESSIONS.pop(value,None)
                    return None
                return current
            with db() as c:account_row=c.execute("SELECT role,totp_enabled FROM accounts WHERE name=?",(entry['name'],)).fetchone()
            if not account_row:SESSIONS.pop(value,None);return None
            if account_row['role']=='admin' and not account_row['totp_enabled'] and entry['name']!='avatun-telegram':return 'mfa_setup'
            if account_row['totp_enabled'] and not entry.get('mfa_verified'):return 'mfa_verify'
            return account_row['role']
        def session(self):
            from http.cookies import SimpleCookie
            cookie=SimpleCookie(self.headers.get("Cookie",""));m=cookie.get("tunnelmgr_session")
            entry=SESSIONS.get(m.value) if m else None
            return entry if entry and entry['expires']>=time.time() else None
        def session_cookie(self,token):
            secure='; Secure' if self.is_secure() else '';entry=SESSIONS.get(token,{})
            max_age=max(0,int(entry.get('expires',time.time()+43200)-time.time()))
            self.send_header('Set-Cookie',f'tunnelmgr_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}')
        def do_GET(self):
            from urllib.parse import urlsplit, parse_qs
            request=urlsplit(self.path)
            route=request.path
            if route=="/telegram-miniapp":
                f=pathlib.Path(__file__).resolve().parents[1]/"web/telegram-miniapp.html"
                if not f.is_file():return self.send(404,{"error":"Telegram Mini App is not installed"})
                return self.send(200,f.read_bytes(),"text/html; charset=utf-8")
            if route=="/":
                # Older bookmarks may still append credentials to the panel URL.
                # Never keep those credentials in the address bar or access logs.
                query=parse_qs(request.query,keep_blank_values=True)
                if "password" in query or "username" in query:
                    self.send_response(302);self.send_header("Location","/#settings");self.send_header("Cache-Control","no-store");self.send_header("Content-Length","0");self.end_headers();return
                f=pathlib.Path(__file__).resolve().parents[1]/"web/index.html";return self.send(200,f.read_bytes(),"text/html; charset=utf-8")
            if route=="/assets/Yekan.woff2":
                f=pathlib.Path(__file__).resolve().parents[1]/"web/assets/Yekan.woff2";return self.send(200,f.read_bytes(),"font/woff2")
            if route in ("/assets/avatun-logo.png",):
                f=pathlib.Path(__file__).resolve().parents[1]/"web"/route.lstrip("/");return self.send(200,f.read_bytes(),"image/png")
            if route=="/assets/world_neon_4096x2048.svg":
                f=pathlib.Path(__file__).resolve().parents[1]/"web/assets/world_neon_4096x2048.svg";return self.send(200,f.read_bytes(),"image/svg+xml")
            if route in ("/assets/mesh-central.svg", "/assets/mesh-iran.svg", "/assets/mesh-abroad.svg", "/assets/mesh-proxy.svg"):
                f=pathlib.Path(__file__).resolve().parents[1]/"web"/route.lstrip("/");return self.send(200,f.read_bytes(),"image/svg+xml")
            if route=="/admin":
                self.send_response(302);self.send_header("Location","/#accounts");self.send_header("Content-Length","0");self.end_headers();return
            if route=="/health":return self.send(200,{"ok":True})
            if route=="/api/v1/auth/session":
                s=self.session();return self.send(200,{"ok":bool(s),"username":s['name'] if s else None,"role":self.role() if s else None})
            role=self.role()
            if not role:return self.send(401,{"error":"sign in required"})
            if role in ('mfa_setup','mfa_verify') and route not in ('/api/v1/auth/mfa','/api/v1/settings/panel-tls'):
                return self.send(403,{"error":"Complete multi-factor authentication before using the panel"})
            if route=="/api/v1/auth/mfa":
                session=self.session()
                with db() as c:row=c.execute("SELECT role,totp_enabled,totp_pending,totp_pending_at FROM accounts WHERE name=?",(session['name'],)).fetchone()
                return self.send(200,{'username':session['name'],'enabled':bool(row['totp_enabled']),'required':row['role']=='admin','setup_pending':bool(row['totp_pending'] and row['totp_pending_at']>=int(time.time())-600),'https_required':not isinstance(self.connection,ssl.SSLSocket)})
            if route=="/api/v1/settings/panel-tls":
                if role not in ("admin","mfa_setup"):return self.send(403,{"error":"admin role required"})
                try:return self.send(200,privileged({'op':'panel-tls','id':'panel-tls','action':'status'}))
                except Exception as e:return self.send(502,{'error':str(e)})
            if route=="/api/v1/settings/telegram":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:return self.send(200,privileged({'op':'telegram-config','id':'telegram-config','action':'status'}))
                except Exception as e:return self.send(502,{'error':str(e)})
            if route=="/api/v1/settings/theme":
                session=self.session();return self.send(200,{'palette':account_theme(session['name'])})
            if route=="/api/v1/updates":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:return self.send(200,github_update_status())
                except Exception as e:return self.send(502,{'error':str(e)})
            if route=="/api/v1/telegram/snapshot":
                with MONITOR_LOCK:
                    health=dict(MONITOR_TUNNELS)
                    statuses=[dict(item) for item in MONITOR_SERVERS]
                    resources=[dict(item) for item in MONITOR_RESOURCES]
                local=[dict(item,server_id="local",health=health.get(item["id"],{"state":"unknown"}),traffic=traffic_totals('tunnel',item['id'])) for item in rows()]
                remote=[dict(tunnel,server_id=status["id"],traffic=traffic_totals('tunnel',tunnel['id'])) for status in statuses if status["id"]!="local" for tunnel in status.get("tunnels",[])]
                servers=[{k:v for k,v in server.items() if k!="identity"}|{"has_identity":bool(server.get("identity"))} for server in server_rows()]
                return self.send(200,{"servers":servers,"statuses":statuses,"tunnels":[*local,*remote],"resources":resources})
            if route=="/api/v1/routing":
                if role not in ("admin","operator"):return self.send(403,{"error":"insufficient permissions"})
                return self.send(200,{"items":routing_rows()})
            if route=="/api/v1/forwards":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                from urllib.parse import parse_qs
                server_id=parse_qs(self.path.partition("?")[2]).get("server_id",["local"])[0]
                if server_id!="local" and not ID.fullmatch(server_id):return self.send(400,{"error":"invalid server id"})
                return self.send(200,{"items":attach_forward_traffic(forward_rows()),"service":forward_service_status(server_id)})
            if route=="/api/v1/proxy-lines":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:return self.send(200,{'items':proxy_line_summaries(),'service':privileged({'op':'xray-config','id':'xray','action':'status'})})
                except Exception as e:return self.send(502,{'error':str(e)})
            if route=="/api/v1/proxy-forwards":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                server_id=parse_qs(request.query).get('server_id',['local'])[0]
                if server_id=='all':return self.send(200,{'items':proxy_forward_rows(),'service':None})
                if server_id!='local' and not ID.fullmatch(server_id):return self.send(400,{'error':'invalid server id'})
                service=privileged({'op':'xray-config','id':'xray','action':'status'}) if server_id=='local' else None
                if server_id!='local':
                    server=next((item for item in server_rows() if item['id']==server_id),None)
                    if not server:return self.send(404,{'error':'server not found'})
                    try:service=server_remote(server,{'op':'xray-config','action':'status'})
                    except Exception as e:service={'ok':False,'active':False,'state':'unreachable','error':str(e)}
                return self.send(200,{'items':[item for item in proxy_forward_rows() if item.get('server_id','local')==server_id],'service':service})
            if route=="/api/v1/tunnels/snapshot":
                with MONITOR_LOCK:
                    health=dict(MONITOR_TUNNELS)
                    statuses=list(MONITOR_SERVERS)
                local=attach_speedtests([dict(item,server_id="local",health=health.get(item["id"],{"state":"unknown"}),traffic=traffic_totals('tunnel',item['id'])) for item in rows()])
                remote=attach_speedtests([dict(item,server_id=status["id"],traffic=traffic_totals('tunnel',item['id'])) for status in statuses if status["id"]!="local" for item in status.get("tunnels",[])])
                return self.send(200,{"items":[*local,*remote]})
            if route=="/api/v1/tunnels":return self.send(200,{"items":attach_speedtests([dict(item,traffic=traffic_totals('tunnel',item['id'])) for item in rows()])})
            if route=="/api/v1/servers":
                settings=resource_report_settings()
                metrics=resource_report_metrics()
                return self.send(200,{"items":[{k:v for k,v in s.items() if k!="identity"}|{"has_identity":bool(s.get("identity")),"telegram_resources_enabled":settings.get(s['id'],True),"telegram_resource_metrics":metrics.get(s['id'],list(RESOURCE_REPORT_METRICS))} for s in server_rows()]})
            if route=="/api/v1/geoip/local":
                try:
                    result=geoip_location()
                    return self.send(200,{k:v for k,v in result.items() if k!="ip"})
                except Exception as e:return self.send(200,{"error":str(e)})
            if route=="/api/v1/servers/status":
                with MONITOR_LOCK:statuses=[dict(item,tunnels=attach_speedtests(item.get("tunnels",[]))) for item in MONITOR_SERVERS]
                return self.send(200,{"items":statuses})
            if route=="/api/v1/servers/resources":
                settings=resource_report_settings()
                metrics=resource_report_metrics()
                with MONITOR_LOCK:resources=[dict(item,telegram_resources_enabled=settings.get(item['id'],True),telegram_resource_metrics=metrics.get(item['id'],list(RESOURCE_REPORT_METRICS))) for item in MONITOR_RESOURCES]
                return self.send(200,{"items":resources})
            bits=route.strip("/").split("/")
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
                    interface=tunnel_interface(item)
                    item['interface_addresses']=interface_ip_addresses(interface) if interface else []
                    item['tun_addresses']=item['interface_addresses']
                    with MONITOR_LOCK:health=MONITOR_TUNNELS.get(ident)
                    item["health"]=health if health is not None else tunnel_health(item)
                    item["speedtest"]=tunnel_speedtest_rows().get(ident)
                    item["traffic"]=traffic_totals('tunnel',ident)
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
            if self.path=="/api/v1/telegram/miniapp/auth":
                try:
                    data=self.body();init_data=data.get('init_data')
                    config=load_telegram_miniapp_config()
                    verified=verify_init_data(init_data,config['bot_token'])
                    user_id=verified['user_id'];mini_role=telegram_miniapp_role(config,user_id)
                    if mini_role is None:return self.send(403,{'error':'این حساب تلگرام برای Mini App مجاز نیست.'})
                    token=_new_session('avatun-telegram',mini_role,True)
                    SESSIONS[token].update({'telegram_id':user_id,'telegram_role':mini_role})
                    self.send_response(200);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.session_cookie(token)
                    payload=json.dumps({'ok':True,'role':mini_role,'telegram_id':user_id,'display_name':str((verified.get('user') or {}).get('first_name') or '')[:80]},ensure_ascii=False).encode();self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload);return
                except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as e:
                    return self.send(401,{'error':str(e)[:180]})
            if self.path=="/api/v1/auth/login":
                try:
                    data=self.body();name=data.get("username","");password=data.get("password","")
                    with db() as c:row=c.execute("SELECT role,digest,totp_enabled FROM accounts WHERE name=?",(name,)).fetchone()
                    if not row or not verify_password(password,row["digest"]):return self.send(401,{"error":"نام کاربری یا گذرواژه نادرست است"})
                    if row['totp_enabled']:
                        if not isinstance(self.connection,ssl.SSLSocket):return self.send(400,{'error':'برای ورود دومرحله‌ای باید پنل را با HTTPS باز کنی.'})
                        challenge=secrets.token_urlsafe(32);PENDING_LOGINS[challenge]={'name':name,'role':row['role'],'expires':time.time()+300,'attempts':0}
                        return self.send(200,{'ok':True,'mfa_required':True,'challenge':challenge,'username':name})
                    service_account=name=='avatun-telegram'
                    session=_new_session(name,row["role"],row['role']!='admin' or service_account)
                    self.send_response(200);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Cache-Control","no-store")
                    self.session_cookie(session)
                    role='mfa_setup' if row['role']=='admin' and not service_account else row['role']
                    payload=json.dumps({"ok":True,"username":name,"role":role,'mfa_setup_required':role=='mfa_setup'},ensure_ascii=False).encode();self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload);return
                except Exception as e:return self.send(400,{"error":str(e)})
            if self.path=="/api/v1/auth/mfa/verify":
                try:
                    if not isinstance(self.connection,ssl.SSLSocket):return self.send(400,{'error':'برای ورود دومرحله‌ای باید پنل را با HTTPS باز کنی.'})
                    data=self.body();challenge=data.get('challenge','');pending=PENDING_LOGINS.get(challenge)
                    if not pending or pending['expires']<time.time():PENDING_LOGINS.pop(challenge,None);return self.send(401,{'error':'درخواست ورود منقضی شده؛ دوباره وارد شو.','restart_login':True})
                    pending['attempts']+=1
                    if pending['attempts']>5:PENDING_LOGINS.pop(challenge,None);return self.send(429,{'error':'تعداد تلاش‌ها زیاد شد؛ دوباره وارد شو.'})
                    with db() as c:
                        c.execute('BEGIN IMMEDIATE');row=c.execute('SELECT role,totp_secret,totp_enabled,totp_last_step,recovery_codes FROM accounts WHERE name=?',(pending['name'],)).fetchone()
                        if not row or not row['totp_enabled']:PENDING_LOGINS.pop(challenge,None);return self.send(401,{'error':'احراز هویت دومرحله‌ای در این حساب فعال نیست.','restart_login':True})
                        last_step=row['totp_last_step'];secret=_mfa_open(row['totp_secret']);matched=_totp_match(secret,data.get('code',''),last_step)
                        if matched=='replay':return self.send(401,{'error':'این کد قبلاً استفاده شده؛ صبر کن کد برنامه عوض شود و کد تازه را وارد کن.'})
                        if matched is not None:c.execute('UPDATE accounts SET totp_last_step=? WHERE name=?',(matched,pending['name']))
                        else:
                            codes=json.loads(row['recovery_codes'] or '[]');remaining=_recovery_consume(codes,data.get('code',''))
                            if remaining is None:return self.send(401,{'error':'کد برنامه نادرست است؛ کد تازه را وارد کن یا از کد بازیابی استفاده کن.'})
                            c.execute('UPDATE accounts SET recovery_codes=? WHERE name=?',(json.dumps(remaining),pending['name']))
                    PENDING_LOGINS.pop(challenge,None);session=_new_session(pending['name'],pending['role'],True)
                    self.send_response(200);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.session_cookie(session)
                    payload=json.dumps({'ok':True,'username':pending['name'],'role':pending['role']}).encode();self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload);return
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/auth/logout":
                from http.cookies import SimpleCookie
                cookie=SimpleCookie(self.headers.get("Cookie",""));m=cookie.get("tunnelmgr_session")
                if m:SESSIONS.pop(m.value,None)
                self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Set-Cookie","tunnelmgr_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"+('; Secure' if isinstance(self.connection,ssl.SSLSocket) else ''));self.send_header("Content-Length","11");self.end_headers();self.wfile.write(b'{"ok":true}');return
            role=self.role()
            if not role:return self.send(401,{"error":"unauthorized"})
            if role in ('mfa_setup','mfa_verify') and self.path!='/api/v1/auth/mfa' and not (role=='mfa_setup' and self.path=='/api/v1/settings/panel-tls'):
                return self.send(403,{'error':'Complete multi-factor authentication before using the panel'})
            if self.path=="/api/v1/auth/mfa":
                try:
                    if not isinstance(self.connection,ssl.SSLSocket):return self.send(400,{'error':'برای فعال‌سازی یا مدیریت TOTP باید پنل را با HTTPS باز کنی.'})
                    data=self.body();session=self.session();name=session['name'];action=data.get('action')
                    with db() as c:
                        c.execute('BEGIN IMMEDIATE');row=c.execute('SELECT role,digest,totp_secret,totp_pending,totp_pending_at,totp_enabled,totp_last_step,recovery_codes FROM accounts WHERE name=?',(name,)).fetchone()
                        if not row:return self.send(401,{'error':'account no longer exists'})
                        if action=='begin':
                            if row['totp_enabled']:raise ValueError('ورود دومرحله‌ای از قبل فعال است؛ کدهای بازیابی را بچرخان یا از مدیر بخواه آن را بازنشانی کند.')
                            if role!='mfa_setup' and not verify_password(data.get('current_password',''),row['digest']):raise ValueError('گذرواژهٔ فعلی درست نیست.')
                            secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
                            uri='otpauth://totp/'+urllib.parse.quote('avaTUN:'+name,safe='')+'?'+urllib.parse.urlencode({'secret':secret,'issuer':'avaTUN','algorithm':'SHA1','digits':6,'period':30})
                            qr=_qr_svg(uri);c.execute('UPDATE accounts SET totp_pending=?,totp_pending_at=? WHERE name=?',(_mfa_seal(secret),int(time.time()),name))
                            return self.send(200,{'ok':True,'secret':secret,'qr_svg_base64':qr})
                        if action=='confirm':
                            if not row['totp_pending'] or row['totp_pending_at']<int(time.time())-600:raise ValueError('مهلت راه‌اندازی تمام شده؛ دوباره شروع کن.')
                            secret=_mfa_open(row['totp_pending']);matched=_totp_match(secret,data.get('code',''))
                            if matched is None:raise ValueError('کد برنامه درست نیست یا ساعت دستگاه هماهنگ نیست.')
                            plain_codes,hashed_codes=_recovery_codes();c.execute('UPDATE accounts SET totp_secret=totp_pending,totp_pending="",totp_pending_at=0,totp_enabled=1,totp_last_step=?,recovery_codes=? WHERE name=?',(matched,json.dumps(hashed_codes),name))
                            session_token=next((k for k,v in SESSIONS.items() if v is session),None);session['mfa_verified']=True;session['expires']=time.time()+12*3600
                            for key,entry in SESSIONS.items():
                                if entry.get('name')==name and key!=session_token:entry['mfa_verified']=False
                            self.send_response(200);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store')
                            if session_token:self.session_cookie(session_token)
                            payload=json.dumps({'ok':True,'enabled':True,'role':row['role'],'recovery_codes':plain_codes}).encode();self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload);return
                        if action=='verify-session':
                            if not row['totp_enabled']:raise ValueError('ورود دومرحله‌ای برای این حساب فعال نیست.')
                            secret=_mfa_open(row['totp_secret']);matched=_totp_match(secret,data.get('code',''),row['totp_last_step'])
                            if matched=='replay':raise ValueError('این کد قبلاً استفاده شده؛ کد تازه یا کد بازیابی را وارد کن.')
                            if matched is not None:c.execute('UPDATE accounts SET totp_last_step=? WHERE name=?',(matched,name))
                            else:
                                codes=json.loads(row['recovery_codes'] or '[]');remaining=_recovery_consume(codes,data.get('code',''))
                                if remaining is None:raise ValueError('کد نادرست است یا قبلاً استفاده شده.')
                                c.execute('UPDATE accounts SET recovery_codes=? WHERE name=?',(json.dumps(remaining),name))
                            session['mfa_verified']=True;session['expires']=time.time()+12*3600
                            token=next((k for k,v in SESSIONS.items() if v is session),None)
                            self.send_response(200);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store')
                            if token:self.session_cookie(token)
                            payload=json.dumps({'ok':True,'username':name,'role':row['role']}).encode();self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload);return
                        if action=='rotate-recovery':
                            if not row['totp_enabled']:raise ValueError('ورود دومرحله‌ای برای این حساب فعال نیست.')
                            matched=_totp_match(_mfa_open(row['totp_secret']),data.get('code',''),row['totp_last_step'])
                            if matched=='replay':raise ValueError('این کد قبلاً استفاده شده؛ کد تازه را وارد کن.')
                            if matched is None:raise ValueError('کد برنامه درست نیست یا قبلاً استفاده شده.')
                            plain_codes,hashed_codes=_recovery_codes();c.execute('UPDATE accounts SET totp_last_step=?,recovery_codes=? WHERE name=?',(matched,json.dumps(hashed_codes),name))
                            return self.send(200,{'ok':True,'recovery_codes':plain_codes})
                        if action=='disable':
                            if row['role']=='admin':raise ValueError('برای مدیر، ورود دومرحله‌ای اجباری است.')
                            if not verify_password(data.get('current_password',''),row['digest']):raise ValueError('گذرواژهٔ فعلی درست نیست.')
                            matched=_totp_match(_mfa_open(row['totp_secret']),data.get('code',''),row['totp_last_step'])
                            if matched=='replay':raise ValueError('این کد قبلاً استفاده شده؛ کد تازه را وارد کن.')
                            if not row['totp_enabled'] or matched is None:raise ValueError('کد برنامه درست نیست یا قبلاً استفاده شده.')
                            c.execute("UPDATE accounts SET totp_secret='',totp_pending='',totp_pending_at=0,totp_enabled=0,totp_last_step=-1,recovery_codes='[]' WHERE name=?",(name,))
                            session['mfa_verified']=True
                            return self.send(200,{'ok':True,'enabled':False})
                        raise ValueError('عملیات MFA نامعتبر است.')
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/settings/panel-tls":
                if role not in ("admin","mfa_setup"):return self.send(403,{"error":"admin role required"})
                try:
                    data=self.body();result=privileged({'op':'panel-tls','id':'panel-tls','action':'apply','domain':data.get('domain'),'email':data.get('email'),'port':data.get('port')},timeout=30)
                    if result.get('error'):return self.send(400,result)
                    return self.send(202,result)
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/settings/telegram":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:
                    data=self.body()
                    result=privileged({'op':'telegram-config','id':'telegram-config','action':'save',
                        'bot_token':data.get('bot_token',''),'admin_ids':data.get('admin_ids')})
                    if result.get('error'):return self.send(400,result)
                    return self.send(202,result)
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/settings/theme":
                if role not in ("admin","operator","viewer"):return self.send(403,{"error":"sign in required"})
                try:
                    data=self.body();session=self.session()
                    return self.send(200,{'ok':True,'palette':set_account_theme(session['name'],data.get('palette','teal'))})
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/servers/resources":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:
                    data=self.body();server_id=data.get('server_id','');enabled=data.get('telegram_resources_enabled');metrics=data.get('telegram_resource_metrics')
                    if not isinstance(server_id,str) or (enabled is not None and not isinstance(enabled,bool)) or (metrics is not None and not isinstance(metrics,list)):raise ValueError('تنظیم گزارش منابع نامعتبر است')
                    if enabled is not None:set_resource_report_enabled(server_id,enabled)
                    if metrics is not None:set_resource_report_metrics(server_id,metrics)
                    settings=resource_report_settings();selected=resource_report_metrics().get(server_id,list(RESOURCE_REPORT_METRICS))
                    with MONITOR_LOCK:resources=[dict(item) for item in MONITOR_RESOURCES]
                    return self.send(200,{'ok':True,'server_id':server_id,'telegram_resources_enabled':settings.get(server_id,True),'telegram_resource_metrics':selected,'items':resources})
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/updates":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                try:
                    data=self.body()
                    action=data.get('action')
                    if action not in ('check','apply'):raise ValueError('عملیات به‌روزرسانی نامعتبر است.')
                    result=privileged({'op':'github-update','id':'github-update','action':'start' if action=='apply' else 'check'},timeout=20)
                    if result.get('error'):return self.send(400,result)
                    return self.send(202,result)
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/proxy-lines":
                if role!="admin":return self.send(403,{'error':'admin role required'})
                try:
                    data=self.body();action=data.get('action')
                    if action=='create':return self.send(201,create_proxy_line(data.get('id',''),data.get('link','')))
                    if action=='delete':return self.send(200,delete_proxy_line(data.get('id','')))
                    raise ValueError('عملیات خط پروکسی نامعتبر است')
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/proxy-forwards":
                if role!="admin":return self.send(403,{'error':'admin role required'})
                try:
                    data=self.body();action=data.get('action');server_id=data.get('server_id','local')
                    if action in ('create','update'):
                        result=save_proxy_forward(data,action)
                        return self.send(201 if action=='create' else 200,result)
                    if action=='delete':return self.send(200,delete_proxy_forward(data.get('id',''),server_id))
                    raise ValueError('عملیات فوروارد خط پروکسی نامعتبر است')
                except Exception as e:return self.send(400,{'error':str(e)})
            if self.path=="/api/v1/forwards":
                if role!="admin":return self.send(403,{"error":"admin role required"})
                FORWARD_LOCK.acquire()
                try:
                    data=self.body();action=data.get("action");ident=data.get("id","");server_id=data.get("server_id","local")
                    if not isinstance(server_id,str) or (server_id!="local" and not ID.fullmatch(server_id)):raise ValueError("شناسهٔ سرور شنود نامعتبر است")
                    if server_id!="local" and not any(s["id"]==server_id for s in server_rows()):raise ValueError("سرور شنود در فهرست مدیریت‌شده‌ها نیست")
                    if action=="set-enabled":
                        return self.send(200,set_forward_enabled(ident,server_id,data.get("enabled")))
                    if action in ("create","update"):
                        if server_id=="local":available_tunnels=rows()
                        else:
                            target=next(s for s in server_rows() if s["id"]==server_id)
                            available_tunnels=server_remote(target,{"op":"list"}).get("items",[])
                            if not isinstance(available_tunnels,list):raise ValueError("فهرست تونل‌های سرور انتخاب‌شده معتبر نیست")
                        cleanup=prune_missing_forward_backends_locked(server_id,{item.get("id") for item in available_tunnels if isinstance(item,dict)})
                        config=normalize_forward(data,server_id,allow_missing_backends=action=="update")
                        current=forward_rows();exists=next((x for x in current if x["id"]==config["id"]),None)
                        if action=="create" and exists:raise ValueError("این شناسه از قبل ثبت شده است")
                        if action=="update" and (not exists or exists.get("server_id","local")!=server_id):raise ValueError("قانون پورت‌فوروارد روی این سرور پیدا نشد")
                        if exists and "enabled" not in data:config["enabled"]=exists.get("enabled",True)
                        desired=[x for x in current if x.get("server_id","local")==server_id and x["id"]!=config["id"]]+[config]
                        apply_forward_set(server_id,desired)
                        with db() as c:c.execute("INSERT INTO port_forwards(id,config) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET config=excluded.config",(config["id"],json.dumps(config)))
                        return self.send(201 if action=="create" else 200,{"ok":True,"item":config,"ha_cleanup":cleanup})
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
                finally:FORWARD_LOCK.release()
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
                try:
                    if remote_op[3]=='restart':
                        data=self.body();return self.send(200,rebuild_tunnel_pair(remote_op[2],data.get('servers')))
                    cleanup=remove_tunnel_from_forward_backends(remote_op[1],remote_op[2]) if remote_op[3]=='delete' else None
                    result=server_remote(srv,{"op":"operate","id":remote_op[2],"action":remote_op[3]})
                    if cleanup:result["ha_cleanup"]=cleanup
                    return self.send(200,result)
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
                        user=data.get("user",current["user"]);proxy_id=data.get("proxy_server_id",current.get("proxy_server_id",""));proxy_line_id=data.get('proxy_line_id',current.get('proxy_line_id',''));password=data.get("ssh_password","");location=data.get("location",current.get("location","abroad"));auto_geoip=data.get("auto_geoip",bool(current.get("auto_geoip",1)))
                        if not isinstance(user,str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}",user):raise ValueError("نام کاربری SSH نامعتبر است")
                        if not isinstance(proxy_id,str):raise ValueError("سرور پروکسی نامعتبر است")
                        if not isinstance(proxy_line_id,str):raise ValueError('خط پروکسی نامعتبر است')
                        if not isinstance(password,str):raise ValueError("گذرواژه SSH نامعتبر است")
                        if not isinstance(auto_geoip,bool):raise ValueError("گزینهٔ GeoIP نامعتبر است")
                        return self.send(200,update_server_host(ident,host,user,proxy_id,password,location,auto_geoip,proxy_line_id))
                    if action=="add":
                        host=data.get("host","");user=data.get("user","root");identity=data.get("identity","");proxy_id=data.get("proxy_server_id","");proxy_line_id=data.get('proxy_line_id','');location=data.get("location","abroad")
                        auto_geoip=data.get("auto_geoip",True)
                        if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError("شناسه سرور نامعتبر است")
                        if not isinstance(host,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}",host):raise ValueError("آدرس سرور نامعتبر است")
                        if not isinstance(user,str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}",user):raise ValueError("نام کاربری SSH نامعتبر است")
                        if not isinstance(proxy_id,str):raise ValueError("سرور پروکسی نامعتبر است")
                        if not isinstance(proxy_line_id,str):raise ValueError('خط پروکسی نامعتبر است')
                        if proxy_id and proxy_line_id:raise ValueError('برای SSH فقط یک مسیر پروکسی انتخاب کن')
                        if proxy_line_id:
                            proxy_line(proxy_line_id)
                            state=privileged({'op':'xray-config','id':'xray','action':'status'})
                            if not state.get('active'):raise ValueError('خط پروکسی روی سرور مرکزی فعال نیست')
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
                            if proxy.get("proxy_server_id") or proxy.get('proxy_line_id'):raise ValueError("سرور پروکسی انتخابی خودش نباید از پروکسی دیگری عبور کند")
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
                            srv=bootstrap_server({"id":ident,"host":host,"user":user,"identity":"","proxy_server_id":proxy_id,'proxy_line_id':proxy_line_id},data["ssh_password"])
                            identity=srv["identity"]
                        else:raise ValueError("گذرواژهٔ SSH یا کلید خصوصی را وارد کن")
                        geo_values=(geoip_result["country_code"],geoip_result["country_name"],geoip_result["city"],geoip_result["latitude"],geoip_result["longitude"]) if geoip_result else (None,None,None,None,None)
                        with db() as c:c.execute("INSERT INTO servers(id,host,user,identity,proxy_server_id,proxy_line_id,location,auto_geoip,geoip_host,geo_country_code,geo_country_name,geo_city,geo_latitude,geo_longitude) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(ident,host,user,identity,proxy_id,proxy_line_id,location,int(auto_geoip),host if geoip_result else "",*geo_values))
                        if data.get("install"):
                            srv={"id":ident,"host":host,"user":user,"identity":identity,"proxy_server_id":proxy_id,'proxy_line_id':proxy_line_id}
                            try:return self.send(201,{"ok":True,"server":ident,"location":location,"geoip":geoip_result,"geoip_error":geoip_error,"install":install_remote(srv)})
                            except Exception as e:return self.send(502,{"error":f"سرور ثبت شد اما نصب ناموفق بود: {e}"})
                        return self.send(201,{"ok":True,"server":ident,"location":location,"geoip":geoip_result,"geoip_error":geoip_error})
                    if action=="delete":
                        srv=next((x for x in server_rows() if x["id"]==ident),None)
                        if not srv:raise ValueError("سرور پیدا نشد")
                        dependents=[x["id"] for x in server_rows() if x.get("proxy_server_id")==ident]
                        if dependents:raise ValueError("ابتدا سرورهای عبوری را از پروکسی جدا کن: "+", ".join(dependents))
                        proxy_forwards=[x['id'] for x in proxy_forward_rows() if x.get('server_id')==ident]
                        if proxy_forwards:raise ValueError('ابتدا فورواردهای پروکسی این سرور را حذف کن: '+', '.join(proxy_forwards))
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
            speedtest_action=re.fullmatch(r"/api/v1/tunnels/([a-z0-9_-]+)/speedtest",self.path)
            operator_create=self.path in ("/api/v1/tunnels/native","/api/v1/tunnels/native-pair","/api/v1/tunnels/backhaul-pair","/api/v1/tunnels/rebuild","/api/v1/tunnels/backhaul","/api/v1/tunnels/secrets","/api/v1/tunnels/wireguard-pair","/api/v1/tunnels/openvpn-pair","/api/v1/tunnels/mtu-probe","/api/v1/routing") or bool(speedtest_action) or bool(re.fullmatch(r"/api/v1/servers/[a-z0-9][a-z0-9_-]{0,47}/tunnels/(native|backhaul)",self.path))
            if role!="admin" and (self.path!="/api/v1/mesh/plan" and not (role=="operator" and (operator_action or operator_create))):
                return self.send(403,{"error":"insufficient permissions"})
            try:
                if speedtest_action:
                    data=self.body()
                    if data.get('id')!=speedtest_action[1]:raise ValueError('speed test tunnel ID does not match request path')
                    with SPEEDTEST_LOCK:return self.send(200,tunnel_speedtest(data))
                if self.path=="/api/v1/admin/accounts":
                    data=self.body()
                    action=data.get("action")
                    with db() as c:
                        if action=="list":return self.send(200,{"items":[dict(r) for r in c.execute("SELECT name,role,totp_enabled FROM accounts ORDER BY name")]})
                        name=data.get("name","")
                        if not ID.fullmatch(name):raise ValueError("Invalid account name")
                        if action=="create" and data.get("role") in ("admin","viewer","operator"):
                            password=data.get("password","")
                            if len(password)<12:raise ValueError("password must contain at least 12 characters")
                            c.execute("INSERT INTO accounts(name,role,digest) VALUES(?,?,?)",(name,data["role"],password_digest(password)))
                            c.commit()
                            return self.send(201,{"ok":True})
                        if action=="mfa-reset":
                            if not c.execute("UPDATE accounts SET totp_secret='',totp_pending='',totp_pending_at=0,totp_enabled=0,totp_last_step=-1,recovery_codes='[]' WHERE name=?",(name,)).rowcount:raise ValueError("unknown account")
                            for key,value in list(SESSIONS.items()):
                                if value.get('name')==name:SESSIONS.pop(key,None)
                            c.commit();return self.send(200,{"ok":True})
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
                if self.path=="/api/v1/tunnels/backhaul-pair":return self.send(201,create_backhaul_pair(self.body()))
                if self.path=="/api/v1/tunnels/backhaul":return self.send(201,create_instance(self.body()))
                if self.path=="/api/v1/tunnels/rebuild":
                    data=self.body()
                    return self.send(200,rebuild_tunnel_pair(data.get('id'),data.get('servers'),data.get('configs'),data.get('operation','restart')))
                if self.path=="/api/v1/tunnels/native-pair":
                    data=self.body();return self.send(200 if data.get("action")=="update" else 201,create_native_pair(data))
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
                    if op=='restart':
                        data=self.body();return self.send(200,rebuild_tunnel_pair(ident,data.get('servers')))
                    if not find(ident):return self.send(404,{"error":"not found"})
                    item=find(ident)
                    native=item["metadata"].get("native_profile")
                    cleanup=remove_tunnel_from_forward_backends("local",ident) if op=="delete" else None
                    if op=="restart" and item["metadata"].get("transport")=="ipsec-esp-udp":
                        response=restart_ipsec_pair(ident)
                    elif op=="delete":
                        response=remove_tunnel_endpoint(ident,delete_secret=True)
                    else:
                        response=privileged({"op":"profile","group":"network","id":native,"action":{"status":"status"}.get(op,op)} if native else {"op":op,"id":ident})
                    if not response.get("ok",op=="status"):return self.send(400,response)
                    if op=="delete":
                        with db() as c:c.execute("DELETE FROM tunnel_speedtests WHERE id=?",(ident,))
                    if cleanup:response["ha_cleanup"]=cleanup
                    return self.send(200,{"ok":True,"id":ident,"operation":op,**response})
                return self.send(404,{"error":"not found"})
            except Exception as e:return self.send(400,{"error":str(e)})
        def log_message(self,fmt,*args):
            message=fmt%args
            message=re.sub(r"(?i)(password|token|secret)=([^&\s]+)",r"\1=[redacted]",message)
            print("api:",message,file=sys.stderr)
    print(f"API on http://{host}:{port} and https://{host}:{port}; password authentication enabled",flush=True)
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
    u=s.add_parser("account");u.add_argument("action",choices=("create","edit","revoke","list","password","mfa-reset"));u.add_argument("name",nargs="?");u.add_argument("--role",choices=("viewer","operator","admin"));u.add_argument("--set-password",action="store_true",help="prompt for a new password (edit only)");u.add_argument("--password",help=argparse.SUPPRESS);u.add_argument("--password-stdin",action="store_true",help=argparse.SUPPRESS)
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
