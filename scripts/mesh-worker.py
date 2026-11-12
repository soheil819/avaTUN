"""Forced SSH command for mesh-only deployment keys."""
import io,json,os,re,runpy,sys
import pathlib
if os.environ.get("SSH_ORIGINAL_COMMAND")!="tunnelmgr-mesh-v1":sys.exit(1)
raw=sys.stdin.buffer.read(4097)
if len(raw)>4096:sys.exit(1)
p=json.loads(raw);ident=p['id']
if not re.fullmatch(r'mesh-[a-z0-9_-]{1,43}',ident) or p['op'] not in ('check','create','delete'):sys.exit(1)
secret_path='/etc/backhaul/secrets/'+ident+'.token'
if p['op']=='create':
    cfg=p['config']
    if cfg.get('secret_file')!=secret_path or set(cfg)-{'id','mode','listen','peer','tun_name','tun_local','tun_remote','tun_mtu','health_port','secret_file'}:sys.exit(1)
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,64}',p['secret']):sys.exit(1)
if p['op']=='delete' and p.get('secret_file')!=secret_path:sys.exit(1)
sys.stdin=io.StringIO(json.dumps(p))
exec(runpy.run_path(str(pathlib.Path(__file__).with_name('mesh-deploy.py')))['REMOTE'])
