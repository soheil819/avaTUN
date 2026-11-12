import json,pathlib,re,sys,os
name=sys.argv[1]
if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,47}',name):sys.exit('invalid profile')
cfg=json.loads(pathlib.Path('/etc/tunnelmgr/mesh',name+'.json').read_text())
nodes=cfg['nodes']
if set(nodes)!=set(cfg['endpoints']):sys.exit('provide exactly one endpoint per node')
args=['/usr/bin/python3','/opt/tunnelmgr/scripts/mesh-deploy.py','--yes','--identity','/etc/tunnelmgr/mesh/ssh-key','--nodes',','.join(nodes),'--endpoints',','.join(n+'='+cfg['endpoints'][n] for n in nodes)]
for k in ('pool','direction','topology','hub'):
    if k in cfg:args.extend(['--'+k,cfg[k]])
os.environ["TUNNELMGR_PROFILE"]="1"
os.execv(args[0],args)
