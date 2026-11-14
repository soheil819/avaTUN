import subprocess as sp,json,pathlib,tempfile,time,secrets,sys,os
binary=sys.argv[1];prefix='at'+secrets.token_hex(3);ns=[prefix+'a',prefix+'b'];tmp=tempfile.TemporaryDirectory();root=pathlib.Path(tmp.name);processes=[]
def run(*args,check=True):return sp.run(args,check=check,capture_output=True,text=True)
def inside(n,*args,check=True):return run('ip','netns','exec',n,*args,check=check)
try:
 for n in ns:run('ip','netns','add',n);inside(n,'ip','link','set','lo','up')
 run('ip','link','add',prefix+'va','type','veth','peer','name',prefix+'vb')
 for i,n in enumerate(ns):
  iface=prefix+('va' if i==0 else 'vb');run('ip','link','set',iface,'netns',n);inside(n,'ip','addr','add',f'198.18.88.{i+1}/30','dev',iface);inside(n,'ip','link','set',iface,'up')
 cert=root/'cert.pem';key=root/'key.pem';run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert),'-days','1')
 for kind in ('tcp','tcpmux','xtcpmux','ws','wsmux','xwsmux','wss','wssmux','anytls'):
  logs=[];processes=[]
  for i,n in enumerate(ns):
   cfg={'transport':{'type':'tun','heartbeat_interval':1,'heartbeat_timeout':5},'tun':{'carrier':kind,'encapsulation':'tcp','name':'bhcheck','local_addr':f'10.249.88.{i+1}/30','remote_addr':f'10.249.88.{2-i}/30','health_port':19080,'mtu':1400},'security':{'token':'private integration test token 123456'},'logging':{'log_level':'error'}}
   if i==0:cfg['listener']={'bind_addr':'198.18.88.1:18443'}
   else:cfg['dialer']={'remote_addr':'198.18.88.1:18443','retry_interval':1}
   if kind in ('wss','wssmux','anytls'):cfg['tls']={'tls_cert':str(cert),'tls_key':str(key)} if i==0 else {'ca_file':str(cert),'sni':'localhost'}
   path=root/(n+'.json');path.write_text(json.dumps(cfg));log=open(root/(n+'.log'),'w+');logs.append(log)
   run(binary,'-c',str(path),'-check')
   processes.append(sp.Popen(['ip','netns','exec',n,binary,'-c',str(path)],stdout=log,stderr=log))
  try:
   for retry in range(12):
    time.sleep(.5)
    if inside(ns[0],'ping','-n','-I','bhcheck','-c','1','-W','1','10.249.88.2',check=False).returncode==0:break
   else:raise RuntimeError('ping failed '+kind)
   inside(ns[1],'ping','-n','-I','bhcheck','-c','2','-W','2','10.249.88.1')
   # HAProxy forwards through the actual IP tunnel to a peer HTTP service.
   http=sp.Popen(['ip','netns','exec',ns[1],'python3','-m','http.server','18080','--bind','10.249.88.2'],stdout=sp.DEVNULL,stderr=sp.DEVNULL);processes.append(http)
   ha=root/'ha.cfg';ha.write_text('global\n maxconn 32\ndefaults\n mode tcp\n timeout connect 3s\n timeout client 3s\n timeout server 3s\nfrontend test\n bind 127.0.0.1:18081\n default_backend peer\nbackend peer\n server peer 10.249.88.2:18080\n')
   processes.append(sp.Popen(['ip','netns','exec',ns[0],'haproxy','-db','-f',str(ha)],stdout=sp.DEVNULL,stderr=sp.DEVNULL));time.sleep(.3)
   inside(ns[0],'curl','-fsS','--max-time','6','http://127.0.0.1:18081/')
   print(kind+': bidirectional ping and HAProxy HTTP PASS',flush=True)
  except Exception:
   for log in logs:log.flush();log.seek(0);print(log.read()[-2000:])
   raise
  finally:
   for proc in reversed(processes):proc.terminate()
   for proc in reversed(processes):
    try:proc.wait(timeout=5)
    except sp.TimeoutExpired:proc.kill();proc.wait()
   processes=[]
   for log in logs:log.close()
finally:
 for proc in processes:proc.kill();proc.wait()
 for n in ns:run('ip','netns','del',n,check=False)
 tmp.cleanup()
