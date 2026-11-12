#!/usr/bin/env python3
"""Provision Let's Encrypt for the panel while retaining clear HTTP."""
import grp, hashlib, ipaddress, json, os, re, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path

REQUEST=Path('/etc/tunnelmgr/panel-tls-request.json')
STATUS=Path('/var/lib/tunnelmgr/panel-tls-status.json')
CERT_DIR=Path('/etc/tunnelmgr/panel-tls')
LIVE=Path('/etc/letsencrypt/live')

def write_json(path,value,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.avatun-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'w') as f:json.dump(value,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def status(state,step,message,**extra):
    write_json(STATUS,{'state':state,'step':step,'message':message,'updated_at':int(time.time()),**extra})

def safe_config():
    cfg=json.loads(REQUEST.read_text())
    domain=cfg.get('domain','').strip().rstrip('.').lower()
    domain=domain.encode('idna').decode('ascii')
    labels=domain.split('.')
    if len(domain)>253 or len(labels)<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in labels):raise ValueError('دامنه باید یک نام کامل معتبر باشد.')
    try:ipaddress.ip_address(domain)
    except ValueError:pass
    else:raise ValueError('به‌جای IP، دامنه یا زیردامنه وارد کن.')
    email=cfg.get('email','').strip()
    if len(email)>254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email):raise ValueError('ایمیل معتبر برای اعلان‌های گواهی وارد کن.')
    port=cfg.get('port')
    if type(port) is not int or not 1024<=port<=65535 or port in (443,):raise ValueError('پورت پنل باید بین ۱۰۲۴ تا ۶۵۵۳۵ باشد؛ ۴۴۳ برای سرویس‌ها رزرو است.')
    return domain,email,port

def run(args,timeout=60):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError((p.stdout+'\n'+p.stderr).strip()[-3000:])
    return p.stdout.strip()

def deploy_copy(cert_name):
    CERT_DIR.mkdir(mode=0o750,parents=True,exist_ok=True)
    group=grp.getgrnam('tunnelmgr').gr_gid
    os.chown(CERT_DIR,0,group);os.chmod(CERT_DIR,0o750)
    for src,name in ((LIVE/cert_name/'fullchain.pem','fullchain.pem'),(LIVE/cert_name/'privkey.pem','privkey.pem')):
        if not src.is_file():raise RuntimeError('گواهی صادر شده اما فایل آن پیدا نشد.')
        target=CERT_DIR/name;tmp=CERT_DIR/('.'+name+'.tmp')
        shutil.copyfile(src,tmp);os.chown(tmp,0,group);os.chmod(tmp,0o640);os.replace(tmp,target)

def apply():
    domain,email,port=safe_config();old={}
    try:old=json.loads(STATUS.read_text())
    except Exception:pass
    status('working','dependencies','در حال آماده‌سازی سرویس صدور گواهی…',domain=domain,email=email,port=port)
    if not shutil.which('certbot'):raise RuntimeError('Certbot هنوز نصب نیست؛ پنل را با نصب‌کنندهٔ رسمی به‌روزرسانی کن تا وابستگی آماده شود.')
    cert_name='avatun-panel-'+hashlib.sha256(domain.encode()).hexdigest()[:12]
    status('working','challenge','در حال دریافت گواهی؛ دامنه باید به این سرور برسد و TCP/80 از اینترنت باز باشد…',domain=domain,email=email,port=port)
    run(['/usr/bin/certbot','certonly','--standalone','--http-01-port','80','--cert-name',cert_name,'-d',domain,'--email',email,'--agree-tos','--non-interactive','--keep-until-expiring'],600)
    deploy_copy(cert_name)
    hook=Path('/etc/letsencrypt/renewal-hooks/deploy/avatun-panel-copy')
    hook.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    hook.write_text('#!/bin/sh\nexec /usr/bin/python3 /opt/tunnelmgr/tunnelmgr/tls_manager.py deploy-hook\n');hook.chmod(0o755)
    run(['/usr/bin/systemctl','enable','--now','certbot.timer'],30)
    old_port=old.get('port',8765)
    if old_port!=port:
        probe=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:probe.bind(('0.0.0.0',port))
        except OSError as e:raise RuntimeError(f'پورت {port} در حال استفاده است؛ پورت آزاد دیگری انتخاب کن.') from e
        finally:probe.close()
        drop=Path('/etc/systemd/system/tunnelmgr.service.d/port.conf');drop.parent.mkdir(parents=True,exist_ok=True)
        drop.write_text('[Service]\nExecStart=\nExecStart=/usr/bin/python3 /opt/tunnelmgr/tunnelmgr/tunnelctl.py api --host 0.0.0.0 --port '+str(port)+'\n');drop.chmod(0o644)
        run(['/usr/bin/systemctl','daemon-reload'],20)
    expiry=run(['/usr/bin/openssl','x509','-enddate','-noout','-in',str(CERT_DIR/'fullchain.pem')]).partition('=')[2]
    result={'state':'ready','step':'complete','message':'گواهی نصب شد؛ HTTP و HTTPS روی یک پورت فعال هستند.','domain':domain,'email':email,'port':port,'certificate_name':cert_name,'certificate_expires':expiry,'updated_at':int(time.time())}
    write_json(STATUS,result)
    if old_port!=port:
        time.sleep(5)
        subprocess.Popen(['/usr/bin/systemctl','restart','tunnelmgr.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    return result

def renew_hook():
    state=json.loads(STATUS.read_text());deploy_copy(state['certificate_name'])

def main():
    try:
        if sys.argv[1:] == ['deploy-hook']:
            state=json.loads(STATUS.read_text());deploy_copy(state['certificate_name']);return
        apply()
    except Exception as exc:
        try:
            request=json.loads(REQUEST.read_text())
            status('error','failed',str(exc),domain=request.get('domain'),email=request.get('email'),port=request.get('port'))
        except Exception:pass
        raise

if __name__=='__main__':main()
