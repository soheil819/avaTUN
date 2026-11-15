#!/usr/bin/env python3
"""Run or validate avaTUN's isolated Xray client configuration."""
import os
import pathlib
import shutil
import subprocess
import sys

CONFIG=pathlib.Path('/var/lib/tunnelmgr/xray/config.json')
CANDIDATES=(
    '/opt/tunnelmgr/bin/xray','/usr/local/bin/xray','/usr/bin/xray','/usr/local/x-ui/bin/xray-linux-amd64',
    '/usr/local/x-ui/bin/xray','/usr/local/x-ui/xray-linux-amd64',
    '/usr/local/x-ui/xray',
)

def binary():
    requested=os.environ.get('TUNNELMGR_XRAY_BIN','').strip()
    candidates=([requested] if requested else [])+list(CANDIDATES)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate,os.X_OK):return candidate
    raise RuntimeError('Xray core is not installed; install Xray or x-ui on this server first.')

def main():
    action=sys.argv[1] if len(sys.argv)>1 else 'run'
    config=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else CONFIG
    if action not in ('run','test'):raise SystemExit('usage: xray_runtime.py [run|test] [config-path]')
    if not config.is_file():raise RuntimeError('managed Xray config is missing')
    exe=binary()
    args=[exe,'run','-config',str(config)]
    if action=='test':args.insert(2,'-test')
    if action=='test':
        result=subprocess.run(args,capture_output=True,text=True,timeout=25)
        if result.returncode:raise RuntimeError((result.stderr or result.stdout).strip()[-2500:] or 'Xray rejected the managed config')
        print((result.stdout or result.stderr).strip() or 'Xray configuration is valid.')
        return
    os.execv(exe,args)

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(1)
