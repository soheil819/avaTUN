"""Managed HAProxy stats/exporter block; credentials stay in root-owned runtime config."""
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

SETTINGS=Path('/etc/avatun/haproxy-stats.json')
BEGIN='# BEGIN AVATUN HAPROXY STATS'
END='# END AVATUN HAPROXY STATS'
PORT=18404


def settings():
    if SETTINGS.exists():data=json.loads(SETTINGS.read_text())
    else:
        data={'username':'admin','password':secrets.token_urlsafe(24)}
        SETTINGS.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile('w',dir=SETTINGS.parent,delete=False) as file:
            pending=Path(file.name)
            try:
                json.dump(data,file);file.flush();os.fsync(file.fileno());os.replace(pending,SETTINGS)
            finally:pending.unlink(missing_ok=True)
    if not isinstance(data,dict) or not all(isinstance(data.get(k),str) and re.fullmatch(r'[A-Za-z0-9_.@+%=-]{1,160}',data[k]) for k in ('username','password')):
        raise ValueError('Invalid HAProxy statistics credentials in runtime configuration')
    SETTINGS.chmod(0o600)
    return data


def without_block(text):
    start=text.find(BEGIN);end=text.find(END)
    if start<0 and end<0:return text
    if start<0 or end<start or text.count(BEGIN)!=1 or text.count(END)!=1:
        raise ValueError('Managed HAProxy statistics markers are incomplete or duplicated')
    return text[:start].rstrip()+'\n'+text[end+len(END):].lstrip()


def append_block(text):
    base=without_block(text)
    if re.search(r'^\s*frontend\s+haproxy_stats\s*$',base,re.M):
        raise ValueError('An unmanaged haproxy_stats frontend already exists; rename it before enabling managed statistics')
    auth=settings()
    return base.rstrip()+'\n\n'+ '\n'.join([
        BEGIN,'frontend haproxy_stats',f'    bind 0.0.0.0:{PORT}','    mode http',
        '    stats enable','    stats uri /stats','    stats refresh 5s',
        '    stats show-legends','    stats show-node',
        '    stats auth '+auth['username']+':'+auth['password'],
        '    http-request use-service prometheus-exporter if { path /metrics }',END,''])
