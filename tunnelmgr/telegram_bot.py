#!/usr/bin/env python3
"""Private Telegram operations and monitoring for the avaTUN panel."""
import argparse
import datetime as dt
import http.client
import fcntl
import http.cookiejar
import json
import logging
import os
import pathlib
import re
import secrets
import sqlite3
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo


class IPv4HTTPSConnection(http.client.HTTPSConnection):
    """Avoid IPv6 connect timeouts on hosts without a working IPv6 route."""
    def connect(self):
        last_error = None
        for family, socktype, proto, _, address in socket.getaddrinfo(
                self.host, self.port, socket.AF_INET, socket.SOCK_STREAM):
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(self.timeout)
                if self.source_address:
                    sock.bind(self.source_address)
                sock.connect(address)
                self.sock = sock
                break
            except OSError as error:
                last_error = error
                sock.close()
        else:
            if last_error:
                raise last_error
            raise OSError('No IPv4 address for Telegram API')
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class IPv4HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(IPv4HTTPSConnection, request, context=self._context)


class PanelError(RuntimeError):
    pass


class Panel:
    def __init__(self, config):
        self.config = config
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def _request(self, path, data=None, timeout=None):
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(
            self.config['panel_url'].rstrip('/') + path, data=body,
            headers={'Content-Type': 'application/json'})
        request_timeout = timeout if timeout is not None else (120 if data is not None else 25)
        with self.opener.open(request, timeout=request_timeout) as response:
            result = json.load(response)
        if result.get('ok') is False or result.get('error'):
            raise PanelError(str(result.get('error', 'عملیات پنل ناموفق بود')))
        return result

    def request(self, path, data=None, timeout=None):
        try:
            return self._request(path, data, timeout)
        except urllib.error.HTTPError as error:
            if error.code != 401:
                try:
                    reason = json.load(error).get('error', 'خطای پنل')
                except (ValueError, AttributeError):
                    reason = 'خطای HTTP ' + str(error.code)
                raise PanelError(str(reason)) from None
        # Only authentication failures are replayed. Never retry ambiguous mutations.
        try:
            self._request('/api/v1/auth/login', {
                'username': self.config['panel_username'],
                'password': self.config['panel_password']}, timeout)
            return self._request(path, data, timeout)
        except urllib.error.HTTPError as error:
            raise PanelError('ورود یا دسترسی حساب ربات به پنل ناموفق بود (' + str(error.code) + ')') from None

    def snapshot(self):
        return self.request('/api/v1/telegram/snapshot')

    def operate(self, tunnel_id, action, expected):
        if action not in ('start', 'stop', 'restart'):
            raise PanelError('عملیات تونل نامعتبر است')
        snapshot = self.snapshot()
        endpoints = [item for item in snapshot['tunnels'] if item['id'] == tunnel_id]
        actual = sorted({item.get('server_id', 'local') for item in endpoints})
        if len(actual) < 2 or actual != sorted(expected):
            raise PanelError('هر دو سمت تونل در دسترس نیستند یا تنظیمات عوض شده؛ فهرست تونل‌ها را بازخوانی کن.')
        statuses = {item['id']: item for item in snapshot['statuses']}
        for server_id in actual:
            if statuses.get(server_id, {}).get('reachable') is not True:
                raise PanelError('دسترسی سرور ' + server_id + ' تأیید نشد؛ عملیات اجرا نشد.')
            if server_id == 'local':
                self.request('/api/v1/tunnels/' + urllib.parse.quote(tunnel_id, safe=''))
            else:
                items = self.request('/api/v1/servers/' + server_id + '/tunnels')['items']
                if not any(item['id'] == tunnel_id for item in items):
                    raise PanelError('تونل روی ' + server_id + ' پیدا نشد؛ فهرست را بازخوانی کن.')
        escaped = urllib.parse.quote(tunnel_id, safe='')
        if action == 'restart' and any(item.get('metadata', {}).get('transport') == 'ipsec-esp-udp' for item in endpoints):
            if 'local' not in actual:
                raise PanelError('برای این جفت IPsec از ریستارت هماهنگ پنل استفاده کن.')
            self.request('/api/v1/tunnels/' + escaped + '/restart', {})
            return ['ریستارت هماهنگ IPsec روی دو سمت انجام شد.']
        results = []
        for server_id in actual:
            prefix = '/api/v1/tunnels/' if server_id == 'local' else '/api/v1/servers/' + server_id + '/tunnels/'
            try:
                self.request(prefix + escaped + '/' + action, {})
                results.append(server_id + ' ✅')
            except (OSError, ValueError, RuntimeError):
                results.append(server_id + ' ❌؛ وضعیت این سمت را بررسی کن.')
        return results


class Telegram:
    def __init__(self, token):
        self.base = 'https://api.telegram.org/bot' + token + '/'
        self.opener = urllib.request.build_opener(IPv4HTTPSHandler())

    def request(self, method, data):
        request = urllib.request.Request(self.base + method, data=json.dumps(data).encode(),
                                         headers={'Content-Type': 'application/json'})
        try:
            timeout = 12 if method == 'getUpdates' else 8
            with self.opener.open(request, timeout=timeout) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 429:
                try:
                    delay = float(json.load(error).get('parameters', {}).get('retry_after', 5))
                except (ValueError, TypeError, AttributeError):
                    delay = 5
                time.sleep(min(max(delay, 1), 60))
            raise RuntimeError('Telegram HTTP ' + str(error.code)) from None
        except (OSError, ValueError):
            # The request URL contains a credential, so never propagate network exceptions.
            raise RuntimeError('Telegram connection failed') from None
        if not result.get('ok'):
            raise RuntimeError('Telegram rejected ' + method)
        return result['result']

    def send(self, user_id, text, keyboard=None):
        # Telegram's limit is counted in UTF-16 units. This keeps emoji-heavy reports below it.
        chunks, current, length = [], [], 0
        for char in str(text):
            units = 2 if ord(char) > 0xFFFF else 1
            if length + units > 3500:
                chunks.append(''.join(current)); current, length = [], 0
            current.append(char); length += units
        chunks.append(''.join(current) or '—')
        for index, chunk in enumerate(chunks):
            data = {'chat_id': user_id, 'text': chunk}
            if keyboard and index == len(chunks) - 1:
                data['reply_markup'] = {'inline_keyboard': keyboard}
            self.request('sendMessage', data)


class State:
    def __init__(self, path):
        path = pathlib.Path(path)
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        os.chmod(path, 0o600)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript('''
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS signals (key TEXT PRIMARY KEY, label TEXT NOT NULL,
                bad_since REAL, alerted INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, key TEXT NOT NULL,
                started REAL NOT NULL, ended REAL);
            CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
                event_key TEXT NOT NULL, text TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0,
                UNIQUE(user_id,event_key));
            CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at REAL NOT NULL,
                user_id INTEGER NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL);
        ''')

    def get(self, key, default=None):
        row = self.connection.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key, value):
        with self.connection:
            self.connection.execute('INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                                    (key, json.dumps(value)))

    def audit(self, user_id, action, target, result):
        with self.connection:
            self.connection.execute('INSERT INTO audit(at,user_id,action,target,result) VALUES(?,?,?,?,?)',
                                    (time.time(), user_id, action, target, result))

    def queue(self, users, event_key, text):
        self.connection.executemany('INSERT OR IGNORE INTO notifications(user_id,event_key,text) VALUES(?,?,?)',
                                    [(user_id, event_key, text) for user_id in users])

    def observe(self, key, label, bad, now, delay, users):
        with self.connection:
            row = self.connection.execute('SELECT * FROM signals WHERE key=?', (key,)).fetchone()
            if row is None:
                self.connection.execute('INSERT INTO signals(key,label,bad_since) VALUES(?,?,?)',
                                        (key, label, now if bad else None))
                return
            if bad:
                since = row['bad_since'] if row['bad_since'] is not None else now
                if not row['alerted'] and now - since >= delay:
                    self.queue(users, f'down:{key}:{since}', '🔴 ' + label + '\nاز ' + duration(now - since) + ' قبل ادامه دارد.')
                    self.connection.execute('INSERT INTO incidents(key,started) VALUES(?,?)', (key, since))
                    self.connection.execute('UPDATE signals SET alerted=1 WHERE key=?', (key,))
                self.connection.execute('UPDATE signals SET bad_since=?,label=? WHERE key=?', (since, label, key))
            else:
                if row['alerted']:
                    since = row['bad_since']
                    self.queue(users, f'up:{key}:{since}', '🟢 بازیابی شد · ' + row['label'] + '\nمدت اختلال ' + duration(now - since))
                    self.connection.execute('UPDATE incidents SET ended=? WHERE key=? AND ended IS NULL', (now, key))
                self.connection.execute('UPDATE signals SET bad_since=NULL,alerted=0,label=? WHERE key=?', (label, key))

    def is_alerted(self, key):
        row = self.connection.execute('SELECT alerted FROM signals WHERE key=?', (key,)).fetchone()
        return bool(row and row[0])

    def deliver(self, telegram, scrub):
        rows = self.connection.execute('SELECT * FROM notifications WHERE sent=0 ORDER BY id LIMIT 20').fetchall()
        for row in rows:
            try:
                telegram.send(row['user_id'], scrub(row['text']))
            except RuntimeError:
                logging.warning('Notification delivery deferred for user %s', row['user_id'])
                return
            with self.connection:
                self.connection.execute('UPDATE notifications SET sent=1 WHERE id=?', (row['id'],))
        # Keep incident and audit history for reports while bounding the delivery log.
        with self.connection:
            self.connection.execute('DELETE FROM notifications WHERE sent=1 AND id < (SELECT MAX(id)-2000 FROM notifications)')
            self.connection.execute('DELETE FROM audit WHERE at<?', (time.time() - 30 * 86400,))


def size(value):
    value = float(value or 0)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(value) < 1024 or unit == 'TiB':
            return f'{value:.1f} {unit}'
        value /= 1024


def duration(seconds):
    seconds = max(0, int(seconds))
    return f'{seconds // 3600} ساعت و {(seconds % 3600) // 60} دقیقه' if seconds >= 3600 else f'{seconds // 60} دقیقه و {seconds % 60} ثانیه'


def hardware_report(item):
    lines = [f"🖥 {item.get('name') or item.get('id', 'سرور')}", str(item.get('host', ''))]
    resources = item.get('resources')
    if not resources:
        return '\n'.join(lines + ['آمار منابع دریافت نشده است.'])
    lines += [f"CPU {resources.get('cpu_percent', '—')}% · Load {resources.get('load_1m', '—')}"]
    for key, label in (('memory', 'RAM'), ('disk', 'دیسک'), ('swap', 'Swap')):
        total = resources.get(key + '_total_bytes', 0)
        if key == 'swap' and not total:
            lines.append('Swap غیرفعال')
        else:
            lines.append(f"{label} {size(resources.get(key + '_used_bytes', 0))} / {size(total)} · {resources.get(key + '_percent', '—')}%")
    lines += [f"↓ دانلود {size(resources.get('download_bytes_per_sec'))}/s",
              f"↑ آپلود {size(resources.get('upload_bytes_per_sec'))}/s"]
    checked = resources.get('checked_at')
    lines.append('نمونهٔ ' + duration(time.time() - checked) + ' قبل' if checked else 'زمان نمونه‌برداری نامشخص است')
    return '\n'.join(lines)


def resource_widget_state(items, page):
    items = list(items or [])
    count = len(items)
    page = min(max(0, int(page)), max(0, count - 1))
    item = items[page] if items else {'id': 'local', 'name': 'سرور مرکزی', 'host': '—'}
    source = item.get('resources') or {}
    fields = ('cpu_percent', 'load_1m', 'memory_used_bytes', 'memory_total_bytes',
              'memory_percent', 'disk_used_bytes', 'disk_total_bytes', 'disk_percent',
              'swap_used_bytes', 'swap_total_bytes', 'swap_percent',
              'download_bytes_per_sec', 'upload_bytes_per_sec', 'checked_at')
    resources = {key: source.get(key, 0) for key in fields}
    checked = resources.get('checked_at') or 0
    return {'p': page, 'n': max(1, count), 'x': {
        'ok': bool(item.get('reachable', True)) and bool(source),
        'name': str(item.get('name') or item.get('id') or 'سرور')[:80],
        'host': str(item.get('host') or '')[:100],
        'stale': bool(checked and time.time() - checked > 30),
        'resources': resources}}


RESOURCE_WIDGET_HTML = r'''<!doctype html><html><body>
<style>
body{margin:0;padding:10px 12px;color:var(--tg-theme-text-color);font:14px/1.35 sans-serif}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.name{font-size:16px;font-weight:700;overflow-wrap:anywhere}.host,.hint{color:var(--tg-theme-hint-color);font-size:12px}
.status{color:var(--tg-theme-accent-text-color);white-space:nowrap;font-size:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:7px}
.metric{background:var(--tg-theme-secondary-bg-color);border-radius:10px;padding:8px 9px;min-width:0}
.line{display:flex;justify-content:space-between;gap:6px;font-size:12px}.value{font-weight:700;white-space:nowrap}
.track{height:5px;border-radius:4px;background:var(--tg-theme-section-separator-color);margin-top:6px;overflow:hidden}
.fill{height:100%;border-radius:4px;background:var(--tg-theme-button-color);width:0}
.network{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-top:7px}
.traffic{background:var(--tg-theme-secondary-bg-color);padding:8px 9px;border-radius:10px}
.traffic .value{display:block;margin-top:3px;color:var(--tg-theme-accent-text-color);font-size:13px}
.foot{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:8px}
.nav{display:flex;gap:6px}.nav button{border:0;border-radius:8px;padding:6px 9px;color:var(--tg-theme-button-text-color);background:var(--tg-theme-button-color);font:inherit}
.nav button:disabled{opacity:.45}.hint{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
</style>
<div class="top"><div><div class="name" id="name">منابع سرور</div><div class="host" id="host"></div></div><div class="status" id="status">در حال دریافت…</div></div>
<div class="grid" id="metrics"></div><div class="network" id="network"></div>
<div class="foot"><div class="nav"><button id="prev">قبلی</button><button id="next">بعدی</button><button id="refresh">↻ تازه‌سازی</button></div><div class="hint" id="page"></div></div>
<script>
const TW=window.TelegramWidget,$=id=>document.getElementById(id);let state={p:0,n:1,x:null},busy=false;
function num(v){return Number.isFinite(Number(v))?Number(v):0}
function fmt(v){v=num(v);const units=['B','KiB','MiB','GiB','TiB'];let i=0;while(v>=1024&&i<units.length-1){v/=1024;i++}return v.toLocaleString(undefined,{maximumFractionDigits:1})+' '+units[i]}
function rate(v){return fmt(v)+'/s'}
function draw(){const x=state.x||{},r=x.resources||{};$('name').textContent=x.name||x.id||'منابع سرور';$('host').textContent=x.host||'';$('status').textContent=x.ok===false?'دریافت آمار ناموفق بود':(x.stale?'آخرین آمار موجود':'آنلاین');
const fields=[['CPU','cpu_percent','%'],['RAM','memory_percent','%'],['دیسک','disk_percent','%'],['Swap','swap_percent','%']];
$('metrics').innerHTML=fields.map(([label,key,suffix])=>{const p=Math.max(0,Math.min(100,num(r[key]))),used=key==='memory_percent'?fmt(r.memory_used_bytes)+' / '+fmt(r.memory_total_bytes):key==='disk_percent'?fmt(r.disk_used_bytes)+' / '+fmt(r.disk_total_bytes):key==='swap_percent'?(!num(r.swap_total_bytes)?'غیرفعال':fmt(r.swap_used_bytes)+' / '+fmt(r.swap_total_bytes)):('Load '+num(r.load_1m).toFixed(2));return '<div class="metric"><div class="line"><span>'+label+'</span><span class="value">'+p.toFixed(1)+suffix+'</span></div><div class="track"><div class="fill" style="width:'+p+'%"></div></div><div class="hint">'+used+'</div></div>'}).join('');
$('network').innerHTML='<div class="traffic"><span class="hint">↓ دانلود</span><span class="value">'+rate(r.download_bytes_per_sec)+'</span></div><div class="traffic"><span class="hint">↑ آپلود</span><span class="value">'+rate(r.upload_bytes_per_sec)+'</span></div>';
$('page').textContent=(state.p+1)+' از '+Math.max(1,state.n)+' سرور · '+(r.checked_at?new Date(r.checked_at*1000).toLocaleTimeString():'زمان نامشخص');$('prev').disabled=state.p<=0;$('next').disabled=state.p>=state.n-1}
function accept(value){try{const next=JSON.parse(value);if(next&&typeof next==='object'){state=next;draw()}}catch(e){$('status').textContent='پاسخ منابع قابل خواندن نیست'}}
function ask(page){if(!TW||busy)return;busy=true;$('status').textContent='در حال به‌روزرسانی…';TW.request('resources:'+page).then(a=>{if(a&&a.result)accept(a.result);else $('status').textContent='پاسخ خالی از پنل'},e=>{$('status').textContent='اتصال موقتاً برقرار نیست'}).finally(()=>{busy=false})}
try{if(TW&&TW.chatData)state=JSON.parse(TW.chatData)}catch(e){}draw();
$('prev').onclick=()=>{if(state.p>0)ask(state.p-1)};$('next').onclick=()=>{if(state.p<state.n-1)ask(state.p+1)};$('refresh').onclick=()=>ask(state.p);
if(TW){ask(state.p);setInterval(()=>{if(TW.isActive&&!busy)ask(state.p)},15000)}
</script></body></html>'''

TUNNEL_WIDGET_HTML = r'''<!doctype html><html><body><style>
body{margin:0;padding:10px 12px;color:var(--tg-theme-text-color);font:14px/1.4 sans-serif}.head,.foot{display:flex;justify-content:space-between;align-items:center;gap:8px}.title{font-weight:700;font-size:16px}.hint{color:var(--tg-theme-hint-color);font-size:12px}.list{display:grid;gap:7px;margin-top:9px}.item{background:var(--tg-theme-secondary-bg-color);border-radius:10px;padding:9px}.row{display:flex;align-items:center;justify-content:space-between;gap:8px}.name{font-weight:700;overflow-wrap:anywhere}.badge{font-size:11px;white-space:nowrap}.up{color:#25a879}.down{color:#e05d66}.unknown{color:#d99b2b}.sub{font-size:12px;color:var(--tg-theme-hint-color);margin-top:4px}.nav{display:flex;gap:6px;margin-top:9px}.nav button{border:0;border-radius:8px;padding:6px 9px;color:var(--tg-theme-button-text-color);background:var(--tg-theme-button-color);font:inherit}.nav button:disabled{opacity:.45}
</style><div class="head"><div class="title">وضعیت تونل‌ها</div><span class="hint" id="summary"></span></div><div class="list" id="list"></div><div class="foot"><div class="nav"><button id="prev">قبلی</button><button id="next">بعدی</button><button id="refresh">↻</button></div><span class="hint" id="page"></span></div><script>
const TW=window.TelegramWidget,$=id=>document.getElementById(id);let s={p:0,n:1,x:[]},busy=false;function draw(){const icons={up:'● برقرار',down:'● قطع',unknown:'● نامشخص'};$('summary').textContent=(s.x||[]).length+' مورد';$('list').innerHTML=(s.x||[]).map(x=>'<div class="item"><div class="row"><span class="name">'+x.id+'</span><span class="badge '+x.state+'">'+(icons[x.state]||icons.unknown)+'</span></div><div class="sub">'+x.type+' · '+x.servers+'</div><div class="sub">'+x.address+' · '+x.latency+'</div></div>').join('')||'<div class="item">تونلی ثبت نشده است.</div>';$('page').textContent=(s.p+1)+' از '+s.n;$('prev').disabled=s.p<=0;$('next').disabled=s.p>=s.n-1}function ask(p){if(!TW||busy)return;busy=true;TW.request('tunnels:'+p).then(v=>{if(v?.result)s=JSON.parse(v.result);draw()}).catch(()=>{}).finally(()=>busy=false)}try{s=JSON.parse(TW.chatData)}catch{}draw();$('prev').onclick=()=>ask(s.p-1);$('next').onclick=()=>ask(s.p+1);$('refresh').onclick=()=>ask(s.p);if(TW){ask(s.p);setInterval(()=>{if(TW.isActive&&!busy)ask(s.p)},15000)}</script></body></html>'''

SERVER_WIDGET_HTML = r'''<!doctype html><html><body><style>
body{margin:0;padding:10px 12px;color:var(--tg-theme-text-color);font:14px/1.4 sans-serif}.head,.foot,.row{display:flex;justify-content:space-between;align-items:center;gap:8px}.title{font-weight:700;font-size:16px}.hint{color:var(--tg-theme-hint-color);font-size:12px}.list{display:grid;gap:7px;margin-top:9px}.item{background:var(--tg-theme-secondary-bg-color);border-radius:10px;padding:9px}.name{font-weight:700;overflow-wrap:anywhere}.badge{font-size:11px;white-space:nowrap}.up{color:#25a879}.down{color:#e05d66}.unknown{color:#d99b2b}.sub{font-size:12px;color:var(--tg-theme-hint-color);margin-top:4px}.detail{margin-top:7px;padding-top:7px;border-top:1px solid var(--tg-theme-hint-color);font-size:12px}.nav{display:flex;gap:6px;margin-top:9px}.nav button,.detail button{border:0;border-radius:8px;padding:6px 9px;color:var(--tg-theme-button-text-color);background:var(--tg-theme-button-color);font:inherit}.nav button:disabled{opacity:.45}
</style><div class="head"><div class="title">وضعیت سرورها</div><span class="hint" id="summary"></span></div><div class="list" id="list"></div><div class="foot"><div class="nav"><button id="prev">قبلی</button><button id="next">بعدی</button><button id="refresh">↻</button></div><span class="hint" id="page"></span></div><script>
const TW=window.TelegramWidget,$=id=>document.getElementById(id);let s={p:0,n:1,x:[]},busy=false;function ask(p,selected=''){if(!TW||busy)return;busy=true;TW.request('servers:'+p+(selected?':'+selected:'')).then(v=>{if(v?.result)s=JSON.parse(v.result);draw()}).catch(()=>{}).finally(()=>busy=false)}function draw(){const icons={up:'● آنلاین',down:'● قطع',unknown:'● نامشخص'};$('summary').textContent=(s.x||[]).length+' سرور';$('list').innerHTML=(s.x||[]).map(x=>'<div class="item"><div class="row"><span class="name">'+x.name+' · '+x.id+'</span><span class="badge '+x.state+'">'+(icons[x.state]||icons.unknown)+'</span></div><div class="sub">'+x.host+' · '+x.tunnels+' تونل · نسخه '+x.version+'</div>'+(x.selected?'<div class="detail">سرویس پنل: '+x.service+' · SSH: '+x.ssh+(x.cpu!==null?' · CPU '+x.cpu+'%':'')+(x.ram!==null?' · RAM '+x.ram+'%':'')+'</div>':'<div class="detail"><button data-id="'+x.id+'">جزئیات</button></div>')+'</div>').join('')||'<div class="item">سروری ثبت نشده است.</div>';$('page').textContent=(s.p+1)+' از '+s.n;$('prev').disabled=s.p<=0;$('next').disabled=s.p>=s.n-1;document.querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>ask(s.p,b.dataset.id))}try{s=JSON.parse(TW.chatData)}catch{}draw();$('prev').onclick=()=>ask(s.p-1);$('next').onclick=()=>ask(s.p+1);$('refresh').onclick=()=>ask(s.p);if(TW){ask(s.p);setInterval(()=>{if(TW.isActive&&!busy)ask(s.p,s.selected||'')},15000)}</script></body></html>'''

HAPROXY_WIDGET_HTML = r'''<!doctype html><html><body><style>
body{margin:0;padding:10px 12px;color:var(--tg-theme-text-color);font:14px/1.4 sans-serif}.head,.foot{display:flex;justify-content:space-between;align-items:center;gap:8px}.title{font-weight:700;font-size:16px}.hint{color:var(--tg-theme-hint-color);font-size:12px}.list{display:grid;gap:7px;margin-top:9px}.item{background:var(--tg-theme-secondary-bg-color);border-radius:10px;padding:9px}.row{display:flex;align-items:center;justify-content:space-between;gap:8px}.name{font-weight:700;overflow-wrap:anywhere}.badge{font-size:11px;white-space:nowrap}.up{color:#25a879}.down{color:#e05d66}.unknown{color:#d99b2b}.sub{font-size:12px;color:var(--tg-theme-hint-color);margin-top:4px}.nav{display:flex;gap:6px;margin-top:9px}.nav button{border:0;border-radius:8px;padding:6px 9px;color:var(--tg-theme-button-text-color);background:var(--tg-theme-button-color);font:inherit}.nav button:disabled{opacity:.45}
</style><div class="head"><div class="title">فورواردر · پورت‌فوروارد</div><span class="hint" id="summary"></span></div><div class="list" id="list"></div><div class="foot"><div class="nav"><button id="prev">قبلی</button><button id="next">بعدی</button><button id="refresh">↻</button></div><span class="hint" id="page"></span></div><script>
const TW=window.TelegramWidget,$=id=>document.getElementById(id);let s={p:0,n:1,x:[],server_id:'local'},busy=false;function draw(){ $('summary').textContent=(s.server_id||'local')+' · '+(s.service?'HAProxy '+s.service:'وضعیت نامشخص');$('list').innerHTML=(s.x||[]).map(x=>'<div class="item"><div class="row"><span class="name">'+x.id+'</span><span class="badge '+(x.enabled?'up':'unknown')+'">'+(x.enabled?'فعال':'متوقف')+'</span></div><div class="sub">'+x.listen+' → پورت '+x.backend_port+' · '+x.algorithm+'</div><div class="sub">'+x.backends+'</div></div>').join('')||'<div class="item">قانونی ثبت نشده است.</div>';$('page').textContent=(s.p+1)+' از '+s.n;$('prev').disabled=s.p<=0;$('next').disabled=s.p>=s.n-1}function ask(p){if(!TW||busy)return;busy=true;TW.request('haproxy:'+(s.server_id||'local')+':'+p).then(v=>{if(v?.result)s=JSON.parse(v.result);draw()}).catch(()=>{}).finally(()=>busy=false)}try{s=JSON.parse(TW.chatData)}catch{}draw();$('prev').onclick=()=>ask(s.p-1);$('next').onclick=()=>ask(s.p+1);$('refresh').onclick=()=>ask(s.p);if(TW){ask(s.p);setInterval(()=>{if(TW.isActive&&!busy)ask(s.p)},15000)}</script></body></html>'''


def tunnel_widget_state(snapshot, page):
    groups = tunnel_groups(snapshot)
    entries = sorted(groups.items())
    pages = max(1, (len(entries) + 4) // 5)
    page = min(max(0, int(page)), pages - 1)
    selected = entries[page * 5:page * 5 + 5]
    items = []
    for ident, endpoints in selected:
        values = list(endpoints.values())
        states = [item.get('health', {}).get('state', 'unknown') for item in values]
        state = 'down' if any(x in ('down', 'error') for x in states) else 'up' if len(values) > 1 and all(x == 'up' for x in states) else 'unknown'
        kinds = sorted({str(item.get('metadata', {}).get('transport') or item.get('kind') or 'تونل') for item in values})
        servers = ' ↔ '.join(str(item.get('server_id') or 'local') for item in values)
        addresses = ' ↔ '.join(str(item.get('metadata', {}).get('tun_local') or '—') for item in values)
        latency = [item.get('health', {}).get('rtt_ms') for item in values if item.get('health', {}).get('rtt_ms') is not None]
        items.append({'id': str(ident)[:48], 'state': state, 'type': ' + '.join(kinds)[:70],
                      'servers': servers[:100], 'address': addresses[:100],
                      'latency': f'{max(latency):.1f} ms' if latency else '—'})
    return {'p': page, 'n': pages, 'x': items}


def server_widget_state(snapshot, page, selected=''):
    statuses = {str(item.get('id')): item for item in snapshot.get('statuses', [])}
    resources = {str(item.get('id')): item for item in snapshot.get('resources', [])}
    servers = [{'id': 'local', 'host': 'سرور پنل'}, *snapshot.get('servers', [])]
    groups = tunnel_groups(snapshot)
    pages = max(1, (len(servers) + 4) // 5)
    page = min(max(0, int(page)), pages - 1)
    items = []
    for server in servers[page * 5:page * 5 + 5]:
        ident = str(server.get('id', ''))
        status = statuses.get(ident, {})
        resource = resources.get(ident, {})
        metrics = resource.get('resources') or resource
        count = sum(ident in endpoints for endpoints in groups.values())
        reachable = status.get('reachable')
        items.append({'id': ident[:48], 'name': ('سرور مرکزی' if ident == 'local' else str(server.get('name') or server.get('label') or ident))[:64],
                      'host': str(server.get('host') or server.get('address') or ident)[:80],
                      'state': 'up' if reachable is True else 'down' if reachable is False else 'unknown',
                      'tunnels': count, 'version': str(status.get('app_version') or '—')[:24],
                      'service': 'فعال' if status.get('services') and all(x == 'active' for x in status['services']) else 'بررسی شود',
                      'ssh': 'در دسترس' if reachable is True else 'قطع' if reachable is False else 'نامشخص',
                      'cpu': metrics.get('cpu_percent'), 'ram': metrics.get('memory_percent'),
                      'selected': ident == selected})
    if selected and not any(item['id'] == selected for item in items):
        selected = ''
    return {'p': page, 'n': pages, 'x': items, 'selected': selected}


def haproxy_widget_state(result, page):
    entries = list(result.get('items') or [])
    pages = max(1, (len(entries) + 5) // 6)
    page = min(max(0, int(page)), pages - 1)
    service = result.get('service') or {}
    items = []
    for rule in entries[page * 6:page * 6 + 6]:
        backends = ', '.join(str(x.get('tunnel_id', '')) for x in rule.get('backends', [])) or '—'
        items.append({'id': str(rule.get('id', ''))[:48], 'enabled': bool(rule.get('enabled', True)),
                      'listen': str(rule.get('listen_ip', '')) + ':' + str(rule.get('listen_port', '')),
                      'backend_port': rule.get('backend_port', '—'), 'algorithm': str(rule.get('algorithm', 'leastconn')),
                      'backends': backends[:120]})
    return {'p': page, 'n': pages, 'server_id': result.get('server_id', 'local'),
            'service': 'فعال' if service.get('active') else 'خاموش/نامشخص', 'x': items}


def tunnel_groups(snapshot):
    groups = {}
    for item in snapshot['tunnels']:
        groups.setdefault(item['id'], {})[item.get('server_id', 'local')] = item
    return groups


def tunnel_state(endpoints):
    states = [item.get('health', {}).get('state') for item in endpoints.values()]
    if len(states) < 2:
        return 'unknown'
    if any(state in ('down', 'error') for state in states):
        return 'down'
    if all(state == 'up' for state in states):
        return 'up'
    return 'unknown'


def endpoint_report(server_id, item):
    meta, health = item.get('metadata', {}), item.get('health', {})
    state = health.get('state', 'unknown')
    label = {'up': '🟢 برقرار', 'down': '🔴 قطع', 'error': '🔴 خطا', 'monitor-only': '🟡 پایش محدود'}.get(state, '🟡 نامشخص')
    lines = [server_id + ' · ' + label,
             str(meta.get('transport') or item.get('kind', '')),
             f"داخلی {meta.get('tun_local', '—')} ⇄ {meta.get('tun_remote', '—')}",
             f"پینگ {health.get('rtt_ms', '—')} ms · MTU {meta.get('mtu') or meta.get('tun_mtu') or '—'}"]
    checked = health.get('checked_at')
    if checked:
        lines.append('آخرین پایش ' + duration(time.time() - checked) + ' قبل')
    reason = health.get('probe_error') or health.get('error')
    if reason:
        lines.append('دلیل ' + str(reason)[:400])
    if item.get('live', {}).get('active') is False:
        lines.append('سرویس این سمت فعال نیست.')
    return '\n'.join(lines)


class Bot:
    def __init__(self, config, panel=None, telegram=None, state=None):
        self.config = config
        self.users = {int(user): 'viewer' for user in config.get('viewers', [])}
        self.users.update({int(user): 'admin' for user in config.get('admins', [])})
        if not self.users and config.get('chat_id'):
            self.users[int(config['chat_id'])] = 'viewer'
        self.panel = panel or Panel(config)
        self.telegram = telegram or Telegram(config['bot_token'])
        self.state = state or State(config['state_path'])
        self.callbacks = {}
        self.zone = ZoneInfo(config.get('timezone', 'Asia/Tehran'))
        state_path = config.get('state_path') or self.state.path
        self.status_path = pathlib.Path(state_path).with_name('telegram-status.json')

    def set_status(self, state, error=None):
        data = {'state': state, 'updated_at': time.time()}
        if error:
            data['error'] = str(error)[:160]
        temporary = self.status_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(data) + '\n')
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.status_path)

    def scrub(self, text):
        text = str(text)
        for key in ('bot_token', 'panel_password'):
            value = self.config.get(key)
            if value:
                text = text.replace(value, '[حذف‌شده]')
        return re.sub(r'(?i)((?:password|token|psk|secret)\s*[=:]\s*)[^\s,;]+', r'\1[حذف‌شده]', text)

    def send(self, user_id, text, keyboard=None):
        self.telegram.send(user_id, self.scrub(text), keyboard)

    def button(self, user_id, label, action, **payload):
        now = time.time()
        self.callbacks = {key: value for key, value in self.callbacks.items() if value['expires'] > now}
        if len(self.callbacks) >= 2048:
            self.callbacks.pop(next(iter(self.callbacks)))
        token = secrets.token_urlsafe(12)
        self.callbacks[token] = {'user': user_id, 'action': action, 'payload': payload, 'expires': now + 600}
        return {'text': label, 'callback_data': token}

    def home(self, user_id):
        rows = [[self.button(user_id, '📊 نمای کلی', 'status'), self.button(user_id, '🖥 سرورها', 'servers')],
                [self.button(user_id, '🔗 وضعیت تونل‌ها', 'tunnel-widget'), self.button(user_id, '📈 منابع', 'hardware')],
                [self.button(user_id, '📋 گزارش ۲۴ ساعت', 'report')]]
        if self.users[user_id] == 'admin':
            rows.insert(2, [self.button(user_id, '↔️ فورواردر', 'forwards')])
            rows.append([self.button(user_id, '🧾 عملیات اخیر', 'audit')])
        self.send(user_id, 'avaTUN · مدیریت شبکه\nیک بخش را انتخاب کن.', rows)

    def status(self, user_id):
        snapshot = self.panel.snapshot()
        online = sum(item.get('reachable') is True for item in snapshot['statuses'])
        groups = tunnel_groups(snapshot)
        healthy = sum(tunnel_state(endpoints) == 'up' for endpoints in groups.values())
        down = sum(tunnel_state(endpoints) == 'down' for endpoints in groups.values())
        version = next((item.get('app_version') for item in snapshot['statuses'] if item['id'] == 'local'), '—')
        self.send(user_id, f'📊 avaTUN {version}\n🖥 سرور آنلاین {online} از {len(snapshot["servers"]) + 1}\n🔗 تونل برقرار {healthy} از {len(groups)}\n🔴 تونل قطع {down}\n🟡 نامشخص {len(groups) - healthy - down}',
                  [[self.button(user_id, '🔄 بازخوانی', 'status'), self.button(user_id, 'منوی اصلی', 'home')]])

    def servers(self, user_id, page=0):
        snapshot = self.panel.snapshot()
        entries = [{'id': 'local', 'host': 'سرور مرکزی'}, *snapshot['servers']]
        state = server_widget_state(snapshot, page)
        try:
            self.widget(user_id, SERVER_WIDGET_HTML, state, '🖥 وضعیت سرورها')
            rows = [[self.button(user_id, item['id'] + ' · ' + item['host'], 'server', server_id=item['id'])]
                    for item in entries[page * 5:page * 5 + 5]]
            rows.append([self.button(user_id, 'فهرست متنی سرورها', 'servers-text'),
                         self.button(user_id, 'منوی اصلی', 'home')])
            self.send(user_id, 'برای جزئیات و عملیات مدیریتی، سرور را انتخاب کن:', rows)
        except RuntimeError:
            rows = [[self.button(user_id, item['id'] + ' · ' + item['host'], 'server', server_id=item['id'])]
                    for item in entries[page * 8:page * 8 + 8]]
            rows += self.pagination(user_id, 'servers-text', page, len(entries))
            self.send(user_id, '🖥 انتخاب سرور', rows)

    def servers_text(self, user_id, page=0):
        entries = [{'id': 'local', 'host': 'سرور مرکزی'}, *self.panel.snapshot()['servers']]
        rows = [[self.button(user_id, item['id'] + ' · ' + item['host'], 'server', server_id=item['id'])]
                for item in entries[page * 8:page * 8 + 8]]
        rows += self.pagination(user_id, 'servers-text', page, len(entries))
        self.send(user_id, '🖥 انتخاب سرور', rows)

    def server(self, user_id, server_id):
        snapshot = self.panel.snapshot()
        item = next((item for item in snapshot['statuses'] if item['id'] == server_id), None)
        resource = next((item for item in snapshot['resources'] if item['id'] == server_id), {'id': server_id})
        reachable = item and item.get('reachable') is True
        text = ('🟢 متصل' if reachable else '🔴 دسترسی برقرار نیست') + '\n' + hardware_report(resource)
        if item:
            text += '\nنسخه ' + str(item.get('app_version', '—'))
            text += '\nسرویس پنل ' + ('فعال' if item.get('services') and all(x == 'active' for x in item['services']) else 'نیاز به بررسی')
        self.send(user_id, text, [[self.button(user_id, '🔗 تونل‌های این سرور', 'tunnels', server_id=server_id)],
                                 [self.button(user_id, '🔄 بازخوانی', 'server', server_id=server_id), self.button(user_id, 'سرورها', 'servers')]])

    def pagination(self, user_id, action, page, count, **payload):
        buttons = []
        if page > 0:
            buttons.append(self.button(user_id, 'قبلی', action, page=page - 1, **payload))
        if (page + 1) * 8 < count:
            buttons.append(self.button(user_id, 'بعدی', action, page=page + 1, **payload))
        return ([buttons] if buttons else []) + [[self.button(user_id, 'منوی اصلی', 'home')]]

    def tunnels(self, user_id, page=0, server_id=None):
        groups = tunnel_groups(self.panel.snapshot())
        entries = [(key, value) for key, value in sorted(groups.items()) if server_id is None or server_id in value]
        icons = {'up': '🟢', 'down': '🔴', 'unknown': '🟡'}
        rows = [[self.button(user_id, icons[tunnel_state(endpoints)] + ' ' + key, 'tunnel', tunnel_id=key)]
                for key, endpoints in entries[page * 8:page * 8 + 8]]
        rows += self.pagination(user_id, 'tunnels', page, len(entries), server_id=server_id)
        self.send(user_id, '🔗 تونل‌ها' + (' · ' + server_id if server_id else '') if entries else 'تونلی ثبت نشده است.', rows)

    def tunnel(self, user_id, tunnel_id):
        endpoints = tunnel_groups(self.panel.snapshot()).get(tunnel_id)
        if not endpoints:
            raise PanelError('تونل پیدا نشد؛ فهرست را بازخوانی کن.')
        text = '🔗 ' + tunnel_id + '\n\n' + '\n\n'.join(endpoint_report(sid, item) for sid, item in endpoints.items())
        rows = [[self.button(user_id, '🔎 بررسی زندهٔ دو سمت', 'diagnose', tunnel_id=tunnel_id)]]
        if self.users[user_id] == 'admin' and len(endpoints) >= 2:
            rows.append([self.button(user_id, label, 'confirm-tunnel', tunnel_id=tunnel_id, operation=action,
                                     expected=sorted(endpoints)) for label, action in
                         [('▶️ شروع', 'start'), ('🔄 ریستارت', 'restart'), ('⏸ توقف', 'stop')]])
        rows.append([self.button(user_id, 'فهرست تونل‌ها', 'tunnels')])
        self.send(user_id, text, rows)

    def diagnose(self, user_id, tunnel_id):
        snapshot = self.panel.snapshot()
        endpoints = tunnel_groups(snapshot).get(tunnel_id, {})
        lines = ['🔎 بررسی زندهٔ ' + tunnel_id]
        for sid in endpoints:
            if sid == 'local':
                item = self.panel.request('/api/v1/tunnels/' + urllib.parse.quote(tunnel_id, safe=''))
            else:
                items = self.panel.request('/api/v1/servers/' + sid + '/tunnels')['items']
                item = next((item for item in items if item['id'] == tunnel_id), None)
            if item:
                lines.append(endpoint_report(sid, item))
        if len(endpoints) < 2:
            lines.append('یک سمت در فهرست پایش نیست؛ اتصال SSH و وضعیت ثبت تونل سمت مقابل را بررسی کن.')
        self.send(user_id, '\n\n'.join(lines), [[self.button(user_id, 'بازگشت به تونل', 'tunnel', tunnel_id=tunnel_id)]])

    def hardware(self, user_id):
        items = self.panel.request('/api/v1/servers/resources', timeout=8)['items']
        if not items:
            self.send(user_id, 'هنوز آماری ثبت نشده است.', [[self.button(user_id, 'منوی اصلی', 'home')]])
            return
        state = resource_widget_state(items, 0)
        try:
            self.telegram.request('sendWidget', {
                'chat_id': user_id, 'html': RESOURCE_WIDGET_HTML,
                'chat_data': json.dumps(state, ensure_ascii=False, separators=(',', ':')),
                'caption': '📈 پایش زندهٔ منابع سرورها', 'allow_queries': True})
        except RuntimeError:
            # Keep the resource command usable if Telegram's widget feature is
            # unavailable for this bot or client/API deployment.
            self.send(user_id, 'ویجت منابع در دسترس نیست؛ گزارش متنی منابع:',
                      [[self.button(user_id, '🔄 تلاش دوباره', 'hardware'), self.button(user_id, 'منوی اصلی', 'home')]])
            self.send(user_id, '\n\n'.join(hardware_report(item) for item in items))

    def widget(self, user_id, html, state, caption):
        self.telegram.request('sendWidget', {
            'chat_id': user_id, 'html': html,
            'chat_data': json.dumps(state, ensure_ascii=False, separators=(',', ':')),
            'caption': caption, 'allow_queries': True})

    def tunnel_widget(self, user_id):
        state = tunnel_widget_state(self.panel.snapshot(), 0)
        try:
            self.widget(user_id, TUNNEL_WIDGET_HTML, state, '🔗 وضعیت تونل‌ها')
            entries = sorted(tunnel_groups(self.panel.snapshot()))
            rows = [[self.button(user_id, '🔎 ' + ident, 'tunnel', tunnel_id=ident)] for ident in entries[:16]]
            rows.append([self.button(user_id, 'فهرست کامل', 'tunnels'), self.button(user_id, 'منوی اصلی', 'home')])
            self.send(user_id, 'برای دیدن جزئیات یا عملیات، تونل را انتخاب کن:', rows)
        except RuntimeError:
            self.tunnels(user_id)

    def haproxy_widget(self, user_id, server_id='local'):
        result = self.panel.request('/api/v1/forwards?server_id=' + urllib.parse.quote(server_id, safe=''))
        result['items'] = [item for item in result.get('items', []) if item.get('server_id', 'local') == server_id]
        result['server_id'] = server_id
        state = haproxy_widget_state(result, 0)
        try:
            self.widget(user_id, HAPROXY_WIDGET_HTML, state, '↔️ وضعیت فورواردر · ' + server_id)
        except RuntimeError:
            self.forwards(user_id, server_id=server_id)

    def resource_widget_query(self, query):
        sender = query.get('from', {}).get('id')
        chat = query.get('chat') or {}
        authorized = (sender in self.users and chat.get('type') == 'private'
                      and chat.get('id') == sender)
        data = query.get('data', '')
        response = {'p': 0, 'n': 1, 'x': {'ok': False, 'name': 'منابع سرور', 'resources': {}}}
        if authorized and isinstance(data, str) and len(data.encode('utf-8')) <= 64:
            match = re.fullmatch(r'resources:(\d{1,5})', data)
            if match:
                try:
                    items = self.panel.request('/api/v1/servers/resources', timeout=8)['items']
                    response = resource_widget_state(items, int(match.group(1)))
                except (OSError, ValueError, KeyError, RuntimeError):
                    response['x']['name'] = 'منابع در دسترس نیست'
        try:
            self.telegram.request('answerWidgetQuery', {
                'widget_query_id': query['id'],
                'data': json.dumps(response, ensure_ascii=False, separators=(',', ':'))})
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            logging.warning('Widget query response failed (%s)', type(error).__name__)

    def status_widget_query(self, query):
        sender = query.get('from', {}).get('id')
        chat = query.get('chat') or {}
        authorized = (sender in self.users and chat.get('type') == 'private' and chat.get('id') == sender)
        data = query.get('data', '')
        response = {'p': 0, 'n': 1, 'x': []}
        if authorized and isinstance(data, str) and len(data.encode('utf-8')) <= 64:
            try:
                tunnel_match = re.fullmatch(r'tunnels:(\d{1,5})', data)
                server_match = re.fullmatch(r'servers:(\d{1,5})(?::([a-z0-9][a-z0-9_-]{0,47}|local))?', data)
                haproxy_match = re.fullmatch(r'haproxy:([a-z0-9][a-z0-9_-]{0,47}|local):(\d{1,5})', data)
                if tunnel_match:
                    response = tunnel_widget_state(self.panel.snapshot(), int(tunnel_match.group(1)))
                elif server_match:
                    response = server_widget_state(self.panel.snapshot(), int(server_match.group(1)), server_match.group(2) or '')
                elif haproxy_match and self.users.get(sender) == 'admin':
                    server_id = haproxy_match.group(1)
                    result = self.panel.request('/api/v1/forwards?server_id=' + urllib.parse.quote(server_id, safe=''))
                    result['items'] = [item for item in result.get('items', []) if item.get('server_id', 'local') == server_id]
                    result['server_id'] = server_id
                    response = haproxy_widget_state(result, int(haproxy_match.group(2)))
            except (OSError, ValueError, KeyError, RuntimeError):
                response = {'p': 0, 'n': 1, 'x': [], 'service': 'دریافت ناموفق'}
        try:
            self.telegram.request('answerWidgetQuery', {
                'widget_query_id': query['id'],
                'data': json.dumps(response, ensure_ascii=False, separators=(',', ':'))})
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            logging.warning('Widget query response failed (%s)', type(error).__name__)

    def forwards(self, user_id, page=0, server_id='local'):
        if self.users.get(user_id) != 'admin':
            self.send(user_id, 'مدیریت HAProxy فقط برای مدیر فعال است.', [[self.button(user_id, 'منوی اصلی', 'home')]])
            return
        snapshot = self.panel.snapshot()
        servers = [{'id': 'local', 'host': 'سرور مرکزی'}] + snapshot.get('servers', [])
        if not any(x['id'] == server_id for x in servers):
            raise PanelError('سرور انتخاب‌شده پیدا نشد.')
        result = self.panel.request('/api/v1/forwards?server_id=' + urllib.parse.quote(server_id, safe=''))
        entries = [item for item in result['items'] if item.get('server_id', 'local') == server_id]
        rows = [[self.button(user_id, ('▶️ ' if item.get('enabled', True) else '⏸ ') + item['id'],
                             'forward', rule_id=item['id'], server_id=item.get('server_id', 'local'))]
                for item in entries[page * 8:page * 8 + 8]]
        rows += self.pagination(user_id, 'forwards', page, len(entries), server_id=server_id)
        server_row = [self.button(user_id, x['id'] + (' · مرکزی' if x['id'] == 'local' else ' · ' + x.get('host', '')),
                                  'forwards', server_id=x['id']) for x in servers[:5]]
        rows.insert(0, server_row)
        rows.append([self.button(user_id, '📊 ویجت وضعیت فورواردر', 'haproxy-widget', server_id=server_id)])
        rows.append([self.button(user_id, '＋ قانون جدید', 'forward-new', server_id=server_id)])
        service = result.get('service') or {}
        self.send(user_id, f'⚖️ HAProxy · {server_id}\nسرویس: {"فعال" if service.get("active") else "خاموش/نامشخص"}\nقوانین: {len(entries)}', rows)

    def forward(self, user_id, rule_id, server_id):
        result = self.panel.request('/api/v1/forwards?server_id=' + urllib.parse.quote(server_id, safe=''))
        rule = next((item for item in result['items'] if item['id'] == rule_id and item.get('server_id', 'local') == server_id), None)
        if not rule:
            raise PanelError('قانون پیدا نشد؛ فهرست را بازخوانی کن.')
        service = result.get('service') or {}
        lines = ['⚖️ ' + rule_id, 'سرور ' + server_id,
                 f"ورودی {rule['listen_ip']}:{rule['listen_port']} → مقصد پورت {rule['backend_port']}",
                 'الگوریتم ' + rule['algorithm'], 'قانون فعال' if rule.get('enabled', True) else 'قانون غیرفعال',
                 'سرویس HAProxy ' + ('فعال' if service.get('active') else 'نامشخص یا غیرفعال')]
        for backend in rule.get('backends', []):
            status = service.get('paths', {}).get(rule_id, {}).get(backend['tunnel_id'], 'UNKNOWN')
            lines.append(f"{backend['tunnel_id']} · {backend['role']} · {backend['address']} · {status}")
        rows = []
        if self.users[user_id] == 'admin':
            rows.append([self.button(user_id, '⏸ غیرفعال‌کردن' if rule.get('enabled', True) else '▶️ فعال‌کردن',
                                     'confirm-forward', rule_id=rule_id, server_id=server_id,
                                     enabled=not rule.get('enabled', True))])
            rows.append([self.button(user_id, '✏️ ویرایش تنظیمات', 'forward-edit', rule_id=rule_id, server_id=server_id),
                         self.button(user_id, '🗑 حذف قانون', 'confirm-forward-delete', rule_id=rule_id, server_id=server_id)])
            rows.append([self.button(user_id, 'قوانین فورواردر', 'forwards', server_id=server_id)])
        self.send(user_id, '\n'.join(lines), rows)

    def prompt(self, user_id, text):
        self.telegram.request('sendMessage', {'chat_id': user_id, 'text': self.scrub(text),
                                               'reply_markup': {'force_reply': True, 'selective': True}})

    def wizard_key(self, user_id):
        return 'forward-wizard:' + str(user_id)

    def wizard_save(self, user_id, draft):
        self.state.put(self.wizard_key(user_id), draft)

    def wizard_get(self, user_id):
        return self.state.get(self.wizard_key(user_id))

    def wizard_clear(self, user_id):
        self.state.put(self.wizard_key(user_id), None)

    def start_forward_wizard(self, user_id, server_id, rule=None):
        draft = {'server_id': server_id, 'action': 'update' if rule else 'create',
                 'enabled': rule.get('enabled', True) if rule else True,
                 'id': rule.get('id', '') if rule else '',
                 'listen_ip': rule.get('listen_ip', '') if rule else '',
                 'listen_port': rule.get('listen_port', '') if rule else '',
                 'backend_port': rule.get('backend_port', '') if rule else '',
                 'algorithm': rule.get('algorithm', 'leastconn') if rule else 'leastconn',
                 'proxy_protocol': rule.get('proxy_protocol', 'none') if rule else 'none',
                 'check_send_proxy': rule.get('check_send_proxy', False) if rule else False,
                 'shutdown_sessions': rule.get('shutdown_sessions', False) if rule else False,
                 'backends': rule.get('backends', []) if rule else [], 'step': 'id'}
        self.wizard_save(user_id, draft)
        self.wizard_prompt(user_id)

    def wizard_prompt(self, user_id):
        draft = self.wizard_get(user_id)
        if not draft:
            return
        field = draft.get('step')
        labels = {'id': ('شناسهٔ قانون', 'مثال: web-entry'),
                  'listen_ip': ('IP شنود روی ' + draft['server_id'], 'مثال: 0.0.0.0 یا IP همین سرور'),
                  'listen_port': ('پورت ورودی', 'عدد ۱ تا ۶۵۵۳۵'),
                  'backend_port': ('پورت مقصد سرویس', 'مثال: 443')}
        if field in labels:
            title, hint = labels[field]
            current = draft.get(field)
            keep = f'\nمقدار فعلی: {current} · برای نگه‌داشتن «.» بفرست.' if draft['action'] == 'update' else ''
            self.prompt(user_id, f'{title}\n{hint}{keep}')
            return
        if field == 'algorithm':
            choices = [('کمترین اتصال', 'leastconn'), ('چرخشی', 'roundrobin'), ('بر اساس IP مبدا', 'source'), ('Failover اصلی/پشتیبان', 'first')]
            self.send(user_id, 'الگوریتم توزیع بار را انتخاب کن:', [[self.button(user_id, label, 'wizard-set', key='algorithm', value=value)] for label, value in choices])
        elif field == 'proxy':
            self.send(user_id, 'ارسال PROXY protocol به مقصد؟', [[self.button(user_id, 'خاموش', 'wizard-set', key='proxy_protocol', value='none'), self.button(user_id, 'PROXY v2', 'wizard-set', key='proxy_protocol', value='send-proxy-v2')]])
        elif field == 'options':
            self.send(user_id, 'تنظیمات بررسی و اتصال HAProxy را تعیین کن:',
                      [[self.button(user_id, ('✅ ' if draft['check_send_proxy'] else '▫️ ') + 'ارسال PROXY به health-check', 'wizard-toggle', key='check_send_proxy')],
                       [self.button(user_id, ('✅ ' if draft['shutdown_sessions'] else '▫️ ') + 'بستن نشست‌ها هنگام down', 'wizard-toggle', key='shutdown_sessions')],
                       [self.button(user_id, 'ادامهٔ انتخاب مسیرها ←', 'wizard-step', step='backends')]])
        elif field == 'backends':
            result = self.panel.request('/api/v1/telegram/snapshot')
            available = [x for x in result.get('tunnels', []) if x.get('server_id', 'local') == draft['server_id'] and x.get('metadata', {}).get('tun_remote') and x.get('metadata', {}).get('transport') != 'erspan']
            selected = {x['tunnel_id']: x for x in draft['backends']}
            rows = []
            for item in available[:40]:
                ident = item['id']; backend = selected.get(ident); role = backend.get('role', 'primary') if backend else ''
                label = ('✅ ' if backend else '▫️ ') + ident + (' · ' + role + ' · وزن ' + str(backend.get('weight', 1)) if backend else '')
                row = [self.button(user_id, label, 'wizard-backend', tunnel_id=ident)]
                if backend:
                    row.append(self.button(user_id, 'وزن +', 'wizard-weight', tunnel_id=ident))
                rows.append(row)
            rows.append([self.button(user_id, 'ادامه و بازبینی تنظیمات', 'wizard-step', step='review')])
            rows.append([self.button(user_id, 'لغو', 'wizard-cancel')])
            self.send(user_id, 'یک یا چند تونل برای pool مقصد انتخاب کن. با زدن دوباره نقش Primary/Backup عوض می‌شود؛ «وزن +» وزن هر مسیر را تغییر می‌دهد.', rows)
        elif field == 'review':
            if not draft['backends']:
                self.wizard_save(user_id, {**draft, 'step': 'backends'})
                self.send(user_id, 'برای ادامه حداقل یک تونل مقصد لازم است.', [[self.button(user_id, 'انتخاب تونل‌ها', 'wizard-step', step='backends')]])
                return
            summary = (f"{draft['action']} · {draft['id']}\nسرور: {draft['server_id']}\nورودی: {draft['listen_ip']}:{draft['listen_port']}\n"
                       f"مقصد پورت: {draft['backend_port']} · الگوریتم: {draft['algorithm']}\n"
                       f"تونل‌ها: {', '.join(x['tunnel_id'] + '/' + x.get('role','primary') + '/w' + str(x.get('weight',1)) for x in draft['backends'])}\n"
                       f"PROXY: {draft['proxy_protocol']} · health-check PROXY: {'روشن' if draft['check_send_proxy'] else 'خاموش'} · بستن نشست: {'روشن' if draft['shutdown_sessions'] else 'خاموش'}")
            self.send(user_id, 'بازبینی قانون HAProxy؛ با تأیید پیکربندی روی سرور اعمال می‌شود:\n\n' + summary,
                      [[self.button(user_id, '✅ اعمال قانون', 'wizard-apply'), self.button(user_id, '↩️ ویرایش مسیرها', 'wizard-step', step='backends')],
                       [self.button(user_id, 'لغو', 'wizard-cancel')]])

    def wizard_text(self, user_id, text):
        draft = self.wizard_get(user_id)
        if not draft or draft.get('step') not in ('id', 'listen_ip', 'listen_port', 'backend_port'):
            return False
        field = draft['step']; value = text.strip()
        if value == '.' and draft['action'] == 'update':
            value = str(draft.get(field, ''))
        if field == 'id' and not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,47}', value):
            self.prompt(user_id, 'شناسه باید با حرف/عدد کوچک شروع شود و فقط حروف کوچک، عدد، _ یا - داشته باشد. دوباره بفرست.')
            return True
        if field == 'listen_ip':
            try:
                import ipaddress
                value = str(ipaddress.ip_address(value))
            except ValueError:
                self.prompt(user_id, 'IP معتبر وارد کن؛ برای شنود همهٔ IPv4ها 0.0.0.0 را بفرست.')
                return True
        if field in ('listen_port', 'backend_port'):
            if not value.isdigit() or not 1 <= int(value) <= 65535:
                self.prompt(user_id, 'پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد. دوباره بفرست.')
                return True
            value = int(value)
        draft[field] = value
        draft['step'] = {'id': 'listen_ip', 'listen_ip': 'listen_port', 'listen_port': 'backend_port', 'backend_port': 'algorithm'}[field]
        self.wizard_save(user_id, draft)
        self.wizard_prompt(user_id)
        return True

    def report(self, user_id):
        now = time.time()
        incidents = self.state.connection.execute('SELECT * FROM incidents WHERE ended IS NULL OR ended>?', (now - 86400,)).fetchall()
        total = sum(max(0, min(now, item['ended'] or now) - max(now - 86400, item['started'])) for item in incidents)
        failures = self.state.connection.execute("SELECT COUNT(*) FROM audit WHERE at>? AND result IN ('failed','partial')", (now - 86400,)).fetchone()[0]
        self.send(user_id, f'📋 گزارش ۲۴ ساعت اخیر\nاختلال‌های تأییدشده {len(incidents)}\nمجموع مدت اختلال‌ها {duration(total)}\nعملیات نیازمند بررسی {failures}\nمدت‌ها مجموع اختلال سرورها، تونل‌ها و منابع هستند.')
        self.status(user_id)

    def audit(self, user_id):
        rows = self.state.connection.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 12').fetchall()
        lines = ['🧾 عملیات اخیر']
        for row in rows:
            stamp = dt.datetime.fromtimestamp(row['at'], self.zone).strftime('%m/%d %H:%M')
            lines.append(f"{stamp} · {row['user_id']} · {row['action']} · {row['target']} · {row['result']}")
        self.send(user_id, '\n'.join(lines))

    def dispatch(self, user_id, action, payload):
        admin_actions = {'confirm-tunnel', 'confirm-forward', 'execute-tunnel', 'execute-forward', 'forward',
                         'confirm-forward-delete', 'execute-forward-delete', 'audit', 'haproxy-widget',
                         'forward-new', 'forward-start', 'forward-edit', 'wizard-set', 'wizard-toggle', 'wizard-step',
                         'wizard-backend', 'wizard-weight', 'wizard-apply', 'wizard-cancel'}
        if action in admin_actions and self.users.get(user_id) != 'admin':
            raise PanelError('این عملیات فقط برای مدیر فعال است.')
        if action.startswith('confirm-'):
            if action == 'confirm-forward-delete':
                target = payload['rule_id']
                self.send(user_id, f'قانون {target} روی {payload["server_id"]} و listener آن حذف شود؟',
                          [[self.button(user_id, '🗑 بله، حذف کن', 'execute-forward-delete', **payload),
                            self.button(user_id, 'انصراف', 'forward', rule_id=target, server_id=payload['server_id'])]])
                return
            kind = action.removeprefix('confirm-')
            target = payload.get('tunnel_id') or payload.get('rule_id')
            operation = payload.get('operation') or ('فعال‌کردن' if payload.get('enabled') else 'غیرفعال‌کردن')
            self.send(user_id, f'اجرای {operation} برای {target} تأیید می‌شود؟',
                      [[self.button(user_id, '✅ تأیید اجرا', 'execute-' + kind, **payload),
                        self.button(user_id, 'انصراف', 'home')]])
        elif action == 'execute-tunnel':
            target = payload['tunnel_id']
            self.state.audit(user_id, payload['operation'], target, 'started')
            try:
                results = self.panel.operate(target, payload['operation'], payload['expected'])
                result = 'partial' if any('❌' in item for item in results) else 'ok'
                self.state.audit(user_id, payload['operation'], target, result)
                self.send(user_id, target + '\n' + '\n'.join(results),
                          [[self.button(user_id, '🔎 وضعیت تونل', 'tunnel', tunnel_id=target)]])
            except Exception:
                self.state.audit(user_id, payload['operation'], target, 'failed')
                raise
        elif action == 'execute-forward':
            target = payload['rule_id']
            self.state.audit(user_id, 'forward-enabled', target, 'started')
            try:
                self.panel.request('/api/v1/forwards', {'action': 'set-enabled', 'id': target,
                                   'server_id': payload['server_id'], 'enabled': payload['enabled']})
            except Exception:
                self.state.audit(user_id, 'forward-enabled', target, 'failed')
                raise
            self.state.audit(user_id, 'forward-enabled', target, 'ok')
            self.forward(user_id, target, payload['server_id'])
        elif action == 'execute-forward-delete':
            target = payload['rule_id']; server_id = payload['server_id']
            self.state.audit(user_id, 'forward-delete', target, 'started')
            try:
                self.panel.request('/api/v1/forwards', {'action': 'delete', 'id': target, 'server_id': server_id})
                self.state.audit(user_id, 'forward-delete', target, 'ok')
                self.forwards(user_id, server_id=server_id)
            except Exception:
                self.state.audit(user_id, 'forward-delete', target, 'failed')
                raise
        elif action == 'haproxy-widget':
            self.haproxy_widget(user_id, payload.get('server_id', 'local'))
        elif action == 'servers-text':
            self.servers_text(user_id, **payload)
        elif action == 'forward-new':
            self.send(user_id, 'سرور اجرای HAProxy برای قانون جدید را انتخاب کن:',
                      [[self.button(user_id, 'سرور مرکزی · local', 'forward-start', server_id='local')]] +
                      [[self.button(user_id, x['id'] + ' · ' + x.get('host', ''), 'forward-start', server_id=x['id'])]
                       for x in self.panel.snapshot().get('servers', [])])
        elif action == 'forward-start':
            self.start_forward_wizard(user_id, payload['server_id'])
        elif action == 'forward-edit':
            result = self.panel.request('/api/v1/forwards?server_id=' + urllib.parse.quote(payload['server_id'], safe=''))
            rule = next((x for x in result.get('items', []) if x.get('id') == payload['rule_id']), None)
            if not rule:
                raise PanelError('قانون برای ویرایش پیدا نشد.')
            self.start_forward_wizard(user_id, payload['server_id'], rule)
        elif action == 'wizard-set':
            draft = self.wizard_get(user_id)
            if not draft:
                raise PanelError('فرم منقضی شده؛ دوباره شروع کن.')
            key = payload['key']; draft[key] = payload['value']
            draft['step'] = {'algorithm': 'proxy', 'proxy_protocol': 'options'}[key]
            self.wizard_save(user_id, draft); self.wizard_prompt(user_id)
        elif action == 'wizard-toggle':
            draft = self.wizard_get(user_id)
            if not draft or payload.get('key') not in ('check_send_proxy', 'shutdown_sessions'):
                raise PanelError('فرم منقضی شده؛ دوباره شروع کن.')
            key = payload['key']; draft[key] = not draft[key]
            self.wizard_save(user_id, draft); self.wizard_prompt(user_id)
        elif action == 'wizard-step':
            draft = self.wizard_get(user_id)
            if not draft:
                raise PanelError('فرم منقضی شده؛ دوباره شروع کن.')
            step = payload.get('step')
            if step not in ('backends', 'review'):
                raise PanelError('مرحلهٔ فرم نامعتبر است.')
            draft['step'] = step; self.wizard_save(user_id, draft); self.wizard_prompt(user_id)
        elif action == 'wizard-backend':
            draft = self.wizard_get(user_id)
            if not draft:
                raise PanelError('فرم منقضی شده؛ دوباره شروع کن.')
            ident = payload.get('tunnel_id'); current = next((x for x in draft['backends'] if x['tunnel_id'] == ident), None)
            if current:
                if current.get('role', 'primary') == 'primary':
                    current['role'] = 'backup'
                else:
                    draft['backends'].remove(current)
            else:
                draft['backends'].append({'tunnel_id': ident, 'weight': 1, 'role': 'primary'})
            self.wizard_save(user_id, draft); self.wizard_prompt(user_id)
        elif action == 'wizard-weight':
            draft = self.wizard_get(user_id)
            if not draft:
                raise PanelError('فرم منقضی شده؛ دوباره شروع کن.')
            backend = next((x for x in draft['backends'] if x['tunnel_id'] == payload.get('tunnel_id')), None)
            if not backend:
                raise PanelError('ابتدا این تونل را به pool اضافه کن.')
            weights = (1, 2, 3, 5, 10, 20, 50, 100, 256)
            current = int(backend.get('weight', 1))
            backend['weight'] = weights[(weights.index(current) + 1) % len(weights)] if current in weights else 1
            self.wizard_save(user_id, draft); self.wizard_prompt(user_id)
        elif action == 'wizard-apply':
            draft = self.wizard_get(user_id)
            if not draft or draft.get('step') != 'review':
                raise PanelError('فرم منقضی شده؛ دوباره شروع کن.')
            data = {key: draft[key] for key in ('action', 'server_id', 'id', 'listen_ip', 'listen_port',
                    'backend_port', 'algorithm', 'proxy_protocol', 'check_send_proxy', 'shutdown_sessions',
                    'backends', 'enabled')}
            self.state.audit(user_id, 'forward-' + data['action'], data['id'], 'started')
            try:
                self.panel.request('/api/v1/forwards', data)
                self.state.audit(user_id, 'forward-' + data['action'], data['id'], 'ok')
                self.wizard_clear(user_id)
                self.send(user_id, 'قانون ذخیره و روی سرور اعمال شد.',
                          [[self.button(user_id, 'مشاهدهٔ قانون', 'forward', rule_id=data['id'], server_id=data['server_id'])],
                           [self.button(user_id, 'قوانین فورواردر', 'forwards', server_id=data['server_id'])]])
            except Exception:
                self.state.audit(user_id, 'forward-' + data['action'], data['id'], 'failed')
                raise
        elif action == 'wizard-cancel':
            self.wizard_clear(user_id); self.send(user_id, 'ویرایش قانون لغو شد.', [[self.button(user_id, 'فورواردر', 'forwards')]])
        else:
            handlers = {'home': self.home, 'status': self.status, 'servers': self.servers,
                        'servers-text': self.servers_text,
                        'server': self.server, 'tunnels': self.tunnels, 'tunnel': self.tunnel,
                        'diagnose': self.diagnose, 'hardware': self.hardware, 'forwards': self.forwards,
                        'tunnel-widget': self.tunnel_widget, 'forward': self.forward,
                        'report': self.report, 'audit': self.audit}
            if action not in handlers:
                raise PanelError('دکمه نامعتبر است؛ منوی اصلی را دوباره باز کن.')
            handlers[action](user_id, **payload)

    def handle_update(self, update):
        update_id = update['update_id']
        if update_id < self.state.get('offset', 0):
            return
        # Commit the offset before side effects, including confirmed restarts.
        self.state.put('offset', update_id + 1)
        widget_query = update.get('widget_query')
        if widget_query:
            kind = str(widget_query.get('data', '')).split(':', 1)[0]
            if kind == 'resources':
                self.resource_widget_query(widget_query)
            else:
                self.status_widget_query(widget_query)
            return
        query = update.get('callback_query')
        message = query.get('message', {}) if query else update.get('message', {})
        sender = (query or message).get('from', {}).get('id')
        chat = message.get('chat', {})
        authorized = sender in self.users and chat.get('type') == 'private' and chat.get('id') == sender
        if query:
            self.telegram.request('answerCallbackQuery', {'callback_query_id': query['id'],
                                  'text': 'در حال بررسی…' if authorized else 'دسترسی مجاز نیست.'})
        if not authorized:
            return
        try:
            if query:
                token = query.get('data', '')
                entry = self.callbacks.get(token)
                if not entry or entry['user'] != sender or entry['expires'] <= time.time():
                    self.send(sender, 'این دکمه منقضی شده است؛ /start را بفرست.')
                    return
                if entry['action'].startswith('execute-'):
                    del self.callbacks[token]
                self.dispatch(sender, entry['action'], entry['payload'])
            else:
                text = message.get('text', '').strip()
                if self.users.get(sender) == 'admin' and self.wizard_text(sender, text):
                    return
                command = text.split()[0].split('@')[0] if text else ''
                actions = {'/start': 'home', '/help': 'home', '/status': 'status', '/servers': 'servers',
                           '/tunnels': 'tunnel-widget', '/tunnel-list': 'tunnels', '/tunnel_list': 'tunnels',
                           '/hardware': 'hardware', '/forwards': 'forwards',
                           '/haproxy': 'forwards',
                           '/report': 'report', '/audit': 'audit'}
                self.dispatch(sender, actions.get(command, 'home'), {})
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            self.send(sender, '⚠️ عملیات کامل نشد.\n' + self.scrub(str(error))[:600])

    def monitor(self, now):
        admins = [user for user, role in self.users.items() if role == 'admin']
        try:
            snapshot = self.panel.snapshot()
        except (OSError, ValueError, RuntimeError):
            self.state.observe('panel', 'ارتباط با پنل مرکزی قطع است', True, now, 60, admins)
            return
        self.state.observe('panel', 'ارتباط با پنل مرکزی قطع است', False, now, 60, admins)
        statuses = {item['id']: item for item in snapshot['statuses']}
        for server in [{'id': 'local'}, *snapshot['servers']]:
            item = statuses.get(server['id'])
            if item is not None:
                self.state.observe('server:' + server['id'], 'دسترسی سرور ' + server['id'] + ' قطع است',
                                   item.get('reachable') is False, now, 60, admins)
        for tunnel_id, endpoints in tunnel_groups(snapshot).items():
            state = tunnel_state(endpoints)
            if state != 'unknown':
                self.state.observe('tunnel:' + tunnel_id, 'تونل ' + tunnel_id + ' قطع است', state == 'down', now, 60, admins)
        for item in snapshot['resources']:
            resources = item.get('resources') or {}
            if now - resources.get('checked_at', 0) > 120:
                continue
            for field, label in [('cpu', 'CPU'), ('memory', 'RAM'), ('disk', 'دیسک')]:
                value = resources.get(field + '_percent')
                if not isinstance(value, (int, float)):
                    continue
                key = 'resource:' + item['id'] + ':' + field
                threshold = 85 if self.state.is_alerted(key) else 90
                self.state.observe(key, f'مصرف بالای {label} روی {item["id"]}', value >= threshold, now, 120, admins)
        local = dt.datetime.fromtimestamp(now, self.zone)
        day = local.strftime('%Y-%m-%d')
        if local.hour >= self.config.get('daily_report_hour', 9) and self.state.get('daily_report_date') != day:
            incidents = self.state.connection.execute('SELECT COUNT(*) FROM incidents WHERE started>?', (now - 86400,)).fetchone()[0]
            text = f'📋 گزارش روزانهٔ avaTUN · {day}\nسرورهای آنلاین {sum(s.get("reachable") is True for s in statuses.values())}\nتونل‌ها {len(tunnel_groups(snapshot))}\nاختلال‌های تأییدشدهٔ ۲۴ ساعت {incidents}\nبرای جزئیات /report را بفرست.'
            with self.state.connection:
                self.state.queue(admins, 'daily:' + day, text)
            self.state.put('daily_report_date', day)

    def run(self):
        self.set_status('starting')
        self.telegram.request('getMe', {})
        if self.telegram.request('getWebhookInfo', {}).get('url'):
            raise RuntimeError('Polling requires removing the existing webhook first')
        self.telegram.request('setMyCommands', {'commands': [
            {'command': 'start', 'description': 'منوی مدیریت avaTUN'},
            {'command': 'status', 'description': 'نمای کلی شبکه'},
            {'command': 'servers', 'description': 'فهرست سرورها'},
            {'command': 'tunnels', 'description': 'وضعیت زندهٔ تونل‌ها'},
            {'command': 'tunnel_list', 'description': 'فهرست متنی تونل‌ها'},
            {'command': 'hardware', 'description': 'منابع و آپلود/دانلود'},
            {'command': 'forwards', 'description': 'قوانین فورواردر'},
            {'command': 'haproxy', 'description': 'مدیریت فورواردر'},
            {'command': 'report', 'description': 'گزارش ۲۴ ساعت'}]})
        self.set_status('ready')
        next_monitor = 0
        while True:
            try:
                # Long-poll first so a scheduled monitor or notification can never
                # hold up an already waiting user command.
                updates = self.telegram.request('getUpdates', {'offset': self.state.get('offset', 0),
                    'timeout': 5, 'limit': 20, 'allowed_updates': ['message', 'callback_query', 'widget_query']})
                self.set_status('ready')
                for update in updates:
                    self.handle_update(update)
                now = time.time()
                if now >= next_monitor:
                    self.monitor(now)
                    next_monitor = time.time() + 20
                self.state.deliver(self.telegram, self.scrub)
            except (OSError, ValueError, KeyError, RuntimeError) as error:
                self.set_status('retrying', type(error).__name__)
                logging.warning('Bot cycle failed (%s)', type(error).__name__)
                time.sleep(5)


def load_config(path):
    config = json.loads(pathlib.Path(path).read_text())
    for key in ('bot_token', 'panel_url', 'panel_username', 'panel_password'):
        if not isinstance(config.get(key), str) or not config[key]:
            raise ValueError('Missing config field: ' + key)
    users = list(config.get('admins', [])) + list(config.get('viewers', []))
    if not users and config.get('chat_id'):
        users = [config['chat_id']]
    if not users or any(type(user) is not int or user <= 0 for user in users):
        raise ValueError('Configure positive numeric Telegram user IDs in admins or viewers')
    url = urllib.parse.urlsplit(config['panel_url'])
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Invalid panel_url')
    if url.scheme == 'http' and url.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('Remote panel connections require HTTPS')
    hour = config.get('daily_report_hour', 9)
    if type(hour) is not int or not 0 <= hour <= 23:
        raise ValueError('daily_report_hour must be 0..23')
    try:
        ZoneInfo(config.get('timezone', 'Asia/Tehran'))
    except (KeyError, ValueError) as error:
        raise ValueError('Invalid report timezone') from error
    config.setdefault('state_path', '/var/lib/tunnelmgr/telegram.sqlite3')
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/avatun/telegram.json')
    parser.add_argument('--check', action='store_true', help='Validate configuration and remote access, then exit')
    args = parser.parse_args()
    bot = None
    try:
        config = load_config(args.config)
        logging.basicConfig(level=logging.INFO)
        bot = Bot(config)
        if args.check:
            profile = bot.telegram.request('getMe', {})
            bot.panel.snapshot()
            print(json.dumps({'ok': True, 'username': profile.get('username'), 'authorized_users': len(bot.users)}))
            return
        # A second process must not consume updates or replay management operations.
        lock_path = pathlib.Path(config['state_path'] + '.lock')
        with lock_path.open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            bot.run()
    except (OSError, ValueError, RuntimeError) as error:
        if bot is not None:
            try:
                bot.set_status('retrying', type(error).__name__)
            except OSError:
                pass
        logging.error('Telegram bot stopped (%s)', type(error).__name__)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
