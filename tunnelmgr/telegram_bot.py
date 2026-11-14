#!/usr/bin/env python3
"""Private Telegram operations and monitoring for the avaTUN panel."""
import argparse
import datetime as dt
import http.client
import fcntl
import http.cookiejar
import hashlib
import json
import logging
import os
import pathlib
import re
import secrets
import sqlite3
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from zoneinfo import ZoneInfo
from telegram_console import ConsoleMixin
from telegram_ui import digits, render, context


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

    def updates(self):
        return self.request('/api/v1/updates')

    def check_updates(self):
        previous = self.updates()
        queued = self.request('/api/v1/updates', {'action': 'check'}, timeout=20)
        requested = float(queued.get('requested_at', time.time()))
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            status = self.updates()
            if float(status.get('checked_at') or 0) >= requested or status.get('state') == 'error':
                return status
            if status.get('state') in ('available', 'current') and status.get('checked_at') != previous.get('checked_at'):
                return status
            time.sleep(1)
        return self.updates()

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
            try:
                payload = json.load(error)
            except (ValueError, AttributeError):
                payload = {}
            detail = str(payload.get('description') or '')[:200]
            if error.code == 429:
                try:
                    delay = float(payload.get('parameters', {}).get('retry_after', 5))
                except (ValueError, TypeError, AttributeError):
                    delay = 5
                time.sleep(min(max(delay, 1), 60))
            raise RuntimeError('Telegram HTTP ' + str(error.code) + (': ' + detail if detail else '')) from None
        except (OSError, ValueError):
            # The request URL contains a credential, so never propagate network exceptions.
            raise RuntimeError('Telegram connection failed') from None
        if not result.get('ok'):
            detail = str(result.get('description') or '')[:200]
            raise RuntimeError('Telegram rejected ' + method + (': ' + detail if detail else ''))
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


CONTROL_WIDGET_HTML = r'''<!doctype html><html><body><style>
body{margin:0;padding:10px 12px;color:var(--tg-theme-text-color);font:14px/1.4 sans-serif}.head,.row,.foot{display:flex;align-items:center;justify-content:space-between;gap:8px}.title{font-size:16px;font-weight:700}.hint,.sub{font-size:12px;color:var(--tg-theme-hint-color)}.nav,.actions{display:flex;gap:5px;flex-wrap:wrap;margin:8px 0}.nav button,.actions button,.foot button,.item button{border:0;border-radius:8px;padding:6px 9px;color:var(--tg-theme-button-text-color);background:var(--tg-theme-button-color);font:inherit}.nav button{font-size:11px}.nav button.active{filter:brightness(.78)}.list{display:grid;gap:6px;margin:8px 0}.item{background:var(--tg-theme-secondary-bg-color);border-radius:10px;padding:9px}.name{font-weight:700;overflow-wrap:anywhere}.sub{margin-top:3px;overflow-wrap:anywhere}.badge{font-size:11px;white-space:nowrap}.up{color:#25a879}.down{color:#e05d66}.unknown{color:#d99b2b}.foot{margin-top:8px}.foot button:disabled{opacity:.45}.message{min-height:18px;margin-top:5px;color:var(--tg-theme-hint-color);font-size:12px}
</style><div class="head"><div class="title" id="title">avaTUN</div><span class="hint" id="summary"></span></div><div class="nav" id="nav"></div><div class="list" id="list"></div><div class="actions" id="actions"></div><div class="foot"><span class="hint" id="page"></span><div><button id="prev">قبلی</button> <button id="next">بعدی</button> <button id="refresh">↻</button></div></div><div class="message" id="message"></div><script>
const TW=window.TelegramWidget,$=x=>document.getElementById(x);let s={page:'overview',role:'viewer',p:0,n:1,rows:[],actions:[]},busy=false;const tabs=[['overview','نمای کلی'],['servers','سرورها'],['tunnels','تونل‌ها'],['resources','منابع'],['forwards','فوروارد'],['report','گزارش'],['audit','عملیات'],['update','به‌روزرسانی']];function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function query(q){if(!TW||busy)return;busy=true;$('message').textContent='در حال دریافت…';TW.request(q).then(a=>{if(a?.result){const next=JSON.parse(a.result);if(next&&typeof next==='object')s=next}draw()}).catch(e=>{$('message').textContent=e?.code==='TIMEOUT'?'پاسخ سرور دیر رسید؛ دوباره بزن.':'اتصال موقتاً برقرار نیست'}).finally(()=>{busy=false})}function draw(){const page=s.page||'overview';$('title').textContent=s.title||'avaTUN';$('summary').textContent=s.summary||'';$('nav').innerHTML=tabs.filter(x=>!['forwards','audit','update'].includes(x[0])||s.role==='admin').map(x=>'<button data-q="nav:'+x[0]+'" class="'+(x[0]===page?'active':'')+'">'+x[1]+'</button>').join('');$('list').innerHTML=(s.rows||[]).map(x=>'<div class="item"><div class="row"><span class="name">'+esc(x.title)+'</span>'+(x.state?'<span class="badge '+esc(x.state)+'">'+esc(x.badge||'')+'</span>':'')+'</div>'+(x.lines||[]).map(y=>'<div class="sub">'+esc(y)+'</div>').join('')+(x.query?'<div class="actions"><button data-q="'+esc(x.query)+'">'+esc(x.button||'جزئیات')+'</button></div>':'')+'</div>').join('')||'<div class="item">داده‌ای برای نمایش نیست.</div>';$('actions').innerHTML=(s.actions||[]).map(x=>'<button data-q="'+esc(x.query)+'">'+esc(x.label)+'</button>').join('');$('page').textContent=s.n>1?((Number(s.p||0)+1)+' از '+s.n):'';$('prev').disabled=busy||Number(s.p||0)<=0;$('next').disabled=busy||Number(s.p||0)>=Number(s.n||1)-1;$('message').textContent=s.message||''}function askPage(p){query('page:'+s.page+':'+p)}for(const id of ['nav','list','actions'])$(id).onclick=e=>{const b=e.target.closest('[data-q]');if(b)query(b.dataset.q)};$('prev').onclick=()=>askPage(Math.max(0,Number(s.p||0)-1));$('next').onclick=()=>askPage(Math.min(Number(s.n||1)-1,Number(s.p||0)+1));$('refresh').onclick=()=>query('refresh');try{if(TW?.chatData)s=JSON.parse(TW.chatData)}catch{}draw();if(TW){TW.onEvent('chatDataChanged',()=>{try{s=JSON.parse(TW.chatData);draw()}catch{}});query('refresh');setInterval(()=>{if(TW.isActive&&!busy)query('refresh')},20000)}
</script></body></html>'''


def widget_chat_data(state, limit=1024):
    """Keep Telegram widget state replies within the Bot API byte limit."""
    display = json.loads(json.dumps(state, ensure_ascii=False))
    def encoded():
        return json.dumps(display, ensure_ascii=False, separators=(',', ':'))
    while len(encoded().encode('utf-8')) > limit:
        rows = display.get('rows') or []
        actions = display.get('actions') or []
        if len(rows) > 1:
            rows.pop()
        elif rows and len(rows[0].get('lines') or []) > 1:
            rows[0]['lines'].pop()
        elif rows and rows[0].get('lines') and len(str(rows[0]['lines'][-1])) > 12:
            line = str(rows[0]['lines'][-1])
            rows[0]['lines'][-1] = line[:max(8, len(line) * 2 // 3)] + '…'
        elif rows:
            rows.pop()
        elif actions:
            actions.pop()
        elif display.get('summary') and len(str(display['summary'])) > 12:
            display['summary'] = str(display['summary'])[:max(8, len(str(display['summary'])) * 2 // 3)] + '…'
        elif display.get('summary'):
            display['summary'] = ''
        elif display.get('message') and len(str(display['message'])) > 12:
            display['message'] = str(display['message'])[:max(8, len(str(display['message'])) * 2 // 3)] + '…'
        elif display.get('message'):
            display['message'] = ''
        elif display.get('title') and len(str(display['title'])) > 18:
            display['title'] = str(display['title'])[:max(10, len(str(display['title'])) * 2 // 3)] + '…'
        else:
            display = {'page':display.get('page','overview'),'role':display.get('role','viewer'),
                       'p':0,'n':1,'title':'avaTUN','summary':'','rows':[],'actions':[],
                       'message':'نمایش اطلاعات کوتاه شد.'}
            break
    return encoded()


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


class Bot(ConsoleMixin):
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
        self.widget_confirmations = {}
        self.widget_views = {}
        self.widget_confirmation_lock = threading.Lock()
        self.zone = ZoneInfo(config.get('timezone', 'Asia/Tehran'))
        with self.state.connection:
            self.state.connection.execute("DELETE FROM meta WHERE key LIKE 'callback:%' AND json_extract(value,'$.expires')<?", (time.time(),))
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
        rows = list(keyboard or [])
        if self.wizard_get(user_id):
            rows.append([self.button(user_id,'لغو فرم','cancel')])
        elif not rows:
            rows.append([self.button(user_id,'خانه','home')])
        self.present(user_id,text,rows)

    def button(self, user_id, label, action, **payload):
        now = time.time()
        self.callbacks = {key: value for key, value in self.callbacks.items() if value['expires'] > now}
        if len(self.callbacks) >= 2048:
            self.callbacks.pop(next(iter(self.callbacks)))
        token = secrets.token_urlsafe(12)
        if action.startswith('wizard-'):
            payload['wizard_revision'] = (self.wizard_get(user_id) or {}).get('revision')
        once = action.startswith('execute-') or action in ('widget-fallback-execute','run-operation','wizard-apply')
        entry = {'user':user_id,'action':action,'payload':payload,'expires':now+(180 if once else 86400),'once':once}
        self.callbacks[token] = entry
        self.state.put('callback:'+token,entry)
        return {'text':digits(label)[:60], 'callback_data':token}

    def home(self, user_id):
        return self.show_screen(user_id, 'overview')

    def status(self, user_id):
        return self.show_screen(user_id, 'overview')

    def servers(self, user_id, page=0):
        return self.show_screen(user_id, 'servers', page)

    def servers_text(self, user_id, page=0):
        return self.show_screen(user_id, 'servers', page)

    def server(self, user_id, server_id):
        return self.show_screen(user_id, 'server', server_id=server_id, selected=server_id)

    def pagination(self, user_id, action, page, count, **payload):
        buttons = []
        if page > 0:
            buttons.append(self.button(user_id, 'قبلی', action, page=page - 1, **payload))
        if (page + 1) * 8 < count:
            buttons.append(self.button(user_id, 'بعدی', action, page=page + 1, **payload))
        return ([buttons] if buttons else []) + [[self.button(user_id, 'منوی اصلی', 'home')]]

    def tunnels(self, user_id, page=0, server_id=None):
        return self.show_screen(user_id, 'tunnels', page, server_id or 'all')

    def tunnel(self, user_id, tunnel_id):
        return self.show_screen(user_id, 'tunnel', selected=tunnel_id)

    def diagnose(self, user_id, tunnel_id):
        return self.show_screen(user_id, 'tunnel', selected=tunnel_id)

    def hardware(self, user_id):
        return self.show_screen(user_id, 'resources')

    def widget(self, user_id, html, state, caption):
        source = html.encode('utf-8')
        if not source or len(source) > 32768 or len(zlib.compress(source, 9)) > 4096:
            raise ValueError('Widget HTML exceeds Telegram size limits.')
        return self.telegram.request('sendWidget', {
            'chat_id': user_id, 'html': html,
            'chat_data': widget_chat_data(state),
            'caption': caption, 'allow_queries': True, 'protect_content': True})

    def widget_delivery_key(self, user_id):
        # A denied chat or a previous bot token must not disable every user.
        identity = hashlib.sha256(self.config['bot_token'].encode()).hexdigest()[:16]
        return f'widget-delivery:{identity}:{user_id}'

    def widget_delivery_fallback(self, user_id, state):
        state = dict(state)
        notice = ('تلگرام ارسال ویجت را رد کرده است (INPUT_MEDIA_WIDGET_NOT_ALLOWED). '
                  'فعلاً منوی دکمه‌ای نمایش داده می‌شود. پس از 5 دقیقه، با بازکردن دوبارهٔ منو '
                  'ارسال ویجت دوباره امتحان می‌شود؛ دکمهٔ زیر همین حالا تلاش می‌کند.')
        state['message'] = '\n'.join(filter(None, [state.get('message'), notice]))
        self.widget_fallback(user_id, state)

    def control_widget_state(self, user_id, page='overview', page_index=0, server_id='all', selected=''):
        role = self.users.get(user_id, 'viewer')
        page = page if page in ('overview','servers','server','tunnels','tunnel','resources','forwards','forward','report','audit','update','confirm') else 'overview'
        snapshot = self.panel.snapshot()
        statuses = {str(x.get('id')): x for x in snapshot.get('statuses', [])}
        resources = {str(x.get('id')): x for x in snapshot.get('resources', [])}
        groups = tunnel_groups(snapshot)
        servers = [{'id':'local','name':'سرور مرکزی','host':'پنل مرکزی'}, *snapshot.get('servers', [])]
        page_size = 4
        state = {'page':page,'role':role,'p':0,'n':1,'title':'avaTUN','summary':'پایش و مدیریت','rows':[],'actions':[],'server_id':server_id,'selected':selected}
        def row(title, lines=(), status='', badge='', query='', button='جزئیات'):
            value={'title':str(title)[:80], 'lines':[str(x)[:110] for x in lines[:3]]}
            if status:value.update({'state':status,'badge':str(badge)[:30]})
            if query:value.update({'query':query[:64],'button':button[:28]})
            return value
        def pages(entries, wanted, title):
            total=max(1,(len(entries)+page_size-1)//page_size);p=min(max(0,int(wanted or 0)),total-1)
            state.update({'title':title,'p':p,'n':total})
            return entries[p*page_size:p*page_size+page_size]
        if page == 'overview':
            online=sum(x.get('reachable') is True for x in snapshot.get('statuses', []));up=sum(tunnel_state(x)=='up' for x in groups.values());down=sum(tunnel_state(x)=='down' for x in groups.values())
            version=next((str(x.get('app_version')) for x in snapshot.get('statuses',[]) if x.get('id')=='local'),'—')
            state.update({'title':'avaTUN · مرکز کنترل','summary':version,'rows':[row('وضعیت شبکه',[f'سرورهای آنلاین {online} از {len(servers)}',f'تونل‌های برقرار {up} از {len(groups)} · قطع {down} · نامشخص {max(0,len(groups)-up-down)}'])],
                          'actions':[{'label':'↻ تازه‌سازی','query':'refresh'}]})
            if role=='admin':state['actions'].append({'label':'بررسی نسخهٔ جدید','query':'nav:update'})
        elif page == 'servers':
            entries=pages(servers,page_index,'سرورها')
            state['rows']=[]
            for item in entries:
                ident=str(item.get('id',''));status=statuses.get(ident,{});resource=resources.get(ident,{}).get('resources') or resources.get(ident,{})
                reachable=status.get('reachable');health='up' if reachable is True else 'down' if reachable is False else 'unknown'
                count=sum(ident in endpoints for endpoints in groups.values())
                state['rows'].append(row(item.get('name') or item.get('label') or ident,[item.get('host') or '—',f'{count} تونل · نسخه {status.get("app_version") or "—"}',f'CPU {resource.get("cpu_percent","—")}% · RAM {resource.get("memory_percent","—")}%'],health,{'up':'آنلاین','down':'قطع','unknown':'نامشخص'}[health],f'open:server:{ident}'))
            state['actions']=[]
        elif page == 'server':
            item=next((x for x in servers if str(x.get('id'))==selected),None)
            if not item:raise PanelError('سرور انتخاب‌شده پیدا نشد.')
            ident=str(item['id']);status=statuses.get(ident,{});res=resources.get(ident,{}).get('resources') or resources.get(ident,{})
            health='up' if status.get('reachable') is True else 'down' if status.get('reachable') is False else 'unknown'
            state.update({'title':str(item.get('name') or ident)[:60],'summary':str(item.get('host') or '')[:60],
                          'rows':[row('اتصال',[f'SSH: {"متصل" if status.get("reachable") else "قطع/نامشخص"}',f'سرویس پنل: {"فعال" if status.get("services") and all(x=="active" for x in status["services"]) else "بررسی شود"}',f'نسخه {status.get("app_version") or "—"}'],health,{'up':'آنلاین','down':'قطع','unknown':'نامشخص'}[health]),
                                  row('منابع',[f'CPU {res.get("cpu_percent","—")}% · Load {res.get("load_1m","—")}',f'RAM {res.get("memory_percent","—")}% · دیسک {res.get("disk_percent","—")}%',f'{sum(ident in e for e in groups.values())} تونل روی این سرور']),
                                  row('تونل‌های متصل به سرور',[', '.join(k for k,v in groups.items() if ident in v) or 'تونلی ثبت نشده'])],
                          'actions':[{'label':'تونل‌های سرور','query':'sp:t:'+ident},{'label':'منابع','query':'sp:r:'+ident},{'label':'بازگشت','query':'nav:servers'}]})
        elif page == 'resources':
            entries=[resources[x['id']] for x in servers if x['id'] in resources]
            if server_id not in ('all','local'):entries=[x for x in entries if x.get('id')==server_id]
            elif server_id=='local':entries=[x for x in entries if x.get('id')=='local']
            visible=pages(entries,page_index,'منابع سرورها')
            state['rows']=[]
            for item in visible:
                r=item.get('resources') or {};ident=str(item.get('id',''));checked=r.get('checked_at')
                state['rows'].append(row(item.get('name') or ident,[item.get('host') or '—',f'CPU {r.get("cpu_percent","—")}% · RAM {r.get("memory_percent","—")}% · دیسک {r.get("disk_percent","—")}%',f'↓ {size(r.get("download_bytes_per_sec"))}/s · ↑ {size(r.get("upload_bytes_per_sec"))}/s · نمونه {duration(time.time()-checked) if checked else "نامشخص"} قبل']))
        elif page == 'tunnels':
            entries=sorted((k,v) for k,v in groups.items() if server_id=='all' or server_id in v)
            visible=pages(entries,page_index,'تونل‌ها')
            for ident,endpoints in visible:
                values=list(endpoints.values());ts=tunnel_state(endpoints);kinds=sorted({str(x.get('metadata',{}).get('transport') or x.get('kind') or 'تونل') for x in values});ips=[x.get('health',{}).get('interface_local_ip') or x.get('metadata',{}).get('tun_local') or '—' for x in values];rtts=[x.get('health',{}).get('rtt_ms') for x in values if x.get('health',{}).get('rtt_ms') is not None]
                state['rows'].append(row(ident,[(' + '.join(kinds))[:100],' ↔ '.join(str(x.get('server_id') or 'local') for x in values)[:100],'IP '+ ' ⇄ '.join(str(x) for x in ips)[:100]+' · پینگ '+(f'{max(rtts):.1f} ms' if rtts else '—')],ts,{'up':'برقرار','down':'قطع','unknown':'نامشخص'}[ts],f'open:tunnel:{ident}'))
        elif page == 'tunnel':
            endpoints=groups.get(selected)
            if not endpoints:raise PanelError('تونل انتخاب‌شده پیدا نشد.')
            state.update({'title':'تونل '+selected,'summary':f'{len(endpoints)} سمت','rows':[]})
            for sid,item in endpoints.items():
                meta=item.get('metadata',{});health=item.get('health',{});live=item.get('live',{});ts=health.get('state','unknown');ip=health.get('interface_local_ip') or meta.get('tun_local') or '—';peer=health.get('interface_peer_ip') or meta.get('tun_remote') or '—'
                state['rows'].append(row(sid,[str(meta.get('transport') or item.get('kind') or 'تونل'),f'IP داخلی {ip} ⇄ {peer}',f'پینگ {health.get("rtt_ms","—")} ms · MTU {meta.get("mtu") or meta.get("tun_mtu") or "—"}'+(' · سرویس خاموش' if live.get('active') is False else '')],ts,{'up':'برقرار','down':'قطع','error':'خطا','monitor-only':'پایش محدود'}.get(ts,'نامشخص')))
            state['actions']=[{'label':'بررسی دوباره','query':f'refresh:tunnel:0:local:{selected}'}]
            if role=='admin' and len(endpoints)>=2:
                state['actions'] += [{'label':label,'query':f'confirm:{op}:{selected}'} for label,op in (('▶ شروع','start'),('↻ راه‌اندازی مجدد','restart'),('⏸ توقف','stop'))]
        elif page == 'forwards':
            if role!='admin':raise PanelError('مدیریت فورواردر فقط برای مدیر فعال است.')
            result=self.panel.request('/api/v1/forwards?server_id='+urllib.parse.quote(server_id,safe=''));entries=[x for x in result.get('items',[]) if x.get('server_id','local')==server_id]
            visible=pages(entries,page_index,'فورواردر · '+server_id);service=result.get('service') or {}
            state.update({'summary':'HAProxy '+('فعال' if service.get('active') else 'خاموش/نامشخص'),'server_id':server_id})
            for rule in visible:
                state['rows'].append(row(rule.get('id'),[f'{rule.get("listen_ip")}:{rule.get("listen_port")} → پورت {rule.get("backend_port")}',f'{len(rule.get("backends",[]))} مسیر · {rule.get("algorithm","leastconn")}'], 'up' if rule.get('enabled',True) else 'unknown','فعال' if rule.get('enabled',True) else 'متوقف',f'open:forward:{server_id}:{rule.get("id")}'))
            state['actions']=[{'label':str(x.get('id'))[:18],'query':'server:'+str(x.get('id'))} for x in servers[:4]]
            state['actions'].append({'label':'＋ قانون جدید','query':'forward-new:'+server_id})
        elif page == 'forward':
            if role!='admin':raise PanelError('مدیریت فورواردر فقط برای مدیر فعال است.')
            result=self.panel.request('/api/v1/forwards?server_id='+urllib.parse.quote(server_id,safe=''));rule=next((x for x in result.get('items',[]) if x.get('id')==selected and x.get('server_id','local')==server_id),None)
            if not rule:raise PanelError('قانون فورواردر پیدا نشد.')
            state.update({'title':'فورواردر '+selected,'summary':server_id,'rows':[row('ورودی',[f'{rule.get("listen_ip")}:{rule.get("listen_port")}',f'مقصد پورت {rule.get("backend_port")} · {rule.get("algorithm","leastconn")}',', '.join(x.get('tunnel_id','') for x in rule.get('backends',[])) or 'مسیر ثبت نشده'],'up' if rule.get('enabled',True) else 'unknown','فعال' if rule.get('enabled',True) else 'متوقف')],
                          'actions':[{'label':'ویرایش','query':'edit-forward:'+selected},
                                     {'label':'فعال/توقف','query':'cf:toggle:'+selected},
                                     {'label':'حذف قانون','query':'cf:delete:'+selected},
                                     {'label':'فورواردر','query':'nav:forwards'}]})
        elif page == 'report':
            now=time.time();incidents=self.state.connection.execute('SELECT * FROM incidents WHERE ended IS NULL OR ended>?',(now-86400,)).fetchall();total=sum(max(0,min(now,x['ended'] or now)-max(now-86400,x['started'])) for x in incidents);failures=self.state.connection.execute("SELECT COUNT(*) FROM audit WHERE at>? AND result IN ('failed','partial')",(now-86400,)).fetchone()[0]
            state.update({'title':'گزارش ۲۴ ساعت','rows':[row('شبکه',[f'{sum(x.get("reachable") is True for x in snapshot.get("statuses",[]))} سرور آنلاین · {sum(tunnel_state(v)=="up" for v in groups.values())} تونل برقرار',f'{len(incidents)} اختلال ثبت‌شده · مجموع {duration(total)}',f'{failures} عملیات ناموفق یا ناقص'])]})
        elif page == 'audit':
            if role!='admin':raise PanelError('فهرست عملیات فقط برای مدیر فعال است.')
            rows=pages(self.state.connection.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 80').fetchall(),page_index,'عملیات اخیر');state.update({'title':'عملیات اخیر','rows':[row(dt.datetime.fromtimestamp(x['at'],self.zone).strftime('%m/%d %H:%M')+' · '+x['action'],[str(x['target'])[:70],str(x['result'])[:30]]) for x in rows]})
        elif page == 'update':
            if role!='admin':raise PanelError('به‌روزرسانی فقط برای مدیر فعال است.')
            status=self.panel.updates();state.update({'title':'به‌روزرسانی avaTUN','summary':str(status.get('state','—')),'update_available':bool(status.get('update_available')),'latest_commit':status.get('latest_commit'),'latest_version':status.get('latest_version'),'rows':[row('نسخهٔ پنل',[f'فعلی {status.get("current_version","—")} · GitHub {status.get("latest_version","—")}',str(status.get('error') or ('نسخهٔ جدید موجود است' if status.get('update_available') else 'به‌روز است'))])], 'actions':[{'label':'بررسی دوباره','query':'update-check'}]})
            if status.get('update_available'):state['actions'].append({'label':'نصب نسخه','query':'confirm:update:panel'})
        elif page == 'confirm':
            state.update({'title':'تأیید عملیات','summary':'این تغییر روی سرور اعمال می‌شود'})
        return state

    def widget_fallback(self, user_id, state):
        text, keyboard = render(state, lambda label, action, **payload:self.button(user_id,label,action,**payload))
        self.present(user_id,text,keyboard,html=True,screen=context(state))

    def fallback_confirm(self, user_id, text, operation, context):
        self.send(user_id, text, [[self.button(user_id,'✅ تأیید و اجرا','widget-fallback-execute',
                                               operation=operation,context=context),
                                   self.button(user_id,'لغو','widget-fallback-query',
                                               query='refresh',context=context)]])

    def widget_fallback_query(self, user_id, data, context=None):
        context=context or {'page':'overview','page_index':0,'server_id':'all','selected':''}
        page=context.get('page','overview');server_id=context.get('server_id','all');selected=context.get('selected','')
        if data=='refresh':
            self.show_control_widget(user_id,page,context.get('page_index',0),server_id,selected);return
        if data.startswith('nav:'):
            page=data.split(':',1)[1];server_id='local' if page=='forwards' else 'all'
            if page=='update':
                self.panel.request('/api/v1/updates',{'action':'check'},timeout=8)
            self.show_control_widget(user_id,page,0,server_id);return
        if data.startswith('page:'):
            _,page,index=data.split(':',2)
            self.show_control_widget(user_id,page,int(index),server_id,selected);return
        if data.startswith('open:server:'):
            selected=data.split(':',2)[2];self.show_control_widget(user_id,'server',0,'local',selected);return
        if data.startswith('open:tunnel:'):
            selected=data.split(':',2)[2];self.show_control_widget(user_id,'tunnel',0,'local',selected);return
        if data.startswith('open:forward:'):
            _,_,server_id,selected=data.split(':',3);self.show_control_widget(user_id,'forward',0,server_id,selected);return
        if data.startswith('sp:'):
            _,code,server_id=data.split(':',2);page={'t':'tunnels','r':'resources','f':'forwards'}.get(code)
            if not page:raise PanelError('بخش سرور نامعتبر است.')
            self.show_control_widget(user_id,page,0,server_id);return
        if data.startswith('server:'):
            server_id=data.split(':',1)[1]
            page='forwards' if page=='forwards' else 'tunnels' if page=='tunnels' else 'resources'
            self.show_control_widget(user_id,page,0,server_id);return
        if data=='update-check':
            self.panel.request('/api/v1/updates',{'action':'check'},timeout=8)
            self.show_control_widget(user_id,'update');return
        if data.startswith('forward-new:'):
            if self.users.get(user_id)!='admin':raise PanelError('این عملیات فقط برای مدیر فعال است.')
            self.start_forward_wizard(user_id,data.split(':',1)[1]);return
        if data.startswith('edit-forward:'):
            if self.users.get(user_id)!='admin':raise PanelError('این عملیات فقط برای مدیر فعال است.')
            self.dispatch(user_id,'forward-edit',{'server_id':server_id,'rule_id':data.split(':',1)[1]});return
        if data.startswith('confirm:'):
            if self.users.get(user_id)!='admin':raise PanelError('این عملیات فقط برای مدیر فعال است.')
            _,action,target=data.split(':',2)
            if action=='update':
                status=self.panel.updates()
                if not status.get('update_available'):raise PanelError('نسخهٔ جدیدی برای نصب موجود نیست.')
                operation={'kind':'update','target':'panel','commit':status.get('latest_commit')}
                label=f"نصب avaTUN {status.get('latest_version')}؟"
            else:
                endpoints=tunnel_groups(self.panel.snapshot()).get(target)
                if action not in ('start','stop','restart') or not endpoints or len(endpoints)<2:
                    raise PanelError('برای این عملیات هر دو سمت تونل باید ثبت شده باشند.')
                operation={'kind':'tunnel','action':action,'target':target,'expected':sorted(endpoints)}
                label=f'اجرای {action} برای تونل {target} روی هر دو سمت؟'
            self.fallback_confirm(user_id,label,operation,context);return
        if data.startswith('cf:'):
            if self.users.get(user_id)!='admin':raise PanelError('این عملیات فقط برای مدیر فعال است.')
            _,action,target=data.split(':',2)
            result=self.panel.request('/api/v1/forwards?server_id='+urllib.parse.quote(server_id,safe=''))
            rule=next((x for x in result.get('items',[]) if x.get('id')==target and x.get('server_id','local')==server_id),None)
            if not rule or action not in ('toggle','delete'):raise PanelError('قانون فورواردر پیدا نشد.')
            operation={'kind':'forward','action':action,'target':target,'server_id':server_id,
                       'enabled':bool(rule.get('enabled',True))}
            self.fallback_confirm(user_id,f'تغییر وضعیت قانون {target} روی {server_id} تأیید می‌شود؟',operation,context);return
        raise PanelError('دکمهٔ این بخش منقضی شده است؛ /start را دوباره بفرست.')

    def execute_widget_fallback(self, user_id, operation, context=None):
        context=context or {'page':'overview','server_id':'all','selected':''}
        kind=operation.get('kind');action=operation.get('action','');target=operation.get('target','')
        audit_action='github-update' if kind=='update' else 'forward-'+action if kind=='forward' else action
        self.state.audit(user_id,audit_action,target,'started')
        try:
            if kind=='update':
                status=self.panel.updates()
                if not status.get('update_available') or status.get('latest_commit')!=operation.get('commit'):
                    raise PanelError('نسخهٔ GitHub عوض شده؛ دوباره بررسی کن.')
                self.panel.request('/api/v1/updates',{'action':'apply'},timeout=30)
                message='درخواست نصب ثبت شد؛ پنل پس از به‌روزرسانی دوباره متصل می‌شود.'
                page='update';server_id='local';selected=''
            elif kind=='tunnel':
                result=self.panel.operate(target,action,operation['expected'])
                message=' · '.join(result)[:180];page='tunnel';server_id='local';selected=target
            elif kind=='forward':
                if action=='toggle':
                    self.panel.request('/api/v1/forwards',{'action':'set-enabled','id':target,
                        'server_id':operation['server_id'],'enabled':not operation['enabled']},timeout=15)
                elif action=='delete':
                    self.panel.request('/api/v1/forwards',{'action':'delete','id':target,
                        'server_id':operation['server_id']},timeout=15)
                else:raise PanelError('عملیات فورواردر نامعتبر است.')
                message='تغییر فورواردر اعمال شد.';page='forwards';server_id=operation['server_id'];selected=''
            else:raise PanelError('نوع عملیات ناشناخته است.')
            self.state.audit(user_id,audit_action,target,'ok')
            self.show_control_widget(user_id,page,0,server_id,selected)
            self.send(user_id,message)
        except Exception as error:
            self.state.audit(user_id,audit_action,target,'failed')
            self.send(user_id,'⚠️ عملیات کامل نشد.\n'+self.scrub(error)[:400])

    def show_control_widget(self, user_id, page='overview', page_index=0, server_id='all', selected=''):
        state=self.control_widget_state(user_id,page,page_index,server_id,selected)
        delivery_key = self.widget_delivery_key(user_id)
        delivery = self.state.get(delivery_key) or {}
        if delivery.get('retry_at', 0) > time.time():
            self.widget_delivery_fallback(user_id,state)
            return
        # Telegram cannot replace the HTML of an existing widget. Send a new
        # message after a layout upgrade instead of editing the old widget's data.
        layout = hashlib.sha256(CONTROL_WIDGET_HTML.encode()).hexdigest()
        storage_key='control-widget:'+str(user_id);saved=self.state.get(storage_key)
        if saved and saved.get('chat_id')==user_id and saved.get('message_id') and saved.get('layout')==layout:
            try:
                self.telegram.request('editMessageWidgetData',{'chat_id':user_id,'message_id':int(saved['message_id']),
                    'chat_data':widget_chat_data(state)})
                self.widget_views[(user_id,user_id,int(saved['message_id']))]={**state,'expires':time.time()+1800}
                self.state.put(f'control-view:{user_id}:{int(saved["message_id"])}',{**state,'expires':time.time()+1800})
                return
            except RuntimeError as error:
                if 'message is not modified' in str(error).lower():
                    self.widget_views[(user_id,user_id,int(saved['message_id']))]={**state,'expires':time.time()+1800}
                    self.state.put(f'control-view:{user_id}:{int(saved["message_id"])}',{**state,'expires':time.time()+1800})
                    return
                self.state.put(storage_key,None)
        try:
            result=self.widget(user_id,CONTROL_WIDGET_HTML,state,'avaTUN · '+state.get('title','مرکز کنترل'))
        except RuntimeError as error:
            if 'INPUT_MEDIA_WIDGET_NOT_ALLOWED' not in str(error):raise
            logging.warning('Telegram rejected sendWidget with INPUT_MEDIA_WIDGET_NOT_ALLOWED; retry after 300 seconds.')
            self.state.put(delivery_key, {'error':'INPUT_MEDIA_WIDGET_NOT_ALLOWED',
                                         'retry_at':time.time()+300})
            self.widget_delivery_fallback(user_id,state)
            return
        self.state.put(delivery_key, {'retry_at':0})
        message_id=(result or {}).get('message_id');chat_id=((result or {}).get('chat') or {}).get('id',user_id)
        if message_id:
            self.state.put(storage_key,{'chat_id':chat_id,'message_id':int(message_id),'layout':layout})
            self.widget_views[(user_id,chat_id,int(message_id))]={**state,'expires':time.time()+1800}
            self.state.put(f'control-view:{user_id}:{int(message_id)}',{**state,'expires':time.time()+1800})

    def answer_widget(self, query, state):
        encoded=widget_chat_data(state)
        sender=query.get('from',{}).get('id');chat=query.get('chat') or {};message_id=query.get('message_id')
        if sender is not None and chat.get('id') is not None and message_id is not None:
            now=time.time();self.widget_views={k:v for k,v in self.widget_views.items() if v.get('expires',0)>now}
            self.widget_views[(sender,chat['id'],int(message_id))]={**state,'expires':now+1800}
            self.state.put(f'control-view:{sender}:{int(message_id)}',{**state,'expires':now+1800})
        self.telegram.request('answerWidgetQuery',{'widget_query_id':query['id'],'data':encoded})

    def _background_audit(self, user_id, action, target, result):
        try:
            connection = sqlite3.connect(self.state.path, timeout=5)
            with connection:
                connection.execute('INSERT INTO audit(at,user_id,action,target,result) VALUES(?,?,?,?,?)',
                                   (time.time(), user_id, action, str(target), result))
            connection.close()
        except sqlite3.Error as error:
            logging.warning('Widget operation audit failed (%s)', type(error).__name__)

    def _run_widget_operation(self, sender, chat_id, message_id, operation):
        kind = operation.get('kind')
        action = operation.get('action', '')
        target = operation.get('target', '')
        server_id = operation.get('server_id', 'local')
        audit_action = ('github-update' if kind == 'update' else
                        'forward-' + action if kind == 'forward' else action)
        self._background_audit(sender, audit_action, target, 'started')
        try:
            if kind == 'update':
                status = self.panel.updates()
                if not status.get('update_available') or status.get('latest_commit') != operation.get('commit'):
                    raise PanelError('نسخهٔ GitHub عوض شده؛ دوباره بررسی کن.')
                result = self.panel.request('/api/v1/updates', {'action': 'apply'}, timeout=30)
                final = {'page':'update','role':'admin','title':'به‌روزرسانی avaTUN','summary':'در حال نصب',
                         'rows':[],'actions':[{'label':'بررسی وضعیت','query':'refresh'}],
                         'message':'درخواست نصب ثبت شد؛ پنل پس از به‌روزرسانی دوباره متصل می‌شود.' if result.get('state')=='installing' else 'درخواست نصب ارسال شد.'}
            elif kind == 'tunnel':
                results = self.panel.operate(target, action, operation['expected'])
                failed = any('❌' in item for item in results)
                self._background_audit(sender, audit_action, target, 'partial' if failed else 'ok')
                final = self.control_widget_state(sender, 'tunnel', 0, 'local', target)
                final['message'] = ' · '.join(results)[:180]
            elif kind == 'forward':
                if action == 'toggle':
                    self.panel.request('/api/v1/forwards', {'action':'set-enabled','id':target,
                        'server_id':server_id,'enabled':not operation['enabled']}, timeout=15)
                elif action == 'delete':
                    self.panel.request('/api/v1/forwards', {'action':'delete','id':target,
                        'server_id':server_id}, timeout=15)
                else:
                    raise PanelError('عملیات فورواردر نامعتبر است.')
                self._background_audit(sender, audit_action, target, 'ok')
                final = self.control_widget_state(sender, 'forwards', 0, server_id)
                final['message'] = 'تغییر فورواردر اعمال شد.'
            else:
                raise PanelError('نوع عملیات ناشناخته است.')
        except Exception as error:
            self._background_audit(sender, audit_action, target, 'failed')
            final = dict(operation.get('return_state') or {})
            final.update({'title':'عملیات ناموفق','message':self.scrub(error)[:180],
                          'actions':[{'label':'بازگشت','query':operation.get('return_query','refresh')} ]})
        final['role'] = 'admin'
        final['expires'] = time.time() + 1800
        key = (sender, chat_id, int(message_id))
        self.widget_views[key] = final
        try:
            self.telegram.request('editMessageWidgetData', {'chat_id':chat_id,'message_id':int(message_id),
                'chat_data':widget_chat_data(final)})
        except (OSError,ValueError,RuntimeError) as error:
            logging.warning('Widget operation result update failed (%s)', type(error).__name__)

    def control_widget_query(self, query):
        sender=query.get('from',{}).get('id');chat=query.get('chat') or {};data=query.get('data','')
        authorized=sender in self.users and chat.get('type')=='private' and chat.get('id')==sender
        message_id=query.get('message_id')
        if not authorized or not isinstance(data,str) or len(data.encode('utf-8'))>64:
            self.answer_widget(query,{'page':'overview','role':'viewer','title':'دسترسی محدود','summary':'','rows':[],'actions':[],'message':'این ویجت برای این حساب قابل استفاده نیست.'});return
        role=self.users[sender];view_key=(sender,chat['id'],int(message_id or 0));current=self.widget_views.get(view_key) or self.state.get(f'control-view:{sender}:{int(message_id or 0)}',{})
        if current.get('expires',0)<time.time():current={}
        try:
            if data=='refresh':
                state=self.control_widget_state(sender,current.get('page','overview'),int(current.get('p',0)),current.get('server_id','local'),current.get('selected',''))
            elif data.startswith('nav:'):
                page=data.split(':',1)[1]
                if page in ('forwards','audit','update') and role!='admin':raise PanelError('این بخش فقط برای مدیر فعال است.')
                if page=='update':
                    self.panel.request('/api/v1/updates',{'action':'check'},timeout=8)
                state=self.control_widget_state(sender,page,0,'local' if page=='forwards' else 'all')
                if page=='update':state['message']='درخواست بررسی نسخه ثبت شد؛ نتیجه با تازه‌سازی نمایش داده می‌شود.'
            elif data.startswith('page:'):
                parts=data.split(':',2);_,page,p=(parts+['']*3)[:3]
                if page in ('forwards','audit','update') and role!='admin':raise PanelError('این بخش فقط برای مدیر فعال است.')
                state=self.control_widget_state(sender,page,int(p or 0),current.get('server_id','local'),current.get('selected',''))
            elif data.startswith('sp:'):
                _,code,server_id=data.split(':',2)
                page={'t':'tunnels','r':'resources','f':'forwards'}.get(code,'')
                if not page:raise PanelError('بخش سرور نامعتبر است.')
                if server_id not in {'local',*(str(x.get('id')) for x in self.panel.snapshot().get('servers',[]))}:raise PanelError('سرور انتخاب‌شده پیدا نشد.')
                if page=='forwards' and role!='admin':raise PanelError('مدیریت فورواردر فقط برای مدیر فعال است.')
                state=self.control_widget_state(sender,page,0,server_id)
            elif data.startswith('server:'):
                server_id=data.split(':',1)[1]
                if server_id not in {'local',*(str(x.get('id')) for x in self.panel.snapshot().get('servers',[]))}:raise PanelError('سرور انتخاب‌شده پیدا نشد.')
                state=self.control_widget_state(sender,'forwards' if current.get('page')=='forwards' else 'tunnels' if current.get('page')=='tunnels' else 'resources',0,server_id)
            elif data.startswith('open:server:'):
                state=self.control_widget_state(sender,'server',0,'local',data.split(':',2)[2])
            elif data.startswith('open:tunnel:'):
                state=self.control_widget_state(sender,'tunnel',0,'local',data.split(':',2)[2])
            elif data.startswith('open:forward:'):
                parts=data.split(':',3)
                if len(parts)!=4:raise PanelError('شناسهٔ فورواردر نامعتبر است.')
                _,_,server_id,ident=parts
                state=self.control_widget_state(sender,'forward',0,server_id,ident)
            elif data.startswith('edit-forward:'):
                if role!='admin':raise PanelError('این عملیات فقط برای مدیر فعال است.')
                ident=data.split(':',1)[1];server_id=current.get('server_id','local')
                self.answer_widget(query,{'page':'forwards','role':'admin','title':'ویرایش فورواردر','summary':'فرم در پیام بعدی باز می‌شود.','rows':[],'actions':[],'message':'در حال بازکردن فرم ویرایش…'})
                self.dispatch(sender,'forward-edit',{'server_id':server_id,'rule_id':ident});return
            elif data.startswith('cf:'):
                if role!='admin':raise PanelError('این عملیات فقط برای مدیر فعال است.')
                _,action,ident=data.split(':',2);server_id=current.get('server_id','local')
                if action not in ('toggle','delete'):raise PanelError('عملیات فورواردر نامعتبر است.')
                result=self.panel.request('/api/v1/forwards?server_id='+urllib.parse.quote(server_id,safe=''))
                rule=next((x for x in result.get('items',[]) if x.get('id')==ident and x.get('server_id','local')==server_id),None)
                if not rule:raise PanelError('قانون فورواردر پیدا نشد.')
                nonce=secrets.token_urlsafe(9);key=(sender,chat['id'],int(message_id or 0));operation={'kind':'forward','action':action,'target':ident,'server_id':server_id,'enabled':bool(rule.get('enabled',True))}
                with self.widget_confirmation_lock:self.widget_confirmations[key]={'nonce':nonce,'operation':operation,'expires':time.time()+180}
                label=f'قانون {ident} روی {server_id} حذف شود؟' if action=='delete' else f'وضعیت قانون {ident} روی {server_id} تغییر کند؟'
                state={'page':'confirm','role':role,'server_id':server_id,'selected':ident,'title':'تأیید فورواردر','summary':'','rows':[{'title':label,'lines':['این تغییر روی HAProxy اعمال می‌شود.']}],
                       'actions':[{'label':'✅ تأیید و اجرا','query':'execute:'+nonce},{'label':'لغو','query':'open:forward:'+server_id+':'+ident}]}
            elif data.startswith('forward-new:'):
                if role!='admin':raise PanelError('این عملیات فقط برای مدیر فعال است.')
                server_id=data.split(':',1)[1]
                if server_id not in {'local',*(str(x.get('id')) for x in self.panel.snapshot().get('servers',[]))}:raise PanelError('سرور فورواردر پیدا نشد.')
                self.answer_widget(query,{'page':'forwards','role':'admin','title':'فورواردر','summary':'فرم در پیام بعدی باز می‌شود.','rows':[],'actions':[],'message':'در حال بازکردن فرم قانون HAProxy…'})
                self.start_forward_wizard(sender,server_id);return
            elif data=='update-check':
                if role!='admin':raise PanelError('به‌روزرسانی فقط برای مدیر فعال است.')
                self.panel.request('/api/v1/updates',{'action':'check'},timeout=8)
                state=self.control_widget_state(sender,'update')
                state['message']='درخواست بررسی نسخه ثبت شد؛ نتیجه با تازه‌سازی نمایش داده می‌شود.'
            elif data.startswith('confirm:'):
                if role!='admin':raise PanelError('عملیات فقط برای مدیر فعال است.')
                _,action,target=data.split(':',2)
                if action=='update':
                    if current.get('page')!='update' or not current.get('update_available') or not current.get('latest_commit'):
                        raise PanelError('نسخهٔ جدیدی برای نصب موجود نیست؛ ابتدا نسخه‌ها را بررسی کن.')
                    operation={'kind':'update','target':'panel','commit':current.get('latest_commit')}
                    label=f"نصب avaTUN {current.get('latest_version','نسخهٔ جدید')}؟ پنل هنگام به‌روزرسانی بازراه‌اندازی می‌شود."
                else:
                    if action not in ('start','stop','restart'):raise PanelError('نوع عملیات نامعتبر است.')
                    endpoints=tunnel_groups(self.panel.snapshot()).get(target)
                    if not endpoints or len(endpoints)<2:raise PanelError('برای این عملیات هر دو سمت تونل باید ثبت شده باشند.')
                    operation={'kind':'tunnel','action':action,'target':target,'expected':sorted(endpoints)}
                    label=f'اجرای {action} برای تونل {target} روی هر دو سمت تأیید می‌شود؟'
                nonce=secrets.token_urlsafe(9);key=(sender,chat['id'],int(message_id or 0))
                with self.widget_confirmation_lock:
                    self.widget_confirmations[key]={'nonce':nonce,'operation':operation,'expires':time.time()+180}
                    state={'page':'confirm','role':role,'server_id':'local','selected':target if operation['kind']=='tunnel' else '', 'title':'تأیید عملیات','summary':'','rows':[{'title':label,'lines':['این درخواست فقط برای مدیر مجاز است.']}],
                       'actions':[{'label':'✅ تأیید و اجرا','query':'execute:'+nonce},{'label':'لغو','query':'open:tunnel:'+target if operation['kind']=='tunnel' else 'nav:update'}]}
            elif data.startswith('execute:'):
                if role!='admin':raise PanelError('عملیات فقط برای مدیر فعال است.')
                nonce=data.split(':',1)[1];key=(sender,chat['id'],int(message_id or 0))
                with self.widget_confirmation_lock:
                    confirmation=self.widget_confirmations.get(key)
                    if not confirmation or confirmation.get('nonce')!=nonce or confirmation['expires']<time.time():raise PanelError('تأیید منقضی شده؛ عملیات را دوباره انتخاب کن.')
                    del self.widget_confirmations[key]
                operation=confirmation['operation']
                return_state = ({'page':'update','role':role,'title':'به‌روزرسانی avaTUN','summary':'در حال نصب',
                                 'rows':[],'actions':[],'message':'درخواست به‌روزرسانی ارسال شد؛ در حال اجرا…'}
                                if operation['kind']=='update' else
                                {'page':'tunnel','role':role,'selected':operation['target'],'title':'تونل '+operation['target'],
                                 'summary':'در حال دریافت وضعیت','rows':[],'actions':[], 'message':'در حال اجرای عملیات…'}
                                if operation['kind']=='tunnel' else
                                {'page':'forwards','role':role,'server_id':operation['server_id'],'title':'فورواردر',
                                 'summary':'در حال دریافت وضعیت','rows':[],'actions':[], 'message':'در حال اجرای عملیات…'})
                operation['return_state'] = return_state
                operation['return_query'] = ('nav:update' if operation['kind']=='update' else
                                             'open:tunnel:'+operation['target'] if operation['kind']=='tunnel' else
                                             'nav:forwards')
                state = dict(return_state)
                state.update({'page':'confirm','title':'در حال اجرا','summary':'درخواست تأییدشده',
                              'message':'عملیات شروع شد؛ نتیجه همین‌جا به‌روزرسانی می‌شود.',
                              'actions':[{'label':'تازه‌سازی','query':'refresh'}]})
                self.answer_widget(query,state)
                threading.Thread(target=self._run_widget_operation,
                                 args=(sender,chat['id'],int(message_id),operation),daemon=True,
                                 name='telegram-widget-operation').start()
                return
            elif data.startswith('refresh'):
                state=self.control_widget_state(sender,'overview')
            else:
                raise PanelError('دستور ویجت نامعتبر است.')
            self.answer_widget(query,state)
        except (OSError,ValueError,KeyError,RuntimeError,TypeError) as error:
            self.answer_widget(query,{'page':'overview','role':role,'title':'خطا','summary':'','rows':[],'actions':[{'label':'بازخوانی','query':'nav:overview'}],'message':self.scrub(error)[:180]})

    def tunnel_widget(self, user_id):
        return self.show_control_widget(user_id, 'tunnels', server_id='all')

    def haproxy_widget(self, user_id, server_id='local'):
        return self.show_control_widget(user_id, 'forwards', server_id=server_id)

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
        if authorized and isinstance(data,str) and (data in ('refresh','update-check') or data.startswith(('page:','nav:','open:','server:','sp:','confirm:','execute:','cf:','forward-new:','edit-forward:'))):
            self.control_widget_query(query)
            return
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
        return self.show_screen(user_id, 'forwards', page, server_id)

    def forward(self, user_id, rule_id, server_id):
        return self.show_screen(user_id, 'forward', server_id=server_id, selected=rule_id)

    def prompt(self, user_id, text):
        self.send(user_id,text+'\n\nپاسخ را در همین چت بفرست. برای خروج /cancel را بزن.')

    def wizard_key(self, user_id):
        return 'forward-wizard:' + str(user_id)

    def wizard_save(self, user_id, draft):
        draft['revision'] = secrets.token_hex(6)
        self.state.put(self.wizard_key(user_id), draft)

    def wizard_get(self, user_id):
        return self.state.get(self.wizard_key(user_id))

    def wizard_clear(self, user_id):
        self.state.put(self.wizard_key(user_id), None)

    def start_forward_wizard(self, user_id, server_id, rule=None):
        if (self.state.get('console-job:'+str(user_id)) or {}).get('state')=='running':
            return self.show_screen(user_id,'job',message='ابتدا منتظر پایان عملیات جاری بمان.')
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
            available = [x for x in result.get('tunnels', []) if x.get('server_id', 'local') == draft['server_id'] and (x.get('health',{}).get('interface_peer_ip') or x.get('metadata', {}).get('tun_remote')) and x.get('metadata', {}).get('transport') != 'erspan']
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
        field = draft['step']; value = digits(text.strip())
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
        return self.show_screen(user_id, 'report')

    def audit(self, user_id):
        return self.show_screen(user_id, 'audit')

    def dispatch(self, user_id, action, payload):
        if action=='cancel':
            self.wizard_clear(user_id)
            return self.show_screen(user_id,'overview',message='فرم جاری لغو شد.')
        if action=='navigate':
            if payload.get('query','').startswith('nav:'):self.wizard_clear(user_id)
            return self.navigate(user_id,payload.get('query',''),payload.get('context'))
        if action=='run-operation':
            return self.start_operation(user_id,payload.get('operation') or {},payload.get('context'))
        if action=='open-widget':
            return self.navigate(user_id,'try-widget')
        if action.startswith('wizard-') and payload.get('wizard_revision') is not None:
            draft=self.wizard_get(user_id)
            if not draft or payload['wizard_revision']!=draft.get('revision'):
                raise PanelError('این مرحله تغییر کرده است؛ از دکمه‌های فرم فعلی استفاده کن.')
        admin_actions = {'confirm-tunnel', 'confirm-forward', 'execute-tunnel', 'execute-forward', 'forward',
                         'confirm-forward-delete', 'execute-forward-delete', 'audit', 'haproxy-widget',
                         'forward-new', 'forward-start', 'forward-edit', 'wizard-set', 'wizard-toggle', 'wizard-step',
                         'wizard-backend', 'wizard-weight', 'wizard-apply', 'wizard-cancel',
                         'update-check', 'confirm-app-update', 'execute-app-update',
                         'widget-fallback-execute'}
        if action in admin_actions and self.users.get(user_id) != 'admin':
            raise PanelError('این عملیات فقط برای مدیر فعال است.')
        if action=='widget-fallback-query':
            self.navigate(user_id,payload.get('query',''),payload.get('context'))
            return
        if action=='widget-fallback-execute':
            self.start_operation(user_id,payload.get('operation') or {},payload.get('context'))
            return
        if action=='widget-retry':
            self.state.put(self.widget_delivery_key(user_id), {'retry_at':0})
            self.show_control_widget(user_id,'overview')
            return
        widget_pages={'home':'overview','status':'overview','servers':'servers','servers-text':'servers',
                      'tunnels':'tunnels','tunnel-widget':'tunnels','hardware':'resources',
                      'forwards':'forward_servers','report':'report','audit':'audit','settings':'settings','help':'help'}
        if action in widget_pages:
            page='forwards' if action=='forwards' and payload.get('server_id') else widget_pages[action]
            self.show_screen(user_id,page,server_id=payload.get('server_id','all'))
            return
        if action in ('server','tunnel','diagnose','forward'):
            page={'server':'server','tunnel':'tunnel','diagnose':'tunnel','forward':'forward'}[action]
            selected=payload.get('server_id') if action=='server' else payload.get('tunnel_id') if action in ('tunnel','diagnose') else payload.get('rule_id')
            self.show_screen(user_id,page,server_id=payload.get('server_id','local'),selected=selected or '')
            return
        if action=='update-check':
            self.panel.request('/api/v1/updates',{'action':'check'},timeout=8)
            self.show_screen(user_id,'update',message='درخواست بررسی GitHub ثبت شد؛ چند لحظه بعد تازه‌سازی را بزن.')
            return
        if action == 'confirm-app-update':
            status = self.panel.updates()
            if not status.get('update_available') or (payload.get('commit') and payload.get('commit') != status.get('latest_commit')):
                self.send(user_id, 'وضعیت نسخه عوض شده است؛ دوباره /update را بفرست.')
                return
            self.send(user_id, f"avaTUN {status.get('latest_version')} نصب شود؟ پنل هنگام به‌روزرسانی برای چند لحظه راه‌اندازی مجدد می‌شود.",
                      [[self.button(user_id, '✅ نصب نسخهٔ جدید', 'execute-app-update', commit=status.get('latest_commit'))],
                       [self.button(user_id, 'انصراف', 'home')]])
        elif action == 'execute-app-update':
            status = self.panel.updates()
            if not status.get('update_available') or (payload.get('commit') and payload.get('commit') != status.get('latest_commit')):
                self.send(user_id, 'این نسخه دیگر در دسترس نیست؛ دوباره /update را بفرست.')
                return
            self.state.audit(user_id, 'github-update', status.get('latest_version', ''), 'started')
            result = self.panel.request('/api/v1/updates', {'action': 'apply'}, timeout=30)
            self.state.audit(user_id, 'github-update', status.get('latest_version', ''), 'ok' if result.get('state') == 'installing' else 'failed')
            self.send(user_id, 'درخواست به‌روزرسانی ثبت شد. پنل پس از نصب نسخهٔ جدید دوباره در دسترس قرار می‌گیرد.')
        elif action.startswith('confirm-'):
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
            self.wizard_save(user_id,{**draft,'step':'submitting'})
            self.start_operation(user_id,{'kind':'forward-save','target':data['id'],
                'server_id':data['server_id'],'data':data})
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
            elif kind in ('page','nav','open','server','sp','confirm','execute','cf','update-check','refresh','forward-new','edit-forward'):
                self.control_widget_query(widget_query)
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
                entry = self.callbacks.get(token) or self.state.get('callback:'+token)
                if not entry or entry['user'] != sender or entry['expires'] <= time.time():
                    self.send(sender, 'این دکمه منقضی شده است؛ /start را بفرست.')
                    return
                if entry.get('once') or entry['action'].startswith('execute-') or entry['action']=='widget-fallback-execute':
                    with self.state.connection:
                        removed=self.state.connection.execute('DELETE FROM meta WHERE key=?',('callback:'+token,)).rowcount
                    self.callbacks.pop(token,None)
                    if not removed:
                        self.send(sender,'این درخواست قبلاً ثبت شده است؛ وضعیت عملیات را بررسی کن.')
                        return
                self.dispatch(sender, entry['action'], entry['payload'])
            else:
                text = message.get('text', '').strip()
                command = text.split()[0].split('@')[0] if text else ''
                if not text.startswith('/') and self.users.get(sender) == 'admin' and self.wizard_text(sender, text):
                    return
                actions = {'/start': 'home', '/help': 'help', '/cancel':'cancel', '/status': 'status', '/servers': 'servers',
                           '/tunnels': 'tunnel-widget', '/tunnel-list': 'tunnels', '/tunnel_list': 'tunnels',
                           '/hardware': 'hardware', '/forwards': 'forwards',
                           '/haproxy': 'forwards',
                           '/report': 'report', '/audit': 'audit', '/update': 'update-check',
                           '/settings':'settings', '/widgets':'open-widget'}
                if command=='/start':
                    self.wizard_clear(sender)
                    self.state.put('console:'+str(sender),None)
                if command not in actions:
                    self.show_screen(sender,'help',message='از دکمه‌های زیر استفاده کن یا /start را بفرست.')
                else:self.dispatch(sender, actions[command], {})
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
        try:
            update = self.panel.updates()
            marker = update.get('latest_commit') or update.get('latest_version')
            if update.get('update_available') and marker and self.state.get('github_update_notice') != marker:
                for user_id in admins:
                    self.send(user_id, f"🆕 نسخهٔ جدید avaTUN موجود است: {update.get('current_version')} → {update.get('latest_version')}\nبرای دیدن جزئیات و تأیید نصب، /update را بفرست.",
                              [[self.button(user_id, 'بررسی و تأیید نسخه', 'update-check')]])
                self.state.put('github_update_notice', marker)
        except (OSError, ValueError, RuntimeError):
            pass
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
        # A process restart cannot prove whether an in-flight mutation completed.
        # Report it for review instead of replaying it.
        for user_id in self.users:
            key='console-job:'+str(user_id);job=self.state.get(key) or {}
            if job.get('state')=='running':
                job.update(state='interrupted',message='ربات هنگام عملیات دوباره راه‌اندازی شد. وضعیت مقصد را بررسی کن؛ درخواست خودکار تکرار نشد.')
                self.state.put(key,job)
        self.telegram.request('getMe', {})
        if self.telegram.request('getWebhookInfo', {}).get('url'):
            raise RuntimeError('Polling requires removing the existing webhook first')
        self.telegram.request('setMyCommands', {'commands': [
            {'command': 'start', 'description': 'منوی مدیریت avaTUN'},
            {'command': 'status', 'description': 'نمای کلی شبکه'},
            {'command': 'servers', 'description': 'فهرست سرورها'},
            {'command': 'tunnels', 'description': 'وضعیت زندهٔ تونل‌ها'},
            {'command': 'hardware', 'description': 'منابع و آپلود/دانلود'},
            {'command': 'report', 'description': 'گزارش 24 ساعت'},
            {'command': 'help', 'description': 'راهنمای ربات'},
            {'command': 'cancel', 'description': 'لغو فرم جاری'}]})
        for user_id,role in self.users.items():
            if role=='admin':
                self.telegram.request('setMyCommands',{'scope':{'type':'chat','chat_id':user_id},'commands':[
                    {'command':name,'description':label} for name,label in (
                    ('start','خانه'),('servers','سرورها'),('tunnels','تونل‌ها'),('hardware','منابع'),
                    ('forwards','فوروارد'),('report','گزارش 24 ساعت'),('update','به‌روزرسانی پنل'),
                    ('audit','عملیات اخیر'),('settings','تنظیمات و راهنما'),('cancel','لغو فرم جاری'))]})
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
                self.state.deliver(self.telegram, lambda text:digits(self.scrub(text)))
            except (OSError, ValueError, KeyError, RuntimeError) as error:
                self.set_status('retrying', type(error).__name__)
                logging.warning('Bot cycle failed (%s: %s)', type(error).__name__, str(error)[:240])
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
