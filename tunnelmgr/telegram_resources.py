"""Resources-only live cards, using HTML widgets when Telegram allows them."""
import hashlib
import json
import logging
import re
import threading
import time

from telegram_console import _screen_locks
from telegram_ui import escape, digits

INTERVAL = 15
LEASE = 600


class ResourceMixin:
    def resource_items(self, scope):
        items = self.panel.request('/api/v1/servers/resources',timeout=8).get('items',[])
        if scope!='all':items=[x for x in items if str(x.get('id'))==scope]
        return items or [{'id':scope if scope!='all' else 'local','name':'منابع سرور','reachable':False}]

    def resource_payload(self, items, page, selected=''):
        if selected:
            page=next((i for i,x in enumerate(items) if str(x.get('id'))==selected),page)
        state=self.resource_data(items,page)
        for field in ('id','name','host'):state['x'][field]=digits(state['x'].get(field,''))
        state['live']=True
        # State has a strict 1024-byte UTF-8 limit, including Persian names.
        while len(json.dumps(state,ensure_ascii=False,separators=(',',':')).encode())>1024:
            x=state['x']
            if len(x.get('name',''))>16:x['name']=x['name'][:max(16,len(x['name'])//2)]
            elif len(x.get('host',''))>24:x['host']=x['host'][:24]
            else:
                for field in ('memory_used_bytes','disk_used_bytes','swap_used_bytes','load_1m'):
                    x.get('resources',{}).pop(field,None)
                break
        return state

    def resource_keyboard(self, user_id, state, scope, paused=False, widget=False):
        ctx={'page':'resources','page_index':state['p'],'server_id':scope,'selected':state['x'].get('id','')}
        def button(label,q):return self.button(user_id,label,'navigate',query=q,context=ctx)
        paging=[]
        if state['p']>0:paging.append(button('‹ قبلی','page:resources:'+str(state['p']-1)))
        if state['p']+1<state['n']:paging.append(button('بعدی ›','page:resources:'+str(state['p']+1)))
        rows=[paging] if paging and not widget else []
        rows.append([button('ادامهٔ پایش' if paused else 'توقف پایش','resource-resume' if paused else 'resource-pause'),
                     button('↻ تازه‌سازی','refresh')])
        back='open:server:'+scope if scope!='all' else 'nav:overview'
        rows.append([button('بازگشت',back),button('خانه','nav:overview')])
        return rows

    def resource_text(self, state, paused=False):
        x=state['x'];r=x.get('resources') or {};checked=r.get('checked_at') or 0
        good=bool(x.get('ok'))
        status='⏸ پایش متوقف است' if paused else '🟢 پایش زنده · هر 15 ثانیه'
        lines=['<b>منابع · '+escape(x.get('name','سرور'),80)+'</b>',
               '<code>'+escape(x.get('host') or x.get('id',''),100)+'</code>','',status]
        if not good:lines+=['⚠️ آمار این سرور در دسترس نیست؛ مقادیر قبلی ممکن است قدیمی باشند.']
        elif x.get('stale'):lines+=['⚠️ نمونهٔ منابع قدیمی است.']
        for name,key in (('CPU','cpu'),('RAM','memory'),('دیسک','disk'),('Swap','swap')):
            value=r.get(key+'_percent')
            known=good and value is not None
            if key=='swap' and known and not r.get('swap_total_bytes'):
                lines+=['','<b>Swap</b> · غیرفعال'];continue
            value=max(0,min(100,float(value or 0)))
            bar='▰'*round(value/10)+'▱'*(10-round(value/10))
            lines+=['','<b>'+name+'</b> · '+(f'{value:.1f}%' if known else '—'),
                    '<code>'+bar+'</code>' if known else 'نمونه‌ای دریافت نشده است.']
            if known and key!='cpu':
                lines.append(escape(self.resource_size(r.get(key+'_used_bytes'))+' / '+self.resource_size(r.get(key+'_total_bytes'))))
        lines+=['','↓ دانلود: '+escape(self.resource_size(r.get('download_bytes_per_sec'))+'/s' if good else '—'),
                '↑ آپلود: '+escape(self.resource_size(r.get('upload_bytes_per_sec'))+'/s' if good else '—')]
        age=f'{max(0,int(time.time()-checked))} ثانیه قبل' if checked else 'نامشخص'
        lines+=['','<i>زمان نمونه: '+age+f" · سرور {state['p']+1} از {state['n']}"+'</i>']
        if not paused:lines+=['<i>پایش خودکار تا 10 دقیقه؛ با ادامهٔ پایش تمدید می‌شود.</i>']
        return '\n'.join(lines)

    def show_resource_screen(self, user_id, page=0, scope='all', selected='', paused=False):
        with _screen_locks[user_id]:
            return self._show_resource_screen(user_id,page,scope,selected,paused)

    def _show_resource_screen(self, user_id, page=0, scope='all', selected='', paused=False):
        items=self.resource_items(scope)
        state=self.resource_payload(items,page,selected)
        state['live']=not paused
        active_key='resource-active:'+str(user_id)
        saved=self.state.get('console:'+str(user_id)) or {}
        old=self.state.get(active_key) or {}
        layout=hashlib.sha256(self.resource_html.encode()).hexdigest()
        keyboard=self.resource_keyboard(user_id,state,scope,paused)
        payload=json.dumps(state,ensure_ascii=False,separators=(',',':'))
        is_widget=saved.get('kind')=='resource-widget' and old.get('layout')==layout
        denied=self.state.get(self.widget_delivery_key(user_id)) or {}
        if is_widget or denied.get('retry_at',0)<=time.time():
            try:
                keyboard=self.resource_keyboard(user_id,state,scope,paused,widget=True)
                if is_widget:
                    try:
                        self.telegram.request('editMessageWidgetData',{'chat_id':user_id,'message_id':saved['message_id'],'chat_data':payload})
                    except RuntimeError as error:
                        if 'message is not modified' not in str(error).lower():raise
                    self.telegram.request('editMessageReplyMarkup',{'chat_id':user_id,'message_id':saved['message_id'],'reply_markup':{'inline_keyboard':keyboard}})
                    message_id=saved['message_id']
                else:
                    result=self.telegram.request('sendWidget',{'chat_id':user_id,'html':self.resource_html,
                        'chat_data':payload,'allow_queries':True,'protect_content':True,
                        'reply_markup':{'inline_keyboard':keyboard}})
                    message_id=result['message_id']
                active={'kind':'widget','scope':scope,'p':state['p'],'selected':state['x'].get('id',''),
                        'message_id':message_id,'until':time.time()+LEASE,'paused':paused,'layout':layout,
                        'return_console':old.get('return_console') if is_widget else saved}
                self.state.put(active_key,active)
                self.state.put('console:'+str(user_id),{'message_id':message_id,'kind':'resource-widget',
                               'screen':{'page':'resources','page_index':state['p'],'server_id':scope,'selected':active['selected']}})
                return
            except RuntimeError as error:
                if 'INPUT_MEDIA_WIDGET_NOT_ALLOWED' not in str(error):raise
                logging.warning('Resource HTML widget rejected by Telegram; live native resource card enabled.')
                self.state.put(self.widget_delivery_key(user_id),{'retry_at':time.time()+300,'error':'INPUT_MEDIA_WIDGET_NOT_ALLOWED'})
                self.leave_resource_screen(user_id)
        keyboard=self.resource_keyboard(user_id,state,scope,paused)
        self.present(user_id,self.resource_text(state,paused),keyboard,html=True,
                     screen={'page':'resources','page_index':state['p'],'server_id':scope,'selected':state['x'].get('id','')})
        saved=self.state.get('console:'+str(user_id)) or {}
        self.state.put(active_key,{'kind':'native','message_id':saved.get('message_id'),'scope':scope,
            'p':state['p'],'selected':state['x'].get('id',''),'until':time.time()+LEASE,
            'paused':paused,'next_at':time.time()+INTERVAL,'last_state':state})

    def leave_resource_screen(self, user_id):
        key='resource-active:'+str(user_id);active=self.state.get(key) or {}
        if not active:return
        if active.get('kind')=='widget':
            try:
                self.telegram.request('editMessageReplyMarkup',{'chat_id':user_id,'message_id':active['message_id'],
                    'reply_markup':{'inline_keyboard':[]}})
            except RuntimeError:pass
            self.state.put('console:'+str(user_id),active.get('return_console') or None)
        self.state.put(key,None)

    def refresh_resource_cards(self):
        due=[];now=time.time()
        for user_id in self.users:
            active=self.state.get('resource-active:'+str(user_id)) or {}
            if active.get('kind')=='native' and not active.get('paused') and active.get('next_at',0)<=now:
                due.append((user_id,active))
        if not due:return
        try:all_items=self.resource_items('all')
        except (OSError,ValueError,RuntimeError):all_items=None
        for user_id,active in due:
            with _screen_locks[user_id]:
                current=self.state.get('resource-active:'+str(user_id)) or {}
                console=self.state.get('console:'+str(user_id)) or {}
                if current!=active or console.get('message_id')!=active.get('message_id') or console.get('screen',{}).get('page')!='resources':continue
                if all_items is None:
                    state=json.loads(json.dumps(active.get('last_state') or self.resource_payload([],0)))
                    state['x'].update(ok=False,stale=True)
                else:
                    items=[x for x in all_items if active['scope']=='all' or str(x.get('id'))==active['scope']]
                    if not items:items=[{'id':active.get('selected') or active['scope'],'name':'منابع سرور','reachable':False}]
                    state=self.resource_payload(items,active['p'],active.get('selected',''))
                paused=now>=active['until']
                self.present(user_id,self.resource_text(state,paused),self.resource_keyboard(user_id,state,active['scope'],paused),
                    html=True,screen={'page':'resources','page_index':state['p'],'server_id':active['scope'],'selected':state['x'].get('id','')})
                self.state.put('resource-active:'+str(user_id),{**active,'paused':paused,
                    'p':state['p'],'selected':state['x'].get('id',''),'next_at':time.time()+INTERVAL,'last_state':state})

    def run_resource_refresh(self):
        def loop():
            worker=self.operation_worker()
            try:
                while True:
                    try:worker.refresh_resource_cards()
                    except Exception as error:logging.warning('Resource live refresh deferred (%s)',type(error).__name__)
                    threading.Event().wait(5)
            finally:worker.state.connection.close()
        threading.Thread(target=loop,daemon=True,name='telegram-resource-live').start()

    def answer_resource_query(self, query):
        sender=query.get('from',{}).get('id');chat=query.get('chat') or {};message_id=query.get('message_id')
        active=self.state.get('resource-active:'+str(sender)) or {}
        allowed=(sender in self.users and chat.get('type')=='private' and chat.get('id')==sender
                 and active.get('kind')=='widget' and active.get('message_id')==message_id)
        state={'p':0,'n':1,'live':False,'x':{'ok':False,'name':'این کارت بسته شده است.','resources':{}}}
        if allowed:
            paused=active.get('paused') or time.time()>=active.get('until',0)
            if not paused:
                try:
                    match=re.fullmatch(r'resources:([0-9]{1,5})',str(query.get('data','')))
                    if not match:raise ValueError('Invalid resource page')
                    page=int(match[1])
                    items=self.resource_items(active['scope'])
                    state=self.resource_payload(items,page,active.get('selected','') if page==active.get('p') else '')
                    active.update(p=state['p'],selected=state['x'].get('id',''))
                    self.state.put('resource-active:'+str(sender),active)
                except (OSError,ValueError,KeyError,RuntimeError):state['x']['name']='منابع در دسترس نیست؛ تازه‌سازی را دوباره بزن.'
            else:state['x']['name']='پایش متوقف شد؛ ادامهٔ پایش را بزن.'
        encoded=json.dumps(state,ensure_ascii=False,separators=(',',':'))
        self.telegram.request('answerWidgetQuery',{'widget_query_id':query['id'],'data':encoded})
        if allowed:
            self.telegram.request('editMessageWidgetData',{'chat_id':sender,'message_id':message_id,'chat_data':encoded})
