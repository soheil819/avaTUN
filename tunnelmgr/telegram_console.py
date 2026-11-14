"""Native, single-message navigation and confirmed background operations."""
import datetime as dt
import secrets
import threading
import time
import urllib.parse
from collections import defaultdict

from telegram_ui import context, digits, escape, render

_screen_locks = defaultdict(threading.RLock)


class ConsoleMixin:
    def present(self, user_id, text, keyboard=None, html=False, screen=None):
        with _screen_locks[user_id]:
            if (screen or {}).get('page')!='resources':self.leave_resource_screen(user_id)
            return self._present(user_id,text,keyboard,html,screen)

    def _present(self, user_id, text, keyboard=None, html=False, screen=None):
        key = 'console:' + str(user_id)
        saved = self.state.get(key) or {}
        data = {'chat_id':user_id, 'text':self.scrub(digits(text)),
                'reply_markup':{'inline_keyboard':keyboard or []},
                'link_preview_options':{'is_disabled':True}}
        if html: data['parse_mode'] = 'HTML'
        result = None
        if saved.get('message_id'):
            try:
                result = self.telegram.request('editMessageText', {**data,'message_id':saved['message_id']})
            except RuntimeError as error:
                detail = str(error).lower()
                if 'message is not modified' not in detail:
                    if not any(x in detail for x in ('message to edit not found',"message can't be edited",'message_id_invalid')):
                        raise
                    saved = {}
        if not saved.get('message_id'):
            result = self.telegram.request('sendMessage',data)
        message_id = result.get('message_id') if isinstance(result,dict) else saved.get('message_id')
        if message_id:
            self.state.put(key, {'message_id':message_id, 'screen':screen or {},'updated_at':time.time()})

    def console_state(self, user_id, page='overview', page_index=0, server_id='all', selected=''):
        role = self.users.get(user_id,'viewer')
        if page in ('forward_servers','forwards','forward','audit','update','settings') and role!='admin':
            raise RuntimeError('این بخش فقط برای مدیر در دسترس است.')
        if page == 'forward_servers':
            snapshot = self.panel.snapshot()
            servers = [{'id':'local','name':'سرور مرکزی','host':'پنل مرکزی'},*snapshot.get('servers',[])]
            total = max(1,(len(servers)+3)//4); index = min(max(0,int(page_index)),total-1)
            state = {'page':page,'title':'فوروارد · انتخاب سرور','summary':'قوانین کدام سرور را مدیریت می‌کنی؟',
                     'p':index,'n':total,'rows':[{'title':s.get('name') or s['id'],
                     'lines':[s.get('host','')],'query':'select-forward-server:'+s['id']}
                     for s in servers[index*4:index*4+4]],'actions':[]}
        elif page in ('settings','help'):
            state = {'page':page,'title':'تنظیمات و راهنما' if page=='settings' else 'راهنمای ربات',
                     'summary':'دسترسی: '+('مدیر' if role=='admin' else 'مشاهده‌گر'),
                     'rows':[{'title':'کار با ربات','lines':['یک بخش را انتخاب کن؛ هر دکمه همان پیام را به‌روز می‌کند.',
                     '/start خانه · /cancel لغو فرم جاری',
                     'توقف، حذف و نصب به‌روزرسانی ابتدا تأیید می‌خواهند.']},
                     {'title':'وضعیت و منابع','lines':['زمان آخرین دریافت زیر هر صفحه نوشته می‌شود.',
                     'تازه‌سازی، اطلاعات جدید را از پنل می‌گیرد.',
                     'پیام‌های هشدار و نتیجهٔ عملیات جداگانه دریافت می‌شوند.']}],
                     'actions':([{'label':'راهنما','query':'nav:help'},
                     {'label':'منابع زنده','query':'nav:resources'}] if page=='settings' else [])}
        elif page == 'job':
            job = self.state.get('console-job:'+str(user_id)) or {}
            state = {'page':page,'title':job.get('title','عملیات'),'selected':job.get('id',''),
                     'summary':{'running':'⏳ در حال اجرا','ok':'✅ انجام شد','partial':'⚠️ بخشی از عملیات ناموفق بود',
                     'failed':'❌ انجام نشد','interrupted':'⚠️ اجرای ربات متوقف شده است'}.get(job.get('state'),'نتیجه‌ای ثبت نشده است.'),
                     'rows':[],'message':job.get('message',''),'actions':[{'label':'بررسی نتیجه','query':'nav:job'}]}
            if job.get('return_query'):state['actions'].append({'label':'مشاهدهٔ وضعیت','query':job['return_query']})
        else:
            state = self.control_widget_state(user_id,page,page_index,server_id,selected)
            if page == 'update':
                status=state.get('summary')
                state['summary']={'current':'نسخهٔ پنل به‌روز است','available':'نسخهٔ جدید موجود است',
                    'checking':'در حال بررسی GitHub','installing':'در حال نصب به‌روزرسانی',
                    'error':'بررسی نسخه انجام نشد'}.get(status,'وضعیت به‌روزرسانی')
                if status=='installing':state['actions']=[]
            if page == 'forwards':
                state['actions'] = [{'label':'＋ قانون جدید','query':'forward-new:'+server_id}]
            if page in ('tunnels','resources') and server_id!='all':
                state['summary'] = 'سرور: '+server_id
                state['actions'] = [*state.get('actions',[]),{'label':'همهٔ سرورها','query':'nav:'+page}]
        state.update({'role':role,'server_id':state.get('server_id',server_id),
                      'selected':state.get('selected',selected),
                      'updated':dt.datetime.now(self.zone).strftime('%H:%M:%S')})
        return state

    def show_screen(self, user_id, page='overview', page_index=0, server_id='all', selected='', message=''):
        if page=='resources':
            with _screen_locks[user_id]:
                return self.show_resource_screen(user_id,page_index,server_id,selected)
        state = self.console_state(user_id,page,page_index,server_id,selected)
        if message:state['message'] = message
        text, keyboard = render(state, lambda label, action, **payload:self.button(user_id,label,action,**payload))
        self.present(user_id,text,keyboard,html=True,screen=context(state))

    def navigate(self, user_id, query, current=None):
        current = current or {'page':'overview','server_id':'all','selected':''}
        page = current.get('page','overview'); server_id = current.get('server_id','all')
        if query in ('resource-pause','resource-resume') or (page=='resources' and query=='refresh'):
            active=self.state.get('resource-active:'+str(user_id)) or {}
            return self.show_resource_screen(user_id,active.get('p',current.get('page_index',0)),
                active.get('scope',server_id),active.get('selected',current.get('selected','')),
                paused=query=='resource-pause')
        if query=='refresh' or query.startswith('refresh:'):
            return self.show_screen(user_id,page,current.get('page_index',0),server_id,current.get('selected',''))
        if query.startswith('nav:'):
            target=query.split(':',1)[1]
            return self.show_screen(user_id,target,server_id=server_id if target=='forwards' else 'all')
        if query.startswith('page:'):
            _,target,index=query.split(':',2)
            return self.show_screen(user_id,target,int(index),server_id,'' if target=='resources' else current.get('selected',''))
        if query.startswith('open:'):
            parts=query.split(':',3); kind=parts[1]
            if kind=='forward' and len(parts)==4:
                return self.show_screen(user_id,'forward',0,parts[2],parts[3])
            if kind in ('server','tunnel') and len(parts)==3:
                return self.show_screen(user_id,kind,0,server_id,parts[2])
            raise RuntimeError('مورد انتخاب‌شده پیدا نشد؛ فهرست را تازه‌سازی کن.')
        if query.startswith('sp:'):
            _,code,ident=query.split(':',2)
            return self.show_screen(user_id,{'t':'tunnels','r':'resources','f':'forwards'}[code],0,ident)
        if query.startswith('select-forward-server:'):
            return self.show_screen(user_id,'forwards',0,query.split(':',1)[1])
        if query=='try-widget':
            self.state.put(self.widget_delivery_key(user_id),{'retry_at':0})
            return self.show_screen(user_id,'resources')
        if self.users.get(user_id)!='admin':raise RuntimeError('این عملیات فقط برای مدیر فعال است.')
        if query=='resume-form':
            return self.wizard_prompt(user_id)
        if query=='update-check':
            self.panel.request('/api/v1/updates',{'action':'check'},timeout=8)
            return self.show_screen(user_id,'update',message='درخواست بررسی GitHub ثبت شد؛ چند لحظه بعد تازه‌سازی را بزن.')
        if query.startswith('forward-new:'):
            return self.start_forward_wizard(user_id,query.split(':',1)[1])
        if query.startswith('edit-forward:'):
            return self.dispatch(user_id,'forward-edit',{'server_id':server_id,'rule_id':query.split(':',1)[1]})
        if query.startswith('confirm:'):
            _,action,target=query.split(':',2)
            if action=='update':
                status=self.panel.updates()
                if not status.get('update_available'):raise RuntimeError('نسخهٔ جدیدی برای نصب موجود نیست.')
                operation={'kind':'update','target':'panel','commit':status.get('latest_commit')}
                title='نصب به‌روزرسانی'; body=f"نسخهٔ {status.get('current_version')} ← {status.get('latest_version')}\nپنل و ربات هنگام نصب دوباره راه‌اندازی می‌شوند."
            else:
                endpoints=self.panel.snapshot().get('tunnels',[])
                sides=sorted({x.get('server_id','local') for x in endpoints if x.get('id')==target})
                if len(sides)<2 or action not in ('start','stop','restart'):raise RuntimeError('هر دو سمت تونل باید در پنل ثبت شده باشند.')
                operation={'kind':'tunnel','target':target,'action':action,'expected':sides}
                title={'start':'شروع تونل','stop':'توقف تونل','restart':'راه‌اندازی مجدد تونل'}[action]
                body=f"تونل: {target}\nسرورها: {' ⇄ '.join(sides)}\n"+('اتصال‌های عبوری ممکن است قطع شوند.' if action!='start' else 'هر دو سمت راه‌اندازی می‌شوند.')
                if action=='restart':body+='\nسرویس و رابط هر دو سمت حذف و از تنظیمات ذخیره‌شده دوباره ساخته می‌شوند.'
            return self.confirm_operation(user_id,title,body,operation,current)
        if query.startswith('cf:'):
            _,action,target=query.split(':',2)
            rules=self.panel.request('/api/v1/forwards?server_id='+urllib.parse.quote(server_id,safe=''))
            rule=next((r for r in rules.get('items',[]) if r.get('id')==target and r.get('server_id','local')==server_id),None)
            if not rule or action not in ('toggle','delete'):raise RuntimeError('قانون پیدا نشد؛ فهرست را تازه‌سازی کن.')
            enabled=bool(rule.get('enabled',True))
            operation={'kind':'forward','target':target,'action':action,'server_id':server_id,'enabled':enabled}
            title='حذف قانون' if action=='delete' else 'توقف قانون' if enabled else 'فعال‌کردن قانون'
            return self.confirm_operation(user_id,title,f"قانون: {target}\nسرور: {server_id}\nورودی: {rule.get('listen_ip')}:{rule.get('listen_port')}\nاین تغییر روی HAProxy اعمال می‌شود.",operation,current)
        raise RuntimeError('این دکمه دیگر در دسترس نیست؛ /start را بفرست.')

    def confirm_operation(self, user_id, title, body, operation, current):
        self.present(user_id,'<b>'+escape(title)+'</b>\n\n'+escape(body,1400)+'\n\nآیا اجرا شود؟',
                     [[self.button(user_id,'تأیید و اجرا','run-operation',operation=operation,context=current)],
                      [self.button(user_id,'انصراف','navigate',query='refresh',context=current)]],
                     html=True,screen={'page':'confirm'})

    def start_operation(self, user_id, operation, current=None):
        if self.users.get(user_id)!='admin':raise RuntimeError('این عملیات فقط برای مدیر فعال است.')
        key='console-job:'+str(user_id);previous=self.state.get(key) or {}
        if previous.get('state')=='running':
            return self.show_screen(user_id,'job',message='عملیات قبلی هنوز در حال اجراست؛ درخواست تکراری ثبت نشد.')
        ident=secrets.token_hex(8);kind=operation.get('kind');target=operation.get('target','')
        return_query=('nav:update' if kind=='update' else 'open:tunnel:'+target if kind=='tunnel'
                      else 'open:forward:'+operation.get('server_id','local')+':'+target if kind=='forward-save'
                      else 'nav:forward_servers')
        title=({'start':'شروع تونل','stop':'توقف تونل','restart':'راه‌اندازی مجدد تونل'}.get(operation.get('action'),'تونل')+' · '+target if kind=='tunnel'
               else 'به‌روزرسانی پنل' if kind=='update' else 'فوروارد · '+target)
        self.state.put(key,{'id':ident,'state':'running','title':title,'started':time.time(),
                            'return_query':return_query,'message':'درخواست ثبت شد. می‌توانی بخش‌های دیگر را باز کنی؛ نتیجه اطلاع داده می‌شود.'})
        self.show_screen(user_id,'job')
        threading.Thread(target=self._console_worker,args=(user_id,ident,operation),daemon=True,
                         name='telegram-console-operation').start()

    def _console_worker(self, user_id, ident, operation):
        worker=self.operation_worker()
        key='console-job:'+str(user_id); job=worker.state.get(key) or {}
        action=operation.get('action') or operation.get('kind');target=operation.get('target','')
        worker.state.audit(user_id,action,target,'started')
        try:
            kind=operation.get('kind');outcome='ok'
            if kind=='tunnel':
                results=worker.panel.operate(target,operation['action'],operation['expected'])
                outcome='partial' if any('❌' in x for x in results) else 'ok'
                message='\n'.join(results)
            elif kind=='update':
                status=worker.panel.updates()
                if not status.get('update_available') or status.get('latest_commit')!=operation.get('commit'):
                    raise RuntimeError('نسخهٔ GitHub تغییر کرده است؛ دوباره بررسی کن.')
                worker.panel.request('/api/v1/updates',{'action':'apply'},timeout=30)
                message='نصب در پس‌زمینه آغاز شد. پنل و ربات پس از پایان نصب دوباره متصل می‌شوند.'
            elif kind=='forward':
                sid=operation['server_id']; rules=worker.panel.request('/api/v1/forwards?server_id='+urllib.parse.quote(sid,safe=''))
                rule=next((r for r in rules.get('items',[]) if r.get('id')==target and r.get('server_id','local')==sid),None)
                if not rule or bool(rule.get('enabled',True))!=operation['enabled']:
                    raise RuntimeError('وضعیت قانون تغییر کرده است؛ آن را دوباره باز کن.')
                data={'action':'delete' if operation['action']=='delete' else 'set-enabled','id':target,'server_id':sid}
                if operation['action']!='delete':data['enabled']=not operation['enabled']
                worker.panel.request('/api/v1/forwards',data)
                message='قانون روی سرور '+sid+' اعمال شد.'
            elif kind=='forward-save':
                worker.panel.request('/api/v1/forwards',operation['data'])
                worker.wizard_clear(user_id)
                message='قانون ذخیره و روی سرور اعمال شد.'
            else:raise RuntimeError('نوع عملیات نامعتبر است.')
            job.update(state=outcome,message=message)
        except Exception as error:
            job.update(state='failed',message=worker.scrub(error)[:500])
            if operation.get('kind')=='forward-save':
                draft=worker.wizard_get(user_id)
                if draft:
                    worker.wizard_save(user_id,{**draft,'step':'review'})
                    job['return_query']='resume-form'
        try:
            job['finished']=time.time();worker.state.put(key,job)
            worker.state.audit(user_id,action,target,job['state'])
            with _screen_locks[user_id]:
                console=worker.state.get('console:'+str(user_id)) or {}
                view=console.get('screen') or {}
                if view.get('page')=='job' and view.get('selected')==ident:
                    worker.show_screen(user_id,'job')
                else:
                    worker.telegram.send(user_id,digits(worker.scrub(('✅ ' if job['state']=='ok' else '⚠️ ')+job['title']+'\n'+job['message'])),
                        [[worker.button(user_id,'مشاهدهٔ نتیجه','navigate',query='nav:job')]])
        finally:
            worker.state.connection.close()

    def operation_worker(self):
        return type(self)({**self.config,'state_path':str(self.state.path)})
