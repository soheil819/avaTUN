#!/usr/bin/env python3
"""Regression checks for bot access, confirmation, alerts and HAProxy state."""
import copy
import json
import pathlib
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tunnelmgr'))
import telegram_bot as tg
import tunnelctl as t


def snapshot():
    checked = int(time.time())
    return {'servers': [{'id': 'peer', 'host': '192.0.2.2'}],
            'statuses': [{'id': 'local', 'reachable': True, 'app_version': 'test'}, {'id': 'peer', 'reachable': True}],
            'resources': [],
            'tunnels': [{'id': 'gre-test', 'server_id': sid, 'kind': 'gre',
                         'health': {'state': 'up', 'checked_at': checked},
                         'metadata': {'transport': 'gre'}} for sid in ('local', 'peer')]}


class FakePanel:
    def __init__(self):
        self.data = snapshot()
        self.operations = []

    def snapshot(self):
        return copy.deepcopy(self.data)

    def operate(self, *args):
        self.operations.append(args)
        return ['local ✅', 'peer ✅']

    def request(self, path, data=None, timeout=None):
        if path=='/api/v1/servers/resources':return {'items':copy.deepcopy(self.data.get('resources',[]))}
        return {'items': []}


class FakeTelegram:
    def __init__(self):
        self.messages = []
        self.requests = []

    def send(self, *args):
        self.messages.append(args)

    def request(self, *args):
        self.requests.append(args)
        if args[0] in ('sendMessage','editMessageText'):
            self.messages.append((args[1]['chat_id'],args[1]['text'],args[1].get('reply_markup',{}).get('inline_keyboard',[])))
            return {'message_id':args[1].get('message_id',len(self.requests)), 'chat':{'id':args[1]['chat_id']}}
        if args[0] == 'sendWidget':
            return {'message_id':len(self.requests),'chat':{'id':args[1]['chat_id']}}
        return True


class BotChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.folder.name) / 'bot.sqlite3'
        self.state = tg.State(self.path)
        self.panel = FakePanel()
        self.telegram = FakeTelegram()
        self.bot = tg.Bot({'bot_token': 'secret-token', 'panel_password': 'secret-password',
                           'admins': [1], 'viewers': [2]}, self.panel, self.telegram, self.state)
        self.counter = 0

    def tearDown(self):
        self.state.connection.close()
        self.folder.cleanup()

    def update(self, user, text=None, callback=None, chat_type='private'):
        self.counter += 1
        message = {'chat': {'type': chat_type, 'id': user}, 'from': {'id': user}, 'text': text or ''}
        if callback:
            update = {'update_id': self.counter, 'callback_query': {'id': str(self.counter),
                'from': {'id': user}, 'message': message, 'data': callback}}
        else:
            update = {'update_id': self.counter, 'message': message}
        self.bot.handle_update(update)
        return update

    def test_unknown_users_and_groups_get_no_data(self):
        self.update(999, '/status')
        self.update(1, '/status', chat_type='group')
        self.assertEqual([], self.telegram.messages)

    def test_viewer_cannot_execute_or_read_audit(self):
        for action in ('execute-tunnel', 'execute-forward', 'audit'):
            with self.assertRaises(tg.PanelError):
                self.bot.dispatch(2, action, {})
        self.assertEqual([], self.panel.operations)

    def test_confirmation_executes_once_and_survives_duplicate_update(self):
        self.bot.dispatch(1, 'confirm-tunnel', {'tunnel_id': 'gre-test', 'operation': 'restart', 'expected': ['local', 'peer']})
        token = self.telegram.messages[-1][2][0][0]['callback_data']
        self.assertEqual([], self.panel.operations)
        update = self.update(1, callback=token)
        self.bot.handle_update(update)
        self.update(1, callback=token)
        self.assertEqual(1, len(self.panel.operations))

    def test_callback_bound_to_user_and_expiry(self):
        button = self.bot.button(1, 'restart', 'execute-tunnel', tunnel_id='gre-test', operation='restart', expected=['local','peer'])
        self.update(2, callback=button['callback_data'])
        self.assertEqual([], self.panel.operations)
        self.bot.callbacks[button['callback_data']]['expires'] = 0
        self.update(1, callback=button['callback_data'])
        self.assertEqual([], self.panel.operations)
        self.assertLessEqual(len(button['callback_data'].encode()), 64)

    def test_secrets_redacted(self):
        result = self.bot.scrub('secret-token secret-password password=abc token=xyz')
        for value in ('secret-token', 'secret-password', 'abc', 'xyz'):
            self.assertNotIn(value, result)

    def test_offset_persists_after_restart(self):
        self.update(1, '/start')
        self.state.connection.close()
        self.state = tg.State(self.path)
        self.assertEqual(2, self.state.get('offset'))
        self.bot.state = self.state
        before = (len(self.telegram.messages), len(self.telegram.requests))
        self.bot.handle_update({'update_id': 1})
        self.assertEqual(before, (len(self.telegram.messages), len(self.telegram.requests)))

    def test_debounced_outage_and_single_recovery(self):
        for now in (100, 120, 159):
            self.state.observe('tunnel:test', 'test down', True, now, 60, [1])
        self.assertEqual(0, self.state.connection.execute('SELECT COUNT(*) FROM notifications').fetchone()[0])
        for now in (160, 180, 220):
            self.state.observe('tunnel:test', 'test down', True, now, 60, [1])
        self.state.observe('tunnel:test', 'test down', False, 240, 60, [1])
        self.state.observe('tunnel:test', 'test down', False, 260, 60, [1])
        self.assertEqual(2, self.state.connection.execute('SELECT COUNT(*) FROM notifications').fetchone()[0])
        row = self.state.connection.execute('SELECT * FROM incidents').fetchone()
        self.assertEqual((100, 240), (row['started'], row['ended']))

    def test_short_outage_is_silent(self):
        self.state.observe('server:test', 'test', True, 100, 60, [1])
        self.state.observe('server:test', 'test', False, 130, 60, [1])
        self.assertEqual(0, self.state.connection.execute('SELECT COUNT(*) FROM notifications').fetchone()[0])

    def test_delivery_failure_does_not_block_command_polling(self):
        with self.state.connection:
            self.state.queue([1], 'test', 'hello')
        with patch.object(self.telegram, 'send', side_effect=RuntimeError('offline')):
            self.state.deliver(self.telegram, self.bot.scrub)
        self.update(1, '/start')
        self.assertTrue(any(r[0] == 'sendMessage' for r in self.telegram.requests))
        self.assertEqual(1, self.state.connection.execute('SELECT COUNT(*) FROM notifications WHERE sent=0').fetchone()[0])

    def test_single_endpoint_is_unknown(self):
        self.assertEqual('unknown', tg.tunnel_state({'local': snapshot()['tunnels'][0]}))

    def test_split_emoji_messages_stays_within_telegram_limit(self):
        telegram = tg.Telegram('test')
        with patch.object(telegram, 'request') as request:
            telegram.send(1, '🖥' * 5000, [[{'text': 'back', 'callback_data': 'a'}]])
        for call in request.call_args_list:
            text = call.args[1]['text']
            self.assertLessEqual(len(text.encode('utf-16-le')) // 2, 4096)
        self.assertNotIn('reply_markup', request.call_args_list[0].args[1])
        self.assertIn('reply_markup', request.call_args_list[-1].args[1])

    def test_admin_and_viewer_menus(self):
        self.bot.tunnel(2, 'gre-test')
        keyboard = self.telegram.messages[-1][2]
        self.assertNotIn('توقف', str(keyboard))
        self.bot.tunnel(1, 'gre-test')
        self.assertIn('توقف', str(self.telegram.messages[-1][2]))


class ClientChecks(unittest.TestCase):
    def test_snapshot_uses_single_consolidated_panel_request(self):
        client = tg.Panel({'panel_url': 'http://127.0.0.1:8765', 'panel_username': 'bot',
                           'panel_password': 'password'})
        expected = snapshot()
        with patch.object(client, 'request', return_value=expected) as request:
            self.assertEqual(expected, client.snapshot())
        request.assert_called_once_with('/api/v1/telegram/snapshot')

    def test_login_renews_session_after_401(self):
        panel = tg.Panel({'panel_url': 'http://127.0.0.1:1', 'panel_username': 'test', 'panel_password': 'test'})
        error = urllib.error.HTTPError('http://localhost', 401, 'expired', {}, None)
        with patch.object(panel, '_request', side_effect=[error, {'ok': True}, {'items': [1]}]) as request:
            self.assertEqual([1], panel.request('/api/v1/servers')['items'])
        self.assertEqual('/api/v1/auth/login', request.call_args_list[1].args[0])

    def test_network_failure_never_replays_mutation(self):
        panel = tg.Panel({'panel_url': 'http://127.0.0.1:1'})
        with patch.object(panel, '_request', side_effect=urllib.error.URLError('offline')) as request:
            with self.assertRaises(urllib.error.URLError):
                panel.request('/api/v1/tunnels/test/restart', {})
        self.assertEqual(1, request.call_count)

    def test_missing_side_refuses_all_operations(self):
        panel = tg.Panel({'panel_url': 'http://127.0.0.1:1'})
        data = snapshot(); data['tunnels'].pop()
        with patch.object(panel, 'snapshot', return_value=data), patch.object(panel, 'request') as request:
            with self.assertRaises(tg.PanelError):
                panel.operate('gre-test', 'restart', ['local', 'peer'])
        request.assert_not_called()

    def test_partial_failure_reports_each_side(self):
        panel = tg.Panel({'panel_url': 'http://127.0.0.1:1'})
        calls = []
        def request(path, data=None):
            calls.append((path, data))
            if path.endswith('/peer/tunnels'):
                return {'items': [{'id': 'gre-test'}]}
            if '/peer/' in path and data is not None:
                raise tg.PanelError('peer unavailable')
            return {'ok': True}
        with patch.object(panel, 'snapshot', return_value=snapshot()), patch.object(panel, 'request', side_effect=request):
            result = panel.operate('gre-test', 'stop', ['local', 'peer'])
        self.assertIn('✅', result[0]); self.assertIn('❌', result[1])
        self.assertEqual(2, sum(data is not None for path, data in calls))

    def test_restart_uses_one_coordinated_rebuild_request(self):
        panel=tg.Panel({'panel_url':'http://127.0.0.1:1'})
        def request(path,data=None,timeout=None):
            return {'items':[{'id':'gre-test'}]} if path.endswith('/peer/tunnels') else {'ok':True}
        with patch.object(panel,'snapshot',return_value=snapshot()),patch.object(panel,'request',side_effect=request) as calls:
            panel.operate('gre-test','restart',['local','peer'])
        mutations=[c for c in calls.call_args_list if len(c.args)>1 and c.args[1] is not None]
        self.assertEqual(1,len(mutations))
        self.assertEqual('/api/v1/tunnels/gre-test/restart',mutations[0].args[0])
        self.assertEqual({'servers':['local','peer']},mutations[0].args[1])


class WidgetChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.state = tg.State(pathlib.Path(self.folder.name) / 'widget.sqlite3')
        self.telegram = FakeTelegram()
        self.bot = tg.Bot({'bot_token':'test-token','admins':[1,2]},
                          FakePanel(), self.telegram, self.state)
        self.denied = RuntimeError('Telegram HTTP 400: Bad Request: INPUT_MEDIA_WIDGET_NOT_ALLOWED')
        self.sent = {'message_id':42,'chat':{'id':1}}

    def tearDown(self):
        self.state.connection.close()
        self.folder.cleanup()

    def deny_widget(self, method, data):
        if method=='sendWidget':raise self.denied
        return {'message_id':43,'chat':{'id':data.get('chat_id')}}

    def test_legacy_global_disable_does_not_block_widget_delivery(self):
        self.state.put('telegram-widget-disabled', True)
        with patch.object(self.telegram, 'request', return_value=self.sent) as request:
            self.bot.show_control_widget(1)
        self.assertEqual('sendWidget', request.call_args.args[0])
        self.assertEqual([], self.telegram.messages)

    def test_denial_is_visible_and_cooldown_is_scoped_to_chat(self):
        with patch.object(self.telegram, 'request', side_effect=self.deny_widget) as request:
            self.bot.show_control_widget(1)
            self.bot.show_control_widget(1)
            self.assertEqual(1, sum(c.args[0]=='sendWidget' for c in request.call_args_list))
            self.bot.show_control_widget(2)
            self.assertEqual(2, sum(c.args[0]=='sendWidget' for c in request.call_args_list))
        self.assertIn('INPUT_MEDIA_WIDGET_NOT_ALLOWED', str(request.call_args_list))
        self.assertGreater(self.state.get(self.bot.widget_delivery_key(1))['retry_at'], time.time())

    def test_denial_does_not_disable_a_different_bot(self):
        self.state.put(self.bot.widget_delivery_key(1), {'retry_at':time.time()+300})
        self.bot.config['bot_token'] = 'other-token'
        with patch.object(self.telegram, 'request', return_value=self.sent) as request:
            self.bot.show_control_widget(1)
        request.assert_called_once()

    def test_cooldown_expires_and_success_clears_failure(self):
        with patch.object(self.telegram, 'request', side_effect=self.deny_widget), patch.object(tg.time, 'time', return_value=1000):
            self.bot.show_control_widget(1)
        with patch.object(self.telegram, 'request', return_value=self.sent) as request, patch.object(tg.time, 'time', return_value=1301):
            self.bot.show_control_widget(1)
        request.assert_called_once()
        self.assertEqual({'retry_at':0}, self.state.get(self.bot.widget_delivery_key(1)))

    def test_manual_retry_bypasses_cooldown(self):
        self.state.put(self.bot.widget_delivery_key(1), {'retry_at':time.time()+300})
        with patch.object(self.telegram, 'request', return_value=self.sent) as request:
            self.bot.dispatch(1, 'widget-retry', {})
        request.assert_called_once()

    def test_upgraded_html_creates_new_widget_unchanged_layout_edits_data(self):
        self.state.put('control-widget:1', {'chat_id':1,'message_id':41,'layout':'old-layout'})
        with patch.object(self.telegram, 'request', return_value=self.sent) as request:
            self.bot.show_control_widget(1)
            self.bot.show_control_widget(1)
        self.assertEqual(['sendWidget','editMessageWidgetData'], [c.args[0] for c in request.call_args_list])

    def test_ambiguous_transport_error_is_not_turned_into_denial(self):
        with patch.object(self.telegram, 'request', side_effect=RuntimeError('Telegram connection failed')):
            with self.assertRaisesRegex(RuntimeError, 'connection failed'):
                self.bot.show_control_widget(1)
        self.assertIsNone(self.state.get(self.bot.widget_delivery_key(1)))

    def test_widget_html_limits_are_checked_before_request(self):
        with patch.object(self.telegram, 'request') as request:
            compressed_oversize = ''.join(tg.hashlib.sha256(str(i).encode()).hexdigest() for i in range(150))
            for html in ('', 'a'*32769, compressed_oversize):
                with self.assertRaises(ValueError):
                    self.bot.widget(1, html, {}, 'test')
        request.assert_not_called()
        for name in dir(tg):
            if name.endswith('_WIDGET_HTML'):
                with patch.object(self.telegram, 'request', return_value=self.sent):
                    self.bot.widget(1, getattr(tg,name), {}, 'test')

    def test_fallback_confirmation_is_consumed_before_execution(self):
        button = self.bot.button(1, 'confirm', 'widget-fallback-execute', operation={'kind':'tunnel'})
        with patch.object(self.bot, 'start_operation') as execute:
            for update_id in (1,2):
                self.bot.handle_update({'update_id':update_id,'callback_query':{
                    'id':str(update_id),'from':{'id':1},'data':button['callback_data'],
                    'message':{'chat':{'type':'private','id':1}}}})
        execute.assert_called_once()

    def test_fallback_refresh_action_opens_the_current_page(self):
        state = self.bot.control_widget_state(1, 'overview')
        action = state['actions'][0]['query']
        with patch.object(self.bot, 'show_control_widget') as show:
            self.bot.widget_fallback_query(1, action, {'page':'overview','server_id':'all'})
        show.assert_called_once_with(1, 'overview', 0, 'all', '')

    def test_fallback_cancel_preserves_selected_forward_and_server(self):
        context = {'page':'forward','server_id':'peer','selected':'rule'}
        self.bot.fallback_confirm(1, 'delete?', {}, context)
        token = self.telegram.messages[-1][2][0][1]['callback_data']
        entry = self.bot.callbacks[token]
        with patch.object(self.bot, 'show_screen') as show:
            self.bot.dispatch(1, entry['action'], entry['payload'])
        show.assert_called_once_with(1, 'forward', 0, 'peer', 'rule')


class ConsoleChecks(unittest.TestCase):
    setUp = BotChecks.setUp
    tearDown = BotChecks.tearDown
    update = BotChecks.update
    def test_native_home_never_attempts_widget_delivery(self):
        self.update(1,'/start')
        methods=[r[0] for r in self.telegram.requests]
        self.assertIn('sendMessage',methods)
        self.assertNotIn('sendWidget',methods)
        text=self.telegram.messages[-1][1]
        self.assertNotIn('INPUT_MEDIA',text)
        self.assertIn('آخرین دریافت',text)

    def test_navigation_edits_single_message_and_has_named_rows(self):
        self.update(1,'/start')
        self.bot.show_screen(1,'servers')
        self.bot.show_screen(1,'tunnels')
        self.assertEqual(1,sum(r[0]=='sendMessage' for r in self.telegram.requests))
        self.assertEqual(2,sum(r[0]=='editMessageText' for r in self.telegram.requests))
        labels=str(self.telegram.messages[-1][2])
        self.assertIn('gre-test',labels)
        self.assertIn('خانه',labels)
        self.assertIn('بازگشت',labels)

    def test_navigation_button_survives_new_bot_instance(self):
        self.update(1,'/start')
        token=self.telegram.messages[-1][2][0][0]['callback_data']
        self.bot=tg.Bot(self.bot.config,self.panel,self.telegram,self.state)
        self.update(1,callback=token)
        self.assertIn('سرورها',self.telegram.messages[-1][1])

    def test_confirmation_consumption_survives_new_bot_instance(self):
        token=self.bot.button(1,'run','run-operation',operation={})['callback_data']
        with patch.object(self.bot,'start_operation') as start:
            self.update(1,callback=token)
            start.assert_called_once()
        self.bot=tg.Bot(self.bot.config,self.panel,self.telegram,self.state)
        with patch.object(self.bot,'start_operation') as start:
            self.update(1,callback=token)
            start.assert_not_called()

    def test_cancel_and_start_are_not_interpreted_as_wizard_input(self):
        self.bot.start_forward_wizard(1,'local')
        self.update(1,'/cancel')
        self.assertIsNone(self.bot.wizard_get(1))
        self.bot.start_forward_wizard(1,'local')
        self.update(1,'/start')
        self.assertIsNone(self.bot.wizard_get(1))

    def test_input_and_output_digits_are_ascii_and_html_escaped(self):
        from telegram_ui import digits, render
        self.assertEqual('123123123',digits('۱۲۳١٢٣１２３'))
        self.bot.wizard_save(1,{'step':'listen_port','action':'create','server_id':'local'})
        self.bot.wizard_text(1,'۲۰۵۳')
        self.assertEqual(2053,self.bot.wizard_get(1)['listen_port'])
        text,_=render({'page':'servers','title':'<script>۱۲۳</script>','rows':[]},lambda *a,**k:{})
        self.assertNotIn('<script>',text)
        self.assertIn('&lt;script&gt;123',text)

    def test_all_managed_servers_are_available_for_forward_selection(self):
        self.panel.data['servers']=[{'id':'s'+str(i),'host':'192.0.2.1'} for i in range(10)]
        seen=[]
        for p in range(3):
            state=self.bot.console_state(1,'forward_servers',p)
            seen.extend(x['query'] for x in state['rows'])
        self.assertIn('select-forward-server:s9',seen)
        self.assertEqual(11,len(seen))

    def test_selected_server_is_preserved_when_returning_from_forward(self):
        with patch.object(self.bot,'show_screen') as show:
            self.bot.navigate(1,'nav:forwards',{'page':'forward','server_id':'peer','selected':'demo'})
        show.assert_called_once_with(1,'forwards',server_id='peer')

    def test_viewer_cannot_reach_admin_routes_by_constructing_queries(self):
        for query in ('nav:forward_servers','nav:update','cf:delete:demo','confirm:stop:gre-test'):
            with self.assertRaises(RuntimeError):self.bot.navigate(2,query)
        with self.assertRaises(RuntimeError):self.bot.start_operation(2,{})

    def test_native_confirmation_does_not_mutate_until_accepted(self):
        self.bot.navigate(1,'confirm:stop:gre-test',{'page':'tunnel','selected':'gre-test'})
        self.assertEqual([],self.panel.operations)
        self.assertIn('اتصال‌های عبوری',self.telegram.messages[-1][1])
        token=self.telegram.messages[-1][2][0][0]['callback_data']
        with patch.object(self.bot,'start_operation') as start:
            self.update(1,callback=token)
        self.assertEqual('stop',start.call_args.args[1]['action'])

    def test_long_operation_starts_in_background_and_duplicate_is_refused(self):
        operation={'kind':'tunnel','target':'gre-test','action':'restart','expected':['local','peer']}
        with patch('telegram_console.threading.Thread') as thread:
            self.bot.start_operation(1,operation)
            self.bot.start_operation(1,operation)
        thread.assert_called_once()
        thread.return_value.start.assert_called_once()
        self.assertEqual([],self.panel.operations)

    def test_uneditable_message_is_replaced_but_network_error_is_not_replayed(self):
        self.bot.home(1)
        saved=self.state.get('console:1')
        with patch.object(self.telegram,'request',side_effect=[RuntimeError("message can't be edited"),{'message_id':99}]) as request:
            self.bot.home(1)
        self.assertEqual(['editMessageText','sendMessage'],[x.args[0] for x in request.call_args_list])
        with patch.object(self.telegram,'request',side_effect=RuntimeError('connection failed')) as request:
            with self.assertRaises(RuntimeError):self.bot.home(1)
        request.assert_called_once()

    def test_stale_wizard_controls_cannot_change_new_draft(self):
        self.bot.wizard_save(1,{'step':'algorithm'})
        button=self.bot.button(1,'old','wizard-set',key='algorithm',value='source')
        self.bot.wizard_save(1,{'step':'algorithm'})
        self.update(1,callback=button['callback_data'])
        self.assertNotIn('algorithm',self.bot.wizard_get(1))

    def test_worker_reports_partial_result_without_replaying(self):
        config={**self.bot.config,'state_path':str(self.path)}
        worker=tg.Bot(config,self.panel,self.telegram,tg.State(self.path))
        self.panel.operate=lambda *args:['local ✅','peer ❌']
        self.state.put('console-job:1',{'id':'test','state':'running','title':'restart'})
        with patch.object(self.bot,'operation_worker',return_value=worker):
            self.bot._console_worker(1,'test',{'kind':'tunnel','target':'gre-test','action':'restart','expected':['local','peer']})
        self.assertEqual('partial',self.state.get('console-job:1')['state'])


class ResourceChecks(unittest.TestCase):
    tearDown = BotChecks.tearDown
    update = BotChecks.update

    def setUp(self):
        BotChecks.setUp(self)
        self.items=[{'id':sid,'name':sid,'host':'192.0.2.1','reachable':True,'resources':{
            'cpu_percent':25,'memory_percent':40,'disk_percent':60,'swap_percent':0,
            'memory_used_bytes':400,'memory_total_bytes':1000,'disk_used_bytes':600,'disk_total_bytes':1000,
            'swap_total_bytes':0,'download_bytes_per_sec':1024,'upload_bytes_per_sec':512,'checked_at':time.time()}}
            for sid in ('local','peer')]
        self.panel.data['resources']=self.items

    def native(self):
        self.state.put(self.bot.widget_delivery_key(1),{'retry_at':time.time()+3600})
        self.bot.show_screen(1,'resources')

    def test_only_resource_page_uses_the_resource_widget(self):
        self.bot.home(1);self.bot.servers(1);self.bot.tunnels(1)
        self.assertFalse(any(r[0]=='sendWidget' for r in self.telegram.requests))
        self.bot.hardware(1)
        request=next(r for r in self.telegram.requests if r[0]=='sendWidget')
        self.assertEqual(tg.RESOURCE_WIDGET_HTML,request[1]['html'])
        self.assertNotEqual(tg.CONTROL_WIDGET_HTML,request[1]['html'])

    def test_resource_widget_respects_selected_server_scope(self):
        self.bot.show_screen(1,'resources',server_id='peer')
        data=json.loads(self.telegram.requests[-1][1]['chat_data'])
        self.assertEqual('peer',data['x']['id'])
        self.assertEqual(1,data['n'])

    def test_denied_widget_keeps_a_live_native_card(self):
        request=self.telegram.request
        def deny(method,data):
            if method=='sendWidget':raise RuntimeError('INPUT_MEDIA_WIDGET_NOT_ALLOWED')
            return request(method,data)
        with patch.object(self.telegram,'request',side_effect=deny):self.bot.hardware(1)
        self.assertEqual('native',self.state.get('resource-active:1')['kind'])
        self.assertIn('پایش زنده',self.telegram.messages[-1][1])
        self.assertIn('25.0%',self.telegram.messages[-1][1])
        self.assertNotIn('INPUT_MEDIA_WIDGET_NOT_ALLOWED',self.telegram.messages[-1][1])

    def test_native_refresh_updates_same_message_without_extending_lease(self):
        self.native();active=self.state.get('resource-active:1');mid=active['message_id']
        self.items[0]['resources']['cpu_percent']=70
        with patch('telegram_resources.time.time',return_value=active['next_at']+1):self.bot.refresh_resource_cards()
        self.assertEqual('editMessageText',self.telegram.requests[-1][0])
        self.assertEqual(mid,self.telegram.requests[-1][1]['message_id'])
        self.assertIn('70.0%',self.telegram.messages[-1][1])
        self.assertEqual(active['until'],self.state.get('resource-active:1')['until'])

    def test_exit_stops_native_polling(self):
        self.native();self.bot.home(1)
        with patch.object(self.bot,'resource_items') as fetch:self.bot.refresh_resource_cards()
        fetch.assert_not_called()
        self.assertIsNone(self.state.get('resource-active:1'))

    def test_pause_resume_and_expiry(self):
        self.native();ctx={'page':'resources','server_id':'all'}
        self.bot.navigate(1,'resource-pause',ctx)
        self.assertTrue(self.state.get('resource-active:1')['paused'])
        with patch.object(self.bot,'resource_items') as fetch:self.bot.refresh_resource_cards()
        fetch.assert_not_called()
        self.bot.navigate(1,'resource-resume',ctx)
        active=self.state.get('resource-active:1')
        self.assertFalse(active['paused'])
        with patch('telegram_resources.time.time',return_value=active['until']+1):self.bot.refresh_resource_cards()
        self.assertTrue(self.state.get('resource-active:1')['paused'])
        self.assertIn('متوقف',self.telegram.messages[-1][1])

    def test_pagination_changes_server_and_refresh_keeps_it(self):
        self.native();ctx={'page':'resources','page_index':0,'server_id':'all','selected':'local'}
        self.bot.navigate(1,'page:resources:1',ctx)
        self.assertEqual('peer',self.state.get('resource-active:1')['selected'])
        self.bot.navigate(1,'refresh',ctx)
        self.assertEqual('peer',self.state.get('resource-active:1')['selected'])

    def test_server_reordering_does_not_switch_selected_server(self):
        self.native();active=self.state.get('resource-active:1')
        self.items.reverse()
        with patch('telegram_resources.time.time',return_value=active['next_at']+1):self.bot.refresh_resource_cards()
        self.assertEqual('local',self.state.get('resource-active:1')['selected'])

    def test_failed_fetch_is_shown_as_unavailable(self):
        self.native();active=self.state.get('resource-active:1')
        with patch.object(self.bot,'resource_items',side_effect=RuntimeError('offline')),patch('telegram_resources.time.time',return_value=active['next_at']+1):
            self.bot.refresh_resource_cards()
        self.assertIn('در دسترس نیست',self.telegram.messages[-1][1])

    def test_navigation_during_fetch_is_not_overwritten(self):
        self.native();active=self.state.get('resource-active:1')
        def fetch(scope):
            self.bot.home(1)
            return self.items
        with patch.object(self.bot,'resource_items',side_effect=fetch),patch('telegram_resources.time.time',return_value=active['next_at']+1):
            self.bot.refresh_resource_cards()
        self.assertEqual('overview',self.state.get('console:1')['screen']['page'])

    def test_leaving_widget_restores_native_console(self):
        self.bot.home(1);old=self.state.get('console:1')['message_id']
        self.bot.hardware(1);widget=self.state.get('console:1')['message_id']
        self.bot.home(1)
        self.assertNotEqual(old,widget)
        self.assertEqual(old,self.state.get('console:1')['message_id'])
        self.assertTrue(any(r[0]=='editMessageReplyMarkup' for r in self.telegram.requests))

    def test_closed_widget_and_unauthorized_user_do_not_fetch_metrics(self):
        query={'id':'query','from':{'id':999},'chat':{'id':999,'type':'private'},'message_id':100,'data':'resources:0'}
        with patch.object(self.bot,'resource_items') as fetch:
            self.bot.answer_resource_query(query)
            query.update({'from':{'id':1},'chat':{'id':1,'type':'private'}})
            self.bot.answer_resource_query(query)
        fetch.assert_not_called()

    def test_widget_query_persists_state_and_does_not_escape_scope(self):
        self.bot.show_screen(1,'resources',server_id='peer');mid=self.state.get('console:1')['message_id']
        self.bot.answer_resource_query({'id':'q','from':{'id':1},'chat':{'id':1,'type':'private'},'message_id':mid,'data':'resources:9'})
        response=json.loads(self.telegram.requests[-1][1]['chat_data'])
        self.assertEqual('peer',response['x']['id'])
        self.assertEqual('editMessageWidgetData',self.telegram.requests[-1][0])

    def test_large_persian_names_stay_under_widget_limit(self):
        items=copy.deepcopy(self.items)
        items[0].update(name='سرور'*100,host='میزبان'*100)
        state=self.bot.resource_payload(items,0)
        self.assertLessEqual(len(json.dumps(state,ensure_ascii=False,separators=(',',':')).encode()),1024)
        self.assertLess(len(self.bot.resource_text(state).encode('utf-16-le'))//2,4096)

    def test_unchanged_widget_can_still_renew_its_live_session(self):
        self.bot.hardware(1);active=self.state.get('resource-active:1')
        request=self.telegram.request
        def unchanged(method,data):
            if method=='editMessageWidgetData':raise RuntimeError('message is not modified')
            return request(method,data)
        with patch.object(self.telegram,'request',side_effect=unchanged),patch('telegram_resources.time.time',return_value=active['until']-1):
            self.bot.hardware(1)
        self.assertGreater(self.state.get('resource-active:1')['until'],active['until'])


class ForwardChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.original = (t.BASE, t.DB)
        t.BASE = pathlib.Path(self.folder.name); t.DB = t.BASE / 'panel.sqlite3'
        self.rule = {'id': 'demo', 'server_id': 'local', 'listen_ip': '0.0.0.0',
                     'listen_port': 443, 'backends': []}
        with t.db() as connection:
            connection.execute('INSERT INTO port_forwards VALUES(?,?)', ('demo', json.dumps(self.rule)))

    def tearDown(self):
        t.BASE, t.DB = self.original
        self.folder.cleanup()

    def test_disable_preserves_rule_and_excludes_it_from_haproxy(self):
        with patch.object(t, 'privileged', return_value={'ok': True}) as apply:
            t.set_forward_enabled('demo', 'local', False)
        self.assertFalse(t.forward_rows()[0]['enabled'])
        self.assertEqual([], apply.call_args.args[0]['rules'])
        with patch.object(t, 'privileged', return_value={'ok': True}) as apply:
            t.set_forward_enabled('demo', 'local', True)
        self.assertTrue(t.forward_rows()[0]['enabled'])
        self.assertEqual(1, len(apply.call_args.args[0]['rules']))
        self.assertNotIn('enabled', apply.call_args.args[0]['rules'][0])

    def test_failed_apply_keeps_previous_database_rule(self):
        with patch.object(t, 'privileged', return_value={'ok': False, 'error': 'invalid config'}):
            with self.assertRaises(RuntimeError):
                t.set_forward_enabled('demo', 'local', False)
        self.assertTrue(t.forward_rows()[0].get('enabled', True))

    def test_invalid_enabled_value_is_rejected(self):
        with self.assertRaises(ValueError):
            t.set_forward_enabled('demo', 'local', 'false')


if __name__ == '__main__':
    unittest.main(verbosity=2)
