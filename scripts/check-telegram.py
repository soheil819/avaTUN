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

    def request(self, path, data=None):
        return {'items': []}


class FakeTelegram:
    def __init__(self):
        self.messages = []
        self.requests = []

    def send(self, *args):
        self.messages.append(args)

    def request(self, *args):
        self.requests.append(args)
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
        before = len(self.telegram.messages)
        self.bot.handle_update({'update_id': 1})
        self.assertEqual(before, len(self.telegram.messages))

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
        self.assertTrue(self.telegram.messages)
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
        labels = str(self.telegram.messages[-1][2])
        self.assertNotIn('ریستارت', labels)
        self.bot.tunnel(1, 'gre-test')
        self.assertIn('ریستارت', str(self.telegram.messages[-1][2]))


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
            result = panel.operate('gre-test', 'restart', ['local', 'peer'])
        self.assertIn('✅', result[0]); self.assertIn('❌', result[1])
        self.assertEqual(2, sum(data is not None for path, data in calls))


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
