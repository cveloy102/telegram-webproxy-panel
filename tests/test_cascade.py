import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'panel'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cascade_control as control
import cascade_network as network
import cascade_fetch

RU = base64.b64encode(b'r' * 32).decode()
EXIT = base64.b64encode(b'e' * 32).decode()
PRIVATE = base64.b64encode(b'p' * 32).decode()


class CascadeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.c = control.Controller(self.root, uids=[1001, 1002])
        self.root.joinpath('private.key').write_text(PRIVATE)
        self.root.joinpath('public.key').write_text(RU)
        guard = patch('migration_state.ROOT', self.root / 'migration')
        guard.start(); self.addCleanup(guard.stop)
        notify = patch('backup_notify.changed')
        notify.start(); self.addCleanup(notify.stop)

    def save(self, enabled=False):
        value = dict(schema=1, enabled=enabled, name='Norway', host='138.16.143.97', port=51821, exit_public_key=EXIT)
        control.atomic(self.c.path, value)
        return value

    def test_public_ipv4_and_key_validation_rejects_injection_and_private_hosts(self):
        for value in ('127.0.0.1', '10.1.2.3', '::1', 'host.example', '1.1.1.1\nPostUp=x', None):
            with self.subTest(value=value), self.assertRaises(ValueError): network.endpoint(value)
        for value in ('x', 'A' * 44, RU + '\n', None, base64.b64encode(bytes(32)).decode()):
            with self.subTest(value=value), self.assertRaises(ValueError): network.public_key(value)
        self.assertEqual(network.public_key(RU), RU)

    def test_configure_and_pair_export_only_public_data(self):
        with patch.object(self.c, 'apply'), patch.object(control, 'remove_runtime'):
            state = self.c.call(dict(op='configure', name='Norway', host='138.16.143.97', port=51821))
            self.assertEqual(state['pairing']['ru_public_key'], RU)
            state = self.c.call(dict(op='pair', reply=dict(schema=1, exit_public_key=EXIT)))
        self.assertTrue(state['configured'])
        self.assertFalse(state['enabled'])
        self.assertNotIn(PRIVATE, json.dumps(state))
        with self.assertRaises(ValueError): self.c.call(dict(op='pair', reply=dict(schema=1, exit_public_key=RU)))

    def test_invalid_config_does_not_touch_runtime_or_saved_state(self):
        self.save()
        before = self.c.path.read_bytes()
        with patch.object(self.c, 'apply') as apply:
            for port in (True, 53, 65536, '51821'):
                with self.assertRaises(ValueError): self.c.call(dict(op='configure', name='N', host='138.16.143.97', port=port))
            apply.assert_not_called()
        self.assertEqual(before, self.c.path.read_bytes())

    def test_failed_probe_does_not_enable_cascade(self):
        self.save()
        with patch.object(self.c, 'apply'), patch.object(control, 'run', side_effect=OSError):
            with self.assertRaises(ValueError): self.c.call({'op': 'enable'})
        self.assertFalse(self.c.read()['enabled'])
        self.assertFalse(self.c.last_check['ok'])

    def test_probe_checks_real_exit_and_cannot_use_environment_proxy_or_dns(self):
        state = self.save()
        with patch.object(self.c, 'apply'), patch.object(control, 'run', return_value=types.SimpleNamespace(stdout='ip=138.16.143.97\n')) as run:
            self.assertTrue(self.c.probe(state)['ok'])
            args = run.call_args.args
            self.assertIn('--noproxy', args)
            self.assertIn('--resolve', args)
            self.assertEqual(args[args.index('--interface') + 1], network.ENTRY)
        with patch.object(self.c, 'apply'), patch.object(control, 'run', return_value=types.SimpleNamespace(stdout='ip=185.220.34.190\n')):
            with self.assertRaises(ValueError): self.c.probe(state)

    def test_transition_stops_clients_before_policy_switch_and_restarts_after(self):
        self.save()
        order = []
        def apply(state):
            self.assertTrue(self.c.read()['enabled'])
            order.append('apply')
        with patch.object(self.c, 'probe', side_effect=lambda state: order.append('probe')), patch.object(self.c, 'stop_clients', side_effect=lambda: order.append('stop') or ['mtproxy']), patch.object(self.c, 'apply', side_effect=apply), patch.object(self.c, 'start_clients', side_effect=lambda names: order.append('start')):
            self.c.call({'op': 'enable'})
        self.assertEqual(order, ['probe', 'stop', 'apply', 'start'])

    def test_apply_failure_leaves_enabled_mode_and_clients_stopped(self):
        self.save()
        with patch.object(self.c, 'probe'), patch.object(self.c, 'stop_clients', return_value=['mtproxy']), patch.object(self.c, 'apply', side_effect=RuntimeError), patch.object(self.c, 'start_clients') as start:
            with self.assertRaises(RuntimeError): self.c.call({'op': 'enable'})
            start.assert_not_called()
        self.assertTrue(self.c.read()['enabled'])
        with self.assertRaises(ValueError): self.c.call(dict(op='configure', name='N', host='1.1.1.1', port=51821))

    def test_disable_requires_explicit_direct_egress_confirmation(self):
        self.save(True)
        with self.assertRaises(ValueError): self.c.call({'op': 'disable'})
        self.assertTrue(self.c.read()['enabled'])
        with patch.object(self.c, 'stop_clients', return_value=[]), patch.object(self.c, 'apply'), patch.object(self.c, 'start_clients'):
            self.c.call({'op': 'disable', 'confirm': 'DIRECT'})
        self.assertFalse(self.c.read()['enabled'])

    def test_guard_installed_before_tunnel_and_routes_on_boot(self):
        state = self.save(True)
        order = []
        with patch.object(control, 'replace_table', side_effect=lambda *args: order.append('guard')), patch.object(control, 'setup_interface', side_effect=lambda *args, **kwargs: order.append('interface')), patch.object(control, 'policy_routes', side_effect=lambda: order.append('routes')):
            self.c.apply(state)
        self.assertEqual(order, ['guard', 'interface', 'routes'])

    def test_firewall_preserves_replies_and_has_no_direct_or_ipv6_fallback(self):
        rules = network.entry_firewall([1001, 1002], True)
        self.assertIn('ct direction reply return', rules)
        self.assertIn('type route hook output', rules)
        self.assertIn('meta mark ' + network.OUTER_MARK + ' return', rules)
        self.assertIn('type filter hook postrouting', rules)
        self.assertIn('meta nfproto ipv6 drop', rules)
        self.assertIn('iifname "awg-relay" oifname != "wg-cascade" drop', rules)
        self.assertIn('oifname "wg-cascade" masquerade', rules)
        disabled = network.entry_firewall([1001, 1002], False)
        self.assertNotIn('mark set', disabled)
        self.assertIn('iifname "wg-cascade" drop', disabled)

    def test_routes_have_terminal_prohibit_and_never_replace_main_default(self):
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            return types.SimpleNamespace(stdout='[]')
        with patch.object(network, 'run', side_effect=run): network.policy_routes()
        self.assertTrue(any('prohibit' in args for args in calls))
        for args in calls:
            if 'route' in args and 'replace' in args:
                self.assertEqual(args[args.index('table') + 1], network.TABLE)

    def test_telegram_bootstrap_uses_prepared_tunnel_even_during_standby(self):
        self.save(False)
        with patch.object(cascade_fetch, 'ROOT', self.root), patch.object(cascade_fetch.subprocess, 'run', return_value=types.SimpleNamespace(stdout=b'synthetic-secret-data')) as run:
            self.assertEqual(cascade_fetch.fetch_telegram('https://core.telegram.org/getProxySecret'), b'synthetic-secret-data')
            args=run.call_args.args[0]
            self.assertEqual(args[args.index('--interface')+1], network.ENTRY)
            self.assertIn('--noproxy', args)
        with self.assertRaises(ValueError):cascade_fetch.fetch_telegram('https://attacker.example/')

    def test_telegram_fetch_rejects_wrong_format_without_saving_it(self):
        self.save()
        with patch.object(cascade_fetch, 'ROOT', self.root), patch.object(cascade_fetch.subprocess, 'run', return_value=types.SimpleNamespace(stdout=b'not-a-telegram-config'*10)):
            with self.assertRaises(RuntimeError):cascade_fetch.fetch_telegram('https://core.telegram.org/getProxyConfig')

    def test_cli_bootstrap_refuses_to_overwrite_completed_panel(self):
        import cascade_install
        path=self.root/'installed.json';path.write_text(json.dumps({'phase':'complete'}))
        setup=types.SimpleNamespace(STATE=path,preflight=unittest.mock.Mock())
        with self.assertRaises(RuntimeError):cascade_install.prepare_entry(setup)
        setup.preflight.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'systemd notification uses Linux UNIX sockets')
    def test_systemd_readiness_notification_uses_main_process_socket(self):
        with patch.dict(os.environ,{'NOTIFY_SOCKET':'@relay-ready'}),patch.object(control.socket,'socket') as socket:
            control.notify_ready()
            connection=socket.return_value.__enter__.return_value
            connection.connect.assert_called_once_with('\0relay-ready')
            connection.sendall.assert_called_once_with(b'READY=1')

    def test_reconciler_repairs_route_removed_by_link_down(self):
        self.save(True)
        with patch.object(control,'run',return_value=types.SimpleNamespace(stdout='[{"type":"prohibit","dst":"default"}]')),patch.object(self.c,'apply') as apply:
            self.c.reconcile();apply.assert_called_once()
        outputs=[types.SimpleNamespace(stdout='[{"dst":"default","dev":"wg-cascade"}]'),types.SimpleNamespace(stdout='[{"priority":10781,"table":20781},{"priority":10782,"table":20781}]')]
        with patch.object(control,'run',side_effect=outputs),patch.object(self.c,'apply') as apply:
            self.c.reconcile();apply.assert_not_called()


if __name__ == '__main__': unittest.main()
