"""Paused WEB profiles must not keep MTProxy's upstream connection pool alive."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'panel'))
import backend
import helper
import installer


def state(enabled=True, paused=False):
    return {'paused': paused, 'users': [
        {'id': 'test', 'secret': 'a' * 32, 'enabled': enabled}]}


class BackendTests(unittest.TestCase):
    def test_conntrack_module_loads_before_tuning_and_preserves_larger_limits(self):
        for initial,expected in ((65536,262144),(524288,524288)):
            events=[]
            def run(*args):events.append(args)
            def current(*args,**kwargs):
                self.assertIn(('modprobe','nf_conntrack'),events)
                return str(initial)+'\n'
            with self.subTest(initial=initial), \
                    patch.object(installer,'directory'), \
                    patch.object(installer,'write') as write, \
                    patch.object(installer,'run',side_effect=run), \
                    patch.object(installer.subprocess,'check_output',side_effect=current):
                installer.configure_conntrack()
            write.assert_any_call('/etc/modules-load.d/relay-conntrack.conf','nf_conntrack\n')
            write.assert_any_call('/etc/sysctl.d/90-relay-conntrack.conf',f'net.netfilter.nf_conntrack_max = {expected}\n')
            self.assertEqual(events[-1],('sysctl','-p','/etc/sysctl.d/90-relay-conntrack.conf'))

    def test_paused_backend_waits_without_executing_mtproxy(self):
        with patch.object(Path, 'read_text', return_value=json.dumps(
                {'enabled': False, 'secrets': ['a' * 32]})), \
                patch.object(backend, 'wait_for_restart') as wait, \
                patch.object(backend.os, 'execv') as execute:
            backend.main()
        wait.assert_called_once_with()
        execute.assert_not_called()

    def test_enabled_and_legacy_configs_start_mtproxy(self):
        for config in ({'enabled': True, 'secrets': ['a' * 32]},
                       {'secrets': ['a' * 32]}):
            with self.subTest(config=config), \
                    patch.object(Path, 'read_text', return_value=json.dumps(config)), \
                    patch.object(backend, 'wait_for_restart') as wait, \
                    patch.object(backend.os, 'execv') as execute:
                backend.main()
                self.assertEqual(execute.call_args.args[0], '/opt/MTProxy/objs/bin/mtproto-proxy')
                args = execute.call_args.args[1]
                self.assertEqual(args[args.index('-S') + 1], 'a' * 32)
                wait.assert_not_called()

    def test_helper_pause_disable_resume_and_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            profiles = root / 'profiles.json'
            managed = root / 'managed-secrets.json'
            previous = {'enabled': True, 'secrets': ['b' * 32]}
            profiles.write_text('{"profiles": []}')
            managed.write_text(json.dumps(previous))
            control = helper.Controller(root)

            def atomic(path, value, *args):
                path.write_text(json.dumps(value))

            response = Mock()
            response.__enter__ = Mock(return_value=Mock(status=200))
            response.__exit__ = Mock(return_value=False)
            with patch.object(helper.pathlib, 'Path', side_effect=lambda p: root / str(p).rsplit('/', 1)[-1]), \
                    patch.object(helper, 'atomic', side_effect=atomic), \
                    patch.object(helper, 'blocked', return_value=False), \
                    patch.object(helper.subprocess, 'run') as run, \
                    patch.object(helper.urllib.request, 'urlopen', return_value=response) as health:
                for value in (state(paused=True), state(enabled=False), state()):
                    control.apply(value)
                    active = bool(backend.active_users(value))
                    self.assertEqual(json.loads(managed.read_text())['enabled'], active)
                    self.assertEqual(health.call_args.args[0], backend.health_url(value))
                    if active:
                        self.assertEqual(json.loads(managed.read_text())['secrets'], ['a' * 32])
                    else:
                        self.assertEqual(json.loads(profiles.read_text())['profiles'][0]['name'], 'suspended')
                before = managed.read_bytes(), profiles.read_bytes()
                # A failed pause must restore the active keys AND enabled flag.
                run.side_effect = RuntimeError('restart failed')
                with self.assertRaises(RuntimeError):
                    control.apply(state(paused=True))
                self.assertEqual((managed.read_bytes(), profiles.read_bytes()), before)

    def test_installer_health_handles_paused_disabled_and_active_profiles(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            response = Mock()
            response.__enter__ = Mock(return_value=Mock(status=200))
            response.__exit__ = Mock(return_value=False)
            for value in (state(paused=True), state(enabled=False), state()):
                (root / 'users.json').write_text(json.dumps(value))
                with patch.object(installer, 'STATE', root / 'install.json'), \
                        patch.object(installer.urllib.request, 'urlopen', return_value=response) as health:
                    installer.health('proxy.example.com', public=False)
                self.assertEqual(health.call_args_list[0].args[0], backend.health_url(value))


if __name__ == '__main__':
    unittest.main()
