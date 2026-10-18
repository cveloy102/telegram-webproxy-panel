"""Release regression matrix for entry menus and restore target compatibility."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import installer as setup
from restore import validate_target


class RestoreMatrix(unittest.TestCase):
    def test_busy_udp_port_retries_for_both_protocols(self):
        import amnezia_install,hysteria_install
        for module,field in ((hysteria_install,'hy2_port'),(amnezia_install,'awg_port')):
            options={'domain':'tg.example.com','ip':'1.1.1.1'}
            with self.subTest(protocol=field),patch('builtins.input',side_effect=['да','vpn.example.com','51820','51821']),\
                 patch.object(setup,'check_dns'),patch.object(setup,'check_udp_port',side_effect=[ValueError('busy'),None]) as check,\
                 contextlib.redirect_stdout(io.StringIO()):
                module.ask_options(setup,options)
            self.assertEqual(options[field],51821);self.assertEqual(check.call_count,2)

    def test_all_sixteen_protocol_target_combinations(self):
        for archived in range(4):
            manifest={'telegram_domain':'tg.example.com','hysteria':bool(archived&1),'amnezia':bool(archived&2),
                      'hysteria_domain':'hy.example.com','amnezia_domain':'awg.example.com'}
            for installed in range(4):
                current={'domain':'tg.example.com'}
                if installed&1:current['hy2_domain']='hy.example.com'
                if installed&2:current['awg_domain']='awg.example.com'
                with self.subTest(archived=archived,installed=installed):
                    if archived==installed:validate_target(manifest,current)
                    else:
                        with self.assertRaises(ValueError):validate_target(manifest,current)
        with self.assertRaises(ValueError):validate_target({'telegram_domain':'old.example.com'},{'domain':'new.example.com'})


@unittest.skipUnless(os.name=='posix','Linux installer locks')
class EntryMenus(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.folder=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state=self.folder/'install.json'
        self.stack.enter_context(patch.object(setup,'STATE',self.state))
        self.stack.enter_context(patch.object(setup,'json_write',side_effect=lambda path,value,**kwargs:Path(path).write_text(json.dumps(value))))
        self.stack.enter_context(patch.object(setup,'preflight'))
        self.stack.enter_context(patch('recovery_wizard.pending',return_value=False))
        self.wizard=self.stack.enter_context(patch('recovery_wizard.run_wizard'))
        self.stack.enter_context(patch('migration_state.blocked',return_value=False))
        self.stack.enter_context(patch('migration_state.mutation',side_effect=contextlib.nullcontext))
        self.stack.enter_context(patch.object(setup,'open_install_lock',side_effect=lambda:open(self.folder/'lock','a')))
        self.stack.enter_context(patch.object(sys,'argv',['installer.py','--source',str(ROOT)]))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.packages=self.stack.enter_context(patch.object(setup,'packages'))
        self.install=self.stack.enter_context(patch.object(setup,'install_files'))
        self.run=self.stack.enter_context(patch.object(setup,'run'))
        self.backup=self.stack.enter_context(patch('manage.backup',return_value=self.folder/'copy.tar.gz'))
        self.stack.enter_context(patch('manage.show_access'))
        self.health=self.stack.enter_context(patch.object(setup,'health'))
        self.optional=self.stack.enter_context(patch.object(setup,'optional_protocols'))
        self.options={'domain':'tg.example.com','phase':'complete'}

    def existing(self):self.state.write_text(json.dumps(self.options))

    def test_exit_and_invalid_menu_retry_on_fresh_and_existing(self):
        for existing in (False,True):
            if existing:self.existing()
            with patch('builtins.input',side_effect=['wrong','9','0']):setup.main()
        self.packages.assert_not_called();self.install.assert_not_called();self.run.assert_not_called()

    def test_check_and_backup_do_not_update_or_offer_protocols(self):
        self.existing()
        for choice in ('1','2'):
            with patch('builtins.input',return_value=choice):setup.main()
        self.health.assert_called_once_with('tg.example.com')
        self.backup.assert_called_once_with()
        self.packages.assert_not_called();self.optional.assert_not_called();self.install.assert_not_called()

    def test_fresh_recovery_dispatches_without_installation(self):
        with patch('builtins.input',return_value='2'):setup.main()
        self.wizard.assert_called_once();self.packages.assert_not_called()

    def test_declining_fresh_install_or_update_has_no_side_effects(self):
        with patch.object(setup,'new_options',return_value=self.options),patch('builtins.input',side_effect=['1','нет']):setup.main()
        self.assertFalse(self.state.exists())
        self.existing();before=self.state.read_bytes()
        with patch('builtins.input',side_effect=['3','нет']):setup.main()
        self.assertEqual(self.state.read_bytes(),before)
        self.packages.assert_not_called();self.run.assert_not_called();self.install.assert_not_called()

    def test_failed_pre_update_backup_restarts_previous_panel(self):
        self.existing();before=self.state.read_bytes()
        self.backup.side_effect=OSError('disk full')
        with patch.object(setup,'users'),patch.object(setup,'build',return_value=(Path('relay'),Path('mtproxy'))),\
             patch.object(setup,'directory'),patch.object(setup,'json_write'),\
             patch('builtins.input',side_effect=['3','да']),self.assertRaisesRegex(OSError,'disk full'):
            setup.main()
        self.run.assert_any_call('systemctl','restart','relay-helper','relay-panel')
        self.install.assert_not_called();self.assertEqual(self.state.read_bytes(),before)

    def test_ctrl_c_during_activation_rolls_back_previous_version(self):
        self.existing()
        self.install.side_effect=KeyboardInterrupt
        with patch.object(setup,'users'),patch.object(setup,'build',return_value=(Path('relay'),Path('mtproxy'))),\
             patch.object(setup,'directory'),patch.object(setup,'json_write'),patch('manage.restore_internal') as restore,\
             patch('builtins.input',side_effect=['3','да']),self.assertRaises(KeyboardInterrupt):
            setup.main()
        restore.assert_called_once_with(self.folder/'copy.tar.gz')


if __name__=='__main__':unittest.main()
