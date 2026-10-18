import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import recovery_wizard as wizard


class RecoveryWizardTests(unittest.TestCase):
    def test_file_selection_by_number_never_defaults_between_multiple_archives(self):
        import installer
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in ('a.tar.gz.age','b.tar.gz.age'):(root/name).write_bytes(b'encrypted')
            with patch('builtins.input',side_effect=['9','2']),contextlib.redirect_stdout(io.StringIO()) as output:
                selected=wizard.choose_file(installer,'Архив',('*.tar.gz.age',),1024,folder=root)
            self.assertEqual(selected,root/'b.tar.gz.age')
            self.assertIn('Нет такого номера',output.getvalue())

    def test_single_key_accepts_enter_and_supports_hidden_extension(self):
        import installer
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in ('relay-recovery-key','relay-recovery-key.txt'):
                key=root/name;key.write_text('private-test-content')
                with patch('builtins.input',return_value=''),contextlib.redirect_stdout(io.StringIO()) as output:
                    selected=wizard.choose_file(installer,'Ключ',('relay-recovery-key','relay-recovery-key.txt'),16384,folder=root)
                self.assertEqual(selected,key)
                self.assertNotIn('private-test-content',output.getvalue())
                key.unlink()

    def test_manual_path_can_be_uploaded_while_prompt_is_open(self):
        import installer
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);archive=root/'uploaded archive.tar.gz.age'
            def upload(prompt):
                archive.write_bytes(b'encrypted')
                return '"'+str(archive)+'"'
            with patch('builtins.input',side_effect=upload),contextlib.redirect_stdout(io.StringIO()):
                selected=wizard.choose_file(installer,'Архив',('*.tar.gz.age',),1024,folder=root)
            self.assertEqual(selected,archive)

    def test_invalid_file_retries_instead_of_aborting_recovery(self):
        import installer
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);empty=root/'empty';empty.touch()
            large=root/'large';large.write_bytes(b'too large')
            good=root/'good';good.write_bytes(b'ok')
            answers=[str(root/'missing'),str(empty),str(large),str(good)]
            with patch('builtins.input',side_effect=answers),contextlib.redirect_stdout(io.StringIO()):
                selected=wizard.choose_file(installer,'Файл',('*.age',),3,folder=root)
            self.assertEqual(selected,good)

    def test_manifest_supplies_domains_and_original_port(self):
        manifest={'telegram_domain':'TG.example.com','hysteria':True,'hysteria_domain':'hy2.example.com','hysteria_port':24443,'redirects':[{'host':'example.com','code':'302'}]}
        options=wizard.options_from_manifest(manifest,'1.1.1.1')
        self.assertEqual(options['domain'],'tg.example.com')
        self.assertEqual(options['hy2_port'],24443)
        for key,value in [('hysteria_domain','tg.example.com'),('hysteria_port',True),('hysteria_port',70000),('telegram_domain','bad.example\n{}')]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                wizard.options_from_manifest({**manifest,key:value},'1.1.1.1')
        with self.assertRaises(ValueError):wizard.options_from_manifest(manifest,'127.0.0.1')

    def test_wait_check_retries_until_valid_and_interrupts_without_success(self):
        check=Mock(side_effect=[RuntimeError('old IP'),OSError('not ready'),None])
        sleep=Mock()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            wizard.wait_check('DNS',check,sleep=sleep)
        self.assertEqual(check.call_count,3)
        self.assertEqual(sleep.call_count,2)
        self.assertIn('✓ DNS',output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as output,self.assertRaises(KeyboardInterrupt):
            wizard.wait_check('DNS',Mock(side_effect=RuntimeError('old IP')),sleep=Mock(side_effect=KeyboardInterrupt))
        self.assertNotIn('✓ DNS',output.getvalue())

    def test_checkpoint_pending_and_tampered_schema(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            self.assertFalse(wizard.pending(root))
            wizard.save({'schema':1,'imported':True},root)
            self.assertTrue(wizard.pending(root))
            self.assertTrue(wizard.read_state(root)['imported'])
            wizard.save({'schema':1,'complete':True},root)
            self.assertFalse(wizard.pending(root))
            wizard.save({'schema':42},root)
            with self.assertRaises(RuntimeError):wizard.read_state(root)

    def test_https_never_disables_certificate_validation(self):
        response=Mock(status=200)
        context=Mock();context.__enter__=Mock(return_value=response);context.__exit__=Mock(return_value=False)
        with patch.object(wizard.urllib.request,'build_opener') as build:
            fetch=build.return_value.open;fetch.return_value=context
            wizard.check_https('tg.example.com',panel=True)
        fetch.assert_called_once_with('https://tg.example.com/control/',timeout=8)
        handler=build.call_args.args[0]
        self.assertIsInstance(handler,wizard.urllib.request.HTTPRedirectHandler)
        self.assertIsNone(handler.redirect_request(None,None,302,'Found',{},'https://tg.example.com/'))

    def test_standby_redirect_is_ready_without_requesting_its_proxy_destination(self):
        for code in (301,302,303,307,308):
            with self.subTest(code=code),patch.object(wizard.urllib.request,'build_opener') as build:
                build.return_value.open.side_effect=wizard.urllib.error.HTTPError('https://example.com/',code,'redirect',{'Location':'https://tg.example.com/'},None)
                wizard.check_https('example.com')
                build.return_value.open.assert_called_once_with('https://example.com/',timeout=8)

    def test_panel_redirect_and_service_failure_remain_errors(self):
        for panel,code in ((True,302),(True,503),(False,503),(False,404)):
            with self.subTest(panel=panel,code=code),patch.object(wizard.urllib.request,'build_opener') as build:
                build.return_value.open.side_effect=wizard.urllib.error.HTTPError('https://example.com/',code,'error',{},None)
                with self.assertRaises(RuntimeError):wizard.check_https('example.com',panel=panel)

    def test_refusing_old_server_confirmation_does_not_start_services(self):
        setup=Mock();setup.ask.return_value='нет'
        with patch.object(wizard,'backup_api',return_value={'phase':'standby','busy':False}) as api,contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(wizard.enable_services({'options':{'domain':'tg.example.com'}},setup))
        api.assert_called_once_with({'op':'migration_status'})

    def test_dns_is_checked_again_after_confirmation(self):
        setup=Mock();setup.ask.return_value='да';setup.check_dns.side_effect=RuntimeError('DNS changed')
        with patch.object(wizard,'backup_api',return_value={'phase':'standby','busy':False}) as api,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(RuntimeError):
            wizard.enable_services({'options':{'domain':'tg.example.com','ip':'1.1.1.1'}},setup)
        api.assert_called_once_with({'op':'migration_status'})

    @unittest.skipUnless(os.name=='posix','Unix installer entry point')
    def test_resume_imported_data_rechecks_dns_without_key_or_reimport(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);archive=root/'archive.tar.gz.age';archive.write_bytes(b'encrypted fixture')
            state={'schema':1,'session':'fixture','sha256':wizard.digest(archive),'installed':True,'imported':True,'dns':True,'https':True,'options':{'domain':'tg.example.com','ip':'1.1.1.1'}}
            wizard.save(state,root)
            setup=Mock();setup.STATE=root/'install.json'
            setup.open_install_lock.side_effect=lambda:open(root/'install.lock','a')
            setup.STATE.write_text(json.dumps({'recovery_session':'fixture'}))
            setup.check_dns.side_effect=KeyboardInterrupt
            with patch.object(os,'geteuid',return_value=0),patch.object(wizard,'identity_file') as key,patch.object(wizard,'inspect_archive') as inspect,patch.object(wizard,'prepare') as prepare,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(KeyboardInterrupt):
                wizard.run_wizard(Path(__file__).resolve().parents[1],'test',setup=setup,root=root)
            key.assert_not_called();inspect.assert_not_called();prepare.assert_not_called()
            saved=wizard.read_state(root)
            self.assertTrue(saved['imported']);self.assertFalse(saved['dns']);self.assertFalse(saved['https'])

    @unittest.skipUnless(os.name=='posix','Unix installer entry point')
    def test_resume_rejects_changed_archive_and_other_installation(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'archive.tar.gz.age').write_bytes(b'changed')
            wizard.save({'schema':1,'session':'fixture','sha256':'wrong'},root)
            setup=Mock();setup.STATE=root/'install.json'
            setup.open_install_lock.side_effect=lambda:open(root/'install.lock','a')
            setup.STATE.write_text(json.dumps({'recovery_session':'fixture'}))
            with patch.object(os,'geteuid',return_value=0),contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(RuntimeError,'изменился'):
                wizard.run_wizard(root,'test',setup=setup,root=root)
            setup.STATE.write_text(json.dumps({'domain':'another.example.com'}))
            with patch.object(os,'geteuid',return_value=0),self.assertRaisesRegex(RuntimeError,'другая установка'):
                wizard.run_wizard(root,'test',setup=setup,root=root)

    def test_standby_activation_never_starts_traffic_units(self):
        import installer
        import hysteria_install
        with patch.object(installer,'run') as run,patch.object(installer,'STATE') as state,patch.object(hysteria_install,'activate') as hy2:
            state.read_text.return_value='{}'
            installer.activate(standby=True)
        invocations=[call.args for call in run.call_args_list]
        for call in invocations:
            if call[:2] in (('systemctl','restart'),('systemctl','start')):
                self.assertFalse(set(call[2:]) & {'mtproxy','tproxy-server','relay-refresh.timer','hysteria-server','relay-hy2'})
        self.assertTrue(hy2.call_args.kwargs['standby'])


if __name__=='__main__':unittest.main()
