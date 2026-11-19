"""СВАЛКА sync server: installer question, Caddy block, backup roundtrip and restore checks."""
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import installer as setup
import svalka_install
from backup_archive import build_tar,inspect_tar
from restore import validate_svalka,new_svalka_instance


class Installer(unittest.TestCase):
    def test_suggested_domain(self):
        self.assertEqual(svalka_install.suggested_domain('tg.example.com'),'sync.example.com')
        self.assertEqual(svalka_install.suggested_domain('example.com'),'sync.example.com')

    def ask(self,answers,options):
        with patch('builtins.input',side_effect=answers),patch.object(setup,'check_dns'),contextlib.redirect_stdout(io.StringIO()):
            svalka_install.ask_options(setup,options)
        return options

    def test_declined_by_default(self):
        options=self.ask([''],{'domain':'tg.example.com','ip':'1.1.1.1'})
        self.assertNotIn('svalka_domain',options)

    def test_accepts_suggested_and_rejects_taken_domain(self):
        options=self.ask(['да',''],{'domain':'tg.example.com','ip':'1.1.1.1'})
        self.assertEqual(options['svalka_domain'],'sync.example.com')
        options=self.ask(['да','vpn.example.com','sync.example.com'],{'domain':'tg.example.com','hy2_domain':'vpn.example.com','ip':'1.1.1.1'})
        self.assertEqual(options['svalka_domain'],'sync.example.com')

    def test_existing_choice_is_kept_without_questions(self):
        with patch('builtins.input',side_effect=AssertionError('asked')):
            options={'domain':'tg.example.com','svalka_domain':'sync.example.com'}
            svalka_install.ask_options(setup,options)
        self.assertEqual(options['svalka_domain'],'sync.example.com')

    def test_caddy_block_and_unit(self):
        block=svalka_install.caddy('sync.example.com')
        self.assertIn('sync.example.com {',block);self.assertIn('reverse_proxy 127.0.0.1:8090',block)
        self.assertNotIn('encode',block)
        unit=svalka_install.service()
        self.assertIn('SVALKA_ALLOW_SIGNUP=false',unit);self.assertIn('--http=127.0.0.1:8090',unit)
        self.assertIn('ReadWritePaths=/opt/svalka-sync/pb_data',unit)

    def test_vendored_server_files_present(self):
        self.assertTrue((ROOT/'svalka/pb_hooks/svalka.pb.js').exists())
        self.assertTrue(list((ROOT/'svalka/pb_migrations').glob('*_svalka_settings.js')))


def svalka_database(path,instance='old'):
    with contextlib.closing(sqlite3.connect(path)) as c,c:
        c.executescript('CREATE TABLE svalka_settings(key TEXT UNIQUE, value TEXT); CREATE TABLE tasks(id TEXT, text TEXT);')
        c.executemany('INSERT INTO svalka_settings VALUES(?,?)',[('signup','false'),('instance',instance)])
        c.execute("INSERT INTO tasks VALUES('t1','купить хлеб')")


class Backup(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        import migration_state
        migration=patch.object(migration_state,'ROOT',self.root/'migration');migration.start();self.addCleanup(migration.stop)
        env=patch.dict(os.environ,{'RELAY_BACKUP_TMP':str(self.root)});env.start();self.addCleanup(env.stop)
        domain=patch('backup_archive.svalka_domain',return_value='sync.example.com');domain.start();self.addCleanup(domain.stop)
        self.paths={k:self.root/k for k in ('users','owner','hy2','usage','site','hy2config','hy2cover','svalka')}
        for k in ('owner','site','svalka'):self.paths[k].mkdir()
        self.paths['users'].write_text(json.dumps({'host':'proxy.example.com','users':[{'id':'default','secret':'a'*32,'enabled':True}]}))
        (self.paths['owner']/'auth.json').write_text(json.dumps({'host':'proxy.example.com','session_key':'synthetic'}))
        with sqlite3.connect(self.paths['owner']/'panel.sqlite3') as c:
            c.executescript('CREATE TABLE owner(salt,hash,totp,verified); CREATE TABLE recovery(hash); CREATE TABLE settings(id,networks); INSERT INTO settings VALUES(1,3);')

    def build(self):
        target=self.root/'copy.tar.gz'
        with target.open('wb') as f:build_tar(f,self.paths)
        return target

    def test_roundtrip_keeps_records(self):
        svalka_database(self.paths['svalka']/'data.db')
        restored=self.root/'restored';manifest=inspect_tar(self.build(),restored)
        self.assertTrue(manifest['svalka']);self.assertEqual(manifest['svalka_domain'],'sync.example.com')
        with contextlib.closing(sqlite3.connect(restored/'svalka/data.db')) as c:
            self.assertEqual(c.execute('SELECT text FROM tasks').fetchone()[0],'купить хлеб')

    def test_without_svalka_nothing_is_added(self):
        manifest=inspect_tar(self.build(),self.root/'restored')
        self.assertFalse(manifest.get('svalka'))

    def test_manifest_flag_mismatch_rejected(self):
        svalka_database(self.paths['svalka']/'data.db')
        source=self.build();forged=self.root/'forged.tar.gz'
        with tarfile.open(source) as old,tarfile.open(forged,'w:gz') as new:
            for item in old.getmembers():
                body=old.extractfile(item).read()
                if item.name=='manifest.json':
                    manifest=json.loads(body);manifest['svalka']=False;body=json.dumps(manifest).encode()
                    item.size=len(body)
                new.addfile(item,io.BytesIO(body))
        with self.assertRaisesRegex(ValueError,'СВАЛКИ'):inspect_tar(forged,self.root/'restored')


class Wizard(unittest.TestCase):
    def test_https_checks_keep_old_calls_and_use_health_for_svalka(self):
        import recovery_wizard as wizard
        data={'options':{'domain':'tg.example.com','hy2_domain':'hy.example.com','svalka_domain':'sync.example.com'}}
        with patch.object(wizard,'check_https') as check:
            for domain in wizard.domains(data):wizard.check_domain(data,domain)
        self.assertEqual([c.args+tuple(sorted(c.kwargs.items())) for c in check.call_args_list],
            [('tg.example.com',('panel',True)),('hy.example.com',('panel',False)),('sync.example.com',('path','/api/health'))])
        manifest={'telegram_domain':'tg.example.com','hysteria':False,'svalka':True,'svalka_domain':'Sync.example.com'}
        self.assertEqual(wizard.options_from_manifest(manifest,'1.1.1.1')['svalka_domain'],'sync.example.com')
        with self.assertRaises(ValueError):wizard.options_from_manifest({**manifest,'svalka_domain':'tg.example.com'},'1.1.1.1')


class Restore(unittest.TestCase):
    def test_target_compatibility(self):
        archived={'svalka':True,'svalka_domain':'sync.example.com'}
        validate_svalka(archived,{'svalka_domain':'sync.example.com'})
        validate_svalka({},{'svalka_domain':'sync.example.com'})
        validate_svalka({},{})
        with self.assertRaises(ValueError):validate_svalka(archived,{})
        with self.assertRaises(ValueError):validate_svalka(archived,{'svalka_domain':'other.example.com'})

    def test_new_instance_after_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            database=Path(folder)/'data.db';svalka_database(database)
            new_svalka_instance(database)
            with contextlib.closing(sqlite3.connect(database)) as c:
                instance=c.execute("SELECT value FROM svalka_settings WHERE key='instance'").fetchone()[0]
            self.assertNotEqual(instance,'old');self.assertTrue(instance)
            empty=Path(folder)/'empty.db';sqlite3.connect(empty).close()
            new_svalka_instance(empty)


if __name__=='__main__':unittest.main()
