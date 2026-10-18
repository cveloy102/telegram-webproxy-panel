import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'panel'))
from backup_archive import build_tar,inspect_tar,encrypt,decrypt
from backup_control import Controller,folder_id

class Backups(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        import migration_state
        migration=patch.object(migration_state,'ROOT',self.root/'migration')
        migration.start();self.addCleanup(migration.stop)
        env=patch.dict(os.environ,{'RELAY_BACKUP_TMP':str(self.root)});env.start();self.addCleanup(env.stop)
        self.paths={k:self.root/k for k in ('users','owner','hy2','usage','site','hy2config','hy2cover')}
        for k in ('owner','hy2','site','hy2cover'):self.paths[k].mkdir()
        self.paths['users'].write_text(json.dumps({'host':'proxy.example.com','users':[{'id':'default','secret':'a'*32,'enabled':True}]}))
        (self.paths['owner']/'auth.json').write_text(json.dumps({'host':'proxy.example.com','session_key':'synthetic'}))
        self.paths['site'].joinpath('index.html').write_text('test page')
        with sqlite3.connect(self.paths['owner']/'panel.sqlite3') as c:
            c.executescript('CREATE TABLE owner(salt,hash,totp,verified); CREATE TABLE recovery(hash); CREATE TABLE settings(id,networks); INSERT INTO settings VALUES(1,3);')
        with sqlite3.connect(self.paths['hy2']/'hy2.sqlite3') as c:
            c.executescript('CREATE TABLE users(id,name,grp,secret,enabled,quota,expires,enforce,up,down,last); CREATE TABLE settings(k,v);')
            c.executemany('INSERT INTO settings VALUES(?,?)',[('host',json.dumps('hy2.example.com')),('port','24443'),('epoch','"test"')])
            c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?,?)',('friend','Friend','Friends','synthetic',1,0,0,0,1,2,0))
    def test_portable_roundtrip_both_databases(self):
        target=self.root/'copy.tar.gz'
        with target.open('wb') as f:build_tar(f,self.paths)
        restored=self.root/'restored';manifest=inspect_tar(target,restored)
        self.assertTrue(manifest['hysteria']);self.assertEqual(manifest['hysteria_domain'],'hy2.example.com')
        self.assertEqual(json.loads((restored/'telegram/users.json').read_text())['users'][0]['secret'],'a'*32)
        with sqlite3.connect(restored/'hysteria/hy2.sqlite3') as c:self.assertEqual(c.execute('SELECT secret FROM users').fetchone()[0],'synthetic')
    def test_traversal_and_links_rejected(self):
        for name,kind in [('../escape',tarfile.REGTYPE),('site/link',tarfile.SYMTYPE),('/absolute',tarfile.REGTYPE)]:
            target=self.root/'bad.tar.gz'
            with tarfile.open(target,'w:gz') as f:
                item=tarfile.TarInfo(name);item.type=kind;item.linkname='/etc/passwd';f.addfile(item)
            with self.assertRaises(ValueError):inspect_tar(target,self.root/'bad')
        self.assertFalse((self.root/'escape').exists())

    def test_malformed_manifest_and_missing_protocol_data_are_rejected(self):
        target=self.root/'original.tar.gz'
        with target.open('wb') as output:build_tar(output,self.paths)
        with tarfile.open(target) as source:payload={m.name:source.extractfile(m).read() for m in source}
        original=json.loads(payload['manifest.json'])
        malformed=[[],{**original,'hysteria':False},{**original,'hysteria':'yes'},
                   {**original,'files':{**original['files'],'telegram/users.json':'bad'}}]
        for index,manifest in enumerate(malformed):
            broken=self.root/f'malformed-{index}.tar.gz'
            with tarfile.open(broken,'w:gz') as archive:
                for name,body in payload.items():
                    if name=='manifest.json':body=json.dumps(manifest).encode()
                    item=tarfile.TarInfo(name);item.size=len(body);archive.addfile(item,io.BytesIO(body))
            with self.subTest(index=index),self.assertRaises(ValueError):inspect_tar(broken,self.root/f'extracted-{index}')
    def test_signature_ignores_traffic_but_detects_secret_and_delete(self):
        control=Controller(self.root/'backup',self.paths);a=control.signature()
        with sqlite3.connect(self.paths['hy2']/'hy2.sqlite3') as c:c.execute('UPDATE users SET up=42,down=50,last=99')
        self.assertEqual(a,control.signature())
        with sqlite3.connect(self.paths['hy2']/'hy2.sqlite3') as c:c.execute('UPDATE users SET secret=?',('rotated',))
        b=control.signature();self.assertNotEqual(a,b)
        with sqlite3.connect(self.paths['hy2']/'hy2.sqlite3') as c:c.execute('DELETE FROM users')
        self.assertNotEqual(b,control.signature())
    def test_failed_upload_retains_pending_generation(self):
        control=Controller(self.root/'backup',self.paths);control.dirty()
        with patch('backup_control.encrypt',side_effect=ValueError('unavailable')):control.snapshot()
        self.assertTrue(control.status()['pending']);self.assertEqual(control.status()['uploaded'],0)
        self.assertEqual(control.status()['error'],'unavailable')
    def test_folder_validation(self):
        self.assertEqual(folder_id('https://drive.google.com/drive/folders/synthetic_folder_123?hl=ru'),'synthetic_folder_123')
        for value in ('https://evil.example/folders/id','../../etc/passwd','bad;touch /tmp/a'):
            with self.assertRaises(ValueError):folder_id(value)
    def test_site_redirects_survive_snapshot_and_merge_without_duplicates(self):
        self.paths['caddy']=self.root/'Caddyfile'
        self.paths['caddy'].write_text('example.com {\n redir https://proxy.example.com{uri} 302\n}\n')
        target=self.root/'redirects.tar.gz'
        with target.open('wb') as f:manifest=build_tar(f,self.paths)
        self.assertEqual(manifest['redirects'],[{'host':'example.com','code':'302'}])
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        from restore import merge_redirects
        config='proxy.example.com {\n reverse_proxy 127.0.0.1:8080\n}\n'
        once=merge_redirects(config,manifest['redirects'],'proxy.example.com')
        self.assertEqual(once,merge_redirects(once,manifest['redirects'],'proxy.example.com'))
        with self.assertRaises(ValueError):merge_redirects(config,[{'host':'bad.example\nexec evil','code':'302'}],'proxy.example.com')
    def test_upload_hash_case_and_concurrent_change(self):
        import hashlib
        for label in ('md5','MD5'):
            control=Controller(self.root/label,self.paths);control.dirty()
            def snapshot(path,*args):
                path.write_bytes(b'encrypted');control.dirty();return {'created':1}
            remote={'Size':9,'Hashes':{label:hashlib.md5(b'encrypted').hexdigest()}}
            with patch('backup_control.encrypt',side_effect=snapshot),patch.object(control,'rclone',side_effect=[b'',json.dumps(remote).encode()]):control.snapshot()
            self.assertGreater(control.status()['uploaded'],0);self.assertTrue(control.status()['pending'])
    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'),'age needs Linux test dependencies')
    def test_encrypted_roundtrip_wrong_key_and_no_plaintext(self):
        key=self.root/'key.txt';subprocess.run(['age-keygen','-o',str(key)],check=True,capture_output=True)
        recipient=subprocess.check_output(['age-keygen','-y',str(key)],text=True).strip()
        cipher=self.root/'backup.age';encrypt(cipher,recipient,self.paths)
        self.assertNotIn(b'synthetic',cipher.read_bytes());result=decrypt(cipher,key.read_text(),self.root/'plain')
        self.assertTrue(result['hysteria']);self.assertFalse((self.root/'plain/identity.txt').exists())
        with self.assertRaises(ValueError):decrypt(cipher,'AGE-SECRET-KEY-INVALID',self.root/'wrong')

if __name__=='__main__':unittest.main()
