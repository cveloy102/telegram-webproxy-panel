import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import awg_control
from awg_control import Controller
from backup_archive import build_tar,inspect_tar
import recovery_wizard


def fake_key():return base64.b64encode(secrets.token_bytes(32)).decode()
def fake_public(private):return base64.b64encode(hashlib.sha256(private.encode()).digest()).decode()


class AmneziaTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for target,value in [('awg_control.key',fake_key),('awg_control.public_key',fake_public),('migration_state.ROOT',self.root/'migration')]:
            p=patch(target,value);p.start();self.addCleanup(p.stop)
        p=patch('backup_notify.changed');p.start();self.addCleanup(p.stop)
        self.c=Controller(self.root/'awg',{'awg_domain':'vpn.example.com','awg_port':51820},test=True)
        self.c.call({'op':'create','name':'Друг','group':'Друзья'})
        self.uid=self.c.public()['users'][0]['id']

    def user(self):
        with self.c.db() as c:return dict(c.execute('SELECT * FROM users WHERE id=?',(self.uid,)).fetchone())

    def test_export_and_public_state_do_not_expose_keys(self):
        conf=self.c.call({'op':'key','id':self.uid})['conf']
        self.assertIn('Endpoint = vpn.example.com:51820',conf)
        self.assertIn('HeaderProtectionKey = ',conf)
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0',conf)
        self.assertIn('PrivateKey = '+self.user()['private'],conf)
        state=json.dumps(self.c.public())
        for k in ('private','public','psk'):self.assertNotIn(self.user()[k],state)
        with self.c.db() as c:
            settings=self.c.settings(c)
            self.assertNotIn(settings['HeaderProtectionKey'],state)
            self.assertNotIn(settings['private'],state)

    def test_toggle_rotate_and_delete_are_isolated(self):
        self.c.call({'op':'create','name':'Второй','group':'Семья'})
        before=self.c.call({'op':'key','id':self.uid})['conf']
        self.c.call({'op':'toggle','id':self.uid,'enabled':False})
        with self.c.db() as c:
            rendered=self.c.render(c)
            self.assertNotIn(self.user()['public'],rendered)
            self.assertEqual(rendered.count('[Peer]'),1)
        self.assertEqual(before,self.c.call({'op':'key','id':self.uid})['conf'])
        self.c.call({'op':'rotate','id':self.uid})
        self.assertNotEqual(before,self.c.call({'op':'key','id':self.uid})['conf'])
        with self.assertRaises(ValueError):self.c.call({'op':'delete','id':self.uid,'confirm_name':'wrong'})
        self.c.call({'op':'delete','id':self.uid,'confirm_name':'Друг'})
        self.assertEqual(len(self.c.public()['users']),1)

    def test_accounting_restart_removed_peer_and_limits(self):
        pub=self.user()['public'];now=1800000000
        self.c.ingest({pub:(10,100,now)},'one',now)
        self.c.ingest({pub:(20,200,now)},'one',now+5)
        restarted=Controller(self.root/'awg',test=True)
        restarted.ingest({pub:(25,250,now)},'one',now+10)
        restarted.ingest({pub:(5,50,now)},'two',now+15)
        self.assertEqual((self.user()['up'],self.user()['down']),(30,300))
        restarted.ingest({},'two',now+20)
        restarted.ingest({pub:(3,30,now)},'two',now+25)
        self.assertEqual((self.user()['up'],self.user()['down']),(33,330))
        self.c.call({'op':'limits','id':self.uid,'quota_gb':0,'expires':'2020-01-01','enforce':False})
        self.assertTrue(self.c.public()['users'][0]['allowed'])
        self.c.call({'op':'limits','id':self.uid,'quota_gb':0,'expires':'2020-01-01','enforce':True})
        self.assertFalse(self.c.public()['users'][0]['allowed'])
        with self.c.db() as c:self.assertNotIn('[Peer]',self.c.render(c))

    def test_repeated_resume_does_not_recount_traffic(self):
        pub=self.user()['public']
        self.c.ingest({pub:(50,100,0)},'one')
        self.c.call({'op':'global','paused':False})
        self.c.ingest({pub:(55,110,0)},'one')
        self.assertEqual((self.user()['up'],self.user()['down']),(55,110))
        conf=self.c.call({'op':'key','id':self.uid})['conf']
        self.c.call({'op':'global','paused':True})
        self.assertFalse(self.c.public()['users'][0]['allowed'])
        self.c.call({'op':'global','paused':False})
        self.assertEqual(conf,self.c.call({'op':'key','id':self.uid})['conf'])

    def test_invalid_limits_and_migration_gate(self):
        for quota in (float('nan'),float('inf'),True,-1):
            with self.assertRaises(ValueError):self.c.call({'op':'limits','id':self.uid,'quota_gb':quota,'enforce':True})
        (self.root/'migration').mkdir();(self.root/'migration/blocked').touch()
        with self.assertRaises(ValueError):self.c.call({'op':'toggle','id':self.uid,'enabled':False})

    def paths(self):
        paths={k:self.root/k for k in ('users','owner','hy2','usage','site','hy2cover')};paths['awg']=self.root/'awg'
        paths['owner'].mkdir(exist_ok=True)
        paths['users'].write_text(json.dumps({'host':'tg.example.com','users':[{'id':'default','secret':'a'*32,'enabled':True}]}))
        (paths['owner']/'auth.json').write_text('{}')
        with contextlib.closing(sqlite3.connect(paths['owner']/'panel.sqlite3')) as c:
            c.executescript('CREATE TABLE IF NOT EXISTS owner(salt,hash,totp,verified); CREATE TABLE IF NOT EXISTS recovery(hash); CREATE TABLE IF NOT EXISTS settings(id);')
        return paths

    def test_backup_restore_keeps_existing_configs_users_and_counters_on_new_ip(self):
        self.c.call({'op':'create','name':'Второй','group':'Семья'})
        self.c.ingest({self.user()['public']:(111,222,0)},'old-server')
        before={u['id']:self.c.call({'op':'key','id':u['id']})['conf'] for u in self.c.public()['users']}
        paths=self.paths();archive=self.root/'backup.tar.gz'
        with archive.open('wb') as output:manifest=build_tar(output,paths)
        files=self.root/'restored';inspected=inspect_tar(archive,files)
        options=recovery_wizard.options_from_manifest(inspected,'8.8.4.4')
        self.assertEqual(options['ip'],'8.8.4.4');self.assertEqual(options['awg_domain'],'vpn.example.com')
        self.assertIn('vpn.example.com',recovery_wizard.domains({'options':options}))
        new=self.root/'new-server';new.mkdir();shutil.copyfile(files/'amnezia/awg.sqlite3',new/'awg.sqlite3')
        restored=Controller(new,test=True)
        with restored.db() as c:c.execute('DELETE FROM samples')
        after={u['id']:restored.call({'op':'key','id':u['id']})['conf'] for u in restored.public()['users']}
        self.assertEqual(before,after)
        self.assertEqual(next(u for u in restored.public()['users'] if u['id']==self.uid)['up'],111)
        self.assertTrue(manifest['amnezia'])
        with restored.db() as c:self.assertEqual(restored.render(c).count('[Peer]'),2)

    def test_backup_fingerprint_ignores_counters_but_detects_keys_and_limits(self):
        from backup_control import Controller as Backup
        paths=self.paths();paths['hy2config']=self.root/'hy2config'
        control=Backup(self.root/'backup-control',paths)
        before=control.signature()
        self.c.ingest({self.user()['public']:(1,2,0)},'one')
        self.assertEqual(before,control.signature())
        self.c.call({'op':'limits','id':self.uid,'quota_gb':2,'enforce':True})
        self.assertNotEqual(before,control.signature())
        before=control.signature();self.c.call({'op':'rotate','id':self.uid})
        self.assertNotEqual(before,control.signature())

    def test_network_units_and_public_destination_isolation(self):
        from amnezia_install import units
        from awg_network import firewall
        for body in units().values():
            self.assertIn('ConditionPathExists=!/var/lib/relay-migration/blocked',body)
            self.assertIn('--can-start',body)
        self.assertIn('iifname "awg-relay" oifname "awg-relay" drop',firewall())
        self.assertIn('10.0.0.0/8',firewall())
        self.assertIn('masquerade',firewall())


if __name__=='__main__':unittest.main()
