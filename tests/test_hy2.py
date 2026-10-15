import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml
from hy2_control import Controller, TZ

class HysteriaTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name)
        config=self.base/'config.yaml';config.write_text(yaml.safe_dump({'listen':'0.0.0.0:24443','acme':{'domains':['hy2.example.com']},'auth':{'password':'original-secret'}}))
        self.c=Controller(self.base/'data',config,test=True)
    def tearDown(self): self.temp.cleanup()
    def test_preserve_key_and_hide_credentials(self):
        self.assertEqual(self.c.authenticate('original-secret'),{'ok':True,'id':'default'})
        state=json.dumps(self.c.public())
        self.assertNotIn('original-secret',state);self.assertNotIn('api_secret',state);self.assertNotIn('auth_token',state)
        self.assertIn('original-secret@',self.c.call({'op':'key','id':'default'})['uri'])
    def test_accounting_persistence_and_restart(self):
        now=int(dt.datetime(2026,10,9,22,0,tzinfo=TZ).timestamp())
        self.c.ingest({'default':{'tx':10,'rx':100}},{'default':1},'one',now)
        self.c.ingest({'default':{'tx':20,'rx':200}},{'default':1},'one',now+5)
        restored=Controller(self.base/'data',self.base/'config.yaml',test=True)
        restored.ingest({'default':{'tx':25,'rx':250}},{},'one',now+10)
        restored.ingest({'default':{'tx':5,'rx':50}},{},'two',now+15)
        u=restored.public()['users'][0]
        self.assertEqual((u['up'],u['down']),(30,300))
        self.assertEqual(u['history'][0]['day'],'2026-10-09')
    def test_isolated_toggle_and_rotation(self):
        self.c.call({'op':'create','name':'Друг','group':'Друзья'})
        user=next(u for u in self.c.public()['users'] if u['id']!='default')
        self.c.call({'op':'toggle','id':user['id'],'enabled':False})
        self.assertTrue(self.c.authenticate('original-secret')['ok'])
        self.c.call({'op':'rotate','id':'default'})
        self.assertFalse(self.c.authenticate('original-secret')['ok'])
    def test_warning_vs_enforcement(self):
        expired='2020-01-01'
        self.c.call({'op':'limits','id':'default','quota_gb':0,'expires':expired,'enforce':False})
        self.assertTrue(self.c.authenticate('original-secret')['ok'])
        self.c.call({'op':'limits','id':'default','quota_gb':0,'expires':expired,'enforce':True})
        self.assertFalse(self.c.authenticate('original-secret')['ok'])
        self.c.call({'op':'limits','id':'default','quota_gb':0,'expires':'','enforce':False})
        self.assertTrue(self.c.authenticate('original-secret')['ok'])
    def test_global_pause_preserves_keys(self):
        self.c.call({'op':'global','paused':True});self.assertFalse(self.c.authenticate('original-secret')['ok'])
        self.c.call({'op':'global','paused':False});self.assertTrue(self.c.authenticate('original-secret')['ok'])
    def test_delete_requires_name_revokes_only_selected_and_handles_last(self):
        self.c.call({'op':'create','name':'Друг','group':'Друзья'})
        uid=next(u['id'] for u in self.c.public()['users'] if u['id']!='default')
        with self.assertRaises(ValueError): self.c.call({'op':'delete','id':'default','confirm_name':'wrong'})
        self.assertTrue(self.c.authenticate('original-secret')['ok'])
        self.c.ingest({'default':{'tx':10,'rx':100}},{'default':1},'one')
        self.c.call({'op':'delete','id':'default','confirm_name':'Мой ключ'})
        self.assertFalse(self.c.authenticate('original-secret')['ok'])
        self.assertEqual([u['id'] for u in self.c.public()['users']],[uid])
        with self.assertRaises(ValueError): self.c.call({'op':'key','id':'default'})
        calls=[]
        def fake_api(path,payload=None):
            calls.append((path,payload))
            return {'default':1,uid:1} if path=='online' else {} if path=='traffic' else None
        with patch.object(self.c,'stats_api',side_effect=fake_api): self.c.collect()
        self.assertIn(('kick',['default']),calls)
        with self.c.db() as c:
            self.assertIsNotNone(c.execute('SELECT * FROM revoked WHERE id=?',('default',)).fetchone())
            self.assertEqual(c.execute('SELECT count(*) FROM days WHERE id=?',('default',)).fetchone()[0],0)
        self.c.call({'op':'delete','id':uid,'confirm_name':'Друг'})
        self.assertEqual(self.c.public()['users'],[])
        # Restarting an empty panel must not resurrect the original password.
        restored=Controller(self.base/'data',self.base/'config.yaml',test=True)
        self.assertEqual(restored.public()['users'],[])
    def test_failed_settings_do_not_commit(self):
        before=self.c.public()['settings']
        with patch.object(self.c,'apply_settings',side_effect=ValueError('rollback')):
            with self.assertRaises(ValueError): self.c.call({'op':'settings','port':24444,'cover':'page','cover_url':'','obfs':True})
        self.assertEqual(before,self.c.public()['settings'])
    def test_input_validation(self):
        with self.assertRaises(ValueError): self.c.call({'op':'toggle','id':'default','enabled':'false'})
        with self.assertRaises(ValueError): self.c.call({'op':'limits','id':'default','quota_gb':float('nan'),'expires':'','enforce':False})
        with self.assertRaises(ValueError): self.c.call({'op':'settings','port':22,'cover':'page','obfs':False})
        with self.assertRaises(ValueError): Controller.validate_url('https://127.0.0.1/')
        with self.assertRaises(ValueError): Controller.validate_url('https://example.com:8082/')
    def test_obfs_uri(self):
        self.c.call({'op':'settings','port':24444,'cover':'page','cover_url':'','obfs':True})
        uri=self.c.call({'op':'key','id':'default'})['uri']
        self.assertIn(':24444/',uri);self.assertIn('obfs=salamander&obfs-password=',uri)

if __name__=='__main__': unittest.main()
