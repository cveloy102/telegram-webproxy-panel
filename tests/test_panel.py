import importlib.util
import json
import os
import pathlib
import tempfile
import time
import unittest
import hashlib
import re

BASE = pathlib.Path(__file__).resolve().parents[1] / "panel"
import sys
sys.path.insert(0,str(BASE))
temp = tempfile.TemporaryDirectory()
root = pathlib.Path(temp.name)
os.environ['RELAY_TEST'] = '1'
os.environ['RELAY_DATA'] = str(root)
os.environ['RELAY_USAGE'] = str(root / 'usage.json')
code = 'test-setup-token'
(root / 'auth.json').write_text(json.dumps({'host':'proxy.example.com','session_key':'test-session-secret',
    'setup_hash':hashlib.sha256(code.encode()).hexdigest(),'setup_expires':time.time()+3600}))
import app as panel
from helper import Controller, atomic

class PanelTests(unittest.TestCase):
    def test_amnezia_auth_csrf_export_and_unavailable_service(self):
        from unittest.mock import patch
        url='https://proxy.example.com'
        self.assertEqual(self.client.get('/control/api/awg/state',base_url=url).status_code,401)
        self.assertEqual(self.client.get('/control/amnezia',base_url=url).status_code,302)
        self.setup_owner()
        page=self.client.get('/control/amnezia',base_url=url)
        self.assertEqual(page.status_code,200)
        token=re.search(r'name="csrf" content="([^"]+)"',page.text).group(1)
        self.assertEqual(self.client.post('/control/api/awg/key',base_url=url,json={'id':'u_one'}).status_code,403)
        headers={'Origin':url,'X-CSRF-Token':token}
        with patch('awg_routes.helper',return_value={'conf':'[Interface]\nPrivateKey = synthetic\n','filename':'u_one.conf','enabled':True}):
            response=self.client.post('/control/api/awg/key',base_url=url,json={'id':'u_one'},headers=headers)
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json['filename'],'u_one.conf')
            self.assertTrue(response.json['qr'])
            self.assertEqual(response.headers['Cache-Control'],'no-store')
        with patch('awg_routes.helper',side_effect=OSError):
            self.assertEqual(self.client.get('/control/api/awg/state',base_url=url).status_code,503)
        with self.client.get('/control/static/amnezia.js',base_url=url) as asset:self.assertEqual(asset.status_code,200)

    def test_migration_auth_assets_and_frozen_writes(self):
        from unittest.mock import patch
        import migration_state
        self.assertEqual(self.client.get('/control/api/migration/state',base_url='https://proxy.example.com').status_code,401)
        self.setup_owner()
        response=self.client.get('/control/migration',base_url='https://proxy.example.com')
        self.assertEqual(response.status_code,200)
        self.assertIn('migration.js',response.text)
        with self.client.get('/control/static/migration.js',base_url='https://proxy.example.com') as asset:
            self.assertEqual(asset.status_code,200)
        with tempfile.TemporaryDirectory() as folder,patch.object(migration_state,'ROOT',pathlib.Path(folder)):
            pathlib.Path(folder,'blocked').touch()
            self.assertEqual(self.post('api/action',op='create').status_code,409)
            self.assertEqual(self.client.get('/control/migration',base_url='https://proxy.example.com').status_code,200)
            self.assertEqual(self.post('logout').status_code,302)

    def setUp(self):
        from unittest.mock import patch
        import migration_state
        migration = patch.object(migration_state, 'ROOT', root / 'migration')
        migration.start();self.addCleanup(migration.stop)
        self.client=panel.app.test_client()
        with panel.db() as conn:
            for table in ('owner','recovery','events','monitor','failures'):
                conn.execute('DELETE FROM '+table)
        self.client.get('/control/',base_url='https://proxy.example.com')
    def post(self,path,**data):
        page=self.client.get('/control/',base_url='https://proxy.example.com')
        token=re.search(r'(?:name="csrf" value|name="csrf" content)="([^"]+)"',page.text).group(1)
        return self.client.post('/control/'+path,base_url='https://proxy.example.com',
            headers={'Origin':'https://proxy.example.com'},data={'csrf':token,**data})
    def setup_owner(self):
        self.assertEqual(self.post('setup',code=code,password='a-long-test-password').status_code,302)
        seed=panel.owner()['totp']
        self.assertEqual(self.post('enroll',otp=panel.otp(seed,int(time.time())//30)).status_code,200)
    def test_auth_and_replay(self):
        self.assertEqual(self.client.get('/control/',base_url='https://proxy.example.com').headers['Referrer-Policy'],'same-origin')
        self.assertEqual(self.client.get('/control/api/state',base_url='https://proxy.example.com').status_code,401)
        self.assertEqual(self.client.post('/control/setup',base_url='https://proxy.example.com').status_code,403)
        self.assertEqual(self.post('setup',code='wrong',password='a-long-test-password').status_code,400)
        self.setup_owner()
        self.assertEqual(self.post('setup',code=code,password='other-password').status_code,403)
        seed=panel.owner()['totp']
        self.post('logout')
        self.client.get('/control/',base_url='https://proxy.example.com')
        self.assertEqual(self.post('login',password='a-long-test-password',otp=panel.otp(seed,int(time.time())//30)).status_code,400)
        with panel.db() as conn:
            conn.execute('INSERT INTO recovery VALUES(?)',(panel.recovery_hash('RECOVERYCODE'),))
        self.assertEqual(self.post('login',password='a-long-test-password',otp='RECOVERYCODE').status_code,302)
        self.post('logout');self.client.get('/control/',base_url='https://proxy.example.com')
        self.assertEqual(self.post('login',password='a-long-test-password',otp='RECOVERYCODE').status_code,400)
    def test_controller_rollback_and_pause(self):
        folder=root/'controller';folder.mkdir(exist_ok=True)
        original={'host':'proxy.example.com','paused':False,'users':[{'id':'default','name':'RELAY','group':'Личное','secret':'a'*32,'enabled':True,'created':1}],'events':[]}
        atomic(folder/'users.json',original)
        control=Controller(folder,apply=lambda state:None)
        self.assertNotIn('secret',control.call({'op':'status'})['users'][0])
        control.call({'op':'toggle','id':'default','enabled':False})
        control.call({'op':'toggle','id':'default','enabled':True})
        self.assertEqual(control.call({'op':'key','id':'default'})['secret'],'a'*32)
        control.call({'op':'create','name':'Друг','group':'Друзья'})
        new=control.read()['users'][1]
        self.assertNotEqual(new['secret'],'a'*32)
        control.call({'op':'rotate','id':new['id']})
        self.assertNotEqual(control.read()['users'][1]['secret'],new['secret'])
        before=control.read()
        def fail(state):raise RuntimeError('failure')
        control.apply_override=fail
        with self.assertRaises(RuntimeError):control.call({'op':'global','paused':True})
        self.assertEqual(control.read(),before)
        with self.assertRaises(RuntimeError): control.call({'op':'delete','id':new['id'],'confirm_name':'Друг'})
        self.assertEqual(control.read(),before)
        control.apply_override=lambda state:None
        with self.assertRaises(ValueError): control.call({'op':'delete','id':new['id'],'confirm_name':'wrong'})
        control.call({'op':'delete','id':new['id'],'confirm_name':'Друг'})
        self.assertEqual([u['id'] for u in control.read()['users']],['default'])
        with self.assertRaises(ValueError): control.call({'op':'key','id':new['id']})
        control.call({'op':'delete','id':'default','confirm_name':'RELAY'})
        self.assertEqual(control.read()['users'],[])
    def test_monitor_does_not_sanction(self):
        self.setup_owner()
        users={'users':[{'id':'default','name':'RELAY','group':'Личное','enabled':True,'suffix':'aaaa'}],'paused':False,'events':[]}
        calls=[]
        panel.helper=lambda payload:(calls.append(payload) or users)
        now=int(time.time());hour=panel.dt.datetime.now(panel.dt.timezone.utc).strftime('%Y-%m-%dT%H')
        rows={}
        for ip in ['192.0.2.1','198.51.100.2','203.0.113.3']:
            rows[ip]={'profile':'default','ip':ip,'first':now,'connected':now,'last':now,'connections':1,'up':1024**3,'down':0,'live':1,'days':{},'hours':{hour:{'up':1024**3,'down':0}}}
        (root/'usage.json').write_text(json.dumps({'started':now,'updated':now,'rows':rows}))
        panel.monitor_once()
        with panel.db() as conn:conn.execute("UPDATE monitor SET since=? WHERE kind='networks'",(now-301,))
        panel.monitor_once();panel.monitor_once()
        result=panel.state_data()
        self.assertEqual(len(result['alerts']),2)
        self.assertEqual(len(result['users'][0]['groups']),3)
        self.assertTrue(result['users'][0]['enabled'])
        self.assertTrue(all(c=={'op':'status'} for c in calls))
        self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(self.client.get('/control/api/state',base_url='https://proxy.example.com').status_code,200)

if __name__=='__main__':unittest.main()
