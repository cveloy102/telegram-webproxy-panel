import base64
import copy
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'panel'))
import awg_control
import awg_routing as routing


class RoutingTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        for target,value in (
                ('awg_control.key',lambda:base64.b64encode(secrets.token_bytes(32)).decode()),
                ('awg_control.public_key',lambda x:base64.b64encode(hashlib.sha256(x.encode()).digest()).decode()),
                ('migration_state.ROOT',self.root/'migration')):
            p=patch(target,value);p.start();self.addCleanup(p.stop)
        p=patch('backup_notify.changed');self.notify=p.start();self.addCleanup(p.stop)
        self.c=awg_control.Controller(self.root/'awg',{'awg_domain':'vpn.example.com','awg_port':51820},test=True)
        self.c.call({'op':'create','name':'First','group':'Семья'})
        self.uid=self.c.public()['users'][0]['id']
        with self.c.db() as c:c.execute('DELETE FROM routing_pending')

    def test_new_default_and_legacy_migration_preserve_configuration(self):
        self.assertEqual(self.c.public()['users'][0]['routing'],'ru_split')
        before=self.c.call({'op':'key','id':self.uid})['conf']
        with self.c.db() as c:c.execute('ALTER TABLE users DROP COLUMN routing')
        restored=awg_control.Controller(self.root/'awg',test=True)
        self.assertEqual(restored.public()['users'][0]['routing'],'cascade')
        self.assertEqual(before,restored.call({'op':'key','id':self.uid})['conf'])
        restored.call({'op':'create','name':'New','group':'Личное'})
        users={u['name']:u for u in restored.public()['users']}
        self.assertEqual(users['New']['routing'],'ru_split')
        users={u['id']:u for u in awg_control.Controller(self.root/'awg',test=True).public()['users']}
        self.assertEqual(users[self.uid]['routing'],'cascade')

    def test_switch_is_isolated_and_never_changes_keys_or_counters(self):
        self.c.call({'op':'create','name':'Second','group':'Друзья','routing':'cascade'})
        before={u['id']:self.c.call({'op':'key','id':u['id']})['conf'] for u in self.c.public()['users']}
        with self.c.db() as c:c.execute('UPDATE users SET up=123,down=456 WHERE id=?',(self.uid,))
        self.c.call({'op':'routing','id':self.uid,'routing':'cascade'})
        state={u['id']:u for u in self.c.public()['users']}
        self.assertTrue(all(u['routing']=='cascade' for u in state.values()))
        self.assertEqual((state[self.uid]['up'],state[self.uid]['down']),(123,456))
        self.assertTrue(state[self.uid]['routing_pending'])
        for uid,conf in before.items():self.assertEqual(conf,self.c.call({'op':'key','id':uid})['conf'])
        self.notify.assert_called_with('awg')

    def test_invalid_modes_do_not_change_profile(self):
        for mode in ('direct','domain',None,True,{},'ru_split\nflush ruleset'):
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                self.c.call({'op':'routing','id':self.uid,'routing':mode})
        self.assertEqual(self.c.public()['users'][0]['routing'],'ru_split')

    def test_reset_failure_keeps_only_target_blocked_and_retries_after_restart(self):
        self.c.call({'op':'routing','id':self.uid,'routing':'cascade'})
        runtime=Mock()
        with patch.object(self.c,'routing_runtime',runtime),patch.object(routing,'clear_connections',side_effect=OSError):
            with self.c.db() as c:
                with self.assertRaises(OSError):self.c.apply_routing(c)
        self.assertEqual(runtime.install.call_args.args[2],['10.77.0.2'])
        restarted=awg_control.Controller(self.root/'awg',test=True)
        with patch.object(restarted,'routing_runtime',runtime),patch.object(routing,'clear_connections') as clear:
            with restarted.db() as c:restarted.apply_routing(c)
        clear.assert_called_once_with('10.77.0.2')
        self.assertEqual(runtime.install.call_args.args[2],[])
        self.assertFalse(restarted.public()['users'][0]['routing_pending'])

    def test_corrupt_database_blocks_split_and_does_not_reseed(self):
        with self.c.db() as c:routing.put(c,'routing_geo',{'schema':1})
        restarted=awg_control.Controller(self.root/'awg',test=True)
        runtime=Mock()
        with patch.object(restarted,'routing_runtime',runtime):
            with restarted.db() as c:restarted.apply_routing(c)
        self.assertEqual(runtime.install.call_args.args,(['10.77.0.2'],[],[]))
        self.assertFalse(restarted.public()['routing']['ready'])
        self.assertIn('ip saddr @split_peers drop',routing.firewall(['10.77.0.2'],[]))

    def test_update_failure_keeps_last_good_and_reports_error(self):
        with self.c.db() as c:before=routing.load(c)
        with patch.object(routing,'fetch',side_effect=OSError),self.assertRaises(ValueError):self.c.geo_update()
        with self.c.db() as c:self.assertEqual(before,routing.load(c))
        self.assertTrue(self.c.public()['routing']['error'])

    def test_update_and_rollback_preserve_profiles_and_previous_data(self):
        with self.c.db() as c:before=routing.load(c)
        new=routing.snapshot('\n'.join(before['networks'])+'\n9.9.9.0/24',before['fetched']+1)
        conf=self.c.call({'op':'key','id':self.uid})['conf']
        with patch.object(routing,'fetch',return_value=new):self.c.geo_update()
        with self.c.db() as c:
            self.assertEqual(routing.load(c),new)
            self.assertEqual(routing.load(c,'routing_previous'),before)
        self.c.call({'op':'geo_rollback'})
        with self.c.db() as c:self.assertEqual(routing.load(c),before)
        self.assertEqual(conf,self.c.call({'op':'key','id':self.uid})['conf'])
        self.assertTrue(self.c.public()['users'][0]['routing_pending'])
        self.assertTrue(self.c.public()['routing']['auto_paused'])
        self.assertTrue(awg_control.Controller(self.root/'awg',test=True).public()['routing']['auto_paused'])
        with patch.object(routing,'fetch',return_value=before):self.c.geo_update()
        self.assertFalse(self.c.public()['routing']['auto_paused'])

    def test_same_update_does_not_reset_sessions_or_destroy_rollback(self):
        with self.c.db() as c:before=routing.load(c)
        with patch.object(routing,'fetch',return_value=before):self.c.geo_update()
        self.assertFalse(self.c.public()['users'][0]['routing_pending'])
        self.assertFalse(self.c.public()['routing']['can_rollback'])

    def test_suspicious_update_is_rejected_before_runtime_change(self):
        with self.c.db() as c:before=routing.load(c)
        new=routing.snapshot('\n'.join(before['networks'][::2]))
        with patch.object(routing,'fetch',return_value=new),self.assertRaises(ValueError):self.c.geo_update()
        with self.c.db() as c:self.assertEqual(before,routing.load(c))
        self.assertTrue(self.c.public()['routing']['error'])

    def test_seed_rejects_private_default_and_tampered_data(self):
        valid='\n'.join(routing.seed()['networks'])
        for addition in ('0.0.0.0/0','10.0.0.0/8','127.0.0.1/32','203.0.113.0/24','not-a-network'):
            with self.subTest(addition=addition),self.assertRaises(ValueError):routing.snapshot(valid+'\n'+addition)
        bad=copy.deepcopy(routing.seed());bad['sha256']='0'*64
        with self.assertRaises(ValueError):routing.validate_geo(bad)
        with self.assertRaises(ValueError):routing.snapshot('1.1.1.0/24')

    def test_diagnostic_matches_profile_mode_and_missing_database(self):
        with patch.object(self.c,'routing_status',return_value={'cascade_enabled':True}):
            self.assertEqual(self.c.call({'op':'route_check','id':self.uid,'address':'2.16.20.1'})['route'],'ru')
            self.assertEqual(self.c.call({'op':'route_check','id':self.uid,'address':'1.1.1.1'})['route'],'cascade')
            with self.c.db() as c:routing.put(c,'routing_geo',{})
            self.assertEqual(self.c.call({'op':'route_check','id':self.uid,'address':'1.1.1.1'})['route'],'blocked')
        with self.assertRaises(ValueError):self.c.call({'op':'route_check','id':self.uid,'address':'127.0.0.1'})

    def test_conntrack_no_flows_is_success_but_permission_failure_is_not(self):
        empty=types.SimpleNamespace(returncode=1,stderr='conntrack v1: 0 flow entries have been deleted.\n')
        with patch.object(routing.subprocess,'run',return_value=empty):routing.clear_connections('10.77.0.2')
        denied=types.SimpleNamespace(returncode=1,stderr='Operation not permitted')
        with patch.object(routing.subprocess,'run',return_value=denied),self.assertRaises(OSError):routing.clear_connections('10.77.0.2')

    def test_geo_download_uses_enabled_cascade_and_ignores_proxy_environment(self):
        data=('\n'.join(routing.seed()['networks'])+'\n').encode()
        path=self.root/'state.json';path.write_text(json.dumps({'enabled':True}))
        with patch.object(routing,'CASCADE_ROOT',self.root),patch.object(routing.subprocess,'run',return_value=types.SimpleNamespace(stdout=data)) as run:
            self.assertEqual(routing.fetch()['sha256'],routing.seed()['sha256'])
            args=run.call_args.args[0]
            self.assertEqual(args[args.index('--interface')+1],'10.78.254.1')
            self.assertIn('--noproxy',args)
            self.assertEqual(args[-1],routing.SOURCE)


if __name__=='__main__':unittest.main()
