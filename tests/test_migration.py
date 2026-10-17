import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'panel'))
import migration_state
from migration_control import Migration, SERVICES
from units import units


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.users=self.root/'users.json';self.users.write_text(json.dumps({'host':'proxy.example.com','users':[{'secret':'preserve-me','enabled':False}]}))
        self.backup=Mock()
        self.backup.lock=threading.RLock();self.backup.running=False
        self.backup.paths={'users':self.users}
        self.backup.ready.return_value=True
        self.backup.status.return_value={'pending':False,'file':'final.age','uploaded':123,'error':''}
        self.control=Migration(self.backup,self.root/'local',group=None)
        self.active={'mtproxy':True,'tproxy-server':True,'relay-refresh.timer':True}
        self.commands=[]
        self.control.systemctl=self.systemctl
        self.addCleanup(patch.stopall)
        patch.object(migration_state,'ROOT',self.control.root).start()

    def systemctl(self,*args,check=True):
        self.commands.append(args)
        action,name=args[:2]
        if action=='show':return subprocess.CompletedProcess(args,0,'loaded' if name in self.active else 'not-found')
        if action=='is-active':return subprocess.CompletedProcess(args,0 if self.active.get(name) else 3,'')
        if action in ('stop','start'):
            self.active[name]=action=='start'
            return subprocess.CompletedProcess(args,0,'')
        raise AssertionError(args)

    def stop(self):
        self.control.data['phase']='freezing';self.control.write('blocked',b'')
        self.control.work('stop',contextlib.nullcontext())

    def test_final_backup_after_stop_and_keys_unchanged(self):
        before=self.users.read_bytes()
        self.backup.snapshot.side_effect=lambda **kwargs:self.assertFalse(any(self.active.values()))
        self.stop()
        self.assertEqual(self.control.status()['phase'],'stopped')
        self.backup.snapshot.assert_called_once_with(final=True)
        self.assertEqual(self.users.read_bytes(),before)
        self.assertTrue(migration_state.blocked())
        self.assertNotIn('caddy',[x[1] for x in self.commands])

    def test_upload_failure_keeps_stopped_and_retry_uses_original_inventory(self):
        self.backup.status.return_value.update(error='Диск недоступен',pending=True)
        self.stop()
        self.assertEqual(self.control.data['phase'],'error')
        self.assertFalse(any(self.active.values()))
        self.assertTrue(self.control.data['previous']['mtproxy'])
        self.backup.status.return_value.update(error='',pending=False)
        self.stop()
        self.assertEqual(self.control.data['phase'],'stopped')
        self.assertTrue(self.control.data['previous']['mtproxy'])

    def test_resume_preserves_inactive_services(self):
        self.active['relay-refresh.timer']=False
        self.stop()
        response=Mock();response.__enter__=Mock(return_value=Mock(status=200));response.__exit__=Mock(return_value=False)
        with patch('urllib.request.urlopen',return_value=response):
            self.control.work('resume',contextlib.nullcontext())
        self.assertEqual(self.control.data['phase'],'running')
        self.assertTrue(self.active['mtproxy']);self.assertFalse(self.active['relay-refresh.timer'])
        self.assertFalse(migration_state.blocked())

    def test_partial_resume_failure_restops_services(self):
        self.stop()
        original=self.systemctl
        def fail(*args,**kwargs):
            if args==('start','tproxy-server'):raise subprocess.CalledProcessError(1,args)
            return original(*args,**kwargs)
        self.control.systemctl=fail
        self.control.work('resume',contextlib.nullcontext())
        self.assertEqual(self.control.data['phase'],'error')
        self.assertFalse(any(self.active.values()));self.assertTrue(migration_state.blocked())

    def test_interrupted_job_is_not_reported_as_success_after_restart(self):
        self.control.data.update(phase='freezing');self.control.save()
        with patch.object(Migration,'systemctl'):
            restarted=Migration(self.backup,self.control.root,group=None)
        self.assertEqual(restarted.data['phase'],'error')
        self.assertTrue(migration_state.blocked())

    def test_interrupted_resume_cannot_start_on_another_boot(self):
        self.control.data.update(phase='resuming',boot_id='old-boot');self.control.save()
        with patch.object(migration_state,'boot_id',return_value='new-boot'):
            self.assertFalse(migration_state.can_start())
        with patch.object(migration_state,'boot_id',return_value='old-boot'):
            self.assertTrue(migration_state.can_start())

    def test_standby_is_local_and_does_not_require_drive(self):
        self.control.standby()
        self.assertEqual(self.control.data['phase'],'standby')
        self.backup.snapshot.assert_not_called()
        self.assertTrue(migration_state.blocked())

    def test_systemd_failure_cannot_be_reported_as_stopped(self):
        self.control.systemctl=Mock(return_value=subprocess.CompletedProcess([],1,''))
        self.stop()
        self.assertEqual(self.control.data['phase'],'error')
        self.backup.snapshot.assert_not_called()

    @unittest.skipUnless(os.name=='posix','Linux flock')
    def test_inflight_mutation_blocks_stop_and_frozen_mutations_are_rejected(self):
        with migration_state.mutation(),self.assertRaises(ValueError):
            self.control.call('stop','proxy.example.com')
        self.assertEqual(self.control.data['phase'],'running')
        self.control.standby()
        with self.assertRaises(ValueError),migration_state.mutation():pass
        with self.assertRaises(ValueError):self.control.call('resume','wrong.example.com')

    def test_every_traffic_unit_has_boot_gate(self):
        for name in ('mtproxy.service','tproxy-server.service','relay-refresh.service','relay-refresh.timer'):
            self.assertIn('ConditionPathExists=!/var/lib/relay-migration/blocked',units()[name])


if __name__=='__main__':unittest.main()
