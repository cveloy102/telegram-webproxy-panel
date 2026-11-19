"""A restart of the cascade during an update or rollback must not leave the client protocols down."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import installer
import manage
import cascade_network


class Units(unittest.TestCase):
    def test_engine_creates_its_folders_and_runs_from_the_active_release(self):
        unit=cascade_network.engine_unit('relay-cascade.service')
        pre=unit.index('ExecStartPre=+/usr/bin/mkdir -p -m 0750 /run/relay-cascade')
        self.assertLess(pre,unit.index('ExecStart=/usr/bin/python3'))
        self.assertIn('ExecStart=/usr/bin/python3 /opt/relay-panel/current/panel/cascade_network.py --engine',unit)
        self.assertNotIn('/tmp/',unit);self.assertIn('PartOf=relay-cascade.service',unit)
        exit_unit=cascade_network.engine_unit('relay-cascade-exit.service')
        self.assertIn(str(Path(cascade_network.__file__).resolve()),exit_unit)

    def test_runtime_folder_survives_restart(self):
        self.assertIn('RuntimeDirectoryPreserve=yes',cascade_network.TRANSPORT_DROPIN)
        source=(ROOT/'cascade_install.py').read_text()
        self.assertIn('RuntimeDirectory=relay-cascade\nRuntimeDirectoryMode=0750\n# The AWG engine',source)
        self.assertIn('RuntimeDirectoryPreserve=yes',source)


class Restarts(unittest.TestCase):
    def test_update_retries_a_cascade_that_fails_once(self):
        calls=[]
        def run(*args,**kwargs):
            calls.append(args)
            if args==('systemctl','restart','relay-cascade') and calls.count(args)==1:raise RuntimeError('226')
        with patch.object(installer,'run',side_effect=run),patch.object(installer.time,'sleep'):
            installer.restart_cascade()
        self.assertEqual(calls.count(('systemctl','restart','relay-cascade')),2)
        with patch.object(installer,'run',side_effect=RuntimeError('down')),patch.object(installer.time,'sleep'),self.assertRaises(RuntimeError):
            installer.restart_cascade()

    def test_rollback_starts_every_service_despite_one_failure(self):
        started=[]
        def run(args,**kwargs):
            if args[1]=='restart':started.append(args[2])
            return subprocess.CompletedProcess(args,1 if args[1:]==['restart','relay-cascade'] else 0)
        with patch.object(manage.subprocess,'run',side_effect=run),patch.object(manage.time,'sleep'):
            failed=manage.start_each(['relay-cascade','mtproxy','hysteria-server','svalka-sync'])
        self.assertEqual(failed,['relay-cascade'])
        self.assertEqual(started.count('relay-cascade'),4)
        for name in ('mtproxy','hysteria-server','svalka-sync'):self.assertIn(name,started)


if __name__=='__main__':unittest.main()
