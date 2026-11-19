"""Local update backups and old releases are pruned without touching what is still in use."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import manage


class Backups(unittest.TestCase):
    def test_keeps_newest_by_timestamp_name(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder)
            names=['20261119T%02d0000-abcdef.tar.gz'%hour for hour in range(8)]
            for name in names:(folder/name).write_bytes(b'x')
            (folder/'notes.txt').write_text('keep')
            removed=manage.prune_backups(keep=5,folder=folder)
            self.assertEqual(sorted(p.name for p in removed),names[:3])
            self.assertEqual(sorted(p.name for p in folder.glob('*.tar.gz')),names[3:])
            self.assertTrue((folder/'notes.txt').exists())

    def test_missing_folder_is_fine(self):
        self.assertEqual(manage.prune_backups(folder=Path(tempfile.gettempdir())/'no-such-relay-backups'),[])


class Releases(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)/'opt';self.units=Path(self.temp.name)/'units'
        (self.base/'releases').mkdir(parents=True);self.units.mkdir()
        self.folders=[]
        now=time.time()
        for index in range(7):
            path=self.base/'releases'/('0.5.0-%d'%index);path.mkdir();(path/'panel').mkdir()
            os.utime(path,(now-1000+index*10,now-1000+index*10));self.folders.append(path)

    def link_current(self,path):
        try:(self.base/'current').symlink_to(path,target_is_directory=True)
        except OSError:self.skipTest('symlinks are not available here')

    def test_keeps_newest_current_and_referenced(self):
        self.link_current(self.folders[1])
        (self.units/'relay-cascade-engine.service').write_text('ExecStart=/usr/bin/python3 '+str(self.folders[0]/'panel'/'cascade_network.py')+'\n')
        removed=manage.prune_releases(keep=3,base=self.base,units=self.units)
        self.assertEqual(sorted(p.name for p in removed),['0.5.0-2','0.5.0-3'])
        left=sorted(p.name for p in (self.base/'releases').iterdir())
        self.assertEqual(left,['0.5.0-0','0.5.0-1','0.5.0-4','0.5.0-5','0.5.0-6'])

    def test_nothing_removed_when_few(self):
        self.link_current(self.folders[6])
        self.assertEqual(manage.prune_releases(keep=10,base=self.base,units=self.units),[])


if __name__=='__main__':unittest.main()
