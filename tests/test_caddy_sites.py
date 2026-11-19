"""Hand-made Caddy sites survive the installer's rewrite of the Caddyfile."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import caddy_sites
from units import caddyfile

OLD='''{
 email me@example.com
 servers {
  protocols h1 h2
 }
}
tg.example.com {
 encode gzip
 redir / https://example.com/ 302
 handle {
  reverse_proxy 127.0.0.1:8080
 }
}

http://hy2.example.com {
 respond "ok" 200
}
# my own site
example.com, www.example.com {
 root * /var/www/site   # comment with { brace
 header X-Note "a } quoted brace"
 file_server
}
old.example.com {
 redir https://tg.example.com{uri} 302
}
sync.example.com {
 reverse_proxy 127.0.0.1:8090
}
(common) {
 encode zstd
}
'''


class Setup:
    def directory(self,path,mode=0o755,**kwargs):Path(path).mkdir(parents=True,exist_ok=True)
    def write(self,path,text,**kwargs):Path(path).write_text(text,encoding='utf-8')


class CustomSites(unittest.TestCase):
    managed=['tg.example.com','hy2.example.com','sync.example.com']

    def test_only_foreign_blocks_are_kept(self):
        kept=caddy_sites.custom_sites(OLD,self.managed)
        self.assertIn('example.com, www.example.com {',kept);self.assertIn('"a } quoted brace"',kept)
        self.assertIn('old.example.com {',kept);self.assertIn('(common) {',kept)
        for owned in ('tg.example.com {','http://hy2.example.com','sync.example.com {','protocols h1 h2'):self.assertNotIn(owned,kept)

    def test_preserve_writes_once_and_template_imports_folders(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);config=root/'Caddyfile';config.write_text(OLD)
            sites=root/'sites.d';proxy=root/'proxy.d'
            first=caddy_sites.preserve(Setup(),self.managed,config,sites,proxy)
            self.assertTrue(first and first.exists() and proxy.is_dir())
            self.assertIn('file_server',first.read_text())
            # A rolled-back update leaves the old Caddyfile beside the kept copy: no duplicate on the next run.
            self.assertIsNone(caddy_sites.preserve(Setup(),self.managed,config,sites,proxy))
            self.assertEqual(len(list(sites.glob('*.caddy'))),1)
            config.write_text(caddyfile('tg.example.com')+caddy_sites.includes())
            self.assertIsNone(caddy_sites.preserve(Setup(),self.managed,config,sites,proxy))
        template=caddyfile('tg.example.com')
        self.assertIn(' import /etc/caddy/proxy.d/*.caddy\n',template)
        self.assertIn('import /etc/caddy/sites.d/*.caddy',caddy_sites.includes())

    def test_package_default_and_catch_all_blocks_are_dropped(self):
        # Fresh Ubuntu: the caddy package's own Caddyfile must not end up serving "Caddy works!" on http://IP/.
        default=':80 {\n root * /usr/share/caddy\n file_server\n}\n'
        self.assertEqual(caddy_sites.custom_sites(default,self.managed),'')
        self.assertEqual(caddy_sites.custom_sites('http:// {\n respond "x"\n}\n:443 {\n respond "y"\n}\n',self.managed),'')

    def test_environment_placeholder_site_is_kept(self):
        kept=caddy_sites.custom_sites('{$SITE} {\n root * {$ROOT}\n file_server\n}\n',self.managed)
        self.assertIn('{$SITE} {',kept);self.assertIn('{$ROOT}',kept)

    def test_mixed_header_keeps_only_the_owners_hosts(self):
        kept=caddy_sites.custom_sites('tg.example.com, www.tg.example.com {\n redir https://tg.example.com{uri}\n}\n',self.managed)
        self.assertTrue(kept.startswith('www.tg.example.com {'),kept)
        self.assertNotIn('tg.example.com,',kept);self.assertIn('redir https://tg.example.com{uri}',kept)
        # Already moved to sites.d: not added a second time.
        self.assertEqual(caddy_sites.custom_sites('tg.example.com, www.tg.example.com {\n}\n',self.managed,'www.tg.example.com {\n}\n'),'')

    def test_rolled_back_update_forgets_the_copy_it_wrote(self):
        # The restored old Caddyfile still defines the moved sites; a leftover copy would define them twice.
        import inspect
        import installer
        with tempfile.TemporaryDirectory() as folder:
            kept=Path(folder)/'kept-1.caddy';kept.write_text('example.com {\n}\n')
            installer.PRESERVED.append(kept)
            installer.forget_preserved()
            self.assertFalse(kept.exists());self.assertEqual(installer.PRESERVED,[])
        main=inspect.getsource(installer.main)
        self.assertLess(main.index('forget_preserved()'),main.index('restore_internal(snapshot)'))
        self.assertIn('PRESERVED.append(kept)',inspect.getsource(installer.install_files))

    def test_unbalanced_file_is_refused(self):
        with self.assertRaises(ValueError):caddy_sites.custom_sites('a.example.com {\n',self.managed)
        with self.assertRaises(ValueError):caddy_sites.custom_sites('}\n',self.managed)


if __name__=='__main__':unittest.main()
