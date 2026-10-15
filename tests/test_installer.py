import io
import json
import pathlib
import socket
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from installer import domain_name,site_options,render_site,check_dns,extract
from units import caddyfile,units,FIREWALL

class InstallerTests(unittest.TestCase):
    def test_domain_cannot_inject_config(self):
        self.assertEqual(domain_name('TG.Example.COM.'),'tg.example.com')
        self.assertTrue(domain_name('прокси.example.com').startswith('xn--'))
        for value in ['https://tg.example.com','example.com:443','example.com/abc','127.0.0.1','x\n{\nimport /etc/*','a..com','-bad.example','x.'+'a'*64+'.com']:
            with self.subTest(value=value),self.assertRaises(ValueError):domain_name(value)
    def test_site_escapes_title_and_contact(self):
        options=site_options('<script>alert(1)</script>','@example_user','pixel')
        body=render_site(options)
        self.assertNotIn('<script>',body)
        self.assertIn('&lt;script&gt;',body)
        self.assertIn('https://t.me/example_user',body)
        self.assertNotIn('https://t.me/',render_site(site_options('Private relay','','minimal')))
        with self.assertRaises(ValueError):site_options('Hi','https://bad.example','pixel')
    def test_dns_rejects_wrong_multiple_and_ipv6(self):
        def record(ip,family=socket.AF_INET):return (family,socket.SOCK_STREAM,6,'',(ip,443))
        with patch('socket.getaddrinfo',return_value=[record('203.0.113.10')]):check_dns('proxy.example.com','203.0.113.10')
        for values in [[record('203.0.113.11')],[record('203.0.113.10'),record('203.0.113.11')],[record('203.0.113.10'),record('2001:db8::1',socket.AF_INET6)]]:
            with patch('socket.getaddrinfo',return_value=values),self.assertRaises(RuntimeError):check_dns('proxy.example.com','203.0.113.10')
    def test_source_archive_rejects_escape_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            for index,name in enumerate(['../escape','/absolute','project/link']):
                path=root/f'{index}.tar.gz'
                with tarfile.open(path,'w:gz') as archive:
                    item=tarfile.TarInfo(name)
                    if index==2:item.type=tarfile.SYMTYPE;item.linkname='/etc'
                    archive.addfile(item)
                with self.assertRaises(RuntimeError):extract(path,root/str(index))
    def test_only_https_front_is_public(self):
        config=caddyfile('proxy.example.com')
        self.assertIn('127.0.0.1:8082',config)
        self.assertIn('handle @panel',config)
        self.assertIn('127.0.0.1:8080',config)
        self.assertIn('2398, 8888',FIREWALL)
        services=units()
        self.assertIn('User=relayadmin',services['relay-panel.service'])
        self.assertIn('LoadCredential=',services['tproxy-server.service'])
        self.assertIn('ReadWritePaths=/var/lib/tproxy-accounting',services['tproxy-server.service'])
        self.assertNotIn('0.0.0.0',services['relay-panel.service'])

if __name__=='__main__':unittest.main()
