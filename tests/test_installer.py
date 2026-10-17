import io
import contextlib
import json
import pathlib
import os
import socket
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from installer import domain_name,site_options,render_site,check_dns,check_tcp_port,extract
from units import caddyfile,units,FIREWALL

class Terminal:
    def __init__(self,code,raw=False,errors='strict'):
        import pty
        import subprocess
        import termios
        self.master,slave=pty.openpty()
        settings=termios.tcgetattr(slave)
        settings[0]&=~0x4000  # Linux IUTF8 is off on the affected VPS terminal.
        if raw:settings[3]&=~(termios.ICANON|termios.ECHO)
        termios.tcsetattr(slave,termios.TCSANOW,settings)
        self.initial=termios.tcgetattr(slave)
        self.process=subprocess.Popen([sys.executable,'-c',code],cwd=pathlib.Path(__file__).resolve().parents[1],
                                      stdin=slave,stdout=slave,stderr=slave,
                                      env={**os.environ,'TERM':'xterm','LC_ALL':'C.UTF-8',
                                           'PYTHONIOENCODING':'utf-8:'+errors})
        os.close(slave)
        self.output=bytearray();self.cursor=0
    def __enter__(self):return self
    def __exit__(self,*args):
        if self.process.poll() is None:self.process.kill();self.process.wait()
        os.close(self.master)
    def send(self,value):os.write(self.master,value.encode() if isinstance(value,str) else value)
    def expect(self,marker):
        import select
        import time
        if isinstance(marker,str):marker=marker.encode()
        deadline=time.monotonic()+8
        while True:
            found=self.output.find(marker,self.cursor)
            if found>=0:self.cursor=found+len(marker);return
            if time.monotonic()>=deadline:raise AssertionError(self.output.decode('utf-8','replace'))
            if select.select([self.master],[],[],0.1)[0]:
                try:chunk=os.read(self.master,65536)
                except OSError:chunk=b''
                if not chunk:raise AssertionError(self.output.decode('utf-8','replace'))
                self.output.extend(chunk)
    def finish(self):
        import termios
        assert self.process.wait(timeout=8)==0,self.output.decode('utf-8','replace')
        assert termios.tcgetattr(self.master)==self.initial,'Terminal settings were not restored'

class InstallerTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','Unix installer entry point')
    def test_full_new_install_dialogue_can_cancel_without_changing_server(self):
        code='''
import installer,sys,tempfile
from pathlib import Path
import recovery_wizard
with tempfile.TemporaryDirectory() as folder:
    root=Path(folder)
    installer.STATE=root/'install.json'
    installer.preflight=lambda existing:None
    installer.public_ipv4=lambda:'45.67.202.147'
    installer.check_dns=lambda *args:None
    installer.open_install_lock=lambda:open(root/'install.lock','a')
    recovery_wizard.pending=lambda:False
    sys.path.insert(0,str(Path(installer.__file__).parent/'panel'))
    import migration_state
    migration_state.ROOT=root/'migration'
    def forbidden(*args,**kwargs):raise AssertionError('Cancelled wizard attempted installation')
    installer.packages=installer.directory=forbidden
    installer.main()
    assert not installer.STATE.exists()
    print('CANCELLED_NO_CHANGES')
'''
        with Terminal(code,raw=True) as terminal:
            terminal.expect('0 — выход [Enter — 1]: ');terminal.send('\n')
            terminal.expect('без https:// и пути): ');terminal.send('tg.hl100.ru\n')
            terminal.expect('Публичный IPv4 этого VPS [Enter — 45.67.202.147]: ');terminal.send('\n')
            terminal.expect('Название страницы (можно по-русски) [Enter — Свои люди]: ');terminal.send('Мой прокси\n')
            terminal.expect('пусто — без кнопки) [Enter — пропустить]: ');terminal.send('\n')
            terminal.expect('нейтральная [Enter — 1]: ');terminal.send('\n')
            terminal.expect('необязательно) [Enter — пропустить]: ');terminal.send('\n')
            terminal.expect('Установить также Hysteria 2? да / нет [Enter — да]: ');terminal.send('нет\n')
            terminal.expect('Установить также AmneziaWG 3.1? да / нет [Enter — нет]: ');terminal.send('\n')
            terminal.expect('Начать? да / нет [Enter — нет]: ');terminal.send('maybe\n')
            terminal.expect('Введи да или нет');terminal.expect('Начать? да / нет [Enter — нет]: ');terminal.send('\n')
            terminal.expect('CANCELLED_NO_CHANGES');terminal.finish()

    @unittest.skipUnless(os.name=='posix','Unix terminal input')
    def test_cyrillic_editing_echo_and_ascii_domain_in_affected_terminal_modes(self):
        code='from installer import ask; title=ask("Title", "Свои люди"); domain=ask("Domain"); print("RESULT:"+title+"|"+domain)'
        for raw in (False,True):
            with self.subTest(raw=raw),Terminal(code,raw=raw) as terminal:
                terminal.expect('Title [Enter — Свои люди]: ')
                terminal.send('Свои людь')
                terminal.expect('Свои людь')  # Typed characters must be visible before Enter.
                terminal.send(b'\x7f'+'и\n'.encode())
                terminal.expect('Domain: ')
                terminal.send(b'hy2.hl100.rux\x7f\n')
                terminal.expect('RESULT:Свои люди|hy2.hl100.ru')
                terminal.finish()
                self.assertNotIn('Не удалось прочитать ввод'.encode(),terminal.output)

    @unittest.skipUnless(os.name=='posix','Unix terminal input')
    def test_complete_options_dialogue_defaults_formats_and_retry(self):
        code='import installer,json; installer.public_ipv4=lambda:"45.67.202.147"; installer.check_dns=lambda *args:None; print("OPTIONS:"+json.dumps(installer.new_options(),ensure_ascii=False))'
        with Terminal(code,raw=True) as terminal:
            terminal.expect('без https:// и пути): ');terminal.send('tg.hl100.ru\n')
            terminal.expect('Публичный IPv4 этого VPS [Enter — 45.67.202.147]: ');terminal.send('\n')
            terminal.expect('Название страницы (можно по-русски) [Enter — Свои люди]: ');terminal.send('\n')
            contact_prompt='Telegram для кнопки связи (@username или username; пусто — без кнопки) [Enter — пропустить]: '
            theme_prompt='Тема страницы: 1 — тёмная пиксельная, 2 — нейтральная [Enter — 1]: '
            email_prompt='Email для сертификата (например name@example.com; необязательно) [Enter — пропустить]: '
            hy2_prompt='Отдельный домен Hysteria (например hy2.example.com, без https:// и пути): '
            port_prompt='UDP-порт Hysteria (число от 1024 до 65535) [Enter — 24443]: '
            terminal.expect(contact_prompt)
            terminal.send('https://t.me/example_user\n')
            terminal.expect('Telegram username');terminal.expect(contact_prompt);terminal.send('@example_user\n')
            terminal.expect(theme_prompt);terminal.send('3\n')
            terminal.expect('Введи 1');terminal.expect(theme_prompt);terminal.send('2\n')
            terminal.expect(email_prompt)
            terminal.send('bad-email\n');terminal.expect('Нужен email');terminal.expect(email_prompt);terminal.send(' hl100@yandex.ru \n')
            terminal.expect('Установить также Hysteria 2? да / нет [Enter — да]: ');terminal.send('\n')
            terminal.expect(hy2_prompt);terminal.send('tg.hl100.ru\n')
            terminal.expect('другой поддомен');terminal.expect(hy2_prompt);terminal.send('hy2.hl100.ru\n')
            terminal.expect(port_prompt)
            for invalid in ('abc','80','70000'):
                terminal.send(invalid+'\n');terminal.expect('Введи номер UDP-порта');terminal.expect(port_prompt)
            terminal.send('\n');terminal.expect('Установить также AmneziaWG 3.1? да / нет [Enter — нет]: ');terminal.send('\n');terminal.expect('OPTIONS:');terminal.expect('\r\n');terminal.finish()
            options=json.loads(terminal.output.split(b'OPTIONS:',1)[1].splitlines()[0])
        self.assertEqual(options['title'],'Свои люди')
        self.assertEqual(options['contact'],'example_user')
        self.assertEqual(options['theme'],'minimal')
        self.assertEqual(options['email'],'hl100@yandex.ru')
        self.assertEqual(options['ip'],'45.67.202.147')
        self.assertEqual(options['hy2_domain'],'hy2.hl100.ru')
        self.assertEqual(options['hy2_port'],24443)

    def test_optional_fields_can_be_skipped_and_hysteria_disabled(self):
        import installer
        with patch('builtins.input',side_effect=['tg.example.com','','','','','','нет','нет']),\
             patch.object(installer,'public_ipv4',return_value='45.67.202.147'),\
             patch.object(installer,'check_dns'),contextlib.redirect_stdout(io.StringIO()):
            options=installer.new_options()
        self.assertEqual(options['title'],'Свои люди')
        self.assertEqual(options['contact'],'')
        self.assertEqual(options['email'],'')
        self.assertNotIn('hy2_domain',options)

    @unittest.skipUnless(os.name=='posix','Unix terminal input')
    def test_real_terminal_recovers_from_malformed_utf8(self):
        code='from installer import ask; print("RESULT:"+ask("Domain", "old.example.com"))'
        for errors in ('strict','surrogateescape'):
            with self.subTest(errors=errors),Terminal(code,raw=True,errors=errors) as terminal:
                terminal.expect('Domain [Enter — old.example.com]: ')
                terminal.send(b'\xd0X\n')
                terminal.expect('Не удалось прочитать ввод')
                terminal.expect('Domain [Enter — old.example.com]: ')
                terminal.send('tg.example.com\n')
                terminal.expect('RESULT:tg.example.com');terminal.finish()

    def test_invalid_utf8_input_retries_without_accepting_default(self):
        from installer import ask
        broken=UnicodeDecodeError('utf-8',b'\xd0X',0,1,'invalid continuation byte')
        for bad in (broken,'\udcd0X'):
            with self.subTest(bad=repr(bad)),patch('builtins.input',side_effect=[bad,'tg.example.com']),contextlib.redirect_stdout(io.StringIO()) as output:
                value=ask('Домен','old.example.com',domain_name)
            self.assertEqual(value,'tg.example.com')
            self.assertIn('UTF-8',output.getvalue())

    @unittest.skipUnless(os.name=='posix','Linux socket reuse rules')
    def test_active_listener_is_rejected_but_closed_connections_do_not_block_install(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(('127.0.0.1',0));listener.listen()
            port=listener.getsockname()[1]
            with self.assertRaises(RuntimeError):check_tcp_port(port)
            with socket.create_connection(('127.0.0.1',port)) as client:
                connection,_=listener.accept();connection.close()
                self.assertEqual(client.recv(1),b'')
        check_tcp_port(port)

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
