"""Real isolated Linux cascade: local proxy sockets, AWG-like forwarding, outage and recovery.

Creates only temporary network namespaces; never modifies host routes or firewall.
Run as root on Linux with wireguard-tools, nftables, iproute2, curl and setpriv.
"""
import os
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

if sys.platform != 'linux' or os.geteuid() != 0: raise SystemExit('Linux root required')
PANEL = Path(__file__).resolve().parents[1] / 'panel'
token = secrets.token_hex(3)
names = {name: 'cc-' + name + '-' + token for name in ('ru', 'exit', 'client', 'web')}
created = []
processes = []


def run(*args, **kwargs):
    try:return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20, **kwargs)
    except subprocess.CalledProcessError as error:
        print(error.stderr,flush=True);raise


def ns(name, *args, **kwargs): return run('ip', 'netns', 'exec', names[name], *args, **kwargs)


def py(name, code): return ns(name, sys.executable, '-c', 'import sys;sys.path.insert(0,' + repr(str(PANEL)) + ');' + code)


def link(left, right, left_device, right_device, left_ip, right_ip):
    first, second = 'cc-a-' + token, 'cc-b-' + token
    run('ip', 'link', 'add', first, 'type', 'veth', 'peer', 'name', second)
    run('ip', 'link', 'set', first, 'netns', names[left])
    run('ip', 'link', 'set', second, 'netns', names[right])
    for name, old, device, address in ((left, first, left_device, left_ip), (right, second, right_device, right_ip)):
        ns(name, 'ip', 'link', 'set', old, 'name', device)
        ns(name, 'ip', 'address', 'add', address, 'dev', device)
        ns(name, 'ip', 'link', 'set', device, 'up')


def curl(name, host='203.0.113.2', uid=None, succeeds=True, source=None):
    command = ['curl', '-q', '--noproxy', '*', '--silent', '--show-error', '--max-time', '2', 'http://' + host + ':18082/']
    if source:command+=['--interface',source]
    if uid: command = ['setpriv', '--reuid', str(uid), '--regid', str(uid), '--clear-groups', *command]
    result = subprocess.run(['ip', 'netns', 'exec', names[name], *command], capture_output=True, text=True, timeout=5)
    if succeeds:
        assert result.returncode == 0, (name, result.stderr)
        return result.stdout.strip()
    assert result.returncode != 0, 'Tunnel outage leaked through direct egress: ' + name


with tempfile.TemporaryDirectory(prefix='relay-cascade-smoke-') as temporary:
    root = Path(temporary)
    try:
        for name in names:
            run('ip', 'netns', 'add', names[name]); created.append(names[name])
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        link('ru', 'exit', 'underlay', 'underlay', '93.184.216.1/30', '93.184.216.2/30')
        link('exit', 'web', 'uplink', 'uplink', '203.0.113.1/30', '203.0.113.2/30')
        link('ru', 'client', 'awg-relay', 'client', '10.77.0.1/24', '10.77.0.2/24')
        ns('client','ip','address','add','10.77.0.3/24','dev','client')
        ns('web','ip','address','add','203.0.113.4/32','dev','uplink')
        ns('exit','ip','route','add','203.0.113.4/32','via','203.0.113.2')
        ns('ru', 'ip', 'route', 'add', 'default', 'via', '93.184.216.2')
        ns('client', 'ip', 'route', 'add', 'default', 'via', '10.77.0.1')
        ns('web', 'ip', 'route', 'add', 'default', 'via', '203.0.113.1')
        for name in ('ru', 'exit'): ns(name, 'sysctl', '-w', 'net.ipv4.ip_forward=1')
        keys = {}
        for name in ('ru', 'exit'):
            private = run('wg', 'genkey').stdout
            path = root / (name + '.key');path.write_text(private);path.chmod(0o600)
            keys[name] = run('wg', 'pubkey', input=private).stdout.strip()
        entry_root=root/'entry';entry_root.mkdir(mode=0o700)
        (entry_root/'private.key').write_bytes((root/'ru.key').read_bytes())
        (entry_root/'state.json').write_text(json.dumps({'schema':1,'enabled':True,'name':'Test','host':'93.184.216.2','port':51821,'exit_public_key':keys['exit']}))
        exit_setup = 'from cascade_network import *;replace_table("relay_cascade_exit",exit_firewall());setup_interface(Path(' + repr(str(root / 'exit.key')) + '),' + repr(keys['ru']) + ',entry=False,port=51821)'
        ru_setup = 'from cascade_network import *;setup_interface(Path(' + repr(str(root / 'ru.key')) + '),' + repr(keys['exit']) + ',host="93.184.216.2",port=51821);policy_routes()'
        py('exit', exit_setup)
        py('ru', ru_setup)
        py('ru', 'from awg_network import firewall;from cascade_network import replace_table;replace_table("relay_awg",firewall())')
        py('ru', 'from cascade_network import *;replace_table("relay_cascade",entry_firewall([1001],False))')
        server = '''from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'x'*524288 if self.path=='/bulk' else self.client_address[0].encode())
 def log_message(self,*args):pass
HTTPServer(('0.0.0.0',18082),Handler).serve_forever()
'''
        # The script is carried in argv, so setpriv doesn't need access to root's files.
        for name, user in (('web', []), ('ru', ['setpriv', '--reuid', '1001', '--regid', '1001', '--clear-groups'])):
            processes.append(subprocess.Popen(['ip', 'netns', 'exec', names[name], *user, sys.executable, '-c', server], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(.4)
        assert curl('ru', uid=1001) == '93.184.216.1'
        assert curl('client') == '93.184.216.1'
        py('ru', 'from cascade_network import *;replace_table("relay_cascade",entry_firewall([1001],True))')
        for _ in range(15):
            try:
                observed = curl('ru', uid=1001)
                assert observed == '203.0.113.1', 'Observed egress: ' + observed
                break
            except AssertionError as error:
                last_error = str(error); time.sleep(.2)
        else: raise AssertionError('Local proxy traffic did not use the exit: ' + last_error)
        assert curl('client') == '203.0.113.1'
        # Compile the actual bundled 13k-prefix set in the real kernel first.
        py('ru','from awg_routing import Runtime,seed;Runtime().install(["10.77.0.2"],seed()["networks"],[])')
        assert curl('client')=='203.0.113.1'
        # Synthetic public test destinations represent RU and non-RU here.
        split='from awg_routing import Runtime;Runtime().install(["10.77.0.2"],["203.0.113.2/32"],[])'
        py('ru',split)
        assert curl('client')=='93.184.216.1','RU destination must use RU egress'
        assert curl('client',host='203.0.113.4')=='203.0.113.1','Foreign destination must use cascade'
        assert curl('client',source='10.77.0.3')=='203.0.113.1','Other profile must retain full cascade'
        assert curl('ru',uid=1001)=='203.0.113.1','Proxy UID routing must remain unchanged'
        # Same UDP tuple survives in conntrack across socket invocations. Flush
        # only the switched peer, then prove that the observed NAT address moves.
        udp_server='import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("0.0.0.0",18083))\nwhile True:\n b,a=s.recvfrom(128);s.sendto(a[0].encode(),a)'
        processes.append(subprocess.Popen(['ip','netns','exec',names['web'],sys.executable,'-c',udp_server],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        time.sleep(.2)
        def udp(source):
            code='import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.bind(('+repr(source)+',20000));s.sendto(b"test",("203.0.113.2",18083));print(s.recv(128).decode())'
            return ns('client',sys.executable,'-c',code).stdout.strip()
        assert udp('10.77.0.2')=='93.184.216.1'
        assert udp('10.77.0.3')=='203.0.113.1'
        py('ru','from awg_routing import Runtime,clear_connections;Runtime().install([],[],["10.77.0.2"]);clear_connections("10.77.0.2");Runtime().install([],[],[])')
        assert udp('10.77.0.2')=='203.0.113.1'
        assert udp('10.77.0.3')=='203.0.113.1'
        py('ru','from awg_routing import Runtime,clear_connections;Runtime().install(["10.77.0.2"],["203.0.113.2/32"],["10.77.0.2"]);clear_connections("10.77.0.2");Runtime().install(["10.77.0.2"],["203.0.113.2/32"],[])')
        assert udp('10.77.0.2')=='93.184.216.1'
        # No usable geo data: block split only, retain the other profile.
        py('ru','from awg_routing import Runtime;Runtime().install(["10.77.0.2"],[],[])')
        curl('client',succeeds=False)
        assert curl('client',source='10.77.0.3')=='203.0.113.1'
        py('ru',split)
        ns('ru','ip','link','delete','wg-cascade')
        assert curl('client')=='93.184.216.1','RU destinations must survive cascade outage'
        curl('client',host='203.0.113.4',succeeds=False)
        curl('client',source='10.77.0.3',succeeds=False)
        curl('ru',uid=1001,succeeds=False)
        py('ru','from cascade_control import Controller;from pathlib import Path;Controller(Path('+repr(str(entry_root))+'),uids=[1001]).reconcile()')
        # Restore all-cascade classification for the original bulk/outage suite.
        py('ru','from awg_routing import Runtime,clear_connections;Runtime().install([],[],["10.77.0.2"]);clear_connections("10.77.0.2");Runtime().install([],[],[])')
        assert curl('client')=='203.0.113.1'
        for name, user in (('ru', ['setpriv','--reuid','1001','--regid','1001','--clear-groups']),('client', [])):
            payload=ns(name,*user,'curl','-q','--noproxy','*','--fail','--silent','--max-time','5','http://203.0.113.2:18082/bulk').stdout
            assert len(payload)==524288, 'Bulk transfer failed: '+name
        assert curl('web', host='93.184.216.1') == '203.0.113.2', 'Service replies incorrectly entered tunnel'
        ns('ru', 'ip', 'link', 'delete', 'wg-cascade')
        curl('ru', uid=1001, succeeds=False)
        curl('client', succeeds=False)
        assert curl('ru') == '93.184.216.1', 'Host management lost direct egress'
        assert curl('web', host='93.184.216.1') == '203.0.113.2'
        py('ru', 'from cascade_control import Controller;from pathlib import Path;Controller(Path('+repr(str(entry_root))+'),uids=[1001]).reconcile()')
        for _ in range(15):
            try:
                assert curl('ru', uid=1001) == '203.0.113.1'
                break
            except AssertionError: time.sleep(.2)
        else: raise AssertionError('Tunnel did not recover')
        assert curl('client') == '203.0.113.1'
        py('ru', 'from cascade_network import *;replace_table("relay_cascade",entry_firewall([1001],False))')
        assert curl('ru', uid=1001) == '93.184.216.1'
        assert curl('client') == '93.184.216.1'
        print('PASS: proxy sockets, AWG full/split profiles, real GeoIP set, scoped NAT reset, missing geo, RU/foreign outage isolation, bulk, recovery, explicit disable')
    except Exception:
        try:
            ns('ru','nft','insert','rule','inet','relay_cascade','mark_output','meta','nftrace','set','1')
            trace_path=root/'trace.log'
            with trace_path.open('w') as trace:
                monitor=subprocess.Popen(['ip','netns','exec',names['ru'],'nft','monitor','trace'],stdout=trace,stderr=subprocess.DEVNULL)
                time.sleep(.2)
                try:curl('ru',uid=1001)
                except AssertionError:pass
                time.sleep(.2);monitor.terminate();monitor.wait(timeout=3)
            print('\n'.join(trace_path.read_text().splitlines()[:45]),flush=True)
        except Exception:pass
        for name in ('ru', 'exit'):
            print('Diagnostics:', name, flush=True)
            for command in (['wg','show'],['ip','-4','rule','show'],['ip','-4','route','show','table','all'],['nft','list','ruleset']):
                try: print(ns(name,*command).stdout, flush=True)
                except Exception: pass
        raise
    finally:
        for process in processes:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill();process.wait()
        for namespace in reversed(created): subprocess.run(['ip', 'netns', 'delete', namespace], capture_output=True)
