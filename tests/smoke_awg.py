"""Real AWG 3.1 tunnel, key revocation, service gates and encrypted recovery.

Only an expendable GitHub runner: creates namespaces, updates OS and firewall.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

if os.getenv('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Expendable GitHub runner only')
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'panel'))
import installer as setup
import amnezia_install
from awg_routes import helper
from backup_archive import encrypt,layout
from restore import main as restore


def run(*args,**kwargs):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=30,**kwargs)
def ns(name,*args,**kwargs):return run('ip','netns','exec',name,*args,**kwargs)


def wait_ready():
    for _ in range(60):
        try:helper({'op':'migration_ready'});return
        except (OSError,ValueError):time.sleep(.5)
    raise AssertionError('AWG control not ready')


with tempfile.TemporaryDirectory(prefix='relay-awg-smoke-',dir='/var/tmp') as folder:
    work=Path(folder);options=json.loads(setup.STATE.read_text())
    options.update(awg_domain='vpn.example.com',awg_port=51820)
    setup.json_write(setup.STATE,options,mode=0o600)
    amnezia_install.install(setup,options,work)
    setup.run('systemctl','daemon-reload');amnezia_install.activate(setup,options)
    run('systemd-analyze','verify','/etc/systemd/system/amneziawg-server.service','/etc/systemd/system/relay-awg.service')
    helper({'op':'create','name':'AWG friend','group':'Друзья'})
    helper({'op':'create','name':'AWG family','group':'Семья'})
    users=helper({'op':'status'})['users'];uid=users[0]['id'];other=users[1]['id']
    original={u['id']:helper({'op':'key','id':u['id']})['conf'] for u in users}
    # Minimal isolated client/target networks. No third-party endpoint needed.
    client=web=None
    try:
        for name in ('awg-ci-client','awg-ci-web'):
            run('ip','netns','add',name);ns(name,'ip','link','set','lo','up')
        for host,peer,namespace,address,peer_address in [
            ('awgc-host','awgc-peer','awg-ci-client','172.30.77.1/30','172.30.77.2/30'),
            ('awgw-host','awgw-peer','awg-ci-web','198.18.77.1/30','198.18.77.2/30')]:
            run('ip','link','add',host,'type','veth','peer','name',peer)
            run('ip','link','set',peer,'netns',namespace)
            run('ip','addr','add',address,'dev',host);run('ip','link','set',host,'up')
            ns(namespace,'ip','addr','add',peer_address,'dev',peer);ns(namespace,'ip','link','set',peer,'up')
        ns('awg-ci-web','ip','route','add','default','via','198.18.77.1')
        # The disposable runner may have Docker's unrelated FORWARD policy DROP.
        run('iptables','-P','FORWARD','ACCEPT')
        www=work/'www';www.mkdir();(www/'index.html').write_text('awg-real-tunnel-ok')
        web=subprocess.Popen(['ip','netns','exec','awg-ci-web',sys.executable,'-m','http.server','18088','--bind','0.0.0.0','--directory',str(www)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        client=subprocess.Popen(['ip','netns','exec','awg-ci-client','/usr/local/bin/amneziawg-go','-f','awg-ci'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(50):
            if Path('/run/amneziawg/awg-ci.sock').exists():break
            time.sleep(.1)
        else:raise AssertionError('Client socket not ready')
        conf='\n'.join(line for line in original[uid].splitlines() if not line.startswith(('Address =','DNS =','MTU =')))
        conf=conf.replace('vpn.example.com:51820','172.30.77.1:51820')
        profile=work/'client.conf';profile.write_text(conf+'\n');profile.chmod(0o600)
        ns('awg-ci-client','/usr/local/bin/awg','setconf','awg-ci',str(profile))
        ns('awg-ci-client','ip','addr','add',users[0]['address']+'/32','dev','awg-ci')
        ns('awg-ci-client','ip','link','set','awg-ci','mtu','1280','up')
        ns('awg-ci-client','ip','route','add','198.18.77.0/30','dev','awg-ci')

        def curl(ok=True):
            for _ in range(12 if ok else 1):
                result=subprocess.run(['ip','netns','exec','awg-ci-client','curl','--silent','--show-error','--noproxy','*','--max-time','2','http://198.18.77.2:18088/'],capture_output=True,text=True)
                if ok and result.returncode==0:
                    assert result.stdout=='awg-real-tunnel-ok';return
                if not ok:
                    assert result.returncode!=0,'Revoked peer still has network access';return
                time.sleep(.5)
            raise AssertionError('Real AWG 3.1 tunnel failed')

        curl();helper({'op':'migration_sample'})
        state=helper({'op':'status'});u=next(u for u in state['users'] if u['id']==uid)
        assert u['up']>0 and u['down']>0,state
        assert 'private' not in json.dumps(state)
        helper({'op':'toggle','id':uid,'enabled':False});curl(ok=False)
        assert helper({'op':'key','id':other})['conf']==original[other]
        helper({'op':'toggle','id':uid,'enabled':True});curl()
        # Limits remove the live peer; relaxing the limit restores the same config.
        helper({'op':'limits','id':uid,'quota_gb':0,'expires':'2020-01-01','enforce':True});curl(ok=False)
        helper({'op':'limits','id':uid,'quota_gb':0,'expires':'','enforce':False});curl()
        helper({'op':'limits','id':uid,'quota_gb':1e-9,'expires':'','enforce':True});curl(ok=False)
        helper({'op':'limits','id':uid,'quota_gb':0,'expires':'','enforce':False});curl()
        # Client netns must not reach a private destination through the tunnel.
        ns('awg-ci-client','ip','route','add','10.77.0.1/32','dev','awg-ci')
        result=subprocess.run(['ip','netns','exec','awg-ci-client','ping','-c','1','-W','1','10.77.0.1'],capture_output=True)
        assert result.returncode!=0,'VPN client reached the server management network'
        # Unchanged peers retain their configuration across service restarts.
        run('systemctl','restart','amneziawg-server','relay-awg');wait_ready();curl()
        assert helper({'op':'key','id':uid})['conf']==original[uid]

        import manage
        rollback=manage.backup(include_programs=True)
        helper({'op':'rotate','id':uid});curl(ok=False)
        manage.restore_internal(rollback);wait_ready();curl()
        assert helper({'op':'key','id':uid})['conf']==original[uid]

        identity=work/'identity.txt';run('age-keygen','-o',str(identity))
        recipient=run('age-keygen','-y',str(identity)).stdout.strip()
        archive=work/'snapshot.age';manifest=encrypt(archive,recipient,layout());assert manifest['amnezia']
        helper({'op':'rotate','id':uid});curl(ok=False)
        helper({'op':'delete','id':other,'confirm_name':next(u['name'] for u in users if u['id']==other)})
        # Real production restore path, including persistent standby boot gates.
        with patch('builtins.input',return_value='ВОССТАНОВИТЬ'):
            restore([str(archive),'--identity',str(identity),'--standby'])
        for name in ('amneziawg-server','relay-awg'):
            run('systemctl','start',name)
            assert subprocess.run(['systemctl','is-active','--quiet',name]).returncode!=0
        from backup_routes import helper as migration
        migration({'op':'migration_resume','confirm':options['domain']})
        for _ in range(120):
            status=migration({'op':'migration_status'})
            if not status['busy']:break
            time.sleep(.5)
        assert status['phase']=='running',status
        wait_ready();curl()
        for uid,conf in original.items():assert helper({'op':'key','id':uid})['conf']==conf
        assert len(helper({'op':'status'})['users'])==2
        setup.health(options['domain'],public=False)
        print('PASS: AWG real tunnel, counters, revoke, limits, restart, standby and encrypted restore with original configs')
    finally:
        for process in (client,web):
            if process is not None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        for name in ('awg-ci-client','awg-ci-web'):subprocess.run(['ip','netns','del',name],capture_output=True)
        for name in ('awgc-host','awgw-host'):subprocess.run(['ip','link','del',name],capture_output=True)
