"""Real systemd: restarting relay-cascade must not fail its AWG engine on a missing runtime folder.

Builds a renamed copy of the generated engine unit and relay-cascade drop-in (with a sleeping stand-in
process) and restarts the pair. The pre-fix variant is run first to show the test reproduces the failure.
"""
import os
from pathlib import Path
import subprocess
import sys
import time

if os.geteuid()!=0:raise SystemExit('root only')
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'panel'))
from cascade_network import engine_unit,TRANSPORT_DROPIN

UNITS=Path('/etc/systemd/system')


def rename(text):
    return (text.replace('/run/relay-cascade','/run/smoke-cascade').replace('/run/amneziawg','/run/smoke-awg')
            .replace('relay-cascade-engine.service','smoke-engine.service').replace('relay-cascade.service','smoke-cascade.service')
            .replace('RuntimeDirectory=relay-cascade','RuntimeDirectory=smoke-cascade'))


def install(fixed):
    engine=rename(engine_unit('relay-cascade.service'))
    engine='\n'.join(line for line in engine.splitlines() if not line.startswith('ConditionPathExists=')
                     and not line.startswith('NotifyAccess') and not line.startswith('CapabilityBoundingSet'))+'\n'
    engine=engine.replace('Type=notify','Type=simple')
    engine=engine.replace(engine[engine.index('ExecStart=/usr/bin/python3'):].split('\n')[0],'ExecStart=/usr/bin/sleep infinity')
    dropin=rename(TRANSPORT_DROPIN)
    if not fixed:
        engine='\n'.join(line for line in engine.splitlines() if not line.startswith('ExecStartPre='))+'\n'
        dropin=dropin.replace('RuntimeDirectoryPreserve=yes\n','')
    (UNITS/'smoke-engine.service').write_text(engine)
    (UNITS/'smoke-cascade.service').write_text('[Unit]\nDescription=smoke cascade\n[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\nRuntimeDirectory=smoke-cascade\nRuntimeDirectoryMode=0750\n')
    folder=UNITS/'smoke-cascade.service.d';folder.mkdir(exist_ok=True);(folder/'awg-transport.conf').write_text(dropin)
    Path('/run/smoke-awg').mkdir(exist_ok=True)
    subprocess.run(['systemctl','daemon-reload'],check=True)


def restart():
    subprocess.run(['systemctl','reset-failed','smoke-engine','smoke-cascade'],capture_output=True)
    subprocess.run(['systemctl','restart','smoke-cascade'],capture_output=True)
    time.sleep(1)
    out=subprocess.run(['systemctl','show','smoke-engine','-p','NRestarts','-p','Result','-p','ActiveState'],capture_output=True,text=True).stdout
    return dict(line.split('=',1) for line in out.split())


try:
    install(fixed=False)
    subprocess.run(['systemctl','start','smoke-cascade'],check=True);time.sleep(1)
    before=restart()
    print('pre-fix engine after restart:',before)
    assert before['Result']!='success' or before['NRestarts']!='0',('the stand-in did not reproduce the 226/NAMESPACE failure',before)
    subprocess.run(['systemctl','stop','smoke-cascade','smoke-engine'],capture_output=True)
    install(fixed=True)
    subprocess.run(['systemctl','start','smoke-cascade'],check=True);time.sleep(1)
    for attempt in range(3):
        state=restart()
        print('fixed engine after restart',attempt+1,':',state)
        assert state['Result']=='success' and state['ActiveState']=='active' and state['NRestarts']=='0',state
    assert Path('/run/smoke-cascade').is_dir()
    print('cascade restart smoke: OK')
finally:
    subprocess.run(['systemctl','stop','smoke-cascade','smoke-engine'],capture_output=True)
    for name in ('smoke-engine.service','smoke-cascade.service'):(UNITS/name).unlink(missing_ok=True)
    (UNITS/'smoke-cascade.service.d'/'awg-transport.conf').unlink(missing_ok=True)
    subprocess.run(['systemctl','daemon-reload'])
