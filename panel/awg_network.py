"""Fixed Linux network lifecycle. No shell commands or user-supplied hooks."""
import ipaddress
import json
from pathlib import Path
import signal
import subprocess
import time
from awg_control import Controller, INTERFACE


def run(*args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=10,**kw)


def firewall():
    # Restrict clients to public IPv4 destinations and isolate peers. IPv6 is
    # routed into the tunnel by clients but deliberately has no public egress.
    return '''table inet relay_awg {
 chain forward {
  type filter hook forward priority -10; policy accept;
  iifname "awg-relay" oifname "awg-relay" drop
  iifname "awg-relay" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } drop
  iifname "awg-relay" ip saddr 10.77.0.0/24 accept
  iifname "awg-relay" drop
  oifname "awg-relay" ct state established,related accept
  oifname "awg-relay" drop
 }
 chain input {
  type filter hook input priority -10; policy accept;
  iifname "awg-relay" drop
 }
 chain nat {
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr 10.77.0.0/24 oifname != "awg-relay" masquerade
 }
}
'''


def main():
    from migration_state import can_start
    if not can_start():raise RuntimeError('Сервер остановлен для переноса')
    existing=subprocess.run(['ip','link','show','dev',INTERFACE],capture_output=True)
    if existing.returncode==0:raise RuntimeError('Интерфейс '+INTERFACE+' уже занят; существующая сеть не изменена')
    Path('/run/amneziawg').mkdir(mode=0o700,exist_ok=True)
    routes=json.loads(run('ip','-j','-4','route','show','table','all').stdout)
    network=ipaddress.ip_network('10.77.0.0/24')
    for route in routes:
        dst=route.get('dst','default')
        if dst!='default' and route.get('dev')!=INTERFACE and ipaddress.ip_network(dst,strict=False).overlaps(network):
            raise RuntimeError('Подсеть 10.77.0.0/24 уже используется на VPS')
    engine=None
    def stop(signum,frame):raise SystemExit(0)
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        engine=subprocess.Popen(['/usr/local/bin/amneziawg-go','-f',INTERFACE])
        for _ in range(50):
            if engine.poll() is not None:raise RuntimeError('AmneziaWG завершилась при запуске')
            if Path('/run/amneziawg/'+INTERFACE+'.sock').exists():break
            time.sleep(.1)
        else:raise RuntimeError('Не появился сокет AmneziaWG')
        run('ip','address','replace','10.77.0.1/24','dev',INTERFACE)
        run('ip','-6','address','replace','fd77:77::1/64','dev',INTERFACE)
        run('ip','link','set','dev',INTERFACE,'mtu','1280','up')
        # Replace only our dedicated table; never flush the host firewall.
        subprocess.run(['nft','delete','table','inet','relay_awg'],capture_output=True)
        run('nft','-f','-',input=firewall())
        controller=Controller()
        with controller.db() as c:controller.apply(c)
        status=engine.wait()
        if status:raise RuntimeError('AmneziaWG остановилась')
    finally:
        if engine is not None and engine.poll() is None:
            engine.terminate()
            try:engine.wait(timeout=5)
            except subprocess.TimeoutExpired:engine.kill();engine.wait()
        subprocess.run(['ip','link','delete',INTERFACE],capture_output=True)
        subprocess.run(['nft','delete','table','inet','relay_awg'],capture_output=True)


if __name__=='__main__':main()
