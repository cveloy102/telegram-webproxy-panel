"""Root-only encrypted snapshot worker; the web process has fixed socket operations."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import sqlite3
import struct
import subprocess
import threading
import time
from backup_archive import layout, encrypt
from migration_state import blocked, mutation

PREFIX=os.getenv('RELAY_BACKUP_PREFIX','relay')
DATA=Path(os.getenv('RELAY_BACKUP_DATA','/var/lib/relay-backup'))
SOCKET=os.getenv('RELAY_BACKUP_SOCKET','/run/relay-backup/control.sock')
GROUP=os.getenv('RELAY_BACKUP_GROUP','relayadmin')

def atomic(path,value):
    temp=path.with_suffix('.new');temp.write_text(json.dumps(value,ensure_ascii=False));temp.chmod(0o600);temp.replace(path)

def folder_id(value):
    match=re.fullmatch(r'(?:https://drive\.google\.com/drive/(?:u/\d+/)?folders/)?([A-Za-z0-9_-]{10,150})(?:\?[^\s]*)?',str(value))
    if not match:raise ValueError('Нужна ссылка на папку Google Диска или её ID.')
    return match[1]

class Controller:
    def __init__(self,data=DATA,paths=None):
        self.data=Path(data);self.data.mkdir(parents=True,exist_ok=True);self.data.chmod(0o700)
        self.paths=paths or layout(PREFIX);self.lock=threading.RLock();self.running=False
        self.config=self.load('config.json',{'folder':'','recipient':'','automatic':True,'dataset':secrets.token_hex(8)})
        self.state=self.load('state.json',{'generation':0,'saved_generation':0,'uploaded':0,'error':'','last_attempt':0})
        self.fingerprint=None
        self.migration=None
    def load(self,name,default):
        p=self.data/name
        return json.loads(p.read_text()) if p.exists() else default
    def save(self):
        atomic(self.data/'config.json',self.config);atomic(self.data/'state.json',self.state)
    def dirty(self):
        with self.lock:
            self.state['generation']+=1;self.state['changed']=time.time();self.save()
    def status(self):
        with self.lock:return {'folder':self.config['folder'],'recipient':self.config['recipient'],'automatic':self.config['automatic'],'connected':(self.data/'rclone.conf').exists(),'running':self.running,'pending':self.state['generation']>self.state['saved_generation'],'uploaded':self.state['uploaded'],'error':self.state['error'],'file':self.state.get('file',''),'created':self.state.get('created',0)}
    def call(self,p):
        op=p.get('op')
        if op=='status':return self.status()
        if op=='migration_status':return self.migration.status()
        if op in ('migration_stop','migration_resume'):
            return self.migration.call(op.removeprefix('migration_'),p.get('confirm',''))
        if op=='changed' and blocked():return {'ok':True}
        if op in ('configure','connect') and self.migration and self.migration.busy:
            raise ValueError('Дождись завершения переноса перед изменением подключения Диска.')
        if op=='changed':self.dirty();return {'ok':True}
        if op=='configure':
            if self.running:raise ValueError('Дождись завершения текущей копии перед изменением настроек.')
            recipient=str(p.get('recipient','')).strip()
            if not re.fullmatch(r'age1[023456789acdefghjklmnpqrstuvwxyz]{58}',recipient):raise ValueError('Нужен публичный ключ age1… из файла восстановления.')
            # age performs checksum validation without receiving any private identity.
            result=subprocess.run(['age','-r',recipient],input=b'',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            if result.returncode:raise ValueError('Повреждён публичный ключ age.')
            with self.lock:
                self.config.update(folder=folder_id(p.get('folder','')),recipient=recipient,automatic=p.get('automatic') is True);self.dirty()
            return self.status()
        if op=='connect':
            if self.running:raise ValueError('Дождись завершения текущей копии перед переподключением Диска.')
            try:token=json.loads(p.get('token',''))
            except (ValueError,TypeError):raise ValueError('Вставь JSON-токен, выданный rclone authorize drive.') from None
            if not isinstance(token,dict) or not all(isinstance(token.get(k),str) and token[k] and '\n' not in token[k] and '\r' not in token[k] for k in ('access_token','refresh_token','token_type','expiry')):raise ValueError('Неполный токен Google Диска.')
            target=self.data/'rclone.conf';temp=target.with_suffix('.new')
            temp.write_text('[backup-drive]\ntype = drive\nscope = drive\ntoken = '+json.dumps(token,separators=(',',':'))+'\n');temp.chmod(0o600);temp.replace(target)
            self.dirty();return self.status()
        if op=='manual':
            if not self.ready():raise ValueError('Сначала укажи папку, публичный ключ и подключи Google Диск.')
            self.dirty();self.state['manual']=True;self.state['last_attempt']=0;self.save();return self.status()
        raise ValueError('Неизвестная операция.')
    def ready(self):return bool(self.config['folder'] and self.config['recipient'] and (self.data/'rclone.conf').exists())
    def rclone(self,*args):
        result=subprocess.run(['rclone',*args,'--config',str(self.data/'rclone.conf'),'--drive-root-folder-id',self.config['folder'],'--contimeout','15s','--timeout','60s','--retries','2'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240)
        if result.returncode:raise ValueError('Google Диск недоступен или доступ к папке отозван. Копия сохранена локально; загрузка будет повторена.')
        return result.stdout
    def snapshot(self,final=False):
        with self.lock:
            if self.running or (blocked() and not final):return
            self.running=True;generation=self.state['generation'];self.state['last_attempt']=time.time();self.save()
        try:
            # One epoch for controller mutations; accounting may advance by a few seconds.
            name='relay-'+self.config['dataset']+'-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+secrets.token_hex(3)+'.tar.gz.age'
            path=self.data/name
            metadata=encrypt(path,self.config['recipient'],self.paths,self.data)
            self.rclone('copyto',str(path),'backup-drive:'+name)
            remote=json.loads(self.rclone('lsjson','--stat','--hash','backup-drive:'+name))
            md5=hashlib.md5(path.read_bytes()).hexdigest()
            hashes={k.lower():v for k,v in remote.get('Hashes',{}).items()}
            if remote.get('Size')!=path.stat().st_size or hashes.get('md5')!=md5:raise ValueError('Google Диск не подтвердил целостность копии; загрузка будет повторена.')
            with self.lock:
                self.state.update(saved_generation=generation,uploaded=int(time.time()),created=metadata['created'],file=name,error='')
                if self.state['generation']==generation:self.state['manual']=False
                self.save()
            # Keep five encrypted local snapshots; cloud history is never deleted automatically.
            for old in sorted(self.data.glob('relay-*.tar.gz.age'),key=lambda x:x.stat().st_mtime,reverse=True)[5:]:old.unlink()
        except Exception as error:
            with self.lock:self.state['error']=str(error) if isinstance(error,ValueError) else 'Не удалось создать копию; задача будет повторена.';self.save()
        finally:
            with self.lock:self.running=False
    def signature(self):
        parts=[]
        for path in (self.paths['users'],self.paths['owner']/'auth.json',self.paths['hy2config']):
            if path.exists():parts.append(path.read_bytes())
        if self.paths.get('caddy') and self.paths['caddy'].exists():parts.append(self.paths['caddy'].read_bytes())
        for path,queries in [(self.paths['owner']/'panel.sqlite3',['SELECT salt,hash,totp,verified FROM owner','SELECT hash FROM recovery ORDER BY hash','SELECT * FROM settings']), (self.paths['hy2']/'hy2.sqlite3',['SELECT id,name,secret,enabled,quota,expires,enforce FROM users ORDER BY id','SELECT k,v FROM settings WHERE k NOT IN ("started","epoch") ORDER BY k'])]:
            if not path.exists():continue
            with contextlib.closing(sqlite3.connect(f'file:{path}?mode=ro',uri=True)) as c:
                for query in queries:
                    try:parts.append(repr(c.execute(query).fetchall()).encode())
                    except sqlite3.OperationalError:
                        # Schema-independent key metadata; excludes rapidly changing counters.
                        if 'FROM users' in query:
                            columns=[r[1] for r in c.execute('PRAGMA table_info(users)') if r[1] not in ('up','down','last_seen','online','updated','total_up','total_down')]
                            parts.append(repr(c.execute('SELECT '+','.join('"'+v+'"' for v in columns)+' FROM users ORDER BY id').fetchall()).encode())
                        else:raise
        for folder in (self.paths['site'],self.paths['hy2cover']):
            if folder.exists():
                for p in sorted(folder.rglob('*')):
                    if p.is_file() and not p.is_symlink():parts.extend([str(p.relative_to(folder)).encode(),p.read_bytes()])
        return hashlib.sha256(b'\0'.join(parts)).hexdigest()
    def tick(self):
        if blocked():return
        signature=self.signature()
        if signature!=self.fingerprint:self.fingerprint=signature;self.dirty()
        with self.lock:
            pending=self.state['generation']>self.state['saved_generation'];now=time.time()
            due=now-self.state['uploaded']>86400 or pending
            enabled=self.config['automatic'] or self.state.get('manual')
            retry=not self.state['error'] or now-self.state['last_attempt']>60
            settled=now-self.state.get('changed',0)>10
        if self.ready() and enabled and due and retry and settled:self.snapshot()

def serve():
    import grp,pwd
    controller=Controller();uid=pwd.getpwnam(GROUP).pw_uid
    from migration_control import Migration
    controller.migration=Migration(controller)
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(20)
            peer=struct.unpack('3i',self.request.getsockopt(__import__('socket').SOL_SOCKET,__import__('socket').SO_PEERCRED,12))[1]
            if peer not in (0,uid):return
            try:
                raw=self.rfile.readline(32769)
                if len(raw)>32768:raise ValueError('Слишком большой запрос.')
                payload=json.loads(raw)
                repair=payload.get('op') in ('configure','connect') and controller.migration.data['phase']=='error'
                if payload.get('op') in ('status','changed','migration_status','migration_stop','migration_resume'):
                    data=controller.call(payload)
                else:
                    with mutation(allow_error=repair):data=controller.call(payload)
                result={'ok':True,'data':data}
            except (ValueError,OSError) as e:result={'ok':False,'error':str(e)}
            except Exception:result={'ok':False,'error':'Служба копирования недоступна.'}
            self.wfile.write(json.dumps(result,ensure_ascii=False).encode()+b'\n')
    class Server(socketserver.ThreadingUnixStreamServer):daemon_threads=True
    Path(SOCKET).unlink(missing_ok=True)
    server=Server(SOCKET,Handler);os.chown(SOCKET,0,grp.getgrnam(GROUP).gr_gid);os.chmod(SOCKET,0o660)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    while True:
        try:controller.tick()
        except Exception:
            with controller.lock:controller.state['error']='Не удалось проверить изменения данных; проверка будет повторена.';controller.save()
        time.sleep(5)

if __name__=='__main__':os.umask(0o077);serve()
