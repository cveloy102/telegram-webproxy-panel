"""СВАЛКА sync server page: sign-up switch and accounts. Shares the panel's login, Origin and CSRF checks.

The panel talks to the local PocketBase over 127.0.0.1 as its own superuser (credentials written by the installer).
"""
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from flask import jsonify, redirect, render_template, request

CREDENTIALS=Path(os.getenv('RELAY_SVALKA_CREDENTIALS','/var/lib/relay-panel/svalka.json'))
API=os.getenv('RELAY_SVALKA_API','http://127.0.0.1:8090')
EMAIL=re.compile(r'[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}')

def installed():
    return CREDENTIALS.exists()

def call(method,path,body=None,token=None):
    data=None if body is None else json.dumps(body).encode()
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']=token
    req=urllib.request.Request(API+path,data=data,method=method,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=10) as response:
            raw=response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        try:detail=json.loads(error.read() or b'{}')
        except ValueError:detail={}
        fields=detail.get('data') or {}
        if 'email' in fields:raise ValueError('Такая почта уже есть или указана неверно.') from None
        if 'password' in fields:raise ValueError('Пароль: от 8 до 71 символа.') from None
        raise ValueError(detail.get('message') or 'Сервер СВАЛКИ ответил ошибкой '+str(error.code)) from None
    except (OSError,ValueError):raise OSError('Сервер СВАЛКИ не отвечает. Проверь службу: systemctl status svalka-sync') from None

def login():
    value=json.loads(CREDENTIALS.read_text())
    return call('POST','/api/collections/_superusers/auth-with-password',{'identity':value['email'],'password':value['password']})['token']

def setting(token,key):
    query=urllib.parse.urlencode({'filter':"key='"+key+"'",'perPage':1})
    items=call('GET','/api/collections/svalka_settings/records?'+query,token=token).get('items') or []
    return items[0] if items else None

def state():
    token=login()
    info=call('GET','/api/svalka/info')
    users=call('GET','/api/collections/users/records?perPage=200&sort=email&fields=id,email,created',token=token)
    domain=json.loads(CREDENTIALS.read_text()).get('domain','')
    return {'domain':domain,'signup':bool(info.get('signup')),
            'users':[{'id':u['id'],'email':u['email'],'created':u.get('created','')} for u in users.get('items',[])]}

def action(data):
    token=login();op=data.get('op')
    if op=='signup':
        value='true' if data.get('open') is True else 'false'
        record=setting(token,'signup')
        if record:call('PATCH','/api/collections/svalka_settings/records/'+record['id'],{'value':value},token)
        else:call('POST','/api/collections/svalka_settings/records',{'key':'signup','value':value},token)
    elif op=='create':
        email=str(data.get('email','')).strip().lower();password=str(data.get('password',''))
        if not EMAIL.fullmatch(email):raise ValueError('Нужна почта вида name@example.com (это просто логин, письма не отправляются).')
        if not 8<=len(password)<=71:raise ValueError('Пароль: от 8 до 71 символа.')
        call('POST','/api/collections/users/records',{'email':email,'password':password,'passwordConfirm':password,'verified':True},token)
    elif op in ('password','delete'):
        user=str(data.get('id',''))
        if not re.fullmatch(r'[a-z0-9]{15}',user):raise ValueError('Неизвестный аккаунт.')
        if op=='delete':call('DELETE','/api/collections/users/records/'+user,token=token)
        else:
            password=str(data.get('password',''))
            if not 8<=len(password)<=71:raise ValueError('Пароль: от 8 до 71 символа.')
            call('PATCH','/api/collections/users/records/'+user,{'password':password,'passwordConfirm':password},token)
    else:raise ValueError('Неизвестная операция.')
    return state()

def register(app,authorized,csrf):
    app.jinja_env.globals['svalka_installed']=installed

    @app.get('/control/svalka')
    def svalka_home():
        if not authorized():return redirect('/control/')
        return render_template('svalka.html',csrf=csrf(),installed=installed())

    @app.get('/control/api/svalka/state')
    def svalka_state():
        if not installed():return jsonify(error='Сервер СВАЛКИ не установлен. Добавь его повторным запуском установщика.'),404
        try:return jsonify(state())
        except (OSError,ValueError) as error:return jsonify(error=str(error)),503

    @app.post('/control/api/svalka/action')
    def svalka_action():
        if not installed():return jsonify(error='Сервер СВАЛКИ не установлен.'),404
        try:return jsonify(action(request.get_json(silent=True)))
        except OSError as error:return jsonify(error=str(error)),503
        except ValueError as error:return jsonify(error=str(error)),400
