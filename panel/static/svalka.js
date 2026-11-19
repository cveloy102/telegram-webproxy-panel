'use strict';
const statusLine=document.querySelector('#svalka-status'),errorLine=document.querySelector('#svalka-error'),signup=document.querySelector('#svalka-signup'),list=document.querySelector('#svalka-users'),form=document.querySelector('#svalka-create');
let current=null;
async function api(payload){
  // Never hang on "Подключаюсь…": give up after 20 s and say what came back.
  const stop=new AbortController(),timer=setTimeout(()=>stop.abort(),20000);
  try{
    const r=await fetch('/control/api/svalka/'+(payload?'action':'state'),{signal:stop.signal,credentials:'same-origin',...(payload?{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf"]').content},body:JSON.stringify(payload)}:{})});
    let d;try{d=await r.json();}catch(e){throw Error('Панель ответила без данных (HTTP '+r.status+'). Обнови страницу или войди заново.');}
    if(!r.ok)throw Error(d.error||'Не удалось выполнить запрос (HTTP '+r.status+')');
    return d;
  }catch(e){if(e.name==='AbortError')throw Error('Сервер СВАЛКИ не ответил за 20 секунд.');throw e;}
  finally{clearTimeout(timer);}
}
function button(text,handler){const b=document.createElement('button');b.type='button';b.className='fc-button';b.textContent=text;b.onclick=handler;return b;}
function render(d){current=d;statusLine.textContent='Сервер работает.';statusLine.className='ok';document.querySelector('#svalka-address').textContent=d.domain?'https://'+d.domain:'—';signup.disabled=false;signup.textContent=d.signup?'Открыта — закрыть':'Закрыта — открыть';document.querySelector('#svalka-count').textContent=d.users.length;list.replaceChildren(...d.users.map(u=>{const li=document.createElement('li'),name=document.createElement('span'),actions=document.createElement('div');name.textContent=u.email;actions.append(button('Сменить пароль',()=>{const p=prompt('Новый пароль для '+u.email+' (от 8 символов):');if(p)run({op:'password',id:u.id,password:p},'Пароль изменён. На устройствах войди с новым паролем.');}),button('Удалить',()=>{if(confirm('Удалить аккаунт '+u.email+' и его записи на сервере? На устройствах записи останутся.'))run({op:'delete',id:u.id},'Аккаунт удалён.');}));li.append(name,actions);return li;}));if(!d.users.length){const li=document.createElement('li');li.className='empty';li.textContent='Аккаунтов пока нет.';list.replaceChildren(li);}}
async function run(payload,done){errorLine.textContent='';try{render(await api(payload));if(done)statusLine.textContent=done;return true;}catch(e){errorLine.textContent=e.message;statusLine.textContent=current?'Сервер работает.':'Нет связи с сервером СВАЛКИ.';statusLine.className=current?'ok':'';return false;}}
if(form){
  signup.onclick=()=>run({op:'signup',open:!current.signup},current&&!current.signup?'Регистрация открыта. Не забудь закрыть.':'Регистрация закрыта.');
  form.addEventListener('submit',async e=>{e.preventDefault();if(await run({op:'create',email:form.email.value.trim(),password:form.password.value},'Аккаунт создан. Войди им в приложениях.'))form.reset();});
  run();
}
