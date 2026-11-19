'use strict';
const statusLine=document.querySelector('#svalka-status'),errorLine=document.querySelector('#svalka-error'),signup=document.querySelector('#svalka-signup'),list=document.querySelector('#svalka-users'),form=document.querySelector('#svalka-create');
let current=null;
async function api(payload){const r=await fetch('/control/api/svalka/'+(payload?'action':'state'),payload?{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf"]').content},body:JSON.stringify(payload)}:{});const d=await r.json();if(!r.ok)throw Error(d.error||'Не удалось выполнить запрос');return d;}
function button(text,handler){const b=document.createElement('button');b.type='button';b.className='fc-button';b.textContent=text;b.onclick=handler;return b;}
function render(d){current=d;statusLine.textContent='Сервер работает.';document.querySelector('#svalka-address').textContent=d.domain?'https://'+d.domain:'—';signup.disabled=false;signup.textContent=d.signup?'Открыта — закрыть':'Закрыта — открыть';document.querySelector('#svalka-count').textContent=d.users.length;list.replaceChildren(...d.users.map(u=>{const li=document.createElement('li'),name=document.createElement('span'),actions=document.createElement('div');name.textContent=u.email;actions.append(button('Сменить пароль',()=>{const p=prompt('Новый пароль для '+u.email+' (от 8 символов):');if(p)run({op:'password',id:u.id,password:p},'Пароль изменён. На устройствах войди с новым паролем.');}),button('Удалить',()=>{if(confirm('Удалить аккаунт '+u.email+' и его записи на сервере? На устройствах записи останутся.'))run({op:'delete',id:u.id},'Аккаунт удалён.');}));li.append(name,actions);return li;}));}
async function run(payload,done){errorLine.textContent='';try{render(await api(payload));if(done)statusLine.textContent=done;return true;}catch(e){errorLine.textContent=e.message;statusLine.textContent=current?'Сервер работает.':'Нет связи с сервером СВАЛКИ.';return false;}}
if(form){
  signup.onclick=()=>run({op:'signup',open:!current.signup},current&&!current.signup?'Регистрация открыта. Не забудь закрыть.':'Регистрация закрыта.');
  form.addEventListener('submit',async e=>{e.preventDefault();if(await run({op:'create',email:form.email.value.trim(),password:form.password.value},'Аккаунт создан. Войди им в приложениях.'))form.reset();});
  run();
}
