'use strict';
const $=id=>document.getElementById(id);
let busy=false,current=null,loaded=false;
async function api(payload){
  const response=await fetch('/control/api/cascade/'+(payload?'action':'state'),payload?{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf"]').content},body:JSON.stringify(payload)}:{});
  const result=await response.json();if(!response.ok)throw Error(result.error||'Запрос не выполнен');return result;
}
function render(state){
  current=state;
  $('cascade-health').textContent=state.error||'';
  $('cascade-state').textContent=state.enabled?'Каскад включён. Выход клиентов разрешён только через зарубежный узел.':state.configured?'Узел подключён, каскад выключен. Клиенты выходят через RU.':'Каскад не настроен. Клиенты выходят через RU.';
  $('cascade-pairing').value=state.pairing?JSON.stringify(state.pairing):'Сначала сохрани адрес выходного сервера.';
  const check=state.last_check;
  $('cascade-check').textContent=check?'Последняя проверка: '+new Date(check.time*1000).toLocaleString()+' — '+(check.ok?'успешно, IP '+check.ip:'выход не подтверждён'):(state.handshake?'Последнее соединение: '+new Date(state.handshake*1000).toLocaleString()+'. Выполни проверку выхода.':'Выход через туннель ещё не подтверждён.');
  if(!loaded){if(state.host){$('cascade-name').value=state.name;$('cascade-host').value=state.host;$('cascade-port').value=state.port;}loaded=true;}
  for(const control of $('cascade-config').elements)control.disabled=busy||state.enabled;
  for(const control of $('cascade-pair').elements)control.disabled=busy||state.enabled||!state.pairing;
  $('cascade-test').disabled=busy||!state.configured;
  $('cascade-enable').disabled=busy||!state.configured||state.enabled;
  $('cascade-disable').disabled=busy||!state.enabled;
}
async function refresh(){if(busy)return;try{render(await api());}catch(error){$('cascade-error').textContent=error.message;for(const button of document.querySelectorAll('.fc-main button'))button.disabled=true;}}
async function act(payload,message){
  if(busy)return;busy=true;if(current)render(current);$('cascade-error').textContent='';$('cascade-message').textContent='Выполняется…';
  try{render(await api(payload));$('cascade-message').textContent=message;}
  catch(error){$('cascade-message').textContent='';$('cascade-error').textContent=error.message;}
  finally{busy=false;await refresh();}
}
$('cascade-config').addEventListener('submit',event=>{event.preventDefault();act({op:'configure',name:$('cascade-name').value.trim(),host:$('cascade-host').value.trim(),port:Number($('cascade-port').value)},'Адрес сохранён. Передай данные RU в установщик выходного узла.');});
$('cascade-pair').addEventListener('submit',event=>{event.preventDefault();try{const reply=JSON.parse($('cascade-reply').value);act({op:'pair',reply},'Ответ добавлен. Проверь выход перед включением.');}catch(error){$('cascade-error').textContent='Не удалось прочитать JSON. Вставь ответ установщика целиком.';}});
$('cascade-test').addEventListener('click',()=>act({op:'check'},'Проверка выхода прошла.'));
$('cascade-enable').addEventListener('click',()=>{if(confirm('Направить весь трафик клиентов через зарубежный сервер? Текущие подключения прервутся.'))act({op:'enable'},'Каскад включён. Переподключи VPN.');});
$('cascade-disable').addEventListener('click',()=>{if(confirm('Разрешить клиентам прямой выход через российский IP? Текущие подключения прервутся.'))act({op:'disable',confirm:'DIRECT'},'Каскад выключен. Прямой выход через RU разрешён.');});
refresh();setInterval(refresh,10000);
