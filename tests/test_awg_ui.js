'use strict';
// Exercise selection and telemetry failure without a browser or VPN service.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const elements=new Map();
const element=selector=>{
  if(!elements.has(selector))elements.set(selector,{content:'csrf',innerHTML:'',textContent:'',disabled:false,open:false,addEventListener(){},replaceChildren(){},close(){this.open=false;},showModal(){this.open=true;}});
  return elements.get(selector);
};
const user=(id,name,online)=>({id,name,online,enabled:true,allowed:true,grp:'Семья',address:'10.77.0.2',today:100,month:200,up:50,down:150,created:1,last:1,expires:0,quota:0,enforce:false,history:[]});
let response={host:'vpn.example.com',port:51820,paused:false,updated:1,telemetry_ok:true,users:[user('one','Первый',true),user('two','Второй <тест>',false)]};
let fail=false;
const context=vm.createContext({document:{querySelector:element},Intl,Date,Number,String,Set,Blob,URL,JSON,Error,console,setInterval(){},fetch:async()=>{if(fail)throw Error('Нет связи');return {ok:true,json:async()=>response};}});
vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../panel/static/amnezia.js'),'utf8'),context);
(async()=>{
  await vm.runInContext('refresh()',context);
  assert.match(element('#detail').innerHTML,/Первый/);
  assert.match(element('#users').innerHTML,/● Онлайн/);
  element('#users').onclick({target:{closest:()=>({dataset:{user:'two'}})}});
  assert.match(element('#detail').innerHTML,/Второй &lt;тест&gt;/);
  assert.match(element('#detail').innerHTML,/○ Офлайн/);
  await vm.runInContext('refresh()',context);
  assert.match(element('#detail').innerHTML,/Второй &lt;тест&gt;/);
  fail=true;
  await vm.runInContext('refresh()',context);
  assert.match(element('#detail').innerHTML,/Нет свежих данных/);
  assert.doesNotMatch(element('#users').innerHTML,/● Онлайн/);
  assert.equal(element('#new').disabled,true);
  fail=false;response={...response,telemetry_ok:true,users:[user('one','Первый',true)]};
  await vm.runInContext('refresh()',context);
  assert.match(element('#detail').innerHTML,/Первый/);
  response={...response,users:[]};
  await vm.runInContext('refresh()',context);
  assert.match(element('#detail').innerHTML,/Выдай первый ключ/);
  console.log('PASS: AWG details selection, escaped names, offline/stale telemetry and deleted selection');
})().catch(error=>{console.error(error);process.exitCode=1;});
