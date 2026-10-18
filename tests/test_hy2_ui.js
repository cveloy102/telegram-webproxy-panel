'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
let click;
const nodes=new Map();
function node(selector){
  if(!nodes.has(selector))nodes.set(selector,{content:'csrf',innerHTML:'',textContent:'',open:false,
    elements:{port:{value:''},cover:{value:''},cover_url:{value:''},obfs:{checked:false}},
    addEventListener(){},replaceChildren(){},showModal(){this.open=true;},close(){this.open=false;}});
  return nodes.get(selector);
}
const expires=Date.UTC(2026,9,18,23,59,59)/1000;
const response={users:[{id:'one',name:'Friend',grp:'Семья',enabled:true,allowed:true,online:false,connections:0,
  history:[],today:0,month:0,up:0,down:0,last:0,expires,quota:0,enforce:true,suffix:'1234'}],
  events:[],telemetry_ok:true,updated:1,started:1,paused:false,
  settings:{host:'hy.example.com',port:24443,cover:'page',cover_url:'',obfs:false},
  metrics:{cpu:0,memory_used:0,memory_total:0,service_memory:0,certificate_expires:0}};
class FixedDate extends Date{static now(){return Date.UTC(2026,9,18,20);}}
const context=vm.createContext({document:{querySelector:node,querySelectorAll:()=>[],addEventListener:(name,handler)=>{if(name==='click')click=handler;}},
  Date:FixedDate,Intl,console,setInterval(){},fetch:async()=>({ok:true,json:async()=>response})});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../panel/static/hysteria.js'),'utf8'),context);
(async()=>{
  await vm.runInContext('refresh()',context);
  await click({target:{closest:()=>({dataset:{limits:'one'}})}});
  assert.match(node('#dialogbody').innerHTML,/value="2026-10-18"/,'Expiry editor shifted the stored UTC date');
  assert.match(node('#dialogbody').innerHTML,/Срок считается по UTC;/);
  assert.match(node('#detail').innerHTML,/2026-10-18<\/span>/,'Graph shifted to the next UTC day');
  assert.match(node('#started').textContent,/местное время/);
  console.log('PASS: Hysteria expiry editor and traffic graph preserve the stored UTC calendar');
})().catch(error=>{console.error(error);process.exitCode=1;});
