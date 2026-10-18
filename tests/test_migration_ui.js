'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const nodes=new Map();
const node=selector=>{if(!nodes.has(selector))nodes.set(selector,{content:'csrf',disabled:true,textContent:'',addEventListener(){}});return nodes.get(selector);};
const base={phase:'running',busy:false,services:['Telegram','Hysteria','AmneziaWG'],backup:{uploaded:0},error:''};
let fail=false;
const context=vm.createContext({document:{querySelector:node},console,Date,setInterval(){},fetch:async()=>{if(fail)throw Error('unavailable');return {ok:true,json:async()=>base};}});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../panel/static/migration.js'),'utf8'),context);
(async()=>{
  await vm.runInContext('refresh()',context);
  for(const [phase,stop,resume] of [['running',false,true],['freezing',true,true],['resuming',true,true],['standby',true,false],['stopped',true,false],['error',false,false]]){
    vm.runInContext('render('+JSON.stringify({...base,phase})+')',context);
    assert.equal(node('#migration-stop').disabled,stop,phase+' stop');
    assert.equal(node('#migration-resume').disabled,resume,phase+' resume');
  }
  fail=true;await vm.runInContext('refresh()',context);
  assert.equal(node('#migration-stop').disabled,true);assert.equal(node('#migration-resume').disabled,true);
  assert.match(node('#migration-error').textContent,/unavailable/);
  console.log('PASS: migration controls reflect every phase and disable operations on stale/error data');
})().catch(error=>{console.error(error);process.exitCode=1;});
