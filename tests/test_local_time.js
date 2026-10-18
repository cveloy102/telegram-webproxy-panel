'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
// Execute the actual formatter used by each page with different browser time zones.
for(const file of ['panel','hysteria','amnezia']){
  const source=fs.readFileSync(path.join(__dirname,'../panel/static/'+file+'.js'),'utf8');
  const declaration=source.split('\n').find(line=>line.startsWith('const date='));
  assert.ok(declaration);
  for(const [zone,day,hour] of [['Asia/Omsk','18.10','02:05'],['America/New_York','17.10','16:05'],['Europe/Berlin','17.10','22:05']]){
    const browserIntl={DateTimeFormat:function(locale,options){return new Intl.DateTimeFormat(locale,{timeZone:zone,...options});}};
    const context=vm.createContext({Intl:browserIntl,Date});
    vm.runInContext(declaration,context);
    const result=vm.runInContext('date('+Date.UTC(2026,9,17,20,5)/1000+')',context);
    assert.ok(result.includes(day)&&result.includes(hour),`${file} ignored browser zone ${zone}: ${result}`);
  }
}
console.log('PASS: Telegram, Hysteria and AWG display browser-local dates across a midnight boundary');
