'use strict';
// Validate browser recovery keys against the real age implementation.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const {execFileSync,spawnSync}=require('node:child_process');
const fields={folder:{value:''},recipient:{value:''},automatic:{checked:true}};
const nodes=new Map(),blobs=[];
const node=selector=>{if(!nodes.has(selector))nodes.set(selector,{...fields,content:'csrf',listeners:{},addEventListener(type,handler){this.listeners[type]=handler;},value:'',textContent:''});return nodes.get(selector);};
class CapturedBlob extends Blob{constructor(...args){super(...args);blobs.push(this);}}
const context=vm.createContext({document:{querySelector:node,createElement:()=>({click(){}})},Blob:CapturedBlob,
  URL:{createObjectURL:()=> 'blob:test',revokeObjectURL(){}},crypto:require('node:crypto').webcrypto,atob,
  confirm:()=>true,setTimeout(){},setInterval(){},fetch:async()=>({ok:true,json:async()=>({folder:'',recipient:'',automatic:true,connected:false,running:false,pending:false,uploaded:0,error:''})})});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../panel/static/backups.js'),'utf8'),context);
(async()=>{
  await vm.runInContext('run()',context);
  const input={value:'synthetic-token'};
  await node('#backup-connect').listeners.submit({preventDefault(){},target:{token:input}});
  assert.equal(input.value,'');
  assert.match(node('#backup-connect-feedback').textContent,/Токен сохранён.*папку.*age1/);
  await vm.runInContext('run()',context);
  assert.match(node('#backup-connect-feedback').textContent,/Токен сохранён/,'Polling erased connection feedback');
  const originalFetch=context.fetch;
  context.fetch=async()=>({ok:false,json:async()=>({error:'Неполный токен Google Диска.'})});
  input.value='bad token';
  await node('#backup-connect').listeners.submit({preventDefault(){},target:{token:input}});
  assert.equal(input.value,'bad token');
  assert.equal(node('#backup-connect-feedback').textContent,'Неполный токен Google Диска.');
  context.fetch=originalFetch;
  await vm.runInContext('run()',context);
  assert.equal(node('#backup-connect-feedback').textContent,'Неполный токен Google Диска.','Polling erased the actionable error');
  await node('#backup-key').onclick();
  assert.equal(blobs.length,1,'Browser did not generate the recovery file');
  const identity=await blobs[0].text(),recipient=fields.recipient.value;
  assert.match(identity,/AGE-SECRET-KEY-1[0-9A-Z]+/);assert.match(recipient,/^age1[0-9a-z]{58}$/);
  assert.ok(identity.includes('# public key: '+recipient));
  if(spawnSync('age',['--version']).error){console.log('PASS: browser recovery key generation (age cross-check requires Linux dependencies)');return;}
  const temp=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'relay-key-test-'));
  try{
    const key=path.join(temp,'identity.txt');fs.writeFileSync(key,identity,{mode:0o600});
    const plain=Buffer.from('synthetic recovery payload');
    const encrypted=execFileSync('age',['--encrypt','--recipient',recipient],{input:plain});
    assert.deepEqual(execFileSync('age',['--decrypt','--identity',key],{input:encrypted}),plain);
    console.log('PASS: browser-generated X25519 recovery key encrypts/decrypts with age');
  }finally{fs.rmSync(temp,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
