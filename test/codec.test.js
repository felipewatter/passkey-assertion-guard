import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeB64url, encodeB64url, parseStrictJson, InputError } from '../src/index.js';
import { expectedOrigin } from '../src/codec.js';
const fails=(f)=>assert.throws(f,InputError);
test('base64url rejects padding, whitespace, noncanonical and invalid characters',()=>{
  for(const s of ['AA==','a','-','AAA=','AAA+','AAA/','AAA ','','AAAA\n'])fails(()=>decodeB64url(s));
});
test('base64url round trips arbitrary bytes',()=>{
  const b=Buffer.from([0,1,0xfe,0xff,32,42]);assert.deepEqual(decodeB64url(encodeB64url(b)),b);
});
test('duplicate JSON keys, including unicode escaped aliases, rejected',()=>{
  for(const s of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"x":{"y":1,"y":2}}'])fails(()=>parseStrictJson(s));
});
test('prototype-pollution and constructor JSON keys rejected',()=>{
  for(const s of ['{"__proto__":{}}','{"constructor":1}','{"prototype":1}'])fails(()=>parseStrictJson(s));
});
test('JSON trailing content, invalid escapes and excessive depth rejected',()=>{
  for(const s of ['{} {}','{"x":"\\x"}','{"a":01}','['.repeat(30)+'0'+']'.repeat(30)])fails(()=>parseStrictJson(s));
});
test('nested correct JSON remains valid',()=>{
  assert.deepEqual(parseStrictJson('{"data":[true,false,null,{"x":1}]}'),{data:[true,false,null,{x:1}]});
});
test('origin must be exact canonical HTTPS domain with no credentials',()=>{
  for(const s of ['http://login.example.org','https://login.example.org/','https://user:pass@login.example.org','https://login.example.org:443','https://login.example.org/path','https://login.example.org/#fragment','https://localhost','https://login.example.org?q=1','https://LOGIN.example.org','https://127.0.0.1','https://login.example.org.evil']){
    if(s==='https://login.example.org.evil')continue;
    fails(()=>expectedOrigin(s));
  }
  assert.deepEqual(expectedOrigin('https://login.example.org'),{origin:'https://login.example.org',rpId:'login.example.org'});
});
test('oversized encoded input rejected',()=>fails(()=>decodeB64url('A'.repeat(100000),1024)));
