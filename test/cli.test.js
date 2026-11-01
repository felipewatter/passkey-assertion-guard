import test from 'node:test';
import assert from 'node:assert/strict';
import { main } from '../src/cli.js';
const logger=()=>{const output=[],errors=[];return {log:x=>output.push(x),error:x=>errors.push(x),output,errors};};
test('CLI help describes scope and limitations',async()=>{
  const log=logger();assert.equal(await main(['--help'],log),0);
  assert.match(log.output[0],/does NOT implement browser credential registration/);
});
test('CLI version matches package version',async()=>{
  const log=logger();assert.equal(await main(['--version'],log),0);
  assert.equal(log.output[0],'0.1.0');
});
test('CLI rejects unsupported commands without exposing input',async()=>{
  const log=logger();assert.equal(await main(['verify','PRIVATE_STRING'],log),2);
  assert.equal(log.errors[0].includes('PRIVATE_STRING'),false);
});
test('CLI demo succeeds with a positive assertion and negative challenges',async()=>{
  const log=logger();assert.equal(await main(['demo'],log),0);
  assert.equal(log.output.length,4);assert.match(log.output[1],/consumed challenge rejected/);
});
