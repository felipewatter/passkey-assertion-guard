import test from 'node:test';
import assert from 'node:assert/strict';
import {CeremonyStore, demoAuthenticator, VerificationError} from '../src/index.js';
const origin='https://login.example.org';

test('a credential cannot use a signed assertion for another credential challenge',()=>{
  const a=demoAuthenticator({origin}), b=demoAuthenticator({origin});
  const store=new CeremonyStore({origin});
  store.enrollTrustedCredential(a.credential);
  store.enrollTrustedCredential(b.credential);
  const challenge=store.issueChallenge(a.credential.id);
  assert.throws(()=>store.authenticate(b.signAssertion(challenge)),VerificationError);
  assert.equal(store.authenticate(a.signAssertion(challenge,{signCount:1})).verified,true);
});

test('each challenge is consumed exactly once, with independently advancing counters',()=>{
  const a=demoAuthenticator({origin});
  const store=new CeremonyStore({origin});
  store.enrollTrustedCredential(a.credential);
  const first=store.issueChallenge(a.credential.id);
  const second=store.issueChallenge(a.credential.id);
  assert.notEqual(first,second);
  assert.equal(store.authenticate(a.signAssertion(first,{signCount:1})).verified,true);
  assert.throws(()=>store.authenticate(a.signAssertion(first,{signCount:2})),VerificationError);
  assert.equal(store.authenticate(a.signAssertion(second,{signCount:2})).signCount,2);
  assert.equal(store.getCredential(a.credential.id).signCount,2);
});

test('expired one-time challenge is rejected but a fresh challenge can authenticate',()=>{
  let time=1700000000000;
  const a=demoAuthenticator({origin});
  const store=new CeremonyStore({origin,now:()=>time});
  store.enrollTrustedCredential(a.credential);
  const old=store.issueChallenge(a.credential.id,{ttlMs:1000});
  time+=1001;
  assert.throws(()=>store.authenticate(a.signAssertion(old)),VerificationError);
  const fresh=store.issueChallenge(a.credential.id,{ttlMs:1000});
  assert.equal(store.authenticate(a.signAssertion(fresh)).verified,true);
});

test('a valid signature from a different origin cannot advance trusted sign counter',()=>{
  const a=demoAuthenticator({origin});
  const store=new CeremonyStore({origin});
  store.enrollTrustedCredential(a.credential);
  const challenge=store.issueChallenge(a.credential.id);
  assert.throws(()=>store.authenticate(a.signAssertion(challenge,
    {originOverride:'https://attacker.example.org',signCount:99})),VerificationError);
  assert.equal(store.getCredential(a.credential.id).signCount,0);
  assert.equal(store.authenticate(a.signAssertion(challenge,{signCount:1})).verified,true);
});
