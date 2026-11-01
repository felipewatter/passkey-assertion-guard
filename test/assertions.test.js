import test from 'node:test';
import assert from 'node:assert/strict';
import { CeremonyStore, demoAuthenticator, verifyAssertion, validateCredential, InputError, VerificationError, encodeB64url, decodeB64url } from '../src/index.js';

const ORIGIN='https://login.example.org';
function setup({algorithm='ES256',flags=5,requireUserVerification=true,allowBackup=true,now=()=>Date.now()}={}){
  const authenticator=demoAuthenticator({origin:ORIGIN,algorithm,flags});
  const store=new CeremonyStore({origin:ORIGIN,requireUserVerification,allowBackup,now});
  store.enrollTrustedCredential(authenticator.credential);
  const id=authenticator.credential.id;
  const challenge=store.issueChallenge(id);
  return {authenticator,store,id,challenge,assertion:(config={})=>authenticator.signAssertion(challenge,config)};
}
const fails=(fn)=>assert.throws(fn, e=>e instanceof InputError||e instanceof VerificationError);

test('ES256 valid assertion, UV and UP accepted and sign counter advanced',()=>{
  const f=setup();const r=f.store.authenticate(f.assertion({signCount:5}));
  assert.equal(r.verified,true);assert.equal(r.userPresent,true);assert.equal(r.userVerified,true);
  assert.equal(f.store.getCredential(f.id).signCount,5);assert.equal(r.counterSupported,true);
});
test('Ed25519 EdDSA assertion accepted',()=>{
  const f=setup({algorithm:'EdDSA'});assert.equal(f.store.authenticate(f.assertion()).verified,true);
});
test('valid 0 counters are admitted with reduced counter assurance',()=>{
  const f=setup();const r=f.store.authenticate(f.assertion({signCount:0}));
  assert.equal(r.counterSupported,false);
});
test('reused challenge cannot authenticate twice even with fresh counter',()=>{
  const f=setup();f.store.authenticate(f.assertion());fails(()=>f.store.authenticate(f.assertion({signCount:2})));
});
test('wrong private key cannot impersonate trusted credential',()=>{
  const f=setup();const other=demoAuthenticator({origin:ORIGIN,credentialId:f.id});
  fails(()=>f.store.authenticate(other.signAssertion(f.challenge)));
});
test('bad signature rejected',()=>{
  const f=setup();const a=f.assertion();const sig=decodeB64url(a.response.signature);sig[0]^=0x40;
  a.response.signature=encodeB64url(sig);fails(()=>f.store.authenticate(a));
});
test('payload changes after signing rejected',()=>{
  const f=setup();const a=f.assertion();const bytes=decodeB64url(a.response.clientDataJSON);
  bytes[5]^=1;a.response.clientDataJSON=encodeB64url(bytes);fails(()=>f.store.authenticate(a));
});
test('incorrect challenge is rejected with valid signature',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.authenticator.signAssertion(encodeB64url(Buffer.alloc(32,8)))));
});
test('challenge missing in store rejected with valid signature',()=>{
  const f=setup();const issued=encodeB64url(Buffer.alloc(32,7));fails(()=>f.store.authenticate(f.authenticator.signAssertion(issued)));
});
test('correctly signed origin from another site rejected',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({originOverride:'https://evil.example.org'})));
});
test('correctly signed RP ID hash of a different domain rejected',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({rpIdOverride:'evil.example.org'})));
});
test('correctly signed wrong client type rejected',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({clientDataOverrides:{type:'webauthn.create'}})));
});
test('correctly signed crossOrigin true rejected',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({clientDataOverrides:{crossOrigin:true}})));
});
test('unknown client JSON property rejected fail-closed',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({clientDataOverrides:{extra:'val'}})));
});
test('missing User Presence rejected even with good signature',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({authDataFlags:4})));
});
test('required User Verification rejected when absent',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({authDataFlags:1})));
});
test('user verification can be disabled explicitly for weaker policy',()=>{
  const f=setup({flags:1,requireUserVerification:false});assert.equal(f.store.authenticate(f.assertion()).userVerified,false);
});
test('backup eligibility flag must match server stored credential',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({authDataFlags:13})));
});
test('backed-up passkey denied when policy forbids backups',()=>{
  const f=setup({flags:13,allowBackup:false});fails(()=>f.store.authenticate(f.assertion({authDataFlags:29})));
});
test('backed-up passkey accepted when policy allows it',()=>{
  const f=setup({flags:13,allowBackup:true});const r=f.store.authenticate(f.assertion({authDataFlags:29}));assert.equal(r.backupState,true);
});
test('invalid backup state BS without BE rejected',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({authDataFlags:21})));
});
test('reserved and attestation/extension flags rejected',()=>{
  for(const flag of [7,37,69,133]){const f=setup();fails(()=>f.store.authenticate(f.assertion({authDataFlags:flag})));}
});
test('authenticator data extended beyond 37 bytes rejected',()=>{
  const f=setup();fails(()=>f.store.authenticate(f.assertion({appendAuthData:Buffer.alloc(3)})));
});
test('signature counter cannot go backwards',()=>{
  const f=setup();f.store.authenticate(f.assertion({signCount:7}));
  const next=f.store.issueChallenge(f.id);fails(()=>f.store.authenticate(f.authenticator.signAssertion(next,{signCount:6})));
});
test('same sign counter cannot be reused across new challenge',()=>{
  const f=setup();f.store.authenticate(f.assertion({signCount:7}));
  const next=f.store.issueChallenge(f.id);fails(()=>f.store.authenticate(f.authenticator.signAssertion(next,{signCount:7})));
});
test('counter cannot reset to zero if it was previously nonzero',()=>{
  const f=setup();f.store.authenticate(f.assertion({signCount:7}));
  const next=f.store.issueChallenge(f.id);fails(()=>f.store.authenticate(f.authenticator.signAssertion(next,{signCount:0})));
});
test('valid counter increment after new challenge succeeds',()=>{
  const f=setup();f.store.authenticate(f.assertion({signCount:7}));
  const next=f.store.issueChallenge(f.id);assert.equal(f.store.authenticate(f.authenticator.signAssertion(next,{signCount:8})).signCount,8);
});
test('expired challenge is rejected',()=>{
  let now=100000;const f=setup({now:()=>now});now+=300000;
  fails(()=>f.store.authenticate(f.assertion()));
});
test('revocation deletes credential and any pending challenges',()=>{
  const f=setup();f.store.revokeCredential(f.id);
  assert.equal(f.store.getCredential(f.id),null);fails(()=>f.store.authenticate(f.assertion()));
});
test('enrollment cannot replace previously trusted credential by same id',()=>{
  const f=setup();fails(()=>f.store.enrollTrustedCredential(f.authenticator.credential));
});
test('untrusted credential ID cannot obtain challenges',()=>{
  const f=setup();fails(()=>f.store.issueChallenge(demoAuthenticator({origin:ORIGIN}).credential.id));
});
test('repeated failed checks exhaust per-challenge attempt budget',()=>{
  const f=setup();const fake=demoAuthenticator({origin:ORIGIN,credentialId:f.id});
  for(let i=0;i<6;i++)fails(()=>f.store.authenticate(fake.signAssertion(f.challenge,{signCount:i+1})));
  fails(()=>f.store.authenticate(f.assertion()));
});
test('credential object is cloned; caller cannot mutate trusted public key',()=>{
  const f=setup();const copy=f.store.getCredential(f.id);copy.publicKeyJwk.x='not-trusted';
  assert.equal(f.store.authenticate(f.assertion()).verified,true);
});
test('challenge length must be at least 32 random bytes',()=>{
  const f=setup();fails(()=>verifyAssertion({assertion:f.assertion(),credential:f.authenticator.credential,challenge:encodeB64url(Buffer.alloc(16)),origin:ORIGIN}));
});
test('wrong rawId rejected',()=>{
  const f=setup();const a=f.assertion();a.rawId=encodeB64url(Buffer.alloc(32,1));fails(()=>f.store.authenticate(a));
});
test('wrong type rejected',()=>{
  const f=setup();const a=f.assertion();a.type='private-key';fails(()=>f.store.authenticate(a));
});
test('mismatched credential id rejected',()=>{
  const f=setup();const a=f.assertion();a.id=encodeB64url(Buffer.alloc(32,1));fails(()=>f.store.authenticate(a));
});
test('unregistered key material is not trusted from assertion response',()=>{
  const f=setup();const a=f.assertion();a.response.publicKeyJwk=f.authenticator.credential.publicKeyJwk;
  fails(()=>f.store.authenticate(a));
});
test('signing profile only admits EC P-256 and OKP Ed25519',()=>{
  const f=setup();for(const record of [
    {...f.authenticator.credential,publicKeyJwk:{kty:'RSA',n:'AA',e:'AQAB'}},
    {...f.authenticator.credential,publicKeyJwk:{...f.authenticator.credential.publicKeyJwk,crv:'P-384'}},
    {...f.authenticator.credential,publicKeyJwk:{...f.authenticator.credential.publicKeyJwk,d:'private'}}
  ])fails(()=>validateCredential(record));
});
