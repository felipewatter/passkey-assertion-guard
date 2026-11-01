import { createPublicKey, createPrivateKey, generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
import { InputError, VerificationError, MAX, expect, decodeB64url, encodeB64url, sha256, equalBytes, exactKeys, validCredentialId, expectedOrigin } from './codec.js';
import { parseStrictJson } from './strict-json.js';

export { InputError, VerificationError, decodeB64url, encodeB64url } from './codec.js';
export { parseStrictJson } from './strict-json.js';

/** Server-provisioned credential. Keys MUST come from a previously authenticated registration ceremony. */
export function validateCredential(record) {
  exactKeys(record,['id','publicKeyJwk','signCount','backupEligible'],['backupState']);
  validCredentialId(record.id);
  expect(Number.isSafeInteger(record.signCount) && record.signCount >= 0 && record.signCount <= 0xffffffff);
  expect(typeof record.backupEligible === 'boolean');
  expect(record.backupState === undefined || typeof record.backupState === 'boolean');
  expect(record.backupEligible || record.backupState !== true);
  const jwk=record.publicKeyJwk;
  let algorithm;
  if (jwk?.kty==='EC') {
    exactKeys(jwk,['kty','crv','x','y']);expect(jwk.crv==='P-256');
    expect(decodeB64url(jwk.x,32).length===32 && decodeB64url(jwk.y,32).length===32);
    algorithm='ES256';
  } else if(jwk?.kty==='OKP') {
    exactKeys(jwk,['kty','crv','x']);expect(jwk.crv==='Ed25519');
    expect(decodeB64url(jwk.x,32).length===32);algorithm='EdDSA';
  } else throw new InputError();
  try {
    const key=createPublicKey({key:jwk,format:'jwk'});
    if(key.asymmetricKeyType!==(algorithm==='ES256'?'ec':'ed25519'))throw new InputError();
  } catch{throw new InputError();}
  return {id:record.id,publicKeyJwk:structuredClone(jwk),signCount:record.signCount,
    backupEligible:record.backupEligible,backupState:record.backupState ?? false,algorithm};
}
function parseClientData(bytes, origin, challenge) {
  let data;
  try { data=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes)); } catch{throw new InputError();}
  exactKeys(data,['type','challenge','origin'],['crossOrigin']);
  if(data.type!=='webauthn.get'||data.origin!==origin||data.crossOrigin===true||
    (data.crossOrigin!==undefined && data.crossOrigin!==false))throw new VerificationError();
  if(!equalBytes(decodeB64url(data.challenge,128),decodeB64url(challenge,128)))throw new VerificationError();
}
function parseAuthData(bytes, rpId, requiresUV) {
  // Narrow authentication profile: no inline attested credentials or extension data.
  if(bytes.length!==37)throw new InputError();
  if(!equalBytes(bytes.subarray(0,32),sha256(Buffer.from(rpId,'utf8'))))throw new VerificationError();
  const flags=bytes[32];
  const UP=Boolean(flags&1),UV=Boolean(flags&4),BE=Boolean(flags&8),BS=Boolean(flags&16);
  if(!UP || (requiresUV&&!UV) || BS&&!BE)throw new VerificationError();
  // Reserved flags and assertion extension/attestation flags not handled by this strict profile.
  if(flags & (2|32|64|128))throw new InputError();
  return {UP,UV,BE,BS,signCount:bytes.readUInt32BE(33)};
}
/**
 * Pure assertion check. Caller supplies both a trusted stored credential and an
 * EXPECTED one-time challenge from server storage, not from the assertion.
 * The caller MUST atomically consume its challenge and commit signCount before
 * approving a session; use CeremonyStore below for one-process demos.
 */
export function verifyAssertion({assertion,credential,challenge,origin,requireUserVerification=true,allowBackup=true}) {
  const expected=expectedOrigin(origin);
  if(typeof requireUserVerification!=='boolean'||typeof allowBackup!=='boolean')throw new InputError();
  const registered=validateCredential(credential);
  exactKeys(assertion,['id','rawId','type','response']);
  if(assertion.type!=='public-key'||assertion.id!==registered.id||assertion.rawId!==registered.id)throw new VerificationError();
  exactKeys(assertion.response,['clientDataJSON','authenticatorData','signature'],['userHandle']);
  const {clientDataJSON,authenticatorData,signature,userHandle}=assertion.response;
  if(userHandle!==undefined && userHandle!==null && (typeof userHandle!=='string'||decodeB64url(userHandle,128).length>128))throw new InputError();
  const client=decodeB64url(clientDataJSON,MAX.clientData),auth=decodeB64url(authenticatorData,MAX.authenticatorData),sig=decodeB64url(signature,MAX.signature);
  expect(sig.length>=8 && sig.length<=MAX.signature);
  const minimumChallenge=decodeB64url(challenge,128);expect(minimumChallenge.length>=32 && minimumChallenge.length<=128);
  parseClientData(client,expected.origin,challenge);
  const data=parseAuthData(auth,expected.rpId,requireUserVerification);
  if(data.BE!==registered.backupEligible || (!allowBackup&&data.BS))throw new VerificationError();
  const prior=registered.signCount,curr=data.signCount;
  if(prior>0 && curr<=prior)throw new VerificationError();
  const message=Buffer.concat([auth,sha256(client)]);
  let accepted=false;
  try {
    const key=createPublicKey({key:registered.publicKeyJwk,format:'jwk'});
    accepted=verify(registered.algorithm==='ES256'?'sha256':null,message,key,sig);
  }catch {throw new InputError();}
  if(!accepted)throw new VerificationError();
  return Object.freeze({verified:true,signCount:curr,userVerified:data.UV,userPresent:data.UP,
    backupEligible:data.BE,backupState:data.BS,counterSupported:curr>0||prior>0});
}
/**
 * Single-process, synchronous ceremony repository for demos and integration tests.
 * NOT appropriate for distributed/multi-process production session stores.
 */
export class CeremonyStore {
  #credentials=new Map();#outstanding=new Map();#now;
  constructor({origin,requireUserVerification=true,allowBackup=true,now=()=>Date.now()}={}) {
    this.origin=expectedOrigin(origin).origin;
    expect(typeof requireUserVerification==='boolean' && typeof allowBackup==='boolean' && typeof now==='function');
    this.requireUserVerification=requireUserVerification;this.allowBackup=allowBackup;this.#now=now;
  }
  enrollTrustedCredential(record) {
    const value=validateCredential(record);
    if(this.#credentials.has(value.id))throw new InputError();
    const {algorithm,...saved}=value;this.#credentials.set(value.id,saved);
  }
  issueChallenge(credentialId,{ttlMs=120000}={}) {
    validCredentialId(credentialId);expect(this.#credentials.has(credentialId));
    expect(Number.isSafeInteger(ttlMs) && ttlMs>=1000 && ttlMs<=300000);
    for(const [issued,record] of this.#outstanding)if(this.#now()>record.expires)this.#outstanding.delete(issued);
    if(this.#outstanding.size>=4096)throw new InputError();
    const challenge=encodeB64url(randomBytes(32));
    this.#outstanding.set(challenge,{credentialId,expires:this.#now()+ttlMs});
    return challenge;
  }
  authenticate(assertion) {
    // Synchronous critical section: no awaits between compare, verify and commit.
    exactKeys(assertion,['id','rawId','type','response']);
    const bytes=decodeB64url(assertion.response?.clientDataJSON,MAX.clientData);
    let client;
    try{client=parseStrictJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new InputError();}
    const challenge=client?.challenge;
    if(typeof challenge!=='string')throw new VerificationError();
    const state=this.#outstanding.get(challenge);
    if(!state||state.credentialId!==assertion.id||this.#now()>state.expires)throw new VerificationError();
    const credential=this.#credentials.get(state.credentialId);
    if(!credential)throw new VerificationError();
    state.attempts=(state.attempts??0)+1;
    if(state.attempts>5){this.#outstanding.delete(challenge);throw new VerificationError();}
    const result=verifyAssertion({assertion,credential,challenge,origin:this.origin,
      requireUserVerification:this.requireUserVerification,allowBackup:this.allowBackup});
    this.#outstanding.delete(challenge);
    this.#credentials.set(state.credentialId,{...credential,signCount:result.signCount,backupState:result.backupState});
    return result;
  }
  revokeCredential(id){this.#credentials.delete(id);for(const [c,v] of this.#outstanding)if(v.credentialId===id)this.#outstanding.delete(c);}
  getCredential(id){const c=this.#credentials.get(id);return c?structuredClone(c):null;}
}
/** Generates a disposable test authenticator, NOT a credential registration ceremony. */
export function demoAuthenticator({algorithm='ES256',origin,credentialId,flags=5}) {
  const {privateKey,publicKey}=algorithm==='ES256'?generateKeyPairSync('ec',{namedCurve:'P-256'}):
    algorithm==='EdDSA'?generateKeyPairSync('ed25519'):(()=>{throw new InputError()})();
  const {rpId}=expectedOrigin(origin);
  const id=credentialId ?? encodeB64url(randomBytes(32));
  validCredentialId(id);
  function signAssertion(challenge,{signCount=1,originOverride=origin,authDataFlags=flags,clientDataOverrides={},
     rpIdOverride=rpId,appendAuthData=Buffer.alloc(0)}={}) {
    const cd=Buffer.from(JSON.stringify({...{type:'webauthn.get',challenge,origin:originOverride,crossOrigin:false},...clientDataOverrides}));
    const auth=Buffer.alloc(37+appendAuthData.length);sha256(Buffer.from(rpIdOverride)).copy(auth,0);auth[32]=authDataFlags;auth.writeUInt32BE(signCount,33);
    Buffer.from(appendAuthData).copy(auth,37);
    const msg=Buffer.concat([auth,sha256(cd)]);
    const sig=sign(algorithm==='ES256'?'sha256':null,msg,privateKey);
    return {id,rawId:id,type:'public-key',response:{clientDataJSON:encodeB64url(cd),authenticatorData:encodeB64url(auth),signature:encodeB64url(sig)}};
  }
  return {credential:{id,publicKeyJwk:publicKey.export({format:'jwk'}),signCount:0,
      backupEligible:Boolean(flags&8),backupState:false},signAssertion};
}