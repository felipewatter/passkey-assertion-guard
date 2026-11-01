import { CeremonyStore, demoAuthenticator, VerificationError } from './index.js';
export async function runDemo(log=console) {
  const origin='https://login.example.org';
  const store=new CeremonyStore({origin});
  const authenticator=demoAuthenticator({origin});
  store.enrollTrustedCredential(authenticator.credential);
  const challenge=store.issueChallenge(authenticator.credential.id);
  const result=store.authenticate(authenticator.signAssertion(challenge,{signCount:1}));
  if(!result.verified || !result.userVerified)throw Error('Expected successful assertion');
  log.log('PASS: ES256 signature, challenge, domain binding and user verification accepted.');
  try {store.authenticate(authenticator.signAssertion(challenge,{signCount:2}));throw Error('Replay accepted');}
  catch(e){if(!(e instanceof VerificationError))throw e;}
  log.log('PASS: previously consumed challenge rejected.');
  const challenge2=store.issueChallenge(authenticator.credential.id);
  const attacker=demoAuthenticator({origin,credentialId:authenticator.credential.id});
  try {store.authenticate(attacker.signAssertion(challenge2,{signCount:2}));throw Error('Untrusted signature accepted');}
  catch(e){if(!(e instanceof VerificationError))throw e;}
  log.log('PASS: unauthorized private key rejected.');
  log.log('Demo only: trusted credential provisioned by the test, not browser registration.');
}
