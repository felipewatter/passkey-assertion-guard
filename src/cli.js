#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { runDemo } from './demo.js';

const HELP=`Passkey Assertion Guard v0.1.0
Usage: passkey-guard demo | --help | --version

This tool demonstrates WebAuthn authentication assertion verification.
It does NOT implement browser credential registration, attestation verification,
a web server, secure session cookies or persistent multi-instance challenge state.
Use the exported library for trusted server-side verification.
`;
export async function main(argv=process.argv.slice(2),log=console) {
  if(argv.length===1&&['--help','-h'].includes(argv[0])){log.log(HELP);return 0;}
  if(argv.length===1&&['--version','-v'].includes(argv[0])){log.log('0.1.0');return 0;}
  if(argv.length===1&&argv[0]==='demo'){
    try {await runDemo(log);return 0;}catch{log.error('ERROR: demo verification failed');return 2;}
  }
  log.error('Invalid command. See --help.');return 2;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  void main().then(code=>{process.exitCode=code;});
}
