import { createHash, timingSafeEqual } from 'node:crypto';

export class InputError extends Error { constructor() { super('Invalid or unsupported authentication input'); this.name = 'InputError'; } }
export class VerificationError extends Error { constructor() { super('Authentication assertion rejected'); this.name = 'VerificationError'; } }
export const MAX = Object.freeze({ clientData: 16384, authenticatorData: 4096, signature: 512, credentialId: 1024 });

export function expect(ok) { if (!ok) throw new InputError(); }
export function decodeB64url(s, max = 16384) {
  expect(typeof s === 'string' && s.length > 0 && s.length <= Math.ceil(max * 4 / 3) + 4 && /^[A-Za-z0-9_-]+$/.test(s));
  const b = Buffer.from(s, 'base64url');
  expect(b.length > 0 && b.length <= max && b.toString('base64url') === s);
  return b;
}
export function encodeB64url(b) { return Buffer.from(b).toString('base64url'); }
export function sha256(b) { return createHash('sha256').update(b).digest(); }
export function equalBytes(a, b) { if (a.length !== b.length) return false; return timingSafeEqual(a,b); }
export function exactKeys(o, required, optional = []) {
  expect(o !== null && typeof o === 'object' && !Array.isArray(o));
  const keys = Object.keys(o);
  expect(required.every(k => Object.hasOwn(o,k)) && keys.every(k => required.includes(k) || optional.includes(k)));
}
export function validCredentialId(id) {
  const b = decodeB64url(id, MAX.credentialId);
  expect(b.length >= 16 && b.length <= MAX.credentialId);
  return id;
}
export function expectedOrigin(value) {
  expect(typeof value === 'string' && value.length < 260 && !/[\x00-\x20\x7f]/.test(value));
  let url;
  try { url = new URL(value); } catch { throw new InputError(); }
  expect(url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash && url.pathname === '/');
  expect(url.origin === value && url.port === '');
  expect(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(url.hostname));
  return { origin: url.origin, rpId: url.hostname };
}
