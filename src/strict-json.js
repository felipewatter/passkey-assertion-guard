/** A defensive JSON pre-parse rejects duplicate decoded object keys. */
import { InputError, expect } from './codec.js';

export function parseStrictJson(source, {maxDepth = 24, maxTokens = 20000} = {}) {
  expect(typeof source === 'string' && source.length > 0 && source.charCodeAt(0) !== 0xfeff && !source.includes('\u0000'));
  let i = 0, tokens = 0;
  const fail = () => { throw new InputError(); };
  const ws = () => { while (' \t\r\n'.includes(source[i]) && i < source.length) i++; };
  function quoted() {
    if (source[i] !== '"') fail();
    const start = i++;
    let done = false;
    while (i < source.length) {
      const c = source[i++];
      if (c === '"') { done=true;break; }
      if (c === '\\') {
        const escape = source[i++];
        if (escape === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(i,i+4))) fail();
          i += 4;
        } else if (!'"\\/bfnrt'.includes(escape||'')) fail();
      } else if (c.charCodeAt(0) < 32) fail();
    }
    if (!done) fail();
    try { return JSON.parse(source.slice(start,i)); } catch { fail(); }
  }
  function value(depth) {
    if (++tokens > maxTokens || depth > maxDepth) fail();
    ws();const c=source[i];
    if (c === '"') { quoted();return; }
    if (c === '{') {
      i++;ws(); const seen=new Set(); if (source[i] === '}') {i++;return;}
      while(true) {
        ws();const key=quoted();
        if (seen.has(key) || ['__proto__','prototype','constructor'].includes(key)) fail();
        seen.add(key);ws();if (source[i++] !== ':') fail();value(depth+1);ws();
        const sep=source[i++];if(sep==='}')return;if(sep!==',')fail();
      }
    }
    if (c === '[') {
      i++;ws();if (source[i]===']'){i++;return;}
      while(true){value(depth+1);ws();const sep=source[i++];if(sep===']')return;if(sep!==',')fail();}
    }
    for(const t of ['null','true','false'])if(source.startsWith(t,i)){i+=t.length;return;}
    if(c==='-' || (c>='0'&&c<='9')) {
      const m=/-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(i));
      if(!m || m.index!==0)fail();i+=m[0].length;return;
    }
    fail();
  }
  value(0);ws();if(i!==source.length)fail();
  try{return JSON.parse(source);}catch{fail();}
}
