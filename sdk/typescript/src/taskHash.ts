/**
 * @file taskHash.ts
 * @description The ServeProof `taskHash` preimage, recomputed client-side.
 *
 * The sealed proxy signs
 *
 *   taskHash = keccak256(method ‖ uri ‖ keccak256(reqBody) ‖ keccak256(respBody) ‖ status)
 *
 * (a plain concatenation; `status` as decimal — 3 digits for 100..999), where
 * `uri` is Go's `r.URL.RequestURI()` of the request as the proxy received it.
 * VerifiedFeedbackRegistry.attestFeedbackWithTask rebuilds the same preimage
 * from a {@link TaskReveal}. Consensus-critical: duplicated in the contract,
 * sealed (internal/proxy) and the attestor console, all pinned to the shared
 * katTaskHash vector — a change must land in every copy.
 */

import { keccak256, toBytes, hexToBytes, concat, type Hash } from 'viem';
import type { TaskReveal } from './types';

/** keccak256(method ‖ uri ‖ reqBodyHash ‖ respBodyHash ‖ decimal statusCode). */
export function taskHashOf(task: TaskReveal): Hash {
  return keccak256(concat([
    toBytes(task.method), toBytes(task.uri),
    hexToBytes(task.reqBodyHash), hexToBytes(task.respBodyHash),
    toBytes(String(task.statusCode)),
  ]));
}

// Go net/url shouldEscape(c, encodePath).
function goShouldEscapePath(c: number): boolean {
  if ((c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39)) return false;
  switch (String.fromCharCode(c)) {
    case '-': case '_': case '.': case '~':
      return false;
    case '$': case '&': case '+': case ',': case '/': case ':': case ';': case '=': case '?': case '@':
      return c === 0x3f; // only '?' is escaped in a path
    default:
      return true;
  }
}

// Go net/url validEncoded(s, encodePath).
function goValidEncodedPath(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ("!$&'()*+,;=:@[]%".includes(s[i])) continue;
    if (c > 0x7f || goShouldEscapePath(c)) return false;
  }
  return true;
}

const HEX = '0123456789ABCDEF';

/**
 * Go's `url.ParseRequestURI(target).RequestURI()` for an origin-form request
 * target (`/path[?query]`, exactly as sent on the wire) — the `uri` the sealed
 * proxy hashes. The path is kept verbatim when Go accepts its encoding;
 * otherwise (a raw `|`, `^`, … that WHATWG URLs leave alone) Go decodes it and
 * re-escapes every byte outside its path set as upper-case `%XX`. The query is
 * kept verbatim, including a bare trailing `?`. A target Go cannot parse (bad
 * `%` escape) is answered 400 by the proxy, so it is returned unchanged.
 */
export function requestUriOf(target: string): string {
  const q = target.indexOf('?');
  const rawPath = q < 0 ? target : target.slice(0, q);
  const query = q < 0 ? '' : target.slice(q); // '?' + RawQuery, or a bare '?'
  if (rawPath === '' || goValidEncodedPath(rawPath)) return (rawPath || '/') + query;
  // unescape(rawPath, encodePath) → bytes
  const bytes: number[] = [];
  for (let i = 0; i < rawPath.length; i++) {
    const ch = rawPath[i];
    if (ch === '%') {
      const h = rawPath.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(h)) return target;
      bytes.push(parseInt(h, 16));
      i += 2;
    } else {
      for (const b of new TextEncoder().encode(ch)) bytes.push(b);
    }
  }
  // escape(path, encodePath)
  let out = '';
  for (const b of bytes) out += goShouldEscapePath(b) ? `%${HEX[b >> 4]}${HEX[b & 15]}` : String.fromCharCode(b);
  return (out || '/') + query;
}

/**
 * The `uri` forms the proxy may have hashed for a request to `url`: Go's
 * RequestURI of the request target, first as Node's fetch (undici) sends it
 * — `pathname + search`, dropping a bare trailing `?` — then, when the URL
 * has such an empty query, as a client that keeps the `?` sends it (the
 * WHATWG fetch spec, browsers). A caller matching a signed taskHash tries
 * each.
 */
export function requestUriCandidates(url: string | URL): string[] {
  const u = typeof url === 'string' ? new URL(url) : url;
  const out = [requestUriOf(u.pathname + u.search)];
  if (u.search === '' && u.href.replace(/#.*$/, '').endsWith('?')) out.push(requestUriOf(`${u.pathname}?`));
  return out;
}
