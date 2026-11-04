/**
 * Shared taskHash vectors (not a test file): mirrored from
 * sealed/internal/proxy/serveproof_test.go (katTaskHash, katTaskHashEdge,
 * requestURIForms) — keep in sync. Used by taskhash.test.mjs (SDK copy) and
 * serveproof-copies.test.mjs (attestor console copy).
 */

export const KAT_TASK_HASH = '0x6c37771076037daf6053adca6126264030e249e0c9a6fc0cc238c56509f842db';
export const KAT_TASK_HASH_EDGE = '0x9e00c178e74e6acfb1c048af8be9a47f3d91adf60a02982ce15810ff452fc81b';

// wire request target → Go r.URL.RequestURI()
export const REQUEST_URI_FORMS = [
  ['/api/x?q=1', '/api/x?q=1'],
  ['/api/x?', '/api/x?'],
  ['/api/a|b', '/api/a%7Cb'],
  ['/api/a^b?x=|^', '/api/a%5Eb?x=|^'],
  ['/api/a|b?', '/api/a%7Cb?'],
  ['/api/a%2Fb|c', '/api/a/b%7Cc'],
  ['/api/a%7cb', '/api/a%7cb'],
  ['/api/a%41|', '/api/aA%7C'],
  ['/api/%C3%A9', '/api/%C3%A9'],
  ['/api/%C3%A9|', '/api/%C3%A9%7C'],
  ["/api/[x]!'()*,;=:@$&+", "/api/[x]!'()*,;=:@$&+"],
  ['/api/[x]|', '/api/%5Bx%5D%7C'],
  ['/api/a??b', '/api/a??b'],
];

export const RESP = '{"a":"out"}';
