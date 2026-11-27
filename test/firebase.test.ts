// Firebase probes: RTDB (shallow), Firestore (one doc), Storage (one item). Fixture-based, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { findFirebaseConfig } from '../src/modules/probe/firebase-config.ts';

const KEY = 'AIza' + 'Sy' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q';
const PROJECT = 'demo-shop-1234';
const DB = `https://${PROJECT}-default-rtdb.europe-west1.firebasedatabase.app`;
const BUCKET = `${PROJECT}.appspot.com`;
const URL_ = 'https://app.example.com/';
const SECRET_EMAIL = 'jane.doe.secret' + '@example.org';
const SECRET_NAME = 'Zaphod-Beeblebrox-' + '4711';
const SECRET_FILE = 'private-contract-' + '9981.pdf';

const html = `<!doctype html><html><head><script type="module" src="/assets/index-Ab12Cd34.js"></script></head><body></body></html>`;
const CONFIG = `const firebaseConfig={apiKey:"${KEY}",authDomain:"${PROJECT}.firebaseapp.com",databaseURL:"${DB}",projectId:"${PROJECT}",storageBucket:"${BUCKET}",messagingSenderId:"1"};`;
const CODE = `${CONFIG}initializeApp(firebaseConfig);const a=collection(db,"users"),b=collection(db,"posts");x.collection("orders");`;

function site(extra: Record<string, object> = {}, code = CODE) {
  return {
    [URL_]: { headers: { 'content-type': 'text/html' }, body: html },
    'https://app.example.com/assets/index-Ab12Cd34.js': { body: code },
    ...extra,
  } as Record<string, any>;
}

const names = ['collect.page', 'collect.bundles', 'stack.detect'];
const run = (s: Record<string, any>, mods: string[], own = true) =>
  runOn(
    s,
    URL_,
    parsePlan({ plan: 't', limits: { totalMs: 10000, requests: 60, browser: false }, modules: [...names, ...mods], presentation: { showFindings: 'all', fixPrompts: true } }),
    { modules: [...MODULES], ownershipVerified: own },
  );
const google = (log: string[]) => log.filter((l) => /googleapis\.com|firebasedatabase\.app|firebaseio\.com/.test(l));
const fs = (c: string) => `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${c}?pageSize=1&key=${KEY}`;

test('findFirebaseConfig: web config, quoted keys, no config', () => {
  const b = (code: string) => [{ url: 'x', source: 'external' as const, status: 200, headers: {}, code, truncated: false }];
  assert.deepEqual(findFirebaseConfig(b(CONFIG)), { apiKey: KEY, projectId: PROJECT, databaseURL: DB, storageBucket: BUCKET });
  const quoted = `{"apiKey":"${KEY}","projectId":"${PROJECT}"}`;
  assert.deepEqual(findFirebaseConfig(b(quoted)), { apiKey: KEY, projectId: PROJECT });
  assert.equal(findFirebaseConfig(b('databaseURL:"https://evil.example.com"'), ''), null);
  const evil = `{apiKey:"${KEY}",projectId:"${PROJECT}",databaseURL:"https://169.254.169.254.example.com",storageBucket:"x.example.com"}`;
  assert.deepEqual(findFirebaseConfig(b(evil)), { apiKey: KEY, projectId: PROJECT });
});

test('rtdb-open: shallow read, only key names, critical', async () => {
  const s = site({ [`${DB}/.json?shallow=true`]: { body: JSON.stringify({ users: true, orders: true, posts: true, a: true, b: true, c: true }) } });
  const { result, http } = await run(s, ['firebase.rtdb-open']);
  const f = result.findings.filter((x) => x.id === 'firebase.rtdb-open/rtdb-open');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, 'critical');
  assert.equal(f[0]!.messageKey, 'firebase.rtdb-open');
  assert.equal(f[0]!.vars!.keys, '6');
  assert.equal(f[0]!.vars!.sample, 'users, orders, posts, a, b');
  assert.deepEqual(google(http.log), [`GET ${DB}/.json?shallow=true`]);
});

test('rtdb-open: locked and empty databases give no finding', async () => {
  for (const r of [{ status: 401, body: '{"error":"Permission denied"}' }, { body: 'null' }, { body: '{}' }]) {
    const { result } = await run(site({ [`${DB}/.json?shallow=true`]: r }), ['firebase.rtdb-open']);
    assert.equal(result.findings.length, 0);
  }
});

test('firestore-open: personal fields are critical, no values in the result', async () => {
  const s = site({
    [fs('users')]: { body: JSON.stringify({ documents: [{ name: 'x/users/1', fields: { email: { stringValue: SECRET_EMAIL }, displayName: { stringValue: SECRET_NAME } } }] }) },
    [fs('posts')]: { body: JSON.stringify({ documents: [{ name: 'x/posts/1', fields: { title: { stringValue: 'Hello' }, likes: { integerValue: '3' } } }] }) },
    [fs('orders')]: { status: 403, body: JSON.stringify({ error: { code: 403, status: 'PERMISSION_DENIED' } }) },
  });
  const { result, http } = await run(s, ['firebase.firestore-open']);
  const f = result.findings.filter((x) => x.id === 'firebase.firestore-open/firestore-open');
  assert.equal(f.length, 2);
  const u = f.find((x) => x.vars!.collection === 'users')!;
  assert.equal(u.severity, 'critical');
  assert.equal(u.vars!.fields, 'email, displayName');
  assert.equal(f.find((x) => x.vars!.collection === 'posts')!.severity, 'high');
  const json = JSON.stringify(result);
  for (const secret of [SECRET_EMAIL, SECRET_NAME, KEY, 'Hello']) assert.ok(!json.includes(secret), secret);
  assert.ok(http.log.every((l) => l.startsWith('GET ')));
  assert.equal(google(http.log).length, 3);
});

test('firestore-open: empty collection gives no finding; maxCollections caps with budget note', async () => {
  const s = site({ [fs('users')]: { body: '{}' } }, `${CONFIG}${[...Array(14)].map((_, i) => `collection(db,"c${i}")`).join(';')};collection(db,"users")`);
  const { result, http } = await run(s, ['firebase.firestore-open']);
  assert.equal(result.findings.length, 0);
  assert.equal(google(http.log).length, 10);
  assert.ok(result.notChecked.some((n) => n.module === 'firebase.firestore-open' && n.reason === 'budget'));
});

test('storage-open: listable bucket is high, object names are not stored', async () => {
  const url = `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o?maxResults=1`;
  const { result, http } = await run(site({ [url]: { body: JSON.stringify({ items: [{ name: SECRET_FILE, bucket: BUCKET }] }) } }), ['firebase.storage-open']);
  const f = result.findings.filter((x) => x.id === 'firebase.storage-open/storage-listable');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, 'high');
  assert.equal(f[0]!.messageKey, 'firebase.storage-listable');
  assert.deepEqual(f[0]!.vars, { bucket: BUCKET });
  assert.ok(!JSON.stringify(result).includes(SECRET_FILE));
  assert.equal(google(http.log).length, 1);
  const denied = await run(site({ [url]: { status: 403, body: '{"error":{"code":403}}' } }), ['firebase.storage-open']);
  assert.equal(denied.result.findings.length, 0);
});

test('no Firebase: probes are skipped by condition', async () => {
  const s = { [URL_]: { headers: { 'content-type': 'text/html' }, body: '<html><body>hi</body></html>' } } as Record<string, any>;
  const { result, http } = await run(s, ['firebase.rtdb-open', 'firebase.firestore-open', 'firebase.storage-open']);
  assert.equal(result.findings.filter((f) => f.id.startsWith('firebase.')).length, 0);
  assert.equal(google(http.log).length, 0);
});

test('without ownership: notChecked ownership and zero requests to Google hosts', async () => {
  const s = site({ [`${DB}/.json?shallow=true`]: { body: '{"users":true}' } });
  const { result, http } = await run(s, ['firebase.rtdb-open', 'firebase.firestore-open', 'firebase.storage-open'], false);
  for (const id of ['firebase.rtdb-open', 'firebase.firestore-open', 'firebase.storage-open']) {
    assert.ok(result.notChecked.some((n) => n.module === id && n.reason === 'ownership'), id);
  }
  assert.equal(google(http.log).length, 0);
  assert.equal(result.findings.filter((f) => f.severity === 'critical').length, 0);
});
