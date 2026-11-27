import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

const web = new URL('../web/', import.meta.url);
const read = (p: string) => readFileSync(new URL(p, web), 'utf8');
const html = read('index.html');
const appJs = read('assets/app.js');

test('index.html has no inline script content and no on* attributes', () => {
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  assert.ok(scripts.length >= 2);
  for (const [, attrs = '', body = ''] of scripts) {
    assert.match(attrs, /\bsrc="[^"]+"/, 'script must be external');
    assert.equal(body.trim(), '', 'script must have no inline content');
  }
  assert.doesNotMatch(html, /<[^>]+\son[a-z]+\s*=/i, 'no inline event handlers');
  assert.doesNotMatch(html, /\sstyle\s*=/i, 'no inline style attributes');
  assert.doesNotMatch(html, /<style\b/i, 'no inline style element');
  assert.doesNotMatch(html, /javascript:/i);
});

test('no external src/href except links to m-ko.de', () => {
  for (const m of html.matchAll(/<(\w+)\b[^>]*?\b(src|href)="(https?:\/\/[^"]+)"[^>]*>/gi)) {
    const [, tag = '', , url = ''] = m;
    assert.equal(tag.toLowerCase(), 'a', `external ${url} only allowed on <a>`);
    assert.match(new URL(url).hostname, /^(www\.)?m-ko\.de$/, url);
  }
  assert.doesNotMatch(html, /(src|href)=["']\/\//i);
});

test('every language group has de, en and pt', () => {
  const langs = [...html.matchAll(/<(?!html\b)\w+\b[^>]*?\blang="(de|en|pt)"/g)].map((m) => m[1]);
  assert.ok(langs.length >= 30 && langs.length % 3 === 0, `got ${langs.length}`);
  for (let i = 0; i < langs.length; i += 3) {
    assert.deepEqual(new Set(langs.slice(i, i + 3)).size, 3, `group at ${i}: ${langs.slice(i, i + 3)}`);
  }
});

test('German text addresses nobody (no du/Sie) and promises nothing', () => {
  const re = /\b(du|dich|dir|dein\w*|Sie|Ihnen|Ihr\w*)\b/i;
  const spans = [...html.matchAll(/<(?!html\b)(\w+)\b[^>]*\blang="de"[^>]*>([\s\S]*?)<\/\1>/g)].map((m) => m[2] ?? '');
  assert.ok(spans.length > 5);
  for (const s of spans) assert.doesNotMatch(s, re, s);
  // dynamic German strings in app.js
  const de = appJs.slice(appJs.indexOf('  de: {'), appJs.indexOf('  en: {'));
  assert.doesNotMatch(de, re);
  for (const text of [...spans, de]) {
    assert.doesNotMatch(text, /\b(sicher|garantiert|zertifiziert)\b/i);
  }
  assert.doesNotMatch(html + appJs, /Ich bin Markus Kosmal/i);
});

test('app.js writes no markup from data', () => {
  for (const m of appJs.matchAll(/innerHTML\s*=\s*(.*)/g)) assert.match(m[1] ?? '', /^''|^""/);
  assert.doesNotMatch(appJs, /outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/);
});

const pow = await import(new URL('assets/pow.js', web).href);

test('leadingZeroBits', () => {
  const f = pow.leadingZeroBits;
  assert.equal(f(new Uint8Array([0xff])), 0);
  assert.equal(f(new Uint8Array([0x80])), 0);
  assert.equal(f(new Uint8Array([0x40])), 1);
  assert.equal(f(new Uint8Array([0x01])), 7);
  assert.equal(f(new Uint8Array([0x00, 0x80])), 8);
  assert.equal(f(new Uint8Array([0x00, 0x0f])), 12);
  assert.equal(f(new Uint8Array([0x00, 0x00])), 16);
  assert.equal(f(new Uint8Array([])), 0);
});

test('solve() finds a valid nonce for difficulty 8', async () => {
  const salt = 'deadbeef';
  const nonce = await pow.solve(salt, 8, { subtle: webcrypto.subtle });
  assert.ok(Number.isInteger(nonce) && nonce >= 0);
  const d = new Uint8Array(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(`${salt}:${nonce}`)));
  assert.ok(pow.leadingZeroBits(d) >= 8);
});

test('link preview: Open Graph tags with an absolute 1200x627 PNG that exists', async () => {
  const { readFileSync, existsSync } = await import('node:fs');
  const meta = (prop: string) => html.match(new RegExp(`<meta (?:property|name)="${prop}" content="([^"]*)"`))?.[1];
  assert.equal(meta('og:url'), 'https://scan.m-ko.de/');
  assert.equal(meta('og:image'), 'https://scan.m-ko.de/og.png');
  assert.equal(meta('og:image:width'), '1200');
  assert.equal(meta('og:image:height'), '627');
  assert.equal(meta('twitter:card'), 'summary_large_image');
  for (const p of ['og:title', 'og:description', 'og:image:alt']) assert.ok((meta(p) ?? '').length > 10, p);
  assert.doesNotMatch(meta('og:description') ?? '', /\b(du|Sie|sicher|garantiert|zertifiziert)\b/);
  assert.ok(existsSync('web/og.png'));
  const png = readFileSync('web/og.png');
  assert.equal(png.subarray(1, 4).toString(), 'PNG');
  assert.deepEqual([png.readUInt32BE(16), png.readUInt32BE(20)], [1200, 627]);
});
