import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertAllowedUrl, isBlockedIp, normaliseTarget } from '../src/fetch/ssrf.ts';

test('private, reserved and metadata IPv4 addresses are blocked', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1']) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '93.184.216.34']) assert.equal(isBlockedIp(ip), false, ip);
});

test('IPv6 loopback, local, mapped and NAT64 forms are blocked', () => {
  for (const ip of ['::1', '::', 'fe80::1', 'fd00::1', 'fc00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::a9fe:a9fe', 'ff02::1', '2001:db8::1']) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
  assert.equal(isBlockedIp('2606:4700:4700::1111'), false);
  assert.equal(isBlockedIp('::ffff:8.8.8.8'), false);
});

test('URLs: only http(s), no credentials, no odd ports, no internal names', () => {
  for (const u of ['ftp://example.com', 'file:///etc/passwd', 'https://user:pw@example.com', 'https://example.com:22', 'http://localhost/', 'http://metadata.google.internal/', 'http://intranet/', 'http://[::1]/', 'http://169.254.169.254/latest']) {
    assert.throws(() => assertAllowedUrl(u), u);
  }
  assert.equal(assertAllowedUrl('https://example.com:8443/x').hostname, 'example.com');
});

test('targets are normalised', () => {
  assert.equal(normaliseTarget(' example.com ').toString(), 'https://example.com/');
  assert.equal(normaliseTarget('https://app.example.com/login#x').toString(), 'https://app.example.com/login');
});
