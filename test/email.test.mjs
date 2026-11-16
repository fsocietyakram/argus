import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  DISPOSABLE_DOMAINS,
  ROLE_ACCOUNTS,
  gravatarHash,
  parseEmail,
  scanEmail,
} from '../src/email.mjs';
import { dnsIntel } from '../src/email.mjs';
import { normalizeDomain } from '../src/domain.mjs';

test('parseEmail normalises valid addresses', () => {
  const result = parseEmail('First.Last+tag@Example.COM');
  assert.equal(result.valid, true);
  assert.equal(result.domain, 'example.com');
  assert.equal(result.normalized, 'first.last+tag@example.com');
  assert.equal(result.local, 'First.Last+tag');

  const idn = parseEmail('user@münchen.de');
  assert.equal(idn.valid, true);
  assert.equal(idn.domain, 'xn--mnchen-3ya.de');
});

test('parseEmail rejects malformed addresses with a reason', () => {
  for (const value of [
    '',
    'plainaddress',
    'two words@example.com',
    'name <name@example.com>',
    '@example.com',
    'name@',
    '.name@example.com',
    'name.@example.com',
    'na..me@example.com',
    'name@example',
    'name@-example.com',
    `${'a'.repeat(65)}@example.com`,
    `${'a'.repeat(250)}@example.com`,
  ]) {
    const result = parseEmail(value);
    assert.equal(result.valid, false, `expected invalid: ${value}`);
    assert.ok(result.reason && result.reason.length > 5, `expected a reason for: ${value}`);
  }
});

test('gravatarHash matches MD5 of the trimmed lowercase address', () => {
  const expected = createHash('md5').update('test@example.com').digest('hex');
  assert.equal(gravatarHash('  Test@Example.com '), expected);
  assert.equal(expected, '55502f40dc8b7c769880b10874abc9d0');
});

test('disposable and role-account registries include known values', () => {
  assert.ok(DISPOSABLE_DOMAINS.has('mailinator.com'));
  assert.ok(DISPOSABLE_DOMAINS.has('yopmail.com'));
  assert.ok(!DISPOSABLE_DOMAINS.has('example.com'));
  assert.ok(ROLE_ACCOUNTS.has('postmaster'));
  assert.ok(ROLE_ACCOUNTS.has('security'));
});

test('invalid email scans short-circuit without network lookups', async () => {
  const result = await scanEmail('not a valid address', {
    config: { settings: { timeoutMs: 1000, hibpApiKeyEnv: 'HIBP_API_KEY' }, sources: {} },
  });

  assert.equal(result.command, 'email');
  assert.equal(result.syntax.valid, false);
  assert.equal(result.risk.score, 100);
  assert.equal(result.gravatar.checked, false);
  assert.equal(result.breaches.checked, false);
  assert.ok(result.notes.some((note) => /syntax validation/i.test(note)));
});

test('dnsIntel reports errors instead of throwing for an unresolvable domain', async () => {
  const result = await dnsIntel('this-domain-should-not-resolve.invalid', {
    timeout: 1500,
    dkim: false,
  });
  assert.equal(result.domain, 'this-domain-should-not-resolve.invalid');
  assert.equal(result.hasMx, false);
  assert.equal(result.spf.present, false);
  assert.equal(result.dmarc.present, false);
  assert.ok(Array.isArray(result.errors));
});

test('normalizeDomain cleans URLs and rejects invalid hosts', () => {
  assert.equal(normalizeDomain('HTTPS://www.Example.com/path?q=1#frag'), 'example.com');
  assert.equal(normalizeDomain('example.com:8443'), 'example.com');
  assert.equal(normalizeDomain('http://sub.example.co.uk/x'), 'sub.example.co.uk');
  assert.equal(normalizeDomain('münchen.de'), 'xn--mnchen-3ya.de');

  for (const value of ['', 'not a domain', 'localhost', 'http://', 'exa mple.com', '127.0.0.1']) {
    assert.throws(() => normalizeDomain(value), /valid registrable domain/i, value);
  }
});
