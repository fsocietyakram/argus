import test from 'node:test';
import assert from 'node:assert/strict';
import { correlateCaseReports } from '../src/correlate.mjs';

const domainReport = {
  command: 'domain',
  target: 'example.com',
  createdAt: '2026-01-01T10:00:00.000Z',
  certificates: { names: ['mail.example.com', 'example.com'] },
  dns: { a: ['203.0.113.10'], aaaa: ['2001:db8::10'] },
};

const emailReport = {
  command: 'email',
  target: 'alice@example.com',
  createdAt: '2026-01-02T10:00:00.000Z',
  syntax: { domain: 'example.com' },
  dns: { a: ['203.0.113.10'], aaaa: [] },
};

const fileReport = {
  command: 'file',
  target: 'letter.pdf',
  createdAt: '2026-01-03T10:00:00.000Z',
  strings: {
    emails: ['alice@example.com', 'bob@example.net'],
    ips: ['203.0.113.10'],
    urls: ['https://www.example.com/contact'],
    handles: ['@alice'],
  },
};

test('correlateCaseReports keeps exact citations for repeated indicators', () => {
  const { repeatedIndicators } = correlateCaseReports([
    { id: 'domain-1', report: domainReport },
    { id: 'email-1', report: emailReport },
    { id: 'file-1', report: fileReport },
  ]);

  const domain = repeatedIndicators.find((item) => item.type === 'domain' && item.value === 'example.com');
  assert.ok(domain);
  assert.ok(domain.occurrences.length >= 2);
  assert.ok(domain.occurrences.every((entry) => entry.reportId && entry.field));
  assert.deepEqual(
    domain.occurrences.map((entry) => [entry.reportId, entry.field]),
    [
      ['domain-1', 'target'],
      ['email-1', 'syntax.domain'],
      ['file-1', 'strings.urls[0]'],
    ],
  );

  const email = repeatedIndicators.find((item) => item.type === 'email' && item.value === 'alice@example.com');
  assert.deepEqual(
    email.occurrences.map((entry) => [entry.reportId, entry.field]),
    [
      ['email-1', 'target'],
      ['file-1', 'strings.emails[0]'],
    ],
  );

  const ip = repeatedIndicators.find((item) => item.type === 'ip' && item.value === '203.0.113.10');
  assert.deepEqual(
    ip.occurrences.map((entry) => [entry.reportId, entry.field]),
    [
      ['domain-1', 'dns.a[0]'],
      ['email-1', 'dns.a[0]'],
      ['file-1', 'strings.ips[0]'],
    ],
  );

  assert.equal(repeatedIndicators.filter((item) => item.value === 'bob@example.net').length, 0);
});

test('one report contributes at most one occurrence per value', () => {
  const { repeatedIndicators } = correlateCaseReports([
    {
      id: 'file-1',
      report: {
        ...fileReport,
        strings: { ...fileReport.strings, emails: ['alice@example.com', 'Alice@Example.com'] },
      },
    },
    { id: 'email-1', report: emailReport },
  ]);
  const email = repeatedIndicators.find((item) => item.type === 'email' && item.value === 'alice@example.com');
  assert.equal(email.occurrences.filter((entry) => entry.reportId === 'file-1').length, 1);
  assert.equal(email.occurrences.length, 2);
});

test('username profile fields and website links cite their exact paths', () => {
  const { repeatedIndicators } = correlateCaseReports([
    {
      id: 'username-1',
      report: {
        command: 'username',
        target: 'alice',
        createdAt: '2026-01-04T10:00:00.000Z',
        findings: [
          {
            name: 'GitHub',
            profile: {
              links: [{ label: 'Personal site', url: 'https://example.com' }],
              fields: [{ label: 'Email', value: 'alice@example.com' }],
            },
          },
        ],
      },
    },
    { id: 'email-1', report: emailReport },
    { id: 'domain-1', report: domainReport },
  ]);
  const domain = repeatedIndicators.find((item) => item.type === 'domain' && item.value === 'example.com');
  assert.ok(domain.occurrences.some((entry) => entry.reportId === 'username-1' && entry.field === 'findings[0].profile.links[0].url'));
  const email = repeatedIndicators.find((item) => item.type === 'email' && item.value === 'alice@example.com');
  assert.ok(email.occurrences.some((entry) => entry.reportId === 'username-1' && entry.field === 'findings[0].profile.fields[0].value'));
});

test('timeline is ascending and ignores undated reports', () => {
  const { timeline } = correlateCaseReports([
    { id: 'file-1', report: fileReport },
    { id: 'domain-1', report: domainReport },
    { id: 'email-1', report: { ...emailReport, createdAt: null } },
  ]);
  assert.deepEqual(
    timeline.map((entry) => [entry.reportId, entry.createdAt]),
    [
      ['domain-1', '2026-01-01T10:00:00.000Z'],
      ['file-1', '2026-01-03T10:00:00.000Z'],
    ],
  );
});
