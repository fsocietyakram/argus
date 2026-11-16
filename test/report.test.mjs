import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readAudit } from '../src/audit.mjs';
import {
  deleteAllData,
  deleteReport,
  listReports,
  purgeReports,
  readReport,
  readReportHtml,
  renderHtml,
  reportStats,
  saveReport,
} from '../src/report.mjs';

const workdir = mkdtempSync(join(tmpdir(), 'argus-report-test-'));
process.env.ARGUS_REPORTS = join(workdir, 'reports');
process.env.ARGUS_DATA = join(workdir, 'data');

const config = { settings: { retentionDays: 0, maxReports: 0, logTargetsInAudit: true }, sources: {} };

test.after(() => {
  rmSync(workdir, { recursive: true, force: true });
});

const daysAgo = (days) => new Date(Date.now() - days * 86_400_000).toISOString();

function makeResult(target = '@example', extra = {}) {
  return {
    schema: 'argus.report/v1',
    command: 'username',
    tool: { name: 'ARGUS', version: '1.0.0' },
    target,
    normalized: 'example',
    createdAt: new Date().toISOString(),
    durationMs: 1234,
    summary: {
      total: 2,
      confirmed: 1,
      possible: 0,
      unverified: 0,
      absent: 1,
      blocked: 0,
      skipped: 0,
      error: 0,
    },
    findings: [
      {
        id: 'example',
        name: 'Example <b>site</b>',
        category: 'social',
        url: 'https://example.com/example',
        status: 'confirmed',
        confidence: 'high',
        detail: 'Marker found <img src=x onerror=alert(1)>',
        retrievedAt: new Date().toISOString(),
        elapsedMs: 25,
        profile: {
          fields: [{ label: 'Bio', value: '<script>alert("x")</script>' }],
          links: [
            { label: 'Bad link', url: 'javascript:alert(1)' },
            { label: 'Good link', url: 'https://example.com/profile' },
          ],
        },
      },
      {
        id: 'other',
        name: 'Other',
        category: 'dev',
        url: 'https://other.example/example',
        status: 'absent',
        detail: 'HTTP 404.',
        retrievedAt: new Date().toISOString(),
      },
    ],
    settings: { enabledSources: 10, selectedSources: 2 },
    notes: ['A shared username is not proof of identity.'],
    ...extra,
  };
}

test('renderHtml escapes hostile target and finding content', () => {
  const html = renderHtml(makeResult('@<script>alert("x")</script>'));

  assert.match(html, /<!doctype html>/i);
  assert.ok(html.includes('&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;'));
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(!html.includes('<img src=x onerror=alert(1)>'));
  assert.ok(!html.includes('javascript:alert'));
  assert.ok(html.includes('https://example.com/profile'));
  assert.ok(html.includes('A shared username is not proof of identity.'));
});

test('saveReport writes JSON and HTML, lists, reads, and deletes them', () => {
  deleteAllData(config);
  const result = makeResult('@example');
  const saved = saveReport(result, config);

  assert.match(saved.id, /^username-example-\d{4}-\d{2}-\d{2}_\d{6}-[a-f0-9]{4}$/);
  assert.ok(existsSync(saved.jsonPath));
  assert.ok(existsSync(saved.htmlPath));

  const listed = listReports(config);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].id, saved.id);
  assert.equal(listed[0].command, 'username');
  assert.equal(listed[0].findingCount, 2);

  const read = readReport(saved.id, config);
  assert.equal(read.target, '@example');
  assert.equal(read.findings.length, 2);

  const html = readReportHtml(saved.id, config);
  assert.ok(html.includes('Results for @example'));

  const stats = reportStats(config);
  assert.equal(stats.count, 1);
  assert.equal(stats.reportsDir, process.env.ARGUS_REPORTS);

  const audit = readAudit(10, config);
  assert.ok(audit.some((entry) => entry.action === 'report.created' && entry.reportId === saved.id));

  assert.equal(deleteReport(saved.id, config), true);
  assert.ok(!existsSync(saved.jsonPath));
  assert.ok(!existsSync(saved.htmlPath));
  assert.throws(() => readReport(saved.id, config), /not found/i);
  assert.throws(() => deleteReport(saved.id, config), /not found/i);
});

test('readReport rejects path traversal and unsafe ids', () => {
  assert.throws(() => readReport('../package', config), /invalid report id/i);
  assert.throws(() => readReport('a/b', config), /invalid report id/i);
  assert.throws(() => readReport('', config), /invalid report id/i);
});

test('purgeReports removes old reports while retention is enabled', () => {
  deleteAllData(config);
  saveReport(makeResult('@old', { createdAt: daysAgo(40) }), config);
  saveReport(makeResult('@fresh', { createdAt: daysAgo(1) }), config);

  const deleted = purgeReports({ settings: { retentionDays: 30, maxReports: 0 } });
  assert.equal(deleted.length, 1);
  const remaining = listReports(config);
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].target, '@fresh');
});

test('purgeReports keeps the newest reports when maxReports is exceeded', () => {
  deleteAllData(config);
  for (const [days, target] of [
    [4, '@four'],
    [3, '@three'],
    [2, '@two'],
    [1, '@one'],
  ]) {
    saveReport(makeResult(target, { createdAt: daysAgo(days) }), config);
  }

  const deleted = purgeReports({ settings: { retentionDays: 0, maxReports: 2 } });
  assert.equal(deleted.length, 2);

  const remaining = listReports(config).map((report) => report.target);
  assert.deepEqual(remaining, ['@one', '@two']);
  assert.equal(readdirSync(process.env.ARGUS_REPORTS).filter((name) => name.endsWith('.json')).length, 2);
});

test('deleteAllData clears reports and the audit log', () => {
  deleteAllData(config);
  saveReport(makeResult('@delete-me'), config);
  assert.ok(listReports(config).length > 0);

  const result = deleteAllData(config);
  assert.ok(result.removed >= 2);
  assert.equal(listReports(config).length, 0);
  const audit = readAudit(50, config);
  assert.ok(audit.some((entry) => entry.action === 'data.deleted_all'));
});
