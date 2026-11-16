import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { saveReport } from '../src/report.mjs';
import { saveAiKey } from '../src/ai.mjs';
import {
  addAnalysis,
  attachReports,
  casesDir,
  createCase,
  deleteAnalysis,
  deleteCase,
  listCases,
  readCase,
  removeReport,
  updateCase,
} from '../src/cases.mjs';

const workdir = mkdtempSync(join(tmpdir(), 'argus-cases-test-'));
process.env.ARGUS_REPORTS = join(workdir, 'reports');
process.env.ARGUS_DATA = join(workdir, 'data');
process.env.ARGUS_CONFIG = join(workdir, 'argus.config.json');

const config = {
  settings: {
    retentionDays: 0,
    maxReports: 0,
    logTargetsInAudit: true,
    ai: { baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
  },
  sources: {},
};

function reportResult(target, createdAt) {
  return {
    command: 'username',
    target,
    createdAt,
    finishedAt: createdAt,
    durationMs: 12,
    summary: { confirmed: 1, possible: 0, unverified: 0, absent: 0, blocked: 0, skipped: 0, error: 0 },
    risk: { score: 10, level: 'low', findings: [], recommendations: [] },
    findings: [
      {
        id: 'github',
        name: 'GitHub',
        category: 'developer',
        status: 'confirmed',
        confidence: 'high',
        detail: 'Profile page exists.',
        url: `https://github.com/${target}`,
        profile: { fields: [{ label: 'Name', value: target }], links: [] },
      },
    ],
    absent: [],
    warnings: [],
    notes: [],
  };
}

const first = saveReport(reportResult('example', '2026-11-16T10:00:00.000Z'), config);
const second = saveReport(reportResult('second', '2026-11-16T10:01:00.000Z'), config);

test.after(() => rmSync(workdir, { recursive: true, force: true }));

test('cases persist title, notes, and report attachments', () => {
  const created = createCase({ title: '  Example   case  ', notes: 'Initial notes.' }, config);
  assert.match(created.id, /^case-example-case-/);
  assert.equal(created.title, 'Example case');
  assert.equal(created.notes, 'Initial notes.');
  assert.deepEqual(created.reportIds, []);

  const attached = attachReports(created.id, [first.id, second.id], config);
  assert.deepEqual(attached.reportIds, [first.id, second.id]);

  const updated = updateCase(created.id, { title: 'Renamed case', notes: 'Updated notes.' }, config);
  assert.equal(updated.title, 'Renamed case');
  assert.equal(updated.notes, 'Updated notes.');

  const reread = readCase(created.id, config);
  assert.equal(reread.title, 'Renamed case');
  assert.deepEqual(reread.reportIds, [first.id, second.id]);

  const listed = listCases(config);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].reportCount, 2);

  assert.ok(existsSync(join(casesDir(config), `${created.id}.json`)));
});

test('validates titles, notes, missing reports, and unsafe case ids', () => {
  assert.throws(() => createCase({ title: '   ' }, config), /title is required/);
  assert.throws(() => createCase({ title: 'x', notes: 'a'.repeat(10001) }, config), /10,000 characters/);
  assert.throws(() => readCase('../../etc/passwd', config), /Invalid case id/);

  const created = createCase({ title: 'Missing report case' }, config);
  assert.throws(
    () => attachReports(created.id, ['does-not-exist'], config),
    (err) => err.code === 'missing_reports' && err.missing.includes('does-not-exist'),
  );
});

test('removing a report leaves the report file but detaches it from the case', () => {
  const created = createCase({ title: 'Detach case' }, config);
  attachReports(created.id, [first.id], config);
  const record = removeReport(created.id, first.id, config);
  assert.deepEqual(record.reportIds, []);
  assert.throws(() => removeReport(created.id, first.id, config), /not attached/);
});

test('saved analyses persist and can be deleted without touching reports', () => {
  const created = createCase({ title: 'Analysis case' }, config);
  attachReports(created.id, [first.id], config);

  const analysis = {
    schema: 'argus.analysis/v1',
    summary: 'Only one report was sent.',
    observedEvidence: [],
    interpretations: [],
    uncertainty: [],
    suggestedNextSteps: [],
    unsupportedClaims: [],
    warnings: [],
    citations: { total: 0, valid: 0, invalid: 0 },
    model: 'mock-model',
  };

  const saved = addAnalysis(
    created.id,
    {
      analysis,
      model: 'mock-model',
      usage: { totalTokens: 42 },
      evidence: { reportIds: [first.id] },
      providerHost: 'api.example.test',
    },
    config,
  );

  assert.match(saved.analysis.id, /^analysis-/);
  assert.equal(saved.case.analyses.length, 1);
  assert.equal(readCase(created.id, config).analyses[0].analysis.summary, 'Only one report was sent.');

  const removed = deleteAnalysis(created.id, saved.analysis.id, config);
  assert.equal(removed.analyses.length, 0);
  assert.throws(() => deleteAnalysis(created.id, saved.analysis.id, config), /Analysis not found/);
});

test('case files never contain the AI API key', () => {
  saveAiKey('sk-must-not-appear-in-case-files', config);
  const created = createCase({ title: 'Secret check case', notes: 'No secrets here.' }, config);
  const contents = readFileSync(join(casesDir(config), `${created.id}.json`), 'utf8');
  assert.doesNotMatch(contents, /sk-must-not-appear-in-case-files/);
});

test('deleting a case does not delete its reports', () => {
  const created = createCase({ title: 'Delete case' }, config);
  attachReports(created.id, [second.id], config);
  assert.equal(deleteCase(created.id, config), true);
  assert.ok(existsSync(join(process.env.ARGUS_REPORTS, `${second.id}.json`)));
  assert.throws(() => readCase(created.id, config), /not found/);
});
