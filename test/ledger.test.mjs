import test from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { saveReport } from '../src/report.mjs';
import {
  addAnalysis,
  attachReports,
  casesDir,
  createCase,
  deleteCase,
  exportCaseBundle,
  readCase,
  updateCase,
  verifyBundleFile,
  verifyCase,
} from '../src/cases.mjs';
import { canonicalJson, caseKeysDir, hashJson, hashString } from '../src/ledger.mjs';

const workdir = mkdtempSync(join(tmpdir(), 'argus-ledger-test-'));
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

test.after(() => rmSync(workdir, { recursive: true, force: true }));

function reportResult(target, createdAt = '2026-01-01T10:00:00.000Z') {
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

function caseFile(id) {
  return join(casesDir(config), `${id}.json`);
}

function editCaseFile(id, mutate) {
  const parsed = JSON.parse(readFileSync(caseFile(id), 'utf8'));
  mutate(parsed);
  writeFileSync(caseFile(id), `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
}

test('canonicalJson is stable regardless of key order', () => {
  assert.equal(canonicalJson({ b: 1, a: [2, { d: 4, c: 3 }] }), '{"a":[2,{"c":3,"d":4}],"b":1}');
  assert.equal(hashJson({ a: 1, b: 2 }), hashJson({ b: 2, a: 1 }));
  assert.equal(hashString('x'), hashString('x'));
});

test('a new case starts a signed ledger with a stable fingerprint', () => {
  const first = createCase({ title: 'Signed case', notes: 'Initial notes' }, config);
  assert.equal(first.ledger.entries.length, 1);
  assert.equal(first.ledger.entries[0].type, 'case.created');
  assert.equal(first.ledger.entries[0].prevHash, '0'.repeat(64));
  assert.match(first.ledger.signer.fingerprint, /^[0-9a-f]{64}$/);

  const verification = verifyCase(first.id, config);
  assert.equal(verification.status, 'valid');
  assert.equal(verification.signed, true);
  assert.equal(verification.errorCount, 0);
  assert.equal(verification.fingerprint, first.ledger.signer.fingerprint);
  assert.equal(verification.keyFilePresent, true);

  const second = createCase({ title: 'Another case' }, config);
  assert.notEqual(second.ledger.signer.fingerprint, first.ledger.signer.fingerprint);
});

test('attaching, editing, removing, and re-reading keep the ledger valid', () => {
  const record = createCase({ title: 'Working case', notes: 'Draft' }, config);
  const report = saveReport(reportResult('torvalds'), config);

  const attached = attachReports(record.id, [report.id], config);
  assert.equal(attached.ledger.entries.at(-1).type, 'report.attached');
  assert.equal(attached.ledger.entries.at(-1).details.reportId, report.id);

  const updated = updateCase(record.id, { notes: 'Reviewed notes' }, config);
  assert.equal(updated.ledger.entries.at(-1).type, 'case.updated');
  assert.deepEqual(updated.ledger.entries.at(-1).details.changed, ['notes']);

  const reread = readCase(record.id, config);
  const verification = verifyCase(record.id, config);
  assert.equal(verification.status, 'valid');
  assert.equal(verification.reports.length, 1);
  assert.equal(verification.reports[0].reportId, report.id);
  assert.equal(verification.reports[0].status, 'match');
  assert.match(verification.reports[0].hash, /^[0-9a-f]{64}$/);
  assert.equal(reread.ledger.entries.length, 3);
});

test('editing case notes outside the ledger is detected', () => {
  const record = createCase({ title: 'Tampered notes', notes: 'Original' }, config);
  editCaseFile(record.id, (parsed) => {
    parsed.notes = 'Something else';
  });
  const verification = verifyCase(record.id, config);
  assert.equal(verification.status, 'invalid');
  assert.ok(verification.problems.some((item) => item.code === 'case_notes_mismatch'));
});

test('editing a saved analysis or its evidence reference is detected', () => {
  const record = createCase({ title: 'Analysed case' }, config);
  addAnalysis(
    record.id,
    {
      analysis: { summary: 'Original summary' },
      evidence: { reportIds: [] },
      model: 'test-model',
    },
    config,
  );
  editCaseFile(record.id, (parsed) => {
    parsed.analyses[0].analysis.summary = 'Forged summary';
    parsed.analyses[0].evidence.reportIds = ['invented-report'];
  });
  const verification = verifyCase(record.id, config);
  assert.equal(verification.status, 'invalid');
  assert.ok(verification.problems.some((item) => item.code === 'analysis_modified'));
  assert.ok(verification.problems.some((item) => item.code === 'analysis_evidence_modified'));
});

test('deleting a saved analysis without a ledger entry is detected', () => {
  const record = createCase({ title: 'Analysis removal' }, config);
  addAnalysis(
    record.id,
    {
      analysis: { summary: 'Keep me' },
      evidence: { reportIds: [] },
    },
    config,
  );
  editCaseFile(record.id, (parsed) => {
    parsed.analyses = [];
  });
  const verification = verifyCase(record.id, config);
  assert.equal(verification.status, 'invalid');
  assert.ok(verification.problems.some((item) => item.code === 'analysis_missing'));
});

test('editing a saved report after attaching it is detected', () => {
  const record = createCase({ title: 'Tampered report' }, config);
  const report = saveReport(reportResult('tamper-target'), config);
  attachReports(record.id, [report.id], config);

  const path = join(process.env.ARGUS_REPORTS, `${report.id}.json`);
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  parsed.target = 'someone-else';
  writeFileSync(path, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');

  const verification = verifyCase(record.id, config);
  assert.equal(verification.status, 'invalid');
  const modified = verification.reports.find((item) => item.reportId === report.id);
  assert.equal(modified.status, 'modified');
  assert.ok(verification.problems.some((item) => item.code === 'report_modified'));
});

test('editing a ledger entry breaks the chain', () => {
  const record = createCase({ title: 'Tampered chain', notes: 'Original' }, config);
  editCaseFile(record.id, (parsed) => {
    parsed.ledger.entries[0].details.notesHash = hashString('forged');
  });
  const verification = verifyCase(record.id, config);
  assert.equal(verification.status, 'invalid');
  assert.ok(verification.problems.some((item) => item.code === 'hash_mismatch'));
});

test('replacing the ledger head without the signing key is detected', () => {
  const record = createCase({ title: 'Forged head', notes: 'Original' }, config);
  editCaseFile(record.id, (parsed) => {
    parsed.ledger.head = 'f'.repeat(64);
  });
  const verification = verifyCase(record.id, config);
  assert.equal(verification.status, 'invalid');
  assert.ok(verification.problems.some((item) => item.code === 'head_mismatch'));
  assert.ok(verification.problems.some((item) => item.code === 'signature_invalid'));
});

test('a bundle that carries an invalid ledger signature is rejected', () => {
  const record = createCase({ title: 'Bad ledger signature' }, config);
  editCaseFile(record.id, (parsed) => {
    parsed.ledger.signature = 'AAAA';
  });
  const { path } = exportCaseBundle(record.id, config);
  const verification = verifyBundleFile(path);
  assert.equal(verification.status, 'invalid');
  assert.ok(verification.problems.some((item) => item.code === 'ledger_signature_invalid'));
});

test('a signed bundle verifies without the private key and detects edits', () => {
  const record = createCase({ title: 'Bundled case', notes: 'Bundle notes' }, config);
  const report = saveReport(reportResult('bundle-target'), config);
  attachReports(record.id, [report.id], config);

  const out = join(workdir, 'dist', 'case.arguscase');
  const { path, bundle } = exportCaseBundle(record.id, config, { outPath: out });
  assert.ok(existsSync(path));
  assert.equal(bundle.manifest.schema, 'argus.bundle/v1');
  assert.equal(bundle.manifest.reportCount, 1);
  assert.ok(bundle.signature);
  assert.equal(bundle.intel.schema, 'argus.case-intel/v1');
  assert.equal(bundle.intel.reportCount, 1);
  assert.ok(bundle.intel.timeline.count >= 1);
  assert.ok(Array.isArray(bundle.intel.correlations.repeatedIndicators));

  const verified = verifyBundleFile(path);
  assert.equal(verified.status, 'valid');
  assert.equal(verified.bundle, true);
  assert.equal(verified.reports[0].status, 'match');
  assert.equal(verified.errorCount, 0);

  const pinned = verifyBundleFile(path, { fingerprint: verified.fingerprint.slice(0, 12) });
  assert.equal(pinned.status, 'valid');

  const wrong = verifyBundleFile(path, { fingerprint: 'deadbeefdeadbeef' });
  assert.equal(wrong.status, 'invalid');
  assert.ok(wrong.problems.some((item) => item.code === 'fingerprint_mismatch'));
});

test('a bundle whose contents were edited fails signature verification', () => {
  const record = createCase({ title: 'Edited bundle', notes: 'Original' }, config);
  const { path } = exportCaseBundle(record.id, config);
  const bundle = JSON.parse(readFileSync(path, 'utf8'));
  bundle.case.notes = 'Edited after export';
  const tampered = join(workdir, 'edited.arguscase');
  writeFileSync(tampered, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');

  const verification = verifyBundleFile(tampered);
  assert.equal(verification.status, 'invalid');
  assert.ok(
    verification.problems.some(
      (item) => item.code === 'bundle_signature_invalid' || item.code === 'bundle_digest_mismatch',
    ),
  );
  assert.ok(verification.problems.some((item) => item.code === 'case_notes_mismatch'));
});

test('a swapped signer key is rejected even though the chain re-verifies', () => {
  const record = createCase({ title: 'Swapped key', notes: 'Notes' }, config);
  const { path } = exportCaseBundle(record.id, config);
  const bundle = JSON.parse(readFileSync(path, 'utf8'));
  const other = createCase({ title: 'Other' }, config);

  bundle.manifest.signer.publicKey = other.ledger.signer.publicKey;
  bundle.manifest.signer.fingerprint = other.ledger.signer.fingerprint;
  bundle.ledger.signer.publicKey = other.ledger.signer.publicKey;
  bundle.ledger.signer.fingerprint = other.ledger.signer.fingerprint;
  const tampered = join(workdir, 'swapped.arguscase');
  writeFileSync(tampered, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');

  const verification = verifyBundleFile(tampered);
  assert.equal(verification.status, 'invalid');
  assert.ok(verification.problems.some((item) => item.code === 'bundle_signature_invalid'));
});

test('deleting a case removes its signing key', () => {
  const record = createCase({ title: 'Delete me' }, config);
  assert.ok(readdirSync(caseKeysDir(config)).some((name) => name.startsWith(record.id)));
  deleteCase(record.id, config);
  assert.equal(existsSync(caseFile(record.id)), false);
  assert.equal(
    readdirSync(caseKeysDir(config)).some((name) => name.startsWith(record.id)),
    false,
  );
});

test('a legacy case gains a backfilled ledger on its next change', () => {
  const record = createCase({ title: 'Legacy case' }, config);
  editCaseFile(record.id, (parsed) => {
    delete parsed.ledger;
  });
  const first = verifyCase(record.id, config);
  assert.equal(first.status, 'unsigned');

  const report = saveReport(reportResult('legacy-target'), config);
  const updated = attachReports(record.id, [report.id], config);
  assert.equal(updated.ledger.entries[0].details.backfilled, true);
  assert.equal(updated.ledger.entries.at(-1).type, 'report.attached');
  assert.equal(verifyCase(record.id, config).status, 'valid');
});

test('bundles default to the git-ignored data directory', () => {
  const record = createCase({ title: 'Default path' }, config);
  const { path } = exportCaseBundle(record.id, config);
  assert.equal(path, join(process.env.ARGUS_DATA, 'bundles', `${record.id}.arguscase`));
  mkdirSync(join(workdir, 'tmpdir'), { recursive: true });
});
