/**
 * Tamper-evident case ledger and signed case bundles.
 *
 * Every case owns an append-only hash chain. Each entry hashes its own fields
 * plus the previous entry's hash, and the chain head is signed with an Ed25519
 * key that lives outside the case file (data/case-keys/, git-ignored, 0600 on
 * POSIX). Editing a case note, a ledger entry, or a saved report breaks the
 * chain or the signature, so verification can point at exactly what changed.
 *
 * A case bundle is a single self-contained JSON file with the case, its ledger,
 * the attached reports, and a detached Ed25519 signature over all of it. Anyone
 * holding the bundle can verify it without ARGUS's private key.
 *
 * What this does NOT protect against: someone who controls the machine and
 * rewrites the case, the key file, and the ledger together, or who rolls the
 * whole case back to an older valid snapshot. Pin the fingerprint out of band
 * (ticket, email, release note) and pass --fingerprint when verifying a bundle;
 * retain exported bundles externally to detect rollback over time.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { dataDir, loadConfig } from './config.mjs';
import { readReport } from './report.mjs';
import { VERSION } from './util.mjs';

export const LEDGER_SCHEMA = 'argus.ledger/v1';
export const BUNDLE_SCHEMA = 'argus.bundle/v1';
export const KEY_SCHEMA = 'argus.key/v1';
export const SIGN_ALGORITHM = 'ed25519';
export const GENESIS_HASH = '0'.repeat(64);

export class LedgerError extends Error {
  constructor(message, { code = 'ledger_error', status = 400, missing = null } = {}) {
    super(message);
    this.name = 'LedgerError';
    this.code = code;
    this.status = status;
    this.missing = missing;
  }
}

/* ------------------------------------------------------------------ */
/* Deterministic hashing                                               */
/* ------------------------------------------------------------------ */

/**
 * Stable JSON: sorted object keys, no whitespace, undefined dropped the same
 * way JSON.stringify drops it. Two machines must hash the same bytes.
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => (item === undefined ? 'null' : canonicalJson(item))).join(',')}]`;
  }
  const keys = Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function sha256Hex(value) {
  const data = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
  return createHash('sha256').update(data).digest('hex');
}

export function hashJson(value) {
  return sha256Hex(canonicalJson(value));
}

export function hashString(value) {
  return sha256Hex(String(value ?? ''));
}

export function hashReport(report) {
  return hashJson(report);
}

/* ------------------------------------------------------------------ */
/* Signing keys                                                        */
/* ------------------------------------------------------------------ */

function safeCaseId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9._-]{3,200}$/.test(id) && !id.includes('..');
}

export function caseKeysDir(config = loadConfig()) {
  return join(dataDir(config), 'case-keys');
}

function keyFilePath(caseId, config) {
  if (!safeCaseId(caseId)) throw new LedgerError('Invalid case id.', { code: 'invalid_case_id' });
  return join(caseKeysDir(config), `${caseId}.key.json`);
}

export function fingerprintOf(publicKeyBase64) {
  return sha256Hex(Buffer.from(String(publicKeyBase64 || ''), 'base64'));
}

export function shortFingerprint(fingerprint) {
  return String(fingerprint || '')
    .slice(0, 16)
    .toUpperCase()
    .replace(/(.{4})(?=.)/g, '$1 ');
}

/** Accepts live fingerprints, spaced display forms, and hex prefixes (8+ chars). */
export function normalizePinnedFingerprint(value) {
  const hex = String(value || '')
    .toLowerCase()
    .replace(/[^0-9a-f]/g, '');
  return hex.length >= 8 ? hex : null;
}

export function readCaseKey(caseId, config = loadConfig()) {
  const path = keyFilePath(caseId, config);
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    if (!parsed?.publicKey || !parsed?.privateKey) return null;
    return {
      schema: KEY_SCHEMA,
      caseId,
      algorithm: SIGN_ALGORITHM,
      createdAt: parsed.createdAt || null,
      publicKey: parsed.publicKey,
      privateKey: parsed.privateKey,
      fingerprint: fingerprintOf(parsed.publicKey),
    };
  } catch {
    return null;
  }
}

export function ensureCaseKey(caseId, config = loadConfig()) {
  const existing = readCaseKey(caseId, config);
  if (existing) return existing;

  const dir = caseKeysDir(config);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const pair = generateKeyPairSync('ed25519');
  const record = {
    schema: KEY_SCHEMA,
    caseId,
    algorithm: SIGN_ALGORITHM,
    createdAt: new Date().toISOString(),
    publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
  };
  record.fingerprint = fingerprintOf(record.publicKey);

  const path = keyFilePath(caseId, config);
  const temp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(temp, `${JSON.stringify(record, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  try {
    chmodSync(temp, 0o600);
  } catch {
    /* Windows may ignore POSIX modes; the file stays in the git-ignored data directory. */
  }
  renameSync(temp, path);
  try {
    chmodSync(path, 0o600);
  } catch {
    /* ignore */
  }
  return record;
}

export function deleteCaseKey(caseId, config = loadConfig()) {
  const path = keyFilePath(caseId, config);
  if (existsSync(path)) {
    unlinkSync(path);
    return true;
  }
  return false;
}

export function signHash(hash, privateKeyBase64) {
  const key = createPrivateKey({
    key: Buffer.from(String(privateKeyBase64), 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
  return sign(null, Buffer.from(hash, 'hex'), key).toString('base64');
}

export function verifyHash(hash, signature, publicKeyBase64) {
  try {
    if (!hash || !signature || !publicKeyBase64) return false;
    const key = createPublicKey({
      key: Buffer.from(String(publicKeyBase64), 'base64'),
      format: 'der',
      type: 'spki',
    });
    return verify(null, Buffer.from(hash, 'hex'), key, Buffer.from(String(signature), 'base64'));
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ */
/* Ledger                                                              */
/* ------------------------------------------------------------------ */

export function emptyLedger() {
  return {
    schema: LEDGER_SCHEMA,
    algorithm: SIGN_ALGORITHM,
    createdAt: new Date().toISOString(),
    entries: [],
    head: GENESIS_HASH,
    signer: null,
    signature: null,
  };
}

export function entryHash(entry) {
  return sha256Hex(
    canonicalJson({
      seq: entry.seq,
      at: entry.at,
      type: entry.type,
      details: entry.details,
      prevHash: entry.prevHash,
    }),
  );
}

/**
 * Append and sign one event. Returns the entry that was added; the record's
 * ledger is replaced in place so callers can write the case once.
 */
export function appendLedgerEntry(record, type, details = {}, config = loadConfig()) {
  const key = ensureCaseKey(record.id, config);
  const ledger =
    record.ledger && Array.isArray(record.ledger.entries) ? record.ledger : emptyLedger();
  const previous = ledger.entries[ledger.entries.length - 1] || null;
  const entry = {
    seq: ledger.entries.length,
    at: new Date().toISOString(),
    type,
    details,
    prevHash: previous ? previous.hash : GENESIS_HASH,
  };
  entry.hash = entryHash(entry);

  ledger.entries.push(entry);
  ledger.head = entry.hash;
  ledger.signer = {
    algorithm: SIGN_ALGORITHM,
    fingerprint: key.fingerprint,
    fingerprintShort: shortFingerprint(key.fingerprint),
    publicKey: key.publicKey,
  };
  ledger.signature = signHash(entry.hash, key.privateKey);
  record.ledger = ledger;
  return entry;
}

/**
 * Give a case created before the ledger existed a signed genesis entry plus
 * one entry per already-attached report. Older state is explicitly marked
 * `backfilled` so nobody mistakes it for evidence collected under the ledger.
 */
export function bootstrapLedger(record, config = loadConfig()) {
  const ledger = emptyLedger();
  ledger.createdAt = record.createdAt || ledger.createdAt;
  record.ledger = ledger;
  appendLedgerEntry(
    record,
    'case.created',
    {
      title: record.title,
      titleHash: hashString(record.title),
      notesHash: hashString(record.notes),
      backfilled: true,
    },
    config,
  );
  for (const reportId of record.reportIds || []) {
    let reportHash = null;
    try {
      reportHash = hashReport(readReport(reportId, config));
    } catch {
      reportHash = null;
    }
    appendLedgerEntry(record, 'report.attached', { reportId, reportHash, backfilled: true }, config);
  }
  return record;
}

function problem(problems, code, message, { severity = 'error', ...extra } = {}) {
  problems.push({ code, severity, message, ...extra });
}

function checkChain(ledger, problems) {
  const entries = Array.isArray(ledger?.entries) ? ledger.entries : [];
  let previous = GENESIS_HASH;
  entries.forEach((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      problem(problems, 'entry_malformed', `Ledger entry ${index} is not an object.`, { seq: index });
      return;
    }
    if (entry.seq !== index) {
      problem(problems, 'sequence_mismatch', `Ledger entry ${index} claims sequence ${entry.seq}.`, {
        seq: index,
      });
    }
    if (entry.prevHash !== previous) {
      problem(problems, 'chain_break', `Ledger entry ${index} does not link to the previous hash.`, {
        seq: index,
      });
    }
    if (entryHash(entry) !== entry.hash) {
      problem(problems, 'hash_mismatch', `Ledger entry ${index} has been modified.`, { seq: index });
    }
    previous = entry.hash;
  });
  return { head: previous, entries };
}

/** Latest known hash per report, replayed from attach/remove events. */
function replayedReports(entries) {
  const known = new Map();
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    if (entry.type === 'report.attached' && entry.details?.reportId) {
      known.set(entry.details.reportId, entry.details.reportHash ?? null);
    }
    if (entry.type === 'report.removed' && entry.details?.reportId) {
      known.delete(entry.details.reportId);
    }
  }
  return known;
}

function checkReports({ entries, caseData, reportMap, problems }) {
  const known = replayedReports(entries);
  const attached = Array.isArray(caseData?.reportIds) ? caseData.reportIds : [];
  const results = [];

  for (const reportId of attached) {
    if (!known.has(reportId)) {
      problem(problems, 'report_unhashed', `Report ${reportId} is attached but has no ledger entry.`, {
        severity: 'warning',
        reportId,
      });
      results.push({ reportId, status: 'unhashed' });
      continue;
    }
    const expectedHash = known.get(reportId);
    const report = reportMap?.[reportId];
    if (!report) {
      problem(problems, 'report_missing', `Report ${reportId} is attached but the file is missing.`, {
        reportId,
      });
      results.push({ reportId, status: 'missing', expectedHash });
      continue;
    }
    const actualHash = hashReport(report);
    if (!expectedHash) {
      problem(problems, 'report_unhashed', `Report ${reportId} has no recorded hash.`, {
        severity: 'warning',
        reportId,
      });
      results.push({ reportId, status: 'unhashed', actualHash });
      continue;
    }
    if (actualHash !== expectedHash) {
      problem(problems, 'report_modified', `Report ${reportId} has changed since it was attached.`, {
        reportId,
        expectedHash,
        actualHash,
      });
      results.push({ reportId, status: 'modified', expectedHash, actualHash });
      continue;
    }
    results.push({ reportId, status: 'match', hash: actualHash });
  }

  for (const reportId of known.keys()) {
    if (!attached.includes(reportId)) {
      problem(problems, 'report_set_mismatch', `Report ${reportId} is in the ledger but no longer attached.`, {
        reportId,
      });
    }
  }

  return results;
}

function checkCaseState(entries, caseData, problems) {
  const lastState = [...entries]
    .reverse()
    .find((entry) => entry?.type === 'case.created' || entry?.type === 'case.updated');
  if (!lastState?.details) return;
  if (lastState.details.titleHash && lastState.details.titleHash !== hashString(caseData?.title)) {
    problem(problems, 'case_title_mismatch', 'The case title does not match the signed ledger.', {
      seq: lastState.seq,
    });
  }
  if (lastState.details.notesHash && lastState.details.notesHash !== hashString(caseData?.notes)) {
    problem(problems, 'case_notes_mismatch', 'The case notes do not match the signed ledger.', {
      seq: lastState.seq,
    });
  }
}

function checkAnalyses(entries, caseData, problems) {
  const known = new Map();
  for (const entry of entries) {
    if (entry?.type === 'analysis.saved' && entry.details?.analysisId) {
      known.set(entry.details.analysisId, {
        outputHash: entry.details.outputHash ?? null,
        evidenceHash: entry.details.evidenceHash ?? null,
      });
    }
    if (entry?.type === 'analysis.deleted' && entry.details?.analysisId) {
      known.delete(entry.details.analysisId);
    }
  }
  const present = new Map(
    (caseData?.analyses || []).filter((analysis) => analysis?.id).map((analysis) => [analysis.id, analysis]),
  );
  for (const analysis of present.values()) {
    const expected = known.get(analysis.id);
    if (!expected) continue;
    if (expected.outputHash && hashJson(analysis.analysis) !== expected.outputHash) {
      problem(problems, 'analysis_modified', `Analysis ${analysis.id} has changed since it was saved.`, {
        analysisId: analysis.id,
      });
    }
    if (expected.evidenceHash && hashJson(analysis.evidence) !== expected.evidenceHash) {
      problem(
        problems,
        'analysis_evidence_modified',
        `The evidence reference for analysis ${analysis.id} has changed since it was saved.`,
        { analysisId: analysis.id },
      );
    }
  }
  for (const analysisId of known.keys()) {
    if (!present.has(analysisId)) {
      problem(
        problems,
        'analysis_missing',
        `Analysis ${analysisId} is in the ledger but no longer saved in the case.`,
        { analysisId },
      );
    }
  }
}

function summarise(problems, entries, ledger) {
  const errors = problems.filter((item) => item.severity === 'error');
  return {
    status: !entries.length ? 'unsigned' : errors.length ? 'invalid' : 'valid',
    signed: Boolean(ledger?.signature && ledger?.signer?.publicKey),
    entries: entries.length,
    head: ledger?.head ?? null,
    fingerprint: ledger?.signer?.fingerprint ?? null,
    fingerprintShort: ledger?.signer?.fingerprint
      ? shortFingerprint(ledger.signer.fingerprint)
      : null,
    problems,
    errorCount: errors.length,
    warningCount: problems.length - errors.length,
  };
}

/**
 * Verify a case file on disk: chain, signature, case notes/title, report set,
 * and each attached report's bytes.
 */
export function verifyLedger(record, config = loadConfig()) {
  const checkedAt = new Date().toISOString();
  const ledger = record.ledger;
  const base = {
    caseId: record.id,
    caseTitle: record.title,
    checkedAt,
    keyFilePresent: Boolean(readCaseKey(record.id, config)),
  };

  if (!ledger || !Array.isArray(ledger.entries) || ledger.entries.length === 0) {
    return {
      ...base,
      status: 'unsigned',
      signed: false,
      entries: 0,
      head: null,
      fingerprint: null,
      fingerprintShort: null,
      reports: [],
      errorCount: 0,
      warningCount: 1,
      problems: [
        {
          code: 'no_ledger',
          severity: 'warning',
          message: 'This case has no evidence ledger yet. Save it or export it to start one.',
        },
      ],
    };
  }

  const problems = [];
  const { head, entries } = checkChain(ledger, problems);

  if (ledger.head !== head || ledger.head !== entries[entries.length - 1]?.hash) {
    problem(problems, 'head_mismatch', 'The ledger head does not match the last entry.');
  }

  const signer = ledger.signer;
  const keyFile = readCaseKey(record.id, config);
  if (!signer?.publicKey || !ledger.signature) {
    problem(problems, 'signature_missing', 'The ledger has no signature.');
  } else {
    if (signer.fingerprint && signer.fingerprint !== fingerprintOf(signer.publicKey)) {
      problem(problems, 'signer_fingerprint_mismatch', 'The signer fingerprint does not match its public key.');
    }
    if (!verifyHash(ledger.head, ledger.signature, signer.publicKey)) {
      problem(problems, 'signature_invalid', 'The ledger signature does not verify.');
    }
    if (keyFile && keyFile.publicKey !== signer.publicKey) {
      problem(problems, 'key_mismatch', 'The ledger was signed by a different key than the case key on disk.');
    }
    if (!keyFile) {
      problem(problems, 'key_file_missing', 'The case signing key is not on this machine; the signature cannot be tied to a local key.', {
        severity: 'warning',
      });
    }
  }

  checkCaseState(entries, record, problems);
  checkAnalyses(entries, record, problems);

  const reportMap = {};
  for (const reportId of record.reportIds || []) {
    try {
      reportMap[reportId] = readReport(reportId, config);
    } catch {
      /* checkReports reports the missing file */
    }
  }
  const reports = checkReports({ entries, caseData: record, reportMap, problems });

  return { ...base, ...summarise(problems, entries, ledger), reports };
}

/* ------------------------------------------------------------------ */
/* Bundles                                                             */
/* ------------------------------------------------------------------ */

export function bundlePayload(bundle) {
  return {
    manifest: bundle.manifest,
    case: bundle.case,
    reports: bundle.reports,
    ledger: bundle.ledger,
    intel: bundle.intel,
  };
}

/**
 * Build a signed, self-contained bundle. `reports` is an array of
 * { id, report } objects; every attached report must be present. `intel` is the
 * optional deterministic case analysis, signed along with everything else.
 */
export function buildCaseBundle(record, reports, config = loadConfig(), { intel = null } = {}) {
  if (!record.ledger?.entries?.length) {
    throw new LedgerError('This case has no ledger to sign yet.', { code: 'no_ledger', status: 400 });
  }
  const key = readCaseKey(record.id, config);
  if (!key) {
    throw new LedgerError('The case signing key is missing. Reopen the case to create a new ledger.', {
      code: 'missing_case_key',
      status: 400,
    });
  }
  if (key.publicKey !== record.ledger.signer?.publicKey) {
    throw new LedgerError('The case signing key does not match the ledger signer.', {
      code: 'key_mismatch',
      status: 409,
    });
  }

  const reportMap = {};
  for (const item of reports) {
    if (item?.id && item.report) reportMap[item.id] = item.report;
  }
  const missing = (record.reportIds || []).filter((id) => !reportMap[id]);
  if (missing.length) {
    throw new LedgerError(`Cannot bundle missing report(s): ${missing.join(', ')}.`, {
      code: 'missing_reports',
      status: 409,
      missing,
    });
  }

  const manifest = {
    schema: BUNDLE_SCHEMA,
    tool: { name: 'ARGUS', version: VERSION },
    exportedAt: new Date().toISOString(),
    caseId: record.id,
    caseTitle: record.title,
    reportIds: [...record.reportIds],
    reportCount: record.reportIds.length,
    analysisCount: record.analyses.length,
    ledgerEntries: record.ledger.entries.length,
    ledgerHead: record.ledger.head,
    signer: {
      algorithm: SIGN_ALGORITHM,
      fingerprint: key.fingerprint,
      fingerprintShort: shortFingerprint(key.fingerprint),
      publicKey: key.publicKey,
    },
  };

  const caseData = {
    schema: record.schema,
    id: record.id,
    title: record.title,
    notes: record.notes,
    reportIds: [...record.reportIds],
    analyses: record.analyses,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };

  const payload = { manifest, case: caseData, reports: reportMap, ledger: record.ledger };
  if (intel) payload.intel = intel;
  const digest = hashJson(payload);
  return { ...payload, digest, signature: signHash(digest, key.privateKey) };
}

/**
 * Verify a bundle with no access to the original case or private key.
 * Pass { fingerprint } to pin the signer out of band.
 */
export function verifyCaseBundle(bundle, { fingerprint = null } = {}) {
  const checkedAt = new Date().toISOString();
  const problems = [];

  if (!bundle || typeof bundle !== 'object') {
    return {
      status: 'invalid',
      bundle: true,
      checkedAt,
      entries: 0,
      signed: false,
      reports: [],
      errorCount: 1,
      warningCount: 0,
      problems: [{ code: 'bundle_unreadable', severity: 'error', message: 'Bundle is not a JSON object.' }],
    };
  }

  const manifest = bundle.manifest;
  const ledger = bundle.ledger;
  const caseData = bundle.case || {};

  if (manifest?.schema !== BUNDLE_SCHEMA) {
    problem(problems, 'bundle_schema', `Expected ${BUNDLE_SCHEMA}.`, {
      actual: manifest?.schema ?? null,
    });
  }
  if (!ledger || !Array.isArray(ledger.entries) || ledger.entries.length === 0) {
    problem(problems, 'no_ledger', 'The bundle contains no ledger.');
  }

  const { head, entries } = checkChain(ledger, problems);
  if (entries.length) {
    if (ledger.head !== head || ledger.head !== entries[entries.length - 1]?.hash) {
      problem(problems, 'head_mismatch', 'The ledger head does not match the last entry.');
    }
    if (manifest?.ledgerHead && manifest.ledgerHead !== ledger.head) {
      problem(problems, 'manifest_head_mismatch', 'The manifest head does not match the ledger head.');
    }
    if (Number(manifest?.ledgerEntries) !== entries.length) {
      problem(problems, 'manifest_entry_count', 'The manifest entry count does not match the ledger.');
    }
  }

  const signer = manifest?.signer;
  if (!signer?.publicKey || !bundle.signature) {
    problem(problems, 'signature_missing', 'The bundle has no signature.');
  } else {
    if (signer.fingerprint && signer.fingerprint !== fingerprintOf(signer.publicKey)) {
      problem(problems, 'signer_fingerprint_mismatch', 'The signer fingerprint does not match its public key.');
    }
    if (ledger?.signer?.publicKey && ledger.signer.publicKey !== signer.publicKey) {
      problem(problems, 'signer_mismatch', 'The ledger and the manifest were signed by different keys.');
    }
    if (fingerprint) {
      const pinned = normalizePinnedFingerprint(fingerprint);
      if (!pinned) {
        problem(problems, 'fingerprint_invalid', 'The pinned fingerprint must contain at least 8 hex characters.');
      } else if (!String(signer.fingerprint || '').startsWith(pinned)) {
        problem(problems, 'fingerprint_mismatch', 'The bundle signer does not match the pinned fingerprint.', {
          expected: pinned,
          actual: signer.fingerprint || null,
        });
      }
    }
    if (ledger?.signer?.publicKey && ledger?.signer?.fingerprint) {
      if (ledger.signer.fingerprint !== fingerprintOf(ledger.signer.publicKey)) {
        problem(problems, 'ledger_fingerprint_mismatch', 'The ledger fingerprint does not match its public key.');
      }
    }
    if (ledger?.head && ledger?.signature && ledger?.signer?.publicKey) {
      if (!verifyHash(ledger.head, ledger.signature, ledger.signer.publicKey)) {
        problem(problems, 'ledger_signature_invalid', 'The ledger head signature inside the bundle does not verify.');
      }
    }
    const digest = hashJson(bundlePayload(bundle));
    if (bundle.digest && bundle.digest !== digest) {
      problem(problems, 'bundle_digest_mismatch', 'The bundle contents do not match their digest.');
    }
    if (!verifyHash(digest, bundle.signature, signer.publicKey)) {
      problem(problems, 'bundle_signature_invalid', 'The bundle signature does not verify.');
    }
  }

  checkCaseState(entries, caseData, problems);

  const reports = checkReports({ entries, caseData, reportMap: bundle.reports || {}, problems });
  for (const reportId of caseData.reportIds || []) {
    if (!bundle.reports || !bundle.reports[reportId]) {
      problem(problems, 'bundle_report_missing', `Report ${reportId} is not included in the bundle.`, {
        reportId,
      });
    }
  }
  if (Array.isArray(manifest?.reportIds)) {
    const listed = [...manifest.reportIds].sort().join('\u0000');
    const attached = [...(caseData.reportIds || [])].sort().join('\u0000');
    if (listed !== attached) {
      problem(problems, 'manifest_report_mismatch', 'The manifest report list does not match the case.');
    }
  }

  const summary = summarise(problems, entries, ledger);
  return {
    ...summary,
    bundle: true,
    checkedAt,
    caseId: manifest?.caseId ?? caseData.id ?? null,
    caseTitle: manifest?.caseTitle ?? caseData.title ?? null,
    exportedAt: manifest?.exportedAt ?? null,
    tool: manifest?.tool ?? null,
    fingerprint: signer?.fingerprint ?? summary.fingerprint,
    fingerprintShort: signer?.fingerprintShort ?? summary.fingerprintShort,
    reports,
  };
}

export function readBundleFile(path) {
  if (!existsSync(path)) {
    throw new LedgerError(`Bundle not found: ${path}`, { code: 'bundle_not_found', status: 404 });
  }
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new LedgerError(`Bundle is unreadable or corrupt: ${err.message}`, {
      code: 'bundle_unreadable',
      status: 400,
    });
  }
}
