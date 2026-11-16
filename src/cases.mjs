/**
 * Local case storage.
 *
 * Cases are deliberately stored under the git-ignored data directory. Each
 * case references saved report IDs and keeps only reviewed AI analyses; it
 * never stores provider prompts, raw responses, or API keys.
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync, chmodSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { dataDir, loadConfig } from './config.mjs';
import { readReport } from './report.mjs';
import { analyseCase } from './case-intel.mjs';
import { correlateCaseReports } from './correlate.mjs';
import {
  BUNDLE_SCHEMA,
  LedgerError,
  appendLedgerEntry,
  buildCaseBundle,
  bootstrapLedger,
  deleteCaseKey,
  emptyLedger,
  hashJson,
  hashReport,
  hashString,
  readBundleFile,
  verifyCaseBundle,
  verifyLedger,
} from './ledger.mjs';
import { nowStamp, slugify, truncate, uniq } from './util.mjs';

export const CASE_SCHEMA = 'argus.case/v1';
export const MAX_CASE_REPORTS = 50;
export const MAX_CASE_ANALYSES = 20;

export class CaseError extends Error {
  constructor(message, { code = 'case_error', status = 400, missing = null } = {}) {
    super(message);
    this.name = 'CaseError';
    this.code = code;
    this.status = status;
    this.missing = missing;
  }
}

export function casesDir(config = loadConfig()) {
  return join(dataDir(config), 'cases');
}

function safeCaseId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9._-]{3,200}$/.test(id) && !id.includes('..');
}

function casePath(id, config) {
  if (!safeCaseId(id)) throw new CaseError('Invalid case id.', { code: 'invalid_case_id', status: 400 });
  return join(casesDir(config), `${id}.json`);
}

export function normalizeCaseTitle(value) {
  const title = String(value ?? '').replace(/\s+/g, ' ').trim();
  if (!title) throw new CaseError('Case title is required.', { code: 'invalid_title', status: 400 });
  if (title.length > 200) {
    throw new CaseError('Case title must be 200 characters or fewer.', { code: 'invalid_title', status: 400 });
  }
  return title;
}

export function normalizeCaseNotes(value) {
  const notes = String(value ?? '');
  if (notes.length > 10000) {
    throw new CaseError('Case notes must be 10,000 characters or fewer.', { code: 'invalid_notes', status: 400 });
  }
  return notes;
}

function normalizeReportIds(value, { existing = [] } = {}) {
  if (!Array.isArray(value)) {
    throw new CaseError('reportIds must be an array of saved report IDs.', {
      code: 'invalid_reports',
      status: 400,
    });
  }
  const ids = uniq(
    value
      .filter((id) => typeof id === 'string')
      .map((id) => id.trim())
      .filter(Boolean),
  );
  if (ids.length > MAX_CASE_REPORTS) {
    throw new CaseError(`A case can contain at most ${MAX_CASE_REPORTS} reports.`, {
      code: 'too_many_reports',
      status: 400,
    });
  }
  if (uniq([...existing, ...ids]).length > MAX_CASE_REPORTS) {
    throw new CaseError(`A case can contain at most ${MAX_CASE_REPORTS} reports.`, {
      code: 'too_many_reports',
      status: 400,
    });
  }
  return ids;
}

function normalizeCase(parsed, id) {
  return {
    schema: CASE_SCHEMA,
    id: parsed?.id || id,
    title: String(parsed?.title || 'Untitled case'),
    notes: String(parsed?.notes || ''),
    reportIds: Array.isArray(parsed?.reportIds) ? parsed.reportIds.filter((value) => typeof value === 'string') : [],
    analyses: Array.isArray(parsed?.analyses) ? parsed.analyses : [],
    ledger: parsed?.ledger && typeof parsed.ledger === 'object' ? parsed.ledger : null,
    createdAt: parsed?.createdAt || new Date().toISOString(),
    updatedAt: parsed?.updatedAt || parsed?.createdAt || new Date().toISOString(),
  };
}

function ensureLedger(record, config) {
  if (record.ledger && Array.isArray(record.ledger.entries) && record.ledger.entries.length) {
    return record;
  }
  return bootstrapLedger(record, config);
}

function writeCaseFile(record, config) {
  const dir = casesDir(config);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = casePath(record.id, config);
  const temp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(temp, `${JSON.stringify(record, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  try {
    chmodSync(temp, 0o600);
  } catch {
    /* Windows may ignore POSIX modes; the file remains in the git-ignored data directory. */
  }
  renameSync(temp, path);
  try {
    chmodSync(path, 0o600);
  } catch {
    /* ignore */
  }
  return record;
}

export function createCase(input = {}, config = loadConfig()) {
  const now = new Date().toISOString();
  const title = normalizeCaseTitle(input.title);
  const id = `case-${slugify(title)}-${nowStamp()}-${randomBytes(2).toString('hex')}`;
  const record = {
    schema: CASE_SCHEMA,
    id,
    title,
    notes: normalizeCaseNotes(input.notes),
    reportIds: [],
    analyses: [],
    ledger: emptyLedger(),
    createdAt: now,
    updatedAt: now,
  };
  appendLedgerEntry(
    record,
    'case.created',
    { title: record.title, titleHash: hashString(record.title), notesHash: hashString(record.notes) },
    config,
  );
  writeCaseFile(record, config);
  return record;
}

export function readCase(id, config = loadConfig()) {
  const path = casePath(id, config);
  if (!existsSync(path)) {
    throw new CaseError('Case not found.', { code: 'case_not_found', status: 404 });
  }
  try {
    return normalizeCase(JSON.parse(readFileSync(path, 'utf8')), id);
  } catch (err) {
    if (err instanceof CaseError) throw err;
    throw new CaseError('Case file is unreadable or corrupt.', { code: 'case_unreadable', status: 500 });
  }
}

export function listCases(config = loadConfig()) {
  const dir = casesDir(config);
  if (!existsSync(dir)) return [];
  const cases = [];
  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    const id = name.replace(/\.json$/, '');
    if (!safeCaseId(id)) continue;
    try {
      const record = normalizeCase(JSON.parse(readFileSync(join(dir, name), 'utf8')), id);
      const lastAnalysis = record.analyses[record.analyses.length - 1] || null;
      cases.push({
        id: record.id,
        title: record.title,
        notesPreview: truncate(record.notes, 180),
        reportCount: record.reportIds.length,
        analysisCount: record.analyses.length,
        ledgerEntries: record.ledger?.entries?.length || 0,
        fingerprintShort: record.ledger?.signer?.fingerprintShort || null,
        lastAnalysisAt: lastAnalysis?.createdAt || null,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      });
    } catch {
      /* ignore unreadable case files */
    }
  }
  return cases.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
}

export function updateCase(id, input = {}, config = loadConfig()) {
  const record = ensureLedger(readCase(id, config), config);
  const before = { title: record.title, notes: record.notes };
  if (input.title !== undefined) record.title = normalizeCaseTitle(input.title);
  if (input.notes !== undefined) record.notes = normalizeCaseNotes(input.notes);
  if (record.title !== before.title || record.notes !== before.notes) {
    record.updatedAt = new Date().toISOString();
    appendLedgerEntry(
      record,
      'case.updated',
      {
        title: record.title,
        titleHash: hashString(record.title),
        notesHash: hashString(record.notes),
        changed: [
          ...(record.title !== before.title ? ['title'] : []),
          ...(record.notes !== before.notes ? ['notes'] : []),
        ],
      },
      config,
    );
  }
  return writeCaseFile(record, config);
}

export function deleteCase(id, config = loadConfig()) {
  const path = casePath(id, config);
  if (!existsSync(path)) {
    throw new CaseError('Case not found.', { code: 'case_not_found', status: 404 });
  }
  unlinkSync(path);
  deleteCaseKey(id, config);
  return true;
}

export function attachReports(id, reportIds, config = loadConfig()) {
  const record = ensureLedger(readCase(id, config), config);
  const ids = normalizeReportIds(reportIds, { existing: record.reportIds });
  const missing = [];
  const loaded = new Map();
  for (const reportId of ids) {
    try {
      loaded.set(reportId, readReport(reportId, config));
    } catch {
      missing.push(reportId);
    }
  }
  if (missing.length) {
    throw new CaseError(`Saved report(s) not found: ${missing.join(', ')}.`, {
      code: 'missing_reports',
      status: 400,
      missing,
    });
  }
  const fresh = ids.filter((reportId) => !record.reportIds.includes(reportId));
  record.reportIds = uniq([...record.reportIds, ...ids]);
  record.updatedAt = new Date().toISOString();
  for (const reportId of fresh) {
    appendLedgerEntry(
      record,
      'report.attached',
      { reportId, reportHash: hashReport(loaded.get(reportId)) },
      config,
    );
  }
  return writeCaseFile(record, config);
}

export function removeReport(id, reportId, config = loadConfig()) {
  const record = ensureLedger(readCase(id, config), config);
  if (!record.reportIds.includes(reportId)) {
    throw new CaseError('That report is not attached to this case.', {
      code: 'report_not_attached',
      status: 404,
    });
  }
  record.reportIds = record.reportIds.filter((value) => value !== reportId);
  record.updatedAt = new Date().toISOString();
  appendLedgerEntry(record, 'report.removed', { reportId }, config);
  return writeCaseFile(record, config);
}

export function addAnalysis(id, analysisRecord = {}, config = loadConfig()) {
  const record = ensureLedger(readCase(id, config), config);
  if (!analysisRecord?.analysis || typeof analysisRecord.analysis !== 'object') {
    throw new CaseError('A structured analysis is required.', {
      code: 'invalid_analysis',
      status: 400,
    });
  }

  const stored = {
    id: `analysis-${nowStamp()}-${randomBytes(2).toString('hex')}`,
    createdAt: new Date().toISOString(),
    model: analysisRecord.model || null,
    providerHost: analysisRecord.providerHost || null,
    usage: analysisRecord.usage || null,
    evidence: analysisRecord.evidence || { reportIds: record.reportIds },
    analysis: analysisRecord.analysis,
  };

  record.analyses = [...record.analyses, stored].slice(-MAX_CASE_ANALYSES);
  record.updatedAt = stored.createdAt;
  appendLedgerEntry(
    record,
    'analysis.saved',
    {
      analysisId: stored.id,
      model: stored.model,
      evidenceHash: hashJson(stored.evidence),
      outputHash: hashJson(stored.analysis),
    },
    config,
  );
  writeCaseFile(record, config);
  return { case: record, analysis: stored };
}

export function deleteAnalysis(id, analysisId, config = loadConfig()) {
  const record = ensureLedger(readCase(id, config), config);
  const before = record.analyses.length;
  record.analyses = record.analyses.filter((analysis) => analysis.id !== analysisId);
  if (record.analyses.length === before) {
    throw new CaseError('Analysis not found.', { code: 'analysis_not_found', status: 404 });
  }
  record.updatedAt = new Date().toISOString();
  appendLedgerEntry(record, 'analysis.deleted', { analysisId }, config);
  writeCaseFile(record, config);
  return record;
}

/* ------------------------------------------------------------------ */
/* Integrity and bundles                                               */
/* ------------------------------------------------------------------ */

/**
 * Verify a stored case without changing it. Returns a stable shape used by the
 * CLI, the API, and the web UI.
 */
export function verifyCase(id, config = loadConfig()) {
  const record = readCase(id, config);
  return verifyLedger(record, config);
}

/**
 * Deterministic timeline and contradiction checks over the attached reports.
 * No model, no network, every item cites a report id and a JSON field path.
 */
export function caseIntel(id, config = loadConfig()) {
  const record = readCase(id, config);
  const reports = loadCaseReports(record, config);
  return { ...analyseCase(record, reports), correlations: correlateCaseReports(reports) };
}

/** Read every attached report, or fail with the exact list that is missing. */
function loadCaseReports(record, config) {
  const reports = [];
  const missing = [];
  for (const reportId of record.reportIds) {
    try {
      reports.push({ id: reportId, report: readReport(reportId, config) });
    } catch {
      missing.push(reportId);
    }
  }
  if (missing.length) {
    throw new CaseError(
      `Cannot bundle missing report(s): ${missing.join(', ')}. Re-attach or remove them first.`,
      { code: 'missing_reports', status: 409, missing },
    );
  }
  return reports;
}

/**
 * Sign and write a self-contained `.arguscase` bundle. Defaults to
 * data/bundles/<case-id>.arguscase so bundles never land in the repo.
 */
export function exportCaseBundle(id, config = loadConfig(), { outPath = null } = {}) {
  let record = readCase(id, config);
  if (!record.ledger?.entries?.length) {
    record = bootstrapLedger(record, config);
    writeCaseFile(record, config);
  }
  const reports = loadCaseReports(record, config);
  const intel = { ...analyseCase(record, reports), correlations: correlateCaseReports(reports) };
  let bundle;
  try {
    bundle = buildCaseBundle(record, reports, config, { intel });
  } catch (err) {
    if (err instanceof LedgerError && err.code === 'key_mismatch') {
      throw new CaseError(
        'The case signing key no longer matches its ledger. Restore data/case-keys/ from backup or create a new case.',
        { code: 'key_mismatch', status: 409 },
      );
    }
    throw err;
  }

  const target =
    outPath && String(outPath).trim()
      ? String(outPath).trim()
      : join(dataDir(config), 'bundles', `${record.id}.arguscase`);
  mkdirSync(dirname(target), { recursive: true });
  const temp = `${target}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(temp, `${JSON.stringify(bundle, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  try {
    chmodSync(temp, 0o600);
  } catch {
    /* ignore */
  }
  renameSync(temp, target);
  return { path: target, bundle, case: record };
}

/**
 * Verify a bundle file without touching the original case or private key.
 * `fingerprint` pins the signer out of band.
 */
export function verifyBundleFile(path, { fingerprint = null } = {}) {
  const bundle = readBundleFile(path);
  if (bundle?.manifest?.schema !== BUNDLE_SCHEMA && bundle?.manifest?.schema) {
    throw new LedgerError(`Unsupported bundle schema: ${bundle.manifest.schema}`, {
      code: 'bundle_schema',
      status: 400,
    });
  }
  return { path, ...verifyCaseBundle(bundle, { fingerprint }) };
}

export function caseStats(config = loadConfig()) {
  return {
    count: listCases(config).length,
    dir: casesDir(config),
    maxReportsPerCase: MAX_CASE_REPORTS,
    maxAnalysesPerCase: MAX_CASE_ANALYSES,
  };
}
