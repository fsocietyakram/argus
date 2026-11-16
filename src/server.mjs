import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AiError, aiSettingsView, currentAiSettings, requestCaseAnalysis, updateAiSettings } from './ai.mjs';
import { appendAudit, clearAudit, readAudit } from './audit.mjs';
import {
  CaseError,
  addAnalysis,
  attachReports,
  caseIntel,
  caseStats,
  createCase,
  deleteAnalysis,
  deleteCase,
  exportCaseBundle,
  listCases,
  readCase,
  removeReport,
  updateCase,
  verifyCase,
} from './cases.mjs';
import {
  createDataDirs,
  loadConfig,
  resolvedSources,
  saveConfig,
  setSourceEnabled,
} from './config.mjs';
import { scanDomain } from './domain.mjs';
import { scanEmail } from './email.mjs';
import { analyzeFile, stripMetadata } from './exif.mjs';
import { deleteAllData, deleteReport, listReports, purgeReports, readReport, readReportHtml, reportStats, saveReport } from './report.mjs';
import { CATEGORY_LABELS } from './sites.mjs';
import { normalizeUsername, scanUsername } from './username.mjs';
import { TOOL, VERSION } from './util.mjs';
import { correlateCaseReports } from './correlate.mjs';

const PUBLIC_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'public');
const MAX_JSON = 1_000_000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const jobs = new Map();
const aiPreviews = new Map();
const AI_PREVIEW_TTL_MS = 30 * 60 * 1000;

function pruneAiPreviews() {
  const now = Date.now();
  for (const [id, preview] of aiPreviews) {
    if (new Date(preview.expiresAt).getTime() <= now) aiPreviews.delete(id);
  }
  while (aiPreviews.size > 20) {
    aiPreviews.delete(aiPreviews.keys().next().value);
  }
}

function providerHost(baseUrl) {
  try {
    return new URL(baseUrl).host || null;
  } catch {
    return null;
  }
}

function caseReportView(record, config) {
  return record.reportIds.map((id) => {
    try {
      const report = readReport(id, config);
      return {
        id,
        command: report.command,
        target: report.target,
        createdAt: report.createdAt,
        riskScore: report.risk?.score ?? null,
        riskLevel: report.risk?.level ?? null,
        missing: false,
      };
    } catch {
      return { id, missing: true };
    }
  });
}

/** Case payload with the report summary and fresh cross-report correlations. */
function caseResponse(record, config) {
  const reports = record.reportIds.flatMap((reportId) => {
    try {
      return [{ id: reportId, report: readReport(reportId, config) }];
    } catch {
      return [];
    }
  });
  return {
    ...record,
    reports: caseReportView(record, config),
    correlations: correlateCaseReports(reports),
  };
}

function json(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    ...extraHeaders,
  });
  res.end(body);
}

function text(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(body);
}

function readBody(req, limit) {
  return new Promise((resolveBody, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > limit) {
        const error = new Error(`Payload exceeds ${Math.round(limit / 1024 / 1024)} MB limit.`);
        error.status = 413;
        reject(error);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolveBody(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJson(req, limit = MAX_JSON) {
  const body = await readBody(req, limit);
  if (!body.length) return {};
  try {
    return JSON.parse(body.toString('utf8'));
  } catch {
    const error = new Error('Invalid JSON body.');
    error.status = 400;
    throw error;
  }
}

function safeFilename(raw, fallback = 'upload.bin') {
  let name = String(raw || fallback);
  try {
    name = decodeURIComponent(name);
  } catch {
    /* keep raw */
  }
  name = name.split(/[\\/]/).pop() || fallback;
  name = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').trim();
  return name.slice(0, 120) || fallback;
}

function startJob(kind, target, runner, config) {
  const id = randomBytes(8).toString('hex');
  const job = {
    id,
    kind,
    target,
    status: 'running',
    progress: { phase: 'start', completed: 0, total: 1 },
    result: null,
    report: null,
    error: null,
    createdAt: new Date().toISOString(),
  };
  jobs.set(id, job);

  appendAudit({ action: 'search.started', command: kind, target }, config);

  (async () => {
    try {
      const result = await runner((progress) => {
        job.progress = { ...progress, at: new Date().toISOString() };
      });
      job.result = result;
      try {
        job.report = saveReport(result, config);
      } catch (err) {
        job.reportError = `Report could not be saved: ${err.message}`;
      }
      job.status = 'done';
      job.progress = { ...job.progress, phase: 'done', completed: job.progress.total };
      appendAudit({ action: 'search.completed', command: kind, target, reportId: job.report?.id }, config);
    } catch (err) {
      job.status = 'error';
      job.error = err.message || String(err);
      appendAudit({ action: 'search.failed', command: kind, target, details: job.error }, config);
    } finally {
      const timer = setTimeout(() => jobs.delete(id), 30 * 60 * 1000);
      timer.unref?.();
    }
  })();

  return job;
}

function summariseSource(source) {
  return {
    id: source.id,
    name: source.name,
    category: source.category,
    categoryLabel: CATEGORY_LABELS[source.category] || source.category,
    access: source.access,
    url: source.url,
    enabled: source.enabled,
    confidence: source.confidence,
    respectRobots: source.respectRobots,
    rateLimit: source.rateLimit,
    rateLimitNote: source.rateLimitNote || null,
    tos: source.tos,
  };
}

export function createAppServer(config = loadConfig()) {
  createDataDirs(config);
  try {
    purgeReports(config);
  } catch (err) {
    console.warn(`[argus] Report retention cleanup failed: ${err.message}`);
  }

  const server = http.createServer(async (req, res) => {
    const started = Date.now();

    res.on('finish', () => {
      if (process.env.ARGUS_HTTP_LOG) {
        console.log(`[http] ${req.method} ${req.url} ${res.statusCode} ${Date.now() - started}ms`);
      }
    });

    try {
      if (!req.url) return json(res, 400, { error: 'Missing URL.' });
      const url = new URL(req.url, 'http://127.0.0.1');
      const path = decodeURIComponent(url.pathname);
      const method = req.method || 'GET';

      // Mutating API requests must carry the custom header; blocks simple cross-site forms.
      if (method !== 'GET' && path.startsWith('/api/')) {
        if (req.headers['x-argus'] !== '1') {
          return json(res, 403, { error: 'Missing X-Argus header.' });
        }
        const origin = req.headers.origin;
        if (origin) {
          try {
            if (new URL(origin).host !== req.headers.host) {
              return json(res, 403, { error: 'Cross-origin request rejected.' });
            }
          } catch {
            return json(res, 403, { error: 'Invalid Origin header.' });
          }
        }
      }

      /* ------------------------------ API ------------------------------ */

      if (path === '/api/health' && method === 'GET') {
        return json(res, 200, {
          ok: true,
          tool: TOOL,
          version: VERSION,
          time: new Date().toISOString(),
          hibpConfigured: Boolean(process.env[config.settings?.hibpApiKeyEnv || 'HIBP_API_KEY']),
          aiConfigured: aiSettingsView(config).keyConfigured,
        });
      }

      if (path === '/api/config' && method === 'GET') {
        const sources = resolvedSources(config);
        const categories = [...new Set(sources.map((source) => source.category))].map((category) => ({
          id: category,
          label: CATEGORY_LABELS[category] || category,
          count: sources.filter((source) => source.category === category).length,
        }));

        return json(res, 200, {
          tool: TOOL,
          version: VERSION,
          settings: {
            concurrency: config.settings.concurrency,
            timeoutMs: config.settings.timeoutMs,
            respectRobots: config.settings.respectRobots,
            retentionDays: config.settings.retentionDays,
            maxReports: config.settings.maxReports,
            maxUploadMb: config.settings.maxUploadMb,
            logTargetsInAudit: config.settings.logTargetsInAudit,
          },
          hibpConfigured: Boolean(process.env[config.settings?.hibpApiKeyEnv || 'HIBP_API_KEY']),
          ai: aiSettingsView(config),
          categories,
          sources: sources.map(summariseSource),
          stats: reportStats(config),
        });
      }

      /* ------------------------------ AI ------------------------------- */

      if (path === '/api/ai/settings' && method === 'GET') {
        return json(res, 200, { settings: aiSettingsView(config) });
      }

      if (path === '/api/ai/settings' && method === 'PUT') {
        const body = await readJson(req, 16_000);
        const result = updateAiSettings(body, config);
        appendAudit(
          {
            action: 'ai.settings_updated',
            details: {
              baseUrl: result.settings.baseUrl,
              model: result.settings.model,
              keyUpdated: result.keyUpdated,
              keyConfigured: result.settings.keyConfigured,
              keySource: result.settings.keySource,
            },
          },
          config,
        );
        return json(res, 200, result);
      }

      /* ----------------------------- Cases ----------------------------- */

      if (path === '/api/cases' && method === 'GET') {
        return json(res, 200, { stats: caseStats(config), cases: listCases(config) });
      }

      if (path === '/api/cases' && method === 'POST') {
        const body = await readJson(req, 32_000);
        const record = createCase(body, config);
        appendAudit({ action: 'case.created', details: { caseId: record.id } }, config);
        return json(res, 201, { case: caseResponse(record, config) });
      }

      const caseAnalyzeMatch = path.match(/^\/api\/cases\/([A-Za-z0-9._-]+)\/analyze$/);
      if (caseAnalyzeMatch && method === 'POST') {
        const id = caseAnalyzeMatch[1];
        const record = readCase(id, config);
        if (!record.reportIds.length) {
          throw new CaseError('Attach at least one saved report before analyzing this case.', {
            code: 'no_reports',
            status: 400,
          });
        }

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
            `Some attached reports no longer exist: ${missing.join(', ')}. Remove them from the case and try again.`,
            { code: 'missing_reports', status: 409, missing },
          );
        }

        let result;
        try {
          const correlations = correlateCaseReports(reports);
          result = await requestCaseAnalysis({ caseData: { ...record, correlations }, reports, config });
        } catch (err) {
          appendAudit(
            {
              action: 'case.analysis_failed',
              details: { caseId: id, code: err.code || 'ai_error' },
            },
            config,
          );
          throw err;
        }

        pruneAiPreviews();
        const previewId = randomBytes(8).toString('hex');
        const createdAt = new Date().toISOString();
        const expiresAt = new Date(Date.now() + AI_PREVIEW_TTL_MS).toISOString();
        aiPreviews.set(previewId, {
          caseId: id,
          createdAt,
          expiresAt,
          analysis: result.analysis,
          model: result.model,
          usage: result.usage,
          evidence: result.evidence,
          providerHost: providerHost(currentAiSettings(config).baseUrl),
        });

        appendAudit(
          {
            action: 'case.analysis_completed',
            details: {
              caseId: id,
              model: result.model,
              reportCount: result.evidence.reportIds.length,
              omittedReportCount: result.evidence.omittedReportIds.length,
              inputChars: result.evidence.inputChars,
            },
          },
          config,
        );

        return json(res, 200, {
          previewId,
          createdAt,
          expiresAt,
          analysis: result.analysis,
          model: result.model,
          usage: result.usage,
          evidence: result.evidence,
        });
      }

      const caseAnalysesMatch = path.match(
        /^\/api\/cases\/([A-Za-z0-9._-]+)\/analyses(?:\/([A-Za-z0-9._-]+))?$/,
      );
      if (caseAnalysesMatch) {
        const [, id, analysisId] = caseAnalysesMatch;
        if (method === 'POST' && !analysisId) {
          const body = await readJson(req, 4_000);
          const previewId = typeof body.previewId === 'string' ? body.previewId : '';
          pruneAiPreviews();
          const preview = aiPreviews.get(previewId);
          if (!preview || preview.caseId !== id) {
            throw new AiError('Analysis preview not found or expired. Run Analyze again before saving.', {
              code: 'preview_expired',
              status: 404,
            });
          }
          if (new Date(preview.expiresAt).getTime() <= Date.now()) {
            aiPreviews.delete(previewId);
            throw new AiError('Analysis preview expired. Run Analyze again.', {
              code: 'preview_expired',
              status: 404,
            });
          }
          const saved = addAnalysis(
            id,
            {
              analysis: preview.analysis,
              model: preview.model,
              usage: preview.usage,
              evidence: preview.evidence,
              providerHost: preview.providerHost,
            },
            config,
          );
          aiPreviews.delete(previewId);
          appendAudit(
            {
              action: 'case.analysis_saved',
              details: { caseId: id, analysisId: saved.analysis.id },
            },
            config,
          );
          return json(res, 201, {
            case: caseResponse(saved.case, config),
            analysis: saved.analysis,
          });
        }

        if (method === 'DELETE' && analysisId) {
          const record = deleteAnalysis(id, analysisId, config);
          appendAudit(
            { action: 'case.analysis_deleted', details: { caseId: id, analysisId } },
            config,
          );
          return json(res, 200, { case: caseResponse(record, config) });
        }
      }

      const caseReportsMatch = path.match(
        /^\/api\/cases\/([A-Za-z0-9._-]+)\/reports(?:\/([A-Za-z0-9._-]+))?$/,
      );
      if (caseReportsMatch) {
        const [, id, reportId] = caseReportsMatch;
        if (method === 'POST' && !reportId) {
          const body = await readJson(req, 32_000);
          const record = attachReports(id, body.reportIds, config);
          appendAudit(
            {
              action: 'case.reports_attached',
              details: { caseId: id, reportCount: record.reportIds.length },
            },
            config,
          );
          return json(res, 200, { case: caseResponse(record, config) });
        }
        if (method === 'DELETE' && reportId) {
          const record = removeReport(id, reportId, config);
          appendAudit(
            {
              action: 'case.report_removed',
              details: { caseId: id, reportCount: record.reportIds.length },
            },
            config,
          );
          return json(res, 200, { case: caseResponse(record, config) });
        }
      }

      const caseIntelMatch = path.match(/^\/api\/cases\/([A-Za-z0-9._-]+)\/intel$/);
      if (caseIntelMatch && method === 'GET') {
        const id = caseIntelMatch[1];
        const intel = caseIntel(id, config);
        return json(res, 200, { intel });
      }

      const caseVerifyMatch = path.match(/^\/api\/cases\/([A-Za-z0-9._-]+)\/verify$/);
      if (caseVerifyMatch && method === 'GET') {
        const id = caseVerifyMatch[1];
        const verification = verifyCase(id, config);
        if (url.searchParams.get('audit') !== '0') {
          appendAudit(
            {
              action: 'case.verified',
              details: {
                caseId: id,
                status: verification.status,
                errorCount: verification.errorCount,
              },
            },
            config,
          );
        }
        return json(res, 200, { verification });
      }

      const caseBundleMatch = path.match(/^\/api\/cases\/([A-Za-z0-9._-]+)\/bundle$/);
      if (caseBundleMatch && method === 'GET') {
        const id = caseBundleMatch[1];
        const { bundle } = exportCaseBundle(id, config);
        appendAudit(
          {
            action: 'case.bundle_exported',
            details: {
              caseId: id,
              entries: bundle.manifest.ledgerEntries,
              fingerprint: bundle.manifest.signer.fingerprint,
            },
          },
          config,
        );
        const body = `${JSON.stringify(bundle, null, 2)}\n`;
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
          'content-disposition': `attachment; filename="${id}.arguscase"`,
        });
        return res.end(body);
      }

      const caseMatch = path.match(/^\/api\/cases\/([A-Za-z0-9._-]+)$/);
      if (caseMatch) {
        const id = caseMatch[1];
        if (method === 'GET') {
          const record = readCase(id, config);
          return json(res, 200, { case: caseResponse(record, config) });
        }
        if (method === 'PATCH' || method === 'PUT') {
          const body = await readJson(req, 32_000);
          const record = updateCase(id, body, config);
          appendAudit({ action: 'case.updated', details: { caseId: id } }, config);
          return json(res, 200, { case: caseResponse(record, config) });
        }
        if (method === 'DELETE') {
          deleteCase(id, config);
          appendAudit({ action: 'case.deleted', details: { caseId: id } }, config);
          return json(res, 200, { deleted: id });
        }
      }

      if (path === '/api/sources' && method === 'GET') {
        return json(res, 200, { sources: resolvedSources(config).map(summariseSource) });
      }

      const sourceMatch = path.match(/^\/api\/sources\/([a-z0-9-]+)$/i);
      if (sourceMatch && (method === 'PATCH' || method === 'PUT')) {
        const body = await readJson(req);
        if (typeof body.enabled !== 'boolean') {
          return json(res, 400, { error: 'Body must contain boolean "enabled".' });
        }
        try {
          setSourceEnabled(sourceMatch[1], body.enabled, config);
          saveConfig(config);
        } catch (err) {
          return json(res, 400, { error: err.message });
        }
        return json(res, 200, {
          source: summariseSource(resolvedSources(config).find((source) => source.id === sourceMatch[1])),
        });
      }

      if (path === '/api/username' && method === 'POST') {
        const body = await readJson(req);
        let username;
        try {
          username = normalizeUsername(body.username);
        } catch (err) {
          return json(res, 400, { error: err.message });
        }
        const categories = Array.isArray(body.categories)
          ? body.categories.filter((category) => typeof category === 'string').slice(0, 20)
          : [];
        const job = startJob(
          'username',
          `@${username}`,
          (onProgress) =>
            scanUsername(username, {
              config,
              categories,
              onProgress,
              timeoutMs: config.settings.timeoutMs,
              concurrency: config.settings.concurrency,
            }),
          config,
        );
        return json(res, 202, { jobId: job.id, target: job.target });
      }

      if (path === '/api/email' && method === 'POST') {
        const body = await readJson(req);
        if (!body.email || typeof body.email !== 'string') {
          return json(res, 400, { error: 'Email is required.' });
        }
        const job = startJob(
          'email',
          body.email,
          (onProgress) => {
            onProgress({ phase: 'checking', completed: 0, total: 4, source: 'DNS, Gravatar, breaches, mentions' });
            return scanEmail(body.email, {
              config,
              linked: Boolean(body.linked),
              timeoutMs: config.settings.timeoutMs,
            });
          },
          config,
        );
        return json(res, 202, { jobId: job.id, target: job.target });
      }

      if (path === '/api/file' && method === 'POST') {
        const maxBytes = (Number(config.settings.maxUploadMb) || 30) * 1024 * 1024;
        const body = await readBody(req, maxBytes);
        if (!body.length) return json(res, 400, { error: 'File body is empty.' });
        const filename = safeFilename(req.headers['x-filename'], 'upload.bin');
        const result = analyzeFile(body, filename);
        let report = null;
        if (req.headers['x-save-report'] === '1') {
          report = saveReport(result, config);
        }
        appendAudit(
          {
            action: 'file.analysed',
            command: 'file',
            target: filename,
            reportId: report?.id,
            details: { size: body.length, sha256: result.file.sha256, saved: Boolean(report) },
          },
          config,
        );
        return json(res, 200, {
          result,
          report: report
            ? {
                id: report.id,
                htmlUrl: `/api/reports/${report.id}/html`,
                jsonUrl: `/api/reports/${report.id}/json`,
              }
            : null,
        });
      }

      if (path === '/api/file/strip' && method === 'POST') {
        const maxBytes = (Number(config.settings.maxUploadMb) || 30) * 1024 * 1024;
        const body = await readBody(req, maxBytes);
        const filename = safeFilename(req.headers['x-filename'], 'upload.bin');
        const stripped = stripMetadata(body, filename);
        if (!stripped.ok) return json(res, 400, { error: stripped.error });
        const extension = stripped.format === 'png' ? 'png' : 'jpg';
        const outputName = `stripped-${filename.replace(/\.[^.]+$/, '')}.${extension}`;
        appendAudit(
          {
            action: 'file.metadata_stripped',
            command: 'file',
            target: filename,
            details: { removed: stripped.removed },
          },
          config,
        );
        res.writeHead(200, {
          'content-type': stripped.format === 'png' ? 'image/png' : 'image/jpeg',
          'content-disposition': `attachment; filename="${outputName.replace(/"/g, '')}"; filename*=UTF-8''${encodeURIComponent(outputName)}`,
          'x-removed': encodeURIComponent(stripped.removed.join(', ')),
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
        });
        return res.end(stripped.buffer);
      }

      const jobMatch = path.match(/^\/api\/jobs\/([a-f0-9]{16})$/i);
      if (jobMatch && method === 'GET') {
        const job = jobs.get(jobMatch[1]);
        if (!job) return json(res, 404, { error: 'Job not found or expired.' });
        return json(res, 200, {
          id: job.id,
          kind: job.kind,
          target: job.target,
          status: job.status,
          progress: job.progress,
          result: job.result,
          report: job.report
            ? {
                id: job.report.id,
                htmlUrl: `/api/reports/${job.report.id}/html`,
                jsonUrl: `/api/reports/${job.report.id}/json`,
              }
            : null,
          reportError: job.reportError || null,
          error: job.error,
        });
      }

      if (path === '/api/reports' && method === 'GET') {
        return json(res, 200, { stats: reportStats(config), reports: listReports(config) });
      }

      if (path === '/api/reports' && method === 'DELETE') {
        return json(res, 200, deleteAllData(config));
      }

      const reportMatch = path.match(/^\/api\/reports\/([A-Za-z0-9._-]+)(\/(html|json))?$/);
      if (reportMatch) {
        const [, id, , format] = reportMatch;
        if (method === 'GET') {
          try {
            if (format === 'html') {
              const html = readReportHtml(id, config);
              res.writeHead(200, {
                'content-type': 'text/html; charset=utf-8',
                'cache-control': 'no-store',
                'x-content-type-options': 'nosniff',
                'referrer-policy': 'no-referrer',
                'content-security-policy':
                  "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
              });
              return res.end(html);
            }

            const report = readReport(id, config);
            if (format === 'json') {
              res.writeHead(200, {
                'content-type': 'application/json; charset=utf-8',
                'content-disposition': `attachment; filename="${id}.json"`,
                'cache-control': 'no-store',
              });
              return res.end(JSON.stringify(report, null, 2));
            }
            return json(res, 200, report);
          } catch (err) {
            return json(res, err.message === 'Report not found.' ? 404 : 400, { error: err.message });
          }
        }

        if (method === 'DELETE') {
          try {
            deleteReport(id, config);
            return json(res, 200, { deleted: id });
          } catch (err) {
            return json(res, err.message === 'Report not found.' ? 404 : 400, { error: err.message });
          }
        }
      }

      if (path === '/api/data' && method === 'DELETE') {
        return json(res, 200, deleteAllData(config));
      }

      if (path === '/api/audit' && method === 'GET') {
        const limit = Math.max(1, Math.min(500, Number(url.searchParams.get('limit')) || 100));
        return json(res, 200, { entries: readAudit(limit, config) });
      }

      if (path === '/api/audit' && method === 'DELETE') {
        return json(res, 200, { cleared: clearAudit(config) });
      }

      /* --------------------------- static UI --------------------------- */

      if (method === 'GET' && !path.startsWith('/api/')) {
        const relative = path === '/' ? 'index.html' : path.replace(/^\/+/, '');
        const filePath = resolve(join(PUBLIC_DIR, relative));
        if (filePath !== PUBLIC_DIR && !filePath.startsWith(PUBLIC_DIR + sep)) {
          return text(res, 403, 'Forbidden');
        }
        if (existsSync(filePath) && MIME[extname(filePath)]) {
          const content = readFileSync(filePath);
          res.writeHead(200, {
            'content-type': MIME[extname(filePath)],
            'cache-control': 'no-store',
            'x-content-type-options': 'nosniff',
            'referrer-policy': 'no-referrer',
            'content-security-policy':
              "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
          });
          return res.end(content);
        }
        return text(res, 404, 'Not found');
      }

      return json(res, 404, { error: 'Not found.' });
    } catch (err) {
      const status = err.status || 500;
      if (status >= 500) console.error('[argus]', err);
      const payload = { error: err.message || 'Internal error.' };
      if (err.code) payload.code = err.code;
      if (err.retryable !== undefined) payload.retryable = Boolean(err.retryable);
      if (err.retryAfter != null) payload.retryAfter = err.retryAfter;
      if (Array.isArray(err.missing)) payload.missing = err.missing;
      if (!res.headersSent) return json(res, status, payload);
      try {
        res.end();
      } catch {
        /* ignore */
      }
    }
  });

  // Explicit limits for receiving requests; AI/provider calls have their own timeout.
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;

  return server;
}

export function startServer({ port, host = '127.0.0.1', open = false, config = loadConfig() } = {}) {
  const listenPort = Number(port) || Number(config.settings?.port) || 8787;
  const server = createAppServer(config);

  return new Promise((resolvePromise, reject) => {
    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        reject(new Error(`Port ${listenPort} is already in use. Try --port ${listenPort + 1}.`));
      } else {
        reject(err);
      }
    });
    server.listen(listenPort, host, () => {
      const address = server.address();
      const actualPort = typeof address === 'object' && address ? address.port : listenPort;
      const url = `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${actualPort}/`;
      if (open) {
        import('./util.mjs').then(({ openPath }) => openPath(url)).catch(() => {});
      }
      resolvePromise({ server, url, port: actualPort, close: () => new Promise((done) => server.close(done)) });
    });
  });
}
