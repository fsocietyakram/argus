import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createAppServer } from '../src/server.mjs';
import { saveReport } from '../src/report.mjs';

const workdir = mkdtempSync(join(tmpdir(), 'argus-ai-server-test-'));
process.env.ARGUS_REPORTS = join(workdir, 'reports');
process.env.ARGUS_DATA = join(workdir, 'data');
process.env.ARGUS_CONFIG = join(workdir, 'argus.config.json');
process.env.ARGUS_AI_API_KEY = 'sk-integration-secret-value';
delete process.env.OPENAI_API_KEY;

const config = {
  settings: {
    concurrency: 2,
    timeoutMs: 2000,
    respectRobots: false,
    retentionDays: 0,
    maxReports: 0,
    maxUploadMb: 5,
    hibpApiKeyEnv: 'HIBP_API_KEY',
    logTargetsInAudit: true,
    ai: {
      baseUrl: 'http://127.0.0.1:9/v1',
      model: 'mock-model',
      timeoutMs: 5000,
      maxOutputTokens: 800,
      maxInputChars: 60000,
    },
  },
  sources: {},
};

let providerRequests = 0;
let providerStatus = 200;
let providerRetryAfter = null;
let lastProviderBody = null;
let provider;
let server;
let base;

function usernameResult(target) {
  return {
    command: 'username',
    target,
    createdAt: '2026-11-16T11:00:00.000Z',
    finishedAt: '2026-11-16T11:00:01.000Z',
    durationMs: 1000,
    summary: { confirmed: 1, possible: 0, unverified: 0, absent: 0, blocked: 0, skipped: 0, error: 0 },
    risk: { score: 10, level: 'low', findings: [], recommendations: [] },
    findings: [
      {
        id: 'github',
        name: 'GitHub',
        category: 'developer',
        status: 'confirmed',
        confidence: 'high',
        detail: 'Public profile exists.',
        url: `https://github.com/${target}`,
        profile: { fields: [{ label: 'Name', value: target }], links: [] },
      },
    ],
    absent: [],
    warnings: [],
    notes: [],
  };
}

const report = saveReport(usernameResult('integration'), config);

const argusHeaders = { 'x-argus': '1', 'content-type': 'application/json' };

test.before(async () => {
  provider = http.createServer(async (req, res) => {
    providerRequests += 1;
    let body = '';
    for await (const chunk of req) body += chunk;
    lastProviderBody = body ? JSON.parse(body) : null;

    if (providerStatus !== 200) {
      const headers = { 'content-type': 'application/json' };
      if (providerRetryAfter != null) headers['retry-after'] = String(providerRetryAfter);
      res.writeHead(providerStatus, headers);
      res.end(JSON.stringify({ error: { message: 'mock provider failure' } }));
      return;
    }

    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        model: 'mock-model',
        usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
        choices: [
          {
            message: {
              content: JSON.stringify({
                summary: 'The report contains one public profile.',
                observedEvidence: [
                  {
                    text: 'A GitHub profile exists for the username.',
                    citations: [{ reportId: report.id, field: 'findings[0].url', finding: 'GitHub' }],
                  },
                ],
                interpretations: [
                  {
                    text: 'The username may belong to one person.',
                    confidence: 'low',
                    citations: [{ reportId: report.id, field: 'target' }],
                  },
                ],
                uncertainty: ['A shared username is not proof of identity.'],
                suggestedNextSteps: [
                  {
                    action: 'Review the public profile manually.',
                    priority: 'low',
                    citations: [{ reportId: report.id, field: 'findings[0].url' }],
                  },
                ],
                unsupportedClaims: ['Ownership cannot be established from this report.'],
              }),
            },
          },
        ],
      }),
    );
  });

  await new Promise((resolve) => provider.listen(0, '127.0.0.1', resolve));
  config.settings.ai.baseUrl = `http://127.0.0.1:${provider.address().port}/v1`;

  server = createAppServer(config);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((done) => server.close(done));
  await new Promise((done) => provider.close(done));
  rmSync(workdir, { recursive: true, force: true });
});

test('AI settings are validated and never expose the API key', async () => {
  const health = await fetch(`${base}/api/health`).then((response) => response.json());
  assert.equal(health.aiConfigured, true);

  const settings = await fetch(`${base}/api/ai/settings`).then((response) => response.json());
  assert.equal(settings.settings.keyConfigured, true);
  assert.equal(settings.settings.keyMasked, '••••••••');
  assert.equal(settings.settings.envOverride, true);
  assert.doesNotMatch(JSON.stringify(settings), /sk-integration-secret-value/);

  const configResponse = await fetch(`${base}/api/config`).then((response) => response.json());
  assert.equal(configResponse.ai.keyConfigured, true);
  assert.doesNotMatch(JSON.stringify(configResponse), /sk-integration-secret-value/);

  const before = providerRequests;
  const invalid = await fetch(`${base}/api/ai/settings`, {
    method: 'PUT',
    headers: argusHeaders,
    body: JSON.stringify({ baseUrl: 'file:///etc/passwd', model: '' }),
  });
  assert.equal(invalid.status, 400);
  const invalidBody = await invalid.json();
  assert.equal(invalidBody.code, 'invalid_ai_settings');
  assert.match(invalidBody.error, /http:\/\/ or https:\/\//);
  assert.match(invalidBody.error, /Model is required/);
  assert.equal(providerRequests, before, 'settings validation must not call the provider');
});

test('case analysis previews only attached evidence, then saves after review', async () => {
  const created = await fetch(`${base}/api/cases`, {
    method: 'POST',
    headers: argusHeaders,
    body: JSON.stringify({ title: 'Integration case', notes: 'Check the public profile only.' }),
  });
  assert.equal(created.status, 201);
  const createdBody = await created.json();
  const caseId = createdBody.case.id;
  assert.ok(caseId);

  const attached = await fetch(`${base}/api/cases/${caseId}/reports`, {
    method: 'POST',
    headers: argusHeaders,
    body: JSON.stringify({ reportIds: [report.id] }),
  });
  assert.equal(attached.status, 200);
  const attachedBody = await attached.json();
  assert.deepEqual(attachedBody.case.reportIds, [report.id]);
  assert.equal(attachedBody.case.reports[0].command, 'username');

  const before = providerRequests;
  const analyze = await fetch(`${base}/api/cases/${caseId}/analyze`, {
    method: 'POST',
    headers: argusHeaders,
  });
  assert.equal(analyze.status, 200);
  const preview = await analyze.json();
  assert.equal(providerRequests, before + 1);
  assert.ok(preview.previewId);
  assert.equal(preview.analysis.observedEvidence[0].supported, true);
  assert.equal(preview.analysis.citations.valid, 3);
  assert.equal(lastProviderBody.model, 'mock-model');
  assert.match(lastProviderBody.messages[1].content, /Check the public profile only/);
  assert.match(lastProviderBody.messages[1].content, new RegExp(report.id));
  assert.doesNotMatch(JSON.stringify(lastProviderBody), /sk-integration-secret-value/);

  const unsaved = await fetch(`${base}/api/cases/${caseId}`).then((response) => response.json());
  assert.equal(unsaved.case.analyses.length, 0, 'analysis is not saved before review');

  const saved = await fetch(`${base}/api/cases/${caseId}/analyses`, {
    method: 'POST',
    headers: argusHeaders,
    body: JSON.stringify({ previewId: preview.previewId }),
  });
  assert.equal(saved.status, 201);
  const savedBody = await saved.json();
  assert.equal(savedBody.analysis.analysis.summary, 'The report contains one public profile.');

  const reread = await fetch(`${base}/api/cases/${caseId}`).then((response) => response.json());
  assert.equal(reread.case.analyses.length, 1);
  assert.equal(reread.case.analyses[0].model, 'mock-model');
  assert.equal(reread.case.analyses[0].evidence.reportIds[0], report.id);

  const expired = await fetch(`${base}/api/cases/${caseId}/analyses`, {
    method: 'POST',
    headers: argusHeaders,
    body: JSON.stringify({ previewId: preview.previewId }),
  });
  assert.equal(expired.status, 404);
  assert.equal((await expired.json()).code, 'preview_expired');
});

test('provider failure returns a retryable error without losing the case', async () => {
  const created = await fetch(`${base}/api/cases`, {
    method: 'POST',
    headers: argusHeaders,
    body: JSON.stringify({ title: 'Failure case', notes: 'Keep this case.' }),
  }).then((response) => response.json());
  const caseId = created.case.id;

  await fetch(`${base}/api/cases/${caseId}/reports`, {
    method: 'POST',
    headers: argusHeaders,
    body: JSON.stringify({ reportIds: [report.id] }),
  });

  providerStatus = 429;
  providerRetryAfter = 9;
  try {
    const response = await fetch(`${base}/api/cases/${caseId}/analyze`, {
      method: 'POST',
      headers: argusHeaders,
    });
    assert.equal(response.status, 429);
    const body = await response.json();
    assert.equal(body.code, 'provider_rate_limited');
    assert.equal(body.retryable, true);
    assert.equal(body.retryAfter, 9);
    assert.doesNotMatch(JSON.stringify(body), /sk-integration-secret-value/);
  } finally {
    providerStatus = 200;
    providerRetryAfter = null;
  }

  const reread = await fetch(`${base}/api/cases/${caseId}`).then((response) => response.json());
  assert.deepEqual(reread.case.reportIds, [report.id]);
  assert.equal(reread.case.notes, 'Keep this case.');
  assert.equal(reread.case.analyses.length, 0);
});

test('local secret storage is used when no environment key is present', async () => {
  delete process.env.ARGUS_AI_API_KEY;
  try {
    const saved = await fetch(`${base}/api/ai/settings`, {
      method: 'PUT',
      headers: argusHeaders,
      body: JSON.stringify({ apiKey: 'sk-local-stored-value' }),
    });
    assert.equal(saved.status, 200);
    const savedBody = await saved.json();
    assert.equal(savedBody.settings.keyConfigured, true);
    assert.equal(savedBody.settings.envOverride, false);
    assert.doesNotMatch(JSON.stringify(savedBody), /sk-local-stored-value/);
    assert.ok(existsSync(join(process.env.ARGUS_DATA, 'ai-secrets.json')));

    const persistedConfig = readFileSync(process.env.ARGUS_CONFIG, 'utf8');
    assert.doesNotMatch(persistedConfig, /sk-local-stored-value/);
    const auditPath = join(process.env.ARGUS_DATA, 'audit.jsonl');
    if (existsSync(auditPath)) {
      assert.doesNotMatch(readFileSync(auditPath, 'utf8'), /sk-local-stored-value/);
    }

    const cleared = await fetch(`${base}/api/ai/settings`, {
      method: 'PUT',
      headers: argusHeaders,
      body: JSON.stringify({ clearKey: true }),
    });
    assert.equal(cleared.status, 200);
    assert.equal((await cleared.json()).settings.keyConfigured, false);
    assert.equal(existsSync(join(process.env.ARGUS_DATA, 'ai-secrets.json')), false);
  } finally {
    process.env.ARGUS_AI_API_KEY = 'sk-integration-secret-value';
  }
});
