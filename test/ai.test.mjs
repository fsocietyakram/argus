import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  AI_SECRETS_FILE,
  aiSecretsPath,
  aiSettingsView,
  buildEvidencePayload,
  callProvider,
  citationLabel,
  clearAiKey,
  getAiKey,
  normalizeAnalysis,
  normalizeBaseUrl,
  redactSecrets,
  requestCaseAnalysis,
  saveAiKey,
  validateAiSettings,
} from '../src/ai.mjs';

const workdir = mkdtempSync(join(tmpdir(), 'argus-ai-test-'));
process.env.ARGUS_DATA = join(workdir, 'data');
delete process.env.ARGUS_AI_API_KEY;
delete process.env.OPENAI_API_KEY;

const config = {
  settings: {
    ai: {
      baseUrl: 'https://api.openai.com/v1',
      model: 'gpt-4o-mini',
      timeoutMs: 60000,
      maxOutputTokens: 1800,
      maxInputChars: 60000,
    },
  },
  sources: {},
};

const reports = [
  {
    id: 'username-example-2026-11-16-abc1',
    report: {
      command: 'username',
      target: 'example',
      createdAt: '2026-11-16T10:00:00.000Z',
      summary: { confirmed: 1, possible: 0 },
      risk: { score: 10, level: 'low' },
      findings: [
        {
          id: 'github',
          name: 'GitHub',
          category: 'developer',
          status: 'confirmed',
          confidence: 'high',
          detail: 'Profile page exists.',
          url: 'https://github.com/example',
          profile: { fields: [{ label: 'Name', value: 'Example User' }], links: [] },
        },
      ],
    },
  },
  {
    id: 'domain-example-com-2026-11-16-def2',
    report: {
      command: 'domain',
      target: 'example.com',
      createdAt: '2026-11-16T10:05:00.000Z',
      whois: { parsed: { registrar: 'Example Registrar', creationDate: '1995-08-14' } },
      dns: { mx: [{ exchange: 'mail.example.com' }], a: ['93.184.216.34'] },
      certificates: { count: 2, names: ['example.com'] },
    },
  },
];

test.after(() => rmSync(workdir, { recursive: true, force: true }));

test('AI settings validation accepts defaults and normalizes the base URL', () => {
  const result = validateAiSettings(
    { baseUrl: 'https://api.openai.com/v1/?utm=1#frag', model: 'gpt-4o-mini' },
    config.settings.ai,
  );
  assert.equal(result.ok, true);
  assert.equal(result.settings.baseUrl, 'https://api.openai.com/v1');
  assert.equal(result.settings.timeoutMs, 60000);

  assert.equal(normalizeBaseUrl('http://127.0.0.1:11434/v1/'), 'http://127.0.0.1:11434/v1');
});

test('AI settings validation reports clear errors for bad endpoints and limits', () => {
  const result = validateAiSettings(
    {
      baseUrl: 'ftp://example.com',
      model: '   ',
      timeoutMs: 10,
      maxOutputTokens: 5,
      maxInputChars: 10,
    },
    config.settings.ai,
  );
  assert.equal(result.ok, false);
  assert.match(result.errors.join(' '), /http:\/\/ or https:\/\//);
  assert.match(result.errors.join(' '), /Model is required/);
  assert.match(result.errors.join(' '), /timeoutMs/);
  assert.match(result.errors.join(' '), /maxOutputTokens/);
  assert.match(result.errors.join(' '), /maxInputChars/);

  assert.throws(() => normalizeBaseUrl('https://user:pass@example.com/v1'), /must not contain credentials/);
  assert.throws(() => normalizeBaseUrl('not a url'), /valid absolute URL/);
  assert.throws(() => normalizeBaseUrl(''), /Base URL is required/);
});

test('API keys stay server-side, are masked in views, and can be cleared', () => {
  saveAiKey('sk-test-secret-value-123', config);
  const path = aiSecretsPath(config);
  assert.equal(path, join(process.env.ARGUS_DATA, AI_SECRETS_FILE));
  assert.ok(existsSync(path));
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).apiKey, 'sk-test-secret-value-123');

  const key = getAiKey(config, {});
  assert.equal(key.apiKey, 'sk-test-secret-value-123');
  assert.equal(key.source, 'local secrets file');

  const view = aiSettingsView(config, {});
  assert.equal(view.keyConfigured, true);
  assert.equal(view.keyMasked, '••••••••');
  assert.equal(Object.prototype.hasOwnProperty.call(view, 'apiKey'), false);
  assert.doesNotMatch(JSON.stringify(view), /sk-test-secret-value-123/);

  if (process.platform !== 'win32') {
    assert.equal(statSync(path).mode & 0o777, 0o600);
  }

  clearAiKey(config);
  assert.equal(existsSync(path), false);
  assert.equal(getAiKey(config, {}).apiKey, null);
});

test('environment variables take precedence over the local secrets file', () => {
  saveAiKey('local-key-value', config);
  try {
    const key = getAiKey(config, { OPENAI_API_KEY: 'env-openai-key' });
    assert.equal(key.apiKey, 'env-openai-key');
    assert.equal(key.source, 'OPENAI_API_KEY');

    const argusKey = getAiKey(config, { ARGUS_AI_API_KEY: 'env-argus-key', OPENAI_API_KEY: 'env-openai-key' });
    assert.equal(argusKey.apiKey, 'env-argus-key');

    const view = aiSettingsView(config, { ARGUS_AI_API_KEY: 'env-argus-key' });
    assert.equal(view.envOverride, true);
    assert.doesNotMatch(JSON.stringify(view), /env-argus-key/);
  } finally {
    clearAiKey(config);
  }
});

test('secret redaction removes keys, bearer tokens, and key assignments', () => {
  const text = redactSecrets(
    'key sk-abcdefghi12345678 and api_key=topsecret plus Authorization: Bearer abcdefghijklmnop',
    ['topsecret'],
  );
  assert.doesNotMatch(text, /sk-abcdefghi12345678/);
  assert.doesNotMatch(text, /topsecret/);
  assert.doesNotMatch(text, /abcdefghijklmnop/);
  assert.match(text, /\[redacted\]/);
});

test('evidence payload contains only selected reports and case notes', () => {
  const payload = buildEvidencePayload(
    { title: 'Example case', notes: 'Only look at the public profile.' },
    reports,
    { maxInputChars: 60000 },
  );
  assert.deepEqual(payload.includedReportIds, reports.map((item) => item.id));
  assert.equal(payload.payload.case.title, 'Example case');
  assert.equal(payload.payload.reports.length, 2);
  assert.equal(payload.payload.reports[0].reportId, reports[0].id);
  assert.equal(payload.payload.reports[0].findings[0].fields[0].value, 'Example User');
  assert.match(JSON.stringify(payload.payload), /Only look at the public profile/);
  assert.equal(payload.truncated, false);
});

test('evidence budget accounts for case notes and stays within the input limit', () => {
  const payload = buildEvidencePayload(
    { title: 'Budget case', notes: 'n'.repeat(10000) },
    reports,
    { maxInputChars: 2000 },
  );
  assert.ok(payload.inputChars <= 2000);
  assert.equal(payload.payload.case.notes.length, 500);
  assert.ok(payload.includedReportIds.length >= 1);
});

test('citation validation flags unknown reports, missing fields, and uncited claims', () => {
  const analysis = normalizeAnalysis(
    {
      summary: 'Two reports were reviewed.',
      observedEvidence: [
        {
          text: 'A GitHub profile exists for the username.',
          citations: [{ reportId: reports[0].id, field: 'findings[0].url', finding: 'GitHub' }],
        },
        {
          text: 'A claim citing a report that was never sent.',
          citations: [{ reportId: 'not-supplied', field: 'whois' }],
        },
      ],
      interpretations: [
        {
          text: 'The accounts may belong to one person.',
          confidence: 'medium',
          citations: [{ reportId: reports[0].id, field: 'findings[0].confidence' }],
        },
      ],
      uncertainty: ['No date of birth was available.'],
      suggestedNextSteps: [
        { action: 'Review the public profile manually.', citations: [{ reportId: reports[0].id, field: 'target' }] },
        { action: 'Contact the account owner.' },
      ],
      unsupportedClaims: ['<script>alert(1)</script> cannot be supported.'],
    },
    { reports: reports.map((item) => ({ id: item.id })), model: 'mock-model' },
  );

  assert.equal(analysis.schema, 'argus.analysis/v1');
  assert.equal(analysis.observedEvidence[0].supported, true);
  assert.equal(analysis.observedEvidence[1].supported, false);
  assert.equal(analysis.observedEvidence[1].citations[0].reportKnown, false);
  assert.equal(analysis.interpretations[0].confidence, 'medium');
  assert.equal(analysis.suggestedNextSteps[1].supported, false);
  assert.equal(analysis.suggestedNextSteps[1].requiresHumanReview, true);
  assert.equal(analysis.citations.total, 4);
  assert.equal(analysis.citations.valid, 3);
  assert.equal(analysis.citations.invalid, 1);
  assert.ok(analysis.unsupportedClaims.some((claim) => claim.includes('<script>')));
  assert.ok(analysis.warnings.some((warning) => /not in the supplied evidence/.test(warning)));
  assert.equal(citationLabel({ reportId: '<r1>', field: 'a&b' }), '&lt;r1&gt; · a&amp;b');
});

function providerResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers,
    text: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

test('provider client parses structured output and does not require response_format', async () => {
  let request;
  const result = await callProvider({
    settings: config.settings.ai,
    apiKey: 'sk-unit-test',
    messages: [{ role: 'user', content: 'hello' }],
    fetchImpl: async (url, options) => {
      request = { url, options };
      return providerResponse(200, {
        model: 'mock-model',
        usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 },
        choices: [
          {
            message: {
              content: '```json\n{"summary":"ok","observedEvidence":[],"interpretations":[],"uncertainty":[],"suggestedNextSteps":[],"unsupportedClaims":[]}\n```',
            },
          },
        ],
      });
    },
  });

  assert.equal(request.url, 'https://api.openai.com/v1/chat/completions');
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers.authorization, 'Bearer sk-unit-test');
  assert.equal(JSON.parse(request.options.body).response_format, undefined);
  assert.equal(result.output.summary, 'ok');
  assert.equal(result.model, 'mock-model');
  assert.equal(result.usage.totalTokens, 30);
});

test('provider client maps auth, rate-limit, timeout, and malformed responses', async () => {
  const base = { settings: config.settings.ai, apiKey: 'sk-unit-test', messages: [] };

  await assert.rejects(
    callProvider({ ...base, fetchImpl: async () => providerResponse(401, { error: { message: 'bad key' } }) }),
    (err) => err.code === 'provider_auth' && err.status === 502,
  );

  await assert.rejects(
    callProvider({
      ...base,
      fetchImpl: async () => providerResponse(429, { error: { message: 'slow down' } }, { 'retry-after': '7' }),
    }),
    (err) => err.code === 'provider_rate_limited' && err.retryAfter === 7 && err.retryable === true,
  );

  await assert.rejects(
    callProvider({ ...base, fetchImpl: async () => ({ ok: false, status: 0, error: 'timeout', headers: {}, text: '' }) }),
    (err) => err.code === 'provider_timeout' && err.status === 504,
  );

  await assert.rejects(
    callProvider({ ...base, fetchImpl: async () => providerResponse(200, '<html>not json</html>') }),
    (err) => err.code === 'provider_invalid_response',
  );

  await assert.rejects(
    callProvider({
      ...base,
      fetchImpl: async () => providerResponse(200, { choices: [{ message: { content: 'plain prose' } }] }),
    }),
    (err) => err.code === 'provider_unstructured',
  );
});

test('analysis refuses to send a request without a configured key', async () => {
  let calls = 0;
  await assert.rejects(
    requestCaseAnalysis({
      caseData: { title: 'No key', notes: '' },
      reports,
      config,
      env: {},
      fetchImpl: async () => {
        calls += 1;
        return providerResponse(200, {});
      },
    }),
    (err) => err.code === 'missing_api_key' && /No request was sent/.test(err.message),
  );
  assert.equal(calls, 0);
});

test('analysis sends only evidence, returns normalized output, and preserves warnings', async () => {
  let sent;
  const result = await requestCaseAnalysis({
    caseData: { title: 'Example case', notes: 'Compare the username and domain.' },
    reports,
    config,
    env: { ARGUS_AI_API_KEY: 'sk-live-test' },
    fetchImpl: async (_url, options) => {
      sent = JSON.parse(options.body);
      return providerResponse(200, {
        model: 'mock-model',
        choices: [
          {
            message: {
              content: JSON.stringify({
                summary: 'The username and domain were linked only by name.',
                observedEvidence: [
                  {
                    text: 'A GitHub profile exists for the username.',
                    citations: [{ reportId: reports[0].id, field: 'findings[0].url' }],
                  },
                ],
                interpretations: [],
                uncertainty: ['A shared name is not proof of identity.'],
                suggestedNextSteps: [
                  {
                    action: 'Review both public pages manually.',
                    priority: 'low',
                    citations: [{ reportId: reports[1].id, field: 'whois.parsed.registrar' }],
                  },
                ],
                unsupportedClaims: ['Ownership cannot be established.'],
              }),
            },
          },
        ],
      });
    },
  });

  assert.equal(sent.model, 'gpt-4o-mini');
  assert.match(sent.messages[0].content, /untrusted data/);
  assert.match(sent.messages[1].content, /Compare the username and domain/);
  assert.match(sent.messages[1].content, new RegExp(reports[0].id));
  assert.doesNotMatch(optionsSafe(sent), /sk-live-test/);
  assert.equal(result.analysis.observedEvidence[0].supported, true);
  assert.equal(result.analysis.suggestedNextSteps[0].priority, 'low');
  assert.ok(result.analysis.warnings.some((warning) => /untrusted lead/.test(warning)));
  assert.deepEqual(result.evidence.reportIds, reports.map((item) => item.id));
});

function optionsSafe(value) {
  return JSON.stringify(value);
}
