import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createAppServer } from '../src/server.mjs';
import { buildExifJpeg } from './helpers/build-jpeg.mjs';

const workdir = mkdtempSync(join(tmpdir(), 'argus-server-test-'));
process.env.ARGUS_REPORTS = join(workdir, 'reports');
process.env.ARGUS_DATA = join(workdir, 'data');

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
  },
  sources: {},
};

let server;
let base;

test.before(async () => {
  server = createAppServer(config);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((done) => server.close(done));
  rmSync(workdir, { recursive: true, force: true });
});

const argusHeaders = { 'x-argus': '1' };

test('health, config, and static UI are served with hardening headers', async () => {
  const health = await fetch(`${base}/api/health`);
  assert.equal(health.status, 200);
  const healthBody = await health.json();
  assert.equal(healthBody.ok, true);
  assert.equal(healthBody.tool, 'ARGUS');
  assert.equal(health.headers.get('cache-control'), 'no-store');

  const configResponse = await fetch(`${base}/api/config`);
  const configBody = await configResponse.json();
  assert.ok(Array.isArray(configBody.sources));
  assert.ok(configBody.sources.length > 10);
  assert.ok(Array.isArray(configBody.categories));
  assert.equal(typeof configBody.hibpConfigured, 'boolean');

  const index = await fetch(`${base}/`);
  assert.equal(index.status, 200);
  assert.match(index.headers.get('content-type'), /text\/html/);
  assert.match(index.headers.get('content-security-policy'), /default-src 'self'/);
  assert.match(await index.text(), /ARGUS/);
});

test('mutating API requests require the x-argus header and same origin', async () => {
  const missing = await fetch(`${base}/api/username`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'example' }),
  });
  assert.equal(missing.status, 403);

  const crossOrigin = await fetch(`${base}/api/username`, {
    method: 'POST',
    headers: { ...argusHeaders, 'content-type': 'application/json', origin: 'https://evil.example' },
    body: JSON.stringify({ username: 'example' }),
  });
  assert.equal(crossOrigin.status, 403);
});

test('username and file endpoints validate input', async () => {
  const invalidUsername = await fetch(`${base}/api/username`, {
    method: 'POST',
    headers: { ...argusHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'bad name' }),
  });
  assert.equal(invalidUsername.status, 400);
  assert.match((await invalidUsername.json()).error, /spaces/i);

  const invalidJson = await fetch(`${base}/api/username`, {
    method: 'POST',
    headers: { ...argusHeaders, 'content-type': 'application/json' },
    body: '{not json',
  });
  assert.equal(invalidJson.status, 400);

  const emptyFile = await fetch(`${base}/api/file`, {
    method: 'POST',
    headers: { ...argusHeaders, 'x-filename': 'empty.jpg' },
    body: Buffer.alloc(0),
  });
  assert.equal(emptyFile.status, 400);

  const missingJob = await fetch(`${base}/api/jobs/0000000000000000`);
  assert.equal(missingJob.status, 404);
});

test('file reports are opt-in', async () => {
  const response = await fetch(`${base}/api/file`, {
    method: 'POST',
    headers: {
      ...argusHeaders,
      'content-type': 'application/octet-stream',
      'x-filename': 'private.jpg',
    },
    body: buildExifJpeg(),
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).report, null);
});

test('file analysis, opt-in report saving, and deletion work end to end', async () => {
  const jpeg = buildExifJpeg();
  const response = await fetch(`${base}/api/file`, {
    method: 'POST',
    headers: {
      ...argusHeaders,
      'content-type': 'application/octet-stream',
      'x-filename': encodeURIComponent('holiday.jpg'),
      'x-save-report': '1',
    },
    body: jpeg,
  });

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.result.command, 'file');
  assert.equal(body.result.file.format, 'jpeg');
  assert.equal(body.result.exif.gps.latitude, 12.9716);
  assert.ok(body.report?.id);
  assert.match(body.report.htmlUrl, /\/html$/);

  const report = await fetch(`${base}${body.report.htmlUrl}`);
  assert.equal(report.status, 200);
  assert.match(report.headers.get('content-security-policy'), /default-src 'none'/);
  const html = await report.text();
  assert.match(html, /GPS location/);
  assert.match(html, /12\.971600/);

  const deleted = await fetch(`${base}/api/reports/${body.report.id}`, {
    method: 'DELETE',
    headers: argusHeaders,
  });
  assert.equal(deleted.status, 200);

  const gone = await fetch(`${base}/api/reports/${body.report.id}/html`);
  assert.equal(gone.status, 404);
});

test('file strip endpoint returns a metadata-free copy and rejects unsupported input', async () => {
  const jpeg = buildExifJpeg();
  const response = await fetch(`${base}/api/file/strip`, {
    method: 'POST',
    headers: {
      ...argusHeaders,
      'content-type': 'application/octet-stream',
      'x-filename': encodeURIComponent('holiday.jpg'),
    },
    body: jpeg,
  });

  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /image\/jpeg/);
  assert.match(decodeURIComponent(response.headers.get('x-removed') || ''), /EXIF/i);

  const stripped = Buffer.from(await response.arrayBuffer());
  assert.equal(stripped[0], 0xff);
  assert.equal(stripped[1], 0xd8);
  assert.ok(stripped.length < jpeg.length);

  const gif = await fetch(`${base}/api/file/strip`, {
    method: 'POST',
    headers: {
      ...argusHeaders,
      'content-type': 'application/octet-stream',
      'x-filename': 'anim.gif',
    },
    body: Buffer.from('GIF89a------'),
  });
  assert.equal(gif.status, 400);
  assert.match((await gif.json()).error, /JPEG and PNG only/i);
});

test('static serving rejects path traversal', async () => {
  const response = await fetch(`${base}/..%2fpackage.json`);
  assert.equal(response.status, 403);
});

test('case integrity and signed bundle endpoints work end to end', async () => {
  const created = await fetch(`${base}/api/cases`, {
    method: 'POST',
    headers: { ...argusHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'Integrity API case', notes: 'Signed from the API' }),
  });
  assert.equal(created.status, 201);
  const { case: record } = await created.json();
  assert.deepEqual(record.correlations, { timeline: [], repeatedIndicators: [] });

  const verify = await fetch(`${base}/api/cases/${record.id}/verify`);
  assert.equal(verify.status, 200);
  const { verification } = await verify.json();
  assert.equal(verification.status, 'valid');
  assert.equal(verification.signed, true);
  assert.equal(verification.entries, 1);
  assert.match(verification.fingerprint, /^[0-9a-f]{64}$/);

  const bundleResponse = await fetch(`${base}/api/cases/${record.id}/bundle`);
  assert.equal(bundleResponse.status, 200);
  assert.match(bundleResponse.headers.get('content-disposition'), /attachment; filename=.*\.arguscase/);
  const bundle = await bundleResponse.json();
  assert.equal(bundle.manifest.schema, 'argus.bundle/v1');
  assert.equal(bundle.manifest.caseId, record.id);
  assert.equal(bundle.manifest.ledgerEntries, 1);
  assert.ok(bundle.signature);
  assert.equal(bundle.intel?.schema, 'argus.case-intel/v1');
  assert.ok(Array.isArray(bundle.intel.correlations.repeatedIndicators));

  const intel = await fetch(`${base}/api/cases/${record.id}/intel`);
  assert.equal(intel.status, 200);
  const { intel: analysis } = await intel.json();
  assert.equal(analysis.schema, 'argus.case-intel/v1');
  assert.equal(analysis.caseId, record.id);
  assert.equal(analysis.reportCount, 0);
  assert.equal(analysis.timeline.count, 0);
  assert.equal(analysis.contradictions.count, 0);
  assert.deepEqual(analysis.correlations, { timeline: [], repeatedIndicators: [] });
});

test('reports and audit endpoints are available', async () => {
  const reports = await fetch(`${base}/api/reports`);
  assert.equal(reports.status, 200);
  const body = await reports.json();
  assert.ok(Array.isArray(body.reports));
  assert.ok(body.stats);

  const audit = await fetch(`${base}/api/audit?limit=5`);
  assert.equal(audit.status, 200);
  assert.ok(Array.isArray((await audit.json()).entries));
});
