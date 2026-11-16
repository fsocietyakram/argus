import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  buildSourceUrl,
  evaluateResponse,
  normalizeUsername,
  scanUsername,
} from '../src/username.mjs';

/* ------------------------------------------------------------------ */
/* Pure helpers                                                        */
/* ------------------------------------------------------------------ */

test('normalizeUsername accepts handles, @handles, and profile URLs', () => {
  assert.equal(normalizeUsername(' Example '), 'Example');
  assert.equal(normalizeUsername('@example'), 'example');
  assert.equal(normalizeUsername('https://instagram.com/example/'), 'example');
  assert.equal(normalizeUsername('github.com/user/example'), 'example');
  assert.equal(normalizeUsername('https://example.com/u/Example_1'), 'Example_1');
  assert.equal(normalizeUsername('üser.name-1'), 'üser.name-1');
});

test('normalizeUsername rejects invalid or dangerous input', () => {
  assert.throws(() => normalizeUsername(''), /required/i);
  assert.throws(() => normalizeUsername('two words'), /spaces/i);
  assert.throws(() => normalizeUsername('bad/name'), /not allowed/i);
  assert.throws(() => normalizeUsername('bad?query'), /not allowed/i);
  assert.throws(() => normalizeUsername('name<script>'), /may only contain/i);
  assert.throws(() => normalizeUsername('a'.repeat(65)), /64 characters/i);
  assert.throws(() => normalizeUsername('x'.repeat(301)), /too long/i);
});

test('buildSourceUrl encodes the username', () => {
  assert.equal(
    buildSourceUrl({ url: 'https://example.com/{u}/profile' }, 'a b/c'),
    'https://example.com/a%20b%2Fc/profile',
  );
});

test('evaluateResponse distinguishes confirmed, possible, absent, blocked, and errors', () => {
  const high = { confidence: 'high', check: 'status' };
  const medium = { confidence: 'medium', check: 'marker', found: ['welcome'] };

  assert.equal(evaluateResponse(high, { status: 404, text: '' }).status, 'absent');
  assert.equal(evaluateResponse(high, { status: 410, text: '' }).status, 'absent');
  assert.equal(evaluateResponse(high, { status: 403, text: '' }).status, 'blocked');
  assert.equal(evaluateResponse(high, { status: 429, text: '' }).status, 'blocked');
  assert.equal(evaluateResponse(high, { status: 0, error: 'timeout' }).status, 'error');
  assert.equal(evaluateResponse(high, { status: 503, text: '' }).status, 'error');

  assert.equal(evaluateResponse(high, { status: 200, text: 'anything' }).status, 'confirmed');
  assert.equal(evaluateResponse(medium, { status: 200, text: 'WELCOME' }).status, 'possible');
  assert.equal(evaluateResponse(medium, { status: 200, text: 'nothing here' }).status, 'unverified');

  const markerSource = {
    confidence: 'high',
    check: 'marker',
    found: ['profile-marker'],
    notFound: ['no such user'],
  };
  assert.equal(
    evaluateResponse(markerSource, { status: 200, text: 'profile-marker' }).status,
    'confirmed',
  );
  assert.equal(
    evaluateResponse(markerSource, { status: 200, text: 'no such user' }).status,
    'absent',
  );
  assert.equal(
    evaluateResponse(markerSource, { status: 200, text: 'profile-marker no such user' }).status,
    'unverified',
  );
  assert.equal(
    evaluateResponse(high, { status: 200, text: '<title>Client Challenge</title>' }).status,
    'blocked',
  );
});

/* ------------------------------------------------------------------ */
/* Integration against a local HTTP server                             */
/* ------------------------------------------------------------------ */

function startFixtureServer() {
  const routes = new Map([
    ['/robots.txt', { status: 200, body: 'User-agent: *\nDisallow: /private\nAllow: /\n' }],
    ['/ok', { status: 200, body: 'public profile page' }],
    ['/public', { status: 200, body: 'public profile page' }],
    ['/marker', { status: 200, body: 'welcome unique-profile-marker' }],
    ['/ambiguous', { status: 200, body: 'unique-profile-marker page not found' }],
    ['/body-404', { status: 200, body: 'page not found' }],
    ['/private', { status: 200, body: 'should never be fetched' }],
    ['/missing', { status: 404, body: 'nope' }],
    ['/blocked', { status: 403, body: 'denied' }],
    ['/fail', { status: 500, body: 'boom' }],
  ]);

  const server = http.createServer((req, res) => {
    const path = new URL(req.url, 'http://127.0.0.1').pathname;
    const key = [...routes.keys()].find((prefix) => path.startsWith(prefix));
    const route = key ? routes.get(key) : { status: 404, body: 'not routed' };
    res.writeHead(route.status, { 'content-type': 'text/html; charset=utf-8' });
    res.end(route.body);
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

const source = (base, id, path, extra = {}) => ({
  id,
  name: id,
  category: 'other',
  access: 'page',
  url: `${base}${path}/{u}`,
  check: 'status',
  enabled: true,
  respectRobots: false,
  rateLimit: 60000,
  confidence: 'high',
  tos: 'Local fixture, read-only.',
  ...extra,
});

test('scanUsername records confirmed, possible, absent, blocked, skipped, and error outcomes', async (t) => {
  const { server, base } = await startFixtureServer();
  t.after(() => new Promise((done) => server.close(done)));

  const sources = [
    source(base, 'ok-status', '/ok'),
    source(base, 'marker-high', '/marker', {
      check: 'marker',
      found: ['unique-profile-marker'],
    }),
    source(base, 'ambiguity', '/ambiguous', {
      check: 'marker',
      found: ['unique-profile-marker'],
      notFound: ['page not found'],
    }),
    source(base, 'missing', '/missing'),
    source(base, 'body-404', '/body-404', {
      check: 'marker',
      notFound: ['page not found'],
    }),
    source(base, 'blocked', '/blocked'),
    source(base, 'server-error', '/fail'),
    source(base, 'refused', '/unused', {
      url: 'http://127.0.0.1:1/x/{u}',
    }),
    source(base, 'robots-private', '/private', {
      respectRobots: true,
    }),
    source(base, 'robots-public', '/public', {
      respectRobots: true,
    }),
    source(base, 'marker-medium', '/marker', {
      check: 'marker',
      found: ['unique-profile-marker'],
      confidence: 'medium',
    }),
  ];

  const events = [];
  const result = await scanUsername('example', {
    config: { settings: { concurrency: 8, timeoutMs: 2500, respectRobots: true }, sources: {} },
    sources,
    onProgress: (event) => events.push(event),
  });

  assert.equal(result.command, 'username');
  assert.equal(result.normalized, 'example');
  assert.equal(result.target, '@example');
  assert.equal(result.summary.total, sources.length);
  assert.equal(result.summary.confirmed, 2);
  assert.equal(result.summary.possible, 1);
  assert.equal(result.summary.unverified, 3);
  assert.equal(result.summary.absent, 2);
  assert.equal(result.summary.blocked, 1);
  assert.equal(result.summary.skipped, 1);
  assert.equal(result.summary.error, 2);
  assert.equal(events[0].phase, 'start');
  assert.ok(events.some((event) => event.phase === 'result'));

  const byId = Object.fromEntries(result.findings.map((finding) => [finding.id, finding]));
  assert.equal(byId['ok-status'].status, 'unverified');
  assert.equal(byId['marker-high'].status, 'confirmed');
  assert.equal(byId['marker-medium'].status, 'possible');
  assert.equal(byId.ambiguity.status, 'unverified');
  assert.equal(byId.missing.status, 'absent');
  assert.equal(byId['body-404'].status, 'absent');
  assert.equal(byId.blocked.status, 'blocked');
  assert.equal(byId['server-error'].status, 'error');
  assert.equal(byId.refused.status, 'error');
  assert.equal(byId['robots-private'].status, 'skipped');
  assert.match(byId['robots-private'].detail, /robots\.txt/i);
  assert.equal(byId['robots-public'].status, 'unverified');

  assert.ok(result.notes.some((note) => /not proof/i.test(note) || /not evidence/i.test(note)));
});

test('scanUsername honours sourceIds and rejects empty input', async (t) => {
  const { server, base } = await startFixtureServer();
  t.after(() => new Promise((done) => server.close(done)));

  const result = await scanUsername('example', {
    config: { settings: { concurrency: 2, timeoutMs: 2500, respectRobots: false }, sources: {} },
    sources: [source(base, 'ok', '/ok'), source(base, 'marker', '/marker')],
    sourceIds: ['ok'],
  });
  assert.equal(result.summary.total, 1);
  assert.equal(result.findings[0].id, 'ok');

  await assert.rejects(() => scanUsername('   ', { config: { settings: {}, sources: {} } }), /required/i);
});
