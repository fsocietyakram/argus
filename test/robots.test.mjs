import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  clearRobotsCache,
  isAllowed,
  isUrlAllowed,
  parseRobots,
} from '../src/robots.mjs';

test('parseRobots groups agents and rules and ignores comments', () => {
  const groups = parseRobots(`
    # comment
    User-agent: *
    Disallow: /private
    Allow: /private/public

    User-agent: Argus
    Disallow: /agent-only
  `);

  assert.equal(groups.length, 2);
  assert.deepEqual(groups[0].agents, ['*']);
  assert.deepEqual(groups[0].rules, [
    { type: 'disallow', pattern: '/private' },
    { type: 'allow', pattern: '/private/public' },
  ]);
  assert.deepEqual(groups[1].agents, ['argus']);
});

test('isAllowed applies longest-match, wildcards, and Allow ties', () => {
  const rules = [
    { type: 'disallow', pattern: '/private' },
    { type: 'allow', pattern: '/private/public' },
    { type: 'disallow', pattern: '/*.pdf$' },
    { type: 'disallow', pattern: '/admin' },
    { type: 'allow', pattern: '/admin' },
  ];

  assert.equal(isAllowed(rules, '/'), true);
  assert.equal(isAllowed(rules, '/public'), true);
  assert.equal(isAllowed(rules, '/private'), false);
  assert.equal(isAllowed(rules, '/private/secret'), false);
  assert.equal(isAllowed(rules, '/private/public/page'), true);
  assert.equal(isAllowed(rules, '/docs/file.pdf'), false);
  assert.equal(
    isAllowed(rules, '/docs/file.pdf?download=1'),
    true,
    '$ anchors the end of the full path including the query string',
  );
  assert.equal(isAllowed(rules, '/docs/file.txt'), true);
  assert.equal(isAllowed(rules, '/admin'), true, 'Allow wins ties');
  assert.equal(isAllowed([], '/anything'), true);
});

test('isUrlAllowed fetches and applies robots.txt, then caches per origin', async (t) => {
  clearRobotsCache();
  let requests = 0;

  const server = http.createServer((req, res) => {
    requests += 1;
    if (req.url === '/robots.txt') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('User-agent: *\nDisallow: /private\n');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('ok');
  });

  const base = await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
  t.after(() => new Promise((done) => server.close(done)));

  const blocked = await isUrlAllowed(`${base}/private/profile`, { timeout: 2000 });
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.reason, 'disallowed-by-robots-txt');
  assert.equal(blocked.robotsStatus, 200);

  const allowed = await isUrlAllowed(`${base}/public/profile`, { timeout: 2000 });
  assert.equal(allowed.allowed, true);
  assert.equal(requests, 1, 'robots.txt should be cached per origin');
});

test('network failures for robots.txt are treated as allowed', async () => {
  clearRobotsCache();
  const result = await isUrlAllowed('http://127.0.0.1:1/anything', { timeout: 800 });
  assert.equal(result.allowed, true);
  assert.equal(result.reason, 'allowed');
});
