import test from 'node:test';
import assert from 'node:assert/strict';
import {
  INTEL_SCHEMA,
  analyseCase,
  buildTimeline,
  extractFacts,
  findContradictions,
  parseDate,
} from '../src/case-intel.mjs';

function usernameReport({
  id = 'report-user-1',
  target = 'alice',
  createdAt = '2026-01-10T10:00:00.000Z',
  findings = [],
} = {}) {
  return {
    id,
    report: {
      schema: 'argus.report/v1',
      command: 'username',
      target,
      normalized: target,
      createdAt,
      findings,
    },
  };
}

function finding({
  sourceId = 'github',
  sourceName = 'GitHub',
  status = 'confirmed',
  fields = [],
} = {}) {
  return {
    id: sourceId,
    name: sourceName,
    status,
    profile: { fields },
  };
}

function fileReport({
  id = 'report-file-1',
  createdAt = '2026-01-10T10:00:00.000Z',
  sha256 = 'a'.repeat(64),
  gps = null,
  original = null,
  digitized = null,
  modified = null,
  camera = null,
} = {}) {
  return {
    id,
    report: {
      schema: 'argus.report/v1',
      command: 'file',
      target: 'photo.jpg',
      createdAt,
      file: { name: 'photo.jpg', sha256 },
      exif: {
        gps,
        timestamps: { original, digitized, modified },
        camera,
      },
    },
  };
}

function emailReport({
  id = 'report-email-1',
  createdAt = '2026-01-10T10:00:00.000Z',
  target = 'alice@example.com',
  hasMx = true,
  implicitMx = false,
  dnsErrors = [],
  breaches = [],
} = {}) {
  return {
    id,
    report: {
      schema: 'argus.report/v1',
      command: 'email',
      target,
      createdAt,
      syntax: { valid: true, domain: target.split('@')[1] },
      dns: { hasMx, implicitMx, errors: dnsErrors },
      breaches: { breaches },
    },
  };
}

function domainReport({
  id = 'report-domain-1',
  createdAt = '2026-01-10T10:00:00.000Z',
  target = 'example.com',
  parsed = {},
} = {}) {
  return {
    id,
    report: {
      schema: 'argus.report/v1',
      command: 'domain',
      target,
      createdAt,
      whois: { parsed },
    },
  };
}

test('parseDate handles ISO, EXIF, date-only, and garbage', () => {
  assert.equal(parseDate('2020-03-01T12:00:00.000Z'), '2020-03-01T12:00:00.000Z');
  assert.equal(parseDate('2020:03:01 12:00:00'), '2020-03-01T12:00:00.000Z');
  assert.equal(parseDate('2020-03-01'), '2020-03-01T00:00:00.000Z');
  assert.equal(parseDate('March 1, 2020 00:00:00 UTC'), '2020-03-01T00:00:00.000Z');
  assert.equal(parseDate('not a date'), null);
  assert.equal(parseDate(''), null);
  assert.equal(parseDate(null), null);
});

test('extractFacts flattens claims, scans, files, emails, and domains', () => {
  const facts = extractFacts([
    usernameReport({
      findings: [
        finding({
          fields: [
            { label: 'Name', value: '  Alice   Example ' },
            { label: 'Joined', value: '2015-06-01' },
            { label: 'Location', value: 'Berlin' },
          ],
        }),
        finding({ sourceId: 'reddit', sourceName: 'Reddit', status: 'absent' }),
        finding({ sourceId: 'x', sourceName: 'X', status: 'blocked' }),
      ],
    }),
    fileReport({ gps: { latitude: 52.52, longitude: 13.405, dateStamp: '2020:01:02', timestamp: '03:04:05' } }),
    emailReport({ breaches: [{ title: 'Example breach', breachDate: '2019-05-01' }] }),
    domainReport({ parsed: { registrar: 'Example Registrar', creationDate: '2010-01-01' } }),
  ]);

  assert.equal(facts.collected.length, 4);
  assert.equal(facts.scans.length, 2, 'blocked results are not scanned facts');
  assert.equal(facts.claims.length, 3, 'only confirmed findings contribute claims');
  assert.deepEqual(facts.claims[0], {
    reportId: 'report-user-1',
    at: '2026-01-10T10:00:00.000Z',
    target: 'alice',
    sourceId: 'github',
    sourceName: 'GitHub',
    label: 'Name',
    value: 'Alice Example',
    field: 'findings[0].profile.fields[0].value',
  });
  assert.equal(facts.files[0].gpsAt, '2020-01-02T03:04:05.000Z');
  assert.equal(facts.emails[0].domain, 'example.com');
  assert.equal(facts.domains[0].registrar, 'Example Registrar');
  assert.equal(facts.domains[0].created, '2010-01-01T00:00:00.000Z');
});

test('buildTimeline merges dated facts in ascending order with citations', () => {
  const timeline = buildTimeline([
    usernameReport({
      createdAt: '2026-02-01T00:00:00.000Z',
      findings: [finding({ fields: [{ label: 'Joined', value: '2015-06-01' }] })],
    }),
    fileReport({
      createdAt: '2026-02-02T00:00:00.000Z',
      sha256: 'b'.repeat(64),
      gps: { latitude: 52.52, longitude: 13.405, dateStamp: '2020:01:02', timestamp: '03:04:05' },
      original: '2020:01:01 10:00:00',
      digitized: '2020:01:03 10:00:00',
      modified: '2020:01:04 10:00:00',
      camera: { model: 'X100' },
    }),
    emailReport({ breaches: [{ title: 'Breach A', breachDate: '2019-05-01', domain: 'example.com' }] }),
    domainReport({ parsed: { creationDate: '2010-01-01T00:00:00.000Z', expiryDate: '2030-01-01T00:00:00.000Z' } }),
  ]);

  assert.equal(timeline.count, timeline.items.length);
  assert.equal(timeline.first, '2010-01-01T00:00:00.000Z');
  assert.equal(timeline.last, '2030-01-01T00:00:00.000Z');
  const ordered = timeline.items.map((item) => item.at);
  assert.deepEqual(ordered, ordered.slice().sort());

  const capture = timeline.items.find((item) => item.label === 'Capture time');
  assert.equal(capture.kind, 'metadata');
  assert.equal(capture.reportId, 'report-file-1');
  assert.equal(capture.field, 'exif.timestamps.original');
  assert.equal(capture.detail, 'photo.jpg · X100');

  const gpsFix = timeline.items.find((item) => item.label === 'GPS fix time');
  assert.equal(gpsFix.kind, 'gps');
  assert.equal(gpsFix.field, 'exif.gps.dateStamp');
  assert.match(gpsFix.detail, /52\.52000, 13\.40500/);

  const breach = timeline.items.find((item) => item.kind === 'breach');
  assert.equal(breach.field, 'breaches.breaches[0].breachDate');

  assert.equal(timeline.byKind.collection, 4);
  assert.equal(timeline.byKind.domain, 2);
});

test('a source that flips between present and absent is a status conflict', () => {
  const first = usernameReport({
    id: 'report-user-1',
    createdAt: '2026-01-01T00:00:00.000Z',
    findings: [finding({ status: 'confirmed' })],
  });
  const second = usernameReport({
    id: 'report-user-2',
    createdAt: '2026-02-01T00:00:00.000Z',
    findings: [finding({ status: 'absent' })],
  });
  const { items } = findContradictions([first, second]);
  const hit = items.find((item) => item.kind === 'status_conflict');
  assert.ok(hit);
  assert.equal(hit.severity, 'medium');
  assert.deepEqual(
    hit.citations.map((cite) => [cite.reportId, cite.field, cite.value]),
    [
      ['report-user-1', 'findings[0].status', 'confirmed'],
      ['report-user-2', 'findings[0].status', 'absent'],
    ],
  );

  const same = findContradictions([first]);
  assert.equal(same.items.length, 0);
});

test('name and location conflicts only fire within the same target', () => {
  const aliceFields = [
    finding({ fields: [{ label: 'Name', value: 'Alice Example' }, { label: 'Location', value: 'Berlin' }] }),
  ];
  const aliceOther = [
    finding({
      sourceId: 'reddit',
      sourceName: 'Reddit',
      fields: [{ label: 'Name', value: 'A. Example' }, { label: 'Location', value: 'Munich' }],
    }),
  ];
  const bob = usernameReport({
    id: 'report-user-3',
    target: 'bob',
    findings: [finding({ fields: [{ label: 'Name', value: 'Bob' }, { label: 'Location', value: 'Paris' }] })],
  });

  const withinTarget = findContradictions([
    usernameReport({ id: 'report-user-1', findings: aliceFields }),
    usernameReport({ id: 'report-user-2', findings: aliceOther }),
  ]).items;
  assert.ok(withinTarget.some((item) => item.kind === 'name_conflict' && item.severity === 'low'));
  assert.ok(withinTarget.some((item) => item.kind === 'location_conflict' && item.severity === 'low'));
  const nameHit = withinTarget.find((item) => item.kind === 'name_conflict');
  assert.ok(nameHit.citations.every((cite) => cite.value.includes(': ')));
  assert.ok(
    nameHit.citations.some(
      (cite) => cite.reportId === 'report-user-1' && cite.field === 'findings[0].profile.fields[0].value',
    ),
  );

  const crossTarget = findContradictions([
    usernameReport({ id: 'report-user-1', findings: aliceFields }),
    bob,
  ]).items;
  assert.equal(crossTarget.filter((item) => item.kind === 'name_conflict').length, 0);
  assert.equal(crossTarget.filter((item) => item.kind === 'location_conflict').length, 0);

  const sameValues = findContradictions([
    usernameReport({ id: 'report-user-1', findings: aliceFields }),
    usernameReport({
      id: 'report-user-2',
      findings: [finding({ sourceId: 'reddit', sourceName: 'Reddit', fields: [{ label: 'Name', value: 'Alice Example' }] })],
    }),
  ]).items;
  assert.equal(sameValues.filter((item) => item.kind === 'name_conflict').length, 0);
});

test('a capture time after collection is an impossible timestamp', () => {
  const file = fileReport({
    createdAt: '2020-01-01T00:00:00.000Z',
    original: '2020:06:01 12:00:00',
  });
  const { items } = findContradictions([file]);
  const hit = items.find((item) => item.kind === 'impossible_timestamp');
  assert.ok(hit);
  assert.equal(hit.severity, 'high');
  assert.ok(hit.citations.some((cite) => cite.field === 'exif.timestamps.original'));

  const normal = findContradictions([
    fileReport({ createdAt: '2020-06-02T00:00:00.000Z', original: '2020:06:01 12:00:00' }),
  ]);
  assert.equal(normal.items.filter((item) => item.kind === 'impossible_timestamp').length, 0);
});

test('two far-apart GPS fixes an hour apart are a travel conflict', () => {
  const newYork = { latitude: 40.7128, longitude: -74.006, dateStamp: '2020:01:01', timestamp: '12:00:00' };
  const london = { latitude: 51.5074, longitude: -0.1278, dateStamp: '2020:01:01', timestamp: '13:00:00' };
  const { items } = findContradictions([
    fileReport({ id: 'report-file-1', sha256: '1'.repeat(64), gps: newYork, original: '2020:01:01 12:00:00' }),
    fileReport({ id: 'report-file-2', sha256: '2'.repeat(64), gps: london, original: '2020:01:01 13:00:00' }),
  ]);
  const hit = items.find((item) => item.kind === 'travel_conflict');
  assert.ok(hit);
  assert.equal(hit.severity, 'high');
  assert.ok(hit.metrics.distanceKm > 5000);
  assert.ok(hit.metrics.speedKmh > 1500);
  assert.equal(hit.citations.length, 4);

  const nearby = findContradictions([
    fileReport({ id: 'report-file-1', sha256: '1'.repeat(64), gps: newYork, original: '2020:01:01 12:00:00' }),
    fileReport({
      id: 'report-file-2',
      sha256: '2'.repeat(64),
      gps: { latitude: 40.72, longitude: -74.01, dateStamp: '2020:01:01', timestamp: '12:30:00' },
      original: '2020:01:01 12:30:00',
    }),
  ]);
  assert.equal(nearby.items.filter((item) => item.kind === 'travel_conflict').length, 0);
});

test('duplicate file bytes are reported as duplication, not corroboration', () => {
  const hash = 'c'.repeat(64);
  const { items } = findContradictions([
    fileReport({ id: 'report-file-1', sha256: hash }),
    fileReport({ id: 'report-file-2', sha256: hash }),
  ]);
  const hit = items.find((item) => item.kind === 'duplicate_file');
  assert.ok(hit);
  assert.equal(hit.severity, 'info');
  assert.equal(hit.citations.length, 2);
  assert.ok(hit.citations.every((cite) => cite.field === 'file.sha256' && cite.value === hash));
});

test('a syntactically valid address with no MX is flagged as unroutable', () => {
  const broken = findContradictions([emailReport({ hasMx: false, implicitMx: false })]).items;
  const hit = broken.find((item) => item.kind === 'unroutable_email');
  assert.ok(hit);
  assert.equal(hit.severity, 'medium');

  assert.equal(
    findContradictions([emailReport({ hasMx: true })]).items.filter((item) => item.kind === 'unroutable_email').length,
    0,
  );
  assert.equal(
    findContradictions([emailReport({ implicitMx: true })]).items.filter((item) => item.kind === 'unroutable_email').length,
    0,
  );
  assert.equal(
    findContradictions([emailReport({ dnsErrors: ['lookup failed'] })]).items.filter(
      (item) => item.kind === 'unroutable_email',
    ).length,
    0,
  );
});

test('contradiction ids are stable and severity-sorted', () => {
  const reports = [
    usernameReport({
      findings: [
        finding({
          status: 'confirmed',
          fields: [{ label: 'Name', value: 'Alice' }],
        }),
      ],
    }),
    usernameReport({
      id: 'report-user-2',
      createdAt: '2026-02-01T00:00:00.000Z',
      findings: [
        finding({
          status: 'absent',
          fields: [{ label: 'Name', value: 'Alicia' }],
        }),
      ],
    }),
    fileReport({ id: 'report-file-1', sha256: 'd'.repeat(64) }),
  ];
  const first = findContradictions(reports);
  const second = findContradictions(reports);
  assert.deepEqual(
    first.items.map((item) => item.id),
    second.items.map((item) => item.id),
  );
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const ranks = first.items.map((item) => order[item.severity]);
  assert.deepEqual(ranks, ranks.slice().sort((a, b) => a - b));
});

test('analyseCase returns a stable, citable shape with coverage counts', () => {
  const record = { id: 'case-1', title: 'Example case' };
  const reports = [
    usernameReport({ findings: [finding({ fields: [{ label: 'Name', value: 'Alice' }] })] }),
    fileReport({ sha256: 'e'.repeat(64) }),
    emailReport(),
    domainReport(),
  ];
  const intel = analyseCase(record, reports);
  assert.equal(intel.schema, INTEL_SCHEMA);
  assert.equal(intel.caseId, 'case-1');
  assert.equal(intel.caseTitle, 'Example case');
  assert.equal(intel.reportCount, 4);
  assert.equal(intel.coverage.reports, 4);
  assert.equal(intel.coverage.files, 1);
  assert.equal(intel.coverage.emails, 1);
  assert.equal(intel.coverage.domains, 1);
  assert.equal(intel.coverage.datedFacts, intel.timeline.count);
  assert.ok(intel.generatedAt);

  for (const item of intel.timeline.items) {
    assert.ok(item.reportId, 'every timeline item cites a report');
    assert.ok(item.field, 'every timeline item cites a field');
  }
  for (const item of intel.contradictions.items) {
    assert.ok(item.citations.length >= 2, 'every contradiction has at least two citations');
    for (const cite of item.citations) {
      assert.ok(cite.reportId);
      assert.ok(cite.field);
    }
  }
});
