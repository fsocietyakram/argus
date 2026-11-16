/**
 * Deterministic case intelligence: a timeline and contradiction checks that
 * never call a model.
 *
 * Every item carries the exact report id and JSON field path it came from, so
 * the output can be cited, audited, and fed to the AI as facts rather than
 * guesses. Rules are deliberately conservative: a hit means "look here", not
 * "this is proof".
 */

import { sha256Hex } from './ledger.mjs';

export const INTEL_SCHEMA = 'argus.case-intel/v1';

const NAME_LABELS = new Set(['name', 'real name']);
const LOCATION_LABELS = new Set(['location']);
const JOINED_LABELS = new Set(['joined', 'created', 'member since']);
const CONFIRMED = new Set(['confirmed', 'possible']);
const ABSENT = new Set(['absent']);

export function text(value) {
  return String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim();
}

function key(value) {
  return text(value).toLowerCase();
}

/** Parse ISO, `YYYY-MM-DD`, `March 3, 2010`, and EXIF `YYYY:MM:DD HH:MM:SS`. */
export function parseDate(value) {
  const raw = text(value);
  if (!raw) return null;
  const exif = raw.match(/^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
  if (exif) {
    const [, year, month, day, hour, minute, second] = exif;
    const date = new Date(
      Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second)),
    );
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }
  const parsed = Date.parse(raw);
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}

function dateOnly(iso) {
  return iso ? iso.slice(0, 10) : null;
}

function distanceKm(a, b) {
  const toRad = (value) => (value * Math.PI) / 180;
  const earth = 6371;
  const dLat = toRad(b.latitude - a.latitude);
  const dLon = toRad(b.longitude - a.longitude);
  const lat1 = toRad(a.latitude);
  const lat2 = toRad(b.latitude);
  const h =
    Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * earth * Math.asin(Math.min(1, Math.sqrt(h)));
}

function citation(reportId, field, value, extra = {}) {
  return { reportId, field, value: text(value).slice(0, 240), ...extra };
}

function contradiction(kind, severity, title, detail, citations, extra = {}) {
  return {
    id: `${kind}-${sha256Hex(JSON.stringify([kind, citations.map((item) => [item.reportId, item.field, item.value])])).slice(0, 10)}`,
    kind,
    severity,
    title,
    detail,
    citations,
    ...extra,
  };
}

/* ------------------------------------------------------------------ */
/* Extraction                                                          */
/* ------------------------------------------------------------------ */

/**
 * Flatten an attached case into citable facts. `reports` is
 * [{ id, report }] in attachment order.
 */
export function extractFacts(reports = []) {
  const facts = {
    collected: [],
    claims: [],
    files: [],
    emails: [],
    domains: [],
    scans: [],
  };

  for (const item of reports) {
    const reportId = item?.id;
    const report = item?.report;
    if (!reportId || !report) continue;
    const collectedAt = parseDate(report.createdAt);

    facts.collected.push({ reportId, at: collectedAt, command: report.command, target: report.target });

    if (report.command === 'username') {
      (report.findings || []).forEach((finding, findingIndex) => {
        if (!finding || (!CONFIRMED.has(finding.status) && !ABSENT.has(finding.status))) return;
        facts.scans.push({
          reportId,
          at: collectedAt,
          target: key(report.normalized || report.target).replace(/^@/, ''),
          sourceId: finding.id || finding.name,
          sourceName: finding.name,
          status: finding.status,
          url: finding.url || null,
          field: `findings[${findingIndex}].status`,
        });
        if (!CONFIRMED.has(finding.status)) return;
        (finding.profile?.fields || []).forEach((field, fieldIndex) => {
          const label = key(field?.label);
          const value = text(field?.value);
          if (!value) return;
          facts.claims.push({
            reportId,
            at: collectedAt,
            target: key(report.normalized || report.target).replace(/^@/, ''),
            sourceId: finding.id || finding.name,
            sourceName: finding.name,
            label: text(field.label),
            value,
            field: `findings[${findingIndex}].profile.fields[${fieldIndex}].value`,
          });
        });
      });
    }

    if (report.command === 'file') {
      const gps =
        report.exif?.gps && Number.isFinite(report.exif.gps.latitude) && Number.isFinite(report.exif.gps.longitude)
          ? { latitude: report.exif.gps.latitude, longitude: report.exif.gps.longitude }
          : null;
      const originalAt = parseDate(report.exif?.timestamps?.original);
      const digitizedAt = parseDate(report.exif?.timestamps?.digitized);
      const modifiedAt = parseDate(report.exif?.timestamps?.modified);
      let gpsAt = null;
      if (report.exif?.gps?.dateStamp && report.exif?.gps?.timestamp) {
        const stamp = String(report.exif.gps.dateStamp).replace(/\0/g, '').trim();
        const time = String(report.exif.gps.timestamp).replace(/\0/g, '').trim();
        gpsAt = parseDate(`${stamp} ${time}`);
      } else if (report.exif?.gps?.dateStamp) {
        gpsAt = parseDate(report.exif.gps.dateStamp);
      }

      facts.files.push({
        reportId,
        report,
        collectedAt,
        filename: report.file?.name || report.target,
        sha256: report.file?.sha256 || null,
        gps,
        originalAt,
        originalField: 'exif.timestamps.original',
        capturedAt: originalAt || gpsAt,
        gpsAt,
        digitizedAt,
        modifiedAt,
        camera: report.exif?.camera || null,
      });
    }

    if (report.command === 'email' && report.syntax?.valid) {
      facts.emails.push({
        reportId,
        address: text(report.target),
        domain: text(report.syntax.domain),
        hasMx: Boolean(report.dns?.hasMx),
        implicitMx: Boolean(report.dns?.implicitMx),
        dnsErrors: Array.isArray(report.dns?.errors) ? report.dns.errors : [],
        gravatar: report.gravatar || null,
        breaches: report.breaches?.breaches || [],
      });
    }

    if (report.command === 'domain') {
      const whois = report.whois?.parsed || {};
      facts.domains.push({
        reportId,
        domain: text(report.target).toLowerCase(),
        registrar: text(whois.registrar),
        registrantOrganization: text(whois.registrantOrganization),
        registrantCountry: text(whois.registrantCountry),
        created: parseDate(whois.creationDate),
        updated: parseDate(whois.updatedDate),
        expires: parseDate(whois.expiryDate),
      });
    }
  }

  return facts;
}

/* ------------------------------------------------------------------ */
/* Timeline                                                            */
/* ------------------------------------------------------------------ */

export function buildTimeline(reports = []) {
  const facts = extractFacts(reports);
  const items = [];
  const seen = new Set();

  const add = (at, item) => {
    const iso = parseDate(at);
    if (!iso) return;
    const row = {
      at: iso,
      date: dateOnly(iso),
      kind: item.kind,
      label: text(item.label),
      detail: item.detail ? text(item.detail).slice(0, 240) : null,
      reportId: item.reportId,
      field: item.field,
    };
    const unique = `${row.at}|${row.reportId}|${row.field}|${row.label}`;
    if (seen.has(unique)) return;
    seen.add(unique);
    items.push(row);
  };

  for (const entry of facts.collected) {
    add(entry.at, {
      kind: 'collection',
      label: `Report collected · ${entry.command || 'unknown'}`,
      detail: entry.target,
      reportId: entry.reportId,
      field: 'createdAt',
    });
  }

  for (const file of facts.files) {
    for (const [at, label, field] of [
      [file.originalAt, 'Capture time', 'exif.timestamps.original'],
      [file.gpsAt, 'GPS fix time', 'exif.gps.dateStamp'],
      [file.digitizedAt, 'Digitized', 'exif.timestamps.digitized'],
      [file.modifiedAt, 'Metadata modified', 'exif.timestamps.modified'],
    ]) {
      if (!at) continue;
      add(at, {
        kind: field === 'exif.gps.dateStamp' ? 'gps' : 'metadata',
        label,
        detail:
          field === 'exif.gps.dateStamp' && file.gps
            ? `${file.filename} · ${file.gps.latitude.toFixed(5)}, ${file.gps.longitude.toFixed(5)}`
            : `${file.filename}${file.camera?.model ? ` · ${file.camera.model}` : ''}`,
        reportId: file.reportId,
        field,
      });
    }
  }

  for (const claim of facts.claims) {
    if (!JOINED_LABELS.has(key(claim.label))) continue;
    add(claim.value, {
      kind: 'account',
      label: `Account created · ${claim.sourceName || 'source'}`,
      detail: claim.value,
      reportId: claim.reportId,
      field: claim.field,
    });
  }

  for (const domain of facts.domains) {
    for (const [label, at, field] of [
      ['Domain registered', domain.created, 'whois.parsed.creationDate'],
      ['Domain updated', domain.updated, 'whois.parsed.updatedDate'],
      ['Domain expires', domain.expires, 'whois.parsed.expiryDate'],
    ]) {
      if (at) {
        add(at, {
          kind: 'domain',
          label,
          detail: domain.domain,
          reportId: domain.reportId,
          field,
        });
      }
    }
  }

  for (const email of facts.emails) {
    for (const breach of email.breaches) {
      if (!breach?.breachDate) continue;
      add(breach.breachDate, {
        kind: 'breach',
        label: `Breach · ${breach.title || breach.name || 'unknown'}`,
        detail: breach.domain || email.address,
        reportId: email.reportId,
        field: `breaches.breaches[${email.breaches.indexOf(breach)}].breachDate`,
      });
    }
  }

  items.sort((a, b) => a.at.localeCompare(b.at) || a.label.localeCompare(b.label));
  return {
    items,
    count: items.length,
    first: items[0]?.at || null,
    last: items[items.length - 1]?.at || null,
    byKind: items.reduce((acc, item) => {
      acc[item.kind] = (acc[item.kind] || 0) + 1;
      return acc;
    }, {}),
  };
}

/* ------------------------------------------------------------------ */
/* Contradictions                                                      */
/* ------------------------------------------------------------------ */

function conflictingValues(claims) {
  const distinct = new Map();
  for (const claim of claims) {
    const normalized = key(claim.value);
    if (!normalized) continue;
    const list = distinct.get(normalized) || [];
    list.push(claim);
    distinct.set(normalized, list);
  }
  return distinct.size > 1 ? [...distinct.values()] : null;
}

export function findContradictions(reports = []) {
  const facts = extractFacts(reports);
  const found = [];

  /* Same target and source disagree between collections. */
  const scanGroups = new Map();
  for (const scan of facts.scans) {
    const bucket = `${scan.target}\u0000${scan.sourceId}`;
    const group = scanGroups.get(bucket) || { target: scan.target, sourceName: scan.sourceName, rows: [] };
    group.rows.push(scan);
    scanGroups.set(bucket, group);
  }
  for (const group of scanGroups.values()) {
    const present = group.rows.find((row) => CONFIRMED.has(row.status));
    const absent = group.rows.find((row) => ABSENT.has(row.status));
    if (!present || !absent) continue;
    found.push(
      contradiction(
        'status_conflict',
        'medium',
        `Conflicting results for ${group.sourceName || 'a source'}`,
        `The same target @${group.target} was recorded as present in one collection and absent in another. Accounts can be deleted or renamed between scans, so compare the collection times.`,
        [
          citation(present.reportId, present.field, present.status, { at: present.at }),
          citation(absent.reportId, absent.field, absent.status, { at: absent.at }),
        ],
      ),
    );
  }

  /* Names and locations asserted by public profiles of the same target. */
  const groupedClaims = new Map();
  for (const claim of facts.claims) {
    const bucket = `${claim.target}\u0000${key(claim.label)}`;
    const list = groupedClaims.get(bucket) || [];
    list.push(claim);
    groupedClaims.set(bucket, list);
  }
  for (const claims of groupedClaims.values()) {
    const label = key(claims[0]?.label);
    const kind = NAME_LABELS.has(label)
      ? { kind: 'name_conflict', severity: 'low', title: 'Profile names differ across sources' }
      : LOCATION_LABELS.has(label)
        ? { kind: 'location_conflict', severity: 'low', title: 'Profile locations differ across sources' }
        : null;
    if (!kind) continue;
    const groups = conflictingValues(claims);
    if (!groups) continue;
    const citations = claims.map((claim) =>
      citation(claim.reportId, claim.field, `${claim.sourceName}: ${claim.value}`),
    );
    const detail = NAME_LABELS.has(label)
      ? 'Public display names commonly differ by nickname, script, or platform convention. Treat this as a lead, not proof of different people.'
      : 'Locations are self-reported and may be stale, approximate, or deliberately vague. Treat this as a lead, not proof of travel.';
    found.push(contradiction(kind.kind, kind.severity, kind.title, detail, citations));
  }

  /* A capture time after the collection time is physically impossible. */
  for (const file of facts.files) {
    if (!file.originalAt || !file.collectedAt) continue;
    const delta = new Date(file.originalAt).getTime() - new Date(file.collectedAt).getTime();
    if (delta > 86_400_000) {
      found.push(
        contradiction(
          'impossible_timestamp',
          'high',
          'File capture time is after the collection time',
          'The embedded capture timestamp is more than a day later than the report that collected it. Either the device clock was wrong or the metadata was edited after capture.',
          [
            citation(file.reportId, 'exif.timestamps.original', file.originalAt),
            citation(file.reportId, 'createdAt', file.collectedAt),
          ],
        ),
      );
    }
  }

  /* Two files cannot be far apart faster than commercial air travel. */
  const located = facts.files.filter((file) => file.gps && file.capturedAt);
  for (let i = 0; i < located.length; i++) {
    for (let j = i + 1; j < located.length; j++) {
      const a = located[i];
      const b = located[j];
      const hours = Math.abs(new Date(a.capturedAt).getTime() - new Date(b.capturedAt).getTime()) / 3_600_000;
      if (!(hours > 0)) continue;
      const km = distanceKm(a.gps, b.gps);
      const speed = km / hours;
      if (speed <= 900) continue;
      const fieldA = a.originalAt ? 'exif.timestamps.original' : 'exif.gps.dateStamp';
      const fieldB = b.originalAt ? 'exif.timestamps.original' : 'exif.gps.dateStamp';
      found.push(
        contradiction(
          'travel_conflict',
          speed > 1500 ? 'high' : 'medium',
          'GPS locations imply faster-than-air travel',
          `The two files place the subject ${Math.round(km).toLocaleString('en-US')} km apart within ${hours.toFixed(1)} hour(s) — about ${Math.round(speed).toLocaleString('en-US')} km/h. EXIF timestamps carry no timezone, so check for edited metadata, clock drift, timezone offsets, or different devices before drawing a conclusion.`,
          [
            citation(a.reportId, fieldA, a.originalAt || a.gpsAt),
            citation(a.reportId, 'exif.gps.latitude', `${a.gps.latitude}, ${a.gps.longitude}`),
            citation(b.reportId, fieldB, b.originalAt || b.gpsAt),
            citation(b.reportId, 'exif.gps.latitude', `${b.gps.latitude}, ${b.gps.longitude}`),
          ],
          {
            metrics: { distanceKm: Math.round(km), hours: Number(hours.toFixed(2)), speedKmh: Math.round(speed) },
          },
        ),
      );
    }
  }

  /* The same bytes attached twice is duplication, not corroboration. */
  const byHash = new Map();
  for (const file of facts.files) {
    if (!file.sha256) continue;
    const list = byHash.get(file.sha256) || [];
    list.push(file);
    byHash.set(file.sha256, list);
  }
  for (const [hash, files] of byHash) {
    if (files.length < 2) continue;
    found.push(
      contradiction(
        'duplicate_file',
        'info',
        'The same file is attached more than once',
        'Identical SHA-256 hashes mean identical bytes. Count this as one piece of evidence, not independent corroboration.',
        files.map((file) => citation(file.reportId, 'file.sha256', hash)),
        { hash },
      ),
    );
  }

  /* Syntax says valid, DNS says nothing can receive mail. */
  for (const email of facts.emails) {
    if (email.hasMx || email.implicitMx || email.dnsErrors.length) continue;
    found.push(
      contradiction(
        'unroutable_email',
        'medium',
        'Address has no usable mail exchanger',
        'The address is syntactically valid but the domain publishes no MX or implicit MX record. It may be a display-only or forged address, or DNS may have changed since collection.',
        [
          citation(email.reportId, 'dns.hasMx', String(email.hasMx)),
          citation(email.reportId, 'dns.implicitMx', String(email.implicitMx)),
        ],
      ),
    );
  }

  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  found.sort(
    (a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) || a.title.localeCompare(b.title),
  );

  return {
    items: found,
    count: found.length,
    bySeverity: found.reduce((acc, item) => {
      acc[item.severity] = (acc[item.severity] || 0) + 1;
      return acc;
    }, {}),
  };
}

/* ------------------------------------------------------------------ */
/* Combined view                                                       */
/* ------------------------------------------------------------------ */

export function analyseCase(record, reports = []) {
  const facts = extractFacts(reports);
  const timeline = buildTimeline(reports);
  const contradictions = findContradictions(reports);
  return {
    schema: INTEL_SCHEMA,
    caseId: record?.id || null,
    caseTitle: record?.title || null,
    generatedAt: new Date().toISOString(),
    reportCount: reports.length,
    timeline,
    contradictions,
    coverage: {
      reports: reports.length,
      profiles: facts.claims.length,
      files: facts.files.length,
      emails: facts.emails.length,
      domains: facts.domains.length,
      scans: facts.scans.length,
      datedFacts: timeline.count,
    },
  };
}
