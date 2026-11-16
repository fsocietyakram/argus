import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

const EMAIL = /^[A-Z0-9._%+-]+@(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i;
const MAX_INDICATORS = 10_000;
const MAX_REPORTS = 50;
const MAX_OCCURRENCES_PER_INDICATOR = 50;
const MAX_SOURCES_PER_OCCURRENCE = 10;
const MAX_REPEATED_INDICATORS = 500;
const items = (value, limit = 5_000) => (Array.isArray(value) ? value.slice(0, limit) : []);

const RELATION_RULES = {
  email: {
    relation: 'same_public_email',
    matchConfidence: 'high',
    attributionConfidence: 'medium',
    caveat: 'A shared public email is a useful lead, but may be shared, forwarded, or reused.',
  },
  domain: {
    relation: 'same_domain_or_link',
    matchConfidence: 'high',
    attributionConfidence: 'low',
    caveat: 'A linked domain does not establish who controls it.',
  },
  ip: {
    relation: 'same_ip_address',
    matchConfidence: 'high',
    attributionConfidence: 'very low',
    caveat: 'Shared hosting, VPN, CDN, or cloud infrastructure can explain this match.',
  },
  handle: {
    relation: 'same_normalized_handle',
    matchConfidence: 'medium',
    attributionConfidence: 'very low',
    caveat: 'A repeated handle can belong to different people; case folding may merge case-sensitive names.',
  },
};

function normalizeIndicator(value, type) {
  const raw = String(value ?? '').trim();
  if (!raw || raw.length > 1024) return null;

  if (type === 'domain') {
    // A wildcard SAN covers subdomains, not the exact apex it resembles.
    if (raw.startsWith('*.')) return null;
    const normalized = domainToASCII(raw.replace(/\.$/, '').toLowerCase());
    return normalized && DOMAIN.test(normalized) ? normalized : null;
  }

  if (type === 'ip') {
    const address = raw.startsWith('[') && raw.endsWith(']') ? raw.slice(1, -1) : raw;
    if (isIP(address) === 4) return address;
    if (isIP(address) !== 6) return null;
    try {
      return new URL(`http://[${address}]/`).hostname.slice(1, -1).toLowerCase();
    } catch {
      return null;
    }
  }

  if (type === 'email') {
    const at = raw.lastIndexOf('@');
    if (at < 1) return null;
    const local = raw.slice(0, at).toLowerCase();
    const domain = domainToASCII(raw.slice(at + 1).replace(/\.$/, '').toLowerCase());
    const normalized = `${local}@${domain}`;
    return domain && local.length <= 64 && normalized.length <= 254 && EMAIL.test(normalized)
      ? normalized
      : null;
  }

  if (type === 'handle') {
    const normalized = raw.replace(/^@/, '').normalize('NFC').toLowerCase();
    return normalized && normalized.length <= 253 ? normalized : null;
  }

  return null;
}

function add(index, value, type, reportId, evidence, field) {
  const normalized = normalizeIndicator(value, type);
  if (!normalized) return;

  const key = `${type}:${normalized}`;
  let group = index.get(key);
  if (!group) {
    if (index.size >= MAX_INDICATORS) {
      index.truncated = true;
      return;
    }
    group = { type, value: normalized, occurrences: [] };
  }

  const source = { evidence, field };
  const occurrence = group.occurrences.find((item) => item.reportId === reportId);
  if (occurrence) {
    if (
      occurrence.sources.length < MAX_SOURCES_PER_OCCURRENCE
      && !occurrence.sources.some((item) => item.field === field && item.evidence === evidence)
    ) {
      occurrence.sources.push(source);
    }
  } else if (group.occurrences.length < MAX_OCCURRENCES_PER_INDICATOR) {
    group.occurrences.push({ reportId, evidence, field, sources: [source] });
  }
  index.set(key, group);
}

function addUrl(index, value, reportId, evidence, field) {
  try {
    const url = new URL(value);
    if (['http:', 'https:'].includes(url.protocol)) {
      add(index, url.hostname.replace(/^www\./, ''), 'domain', reportId, evidence, field);
    }
  } catch {
    // Non-URL profile values are ignored at this boundary.
  }
}

function reportArrays(report) {
  const dns = report.dns || {};
  return {
    a: items(dns.a),
    aaaa: items(dns.aaaa),
    certificates: items(report.certificates?.names),
  };
}

export function correlateCaseReports(reports) {
  const indicators = new Map();
  const timeline = [];
  const reportSummaries = [];

  for (const entry of items(reports, MAX_REPORTS)) {
    if (!entry || typeof entry !== 'object' || !entry.report || typeof entry.report !== 'object') continue;
    const id = String(entry.id ?? '').slice(0, 200);
    if (!id) continue;
    const report = entry.report;
    const summary = { reportId: id, command: report.command, target: report.target, createdAt: report.createdAt };
    reportSummaries.push(summary);
    if (report.createdAt && Number.isFinite(Date.parse(report.createdAt))) timeline.push(summary);

    if (report.command === 'domain') {
      const arrays = reportArrays(report);
      add(indicators, report.target, 'domain', id, 'domain scan target', 'target');
      arrays.certificates.forEach((name, index) => {
        add(indicators, name, 'domain', id, 'certificate transparency name', `certificates.names[${index}]`);
      });
      arrays.a.forEach((ip, index) => add(indicators, ip, 'ip', id, 'DNS A answer', `dns.a[${index}]`));
      arrays.aaaa.forEach((ip, index) => add(indicators, ip, 'ip', id, 'DNS AAAA answer', `dns.aaaa[${index}]`));
    } else if (report.command === 'email') {
      const arrays = reportArrays(report);
      add(indicators, report.target, 'email', id, 'email report target', 'target');
      add(indicators, report.syntax?.domain, 'domain', id, 'email domain', 'syntax.domain');
      arrays.a.forEach((ip, index) => add(indicators, ip, 'ip', id, 'email domain DNS A answer', `dns.a[${index}]`));
      arrays.aaaa.forEach((ip, index) => add(indicators, ip, 'ip', id, 'email domain DNS AAAA answer', `dns.aaaa[${index}]`));
    } else if (report.command === 'file') {
      const strings = report.strings || {};
      items(strings.emails).forEach((value, index) => {
        add(indicators, value, 'email', id, 'file string indicator', `strings.emails[${index}]`);
      });
      items(strings.ips).forEach((value, index) => {
        add(indicators, value, 'ip', id, 'file string indicator', `strings.ips[${index}]`);
      });
      items(strings.urls).forEach((value, index) => {
        addUrl(indicators, value, id, 'embedded file URL', `strings.urls[${index}]`);
      });
      items(strings.handles).forEach((value, index) => {
        add(indicators, value, 'handle', id, 'embedded file handle', `strings.handles[${index}]`);
      });
    } else if (report.command === 'username') {
      add(indicators, report.target, 'handle', id, 'username search target', 'target');
      items(report.findings, 1_000).forEach((finding, findingIndex) => {
        if (!finding || typeof finding !== 'object') return;
        if (finding.status && !['confirmed', 'possible'].includes(finding.status)) return;
        items(finding.profile?.links, 100).forEach((link, linkIndex) => {
          if (!link || !/website|personal site|blog/i.test(String(link.label || ''))) return;
          addUrl(
            indicators,
            link.url,
            id,
            `${finding.name || 'Profile'} profile link`,
            `findings[${findingIndex}].profile.links[${linkIndex}].url`,
          );
        });
        items(finding.profile?.fields, 100).forEach((field, fieldIndex) => {
          if (!field || typeof field !== 'object') return;
          const path = `findings[${findingIndex}].profile.fields[${fieldIndex}].value`;
          if (/email/i.test(String(field.label || ''))) {
            add(indicators, field.value, 'email', id, `${finding.name || 'Profile'}: ${field.label}`, path);
          } else if (/website|domain/i.test(String(field.label || ''))) {
            addUrl(indicators, field.value, id, `${finding.name || 'Profile'}: ${field.label}`, path);
          }
        });
      });
    }
  }

  timeline.sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
  const commandByReport = new Map(reportSummaries.map((item) => [item.reportId, item.command || 'unknown']));
  const allRepeated = [...indicators.values()]
    .filter((item) => item.occurrences.length > 1)
    .map((item) => {
      const occurrences = item.occurrences.map((occurrence) => ({
        ...occurrence,
        command: commandByReport.get(occurrence.reportId) || 'unknown',
        sources: occurrence.sources.slice(0, MAX_SOURCES_PER_OCCURRENCE),
      }));
      const observedInCommands = [...new Set(occurrences.map((occurrence) => occurrence.command))].sort();
      return {
        ...item,
        ...RELATION_RULES[item.type],
        occurrenceCount: occurrences.length,
        occurrences: occurrences.slice(0, 20),
        observedInCommands,
        pattern: observedInCommands.length > 1 ? `cross_tool_${item.type}_overlap` : `repeated_${item.type}_indicator`,
      };
    })
    .sort((a, b) => b.occurrenceCount - a.occurrenceCount
      || a.type.localeCompare(b.type) || a.value.localeCompare(b.value));

  const repeatedIndicatorsTruncated = indicators.truncated === true || allRepeated.length > MAX_REPEATED_INDICATORS;
  const repeatedIndicators = allRepeated.slice(0, MAX_REPEATED_INDICATORS);
  // Preserve the compact v1 shape for empty cases and existing API clients.
  if (!repeatedIndicators.length) return { timeline, repeatedIndicators };

  const graphIndicators = repeatedIndicators.slice(0, 40);
  const graphIndicatorIds = new Set(graphIndicators.map((item) => `${item.type}:${item.value}`));
  const graphLinks = [];
  for (const indicator of graphIndicators) {
    for (const occurrence of indicator.occurrences) {
      if (graphLinks.length >= 200) break;
      graphLinks.push({
        reportId: occurrence.reportId,
        indicatorId: `${indicator.type}:${indicator.value}`,
        evidence: occurrence.evidence,
        field: occurrence.field,
        relation: indicator.relation,
        matchConfidence: indicator.matchConfidence,
        attributionConfidence: indicator.attributionConfidence,
        caveat: indicator.caveat,
        sources: occurrence.sources,
      });
    }
    if (graphLinks.length >= 200) break;
  }
  const graphReportIds = new Set(graphLinks.map((item) => item.reportId));
  const graph = {
    reports: reportSummaries.filter((item) => graphReportIds.has(item.reportId)),
    indicators: graphIndicators,
    links: graphLinks,
    truncated: repeatedIndicatorsTruncated
      || allRepeated.length > graphIndicators.length
      || graphIndicators.some((item) => item.occurrenceCount > item.occurrences.length)
      || graphIndicatorIds.size !== graphIndicators.length
      || graphIndicators.reduce((count, item) => count + item.occurrences.length, 0) > graphLinks.length,
  };

  return {
    timeline,
    repeatedIndicators,
    repeatedIndicatorsTruncated,
    graph,
  };
}
