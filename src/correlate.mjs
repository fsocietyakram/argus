import { isIP } from 'node:net';

const EMAIL = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

/**
 * Build an exact-value index across attached reports. Each occurrence keeps
 * the report id, a human-readable description, and the JSON field path it came
 * from so a reviewer can check the original value.
 */
function add(index, value, type, reportId, evidence, field) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized || normalized.length > 253) return;
  if (type === 'email' && !EMAIL.test(normalized)) return;
  if (type === 'ip' && !isIP(normalized)) return;
  if (type === 'domain' && !DOMAIN.test(normalized)) return;
  const key = `${type}:${normalized}`;
  const group = index.get(key) || { type, value: normalized, occurrences: [] };
  if (!group.occurrences.some((item) => item.reportId === reportId)) {
    group.occurrences.push({ reportId, evidence, field });
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
    /* ignore values that are not absolute URLs */
  }
}

export function correlateCaseReports(reports) {
  const indicators = new Map();
  const timeline = [];

  const dnsAnswers = (report) => [
    ...(report.dns?.a || []).map((ip, index) => [`dns.a[${index}]`, ip]),
    ...(report.dns?.aaaa || []).map((ip, index) => [`dns.aaaa[${index}]`, ip]),
  ];

  for (const { id, report } of reports) {
    timeline.push({ reportId: id, command: report.command, target: report.target, createdAt: report.createdAt });
    if (report.command === 'domain') {
      add(indicators, report.target, 'domain', id, 'domain scan target', 'target');
      (report.certificates?.names || []).forEach((name, index) => {
        add(indicators, name, 'domain', id, 'certificate transparency name', `certificates.names[${index}]`);
      });
      for (const [field, ip] of dnsAnswers(report)) add(indicators, ip, 'ip', id, 'DNS answer', field);
    } else if (report.command === 'email') {
      add(indicators, report.target, 'email', id, 'email report target', 'target');
      if (report.syntax?.domain) add(indicators, report.syntax.domain, 'domain', id, 'email domain', 'syntax.domain');
      for (const [field, ip] of dnsAnswers(report)) {
        add(indicators, ip, 'ip', id, 'email domain DNS answer', field);
      }
    } else if (report.command === 'file') {
      (report.strings?.emails || []).forEach((value, index) => {
        add(indicators, value, 'email', id, 'file string indicator', `strings.emails[${index}]`);
      });
      (report.strings?.ips || []).forEach((value, index) => {
        add(indicators, value, 'ip', id, 'file string indicator', `strings.ips[${index}]`);
      });
      (report.strings?.urls || []).forEach((value, index) => {
        addUrl(indicators, value, id, 'embedded file URL', `strings.urls[${index}]`);
      });
      (report.strings?.handles || []).forEach((value, index) => {
        add(indicators, value, 'handle', id, 'embedded file handle', `strings.handles[${index}]`);
      });
    } else if (report.command === 'username') {
      (report.findings || []).forEach((finding, findingIndex) => {
        (finding.profile?.links || []).forEach((link, linkIndex) => {
          if (/website|personal site|blog/i.test(link.label || '')) {
            addUrl(
              indicators,
              link.url,
              id,
              `${finding.name} profile link`,
              `findings[${findingIndex}].profile.links[${linkIndex}].url`,
            );
          }
        });
        (finding.profile?.fields || []).forEach((field, fieldIndex) => {
          const path = `findings[${findingIndex}].profile.fields[${fieldIndex}].value`;
          if (/email/i.test(field.label || '')) {
            add(indicators, field.value, 'email', id, `${finding.name}: ${field.label}`, path);
          } else if (/website|domain/i.test(field.label || '')) {
            addUrl(indicators, field.value, id, `${finding.name}: ${field.label}`, path);
          }
        });
      });
    }
  }
  return {
    timeline: timeline
      .filter((item) => item.createdAt)
      .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt)),
    repeatedIndicators: [...indicators.values()]
      .filter((item) => item.occurrences.length > 1)
      .map((item) => ({ ...item, occurrences: item.occurrences.slice(0, 20) }))
      .sort((a, b) => b.occurrences.length - a.occurrences.length || a.type.localeCompare(b.type)),
  };
}
