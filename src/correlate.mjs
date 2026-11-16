import { isIP } from 'node:net';

const EMAIL = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function add(index, value, type, reportId, evidence) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized || normalized.length > 253) return;
  if (type === 'email' && !EMAIL.test(normalized)) return;
  if (type === 'ip' && !isIP(normalized)) return;
  if (type === 'domain' && !DOMAIN.test(normalized)) return;
  const key = `${type}:${normalized}`;
  const group = index.get(key) || { type, value: normalized, occurrences: [] };
  if (!group.occurrences.some((item) => item.reportId === reportId)) group.occurrences.push({ reportId, evidence });
  index.set(key, group);
}

function addUrl(index, value, reportId, evidence) {
  try {
    const url = new URL(value);
    if (['http:', 'https:'].includes(url.protocol)) add(index, url.hostname.replace(/^www\./, ''), 'domain', reportId, evidence);
  } catch { /* ignore values that are not absolute URLs */ }
}

export function correlateCaseReports(reports) {
  const indicators = new Map();
  const timeline = [];
  for (const { id, report } of reports) {
    timeline.push({ reportId: id, command: report.command, target: report.target, createdAt: report.createdAt });
    if (report.command === 'domain') {
      add(indicators, report.target, 'domain', id, 'domain scan target');
      for (const name of report.certificates?.names || []) add(indicators, name, 'domain', id, 'certificate transparency name');
      for (const ip of [...(report.dns?.a || []), ...(report.dns?.aaaa || [])]) add(indicators, ip, 'ip', id, 'DNS answer');
    } else if (report.command === 'email') {
      add(indicators, report.target, 'email', id, 'email report target');
      if (report.syntax?.domain) add(indicators, report.syntax.domain, 'domain', id, 'email domain');
      for (const ip of [...(report.dns?.a || []), ...(report.dns?.aaaa || [])]) add(indicators, ip, 'ip', id, 'email domain DNS answer');
    } else if (report.command === 'file') {
      for (const value of report.strings?.emails || []) add(indicators, value, 'email', id, 'file string indicator');
      for (const value of report.strings?.ips || []) add(indicators, value, 'ip', id, 'file string indicator');
      for (const value of report.strings?.urls || []) addUrl(indicators, value, id, 'embedded file URL');
      for (const value of report.strings?.handles || []) add(indicators, value, 'handle', id, 'embedded file handle');
    } else if (report.command === 'username') {
      for (const finding of report.findings || []) {
        for (const link of finding.profile?.links || []) {
          if (/website|personal site|blog/i.test(link.label || '')) addUrl(indicators, link.url, id, `${finding.name} profile link`);
        }
        for (const field of finding.profile?.fields || []) {
          if (/email/i.test(field.label || '')) add(indicators, field.value, 'email', id, `${finding.name}: ${field.label}`);
          else if (/website|domain/i.test(field.label || '')) addUrl(indicators, field.value, id, `${finding.name}: ${field.label}`);
        }
      }
    }
  }
  return {
    timeline: timeline.filter((item) => item.createdAt).sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt)),
    repeatedIndicators: [...indicators.values()].filter((item) => item.occurrences.length > 1)
      .map((item) => ({ ...item, occurrences: item.occurrences.slice(0, 20) }))
      .sort((a, b) => b.occurrences.length - a.occurrences.length || a.type.localeCompare(b.type)),
  };
}
