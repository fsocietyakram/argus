import net from 'node:net';
import { domainToASCII } from 'node:url';
import { loadConfig } from './config.mjs';
import { dnsIntel } from './email.mjs';
import { fetchLimited, parseJson, uniq, truncate } from './util.mjs';

export function normalizeDomain(input) {
  let value = String(input ?? '').trim().toLowerCase();
  if (!value) throw new Error('Provide a valid registrable domain, for example example.com.');
  value = value.replace(/^[a-z]+:\/\//i, '');
  value = value.split('/')[0].split('?')[0].split('#')[0];
  value = value.replace(/^www\./, '');
  value = value.replace(/:\d+$/, '');
  const ascii = domainToASCII(value);
  if (!ascii || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(ascii)) {
    throw new Error('That does not look like a valid registrable domain.');
  }
  return ascii;
}

/* ------------------------------------------------------------------ */
/* WHOIS (port 43)                                                     */
/* ------------------------------------------------------------------ */

function queryWhois(server, query, timeout = 9000) {
  return new Promise((resolve) => {
    let data = '';
    let settled = false;
    let socket;

    const finish = (error) => {
      if (settled) return;
      settled = true;
      try {
        socket?.destroy();
      } catch {
        /* ignore */
      }
      resolve({ error, text: data });
    };

    try {
      socket = net.createConnection({ host: server, port: 43 });
    } catch (err) {
      resolve({ error: err.message, text: '' });
      return;
    }

    socket.setTimeout(timeout, () => finish('timeout'));
    socket.on('connect', () => socket.write(`${query}\r\n`));
    socket.on('data', (chunk) => {
      data += chunk.toString('latin1');
      if (data.length > 512 * 1024) finish('response-too-large');
    });
    socket.on('end', () => finish(null));
    socket.on('error', (err) => finish(err.code || err.message));
  });
}

const WHOIS_SERVERS = {
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.pir.org',
  io: 'whois.nic.io',
  co: 'whois.nic.co',
  dev: 'whois.nic.google',
  app: 'whois.nic.google',
  xyz: 'whois.nic.xyz',
  info: 'whois.afilias.net',
  me: 'whois.nic.me',
  uk: 'whois.nic.uk',
  de: 'whois.denic.de',
  in: 'whois.registry.in',
};

function parseWhoisDate(value) {
  if (!value) return null;
  const cleaned = value.trim().replace(/\s+/g, ' ');
  const parsed = new Date(cleaned);
  return Number.isNaN(parsed.getTime()) ? cleaned : parsed.toISOString();
}

function firstMatch(text, regexes) {
  for (const regex of regexes) {
    const match = text.match(regex);
    if (match?.[1] && !/^(not disclosed|redacted|none|n\/a)$/i.test(match[1].trim())) {
      return match[1].trim();
    }
  }
  return null;
}

function allMatches(text, regexes) {
  const values = [];
  for (const regex of regexes) {
    for (const match of text.matchAll(regex)) {
      const value = match[1]?.trim();
      if (value) values.push(value.replace(/^https?:\/\//i, ''));
    }
  }
  return uniq(values);
}

function parseWhois(text) {
  const creation = firstMatch(text, [
    /^(?:Creation Date|Created On|Created|Domain Registration Date|Registration Time|Registered on):\s*(.+)$/im,
  ]);
  const expiry = firstMatch(text, [
    /^(?:Registry Expiry Date|Expiration Date|Expiry Date|Registrar Registration Expiration Date|paid-till):\s*(.+)$/im,
  ]);
  const updated = firstMatch(text, [
    /^(?:Updated Date|Last Updated On|Last Modified|changed):\s*(.+)$/im,
  ]);
  const statuses = allMatches(text, [/^(?:Domain Status|Status):\s*(.+)$/gim]).map((value) =>
    value.split(/\s+/)[0],
  );

  return {
    registrar: firstMatch(text, [/^Registrar:\s*(.+)$/im, /^Sponsoring Registrar:\s*(.+)$/im]),
    registrarIanaId: firstMatch(text, [/^Registrar IANA ID:\s*(.+)$/im]),
    creationDate: parseWhoisDate(creation),
    expiryDate: parseWhoisDate(expiry),
    updatedDate: parseWhoisDate(updated),
    nameServers: allMatches(text, [/^Name Server:\s*(.+)$/gim, /^nserver:\s*(.+)$/gim]),
    statuses: uniq(statuses),
    dnssec: firstMatch(text, [/^DNSSEC:\s*(.+)$/im]),
    registrantOrganization: firstMatch(text, [
      /^Registrant Organization:\s*(.+)$/im,
      /^org:\s*(.+)$/im,
    ]),
    registrantCountry: firstMatch(text, [
      /^Registrant Country:\s*(.+)$/im,
      /^country:\s*(.+)$/im,
    ]),
    abuseEmail: firstMatch(text, [
      /^Registrar Abuse Contact Email:\s*(.+)$/im,
      /^abuse-mailbox:\s*(.+)$/im,
    ]),
    redacted: /redacted for privacy|data protected|not disclosed|gdpr redacted/i.test(text),
  };
}

async function whoisLookup(domain) {
  const iana = await queryWhois('whois.iana.org', domain, 8000);
  let text = iana.text;
  let server = iana.text.match(/^refer:\s*(\S+)/im)?.[1]?.trim();

  if (!server) server = WHOIS_SERVERS[domain.split('.').pop()];

  if (server && server !== 'whois.iana.org') {
    const referred = await queryWhois(server, domain, 10_000);
    if (!referred.error && referred.text.trim()) text = referred.text;
    else if (referred.error) {
      return {
        server,
        error: `WHOIS query failed: ${referred.error}`,
        raw: truncate(iana.text, 2000),
        parsed: parseWhois(iana.text),
      };
    }
  }

  if (!text.trim()) {
    return { server: server || 'whois.iana.org', error: 'WHOIS returned no data.', parsed: {} };
  }

  return {
    server: server || 'whois.iana.org',
    parsed: parseWhois(text),
    raw: truncate(text, 6000),
    error: null,
  };
}

/* ------------------------------------------------------------------ */
/* Certificate transparency (crt.sh)                                   */
/* ------------------------------------------------------------------ */

async function crtSh(domain, timeout = 20_000) {
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
  const res = await fetchLimited(url, {
    timeout,
    maxBytes: 3_500_000,
    headers: { accept: 'application/json' },
  });

  if (res.error) return { error: `crt.sh request failed: ${res.error}`, names: [] };
  if (res.status !== 200) return { error: `crt.sh returned HTTP ${res.status}.`, names: [] };

  const rows = parseJson(res.text);
  if (!Array.isArray(rows)) {
    return {
      error: res.truncated ? 'crt.sh response was truncated; subdomain list is incomplete.' : 'crt.sh returned unexpected JSON.',
      names: [],
    };
  }

  const names = [];
  for (const row of rows) {
    for (const name of String(row.name_value || '').split(/\r?\n/)) {
      const cleaned = name.trim().toLowerCase();
      if (!cleaned) continue;
      if (cleaned === domain || cleaned.endsWith(`.${domain}`)) names.push(cleaned);
    }
  }

  const uniqueNames = uniq(names).sort();
  return {
    error: null,
    count: uniqueNames.length,
    names: uniqueNames.slice(0, 200),
    truncated: uniqueNames.length > 200,
  };
}

/* ------------------------------------------------------------------ */
/* HTTP headers                                                        */
/* ------------------------------------------------------------------ */

function titleOf(html) {
  const match = String(html).match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? truncate(match[1].replace(/\s+/g, ' ').trim(), 160) : null;
}

async function httpIntel(domain, timeout) {
  let lastError = null;
  for (const scheme of ['https', 'http']) {
    const res = await fetchLimited(`${scheme}://${domain}/`, { timeout, maxBytes: 400_000 });
    if (res.error) {
      lastError = res.error;
      continue;
    }
    const headers = res.headers;
    return {
      url: res.finalUrl,
      scheme,
      status: res.status,
      title: titleOf(res.text),
      server: headers.server || null,
      poweredBy: headers['x-powered-by'] || null,
      security: {
        strictTransportSecurity: headers['strict-transport-security'] || null,
        contentSecurityPolicy: headers['content-security-policy'] || null,
        xFrameOptions: headers['x-frame-options'] || null,
        xContentTypeOptions: headers['x-content-type-options'] || null,
        referrerPolicy: headers['referrer-policy'] || null,
        permissionsPolicy: headers['permissions-policy'] || null,
        frameAncestors: /frame-ancestors/i.test(headers['content-security-policy'] || '') ? 'via CSP' : null,
      },
      error: null,
    };
  }

  return {
    url: `https://${domain}/`,
    scheme: null,
    status: null,
    title: null,
    server: null,
    poweredBy: null,
    security: {},
    error: lastError ? `HTTP request failed: ${lastError}` : 'HTTP request failed.',
  };
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

export async function scanDomain(input, options = {}) {
  const config = options.config || loadConfig();
  const domain = normalizeDomain(input);
  const startedAt = new Date();
  const started = Date.now();
  const timeout = options.timeoutMs ?? config.settings.timeoutMs ?? 12_000;

  const [dns, whois, certificates, http] = await Promise.all([
    dnsIntel(domain, { timeout, dkim: true }),
    whoisLookup(domain),
    crtSh(domain, Math.max(timeout, 15_000)),
    httpIntel(domain, timeout),
  ]);

  const findings = [];
  let riskScore = 0;
  const add = (points, text) => {
    riskScore += points;
    findings.push({ points, text });
  };

  let ageDays = null;
  if (whois.parsed?.creationDate && !Number.isNaN(new Date(whois.parsed.creationDate).getTime())) {
    ageDays = Math.floor((Date.now() - new Date(whois.parsed.creationDate).getTime()) / 86_400_000);
    if (ageDays <= 30) add(20, `Domain was registered ${ageDays} day(s) ago.`);
  }
  if (whois.parsed?.expiryDate && !Number.isNaN(new Date(whois.parsed.expiryDate).getTime())) {
    const daysLeft = Math.floor((new Date(whois.parsed.expiryDate).getTime() - Date.now()) / 86_400_000);
    if (daysLeft <= 30) add(15, `Domain expires in ${daysLeft} day(s).`);
  }
  if (!dns.spf?.present) add(5, 'No SPF record published.');
  if (!dns.dmarc?.present) add(10, 'No DMARC record published.');
  if (!http.error && !http.security?.strictTransportSecurity) add(10, 'No HSTS header on the home page.');
  if (!http.error && !http.security?.contentSecurityPolicy) add(5, 'No Content-Security-Policy header on the home page.');
  if (whois.parsed?.dnssec && /unsigned/i.test(whois.parsed.dnssec)) add(5, 'DNSSEC is not enabled.');

  riskScore = Math.min(100, riskScore);

  return {
    schema: 'argus.report/v1',
    command: 'domain',
    tool: { name: 'ARGUS', version: '1.0.0' },
    target: domain,
    createdAt: startedAt.toISOString(),
    durationMs: Date.now() - started,
    dns,
    whois,
    certificates,
    http,
    ageDays,
    risk: {
      score: riskScore,
      level: riskScore >= 60 ? 'high' : riskScore >= 30 ? 'medium' : riskScore > 0 ? 'low' : 'none',
      findings,
    },
    notes: [
      'WHOIS data may be redacted for privacy; missing registrant fields are not evidence of anything.',
      'Certificate transparency names come from public certificate logs and may include third-party or historical hosts.',
      'Security-header checks reflect a single HTTP request and can differ by CDN edge or path.',
      'Only public DNS, WHOIS, certificate transparency, and HTTP data were queried.',
    ],
  };
}
