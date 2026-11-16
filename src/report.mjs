import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { appendAudit, clearAudit } from './audit.mjs';
import { createDataDirs, dataDir, loadConfig, reportsDir } from './config.mjs';
import { CATEGORY_LABELS } from './sites.mjs';
import {
  c,
  escapeHtml,
  formatDuration,
  nowStamp,
  slugify,
  stripHtml,
  truncate,
} from './util.mjs';

/* ------------------------------------------------------------------ */
/* Shared formatting helpers                                           */
/* ------------------------------------------------------------------ */

const STATUS_LABELS = {
  confirmed: 'Account found (high confidence)',
  possible: 'Possible account',
  unverified: 'Inconclusive',
  absent: 'Not detected',
  blocked: 'Blocked / rate-limited',
  skipped: 'Skipped',
  error: 'Source error',
};

const STATUS_SHORT = {
  confirmed: 'Confirmed',
  possible: 'Possible',
  unverified: 'Inconclusive',
  absent: 'Not detected',
  blocked: 'Blocked',
  skipped: 'Skipped',
  error: 'Error',
};

const categoryLabel = (category) => CATEGORY_LABELS[category] || category;

function safeUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? escapeHtml(url) : null;
  } catch {
    return null;
  }
}

function linkHtml(url, label) {
  const safe = safeUrl(url);
  if (!safe) return `<span>${escapeHtml(label || url || '')}</span>`;
  return `<a href="${safe}" rel="noopener noreferrer nofollow" target="_blank">${escapeHtml(label || url)}</a>`;
}

function fieldRows(fields = []) {
  return fields
    .filter((field) => field && field.value != null && String(field.value).trim() !== '')
    .map(
      (field) => `<tr><th>${escapeHtml(field.label)}</th><td>${
        field.url ? linkHtml(field.url, String(field.value)) : escapeHtml(String(field.value))
      }</td></tr>`,
    )
    .join('');
}

function linkChips(links = []) {
  const rendered = links
    .filter((link) => link?.url)
    .map(
      (link) =>
        `<a class="chip link" href="${safeUrl(link.url) || '#'}" rel="noopener noreferrer nofollow" target="_blank">${escapeHtml(link.label || link.url)}</a>`,
    )
    .join('');
  return rendered ? `<div class="chips">${rendered}</div>` : '';
}

function notesBlock(notes = []) {
  if (!notes?.length) return '';
  return `<section class="panel"><h2>Limitations &amp; notes</h2><ul class="notes">${notes
    .map((note) => `<li>${escapeHtml(note)}</li>`)
    .join('')}</ul></section>`;
}

function riskBlock(risk) {
  if (!risk) return '';
  const level = risk.level || 'none';
  return `<section class="panel risk ${escapeHtml(level)}">
    <div class="risk-head"><h2>Exposure indicators</h2><strong>${risk.score ?? 0}/100 · ${escapeHtml(level)}</strong></div>
    <div class="meter"><span style="width:${Math.max(0, Math.min(100, Number(risk.score) || 0))}%"></span></div>
    <ul class="notes">${(risk.findings || [])
      .map((finding) => `<li>${escapeHtml(finding.text || finding)}</li>`)
      .join('')}</ul>
    ${
      risk.recommendations?.length
        ? `<p class="muted">Recommendations: ${escapeHtml(risk.recommendations.join(' '))}</p>`
        : ''
    }
  </section>`;
}

function warningsBlock(warnings = []) {
  if (!warnings?.length) return '';
  return `<section class="panel warn"><h2>Parser warnings</h2><ul class="notes">${warnings
    .map((warning) => `<li>${escapeHtml(warning)}</li>`)
    .join('')}</ul></section>`;
}

function summaryChips(summary) {
  const keys = ['confirmed', 'possible', 'unverified', 'absent', 'blocked', 'skipped', 'error'];
  return `<div class="summary">${keys
    .filter((key) => summary?.[key])
    .map(
      (key) =>
        `<span class="stat ${key}"><b>${summary[key]}</b> ${escapeHtml(STATUS_SHORT[key])}</span>`,
    )
    .join('')}</div>`;
}

/* ------------------------------------------------------------------ */
/* Username report                                                     */
/* ------------------------------------------------------------------ */

function renderFinding(finding) {
  const fields = finding.profile?.fields || [];
  const links = finding.profile?.links || [];
  const search = [
    finding.name,
    finding.category,
    finding.status,
    finding.detail,
    ...fields.map((field) => `${field.label} ${field.value}`),
  ]
    .join(' ')
    .toLowerCase();

  return `<article class="card finding ${escapeHtml(finding.status)}" data-finding data-status="${escapeHtml(
    finding.status,
  )}" data-search="${escapeHtml(search)}">
    <div class="card-head">
      <span class="dot ${escapeHtml(finding.status)}"></span>
      <h3>${escapeHtml(finding.name)}</h3>
      <span class="badge ${escapeHtml(finding.status)}">${escapeHtml(STATUS_SHORT[finding.status] || finding.status)}</span>
      <span class="cat">${escapeHtml(categoryLabel(finding.category))}</span>
    </div>
    <p class="detail">${escapeHtml(finding.detail || '')}</p>
    ${fields.length ? `<table class="kv">${fieldRows(fields)}</table>` : ''}
    ${linkChips([{ label: 'Open profile', url: finding.url }, ...links])}
    ${
      finding.profile?.note
        ? `<p class="muted small">${escapeHtml(finding.profile.note)}</p>`
        : ''
    }
    ${finding.enrichError ? `<p class="muted small">Enrichment: ${escapeHtml(finding.enrichError)}</p>` : ''}
    <div class="card-foot">Retrieved ${escapeHtml(finding.retrievedAt || '')}${
      finding.elapsedMs != null ? ` · ${formatDuration(finding.elapsedMs)}` : ''
    }${finding.confidence ? ` · ${escapeHtml(finding.confidence)} confidence` : ''}</div>
  </article>`;
}

function renderUsername(result) {
  const statuses = ['confirmed', 'possible', 'unverified', 'absent', 'blocked', 'error', 'skipped'];
  const present = result.findings.filter((finding) => finding.status !== 'absent');
  const filterButtons = [
    `<button class="filter active" data-filter="all">All (${result.findings.length})</button>`,
    ...statuses
      .filter((status) => result.summary?.[status])
      .map(
        (status) =>
          `<button class="filter" data-filter="${status}">${escapeHtml(STATUS_SHORT[status])} (${result.summary[status]})</button>`,
      ),
  ].join('');

  return `
  <section class="panel">
    <div class="panel-head">
      <h2>Results for ${escapeHtml(result.target)}</h2>
      <input id="filterText" type="search" placeholder="Filter by site, field, or URL…" aria-label="Filter results" />
    </div>
    ${summaryChips(result.summary)}
    <div class="filters">${filterButtons}</div>
    <p class="callout">A shared username does <strong>not</strong> prove that two accounts belong to the same person. Confirm identity with independent, lawful evidence.</p>
    <div class="grid">
      ${present.length ? present.map(renderFinding).join('') : '<p class="muted">No accounts were detected.</p>'}
    </div>
    ${
      result.summary?.absent
        ? `<details class="absent-list"><summary>${result.summary.absent} source(s) returned no account</summary><ul class="notes">${result.findings
            .filter((finding) => finding.status === 'absent')
            .map((finding) => `<li>${escapeHtml(finding.name)} — ${escapeHtml(finding.detail || '')}</li>`)
            .join('')}</ul></details>`
        : ''
    }
  </section>
  ${notesBlock(result.notes)}`;
}

/* ------------------------------------------------------------------ */
/* Email report                                                        */
/* ------------------------------------------------------------------ */

function renderEmail(result) {
  const dns = result.dns || {};
  const breaches = result.breaches || {};
  const gravatar = result.gravatar || {};

  const mxText = (dns.mx || [])
    .map((record) => `${record.exchange} (priority ${record.priority})`)
    .join(', ');
  const dnsRows = [
    ['MX', mxText || (dns.nullMx ? 'Null MX — the domain does not accept email' : '—')],
    ['A', (dns.a || []).join(', ') || '—'],
    ['AAAA', (dns.aaaa || []).join(', ') || '—'],
    ['NS', (dns.ns || []).join(', ') || '—'],
    ['SPF', dns.spf?.present ? dns.spf.record : 'Not published'],
    ['DMARC', dns.dmarc?.present ? dns.dmarc.record : 'Not published'],
    [
      'DKIM',
      dns.dkim?.found?.length
        ? dns.dkim.found.map((selector) => selector.selector).join(', ')
        : 'No common selector found',
    ],
  ];

  return `
  ${riskBlock(result.risk)}

  <section class="panel">
    <h2>Address</h2>
    <table class="kv">
      <tr><th>Address</th><td>${escapeHtml(result.target)}</td></tr>
      <tr><th>Syntax</th><td>${result.syntax?.valid ? 'Valid' : `Invalid — ${escapeHtml(result.syntax?.reason || '')}`}</td></tr>
      <tr><th>Domain</th><td>${escapeHtml(result.syntax?.domain || '—')}</td></tr>
      <tr><th>Disposable provider</th><td>${result.risk?.findings?.some((f) => /disposable/i.test(f.text)) ? 'Yes' : 'No'}</td></tr>
      <tr><th>Receives mail (MX)</th><td>${dns.hasMx ? 'Yes' : dns.implicitMx ? 'No MX; implicit A-record fallback' : 'No'}</td></tr>
    </table>
  </section>

  <section class="panel">
    <h2>Public breach records</h2>
    ${
      !breaches.available
        ? `<p class="muted">${escapeHtml(breaches.reason || 'Breach lookup is not configured.')}</p>`
        : breaches.error
          ? `<p class="muted">${escapeHtml(breaches.error)}</p>`
          : breaches.breaches?.length
            ? `<table class="data"><thead><tr><th>Breach</th><th>Domain</th><th>Date</th><th>Accounts</th><th>Data classes</th></tr></thead><tbody>${breaches.breaches
                .map(
                  (breach) =>
                    `<tr><td>${escapeHtml(breach.title || breach.name)}</td><td>${escapeHtml(breach.domain || '')}</td><td>${escapeHtml(breach.breachDate || '')}</td><td>${escapeHtml(String(breach.pwnCount ?? ''))}</td><td>${escapeHtml((breach.dataClasses || []).join(', '))}</td></tr>`,
                )
                .join('')}</tbody></table><p class="muted small">Breach metadata only. No passwords, hashes, or credentials are retrieved or displayed.</p>`
            : '<p class="muted">No public breach records were returned for this address.</p>'
    }
    ${breaches.checked && breaches.available ? `<p class="muted small">Checked: Have I Been Pwned API.</p>` : ''}
  </section>

  <section class="panel">
    <h2>Gravatar (public profile)</h2>
    ${
      gravatar.found
        ? `<table class="kv">${fieldRows([
            { label: 'Display name', value: gravatar.profile?.displayName },
            { label: 'Username', value: gravatar.profile?.preferredUsername },
            { label: 'About', value: gravatar.profile?.aboutMe },
            { label: 'Location', value: gravatar.profile?.currentLocation },
            { label: 'Profile', value: gravatar.profileUrl, url: gravatar.profileUrl },
          ])}</table>
          ${
            gravatar.profile?.accounts?.length
              ? `<table class="data"><thead><tr><th>Domain</th><th>Username</th><th>Verified</th></tr></thead><tbody>${gravatar.profile.accounts
                  .map(
                    (account) =>
                      `<tr><td>${escapeHtml(account.domain || '')}</td><td>${
                        account.url ? linkHtml(account.url, account.username || account.display || '') : escapeHtml(account.username || '')
                      }</td><td>${account.verified ? 'Yes' : 'No'}</td></tr>`,
                  )
                  .join('')}</tbody></table>`
              : ''
          }`
        : `<p class="muted">${escapeHtml(gravatar.error || 'No public Gravatar profile found.')}</p>`
    }
  </section>

  <section class="panel">
    <h2>Domain &amp; email authentication</h2>
    <table class="kv">${dnsRows
      .map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`)
      .join('')}</table>
    ${dns.errors?.length ? `<p class="muted small">DNS notes: ${escapeHtml(dns.errors.join(' · '))}</p>` : ''}
  </section>

  <section class="panel">
    <h2>Public mentions</h2>
    ${
      result.publicMentions?.github?.users?.length
        ? `<p>GitHub accounts with this address in their public profile:</p><ul class="notes">${result.publicMentions.github.users
            .map((user) => `<li>${linkHtml(user.url, user.login)}</li>`)
            .join('')}</ul>`
        : `<p class="muted">${
            result.publicMentions?.github?.error
              ? escapeHtml(result.publicMentions.github.error)
              : 'No GitHub profile lists this address publicly.'
          }</p>`
    }
  </section>

  ${
    result.linked?.requested
      ? `<section class="panel">
          <h2>Linked username scan (opt-in)</h2>
          <p class="muted">Derived from the email local part. A username match is not proof of ownership.</p>
          ${
            result.linked.scans?.length
              ? result.linked.scans
                  .map(
                    (scan) => `<div class="linked">
                      <h3>@${escapeHtml(scan.username)} ${
                        scan.error
                          ? `<span class="muted">— ${escapeHtml(scan.error)}</span>`
                          : `<span class="muted">— ${scan.summary?.confirmed || 0} confirmed / ${scan.summary?.possible || 0} possible</span>`
                      }</h3>
                      ${
                        scan.findings?.length
                          ? `<ul class="notes">${scan.findings
                              .map(
                                (finding) =>
                                  `<li>${escapeHtml(finding.name)} — ${linkHtml(finding.url, 'profile')} <span class="badge ${escapeHtml(finding.status)}">${escapeHtml(STATUS_SHORT[finding.status] || finding.status)}</span></li>`,
                              )
                              .join('')}</ul>`
                          : '<p class="muted small">No matches.</p>'
                      }
                    </div>`,
                  )
                  .join('')
              : '<p class="muted">No username candidates could be derived.</p>'
          }
        </section>`
      : ''
  }

  ${notesBlock(result.notes)}`;
}

/* ------------------------------------------------------------------ */
/* File report                                                         */
/* ------------------------------------------------------------------ */

function renderFile(result) {
  const exif = result.exif || {};
  const file = result.file || {};
  const gps = exif.gps;
  const camera = exif.camera || {};
  const groupOrder = ['IFD0', 'Exif', 'GPS', 'Interop', 'IFD1'];

  const cameraRows = [
    ['Make', camera.make],
    ['Model', camera.model],
    ['Lens', camera.lensModel],
    ['Lens make', camera.lensMake],
    ['Body serial', camera.serialNumber],
    ['Lens serial', camera.lensSerialNumber],
    ['Owner', camera.ownerName],
    ['Software', camera.software],
    ['Artist', camera.artist],
    ['Copyright', camera.copyright],
    ['Description', camera.imageDescription],
    ['Captured', exif.timestamps?.original],
    ['Digitised', exif.timestamps?.digitized],
    ['Modified', exif.timestamps?.modified],
    ['User comment', exif.userComment],
    ['Image unique ID', exif.uniqueId],
  ].filter(([, value]) => value);

  return `
  ${riskBlock(result.risk)}

  <section class="panel">
    <h2>File</h2>
    <table class="kv">
      <tr><th>Name</th><td>${escapeHtml(file.name || '')}</td></tr>
      <tr><th>Size</th><td>${escapeHtml(file.sizeHuman || String(file.size || ''))}</td></tr>
      <tr><th>Detected format</th><td>${escapeHtml(file.format || '')} (${escapeHtml(file.mime || '')})</td></tr>
      <tr><th>Dimensions</th><td>${result.image?.width || '—'} × ${result.image?.height || '—'}</td></tr>
      <tr><th>SHA-256</th><td class="mono">${escapeHtml(file.sha256 || '')}</td></tr>
      <tr><th>SHA-1</th><td class="mono">${escapeHtml(file.sha1 || '')}</td></tr>
      <tr><th>MD5</th><td class="mono">${escapeHtml(file.md5 || '')}</td></tr>
      <tr><th>ICC profile</th><td>${result.image?.hasIccProfile ? 'Present' : 'Not detected'}</td></tr>
      <tr><th>IPTC / Photoshop</th><td>${result.image?.hasIptc ? 'Present' : 'Not detected'}</td></tr>
      <tr><th>Embedded thumbnail</th><td>${result.image?.hasThumbnail ? 'Present' : 'Not detected'}</td></tr>
    </table>
  </section>

  ${
    gps
      ? `<section class="panel gps">
          <h2>GPS location</h2>
          <p class="coordinates">${gps.latitude.toFixed(6)}, ${gps.longitude.toFixed(6)}${
            gps.altitude != null ? ` · ${gps.altitude} m` : ''
          }</p>
          <p class="muted">${escapeHtml(gps.latitudeRef || '')} ${escapeHtml(gps.longitudeRef || '')}${
            gps.dateStamp ? ` · ${escapeHtml(gps.dateStamp)}` : ''
          }${gps.mapDatum ? ` · ${escapeHtml(gps.mapDatum)}` : ''}</p>
          <div class="chips">
            ${linkHtml(gps.maps?.openstreetmap, 'OpenStreetMap')}
            ${linkHtml(gps.maps?.google, 'Google Maps')}
            ${linkHtml(gps.maps?.geohack, 'GeoHack')}
          </div>
        </section>`
      : '<section class="panel"><h2>GPS location</h2><p class="muted">No GPS coordinates found.</p></section>'
  }

  ${
    cameraRows.length
      ? `<section class="panel"><h2>EXIF highlights</h2><table class="kv">${cameraRows
          .map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(String(value))}</td></tr>`)
          .join('')}</table></section>`
      : ''
  }

  ${
    exif.present
      ? groupOrder
          .filter((group) => exif.groups?.[group]?.length)
          .map(
            (group) => `<details class="panel" ${group === 'IFD0' ? 'open' : ''}>
              <summary><h2 style="display:inline">${escapeHtml(group)}</h2> <span class="muted">${exif.groups[group].length} tags</span></summary>
              <table class="data"><thead><tr><th>Tag</th><th>Name</th><th>Value</th></tr></thead><tbody>${exif.groups[group]
                .map(
                  (entry) =>
                    `<tr><td class="mono">${escapeHtml(entry.tag)}</td><td>${escapeHtml(entry.name)}</td><td>${escapeHtml(String(entry.value))}</td></tr>`,
                )
                .join('')}</tbody></table>
            </details>`,
          )
          .join('')
      : '<section class="panel"><h2>EXIF</h2><p class="muted">No EXIF block was found.</p></section>'
  }

  ${
    result.metadataText?.length
      ? `<section class="panel"><h2>Other embedded text</h2><table class="data"><thead><tr><th>Source</th><th>Key</th><th>Value</th></tr></thead><tbody>${result.metadataText
          .map(
            (entry) =>
              `<tr><td>${escapeHtml(entry.source || '')}</td><td>${escapeHtml(entry.key || '')}</td><td>${escapeHtml(String(entry.value))}</td></tr>`,
          )
          .join('')}</tbody></table></section>`
      : ''
  }

  ${
    result.strings
      ? `<section class="panel"><h2>Strings found in file bytes</h2>${Object.entries(result.strings)
          .filter(([, values]) => values?.length)
          .map(
            ([key, values]) =>
              `<h3>${escapeHtml(key)}</h3><div class="chips">${values
                .map((value) => `<span class="chip">${escapeHtml(value)}</span>`)
                .join('')}</div>`,
          )
          .join('') || '<p class="muted">No emails, URLs, handles, paths, or IP addresses detected.</p>'}</section>`
      : ''
  }

  ${warningsBlock(result.warnings)}
  ${notesBlock(result.notes)}`;
}

/* ------------------------------------------------------------------ */
/* Domain report                                                       */
/* ------------------------------------------------------------------ */

function renderDomain(result) {
  const whois = result.whois || {};
  const parsed = whois.parsed || {};
  const dns = result.dns || {};
  const http = result.http || {};
  const certificates = result.certificates || {};

  return `
  ${riskBlock(result.risk)}

  <section class="panel">
    <h2>WHOIS</h2>
    <table class="kv">
      <tr><th>Registrar</th><td>${escapeHtml(parsed.registrar || 'Not disclosed')}</td></tr>
      <tr><th>Created</th><td>${escapeHtml(parsed.creationDate || 'Unknown')}</td></tr>
      <tr><th>Expires</th><td>${escapeHtml(parsed.expiryDate || 'Unknown')}</td></tr>
      <tr><th>Updated</th><td>${escapeHtml(parsed.updatedDate || 'Unknown')}</td></tr>
      <tr><th>Name servers</th><td>${escapeHtml((parsed.nameServers || []).join(', ') || 'Not disclosed')}</td></tr>
      <tr><th>Status</th><td>${escapeHtml((parsed.statuses || []).join(', ') || 'Unknown')}</td></tr>
      <tr><th>DNSSEC</th><td>${escapeHtml(parsed.dnssec || 'Unknown')}</td></tr>
      <tr><th>Registrant org</th><td>${escapeHtml(parsed.registrantOrganization || (parsed.redacted ? 'Redacted for privacy' : 'Not disclosed'))}</td></tr>
      <tr><th>Registrant country</th><td>${escapeHtml(parsed.registrantCountry || (parsed.redacted ? 'Redacted for privacy' : 'Not disclosed'))}</td></tr>
      <tr><th>WHOIS server</th><td>${escapeHtml(whois.server || '')}</td></tr>
    </table>
    ${whois.error ? `<p class="muted">${escapeHtml(whois.error)}</p>` : ''}
    ${
      whois.raw
        ? `<details><summary>Raw WHOIS response</summary><pre>${escapeHtml(whois.raw)}</pre></details>`
        : ''
    }
  </section>

  <section class="panel">
    <h2>DNS</h2>
    <table class="kv">
      <tr><th>A</th><td>${escapeHtml((dns.a || []).join(', ') || '—')}</td></tr>
      <tr><th>AAAA</th><td>${escapeHtml((dns.aaaa || []).join(', ') || '—')}</td></tr>
      <tr><th>MX</th><td>${escapeHtml(dns.nullMx ? 'Null MX — the domain does not accept email' : (dns.mx || []).map((r) => `${r.exchange} (${r.priority})`).join(', ') || '—')}</td></tr>
      <tr><th>NS</th><td>${escapeHtml((dns.ns || []).join(', ') || '—')}</td></tr>
      <tr><th>SPF</th><td>${escapeHtml(dns.spf?.record || 'Not published')}</td></tr>
      <tr><th>DMARC</th><td>${escapeHtml(dns.dmarc?.record || 'Not published')}</td></tr>
      <tr><th>DKIM selectors</th><td>${escapeHtml((dns.dkim?.found || []).map((r) => r.selector).join(', ') || 'None found')}</td></tr>
      <tr><th>SOA</th><td>${escapeHtml(dns.soa ? `${dns.soa.nsname} · ${dns.soa.hostmaster}` : '—')}</td></tr>
    </table>
  </section>

  <section class="panel">
    <h2>HTTP</h2>
    <table class="kv">
      <tr><th>URL</th><td>${linkHtml(http.url, http.url)}</td></tr>
      <tr><th>Status</th><td>${escapeHtml(http.status == null ? '—' : String(http.status))}</td></tr>
      <tr><th>Title</th><td>${escapeHtml(http.title || '—')}</td></tr>
      <tr><th>Server</th><td>${escapeHtml(http.server || '—')}</td></tr>
      <tr><th>Powered by</th><td>${escapeHtml(http.poweredBy || '—')}</td></tr>
      <tr><th>HSTS</th><td>${http.security?.strictTransportSecurity ? 'Present' : 'Missing'}</td></tr>
      <tr><th>CSP</th><td>${http.security?.contentSecurityPolicy ? 'Present' : 'Missing'}</td></tr>
      <tr><th>X-Frame-Options</th><td>${escapeHtml(http.security?.xFrameOptions || http.security?.frameAncestors || 'Missing')}</td></tr>
      <tr><th>X-Content-Type-Options</th><td>${escapeHtml(http.security?.xContentTypeOptions || 'Missing')}</td></tr>
    </table>
    ${http.error ? `<p class="muted">${escapeHtml(http.error)}</p>` : ''}
  </section>

  <section class="panel">
    <h2>Certificate transparency hosts <span class="muted">${certificates.count ?? 0}</span></h2>
    ${certificates.error ? `<p class="muted">${escapeHtml(certificates.error)}</p>` : ''}
    ${
      certificates.names?.length
        ? `<div class="chips">${certificates.names
            .map((name) => `<span class="chip mono">${escapeHtml(name)}</span>`)
            .join('')}</div>${certificates.truncated ? '<p class="muted small">Showing the first 200 names.</p>' : ''}`
        : '<p class="muted">No certificate transparency names returned.</p>'
    }
  </section>

  ${notesBlock(result.notes)}`;
}

/* ------------------------------------------------------------------ */
/* HTML document                                                       */
/* ------------------------------------------------------------------ */

const STYLES = `
:root{--bg:#0a0f18;--panel:#111827;--panel2:#0f172a;--line:#1f2b3d;--text:#e6edf6;--muted:#8ba0b8;--accent:#22d3ee;--green:#34d399;--yellow:#fbbf24;--red:#f87171;--purple:#a78bfa;--orange:#fb923c}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 85% -10%,#12263a 0%,var(--bg) 60%);color:var(--text);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.mono,.coordinates{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header.top{display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between;align-items:flex-end;padding:28px 32px 18px;border-bottom:1px solid var(--line);background:rgba(10,15,24,.7)}
.brand{font-size:26px;letter-spacing:.28em;font-weight:700}.brand span{font-size:11px;letter-spacing:.18em;color:var(--muted);margin-left:12px;text-transform:uppercase}
.meta{color:var(--muted);font-size:12px;text-align:right}
main{max-width:1180px;margin:0 auto;padding:24px 28px 60px}
.hero{padding:18px 0 8px}.hero h1{margin:0;font-size:22px;word-break:break-all}.hero .sub{color:var(--muted);margin-top:6px}
.panel{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:16px 0;box-shadow:0 10px 30px rgba(0,0,0,.18)}
.panel h2{font-size:13px;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin:0 0 12px}
.panel-head{display:flex;flex-wrap:wrap;gap:12px;justify-content:space-between;align-items:center;margin-bottom:8px}
.panel-head h2{margin:0}
.panel-head input{background:#0b1220;border:1px solid var(--line);color:var(--text);border-radius:9px;padding:9px 12px;min-width:260px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13.5px}
th{color:var(--muted);font-weight:600;white-space:nowrap;width:180px}
.data th{width:auto}.data tbody tr:hover{background:rgba(34,211,238,.04)}
.summary{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 14px}
.stat{border:1px solid var(--line);border-radius:999px;padding:5px 10px;font-size:12px;color:var(--muted)}
.stat b{color:var(--text);margin-right:4px}
.stat.confirmed{border-color:#14532d}.stat.possible{border-color:#713f12}.stat.error{border-color:#7f1d1d}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.filter{background:#0b1220;border:1px solid var(--line);color:var(--muted);border-radius:999px;padding:6px 11px;font-size:12px;cursor:pointer}
.filter.active{border-color:var(--accent);color:var(--accent);background:rgba(34,211,238,.08)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:14px}
.card{background:#0c1524;border:1px solid var(--line);border-radius:12px;padding:14px;display:flex;flex-direction:column;gap:10px}
.card-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.card-head h3{margin:0;font-size:15px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--muted);flex:none}
.dot.confirmed{background:var(--green);box-shadow:0 0 10px var(--green)}.dot.possible{background:var(--yellow)}.dot.error{background:var(--red)}.dot.blocked{background:var(--orange)}.dot.unverified{background:var(--purple)}
.badge{font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;padding:3px 7px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.badge.confirmed{color:var(--green);border-color:#14532d}.badge.possible{color:var(--yellow);border-color:#713f12}
.cat{font-size:11px;color:var(--muted);margin-left:auto;text-transform:uppercase;letter-spacing:.08em}
.detail{margin:0;color:var(--muted);font-size:12.5px}
.kv th{width:132px;font-size:12px}.kv td{font-size:12.5px;word-break:break-word}
.card .kv th,.card .kv td{padding:4px 0;border-bottom:1px dashed rgba(31,43,61,.6)}
.card-foot{font-size:11px;color:var(--muted);margin-top:auto}
.muted{color:var(--muted)}.small{font-size:11.5px}
.chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:4px}
.chip{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:3px 9px;font-size:11.5px;color:var(--muted);background:#0b1220}
.chip.link{color:var(--accent);border-color:#164e63}
.notes{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:12.5px}.notes li{margin:4px 0}
.callout{border-left:3px solid var(--yellow);background:rgba(251,191,36,.06);padding:9px 12px;border-radius:0 8px 8px 0;font-size:12.5px;color:#fde68a}
.risk .risk-head{display:flex;justify-content:space-between;align-items:center;gap:12px}
.risk .risk-head h2{margin:0}.risk strong{font-size:15px}
.risk.high strong{color:var(--red)}.risk.medium strong{color:var(--yellow)}.risk.low strong{color:var(--accent)}
.meter{height:8px;background:#0b1220;border-radius:999px;overflow:hidden;margin:10px 0;border:1px solid var(--line)}
.meter span{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--yellow),var(--red))}
.panel.warn{border-color:#7c2d12}.panel.warn h2{color:var(--orange)}
details summary{cursor:pointer;color:var(--muted);padding:2px 0}details[open] summary{margin-bottom:12px}
pre{white-space:pre-wrap;word-break:break-word;background:#0b1220;border:1px solid var(--line);border-radius:9px;padding:12px;font-size:11.5px;max-height:360px;overflow:auto;color:#c7d5e6}
.gps .coordinates{font-size:19px;margin:0 0 4px;color:var(--green)}
.absent-list{margin-top:14px}
.disclaimer{border-top:1px solid var(--line);margin-top:28px;padding-top:14px;color:var(--muted);font-size:11.5px}
footer{color:var(--muted);font-size:11px;text-align:center;padding:0 20px 30px}
@media(max-width:640px){main{padding:16px}header.top{padding:20px}th{width:110px}.panel-head input{min-width:100%;width:100%}}
@media print{body{background:#fff;color:#111}.panel,.card{background:#fff;border-color:#ccc;box-shadow:none}.filters,.panel-head input{display:none}a{color:#0645ad}}
`;

const SCRIPT = `
(() => {
  const buttons = [...document.querySelectorAll('[data-filter]')];
  const cards = [...document.querySelectorAll('[data-finding]')];
  const search = document.getElementById('filterText');
  if (!cards.length) return;
  let active = 'all';
  const apply = () => {
    const query = (search?.value || '').toLowerCase().trim();
    for (const card of cards) {
      const matchesStatus = active === 'all' || card.dataset.status === active;
      const matchesQuery = !query || (card.dataset.search || '').includes(query);
      card.style.display = matchesStatus && matchesQuery ? '' : 'none';
    }
  };
  for (const button of buttons) {
    button.addEventListener('click', () => {
      active = button.dataset.filter;
      buttons.forEach((item) => item.classList.toggle('active', item === button));
      apply();
    });
  }
  search?.addEventListener('input', apply);
})();
`;

export function renderHtml(result) {
  const commandLabel =
    result.command === 'username'
      ? 'Username sweep'
      : result.command === 'email'
        ? 'Email intelligence'
        : result.command === 'file'
          ? 'File metadata forensics'
          : 'Domain reconnaissance';

  let body = '';
  if (result.command === 'username') body = renderUsername(result);
  else if (result.command === 'email') body = renderEmail(result);
  else if (result.command === 'file') body = renderFile(result);
  else if (result.command === 'domain') body = renderDomain(result);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>ARGUS · ${escapeHtml(commandLabel)} · ${escapeHtml(result.target)}</title>
<style>${STYLES}</style>
</head>
<body>
<header class="top">
  <div class="brand">ARGUS<span>Public-data OSINT</span></div>
  <div class="meta">
    ${escapeHtml(commandLabel)}<br>
    ${escapeHtml(result.createdAt)} · ${formatDuration(result.durationMs)}<br>
    ARGUS ${escapeHtml(result.tool?.version || '')} · read-only
  </div>
</header>
<main>
  <section class="hero">
    <h1>${escapeHtml(result.target)}</h1>
    <div class="sub">Generated locally. Public sources only. Retrieved values may change.</div>
  </section>
  ${body}
  <p class="disclaimer">ARGUS collects only publicly accessible information and files supplied by the operator. It does not log in, reset passwords, bypass CAPTCHAs, or access private accounts. Matching usernames, shared emails, or metadata are not proof of identity. Use this report only where you have a lawful basis, and delete it when no longer needed.</p>
</main>
<footer>Report ${escapeHtml(result.createdAt)} · ARGUS ${escapeHtml(result.tool?.version || '')}</footer>
<script>${SCRIPT}</script>
</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/* Report storage                                                      */
/* ------------------------------------------------------------------ */

function safeId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9._-]{3,200}$/.test(id) && !id.includes('..');
}

export function saveReport(result, config = loadConfig()) {
  createDataDirs(config);
  const dir = reportsDir(config);
  const id = `${result.command}-${slugify(result.target)}-${nowStamp()}-${randomBytes(2).toString('hex')}`;
  const jsonPath = join(dir, `${id}.json`);
  const htmlPath = join(dir, `${id}.html`);

  writeFileSync(jsonPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  writeFileSync(htmlPath, renderHtml(result), 'utf8');

  appendAudit(
    {
      action: 'report.created',
      command: result.command,
      target: result.target,
      reportId: id,
    },
    config,
  );

  purgeReports(config);

  return {
    id,
    command: result.command,
    target: result.target,
    createdAt: result.createdAt,
    jsonPath,
    htmlPath,
  };
}

export function listReports(config = loadConfig()) {
  const dir = reportsDir(config);
  mkdirSync(dir, { recursive: true });
  const reports = [];

  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    try {
      const data = JSON.parse(readFileSync(join(dir, name), 'utf8'));
      reports.push({
        id: name.replace(/\.json$/, ''),
        command: data.command,
        target: data.target,
        createdAt: data.createdAt,
        riskScore: data.risk?.score ?? null,
        riskLevel: data.risk?.level ?? null,
        summary: data.summary || null,
        findingCount:
          data.findings?.length ??
          data.breaches?.breaches?.length ??
          (data.exif?.present ? data.exif.tagCount : null),
      });
    } catch {
      /* ignore unreadable reports */
    }
  }

  return reports.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

export function readReport(id, config = loadConfig()) {
  if (!safeId(id)) throw new Error('Invalid report id.');
  const path = join(reportsDir(config), `${id}.json`);
  if (!existsSync(path)) throw new Error('Report not found.');
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function readReportHtml(id, config = loadConfig()) {
  if (!safeId(id)) throw new Error('Invalid report id.');
  const path = join(reportsDir(config), `${id}.html`);
  if (!existsSync(path)) throw new Error('Report not found.');
  return readFileSync(path, 'utf8');
}

export function deleteReport(id, config = loadConfig()) {
  if (!safeId(id)) throw new Error('Invalid report id.');
  const dir = reportsDir(config);
  let removed = false;
  for (const extension of ['json', 'html']) {
    const path = join(dir, `${id}.${extension}`);
    if (existsSync(path)) {
      unlinkSync(path);
      removed = true;
    }
  }
  if (!removed) throw new Error('Report not found.');
  appendAudit({ action: 'report.deleted', reportId: id }, config);
  return true;
}

export function purgeReports(config = loadConfig()) {
  // listReports() returns newest first, so retention and overflow can both keep the newest entries.
  const reports = listReports(config);
  const retentionDays = Number(config.settings?.retentionDays) || 0;
  const maxReports = Number(config.settings?.maxReports) || 0;
  const dir = reportsDir(config);
  const deleted = [];

  const cutoff = retentionDays > 0 ? Date.now() - retentionDays * 86_400_000 : null;

  const remove = (report) => {
    for (const extension of ['json', 'html']) {
      const path = join(dir, `${report.id}.${extension}`);
      if (existsSync(path)) unlinkSync(path);
    }
    deleted.push(report.id);
  };

  const surviving = [];
  for (const report of reports) {
    const created = new Date(report.createdAt).getTime();
    if (cutoff && Number.isFinite(created) && created < cutoff) remove(report);
    else surviving.push(report);
  }

  if (maxReports > 0 && surviving.length > maxReports) {
    for (const report of surviving.slice(maxReports)) remove(report);
  }

  return deleted;
}

export function deleteAllData(config = loadConfig()) {
  const dir = reportsDir(config);
  let removed = 0;
  if (existsSync(dir)) {
    for (const name of readdirSync(dir)) {
      if (name.endsWith('.json') || name.endsWith('.html')) {
        unlinkSync(join(dir, name));
        removed++;
      }
    }
  }
  clearAudit(config);
  appendAudit({ action: 'data.deleted_all', details: { files: removed } }, config);
  return { removed, dataDir: dataDir(config) };
}

export function reportStats(config = loadConfig()) {
  const reports = listReports(config);
  return {
    count: reports.length,
    retentionDays: config.settings?.retentionDays ?? null,
    maxReports: config.settings?.maxReports ?? null,
    reportsDir: reportsDir(config),
  };
}

/* ------------------------------------------------------------------ */
/* Terminal rendering                                                  */
/* ------------------------------------------------------------------ */

const symbol = (status) =>
  status === 'confirmed'
    ? c.green('●')
    : status === 'possible'
      ? c.yellow('◐')
      : status === 'absent'
        ? c.gray('○')
        : status === 'blocked'
          ? c.magenta('⊘')
          : status === 'skipped'
            ? c.gray('–')
            : status === 'error'
              ? c.red('✕')
              : c.yellow('?');

function printUsername(result) {
  console.log(
    `${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('username sweep')}  ${c.dim(result.createdAt)}`,
  );
  console.log(`  Target ${c.bold(result.target)} · ${result.summary.total} sources · ${formatDuration(result.durationMs)}`);
  console.log(
    `  ${c.green(`${result.summary.confirmed} confirmed`)} · ${c.yellow(`${result.summary.possible} possible`)} · ${c.gray(`${result.summary.absent} absent`)} · ${c.magenta(`${result.summary.blocked} blocked`)} · ${c.red(`${result.summary.error} errors`)} · ${c.gray(`${result.summary.skipped} skipped`)}`,
  );
  console.log('');

  const groups = [
    ['confirmed', 'CONFIRMED ACCOUNTS'],
    ['possible', 'POSSIBLE ACCOUNTS'],
    ['unverified', 'INCONCLUSIVE'],
    ['blocked', 'BLOCKED / RATE-LIMITED'],
    ['error', 'SOURCE ERRORS'],
    ['skipped', 'SKIPPED (robots.txt)'],
  ];

  for (const [status, label] of groups) {
    const items = result.findings.filter((finding) => finding.status === status);
    if (!items.length) continue;
    console.log(c.bold(`  ${label}`));
    for (const finding of items) {
      console.log(`   ${symbol(status)} ${c.bold(finding.name)} ${c.dim(`(${categoryLabel(finding.category)})`)}`);
      console.log(`     ${c.dim(finding.detail || '')}`);
      for (const field of (finding.profile?.fields || []).slice(0, 3)) {
        console.log(`     ${c.cyan(field.label)}: ${truncate(String(field.value), 90)}`);
      }
      console.log(`     ${c.blue(finding.url)}`);
      if (finding.enrichError) console.log(`     ${c.dim(finding.enrichError)}`);
      for (const link of (finding.profile?.links || []).slice(0, 4)) {
        if (link.label === 'Open profile') continue;
        console.log(`     ${c.dim('↳')} ${link.label}: ${c.blue(link.url)}`);
      }
    }
    console.log('');
  }

  console.log(c.yellow('  Note: a shared username does not prove shared identity.'));
}

function printEmail(result) {
  const dns = result.dns || {};
  console.log(`${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('email intelligence')}  ${c.dim(result.createdAt)}`);
  console.log(`  Target ${c.bold(result.target)}`);
  console.log(
    `  ${result.syntax?.valid ? c.green('valid syntax') : c.red('invalid syntax')} · risk ${c.bold(`${result.risk?.score ?? 0}/100 ${result.risk?.level || ''}`)} · ${formatDuration(result.durationMs)}`,
  );
  console.log('');
  console.log(`  MX          ${dns.hasMx ? c.green(`${dns.mx.length} record(s) — ${dns.mx.map((m) => m.exchange).slice(0, 3).join(', ')}`) : dns.nullMx ? c.yellow('null MX — the domain does not accept email') : c.yellow('none')}`);
  console.log(`  SPF         ${dns.spf?.present ? c.green('present') : c.yellow('missing')}`);
  console.log(`  DMARC       ${dns.dmarc?.present ? c.green(`present${dns.dmarc.policy ? ` (p=${dns.dmarc.policy})` : ''}`) : c.yellow('missing')}`);
  console.log(`  DKIM        ${dns.dkim?.found?.length ? c.green(dns.dkim.found.map((d) => d.selector).join(', ')) : c.gray('no common selector found')}`);

  if (result.gravatar?.found) {
    console.log(
      `  Gravatar    ${c.green('public profile')} — ${result.gravatar.profile?.displayName || result.gravatar.profile?.preferredUsername || ''}`,
    );
    for (const account of (result.gravatar.profile?.accounts || []).slice(0, 5)) {
      console.log(`              ↳ ${account.domain}: ${account.username || account.display || ''}`);
    }
  } else {
    console.log(`  Gravatar    ${c.gray('no profile')}`);
  }

  if (!result.breaches?.available) {
    console.log(`  Breaches    ${c.gray(result.breaches?.reason || 'not configured')}`);
  } else if (result.breaches.error) {
    console.log(`  Breaches    ${c.red(result.breaches.error)}`);
  } else if (result.breaches.breaches?.length) {
    console.log(`  Breaches    ${c.red(`${result.breaches.breaches.length} record(s)`)} — ${result.breaches.breaches.map((b) => b.title || b.name).slice(0, 5).join(', ')}`);
  } else {
    console.log(`  Breaches    ${c.green('none found')}`);
  }

  const github = result.publicMentions?.github;
  if (github?.users?.length) {
    console.log(`  Mentions    ${github.users.length} GitHub profile(s) — ${github.users.map((u) => u.login).join(', ')}`);
  }

  if (result.risk?.findings?.length) {
    console.log('');
    console.log(c.bold('  EXPOSURE INDICATORS'));
    for (const finding of result.risk.findings) console.log(`   • ${finding.text}`);
  }

  if (result.linked?.requested) {
    console.log('');
    console.log(c.bold('  LINKED USERNAME SCAN'));
    for (const scan of result.linked.scans || []) {
      if (scan.error) console.log(`   @${scan.username}: ${c.red(scan.error)}`);
      else {
        console.log(
          `   @${scan.username}: ${c.green(`${scan.summary?.confirmed || 0} confirmed`)} · ${c.yellow(`${scan.summary?.possible || 0} possible`)}`,
        );
        for (const finding of scan.findings || []) {
          console.log(`     ${symbol(finding.status)} ${finding.name} — ${c.blue(finding.url)}`);
        }
      }
    }
  }

  console.log('');
  console.log(c.dim('  No login, password-reset, or inbox access was attempted.'));
}

function printFile(result) {
  const exif = result.exif || {};
  const gps = exif.gps;
  console.log(`${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('file metadata forensics')}  ${c.dim(result.createdAt)}`);
  console.log(`  File ${c.bold(result.target)} · ${result.file.sizeHuman} · ${result.file.format.toUpperCase()} ${result.image.width || '?'}×${result.image.height || '?'}`);
  console.log(`  SHA-256 ${c.dim(result.file.sha256)}`);
  console.log(`  Risk ${c.bold(`${result.risk.score}/100 ${result.risk.level}`)} · ${exif.tagCount || 0} EXIF tags · ${formatDuration(result.durationMs)}`);
  console.log('');

  if (exif.camera?.make || exif.camera?.model) {
    console.log(`  Camera      ${[exif.camera.make, exif.camera.model].filter(Boolean).join(' ')}`);
  }
  if (exif.camera?.lensModel) console.log(`  Lens        ${exif.camera.lensModel}`);
  if (exif.camera?.serialNumber) console.log(`  Serial      ${c.yellow(exif.camera.serialNumber)}`);
  if (exif.camera?.software) console.log(`  Software    ${exif.camera.software}`);
  if (exif.timestamps?.original) console.log(`  Captured    ${exif.timestamps.original}`);
  if (exif.userComment) console.log(`  Comment     ${truncate(exif.userComment, 100)}`);

  if (gps) {
    console.log(
      `  GPS         ${c.green(`${gps.latitude.toFixed(6)}, ${gps.longitude.toFixed(6)}`)}${gps.altitude != null ? ` (${gps.altitude} m)` : ''}`,
    );
    console.log(`              ${c.blue(gps.maps.openstreetmap)}`);
  } else {
    console.log(`  GPS         ${c.gray('none found')}`);
  }

  if (result.metadataText?.length) {
    console.log('');
    console.log(c.bold('  EMBEDDED TEXT'));
    for (const entry of result.metadataText.slice(0, 8)) {
      console.log(`   ${entry.key}: ${truncate(String(entry.value), 100)} ${c.dim(`(${entry.source})`)}`);
    }
  }

  for (const [key, values] of Object.entries(result.strings || {})) {
    if (!values?.length) continue;
    console.log(`  ${key.padEnd(10)} ${values.slice(0, 5).map((value) => truncate(value, 50)).join(', ')}`);
  }

  if (result.risk.findings.length) {
    console.log('');
    console.log(c.bold('  EXPOSURE INDICATORS'));
    for (const finding of result.risk.findings) console.log(`   • ${finding.text}`);
  }

  console.log('');
  console.log(
    result.stripSupported
      ? c.dim('  A metadata-free copy can be produced from the web UI (no original is modified).')
      : c.dim('  Metadata stripping is available for JPEG and PNG files.'),
  );
}

function printDomain(result) {
  const parsed = result.whois?.parsed || {};
  const dns = result.dns || {};
  const http = result.http || {};
  console.log(`${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('domain reconnaissance')}  ${c.dim(result.createdAt)}`);
  console.log(`  Target ${c.bold(result.target)} · risk ${result.risk.level} · ${formatDuration(result.durationMs)}`);
  console.log('');
  console.log(`  Registrar   ${parsed.registrar || c.gray('not disclosed')}`);
  console.log(`  Created     ${parsed.creationDate || c.gray('unknown')}`);
  console.log(`  Expires     ${parsed.expiryDate || c.gray('unknown')}`);
  console.log(`  Nameservers ${(parsed.nameServers || []).join(', ') || c.gray('unknown')}`);
  console.log(`  A           ${(dns.a || []).join(', ') || c.gray('none')}`);
  console.log(`  MX          ${(dns.mx || []).map((record) => record.exchange).join(', ') || c.gray('none')}`);
  console.log(`  SPF/DMARC   ${dns.spf?.present ? c.green('SPF') : c.red('no SPF')} · ${dns.dmarc?.present ? c.green('DMARC') : c.red('no DMARC')}`);
  console.log(`  HTTP        ${http.status ?? '—'} ${http.title ? `— ${truncate(http.title, 70)}` : ''}`);
  console.log(`  HSTS/CSP    ${http.security?.strictTransportSecurity ? c.green('HSTS') : c.yellow('no HSTS')} · ${http.security?.contentSecurityPolicy ? c.green('CSP') : c.yellow('no CSP')}`);
  console.log(`  CT hosts    ${result.certificates?.count ?? 0}`);
  if (result.certificates?.names?.length) {
    console.log(`              ${result.certificates.names.slice(0, 8).join(', ')}${result.certificates.names.length > 8 ? ' …' : ''}`);
  }
  if (result.risk.findings?.length) {
    console.log('');
    console.log(c.bold('  EXPOSURE INDICATORS'));
    for (const finding of result.risk.findings) console.log(`   • ${finding.text}`);
  }
}

export function printResult(result) {
  if (result.command === 'username') printUsername(result);
  else if (result.command === 'email') printEmail(result);
  else if (result.command === 'file') printFile(result);
  else if (result.command === 'domain') printDomain(result);
}
