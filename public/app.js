/* ARGUS local web UI — talks only to the loopback API served by src/server.mjs. */

const state = {
  config: null,
  categories: new Set(),
  activeTab: 'username',
  usernameJob: null,
  emailJob: null,
  file: null,
  fileResult: null,
  emailTimer: null,
  reports: [],
  cases: [],
  activeCase: null,
  casePreview: null,
  aiSettings: null,
};

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const esc = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch],
  );

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const STATUS_LABELS = {
  confirmed: 'Account found',
  possible: 'Possible account',
  unverified: 'Inconclusive',
  absent: 'Not detected',
  blocked: 'Blocked',
  skipped: 'Skipped',
  error: 'Source error',
};

const COMMAND_LABELS = {
  username: 'Username sweep',
  email: 'Email intelligence',
  file: 'File metadata',
  domain: 'Domain reconnaissance',
};

function safeHref(url) {
  if (!url) return null;
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : null;
  } catch {
    return null;
  }
}

function link(url, label, extra = '') {
  const href = safeHref(url);
  const text = esc(label || url || '');
  if (!href) return `<span>${text}</span>`;
  return `<a href="${esc(href)}" ${extra} rel="noopener noreferrer nofollow" target="_blank">${text}</a>`;
}

const fmtDate = (value) => {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
};

const fmtDuration = (ms) => {
  if (ms == null) return '—';
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
};

function toast(message, type = 'info') {
  const host = $('#toasts');
  if (!host) return;
  const node = document.createElement('div');
  node.className = `toast ${type}`;
  node.textContent = message;
  host.append(node);
  setTimeout(() => {
    node.style.opacity = '0';
    setTimeout(() => node.remove(), 200);
  }, type === 'error' ? 7000 : 4200);
}

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

async function api(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };
  if (method !== 'GET') headers['x-argus'] = '1';

  let body = options.body;
  if (options.json !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(options.json);
  }

  const res = await fetch(path, { method, headers, body });
  const type = res.headers.get('content-type') || '';

  if (!res.ok) {
    let message = `Request failed (HTTP ${res.status}).`;
    let data = null;
    if (type.includes('application/json')) {
      data = await res.json().catch(() => null);
      if (data?.error) message = data.error;
    } else {
      const text = await res.text().catch(() => '');
      if (text) message = text.slice(0, 300);
    }
    const error = new Error(message);
    error.status = res.status;
    error.code = data?.code || null;
    error.retryable = Boolean(data?.retryable);
    error.retryAfter = data?.retryAfter ?? null;
    error.missing = Array.isArray(data?.missing) ? data.missing : null;
    throw error;
  }

  if (type.includes('application/json')) return res.json();
  return res;
}

async function pollJob(jobId, onUpdate) {
  const started = Date.now();
  for (;;) {
    const job = await api(`/api/jobs/${jobId}`);
    onUpdate?.(job);
    if (job.status === 'done') return job;
    if (job.status === 'error') throw new Error(job.error || 'The scan failed.');
    if (Date.now() - started > 6 * 60 * 1000) {
      throw new Error('Timed out waiting for the scan to finish.');
    }
    await sleep(700);
  }
}

/* ------------------------------------------------------------------ */
/* Tabs                                                                */
/* ------------------------------------------------------------------ */

function activateTab(name) {
  state.activeTab = name;
  $$('.tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === name));
  $$('.tab-panel').forEach((panel) => panel.classList.toggle('active', panel.id === `tab-${name}`));
  if (history.replaceState) history.replaceState(null, '', `#${name}`);
  if (name === 'reports') refreshReports();
  if (name === 'cases') {
    refreshCases();
    loadCaseReportOptions();
  }
  if (name === 'ai-settings') loadAiSettings();
}

function initTabs() {
  $$('.tab').forEach((tab) => {
    tab.addEventListener('click', () => activateTab(tab.dataset.tab));
  });
  const hash = (window.location.hash || '').replace('#', '');
  if (['username', 'email', 'file', 'reports', 'cases', 'ai-settings'].includes(hash)) activateTab(hash);
}

/* ------------------------------------------------------------------ */
/* Configuration / sources                                             */
/* ------------------------------------------------------------------ */

async function loadConfig() {
  const config = await api('/api/config');
  state.config = config;
  if (config.ai) applyAiSettings(config.ai);

  const hibp = $('#hibp-badge');
  if (hibp) {
    hibp.textContent = config.hibpConfigured ? 'Breach API: enabled' : 'Breach API: not configured';
    hibp.classList.toggle('ok', Boolean(config.hibpConfigured));
    hibp.classList.toggle('off', !config.hibpConfigured);
  }

  const note = $('#hibp-note');
  if (note) {
    note.textContent = config.hibpConfigured
      ? 'Breach metadata will be checked through Have I Been Pwned. Only breach names, dates, and data classes are shown.'
      : 'Optional: set the HIBP_API_KEY environment variable and restart ARGUS to enable public breach-metadata checks.';
  }

  const limit = $('#upload-limit');
  if (limit) {
    limit.textContent = `JPEG, PNG, WebP, GIF, TIFF, HEIC, PDF — up to ${config.settings.maxUploadMb} MB`;
  }

  renderCategories();
  renderSources();
  renderReportStats(config.stats);
}

function renderCategories() {
  const host = $('#username-categories');
  if (!host || !state.config) return;
  const chips = state.config.categories
    .map(
      (category) =>
        `<button type="button" class="chip category-chip${
          state.categories.has(category.id) ? ' active' : ''
        }" data-category="${esc(category.id)}" aria-pressed="${state.categories.has(category.id)}">${esc(
          category.label,
        )} <span class="count">${category.count}</span></button>`,
    )
    .join('');

  host.innerHTML = `<button type="button" class="chip category-chip${
    state.categories.size === 0 ? ' active' : ''
  }" data-category="" aria-pressed="${state.categories.size === 0}">All categories</button>${chips}`;

  $$('.category-chip', host).forEach((chip) => {
    chip.addEventListener('click', () => {
      const id = chip.dataset.category;
      if (!id) state.categories.clear();
      else if (state.categories.has(id)) state.categories.delete(id);
      else state.categories.add(id);
      renderCategories();
    });
  });
}

function sourceMeta(source) {
  const parts = [
    source.access === 'api' ? 'API' : 'page',
    `${source.confidence} confidence`,
    `${source.rateLimit}/min`,
  ];
  return parts.join(' · ');
}

function renderSources() {
  const host = $('#source-list');
  const count = $('#source-count');
  if (!host || !state.config) return;

  const enabled = state.config.sources.filter((source) => source.enabled).length;
  if (count) count.textContent = `(${enabled}/${state.config.sources.length} enabled)`;

  const groups = new Map();
  for (const source of state.config.sources) {
    if (!groups.has(source.category)) groups.set(source.category, []);
    groups.get(source.category).push(source);
  }

  host.innerHTML = [...groups.entries()]
    .map(([category, sources]) => {
      const label = sources[0]?.categoryLabel || category;
      const rows = sources
        .map(
          (source) => `<label class="source-row" title="${esc(source.tos || '')}">
            <input type="checkbox" data-source="${esc(source.id)}" ${source.enabled ? 'checked' : ''}>
            <span>${esc(source.name)}${source.respectRobots ? '' : ' <span class="muted">· no robots</span>'}</span>
            <span class="source-meta"><span class="access">${esc(sourceMeta(source))}</span></span>
          </label>`,
        )
        .join('');
      return `<div class="source-group"><h4>${esc(label)}</h4>${rows}</div>`;
    })
    .join('');

  $$('input[data-source]', host).forEach((input) => {
    input.addEventListener('change', async () => {
      const id = input.dataset.source;
      input.disabled = true;
      try {
        const data = await api(`/api/sources/${encodeURIComponent(id)}`, {
          method: 'PATCH',
          json: { enabled: input.checked },
        });
        const source = state.config.sources.find((item) => item.id === id);
        if (source) source.enabled = data.source.enabled;
        renderSources();
        toast(`${source?.name || id} ${data.source.enabled ? 'enabled' : 'disabled'}.`, 'success');
      } catch (err) {
        input.checked = !input.checked;
        toast(err.message, 'error');
      } finally {
        input.disabled = false;
      }
    });
  });
}

/* ------------------------------------------------------------------ */
/* Username scan                                                       */
/* ------------------------------------------------------------------ */

function initUsername() {
  const form = $('#username-form');
  const clear = $('#clear-categories');
  if (clear) {
    clear.addEventListener('click', () => {
      state.categories.clear();
      renderCategories();
    });
  }
  if (!form) return;

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = $('#username-input');
    const submit = $('#username-submit');
    const username = input.value.trim();
    if (!username) {
      toast('Enter a username or profile URL.', 'error');
      input.focus();
      return;
    }
    if (submit.disabled) return;

    submit.disabled = true;
    submit.textContent = 'Starting…';
    $('#username-result').classList.add('hidden');
    const progress = $('#username-progress');
    progress.classList.remove('hidden');
    $('#username-progress-count').textContent = '0 / 0';
    $('#username-progress-fill').style.width = '0%';
    $('#username-progress-current').textContent = 'Starting…';
    $('#username-progress-log').textContent = '';

    const log = [];
    try {
      const { jobId } = await api('/api/username', {
        method: 'POST',
        json: { username, categories: [...state.categories] },
      });
      state.usernameJob = jobId;
      submit.textContent = 'Scanning…';

      const job = await pollJob(jobId, (update) => {
        const total = update.progress?.total || 0;
        const completed = update.progress?.completed || 0;
        const percent = total ? Math.min(100, Math.round((completed / total) * 100)) : 0;
        $('#username-progress-count').textContent = `${completed} / ${total}`;
        $('#username-progress-fill').style.width = `${percent}%`;
        if (update.progress?.source) {
          $('#username-progress-current').textContent =
            update.progress.phase === 'checking'
              ? `Checking ${update.progress.source}…`
              : `${update.progress.source}: ${STATUS_LABELS[update.progress.status] || update.progress.status || 'done'}`;
        }
        if (update.progress?.phase === 'result') {
          log.unshift(
            `${update.progress.source || 'source'} — ${
              STATUS_LABELS[update.progress.status] || update.progress.status || 'done'
            }`,
          );
          $('#username-progress-log').textContent = log.slice(0, 6).join('\n');
        }
      });

      if (!job.result) throw new Error(job.error || 'No result was returned.');
      renderUsernameResult(job.result, job.report);
      if (job.reportError) toast(job.reportError, 'error');
    } catch (err) {
      toast(err.message, 'error');
      $('#username-progress').classList.add('hidden');
    } finally {
      submit.disabled = false;
      submit.textContent = 'Search sources';
    }
  });
}

function summaryChips(summary) {
  const order = ['confirmed', 'possible', 'unverified', 'absent', 'blocked', 'skipped', 'error'];
  const chips = order
    .filter((key) => summary?.[key])
    .map(
      (key) =>
        `<span class="stat ${esc(key)}"><b>${summary[key]}</b> ${esc(STATUS_LABELS[key])}</span>`,
    )
    .join('');
  return `<div class="summary">${chips}</div>`;
}

function notesBlock(notes) {
  if (!notes?.length) return '';
  return `<div class="panel"><h2>Limitations &amp; notes</h2><ul class="muted small">${notes
    .map((note) => `<li>${esc(note)}</li>`)
    .join('')}</ul></div>`;
}

function riskBlock(risk) {
  if (!risk) return '';
  const score = Math.max(0, Math.min(100, Number(risk.score) || 0));
  return `<div class="panel risk ${esc(risk.level || 'none')}">
    <div class="risk-head"><h2>Exposure indicators</h2><strong class="risk-score">${score}/100 · ${esc(
      risk.level || 'none',
    )}</strong></div>
    <div class="meter"><span style="width:${score}%"></span></div>
    ${risk.findings?.length ? `<ul class="muted small">${risk.findings
      .map((finding) => `<li>${esc(finding.text || finding)}</li>`)
      .join('')}</ul>` : ''}
    ${
      risk.recommendations?.length
        ? `<p class="muted small">${esc(risk.recommendations.join(' '))}</p>`
        : ''
    }
  </div>`;
}

function kvRows(rows) {
  return rows
    .filter(([, value]) => value != null && String(value).trim() !== '')
    .map(([label, value, url]) => `<tr><th>${esc(label)}</th><td>${url ? link(url, value) : esc(value)}</td></tr>`)
    .join('');
}

function renderFinding(finding) {
  const fields = (finding.profile?.fields || []).filter((field) => field?.value != null);
  const links = (finding.profile?.links || []).filter((item) => item?.url);
  const search = [
    finding.name,
    finding.category,
    finding.status,
    finding.detail,
    finding.url,
    ...fields.map((field) => `${field.label} ${field.value}`),
  ]
    .join(' ')
    .toLowerCase();

  return `<article class="card" data-finding data-status="${esc(finding.status)}" data-search="${esc(search)}">
    <div class="card-head">
      <span class="dot ${esc(finding.status)}"></span>
      <h3>${esc(finding.name)}</h3>
      <span class="badge ${esc(finding.status)}">${esc(STATUS_LABELS[finding.status] || finding.status)}</span>
      <span class="cat">${esc(finding.category)}</span>
    </div>
    <p class="detail">${esc(finding.detail || '')}</p>
    ${fields.length ? `<table class="kv"><tbody>${kvRows(fields.map((field) => [field.label, field.value, field.url]))}</tbody></table>` : ''}
    <div class="chips">${link(finding.url, 'Open profile', 'class="chip link"')}${links
      .map((item) => link(item.url, item.label, 'class="chip link"'))
      .join('')}</div>
    ${finding.profile?.note ? `<p class="muted small">${esc(finding.profile.note)}</p>` : ''}
    ${finding.enrichError ? `<p class="muted small">Enrichment: ${esc(finding.enrichError)}</p>` : ''}
    <div class="card-foot">Retrieved ${esc(fmtDate(finding.retrievedAt))}${
      finding.elapsedMs != null ? ` · ${fmtDuration(finding.elapsedMs)}` : ''
    }${finding.confidence ? ` · ${esc(finding.confidence)} confidence` : ''}</div>
  </article>`;
}

function renderUsernameResult(result, report) {
  const host = $('#username-result');
  const present = result.findings.filter((finding) => finding.status !== 'absent');
  const counts = result.summary || {};
  const filters = [
    `<button type="button" class="filter active" data-filter="all">All (${result.findings.length})</button>`,
    ...['confirmed', 'possible', 'unverified', 'blocked', 'error', 'skipped']
      .filter((status) => counts[status])
      .map(
        (status) =>
          `<button type="button" class="filter" data-filter="${status}">${esc(
            STATUS_LABELS[status],
          )} (${counts[status]})</button>`,
      ),
  ].join('');

  host.innerHTML = `
    <div class="panel">
      <div class="result-toolbar">
        <div>
          <h2 style="margin:0 0 4px">Results for ${esc(result.target)}</h2>
          <span class="muted small">${esc(fmtDate(result.createdAt))} · ${fmtDuration(result.durationMs)} · ${
            result.settings?.selectedSources ?? result.findings.length
          } sources</span>
        </div>
        <div class="result-actions">
          ${report ? link(report.htmlUrl, 'Open HTML report', 'class="chip link"') : ''}
          ${report ? link(report.jsonUrl, 'Download JSON', 'class="chip link" download') : ''}
        </div>
      </div>
      ${summaryChips(counts)}
      <div class="filters">${filters}</div>
      <input class="filter-input" id="username-filter-text" type="search" placeholder="Filter by site, field, or URL…" aria-label="Filter results">
      <p class="callout">A shared username does <strong>not</strong> prove that two accounts belong to the same person. Confirm identity with independent, lawful evidence.</p>
      <div class="grid" id="username-cards">${
        present.length ? present.map(renderFinding).join('') : '<p class="muted">No accounts were detected.</p>'
      }</div>
      ${
        counts.absent
          ? `<details class="absent-list"><summary>${counts.absent} source(s) returned no account</summary><ul class="muted small">${result.findings
              .filter((finding) => finding.status === 'absent')
              .map((finding) => `<li>${esc(finding.name)} — ${esc(finding.detail || '')}</li>`)
              .join('')}</ul></details>`
          : ''
      }
    </div>
    ${notesBlock(result.notes)}`;

  host.classList.remove('hidden');

  let active = 'all';
  const cards = $$('[data-finding]', host);
  const search = $('#username-filter-text', host);
  const apply = () => {
    const query = (search?.value || '').toLowerCase().trim();
    for (const card of cards) {
      const matchesStatus = active === 'all' || card.dataset.status === active;
      const matchesQuery = !query || (card.dataset.search || '').includes(query);
      card.style.display = matchesStatus && matchesQuery ? '' : 'none';
    }
  };
  $$('.filter', host).forEach((button) => {
    button.addEventListener('click', () => {
      active = button.dataset.filter;
      $$('.filter', host).forEach((item) => item.classList.toggle('active', item === button));
      apply();
    });
  });
  search?.addEventListener('input', apply);

  if (report) toast('Report saved locally.', 'success');
}

/* ------------------------------------------------------------------ */
/* Email checks                                                        */
/* ------------------------------------------------------------------ */

function initEmail() {
  const form = $('#email-form');
  if (!form) return;

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = $('#email-input');
    const submit = $('#email-submit');
    const email = input.value.trim();
    if (!email) {
      toast('Enter an email address.', 'error');
      input.focus();
      return;
    }
    if (submit.disabled) return;

    submit.disabled = true;
    submit.textContent = 'Running…';
    $('#email-result').classList.add('hidden');
    const progress = $('#email-progress');
    progress.classList.remove('hidden');
    const timer = $('#email-timer');
    const started = Date.now();
    timer.textContent = '0s';
    state.emailTimer = setInterval(() => {
      timer.textContent = `${Math.round((Date.now() - started) / 1000)}s`;
    }, 1000);

    try {
      const { jobId } = await api('/api/email', {
        method: 'POST',
        json: { email, linked: $('#email-linked')?.checked || false },
      });
      state.emailJob = jobId;
      const job = await pollJob(jobId);
      if (!job.result) throw new Error(job.error || 'No result was returned.');
      renderEmailResult(job.result, job.report);
      if (job.reportError) toast(job.reportError, 'error');
    } catch (err) {
      toast(err.message, 'error');
      progress.classList.add('hidden');
    } finally {
      clearInterval(state.emailTimer);
      state.emailTimer = null;
      submit.disabled = false;
      submit.textContent = 'Run checks';
    }
  });
}

function renderEmailResult(result, report) {
  const host = $('#email-result');
  const dns = result.dns || {};
  const breaches = result.breaches || {};
  const gravatar = result.gravatar || {};
  const github = result.publicMentions?.github;

  const dnsRows = [
    [
      'MX',
      (dns.mx || []).map((record) => `${record.exchange} (priority ${record.priority})`).join(', ') ||
        (dns.nullMx ? 'Null MX — the domain does not accept email' : '—'),
    ],
    ['A', (dns.a || []).join(', ') || '—'],
    ['AAAA', (dns.aaaa || []).join(', ') || '—'],
    ['NS', (dns.ns || []).join(', ') || '—'],
    ['SPF', dns.spf?.present ? dns.spf.record : 'Not published'],
    ['DMARC', dns.dmarc?.present ? dns.dmarc.record : 'Not published'],
    [
      'DKIM',
      dns.dkim?.found?.length
        ? dns.dkim.found.map((item) => item.selector).join(', ')
        : 'No common selector found',
    ],
  ];

  host.innerHTML = `
    <div class="panel">
      <div class="result-toolbar">
        <div>
          <h2 style="margin:0 0 4px">Email results for ${esc(result.target)}</h2>
          <span class="muted small">${esc(fmtDate(result.createdAt))} · ${fmtDuration(result.durationMs)}</span>
        </div>
        <div class="result-actions">
          ${report ? link(report.htmlUrl, 'Open HTML report', 'class="chip link"') : ''}
          ${report ? link(report.jsonUrl, 'Download JSON', 'class="chip link" download') : ''}
        </div>
      </div>
      <table class="kv"><tbody>${kvRows([
        ['Address', result.target],
        ['Syntax', result.syntax?.valid ? 'Valid' : `Invalid — ${result.syntax?.reason || ''}`],
        ['Domain', result.syntax?.domain || '—'],
        [
          'Receives mail (MX)',
          dns.hasMx
            ? 'Yes'
            : dns.nullMx
              ? 'No — null MX record'
              : dns.implicitMx
                ? 'No MX; implicit A-record fallback'
                : 'No',
        ],
      ])}</tbody></table>
    </div>

    ${riskBlock(result.risk)}

    <div class="panel">
      <h2>Public breach records</h2>
      ${
        !breaches.available
          ? `<p class="muted">${esc(breaches.reason || 'Breach lookup is not configured.')}</p>`
          : breaches.error
            ? `<p class="muted">${esc(breaches.error)}</p>`
            : breaches.breaches?.length
              ? `<table class="data-table"><thead><tr><th>Breach</th><th>Domain</th><th>Date</th><th>Accounts</th><th>Data classes</th></tr></thead><tbody>${breaches.breaches
                  .map(
                    (breach) =>
                      `<tr><td>${esc(breach.title || breach.name)}</td><td>${esc(
                        breach.domain || '',
                      )}</td><td>${esc(breach.breachDate || '')}</td><td>${esc(
                        String(breach.pwnCount ?? ''),
                      )}</td><td>${esc((breach.dataClasses || []).join(', '))}</td></tr>`,
                  )
                  .join('')}</tbody></table>
                <p class="muted small">Breach metadata only. No passwords, hashes, or credentials are retrieved or displayed.</p>`
              : '<p class="muted">No public breach records were returned for this address.</p>'
      }
    </div>

    <div class="panel">
      <h2>Gravatar (public profile)</h2>
      ${
        gravatar.found
          ? `<table class="kv"><tbody>${kvRows([
              ['Display name', gravatar.profile?.displayName],
              ['Username', gravatar.profile?.preferredUsername],
              ['About', gravatar.profile?.aboutMe],
              ['Location', gravatar.profile?.currentLocation],
              ['Profile', gravatar.profileUrl, gravatar.profileUrl],
            ])}</tbody></table>
            ${
              gravatar.profile?.accounts?.length
                ? `<table class="data-table"><thead><tr><th>Domain</th><th>Username</th><th>Verified</th></tr></thead><tbody>${gravatar.profile.accounts
                    .map(
                      (account) =>
                        `<tr><td>${esc(account.domain || '')}</td><td>${
                          account.url
                            ? link(account.url, account.username || account.display || '')
                            : esc(account.username || '')
                        }</td><td>${account.verified ? 'Yes' : 'No'}</td></tr>`,
                    )
                    .join('')}</tbody></table>`
                : ''
            }`
          : `<p class="muted">${esc(gravatar.error || 'No public Gravatar profile found.')}</p>`
      }
    </div>

    <div class="panel">
      <h2>Domain &amp; email authentication</h2>
      <table class="kv"><tbody>${kvRows(dnsRows)}</tbody></table>
      ${dns.errors?.length ? `<p class="muted small">DNS notes: ${esc(dns.errors.join(' · '))}</p>` : ''}
    </div>

    <div class="panel">
      <h2>Public mentions</h2>
      ${
        github?.users?.length
          ? `<p class="muted small">GitHub accounts with this address in their public profile:</p><ul class="muted small">${github.users
              .map((user) => `<li>${link(user.url, user.login)}</li>`)
              .join('')}</ul>`
          : `<p class="muted">${esc(
              github?.error || 'No GitHub profile lists this address publicly.',
            )}</p>`
      }
    </div>

    ${
      result.linked?.requested
        ? `<div class="panel">
            <h2>Linked username scan (opt-in)</h2>
            <p class="muted small">Derived from the email local part. A username match is not proof of ownership.</p>
            ${
              result.linked.scans?.length
                ? result.linked.scans
                    .map(
                      (scan) => `<div class="card" style="margin-bottom:10px">
                        <div class="card-head"><h3>@${esc(scan.username)}</h3><span class="muted small">${
                          scan.error
                            ? esc(scan.error)
                            : `${scan.summary?.confirmed || 0} confirmed · ${scan.summary?.possible || 0} possible`
                        }</span></div>
                        ${
                          scan.findings?.length
                            ? `<ul class="muted small">${scan.findings
                                .map(
                                  (finding) =>
                                    `<li>${esc(finding.name)} — ${link(finding.url, 'profile')} <span class="badge ${esc(
                                      finding.status,
                                    )}">${esc(STATUS_LABELS[finding.status] || finding.status)}</span></li>`,
                                )
                                .join('')}</ul>`
                            : '<p class="muted small">No matches.</p>'
                        }
                      </div>`,
                    )
                    .join('')
                : '<p class="muted">No username candidates could be derived.</p>'
            }
          </div>`
        : ''
    }

    ${notesBlock(result.notes)}`;

  host.classList.remove('hidden');
  $('#email-progress').classList.add('hidden');
  if (report) toast('Report saved locally.', 'success');
}

/* ------------------------------------------------------------------ */
/* File metadata                                                       */
/* ------------------------------------------------------------------ */

function initFile() {
  const dropzone = $('#dropzone');
  const input = $('#file-input');
  const analyze = $('#file-analyze');
  const save = $('#file-save');
  if (!dropzone || !input || !analyze) return;

  const choose = () => input.click();
  dropzone.addEventListener('click', choose);
  dropzone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      choose();
    }
  });

  for (const type of ['dragenter', 'dragover']) {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.add('dragover');
    });
  }
  for (const type of ['dragleave', 'drop']) {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.remove('dragover');
    });
  }
  dropzone.addEventListener('drop', (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) selectFile(file);
  });

  input.addEventListener('change', () => {
    const file = input.files?.[0];
    if (file) selectFile(file);
  });

  analyze.addEventListener('click', runFileAnalysis);
  save?.addEventListener('change', () => {});

  function selectFile(file) {
    const maxMb = state.config?.settings?.maxUploadMb || 30;
    if (file.size > maxMb * 1024 * 1024) {
      toast(`File is larger than the ${maxMb} MB limit.`, 'error');
      return;
    }
    state.file = file;
    $('#file-name').textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
    analyze.disabled = false;
    $('#file-result').classList.add('hidden');
    $('#file-progress').classList.add('hidden');
  }
}

async function runFileAnalysis() {
  if (!state.file) {
    toast('Choose a file first.', 'error');
    return;
  }
  const button = $('#file-analyze');
  button.disabled = true;
  button.textContent = 'Analysing…';
  $('#file-result').classList.add('hidden');
  $('#file-progress').classList.remove('hidden');

  try {
    const saveReport = Boolean($('#file-save')?.checked);
    const buffer = await state.file.arrayBuffer();
    const res = await fetch('/api/file', {
      method: 'POST',
      headers: {
        'x-argus': '1',
        'content-type': 'application/octet-stream',
        'x-filename': encodeURIComponent(state.file.name),
        ...(saveReport ? { 'x-save-report': '1' } : {}),
      },
      body: buffer,
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new Error(data?.error || `Analysis failed (HTTP ${res.status}).`);
    state.fileResult = data.result;
    renderFileResult(data.result, data.report);
    if (data.report) toast('File report saved locally.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    $('#file-progress').classList.add('hidden');
    button.disabled = false;
    button.textContent = 'Analyse file';
  }
}

function renderFileResult(result, report) {
  const host = $('#file-result');
  const exif = result.exif || {};
  const file = result.file || {};
  const gps = exif.gps;
  const camera = exif.camera || {};

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
  ];

  const groups = ['IFD0', 'Exif', 'GPS', 'Interop', 'IFD1'].filter(
    (group) => exif.groups?.[group]?.length,
  );

  host.innerHTML = `
    <div class="panel">
      <div class="result-toolbar">
        <div>
          <h2 style="margin:0 0 4px">${esc(result.target)}</h2>
          <span class="muted small">${esc(fmtDate(result.createdAt))} · ${fmtDuration(result.durationMs)}</span>
        </div>
        <div class="result-actions">
          ${
            result.stripSupported
              ? '<button type="button" class="secondary" id="file-strip">Download metadata-stripped copy</button>'
              : ''
          }
          ${report ? link(report.htmlUrl, 'Open HTML report', 'class="chip link"') : ''}
          ${report ? link(report.jsonUrl, 'Download JSON', 'class="chip link" download') : ''}
        </div>
      </div>
      <table class="kv"><tbody>${kvRows([
        ['Name', file.name],
        ['Size', file.sizeHuman],
        ['Format', `${file.format || ''} (${file.mime || ''})`],
        ['Dimensions', result.image?.width ? `${result.image.width} × ${result.image.height}` : '—'],
        ['SHA-256', file.sha256],
        ['SHA-1', file.sha1],
        ['MD5', file.md5],
        ['ICC profile', result.image?.hasIccProfile ? 'Present' : 'Not detected'],
        ['IPTC / Photoshop', result.image?.hasIptc ? 'Present' : 'Not detected'],
        ['Embedded thumbnail', result.image?.hasThumbnail ? 'Present' : 'Not detected'],
      ])}</tbody></table>
    </div>

    ${riskBlock(result.risk)}

    <div class="panel">
      <h2>GPS location</h2>
      ${
        gps
          ? `<p class="mono" style="font-size:18px;color:var(--green);margin:0 0 4px">${gps.latitude.toFixed(
              6,
            )}, ${gps.longitude.toFixed(6)}${
              gps.altitude != null ? ` · ${esc(String(gps.altitude))} m` : ''
            }</p>
            <p class="muted small">${esc(gps.latitudeRef || '')} ${esc(gps.longitudeRef || '')}${
              gps.dateStamp ? ` · ${esc(gps.dateStamp)}` : ''
            }${gps.mapDatum ? ` · ${esc(gps.mapDatum)}` : ''}</p>
            <div class="chips">${link(gps.maps?.openstreetmap, 'OpenStreetMap', 'class="chip link"')}${link(
              gps.maps?.google,
              'Google Maps',
              'class="chip link"',
            )}${link(gps.maps?.geohack, 'GeoHack', 'class="chip link"')}</div>`
          : '<p class="muted">No GPS coordinates found.</p>'
      }
    </div>

    ${
      cameraRows.some(([, value]) => value)
        ? `<div class="panel"><h2>EXIF highlights</h2><table class="kv"><tbody>${kvRows(
            cameraRows,
          )}</tbody></table></div>`
        : ''
    }

    ${
      exif.present
        ? groups
            .map(
              (group) => `<details class="panel" ${group === 'IFD0' ? 'open' : ''}>
                <summary><strong>${esc(group)}</strong> <span class="muted small">${
                  exif.groups[group].length
                } tags</span></summary>
                <table class="data-table"><thead><tr><th>Tag</th><th>Name</th><th>Value</th></tr></thead><tbody>${exif.groups[
                  group
                ]
                  .map(
                    (entry) =>
                      `<tr><td class="mono">${esc(entry.tag)}</td><td>${esc(entry.name)}</td><td>${esc(
                        String(entry.value),
                      )}</td></tr>`,
                  )
                  .join('')}</tbody></table>
              </details>`,
            )
            .join('')
        : '<div class="panel"><h2>EXIF</h2><p class="muted">No EXIF block was found.</p></div>'
    }

    ${
      result.metadataText?.length
        ? `<div class="panel"><h2>Other embedded text</h2><table class="data-table"><thead><tr><th>Source</th><th>Key</th><th>Value</th></tr></thead><tbody>${result.metadataText
            .map(
              (entry) =>
                `<tr><td>${esc(entry.source || '')}</td><td>${esc(entry.key || '')}</td><td>${esc(
                  String(entry.value),
                )}</td></tr>`,
            )
            .join('')}</tbody></table></div>`
        : ''
    }

    ${
      result.strings
        ? `<div class="panel"><h2>Strings found in file bytes</h2>${
            Object.entries(result.strings)
              .filter(([, values]) => values?.length)
              .map(
                ([key, values]) =>
                  `<h3 style="margin-top:10px">${esc(key)}</h3><div class="chips">${values
                    .map((value) => `<span class="chip mono">${esc(value)}</span>`)
                    .join('')}</div>`,
              )
              .join('') || '<p class="muted">No emails, URLs, handles, paths, or IP addresses detected.</p>'
          }</div>`
        : ''
    }

    ${
      result.warnings?.length
        ? `<div class="panel"><h2>Parser warnings</h2><ul class="muted small">${result.warnings
            .map((warning) => `<li>${esc(warning)}</li>`)
            .join('')}</ul></div>`
        : ''
    }

    ${notesBlock(result.notes)}`;

  host.classList.remove('hidden');

  $('#file-strip')?.addEventListener('click', stripSelectedFile);
}

async function stripSelectedFile() {
  if (!state.file) return;
  const button = $('#file-strip');
  if (button) {
    button.disabled = true;
    button.textContent = 'Stripping…';
  }
  try {
    const buffer = await state.file.arrayBuffer();
    const res = await fetch('/api/file/strip', {
      method: 'POST',
      headers: {
        'x-argus': '1',
        'content-type': 'application/octet-stream',
        'x-filename': encodeURIComponent(state.file.name),
      },
      body: buffer,
    });
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      throw new Error(data?.error || `Strip failed (HTTP ${res.status}).`);
    }
    const blob = await res.blob();
    const removed = decodeURIComponent(res.headers.get('x-removed') || '');
    const extension = (res.headers.get('content-type') || '').includes('png') ? 'png' : 'jpg';
    const base = state.file.name.replace(/\.[^.]+$/, '');
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `stripped-${base}.${extension}`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
    toast(
      removed ? `Stripped copy downloaded. Removed: ${removed}.` : 'Stripped copy downloaded.',
      'success',
    );
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Download metadata-stripped copy';
    }
  }
}

/* ------------------------------------------------------------------ */
/* Reports & audit                                                     */
/* ------------------------------------------------------------------ */

function renderReportStats(stats) {
  const host = $('#report-stats');
  if (!host) return;
  if (!stats) {
    host.innerHTML = '';
    return;
  }
  host.innerHTML = `
    <span class="stat"><b>${stats.count ?? 0}</b> saved reports</span>
    <span class="stat">Retention <b>${stats.retentionDays ?? '—'}</b> days</span>
    <span class="stat">Max <b>${stats.maxReports ?? '—'}</b> reports</span>`;
}

async function refreshReports() {
  const host = $('#reports-table');
  if (!host) return;
  host.innerHTML = '<p class="muted">Loading…</p>';
  try {
    const data = await api('/api/reports');
    state.reports = data.reports || [];
    renderReportStats(data.stats);
    if (!state.reports.length) {
      host.innerHTML = '<p class="muted">No saved reports yet. Username and email scans are saved automatically; file reports are opt-in.</p>';
      return;
    }
    host.innerHTML = `<table class="data-table">
      <thead><tr><th>Created</th><th>Tool</th><th>Target</th><th>Risk</th><th>Findings</th><th>Actions</th></tr></thead>
      <tbody>${state.reports
        .map(
          (report) => `<tr data-report="${esc(report.id)}">
            <td>${esc(fmtDate(report.createdAt))}</td>
            <td>${esc(COMMAND_LABELS[report.command] || report.command || '')}</td>
            <td>${esc(report.target || '')}</td>
            <td>${report.riskScore != null ? `${report.riskScore}/100 · ${esc(report.riskLevel || '')}` : '—'}</td>
            <td>${report.findingCount ?? '—'}</td>
            <td><div class="report-row-actions">
              <button type="button" data-action="open" data-id="${esc(report.id)}">Open</button>
              <button type="button" data-action="json" data-id="${esc(report.id)}">JSON</button>
              <button type="button" class="danger" data-action="delete" data-id="${esc(report.id)}">Delete</button>
            </div></td>
          </tr>`,
        )
        .join('')}</tbody></table>`;

    $$('button[data-action]', host).forEach((button) => {
      button.addEventListener('click', () => {
        const id = button.dataset.id;
        const action = button.dataset.action;
        if (action === 'open') window.open(`/api/reports/${encodeURIComponent(id)}/html`, '_blank', 'noopener');
        else if (action === 'json') {
          const anchor = document.createElement('a');
          anchor.href = `/api/reports/${encodeURIComponent(id)}/json`;
          anchor.download = `${id}.json`;
          document.body.append(anchor);
          anchor.click();
          anchor.remove();
        } else if (action === 'delete') deleteReport(id);
      });
    });
  } catch (err) {
    host.innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  }
}

async function deleteReport(id) {
  if (!window.confirm('Delete this report and its HTML copy? This cannot be undone.')) return;
  try {
    await api(`/api/reports/${encodeURIComponent(id)}`, { method: 'DELETE' });
    toast('Report deleted.', 'success');
    refreshReports();
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function loadAudit() {
  const host = $('#audit-table');
  if (!host) return;
  host.innerHTML = '<p class="muted">Loading…</p>';
  try {
    const data = await api('/api/audit?limit=200');
    if (!data.entries?.length) {
      host.innerHTML = '<p class="muted">The audit log is empty.</p>';
      return;
    }
    host.innerHTML = `<table class="data-table">
      <thead><tr><th>Time</th><th>Action</th><th>Tool</th><th>Target</th><th>Report</th></tr></thead>
      <tbody>${data.entries
        .map(
          (entry) => `<tr>
            <td>${esc(fmtDate(entry.timestamp))}</td>
            <td>${esc(entry.action || '')}</td>
            <td>${esc(COMMAND_LABELS[entry.command] || entry.command || '')}</td>
            <td>${esc(entry.target || '—')}</td>
            <td class="mono">${esc(entry.reportId || '—')}</td>
          </tr>`,
        )
        .join('')}</tbody></table>
        <p class="muted small">The audit log records actions and timestamps, not the findings themselves. Targets are redacted when logTargetsInAudit is false.</p>`;
  } catch (err) {
    host.innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  }
}

function initReports() {
  $('#reports-refresh')?.addEventListener('click', refreshReports);

  $('#reports-delete-all')?.addEventListener('click', async () => {
    if (
      !window.confirm(
        'Delete all saved reports, their HTML copies, and clear the audit log? This cannot be undone.',
      )
    ) {
      return;
    }
    try {
      const result = await api('/api/reports', { method: 'DELETE' });
      toast(`Deleted ${result.removed ?? 0} file(s) and cleared the audit log.`, 'success');
      refreshReports();
      $('#audit-table').innerHTML = '';
    } catch (err) {
      toast(err.message, 'error');
    }
  });

  $('#audit-load')?.addEventListener('click', loadAudit);

  $('#audit-clear')?.addEventListener('click', async () => {
    if (!window.confirm('Clear the audit log? This cannot be undone.')) return;
    try {
      await api('/api/audit', { method: 'DELETE' });
      $('#audit-table').innerHTML = '<p class="muted">Audit log cleared.</p>';
      toast('Audit log cleared.', 'success');
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

/* ------------------------------------------------------------------ */
/* AI settings                                                         */
/* ------------------------------------------------------------------ */

function aiSourceLabel(settings) {
  if (!settings?.keyConfigured) return 'No key configured';
  if (settings.envOverride) return `Environment variable (${settings.keySource})`;
  return 'Local secrets file (data/ai-secrets.json)';
}

function applyAiSettings(settings) {
  state.aiSettings = settings || null;
  if (!settings) return;

  $('#ai-base-url').value = settings.baseUrl || '';
  $('#ai-model').value = settings.model || '';
  $('#ai-timeout').value = settings.timeoutMs ?? '';
  $('#ai-max-tokens').value = settings.maxOutputTokens ?? '';
  $('#ai-max-input').value = settings.maxInputChars ?? '';
  $('#ai-api-key').value = '';

  const status = $('#ai-key-status');
  if (status) {
    status.textContent = settings.keyConfigured ? `Key saved ${settings.keyMasked || ''}`.trim() : 'No API key saved';
    status.classList.toggle('ok', Boolean(settings.keyConfigured));
  }
  const source = $('#ai-key-source');
  if (source) source.textContent = `Source: ${aiSourceLabel(settings)}`;
}

async function loadAiSettings() {
  try {
    const data = await api('/api/ai/settings');
    applyAiSettings(data.settings);
    return data.settings;
  } catch (err) {
    toast(`Could not load AI settings: ${err.message}`, 'error');
    return null;
  }
}

async function saveAiSettings(event) {
  event?.preventDefault();
  const button = $('#ai-save');
  const apiKey = $('#ai-api-key').value;
  const payload = {
    baseUrl: $('#ai-base-url').value.trim(),
    model: $('#ai-model').value.trim(),
    timeoutMs: Number($('#ai-timeout').value),
    maxOutputTokens: Number($('#ai-max-tokens').value),
    maxInputChars: Number($('#ai-max-input').value),
  };
  if (apiKey.trim()) payload.apiKey = apiKey.trim();

  if (button) {
    button.disabled = true;
    button.textContent = 'Saving…';
  }
  try {
    const data = await api('/api/ai/settings', { method: 'PUT', json: payload });
    applyAiSettings(data.settings);
    toast(data.keyUpdated ? 'AI settings and key saved on the server.' : 'AI settings saved.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Save settings';
    }
  }
}

async function clearAiKey() {
  const settings = state.aiSettings;
  const extra = settings?.envOverride
    ? `\n\nNote: ${settings.keySource} is currently set and takes precedence. Clearing the local file will not remove the environment variable.`
    : '';
  if (!window.confirm(`Clear the locally saved AI API key?${extra}`)) return;
  try {
    const data = await api('/api/ai/settings', { method: 'PUT', json: { clearKey: true } });
    applyAiSettings(data.settings);
    toast('Locally saved API key cleared.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  }
}

function initAiSettings() {
  $('#ai-form')?.addEventListener('submit', saveAiSettings);
  $('#ai-clear-key')?.addEventListener('click', clearAiKey);
  $('#ai-reload')?.addEventListener('click', loadAiSettings);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

async function loadCaseReportOptions() {
  const select = $('#case-report-select');
  if (!select) return;
  try {
    const data = await api('/api/reports');
    state.reports = data.reports || [];
  } catch (err) {
    console.warn('[argus] could not load report options', err.message);
  }

  const attached = new Set(state.activeCase?.reportIds || []);
  const previous = select.value;
  select.innerHTML = '<option value="">Choose a saved report…</option>';
  for (const report of state.reports) {
    if (attached.has(report.id)) continue;
    const option = document.createElement('option');
    option.value = report.id;
    option.textContent = `${COMMAND_LABELS[report.command] || report.command || 'Report'} · ${report.target || report.id} · ${fmtDate(report.createdAt)}`;
    select.append(option);
  }
  if ([...select.options].some((option) => option.value === previous)) select.value = previous;
}

function renderCaseList() {
  const host = $('#case-list');
  if (!host) return;
  if (!state.cases.length) {
    host.innerHTML = '<p class="muted">No cases yet. Create one, then attach saved reports.</p>';
    return;
  }
  host.innerHTML = `<table class="data-table">
    <thead><tr><th>Updated</th><th>Title</th><th>Reports</th><th>Analyses</th><th>Actions</th></tr></thead>
    <tbody>${state.cases
      .map(
        (item) => `<tr>
          <td>${esc(fmtDate(item.updatedAt))}</td>
          <td>${esc(item.title)}</td>
          <td>${item.reportCount ?? 0}</td>
          <td>${item.analysisCount ?? 0}</td>
          <td><button type="button" class="secondary" data-open-case="${esc(item.id)}">Open</button></td>
        </tr>`,
      )
      .join('')}</tbody></table>`;

  $$('button[data-open-case]', host).forEach((button) => {
    button.addEventListener('click', () => openCase(button.dataset.openCase));
  });
}

async function refreshCases() {
  const host = $('#case-list');
  if (host && !state.cases.length) host.innerHTML = '<p class="muted">Loading…</p>';
  try {
    const data = await api('/api/cases');
    state.cases = data.cases || [];
    renderCaseList();
  } catch (err) {
    if (host) host.innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  }
}

function caseCitation(citation) {
  const reportId = String(citation?.reportId || 'unknown report');
  const known = citation?.reportKnown && citation?.valid !== false;
  const refs = [citation?.field, citation?.finding].filter(Boolean).map((value) => esc(value)).join(' · ');
  const label = `<span class="mono">${esc(reportId)}</span>${refs ? ` · ${refs}` : ''}`;
  if (citation?.reportKnown) {
    return `<a class="chip link citation${known ? '' : ' bad'}" href="/api/reports/${encodeURIComponent(reportId)}/html" target="_blank" rel="noopener noreferrer">${label}</a>`;
  }
  return `<span class="chip citation bad">${label} <span class="muted">(unknown report)</span></span>`;
}

function analysisSourceNote() {
  const settings = state.aiSettings;
  const host = settings?.baseUrl ? (() => {
    try {
      return new URL(settings.baseUrl).host;
    } catch {
      return 'the configured provider';
    }
  })() : 'the configured provider';
  return `Sends the attached report evidence and case notes to ${host}.`;
}

function renderAnalysisItems(items, emptyText) {
  if (!items?.length) return `<p class="muted small">${esc(emptyText)}</p>`;
  return `<ul class="analysis-list">${items
    .map(
      (item) => `<li class="${item.supported ? '' : 'unsupported'}">
        <div class="analysis-text">${esc(item.text)}</div>
        ${item.confidence ? `<span class="chip">confidence: ${esc(item.confidence)}</span>` : ''}
        ${item.priority ? `<span class="chip">priority: ${esc(item.priority)}</span>` : ''}
        ${item.requiresHumanReview ? '<span class="chip warn">human review required</span>' : ''}
        ${item.supported ? '' : '<span class="chip bad">unsupported claim</span>'}
        <div class="citations">${(item.citations || []).map((citation) => caseCitation(citation)).join('') || '<span class="muted small">No citation</span>'}</div>
      </li>`,
    )
    .join('')}</ul>`;
}

function renderAnalysis(analysis, { preview = false, evidenceIds: evidenceInput = [] } = {}) {
  if (!analysis) return '<p class="muted">No analysis.</p>';
  const evidenceIds = (evidenceInput || []).map((id) => esc(id));
  const citations = analysis.citations || {};
  const warnings = analysis.warnings || [];
  const unsupported = analysis.unsupportedClaims || [];

  return `<div class="analysis ${preview ? 'preview' : ''}">
    <div class="analysis-head">
      <span class="badge ${preview ? 'possible' : 'unverified'}">${preview ? 'AI analysis — review before saving' : 'Saved AI analysis'}</span>
      ${analysis.model ? `<span class="chip">${esc(analysis.model)}</span>` : ''}
      <span class="chip">citations ${Number(citations.valid || 0)}/${Number(citations.total || 0)} valid</span>
    </div>

    <p class="analysis-summary">${esc(analysis.summary || '')}</p>

    ${warnings.length ? `<div class="callout warn">${warnings.map((warning) => `<div>${esc(warning)}</div>`).join('')}</div>` : ''}

    <section class="analysis-section">
      <h4>Observed evidence</h4>
      <p class="muted small">Only facts directly present in a cited report. AI interpretation is kept separate.</p>
      ${renderAnalysisItems(analysis.observedEvidence, 'The provider reported no directly observed evidence.')}
    </section>

    <section class="analysis-section">
      <h4>Interpretations</h4>
      ${renderAnalysisItems(analysis.interpretations, 'No interpretations were provided.')}
    </section>

    <section class="analysis-section">
      <h4>Uncertainty</h4>
      ${analysis.uncertainty?.length
        ? `<ul class="analysis-list">${analysis.uncertainty.map((item) => `<li><div class="analysis-text">${esc(item)}</div></li>`).join('')}</ul>`
        : '<p class="muted small">No uncertainty was stated. Treat that as a warning sign, not confidence.</p>'}
    </section>

    <section class="analysis-section">
      <h4>Suggested next steps</h4>
      <p class="muted small">Suggestions only. ARGUS will not contact anyone, log in, or scan third-party systems.</p>
      ${renderAnalysisItems(analysis.suggestedNextSteps, 'No next steps were provided.')}
    </section>

    ${unsupported.length
      ? `<section class="analysis-section unsupported-block">
          <h4>Unsupported or dropped claims</h4>
          <p class="muted small">These claims were not backed by a supplied report and must not be treated as facts.</p>
          <ul class="analysis-list">${unsupported.map((item) => `<li class="unsupported"><div class="analysis-text">${esc(item)}</div></li>`).join('')}</ul>
        </section>`
      : ''}

    <p class="muted small">${esc(analysis.disclaimer || 'AI output is untrusted assistance, not evidence.')}</p>
    ${evidenceIds.length ? `<p class="muted small">Evidence sent: ${evidenceIds.map((id) => `<span class="mono">${id}</span>`).join(', ')}</p>` : ''}
  </div>`;
}

function renderCasePreview() {
  const host = $('#case-preview');
  if (!host) return;
  const preview = state.casePreview;
  if (!preview || preview.caseId !== state.activeCase?.id) {
    host.innerHTML = '';
    return;
  }
  host.innerHTML = `${renderAnalysis(preview.analysis, { preview: true, evidenceIds: preview.evidence?.reportIds })}
    <div class="actions-row analysis-actions">
      <button type="button" class="primary" id="analysis-save">Save analysis to case</button>
      <button type="button" class="secondary" id="analysis-discard">Discard preview</button>
      <button type="button" class="secondary" id="analysis-retry">Run again</button>
      <span class="muted small">Preview expires ${esc(fmtDate(preview.expiresAt))}. Nothing is saved until you choose Save.</span>
    </div>`;

  $('#analysis-save')?.addEventListener('click', saveCaseAnalysis);
  $('#analysis-discard')?.addEventListener('click', () => {
    state.casePreview = null;
    renderCasePreview();
  });
  $('#analysis-retry')?.addEventListener('click', analyzeCase);
}

function renderCaseAnalyses() {
  const host = $('#case-analyses');
  if (!host) return;
  const analyses = state.activeCase?.analyses || [];
  if (!analyses.length) {
    host.innerHTML = '<p class="muted small">No saved analyses yet.</p>';
    return;
  }
  host.innerHTML = `<h4 class="saved-analyses-head">Saved analyses</h4>${analyses
    .slice()
    .reverse()
    .map(
      (entry) => `<details class="saved-analysis" data-analysis="${esc(entry.id)}">
        <summary>
          <span>${esc(fmtDate(entry.createdAt))}</span>
          <span class="muted">${esc(entry.model || 'model unknown')}</span>
          <span class="muted">citations ${Number(entry.analysis?.citations?.valid || 0)}/${Number(entry.analysis?.citations?.total || 0)}</span>
        </summary>
        ${renderAnalysis(entry.analysis, { evidenceIds: entry.evidence?.reportIds })}
        <div class="actions-row">
          <button type="button" class="danger" data-delete-analysis="${esc(entry.id)}">Delete this analysis</button>
        </div>
      </details>`,
    )
    .join('')}`;

  $$('button[data-delete-analysis]', host).forEach((button) => {
    button.addEventListener('click', () => deleteCaseAnalysis(button.dataset.deleteAnalysis));
  });
}

function renderCase() {
  const record = state.activeCase;
  const editor = $('#case-editor');
  if (!editor) return;
  if (!record) {
    editor.classList.add('hidden');
    return;
  }
  editor.classList.remove('hidden');
  $('#case-editor-title').textContent = record.title || 'Case';
  $('#case-title').value = record.title || '';
  $('#case-notes').value = record.notes || '';
  $('#case-meta').textContent = `${record.reportIds?.length || 0} report(s) · ${record.analyses?.length || 0} saved analysis(es) · updated ${fmtDate(record.updatedAt)}`;
  $('#case-report-count').textContent = `(${record.reportIds?.length || 0})`;

  const byId = new Map((record.reports || []).map((report) => [report.id, report]));
  const reportsHost = $('#case-reports');
  if (!record.reportIds?.length) {
    reportsHost.innerHTML = '<p class="muted small">No reports attached. Attach at least one before analyzing.</p>';
  } else {
    reportsHost.innerHTML = `<table class="data-table compact">
      <thead><tr><th>Report</th><th>Tool</th><th>Target</th><th>Risk</th><th>Actions</th></tr></thead>
      <tbody>${record.reportIds
        .map((id) => {
          const report = byId.get(id);
          if (!report || report.missing) {
            return `<tr><td class="mono">${esc(id)}</td><td colspan="3"><span class="chip bad">missing report file</span></td>
              <td><div class="report-row-actions">
                <button type="button" class="danger" data-remove-report="${esc(id)}">Remove</button>
              </div></td></tr>`;
          }
          return `<tr>
            <td class="mono">${esc(id)}</td>
            <td>${esc(COMMAND_LABELS[report.command] || report.command || '')}</td>
            <td>${esc(report.target || '')}</td>
            <td>${report.riskScore != null ? `${report.riskScore}/100 · ${esc(report.riskLevel || '')}` : '—'}</td>
            <td><div class="report-row-actions">
              <button type="button" data-open-report="${esc(id)}">Open</button>
              <button type="button" class="danger" data-remove-report="${esc(id)}">Remove</button>
            </div></td>
          </tr>`;
        })
        .join('')}</tbody></table>`;
  }

  const correlations = record.correlations || {};
  const repeated = correlations.repeatedIndicators || [];
  const timeline = correlations.timeline || [];
  reportsHost.insertAdjacentHTML('beforeend', `<section class="case-correlations">
    <h3>Cross-report intelligence</h3>
    <p class="muted small">${repeated.length} exact repeated indicator(s). Matches are review leads, not proof of common ownership.</p>
    ${repeated.length ? `<div class="correlation-grid">${repeated.map((item) => `<article><strong>${esc(item.type)} · ${esc(item.value)}</strong><ul>${item.occurrences.map((entry) => `<li><span class="mono">${esc(entry.reportId)}</span> — ${esc(entry.evidence)}</li>`).join('')}</ul></article>`).join('')}</div>` : '<p class="muted small">No exact shared indicators found in readable attached reports.</p>'}
    <h4>Evidence timeline</h4><ol>${timeline.map((entry) => `<li>${esc(fmtDate(entry.createdAt))} · ${esc(COMMAND_LABELS[entry.command] || entry.command || 'Report')} · ${esc(entry.target || '')} <span class="mono">${esc(entry.reportId)}</span></li>`).join('') || '<li class="muted">No readable reports.</li>'}</ol>
  </section>`);

  $$('button[data-remove-report]', reportsHost).forEach((button) => {
    button.addEventListener('click', () => removeCaseReport(button.dataset.removeReport));
  });
  $$('button[data-open-report]', reportsHost).forEach((button) => {
    button.addEventListener('click', () => {
      window.open(`/api/reports/${encodeURIComponent(button.dataset.openReport)}/html`, '_blank', 'noopener');
    });
  });

  renderCasePreview();
  renderCaseAnalyses();
  loadCaseReportOptions();
}

async function openCase(id) {
  const host = $('#case-list');
  if (host) host.innerHTML = '<p class="muted">Loading case…</p>';
  try {
    const data = await api(`/api/cases/${encodeURIComponent(id)}`);
    state.activeCase = data.case;
    if (state.casePreview?.caseId !== id) state.casePreview = null;
    renderCase();
    if (host) renderCaseList();
    $('#case-editor')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    toast(err.message, 'error');
    refreshCases();
  }
}

async function createCase(event) {
  event?.preventDefault();
  const title = $('#case-create-title').value.trim();
  const notes = $('#case-create-notes').value;
  if (!title) {
    toast('Case title is required.', 'error');
    return;
  }
  const button = $('#case-create-submit');
  if (button) button.disabled = true;
  try {
    const data = await api('/api/cases', { method: 'POST', json: { title, notes } });
    state.activeCase = data.case;
    state.casePreview = null;
    $('#case-create-title').value = '';
    $('#case-create-notes').value = '';
    $('#case-create-panel').classList.add('hidden');
    renderCase();
    await refreshCases();
    toast('Case created.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

async function saveCaseDetails(event) {
  event?.preventDefault();
  if (!state.activeCase) return;
  const button = $('#case-save');
  if (button) button.disabled = true;
  try {
    const data = await api(`/api/cases/${encodeURIComponent(state.activeCase.id)}`, {
      method: 'PATCH',
      json: { title: $('#case-title').value.trim(), notes: $('#case-notes').value },
    });
    state.activeCase = data.case;
    renderCase();
    await refreshCases();
    toast('Case saved.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

async function deleteCase() {
  const record = state.activeCase;
  if (!record) return;
  if (!window.confirm('Delete this case, its notes, and its saved analyses? Saved reports are not deleted.')) return;
  try {
    await api(`/api/cases/${encodeURIComponent(record.id)}`, { method: 'DELETE' });
    state.activeCase = null;
    state.casePreview = null;
    renderCase();
    await refreshCases();
    toast('Case deleted.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function attachCaseReport() {
  const record = state.activeCase;
  const select = $('#case-report-select');
  if (!record || !select?.value) {
    toast('Choose a saved report to attach.', 'error');
    return;
  }
  const button = $('#case-attach');
  if (button) button.disabled = true;
  try {
    const data = await api(`/api/cases/${encodeURIComponent(record.id)}/reports`, {
      method: 'POST',
      json: { reportIds: [select.value] },
    });
    state.activeCase = data.case;
    renderCase();
    await refreshCases();
    toast('Report attached.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

async function removeCaseReport(reportId) {
  const record = state.activeCase;
  if (!record) return;
  if (!window.confirm('Remove this report from the case? The saved report itself is not deleted.')) return;
  try {
    const data = await api(
      `/api/cases/${encodeURIComponent(record.id)}/reports/${encodeURIComponent(reportId)}`,
      { method: 'DELETE' },
    );
    state.activeCase = data.case;
    renderCase();
    await refreshCases();
    toast('Report removed from case.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  }
}

function renderAnalysisError(err) {
  const host = $('#case-preview');
  if (host) {
    host.innerHTML = `<div class="callout error">
      <strong>Analysis failed.</strong>
      <p>${esc(err.message)}</p>
      <p class="muted small">Your case and attached reports are unchanged.${err.retryable ? ' This error may be temporary.' : ''}</p>
      <button type="button" class="secondary" id="analysis-error-retry">Retry analysis</button>
    </div>`;
    $('#analysis-error-retry')?.addEventListener('click', analyzeCase);
  }
  const status = $('#case-analyze-status');
  if (status) status.textContent = 'Analysis failed. Nothing was saved.';
}

async function analyzeCase() {
  const record = state.activeCase;
  if (!record) return;
  if (!record.reportIds?.length) {
    toast('Attach at least one saved report before analyzing.', 'error');
    return;
  }

  let settings = state.aiSettings;
  if (!settings) {
    try {
      settings = (await api('/api/ai/settings')).settings;
      state.aiSettings = settings;
    } catch (err) {
      toast(`Could not load AI settings: ${err.message}`, 'error');
      return;
    }
  }
  if (!settings?.keyConfigured) {
    toast('No AI API key is configured. Save one in AI settings first.', 'error');
    activateTab('ai-settings');
    return;
  }

  const confirmed = window.confirm(
    `Analyze this case with ${settings.model}?\n\n${analysisSourceNote().replace(/<[^>]+>/g, '')}\nOnly the attached reports and case notes are sent. This contact is made only because you pressed Analyze. No people or third-party services are contacted from the result.`,
  );
  if (!confirmed) return;

  const button = $('#case-analyze');
  const status = $('#case-analyze-status');
  if (button) {
    button.disabled = true;
    button.textContent = 'Analyzing…';
  }
  if (status) status.textContent = `Waiting for ${settings.model || 'the provider'}…`;
  const previousPreview = state.casePreview;
  if (previousPreview) state.casePreview = null;
  renderCasePreview();

  try {
    const data = await api(`/api/cases/${encodeURIComponent(record.id)}/analyze`, { method: 'POST' });
    state.casePreview = { ...data, caseId: record.id };
    renderCasePreview();
    if (status) {
      status.textContent = `Received ${data.analysis?.observedEvidence?.length ?? 0} observed item(s) from ${data.model || 'the provider'}. Review before saving.`;
    }
    toast('Analysis ready for review. Nothing has been saved yet.', 'success');
  } catch (err) {
    if (previousPreview) state.casePreview = previousPreview;
    renderAnalysisError(err);
    toast(err.message, 'error');
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Analyze case';
    }
  }
}

async function saveCaseAnalysis() {
  const record = state.activeCase;
  const preview = state.casePreview;
  if (!record || !preview) return;
  const button = $('#analysis-save');
  if (button) button.disabled = true;
  try {
    const data = await api(`/api/cases/${encodeURIComponent(record.id)}/analyses`, {
      method: 'POST',
      json: { previewId: preview.previewId },
    });
    state.activeCase = data.case;
    state.casePreview = null;
    renderCase();
    await refreshCases();
    toast('Analysis saved with the case.', 'success');
  } catch (err) {
    if (button) button.disabled = false;
    toast(err.message, 'error');
  }
}

async function deleteCaseAnalysis(analysisId) {
  const record = state.activeCase;
  if (!record) return;
  if (!window.confirm('Delete this saved analysis? This cannot be undone.')) return;
  try {
    const data = await api(
      `/api/cases/${encodeURIComponent(record.id)}/analyses/${encodeURIComponent(analysisId)}`,
      { method: 'DELETE' },
    );
    state.activeCase = data.case;
    renderCase();
    await refreshCases();
    toast('Analysis deleted.', 'success');
  } catch (err) {
    toast(err.message, 'error');
  }
}

function initCases() {
  $('#cases-refresh')?.addEventListener('click', refreshCases);
  $('#case-new')?.addEventListener('click', () => {
    $('#case-create-panel').classList.remove('hidden');
    $('#case-create-title').focus();
  });
  $('#case-create-cancel')?.addEventListener('click', () => {
    $('#case-create-panel').classList.add('hidden');
  });
  $('#case-create-form')?.addEventListener('submit', createCase);
  $('#case-form')?.addEventListener('submit', saveCaseDetails);
  $('#case-delete')?.addEventListener('click', deleteCase);
  $('#case-attach')?.addEventListener('click', attachCaseReport);
  $('#case-analyze')?.addEventListener('click', analyzeCase);
}

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */

async function boot() {
  initTabs();
  initUsername();
  initEmail();
  initFile();
  initReports();
  initCases();
  initAiSettings();

  try {
    await loadConfig();
  } catch (err) {
    toast(`Could not load configuration: ${err.message}`, 'error');
  }
}

boot();
