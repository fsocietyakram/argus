import { loadConfig, resolvedSources } from './config.mjs';
import { PROBES } from './probes.mjs';
import { ENRICHERS } from './enrich.mjs';
import { isUrlAllowed } from './robots.mjs';
import { hostGate } from './ratelimit.mjs';
import { TOOL, VERSION, fetchLimited, mapLimit } from './util.mjs';

const ORDER = {
  confirmed: 0,
  possible: 1,
  unverified: 2,
  blocked: 3,
  error: 4,
  skipped: 5,
  absent: 6,
};

/** Strip @, decode profile URLs, and validate a username. */
export function normalizeUsername(input) {
  let value = String(input ?? '').trim();
  if (!value) throw new Error('Username is required.');
  if (value.length > 300) throw new Error('Input is too long to be a username.');

  // Accept pasted profile URLs, e.g. https://instagram.com/example
  if (/^(https?:\/\/|www\.)/i.test(value) || /^[a-z0-9.-]+\.[a-z]{2,}\//i.test(value)) {
    try {
      const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
      if (url.hostname.includes('.') && url.pathname.length > 1) {
        const segments = url.pathname.split('/').filter(Boolean);
        const first = segments[0]?.toLowerCase();
        const candidate =
          first === 'user' || first === 'u' || first === 'in' || first === 'add'
            ? segments[1]
            : segments[0];
        if (candidate) value = decodeURIComponent(candidate);
      }
    } catch {
      /* not a URL, continue as a plain username */
    }
  }

  value = value.replace(/^@+/, '').trim();

  if (/\s/.test(value)) throw new Error('Username must not contain spaces.');
  if (/[/?#\\]/.test(value)) throw new Error('Username contains characters that are not allowed.');
  if (value.length > 64) throw new Error('Username is longer than 64 characters.');
  if (!/^[\p{L}\p{N}._-]+$/u.test(value)) {
    throw new Error('Username may only contain letters, numbers, dots, underscores, and hyphens.');
  }

  return value;
}

export function buildSourceUrl(source, username) {
  return (source.url || '').replaceAll('{u}', encodeURIComponent(username));
}

/**
 * Decide a source result from an HTTP response.
 * A match means "this account exists", never "this is the same person".
 */
export function evaluateResponse(source, res) {
  if (!res) return { status: 'error', detail: 'No response.' };
  if (res.error) {
    const detail = res.error === 'timeout' ? 'Request timed out.' : `Request failed: ${res.error}`;
    return { status: 'error', detail };
  }

  const code = res.status;
  if ([401, 403, 429, 451, 999].includes(code)) {
    return {
      status: 'blocked',
      detail: `HTTP ${code}. Access denied, rate-limited, or blocked; result inconclusive.`,
    };
  }
  if (code === 404 || code === 410) {
    return { status: 'absent', confidence: 'high', detail: `HTTP ${code}: profile not found.` };
  }
  if (code >= 500) {
    return { status: 'error', detail: `Source returned HTTP ${code}.` };
  }

  const body = String(res.text || '').toLowerCase();
  const challengeMarkers = [
    'client challenge',
    'just a moment...',
    'checking your browser',
    'enable javascript and cookies to continue',
    'attention required! | cloudflare',
    'cf-chl-',
  ];
  if (code === 200 && challengeMarkers.some((marker) => body.includes(marker))) {
    return {
      status: 'blocked',
      detail: 'An anti-bot challenge page was returned instead of the profile; result inconclusive.',
    };
  }

  const missing = (source.notFound || []).find((marker) =>
    body.includes(String(marker).toLowerCase()),
  );
  const hit = (source.found || []).find((marker) => body.includes(String(marker).toLowerCase()));

  if (missing && hit) {
    return {
      status: 'unverified',
      confidence: 'low',
      detail: 'Page contains both found and not-found markers; result is ambiguous.',
    };
  }

  if (missing) {
    return { status: 'absent', confidence: 'high', detail: 'Page contains a not-found marker.' };
  }

  if (hit) {
    return {
      status: source.confidence === 'high' ? 'confirmed' : 'possible',
      confidence: source.confidence || 'medium',
      detail: 'Profile marker found.',
    };
  }

  if (code === 200 && source.check === 'status') {
    return {
      status: source.confidence === 'high' ? 'confirmed' : 'possible',
      confidence: source.confidence || 'medium',
      detail: `HTTP ${code}: page exists.`,
    };
  }

  if (code === 200) {
    return {
      status: 'unverified',
      confidence: 'low',
      detail: 'HTTP 200, but no decisive found/not-found marker was present.',
    };
  }

  return { status: 'unverified', confidence: 'low', detail: `HTTP ${code}; result inconclusive.` };
}

function summarise(findings) {
  const summary = {
    total: findings.length,
    confirmed: 0,
    possible: 0,
    unverified: 0,
    absent: 0,
    blocked: 0,
    skipped: 0,
    error: 0,
  };
  for (const finding of findings) summary[finding.status] = (summary[finding.status] || 0) + 1;
  return summary;
}

async function runPageSource(source, username, { timeout }) {
  const url = buildSourceUrl(source, username);
  const provided = {
    id: source.id,
    name: source.name,
    category: source.category,
    url,
    access: source.access,
    confidence: source.confidence,
    retrievedAt: new Date().toISOString(),
  };

  try {
    const host = new URL(url).host;
    await hostGate(host, source.rateLimit);
    const res = await fetchLimited(url, { timeout, maxBytes: 300_000 });
    const verdict = evaluateResponse(source, res);
    return {
      ...provided,
      status: verdict.status,
      confidence: verdict.confidence || source.confidence,
      detail: verdict.detail,
      elapsedMs: res.elapsedMs,
    };
  } catch (err) {
    return {
      ...provided,
      status: 'error',
      detail: `Unexpected error: ${err.message}`,
      elapsedMs: 0,
    };
  }
}

async function runProbe(source, username, { timeout }) {
  const url = buildSourceUrl(source, username);
  const provided = {
    id: source.id,
    name: source.name,
    category: source.category,
    url,
    access: source.access,
    confidence: source.confidence,
    retrievedAt: new Date().toISOString(),
  };
  const probe = PROBES[source.probe];
  if (!probe) return { ...provided, status: 'error', detail: 'Probe not implemented.', elapsedMs: 0 };

  const started = Date.now();
  try {
    await hostGate(new URL(url).host, source.rateLimit);
    const verdict = await probe({ username, timeout });
    let status = verdict.status;
    if (status === 'confirmed' && (verdict.confidence || source.confidence) !== 'high') {
      status = 'possible';
    }
    return {
      ...provided,
      status,
      confidence: verdict.confidence || source.confidence,
      detail: verdict.detail,
      profile: verdict.profile,
      elapsedMs: Date.now() - started,
    };
  } catch (err) {
    return {
      ...provided,
      status: 'error',
      detail: `Probe failed: ${err.message}`,
      elapsedMs: Date.now() - started,
    };
  }
}

/**
 * Scan public sources for a username.
 * Returns a JSON-serialisable report object.
 */
export async function scanUsername(input, options = {}) {
  const config = options.config || loadConfig();
  const username = normalizeUsername(input);
  const startedAt = new Date();
  const started = Date.now();

  const allSources = options.sources || resolvedSources(config);
  const selected = allSources.filter((source) => {
    if (!source.enabled && !options.includeDisabled) return false;
    if (options.sourceIds?.length && !options.sourceIds.includes(source.id)) return false;
    if (options.categories?.length && !options.categories.includes(source.category)) return false;
    return true;
  });

  const total = selected.length;
  let completed = 0;
  const concurrency = Math.min(24, Math.max(1, options.concurrency ?? config.settings.concurrency ?? 12));
  const timeout = options.timeoutMs ?? config.settings.timeoutMs ?? 12_000;
  const respectRobots = options.respectRobots ?? config.settings.respectRobots ?? true;

  const emit = (event) => {
    try {
      options.onProgress?.({ ...event, total, completed });
    } catch {
      /* progress callbacks must never break a scan */
    }
  };

  emit({ phase: 'start', completed: 0 });

  const findings = await mapLimit(selected, concurrency, async (source) => {
    emit({ phase: 'checking', source: source.name, sourceId: source.id });

    let finding;

    if (source.access === 'page' && source.respectRobots && respectRobots) {
      const url = buildSourceUrl(source, username);
      const robots = await isUrlAllowed(url, { timeout: Math.min(timeout, 8000) });
      if (!robots.allowed) {
        finding = {
          id: source.id,
          name: source.name,
          category: source.category,
          url,
          access: source.access,
          confidence: source.confidence,
          status: 'skipped',
          detail: 'robots.txt disallows automated access to this path. Open the link manually if you have a lawful basis.',
          elapsedMs: 0,
          retrievedAt: new Date().toISOString(),
        };
        completed++;
        emit({ phase: 'result', source: source.name, sourceId: source.id, status: 'skipped' });
        return finding;
      }
    }

    if (source.access === 'api') {
      finding = await runProbe(source, username, { timeout });
    } else {
      finding = await runPageSource(source, username, { timeout });
    }

    if (
      (finding.status === 'confirmed' || finding.status === 'possible') &&
      source.enrich &&
      ENRICHERS[source.enrich]
    ) {
      try {
        const enrichment = await ENRICHERS[source.enrich]({ username, timeout });
        if (enrichment?.error) {
          finding.enrichError = enrichment.error;
        } else if (enrichment) {
          finding.profile = {
            fields: [...(finding.profile?.fields || []), ...(enrichment.fields || [])],
            links: [...(finding.profile?.links || []), ...(enrichment.links || [])],
            note: enrichment.note || finding.profile?.note,
            raw: { ...(finding.profile?.raw || {}), ...(enrichment.raw || {}) },
          };
        }
      } catch (err) {
        finding.enrichError = `Profile enrichment failed: ${err.message}`;
      }
    }

    completed++;
    emit({ phase: 'result', source: source.name, sourceId: source.id, status: finding.status });
    return finding;
  });

  const cleaned = findings.map((finding) => (finding?.error ? {
    id: finding.id || 'unknown',
    name: finding.name || 'Unknown',
    category: 'other',
    status: 'error',
    detail: finding.error,
    elapsedMs: 0,
    retrievedAt: new Date().toISOString(),
  } : finding));

  cleaned.sort(
    (a, b) => (ORDER[a.status] ?? 9) - (ORDER[b.status] ?? 9) || a.name.localeCompare(b.name),
  );

  return {
    schema: 'argus.report/v1',
    command: 'username',
    tool: { name: TOOL, version: VERSION },
    target: `@${username}`,
    normalized: username,
    createdAt: startedAt.toISOString(),
    durationMs: Date.now() - started,
    summary: summarise(cleaned),
    findings: cleaned,
    settings: {
      concurrency,
      timeoutMs: timeout,
      respectRobots,
      enabledSources: allSources.filter((source) => source.enabled).length,
      selectedSources: total,
    },
    notes: [
      'A matching username is not evidence that two accounts belong to the same person.',
      'Only publicly accessible pages and APIs were queried; no login, CAPTCHA, or access control was bypassed.',
      'Sources can change, block automated clients, or be incomplete. “Absent” means “not detected”, not “does not exist”.',
      'Self-published cross-links (for example Keybase proofs) are reported as claims, not verified identity.',
    ],
  };
}
