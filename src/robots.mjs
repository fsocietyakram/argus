import { fetchLimited } from './util.mjs';

const cache = new Map();
const CACHE_MS = 60 * 60 * 1000;

export function clearRobotsCache() {
  cache.clear();
}

/** Parse robots.txt into groups of user-agents and rules. */
export function parseRobots(text) {
  const groups = [];
  let current = null;
  let lastWasAgent = false;

  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const index = line.indexOf(':');
    if (index === -1) continue;
    const key = line.slice(0, index).trim().toLowerCase();
    const value = line.slice(index + 1).trim();

    if (key === 'user-agent') {
      if (!current || !lastWasAgent) {
        current = { agents: [], rules: [] };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
      continue;
    }

    if ((key === 'allow' || key === 'disallow') && current) {
      lastWasAgent = false;
      if (value) current.rules.push({ type: key, pattern: value });
    }
  }

  return groups;
}

function ruleToRegex(pattern) {
  let end = false;
  if (pattern.endsWith('$')) {
    end = true;
    pattern = pattern.slice(0, -1);
  }
  const escaped = pattern
    .split('*')
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${escaped}${end ? '$' : ''}`);
}

/**
 * Returns true when a path is allowed for our agent.
 * Longest matching rule wins; Allow wins ties (Google convention).
 */
export function isAllowed(rules, path, agent = 'argus') {
  if (!rules || rules.length === 0) return true;

  const target = path || '/';
  let best = null;

  for (const rule of rules) {
    if (!ruleToRegex(rule.pattern).test(target)) continue;
    const score = rule.pattern.replace(/\*/g, '').replace(/\$$/, '').length;
    if (
      !best ||
      score > best.score ||
      (score === best.score && rule.type === 'allow' && best.type === 'disallow')
    ) {
      best = { ...rule, score };
    }
  }

  return !best || best.type === 'allow';
}

function selectRules(groups, agent = 'argus') {
  const specific = groups.filter((group) =>
    group.agents.some((a) => a !== '*' && (a.includes(agent) || agent.includes(a))),
  );
  const chosen = specific.length > 0
    ? specific
    : groups.filter((group) => group.agents.includes('*'));
  return chosen.flatMap((group) => group.rules);
}

/**
 * Check robots.txt for a URL. Network failures are treated as allowed,
 * matching the behaviour of standard crawlers (RFC 9309).
 */
export async function isUrlAllowed(url, { timeout = 6000, agent = 'argus' } = {}) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { allowed: true, reason: 'invalid-url' };
  }

  const origin = parsed.origin;
  const now = Date.now();
  const cached = cache.get(origin);

  let entry;
  if (cached && now - cached.fetchedAt < CACHE_MS) {
    entry = cached;
  } else {
    const res = await fetchLimited(`${origin}/robots.txt`, {
      timeout,
      maxBytes: 512_000,
      headers: { accept: 'text/plain' },
    });
    entry = {
      fetchedAt: now,
      rules: res.status === 200 ? selectRules(parseRobots(res.text), agent) : [],
      status: res.status,
    };
    cache.set(origin, entry);
  }

  const allowed = isAllowed(entry.rules, parsed.pathname + parsed.search, agent);
  return {
    allowed,
    reason: allowed ? 'allowed' : 'disallowed-by-robots-txt',
    robotsStatus: entry.status,
  };
}
