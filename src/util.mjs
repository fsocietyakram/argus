import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { statSync } from 'node:fs';

export const TOOL = 'ARGUS';
export const VERSION = '1.1.0';
export const DEFAULT_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

/* ------------------------------------------------------------------ */
/* Colors                                                              */
/* ------------------------------------------------------------------ */

let colorEnabled = process.env.NO_COLOR === undefined && Boolean(process.stdout.isTTY);

export function setColor(value) {
  colorEnabled = Boolean(value);
}

export function colorEnabledNow() {
  return colorEnabled;
}

const paint = (open, close) => (s) =>
  colorEnabled ? `\x1b[${open}m${s}\x1b[${close}m` : String(s);

export const c = {
  bold: paint(1, 22),
  dim: paint(2, 22),
  italic: paint(3, 23),
  underline: paint(4, 24),
  red: paint(31, 39),
  green: paint(32, 39),
  yellow: paint(33, 39),
  blue: paint(34, 39),
  magenta: paint(35, 39),
  cyan: paint(36, 39),
  white: paint(37, 39),
  gray: paint(90, 39),
};

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */

/**
 * Fetch a URL with a hard timeout and a response-size cap.
 * Never throws: always resolves with a result object.
 */
export async function fetchLimited(url, opts = {}) {
  const {
    timeout = 12000,
    maxBytes = 200_000,
    headers = {},
    method = 'GET',
    body,
  } = opts;

  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(url, {
      method,
      body,
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': DEFAULT_USER_AGENT,
        'accept-language': 'en-US,en;q=0.9',
        accept: 'text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8',
        'x-osint-tool': `${TOOL}/${VERSION} (public-data-only)`,
        ...headers,
      },
    });

    let text = '';
    let truncated = false;

    if (res.body && maxBytes != null) {
      const reader = res.body.getReader();
      const chunks = [];
      let total = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (maxBytes > 0 && total >= maxBytes) {
            const keep = value.byteLength - (total - maxBytes);
            if (keep > 0) chunks.push(value.subarray(0, keep));
            truncated = true;
            await reader.cancel().catch(() => {});
            break;
          }
          chunks.push(value);
        }
      } catch {
        /* body read failures are non-fatal */
      }
      text = Buffer.concat(chunks.map((v) => Buffer.from(v))).toString('utf8');
    }

    const responseHeaders = {};
    res.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    return {
      ok: res.ok,
      status: res.status,
      finalUrl: res.url || url,
      headers: responseHeaders,
      contentType: responseHeaders['content-type'] || '',
      text,
      truncated,
      elapsedMs: Date.now() - started,
    };
  } catch (err) {
    const aborted = err?.name === 'AbortError' || controller.signal.aborted;
    return {
      ok: false,
      status: 0,
      error: aborted ? 'timeout' : err?.cause?.code || err?.message || String(err),
      text: '',
      headers: {},
      finalUrl: url,
      elapsedMs: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Run async workers over items with a concurrency limit, preserving order. */
export async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const width = Math.max(1, Math.min(limit || 1, items.length || 1));

  async function run() {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      try {
        results[index] = await worker(items[index], index);
      } catch (err) {
        results[index] = { error: err?.message || String(err) };
      }
    }
  }

  await Promise.all(Array.from({ length: width }, run));
  return results;
}

/* ------------------------------------------------------------------ */
/* Hashing / formatting                                                */
/* ------------------------------------------------------------------ */

export const md5 = (data) => createHash('md5').update(data).digest('hex');
export const sha1 = (data) => createHash('sha1').update(data).digest('hex');
export const sha256 = (data) => createHash('sha256').update(data).digest('hex');

export function formatBytes(bytes) {
  if (bytes == null || Number.isNaN(bytes)) return '?';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`;
}

export function formatDuration(ms) {
  if (ms == null) return '?';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function nowStamp(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}_` +
    `${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`
  );
}

export function slugify(value) {
  return String(value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60) || 'target';
}

export function truncate(value, length = 120) {
  if (value == null) return '';
  const text = String(value).replace(/\s+/g, ' ').trim();
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

export function uniq(values) {
  return [...new Set(values)];
}

export function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function stripHtml(value = '') {
  return String(value)
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|li)>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&apos;/gi, "'")
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */

export function fileExists(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

export function openPath(path) {
  const platform = process.platform;
  let command;
  let args;

  if (platform === 'win32') {
    command = 'cmd';
    args = ['/c', 'start', '', path];
  } else if (platform === 'darwin') {
    command = 'open';
    args = [path];
  } else {
    command = 'xdg-open';
    args = [path];
  }

  try {
    const child = spawn(command, args, { detached: true, stdio: 'ignore' });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

export function withTimeout(promise, ms, label = 'operation') {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms} ms`)), ms);
  });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}
