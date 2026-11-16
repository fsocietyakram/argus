import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SOURCES } from './sites.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export const DEFAULTS = {
  settings: {
    port: 8787,
    concurrency: 12,
    timeoutMs: 12000,
    respectRobots: true,
    retentionDays: 30,
    maxReports: 200,
    maxUploadMb: 30,
    hibpApiKeyEnv: 'HIBP_API_KEY',
    logTargetsInAudit: true,
  },
  sources: {},
};

export function projectRoot() {
  return ROOT;
}

export function configPath() {
  return process.env.ARGUS_CONFIG
    ? resolve(process.env.ARGUS_CONFIG)
    : join(ROOT, 'argus.config.json');
}

export function reportsDir(config = loadConfig()) {
  return process.env.ARGUS_REPORTS
    ? resolve(process.env.ARGUS_REPORTS)
    : join(ROOT, config.settings?.reportDir || 'reports');
}

export function dataDir(config = loadConfig()) {
  return process.env.ARGUS_DATA
    ? resolve(process.env.ARGUS_DATA)
    : join(ROOT, config.settings?.dataDir || 'data');
}

function deepMerge(base, override) {
  if (!override || typeof override !== 'object' || Array.isArray(override)) return base;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] =
      value && typeof value === 'object' && !Array.isArray(value) && typeof base[key] === 'object'
        ? deepMerge(base[key] ?? {}, value)
        : value;
  }
  return out;
}

export function loadConfig() {
  const path = configPath();
  if (!existsSync(path)) return structuredClone(DEFAULTS);
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return deepMerge(structuredClone(DEFAULTS), parsed);
  } catch (err) {
    console.warn(`[argus] Could not read ${path}: ${err.message}. Using defaults.`);
    return structuredClone(DEFAULTS);
  }
}

export function saveConfig(config) {
  const path = configPath();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
  return path;
}

/** Merge registry defaults with per-source overrides from config. */
export function resolvedSources(config = loadConfig()) {
  return SOURCES.map((source) => {
    const override = config.sources?.[source.id] || {};
    return {
      ...source,
      enabled: override.enabled ?? source.enabled,
      respectRobots: override.respectRobots ?? source.respectRobots,
      rateLimit: override.rateLimit ?? source.rateLimit,
      confidence: override.confidence ?? source.confidence,
    };
  });
}

export function setSourceEnabled(id, enabled, config = loadConfig()) {
  const source = SOURCES.find((s) => s.id === id);
  if (!source) throw new Error(`Unknown source: ${id}`);
  config.sources = config.sources || {};
  config.sources[id] = { ...(config.sources[id] || {}), enabled: Boolean(enabled) };
  saveConfig(config);
  return config;
}

export function createDataDirs(config = loadConfig()) {
  mkdirSync(reportsDir(config), { recursive: true });
  mkdirSync(dataDir(config), { recursive: true });
}
