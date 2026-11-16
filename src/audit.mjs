import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { dataDir, loadConfig } from './config.mjs';

function auditPath(config = loadConfig()) {
  const dir = dataDir(config);
  mkdirSync(dir, { recursive: true });
  return join(dir, 'audit.jsonl');
}

export function appendAudit(entry, config = loadConfig()) {
  const record = {
    id: randomBytes(6).toString('hex'),
    timestamp: new Date().toISOString(),
    action: entry.action,
    command: entry.command || null,
    target: entry.target && config.settings?.logTargetsInAudit !== false ? entry.target : '[redacted]',
    reportId: entry.reportId || null,
    details: entry.details || null,
  };

  try {
    appendFileSync(auditPath(config), `${JSON.stringify(record)}\n`, 'utf8');
    return record;
  } catch (err) {
    console.warn(`[argus] Could not write audit log: ${err.message}`);
    return record;
  }
}

export function readAudit(limit = 100, config = loadConfig()) {
  const path = auditPath(config);
  if (!existsSync(path)) return [];
  try {
    return readFileSync(path, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean)
      .reverse()
      .slice(0, Math.min(1000, Math.max(1, limit)));
  } catch {
    return [];
  }
}

export function clearAudit(config = loadConfig()) {
  const path = auditPath(config);
  try {
    writeFileSync(path, '', 'utf8');
    return true;
  } catch {
    return false;
  }
}
