#!/usr/bin/env node
/**
 * ARGUS command line interface.
 * Zero dependencies, Node 18+. Shares its engine with the local web UI.
 */

import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { analyzeFile, stripMetadata } from './src/exif.mjs';
import { loadConfig } from './src/config.mjs';
import {
  attachReports,
  caseIntel,
  createCase,
  deleteCase,
  exportCaseBundle,
  listCases,
  readCase,
  updateCase,
  verifyBundleFile,
  verifyCase,
} from './src/cases.mjs';
import { scanDomain } from './src/domain.mjs';
import { scanEmail } from './src/email.mjs';
import {
  deleteAllData,
  deleteReport,
  listReports,
  printResult,
  purgeReports,
  readReport,
  reportStats,
  saveReport,
} from './src/report.mjs';
import { resolvedSources } from './src/config.mjs';
import { startServer } from './src/server.mjs';
import { scanUsername } from './src/username.mjs';
import {
  TOOL,
  VERSION,
  c,
  formatBytes,
  setColor,
  truncate,
} from './src/util.mjs';

/* ------------------------------------------------------------------ */
/* Help                                                                */
/* ------------------------------------------------------------------ */

const HELP = `${c.bold(c.cyan('◆ ARGUS'))} ${VERSION} — public-data OSINT & file forensics

${c.bold('USAGE')}
  argus <command> [target] [options]
  argus                       start the interactive shell

${c.bold('COMMANDS')}
  username <name|url>         check public profile sources for a username
  email <address>             syntax, DNS, Gravatar, breach metadata, public mentions
  domain <domain>             WHOIS, DNS, certificate transparency, HTTP headers
  file <path>                 extract EXIF/document metadata (in memory)
  strip <path>                write a metadata-stripped copy (JPEG/PNG)
  auto <target>               detect target type and run the right scan
  all <target>                auto + linked username scan for an email
  serve                       start the local web UI on 127.0.0.1
  sites                       list the source registry
  reports [action]            list, show, delete, purge, or delete-all
  case [action]               create, list, show, attach, intel, verify, export, or verify-bundle
  help | version

${c.bold('OPTIONS')}
  --json                      print the raw report JSON to stdout
  --no-save                   do not write a report to disk
  --save                      save a report (required for file reports)
  --open                      open the HTML report / web UI in a browser
  --linked                    email: also scan derived usernames
  --category <a,b>            username: restrict to categories (repeatable)
  --sites <id,id>             username: restrict to source ids
  --concurrency <n>           username: parallel requests (1-24)
  --timeout <ms|12s>          request timeout (default 12000 ms)
  --port <n>                  web UI port (default 8787)
  --out <path>                strip or case export: destination file
  --notes <text>              case create: case notes
  --fingerprint <hex>         case verify-bundle: pin the signer (8+ hex chars)
  --limit <n>                 reports/audit rows to show
  --yes                       reports delete-all: skip confirmation
  --no-color                  disable ANSI color
  -h, --help                  this help
  -v, --version               version

${c.bold('EXAMPLES')}
  argus username torvalds
  argus username @example --category social,dev --json
  argus email person@example.com --linked
  argus domain example.com
  argus file ./photo.jpg --save
  argus strip ./photo.jpg --out ./shared/photo.jpg
  argus serve --port 8787 --open
  argus reports show username-torvalds-20260101_120000-ab12
  argus case create "Domain due diligence" --notes "Scope: public sources only"
  argus case intel case-domain-due-diligence-20260101_120000-ab12
  argus case verify case-domain-due-diligence-20260101_120000-ab12
  argus case export case-domain-due-diligence-20260101_120000-ab12 --out ./handoff.arguscase
  argus case verify-bundle ./handoff.arguscase --fingerprint A1B2C3D4
  argus reports delete-all --yes

${c.bold('ETHICS')}
  Use only public information and files you are authorised to examine. ARGUS never logs in,
  resets passwords, reads inboxes, bypasses CAPTCHAs, or circumvents access controls.
  A matching username or metadata is not proof of identity. Use only where you have a lawful
  basis, and delete reports when they are no longer needed.
`;

const ALIASES = {
  username: 'username',
  user: 'username',
  u: 'username',
  email: 'email',
  mail: 'email',
  e: 'email',
  file: 'file',
  exif: 'file',
  f: 'file',
  domain: 'domain',
  dns: 'domain',
  d: 'domain',
  strip: 'strip',
  auto: 'auto',
  all: 'all',
  serve: 'serve',
  web: 'serve',
  ui: 'serve',
  sites: 'sites',
  reports: 'reports',
  case: 'case',
  cases: 'case',
  bundle: 'case',
  help: 'help',
  version: 'version',
};

const BOOLEAN_FLAGS = new Set([
  'json',
  'open',
  'save',
  'no-save',
  'linked',
  'no-color',
  'yes',
  'pretty',
  'help',
  'version',
]);

const VALUE_FLAGS = new Set([
  'category',
  'sites',
  'site',
  'concurrency',
  'timeout',
  'port',
  'out',
  'limit',
  'notes',
  'fingerprint',
]);

/* ------------------------------------------------------------------ */
/* Argument parsing                                                    */
/* ------------------------------------------------------------------ */

function camel(name) {
  return name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

export function parseArgs(argv) {
  const positionals = [];
  const flags = {};

  for (let index = 0; index < argv.length; index++) {
    const token = argv[index];
    if (token === '--') {
      positionals.push(...argv.slice(index + 1));
      break;
    }

    if (!token.startsWith('-') || token === '-') {
      positionals.push(token);
      continue;
    }

    if (token === '-h') {
      flags.help = true;
      continue;
    }
    if (token === '-v') {
      flags.version = true;
      continue;
    }
    if (token === '-j') {
      flags.json = true;
      continue;
    }

    if (!token.startsWith('--')) throw new Error(`Unknown option: ${token}`);

    const body = token.slice(2);
    const equals = body.indexOf('=');
    const rawName = equals === -1 ? body : body.slice(0, equals);
    const inlineValue = equals === -1 ? undefined : body.slice(equals + 1);

    if (BOOLEAN_FLAGS.has(rawName)) {
      if (inlineValue !== undefined) throw new Error(`Option --${rawName} does not take a value.`);
      flags[camel(rawName)] = true;
      continue;
    }

    if (VALUE_FLAGS.has(rawName)) {
      const value = inlineValue ?? argv[++index];
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`Option --${rawName} needs a value.`);
      }
      const key = camel(rawName);
      if (key === 'category') {
        flags.categories = [...(flags.categories || []), ...value.split(',').map((item) => item.trim()).filter(Boolean)];
      } else if (key === 'sites' || key === 'site') {
        flags.sourceIds = [...(flags.sourceIds || []), ...value.split(',').map((item) => item.trim()).filter(Boolean)];
      } else {
        flags[key] = value;
      }
      continue;
    }

    throw new Error(`Unknown option: --${rawName}`);
  }

  return { positionals, flags };
}

function parseDuration(value, fallback) {
  if (value == null) return fallback;
  const match = String(value).trim().match(/^(\d+(?:\.\d+)?)\s*(ms|s)?$/i);
  if (!match) throw new Error(`Invalid duration: ${value}`);
  const number = Number(match[1]);
  return Math.round(match[2]?.toLowerCase() === 's' ? number * 1000 : number);
}

function parseCount(value, fallback, min, max, label) {
  if (value == null) return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  }
  return number;
}

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

function usageError(message) {
  const error = new Error(message);
  error.isUsage = true;
  return error;
}

function reportLine(saved, flags) {
  if (!saved || flags.json) return;
  console.log(c.dim(`  Report ${saved.id}`));
  console.log(c.dim(`  HTML   ${saved.htmlPath}`));
  console.log(c.dim(`  JSON   ${saved.jsonPath}`));
}

function maybeOpen(saved, flags) {
  if (!flags.open || !saved) return;
  import('./src/util.mjs')
    .then(({ openPath }) => {
      if (!openPath(saved.htmlPath)) console.log(c.yellow('  Could not launch a browser automatically.'));
    })
    .catch(() => {});
}

function persist(result, flags, { forceSave = false } = {}) {
  if (flags.noSave) return null;
  if (flags.json && !flags.save && !forceSave) return null;
  if (result.command === 'file' && !flags.save && !forceSave) return null;
  try {
    return saveReport(result);
  } catch (err) {
    console.error(c.red(`  Report could not be saved: ${err.message}`));
    return null;
  }
}

function progressReporter(flags) {
  if (flags.json || !process.stderr.isTTY) return null;
  let completed = 0;
  let total = 0;

  const clear = () => {
    if (process.stderr.isTTY) process.stderr.write('\r\x1b[2K');
  };

  const onProgress = (event) => {
    if (event.total != null) total = event.total;
    if (event.completed != null) completed = event.completed;
    let label = event.phase;
    if (event.phase === 'checking') label = `checking ${event.source}`;
    else if (event.phase === 'result') label = `${event.source} — ${event.status}`;
    process.stderr.write(
      `\r\x1b[2K  ${String(completed).padStart(2)}/${String(total).padEnd(2)}  ${truncate(label, 72)}`,
    );
  };

  onProgress.clear = clear;
  return onProgress;
}

function exitHelp() {
  console.log(HELP);
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

async function commandUsername(target, flags) {
  if (!target) throw usageError('Usage: argus username <name|url> [options]');
  const config = loadConfig();
  const progress = progressReporter(flags);
  const result = await scanUsername(target, {
    config,
    categories: flags.categories,
    sourceIds: flags.sourceIds,
    concurrency: parseCount(flags.concurrency, config.settings.concurrency, 1, 24, '--concurrency'),
    timeoutMs: parseDuration(flags.timeout, config.settings.timeoutMs),
    onProgress: progress || undefined,
  });
  progress?.clear();

  if (flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printResult(result);
  }

  const saved = persist(result, flags);
  reportLine(saved, flags);
  maybeOpen(saved, flags);
  return result;
}

async function commandEmail(target, flags) {
  if (!target) throw usageError('Usage: argus email <address> [options]');
  const config = loadConfig();
  if (!flags.json) console.log(c.dim('  Running syntax, DNS, Gravatar, breach, and mention checks…'));
  const result = await scanEmail(target, {
    config,
    linked: Boolean(flags.linked),
    timeoutMs: parseDuration(flags.timeout, config.settings.timeoutMs),
  });

  if (flags.json) console.log(JSON.stringify(result, null, 2));
  else printResult(result);

  const saved = persist(result, flags);
  reportLine(saved, flags);
  maybeOpen(saved, flags);
  return result;
}

async function commandDomain(target, flags) {
  if (!target) throw usageError('Usage: argus domain <example.com> [options]');
  const config = loadConfig();
  if (!flags.json) console.log(c.dim('  Querying WHOIS, DNS, certificate transparency, and HTTP headers…'));
  const result = await scanDomain(target, {
    config,
    timeoutMs: parseDuration(flags.timeout, config.settings.timeoutMs),
  });

  if (flags.json) console.log(JSON.stringify(result, null, 2));
  else printResult(result);

  const saved = persist(result, flags);
  reportLine(saved, flags);
  maybeOpen(saved, flags);
  return result;
}

function readTargetFile(path, config) {
  if (!path) throw usageError('Usage: argus file <path> [--save]');
  const absolute = resolve(path);
  if (!existsSync(absolute)) throw new Error(`File not found: ${path}`);
  const stat = statSync(absolute);
  if (!stat.isFile()) throw new Error(`Not a file: ${path}`);
  const hardLimit = 200 * 1024 * 1024;
  if (stat.size > hardLimit) {
    throw new Error(`File is larger than the ${formatBytes(hardLimit)} CLI limit.`);
  }
  const configured = Number(config.settings?.maxUploadMb) || 30;
  if (stat.size > configured * 1024 * 1024) {
    console.log(
      c.yellow(`  Note: file is larger than the web upload limit (${configured} MB); reading it locally anyway.`),
    );
  }
  return { absolute, buffer: readFileSync(absolute) };
}

async function commandFile(path, flags) {
  const config = loadConfig();
  const { absolute, buffer } = readTargetFile(path, config);
  const result = analyzeFile(buffer, basename(absolute));

  if (flags.json) console.log(JSON.stringify(result, null, 2));
  else printResult(result);

  const saved = persist(result, flags, { forceSave: false });
  reportLine(saved, flags);
  maybeOpen(saved, flags);
  return result;
}

async function commandStrip(path, flags) {
  if (!path) throw usageError('Usage: argus strip <path> [--out <path>]');
  const absolute = resolve(path);
  if (!existsSync(absolute)) throw new Error(`File not found: ${path}`);
  const buffer = readFileSync(absolute);
  const stripped = stripMetadata(buffer, basename(absolute));

  if (!stripped.ok) {
    throw new Error(
      `${stripped.error} The original file was not modified. Preserve it separately if it is evidence.`,
    );
  }

  const extension = stripped.format === 'png' ? 'png' : 'jpg';
  const defaultName = `stripped-${basename(absolute, extname(absolute))}.${extension}`;
  const destination = resolve(flags.out || join(dirname(absolute), defaultName));

  if (destination === absolute) {
    throw new Error('Refusing to overwrite the original file. Choose a different --out path.');
  }
  writeFileSync(destination, stripped.buffer);

  if (flags.json) {
    console.log(
      JSON.stringify(
        {
          ok: true,
          format: stripped.format,
          source: absolute,
          destination,
          originalBytes: buffer.length,
          strippedBytes: stripped.buffer.length,
          removed: stripped.removed,
          note: stripped.note,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(`${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('metadata strip')}`);
    console.log(`  Source       ${absolute}`);
    console.log(`  Copy         ${destination}`);
    console.log(`  Size         ${formatBytes(buffer.length)} → ${formatBytes(stripped.buffer.length)}`);
    console.log(
      `  Removed      ${stripped.removed.length ? stripped.removed.join(', ') : c.yellow('nothing detected')}`,
    );
    console.log(c.dim(`  ${stripped.note}`));
    console.log(c.yellow('  The original file was not modified. Verify the copy opens correctly before sharing.'));
  }

  return { destination, removed: stripped.removed };
}

function detectKind(target) {
  if (existsSync(target) && statSync(target).isFile()) return 'file';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(target)) return 'email';
  if (
    /^(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\/?$/i.test(target) &&
    !target.includes('@')
  ) {
    return 'domain';
  }
  return 'username';
}

async function commandAuto(target, flags, { linked = false } = {}) {
  if (!target) throw usageError('Usage: argus auto <target> [options]');
  const kind = detectKind(target);
  if (!flags.json) console.log(c.dim(`  Detected target type: ${kind}`));
  if (kind === 'file') return commandFile(target, flags);
  if (kind === 'email') {
    if (linked) flags.linked = true;
    return commandEmail(target, flags);
  }
  if (kind === 'domain') return commandDomain(target, flags);
  return commandUsername(target, flags);
}

async function commandSites(flags) {
  const sources = resolvedSources(loadConfig());
  if (flags.json) {
    console.log(JSON.stringify(sources, null, 2));
    return sources;
  }

  console.log(`${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('source registry')}  ${sources.length} sources`);
  console.log('');
  console.log(
    c.dim(
      `  ${'ID'.padEnd(14)} ${'NAME'.padEnd(18)} ${'CATEGORY'.padEnd(9)} ${'ACCESS'.padEnd(5)} ${'CONF'.padEnd(6)} ${'RATE'.padEnd(5)} ${'ROBOTS'.padEnd(6)} ON`,
    ),
  );
  for (const source of sources) {
    console.log(
      `  ${source.id.padEnd(14)} ${truncate(source.name, 18).padEnd(18)} ${source.category.padEnd(9)} ${source.access.padEnd(5)} ${source.confidence.padEnd(6)} ${String(source.rateLimit).padEnd(5)} ${(source.respectRobots ? 'yes' : 'no').padEnd(6)} ${source.enabled ? 'yes' : 'no'}`,
    );
  }
  console.log('');
  console.log(c.dim('  Toggle sources in argus.config.json or from the web UI. Each source declares its ToS note.'));
  return sources;
}

async function commandReports(args, flags) {
  const action = args[0] || 'list';
  const id = args[1];
  const limit = parseCount(flags.limit, 50, 1, 1000, '--limit');

  if (action === 'list') {
    const reports = listReports();
    const stats = reportStats();
    if (flags.json) {
      console.log(JSON.stringify({ stats, reports }, null, 2));
      return reports;
    }
    console.log(
      `${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('saved reports')}  ${stats.count} · retention ${stats.retentionDays ?? '—'} days · max ${stats.maxReports ?? '—'}`,
    );
    console.log('');
    if (!reports.length) {
      console.log(c.dim('  No saved reports.'));
      return reports;
    }
    console.log(
      c.dim(`  ${'CREATED'.padEnd(20)} ${'TOOL'.padEnd(10)} ${'TARGET'.padEnd(30)} ${'RISK'.padEnd(12)} ID`),
    );
    for (const report of reports.slice(0, limit)) {
      console.log(
        `  ${String(report.createdAt || '').slice(0, 19).padEnd(20)} ${String(report.command || '').padEnd(10)} ${truncate(report.target || '', 30).padEnd(30)} ${String(report.riskScore != null ? `${report.riskScore}/100 ${report.riskLevel || ''}` : '—').padEnd(12)} ${report.id}`,
      );
    }
    if (reports.length > limit) console.log(c.dim(`  … ${reports.length - limit} more (use --limit)`));
    return reports;
  }

  if (action === 'show' || action === 'open') {
    if (!id) throw usageError('Usage: argus reports show <report-id>');
    const report = readReport(id);
    if (flags.json) {
      console.log(JSON.stringify(report, null, 2));
      return report;
    }
    printResult(report);
    const reportMeta = listReports().find((item) => item.id === id);
    if (reportMeta && flags.open) {
      maybeOpen({ htmlPath: join(reportStats().reportsDir, `${id}.html`) }, { open: true });
    }
    return report;
  }

  if (action === 'delete') {
    if (!id) throw usageError('Usage: argus reports delete <report-id>');
    deleteReport(id);
    console.log(c.green(`  Deleted ${id}.`));
    return true;
  }

  if (action === 'purge') {
    const deleted = purgeReports();
    console.log(`  Purged ${deleted.length} report(s) by retention settings.`);
    return deleted;
  }

  if (action === 'delete-all') {
    if (!flags.yes) {
      throw usageError('Refusing to delete everything without --yes. This removes reports, HTML copies, and the audit log.');
    }
    const result = deleteAllData();
    console.log(c.green(`  Deleted ${result.removed} file(s) and cleared the audit log.`));
    return result;
  }

  throw usageError('Usage: argus reports [list|show <id>|delete <id>|purge|delete-all --yes]');
}

function printIntegrity(result, { label = 'case integrity' } = {}) {
  const status = String(result.status || 'unknown');
  const statusColor = status === 'valid' ? c.green : status === 'unsigned' ? c.yellow : c.red;
  console.log(
    `${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold(label)}  ${statusColor(status.toUpperCase())}`,
  );
  if (result.caseTitle) console.log(`  Case       ${result.caseTitle}`);
  if (result.caseId) console.log(`  Case ID    ${result.caseId}`);
  if (result.exportedAt) console.log(`  Exported   ${result.exportedAt}`);
  console.log(
    `  Ledger     ${result.entries} entr${result.entries === 1 ? 'y' : 'ies'}${
      result.head ? c.dim(` · head ${String(result.head).slice(0, 16)}…`) : ''
    }`,
  );
  if (result.fingerprintShort) console.log(`  Signer     ${result.fingerprintShort}`);
  if (result.bundle) {
    console.log(
      `  Signature  ${result.signed ? c.green('ed25519 · verified') : c.red('missing or invalid')}`,
    );
  }
  if (result.reports?.length) {
    const counts = result.reports.reduce((acc, item) => {
      acc[item.status] = (acc[item.status] || 0) + 1;
      return acc;
    }, {});
    console.log(
      `  Reports    ${Object.entries(counts)
        .map(([key, value]) => `${value} ${key}`)
        .join(' · ')}`,
    );
  }
  for (const item of result.problems || []) {
    const mark = item.severity === 'error' ? c.red('✖') : c.yellow('!');
    console.log(`  ${mark} ${item.code}  ${item.message}`);
  }
  if (status === 'valid') {
    console.log(c.dim('  Chain, signature, case notes, and attached report hashes all match.'));
  }
  return result;
}

async function commandCase(args, flags) {
  const action = args[0] || 'list';
  const id = args[1];

  if (action === 'list') {
    const cases = listCases();
    const limit = parseCount(flags.limit, 50, 1, 1000, '--limit');
    if (flags.json) {
      console.log(JSON.stringify({ cases }, null, 2));
      return cases;
    }
    console.log(`${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('cases')}  ${cases.length}`);
    console.log('');
    if (!cases.length) {
      console.log(c.dim('  No cases yet. Create one with "argus case create <title>".'));
      return cases;
    }
    console.log(
      c.dim(`  ${'UPDATED'.padEnd(20)} ${'REPORTS'.padEnd(8)} ${'LEDGER'.padEnd(7)} ${'TITLE'.padEnd(34)} ID`),
    );
    for (const item of cases.slice(0, limit)) {
      console.log(
        `  ${String(item.updatedAt || '').slice(0, 19).padEnd(20)} ${String(item.reportCount).padEnd(8)} ${String(item.ledgerEntries).padEnd(7)} ${truncate(item.title, 34).padEnd(34)} ${item.id}`,
      );
    }
    if (cases.length > limit) console.log(c.dim(`  … ${cases.length - limit} more (use --limit)`));
    return cases;
  }

  if (action === 'create') {
    const title = args.slice(1).join(' ').trim();
    if (!title) throw usageError('Usage: argus case create <title> [--notes <text>]');
    const record = createCase({ title, notes: flags.notes || '' });
    console.log(c.green(`  Created ${record.id}`));
    console.log(c.dim(`  Ledger started · signer ${record.ledger.signer.fingerprintShort}`));
    return record;
  }

  if (action === 'show') {
    if (!id) throw usageError('Usage: argus case show <case-id>');
    const record = readCase(id);
    if (flags.json) {
      console.log(JSON.stringify(record, null, 2));
      return record;
    }
    console.log(`${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold(record.title)}`);
    console.log(`  Case ID    ${record.id}`);
    console.log(`  Created    ${record.createdAt}`);
    console.log(`  Updated    ${record.updatedAt}`);
    console.log(`  Reports    ${record.reportIds.length}`);
    console.log(`  Analyses   ${record.analyses.length}`);
    console.log(
      `  Ledger     ${record.ledger?.entries?.length || 0} entries · signer ${
        record.ledger?.signer?.fingerprintShort || '—'
      }`,
    );
    if (record.notes) {
      console.log('');
      console.log(c.dim(`  ${truncate(record.notes.replace(/\\s+/g, ' '), 240)}`));
    }
    if (record.ledger?.entries?.length) {
      console.log('');
      console.log(c.dim('  LEDGER EVENTS'));
      for (const entry of record.ledger.entries.slice(-12)) {
        console.log(
          `  ${String(entry.seq).padStart(3)}  ${String(entry.at).slice(0, 19)}  ${entry.type.padEnd(16)} ${truncate(
            entry.details?.reportId || entry.details?.analysisId || entry.details?.title || '',
            48,
          )}`,
        );
      }
      if (record.ledger.entries.length > 12) {
        console.log(c.dim(`  … ${record.ledger.entries.length - 12} earlier event(s)`));
      }
    }
    return record;
  }

  if (action === 'attach') {
    const reportIds = args
      .slice(2)
      .join(',')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    if (!id || !reportIds.length) throw usageError('Usage: argus case attach <case-id> <report-id,...>');
    const record = attachReports(id, reportIds);
    console.log(
      c.green(
        `  Attached ${reportIds.length} report(s). Ledger now has ${record.ledger.entries.length} entries.`,
      ),
    );
    return record;
  }

  if (action === 'intel') {
    if (!id) throw usageError('Usage: argus case intel <case-id> [--limit <n>]');
    const intel = caseIntel(id);
    if (flags.json) {
      console.log(JSON.stringify(intel, null, 2));
      return intel;
    }
    const limit = parseCount(flags.limit, 40, 1, 500, '--limit');
    const repeated = intel.correlations?.repeatedIndicators || [];
    console.log(
      `${c.bold(c.cyan('◆ ARGUS'))}  ${c.bold('case intelligence')}  ${intel.caseTitle || intel.caseId}`,
    );
    console.log(
      `  Coverage   ${intel.reportCount} report(s) · ${intel.coverage.datedFacts} dated fact(s) · ${intel.contradictions.count} contradiction(s) · ${repeated.length} repeated indicator(s)`,
    );
    if (intel.timeline.items.length) {
      console.log('');
      console.log(c.dim('  TIMELINE'));
      for (const item of intel.timeline.items.slice(0, limit)) {
        const stamp = `${item.at.slice(0, 10)} ${item.at.slice(11, 16)}`;
        console.log(
          `  ${stamp}  ${String(item.kind).padEnd(10)} ${truncate(item.label, 44).padEnd(44)} ${c.dim(
            truncate(item.detail || item.reportId, 40),
          )}`,
        );
      }
      if (intel.timeline.items.length > limit) {
        console.log(c.dim(`  … ${intel.timeline.items.length - limit} more (use --limit)`));
      }
    }
    if (intel.contradictions.count) {
      console.log('');
      console.log(c.dim('  CONTRADICTIONS'));
      for (const item of intel.contradictions.items) {
        const mark =
          item.severity === 'high'
            ? c.red('✖')
            : item.severity === 'medium'
              ? c.yellow('!')
              : item.severity === 'low'
                ? c.cyan('·')
                : c.dim('·');
        console.log(`  ${mark} ${item.title} ${c.dim(`[${item.severity}]`)}`);
        console.log(`    ${item.detail}`);
        for (const cite of item.citations) {
          console.log(c.dim(`    ${cite.reportId}  ${cite.field} = ${cite.value}`));
        }
      }
    } else {
      console.log(c.dim('  No deterministic contradictions found.'));
    }
    if (repeated.length) {
      console.log('');
      console.log(c.dim('  REPEATED INDICATORS'));
      for (const item of repeated.slice(0, limit)) {
        console.log(`  · ${String(item.type).padEnd(8)} ${truncate(item.value, 64)}`);
        for (const entry of item.occurrences.slice(0, 5)) {
          console.log(c.dim(`    ${entry.reportId}  ${entry.field || ''}  ${entry.evidence || ''}`));
        }
        if (item.occurrences.length > 5) {
          console.log(c.dim(`    … ${item.occurrences.length - 5} more occurrence(s)`));
        }
      }
      if (repeated.length > limit) {
        console.log(c.dim(`  … ${repeated.length - limit} more indicator(s) (use --limit)`));
      }
    } else {
      console.log(c.dim('  No exact indicators repeated across reports.'));
    }
    return intel;
  }

  if (action === 'verify') {
    if (!id) throw usageError('Usage: argus case verify <case-id>');
    const result = verifyCase(id);
    if (flags.json) {
      console.log(JSON.stringify(result, null, 2));
      return result;
    }
    return printIntegrity(result);
  }

  if (action === 'export') {
    if (!id) throw usageError('Usage: argus case export <case-id> [--out <path>]');
    const { path, bundle } = exportCaseBundle(id, undefined, { outPath: flags.out });
    if (flags.json) {
      console.log(JSON.stringify({ path, manifest: bundle.manifest }, null, 2));
      return { path, bundle };
    }
    let size = '';
    try {
      size = ` · ${formatBytes(statSync(path).size)}`;
    } catch {
      size = '';
    }
    console.log(c.green('  Signed case bundle written.'));
    console.log(`  File       ${path}${c.dim(size)}`);
    console.log(`  Reports    ${bundle.manifest.reportCount}`);
    console.log(`  Entries    ${bundle.manifest.ledgerEntries}`);
    console.log(`  Signer     ${bundle.manifest.signer.fingerprintShort}`);
    console.log(c.dim('  Verify anywhere: argus case verify-bundle <file> --fingerprint <signer>'));
    return { path, bundle };
  }

  if (action === 'verify-bundle' || action === 'verifybundle') {
    const file = args[1];
    if (!file) throw usageError('Usage: argus case verify-bundle <path> [--fingerprint <hex>]');
    const result = verifyBundleFile(file, { fingerprint: flags.fingerprint || null });
    if (flags.json) {
      console.log(JSON.stringify(result, null, 2));
      return result;
    }
    return printIntegrity(result, { label: 'bundle integrity' });
  }

  if (action === 'delete') {
    if (!id) throw usageError('Usage: argus case delete <case-id>');
    deleteCase(id);
    console.log(c.green(`  Deleted ${id} and its signing key.`));
    return true;
  }

  throw usageError(
    'Usage: argus case [list|show <id>|create <title>|attach <id> <report-id,...>|verify <id>|export <id>|verify-bundle <path>|delete <id>]',
  );
}

async function commandServe(flags) {
  const port = parseCount(flags.port, 0, 0, 65535, '--port') || undefined;
  let running;
  try {
    running = await startServer({ port, open: Boolean(flags.open) });
  } catch (err) {
    throw new Error(err.message);
  }

  console.log(`${c.bold(c.cyan('◆ ARGUS'))} ${VERSION} — local web UI`);
  console.log(`  Listening ${c.bold(running.url)}`);
  console.log(c.dim('  Bound to loopback only. Press Ctrl+C to stop.'));
  console.log(c.dim('  Mutating API calls require the x-argus header; reports stay on this machine.'));
  return running;
}

/* ------------------------------------------------------------------ */
/* Dispatcher                                                          */
/* ------------------------------------------------------------------ */

async function dispatch(argv, repl = false) {
  const { positionals, flags } = parseArgs(argv);
  if (flags.noColor || flags.json) setColor(false);
  if (flags.help) {
    exitHelp();
    return { done: true };
  }
  if (flags.version) {
    console.log(`${TOOL} ${VERSION}`);
    return { done: true };
  }

  const [rawCommand, ...args] = positionals;
  if (!rawCommand) {
    exitHelp();
    return { done: true };
  }

  const command = ALIASES[rawCommand];
  if (!command) throw usageError(`Unknown command: ${rawCommand}. Run "argus help".`);

  if (command === 'help') {
    exitHelp();
    return { done: true };
  }
  if (command === 'version') {
    console.log(`${TOOL} ${VERSION}`);
    return { done: true };
  }
  if (command === 'sites') return { value: await commandSites(flags) };
  if (command === 'reports') return { value: await commandReports(args, flags) };
  if (command === 'case') return { value: await commandCase(args, flags) };
  if (command === 'serve') {
    const running = await commandServe(flags);
    return { value: running, server: running, serve: !repl };
  }
  if (command === 'strip') return { value: await commandStrip(args[0], flags) };
  if (command === 'auto') return { value: await commandAuto(args[0], flags) };
  if (command === 'all') return { value: await commandAuto(args[0], flags, { linked: true }) };
  if (command === 'username') return { value: await commandUsername(args[0], flags) };
  if (command === 'email') return { value: await commandEmail(args[0], flags) };
  if (command === 'domain') return { value: await commandDomain(args[0], flags) };
  if (command === 'file') return { value: await commandFile(args[0], flags) };

  throw usageError(`Unknown command: ${rawCommand}. Run "argus help".`);
}

/* ------------------------------------------------------------------ */
/* Interactive shell                                                   */
/* ------------------------------------------------------------------ */

function tokenize(line) {
  const tokens = [];
  let current = '';
  let quote = null;
  let escaped = false;

  for (const char of line) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === '\\' && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      else current += char;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = '';
      }
      continue;
    }
    current += char;
  }

  if (current) tokens.push(current);
  return tokens;
}

async function repl() {
  console.log(`${c.bold(c.cyan('◆ ARGUS'))} ${VERSION} — interactive shell`);
  console.log(c.dim('  Type a command, e.g. "username torvalds", "email name@example.com", "help", or "exit".'));
  console.log(c.dim('  Public sources only. No logins, password resets, inbox access, or CAPTCHA bypass.'));

  const rl = createInterface({ input, output });
  let runningServer = null;

  const shutdown = async () => {
    if (runningServer) {
      try {
        await runningServer.close();
      } catch {
        /* ignore */
      }
    }
    rl.close();
  };

  const onSigint = () => {
    console.log('');
    shutdown().finally(() => process.exit(0));
  };
  process.once('SIGINT', onSigint);

  for (;;) {
    let line;
    try {
      line = await rl.question(c.cyan('argus> '));
    } catch {
      break;
    }

    const trimmed = line.trim();
    if (!trimmed) continue;
    if (['exit', 'quit', ':q'].includes(trimmed)) break;

    const tokens = tokenize(trimmed);
    if (!tokens.length) continue;

    if (tokens[0] === 'serve' || tokens[0] === 'web' || tokens[0] === 'ui') {
      if (runningServer) {
        console.log(c.dim(`  Already serving ${runningServer.url}`));
        continue;
      }
    }

    try {
      const outcome = await dispatch(tokens, true);
      if (outcome.server) runningServer = outcome.server;
    } catch (err) {
      console.log(c.red(`  ${err.message}`));
      if (err.isUsage) console.log(c.dim('  Type "help" for available commands.'));
    }
  }

  await shutdown();
  process.removeListener('SIGINT', onSigint);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

export async function main(argv = process.argv.slice(2)) {
  if (!argv.length) {
    if (input.isTTY) {
      await repl();
      return 0;
    }
    exitHelp();
    return 0;
  }

  try {
    const outcome = await dispatch(argv, false);
    if (outcome.serve && outcome.server) {
      await new Promise(() => {});
    }
    return 0;
  } catch (err) {
    console.error(c.red(`\n  ${err.message}`));
    if (err.isUsage) console.error(c.dim('  Run "argus help" for usage.'));
    return 1;
  }
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (invokedDirectly || process.env.ARGUS_CLI_MAIN === '1') {
  const code = await main();
  if (code) process.exit(code);
}
