# ARGUS

**Public-data OSINT and file-metadata forensics — zero dependencies, local-only.**

ARGUS is a small Node.js toolkit for lawful, privacy-conscious research. It checks public
sources for a username, runs email and domain checks, reads embedded metadata from files you
are authorised to inspect, and writes searchable HTML/JSON reports. It ships with both a
command-line interface and a local web UI that share the same engine.

ARGUS deliberately does **not** log in, reset passwords, read inboxes, bypass CAPTCHAs, scrape
private data, or circumvent access controls. A matching username or a piece of metadata is
**not** proof of identity. Use it only where you have a lawful basis, and delete reports when
they are no longer needed.

```
◆ ARGUS  username sweep
  Target @torvalds · 53 sources · 12.4 s
  8 confirmed · 2 possible · 0 unverified · 39 absent · 3 blocked · 1 skipped
```

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
  - [Windows](#windows)
  - [Kali Linux / Debian / Ubuntu](#kali-linux--debian--ubuntu)
  - [macOS and other Linux](#macos-and-other-linux)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Web UI](#web-ui)
- [Source registry](#source-registry)
- [Email checks and HIBP](#email-checks-and-hibp)
- [File metadata](#file-metadata)
- [AI-assisted case investigation](#ai-assisted-case-investigation)
- [Reports, audit log, and retention](#reports-audit-log-and-retention)
- [Configuration](#configuration)
- [Privacy and security controls](#privacy-and-security-controls)
- [Tests](#tests)
- [Limitations](#limitations)
- [Legal and ethical use](#legal-and-ethical-use)

---

## Features

| Area | What ARGUS does |
| --- | --- |
| **Username search** | Checks 53 public profile sources, grouped into social, developer, creative, music, gaming, books, film, and other. Results are labelled `confirmed`, `possible`, `unverified`, `absent`, `blocked`, `skipped`, or `error`. |
| **Email checks** | Syntax validation, MX/A/AAAA/NS/SOA records, SPF, DMARC, common DKIM selectors, Gravatar public profile, optional Have I Been Pwned breach metadata (no credentials), and public GitHub mentions. Optional linked username scan derived from the local part. |
| **Domain reconnaissance** | WHOIS over port 43, DNS records, certificate-transparency subdomains (crt.sh), HTTP headers/redirects, and email-authentication posture. |
| **File metadata** | Parses EXIF/TIFF (including GPS, camera, serial numbers, timestamps), PNG text chunks, PDF/GIF/HEIC labels, embedded strings, hashes, and an exposure score. |
| **Metadata stripping** | Writes a metadata-free **copy** of JPEG or PNG files. The original is never modified. |
| **Reports** | HTML and JSON export with timestamps, links, collection notes, confidence labels, audit entries, deletion controls, and retention limits. |
| **AI-assisted cases** | Optional case workspace that attaches saved reports and asks an OpenAI-compatible provider for a structured analysis with report-level citations. Disabled and idle until you configure a key and press **Analyze**. |
| **Two interfaces** | Full CLI plus a local web UI bound to `127.0.0.1` with CSP, no-store headers, and CSRF-style header checks on mutations. |

Everything runs locally except explicit public-source checks and, only when you start a case
analysis, the AI provider request. There is no account, telemetry, cloud storage, or npm
dependency.

---

## Requirements

- **Node.js 18.17 or newer** (tested on Node 26).
- No npm packages. `npm install` is not needed.
- Network access for public-source checks (optional; file analysis works offline).
- A modern browser for the web UI.

---

## Install

Clone or copy the `argus` directory, then run one of the following.

### Windows

```powershell
cd argus
node argus.mjs version
node argus.mjs help
node argus.mjs serve --open
```

If you want a shim on your `PATH`, add the directory to `PATH` and call `node argus.mjs …`.
No build step or dependency install is required.

### Kali Linux / Debian / Ubuntu

The included installer checks Node, sets executable bits, verifies the core modules, and
creates the local data directories. It does **not** install npm packages.

```bash
cd argus
chmod +x install.sh argus.sh argus.mjs
./install.sh
```

Options:

```bash
./install.sh --with-node   # install Node.js + npm with apt (needs sudo/root)
./install.sh --link        # symlink argus.sh to ~/.local/bin/argus
./install.sh --with-node --link
```

If your distribution's `nodejs` package is older than 18 (common on older Kali images), use
NodeSource or `nvm`:

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

Then run:

```bash
./argus.sh version
./argus.sh username example
./argus.sh serve --open
```

`argus.sh` is a portable launcher that checks for Node 18+ and preserves your current working
directory, so relative file paths behave as expected. If you used `--link`, `argus` works from
anywhere:

```bash
argus serve --port 8787
```

### macOS and other Linux

```bash
chmod +x argus.mjs argus.sh
./argus.sh help
```

Node installed through Homebrew, `nvm`, `asdf`, or your package manager is fine.

---

## Quick start

```bash
# Check a username across enabled sources
node argus.mjs username torvalds

# Limit to specific categories or sources
node argus.mjs username example --category social,dev
node argus.mjs username example --sites github,reddit,gitlab

# Email checks (add --linked to also scan plausible usernames)
node argus.mjs email person@example.com --linked

# Domain reconnaissance
node argus.mjs domain example.com

# Local file metadata (nothing is uploaded)
node argus.mjs file ./photo.jpg --save

# Produce a metadata-free copy; the original is untouched
node argus.mjs strip ./photo.jpg --out ./shared/photo.jpg

# Start the local web UI
node argus.mjs serve --open
```

If you run `node argus.mjs` with no arguments in an interactive terminal, ARGUS starts a small
shell:

```
argus> username example
argus> email person@example.com
argus> reports list
argus> serve
argus> exit
```

---

## CLI reference

```
argus <command> [target] [options]
```

| Command | Purpose |
| --- | --- |
| `username <name\|url>` | Public profile sweep. Accepts `@handle`, bare handles, or profile URLs. |
| `email <address>` | Email syntax, DNS/authentication, Gravatar, breach metadata, public mentions. |
| `domain <domain>` | WHOIS, DNS, certificate transparency, HTTP headers. |
| `file <path>` | Extract EXIF/document metadata in memory. |
| `strip <path>` | Write a metadata-stripped JPEG/PNG copy. |
| `auto <target>` | Detect file, email, domain, or username and run the right check. |
| `all <target>` | `auto`, plus a linked username scan when the target is an email. |
| `serve` / `web` / `ui` | Start the local web UI on `127.0.0.1`. |
| `sites` | Print the source registry. |
| `reports [action]` | `list`, `show <id>`, `delete <id>`, `purge`, or `delete-all --yes`. |
| `help`, `version` | Usage and version. |

Common options:

| Option | Meaning |
| --- | --- |
| `--json` | Print raw result JSON. By default this skips report saving; add `--save` to save. |
| `--no-save` | Never write a report. |
| `--save` | Save a report (required for file reports). |
| `--open` | Open the HTML report or web UI in a browser. |
| `--linked` | Email: also scan usernames derived from the local part. |
| `--category <a,b>` | Username: restrict to categories. Repeatable. |
| `--sites <id,id>` | Username: restrict to source IDs. Repeatable. |
| `--concurrency <n>` | Username: parallel requests, 1–24. |
| `--timeout <ms\|12s>` | Request timeout (default 12000 ms). |
| `--port <n>` | Web UI port (default 8787). |
| `--out <path>` | Strip: destination file. |
| `--limit <n>` | Reports/audit rows to show. |
| `--yes` | Skip the `reports delete-all` confirmation. |
| `--no-color` | Disable ANSI colour. |

**Saving behaviour**

- Username, email, and domain scans save a report by default.
- File reports are opt-in (`--save`), because file metadata is often more sensitive.
- `--json` implies no save unless `--save` is also present.
- `--no-save` always wins.

Examples:

```bash
node argus.mjs username @example --category social,dev --json
node argus.mjs email person@example.com --linked --save
node argus.mjs file ./evidence.jpg --save --open
node argus.mjs strip ./evidence.jpg --out ./public/copy.jpg
node argus.mjs reports show username-example-20260101_120000-ab12
node argus.mjs reports purge
node argus.mjs reports delete-all --yes
```

---

## Web UI

```bash
node argus.mjs serve
# http://127.0.0.1:8787/
```

Open `http://127.0.0.1:8787/` (or `http://localhost:8787/`). The server binds to loopback
only and refuses cross-origin mutating requests.

Tabs:

1. **Username Search** — choose categories, pick or disable sources, watch live progress, then
   filter results by status or free text. Reports are saved automatically.
2. **Email Checks** — syntax/DNS/breach/Gravatar/mention results, with an optional linked
   username scan. Reports are saved automatically.
3. **File Metadata** — drag a file, inspect EXIF/GPS/strings, optionally save a report, and
   download a metadata-stripped copy. The original is never modified.
4. **Reports** — list saved reports, open HTML, download JSON, delete one, or delete everything
   (including the audit log). The audit panel shows action history, not findings.
5. **Cases** — create a local case with a title and notes, attach or remove saved reports, and
   run a reviewed AI analysis. Only attached reports and case notes are sent, and the preview
   must be saved explicitly.
6. **AI settings** — configure an OpenAI-compatible base URL, model, limits, and API key. The
   key is stored server-side and is never returned to the browser.

Security headers and behaviour:

- `Content-Security-Policy` with `default-src 'self'` for the UI.
- `Cache-Control: no-store` on API responses.
- API mutations require an `x-argus: 1` header and reject cross-origin requests.
- Report HTML is served with `default-src 'none'`, `form-action 'none'`, and no framing.
- Uploads are size-limited (`maxUploadMb`, default 30 MB).
- JSON bodies have per-route size limits; AI provider requests have a configurable timeout and
  a hard response/request cap.

### Local API (advanced)

The UI uses a small JSON API on the same origin:

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness, tool version, HIBP and AI key status (booleans only). |
| `GET` | `/api/config` | Settings, categories, resolved sources, HIBP status, masked AI settings. |
| `GET` | `/api/sources` | Resolved source registry. |
| `PATCH` | `/api/sources/:id` | Enable/disable a source (persisted to config). |
| `POST` | `/api/username` | Body `{ username, categories? }` → `{ jobId }`. |
| `POST` | `/api/email` | Body `{ email, linked? }` → `{ jobId }`. |
| `POST` | `/api/file` | Raw bytes, `x-filename`, optional `x-save-report: 1`. |
| `POST` | `/api/file/strip` | Raw bytes; returns a stripped binary copy. |
| `GET` | `/api/jobs/:id` | Job status, progress, result, report links. |
| `GET`/`DELETE` | `/api/reports` | List stats/reports or delete all. |
| `GET`/`DELETE` | `/api/reports/:id` | Read/delete one report. |
| `GET` | `/api/reports/:id/html` and `/json` | Rendered report. |
| `GET`/`DELETE` | `/api/audit` | Read or clear the audit log. |
| `GET`/`PUT` | `/api/ai/settings` | Read masked settings or update settings/key. Never returns the key. |
| `GET`/`POST` | `/api/cases` | List cases or create one with `{ title, notes? }`. |
| `GET`/`PATCH`/`DELETE` | `/api/cases/:id` | Read, update title/notes, or delete a case. |
| `POST`/`DELETE` | `/api/cases/:id/reports` | Attach `{ reportIds: [...] }` or remove `/api/cases/:id/reports/:reportId`. |
| `POST` | `/api/cases/:id/analyze` | Explicit provider call; returns an unsaved preview with `previewId`. |
| `POST` | `/api/cases/:id/analyses` | Save a reviewed preview with `{ previewId }`. |
| `DELETE` | `/api/cases/:id/analyses/:analysisId` | Delete a saved analysis. |

Mutating calls must include `x-argus: 1`. Username/email scans are asynchronous: poll
`/api/jobs/:id` until `status` is `done` or `error`.

---

## Source registry

The registry lives in [`src/sites.mjs`](src/sites.mjs). Every entry declares its access method,
hit detection, confidence, rate limit, robots.txt policy, and a terms-of-use note. Sources can
be enabled or disabled in `argus.config.json` or from the web UI.

Current categories (53 sources):

| Category | Sources |
| --- | --- |
| `social` | Instagram, X (Twitter), Reddit, TikTok, YouTube, Threads, Pinterest, Tumblr, VK, About.me, Facebook, Mastodon, Bluesky |
| `dev` | GitHub, GitLab, Codeberg, Bitbucket, SourceForge, Keybase, Hacker News, Stack Overflow, npm, PyPI, Docker Hub, Hugging Face, CodePen, Pastebin, LeetCode, Codeforces, TryHackMe, Replit |
| `creative` | Behance, Dribbble, DeviantArt, Flickr, Vimeo, Medium, Substack, WordPress.com, Blogger |
| `music` | Bandcamp, SoundCloud, Mixcloud, Spotify, Last.fm |
| `gaming` | Steam, Twitch, Chess.com, Lichess |
| `books` | Goodreads |
| `film` | Letterboxd |
| `other` | Patreon, Venmo |

Some sources are disabled by default where automated access is commonly blocked or where the
site's terms warrant extra care (for example Cloudflare-protected or JavaScript-rendered pages).
Run `node argus.mjs sites` to see current state.

### Result statuses

| Status | Meaning |
| --- | --- |
| `confirmed` | HTTP 200 or an explicit positive marker on a source rated high confidence. |
| `possible` | A positive marker on a medium/low-confidence source. |
| `unverified` | The page loaded but did not clearly confirm or deny the account, or contained both positive and not-found markers. |
| `absent` | A clear 404/410 or a specific not-found marker. |
| `blocked` | 401/403/429, an anti-bot challenge page, or another access denial. Not evidence of absence. |
| `skipped` | Deliberately not fetched, e.g. `robots.txt` disallows the path. |
| `error` | Network failure, timeout, 5xx, or an unexpected response. |

`confirmed` means "the public page appears to exist", never "this person owns the account".
Shared usernames are common. Corroborate with independent, lawful evidence before making any
identity claim.

Robots.txt is fetched and enforced by default for page sources. API probes are exempt. Network
failures while fetching `robots.txt` are treated as allowed, but the result still records the
request. Rate limits are applied per host, and failures are reported rather than hidden.

---

## Email checks and HIBP

ARGUS performs:

- RFC-style syntax and length validation, IDN normalisation, and local-part checks.
- Domain MX, A/AAAA, NS, SOA, SPF, DMARC, and common DKIM selector lookups.
- Disposable-domain and role-account labels (`postmaster`, `security`, etc.).
- Gravatar public profile lookup using the MD5 hash of the normalised address.
- Public GitHub profile mentions through GitHub's user-search API.
- Optional breach **metadata** through Have I Been Pwned.

### Enabling breach metadata

```bash
# Linux / macOS
export HIBP_API_KEY="your-key"

# Windows PowerShell
$env:HIBP_API_KEY = "your-key"
```

Restart ARGUS afterwards. The web UI shows whether the key is configured. ARGUS displays only
breach names, domains, dates, account counts, and data classes. It never requests, stores, or
displays passwords, hashes, or credentials. If no key is configured, the check is reported as
unavailable rather than silently skipped.

> HIBP requires a paid API key for most programmatic use. Respect their terms and rate limits.

Null MX records are recognised and reported as "the domain does not accept email" rather than
as a usable mail exchanger.

The optional `--linked` scan derives candidate usernames from the email local part and runs the
normal username sweep. This is a heuristic: it does not prove that the mailbox owner controls
those accounts.

---

## File metadata

ARGUS parses files locally, in memory. File bytes are never uploaded anywhere.

Supported analysis:

- **JPEG** — EXIF/TIFF tags in APP1, GPS coordinates, camera make/model/lens, serial numbers,
  owner/artist/copyright, timestamps, user comments, embedded thumbnails, IPTC/ICC presence,
  and printable strings.
- **PNG** — `eXIf`, `tEXt`, `zTXt`, `iTXt`, dimensions, and embedded text.
- **TIFF** — standalone TIFF/EXIF.
- **PDF, GIF, HEIC** — format identification and limited labels. Metadata extraction and
  stripping are not supported for these containers; ARGUS says so instead of guessing.
- **All formats** — size, MIME guess, SHA-256/SHA-1/MD5, detected URLs/emails/handles/paths/IPs,
  parser warnings, and an exposure score (0–100) with findings and recommendations.

### Stripping metadata

```bash
node argus.mjs strip ./photo.jpg --out ./shared/photo.jpg
```

- Produces a **copy**. The source file is opened read-only and is never overwritten.
- JPEG: removes APP1/EXIF and related metadata segments while preserving image data.
- PNG: removes `eXIf`, text chunks, and related metadata chunks.
- Other formats return a clear error; no output is written.
- Always open and verify the copy before sharing it. Stripping reduces metadata exposure but
  cannot detect every proprietary container or steganographic payload.

---

## AI-assisted case investigation

The AI feature is optional. ARGUS works normally with no key, with a blank configuration, or
while the provider is unreachable. No request is sent to an AI provider until you create a case,
attach reports, and press **Analyze case**.

### Configure a provider

Open **AI settings** in the web UI and set:

| Setting | Default | Notes |
| --- | --- | --- |
| Base URL | `https://api.openai.com/v1` | Any OpenAI-compatible endpoint. The request goes to `<base URL>/chat/completions`. |
| Model | `gpt-4o-mini` | Any chat-completions model the provider exposes. |
| API key | — | Stored server-side only. Never returned by an API or rendered in the UI. |
| Timeout | `60000` ms | Per analysis request, 1,000–120,000 ms. |
| Max output tokens | `1800` | 256–8,192. |
| Max input characters | `60000` | 2,000–200,000. Larger evidence sets are truncated and omitted report IDs are reported. |

Do not add a provider “test connection” button: static validation only is intentional, so saving
settings cannot trigger an AI network request.

You can also provide the key without saving anything locally:

```bash
# Linux / macOS
export ARGUS_AI_API_KEY="your-key"
node argus.mjs serve

# Windows PowerShell
$env:ARGUS_AI_API_KEY = "your-key"
node argus.mjs serve
```

### API key storage and precedence

The key is resolved in this order:

1. `ARGUS_AI_API_KEY`
2. `OPENAI_API_KEY`
3. `data/ai-secrets.json`, written with mode `0600` on POSIX (created/updated atomically).

Environment variables always win. If one is set, the UI shows that the key comes from the
environment and clearing the local file will not remove it. **Windows caveat:** POSIX file modes
are not meaningful on NTFS; the file stays inside the git-ignored `data/` directory, and you
should rely on OS account permissions and full-disk encryption.

The key is never written to `argus.config.json`, reports, cases, or the audit log, and it is
never sent to browser JavaScript. Only `keyConfigured`, a masked placeholder, and a source label
are exposed.

### Case workflow and data flow

1. Create a case with a title and notes.
2. Attach saved report IDs. Reports can be removed again without deleting the underlying report.
3. Press **Analyze case** and confirm the provider/model and host shown in the dialog.
4. ARGUS builds a minimised evidence payload containing only the selected reports and the case
   notes. It sends one `POST` to the configured chat-completions endpoint.
5. The result is validated and shown as a preview. Nothing is saved automatically.
6. Review the structured sections, then **Save analysis to case**, **Discard preview**, or
   **Run again**. Provider failures keep the case, notes, and report attachments intact and
   show a retry button.

Case data is stored under `data/cases/` as `argus.case/v1` JSON. Each case keeps at most 50
reports and 20 reviewed analyses. Analyses are stored as `argus.analysis/v1` records. Prompts
and full raw provider responses are not stored.

### Structured output and citations

The provider must return JSON with these sections:

- `summary` — a short neutral overview.
- `observedEvidence` — facts directly present in a supplied report.
- `interpretations` — explicitly labelled inferences with low/medium/high confidence.
- `uncertainty` — missing data, conflicts, and limitations.
- `suggestedNextSteps` — passive, public-source steps with priority and human review.
- `unsupportedClaims` — claims the model considered but could not support.

Every observed evidence item, interpretation, and next step must include at least one citation
with an exact attached `reportId` and a specific `field` or `finding`. ARGUS validates every
citation against the attached report IDs. Items with unknown reports, missing fields, or no
citation stay visible but are flagged as unsupported and listed in the warnings. A matching
username or metadata value is treated as a lead, not proof of identity.

AI text is untrusted input: every string is escaped before rendering. Citation links only open
local report HTML. ARGUS never contacts people, accounts, websites, or third-party services from
an AI suggestion, and the prompt explicitly forbids active scanning, login attempts, or access
to private data.

### Provider errors

Errors are returned with a stable `code`, a human-readable message, and `retryable` where useful:

| Condition | HTTP status | `code` |
| --- | --- | --- |
| Missing key | 400 | `missing_api_key` |
| Invalid settings | 400 | `invalid_ai_settings` |
| No attached reports | 400 | `no_reports` |
| Input cannot fit | 413 | `empty_evidence` / `request_too_large` |
| Provider rate limit | 429 | `provider_rate_limited` (may include `retryAfter`) |
| Timeout | 504 | `provider_timeout` |
| Auth, endpoint, or provider failure | 502 | `provider_auth`, `provider_endpoint`, `provider_error` |
| Malformed or unstructured output | 502 | `provider_invalid_response`, `provider_unstructured` |
| Expired save preview | 404 | `preview_expired` |

Provider error text is truncated and redacted before it reaches the UI or logs. Full provider
responses and prompts are not logged.

---

## Reports, audit log, and retention

Reports are written to `reports/` by default; the audit log is `data/audit.jsonl`.

- Each report gets an ID such as `username-example-20260101_120000-ab12`.
- JSON is the canonical machine-readable record; HTML is a self-contained, searchable view.
- Reports include timestamps, source URLs, status and confidence labels, collection notes,
  settings, and a disclaimer.
- HTML output escapes hostile content and refuses unsafe link schemes.
- The audit log records actions, timestamps, targets, and report IDs — not findings. Set
  `logTargetsInAudit: false` to redact targets.
- Retention defaults to 30 days and 200 reports. Expired and overflow reports are purged on
  save. `reports purge` applies the same rules on demand.
- `reports delete <id>`, the UI delete buttons, and `reports delete-all --yes` remove the JSON,
  HTML, and (for delete-all) the audit log.

Data minimisation is deliberate: file scans do not save reports unless you opt in, and
`--json` does not save by default.

---

## Configuration

Create `argus.config.json` in the project root, or point `ARGUS_CONFIG` at another file. Missing
keys fall back to defaults.

```json
{
  "settings": {
    "port": 8787,
    "concurrency": 12,
    "timeoutMs": 12000,
    "respectRobots": true,
    "retentionDays": 30,
    "maxReports": 200,
    "maxUploadMb": 30,
    "hibpApiKeyEnv": "HIBP_API_KEY",
    "logTargetsInAudit": true,
    "reportDir": "reports",
    "dataDir": "data",
    "ai": {
      "baseUrl": "https://api.openai.com/v1",
      "model": "gpt-4o-mini",
      "timeoutMs": 60000,
      "maxOutputTokens": 1800,
      "maxInputChars": 60000
    }
  },
  "sources": {
    "reddit": { "enabled": false },
    "tryhackme": { "enabled": true },
    "github": { "rateLimit": 30 }
  }
}
```

Per-source overrides can change `enabled`, `respectRobots`, `rateLimit`, and `confidence`.

Environment variables:

| Variable | Purpose |
| --- | --- |
| `HIBP_API_KEY` | Enables optional breach-metadata checks. |
| `ARGUS_AI_API_KEY` | AI provider key; takes precedence over `OPENAI_API_KEY` and the local secrets file. |
| `OPENAI_API_KEY` | Fallback AI provider key when `ARGUS_AI_API_KEY` is unset. |
| `ARGUS_CONFIG` | Path to an alternative config file. |
| `ARGUS_REPORTS` | Override the reports directory. |
| `ARGUS_DATA` | Override the data/audit directory. |
| `NO_COLOR` | Disable ANSI colour in the CLI. |

### Supporting a new source

Add an entry in `src/sites.mjs` using the `page(...)` or `api(...)` helper, including URL
template, access method, detection markers, confidence, rate limit, robots policy, and a terms
note. Then add tests or fixtures for its detection behaviour. Keep markers specific: broad
strings such as a bare `404` cause false negatives.

---

## Privacy and security controls

- **Local-only server.** Binds to `127.0.0.1`; no remote access or cloud component.
- **No credentials.** ARGUS never logs in, requests password resets, reads inboxes, or handles
  account passwords.
- **No CAPTCHA or access-control bypass.** Blocked responses are reported honestly.
- **No breach secrets.** HIBP results are restricted to public breach metadata.
- **Opt-in file reports.** File analysis happens in memory; saving is a deliberate choice.
- **Data minimisation.** Retention limits, explicit deletion, and an audit trail.
- **Server-side AI key.** The key is resolved from env or the git-ignored `data/ai-secrets.json`
  and is never returned to the browser, written to reports/cases, or added to the audit log.
- **Explicit AI requests only.** No provider call happens until **Analyze case** is pressed;
  only attached report evidence and case notes are sent.
- **Untrusted AI output.** All model text is escaped before rendering, citations are validated
  against attached report IDs, and unsupported claims are flagged instead of shown as facts.
- **No automated outreach.** AI suggestions never trigger messages, logins, scans, or third-party
  actions.
- **Output hardening.** HTML escaping, safe URL schemes, CSP, `no-store`, `nosniff`, and
  cross-origin mutation rejection.
- **Honest failures.** Timeouts, 5xx responses, robots denials, and ambiguous pages are
  surfaced as their own statuses instead of being reported as "not found".

Operational advice:

- Run ARGUS from a dedicated directory and keep `reports/`, `data/`, and `argus.config.json` out
  of version control (`.gitignore` already covers them).
- Treat `data/ai-secrets.json` as a credential. Prefer `ARGUS_AI_API_KEY` when your environment
  supports it, and remove the local file when it is no longer needed.
- AI providers receive the attached evidence. Check your provider's retention and training
  policies, and avoid attaching reports you are not permitted to disclose.
- Use full-disk encryption where possible; reports can contain personal data.
- Delete reports and the audit log when an investigation ends.
- Do not expose the web server through a reverse proxy or bind it to `0.0.0.0`.

---

## Tests

The test suite uses Node's built-in runner and local HTTP fixtures. It makes no external
network calls except a DNS lookup that expects an unresolvable `.invalid` domain.

```bash
npm test
# or
node --test
```

Coverage includes:

- Username normalisation and rejection of unsafe input.
- Confirmed/possible/unverified/absent/blocked/skipped/error classification.
- Robots.txt parsing, longest-match rules, caching, and failure behaviour.
- EXIF/PNG/TIFF parsing, GPS extraction, risk scoring, and metadata stripping.
- Email syntax, MD5 Gravatar hash, disposable/role lists, DNS failure handling, and domain
  normalisation.
- Report HTML escaping, save/list/read/delete, retention and overflow purging.
- AI settings validation, key masking/redaction, env precedence, provider error mapping, evidence
  minimisation, citation validation, and no-request behaviour without a key.
- Case creation, report attachment/removal, analysis persistence, and deletion without losing
  reports.
- Server headers, CSRF-style header checks, file analysis, report download/deletion, and path
  traversal rejection.
- End-to-end case analysis against a local mock OpenAI-compatible provider, including preview
  review, save, rate-limit failure recovery, and local secret storage.
- CLI argument parsing and option errors.

---

## Limitations

- Public pages change constantly. Markers, layouts, and anti-bot protections can produce false
  negatives (`absent`) or inconclusive results. `blocked` and `error` do not mean "no account".
- Confidence labels describe source reliability, not identity. The same username on two sites
  may belong to different people.
- HTML-only pages may be JavaScript-rendered; ARGUS does not execute JavaScript or solve
  challenges, so some sources will be blocked or unverified.
- WHOIS output varies by registry; some servers rate-limit or redact data. Certificate
  transparency may include historical or wildcard names.
- HIBP coverage is limited to breaches in their dataset and requires a key.
- Metadata parsing covers common EXIF/TIFF and PNG chunks, not every proprietary format.
  HEIC and PDF are identified but not fully parsed.
- Stripping handles JPEG and PNG only. It cannot guarantee removal of every watermark,
  steganographic payload, or vendor-specific block.
- Gravatar data is self-published and can be outdated or misleading.
- AI output can be wrong, overconfident, or subtly unsupported even when it returns valid JSON.
  Citations are checked for report/field presence, not semantic correctness; a human must verify
  every claim against the report. Provider prompts and model behaviour vary by vendor.
- The AI evidence payload is deliberately minimised, so a provider can miss details that were
  truncated or omitted. Omitted report IDs are reported in the preview.
- Cases and analyses are local files with no encryption at rest beyond OS/disk controls. They are
  not a chain-of-custody system, and deleting a case does not delete its saved reports.
- The tool is not a substitute for legal process, verified identity checks, or forensic
  chain-of-custody procedures.

---

## Legal and ethical use

Use ARGUS only for lawful purposes and only on information that is publicly accessible or files
you are authorised to examine. Respect robots.txt, site terms, rate limits, privacy laws, and
applicable computer-misuse legislation. Do not use it to harass, stalk, dox, discriminate
against, or surveil anyone.

A username match, shared email address, or metadata field is an investigative lead — not proof
of identity. Document your lawful basis, corroborate findings independently, and delete data
that is no longer needed.

You are responsible for how you use this tool.

---

**ARGUS 1.0.0** · zero dependencies · Node 18+ · local-only · MIT
