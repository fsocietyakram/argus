import dns from 'node:dns/promises';
import { domainToASCII } from 'node:url';
import {
  fetchLimited,
  md5,
  parseJson,
  stripHtml,
  truncate,
  uniq,
  withTimeout,
} from './util.mjs';

export const DISPOSABLE_DOMAINS = new Set(
  `10minutemail.com 20minutemail.com 33mail.com anonbox.net anonmails.de antipow.com armyspy.com binkmail.com bobmail.info bofthew.com bugmenot.com bund.us byom.de clrmail.com cool.fr.nf correo.blogos.net cosmorph.com courriel.fr.nf cuvox.de dandikmail.com deadaddress.com despammed.com discard.email discardmail.com discardmail.de disposableaddress.com disposableemail.co.uk dispose.it disposeamail.com disposemail.com dodgit.com dodgit.org dongyang.com dontreg.com dropmail.me edv.to email60.com emaildienst.de emailgo.de emailias.com emailinfive.com emailmiser.com emailondeck.com emailtemporario.com.br emailthe.net emailtmp.com emailwarden.com enterto.com ephemail.net etranquil.com evopo.com explodemail.com fakeinbox.com fakeinformation.com fastacura.com fastchevy.com fastchrysler.com fastkawasaki.com fastmazda.com fastmitsubishi.com fastnissan.com fastsubaru.com fastsuzuki.com fasttoyota.com fastyamaha.com filzmail.com fixmail.tk flyspam.com fraudno.com garbagemail.org getairmail.com getonemail.com gishpuppy.com gmailbox.org grr.la guerrillamail.com guerrillamail.de guerrillamail.info guerrillamail.net guerrillamail.org guerrillamailblock.com gustr.com haltospam.com hat-geld.de hushmail.com ieatspam.eu imgof.com imstations.com incognitomail.com inboxkitten.com ipoo.org irish2me.com jetable.com jetable.fr.nf jetable.net jetable.org jnkpc.com kasmail.com klassmaster.com klzlk.com koszmail.pl kurzepost.de lackmail.net letthemeatspam.com lhosep.com lookugly.com lortemail.dk lroid.com maileater.com mailexpire.com mailforspam.com mailimate.com mailin8r.com mailinator.com mailinator.net mailinator2.com mailincubator.com mailmetrash.com mailmoat.com mailnator.com mailnesia.com mailnull.com mailshell.com mailsiphon.com mailslite.com mailtemp.info mailtome.de mailzilla.com meltmail.com messagebeamer.de mintemail.com moakt.com mvrht.com mycleaninbox.net mytrashmail.com neverbox.com no-spam.ws no-spam.ws no-ux.com nomail.xl.cx nospamfor.us nospamthanks.info notmailinator.com nowmymail.com objectmail.com obobbo.com oneoffemail.com onewaymail.com owlpic.com pokemail.net politikerclub.de pookmail.com privy-mail.com proxymail.eu punkass.com putthisinyourspamdatabase.com rcpt.at recode.me recyclingmail.com rejectmail.com rhyta.com safersignup.de safetymail.info sandelf.de saynotospams.com schafmail.de selfdestructingmail.com sharklasers.com shitmail.me shortmail.net sjua.com smspam.com snakemail.com sneakemail.com sofort-mail.de sogetthis.com soodonims.com spam.la spam.su spam4.me spamavert.com spambob.com spamcorptastic.com spamcowboy.com spamday.com spamex.com spamfree24.com spamgourmet.com spamgourmet.net spamgourmet.org spamherelots.com spamify.com spaminator.de spamkill.info spaml.com spamobox.com spamev.com spamspot.com spamthis.co.uk spamtraps.net spamtroll.net speed.1s.fr supergreatmail.com supermailer.jp suremail.info tafmail.com teewars.org teleworm.com teleworm.us temp-mail.com temp-mail.de tempail.com tempalias.com tempemail.biz tempemail.co.za tempemail.com tempinbox.co.uk tempinbox.com tempmail.eu tempmail.it tempmail2.com tempomail.fr temporarioemail.com.br temporaryemail.net temporaryforwarding.com temporaryinbox.com tempsky.com tempthe.net thankyou2010.com thisisnotmyrealemail.com throwam.com throwam.net throwawayemailaddress.com tilien.com tmailinator.com tradermail.info trash-mail.com trash-mail.de trash2009.com trashdevil.com trashemail.de trashmail.com trashmail.de trashmail.net trashymail.com trimail.com trivial.xyz turual.com tvchd.com tweakly.com tyldd.com ugmail.com venoded.com viditag.com viewcastmedia.com vomoto.com vubby.com w3internet.co.uk walala.org webemail.me webm4il.info wegwerfadresse.de wegwerfemail.de wegwerfmail.de wegwerfmail.net wegwerfmail.org whyspam.me wikidocus.com willhackforfood.biz willselfdestruct.com winemaven.info wronghead.com wuzup.net xagloo.com xemaps.com xents.com xmaily.com xoxy.net yep.it yogamaven.com yopmail.com yopmail.fr yopmail.net ypmail.web.id yuurok.com zehnminuten.de zippymail.info zoemail.net zoemail.org zomg.info`
    .split(/\s+/)
    .filter(Boolean),
);

export const ROLE_ACCOUNTS = new Set(
  `admin administrator billing contact hello help info inquiries jobs marketing noreply no-reply office postmaster press privacy sales security support team webmaster abuse legal hr recruitment careers it accounts finance newsletter alerts notifications`.split(
    /\s+/,
  ),
);

export function gravatarHash(email) {
  return md5(String(email).trim().toLowerCase());
}

export function parseEmail(input) {
  const email = String(input ?? '').trim();
  if (!email) return { valid: false, reason: 'Email is required.', email };
  if (email.length > 254) return { valid: false, reason: 'Email is longer than 254 characters.', email };
  if (email.includes(' ')) return { valid: false, reason: 'Email must not contain spaces.', email };

  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) {
    return { valid: false, reason: 'Email must contain one @ with text on both sides.', email };
  }

  const local = email.slice(0, at);
  const domain = email.slice(at + 1).toLowerCase();

  if (local.length > 64) return { valid: false, reason: 'Local part is longer than 64 characters.', email };
  if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) {
    return { valid: false, reason: 'Local part contains unsupported characters.', email };
  }
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    return { valid: false, reason: 'Local part has invalid dot placement.', email };
  }

  const asciiDomain = domainToASCII(domain);
  if (!asciiDomain) return { valid: false, reason: 'Domain is not valid internationalised text.', email };
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(asciiDomain)) {
    if (!/^\[[0-9a-f:.]+\]$/i.test(domain)) {
      return { valid: false, reason: 'Domain does not look like a valid hostname.', email };
    }
  }

  return {
    valid: true,
    email,
    normalized: `${local.toLowerCase()}@${asciiDomain}`,
    local,
    domain: asciiDomain,
  };
}

async function safe(fn, ms, label) {
  try {
    return { value: await withTimeout(fn(), ms, label) };
  } catch (err) {
    return { error: err?.code || err?.message || String(err) };
  }
}

function parseTagString(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    tags[part.slice(0, index).trim().toLowerCase()] = part.slice(index + 1).trim();
  }
  return tags;
}

const asStrings = (records) => (records || []).map((chunks) => chunks.join(''));

/**
 * DNS / email-authentication intelligence for a domain.
 * Shared by the email and domain commands.
 */
export async function dnsIntel(domain, options = {}) {
  const timeout = options.timeout ?? 8000;
  const includeDkim = options.dkim !== false;

  const [mx, a, aaaa, ns, txtRecords, soa] = await Promise.all([
    safe(() => dns.resolveMx(domain), timeout, 'MX lookup'),
    safe(() => dns.resolve4(domain), timeout, 'A lookup'),
    safe(() => dns.resolve6(domain), timeout, 'AAAA lookup'),
    safe(() => dns.resolveNs(domain), timeout, 'NS lookup'),
    safe(() => dns.resolveTxt(domain), timeout, 'TXT lookup'),
    safe(() => dns.resolveSoa(domain), timeout, 'SOA lookup'),
  ]);

  const txt = txtRecords.value ? asStrings(txtRecords.value) : [];
  const spfRecord = txt.find((record) => /^v=spf1(\s|$)/i.test(record)) || null;

  const dmarcQuery = await safe(
    () => dns.resolveTxt(`_dmarc.${domain}`),
    timeout,
    'DMARC lookup',
  );
  const dmarcTxt = dmarcQuery.value ? asStrings(dmarcQuery.value) : [];
  const dmarcRecord = dmarcTxt.find((record) => /^v=DMARC1\s*;/i.test(record)) || null;
  const dmarcTags = dmarcRecord ? parseTagString(dmarcRecord) : null;

  let dkim = null;
  if (includeDkim) {
    const selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 's1', 's2'];
    const checks = await Promise.all(
      selectors.map(async (selector) => {
        const name = `${selector}._domainkey.${domain}`;
        const result = await safe(() => dns.resolveTxt(name), 5000, `DKIM ${selector}`);
        const records = result.value ? asStrings(result.value) : [];
        const record = records.find((value) => /v=DKIM1|k=rsa|p=/i.test(value));
        return record ? { selector, name, record: truncate(record, 160) } : null;
      }),
    );
    dkim = { checkedSelectors: selectors, found: checks.filter(Boolean) };
  }

  const errors = Object.entries({ mx, a, aaaa, ns, txt, soa }).filter(([, r]) => r.error).map(
    ([key, r]) => `${key.toUpperCase()}: ${r.error}`,
  );

  const mxRecords = mx.value || [];
  const nullMx = mxRecords.some((record) => !record.exchange || record.exchange === '.');
  const usableMx = mxRecords
    .filter((record) => record.exchange && record.exchange !== '.')
    .sort((x, y) => x.priority - y.priority);

  return {
    domain,
    mx: usableMx,
    nullMx,
    a: a.value || [],
    aaaa: aaaa.value || [],
    ns: ns.value || [],
    soa: soa.value || null,
    txt,
    spf: { present: Boolean(spfRecord), record: spfRecord, valid: Boolean(spfRecord && /[-~+?]all\b/i.test(spfRecord)) },
    dmarc: {
      present: Boolean(dmarcRecord),
      record: dmarcRecord,
      tags: dmarcTags,
      policy: dmarcTags?.p || null,
      subdomainPolicy: dmarcTags?.sp || null,
    },
    dkim,
    hasMx: usableMx.length > 0,
    hasA: (a.value || []).length > 0,
    implicitMx: usableMx.length === 0 && !nullMx && (a.value || []).length > 0,
    errors,
  };
}

async function checkGravatar(email, timeout) {
  const hash = gravatarHash(email);
  const res = await fetchLimited(`https://gravatar.com/${hash}.json`, {
    timeout,
    maxBytes: 300_000,
    headers: { accept: 'application/json' },
  });

  if (res.error) return { checked: true, found: false, error: res.error, hash };
  if (res.status === 404) return { checked: true, found: false, hash };
  if (res.status !== 200) {
    return {
      checked: true,
      found: false,
      hash,
      error: `Gravatar returned HTTP ${res.status}`,
    };
  }

  const payload = parseJson(res.text);
  const entry = payload?.entry?.[0];
  if (!entry) return { checked: true, found: false, hash };

  const accounts = Array.isArray(entry.accounts)
    ? entry.accounts.map((account) => ({
        domain: account.domain,
        display: account.display,
        username: account.username,
        url: account.url,
        verified: Boolean(account.verified),
      }))
    : [];

  return {
    checked: true,
    found: true,
    hash,
    avatarUrl: `https://gravatar.com/avatar/${hash}`,
    profileUrl: entry.profileUrl,
    profile: {
      displayName: entry.displayName,
      preferredUsername: entry.preferredUsername,
      aboutMe: truncate(stripHtml(entry.aboutMe || ''), 300),
      currentLocation: entry.currentLocation,
      accounts,
    },
  };
}

async function checkHibp(email, config, timeout) {
  const envName = config.settings?.hibpApiKeyEnv || 'HIBP_API_KEY';
  const key = process.env[envName];
  if (!key) {
    return {
      checked: false,
      available: false,
      reason: `No ${envName} set. Breach lookup is optional and uses the Have I Been Pwned API.`,
    };
  }

  const res = await fetchLimited(
    `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
    {
      timeout,
      maxBytes: 600_000,
      headers: {
        accept: 'application/json',
        'hibp-api-key': key,
        'user-agent': 'Argus-OSINT',
      },
    },
  );

  if (res.error) return { checked: true, available: true, error: res.error, breaches: [] };
  if (res.status === 404) return { checked: true, available: true, breaches: [] };
  if (res.status === 401) {
    return { checked: true, available: false, reason: 'HIBP rejected the API key (401).', breaches: [] };
  }
  if (res.status === 429) {
    return {
      checked: true,
      available: false,
      reason: `HIBP rate limit reached${res.headers['retry-after'] ? `; retry after ${res.headers['retry-after']}s` : ''}.`,
      breaches: [],
    };
  }

  const data = parseJson(res.text);
  if (!Array.isArray(data)) {
    return { checked: true, available: true, error: `Unexpected HIBP response (HTTP ${res.status}).`, breaches: [] };
  }

  return {
    checked: true,
    available: true,
    breaches: data.map((breach) => ({
      name: breach.Name,
      title: breach.Title,
      domain: breach.Domain,
      breachDate: breach.BreachDate,
      addedDate: breach.AddedDate,
      pwnCount: breach.PwnCount,
      dataClasses: breach.DataClasses || [],
      verified: Boolean(breach.IsVerified),
      sensitive: Boolean(breach.IsSensitive),
    })),
  };
}

async function checkGithubMentions(email, timeout) {
  const res = await fetchLimited(
    `https://api.github.com/search/users?q=${encodeURIComponent(email)}+in:email&per_page=5`,
    {
      timeout,
      maxBytes: 200_000,
      headers: { accept: 'application/vnd.github+json' },
    },
  );

  if (res.error) return { checked: true, error: res.error, users: [] };
  if ([403, 429].includes(res.status)) {
    return { checked: true, error: `GitHub search rate-limited (HTTP ${res.status}).`, users: [] };
  }

  const data = parseJson(res.text);
  if (!data?.items) return { checked: true, users: [], count: 0 };

  return {
    checked: true,
    count: data.total_count || data.items.length,
    users: data.items.slice(0, 5).map((user) => ({
      login: user.login,
      url: user.html_url,
    })),
  };
}

function candidateUsernames(localPart) {
  const base = localPart.split('+')[0];
  const candidates = uniq([
    base.replace(/[^A-Za-z0-9._-]/g, ''),
    base.replace(/[._-]/g, ''),
    base.replace(/[._]/g, '-'),
  ]).filter(
    (candidate) =>
      candidate.length >= 3 &&
      candidate.length <= 40 &&
      /^[\p{L}\p{N}._-]+$/u.test(candidate),
  );
  return candidates.slice(0, 2);
}

function riskFor({ syntax, dns, gravatar, breaches }) {
  const findings = [];
  let score = 0;
  const add = (points, text) => {
    score += points;
    findings.push({ points, text });
  };

  if (!syntax.valid) add(100, `Email syntax is invalid: ${syntax.reason}`);
  if (syntax.valid && !dns.hasMx && !dns.implicitMx) add(40, 'Domain has no MX records, so it likely cannot receive email.');
  if (syntax.valid && DISPOSABLE_DOMAINS.has(syntax.domain)) add(30, 'Domain is a known disposable-email provider.');
  if (syntax.valid && ROLE_ACCOUNTS.has(String(syntax.local || '').toLowerCase().split(/[+.]/)[0])) {
    add(10, 'Local part looks like a shared role account.');
  }
  if (breaches.breaches?.length) {
    add(Math.min(30, breaches.breaches.length * 10), `Address appears in ${breaches.breaches.length} public breach record(s).`);
  }
  if (gravatar.found) add(5, 'A public Gravatar profile is linked to this address.');
  if (!dns.spf?.present) add(5, 'Domain publishes no SPF record.');
  if (!dns.dmarc?.present) add(10, 'Domain publishes no DMARC record.');

  score = Math.min(100, score);
  const level = score >= 60 ? 'high' : score >= 30 ? 'medium' : score > 0 ? 'low' : 'none';
  return { score, level, findings };
}

export async function scanEmail(input, options = {}) {
  const { loadConfig } = await import('./config.mjs');
  const config = options.config || loadConfig();
  const startedAt = new Date();
  const started = Date.now();
  const timeout = options.timeoutMs ?? config.settings.timeoutMs ?? 12_000;

  const syntax = parseEmail(input);
  if (!syntax.valid) {
    const dnsEmpty = { hasMx: false, hasA: false, implicitMx: false, spf: {}, dmarc: {}, errors: [] };
    return {
      schema: 'argus.report/v1',
      command: 'email',
      tool: { name: 'ARGUS', version: '1.0.0' },
      target: syntax.email,
      createdAt: startedAt.toISOString(),
      durationMs: Date.now() - started,
      syntax,
      dns: dnsEmpty,
      gravatar: { checked: false, found: false },
      breaches: { checked: false, available: false, breaches: [] },
      publicMentions: {},
      linked: { requested: false, candidates: [], scans: [] },
      risk: { score: 100, level: 'high', findings: [{ points: 100, text: syntax.reason }] },
      notes: ['The address failed syntax validation, so no external lookups were made.'],
    };
  }

  const email = syntax.normalized;

  const [dnsData, gravatar, breaches, mentions] = await Promise.all([
    dnsIntel(syntax.domain, { timeout, dkim: true }),
    checkGravatar(email, timeout),
    checkHibp(email, config, timeout),
    checkGithubMentions(email, timeout),
  ]);

  let linked = { requested: Boolean(options.linked), candidates: [], scans: [] };
  if (options.linked) {
    const { scanUsername } = await import('./username.mjs');
    const candidates = candidateUsernames(syntax.local);
    linked.candidates = candidates;
    for (const candidate of candidates) {
      try {
        const scan = await scanUsername(candidate, {
          config,
          concurrency: Math.min(8, config.settings?.concurrency ?? 8),
          timeoutMs: timeout,
        });
        linked.scans.push({
          username: candidate,
          summary: scan.summary,
          findings: scan.findings
            .filter((finding) => ['confirmed', 'possible'].includes(finding.status))
            .slice(0, 15)
            .map((finding) => ({
              name: finding.name,
              url: finding.url,
              status: finding.status,
              confidence: finding.confidence,
            })),
        });
      } catch (err) {
        linked.scans.push({ username: candidate, error: err.message, summary: null, findings: [] });
      }
    }
  }

  const risk = riskFor({ syntax, dns: dnsData, gravatar, breaches });

  return {
    schema: 'argus.report/v1',
    command: 'email',
    tool: { name: 'ARGUS', version: '1.0.0' },
    target: email,
    createdAt: startedAt.toISOString(),
    durationMs: Date.now() - started,
    syntax,
    dns: dnsData,
    gravatar,
    breaches,
    publicMentions: {
      github: mentions,
    },
    linked,
    risk,
    notes: [
      'No login, password reset, inbox access, or account-access attempt was made.',
      'Breach data is limited to breach metadata from Have I Been Pwned; no passwords or tokens are collected.',
      'The exposure score describes publicly observable email/domain hygiene, not the security of a person.',
      'A shared email or username does not prove identity; confirm with independent evidence.',
      'Gravatar and GitHub email search only reveal information that the owner chose to make public.',
    ],
  };
}
