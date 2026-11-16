import { fetchLimited, parseJson, stripHtml, truncate } from './util.mjs';

const clean = (value) => (value == null ? '' : String(value).trim());

const proofLabels = {
  twitter: 'X / Twitter',
  github: 'GitHub',
  reddit: 'Reddit',
  hackernews: 'Hacker News',
  dns: 'DNS',
  pgp: 'PGP key',
  website: 'Website',
  https: 'HTTPS',
  btc: 'Bitcoin',
  zcash: 'Zcash',
  stellar: 'Stellar',
  keybase: 'Keybase',
};

/* ------------------------------------------------------------------ */
/* GitHub                                                              */
/* ------------------------------------------------------------------ */

async function github({ username, timeout }) {
  const res = await fetchLimited(`https://api.github.com/users/${encodeURIComponent(username)}`, {
    timeout,
    maxBytes: 200_000,
    headers: { accept: 'application/vnd.github+json' },
  });

  if (res.error) return { error: `GitHub API request failed: ${res.error}` };
  if (res.status === 404) return { error: 'GitHub profile page exists, but the API reports 404 (possible rate limit or rename).' };
  if ([403, 429].includes(res.status)) {
    return { error: `GitHub API rate limit or access denied (HTTP ${res.status}).` };
  }

  const data = parseJson(res.text);
  if (!data?.login) return { error: `Unexpected GitHub API response (HTTP ${res.status}).` };

  const fields = [
    { label: 'Name', value: data.name },
    { label: 'Bio', value: truncate(data.bio, 300) },
    { label: 'Company', value: data.company },
    { label: 'Location', value: data.location },
    {
      label: 'Blog',
      value: data.blog,
      url: /^https?:\/\//i.test(data.blog || '') ? data.blog : undefined,
    },
    { label: 'Public email', value: data.email },
    {
      label: 'X / Twitter',
      value: data.twitter_username ? `@${data.twitter_username}` : '',
      url: data.twitter_username ? `https://x.com/${data.twitter_username}` : undefined,
    },
    { label: 'Public repos', value: data.public_repos != null ? String(data.public_repos) : '' },
    { label: 'Gists', value: data.public_gists != null ? String(data.public_gists) : '' },
    { label: 'Followers', value: data.followers != null ? String(data.followers) : '' },
    { label: 'Following', value: data.following != null ? String(data.following) : '' },
    {
      label: 'Joined',
      value: data.created_at ? new Date(data.created_at).toISOString().slice(0, 10) : '',
    },
    { label: 'Hireable', value: data.hireable ? 'yes' : '' },
  ].filter((field) => field.value);

  return {
    fields,
    links: [
      { label: 'GitHub profile', url: data.html_url },
      { label: 'Avatar', url: data.avatar_url },
      ...(data.blog && /^https?:\/\//i.test(data.blog)
        ? [{ label: 'Personal site', url: data.blog }]
        : []),
    ],
  };
}

/* ------------------------------------------------------------------ */
/* Reddit                                                              */
/* ------------------------------------------------------------------ */

async function reddit({ username, timeout }) {
  const res = await fetchLimited(
    `https://www.reddit.com/user/${encodeURIComponent(username)}/about.json?raw_json=1`,
    {
      timeout,
      maxBytes: 300_000,
      headers: { accept: 'application/json' },
    },
  );

  if (res.error) return { error: `Reddit request failed: ${res.error}` };
  if (res.status === 404) return { error: 'Reddit profile page exists, but the JSON endpoint reports 404.' };
  if ([403, 429].includes(res.status)) return { error: `Reddit rate limit or access denied (HTTP ${res.status}).` };

  const data = parseJson(res.text)?.data;
  if (!data) return { error: `Unexpected Reddit API response (HTTP ${res.status}).` };

  const profile = data.subreddit || {};
  const fields = [
    { label: 'Display name', value: data.name },
    { label: 'Created', value: data.created_utc ? new Date(data.created_utc * 1000).toISOString().slice(0, 10) : '' },
    { label: 'Total karma', value: data.total_karma != null ? String(data.total_karma) : '' },
    { label: 'Post karma', value: data.link_karma != null ? String(data.link_karma) : '' },
    { label: 'Comment karma', value: data.comment_karma != null ? String(data.comment_karma) : '' },
    { label: 'Verified', value: data.verified ? 'yes' : '' },
    { label: 'Employee', value: data.is_employee ? 'yes' : '' },
    { label: 'Suspended', value: data.is_suspended ? 'yes' : '' },
    { label: 'NSFW profile', value: data.over_18 ? 'yes' : '' },
    { label: 'Profile title', value: profile.title },
    { label: 'Profile description', value: truncate(stripHtml(profile.public_description || ''), 300) },
    { label: 'Subscribers', value: profile.subscribers != null ? String(profile.subscribers) : '' },
  ].filter((field) => field.value);

  return {
    fields,
    links: [
      { label: 'Reddit profile', url: `https://www.reddit.com/user/${username}` },
      ...(data.icon_img ? [{ label: 'Avatar', url: data.icon_img.split('?')[0] }] : []),
    ],
  };
}

/* ------------------------------------------------------------------ */
/* Hacker News (Algolia)                                               */
/* ------------------------------------------------------------------ */

async function hackernews({ username, timeout }) {
  const res = await fetchLimited(
    `https://hn.algolia.com/api/v1/users/${encodeURIComponent(username)}`,
    { timeout, maxBytes: 150_000, headers: { accept: 'application/json' } },
  );

  if (res.error) return { error: `Hacker News API request failed: ${res.error}` };
  if (res.status === 404) return { error: 'Hacker News page exists, but the Algolia API reports 404.' };

  const data = parseJson(res.text);
  if (!data?.username) return { error: `Unexpected Hacker News API response (HTTP ${res.status}).` };

  const fields = [
    { label: 'Karma', value: data.karma != null ? String(data.karma) : '' },
    { label: 'Joined', value: data.created_at ? new Date(data.created_at).toISOString().slice(0, 10) : '' },
    { label: 'About', value: truncate(stripHtml(data.about || ''), 300) },
  ].filter((field) => field.value);

  return {
    fields,
    links: [{ label: 'Hacker News profile', url: `https://news.ycombinator.com/user?id=${username}` }],
  };
}

/* ------------------------------------------------------------------ */
/* Keybase                                                             */
/* ------------------------------------------------------------------ */

async function keybase({ username, timeout }) {
  const res = await fetchLimited(
    `https://keybase.io/_/api/1.0/user/lookup.json?username=${encodeURIComponent(username)}&fields=basics,profile,proofs_summary,pictures`,
    { timeout, maxBytes: 400_000, headers: { accept: 'application/json' } },
  );

  if (res.error) return { error: `Keybase API request failed: ${res.error}` };
  if ([403, 429].includes(res.status)) return { error: `Keybase rate limit or access denied (HTTP ${res.status}).` };

  const data = parseJson(res.text);
  if (data?.status?.code !== 0) return { error: `Keybase API error: ${data?.status?.desc || `HTTP ${res.status}`}` };

  const them = data.them?.[0];
  if (!them) return { error: 'Keybase returned no public profile details.' };

  const profile = them.profile || {};
  const proofs = them.proofs_summary?.all || [];
  const verified = proofs.filter((proof) => proof.state === 1);

  const fields = [
    { label: 'Full name', value: profile.full_name },
    { label: 'Location', value: profile.location },
    { label: 'Bio', value: truncate(profile.bio, 300) },
    {
      label: 'Joined',
      value: them.basics?.ctime ? new Date(them.basics.ctime * 1000).toISOString().slice(0, 10) : '',
    },
    { label: 'Verified proofs', value: String(verified.length) },
  ].filter((field) => field.value);

  const links = [{ label: 'Keybase profile', url: `https://keybase.io/${username}` }];
  for (const proof of proofs) {
    if (!proof.human_url) continue;
    const label = proofLabels[proof.proof_type] || proof.proof_type;
    links.push({
      label: `${label}: ${proof.nametag}${proof.state === 1 ? ' ✓' : ' (pending)'}`,
      url: proof.human_url,
    });
  }

  return {
    fields,
    links,
    note: 'Keybase proofs are self-published by the account owner; ARGUS has not verified ownership.',
  };
}

export const ENRICHERS = { github, reddit, hackernews, keybase };
