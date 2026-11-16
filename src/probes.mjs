import { fetchLimited, parseJson, stripHtml, truncate } from './util.mjs';

const iso = (unixSeconds) =>
  unixSeconds ? new Date(unixSeconds * 1000).toISOString() : undefined;

const boolean = (value) => (value === true ? 'yes' : value === false ? 'no' : undefined);

function steamField(xml, tag) {
  const cdata = xml.match(new RegExp(`<${tag}><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>`, 'i'));
  if (cdata) return cdata[1].trim();
  const plain = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'i'));
  return plain ? plain[1].trim() : '';
}

/* ------------------------------------------------------------------ */
/* Steam                                                               */
/* ------------------------------------------------------------------ */

async function steam({ username, timeout }) {
  const profileUrl = `https://steamcommunity.com/id/${encodeURIComponent(username)}/`;
  const res = await fetchLimited(`${profileUrl}?xml=1`, {
    timeout,
    maxBytes: 200_000,
  });

  if (res.error) return { status: 'error', detail: `Request failed: ${res.error}` };
  if (res.status === 404 || /<error>/i.test(res.text)) {
    return { status: 'absent', detail: 'No Steam vanity URL with this name' };
  }
  if (!/<steamID64>/i.test(res.text)) {
    if ([403, 429].includes(res.status)) {
      return { status: 'blocked', detail: `HTTP ${res.status}` };
    }
    return { status: 'error', detail: `Unexpected response (HTTP ${res.status})` };
  }

  const fields = [
    { label: 'SteamID64', value: steamField(res.text, 'steamID64') },
    { label: 'SteamID', value: steamField(res.text, 'steamID') },
    { label: 'Real name', value: steamField(res.text, 'realname') },
    { label: 'Location', value: steamField(res.text, 'location') },
    { label: 'Member since', value: steamField(res.text, 'memberSince') },
    { label: 'Privacy', value: steamField(res.text, 'privacyState') },
    { label: 'Status', value: steamField(res.text, 'stateMessage') },
    { label: 'Summary', value: truncate(steamField(res.text, 'summary'), 300) },
  ].filter((field) => field.value);

  const avatar = steamField(res.text, 'avatarFull');

  return {
    status: 'confirmed',
    confidence: 'high',
    detail: 'Public Steam profile XML',
    profile: {
      fields,
      links: [
        { label: 'Steam profile', url: profileUrl },
        ...(avatar ? [{ label: 'Avatar', url: avatar }] : []),
      ],
    },
  };
}

/* ------------------------------------------------------------------ */
/* Mastodon                                                            */
/* ------------------------------------------------------------------ */

async function mastodon({ username, timeout }) {
  const lookupUrl = `https://mastodon.social/api/v1/accounts/lookup?acct=${encodeURIComponent(username)}`;
  const res = await fetchLimited(lookupUrl, {
    timeout,
    maxBytes: 250_000,
    headers: { accept: 'application/json' },
  });

  if (res.error) return { status: 'error', detail: `Request failed: ${res.error}` };
  if (res.status === 404) return { status: 'absent', detail: 'No such account on mastodon.social' };
  if ([401, 403, 429].includes(res.status)) return { status: 'blocked', detail: `HTTP ${res.status}` };

  const account = parseJson(res.text);
  if (!account || !account.username) {
    return { status: 'error', detail: `Unexpected API response (HTTP ${res.status})` };
  }

  const fields = [
    { label: 'Display name', value: account.display_name },
    { label: 'Bio', value: truncate(stripHtml(account.note || ''), 300) },
    { label: 'Followers', value: String(account.followers_count ?? '') },
    { label: 'Following', value: String(account.following_count ?? '') },
    { label: 'Posts', value: String(account.statuses_count ?? '') },
    { label: 'Joined', value: account.created_at },
    { label: 'Bot account', value: boolean(account.bot) },
    { label: 'Locked', value: boolean(account.locked) },
    ...(Array.isArray(account.fields)
      ? account.fields
          .filter((f) => f.value)
          .map((f) => ({
            label: stripHtml(f.name || 'Profile field'),
            value: truncate(stripHtml(f.value), 160),
            url: /^https?:\/\//i.test(stripHtml(f.value)) ? stripHtml(f.value) : undefined,
          }))
      : []),
  ].filter((field) => field.value);

  return {
    status: 'confirmed',
    confidence: 'high',
    detail: 'Public mastodon.social account lookup',
    profile: {
      fields,
      links: [{ label: 'Mastodon profile', url: account.url || `https://mastodon.social/@${username}` }],
      raw: { id: account.id, acct: account.acct, createdAt: account.created_at },
    },
  };
}

/* ------------------------------------------------------------------ */
/* Bluesky                                                             */
/* ------------------------------------------------------------------ */

async function bluesky({ username, timeout }) {
  const handle = username.includes('.') ? username : `${username}.bsky.social`;
  const resolveUrl = `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`;
  const resolved = await fetchLimited(resolveUrl, {
    timeout,
    maxBytes: 100_000,
    headers: { accept: 'application/json' },
  });

  if (resolved.error) return { status: 'error', detail: `Request failed: ${resolved.error}` };
  if (resolved.status === 400 || resolved.status === 404) {
    return { status: 'absent', detail: `No Bluesky handle ${handle}` };
  }
  if ([401, 403, 429].includes(resolved.status)) {
    return { status: 'blocked', detail: `HTTP ${resolved.status}` };
  }

  const identity = parseJson(resolved.text);
  if (!identity?.did) {
    return { status: 'error', detail: `Unexpected resolveHandle response (HTTP ${resolved.status})` };
  }

  const profileRes = await fetchLimited(
    `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(identity.did)}`,
    { timeout, maxBytes: 300_000, headers: { accept: 'application/json' } },
  );

  const profile = parseJson(profileRes.text);
  if (profileRes.status !== 200 || !profile) {
    return {
      status: 'blocked',
      detail: `Handle resolves, but profile is unavailable (HTTP ${profileRes.status})`,
      profile: { fields: [{ label: 'DID', value: identity.did }], links: [] },
    };
  }

  const fields = [
    { label: 'Display name', value: profile.displayName },
    { label: 'Bio', value: truncate(profile.description || '', 300) },
    { label: 'Followers', value: String(profile.followersCount ?? '') },
    { label: 'Following', value: String(profile.followsCount ?? '') },
    { label: 'Posts', value: String(profile.postsCount ?? '') },
    { label: 'Joined', value: profile.createdAt },
    { label: 'DID', value: profile.did },
  ].filter((field) => field.value);

  return {
    status: 'confirmed',
    confidence: 'high',
    detail: `Public Bluesky profile (${handle})`,
    profile: {
      fields,
      links: [
        { label: 'Bluesky profile', url: `https://bsky.app/profile/${handle}` },
        ...(profile.avatar ? [{ label: 'Avatar', url: profile.avatar }] : []),
      ],
      raw: { did: profile.did, handle },
    },
  };
}

/* ------------------------------------------------------------------ */
/* Stack Overflow                                                      */
/* ------------------------------------------------------------------ */

async function stackoverflow({ username, timeout }) {
  const url = `https://api.stackexchange.com/2.3/users?inname=${encodeURIComponent(username)}&site=stackoverflow&pagesize=30&filter=default`;
  const res = await fetchLimited(url, {
    timeout,
    maxBytes: 500_000,
    headers: { accept: 'application/json' },
  });

  if (res.error) return { status: 'error', detail: `Request failed: ${res.error}` };
  if ([400, 403, 429].includes(res.status)) return { status: 'blocked', detail: `HTTP ${res.status}` };

  const data = parseJson(res.text);
  if (!data || !Array.isArray(data.items)) {
    return { status: 'error', detail: `Unexpected API response (HTTP ${res.status})` };
  }

  const match = data.items.find(
    (item) => String(item.display_name || '').toLowerCase() === username.toLowerCase(),
  );

  if (!match) {
    return {
      status: 'absent',
      detail: `No user with the exact display name "${username}" (${data.items.length} similar found)`,
    };
  }

  const fields = [
    { label: 'Display name', value: match.display_name },
    { label: 'Reputation', value: String(match.reputation ?? '') },
    {
      label: 'Badges',
      value: `${match.badge_counts?.gold ?? 0} gold / ${match.badge_counts?.silver ?? 0} silver / ${match.badge_counts?.bronze ?? 0} bronze`,
    },
    { label: 'Location', value: match.location },
    { label: 'Website', value: match.website_url },
    { label: 'Joined', value: iso(match.creation_date) },
    { label: 'Last active', value: iso(match.last_access_date) },
  ].filter((field) => field.value);

  return {
    status: 'confirmed',
    confidence: 'medium',
    detail: 'Exact Stack Overflow display-name match (display names are not unique)',
    profile: {
      fields,
      links: match.link ? [{ label: 'Stack Overflow profile', url: match.link }] : [],
      raw: { user_id: match.user_id, link: match.link },
    },
  };
}

/* ------------------------------------------------------------------ */
/* Docker Hub                                                          */
/* ------------------------------------------------------------------ */

async function dockerhub({ username, timeout }) {
  const url = `https://hub.docker.com/v2/users/${encodeURIComponent(username)}/`;
  const res = await fetchLimited(url, {
    timeout,
    maxBytes: 150_000,
    headers: { accept: 'application/json' },
  });

  if (res.error) return { status: 'error', detail: `Request failed: ${res.error}` };
  if (res.status === 404) return { status: 'absent', detail: 'No Docker Hub user' };
  if ([401, 403, 429].includes(res.status)) return { status: 'blocked', detail: `HTTP ${res.status}` };

  const data = parseJson(res.text);
  if (res.status !== 200 || !data?.username) {
    return { status: 'error', detail: `Unexpected API response (HTTP ${res.status})` };
  }

  const fields = [
    { label: 'Username', value: data.username },
    { label: 'Full name', value: data.full_name },
    { label: 'Company', value: data.company },
    { label: 'Location', value: data.location },
    { label: 'Joined', value: data.date_joined },
    { label: 'Account type', value: data.type },
  ].filter((field) => field.value);

  return {
    status: 'confirmed',
    confidence: 'high',
    detail: 'Public Docker Hub user API',
    profile: {
      fields,
      links: [
        { label: 'Docker Hub profile', url: `https://hub.docker.com/u/${username}` },
        ...(data.profile_url ? [{ label: 'Profile URL', url: data.profile_url }] : []),
      ],
      raw: { id: data.id },
    },
  };
}

async function codewars({ username, timeout }) {
  const res = await fetchLimited(`https://www.codewars.com/api/v1/users/${encodeURIComponent(username)}`, {
    timeout, maxBytes: 200_000, headers: { accept: 'application/json' },
  });
  if (res.error) return { status: 'error', detail: `Request failed: ${res.error}` };
  if (res.status === 404) return { status: 'absent', detail: 'No Codewars user with this username.' };
  if ([401, 403, 429].includes(res.status)) return { status: 'blocked', detail: `HTTP ${res.status}` };
  const data = parseJson(res.text);
  if (res.status !== 200 || !data?.username) return { status: 'error', detail: `Unexpected Codewars API response (HTTP ${res.status}).` };
  return {
    status: 'confirmed', confidence: 'high', detail: 'Public Codewars user API',
    profile: {
      fields: [
        { label: 'Username', value: data.username }, { label: 'Display name', value: data.name },
        { label: 'Honor', value: String(data.honor ?? '') }, { label: 'Clan', value: data.clan },
        { label: 'Overall rank', value: data.ranks?.overall?.name },
        { label: 'Completed challenges', value: String(data.codeChallenges?.totalCompleted ?? '') },
        { label: 'Skills', value: Array.isArray(data.skills) ? data.skills.join(', ') : '' },
      ].filter((field) => field.value),
      links: [{ label: 'Codewars profile', url: data.url || `https://www.codewars.com/users/${encodeURIComponent(username)}` }],
    },
  };
}

async function huggingface({ username, timeout }) {
  const res = await fetchLimited(`https://huggingface.co/api/users/${encodeURIComponent(username)}/overview`, {
    timeout, maxBytes: 200_000, headers: { accept: 'application/json' },
  });
  if (res.error) return { status: 'error', detail: `Request failed: ${res.error}` };
  if (res.status === 404) return { status: 'absent', detail: 'No public Hugging Face user overview.' };
  if ([401, 403, 429].includes(res.status)) return { status: 'blocked', detail: `HTTP ${res.status}` };
  const data = parseJson(res.text);
  const user = data?.user || data;
  const handle = user?.username || user?.name;
  if (res.status !== 200 || !handle) return { status: 'error', detail: `Unexpected Hugging Face API response (HTTP ${res.status}).` };
  return {
    status: 'confirmed', confidence: 'high', detail: 'Public Hugging Face Hub user overview API',
    profile: {
      fields: [
        { label: 'Username', value: handle }, { label: 'Full name', value: user.fullname || user.fullName },
        { label: 'Bio', value: user.bio }, { label: 'Followers', value: String(data.numFollowers ?? user.numFollowers ?? '') },
        { label: 'Public models', value: String(data.numModels ?? user.numModels ?? '') },
        { label: 'Public datasets', value: String(data.numDatasets ?? user.numDatasets ?? '') },
      ].filter((field) => field.value),
      links: [{ label: 'Hugging Face profile', url: `https://huggingface.co/${encodeURIComponent(handle)}` }],
    },
  };
}

export const PROBES = { steam, mastodon, bluesky, stackoverflow, dockerhub, codewars, huggingface };
