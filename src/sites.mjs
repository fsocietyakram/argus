/**
 * ARGUS source registry.
 *
 * Every connector is declared here with:
 *   - how it is accessed (public page, official API, or a custom probe)
 *   - how a hit is detected (HTTP status or body markers)
 *   - a confidence level (a username match is never proof of identity)
 *   - a polite rate limit and a terms-of-use note
 *   - whether robots.txt applies
 *
 * Sources can be disabled/enabled in argus.config.json or from the web UI.
 */

const GENERIC_TOS =
  'Public profile page, read-only. One user-initiated request; no login, interaction, or bypass.';

const page = (id, name, category, url, extra = {}) => ({
  id,
  name,
  category,
  access: 'page',
  url,
  check: 'status',
  enabled: true,
  respectRobots: true,
  rateLimit: 20,
  confidence: 'high',
  tos: GENERIC_TOS,
  ...extra,
});

const api = (id, name, category, url, probe, extra = {}) => ({
  id,
  name,
  category,
  access: 'api',
  url,
  probe,
  enabled: true,
  respectRobots: false,
  rateLimit: 20,
  confidence: 'high',
  tos: 'Official public API. Single user-initiated lookup; no credentials used.',
  ...extra,
});

export const SOURCES = [
  /* ----------------------------- social ----------------------------- */
  page('instagram', 'Instagram', 'social', 'https://www.instagram.com/{u}/', {
    check: 'marker',
    confidence: 'medium',
    notFound: [
      "sorry, this page isn't available",
      'the link you followed may be broken',
      'page not found',
    ],
    tos: 'Public profile page. Instagram may show a login wall; ARGUS never logs in.',
  }),
  page('x', 'X (Twitter)', 'social', 'https://x.com/{u}', {
    check: 'marker',
    confidence: 'medium',
    notFound: ['this account doesn’t exist', "this account doesn't exist", 'account doesn’t exist'],
    tos: 'Public profile page. X may require JavaScript or block automated requests.',
  }),
  page('reddit', 'Reddit', 'social', 'https://www.reddit.com/user/{u}', {
    confidence: 'high',
    enrich: 'reddit',
    tos: 'Public profile page and public about.json. No login.',
  }),
  page('tiktok', 'TikTok', 'social', 'https://www.tiktok.com/@{u}', {
    check: 'marker',
    confidence: 'medium',
    found: ['"uniqueid"'],
    notFound: ["couldn't find this account", 'could not find this account'],
  }),
  page('youtube', 'YouTube', 'social', 'https://www.youtube.com/@{u}', {
    check: 'marker',
    confidence: 'medium',
    found: ['"channelid"'],
    notFound: ["this page isn't available", '404 not found'],
  }),
  page('threads', 'Threads', 'social', 'https://www.threads.net/@{u}', {
    check: 'marker',
    confidence: 'medium',
    notFound: ["sorry, this page isn't available", "page isn't available"],
  }),
  page('pinterest', 'Pinterest', 'social', 'https://www.pinterest.com/{u}/', {
    check: 'marker',
    confidence: 'medium',
    notFound: ['user not found', "couldn't find that page", 'page not found'],
  }),
  page('tumblr', 'Tumblr', 'social', 'https://{u}.tumblr.com', {
    confidence: 'medium',
    tos: 'Public blog subdomain. Read-only; single request.',
  }),
  page('vk', 'VK', 'social', 'https://vk.com/{u}', {
    check: 'marker',
    confidence: 'low',
    notFound: ['user not found', 'page not found', 'ничего не найдено'],
  }),
  page('aboutme', 'About.me', 'social', 'https://about.me/{u}', {
    confidence: 'high',
  }),
  page('facebook', 'Facebook', 'social', 'https://www.facebook.com/{u}', {
    check: 'marker',
    confidence: 'low',
    enabled: false,
    notFound: ["this content isn't available", 'the link you followed may be broken'],
    tos: 'Public page. Facebook aggressively blocks non-browser clients; disabled by default.',
  }),

  /* ------------------------------- dev ------------------------------ */
  page('github', 'GitHub', 'dev', 'https://github.com/{u}', {
    enrich: 'github',
    tos: 'Public profile page and GitHub public API (60 req/hour unauthenticated).',
  }),
  page('gitlab', 'GitLab', 'dev', 'https://gitlab.com/{u}', {
    confidence: 'high',
  }),
  page('codeberg', 'Codeberg', 'dev', 'https://codeberg.org/{u}', {
    confidence: 'high',
  }),
  page('bitbucket', 'Bitbucket', 'dev', 'https://bitbucket.org/{u}/', {
    confidence: 'high',
  }),
  page('sourceforge', 'SourceForge', 'dev', 'https://sourceforge.net/u/{u}/profile', {
    confidence: 'medium',
  }),
  page('keybase', 'Keybase', 'dev', 'https://keybase.io/{u}', {
    enrich: 'keybase',
    tos: 'Public profile and Keybase lookup API. Self-published proofs are not verified by ARGUS.',
  }),
  page('hackernews', 'Hacker News', 'dev', 'https://news.ycombinator.com/user?id={u}', {
    check: 'marker',
    notFound: ['no such user'],
    enrich: 'hackernews',
    tos: 'Public profile page and the public Algolia HN API.',
  }),
  api('stackoverflow', 'Stack Overflow', 'dev', 'https://stackoverflow.com/users', 'stackoverflow', {
    confidence: 'medium',
    rateLimit: 5,
    rateLimitNote: 'Stack Exchange API: 300 requests/day unauthenticated.',
    tos: 'Stack Exchange public API. Exact display-name match only; display names are not handles.',
  }),
  page('npm', 'npm', 'dev', 'https://www.npmjs.com/~{u}', {
    confidence: 'high',
  }),
  page('pypi', 'PyPI', 'dev', 'https://pypi.org/user/{u}/', {
    confidence: 'high',
  }),
  api('dockerhub', 'Docker Hub', 'dev', 'https://hub.docker.com/u/{u}', 'dockerhub', {
    confidence: 'high',
    tos: 'Docker Hub public user API. Read-only.',
  }),
  api('huggingface', 'Hugging Face', 'dev', 'https://huggingface.co/{u}', 'huggingface', {
    confidence: 'high',
    rateLimit: 30,
    tos: 'Public Hugging Face Hub user overview API. Read-only; no authentication.',
  }),
  page('codepen', 'CodePen', 'dev', 'https://codepen.io/{u}', {
    confidence: 'high',
  }),
  page('pastebin', 'Pastebin', 'dev', 'https://pastebin.com/u/{u}', {
    confidence: 'high',
  }),
  page('leetcode', 'LeetCode', 'dev', 'https://leetcode.com/{u}/', {
    check: 'marker',
    confidence: 'medium',
    notFound: ['that page does not exist', 'page not found'],
  }),
  page('codeforces', 'Codeforces', 'dev', 'https://codeforces.com/profile/{u}', {
    check: 'marker',
    confidence: 'medium',
    notFound: ['user not found'],
  }),
  api('codewars', 'Codewars', 'dev', 'https://www.codewars.com/api/v1/users/{u}', 'codewars', {
    confidence: 'high',
    rateLimit: 30,
    tos: 'Public Codewars API v1 user endpoint. Read-only; no authentication.',
  }),
  page('tryhackme', 'TryHackMe', 'dev', 'https://tryhackme.com/p/{u}', {
    check: 'marker',
    confidence: 'low',
    enabled: false,
    notFound: ['user not found', 'page not found'],
    tos: 'Public profile page. Cloudflare protection often blocks automated clients; disabled by default.',
  }),
  page('replit', 'Replit', 'dev', 'https://replit.com/@{u}', {
    check: 'marker',
    confidence: 'low',
    enabled: false,
    found: ['"username"'],
    notFound: ['user not found', 'page not found'],
    tos: 'JavaScript-rendered profile page; unreliable without a browser. Disabled by default.',
  }),

  /* ----------------------------- creative --------------------------- */
  page('behance', 'Behance', 'creative', 'https://www.behance.net/{u}', {
    check: 'marker',
    confidence: 'medium',
    notFound: ['page not found'],
  }),
  page('dribbble', 'Dribbble', 'creative', 'https://dribbble.com/{u}', {
    confidence: 'medium',
  }),
  page('deviantart', 'DeviantArt', 'creative', 'https://www.deviantart.com/{u}', {
    confidence: 'high',
  }),
  page('flickr', 'Flickr', 'creative', 'https://www.flickr.com/people/{u}/', {
    check: 'marker',
    confidence: 'medium',
    notFound: ['page not found', "this page isn't available"],
  }),
  page('vimeo', 'Vimeo', 'creative', 'https://vimeo.com/{u}', {
    confidence: 'high',
  }),
  page('medium', 'Medium', 'creative', 'https://medium.com/@{u}', {
    confidence: 'medium',
  }),
  page('substack', 'Substack', 'creative', 'https://{u}.substack.com', {
    confidence: 'medium',
    tos: 'Public newsletter subdomain. Read-only.',
  }),
  page('wordpress', 'WordPress.com', 'creative', 'https://{u}.wordpress.com', {
    check: 'marker',
    confidence: 'low',
    notFound: ['no site found', "this site doesn't exist", 'this site does not exist'],
  }),
  page('blogger', 'Blogger', 'creative', 'https://{u}.blogspot.com', {
    confidence: 'medium',
  }),
  page('bandcamp', 'Bandcamp', 'music', 'https://bandcamp.com/{u}', {
    check: 'marker',
    confidence: 'low',
    notFound: ['page not found'],
  }),
  page('soundcloud', 'SoundCloud', 'music', 'https://soundcloud.com/{u}', {
    confidence: 'high',
  }),
  page('mixcloud', 'Mixcloud', 'music', 'https://www.mixcloud.com/{u}/', {
    confidence: 'medium',
  }),
  page('spotify', 'Spotify', 'music', 'https://open.spotify.com/user/{u}', {
    check: 'marker',
    confidence: 'low',
    notFound: ['page not found', "couldn't find that page"],
  }),

  /* ------------------------------ gaming ---------------------------- */
  api('steam', 'Steam', 'gaming', 'https://steamcommunity.com/id/{u}/', 'steam', {
    confidence: 'high',
    rateLimit: 20,
    tos: 'Public Steam Community XML profile endpoint. Read-only.',
  }),
  page('twitch', 'Twitch', 'gaming', 'https://www.twitch.tv/{u}', {
    confidence: 'medium',
  }),
  page('chess', 'Chess.com', 'gaming', 'https://www.chess.com/member/{u}', {
    confidence: 'medium',
  }),
  page('lichess', 'Lichess', 'gaming', 'https://lichess.org/@{u}', {
    confidence: 'high',
  }),

  /* --------------------------- books / film ------------------------- */
  page('goodreads', 'Goodreads', 'books', 'https://www.goodreads.com/{u}', {
    confidence: 'medium',
  }),
  page('letterboxd', 'Letterboxd', 'film', 'https://letterboxd.com/{u}/', {
    confidence: 'high',
  }),
  page('lastfm', 'Last.fm', 'music', 'https://www.last.fm/user/{u}', {
    confidence: 'high',
  }),
  page('patreon', 'Patreon', 'other', 'https://www.patreon.com/{u}', {
    check: 'marker',
    confidence: 'medium',
    notFound: ['page not found'],
  }),
  page('venmo', 'Venmo', 'other', 'https://account.venmo.com/u/{u}', {
    check: 'marker',
    confidence: 'low',
    enabled: false,
    notFound: ['page not found'],
    tos: 'Public payment profile. Requires care; disabled by default.',
  }),

  /* ------------------------ api-backed probes ----------------------- */
  api('mastodon', 'Mastodon', 'social', 'https://mastodon.social/@{u}', 'mastodon', {
    confidence: 'high',
    rateLimit: 30,
    rateLimitNote: 'mastodon.social API: 300 requests / 5 minutes.',
    tos: 'Public account lookup API on mastodon.social. Read-only.',
  }),
  api('bluesky', 'Bluesky', 'social', 'https://bsky.app/profile/{u}', 'bluesky', {
    confidence: 'high',
    rateLimit: 60,
    rateLimitNote: 'AT Protocol public AppView; UDP (unauthenticated) rate limits apply.',
    tos: 'Public AT Protocol AppView API. Read-only.',
  }),
];

export function getSource(id) {
  return SOURCES.find((source) => source.id === id) || null;
}

export function categories() {
  return [...new Set(SOURCES.map((source) => source.category))];
}

export const CATEGORY_LABELS = {
  social: 'Social',
  dev: 'Developer',
  creative: 'Creative',
  music: 'Music',
  gaming: 'Gaming',
  books: 'Books',
  film: 'Film',
  other: 'Other',
};
