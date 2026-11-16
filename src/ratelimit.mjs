/**
 * Tiny per-host rate limiter. Each source declares a requests-per-minute
 * budget in the registry; the limiter spaces requests to that host.
 */
const lastHit = new Map();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function hostGate(host, requestsPerMinute = 60) {
  if (!host) return;
  const interval = 60_000 / Math.max(1, requestsPerMinute);
  const now = Date.now();
  const previous = lastHit.get(host) ?? 0;
  const wait = previous + interval - now;
  if (wait > 0) await sleep(wait);
  lastHit.set(host, Date.now());
}

export function resetHostGates() {
  lastHit.clear();
}
