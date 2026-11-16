/**
 * Tiny per-host rate limiter. Each source declares a requests-per-minute
 * budget in the registry; the limiter spaces requests to that host.
 */
// Reserve slots at call time so concurrent scans cannot bunch after one sleep.
const nextSlot = new Map();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function hostGate(host, requestsPerMinute = 60) {
  if (!host) return;
  const rate = Number.isFinite(Number(requestsPerMinute)) ? Number(requestsPerMinute) : 60;
  const interval = 60_000 / Math.max(1, rate);
  const now = Date.now();
  const slot = Math.max(now, nextSlot.get(host) ?? now);
  nextSlot.set(host, slot + interval);
  const wait = slot - now;
  if (wait > 0) await sleep(wait);
}

export function resetHostGates() {
  nextSlot.clear();
}
