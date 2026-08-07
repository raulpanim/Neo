import { redisGet, redisSet } from '../redis.js';
import { formatConflictAlert, formatExploitableAlert } from './format.js';

const SEEN_TTL_SECONDS = 60 * 60 * 24 * 7; // a week - long enough a Redis blip doesn't re-alert everything
const MAX_SEEN_KEYS = 500; // caps unbounded growth over the TTL window
const DEFAULT_INTERVAL_MS = Number(process.env.TELEGRAM_ALERT_INTERVAL_MINUTES || 15) * 60_000;

export const conflictKey = (c) => `conflict|${c.kind}|${c.subject_id}|${c.predicate}|${c.object_id ?? ''}`;
export const exploitableKey = (e) => `exploitable|${e.cve}`;

/**
 * Given the keys already alerted on and the current set of items, returns
 * which items are genuinely new plus the updated key set (oldest first, so
 * callers can truncate the front to cap growth). Pure - no I/O - so this is
 * the one part of the poller that's actually unit-testable.
 */
export function diffNew(seenKeys, items, keyOf) {
  const seen = new Set(seenKeys);
  const fresh = [];
  for (const item of items) {
    const key = keyOf(item);
    if (!seen.has(key)) {
      fresh.push(item);
      seen.add(key);
    }
  }
  return { fresh, seen: [...seen] };
}

// In-memory fallback so a Redis outage doesn't stop alerting - it just risks
// re-alerting already-seen items once, until Redis comes back.
const localSeen = new Map(); // kind -> string[]

async function loadSeen(kind) {
  const remote = await redisGet(`nexus:alerts:seen:${kind}`);
  return remote ?? localSeen.get(kind) ?? [];
}

async function saveSeen(kind, keys) {
  const capped = keys.slice(-MAX_SEEN_KEYS);
  localSeen.set(kind, capped);
  await redisSet(`nexus:alerts:seen:${kind}`, capped, SEEN_TTL_SECONDS);
}

/**
 * Fetches one kind of item, alerts on anything new, and remembers what it
 * saw. The very first poll ever (empty seen state) establishes a baseline
 * silently rather than alerting on the entire graph's current contents.
 */
async function pollKind({ telegram, chatId, kind, fetchItems, keyOf, format }) {
  const items = await fetchItems();
  if (!items) return; // the nexus API call failed - try again next poll

  const seenBefore = await loadSeen(kind);
  const { fresh, seen } = diffNew(seenBefore, items, keyOf);
  const isBaseline = seenBefore.length === 0;

  if (!isBaseline) {
    for (const item of fresh.slice(0, 5)) {
      try {
        await telegram.sendMessage(chatId, format(item));
      } catch (err) {
        console.error(`[alerts] sendMessage failed for ${kind}:`, err.message);
      }
    }
  }

  await saveSeen(kind, seen);
}

async function pollOnce(telegram, nexus, chatId) {
  await pollKind({
    telegram,
    chatId,
    kind: 'conflict',
    fetchItems: () => nexus.conflicts().then((r) => (r.ok ? r.data.conflicts : null)),
    keyOf: conflictKey,
    format: formatConflictAlert,
  });
  await pollKind({
    telegram,
    chatId,
    kind: 'exploitable',
    fetchItems: () => nexus.exploitable().then((r) => (r.ok ? r.data.items : null)),
    keyOf: exploitableKey,
    format: formatExploitableAlert,
  });
}

/**
 * Starts polling in the background. No-op (returns a no-op stop function)
 * when no chat id is configured - alerts are opt-in.
 */
export function startAlertPoller({ telegram, nexus, chatId, intervalMs = DEFAULT_INTERVAL_MS }) {
  if (!chatId) {
    console.log('[alerts] TELEGRAM_ALERT_CHAT_ID not set - push alerts disabled.');
    return () => {};
  }

  console.log(`[alerts] polling every ${Math.round(intervalMs / 60_000)}m for new conflicts/exploitable CVEs`);
  let stopped = false;

  (async () => {
    while (!stopped) {
      try {
        await pollOnce(telegram, nexus, chatId);
      } catch (err) {
        console.error('[alerts] poll failed:', err.message);
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  })();

  return () => {
    stopped = true;
  };
}
