import { createClient } from 'redis';

const URL = process.env.REDIS_URL || 'redis://localhost:6379';
const CONNECT_TIMEOUT_MS = 2000;
// Once a connection attempt fails, don't retry on every subsequent call for
// a while - a hung/down Redis would otherwise stall every request that
// touches it, one failed connect attempt at a time.
const RETRY_COOLDOWN_MS = 10_000;

let client = null;
let connecting = null;
let lastFailureAt = 0;

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)),
  ]);
}

/**
 * Lazily connects on first use and reuses one client. Redis is optional
 * infrastructure here - live sync-job progress persists through it when
 * it's reachable, but nothing in the app requires it to function, so a down
 * Redis must fail fast rather than hang the request that touched it.
 */
async function getClient() {
  if (client?.isOpen) return client;

  if (Date.now() - lastFailureAt < RETRY_COOLDOWN_MS) {
    throw new Error('Redis unavailable (cooling down after a recent failure).');
  }

  if (!connecting) {
    const c = createClient({
      url: URL,
      socket: {
        connectTimeout: CONNECT_TIMEOUT_MS,
        reconnectStrategy: false, // don't let the client retry in the background - we handle retries per call
      },
    });
    c.on('error', () => {}); // connect()'s own rejection is what we act on; this just stops it being "unhandled"

    connecting = withTimeout(c.connect(), CONNECT_TIMEOUT_MS, 'redis connect')
      .then(() => {
        client = c;
        connecting = null;
        return c;
      })
      .catch((err) => {
        connecting = null;
        lastFailureAt = Date.now();
        c.destroy?.();
        throw err;
      });
  }
  return connecting;
}

/** Best-effort JSON get. Returns null on a miss OR on any Redis failure -
 *  callers treat "unavailable" the same as "not found" and fall back. */
export async function redisGet(key) {
  try {
    const c = await getClient();
    const raw = await c.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

/** Best-effort JSON set. Returns whether it actually landed in Redis, so a
 *  caller that also keeps an in-memory copy knows not to rely on this one. */
export async function redisSet(key, value, ttlSeconds) {
  try {
    const c = await getClient();
    await c.set(key, JSON.stringify(value), ttlSeconds ? { EX: ttlSeconds } : undefined);
    return true;
  } catch {
    return false;
  }
}

export async function redisKeys(pattern) {
  try {
    const c = await getClient();
    return await c.keys(pattern);
  } catch {
    return [];
  }
}

export async function redisDel(key) {
  try {
    const c = await getClient();
    await c.del(key);
    return true;
  } catch {
    return false;
  }
}
