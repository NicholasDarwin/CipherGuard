// HTTP helper shared by every enrichment source: JSON fetch with a timeout,
// a TTL cache (memory, plus disk when writable), per-source rate limiting,
// and one retry on 429/5xx.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const config = require("../config");

const memory = new Map();
const MEMORY_MAX = 5000;
let diskDir = null;

function cacheDir() {
  if (diskDir !== null) return diskDir;
  try {
    diskDir = config.cacheDir || path.join(os.tmpdir(), "cipherguard-cache");
    fs.mkdirSync(diskDir, { recursive: true });
  } catch {
    diskDir = "";
  }
  return diskDir;
}

function cacheGet(key) {
  const hit = memory.get(key);
  if (hit && hit.expires > Date.now()) return hit.value;
  const dir = cacheDir();
  if (!dir) return undefined;
  try {
    const entry = JSON.parse(fs.readFileSync(path.join(dir, key + ".json"), "utf8"));
    if (entry.expires > Date.now()) {
      memory.set(key, entry);
      return entry.value;
    }
  } catch {
    /* miss */
  }
  return undefined;
}

function cacheSet(key, value, ttlMs) {
  const entry = { value, expires: Date.now() + ttlMs };
  if (memory.size >= MEMORY_MAX) memory.delete(memory.keys().next().value);
  memory.set(key, entry);
  const dir = cacheDir();
  if (!dir) return;
  fs.promises.writeFile(path.join(dir, key + ".json"), JSON.stringify(entry)).catch(() => {});
}

// Sliding-window limiter: at most `max` calls per `windowMs`.
class RateLimiter {
  constructor(max, windowMs) {
    this.max = max;
    this.windowMs = windowMs;
    this.calls = [];
    this.queue = Promise.resolve();
  }
  take() {
    const next = this.queue.then(async () => {
      for (;;) {
        const now = Date.now();
        this.calls = this.calls.filter((t) => now - t < this.windowMs);
        if (this.calls.length < this.max) {
          this.calls.push(now);
          return;
        }
        await new Promise((r) => setTimeout(r, this.windowMs - (now - this.calls[0]) + 5));
      }
    });
    this.queue = next.catch(() => {});
    return next;
  }
}

class HttpError extends Error {
  constructor(status, url) {
    super(`HTTP ${status} from ${new URL(url).host}`);
    this.status = status;
  }
}

/**
 * Fetch JSON with caching. Returns `null` for 404 so callers can treat
 * "not found" as data rather than failure.
 */
async function getJson(url, { method = "GET", body, headers = {}, ttlMs = 6 * 3600e3, timeoutMs = 10_000, limiter, cacheKey } = {}) {
  const key = crypto.createHash("sha1").update(cacheKey || `${method} ${url} ${body ? JSON.stringify(body) : ""}`).digest("hex");
  const cached = cacheGet(key);
  if (cached !== undefined) return cached;

  for (let attempt = 0; attempt < 2; attempt++) {
    if (limiter) await limiter.take();
    const res = await fetch(url, {
      method,
      headers: { "User-Agent": "CipherGuard", Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status === 404) {
      cacheSet(key, null, ttlMs);
      return null;
    }
    if ((res.status === 429 || res.status >= 500) && attempt === 0) {
      const retryAfter = Number(res.headers.get("retry-after")) || 2;
      await new Promise((r) => setTimeout(r, Math.min(retryAfter, 6) * 1000));
      continue;
    }
    if (!res.ok) throw new HttpError(res.status, url);
    const json = await res.json();
    cacheSet(key, json, ttlMs);
    return json;
  }
  throw new HttpError(429, url);
}

/**
 * Run `fn` over items with bounded concurrency; failures become `undefined`.
 * With a deadline, resolves shortly before it with whatever has finished, so
 * a slow source still contributes partial results.
 */
async function mapLimit(items, limit, fn, { deadline } = {}) {
  const results = new Array(items.length);
  let i = 0;
  const worker = async () => {
    while (i < items.length) {
      const idx = i++;
      if (deadline && Date.now() > deadline) return;
      try {
        results[idx] = await fn(items[idx], idx);
      } catch {
        results[idx] = undefined;
      }
    }
  };
  const all = Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  if (!deadline) {
    await all;
    return results;
  }
  let timer;
  const cutoff = new Promise((r) => (timer = setTimeout(r, Math.max(0, deadline - Date.now() - 300))));
  await Promise.race([all, cutoff]).finally(() => clearTimeout(timer));
  return results.slice();
}

module.exports = { getJson, mapLimit, RateLimiter, HttpError };
