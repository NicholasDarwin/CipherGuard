// Shared-report storage. Uses Upstash Redis over REST (Vercel KV exposes the
// same API) when configured; the Express server can opt into an in-memory
// store for local development with SHARE_STORE=memory.
const crypto = require("crypto");
const config = require("../config");
const { sanitizeReport } = require("../sanitize");

const MAX_BYTES = 2_000_000;
const ID_PATTERN = /^[A-Za-z0-9_-]{16}$/;
const memory = new Map();

const useKv = () => !!(config.kvUrl && config.kvToken);
const useMemory = () => process.env.SHARE_STORE === "memory";
const available = () => useKv() || useMemory();

async function kv(command) {
  const res = await fetch(config.kvUrl, {
    method: "POST",
    headers: { Authorization: `Bearer ${config.kvToken}`, "Content-Type": "application/json" },
    body: JSON.stringify(command),
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`Share storage returned ${res.status}`);
  return (await res.json()).result;
}

async function put(report) {
  if (!report || !Array.isArray(report.findings) || !report.repository) {
    throw Object.assign(new Error("Request must include a report."), { status: 400 });
  }
  // Never trust the client to have redacted: sanitize again server-side.
  const payload = JSON.stringify({ report: sanitizeReport(report), createdAt: new Date().toISOString() });
  if (payload.length > MAX_BYTES) throw Object.assign(new Error("Report is too large to share; export it instead."), { status: 413 });

  // 12 random bytes: unguessable, and short enough for a URL.
  const id = crypto.randomBytes(12).toString("base64url");
  const ttl = config.shareTtlDays * 86400;
  if (useKv()) await kv(["SET", `share:${id}`, payload, "EX", String(ttl)]);
  else memory.set(id, { payload, expires: Date.now() + ttl * 1000 });
  return { id, expiresAt: new Date(Date.now() + ttl * 1000).toISOString() };
}

async function get(id) {
  if (!ID_PATTERN.test(id || "")) return null;
  let payload = null;
  if (useKv()) payload = await kv(["GET", `share:${id}`]);
  else {
    const hit = memory.get(id);
    payload = hit && hit.expires > Date.now() ? hit.payload : null;
  }
  return payload ? JSON.parse(payload) : null;
}

module.exports = { available, put, get };
