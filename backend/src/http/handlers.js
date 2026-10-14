// HTTP handlers written against Node's (req, res), so the same code serves
// Vercel functions and the Express server.
const config = require("../config");
const { runScan } = require("../pipeline");
const { parseGitHubUrl } = require("../scanner/fetchRepo");
const shares = require("./shareStore");

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

function query(req) {
  if (req.query) return req.query;
  return Object.fromEntries(new URL(req.url, "http://localhost").searchParams);
}

async function readBody(req, limit = 5_000_000) {
  if (req.body !== undefined) return typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error("Body too large"), { status: 413 });
    chunks.push(chunk);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
}

/**
 * GET /api/scan-stream?repo=<url>  (also served at /scan_stream)
 * Server-sent events: `step`, `status`, `result`, `error`.
 */
async function scanStream(req, res, { mode = "stream" } = {}) {
  const repoUrl = String(query(req).repo || "");
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  const send = (event, data) => {
    if (res.writableEnded) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    res.flush?.();
  };
  // Comment lines keep proxies from closing an idle connection.
  const heartbeat = setInterval(() => !res.writableEnded && res.write(": ping\n\n"), 15_000);
  const abort = new AbortController();
  req.on("close", () => abort.abort());

  if (!parseGitHubUrl(repoUrl)) {
    send("error", { error: "Enter a GitHub repository URL like https://github.com/owner/repo." });
    clearInterval(heartbeat);
    return res.end();
  }

  try {
    send("status", { step: "Initializing", message: "Starting scan", progress: 0, mode });
    const result = await runScan(repoUrl, { emit: send, signal: abort.signal });
    send("result", { result });
  } catch (err) {
    send("error", { error: err.message, steps: err.steps });
  } finally {
    clearInterval(heartbeat);
    res.end();
  }
}

function health(_req, res, extra = {}) {
  sendJson(res, 200, {
    status: "ok",
    version: config.version,
    mode: "stream",
    gemini_configured: !!config.geminiApiKey,
    ai: !!config.geminiApiKey,
    sharing: shares.available(),
    sources: { github_token: !!config.githubToken, nvd_api_key: !!config.nvdApiKey, snyk: !!config.snykToken },
    ...extra,
  });
}

/** POST /api/share  { report } -> { id, expiresAt } */
async function createShare(req, res) {
  if (!shares.available()) return sendJson(res, 501, { error: "Report sharing is not configured on this server." });
  try {
    const body = await readBody(req);
    const { id, expiresAt } = await shares.put(body.report);
    sendJson(res, 201, { id, expiresAt });
  } catch (err) {
    sendJson(res, err.status || 400, { error: err.message });
  }
}

/** GET /api/share/:id */
async function getShare(req, res, id) {
  if (!shares.available()) return sendJson(res, 501, { error: "Report sharing is not configured on this server." });
  try {
    const entry = await shares.get(id);
    if (!entry) return sendJson(res, 404, { error: "This shared report does not exist or has expired." });
    sendJson(res, 200, entry);
  } catch (err) {
    sendJson(res, 502, { error: err.message });
  }
}

module.exports = { scanStream, health, createShare, getShare, sendJson, readBody };
