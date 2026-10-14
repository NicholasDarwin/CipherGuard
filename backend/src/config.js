// Central configuration. Every value is optional; the scanner degrades to
// fewer data sources when a key is missing.
const path = require("path");

// Root .env first, then backend/.env; real environment variables win over both.
require("dotenv").config({ path: [path.join(__dirname, "../../.env"), path.join(__dirname, "../.env")], quiet: true });

const int = (name, fallback) => {
  const n = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(n) ? n : fallback;
};

module.exports = {
  version: "3.0.0",

  geminiApiKey: process.env.GEMINI_API_KEY || "",
  geminiModel: process.env.GEMINI_MODEL || "gemini-3.5-flash",
  snykToken: process.env.SNYK_TOKEN || "",
  githubToken: process.env.GITHUB_TOKEN || "",
  nvdApiKey: process.env.NVD_API_KEY || "",

  // Shared report storage (Upstash Redis REST, which is what Vercel KV uses).
  kvUrl: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || "",
  kvToken: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || "",
  shareTtlDays: int("SHARE_TTL_DAYS", 30),

  // Limits that keep one scan inside a serverless invocation.
  maxRepoBytes: int("MAX_REPO_MB", 100) * 1e6,
  maxFileBytes: 500_000,
  maxFiles: int("MAX_FILES", 6000),
  scanBudgetMs: int("SCAN_BUDGET_MS", 55_000),
  enrichBudgetMs: int("ENRICH_BUDGET_MS", 20_000),

  cacheDir: process.env.CACHE_DIR || "",
};
