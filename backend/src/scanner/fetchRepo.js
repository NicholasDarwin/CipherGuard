const { unzipSync } = require("fflate");
const config = require("../config");

const SKIP_DIRS = new Set([
  ".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build",
  "vendor", "bower_components", ".next", ".nuxt", "coverage", ".cache",
  "target", ".terraform",
]);

const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot",
  ".mp3", ".mp4", ".mov", ".zip", ".tar", ".gz", ".tgz", ".7z", ".pdf",
  ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".class", ".jar", ".svg",
  ".webp", ".bmp", ".map", ".wasm", ".psd", ".sqlite", ".db",
]);

// Lockfiles are read for dependency extraction but are too large and too
// machine-generated to pattern-scan line by line.
const MANIFEST_ONLY = new Set([
  "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
  "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum",
]);

const GITHUB_URL = /^https?:\/\/(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i;

function parseGitHubUrl(url) {
  const m = String(url || "").trim().match(GITHUB_URL);
  if (!m) return null;
  return { owner: m[1], repo: m[2], slug: `${m[1]}/${m[2]}`, url: `https://github.com/${m[1]}/${m[2]}` };
}

function extname(name) {
  if (name.endsWith(".min.js")) return ".min.js";
  if (name.endsWith(".min.css")) return ".min.css";
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(i).toLowerCase() : "";
}

function shouldKeep(relPath) {
  const parts = relPath.split("/");
  const name = parts[parts.length - 1];
  if (parts.slice(0, -1).some((p) => SKIP_DIRS.has(p))) return false;
  const ext = extname(name);
  if (SKIP_EXTS.has(ext) || ext === ".min.js" || ext === ".min.css") return false;
  // Dotfiles are skipped except the ones that commonly hold secrets.
  if (name.startsWith(".") && !/^\.env(\..+)?$|^\.npmrc$|^\.pypirc$/.test(name)) return false;
  return true;
}

class RepoError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

/**
 * Download a public repo's default branch as a zip and return its text files.
 * Uses codeload, which does not count against the REST API rate limit.
 */
async function fetchRepo(target, { signal } = {}) {
  const url = `https://codeload.github.com/${target.owner}/${target.repo}/zip/HEAD`;
  const headers = { "User-Agent": "CipherGuard" };
  if (config.githubToken) headers.Authorization = `Bearer ${config.githubToken}`;

  const res = await fetch(url, { headers, signal, redirect: "follow" });
  if (res.status === 404) throw new RepoError("Repository not found. Check the URL; private repositories are not supported.", 404);
  if (!res.ok) throw new RepoError(`GitHub returned ${res.status} while downloading the repository.`, res.status);

  const declared = Number(res.headers.get("content-length") || 0);
  if (declared > config.maxRepoBytes) {
    throw new RepoError(`Repository archive is ${(declared / 1e6).toFixed(0)} MB; the limit is ${(config.maxRepoBytes / 1e6).toFixed(0)} MB.`, 413);
  }
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.byteLength > config.maxRepoBytes) {
    throw new RepoError(`Repository archive exceeds ${(config.maxRepoBytes / 1e6).toFixed(0)} MB.`, 413);
  }

  const files = new Map();
  const manifests = new Map();
  let skipped = 0;
  const decoder = new TextDecoder("utf-8", { fatal: false });

  const entries = unzipSync(buf, {
    filter: (f) => {
      if (f.name.endsWith("/")) return false;
      const rel = f.name.slice(f.name.indexOf("/") + 1);
      if (!rel || !shouldKeep(rel)) {
        skipped++;
        return false;
      }
      if (f.originalSize > config.maxFileBytes && !MANIFEST_ONLY.has(rel.split("/").pop())) {
        skipped++;
        return false;
      }
      return true;
    },
  });

  for (const [name, data] of Object.entries(entries)) {
    const rel = name.slice(name.indexOf("/") + 1);
    // A NUL byte in the first 8 KB means binary content.
    if (data.subarray(0, 8192).includes(0)) {
      skipped++;
      continue;
    }
    const text = decoder.decode(data);
    if (MANIFEST_ONLY.has(rel.split("/").pop())) manifests.set(rel, text);
    else if (files.size < config.maxFiles) files.set(rel, text);
    else skipped++;
  }

  // Manifests that are also worth pattern-scanning (package.json, go.mod...)
  // live in `files`; dependency parsing reads both maps.
  return { files, manifests, skipped, archiveBytes: buf.byteLength };
}

module.exports = { fetchRepo, parseGitHubUrl, RepoError };
