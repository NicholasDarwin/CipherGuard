#!/usr/bin/env node
/**
 * CipherGuard scanner worker: runs one scan inside a Kubernetes Job.
 *
 * Env:
 *   REPO_URL       GitHub repository URL to scan
 *   SCAN_ID        scan identifier issued by the API
 *   CALLBACK_URL   POST target for results (…/scan-results); progress goes to …/scan-progress
 *   GEMINI_API_KEY, SNYK_TOKEN, GITHUB_TOKEN, NVD_API_KEY  optional
 */
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const config = require("./src/config");
const { runScan } = require("./src/pipeline");
const { findingId } = require("./src/scanner/patternScan");

const { REPO_URL, SCAN_ID, CALLBACK_URL } = process.env;
const PROGRESS_URL = CALLBACK_URL ? CALLBACK_URL.replace(/\/scan-results$/, "/scan-progress") : null;

const log = (msg) => console.log(`[worker][${(SCAN_ID || "").slice(0, 8)}] ${msg}`);

async function post(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
}

// Snyk needs manifests on disk, so write them to a temp dir and run the CLI.
async function snykScan({ files, manifests }) {
  if (!config.snykToken) return [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-snyk-"));
  try {
    for (const [rel, text] of [...files, ...manifests]) {
      if (!/(^|\/)(package(-lock)?\.json|yarn\.lock|requirements[^/]*\.txt|Pipfile(\.lock)?|go\.(mod|sum)|Gemfile(\.lock)?|composer\.(json|lock)|Cargo\.(toml|lock))$/.test(rel)) continue;
      const dest = path.join(dir, rel);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, text);
    }
    let out;
    try {
      out = execFileSync("snyk", ["test", "--all-projects", "--json"], { cwd: dir, env: { ...process.env, SNYK_TOKEN: config.snykToken }, maxBuffer: 50 * 1024 * 1024, timeout: 180_000 });
    } catch (err) {
      out = err.stdout; // exit code 1 means "vulnerabilities found"
    }
    const parsed = JSON.parse(out?.toString() || "[]");
    const projects = Array.isArray(parsed) ? parsed : [parsed];
    return projects.flatMap((p) =>
      (p.vulnerabilities || []).map((v) => ({
        id: findingId(["snyk", v.id, v.packageName, v.version]),
        type: "dependency",
        rule: v.identifiers?.CVE?.[0] || v.id,
        severity: v.severity === "medium" ? "medium" : v.severity,
        title: v.title,
        description: v.title,
        file: p.displayTargetFile || "",
        line: 0,
        match: `${v.packageName}@${v.version}`,
        context: "",
        package: { ecosystem: p.packageManager, name: v.packageName, version: v.version, fixedVersion: v.fixedIn?.[0] || null, direct: (v.from || []).length <= 2 },
        remediation: v.fixedIn?.length ? `Upgrade ${v.packageName} to ${v.fixedIn[0]} or later.` : "No fix available yet.",
        sources: [{ name: "Snyk", url: `https://security.snyk.io/vuln/${v.id}` }],
      }))
    );
  } catch (err) {
    log(`Snyk skipped: ${err.message}`);
    return [];
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function main() {
  if (!REPO_URL || !SCAN_ID || !CALLBACK_URL) {
    console.error("REPO_URL, SCAN_ID, and CALLBACK_URL are required");
    process.exit(1);
  }

  const emit = (event, data) => {
    if (event !== "step") return;
    log(`${data.label}: ${data.status}${data.detail ? ` – ${data.detail}` : ""}`);
    const { progress, ...step } = data;
    post(PROGRESS_URL, { scanId: SCAN_ID, step }).catch(() => {});
  };

  try {
    const report = await runScan(REPO_URL, { emit, extraDependencyScan: snykScan });
    await post(CALLBACK_URL, { scanId: SCAN_ID, status: "completed", results: report });
    log("Results submitted");
  } catch (err) {
    console.error("Scan failed:", err);
    try {
      await post(CALLBACK_URL, { scanId: SCAN_ID, status: "failed", results: { error: err.message, steps: err.steps } });
    } catch (cbErr) {
      console.error("Callback also failed:", cbErr.message);
    }
    process.exit(1);
  }
}

main();
