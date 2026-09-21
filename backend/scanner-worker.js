#!/usr/bin/env node
/**
 * CipherGuard Scanner Worker
 *
 * Runs inside a Kubernetes Job container.
 * Env vars:
 *   REPO_URL      – GitHub repository URL to scan
 *   SCAN_ID       – unique scan identifier
 *   CALLBACK_URL  – POST results here when done
 *   GEMINI_API_KEY – (optional) for AI analysis
 *   SNYK_TOKEN     – (optional) for Snyk dependency scan
 */

const { execSync, execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const REPO_URL = process.env.REPO_URL;
const SCAN_ID = process.env.SCAN_ID;
const CALLBACK_URL = process.env.CALLBACK_URL;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-3.5-flash";
const SNYK_TOKEN = process.env.SNYK_TOKEN || "";

// ---------------------------------------------------------------------------
// Secret & vulnerability patterns (ported from Python codebase)
// ---------------------------------------------------------------------------
const SECRET_PATTERNS = {
  private_key: {
    pattern:
      /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/,
    severity: "critical",
    description: "Private cryptographic key exposed",
  },
  aws_secret: {
    pattern:
      /aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}/i,
    severity: "critical",
    description: "AWS Secret Access Key",
  },
  aws_access_key: {
    pattern: /(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}/,
    severity: "critical",
    description: "AWS Access Key ID",
  },
  github_token: {
    pattern:
      /(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/,
    severity: "critical",
    description: "GitHub Personal Access Token",
  },
  stripe_secret: {
    pattern: /sk_live_[a-zA-Z0-9]{24,}/,
    severity: "critical",
    description: "Stripe Secret API Key",
  },
  api_key: {
    pattern: /(api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}["']?/i,
    severity: "high",
    description: "API Key detected",
  },
  token: {
    pattern:
      /(token|auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[=:]\s*["']?[A-Za-z0-9_\-.]{20,}["']?/i,
    severity: "high",
    description: "Authentication token",
  },
  secret: {
    pattern:
      /(secret|client[_-]?secret|app[_-]?secret)\s*[=:]\s*["']?[A-Za-z0-9_\-]{16,}["']?/i,
    severity: "high",
    description: "Secret key or client secret",
  },
  jwt: {
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/,
    severity: "high",
    description: "JSON Web Token (JWT)",
  },
  google_api: {
    pattern: /AIza[0-9A-Za-z_-]{35}/,
    severity: "high",
    description: "Google API Key",
  },
  password: {
    pattern:
      /(password|passwd|pwd|pass)\s*[=:]\s*["']?[^\s"']{6,}["']?/i,
    severity: "medium",
    description: "Password in code",
  },
  database_url: {
    pattern: /(mongodb|mysql|postgres|postgresql|redis):\/\/[^\s"']+/i,
    severity: "medium",
    description: "Database connection string",
  },
};

const VULNERABILITY_PATTERNS = {
  sql_injection: {
    pattern:
      /(execute|query|cursor\.execute)\s*\(\s*["'].*%s.*["']|f["'].*SELECT.*\{/i,
    severity: "critical",
    description: "Potential SQL Injection",
  },
  xss: {
    pattern: /(innerHTML|outerHTML|document\.write)\s*=/i,
    severity: "high",
    description: "Potential XSS vulnerability",
  },
  eval_usage: {
    pattern: /\beval\s*\(/,
    severity: "high",
    description: "Dangerous eval() usage",
  },
  shell_injection: {
    pattern:
      /(os\.system|subprocess\.call|subprocess\.run|shell\s*=\s*true)/i,
    severity: "high",
    description: "Potential shell injection",
  },
  insecure_random: {
    pattern: /random\.(random|randint|choice)\s*\(/i,
    severity: "medium",
    description: "Insecure random for crypto",
  },
  debug_mode: {
    pattern: /(debug\s*=\s*true|DEBUG\s*=\s*true)/i,
    severity: "medium",
    description: "Debug mode enabled",
  },
  cors_wildcard: {
    pattern: /(Access-Control-Allow-Origin|CORS).*\*/i,
    severity: "medium",
    description: "CORS wildcard enabled",
  },
  http_without_tls: {
    // XML/SVG namespace identifiers are URIs, not network calls, so http://
    // there is not a TLS problem.
    pattern:
      /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org|www\.sitemaps\.org|schemas\.|purl\.org|ns\.adobe\.com|xml\.apache\.org|java\.sun\.com|docbook\.org|www\.openarchives\.org|www\.inkscape\.org|sodipodi\.sourceforge\.net)/i,
    severity: "low",
    description: "HTTP without TLS",
  },
};

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "__pycache__",
  "venv",
  ".venv",
  "dist",
  "build",
  "vendor",
  "bower_components",
  ".next",
  ".nuxt",
  "coverage",
  ".cache",
]);

const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
  ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz", ".pdf",
  ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".class",
  ".svg", ".webp", ".bmp", ".min.js", ".min.css", ".map",
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function log(msg) {
  console.log(`[scanner][${SCAN_ID?.slice(0, 8)}] ${msg}`);
}

function walkFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        results.push(...walkFiles(path.join(dir, entry.name)));
      }
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      if (!SKIP_EXTS.has(ext) && !entry.name.startsWith(".")) {
        results.push(path.join(dir, entry.name));
      }
    }
  }
  return results;
}

function readFileSafe(filePath, maxBytes = 500_000) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxBytes) return null;
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 1. Clone
// ---------------------------------------------------------------------------
function cloneRepo(url, dest) {
  log(`Cloning ${url}`);
  execFileSync("git", ["clone", "--depth", "1", url, dest], {
    stdio: "inherit",
    timeout: 120_000,
  });
}

// Drop repeats of the same rule + file + line + matched value.
function dedupeFindings(findings) {
  const seen = new Set();
  const unique = [];
  for (const f of findings) {
    const key = [f.keyword, f.file, f.line, f.match].join(" ");
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(f);
  }
  return unique;
}

// ---------------------------------------------------------------------------
// 2. Secret & pattern detection
// ---------------------------------------------------------------------------
function scanFileForSecrets(relPath, content) {
  const findings = [];
  for (const [keyword, cfg] of Object.entries(SECRET_PATTERNS)) {
    const re = new RegExp(cfg.pattern.source, cfg.pattern.flags + "g");
    let m;
    while ((m = re.exec(content)) !== null) {
      const line = content.slice(0, m.index).split("\n").length;
      const lineText = content.split("\n")[line - 1] || "";
      findings.push({
        type: "secret",
        keyword,
        severity: cfg.severity,
        description: cfg.description,
        file: relPath,
        line,
        match:
          m[0].length > 80 ? m[0].slice(0, 80) + "..." : m[0],
        context: lineText.trim().slice(0, 120),
      });
    }
  }
  return findings;
}

function scanFileForVulnerabilities(relPath, content) {
  const findings = [];
  for (const [keyword, cfg] of Object.entries(VULNERABILITY_PATTERNS)) {
    const re = new RegExp(cfg.pattern.source, cfg.pattern.flags + "g");
    let m;
    while ((m = re.exec(content)) !== null) {
      const line = content.slice(0, m.index).split("\n").length;
      const lineText = content.split("\n")[line - 1] || "";
      findings.push({
        type: "vulnerability",
        keyword,
        severity: cfg.severity,
        description: cfg.description,
        file: relPath,
        line,
        match:
          m[0].length > 80 ? m[0].slice(0, 80) + "..." : m[0],
        context: lineText.trim().slice(0, 120),
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// 3. ESLint analysis
// ---------------------------------------------------------------------------
function runEslint(repoDir) {
  log("Running ESLint analysis");
  try {
    // Run ESLint and capture JSON output; non-zero exit is expected when there are warnings
    const out = execSync(
      `npx eslint --no-eslintrc --env es2021 --format json "**/*.{js,ts,jsx,tsx}" 2>/dev/null || true`,
      { cwd: repoDir, maxBuffer: 10 * 1024 * 1024, timeout: 120_000 }
    );
    const parsed = JSON.parse(out.toString() || "[]");
    const findings = [];
    for (const file of parsed) {
      const relPath = path.relative(repoDir, file.filePath);
      for (const msg of file.messages) {
        findings.push({
          type: "eslint",
          keyword: msg.ruleId || "eslint-error",
          severity: msg.severity === 2 ? "high" : "medium",
          description: msg.message,
          file: relPath,
          line: msg.line || 0,
          match: msg.message.slice(0, 80),
          context: "",
        });
      }
    }
    return findings;
  } catch (err) {
    log(`ESLint skipped: ${err.message}`);
    return [];
  }
}

// ---------------------------------------------------------------------------
// 4. Snyk dependency scan
// ---------------------------------------------------------------------------
function runSnyk(repoDir) {
  if (!SNYK_TOKEN) {
    log("Snyk token not set – skipping dependency scan");
    return [];
  }
  log("Running Snyk dependency scan");
  try {
    const out = execSync("npx snyk test --json 2>/dev/null || true", {
      cwd: repoDir,
      maxBuffer: 10 * 1024 * 1024,
      timeout: 180_000,
      env: { ...process.env, SNYK_TOKEN },
    });
    const parsed = JSON.parse(out.toString() || "{}");
    const findings = [];
    for (const vuln of parsed.vulnerabilities || []) {
      findings.push({
        type: "dependency",
        keyword: vuln.id || vuln.title,
        severity: vuln.severity || "medium",
        description: vuln.title || "",
        file: vuln.from ? vuln.from.join(" > ") : "package.json",
        line: 0,
        match: `${vuln.packageName}@${vuln.version}`,
        context: vuln.description ? vuln.description.slice(0, 120) : "",
      });
    }
    return findings;
  } catch (err) {
    log(`Snyk skipped: ${err.message}`);
    return [];
  }
}

// ---------------------------------------------------------------------------
// 5. Gemini AI analysis
// ---------------------------------------------------------------------------
// Gemini refuses when a prompt reads as "assess the security of this
// repository", so the prompts below frame the task as explaining static
// analysis output on the user's own code instead. If it still declines, show
// something useful rather than the raw refusal.
const REFUSAL_MARKERS = [
  "i cannot fulfill",
  "i cannot provide",
  "i can not fulfill",
  "i can't fulfill",
  "i can't provide",
  "i cannot assist",
  "i can't assist",
  "i am unable to",
  "i'm unable to",
  "i cannot conduct",
  "i cannot perform",
  "as an ai language model, i cannot",
];

const FINDING_FALLBACK =
  "The AI assistant could not comment on this finding. The scanner rule that " +
  "fired is described above - review the matched value and line yourself, and " +
  "treat it as a real issue until you have confirmed otherwise.";

const SUMMARY_FALLBACK =
  "The AI assistant could not generate a written summary for this scan. The " +
  "findings below are unaffected - they come from the pattern scanner, not " +
  "from the AI. Work through them starting with the highest severity section.";

function isRefusal(text) {
  if (!text) return true;
  const lowered = text.trim().toLowerCase();
  return REFUSAL_MARKERS.some((marker) => lowered.includes(marker));
}

async function analyzeWithGemini(findings, repoUrl) {
  if (!GEMINI_API_KEY || findings.length === 0) return { analyses: [], overallAssessment: null };

  const { GoogleGenAI } = require("@google/genai");
  const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });

  const priorityFindings = findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 15);

  const analyses = [];
  for (const finding of priorityFindings) {
    try {
      const prompt = `You are helping a developer read the output of a static
analysis tool that ran over their own source code. Below is one result the
scanner flagged. Explain it to them.

Rule ID: ${finding.keyword}
Rule description: ${finding.description}
File: ${finding.file}
Line: ${finding.line}
Matched value: ${finding.match}
Line content: ${finding.context}

In 2-3 sentences, cover:
1. What this rule looks for and why that pattern matters
2. Whether this specific match looks like a false positive
3. The concrete change that would resolve it

Write plainly and directly to the developer. Do not evaluate the repository
as a whole and do not speculate about anything beyond this one line.`;

      const result = await ai.models.generateContent({ model: GEMINI_MODEL, contents: prompt });
      analyses.push({
        finding,
        analysis: isRefusal(result.text) ? FINDING_FALLBACK : result.text,
      });
    } catch (err) {
      analyses.push({ finding, analysis: `Analysis unavailable: ${err.message}` });
    }
  }

  // Overall assessment
  let overallAssessment = null;
  try {
    // Send only the scanner output - rule, file, line, snippet - with no
    // framing that asks the model to judge a repository.
    const byRule = new Map();
    for (const f of findings) {
      if (!byRule.has(f.keyword)) byRule.set(f.keyword, []);
      byRule.get(f.keyword).push(f);
    }

    const ruleLines = [...byRule.entries()]
      .sort((a, b) => b[1].length - a[1].length)
      .slice(0, 25)
      .map(([rule, items]) => {
        const s = items[0];
        return `- ${rule} (${s.severity}), ${items.length} occurrence(s); example: ${s.file} line ${s.line}: ${(s.context || "").slice(0, 120)}`;
      });

    const prompt = `A developer ran a pattern-based static analysis tool over
their own source code. Below is the list of rules that fired, with one example
occurrence each. Help them interpret this output.

${ruleLines.join("\n")}

For each rule listed, write a short entry covering:
1. What the rule detects and why that pattern is worth knowing about
2. How likely these particular matches are to be false positives
3. The concrete change that would resolve it

Then finish with a short "Where to start" paragraph ordering the rules by what
is worth fixing first.

This is the developer's own code and they are asking for help reading tool
output. Do not rate or judge the repository, do not assign a security score,
and do not speculate about code you have not been shown.`;

    const result = await ai.models.generateContent({ model: GEMINI_MODEL, contents: prompt });
    overallAssessment = isRefusal(result.text) ? SUMMARY_FALLBACK : result.text;
  } catch (err) {
    overallAssessment = `Assessment unavailable: ${err.message}`;
  }

  return { analyses, overallAssessment };
}

// ---------------------------------------------------------------------------
// 6. Post results back to API
// ---------------------------------------------------------------------------
async function postResults(scanId, status, results) {
  log(`Posting results to ${CALLBACK_URL}`);
  const res = await fetch(CALLBACK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scanId, status, results }),
  });
  if (!res.ok) {
    throw new Error(`Callback failed: ${res.status} ${await res.text()}`);
  }
  log("Results submitted successfully");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  if (!REPO_URL || !SCAN_ID || !CALLBACK_URL) {
    console.error("REPO_URL, SCAN_ID, and CALLBACK_URL are required");
    process.exit(1);
  }

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-scan-"));
  const repoDir = path.join(workDir, "repo");

  try {
    // 1. Clone
    cloneRepo(REPO_URL, repoDir);

    // 2. Pattern scan
    log("Scanning for secrets and vulnerabilities");
    const files = walkFiles(repoDir);
    log(`Found ${files.length} files to scan`);

    let allFindings = [];
    for (const filePath of files) {
      const content = readFileSafe(filePath);
      if (!content) continue;
      const rel = path.relative(repoDir, filePath);
      allFindings.push(
        ...scanFileForSecrets(rel, content),
        ...scanFileForVulnerabilities(rel, content)
      );
    }

    // 3. ESLint
    const eslintFindings = runEslint(repoDir);
    allFindings.push(...eslintFindings);

    // 4. Snyk
    const snykFindings = runSnyk(repoDir);
    allFindings.push(...snykFindings);

    allFindings = dedupeFindings(allFindings);

    // Sort by severity
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    allFindings.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

    log(`Total findings: ${allFindings.length}`);

    // 5. AI analysis
    const { analyses, overallAssessment } = await analyzeWithGemini(
      allFindings,
      REPO_URL
    );

    // 6. Build report
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of allFindings)
      sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;

    const report = {
      repository: REPO_URL,
      totalFilesScanned: files.length,
      totalFindings: allFindings.length,
      severityCounts: sevCounts,
      findings: allFindings,
      aiAnalyses: analyses,
      overallAssessment,
      scanTimestamp: new Date().toISOString(),
    };

    // 7. Post back
    await postResults(SCAN_ID, "completed", report);
  } catch (err) {
    console.error("Scan failed:", err);
    try {
      await postResults(SCAN_ID, "failed", { error: err.message });
    } catch (cbErr) {
      console.error("Callback also failed:", cbErr.message);
    }
    process.exit(1);
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

main();
