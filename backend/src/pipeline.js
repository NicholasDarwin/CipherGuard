// The scan pipeline shared by the Vercel function, the local Express server,
// and the Kubernetes worker. Callers observe progress through `emit`.
const config = require("./config");
const { fetchRepo, parseGitHubUrl } = require("./scanner/fetchRepo");
const { scanSecrets, scanCode, dedupe } = require("./scanner/patternScan");
const { runEslint } = require("./scanner/eslintScan");
const { extractDependencies } = require("./scanner/dependencies");
const { enrich } = require("./enrich");
const { analyze } = require("./ai");
const { computeRisk, priority } = require("./risk");

const STEPS = [
  { id: "clone", label: "Cloning" },
  { id: "secrets", label: "Secret scan" },
  { id: "static", label: "Static analysis" },
  { id: "deps", label: "Dependencies" },
  { id: "osint", label: "OSINT enrichment" },
  { id: "ai", label: "AI analysis" },
];
const PROGRESS_AT = { clone: 5, secrets: 25, static: 40, deps: 55, osint: 65, ai: 85 };
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

/**
 * Run a full scan.
 * @param {string} repoUrl
 * @param {object} [opts]
 * @param {(event:string, data:object)=>void} [opts.emit]
 * @param {(ctx:{files:Map, manifests:Map})=>Promise<Array>} [opts.extraDependencyScan] e.g. Snyk in the worker
 * @param {AbortSignal} [opts.signal]
 */
async function runScan(repoUrl, { emit = () => {}, extraDependencyScan, signal } = {}) {
  const target = parseGitHubUrl(repoUrl);
  if (!target) throw Object.assign(new Error("Enter a GitHub repository URL like https://github.com/owner/repo."), { status: 400 });

  const started = Date.now();
  const deadline = started + config.scanBudgetMs;
  const steps = STEPS.map((s) => ({ ...s, status: "pending", detail: null, durationMs: null }));

  let current = null;
  let stepStart = 0;
  const begin = (id, detail) => {
    current = steps.find((s) => s.id === id);
    stepStart = Date.now();
    Object.assign(current, { status: "running", detail });
    emit("step", { ...current, progress: PROGRESS_AT[id] });
    emit("status", { step: current.label, message: detail || current.label, progress: PROGRESS_AT[id] });
  };
  const end = (status, detail) => {
    Object.assign(current, { status, detail, durationMs: Date.now() - stepStart });
    emit("step", { ...current });
  };
  const note = (detail) => {
    current.detail = detail;
    emit("step", { ...current });
  };

  try {
    // 1. Download
    begin("clone", `Downloading ${target.slug}`);
    const repo = await fetchRepo(target, { signal });
    end("done", `${repo.files.size} files${repo.skipped ? `, ${repo.skipped} binary or vendored skipped` : ""}`);

    // 2. Secrets
    begin("secrets", `Checking ${repo.files.size} files for credentials`);
    const secretFindings = [];
    for (const [rel, content] of repo.files) secretFindings.push(...scanSecrets(rel, content));
    end("done", `${secretFindings.filter((f) => f.severity !== "info").length} potential secrets`);

    // 3. Static analysis
    begin("static", "Pattern rules and ESLint security rules");
    const codeFindings = [];
    for (const [rel, content] of repo.files) codeFindings.push(...scanCode(rel, content));
    const lint = await runEslint(repo.files, { deadline: Math.min(deadline - 25_000, Date.now() + 15_000) });
    codeFindings.push(...lint.findings);
    end("done", `${codeFindings.length} issues; ${lint.linted} JS files linted`);

    // 4. Dependencies
    begin("deps", "Reading lockfiles and manifests");
    const deps = extractDependencies(repo.files, repo.manifests);
    let extraFindings = [];
    if (extraDependencyScan) {
      try {
        extraFindings = (await extraDependencyScan({ files: repo.files, manifests: repo.manifests })) || [];
      } catch {
        extraFindings = [];
      }
    }
    end(
      "done",
      deps.dependencies.length
        ? `${deps.dependencies.length} packages from ${deps.manifests.length} manifest${deps.manifests.length === 1 ? "" : "s"}${deps.truncated ? " (first 1000)" : ""}`
        : "No supported lockfiles or manifests found"
    );

    // 5. OSINT
    begin("osint", "OSV, GitHub Advisories, NVD, CISA KEV, EPSS, Scorecard, deps.dev");
    const enrichDeadline = Math.min(Date.now() + config.enrichBudgetMs, deadline - 12_000);
    const intel = await enrich({ target, files: repo.files, dependencies: deps.dependencies, deadline: enrichDeadline, onProgress: note });
    const down = intel.sources.filter((s) => s.status === "unavailable").length;
    end("done", `${intel.findings.length} dependency findings; ${intel.sources.length - down} of ${intel.sources.length} sources responded`);

    // Assemble, prioritize, score.
    let findings = dedupe([...secretFindings, ...codeFindings, ...extraFindings, ...intel.findings]);
    findings.sort((a, b) => priority(b) - priority(a));
    findings = findings.map((f) => ({ ...f, keyword: f.rule }));

    const severityCounts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    for (const f of findings) severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    const risk = computeRisk(findings, intel.posture.scorecard);

    const report = {
      schemaVersion: 3,
      repository: target.url,
      target: { owner: target.owner, repo: target.repo, slug: target.slug },
      scanTimestamp: new Date().toISOString(),
      commit: repo.commit,
      totalFilesScanned: repo.files.size,
      filesSkipped: repo.skipped,
      dependenciesScanned: deps.dependencies.length,
      manifests: deps.manifests,
      totalFindings: findings.length,
      severityCounts,
      risk,
      posture: intel.posture,
      dependencyHealth: intel.dependencyHealth,
      findings,
      sources: intel.sources,
    };

    // 6. AI
    begin("ai", config.geminiApiKey ? `Explaining the top findings with ${config.geminiModel}` : "Skipped");
    const ai = await analyze(report, findings, { deadline: deadline - 2_000 });
    for (const f of report.findings) {
      const a = ai.byId.get(f.id);
      if (a) f.ai = a;
    }
    report.overallAssessment = ai.summary;
    report.ai = { status: ai.status, detail: ai.detail, model: config.geminiApiKey ? config.geminiModel : null };
    // Kept for clients of the v2 API.
    report.aiAnalyses = report.findings.filter((f) => f.ai).map((f) => ({ finding: { file: f.file, keyword: f.rule, line: f.line }, analysis: `${f.ai.explanation} ${f.ai.fix}`.trim() }));
    end(ai.status === "ok" ? "done" : "skipped", ai.detail);

    report.durationMs = Date.now() - started;
    report.steps = steps;
    emit("status", { step: "Complete", message: "Scan complete", progress: 100 });
    return report;
  } catch (err) {
    if (current && current.status === "running") end("failed", err.message);
    err.steps = steps;
    throw err;
  }
}

module.exports = { runScan, STEPS };
