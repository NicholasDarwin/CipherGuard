// OSINT enrichment. Every source is optional: a failure or timeout marks the
// source "unavailable" in the report and the scan carries on without it.
const config = require("../config");
const S = require("./sources");
const { cvss3Score, severityFromScore } = require("./cvss");
const { findingId } = require("../scanner/patternScan");

const SOURCE_META = {
  osv: { name: "OSV.dev", url: "https://osv.dev" },
  ghsa: { name: "GitHub Advisory Database", url: "https://github.com/advisories" },
  nvd: { name: "NVD", url: "https://nvd.nist.gov" },
  kev: { name: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
  epss: { name: "FIRST EPSS", url: "https://www.first.org/epss/" },
  scorecard: { name: "OpenSSF Scorecard", url: "https://scorecard.dev" },
  depsdev: { name: "deps.dev", url: "https://deps.dev" },
  github: { name: "GitHub", url: "https://docs.github.com/rest/repos" },
};

const MAX_OSV_DETAILS = 250;
const MAX_DEPSDEV = 40;
const TWO_YEARS = 2 * 365 * 24 * 3600e3;

const TIMEOUT = Symbol("timeout");
function beforeDeadline(promise, deadline) {
  const ms = Math.max(0, deadline - Date.now());
  let timer;
  return Promise.race([promise, new Promise((r) => (timer = setTimeout(() => r(TIMEOUT), ms)))]).finally(() => clearTimeout(timer));
}

// Loose version ordering, good enough to pick the nearest fixed release.
function compareVersions(a, b) {
  const pa = String(a).replace(/^v/, "").split(/[.+-]/);
  const pb = String(b).replace(/^v/, "").split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = Number(x);
    const ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function fixedVersionFor(vuln, dep) {
  const fixes = [];
  for (const a of vuln.affected || []) {
    if (a.package?.name?.toLowerCase() !== dep.name.toLowerCase()) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixes.push(e.fixed);
  }
  const later = fixes.filter((f) => compareVersions(f, dep.version) > 0).sort(compareVersions);
  return later[0] || null;
}

function normalizeOsv(v) {
  const aliases = [v.id, ...(v.aliases || [])];
  const db = v.database_specific || {};
  const vec3 = (v.severity || []).find((s) => s.type === "CVSS_V3")?.score || null;
  const vec4 = (v.severity || []).find((s) => s.type === "CVSS_V4")?.score || null;
  const dbSeverity = typeof db.severity === "string" ? db.severity.toLowerCase().replace("moderate", "medium") : null;
  return {
    id: v.id,
    aliases,
    cve: aliases.find((a) => /^CVE-\d{4}-\d+$/.test(a)) || null,
    ghsa: aliases.find((a) => a.startsWith("GHSA-")) || null,
    summary: v.summary || (v.details || "").split("\n")[0].slice(0, 200),
    details: (v.details || "").slice(0, 1200),
    published: v.published,
    cvssOsv: vec3 ? { score: cvss3Score(vec3), vector: vec3, source: "OSV" } : vec4 ? { score: null, vector: vec4, source: "OSV" } : null,
    dbSeverity: ["critical", "high", "medium", "low"].includes(dbSeverity) ? dbSeverity : null,
    cwes: db.cwe_ids || [],
    raw: v,
  };
}

function practicesFromFiles(files) {
  const paths = [...files.keys()];
  const has = (re) => paths.find((p) => re.test(p)) || null;
  const workflows = paths.filter((p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p));
  return {
    securityPolicy: has(/^(\.github\/|docs\/)?SECURITY\.md$/i),
    dependabot: !!has(/^\.github\/dependabot\.ya?ml$/),
    renovate: !!has(/^(\.github\/)?renovate\.json5?$|^\.renovaterc(\.json)?$/),
    codeql: workflows.some((p) => /github\/codeql-action/.test(files.get(p) || "")),
    ciWorkflows: workflows.length,
  };
}

/**
 * @param {object} args
 * @param {{owner:string, repo:string}} args.target
 * @param {Map<string,string>} args.files
 * @param {Array} args.dependencies
 * @param {number} args.deadline epoch ms after which outstanding calls are abandoned
 * @param {(msg:string)=>void} [args.onProgress]
 */
async function enrich({ target, files, dependencies, deadline, onProgress = () => {} }) {
  const sources = {};
  const mark = (key, status, detail) => {
    sources[key] = { key, ...SOURCE_META[key], status, detail: detail || null };
  };
  const guard = async (key, promise) => {
    try {
      const value = await beforeDeadline(promise, deadline);
      if (value === TIMEOUT) {
        mark(key, "unavailable", "Timed out");
        return null;
      }
      return value;
    } catch (err) {
      mark(key, "unavailable", err.message);
      return null;
    }
  };

  const hasDeps = dependencies.length > 0;
  const direct = dependencies.filter((d) => d.direct).slice(0, MAX_DEPSDEV);

  // Independent lookups run in parallel with the OSV chain.
  const kevP = guard("kev", S.kevCatalog());
  const scorecardP = guard("scorecard", S.scorecard(target.owner, target.repo));
  const repoP = guard("github", S.githubRepo(target.owner, target.repo));
  const depsDevP = hasDeps ? guard("depsdev", S.mapLimit(direct, 8, S.depsDevHealth, { deadline })) : Promise.resolve([]);

  // 1. OSV: which dependency versions have known vulnerabilities.
  let pairs = [];
  if (hasDeps) {
    onProgress(`Querying OSV for ${dependencies.length} packages`);
    const idLists = await guard("osv", S.osvQueryBatch(dependencies));
    if (idLists) {
      const uniqueIds = [...new Set(idLists.flat())].slice(0, MAX_OSV_DETAILS);
      const details = await guard("osv", S.mapLimit(uniqueIds, 12, S.osvVuln, { deadline }));
      const byId = new Map();
      (details || []).forEach((v) => v && byId.set(v.id, normalizeOsv(v)));
      if (!sources.osv) mark("osv", byId.size < uniqueIds.length ? "partial" : "ok", `${dependencies.length} packages, ${byId.size} advisories`);

      idLists.forEach((ids, i) => {
        const dep = dependencies[i];
        const seen = new Set();
        for (const id of ids) {
          const v = byId.get(id);
          if (!v || v.aliases.some((a) => seen.has(a))) continue; // same advisory under another ID
          v.aliases.forEach((a) => seen.add(a));
          pairs.push({ dep, vuln: v, fixed: fixedVersionFor(v.raw, dep) });
        }
      });
    }
  } else {
    for (const k of ["osv", "ghsa", "nvd", "epss", "depsdev"]) mark(k, "skipped", "No dependency manifests found");
  }

  // 2. Scores and exploitation data for the advisories found.
  const cves = [...new Set(pairs.map((p) => p.vuln.cve).filter(Boolean))];
  const ghsaIds = [...new Set(pairs.map((p) => p.vuln.ghsa).filter(Boolean))];
  let kev = await kevP;
  if (kev && !sources.kev) mark("kev", "ok", `${kev.size} CVEs in catalog`);
  kev = kev || new Map();

  if (pairs.length) {
    onProgress(`Scoring ${pairs.length} advisories with GHSA, NVD, EPSS and KEV`);
    const ghsaCap = config.githubToken ? 150 : 25;
    // NVD is the slowest source; spend its budget on CVEs nothing else scored
    // and on the ones attackers are known to use.
    const nvdCap = config.nvdApiKey ? 60 : 8;
    const nvdOrder = [...cves].sort((a, b) => Number(kev.has(b)) - Number(kev.has(a)));

    const [epss, ghsa, nvd] = await Promise.all([
      cves.length ? guard("epss", S.epssScores(cves)) : Promise.resolve(new Map()),
      guard("ghsa", S.mapLimit(ghsaIds.slice(0, ghsaCap), 6, S.ghsaAdvisory, { deadline })),
      guard("nvd", S.mapLimit(nvdOrder.slice(0, nvdCap), 3, S.nvdCve, { deadline })),
    ]);

    const ghsaMap = new Map((ghsa || []).filter(Boolean).map((a) => [a.id, a]));
    const nvdMap = new Map((nvd || []).filter(Boolean).map((n) => [n.id, n]));
    const epssMap = epss || new Map();
    if (epss && !sources.epss) mark("epss", "ok", `${epssMap.size} of ${cves.length} CVEs scored`);
    if (ghsa && !sources.ghsa) mark("ghsa", ghsaIds.length > ghsaCap ? "partial" : "ok", `${ghsaMap.size} advisories${ghsaIds.length > ghsaCap ? `; capped at ${ghsaCap} without GITHUB_TOKEN` : ""}`);
    if (nvd && !sources.nvd) mark("nvd", cves.length > nvdCap ? "partial" : "ok", `${nvdMap.size} CVEs${cves.length > nvdCap ? `; capped at ${nvdCap}${config.nvdApiKey ? "" : " without NVD_API_KEY"}` : ""}`);

    for (const p of pairs) {
      const g = p.vuln.ghsa ? ghsaMap.get(p.vuln.ghsa) : null;
      const n = p.vuln.cve ? nvdMap.get(p.vuln.cve) : null;
      p.ghsa = g;
      p.nvd = n;
      p.kev = p.vuln.cve ? kev.get(p.vuln.cve) || null : null;
      p.epss = p.vuln.cve ? epssMap.get(p.vuln.cve) || null : null;
    }
  } else if (hasDeps) {
    for (const k of ["ghsa", "nvd", "epss"]) if (!sources[k]) mark(k, "ok", "No vulnerable packages to look up");
  }

  const findings = pairs.map(toFinding);

  // 3. Package health from deps.dev.
  const health = ((await depsDevP) || []).filter(Boolean);
  if (hasDeps && !sources.depsdev) mark("depsdev", "ok", `${health.length} direct dependencies checked`);
  for (const h of health) {
    const stale = h.latestPublishedAt && Date.now() - Date.parse(h.latestPublishedAt) > TWO_YEARS;
    if (h.deprecated || stale) findings.push(healthFinding(h, stale));
  }

  // 4. Repository posture.
  const [card, repo] = await Promise.all([scorecardP, repoP]);
  if (!sources.scorecard) mark("scorecard", card ? "ok" : "unavailable", card ? `Score ${card.score}/10` : "This repository has not been scored by OpenSSF");
  if (!sources.github) mark("github", repo ? "ok" : "unavailable", repo ? null : "Repository metadata not found");

  return {
    findings,
    dependencyHealth: health.map((h) => ({
      ecosystem: h.ecosystem, name: h.name, version: h.version, latestVersion: h.latestVersion,
      licenses: h.licenses, deprecated: h.deprecated, deprecatedReason: h.deprecatedReason,
      latestPublishedAt: h.latestPublishedAt, url: h.url,
    })),
    posture: { scorecard: card, repo, practices: practicesFromFiles(files) },
    sources: Object.values(sources),
  };
}

function toFinding({ dep, vuln, fixed, ghsa, nvd, kev, epss }) {
  const cvss = nvd?.cvss31 || ghsa?.cvss || (vuln.cvssOsv?.score != null ? vuln.cvssOsv : null) || nvd?.cvss40 || null;
  const severity = severityFromScore(cvss?.score) || ghsa?.severity || vuln.dbSeverity || "medium";
  const cwes = [...new Set([...(nvd?.cwes || []), ...(ghsa?.cwes || []).map((c) => c.id), ...vuln.cwes])];
  const urls = {
    osv: `https://osv.dev/vulnerability/${vuln.id}`,
    ghsa: vuln.ghsa ? `https://github.com/advisories/${vuln.ghsa}` : null,
    nvd: vuln.cve ? `https://nvd.nist.gov/vuln/detail/${vuln.cve}` : null,
    kev: kev ? `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${vuln.cve}` : null,
    epss: epss ? `https://api.first.org/data/v1/epss?cve=${vuln.cve}` : null,
  };
  const sources = [{ name: "OSV", url: urls.osv }];
  if (ghsa) sources.push({ name: "GHSA", url: urls.ghsa });
  if (nvd) sources.push({ name: "NVD", url: urls.nvd });
  if (kev) sources.push({ name: "KEV", url: urls.kev });
  if (epss) sources.push({ name: "EPSS", url: urls.epss });

  const label = vuln.cve || vuln.ghsa || vuln.id;
  return {
    id: findingId(["dep", dep.ecosystem, dep.name, dep.version, vuln.id]),
    type: "dependency",
    rule: label,
    severity,
    title: vuln.summary || `Vulnerability in ${dep.name}`,
    description: vuln.details || vuln.summary,
    file: dep.file,
    line: dep.line || 0,
    match: `${dep.name}@${dep.version}`,
    context: "",
    package: { ecosystem: dep.ecosystem, name: dep.name, version: dep.version, fixedVersion: fixed, direct: dep.direct, dev: !!dep.dev },
    advisory: {
      id: vuln.id,
      cve: vuln.cve,
      ghsa: vuln.ghsa,
      aliases: vuln.aliases,
      published: vuln.published,
      cvss,
      cwes: cwes.slice(0, 5),
      cweNames: Object.fromEntries((ghsa?.cwes || []).map((c) => [c.id, c.name])),
      kev,
      epss,
      urls,
    },
    exploited: !!kev,
    remediation: fixed
      ? `Upgrade ${dep.name} to ${fixed} or later${dep.direct ? "" : " (it is a transitive dependency; upgrade the package that pulls it in, or add an override)"}.`
      : `No fixed version of ${dep.name} is published. Check the advisory for workarounds, or replace the package.`,
    sources,
  };
}

function healthFinding(h, stale) {
  return {
    id: findingId(["health", h.ecosystem, h.name, h.version]),
    type: "dependency",
    rule: h.deprecated ? "deprecated-package" : "stale-package",
    severity: h.deprecated ? "low" : "info",
    title: h.deprecated ? `${h.name} is deprecated` : `${h.name} has had no release in over two years`,
    description: h.deprecated
      ? h.deprecatedReason || "The maintainers have marked this package deprecated."
      : `Latest release ${h.latestVersion} was published ${h.latestPublishedAt?.slice(0, 10)}. Unmaintained packages do not get security fixes.`,
    file: "",
    line: 0,
    match: `${h.name}@${h.version}`,
    context: "",
    package: { ecosystem: h.ecosystem, name: h.name, version: h.version, fixedVersion: null, direct: true, latestVersion: h.latestVersion, licenses: h.licenses },
    remediation: h.deprecated
      ? "Move to the replacement the maintainers recommend, or a maintained alternative."
      : "Check whether the project is still maintained, and plan a replacement if it is not.",
    sources: [{ name: "deps.dev", url: h.url }],
    stale,
  };
}

module.exports = { enrich, compareVersions, fixedVersionFor, SOURCE_META };
