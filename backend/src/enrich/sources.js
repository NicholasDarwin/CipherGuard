// One function per public data source. Each returns plain data and throws on
// failure; the orchestrator in index.js decides what a failure means.
const config = require("../config");
const { getJson, mapLimit, RateLimiter } = require("./http");

const HOUR = 3600e3;

// ---------------------------------------------------------------- OSV.dev --
const OSV = "https://api.osv.dev/v1";

/** For each dependency, the OSV vulnerability IDs affecting that version. */
async function osvQueryBatch(deps) {
  const ids = new Array(deps.length).fill(null).map(() => []);
  for (let start = 0; start < deps.length; start += 1000) {
    const chunk = deps.slice(start, start + 1000);
    const res = await getJson(`${OSV}/querybatch`, {
      method: "POST",
      body: { queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) },
      ttlMs: 6 * HOUR,
      timeoutMs: 20_000,
    });
    (res?.results || []).forEach((r, i) => {
      ids[start + i] = (r.vulns || []).map((v) => v.id);
    });
  }
  return ids;
}

const osvVuln = (id) => getJson(`${OSV}/vulns/${encodeURIComponent(id)}`, { ttlMs: 24 * HOUR });

// ------------------------------------------------- GitHub Advisory Database --
// 60 requests/hour without a token, 5000 with one.
const githubLimiter = new RateLimiter(config.githubToken ? 20 : 8, 1000);
const githubHeaders = () => ({
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  ...(config.githubToken ? { Authorization: `Bearer ${config.githubToken}` } : {}),
});

async function ghsaAdvisory(ghsaId) {
  const a = await getJson(`https://api.github.com/advisories/${ghsaId}`, { headers: githubHeaders(), limiter: githubLimiter, ttlMs: 24 * HOUR });
  if (!a) return null;
  return {
    id: a.ghsa_id,
    cve: a.cve_id || null,
    severity: a.severity === "moderate" ? "medium" : a.severity,
    cvss: a.cvss?.score ? { score: a.cvss.score, vector: a.cvss.vector_string, source: "GHSA" } : null,
    cwes: (a.cwes || []).map((c) => ({ id: c.cwe_id, name: c.name })),
    url: a.html_url,
  };
}

// ------------------------------------------------------------------ NVD 2.0 --
// 5 requests / 30 s without a key, 50 / 30 s with one.
const nvdLimiter = new RateLimiter(config.nvdApiKey ? 45 : 5, 30_000);

async function nvdCve(cveId) {
  const res = await getJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, {
    headers: config.nvdApiKey ? { apiKey: config.nvdApiKey } : {},
    limiter: nvdLimiter,
    ttlMs: 24 * HOUR,
    timeoutMs: 15_000,
  });
  const cve = res?.vulnerabilities?.[0]?.cve;
  if (!cve) return null;
  const pick = (list) => (list || []).find((m) => m.type === "Primary") || (list || [])[0];
  const v4 = pick(cve.metrics?.cvssMetricV40);
  const v31 = pick(cve.metrics?.cvssMetricV31) || pick(cve.metrics?.cvssMetricV30);
  const cwes = new Set();
  for (const w of cve.weaknesses || []) for (const d of w.description || []) if (/^CWE-\d+$/.test(d.value)) cwes.add(d.value);
  return {
    id: cve.id,
    cvss31: v31 ? { score: v31.cvssData.baseScore, vector: v31.cvssData.vectorString, source: "NVD" } : null,
    cvss40: v4 ? { score: v4.cvssData.baseScore, vector: v4.cvssData.vectorString, source: "NVD" } : null,
    cwes: [...cwes],
    url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
  };
}

// --------------------------------------------------------------- CISA KEV --
const KEV_FEEDS = [
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
];
let kevIndex = null;

async function kevCatalog() {
  if (kevIndex && kevIndex.expires > Date.now()) return kevIndex.map;
  let lastErr;
  for (const url of KEV_FEEDS) {
    try {
      const feed = await getJson(url, { ttlMs: 12 * HOUR, timeoutMs: 15_000, cacheKey: "cisa-kev" });
      const map = new Map();
      for (const v of feed?.vulnerabilities || []) {
        map.set(v.cveID, {
          dateAdded: v.dateAdded,
          dueDate: v.dueDate,
          name: v.vulnerabilityName,
          ransomware: v.knownRansomwareCampaignUse === "Known",
          requiredAction: v.requiredAction,
        });
      }
      kevIndex = { map, expires: Date.now() + 12 * HOUR };
      return map;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

// -------------------------------------------------------------- FIRST EPSS --
async function epssScores(cves) {
  const out = new Map();
  for (let i = 0; i < cves.length; i += 100) {
    const chunk = cves.slice(i, i + 100);
    const res = await getJson(`https://api.first.org/data/v1/epss?cve=${chunk.join(",")}`, { ttlMs: 12 * HOUR });
    for (const row of res?.data || []) {
      out.set(row.cve, { score: Number(row.epss), percentile: Number(row.percentile), date: row.date });
    }
  }
  return out;
}

// ------------------------------------------------------ OpenSSF Scorecard --
async function scorecard(owner, repo) {
  const res = await getJson(`https://api.securityscorecards.dev/projects/github.com/${owner}/${repo}`, { ttlMs: 12 * HOUR });
  if (!res) return null;
  return {
    score: res.score,
    date: res.date,
    url: `https://scorecard.dev/viewer/?uri=github.com/${owner}/${repo}`,
    checks: (res.checks || [])
      .map((c) => ({ name: c.name, score: c.score, reason: c.reason, url: c.documentation?.url, description: c.documentation?.short }))
      .sort((a, b) => a.score - b.score),
  };
}

// --------------------------------------------------------------- deps.dev --
const DEPSDEV_SYSTEM = { npm: "NPM", PyPI: "PYPI", Go: "GO", "crates.io": "CARGO", RubyGems: "RUBYGEMS" };

async function depsDevHealth(dep) {
  const system = DEPSDEV_SYSTEM[dep.ecosystem];
  if (!system) return null;
  const base = `https://api.deps.dev/v3/systems/${system}/packages/${encodeURIComponent(dep.name)}`;
  const [version, pkg] = await Promise.all([
    getJson(`${base}/versions/${encodeURIComponent(dep.version)}`, { ttlMs: 24 * HOUR }),
    getJson(base, { ttlMs: 24 * HOUR }),
  ]);
  if (!version && !pkg) return null;
  const latest = (pkg?.versions || []).find((v) => v.isDefault);
  return {
    ...dep,
    licenses: version?.licenses || [],
    deprecated: !!(version?.isDeprecated || latest?.isDeprecated),
    deprecatedReason: version?.deprecatedReason || latest?.deprecatedReason || null,
    publishedAt: version?.publishedAt || null,
    latestVersion: latest?.versionKey?.version || null,
    latestPublishedAt: latest?.publishedAt || null,
    url: `https://deps.dev/${system.toLowerCase()}/${encodeURIComponent(dep.name)}/${encodeURIComponent(dep.version)}`,
  };
}

// ------------------------------------------------------- GitHub repo meta --
async function githubRepo(owner, repo) {
  const r = await getJson(`https://api.github.com/repos/${owner}/${repo}`, { headers: githubHeaders(), limiter: githubLimiter, ttlMs: HOUR });
  if (!r) return null;
  let openSecurityIssues = null;
  try {
    const q = encodeURIComponent(`repo:${owner}/${repo} is:issue is:open label:security`);
    const s = await getJson(`https://api.github.com/search/issues?q=${q}&per_page=1`, { headers: githubHeaders(), limiter: githubLimiter, ttlMs: HOUR });
    openSecurityIssues = s?.total_count ?? null;
  } catch {
    /* search has its own, stricter rate limit */
  }
  return {
    fullName: r.full_name,
    description: r.description,
    url: r.html_url,
    stars: r.stargazers_count,
    forks: r.forks_count,
    openIssues: r.open_issues_count,
    openSecurityIssues,
    defaultBranch: r.default_branch,
    license: r.license?.spdx_id && r.license.spdx_id !== "NOASSERTION" ? r.license.spdx_id : null,
    archived: r.archived,
    pushedAt: r.pushed_at,
    language: r.language,
  };
}

module.exports = { osvQueryBatch, osvVuln, ghsaAdvisory, nvdCve, kevCatalog, epssScores, scorecard, depsDevHealth, githubRepo, mapLimit };
