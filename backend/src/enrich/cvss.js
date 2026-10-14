// CVSS v3.x base score from a vector string, per the FIRST v3.1 specification
// (https://www.first.org/cvss/v3.1/specification-document#7-4-Metric-Values).
// OSV records carry vectors but not scores; this fills the gap when GHSA and
// NVD are unavailable.

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

function roundUp(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

function cvss3Score(vector) {
  if (!/^CVSS:3\.[01]\//.test(vector || "")) return null;
  const m = Object.fromEntries(vector.split("/").slice(1).map((p) => p.split(":")));
  const scope = m.S;
  if (!W.AV[m.AV] || !W.AC[m.AC] || !W.UI[m.UI] || !scope || !W.PR[scope]?.[m.PR]) return null;
  if ([m.C, m.I, m.A].some((v) => W.CIA[v] === undefined)) return null;

  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * W.PR[scope][m.PR] * W.UI[m.UI];
  if (impact <= 0) return 0;
  return scope === "U" ? roundUp(Math.min(impact + exploitability, 10)) : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

function severityFromScore(score) {
  if (score == null) return null;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

module.exports = { cvss3Score, severityFromScore };
