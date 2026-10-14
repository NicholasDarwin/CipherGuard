// Overall risk score (0-100, higher is worse) and letter grade.
// The formula is documented in README.md#risk-score; keep the two in sync.

const SEVERITY_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
const SATURATION = 30;
const GRADES = [
  [15, "A"],
  [35, "B"],
  [55, "C"],
  [75, "D"],
  [Infinity, "F"],
];

/** Weight of one finding: CVSS when known, else severity, scaled by exploitation evidence. */
function findingWeight(f) {
  const base = f.advisory?.cvss?.score ?? SEVERITY_WEIGHT[f.severity] ?? 0;
  const kev = f.advisory?.kev ? 2 : 1;
  const epss = 1 + 2 * (f.advisory?.epss?.score ?? 0);
  return base * kev * epss;
}

/** Order findings for triage: severity, then known exploitation, EPSS, CVSS. */
function priority(f) {
  return findingWeight(f) + (f.advisory?.kev ? 1000 : 0) + (4 - (Object.keys(SEVERITY_WEIGHT).indexOf(f.severity))) * 100;
}

function computeRisk(findings, scorecard) {
  // Repeats of the same rule add little: the worst instance counts in full,
  // the rest at 10%, capped at double the worst.
  const groups = new Map();
  for (const f of findings) {
    const key = f.type === "dependency" ? `dep:${f.advisory?.id || f.rule}` : `${f.type}:${f.rule}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(findingWeight(f));
  }

  let total = 0;
  for (const weights of groups.values()) {
    weights.sort((a, b) => b - a);
    const rest = weights.slice(1).reduce((s, w) => s + w, 0);
    total += Math.min(weights[0] + 0.1 * rest, 2 * weights[0]);
  }

  let score = 100 * (1 - Math.exp(-total / SATURATION));
  const postureAdj = scorecard?.score != null ? Math.min(10, Math.max(0, (7 - scorecard.score) * 2)) : 0;
  score = Math.min(100, score + postureAdj);

  const floors = [];
  if (findings.some((f) => f.advisory?.kev)) floors.push("Known exploited vulnerability present");
  if (findings.some((f) => f.type === "secret" && f.severity === "critical")) floors.push("Critical secret exposed");
  if (floors.length) score = Math.max(score, 55);

  score = Math.round(score);
  const grade = GRADES.find(([max]) => score < max)[1];
  return {
    score,
    grade,
    inputs: { weightedTotal: Math.round(total * 10) / 10, scorecardAdjustment: postureAdj, floors },
  };
}

module.exports = { computeRisk, findingWeight, priority, SEVERITY_WEIGHT };
