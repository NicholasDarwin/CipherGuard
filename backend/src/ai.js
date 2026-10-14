// Gemini analysis. One request explains the top findings and writes a summary,
// grounded in the scanner output and the OSINT data (CVSS, EPSS, KEV,
// Scorecard). Secret values are masked before they leave this process.
const config = require("./config");

const MAX_FINDINGS = 20;

// Gemini declines prompts that read as "judge this repository's security",
// so the task is framed as explaining tool output on the developer's own code.
const REFUSAL_MARKERS = [
  "i cannot fulfill", "i cannot provide", "i can not fulfill", "i can't fulfill",
  "i can't provide", "i cannot assist", "i can't assist", "i am unable to",
  "i'm unable to", "i cannot conduct", "i cannot perform", "as an ai language model, i cannot",
];

const isRefusal = (text) => !text || REFUSAL_MARKERS.some((m) => text.toLowerCase().includes(m));

function redact(text, finding) {
  if (!text || !finding.secret) return text;
  return text.split(finding.secret.value).join(finding.secret.masked);
}

function describe(f) {
  const a = f.advisory;
  const lines = [`id: ${f.id}`, `rule: ${f.rule} (${f.severity})`, `title: ${f.title}`];
  if (f.file) lines.push(`location: ${f.file}${f.line ? `:${f.line}` : ""}`);
  if (f.context) lines.push(`line content: ${redact(f.context, f).slice(0, 200)}`);
  if (f.package) lines.push(`package: ${f.package.ecosystem} ${f.package.name}@${f.package.version}${f.package.fixedVersion ? ` (fixed in ${f.package.fixedVersion})` : ""}${f.package.direct ? ", direct" : ", transitive"}`);
  if (a) {
    if (a.cvss) lines.push(`CVSS ${a.cvss.score ?? "?"} (${a.cvss.source}) ${a.cvss.vector || ""}`);
    if (a.epss) lines.push(`EPSS ${(a.epss.score * 100).toFixed(1)}% probability of exploitation in 30 days (percentile ${(a.epss.percentile * 100).toFixed(0)})`);
    if (a.kev) lines.push(`CISA KEV: actively exploited, added ${a.kev.dateAdded}${a.kev.ransomware ? ", used in ransomware campaigns" : ""}`);
    if (a.cwes?.length) lines.push(`CWE: ${a.cwes.join(", ")}`);
  }
  return lines.map((l) => "  " + l).join("\n");
}

function buildPrompt(report, top) {
  const p = report.posture || {};
  const posture = [];
  if (p.scorecard) posture.push(`OpenSSF Scorecard ${p.scorecard.score}/10; weakest checks: ${p.scorecard.checks.slice(0, 4).map((c) => `${c.name} ${c.score}/10`).join(", ")}`);
  if (p.practices) posture.push(`SECURITY.md: ${p.practices.securityPolicy ? "yes" : "no"}; Dependabot: ${p.practices.dependabot ? "yes" : "no"}; CodeQL: ${p.practices.codeql ? "yes" : "no"}`);
  if (p.repo?.pushedAt) posture.push(`last push ${p.repo.pushedAt.slice(0, 10)}`);

  return `A developer ran static analysis and dependency checks over their own
source code. Help them read the output. All facts below come from the tools and
from public vulnerability databases (OSV, GitHub Advisories, NVD, CISA KEV,
FIRST EPSS, OpenSSF Scorecard). Use only these facts; do not invent CVEs,
scores, or code you were not shown.

Computed risk: ${report.risk.score}/100 (grade ${report.risk.grade}).
Counts: ${Object.entries(report.severityCounts).map(([k, v]) => `${v} ${k}`).join(", ")}.
${posture.length ? "Repository posture: " + posture.join("; ") + "." : ""}

Findings, highest priority first:
${top.map(describe).join("\n\n")}

Respond with JSON only, in this shape:
{
  "summary": "Markdown, under 220 words. Two or three sentences on what matters most, then a short 'Where to start' list ordered by what to fix first. Mention EPSS or KEV only where it changes the priority.",
  "findings": [
    { "id": "<id from above>",
      "explanation": "2-3 sentences: what the issue is and why it matters here.",
      "fix": "1-2 sentences: the concrete change.",
      "falsePositive": "likely" | "possible" | "unlikely" }
  ]
}
Write directly to the developer, plainly. Include every finding id listed.`;
}

function parseJson(text) {
  const body = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "");
  return JSON.parse(body);
}

/**
 * Returns { summary, byId: Map<id, {explanation, fix, falsePositive}>, status }.
 * Never throws: AI is an optional layer on top of the scan.
 */
async function analyze(report, findings, { deadline } = {}) {
  if (!config.geminiApiKey) return { status: "skipped", detail: "GEMINI_API_KEY is not set", summary: null, byId: new Map() };
  if (!findings.length) return { status: "skipped", detail: "Nothing to analyze", summary: null, byId: new Map() };

  const top = findings.filter((f) => f.severity !== "info").slice(0, MAX_FINDINGS);
  if (!top.length) return { status: "skipped", detail: "Only informational findings", summary: null, byId: new Map() };

  try {
    const { GoogleGenAI } = require("@google/genai");
    const ai = new GoogleGenAI({ apiKey: config.geminiApiKey });
    const ms = Math.max(5_000, (deadline || Date.now() + 30_000) - Date.now());
    const result = await Promise.race([
      ai.models.generateContent({
        model: config.geminiModel,
        contents: buildPrompt(report, top),
        config: { responseMimeType: "application/json", temperature: 0.2 },
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("AI analysis timed out")), ms)),
    ]);
    const text = result.text || "";
    if (isRefusal(text)) return { status: "unavailable", detail: "The model declined to answer", summary: null, byId: new Map() };

    const parsed = parseJson(text);
    const byId = new Map();
    for (const item of parsed.findings || []) {
      if (item?.id) byId.set(item.id, { explanation: item.explanation || "", fix: item.fix || "", falsePositive: item.falsePositive || null });
    }
    return { status: "ok", detail: `${config.geminiModel}, ${byId.size} findings explained`, summary: parsed.summary || null, byId };
  } catch (err) {
    return { status: "unavailable", detail: err.message.slice(0, 200), summary: null, byId: new Map() };
  }
}

module.exports = { analyze, buildPrompt };
