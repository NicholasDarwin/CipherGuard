// Client-side twin of backend/src/sanitize.js: replace every detected secret
// value with its masked form before a report is stored, exported or shared.
function maskAll(text, secrets) {
  if (typeof text !== "string") return text;
  let out = text;
  for (const s of secrets) out = out.split(s.value).join(s.masked);
  return out;
}

export function maskKeyBlock(lines) {
  let inside = false;
  return lines.map((l) => {
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(l)) {
      inside = true;
      return l;
    }
    if (/-----END [A-Z ]*PRIVATE KEY-----/.test(l)) {
      inside = false;
      return l;
    }
    return inside ? l.replace(/[A-Za-z0-9+/=]{8,}/g, (m) => m.slice(0, 2) + "*".repeat(Math.max(0, m.length - 4)) + m.slice(-2)) : l;
  });
}

export function sanitizeFinding(f, secrets) {
  const copy = { ...f, match: maskAll(f.match, secrets), context: maskAll(f.context, secrets) };
  if (f.secret) copy.secret = { masked: f.secret.masked };
  if (f.snippet) {
    let lines = f.snippet.lines.map((l) => maskAll(l, secrets));
    if (f.rule === "private_key") lines = maskKeyBlock(lines);
    copy.snippet = { ...f.snippet, lines };
  }
  if (f.ai) copy.ai = { ...f.ai, explanation: maskAll(f.ai.explanation, secrets), fix: maskAll(f.ai.fix, secrets) };
  return copy;
}

export function secretsOf(report) {
  return (report?.findings || [])
    .filter((f) => f.secret?.value)
    .map((f) => f.secret)
    .sort((a, b) => b.value.length - a.value.length);
}

export function sanitizeReport(report) {
  if (!report?.findings) return report;
  const secrets = secretsOf(report);
  return {
    ...report,
    findings: report.findings.map((f) => sanitizeFinding(f, secrets)),
    overallAssessment: maskAll(report.overallAssessment, secrets),
    aiAnalyses: (report.aiAnalyses || []).map((a) => ({ ...a, analysis: maskAll(a.analysis, secrets) })),
    redacted: true,
  };
}
