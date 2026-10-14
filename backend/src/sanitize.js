// Produce a copy of a report that is safe to store, share, or export:
// every detected secret value is replaced by its masked form.

function maskAll(text, secrets) {
  if (typeof text !== "string") return text;
  let out = text;
  for (const s of secrets) out = out.split(s.value).join(s.masked);
  return out;
}

// Private keys span many lines; mask every base64 body line under a header.
function maskKeyBlock(lines) {
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

function sanitizeReport(report) {
  if (!report || !Array.isArray(report.findings)) return report;
  const secrets = report.findings.filter((f) => f.secret?.value).map((f) => f.secret);
  // Longest first, so a secret that contains another is masked whole.
  secrets.sort((a, b) => b.value.length - a.value.length);

  const findings = report.findings.map((f) => {
    const copy = { ...f, match: maskAll(f.match, secrets), context: maskAll(f.context, secrets) };
    if (f.secret) copy.secret = { masked: f.secret.masked };
    if (f.snippet) {
      let lines = f.snippet.lines.map((l) => maskAll(l, secrets));
      if (f.rule === "private_key") lines = maskKeyBlock(lines);
      copy.snippet = { ...f.snippet, lines };
    }
    if (f.ai) copy.ai = { ...f.ai, explanation: maskAll(f.ai.explanation, secrets), fix: maskAll(f.ai.fix, secrets) };
    return copy;
  });

  return {
    ...report,
    findings,
    overallAssessment: maskAll(report.overallAssessment, secrets),
    aiAnalyses: (report.aiAnalyses || []).map((a) => ({ ...a, analysis: maskAll(a.analysis, secrets) })),
    redacted: true,
  };
}

module.exports = { sanitizeReport };
