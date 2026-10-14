const crypto = require("crypto");
const { SECRET_PATTERNS, VULNERABILITY_PATTERNS } = require("./patterns");

const SNIPPET_RADIUS = 3;
const SNIPPET_LINE_MAX = 240;

// --- False-positive suppression -------------------------------------------
// A scanner that reads its own rule table finds its own regexes, and a URL
// inside a comment is not a network call.
const COMMENT_LINE = /^\s*(#|\/\/|\/\*|\*(?!\/)|<!--)/;
const PATTERN_DEF_LINE = /['"]?(pattern|description|severity|title|remediation)['"]?\s*:/i;
// Reading a credential from the environment is the fix, not the bug.
const ENV_REF = /(process\.env\.|os\.getenv|os\.environ|import\.meta\.env|ENV\[)/i;
const CREDENTIAL_RULES = new Set([
  "api_key", "token", "secret", "bearer", "password",
  "authorization", "connection_string", "database_url", "hardcoded_secret",
]);
// Bind/placeholder addresses are configuration, not a leaked host.
const IGNORED_IPS = new Set(["0.0.0.0", "127.0.0.1", "255.255.255.255", "0.0.0.1"]);
// innerHTML assigned a literal with no interpolation cannot inject anything.
const XSS_STATIC_RHS =
  /(?:innerHTML|outerHTML)\s*=\s*(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`$\\]|\\.|\$(?!\{))*`)\s*;?\s*$/;
const INTERPOLATION = /\$\{([^}]*)\}/g;
const XSS_TEMPLATE_RHS = /^(?:innerHTML|outerHTML|document\.write)\s*=\s*`/;

// Rules whose matches are discarded inside inline SVG geometry, where
// coordinate runs look like dotted quads.
const SVG_SENSITIVE_RULES = new Set(["ip_address"]);
const SVG_REGIONS = [
  /<svg\b[^>]*>[\s\S]*?<\/svg>/gi,
  /\b(?:d|points|viewBox|transform|preserveAspectRatio)\s*=\s*"[^"]*"/gi,
  /\b(?:d|points|viewBox|transform|preserveAspectRatio)\s*=\s*'[^']*'/gi,
];

function svgSpans(content) {
  const spans = [];
  for (const re of SVG_REGIONS) {
    for (const m of content.matchAll(re)) spans.push([m.index, m.index + m[0].length]);
  }
  return spans;
}

// Looks at the whole template literal rather than the matched line, because
// these assignments open a backtick and close it several lines later. Only
// fires when the right-hand side *is* a template literal, so
// `el.innerHTML = user` is still reported.
function xssSafeTemplate(content, start) {
  const window = content.slice(start, start + 4000);
  const m = window.match(XSS_TEMPLATE_RHS);
  if (!m) return false;
  const close = window.indexOf("`", m[0].length);
  const literal = close !== -1 ? window.slice(m[0].length, close) : window.slice(m[0].length);
  const spans = [...literal.matchAll(INTERPOLATION)].map((s) => s[1]);
  if (spans.length === 0) return true;
  return spans.every((s) => s.includes("escapeHtml("));
}

function isFalsePositive(rule, lineText, matchText, content, start) {
  if (!lineText) return false;
  if (COMMENT_LINE.test(lineText) || PATTERN_DEF_LINE.test(lineText)) return true;
  if (CREDENTIAL_RULES.has(rule) && ENV_REF.test(lineText)) return true;
  if (rule === "ip_address" && IGNORED_IPS.has(matchText)) return true;
  if (rule === "xss") {
    if (XSS_STATIC_RHS.test(lineText)) return true;
    const spans = [...lineText.matchAll(INTERPOLATION)].map((m) => m[1]);
    if (spans.length && spans.every((s) => s.includes("escapeHtml("))) return true;
    if (xssSafeTemplate(content, start)) return true;
  }
  return false;
}

// --- Secret masking --------------------------------------------------------
// The secret is the longest credential-looking run inside the match, so
// `api_key = "abc..."` keeps the key name readable and masks only the value.
function secretValue(match) {
  const runs = match.match(/[A-Za-z0-9_\-./+=@:]{8,}/g) || [];
  return runs.sort((a, b) => b.length - a.length)[0] || match;
}

function maskSecret(value) {
  if (value.length <= 8) return "*".repeat(value.length);
  const keep = value.length >= 20 ? 4 : 2;
  return value.slice(0, keep) + "*".repeat(value.length - keep * 2) + value.slice(-keep);
}

// --- Helpers ---------------------------------------------------------------
function findingId(parts) {
  return crypto.createHash("sha1").update(parts.join("\u0000")).digest("hex").slice(0, 12);
}

function lineStarts(content) {
  const starts = [0];
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineAt(starts, index) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

function snippetFor(lines, line) {
  const start = Math.max(1, line - SNIPPET_RADIUS);
  const end = Math.min(lines.length, line + SNIPPET_RADIUS);
  return {
    startLine: start,
    lines: lines.slice(start - 1, end).map((l) => (l.length > SNIPPET_LINE_MAX ? l.slice(0, SNIPPET_LINE_MAX) + "…" : l)),
  };
}

function scanContent(relPath, content, rules, type) {
  const findings = [];
  let starts = null;
  let lines = null;
  let svg = null;

  for (const [rule, cfg] of Object.entries(rules)) {
    const re = new RegExp(cfg.pattern.source, cfg.pattern.flags.replace("g", "") + "g");
    for (const m of content.matchAll(re)) {
      if (SVG_SENSITIVE_RULES.has(rule)) {
        svg ??= svgSpans(content);
        if (svg.some(([s, e]) => m.index >= s && m.index < e)) continue;
      }
      starts ??= lineStarts(content);
      lines ??= content.split("\n");
      const line = lineAt(starts, m.index);
      const lineText = lines[line - 1] || "";
      if (isFalsePositive(rule, lineText, m[0], content, m.index)) continue;

      const match = m[0].length > 120 ? m[0].slice(0, 120) + "…" : m[0];
      const finding = {
        id: findingId([type, rule, relPath, line, m[0]]),
        type,
        rule,
        severity: cfg.severity,
        title: cfg.title,
        description: cfg.title,
        file: relPath,
        line,
        match,
        context: lineText.trim().slice(0, 200),
        snippet: snippetFor(lines, line),
        remediation: cfg.remediation,
        sources: [{ name: "CipherGuard rules" }],
      };
      if (type === "secret" && cfg.severity !== "info") {
        const value = secretValue(m[0]);
        finding.secret = { value, masked: maskSecret(value) };
      }
      findings.push(finding);
    }
  }
  return findings;
}

const scanSecrets = (relPath, content) => scanContent(relPath, content, SECRET_PATTERNS, "secret");
const scanCode = (relPath, content) => scanContent(relPath, content, VULNERABILITY_PATTERNS, "code");

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    if (seen.has(f.id)) return false;
    seen.add(f.id);
    return true;
  });
}

module.exports = { scanSecrets, scanCode, dedupe, maskSecret, secretValue, findingId, isFalsePositive };
