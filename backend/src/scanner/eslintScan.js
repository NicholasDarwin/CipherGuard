const os = require("os");
const path = require("path");
const { findingId } = require("./patternScan");

// Security-focused rules only. Style rules are noise in a security report,
// and the noisiest security rules (object injection, non-literal fs paths,
// timing attacks) are left out because they fire on most codebases.
const RULES = {
  "no-implied-eval": ["error", "high", "String passed to a timer or Function", "Pass a function to setTimeout/setInterval instead of a string."],
  "no-new-func": ["error", "high", "Function constructor", "Replace new Function(...) with a normal function; it evaluates strings like eval."],
  "no-script-url": ["error", "medium", "javascript: URL", "Attach an event handler instead of using a javascript: URL."],
  "security/detect-child-process": ["warn", "medium", "child_process with a dynamic argument", "Use execFile/spawn with an argument array and validate inputs."],
  "security/detect-eval-with-expression": ["error", "high", "eval with a non-literal argument", "Remove dynamic evaluation; parse data explicitly."],
  "security/detect-non-literal-require": ["warn", "medium", "require() with a dynamic path", "Require modules by literal path or from an allow-list."],
  "security/detect-non-literal-regexp": ["warn", "low", "RegExp built from a variable", "Escape user input before building a RegExp, or avoid it; untrusted patterns enable ReDoS."],
  "security/detect-unsafe-regex": ["warn", "medium", "Regex vulnerable to catastrophic backtracking", "Rewrite the pattern to avoid nested quantifiers, or add an input length limit."],
  "security/detect-pseudoRandomBytes": ["error", "medium", "crypto.pseudoRandomBytes", "Use crypto.randomBytes."],
  "security/detect-buffer-noassert": ["error", "medium", "Buffer read/write with noAssert", "Remove the noAssert flag so bounds are checked."],
  "security/detect-new-buffer": ["error", "medium", "new Buffer() with a variable", "Use Buffer.from or Buffer.alloc."],
  "security/detect-disable-mustache-escape": ["error", "high", "Template escaping disabled", "Keep escapeMarkup enabled."],
  "security/detect-no-csrf-before-method-override": ["error", "medium", "CSRF middleware before methodOverride", "Register methodOverride before csrf."],
  "security/detect-bidi-characters": ["error", "high", "Bidirectional control characters (Trojan Source)", "Remove the invisible bidi characters; they can make code read differently than it runs."],
};

const JS_EXT = /\.(?:m|c)?jsx?$/i;
const MAX_LINT_FILES = 500;
const MAX_LINT_BYTES = 200_000;

let engine = null;

function getEngine() {
  if (engine) return engine;
  const { ESLint } = require("eslint");
  const security = require("eslint-plugin-security");
  const rules = Object.fromEntries(Object.entries(RULES).map(([k, [level]]) => [k, level]));
  engine = new ESLint({
    cwd: os.tmpdir(),
    overrideConfigFile: true,
    overrideConfig: [
      {
        files: ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs"],
        languageOptions: {
          ecmaVersion: "latest",
          sourceType: "module",
          parserOptions: { ecmaFeatures: { jsx: true } },
          // no-implied-eval only recognizes timers it knows are globals.
          globals: Object.fromEntries(
            ["setTimeout", "setInterval", "execScript", "window", "global", "globalThis", "self", "require", "module", "process", "Buffer"].map((g) => [g, "readonly"])
          ),
        },
        plugins: { security },
        rules,
      },
    ],
  });
  return engine;
}

/** Lint JS files in memory. Files that do not parse are skipped silently. */
async function runEslint(files, { deadline } = {}) {
  const eslint = getEngine();
  const findings = [];
  let linted = 0;

  for (const [rel, content] of files) {
    if (!JS_EXT.test(rel) || content.length > MAX_LINT_BYTES) continue;
    // Bundled or minified output: one enormous line.
    if (content.length > 5000 && content.split("\n", 20).length < 5) continue;
    if (linted >= MAX_LINT_FILES || (deadline && Date.now() > deadline)) break;
    linted++;

    let results;
    try {
      results = await eslint.lintText(content, { filePath: path.join(os.tmpdir(), "cg-lint", rel), warnIgnored: false });
    } catch {
      continue;
    }
    const lines = content.split("\n");
    for (const msg of results[0]?.messages || []) {
      if (msg.fatal || !RULES[msg.ruleId]) continue;
      const [, severity, title, remediation] = RULES[msg.ruleId];
      const line = msg.line || 1;
      const start = Math.max(1, line - 3);
      findings.push({
        id: findingId(["eslint", msg.ruleId, rel, line, msg.column]),
        type: "code",
        rule: msg.ruleId,
        severity,
        title,
        description: msg.message,
        file: rel,
        line,
        match: (lines[line - 1] || "").trim().slice(0, 120),
        context: (lines[line - 1] || "").trim().slice(0, 200),
        snippet: { startLine: start, lines: lines.slice(start - 1, Math.min(lines.length, line + 3)).map((l) => l.slice(0, 240)) },
        remediation,
        sources: [{ name: "ESLint", url: msg.ruleId.startsWith("security/") ? "https://github.com/eslint-community/eslint-plugin-security" : `https://eslint.org/docs/latest/rules/${msg.ruleId}` }],
      });
    }
  }
  return { findings, linted };
}

module.exports = { runEslint };
