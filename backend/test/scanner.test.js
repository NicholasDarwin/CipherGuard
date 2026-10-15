const test = require("node:test");
const assert = require("node:assert/strict");
const { scanSecrets, scanCode, maskSecret } = require("../src/scanner/patternScan");
const { parseGitHubUrl } = require("../src/scanner/fetchRepo");
const { extractDependencies, _parsers: P } = require("../src/scanner/dependencies");
const { cvss3Score, severityFromScore } = require("../src/enrich/cvss");
const { compareVersions } = require("../src/enrich");
const { computeRisk } = require("../src/risk");
const { sanitizeReport } = require("../src/sanitize");

// Built at runtime so this file does not trip CipherGuard's own scanner.
const FAKE_AWS = "AKIA" + "QYLPMN5HHHFPZAM2";

test("parseGitHubUrl accepts repo URLs and rejects everything else", () => {
  assert.equal(parseGitHubUrl("https://github.com/OWASP/NodeGoat").slug, "OWASP/NodeGoat");
  assert.equal(parseGitHubUrl("https://github.com/socketio/socket.io.git").repo, "socket.io");
  assert.equal(parseGitHubUrl("https://github.com/a/b/tree/main"), null);
  assert.equal(parseGitHubUrl("https://gitlab.com/a/b"), null);
  assert.equal(parseGitHubUrl("C:\\code\\repo"), null);
});

test("secret scan finds an AWS key, masks it, and reports a snippet", () => {
  const content = `const region = "us-east-1";\nconst key = "${FAKE_AWS}";\n`;
  const [f] = scanSecrets("src/config.js", content).filter((x) => x.rule === "aws_access_key");
  assert.equal(f.severity, "critical");
  assert.equal(f.line, 2);
  assert.equal(f.secret.value, FAKE_AWS);
  assert.match(f.secret.masked, /^AKIA\*+AM2$|^AKIA\*+ZAM2$/);
  assert.equal(f.snippet.startLine, 1);
});

test("credentials read from the environment are not reported", () => {
  const content = "const apiKey = process.env.STRIPE_API_KEY_LIVE_SECRET_VALUE;\n";
  assert.equal(scanSecrets("a.js", content).filter((f) => f.rule === "api_key").length, 0);
});

test("innerHTML with a static literal is not reported, with a variable it is", () => {
  assert.equal(scanCode("a.js", "el.innerHTML = '<b>hi</b>';").filter((f) => f.rule === "xss").length, 0);
  assert.equal(scanCode("a.js", "el.innerHTML = userInput;").filter((f) => f.rule === "xss").length, 1);
});

test("maskSecret keeps only the ends", () => {
  assert.equal(maskSecret("abcdefgh"), "********");
  assert.equal(maskSecret("0123456789abcdefghij"), "0123************ghij");
});

test("package-lock v3 parser marks direct dependencies", () => {
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { lodash: "^4.17.15" } },
      "node_modules/lodash": { version: "4.17.15" },
      "node_modules/minimist": { version: "1.2.0", dev: true },
    },
  });
  const deps = P.packageLock(lock, "package-lock.json");
  assert.deepEqual(deps.map((d) => [d.name, d.direct]), [["lodash", true], ["minimist", false]]);
});

test("manifest parsers for PyPI, Go, Cargo and yarn", () => {
  assert.deepEqual(P.requirementsTxt("Django==3.2.0\nrequests>=2\nflask[async]==2.0.1 # web", "r.txt").map((d) => d.name), ["Django", "flask"]);
  const go = "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n\tgolang.org/x/net v0.1.0 // indirect\n)\n";
  assert.deepEqual(P.goMod(go, "go.mod").map((d) => [d.name, d.direct]), [["github.com/gin-gonic/gin", true], ["golang.org/x/net", false]]);
  const cargo = '[[package]]\nname = "serde"\nversion = "1.0.100"\n';
  assert.equal(P.tomlPackages(cargo, "Cargo.lock", "crates.io")[0].version, "1.0.100");
  const yarn = '"@babel/core@^7.0.0":\n  version "7.1.0"\n\nlodash@^4.17.0, lodash@^4.17.15:\n  version "4.17.15"\n';
  assert.deepEqual(P.yarnLock(yarn, "yarn.lock").map((d) => d.name), ["@babel/core", "lodash"]);
});

test("package.json is only used when no lockfile sits beside it", () => {
  const pkg = JSON.stringify({ dependencies: { express: "^4.17.1" } });
  assert.equal(extractDependencies(new Map([["package.json", pkg]]), new Map()).dependencies.length, 1);
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/express": { version: "4.17.1" } } });
  const withLock = extractDependencies(new Map([["package.json", pkg]]), new Map([["package-lock.json", lock]]));
  assert.equal(withLock.dependencies.length, 1);
  assert.equal(withLock.dependencies[0].approximate, undefined);
});

test("CVSS 3.1 base scores match the FIRST calculator", () => {
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"), 7.2);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  assert.equal(cvss3Score("CVSS:4.0/AV:N"), null);
  assert.equal(severityFromScore(9.8), "critical");
  assert.equal(severityFromScore(4.0), "medium");
});

test("compareVersions orders numeric parts numerically", () => {
  assert.ok(compareVersions("4.17.21", "4.17.15") > 0);
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
  assert.equal(compareVersions("v1.2.0", "1.2.0"), 0);
});

test("risk: clean repo is A, a KEV vulnerability floors at D or worse", () => {
  assert.deepEqual([computeRisk([]).score, computeRisk([]).grade], [0, "A"]);
  const kevFinding = { type: "dependency", rule: "CVE-1", severity: "medium", advisory: { id: "X", cvss: { score: 5 }, kev: { dateAdded: "2024-01-01" }, epss: { score: 0.5 } } };
  const r = computeRisk([kevFinding]);
  assert.ok(r.score >= 55, `score ${r.score}`);
  assert.ok(["D", "F"].includes(r.grade));
});

test("risk: repeats of one rule add far less than distinct rules", () => {
  const low = (rule) => ({ type: "code", rule, severity: "low" });
  const repeated = computeRisk(Array.from({ length: 50 }, () => low("http_without_tls"))).score;
  const distinct = computeRisk(Array.from({ length: 10 }, (_, i) => low("r" + i))).score;
  assert.ok(repeated < distinct, `${repeated} < ${distinct}`);
});

test("sanitizeReport removes secret values everywhere", () => {
  const [f] = scanSecrets("a.js", `const k = "${FAKE_AWS}";`).filter((x) => x.rule === "aws_access_key");
  const out = sanitizeReport({ repository: "x", findings: [f], overallAssessment: `rotate ${FAKE_AWS}` });
  const text = JSON.stringify(out);
  assert.ok(!text.includes(FAKE_AWS));
  assert.equal(out.findings[0].secret.value, undefined);
  assert.equal(out.redacted, true);
});

test("dependencies record the lockfile line of the exact installed copy", () => {
  const lock = JSON.stringify(
    {
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { minimist: "^1.2.0" } },
        "node_modules/minimist": { version: "1.2.0" },
        "node_modules/mkdirp/node_modules/minimist": { version: "0.0.8" },
      },
    },
    null,
    2
  );
  const { dependencies } = extractDependencies(new Map(), new Map([["package-lock.json", lock]]));
  const lines = lock.split("\n");
  for (const d of dependencies) {
    assert.match(lines[d.line - 1], new RegExp(`"${d.lockKey}": \{`));
    assert.match(lines[d.line], new RegExp(`"version": "${d.version.replace(/\./g, "\.")}"`));
  }
});
