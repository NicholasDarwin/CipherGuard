// Extract (ecosystem, name, version) triples from lockfiles and manifests.
// Ecosystem names follow OSV (https://ossf.github.io/osv-schema/#affectedpackage-field).

const MAX_DEPENDENCIES = 1000; // OSV querybatch limit

const basename = (p) => p.split("/").pop();
const dirname = (p) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const cleanVersion = (v) => String(v || "").trim().replace(/^[v=]+/, "");
const EXACT = /^\d+(\.\d+){0,3}([-+][\w.-]+)?$/;

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function packageLock(text, file) {
  const lock = parseJson(text);
  if (!lock) return [];
  const out = [];
  const root = lock.packages?.[""] || {};
  const direct = new Set([...Object.keys(root.dependencies || {}), ...Object.keys(root.devDependencies || {})]);

  if (lock.packages) {
    for (const [key, meta] of Object.entries(lock.packages)) {
      if (!key || !meta.version || meta.link) continue;
      const name = meta.name || key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      const isDirect = key === `node_modules/${name}` && direct.has(name);
      out.push({ ecosystem: "npm", name, version: meta.version, file, direct: isDirect, dev: !!meta.dev, lockKey: key });
    }
  } else if (lock.dependencies) {
    // lockfileVersion 1: nested tree.
    const walk = (deps, depth) => {
      for (const [name, meta] of Object.entries(deps || {})) {
        if (meta.version) out.push({ ecosystem: "npm", name, version: meta.version, file, direct: depth === 0, dev: !!meta.dev });
        walk(meta.dependencies, depth + 1);
      }
    };
    walk(lock.dependencies, 0);
  }
  return out;
}

function packageJson(text, file) {
  const pkg = parseJson(text);
  if (!pkg) return [];
  const out = [];
  for (const [field, dev] of [["dependencies", false], ["devDependencies", true]]) {
    for (const [name, range] of Object.entries(pkg[field] || {})) {
      const version = cleanVersion(String(range).replace(/^[\^~>=<\s]+/, ""));
      if (EXACT.test(version)) out.push({ ecosystem: "npm", name, version, file, direct: true, dev, approximate: true });
    }
  }
  return out;
}

function yarnLock(text, file) {
  const out = [];
  const blocks = text.split(/\n(?=\S)/);
  for (const block of blocks) {
    const header = block.split("\n")[0];
    const version = block.match(/^\s+version:?\s+"?([^"\s]+)"?/m);
    if (!version || header.startsWith("#") || header.startsWith("__metadata")) continue;
    const first = header.replace(/^"/, "").split(/,\s*/)[0];
    const at = first.lastIndexOf("@");
    if (at <= 0) continue;
    out.push({ ecosystem: "npm", name: first.slice(0, at), version: cleanVersion(version[1]), file, direct: false });
  }
  return out;
}

function pnpmLock(text, file) {
  const out = [];
  const section = text.split(/^packages:\s*$/m)[1];
  if (!section) return out;
  for (const m of section.matchAll(/^ {2}'?\/?((?:@[^/@\s]+\/)?[^/@\s]+)[@/](\d[^:'(\s]*)/gm)) {
    out.push({ ecosystem: "npm", name: m[1], version: m[2], file, direct: false });
  }
  return out;
}

function requirementsTxt(text, file) {
  const out = [];
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0].trim();
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([\w.+!-]+)/);
    if (m) out.push({ ecosystem: "PyPI", name: m[1], version: m[2], file, direct: true });
  }
  return out;
}

function pipfileLock(text, file) {
  const lock = parseJson(text);
  if (!lock) return [];
  const out = [];
  for (const [section, dev] of [["default", false], ["develop", true]]) {
    for (const [name, meta] of Object.entries(lock[section] || {})) {
      const version = cleanVersion((meta.version || "").replace(/^==/, ""));
      if (version) out.push({ ecosystem: "PyPI", name, version, file, direct: false, dev });
    }
  }
  return out;
}

// [[package]] tables in TOML lockfiles (poetry.lock, Cargo.lock).
function tomlPackages(text, file, ecosystem) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m);
    const version = block.match(/^version\s*=\s*"([^"]+)"/m);
    if (name && version) out.push({ ecosystem, name: name[1], version: version[1], file, direct: false });
  }
  return out;
}

function goMod(text, file) {
  const out = [];
  const add = (line) => {
    const m = line.trim().match(/^([^\s]+)\s+(v[^\s]+)(\s*\/\/\s*indirect)?/);
    if (m && m[1] !== "require") out.push({ ecosystem: "Go", name: m[1], version: m[2], file, direct: !m[3] });
  };
  for (const block of text.matchAll(/^require\s*\(([\s\S]*?)^\)/gm)) block[1].split("\n").forEach(add);
  for (const single of text.matchAll(/^require\s+([^(\s].*)$/gm)) add(single[1]);
  return out;
}

function gemfileLock(text, file) {
  const out = [];
  const specs = text.match(/^ {2}specs:\n([\s\S]*?)(?:\n\S|\n\n|$)/m);
  if (!specs) return out;
  for (const m of specs[1].matchAll(/^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)/gm)) {
    out.push({ ecosystem: "RubyGems", name: m[1], version: m[2].split("-")[0], file, direct: false });
  }
  return out;
}

function composerLock(text, file) {
  const lock = parseJson(text);
  if (!lock) return [];
  return [...(lock.packages || []), ...(lock["packages-dev"] || [])]
    .filter((p) => p.name && p.version)
    .map((p) => ({ ecosystem: "Packagist", name: p.name, version: cleanVersion(p.version), file, direct: false }));
}

const PARSERS = {
  "package-lock.json": packageLock,
  "npm-shrinkwrap.json": packageLock,
  "yarn.lock": yarnLock,
  "pnpm-lock.yaml": pnpmLock,
  "Pipfile.lock": pipfileLock,
  "poetry.lock": (t, f) => tomlPackages(t, f, "PyPI"),
  "Cargo.lock": (t, f) => tomlPackages(t, f, "crates.io"),
  "go.mod": goMod,
  "Gemfile.lock": gemfileLock,
  "composer.lock": composerLock,
};

// Line-start offsets per manifest text, cleared after each extraction.
const lineIndexCache = new Map();

function declarationLine(text, dep) {
  if (!text) return 0;
  const name = dep.name;
  const base = basename(dep.file);
  const needles = {
    "package-lock.json": [dep.lockKey && `"${dep.lockKey}": {`, `"node_modules/${name}": {`, `"${name}": {`],
    "npm-shrinkwrap.json": [dep.lockKey && `"${dep.lockKey}": {`, `"node_modules/${name}": {`, `"${name}": {`],
    "package.json": [`"${name}":`],
    "yarn.lock": [`"${name}@`, `${name}@`],
    "pnpm-lock.yaml": [`/${name}@${dep.version}`, `${name}@${dep.version}`],
    "Pipfile.lock": [`"${name}": {`],
    "poetry.lock": [`name = "${name}"`],
    "Cargo.lock": [`name = "${name}"\nversion = "${dep.version}"`, `name = "${name}"`],
    "go.mod": [`${name} ${dep.version}`],
    "Gemfile.lock": [`    ${name} (${dep.version}`],
    "composer.lock": [`"name": "${name}"`],
  }[base] || [name];

  for (const needle of [...needles, name].filter(Boolean)) {
    const idx = text.indexOf(needle);
    if (idx === -1) continue;
    let starts = lineIndexCache.get(text);
    if (!starts) {
      starts = [0];
      for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
      lineIndexCache.set(text, starts);
    }
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }
  return 0;
}

const NPM_LOCKS =["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"];

/** Collect dependencies from every manifest in the repo. */
function extractDependencies(files, manifests) {
  const all = new Map([...files, ...manifests]);
  const deps = [];
  const manifestsFound = [];

  for (const [rel, text] of all) {
    const name = basename(rel);
    let parser = PARSERS[name];
    if (!parser && /^requirements.*\.txt$/i.test(name)) parser = requirementsTxt;
    // package.json versions are ranges; only use them when no lockfile sits beside it.
    if (!parser && name === "package.json" && !NPM_LOCKS.some((l) => all.has(dirname(rel) ? `${dirname(rel)}/${l}` : l))) {
      parser = packageJson;
    }
    if (!parser) continue;
    const found = parser(text, rel);
    if (found.length) manifestsFound.push({ file: rel, count: found.length });
    deps.push(...found);
  }

  // Line where each package is declared, so reports can link straight to it.
  for (const d of deps) d.line = declarationLine(all.get(d.file), d);
  lineIndexCache.clear();

  // Mark packages that are direct anywhere as direct, then dedupe.
  const directKeys = new Set(deps.filter((d) => d.direct).map((d) => `${d.ecosystem}|${d.name}`));
  const unique = new Map();
  for (const d of deps) {
    const key = `${d.ecosystem}|${d.name}|${d.version}`;
    if (!unique.has(key)) unique.set(key, { ...d, direct: directKeys.has(`${d.ecosystem}|${d.name}`) });
  }
  const list = [...unique.values()].sort((a, b) => Number(b.direct) - Number(a.direct));
  return { dependencies: list.slice(0, MAX_DEPENDENCIES), truncated: list.length > MAX_DEPENDENCIES, manifests: manifestsFound };
}

module.exports = { extractDependencies, _parsers: { packageLock, packageJson, yarnLock, pnpmLock, requirementsTxt, pipfileLock, tomlPackages, goMod, gemfileLock, composerLock } };
