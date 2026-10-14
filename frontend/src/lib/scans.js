// In-memory store for scans started in this tab. Keeps streams and polls
// alive across route changes; components read it with useScan().
import { useSyncExternalStore } from "react";
import { getClusterScan, getHealth, startClusterScan, streamUrl } from "./api";
import { saveToHistory } from "./history";
import { slugOf } from "./repoUrl";

export const STEPS = [
  { id: "clone", label: "Cloning", hint: "Download the default branch" },
  { id: "secrets", label: "Secret scan", hint: "Keys, tokens and credentials" },
  { id: "static", label: "Static analysis", hint: "Risky code patterns, ESLint security rules" },
  { id: "deps", label: "Dependencies", hint: "Lockfiles across seven ecosystems" },
  { id: "osint", label: "OSINT enrichment", hint: "OSV, NVD, CISA KEV, EPSS, Scorecard" },
  { id: "ai", label: "AI analysis", hint: "Explanations grounded in the data" },
];

const POLL_MS = 1500;
const scans = new Map();
const listeners = new Set();
const handles = new Map(); // id -> { close() }

const notify = () => listeners.forEach((l) => l());
const subscribe = (l) => {
  listeners.add(l);
  return () => listeners.delete(l);
};

function set(id, patch) {
  const prev = scans.get(id);
  if (!prev) return;
  scans.set(id, { ...prev, ...(typeof patch === "function" ? patch(prev) : patch) });
  notify();
}

function mergeStep(steps, step) {
  return steps.map((s) => (s.id === step.id ? { ...s, ...step } : s));
}

function finish(id, status, { report, error, steps } = {}) {
  handles.get(id)?.close();
  handles.delete(id);
  set(id, (prev) => ({
    status,
    report: report || null,
    error: error || null,
    completedAt: new Date().toISOString(),
    steps: report?.steps ? mergeSteps(prev.steps, report.steps) : steps ? mergeSteps(prev.steps, steps) : prev.steps,
  }));
  const scan = scans.get(id);
  if (status !== "cancelled") saveToHistory(id, scan, report);
}

function mergeSteps(current, incoming) {
  return current.map((s) => ({ ...s, ...(incoming.find((i) => i.id === s.id) || {}) }));
}

function freshSteps() {
  return STEPS.map((s) => ({ ...s, status: "pending", detail: null, durationMs: null }));
}

function streamScan(id, repoUrl) {
  const es = new EventSource(streamUrl(repoUrl));
  let done = false;
  handles.set(id, { close: () => es.close() });

  es.addEventListener("step", (e) => {
    const step = JSON.parse(e.data);
    set(id, (prev) => ({ steps: mergeStep(prev.steps, step) }));
  });
  es.addEventListener("result", (e) => {
    done = true;
    es.close();
    finish(id, "completed", { report: JSON.parse(e.data).result });
  });
  // The server sends a named "error" event with data; the browser fires a
  // data-less "error" when the connection drops. EventSource would then
  // reconnect and start a second scan, so close it either way.
  es.addEventListener("error", (e) => {
    es.close();
    if (done) return;
    done = true;
    if (e.data) {
      const body = JSON.parse(e.data);
      finish(id, "failed", { error: body.error, steps: body.steps });
    } else {
      finish(id, "failed", { error: "Lost the connection to the scanner. Check your network and run the scan again." });
    }
  });
}

function pollScan(id) {
  let timer = null;
  let stopped = false;
  handles.set(id, { close: () => ((stopped = true), clearTimeout(timer)) });

  const tick = async () => {
    if (stopped) return;
    try {
      const rec = await getClusterScan(id);
      if (rec.steps?.length) set(id, (prev) => ({ steps: mergeSteps(prev.steps, rec.steps) }));
      if (rec.status === "completed") return finish(id, "completed", { report: rec.results });
      if (rec.status === "failed") return finish(id, "failed", { error: rec.results?.error || "The scan failed.", steps: rec.results?.steps });
    } catch (err) {
      if (err.status === 404) return finish(id, "failed", { error: "The server no longer has this scan." });
    }
    timer = setTimeout(tick, POLL_MS);
  };
  tick();
}

/** Start a scan and return its id (also the report route). */
export async function startScan(repoUrl) {
  let mode = "stream";
  try {
    mode = (await getHealth()).mode || "stream";
  } catch {
    /* fall back to streaming; it reports its own errors */
  }

  let id;
  if (mode === "cluster") {
    const rec = await startClusterScan(repoUrl);
    id = rec.scanId;
  } else {
    id = crypto.randomUUID();
  }

  scans.set(id, {
    id,
    mode,
    repoUrl,
    slug: slugOf(repoUrl),
    status: "running",
    startedAt: new Date().toISOString(),
    steps: freshSteps(),
    report: null,
    error: null,
  });
  notify();

  if (mode === "cluster") pollScan(id);
  else streamScan(id, repoUrl);
  return id;
}

export function cancelScan(id) {
  if (scans.get(id)?.status !== "running") return;
  finish(id, "cancelled", { error: "Scan cancelled." });
}

/** Adopt a cluster scan that this tab did not start (e.g. opened from History). */
export function watchClusterScan(id, rec) {
  if (scans.has(id)) return;
  scans.set(id, {
    id,
    mode: "cluster",
    repoUrl: rec.repoUrl,
    slug: slugOf(rec.repoUrl),
    status: rec.status === "queued" ? "running" : rec.status,
    startedAt: rec.timestamp,
    completedAt: rec.completedAt || null,
    steps: mergeSteps(freshSteps(), rec.steps || []),
    report: rec.status === "completed" ? rec.results : null,
    error: rec.status === "failed" ? rec.results?.error : null,
  });
  notify();
  if (rec.status === "running" || rec.status === "queued") pollScan(id);
}

export function useScan(id) {
  return useSyncExternalStore(subscribe, () => scans.get(id));
}

export function useScans() {
  return useSyncExternalStore(subscribe, () => scansSnapshot());
}

let snapshot = [];
let snapshotKey = "";
function scansSnapshot() {
  const key = [...scans.values()].map((s) => `${s.id}:${s.status}`).join("|");
  if (key !== snapshotKey) {
    snapshotKey = key;
    snapshot = [...scans.values()];
  }
  return snapshot;
}
