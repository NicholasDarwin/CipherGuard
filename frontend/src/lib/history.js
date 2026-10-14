// Scan history kept in this browser. Reports are stored redacted, and only
// the most recent few, so localStorage never holds a leaked secret.
import { sanitizeReport } from "./sanitize";

const INDEX = "cg-history:v1";
const REPORT = (id) => `cg-report:v1:${id}`;
const MAX_ENTRIES = 30;
const MAX_REPORTS = 8;

function readIndex() {
  try {
    return JSON.parse(localStorage.getItem(INDEX) || "[]");
  } catch {
    return [];
  }
}

function writeIndex(list) {
  try {
    localStorage.setItem(INDEX, JSON.stringify(list));
  } catch {
    /* storage full or blocked */
  }
}

export function listHistory() {
  return readIndex();
}

export function summarize(id, scan, report) {
  return {
    id,
    repoUrl: scan.repoUrl,
    slug: scan.slug,
    status: scan.status,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt || null,
    error: scan.error || null,
    risk: report?.risk || null,
    severityCounts: report?.severityCounts || null,
    totalFindings: report?.totalFindings ?? null,
  };
}

export function saveToHistory(id, scan, report) {
  const list = readIndex().filter((e) => e.id !== id);
  list.unshift(summarize(id, scan, report));
  const kept = list.slice(0, MAX_ENTRIES);
  writeIndex(kept);
  if (report) {
    try {
      localStorage.setItem(REPORT(id), JSON.stringify(sanitizeReport(report)));
    } catch {
      /* report too large for storage; the summary is still kept */
    }
  }
  // Drop stored reports beyond the newest MAX_REPORTS.
  kept.slice(MAX_REPORTS).forEach((e) => {
    try {
      localStorage.removeItem(REPORT(e.id));
    } catch {
      /* ignore */
    }
  });
}

export function getStoredReport(id) {
  try {
    const raw = localStorage.getItem(REPORT(id));
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function removeFromHistory(id) {
  writeIndex(readIndex().filter((e) => e.id !== id));
  try {
    localStorage.removeItem(REPORT(id));
  } catch {
    /* ignore */
  }
}

export function clearHistory() {
  readIndex().forEach((e) => removeFromHistory(e.id));
  writeIndex([]);
}
