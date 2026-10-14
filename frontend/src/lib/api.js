// API client. The app talks to one of two backends:
//   stream  – scans run in a request and report progress over SSE
//             (Vercel functions, or the Express server without Kubernetes)
//   cluster – POST /scan starts a Kubernetes Job; progress is polled
const BASE = import.meta.env.VITE_API_URL || "";

let healthPromise = null;

export function getHealth({ refresh = false } = {}) {
  if (!healthPromise || refresh) {
    healthPromise = fetch(`${BASE}/api/health`, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error(`Health check returned ${r.status}`);
        return r.json();
      })
      .catch((err) => {
        healthPromise = null;
        throw err;
      });
  }
  return healthPromise;
}

export function streamUrl(repoUrl) {
  return `${BASE}/api/scan-stream?repo=${encodeURIComponent(repoUrl)}`;
}

async function json(res) {
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(body.error || `Request failed (${res.status})`), { status: res.status });
  return body;
}

export const startClusterScan = (repoUrl) =>
  fetch(`${BASE}/scan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repoUrl }) }).then(json);

export const getClusterScan = (id) => fetch(`${BASE}/scan/${encodeURIComponent(id)}`, { cache: "no-store" }).then(json);

export const listClusterScans = () => fetch(`${BASE}/scans`, { cache: "no-store" }).then(json);

export const createShare = (report) =>
  fetch(`${BASE}/api/share`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ report }) }).then(json);

export const getShare = (id) => fetch(`${BASE}/api/share/${encodeURIComponent(id)}`).then(json);
