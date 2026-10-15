// CipherGuard API server.
//
// With a Kubernetes cluster available, POST /scan launches one Job per scan
// and workers report back via /scan-progress and /scan-results ("cluster"
// mode). Without one, scans run in-process and the frontend streams them
// from /scan_stream ("stream" mode), which is also how local development works.
const express = require("express");
const cors = require("cors");
const { randomUUID } = require("crypto");
const config = require("./src/config");
const { runScan } = require("./src/pipeline");
const { parseGitHubUrl } = require("./src/scanner/fetchRepo");
const handlers = require("./src/http/handlers");

const app = express();
const PORT = process.env.PORT || 4000;

// Local development opts into in-memory share links unless KV is configured.
if (!process.env.SHARE_STORE && !config.kvUrl) process.env.SHARE_STORE = "memory";

app.disable("x-powered-by");
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(",") : true }));
app.use(express.json({ limit: "25mb" }));

// ---------------------------------------------------------------------------
// In-memory scan store (one API replica; use a database for more)
// ---------------------------------------------------------------------------
const scans = new Map();
const MAX_STORED_SCANS = 500;

function remember(scan) {
  scans.set(scan.scanId, scan);
  if (scans.size > MAX_STORED_SCANS) scans.delete(scans.keys().next().value);
}

// ---------------------------------------------------------------------------
// Kubernetes client
// ---------------------------------------------------------------------------
let batchApi = null;
if (process.env.DISABLE_K8S !== "true") {
  try {
    const k8s = require("@kubernetes/client-node");
    const kc = new k8s.KubeConfig();
    if (process.env.KUBECONFIG) kc.loadFromFile(process.env.KUBECONFIG);
    else kc.loadFromCluster();
    batchApi = kc.makeApiClient(k8s.BatchV1Api);
  } catch (err) {
    console.log(`[api] Kubernetes unavailable (${err.message}); scans run in-process`);
  }
}
// SCAN_MODE=cluster exercises the POST/poll flow locally without a cluster.
const MODE = batchApi || process.env.SCAN_MODE === "cluster" ? "cluster" : "stream";

const WORKER_IMAGE = process.env.WORKER_IMAGE || "cipherguard/scanner-worker:latest";
const API_CALLBACK_URL = process.env.API_CALLBACK_URL || `http://cipherguard-api:${PORT}`;
const JOB_NAMESPACE = process.env.JOB_NAMESPACE || "default";

// ---------------------------------------------------------------------------
// POST /scan – start a scan; returns the scan record
// ---------------------------------------------------------------------------
app.post("/scan", async (req, res) => {
  const { repoUrl } = req.body || {};
  const target = parseGitHubUrl(repoUrl);
  if (!target) return res.status(400).json({ error: "Invalid GitHub repository URL" });

  const scan = {
    scanId: randomUUID(),
    repoUrl: target.url,
    status: "queued",
    timestamp: new Date().toISOString(),
    steps: [],
    results: null,
  };
  remember(scan);

  if (batchApi) {
    try {
      await createScanJob(scan.scanId, scan.repoUrl);
      scan.status = "running";
    } catch (err) {
      console.error("[k8s] Failed to create job:", err.message);
      scan.status = "failed";
      scan.results = { error: err.message };
    }
  } else {
    runInProcess(scan);
  }
  res.status(201).json(scan);
});

function runInProcess(scan) {
  scan.status = "running";
  const emit = (event, data) => {
    if (event === "step") upsertStep(scan, data);
  };
  runScan(scan.repoUrl, { emit })
    .then((report) => complete(scan, "completed", report))
    .catch((err) => {
      if (err.steps) scan.steps = err.steps;
      complete(scan, "failed", { error: err.message });
    });
}

function upsertStep(scan, step) {
  const { progress, ...clean } = step;
  const i = scan.steps.findIndex((s) => s.id === clean.id);
  if (i === -1) scan.steps.push(clean);
  else scan.steps[i] = clean;
}

function complete(scan, status, results) {
  scan.status = status === "failed" ? "failed" : "completed";
  scan.results = results || null;
  if (results?.steps) scan.steps = results.steps;
  scan.completedAt = new Date().toISOString();
  console.log(`[scan] ${scan.scanId} -> ${scan.status}`);
}

// ---------------------------------------------------------------------------
// GET /scans – list scans (summaries, newest first)
// ---------------------------------------------------------------------------
app.get("/scans", (_req, res) => {
  const list = [...scans.values()]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .map(({ results, ...rest }) => ({
      ...rest,
      results: results
        ? { error: results.error, risk: results.risk, severityCounts: results.severityCounts, totalFindings: results.totalFindings }
        : null,
    }));
  res.json(list);
});

// GET /scan/:id – full scan record
app.get("/scan/:id", (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  res.json(scan);
});

// POST /scan-progress – worker reports a step change
app.post("/scan-progress", (req, res) => {
  const { scanId, step } = req.body || {};
  const scan = scans.get(scanId);
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (step?.id) upsertStep(scan, step);
  res.json({ ok: true });
});

// POST /scan-results – worker callback with the final report
app.post("/scan-results", (req, res) => {
  const { scanId, status, results } = req.body || {};
  if (!scanId) return res.status(400).json({ error: "scanId is required" });
  const scan = scans.get(scanId);
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  complete(scan, status, results);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Streaming scans, sharing, health (same handlers as the Vercel functions)
// ---------------------------------------------------------------------------
app.get(["/scan_stream", "/api/scan-stream"], (req, res) => handlers.scanStream(req, res, { mode: MODE }));
app.post("/api/share", handlers.createShare);
app.get("/api/share/:id", (req, res) => handlers.getShare(req, res, req.params.id));

const healthExtra = () => ({ mode: MODE, k8s: !!batchApi, scans: scans.size });
app.get("/health", (req, res) => handlers.health(req, res, healthExtra()));
app.get("/api/health", (req, res) => handlers.health(req, res, healthExtra()));

// ---------------------------------------------------------------------------
// Kubernetes Job for one scan
// ---------------------------------------------------------------------------
const secretEnv = (key) => ({
  name: key,
  valueFrom: { secretKeyRef: { name: "cipherguard-secrets", key, optional: true } },
});

async function createScanJob(scanId, repoUrl) {
  const jobName = `scan-${scanId.slice(0, 8)}`;
  const job = {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: { name: jobName, namespace: JOB_NAMESPACE, labels: { app: "cipherguard-scanner", scanId } },
    spec: {
      ttlSecondsAfterFinished: 600,
      backoffLimit: 1,
      activeDeadlineSeconds: 600,
      template: {
        metadata: { labels: { app: "cipherguard-scanner", scanId } },
        spec: {
          restartPolicy: "Never",
          securityContext: { runAsNonRoot: true, runAsUser: 1000 },
          containers: [
            {
              name: "scanner",
              image: WORKER_IMAGE,
              env: [
                { name: "REPO_URL", value: repoUrl },
                { name: "SCAN_ID", value: scanId },
                { name: "CALLBACK_URL", value: `${API_CALLBACK_URL}/scan-results` },
                { name: "SCAN_BUDGET_MS", value: "300000" },
                { name: "ENRICH_BUDGET_MS", value: "90000" },
                secretEnv("GEMINI_API_KEY"),
                secretEnv("SNYK_TOKEN"),
                secretEnv("GITHUB_TOKEN"),
                secretEnv("NVD_API_KEY"),
              ],
              securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: false },
              resources: { requests: { cpu: "250m", memory: "512Mi" }, limits: { cpu: "1", memory: "1Gi" } },
            },
          ],
        },
      },
    },
  };
  await batchApi.createNamespacedJob({ namespace: JOB_NAMESPACE, body: job });
  console.log(`[k8s] Created job ${jobName} for scan ${scanId}`);
}

if (require.main === module) {
  app.listen(PORT, () => console.log(`CipherGuard API listening on :${PORT} (${MODE} mode)`));
}

module.exports = app;
