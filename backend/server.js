require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const k8s = require("@kubernetes/client-node");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: "50mb" }));

// ---------------------------------------------------------------------------
// In-memory scan store (swap for a DB in production)
// ---------------------------------------------------------------------------
const scans = new Map();

// ---------------------------------------------------------------------------
// Kubernetes client setup
// ---------------------------------------------------------------------------
let batchApi = null;
try {
  const kc = new k8s.KubeConfig();
  if (process.env.KUBECONFIG) {
    kc.loadFromFile(process.env.KUBECONFIG);
  } else {
    kc.loadFromCluster(); // inside a pod
  }
  batchApi = kc.makeApiClient(k8s.BatchV1Api);
} catch (err) {
  console.warn(
    "Kubernetes client not available – jobs will not be launched.",
    err.message
  );
}

const WORKER_IMAGE =
  process.env.WORKER_IMAGE || "cipherguard/scanner-worker:latest";
const API_CALLBACK_URL =
  process.env.API_CALLBACK_URL || `http://cipherguard-api:${PORT}`;
const JOB_NAMESPACE = process.env.JOB_NAMESPACE || "default";

// ---------------------------------------------------------------------------
// POST /scan  – accept a repo URL, create a K8s Job
// ---------------------------------------------------------------------------
app.post("/scan", async (req, res) => {
  const { repoUrl } = req.body;
  if (!repoUrl || typeof repoUrl !== "string") {
    return res.status(400).json({ error: "repoUrl is required" });
  }

  // Basic GitHub URL validation
  const ghPattern = /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+\/?$/;
  if (!ghPattern.test(repoUrl.trim())) {
    return res.status(400).json({ error: "Invalid GitHub repository URL" });
  }

  const scanId = uuidv4();
  const scan = {
    scanId,
    repoUrl: repoUrl.trim(),
    status: "queued",
    timestamp: new Date().toISOString(),
    results: null,
  };
  scans.set(scanId, scan);

  // Launch Kubernetes Job if the client is available
  if (batchApi) {
    try {
      await createScanJob(scanId, scan.repoUrl);
      scan.status = "running";
    } catch (err) {
      console.error("Failed to create K8s job:", err.message);
      scan.status = "failed";
      scan.results = { error: err.message };
    }
  } else {
    // No k8s – mark as queued so a manual worker can pick it up
    console.log(`[scan] K8s unavailable – scan ${scanId} stays queued`);
  }

  return res.status(201).json(scan);
});

// ---------------------------------------------------------------------------
// GET /scans  – list all scans
// ---------------------------------------------------------------------------
app.get("/scans", (_req, res) => {
  const list = Array.from(scans.values()).sort(
    (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
  );
  res.json(list);
});

// ---------------------------------------------------------------------------
// GET /scan/:id  – detailed result for one scan
// ---------------------------------------------------------------------------
app.get("/scan/:id", (req, res) => {
  const scan = scans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  res.json(scan);
});

// ---------------------------------------------------------------------------
// POST /scan-results  – worker callback to submit results
// ---------------------------------------------------------------------------
app.post("/scan-results", (req, res) => {
  const { scanId, status, results } = req.body;
  if (!scanId) return res.status(400).json({ error: "scanId is required" });

  const scan = scans.get(scanId);
  if (!scan) return res.status(404).json({ error: "Scan not found" });

  scan.status = status === "failed" ? "failed" : "completed";
  scan.results = results || null;
  scan.completedAt = new Date().toISOString();

  console.log(`[scan-results] ${scanId} → ${scan.status}`);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
app.get("/health", (_req, res) => {
  res.json({ status: "ok", k8s: !!batchApi, scans: scans.size });
});

// ---------------------------------------------------------------------------
// Create a Kubernetes Job for a scan
// ---------------------------------------------------------------------------
async function createScanJob(scanId, repoUrl) {
  const jobName = `scan-${scanId.slice(0, 8)}`;

  const job = {
    apiVersion: "batch/v1",
    kind: "Job",
    metadata: {
      name: jobName,
      namespace: JOB_NAMESPACE,
      labels: { app: "cipherguard-scanner", scanId },
    },
    spec: {
      ttlSecondsAfterFinished: 600,
      backoffLimit: 1,
      template: {
        metadata: {
          labels: { app: "cipherguard-scanner", scanId },
        },
        spec: {
          restartPolicy: "Never",
          containers: [
            {
              name: "scanner",
              image: WORKER_IMAGE,
              env: [
                { name: "REPO_URL", value: repoUrl },
                { name: "SCAN_ID", value: scanId },
                {
                  name: "CALLBACK_URL",
                  value: `${API_CALLBACK_URL}/scan-results`,
                },
                {
                  name: "GEMINI_API_KEY",
                  valueFrom: {
                    secretKeyRef: {
                      name: "cipherguard-secrets",
                      key: "GEMINI_API_KEY",
                      optional: true,
                    },
                  },
                },
                {
                  name: "SNYK_TOKEN",
                  valueFrom: {
                    secretKeyRef: {
                      name: "cipherguard-secrets",
                      key: "SNYK_TOKEN",
                      optional: true,
                    },
                  },
                },
              ],
              resources: {
                requests: { cpu: "250m", memory: "512Mi" },
                limits: { cpu: "1", memory: "1Gi" },
              },
            },
          ],
        },
      },
    },
  };

  await batchApi.createNamespacedJob({ namespace: JOB_NAMESPACE, body: job });
  console.log(`[k8s] Created job ${jobName} for scan ${scanId}`);
}

// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`CipherGuard API listening on :${PORT}`);
});
