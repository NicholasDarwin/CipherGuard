# CipherGuard v2 — Kubernetes Deployment Guide

## Architecture Overview

```
┌─────────────────────┐       ┌────────────────────────┐
│  React Frontend     │──────▶│  Express API Server    │
│  (nginx container)  │       │  (Node.js container)   │
└─────────────────────┘       └────────┬───────────────┘
                                       │ creates K8s Jobs
                              ┌────────▼───────────────┐
                              │  Kubernetes Jobs        │
                              │  ┌──────────────────┐   │
                              │  │ scanner-worker #1 │   │
                              │  └──────────────────┘   │
                              │  ┌──────────────────┐   │
                              │  │ scanner-worker #2 │   │
                              │  └──────────────────┘   │
                              │  ┌──────────────────┐   │
                              │  │ scanner-worker #N │   │
                              │  └──────────────────┘   │
                              └─────────────────────────┘
```

Each scan request creates a **new Kubernetes Job**. Jobs run concurrently and
POST their results back to the API via the `/scan-results` endpoint.

---

## Prerequisites

- Docker
- A Kubernetes cluster (minikube, kind, EKS, GKE, etc.)
- `kubectl` configured to talk to your cluster

---

## 1. Build Docker Images

From the project root:

```bash
# API server
docker build -f Dockerfile.api -t cipherguard/api:latest .

# Scanner worker
docker build -f Dockerfile.worker -t cipherguard/scanner-worker:latest .

# React frontend
docker build -f Dockerfile.frontend -t cipherguard/frontend:latest .
```

If using a remote registry, tag and push:

```bash
docker tag cipherguard/api:latest <registry>/cipherguard/api:latest
docker push <registry>/cipherguard/api:latest
# ... same for worker and frontend
```

For **minikube**, load images directly:

```bash
minikube image load cipherguard/api:latest
minikube image load cipherguard/scanner-worker:latest
minikube image load cipherguard/frontend:latest
```

---

## 2. Create Secrets

```bash
kubectl create secret generic cipherguard-secrets \
  --from-literal=GEMINI_API_KEY=<your-gemini-key> \
  --from-literal=SNYK_TOKEN=<your-snyk-token>
```

Both are optional — scans will still run without them (AI analysis and Snyk
dependency scanning will be skipped).

---

## 3. Apply Kubernetes Manifests

```bash
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/api-deployment.yaml
kubectl apply -f k8s/api-service.yaml
kubectl apply -f k8s/frontend.yaml
```

> The scan Job template (`k8s/scan-job-template.yaml`) is for reference only.
> The API server creates Jobs programmatically via the `@kubernetes/client-node`
> library at runtime.

---

## 4. Access the Application

```bash
# If using minikube:
minikube service cipherguard-frontend --url

# If using a cloud LoadBalancer, get the external IP:
kubectl get svc cipherguard-frontend
```

Open the URL in your browser. You'll see the scan dashboard.

---

## 5. Test Concurrent Scans

1. Open the dashboard.
2. Submit multiple GitHub repository URLs one after another.
3. Each submission calls **POST /scan**, which creates a Kubernetes Job.
4. The dashboard polls **GET /scans** every 4 seconds to update statuses.
5. When a Job finishes, the worker POSTs to **/scan-results** and the scan
   transitions to `completed` (or `failed`).
6. Click **View Report** on any completed scan to see detailed findings.

You can verify Jobs are running:

```bash
kubectl get jobs -l app=cipherguard-scanner
kubectl get pods -l app=cipherguard-scanner
```

---

## Local Development (without Kubernetes)

### API server

```bash
cd backend
npm install
# Create .env with optional GEMINI_API_KEY and SNYK_TOKEN
node server.js          # runs on :4000
```

Without a Kubernetes cluster the API will still accept scan requests — they'll
stay in `queued` status. You can run the worker manually:

```bash
REPO_URL=https://github.com/owner/repo \
SCAN_ID=<uuid-from-POST-response> \
CALLBACK_URL=http://localhost:4000/scan-results \
node scanner-worker.js
```

### React frontend

```bash
cd frontend
npm install
npm start               # runs on :3000, proxies /scan* to :4000
```

---

## API Endpoints

| Method | Path             | Description                        |
|--------|------------------|------------------------------------|
| POST   | `/scan`          | Start a new scan (creates K8s Job) |
| GET    | `/scans`         | List all scans with status         |
| GET    | `/scan/:id`      | Get detailed results for one scan  |
| POST   | `/scan-results`  | Worker callback to submit results  |
| GET    | `/health`        | Health check                       |

---

## Project Structure (new files)

```
backend/
  package.json
  server.js              # Express API + K8s Job creation
  scanner-worker.js      # Standalone scan worker
frontend/
  package.json
  public/index.html
  src/
    index.js
    App.js
    App.css
    components/
      ScanDashboard.js   # Dashboard with polling
      ScanForm.js        # URL submission form
      ScanCard.js        # Individual scan card
      ScanReport.js      # Detailed report page
k8s/
  api-deployment.yaml    # API Deployment
  api-service.yaml       # API ClusterIP Service
  frontend.yaml          # Frontend Deployment + LoadBalancer
  rbac.yaml              # ServiceAccount + Role for Job creation
  scan-job-template.yaml # Reference Job template
  secrets.yaml           # Secret placeholder
Dockerfile.api
Dockerfile.worker
Dockerfile.frontend
nginx.conf               # Frontend reverse-proxy config
```
