# CipherGuard – AI-Powered GitHub Security Scanner

CipherGuard scans GitHub repositories for security vulnerabilities, exposed secrets, and dependency issues using AI-powered analysis. Multiple repos can be scanned concurrently via Kubernetes Jobs.

![CipherGuard](https://img.shields.io/badge/CipherGuard-Security%20Scanner-blue?style=for-the-badge)
![Node.js](https://img.shields.io/badge/Node.js-20+-green?style=for-the-badge&logo=node.js)
![React](https://img.shields.io/badge/React-19-blue?style=for-the-badge&logo=react)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Jobs-326CE5?style=for-the-badge&logo=kubernetes)

## Architecture

```
┌─────────────────────┐       ┌────────────────────────┐
│  React Frontend     │──────▶│  Express API Server    │
│  (nginx container)  │       │  (Node.js container)   │
└─────────────────────┘       └────────┬───────────────┘
                                       │ creates K8s Jobs
                              ┌────────▼───────────────┐
                              │  Scanner Worker Pods    │
                              │  (one per scan, runs    │
                              │   in parallel)          │
                              └─────────────────────────┘
```

## ✨ Features

- **Concurrent Scanning**: Submit multiple repos at once — each runs as a separate Kubernetes Job
- **Secret Detection**: Finds passwords, API keys, tokens, private keys, AWS credentials, JWTs, and more
- **Static Analysis**: ESLint code quality analysis on JS/TS files
- **Dependency Scanning**: Snyk vulnerability detection for project dependencies
- **AI Threat Analysis**: Gemini AI provides per-finding risk assessment and an overall security report
- **Scan Dashboard**: React UI tracks all scans in real time with status polling
- **Detailed Reports**: Severity-grouped findings with AI remediation guidance

## 🚀 Quick Start

### Local Development (no Kubernetes required)

```bash
# API server
cd backend
npm install
cp .env.example .env   # add your GEMINI_API_KEY and SNYK_TOKEN
node server.js          # runs on :4000

# React frontend (separate terminal)
cd frontend
npm install
npm start               # runs on :3000, proxies API to :4000
```

Without a Kubernetes cluster, scans stay in `queued` status. Run the worker manually:

```bash
REPO_URL=https://github.com/owner/repo \
SCAN_ID=<uuid-from-POST-response> \
CALLBACK_URL=http://localhost:4000/scan-results \
node backend/scanner-worker.js
```

### Kubernetes Deployment

```bash
# Build images
docker build -f Dockerfile.api    -t cipherguard/api:latest .
docker build -f Dockerfile.worker -t cipherguard/scanner-worker:latest .
docker build -f Dockerfile.frontend -t cipherguard/frontend:latest .

# Create secrets
kubectl create secret generic cipherguard-secrets \
  --from-literal=GEMINI_API_KEY=<key> \
  --from-literal=SNYK_TOKEN=<token>

# Deploy
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/api-deployment.yaml
kubectl apply -f k8s/api-service.yaml
kubectl apply -f k8s/frontend.yaml
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full guide.

## 🔌 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan` | Start a new scan (creates a K8s Job) |
| GET | `/scans` | List all scans with current status |
| GET | `/scan/:id` | Detailed results for one scan |
| POST | `/scan-results` | Worker callback to submit results |
| GET | `/health` | Health check |

## 📁 Project Structure

```
backend/
  server.js              # Express API + Kubernetes Job creation
  scanner-worker.js      # Standalone scan worker (runs in K8s Jobs)
  package.json
  .env.example
frontend/
  src/
    App.js               # React router setup
    App.css              # Dashboard styles
    components/
      ScanDashboard.js   # Main dashboard with polling
      ScanForm.js        # Multi-repo submission form
      ScanCard.js        # Individual scan status card
      ScanReport.js      # Detailed report page
  public/index.html
k8s/
  api-deployment.yaml    # API Deployment (2 replicas)
  api-service.yaml       # ClusterIP Service
  frontend.yaml          # Frontend Deployment + LoadBalancer
  rbac.yaml              # ServiceAccount + Role for Job creation
  scan-job-template.yaml # Reference Job template
  secrets.yaml           # Secret placeholder
Dockerfile.api           # API server image
Dockerfile.worker        # Scanner worker image
Dockerfile.frontend      # React build → nginx
nginx.conf               # Frontend reverse proxy
```

## 🔐 Secret Patterns Detected

| Category | Examples |
|----------|----------|
| **Critical** | Private keys, AWS credentials, GitHub tokens, Stripe keys |
| **High** | API keys, auth tokens, client secrets, JWTs, Google API keys |
| **Medium** | Passwords, database URLs, connection strings |
| **Low** | Email addresses, hardcoded IPs |

## 🛡️ Vulnerability Patterns Detected

SQL injection, XSS, eval/exec usage, shell injection, insecure random, debug mode, CORS wildcards, HTTP without TLS

## 🔧 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GEMINI_API_KEY` | Google Gemini API key for AI analysis | Optional |
| `SNYK_TOKEN` | Snyk token for dependency scanning | Optional |
| `PORT` | API server port (default: 4000) | No |
| `WORKER_IMAGE` | Docker image for scanner worker | No |
| `API_CALLBACK_URL` | URL workers POST results to | No |
| `JOB_NAMESPACE` | Kubernetes namespace for Jobs | No |

## 📄 License

MIT — see [LICENSE](LICENSE).

## ⚠️ Disclaimer

This tool is for security research and education. Ensure you have permission to scan a repository before use.

---

Made with ❤️ by the CipherGuard Team
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
