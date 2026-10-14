# Deploying CipherGuard

CipherGuard runs in one of two modes from the same code:

| | Vercel (stream mode) | Kubernetes (cluster mode) |
|---|---|---|
| Frontend | Static Vite build | nginx container |
| Scans | One streaming serverless function per scan | One Kubernetes Job per scan |
| Progress | Server-sent events | Worker posts steps; the app polls |
| Extra | Share links via Vercel KV | Optional Snyk scan, longer time budget |

## Vercel

The repository root is the project root; `vercel.json` sets the install, build and output settings.

1. Import the repository in Vercel. Leave the framework preset on **Other**.
2. Add environment variables (all optional): `GEMINI_API_KEY`, `GITHUB_TOKEN`, `NVD_API_KEY`.
3. For server-stored share links, add a Redis store from the Vercel Marketplace (Upstash). It sets `KV_REST_API_URL` and `KV_REST_API_TOKEN`. Without it, share links embed the redacted report in the URL.
4. Deploy.

`api/scan-stream.js` has `maxDuration: 60`, which works on every plan. Scans stay inside it through `SCAN_BUDGET_MS` (default 55 s). On a plan with longer functions, raise both together.

Security headers (CSP, HSTS, frame denial) are set in `vercel.json`.

## Kubernetes

### Build images

```bash
docker build -f Dockerfile.api      -t cipherguard/api:latest .
docker build -f Dockerfile.worker   -t cipherguard/scanner-worker:latest .
docker build -f Dockerfile.frontend -t cipherguard/frontend:latest .
```

For minikube, load them with `minikube image load <image>`; otherwise push to your registry and update the image names in `k8s/`.

### Secrets

```bash
kubectl create secret generic cipherguard-secrets \
  --from-literal=GEMINI_API_KEY=<key> \
  --from-literal=GITHUB_TOKEN=<read-only token> \
  --from-literal=NVD_API_KEY=<key> \
  --from-literal=SNYK_TOKEN=<token>
```

Every key is optional.

### Apply

```bash
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/api-deployment.yaml
kubectl apply -f k8s/api-service.yaml
kubectl apply -f k8s/frontend.yaml
```

`k8s/scan-job-template.yaml` documents the Job the API creates; it is not applied directly.

The API keeps scan state in memory, so it runs as a single replica. Worker callbacks must reach the pod that created the scan. Add a shared store (Redis or a database) before scaling it out.

### Verify

```bash
kubectl get svc cipherguard-frontend        # external address
kubectl get jobs -l app=cipherguard-scanner  # one Job per scan
curl http://<address>/api/health             # "mode": "cluster"
```

Workers run as a non-root user, with a 10-minute deadline (`activeDeadlineSeconds`) and a 5-minute scan budget.
