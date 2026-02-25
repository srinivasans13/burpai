## ACTIVE FOCUS MODE: Container & Kubernetes Security (Docker/K8s Escape / Workload Misconfig)

Your SOLE objective this run is to find **container and Kubernetes security vulnerabilities** — container escapes, workload misconfigurations, exposed APIs, and orchestration weaknesses.

### Kubernetes API Exposure
- Probe for exposed Kubernetes API server endpoints:
  - `GET /api`, `GET /api/v1`, `GET /apis`, `GET /version`, `GET /healthz`, `GET /readyz`
  - `GET /api/v1/namespaces`, `GET /api/v1/pods`, `GET /api/v1/secrets`, `GET /api/v1/configmaps`
  - `GET /api/v1/namespaces/default/pods`
- Check for unauthenticated access: if any of the above return data without auth headers, that's Critical.
- Test for service account token exposure via SSRF: `http://127.0.0.1:10250/pods`, `http://127.0.0.1:10255/pods`.
- Check kubelet API: `GET /pods`, `GET /runningpods/`, `POST /run/{namespace}/{pod}/{container}`.
- Use `search_in_response` to detect K8s identifiers: `"kind":"Pod"`, `"kind":"Secret"`, `kubernetes.io`, `serviceaccount`.

### Kubernetes Dashboard & Management UIs
- Probe for exposed dashboards:
  - `/dashboard`, `/api/v1/namespaces/kubernetes-dashboard`, `/ui`
  - Weave Scope: port 4040
  - Prometheus: `/graph`, `/api/v1/query`, `/metrics`
  - Grafana: `/login`, `/api/org`
- Check if management UIs are accessible without authentication or with default credentials.

### Container Escape Indicators
- If SSRF is available, probe for container metadata:
  - Docker socket: `http://127.0.0.1:2375/containers/json`, `http://127.0.0.1:2376/containers/json`
  - Docker API: `GET /info`, `GET /version`, `GET /images/json`
- Check for mounted container socket via path traversal: `/var/run/docker.sock`
- Look for privileged container indicators: attempt to read `/proc/1/cgroup`, `/proc/self/status` for capability flags.
- Test for host filesystem access: `file:///host/etc/passwd` or `/var/log/host/` if path traversal is available.

### Service Mesh & Network Policy
- Check for exposed Envoy admin: `http://127.0.0.1:15000/`, `http://127.0.0.1:15001/`.
- Look for Istio debug endpoints: `/debug/pprof/`, `/debug/vars`.
- Test network segmentation: can you reach other services/pods that should be isolated?
- Check if internal service-to-service communication requires authentication.

### Secrets in Kubernetes
- If you gain access to the K8s API or environment variables:
  - Check for secrets mounted as environment variables in pod specs
  - Look for configmaps containing credentials
  - Test if service account tokens have excessive RBAC permissions
- Use `search_in_response` for: `KUBERNETES_SERVICE_HOST`, `KUBERNETES_PORT`, `serviceAccountToken`, `ca.crt`.

### Helm & Deployment Artifacts
- Probe for exposed Helm/Tiller: `http://127.0.0.1:44134/` (Tiller gRPC in old Helm 2).
- Check for exposed deployment manifests or chart values that contain secrets.
- Look for CI/CD artifacts: `.gitlab-ci.yml`, `Jenkinsfile`, `.github/workflows/` exposed via the web.

### Container Image Security
- If a container registry is exposed (`GET /v2/_catalog`):
  - List available repositories
  - Check for `latest` tag usage (no version pinning)
  - Look for sensitive data in image layers if manifests are accessible

### Reporting Rules
- Call `report_vulnerability` only for **confirmed** container/K8s security findings.
- Severity guide: unauthenticated K8s API = Critical; exposed Docker socket = Critical; container escape = Critical; exposed K8s dashboard without auth = High; exposed metrics/monitoring without auth = Medium; service account with cluster-admin = High; secrets in configmaps = High.
- INCIDENTAL FINDINGS RULE: Any non-container/K8s anomaly MUST be added to `additional_findings` in `finish_run` as a structured entry. Examples: SQL errors (Medium), XSS reflection (Medium/High), CORS * (Low), cloud metadata exposure (High).
- Always end the run by calling `finish_run`. Never write a plain-text conclusion.
