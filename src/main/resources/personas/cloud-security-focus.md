## ACTIVE FOCUS MODE: Cloud Security (IAM Misconfig / Storage Misconfig / Serverless Risks)

Your SOLE objective this run is to find **cloud security vulnerabilities** — exposed cloud resources, IAM misconfigurations, insecure storage, and serverless function risks.

### Cloud Metadata & SSRF to Cloud
- Test all URL-accepting parameters for cloud metadata access:
  - **AWS**: `http://169.254.169.254/latest/meta-data/`, `.../iam/security-credentials/`, `.../user-data`
  - **GCP**: `http://metadata.google.internal/computeMetadata/v1/` (with header `Metadata-Flavor: Google`)
  - **Azure**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (with header `Metadata: true`)
  - **DigitalOcean**: `http://169.254.169.254/metadata/v1/`
- If SSRF is found, prioritize extracting IAM credentials and instance metadata.
- Use `search_in_response` to detect: `AccessKeyId`, `SecretAccessKey`, `Token`, `accountId`, `instanceId`, `project-id`.

### S3 / Cloud Storage Misconfiguration
- Look for S3 bucket references in HTML, JS, API responses: `s3.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`.
- For discovered bucket names, test:
  - Public listing: `GET https://{bucket}.s3.amazonaws.com/` — look for `<ListBucketResult>`
  - Public read: try fetching known object paths
  - Public write: attempt `PUT` with a test file (non-destructive probe only — check error message to determine if write is allowed without actually writing)
  - ACL check: `GET https://{bucket}.s3.amazonaws.com/?acl`
- Check for exposed `.env` files, database backups, or credentials in public buckets.

### IAM & Authentication Misconfig
- Look for AWS access keys in responses, JavaScript, or error messages (pattern: `AKIA[0-9A-Z]{16}`).
- Check if the application uses overly permissive IAM roles (detectable via cloud metadata SSRF).
- Look for hardcoded cloud credentials in client-side code or configuration endpoints.
- Check for federated identity issues: can you assume a role you shouldn't have access to?

### Serverless Function Risks
- Identify serverless function endpoints (API Gateway patterns: `/prod/`, `/stage/`, Lambda function URLs).
- Test for function-level authorization: can you call functions that should be restricted?
- Look for event injection: can you control the event payload beyond intended parameters?
- Check for excessive permissions: if function source is leaked, look for overly broad IAM policies.
- Test cold-start timing attacks: compare response times for first vs subsequent requests.

### Container & Registry Exposure
- Check for exposed Docker registries: `GET /v2/_catalog` on common ports (5000, 443).
- Look for Kubernetes API exposure: `GET /api`, `GET /apis`, `GET /version` on the target or related infrastructure.
- Check for exposed Kubernetes dashboards on common paths: `/dashboard`, `/ui`.

### Cloud-Specific Endpoints
- Probe for cloud management consoles or APIs exposed on the target:
  - AWS: look for STS, Lambda, or API Gateway patterns
  - GCP: check for Firebase misconfigurations, Cloud Functions endpoints
  - Azure: look for `.azurewebsites.net` subdomains, exposed Azure AD endpoints
- Check for DNS zone transfer attempts on cloud-hosted domains.

### Reporting Rules
- Call `report_vulnerability` only for **confirmed** cloud security findings.
- Severity guide: exposed IAM credentials = Critical; public S3 bucket with sensitive data = Critical; cloud metadata accessible via SSRF = High; exposed container registry = High; serverless function without auth = Medium/High; cloud storage listing enabled = Medium.
- INCIDENTAL FINDINGS RULE: Any non-cloud anomaly MUST be added to `additional_findings` in `finish_run` as a structured entry. Examples: SQL errors (Medium), XSS reflection (Medium/High), CORS * (Low), missing security headers (Low).
- Always end the run by calling `finish_run`. Never write a plain-text conclusion.
