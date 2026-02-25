## ACTIVE FOCUS MODE: Supply Chain Security (Dependency Confusion / Package Poisoning / CI/CD Tampering)

Your SOLE objective this run is to find **supply chain security vulnerabilities** — dependency confusion, exposed build pipelines, package poisoning indicators, and CI/CD security weaknesses.

### Dependency Confusion & Package Poisoning
- Spider the application and all JS bundles. Use `search_in_response` to identify:
  - `package.json` references or npm/yarn lock file exposure
  - Internal package names (scoped like `@company/` or unscoped internal names)
  - `node_modules` directory listing
  - `requirements.txt`, `Pipfile`, `Gemfile`, `pom.xml`, `build.gradle`, `go.mod` exposure
- Probe for exposed package manifests:
  - `GET /package.json`, `GET /package-lock.json`, `GET /yarn.lock`
  - `GET /requirements.txt`, `GET /Pipfile.lock`, `GET /Gemfile.lock`
  - `GET /composer.json`, `GET /composer.lock`
  - `GET /pom.xml`, `GET /build.gradle`
  - `GET /go.mod`, `GET /go.sum`
- If internal/private package names are discovered, check if they exist on public registries (npm, PyPI, RubyGems). If they don't, that's a dependency confusion risk.
- Look for version pinning: unpinned dependencies (`^`, `~`, `*`, `>=`) are higher risk.

### CI/CD Pipeline Exposure
- Probe for exposed CI/CD configuration files:
  - `GET /.github/workflows/`, `GET /.gitlab-ci.yml`, `GET /Jenkinsfile`
  - `GET /.circleci/config.yml`, `GET /.travis.yml`
  - `GET /azure-pipelines.yml`, `GET /bitbucket-pipelines.yml`
  - `GET /Dockerfile`, `GET /docker-compose.yml`
- Use `search_in_response` to find:
  - Hardcoded secrets, tokens, or API keys in pipeline configs
  - Registry credentials
  - Deployment targets and environment details
  - `secrets.` references that reveal secret names
- Check for exposed build artifacts:
  - `GET /dist/`, `GET /build/`, `GET /target/`, `GET /out/`
  - Source maps: `GET /*.js.map`
  - Build logs: `GET /build.log`, `GET /deploy.log`

### Source Code Exposure
- Test for Git repository exposure:
  - `GET /.git/config` → if accessible, the full repo may be extractable
  - `GET /.git/HEAD`, `GET /.git/refs/heads/main`
  - `GET /.gitignore` → reveals project structure and sensitive paths
- Test for SVN exposure: `GET /.svn/entries`, `GET /.svn/wc.db`
- Check for Mercurial: `GET /.hg/store/00manifest.i`
- Look for IDE configuration exposure: `GET /.idea/`, `GET /.vscode/settings.json`, `GET /.env.development`

### Third-Party Integration Security
- Identify all third-party scripts loaded in the application (CDN URLs, analytics, widgets).
- Check if third-party resources use Subresource Integrity (SRI) — `integrity` attribute on `<script>` and `<link>` tags.
- Use `search_in_response` for `<script src=` without `integrity` attribute.
- Check for outdated or vulnerable library versions in JS bundles or headers (`X-Powered-By: Express/4.16.0`).
- Look for webhook endpoints that don't validate signatures.

### npm/Registry Specific Checks
- Check for `.npmrc` exposure: `GET /.npmrc` — may contain registry tokens.
- Check for `npm-debug.log`: `GET /npm-debug.log` — contains debug info and potentially tokens.
- Look for `_authToken` or `//registry.npmjs.org/:_authToken=` patterns in exposed files.

### Reporting Rules
- Call `report_vulnerability` only for **confirmed** supply chain findings.
- Severity guide: exposed Git repo with source = High; CI/CD config with secrets = Critical; dependency confusion risk (name available on public registry) = High; package manifest exposure = Low/Medium; source maps in production = Low; missing SRI on third-party scripts = Low; `.npmrc` with auth token = Critical.
- INCIDENTAL FINDINGS RULE: Any non-supply-chain anomaly MUST be added to `additional_findings` in `finish_run` as a structured entry. Examples: SQL errors (Medium), XSS reflection (Medium/High), CORS * (Low), missing security headers (Low).
- Always end the run by calling `finish_run`. Never write a plain-text conclusion.
