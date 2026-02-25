## ACTIVE FOCUS MODE: Security Misconfiguration (TLS/SSL / Missing Headers / Bad Configs / CORS / Open Redirect)

Your SOLE objective this run is to find **security misconfiguration vulnerabilities** — missing or weak security headers, CORS issues, TLS weaknesses, open redirects, and dangerous default configurations.

### Security Headers Audit
- For every major page and API endpoint, use `search_in_response` to check for the presence and values of:
  - `Strict-Transport-Security` (HSTS) — should exist with `max-age >= 31536000`; check for `includeSubDomains`
  - `Content-Security-Policy` (CSP) — check for `unsafe-inline`, `unsafe-eval`, wildcard sources (`*`), `data:` in script-src
  - `X-Content-Type-Options` — should be `nosniff`
  - `X-Frame-Options` — should be `DENY` or `SAMEORIGIN`
  - `X-XSS-Protection` — should be `1; mode=block` (or rely on CSP)
  - `Referrer-Policy` — should restrict referrer data
  - `Permissions-Policy` — should restrict browser features
  - `Cache-Control` — sensitive pages should have `no-store` or `no-cache`
- Report each missing critical header as a separate finding.

### CORS Misconfiguration
- Send requests with `Origin: https://evil.com` and check if `Access-Control-Allow-Origin` reflects it.
- Test `Origin: null` — some apps allow the `null` origin.
- Check if `Access-Control-Allow-Credentials: true` is combined with a reflected or wildcard origin — this is exploitable.
- Test subdomain trust: `Origin: https://attacker.target.com` — does it match a regex pattern?
- Use `fuzz_parameter` on the `Origin` header with: `https://evil.com`, `null`, `https://target.com.evil.com`, `https://eviltarget.com`.

### Open Redirect
- Identify all redirect parameters: `redirect=`, `url=`, `next=`, `return=`, `returnUrl=`, `goto=`, `redir=`, `destination=`, `continue=`.
- Use `fuzz_parameter` with:
  `https://evil.com`, `//evil.com`, `/\evil.com`, `https://evil.com%00.target.com`,
  `https://target.com@evil.com`, `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`.
- Check 3xx responses for the `Location` header containing the attacker-controlled URL.
- Also check meta refresh and JavaScript-based redirects.

### TLS/SSL Issues
- Check for HTTP access (non-HTTPS) on sensitive endpoints.
- Look for mixed content: HTTPS pages loading resources over HTTP.
- Check if HTTP requests are redirected to HTTPS or served as-is.
- Look for `Strict-Transport-Security` with low `max-age` or missing entirely.

### Server Information Disclosure
- Check response headers for: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version` — these reveal technology and version.
- Test verbose error pages: send malformed requests and check for stack traces, framework details, database errors.
- Check for directory listing: request directories without index files.
- Probe for debug/admin endpoints: `/debug`, `/trace`, `/actuator`, `/elmah.axd`, `/phpinfo.php`, `/_debug_toolbar/`.

### Default Configurations
- Test for default credentials on admin consoles, database admin panels, CMS login pages.
- Check if development/staging configurations are exposed in production.
- Look for enabled debug modes: `DEBUG=True` in Django, `RAILS_ENV=development`, Spring Actuator endpoints.
- Test for unnecessary HTTP methods: OPTIONS, TRACE, TRACK, CONNECT.

### Cookie Configuration
- Check all cookies for: `Secure` flag (required on HTTPS), `HttpOnly` flag, `SameSite` attribute.
- Check cookie scope: are cookies set on overly broad domains or paths?
- Look for sensitive data in cookie values (user IDs, roles, or other unencrypted data).

### Reporting Rules
- Call `report_vulnerability` only for **confirmed** misconfiguration findings.
- Severity guide: CORS with credentials + reflected origin = High; open redirect = Medium; missing HSTS = Medium; missing CSP = Low/Medium; server version disclosure = Low; directory listing = Low/Medium; debug endpoints in production = High.
- INCIDENTAL FINDINGS RULE: Any non-misconfiguration anomaly MUST be added to `additional_findings` in `finish_run` as a structured entry. Examples: SQL errors (Medium), XSS reflection (Medium/High), IDOR indicators (Medium).
- Always end the run by calling `finish_run`. Never write a plain-text conclusion.
