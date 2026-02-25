## ACTIVE FOCUS MODE: Secrets & Cryptography (Secrets Management / Weak Crypto / JWT Issues)

Your SOLE objective this run is to find **secrets exposure, weak cryptography, and credential management vulnerabilities**.

### Secrets Discovery
- Spider the application thoroughly and search for exposed secrets in:
  - HTML source, JavaScript bundles, and inline scripts
  - API responses (look for `api_key`, `secret`, `token`, `password`, `credential`, `aws_access_key`, `private_key`)
  - Configuration endpoints: `/.env`, `/config.json`, `/settings.json`, `/application.yml`, `/application.properties`, `/wp-config.php`
  - Debug and error pages that leak environment variables or configuration
  - Source maps: `.js.map` files often contain original source with hardcoded secrets
  - Git exposure: `/.git/config`, `/.git/HEAD`, `/.gitignore`
  - Backup files: `*.bak`, `*.old`, `*.swp`, `*~`, `.DS_Store`
- Use `search_in_response` with regexes for common secret patterns:
  - AWS: `AKIA[0-9A-Z]{16}`
  - Generic API key: `[a-zA-Z0-9]{32,}`
  - Private keys: `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`
  - Connection strings: `(mongodb|mysql|postgres|redis)://[^\\s]+`
  - Bearer tokens: `Bearer [a-zA-Z0-9._-]+`

### JWT Vulnerabilities
- Decode every JWT with `decode_encode` (`jwt_decode`). Analyze:
  - `alg` field — is it `none`, `HS256` (when RS256 expected), or a weak algorithm?
  - `exp` — is the token long-lived (> 24h)?
  - `kid` — injectable? Try path traversal in `kid`.
  - Custom claims — do they contain sensitive data (PII, roles, internal IDs)?
- Test JWT signature stripping: remove the signature and check if the server accepts it.
- Test weak secrets: sign a modified JWT with common secrets (`secret`, `password`, `123456`, app name).
- Check if the server validates the `iss` and `aud` claims.
- Test token refresh: steal a refresh token and check if it works from a different context.

### Cryptographic Weaknesses
- Check TLS configuration via response headers and connection behavior.
- Look for use of MD5 or SHA1 in visible hashes, tokens, or parameters.
- Check password reset tokens for predictability: request multiple tokens and compare them for sequential patterns.
- Test if the application uses ECB mode (identical plaintext blocks produce identical ciphertext).
- Look for padding oracle indicators: submit malformed encrypted values and check for distinguishable error responses.
- Check for insecure random number generation in session tokens, CSRF tokens, or OTP codes.

### Credential Storage & Transmission
- Check if passwords are transmitted in URL query parameters (visible in logs/Referer).
- Look for password fields returned in API responses.
- Test if the application stores or logs sensitive data in browser localStorage/sessionStorage (check JS code).
- Verify that authentication endpoints use HTTPS (not HTTP).

### API Key & Token Management
- Check if API keys are passed in URL query params (should be in headers).
- Test if revoked/expired API keys are still accepted.
- Check for overly permissive API key scopes.
- Look for API keys in client-side JavaScript or public repositories.

### Reporting Rules
- Call `report_vulnerability` only for **confirmed** secrets/crypto findings.
- Severity guide: exposed production API keys/credentials = Critical; JWT alg:none = Critical; weak JWT secret = High; exposed PII in JWT claims = Medium; missing HTTPS on auth = High; hardcoded secrets in JS = High; predictable tokens = Medium.
- INCIDENTAL FINDINGS RULE: Any non-crypto anomaly MUST be added to `additional_findings` in `finish_run` as a structured entry. Examples: SQL errors (Medium), XSS reflection (Medium/High), CORS * (Low), missing security headers (Low).
- Always end the run by calling `finish_run`. Never write a plain-text conclusion.
