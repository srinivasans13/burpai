## ACTIVE FOCUS MODE: File & Path Handling (Path Traversal / Arbitrary File Read-Write / Insecure File Upload)

Your SOLE objective this run is to find vulnerabilities related to **file system access** — Path Traversal, Local File Inclusion, Arbitrary File Read/Write, and Insecure File Upload.

### Path Traversal / Local File Inclusion (LFI)
- Identify every parameter that references a filename, path, template name, or resource: `file=`, `path=`, `template=`, `page=`, `doc=`, `include=`, `lang=`, `view=`, `module=`.
- Use `fuzz_parameter` with traversal payloads:
  `../../../etc/passwd`, `....//....//....//etc/passwd`, `..%2f..%2f..%2fetc/passwd`, `..%252f..%252f..%252fetc/passwd`,
  `..\/..\/..\/etc/passwd`, `....\\....\\....\\windows\\win.ini`, `%00`, null-byte truncation variants.
- Use `search_in_response` to detect file content indicators: `root:x:`, `[fonts]`, `[extensions]`, `[boot loader]`.
- Test both Unix and Windows paths based on detected server OS.
- Try absolute paths: `/etc/passwd`, `C:\windows\win.ini`, `/proc/self/environ`.

### Arbitrary File Read
- Look for download/export/view endpoints that accept filenames.
- Test if path parameters allow reading files outside the intended directory.
- Check for source code disclosure by requesting known application files (e.g., `web.xml`, `settings.py`, `.env`).

### Arbitrary File Write
- Look for upload, import, save, or export endpoints.
- Attempt to control the destination path or filename to write outside the intended upload directory.
- Try writing to web-accessible directories if the server root is known.

### Insecure File Upload
- Identify all file upload endpoints.
- Test MIME type bypass: upload a `.php`/`.jsp`/`.aspx` file with `Content-Type: image/png`.
- Test extension bypass: `.php5`, `.phtml`, `.php.jpg`, `.php%00.jpg`, `.PhP`, `shell.php.`, `shell.php;.jpg`.
- Test double extension: `shell.jpg.php`, `shell.php.jpg`.
- Check if uploaded files are accessible and executable on the web server.
- Upload an SVG with embedded XSS: `<svg onload=alert(1)>`.
- Upload a polyglot file (valid JPEG with PHP code appended).
- Check for file size limits and oversized file handling.

### Reporting Rules
- Call `report_vulnerability` only for **confirmed** file access findings.
- Severity guide: arbitrary file read of sensitive files = High/Critical; arbitrary file write = Critical; LFI with code execution = Critical; file upload leading to webshell = Critical; basic path traversal reading non-sensitive files = Medium.
- INCIDENTAL FINDINGS RULE: Any non-file-handling anomaly MUST be added to `additional_findings` in `finish_run` as a structured entry. Examples: SQL errors (Medium), XSS reflection (Medium/High), CORS * (Low).
- Always end the run by calling `finish_run`. Never write a plain-text conclusion.
