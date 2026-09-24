# WSTG SESS — Session Management

OWASP WSTG v4.2. Tests WSTG-SESS-01 → 09.

## Table of Contents

- [SESS-01 Session Management Schema](#wstg-sess-01)
- [SESS-02 Cookies Attributes](#wstg-sess-02)
- [SESS-03 Session Fixation](#wstg-sess-03)
- [SESS-04 Exposed Session Variables](#wstg-sess-04)
- [SESS-05 Cross Site Request Forgery](#wstg-sess-05)
- [SESS-06 Logout Functionality](#wstg-sess-06)
- [SESS-07 Session Timeout](#wstg-sess-07)
- [SESS-08 Session Puzzling](#wstg-sess-08)
- [SESS-09 Session Hijacking](#wstg-sess-09)

---

## WSTG-SESS-01

**Testing for Session Management Schema**

Goal: confirm session tokens (cookies, SessionID, hidden fields) are generated unpredictably and can't be forged, replayed, or brute-forced.

Black-box:

**Cookie collection** — map how the app uses cookies: how many exist, which page sets/modifies each (`Set-Cookie`), which pages require them (retry requests without the cookie or with a tampered value).

**Token structure & leakage** — inspect the token for embedded cleartext data instead of an opaque server-side reference:
```
Cleartext: 192.168.100.1:owaspuser:password:15:58
Hex:       3139322E3136382E3130302E313A6F77617370757365723A70617373776F72643A31353A3538
Base64:    MTkyLjE2OC4xMDAuMTpvd2FzcHVzZXI6cGFzc3dvcmQ6MTU6NTg=
MD5:       01c2fc4f0a817afd8366689bd29dd40a
```
Gather a representative sample and vary one input at a time (user, IP, login time) to find which bit-ranges are static vs. variable, and whether variable ranges are sequential or time-derived.

**Predictability/randomness** — request many tokens under identical login conditions; check for reproducibility, time-linked segments, and whether the generation algorithm plus known prior IDs let you predict the next one.

**Structure example**: `ID=5a0acfc7ffeb919:CR=1:TM=1120514521:LM=1120514521:S=j3am5KzC4v01ba3q` — 5 typed fields (hex ID, small-int CR, two matching large-int timestamps worth perturbing individually, alphanumeric S) with no delimiter needed once enough samples reveal the boundaries.

**Brute force** — weigh Session ID space against session lifetime: short-lived, low-variance IDs are far more brute-forceable than long-lived, high-variance ones. Check whether per-attempt delay is enforced.

Gray-box, require:
- Cryptographically random token (e.g. AES 256-bit), never a linear function of predictable inputs like client IP.
- Minimum 50-character token length.
- Defined timeout appropriate to data sensitivity.
- `Set-Cookie: cookie=data; path=/; domain=.aaa.it; secure; HttpOnly` — non-persistent, HTTPS-only, unreadable by script.

Tools: OWASP ZAP (session token analysis), Burp Sequencer, JHijack.

Refs: RFC 2965, RFC 1750; Zalewski, *Strange Attractors and TCP/IP Sequence Number Analysis* (2001/2002); OWASP Code Review Guide.

---

## WSTG-SESS-02

**Testing for Cookies Attributes**

Goal: confirm session cookies carry the attributes/prefixes needed to resist theft, tampering, and cross-site leakage.

| Attribute | Purpose |
|---|---|
| `Secure` | sent only over HTTPS — without it, an HTTP fallback (even on an HTTPS-first app) can leak the cookie |
| `HttpOnly` | blocks JS access — limits (not eliminates) XSS impact |
| `Domain` | scopes which hosts receive the cookie; can't be a bare TLD; loosening to a parent domain (e.g. `mydomain.com`) exposes it to every subdomain, including a vulnerable one |
| `Path` | scopes cookie to a URL path; `path=/` on a shared host leaks it to every app on that host |
| `Expires` | sets/limits persistence, or force-deletes by setting a past date |
| `SameSite` | `Strict` (first-party nav only, safest, may force re-login from email/external links), `Lax` (sent on top-level cross-site navigation, browser default), `None` (sent cross-site, requires `Secure`) |

Cookie name prefixes (enforced by the browser, so the server can trust them even if it can't trust the rest of the cookie):

| Prefix | Requires |
|---|---|
| `__Host-` | `Secure`, set from a secure origin, no `Domain` attribute, `Path=/` |
| `__Secure-` | `Secure`, set from a secure origin |

Strongest practical config: `Set-Cookie: __Host-SID=<token>; path=/; Secure; HttpOnly; SameSite=Strict`.

Tools: OWASP ZAP, Burp Suite; browser extensions (EditThisCookie, Cookiebro).

Refs: RFC 2965, RFC 2616; IETF SameSite cookies draft.

---

## WSTG-SESS-03

**Testing for Session Fixation**

Goal: confirm the session token is rotated on login — a pre-auth token that survives into the authenticated session lets an attacker plant a known cookie in the victim's browser and hijack it after they log in.

Black-box:
1. Request the site unauthenticated, note the issued `Set-Cookie` (e.g. `JSESSIONID=...`).
2. Authenticate while replaying that same cookie.
3. If the post-login response issues **no new session cookie**, the app is vulnerable — same token now carries elevated privilege.

Forced-cookie variant (targets network attackers, only needed absent full HSTS):
```
1. Reach the login page, snapshot the cookie jar (excluding __Host-/__Secure- cookies).
2. Log in as victim, reach an authenticated function.
3. Restore the pre-login snapshot into the jar.
4. Retrigger that function — success means it's still tied to the old (attacker-known) token.
5. Repeat as attacker: write the victim's pre-login cookies into your own jar, trigger the function,
   then re-login as victim and retrigger — success confirms session fixation.
```
Use separate machines/browsers for victim and attacker to rule out fingerprinting false positives.

Remediation: invalidate the existing session ID before authentication, then issue a fresh one only on success.

Tools: OWASP ZAP.

Refs: Calzavara, Rabitti, Ragazzo, Bugliesi, *Testing for Integrity Flaws in Web Sessions*; Chris Shiflett on session fixation.

---

## WSTG-SESS-04

**Testing for Exposed Session Variables**

Goal: confirm session tokens are always encrypted in transit and never cached, regardless of general site caching policy.

Black-box, via proxy:
- **Encryption/reuse**: swap `https://` for `http://` mid-session and check whether the same token is reused unencrypted. Every successful auth should issue a distinct token, sent only over an encrypted channel.
- **Caching**: every response carrying a session ID should send `Cache-Control: no-cache` (HTTP/1.1) plus `Expires: 0` and `max-age=0` — `Cache-Control: private` alone still allows caching on non-shared proxies (a risk on shared/public machines), and HTTP/1.0 caches ignore `no-cache` entirely.
- **GET vs POST**: session IDs sent via GET risk leaking into proxy/firewall logs and are easier to trigger via a crafted link (classic CSRF/XSS vector). Confirm server-side handlers reject the same parameters when resent as GET, e.g. a `POST /login.asp` with `SessionID=...` in the body shouldn't also work as `GET /login.asp?SessionID=...`.

Refs: RFC 2109/2965, RFC 2616.

---

## WSTG-SESS-05

**Testing for Cross Site Request Forgery**

Goal: confirm state-changing requests can't be triggered by a third-party page riding the victim's existing session.

CSRF requires: (1) the browser auto-attaches session credentials (cookies, HTTP auth) to every request, (2) the attacker knows a valid app URL/request shape, (3) the app relies solely on browser-supplied credentials for session identification (cookie- or HTTP-auth-based; not one-time form login). An auto-firing tag (`<img>`) makes exploitation trivial but isn't required — a plain link works too.

GET-based example — an invisible image tag fires a real request with no click needed:
```html
<img src="https://www.company.example/action" width="0" height="0">
```
Firewall-management example — deleting all rules via a naive GET-based delete function:
```
https://[target]/fwmgt/delete?rule=*
```
POST-based example — auto-submitting hidden form:
```html
<body onload='document.CSRF.submit()'>
<form action='http://targetWebsite/Authenticate.jsp' method='POST' name='CSRF'>
<input type='hidden' name='name' value='Hacked'>
<input type='hidden' name='password' value='Hacked'>
</form>
```
JSON-API bypass — `enctype='text/plain'` delivers a JSON-shaped body without needing a JS `fetch()`:
```html
<form action='http://victimsite.com' method='POST' enctype='text/plain'>
<input type='hidden' name='{"name":"hacked","password":"hacked","padding":"' value='something"}' />
```
which the server receives as:
```
POST / HTTP/1.1
Content-Type: text/plain
{"name":"hacked","password":"hacked","padding":"=something"}
```
Any padding field the server doesn't check is silently ignored, so `name`/`password` still land as valid.

Remediation: OWASP CSRF Prevention Cheat Sheet (anti-CSRF tokens, `SameSite` cookies, re-auth for sensitive actions).

Tools: OWASP ZAP, CSRF Tester, Pinata-csrf-tool.

Refs: Peter W, *Cross-Site Request Forgeries*; Thomas Schreiber, *Session Riding*.

---

## WSTG-SESS-06

**Testing for Logout Functionality**

Goal: confirm logout is easy to find, actually invalidates the session server-side, and (where SSO is in play) terminates every connected session.

Black-box:
- **UI**: a logout control should be visible on every page without scrolling.
- **Server-side termination**: capture the session cookie, log out, then replay the old cookie value against an authenticated page (e.g. via browser back button + reload). No sensitive data should render — ideally the app redirects to login. Test multiple protected pages, not just one.
- **SSO (single sign-off)**: log out of the tested app, then check whether the SSO portal still offers silent re-login; separately, log out of the SSO system and confirm the connected app also loses access.

Common failure modes: session cookie value refreshes but the old server-side session stays valid (replay works); logout only shows a confirmation message without actually invalidating anything; app relies purely on a self-contained encrypted cookie with no server-side session table, so logout can only delete the client copy — the old cookie value stays valid forever if intercepted (classic ASP.NET Forms Auth replay issue).

Tools: Burp Suite Repeater.

Refs: *Cookie replay attacks in ASP.NET when using forms authentication*.

---

## WSTG-SESS-07

**Testing Session Timeout**

Goal: confirm an idle session is invalidated server-side after a bounded period, appropriate to data sensitivity (e.g. ≤15 min for banking, up to an hour+ for a forum).

Black-box: log in, wait past the suspected timeout, then confirm the session token is rejected. Determine whether timeout is enforced client-side (cookie carries a time value you can tamper, e.g. push expiry into the future) or server-side (tampering has no effect — this is the required behavior). A non-persistent cookie with no embedded time data implies server enforcement by default.

Gray-box, confirm:
- Logout destroys/invalidates the token, not just removes it client-side (`HttpSession.invalidate()` in Java, `Session.abandon()` in .NET).
- The server rejects replay of a destroyed session ID.
- If a client-supplied value informs timeout at all, it's cryptographically protected from tampering — not advisable at all.

Refs: OWASP Session Management Cheat Sheet.

---

## WSTG-SESS-08

**Testing for Session Puzzling**

Goal: find cases where a session variable is set in one context and trusted in a different, unintended context — enabling auth bypass, privilege escalation, or multi-step flow skipping.

Example: a password-recovery entry point (unauthenticated) populates a session variable from user-supplied identity data. A later, supposedly-authenticated page reads that same session variable to show private data — an attacker who never logs in can reach it by hitting the recovery flow first.

Black-box: enumerate every session variable and every entry point that sets or reads it; try accessing pages in developer-unanticipated order (recovery flow → private page) to see if state bleeds across contexts. Results vary by request sequence — expect some trial and error.

Gray-box: source review is the most reliable way to find this class.

Remediation: one session variable, one consistent purpose — never reused across unrelated flows.

Refs: *Session Puzzles*; *Session Puzzling and Session Race Conditions*.

---

## WSTG-SESS-09

**Testing for Session Hijacking**

Goal: confirm session cookies can't leak to a network attacker even when the app is fully deployed over HTTPS.

Even an all-HTTPS app is vulnerable without the `Secure` attribute:
```
1. Victim requests http://another-site.com.
2. Attacker corrupts that response to trigger a request to http://example.com.
3. The browser's request to http://example.com fails, but the session cookie
   is sent — and leaked — in the clear over HTTP first.
```
If cookies use a `Domain` attribute (shared across subdomains), partial HSTS (no `includeSubDomains`) isn't enough — an attacker can redirect to `http://fake.example.com`, which is still permitted by HSTS but still leaks the domain-scoped cookie over HTTP. Full HSTS on the apex domain is required to close this.

Black-box hijack simulation (targets network attackers, only needed absent full HSTS):
```
1. Log in as victim, reach an authenticated function.
2. Drop from the jar every cookie protected against HTTP disclosure
   (Secure-flagged, or — under partial HSTS — also any without Domain set).
3. Snapshot the remaining jar; trigger the function (should still work).
4. Clear jar, log in as attacker, write in the victim's snapshotted cookies.
5. Trigger the function again, then re-login as victim and check whether
   the attacker's action landed in the victim's account — confirms hijack.
```
Use separate machines/browsers for victim and attacker to rule out fingerprinting false positives.

Tools: OWASP ZAP, JHijack.

Refs: Calzavara, Rabitti, Ragazzo, Bugliesi, *Testing for Integrity Flaws in Web Sessions*.
