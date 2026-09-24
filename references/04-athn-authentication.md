# WSTG ATHN — Authentication

OWASP WSTG v4.2. Tests WSTG-ATHN-01 → 10.

## Table of Contents

- [ATHN-01 Creds over Encrypted Channel](#wstg-athn-01)
- [ATHN-02 Default Credentials](#wstg-athn-02)
- [ATHN-03 Weak Lock Out Mechanism](#wstg-athn-03)
- [ATHN-04 Bypassing Authentication Schema](#wstg-athn-04)
- [ATHN-05 Vulnerable Remember Password](#wstg-athn-05)
- [ATHN-06 Browser Cache Weaknesses](#wstg-athn-06)
- [ATHN-07 Weak Password Policy](#wstg-athn-07)
- [ATHN-08 Weak Security Question Answer](#wstg-athn-08)
- [ATHN-09 Weak Password Change/Reset](#wstg-athn-09)
- [ATHN-10 Weaker Auth in Alt Channel](#wstg-athn-10)

---

## WSTG-ATHN-01

**Testing for Credentials Transported over an Encrypted Channel**

Goal: confirm creds, session tokens, and reset codes are only ever sent over HTTPS — never plaintext HTTP.

Black-box: capture traffic (devtools or ZAP) with HTTPS-forcing browser extensions disabled, then force-browse the HTTP variant of every sensitive flow and check the request scheme.

| Flow | Force this URL | Pass condition |
|---|---|---|
| Login | `http://site/login` | request still upgrades to HTTPS |
| Account creation | `http://site/createAccount` | request still upgrades to HTTPS |
| Password reset / change | HTTP variant of recovery/edit forms | request still upgrades to HTTPS |
| Authenticated browsing | any page while logged in | session cookie only sent over HTTPS |

Fail example — creds sent in the clear:
```
Request URL: http://www.example.org/j_acegi_security_check
Request method: POST
POST data:
j_username=userabc
j_password=My-Protected-Password-452
```
Also check any `Set-Cookie` response carries the `Secure` attribute — without it, a later HTTP request can still leak the session token even if login itself was HTTPS.

Remediation: HTTPS site-wide, HSTS, redirect HTTP→HTTPS. If a full switch isn't immediate, prioritize sensitive operations first. Use Let's Encrypt or another free CA if cost is a blocker.

Refs: Testing for Weak Transport Layer Security.

---

## WSTG-ATHN-02

**Testing for Default Credentials**

Goal: find default or predictable credentials that were never changed, on both known software/hardware admin panels and newly provisioned accounts.

Black-box:
- Known interface (Cisco, WebLogic, etc.) → check vendor default creds don't still work.
- Unknown app → try common admin usernames: `admin`, `administrator`, `root`, `system`, `guest`, `operator`, `super`, `test`, `qa`. Try blank password, then `password`, `admin`, `guest`, `pass123`.
- App named "Obscurity" → try `obscurity`/`obscurity`. Known contact/org names → derive likely usernames (`John Doe` → `jdoe`).
- Check page source/JS for hardcoded creds or conditional logic like `if username='admin' then /admin.asp`.
- Check backup directories for leaked source with embedded creds/comments.
- New-account defaults: find the username-generation pattern (email-based? sequential like `user7811`?) and the password-generation pattern (create several accounts fast, diff the passwords for a pattern). Correlate and brute-force.
- Watch account-lockout thresholds while probing — don't lock yourself out of the only admin account.

Gray-box: ask IT staff how admin creds/access work and whether defaults were changed; check user DB, config files, and source for hardcoded/default creds and password-generation logic.

Tools: Burp Intruder, THC Hydra, Nikto 2.

Refs: CIRT default-password database; [ATHN-04](#wstg-athn-04) (enumeration), [ATHN-07](#wstg-athn-07) (weak password policy).

---

## WSTG-ATHN-03

**Testing for Weak Lock Out Mechanism**

Goal: confirm lockout resists brute force without being trivially DoS-able, and the unlock path isn't itself abusable.

Black-box — probe the threshold and reset window (use a disposable test account, do this test last if it's the only one):

```
1. Wrong password x3 → correct password succeeds (no lockout at 3)
2. Wrong password x4 → correct password succeeds (no lockout at 4)
3. Wrong password x5 → correct password fails: "Your account is locked out."
4. Correct password 5 min later  → still locked
5. Correct password 10 min later → still locked
6. Correct password 15 min later → succeeds (auto-clears 10-15 min)
```

CAPTCHA is not a lockout substitute. Common CAPTCHA flaws to test:

| Flaw | Test |
|---|---|
| Weak challenge (arithmetic, tiny question set) | attempt automated solve |
| Checks HTTP status not actual solve | submit unsolved via proxy |
| Server defaults to "solved" on error | submit intentionally wrong answer |
| Never validated server-side | replay a known-good response |
| Solution leaked in alt-text/filename/hidden field | inspect page source |
| Only shown after N fails | clear cookies, retry |
| Multi-step flow | skip straight to a later step, bypassing the CAPTCHA step |
| Alt entry point (mobile API) | check if it enforces CAPTCHA too |

Unlock mechanism: check it can't be triggered/guessed by an attacker (e.g. unlock links must be unique, one-time). Distinct from password recovery, but should meet the same bar.

Remediation — pick unlock method by risk, lowest to highest assurance: time-based, self-service email, manual admin, manual admin + positive ID check. Typical bad-attempt threshold: 5-10. Typical time-based window: 5-30 min. Manual admin unlock is safest but enables an attacker to mass-lock every account as a DoS — the admin needs their own recovery path too.

Refs: OWASP Brute Force Attacks; Forgot Password Cheat Sheet.

---

## WSTG-ATHN-04

**Testing for Bypassing Authentication Schema**

Goal: confirm every route to protected functionality actually enforces auth — not just the login page.

Black-box:

| Technique | What to try |
|---|---|
| Direct page request | force-browse straight to a protected URL, skipping login |
| Parameter modification | flip a login-state param/cookie, e.g. `?authenticated=yes` |
| Session ID prediction | check cookie values for linear/predictable sequences |
| SQL injection | try SQLi payloads in the login form (see injection sections) |

Example parameter-modification bypass:
```
GET /page.asp?authenticated=yes HTTP/1.0
HTTP/1.1 200 OK
<H1>You Are Authenticated</H1>
```

Gray-box (source available): look for logic bugs like PHPBB 2.0.13's `unserialize()` on a user-supplied cookie compared with PHP loose `==` against a boolean — supplying a serialized boolean (`b:1`) bypasses the password check entirely.

Tools: WebGoat, OWASP ZAP.

Refs: Mark Roxberry, *PHPBB 2.0.13 vulnerability*; David Endler, *Session ID Brute Force Exploitation and Prediction*.

---

## WSTG-ATHN-05

**Testing for Vulnerable Remember Password**

Goal: confirm "remember me" and password-manager auto-fill don't expose creds or long-lived tokens to compromise.

Check:
- Creds encoded (not encrypted server-side) in browser storage — should use server-generated tokens instead, never store creds client-side.
- Auto-filled login forms abusable via clickjacking or CSRF.
- Remember-me token lifetime — tokens that never expire are high-value if stolen.

Remediation: follow session management best practices; never store creds client-side in clear or reversibly-encoded form.

---

## WSTG-ATHN-06

**Testing for Browser Cache Weaknesses**

Goal: confirm sensitive data isn't retrievable from browser history or disk cache after logout.

Black-box:
- **History**: enter sensitive data, log out, hit Back — page shouldn't still render the sensitive content while unauthenticated. Mitigate with HTTPS + `Cache-Control: must-revalidate`.
- **Cache**: proxy every authenticated response and confirm sensitive pages send:
  ```
  Cache-Control: no-cache, no-store, must-revalidate, max-age=0, s-maxage=0
  Pragma: no-cache
  Expires: 0
  ```
  Missing directives → verify the page actually lands in the on-disk cache:

| Browser | Cache path |
|---|---|
| Firefox (Linux) | `~/.cache/mozilla/firefox/` |
| Firefox (Windows) | `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\<id>\Cache2\` |
| IE | `%LOCALAPPDATA%\Microsoft\Windows\INetCache\` |
| Chrome (Windows) | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache` |
| Chrome (Linux) | `~/.cache/google-chrome` |

Also check mobile: fresh clean-cache session, spoof a mobile User-Agent via proxy, re-verify the same directives are sent.

Gray-box: same method, with creds to reach authenticated-only sensitive pages.

Tools: OWASP ZAP.

Refs: *Caching in HTTP*.

---

## WSTG-ATHN-07

**Testing for Weak Password Policy**

Goal: assess resistance to dictionary/brute-force guessing via length, complexity, reuse, and aging rules.

Black-box, check:

| # | Question |
|---|---|
| 1 | What chars are allowed/required (multi-charset)? |
| 2 | How fast can password be changed repeatedly (history-rule dodge)? |
| 3 | Is periodic forced expiry enforced? (NIST/NCSC advise against it; PCI DSS may require it) |
| 4 | Does app track last N passwords to block reuse? |
| 5 | Is a minimum diff from the old password enforced? |
| 6 | Is username/first/last name blocked from appearing in password? |
| 7 | Are min/max length appropriate for the account's sensitivity? |
| 8 | Are common passwords (`Password1`, `123456`) rejected? |

Remediation: enforce a strong length/complexity/reuse/aging policy, and add 2FA where feasible.

Refs: OWASP Brute Force Attacks.

---

## WSTG-ATHN-08

**Testing for Weak Security Question Answer**

Goal: assess whether secret Q&A (for recovery or step-up auth) can be guessed, brute-forced, or socially engineered.

| Question type | Weakness |
|---|---|
| Pre-generated ("mother's maiden name") | known to family/friends |
| Pre-generated ("favorite color") | easily guessable |
| Pre-generated ("favorite HS teacher") | brute-forcible against common-name lists |
| Pre-generated ("favorite movie") | publicly discoverable on social media |
| Self-generated | user may write a trivial question ("What is 1+1?") or leak the answer directly |

Black-box:
- Enumerate the full preset question list via account creation / forgot-password flow; flag any in the weak categories above.
- If self-generated questions are allowed, they're vulnerable by design — combine with username enumeration ([ATHN-04](#wstg-athn-04)) to harvest many.
- Check for lockout after N wrong answers (see [ATHN-03](#wstg-athn-03)); note unlimited attempts as a finding.
- Rank candidate questions by public discoverability / answer-set size, and prioritize the weakest — the scheme is only as strong as its weakest question.

Refs: *The Curse of the Secret Question*; OWASP Security Questions Cheat Sheet.

---

## WSTG-ATHN-09

**Testing for Weak Password Change or Reset Functionalities**

Goal: confirm password change/reset can't be hijacked to take over another account.

Black-box, check for both flows:
1. Can a non-admin change/reset another account's password?
2. Can the flow be manipulated to target a different user/admin?
3. Is the flow CSRF-protected?

Password reset specifics:

| Question | Best practice |
|---|---|
| Gated by secret question? | required for high-security apps, not just email |
| How is new password delivered? | worst: shown directly in-app; best: emailed link to registered address |
| Is the reset password random? | worst: old password emailed in cleartext (implies unhashed storage); best: securely random |
| Is confirmation required before the change takes effect? | best: emailed one-time token, old password stays valid until clicked |

Password change specifics: is the current password required? Allowing change without it lets a hijacked session take over the account permanently.

Remediation: require re-authentication or a confirmation step for both flows.

Refs: OWASP Forgot Password Cheat Sheet.

---

## WSTG-ATHN-10

**Testing for Weaker Authentication in Alternative Channel**

Goal: find alternate channels serving the same accounts (mobile site, call center, partner SSO, staging) and confirm they enforce equally strong auth.

Black-box:
1. Fully baseline the primary channel's auth (creation, recovery, change, elevated auth).
2. Find alt channels: site content (help/FAQ/T&Cs/robots.txt/sitemap.xml), proxy log strings (`mobile`, `sso`, `wireless`, `ipad`...), search engines for sibling org/domain sites.
3. For each candidate sharing accounts, enumerate which auth functions exist there vs. primary — a comparison grid works well (register/login/logout/reset/change × channel).
4. Give call centers extra scrutiny — phone identity checks are often weaker than the web flow.
5. If in scope, run every other ATHN test against the alt channel and compare to the primary baseline. Out of scope → still document its existence.

Example: primary site enforces TLS everywhere; a parallel `m.example.com` mobile site has no TLS and weaker recovery — a real gap even though the primary channel is clean.

Remediation: apply one consistent auth policy across every channel.

Refs: all other ATHN test cases apply here too.
