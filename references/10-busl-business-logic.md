# WSTG BUSL — Business Logic

OWASP WSTG v4.2. Tests WSTG-BUSL-01 → 09.

## Table of Contents

- [BUSL-01 Business Logic Data Validation](#wstg-busl-01)
- [BUSL-02 Ability to Forge Requests](#wstg-busl-02)
- [BUSL-03 Integrity Checks](#wstg-busl-03)
- [BUSL-04 Process Timing](#wstg-busl-04)
- [BUSL-05 Function Usage Limits](#wstg-busl-05)
- [BUSL-06 Circumvention of Work Flows](#wstg-busl-06)
- [BUSL-07 Defenses Against Application Misuse](#wstg-busl-07)
- [BUSL-08 Upload of Unexpected File Types](#wstg-busl-08)
- [BUSL-09 Upload of Malicious Files](#wstg-busl-09)

---

## WSTG-BUSL-01

**Test Business Logic Data Validation**

Goal: confirm the server independently validates that data is *logically* valid — not just well-formed — rather than trusting client-side checks or Boundary Value Analysis alone.

Logically-valid data still needs application-specific checks: a 9-digit SSN might pass BVA but reference a deceased person or nonexistent region. Data validity can also depend on state — a carpet order might route to an in-stock warehouse or a partner's out-of-stock fulfillment; an attacker who forges the routing flag could get free stock shipped or bypass payment. Cached/nightly-synced balances (e.g. credit limits recalculated once a day) open a window where rapid transactions exceed real limits. The "Distributed Denial of Dollar" case: exploiting a bank's free-transfer threshold (1000 transfers) by flooding $0.13 payments, flipping a fee meant to deter abuse into a cost for the target instead.

**Black-box**: intercept POST/GET traffic, identify hand-off points between systems (params like cost, quantity, or identifiers passed across a system boundary), then submit logically-invalid values (impossible SSNs, IDs that don't exist, values that break state assumptions) and confirm the server rejects them independent of front-end checks.

**Remediation**: validate logical correctness at every input and hand-off point server-side; never trust data because it already passed the front end.

**Tools**: OWASP ZAP, Burp Suite.

**Refs**: OWASP Proactive Controls C5 (Validate All Inputs); OWASP Input Validation Cheat Sheet.

---

## WSTG-BUSL-02

**Test Ability to Forge Requests**

Goal: confirm the server enforces business rules independent of the client UI, so an attacker can't bypass workflow logic by crafting raw HTTP requests via proxy — exploiting guessable/predictable parameters or hidden dev/debug functionality ("Easter eggs").

Example: an e-commerce ticket site applies a one-time 10% senior discount via a hidden `discount_applied` flag (0/1); if the client can resend `0` after a discount was taken, they stack it repeatedly. Example: a game exposes a hidden dev field to jump to high levels or reveal other players'/treasure locations, letting an attacker farm points meant to require real play.

**Black-box**:
- Watch for incrementing/guessable values in captured requests — mutate and see if unauthorized state is reachable.
- Watch for hidden fields/params (debug flags, dev shortcuts) — try flipping or enabling them.

**Remediation**: enforce workflow state and stage transitions server-side; strip/ignore debug functionality in production builds.

**Tools**: OWASP ZAP, Burp Suite.

**Refs**: CSRF — Legitimizing Forged Requests; Easter Egg (Wikipedia).

---

## WSTG-BUSL-03

**Test Integrity Checks**

Goal: confirm the server re-validates any value the UI treats as fixed (hidden fields, dropdowns, disabled controls) rather than trusting it because the browser made it non-editable — and confirm audit logs can't be tampered with.

Non-editable controls are only non-editable in the browser; a proxy can submit arbitrary values in their place. If the server accepts them without a matching authorization/relational check, integrity breaks.

| Example | Attack |
|---|---|
| Admin-only password-reset form | Non-admin submits the admin-only `username`/`password` fields directly via proxy, tricking the server into processing the request as if from an admin |
| Project dropdown scoped to user's own projects | Attacker submits a project ID they don't have access to; server must still reject it, not just omit it from the UI list |
| Citizen self-service portal built on top of an employee-verified system | Attacker adds/edits fields (e.g. marital status) that were meant to only ever be set by a verifying employee, destroying data integrity |
| Audit/troubleshooting logs | Can an attacker read, modify, or delete log entries — intentionally or incidentally? |

**Black-box**: capture traffic, identify hidden fields and nominally non-editable values, resubmit with different/unauthorized values via proxy and confirm the server rejects them; separately, enumerate log/data stores and attempt direct read/write/delete.

**Remediation**: enforce strict server-side access control on every field regardless of UI editability; protect logs from unauthorized read/write/delete through trusted channels only.

**Tools**: file/log editors, OWASP ZAP, Burp Suite.

**Refs**: Referential Integrity & Shared Business Logic in RDBs; Rules and Integrity Constraints in DB Systems; Oracle referential integrity for business rules; Maximizing Business Logic Reuse with Reactive Logic; Tamper Evidence Logging.

---

## WSTG-BUSL-04

**Test for Process Timing**

Goal: confirm response timing doesn't leak information about internal state, and that time-bound transactions can't be held open indefinitely to gain an advantage.

| Example | Leak / abuse |
|---|---|
| Slot machines | Longer processing time just before a large payout tips off attentive gamblers to raise their bet |
| Login forms | Invalid-username + invalid-password often returns faster than valid-username + invalid-password, leaking username validity without needing the error message itself |
| Ticket/seat reservation | Reserving seats without ever checking out — does the system release the hold, or does inventory silently lock up? |
| Price-quote-at-login e-commerce | Logging in early to lock a low price quote, then completing the purchase later after the market price rises |

**How to test**: map which processes are time-dependent (a completion window, or execution-time gaps between steps that could be exploited). Automate timed requests against those processes for precision — manual testing works but is less reliable. Diagram the flow and injection points before firing timed requests, then compare timing/outcomes against expected business logic.

**Remediation**: normalize response time across outcomes where timing could leak information (e.g. constant-time auth checks); enforce hard expiry/rollback on time-bound transactions (ticket vendors' 5-minute holds).

**Related**: Cookie attributes testing; session timeout testing.

---

## WSTG-BUSL-05

**Test Number of Times a Function Can Be Used Limits**

Goal: confirm per-use or per-period limits (one discount per order, N downloads per month) are enforced server-side and can't be replayed by navigating back/forward or repeating the triggering action.

Example: an e-commerce checkout allows one discount; can the attacker return to the discount page after applying it and take a second one, or reapply the same one repeatedly?

**How to test**: identify every function meant to be capped at N uses within a workflow; develop misuse cases that repeat the triggering action (back-navigation, cart reload/unload, resubmission) and confirm the limit still holds server-side.

**Remediation**: enforce the limit at the database/session level (e.g. invalidate a coupon after use, track a per-user counter tied to session identity) rather than relying on UI flow to prevent repetition.

**Related**: Account enumeration / guessable account testing; weak lockout mechanism testing.

**Refs**: InfoPath Forms Services business-logic operation-limit rule; CME gold trading halt incident (real-world limit-breach precedent).

---

## WSTG-BUSL-06

**Testing for the Circumvention of Work Flows**

Goal: confirm multi-step workflows enforce correct step order, and that any side effect of an incomplete/abandoned workflow (points, credits, posted content) is rolled back rather than left in a partial, exploitable state.

| Example | Abuse |
|---|---|
| Loyalty points credited mid-transaction | Start a transaction, let points post, then cancel or remove items before tendering — points/credits should be rolled back to match the final tender, otherwise an attacker farms points without buying anything |
| Bulletin board profanity filter checked only on initial post | Filter runs on create but not on edit — post something clean, then edit in banned content that was never re-checked |

**How to test**: map the intended step order from documentation, then try skipping, reordering, or partially completing/canceling steps; verify side effects (credits, saved state) are rolled back or blocked when the workflow isn't completed correctly, and that re-validation runs on edit paths, not just create paths.

**Remediation**: enforce step order and rollback-on-incomplete server-side; re-run the same validation on every mutation path (create *and* edit), not just the initial one.

**Related**: Directory traversal; bypassing authorization schema; bypassing session management; BUSL-01 through BUSL-05, BUSL-07 through BUSL-09 (workflow circumvention often compounds with these).

**Refs**: OWASP Abuse Case Cheat Sheet; CWE-840 (Business Logic Errors).

---

## WSTG-BUSL-07

**Test Defenses Against Application Misuse**

Goal: confirm the application has active, application-layer defenses that detect and respond to abuse patterns — not just per-field input validation — so attackers can't probe indefinitely without consequence.

Localized defenses (rejecting bad characters, temporary lockout after failed logins) are necessary but not sufficient. There is usually no defense against broader misuse signals:

| Misuse signal |
|---|
| Forced browsing |
| Bypassing presentation-layer validation |
| Repeated access-control errors |
| Extra/duplicated/missing parameters |
| Malformed structured data (JSON/XML) |
| Obvious XSS/SQLi payloads |
| Automation-speed usage |
| Geo-location or user-agent jumps mid-session |
| Multi-stage process accessed out of order |
| High-rate use of sensitive functions (voucher redemption, failed payments, uploads, downloads, logouts) |

A well-defended app responds to accumulating suspicious signals by disabling functionality, stepping up authentication, adding delay, or increasing logging — even silently, without telling the user.

**How to test**: this is a rollup of every other test performed — while testing, note whether any response changed, request got blocked, or account got logged out/locked in reaction to aggressive input. Absence of any reaction across all testing indicates no application-wide active defense (though silent server-side responses like alerting can't be ruled out from the outside).

**Remediation**: implement active defenses (e.g. an AppSensor-style detection layer) that respond to abuse signal accumulation, not just per-field validation.

**Refs**: NIST IR 7684 (CMSS); MITRE CAPEC; OWASP AppSensor Project & Guide v2; "Creating Attack-Aware Software Applications with Real-Time Defenses" (CrossTalk, 2011).

---

## WSTG-BUSL-08

**Test Upload of Unexpected File Types**

Goal: confirm the upload feature only accepts approved file types and rejects everything else — distinct from BUSL-09, since a wrong-but-non-malicious file type can still corrupt data or be misused (e.g. an executable script accepted where only images were expected).

Example: a picture-sharing app expects `.gif`/`.jpg`; if it accepts an HTML file with a `<script>` tag or a PHP file, and later serves it from a web-accessible path, the script executes against the application.

**Black-box checklist**:
- Prepare a set of disallowed files (`.jsp`, `.exe`, HTML with embedded script) and attempt upload.
- Check whether validation is client-side JS only.
- Check whether validation trusts the `Content-Type` header.
- Check whether validation is extension-only.
- Check whether uploaded files are directly reachable by URL.
- Check whether uploaded content can include injected code/script.
- Check path handling — a ZIP containing crafted internal paths can extract outside the intended upload directory.

**Remediation**: use allow lists (not deny lists) of extensions, verify actual content type (not just `Content-Type` header or extension), and sanitize/validate archive member paths before extraction.

**Related**: File extension handling for sensitive info; BUSL-09.

**Refs**: OWASP Unrestricted File Upload; "File upload security best practices"; "Stop people uploading malicious PHP files via forms"; CWE-434.

---

## WSTG-BUSL-09

**Test Upload of Malicious Files**

Goal: confirm that even *accepted* file types are scanned for malicious content — an allowed extension doesn't mean safe contents.

**Web shells**: if the server executes code from the upload path, an uploaded script grants remote command execution.

```php
<?php
if ($_SERVER['REMOTE_HOST'] === "FIXME") { // Set your IP address here
if(isset($_REQUEST['cmd'])){
$cmd = ($_REQUEST['cmd']);
echo "<pre>\n";
system($cmd);
echo "</pre>";
}
}
?>
```
```
https://example.org/7sna8uuorvcx3x4fx.php?cmd=cat+/etc/passwd
```
Mitigate accidental exposure during testing: randomize the shell's filename, password-protect it, restrict by IP, and remove it after the test.

**Filter evasion** — once client-side-only checks are ruled out (trivially bypassed via proxy), try against server-side filters:

| Technique | Example |
|---|---|
| Spoof Content-Type | Set `image/jpeg` regardless of actual content |
| Uncommon extensions | `.php5`, `.shtml`, `.asa`, `.jsp`, `.jspx`, `.aspx`, `.asp`, `.phtml`, `.cshtml` |
| Case variation | `file.PhP`, `file.AspX` |
| Multiple filenames in one request | Vary each one independently |
| Trailing/injected characters | `file.asp...`, `file.php;jpg`, `file.asp%00.jpg`, `1.jpg%00.php` |
| Path confusion (nginx misconfig) | `test.jpg/x.php` executed as `x.php` |

**Malicious contents** (harder — depends on file type):
- **Malware**: scan with anti-malware; use the EICAR test file (safe, universally flagged) to confirm scanning is wired up. Also test macro-laden Office docs — Metasploit / Social-Engineer Toolkit can generate samples.
- **Archive directory traversal**: a crafted zip with entries like `..\..\..\..\shell.php` can write outside the intended extraction directory.
- **Zip bombs**: small archive, huge decompressed size, causing DoS via disk/memory exhaustion (also applies to gzip). Example construction:
  ```
  dd if=/dev/zero bs=1M count=1024 | zip -9 > bomb.zip
  ```
  Higher ratios achievable via nested compression, format abuse, or quines. Do not run this against a live target without written approval — risk of real DoS and cloud auto-scaling cost.
- **XML**: XXE and billion-laughs-style DoS (see XML Injection testing).
- **Other formats**: CSV injection; Office macros/PowerShell payloads; PDF embedded JavaScript.

**Source review** — grep for upload/file-handling APIs:

| Language | Look for |
|---|---|
| Java | `new file`, `import`, `upload`, `getFileName`, `Download`, `getOutputString` |
| C/C++ | `open`, `fopen` |
| PHP | `move_uploaded_file()`, `Readfile`, `file_put_contents()`, `file()`, `parse_ini_file()`, `copy()`, `fopen()`, `include()`, `require()` |

**Remediation**: scan uploaded content (not just extension/type), validate archive member paths before extraction, cap decompressed size, and treat file-format-specific risks (macros, XXE, CSV injection) per format. See the File Upload Cheat Sheet for full guidance.

**Tools**: Metasploit payload generation, intercepting proxy.

**Related**: File extension handling for sensitive info; XML Injection testing; BUSL-08.

**Refs**: OWASP File Upload Cheat Sheet; OWASP Unrestricted File Upload; "Why File Upload Forms are a Major Security Threat"; "Overview of Malicious File Upload Attacks"; "8 Basic Rules to Implement Secure File Uploads"; CWE-434.
