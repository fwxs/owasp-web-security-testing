# WSTG IDNT — Identity Management

OWASP WSTG v4.2. Tests WSTG-IDNT-01 → 05.

## Table of Contents

- [IDNT-01 Role Definitions](#wstg-idnt-01)
- [IDNT-02 User Registration](#wstg-idnt-02)
- [IDNT-03 Account Provisioning](#wstg-idnt-03)
- [IDNT-04 Account Enumeration](#wstg-idnt-04)
- [IDNT-05 Weak Username Policy](#wstg-idnt-05)

---

## WSTG-IDNT-01

**Test Role Definitions**

Goal: confirm app roles (admin, auditor, support, customer) are well-defined, non-switchable without auth, and least-privilege.

Black-box:
- ID roles via docs, admin guidance, comments.
- Fuzz role indicators: cookie vars (`role=admin`, `isAdmin=True`), account vars (`Role: manager`), hidden paths (`/admin`, `/mod`, `/backups`), known usernames (`admin`, `backups`).
- Attempt switching to found roles — role existing isn't itself a vuln; unauthorized access to it is.
- Review perms per role: support shouldn't reach admin functions or transact as user; admin shouldn't hold unchecked full power — sensitive admin actions need maker-checker or MFA (ref: Twitter 2020 incident).

Tools: Burp Autorize, ZAP Access Control Testing add-on.

Refs: *Role Engineering for Enterprise Security Management*, Coyne & Davis, 2007; RBAC standards.

---

## WSTG-IDNT-02

**Test User Registration Process**

Goal: verify identity requirements for registration match business/security needs, and the process can't be forged or manipulated.

Black-box, check:

| # | Question |
|---|---|
| 1 | Can anyone register? |
| 2 | Registrations vetted by human, or auto-granted on criteria? |
| 3 | Can one identity register multiple times? |
| 4 | Can users register for different roles/perms? |
| 5 | What ID proof is required? |
| 6 | Are registered identities verified? |
| 7 | Can identity info be forged/faked? |
| 8 | Can identity info be manipulated in transit during registration? |

Example: WordPress requires only an accessible email. Google requires name, DOB, country, mobile, email, CAPTCHA — only email/mobile verifiable, but stricter overall than WordPress.

Remediation: match ID/verification requirements to the sensitivity of what the credentials protect.

Tools: HTTP proxy.

Refs: User Registration Design (OWASP).

---

## WSTG-IDNT-03

**Test Account Provisioning Process**

Goal: verify only authorized roles can provision accounts, and de-provisioning is controlled.

Black-box, check:
- Which roles can provision users, and what account types.
- Is provisioning/de-provisioning vetted or authorized?
- Can an admin provision other admins, or only regular users?
- Can a user/admin provision perms greater than their own?
- Can an admin/user de-provision themselves?
- What happens to a de-provisioned user's files/resources — deleted or transferred?

Example: WordPress provisions a user from just name + email; de-provisioning prompts admin to delete or transfer the user's posts.

Tools: manual testing preferred; HTTP proxy helps.

---

## WSTG-IDNT-04

**Testing for Account Enumeration and Guessable User Account**

Goal: determine if valid usernames can be collected via differing app responses, enabling targeted brute force.

Black-box — record and diff server responses for:

| Case | Input | Look for |
|---|---|---|
| Valid creds | valid user + valid pass | HTTP 200, response length |
| Valid user, wrong pass | valid user + bad pass | error msg + length |
| Invalid user | bad user + bad pass | error msg + length |

If error text/length/behavior differs between "valid user, wrong pass" and "invalid user", the app leaks username validity (e.g. "Password not correct" vs "User not recognized").

Other enumeration channels:

| Technique | Signal |
|---|---|
| Error codes on login page | app-specific code per failure type |
| URL/redirect params | `err.jsp?User=baduser&Error=0` vs `...&Error=2` |
| URI probing | `403 Forbidden` (exists, no access) vs `404 Not Found` (doesn't exist) on per-user paths |
| Page titles | "Invalid user" vs "Invalid authentication" |
| Password-recovery messages | "user not found" vs "password sent to your email" |
| Friendly 404 | `200 OK` with an image standing in for a real 404 |
| Response timing | external calls (e.g. recovery email) add measurable delay for valid users |

Guessing usernames: sequential IDs (`CN000100`, `CN000101`...), realm+number (`R1001`), IDs derived from real names (Freddie Mercury → `fmercury`), LDAP queries, Google dorking. Script enumeration with curl/wget/Perl. Watch for lockout/IP-ban thresholds.

Gray-box: confirm the app returns the same error/message/length for every failed auth path, e.g. always "Credentials submitted are not valid".

Remediation:
- Return one consistent, generic error for any invalid login/registration/recovery input.
- Remove default/test accounts before production release.

Tools: ZAP, curl, Perl.

Refs: Marco Mella, *Sun Java Access & Identity Manager Users enumeration*; Username Enumeration Vulnerabilities (OWASP).

---

## WSTG-IDNT-05

**Testing for Weak or Unenforced Username Policy**

Goal: determine if predictable account-name structure (Joe Bloggs → `jbloggs`) enables enumeration.

Black-box:
1. Determine the account-name structure.
2. Compare app responses for valid vs invalid names.
3. Use response diffs or name dictionaries to enumerate valid accounts.

Remediation: same as IDNT-04 — consistent, generic error messages for any invalid login credential.
