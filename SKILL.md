---
name: owasp-web-security-testing
description: Structured web application security assessment methodology based on the OWASP Web Security Testing Guide (WSTG) v4.2, covering all 97 test cases across 12 categories (information gathering, configuration, identity, authentication, authorization, session, input validation, error handling, cryptography, business logic, client-side, API). Use this whenever the user is planning, scoping, executing, tracking, or reporting a web application security assessment, penetration test, appsec review, or vulnerability test — including requests that mention WSTG, OWASP testing, pentest methodology, security test coverage, or "how do I test for" a specific web vulnerability class. Prefer this skill over ad-hoc recall for any WSTG-aligned testing task.
---

# OWASP Web Security Testing (WSTG v4.2)

This skill turns an assessment into a repeatable, coverage-tracked engagement mapped to the
OWASP Web Security Testing Guide v4.2. It provides the per-test authoritative guidance
(objectives, how-to-test, remediation), a coverage checklist, a risk-rating convention, and a
report template. It does **not** exploit systems autonomously — it plans tests, suggests
concrete techniques/commands/payloads for the engineer to run in their authorized environment,
organizes evidence, and produces the report.

## Non-negotiable guardrail: authorization first

Active security testing against a system you are not explicitly authorized to test is illegal in
most jurisdictions. Before producing any active-testing steps, payloads, or scanning commands
against a named target, confirm the engagement basics are in place:

1. **Written authorization** exists (signed scope / rules of engagement / bug-bounty program that
   covers the asset).
2. **In-scope targets** are enumerated (domains, IP ranges, apps, environments).
3. **Explicit exclusions** and testing windows are known (no-touch endpoints, prod vs staging,
   rate limits, DoS prohibitions).

If the user has not confirmed these, ask once, concisely, before generating active-testing
content. Passive/OSINT guidance (WSTG-INFO reconnaissance that only touches public third-party
sources) and general methodology can be discussed without a target. When in doubt, treat the task
as active and gate on authorization. Do not help circumvent authorization controls the user does
not own.

## Engagement workflow

Run the assessment in phases. Track coverage continuously against
`resources/wstg-checklist.csv` (copy it into the working directory and update `status`/`result`
per test as you go).

1. **Scope & rules of engagement.** Record in-scope targets, exclusions, credentials/roles
   provided, environment (prod/staging), and constraints. Decide which of the 12 categories apply
   (e.g. a public marketing site with no auth skips most of ATHN/ATHZ/SESS; an API-only backend
   leans on APIT/ATHZ/INPV).
2. **Information gathering (passive → active).** Start with `references/01-info-*.md`
   (WSTG-INFO). Fingerprint the stack, map the application surface, enumerate entry points. The
   surface map drives everything downstream — do not skip it.
3. **Plan test selection.** From the surface map, pick the applicable test IDs per category. Use
   the "category routing" table below to jump to the right reference file. Mark
   non-applicable tests as `N/A` with a one-line justification in the checklist (coverage means
   every test was *considered*, not that every test was run).
4. **Execute per category.** For each selected test, load its category reference file, read the
   test's **Test Objectives** and **How to Test**, adapt the techniques to the target, run them in
   the authorized environment, and capture evidence (request/response, screenshots, payloads,
   timestamps). Record status and result in the checklist.
5. **Rate findings.** Apply a consistent risk model (see "Risk rating" below) to every confirmed
   issue. Note remediation from the test's **Remediation** section where present.
6. **Report.** Populate `resources/report-template.md` from the checklist and findings. Include an
   executive summary, per-finding detail with reproduction steps and evidence, and the coverage
   appendix (the completed checklist).

At any point, run `scripts/coverage_report.py` against the working checklist to get a
category-by-category coverage summary and a list of untouched tests.

## Category routing

Load only the reference file(s) relevant to the current phase — each is self-contained and holds
the full WSTG text for its tests. Do not load them all at once. There are 12 categories; Input
Validation (INPV) is split across six files by injection class, since as one file it was too heavy
to load efficiently.

| Category | Reference file | When to reach for it |
|----------|----------------|----------------------|
| INFO — Information Gathering (10) | `references/01-info-information-gathering.md` | Recon, fingerprinting, surface mapping, metafiles, entry points |
| CONF — Configuration & Deployment (11) | `references/02-conf-configuration-deployment-management.md` | Server/platform config, HTTP methods, HSTS, admin interfaces, cloud storage, subdomain takeover |
| IDNT — Identity Management (5) | `references/03-idnt-identity-management.md` | Role definitions, registration, account provisioning, username enumeration |
| ATHN — Authentication (10) | `references/04-athn-authentication.md` | Credentials over channel, default creds, lockout, bypass, remember-me, password reset, MFA |
| ATHZ — Authorization (4) | `references/05-athz-authorization.md` | Directory traversal, privilege escalation, IDOR, OAuth |
| SESS — Session Management (9) | `references/06-sess-session-management.md` | Cookie attributes, session fixation, CSRF, logout, timeout, JWT, session puzzling |
| INPV — XSS & incubated (3) | `references/07a-inpv-xss.md` | Reflected/stored XSS (INPV-01/02), incubated/persistent input execution (INPV-14) |
| INPV — SQL injection (1) | `references/07b-inpv-sql-injection.md` | SQL injection incl. DBMS-specific and NoSQL/ORM (INPV-05) — heaviest file |
| INPV — Code/command injection (3) | `references/07c-inpv-code-command-injection.md` | Server-side code exec, OS command, format-string (INPV-11/12/13) |
| INPV — Interpreter injection (5) | `references/07d-inpv-interpreter-injection.md` | LDAP, XML, SSI, XPath, IMAP/SMTP injection (INPV-06/07/08/09/10) |
| INPV — HTTP manipulation (5) | `references/07e-inpv-http-manipulation.md` | Verb tampering, parameter pollution, splitting/smuggling, incoming requests, host header (INPV-03/04/15/16/17) |
| INPV — SSTI & SSRF (2) | `references/07f-inpv-ssti-ssrf.md` | Server-side template injection (INPV-18), SSRF (INPV-19) |
| ERRH — Error Handling (2) | `references/08-errh-error-handling.md` | Error codes/messages, stack traces |
| CRYP — Cryptography (4) | `references/09-cryp-cryptography.md` | Weak transport (TLS), padding oracle, sensitive data over unencrypted channels, weak encryption |
| BUSL — Business Logic (9) | `references/10-busl-business-logic.md` | Logic data validation, request forging, integrity checks, process timing, function abuse, file upload logic |
| CLNT — Client-side (13) | `references/11-clnt-client-side.md` | DOM XSS, JS execution, CSS/URL/resource manipulation, clickjacking, WebSockets, postMessage, CORS |
| APIT — API Testing (1) | `references/12-apit-api-testing.md` | GraphQL and general API attack surface |

**"How do I test for X" shortcut:** map the vulnerability to its file and open just that one.
XSS → 07a. SQLi → 07b. Code/command/format-string injection → 07c. LDAP/XML/XPath/SSI/mail
injection → 07d. HTTP verb/parameter-pollution/splitting/smuggling/host-header → 07e. SSTI/SSRF →
07f. IDOR/privilege escalation/traversal → ATHZ. CSRF/session fixation/cookie flags/JWT → SESS.
Clickjacking/DOM issues/CORS/postMessage → CLNT. TLS/crypto → CRYP.
Rate-limit/workflow/price-tampering → BUSL.

## Using the reference files

Each category file has a table of contents and one section per test ID (`## WSTG-XXXX-NN`) with the
verbatim WSTG **Summary**, **Test Objectives**, **How to Test**, and (where WSTG provides them)
**Remediation** and **References**. The text is authoritative OWASP content — treat **How to Test**
as the procedure to adapt, and translate it into concrete tool commands and payloads for the
target. Do not paraphrase objectives loosely; the objective defines what "done" means for that
test.

## Coverage tracking

`resources/wstg-checklist.csv` lists all 97 tests with columns:
`id, category, name, status, result, severity, evidence, notes`.

- `status`: `not-started` | `in-progress` | `done` | `n/a`
- `result`: `pass` | `fail` | `info` | `` (blank until tested) — `fail` means a vulnerability was found
- `severity`: only for `result=fail` — `critical` | `high` | `medium` | `low` | `info`

Update it as the single source of truth for the engagement. Run the coverage script to summarize:

```bash
python3 scripts/coverage_report.py resources/wstg-checklist.csv
```

It prints per-category counts (done / in-progress / n/a / not-started), the confirmed findings by
severity, and the list of tests still not-started. Stdlib only — no dependencies to install.

## Risk rating

Rate every confirmed finding consistently so the report is defensible. Default to the **OWASP Risk
Rating Methodology**: `Risk = Likelihood × Impact`, each estimated from threat-agent, vulnerability,
technical-impact, and business-impact factors, then mapped to Low/Medium/High/Critical. If the
client standardizes on **CVSS**, score with CVSS v3.1 or v4.0 and record the vector string. State
which model was used; do not mix them within one report. Business impact is client-specific — ask
rather than assume when it materially changes the rating.

## Reporting

Use `resources/report-template.md`. Minimum contents: version control, scope, limitations, and
timeline; an executive summary readable by non-technical stakeholders; a findings summary table;
per-finding detail (description, affected assets, reproduction steps, evidence, risk rating,
remediation, references to the WSTG test ID); and a coverage appendix (the completed checklist).
Encrypt/secure the report in transit — it is a map of exploitable weaknesses.

## Scope of this skill

- **In scope:** WSTG-aligned planning, test selection, per-test technique guidance, payload and
  command suggestions for the engineer to run under authorization, coverage tracking, risk rating,
  evidence organization, and report generation.
- **Out of scope:** autonomous exploitation, testing without confirmed authorization, and anything
  that helps attack systems the user does not own or have permission to test.
