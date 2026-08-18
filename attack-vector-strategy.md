# Strategy: identifying attack vectors on an authorized web application

The core idea: **attack vectors are derived from the attack surface, not from reading the WSTG
checklist top to bottom.** Running WSTG-INFO-01 through APIT-01 in order wastes time on tests that
don't apply and buries the high-value vectors under low-value ones. Instead, map the surface first,
derive candidate vectors from what you find, prioritize by exposure × impact, and only then reach
into the relevant WSTG category to execute. The checklist becomes a coverage backstop, not the plan.

Prerequisite: written authorization, defined scope, exclusions, and a testing window. Everything
below assumes an asset you are authorized to test.

## Step 1 — Establish rules of engagement

Record targets, exclusions, provided credentials/roles, environment (prod vs staging), rate limits,
and prohibited actions (e.g. no DoS, no data exfiltration). This bounds which vectors you're even
allowed to pursue. Log it as the top of the working checklist.

## Step 2 — Build the surface map (WSTG-INFO)

Load `references/01-info-information-gathering.md`. The output you need before deriving vectors:

- **Entry points** — every place input crosses into the app: URL params, form fields, headers,
  cookies, JSON/GraphQL bodies, file uploads, WebSocket messages, redirects. (WSTG-INFO-06 maps these.)
- **Technology stack** — server, framework, language, WAF/CDN, client-side frameworks. (INFO-02, -08, -09.)
- **Authentication & session mechanisms** — login types, SSO/OAuth, MFA, cookie/token scheme.
- **Roles and tenancy** — anonymous vs user vs admin; multi-tenant boundaries; object ownership model.
- **Sensitive data & flows** — where PII, payments, credentials, and privileged actions live.
- **Trust boundaries** — every point where data crosses from less-trusted to more-trusted (client→server,
  tenant→tenant, user→admin, app→backend service/third party).

Vectors cluster at entry points and trust boundaries. If you skip this step, you're guessing.

## Step 3 — Derive candidate vectors from the surface

For each surface element, ask "what class of attack does this invite?" and record the WSTG test that
covers it. Typical mappings:

| Surface element observed | Candidate attack vector | WSTG category → tests |
|--------------------------|-------------------------|-----------------------|
| Any input reflected/stored/rendered | XSS (reflected/stored/DOM) | INPV-01/02, CLNT-01 |
| Input reaching a query/command/parser | SQLi, NoSQLi, command, LDAP, XML/XXE, SSTI | INPV-05/06/07/12/etc. |
| Numeric/opaque object IDs in requests | IDOR / broken object-level authz | ATHZ-04 |
| Role- or privilege-bearing requests | Vertical/horizontal privilege escalation | ATHZ-02/03 |
| Login / credential handling | Auth bypass, default creds, weak lockout, credential-in-transit | ATHN-01/02/03/04 |
| Password reset / "remember me" / security questions | Reset abuse, predictable tokens | ATHN-05/08/09 |
| Session cookies / tokens / JWT | Missing flags, fixation, weak JWT, no CSRF | SESS-01/02/03/05/10 |
| State-changing requests without anti-CSRF | CSRF | SESS-05 |
| Server-side fetch of user-supplied URLs | SSRF | INPV-19 |
| File upload | Malicious upload, path/logic bypass | BUSL-09, INPV-* |
| Multi-step workflows (checkout, transfer) | Logic bypass, step-skipping, race, price tampering | BUSL-01..07 |
| Redirects / URL params controlling navigation | Open redirect, client-side URL/resource manipulation | CLNT-04/05, INPV-* |
| CORS headers / postMessage / WebSockets | Origin trust abuse, cross-origin leakage | CLNT-07/10/11 |
| TLS / cert / crypto in transit | Weak transport, sensitive data unencrypted, padding oracle | CRYP-01/03/02 |
| Admin panels / management interfaces / cloud buckets | Exposed admin, subdomain takeover, open storage | CONF-05/10/11 |
| Verbose errors / stack traces | Information leakage aiding other vectors | ERRH-01/02 |
| GraphQL / rich API | Introspection, injection, missing object authz | APIT-01, ATHZ-04 |

This table is a starting generator, not a limit — add vectors the specific app suggests.

## Step 4 — Prioritize the vectors

Rank by **exposure × impact**, and test in this order:

1. **Unauthenticated + high impact.** Auth bypass, injection on pre-auth entry points, SSRF,
   exposed admin/management interfaces, secrets in client code or errors. Reachable by anyone; often
   full-compromise impact.
2. **Authorization boundary crossings.** IDOR and privilege escalation across user↔user (tenant
   isolation) and user↔admin. In multi-tenant apps this is usually the highest-value finding class.
3. **Authenticated injection & input handling.** XSS, SQLi, file upload, template injection behind login.
4. **Session & CSRF.** Cookie flags, fixation, token strength, missing anti-CSRF on state changes.
5. **Business-logic abuse.** Step-skipping, race conditions, price/quantity tampering, quota bypass —
   the vectors scanners miss and that map directly to money or data.
6. **Transport, config, and defense-in-depth.** TLS, headers, error verbosity, information leakage.

Rationale: an unauthenticated RCE outranks a missing `HttpOnly` flag even though both are "findings."
Testing in impact order means that if the window is cut short, you've spent it on what matters.

## Step 5 — Execute per vector

For each prioritized vector: open its WSTG category file, read the test's **Test Objectives** (this
defines "done") and **How to Test**, translate the procedure into concrete requests/payloads/tooling
for this target, run it in the authorized environment, and capture evidence (request/response,
payload, timestamp, screenshot). Update `status`/`result`/`severity`/`evidence` in the checklist as
you go. Mark inapplicable tests `n/a` with a one-line reason so coverage stays honest.

## Step 6 — Chain the findings

Individual findings understate real risk; attackers chain. After the first pass, look for chains:

- Info leak (ERRH/INFO) → reveals a parameter or path → IDOR (ATHZ) → data exfiltration.
- Open redirect (CLNT) → OAuth token theft (SESS/ATHZ) → account takeover.
- Weak upload validation (BUSL) → stored XSS or code execution (INPV/CLNT).
- Username enumeration (IDNT) → weak lockout (ATHN) → credential stuffing.

A chain that reaches admin or another tenant's data is a single high/critical finding, not three
mediums. Document the chain explicitly.

## Step 7 — Track coverage and report

Run `python3 scripts/coverage_report.py resources/wstg-checklist.csv` to confirm every applicable
test was considered and to list what's untouched. Rate each confirmed finding with one consistent
model (OWASP Risk Rating or CVSS — state which). Populate `resources/report-template.md`: executive
summary, findings summary table, per-finding detail with reproduction and evidence, and the coverage
appendix.

---

## Worked mini-example

**Target (authorized):** multi-tenant B2B SaaS. Surface map from Step 2 finds: email/password login
with "remember me," REST API using integer `account_id`/`invoice_id` in paths, a file-upload avatar
feature, a multi-step billing workflow, an `/admin` panel, and a server-side "import from URL" feature.

**Derived + prioritized vectors:**

1. *Unauth/high:* SSRF via "import from URL" (INPV-19); auth bypass on login (ATHN-04); is `/admin`
   reachable or guessable (CONF-05).
2. *Authz boundaries:* change `account_id`/`invoice_id` to another tenant's → IDOR (ATHZ-04); reach
   admin functions as a normal user (ATHZ-02).
3. *Authenticated input:* avatar upload — content-type/extension/path handling (BUSL-09); stored XSS
   via profile fields (INPV-02).
4. *Session/CSRF:* "remember me" token strength (ATHN-05); cookie flags and CSRF on billing actions
   (SESS-01/05).
5. *Business logic:* skip payment step or tamper invoice amount in the billing workflow (BUSL-01/07);
   race on quota-limited actions (BUSL-... timing).
6. *Transport/config:* TLS config (CRYP-01); verbose API errors leaking stack/paths (ERRH-01).

The tenant-isolation IDOR (vector 2) is where you spend your best hour: in a multi-tenant app it's
both the most likely to exist and the highest impact. The strategy surfaced it because Step 2 flagged
opaque integer IDs crossing a tenant trust boundary — not because it was next on a checklist.
