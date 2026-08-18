# Web Application Security Assessment Report

> Structure adapted from the OWASP WSTG v4.2 Reporting guidance. Consultancy-grade;
> trim for internal or bug-bounty contexts. Secure/encrypt this report in transit —
> it documents exploitable weaknesses. Replace every `<...>` placeholder and delete
> guidance notes before delivery.

## 1. Introduction

### 1.1 Version control
| Version | Description | Date | Author |
|---------|-------------|------|--------|
| 0.1 | Draft | `<DD/MM/YYYY>` | `<name>` |
| 1.0 | Final | `<DD/MM/YYYY>` | `<name>` |

### 1.2 Team
`<members, roles, relevant qualifications>`

### 1.3 Scope
In-scope targets (domains, IPs, apps, environments), test type (black/grey/white-box),
and roles/credentials provided. State the environment (prod vs staging).

### 1.4 Limitations
Out-of-bounds areas, broken functionality encountered, lack of cooperation/time/access,
and any test that could not be completed and why.

### 1.5 Timeline
Testing window(s), retest window if applicable.

### 1.6 Disclaimer
A point-in-time assessment; absence of a finding is not proof of absence of the flaw.

## 2. Executive Summary

Non-technical narrative for management: what was assessed, overall risk posture, the most
important themes, and the headline count of findings by severity. No jargon. One page max.

| Severity | Count |
|----------|-------|
| Critical | `<n>` |
| High | `<n>` |
| Medium | `<n>` |
| Low | `<n>` |
| Informational | `<n>` |

Risk-rating model used: `<OWASP Risk Rating | CVSS v3.1 | CVSS v4.0>` (do not mix models).

## 3. Findings

### 3.1 Findings summary
| # | Title | WSTG ID | Severity | Affected asset | Status |
|---|-------|---------|----------|----------------|--------|
| 1 | `<title>` | `WSTG-XXXX-NN` | `<sev>` | `<asset>` | Open |

### 3.2 Findings detail

Repeat this block per finding.

#### Finding 1 — `<title>`
- **Severity / rating:** `<sev>` — `<OWASP Risk score or CVSS vector>`
- **WSTG reference:** `WSTG-XXXX-NN` — `<test name>`
- **Affected assets:** `<URLs / endpoints / parameters>`
- **Description:** What the issue is and why it matters in this application's context.
- **Reproduction steps:** Numbered, exact steps. Include the request/payload and observed
  response. An analyst should be able to reproduce it from this alone.
- **Evidence:** Request/response excerpts, screenshots, logs, timestamps.
- **Impact:** Concrete consequence for this client (data exposed, accounts affected, etc.).
- **Remediation:** Specific, actionable fix. Cite the WSTG test's Remediation guidance where it
  applies, plus framework-specific direction.
- **References:** WSTG test ID, CWE, vendor advisories.

## Appendix A — Coverage checklist
Attach the completed `wstg-checklist.csv` (all 97 WSTG tests with status/result), or paste the
output of `scripts/coverage_report.py`. Coverage means every applicable test was considered;
`n/a` entries should carry a one-line justification.

## Appendix B — Tooling
List tools and versions used (proxy, scanners, custom scripts) for reproducibility.
