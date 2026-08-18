# Security Policy

## What this project is

`owasp-web-security-testing` is a **local, offline Claude Agent Skill**: Markdown guidance derived
from the OWASP Web Security Testing Guide plus a few standard-library Python helper scripts
(`scripts/coverage_report.py`, `scripts/validate_skill.py`). It is not a hosted service and does not
process untrusted input at runtime.

Trust properties worth knowing:

- **No network calls.** The scripts use only the Python standard library and touch only the files
  you point them at. They make no outbound connections and send no telemetry.
- **No credentials or secrets** are stored, requested, or transmitted by this repository.
- **Local execution only.** Everything runs on your machine (or your Claude runtime); nothing here
  phones home.

If any of the above ever stops being true in a change, that change should be treated as a security-
relevant modification and called out explicitly in review.

## Supported versions

Security fixes are provided for the latest tagged release and the `main` branch. Older tags are not
patched — upgrade to the latest release.

| Version | Supported |
|---------|-----------|
| latest release / `main` | Yes |
| older tags | No |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue.

1. **Preferred:** use GitHub's private vulnerability reporting — the **Security** tab →
   **Report a vulnerability**. This opens a private advisory visible only to the maintainers.
2. **Alternative:** email the maintainer at `mrpacmanator@gmail.com` (replace before publishing).

In your report, include: a description of the issue, steps to reproduce, the affected file(s) or
script(s), the potential impact, and a suggested fix if you have one.

**Response targets:** acknowledgement within a few business days; for confirmed issues, a fix or
mitigation plan communicated as soon as practical. Please allow a reasonable disclosure window before
publishing details, and act in good faith — no data destruction, privacy violations, or service
disruption while investigating.

## What is in scope

- The helper scripts in `scripts/` (e.g. input handling, path handling, unsafe operations).
- The CI workflow and any repository automation.
- Packaging or install instructions that could lead a user to run something unsafe.

## What is out of scope

- **The offensive-security content itself.** This repository intentionally documents how to test web
  applications for vulnerabilities (per the OWASP WSTG). Describing an attack technique is the
  purpose of the project, not a vulnerability in it.
- **Vulnerabilities you find in a target application** using this methodology — report those to the
  owner of that application, not here.
- Issues in the upstream OWASP WSTG — report those to the
  [OWASP WSTG project](https://github.com/OWASP/wstg).

## Authorized use only

This skill produces guidance for active security testing and is designed to gate that guidance on
confirmed authorization. Using it to test systems you do not own or lack written permission to assess
is likely illegal and is not endorsed by this project or its maintainers. You are responsible for
operating within the law and your rules of engagement.
