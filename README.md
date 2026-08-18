# owasp-web-security-testing

A Claude Agent Skill for running web application security assessments aligned to the
**OWASP Web Security Testing Guide (WSTG) v4.2** — all 97 test cases across 12 categories.

It provides a phased engagement workflow, per-test authoritative WSTG guidance (objectives,
how-to-test, remediation), a coverage checklist, a stdlib-only coverage summarizer, a risk-rating
convention, and a report template. It is a methodology and knowledge navigator — it does not
exploit systems autonomously, and it gates active-testing output on confirmed authorization.

## Layout
```
owasp-web-security-testing/
├── SKILL.md                     # methodology, workflow, category routing, guardrails
├── references/                  # 17 files across 12 WSTG categories, loaded on demand
│                                 #   (Input Validation is split into 07a–07f by injection class)
├── resources/
│   ├── wstg-checklist.csv        # all 97 tests for coverage tracking
│   └── report-template.md        # findings report skeleton
└── scripts/
    └── coverage_report.py        # python3 stdlib only; summarizes the checklist
```

## Install
- **From GitHub (Claude Code):**
  ```bash
  git clone https://github.com/fwxs/owasp-web-security-testing \
    ~/.claude/skills/owasp-web-security-testing
  ```
  Restart Claude Code; the skill is auto-discovered (SKILL.md is at the repo root).
- **Claude Code (manual):** copy this folder into `~/.claude/skills/` (personal) or
  `.claude/skills/` (project).
- **claude.ai:** download the release `.zip` and upload via Settings → Capabilities → Skills.
- **Claude API:** upload via the `/v1/skills` endpoint with the Skills beta headers.

Note: skills do not sync across surfaces; upload separately where needed.

## Use
Ask Claude to plan, execute, track, or report a web app assessment (e.g. "help me scope a WSTG
pentest of staging.example.com" or "how do I test for SQL injection per WSTG"). Coverage summary:
```bash
python3 scripts/coverage_report.py resources/wstg-checklist.csv
```

## Development
```bash
python3 scripts/validate_skill.py   # structural integrity check (also runs in CI)
```

## License and attribution
This repository is dual-licensed:

- **WSTG-derived content** — `references/**`, `resources/wstg-checklist.csv`,
  `resources/report-template.md` — is adapted from the OWASP Web Security Testing Guide v4.2 and is
  licensed under **CC BY-SA 4.0**. See `LICENSE-DOCS` and `NOTICE`. ShareAlike applies: adaptations
  of this content must stay under a CC BY-SA-compatible license.
- **Original code and methodology** — `SKILL.md`, `scripts/**`, and the strategy/integration/
  test-prompt docs — is licensed under **MIT**. See `LICENSE`.

The OWASP Web Security Testing Guide is © the OWASP Foundation, licensed CC BY-SA 4.0
(https://owasp.org/www-project-web-security-testing-guide/). Changes made in this repo are listed in
`NOTICE`. "OWASP" is a registered trademark of the OWASP Foundation; this project is not affiliated
with or endorsed by OWASP.

## Authorized use only
This skill produces offensive-security guidance and gates active-testing output on confirmed
authorization. Only run active tests against systems you are explicitly authorized to test.
