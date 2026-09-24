# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A Claude Agent Skill (`SKILL.md` at repo root) that turns a web application security assessment into
a repeatable, coverage-tracked engagement mapped to the **OWASP Web Security Testing Guide (WSTG)
v4.2** — all 97 test cases across 12 categories. It is a methodology and knowledge navigator, not a
scanner: it plans tests and suggests techniques/payloads for the engineer to run under confirmed
authorization; it does not exploit systems autonomously.

There is no application code to build or run. "Development" here means editing `SKILL.md`, the
`references/**` WSTG content, `resources/**`, and the two stdlib-only Python scripts in `scripts/`.

## Commands

```bash
# Structural integrity check — same check CI runs on every push/PR to main; run before opening a PR
python3 scripts/validate_skill.py

# Coverage summary against a (possibly filled-in) checklist copy
python3 scripts/coverage_report.py resources/wstg-checklist.csv
```

There is no separate lint/test/build step and no third-party dependencies anywhere in this repo —
both scripts are stdlib-only by design (see "Scripts stay stdlib-only" below).

`validate_skill.py` checks, in order: `SKILL.md` frontmatter validity (name lowercase/hyphen ≤64
chars with no reserved word, description non-empty ≤1024 chars); every `references/*.md` path
mentioned in `SKILL.md` exists; the reference files together contain **exactly 97** unique
`## WSTG-XXXX-NN` IDs; `resources/wstg-checklist.csv` has exactly 97 rows with the expected columns
and its ID set matches the reference files' ID set exactly; all scripts under `scripts/` compile.
Any of these failing blocks CI on the PR.

## Architecture

```
SKILL.md                     # methodology, engagement workflow, category routing table, guardrails
references/                  # 17 files across 12 WSTG categories, loaded on demand by category
                              #   (Input Validation is split 07a–07f by injection class — one INPV
                              #   file was too heavy to load efficiently)
resources/
  wstg-checklist.csv          # all 97 tests: id, category, name, status, result, severity, evidence, notes
  report-template.md          # findings report skeleton
scripts/
  coverage_report.py           # stdlib-only; summarizes a checklist copy
  validate_skill.py            # stdlib-only; CI integrity gate (see above)
```

**The 97-ID invariant is load-bearing.** `SKILL.md`'s category routing table, the reference files'
`## WSTG-XXXX-NN` headers, and `wstg-checklist.csv` rows must always agree 1:1. Adding, renaming, or
splitting a test ID means updating all three together, or `validate_skill.py` fails.

**Reference files are one level deep and self-contained.** `SKILL.md` points directly at each
`references/*.md`; reference files never point at each other. Each has its own table of contents and
one section per test ID with the WSTG **Summary/Goal**, **Test Objectives**, **How to Test**, and
(where WSTG provides them) **Remediation** and **References**. This content is authoritative and
adapted from upstream OWASP WSTG — treat **How to Test** as the procedure to adapt, not to paraphrase
loosely, since the objective defines what "done" means for that test. If you add a new category file,
add a direct row to the routing table in `SKILL.md` — do not nest references.

**Engagement workflow (in `SKILL.md`)** runs in phases: scope & rules of engagement → information
gathering (`references/01-info-*.md` drives the surface map that everything downstream depends on) →
test selection via the category routing table → per-category execution against
`resources/wstg-checklist.csv` → risk rating → report via `resources/report-template.md`. The
checklist is the single source of truth for engagement state; `coverage_report.py` reads it directly.

**Non-negotiable guardrail:** `SKILL.md` gates any active-testing output (payloads, scanning
commands, exploitation steps against a named target) on the user confirming written authorization,
enumerated in-scope targets, and known exclusions/testing windows. Passive/OSINT guidance and general
methodology discussion don't require this gate; when in doubt, treat the task as active and gate on
authorization.

## Dual licensing — know which one applies before editing

- **WSTG-derived content** (`references/**`, `resources/wstg-checklist.csv`,
  `resources/report-template.md`) is **CC BY-SA 4.0** (adapted from OWASP WSTG). ShareAlike applies:
  keep the `## WSTG-XXXX-NN` structure, preserve the source's meaning, and record substantive changes
  in `NOTICE`.
- **Original code and methodology** (`SKILL.md`, `scripts/**`, the strategy/integration/test-prompt
  docs) is **MIT**.

Contributions are accepted under whichever license governs the files touched (inbound = outbound);
see `CONTRIBUTING.md` for the DCO sign-off convention (`git commit -s`) used in this repo's PR flow.

## Content boundaries

This is an offensive-security methodology project. Contribute test procedures, detection guidance,
and remediation — not exploit payloads targeting specific real-world hosts, and nothing whose only
purpose is to attack systems the reader doesn't own. Never commit engagement data (filled-in
checklists, real target findings, client names, credentials) — `.gitignore` excludes working
checklist copies; keep it that way.

## Scripts stay stdlib-only

No third-party dependencies in `scripts/**`, ever — this keeps the skill runnable in offline /
network-restricted environments and keeps the "no network calls" property in `SECURITY.md` true.
