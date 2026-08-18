# Contributing

Thanks for helping improve this skill. Please read the licensing section first — this repository is
dual-licensed, and which license applies depends on which files you touch.

## Licensing of contributions (read before you start)

This repo mixes two licenses (see `LICENSE`, `LICENSE-DOCS`, `NOTICE`):

- **WSTG-derived content** — `references/**`, `resources/wstg-checklist.csv`,
  `resources/report-template.md` — is under **CC BY-SA 4.0**. Any contribution to these files is
  accepted **only** under CC BY-SA 4.0. ShareAlike is not optional: your changes to this content stay
  under a CC BY-SA-compatible license, and if your change adapts the upstream OWASP WSTG you must
  keep attribution intact and record the change in `NOTICE`.
- **Original code and methodology** — `SKILL.md`, `scripts/**`, and the strategy / integration /
  test-prompt docs — is under **MIT**. Contributions to these files are accepted under MIT.

By opening a pull request you agree that your contribution is licensed under whichever of the two
licenses governs the files you changed (inbound = outbound). Sign your commits with the Developer
Certificate of Origin to certify you have the right to submit the work:

```bash
git commit -s -m "your message"
```

The `-s` adds a `Signed-off-by` line. Do not paste content you do not have the right to relicense.

## Content boundaries

This is an offensive-security methodology project, and contributions must respect that scope:

- **Keep it methodology, not weaponization.** Contribute test procedures, detection guidance, and
  remediation. Do **not** contribute exploit payloads targeting specific real-world hosts, or
  material whose only purpose is to attack systems the reader does not own.
- **Do not commit engagement data.** Never add a filled-in checklist, a real target's findings,
  client names, or credentials. `.gitignore` excludes working checklists; keep it that way.
- **Fixing reference text:** small corrections to `references/**` are welcome, but remember this is
  adapted OWASP WSTG. Preserve the meaning of the source, keep the `## WSTG-XXXX-NN` structure, and
  note substantive changes in `NOTICE`. For large content changes, consider contributing upstream to
  [OWASP/wstg](https://github.com/OWASP/wstg) first.

## Repository conventions

- **SKILL.md:** keep it under ~500 lines. The `description` frontmatter must stay under 1024
  characters, third-person, with concrete trigger terms. `name` stays lowercase/hyphen, ≤64 chars,
  with no reserved words.
- **References are one level deep.** `SKILL.md` points directly at each `references/*.md`; reference
  files do not point at each other. If you add a category file, add a direct row to the routing table
  in `SKILL.md`.
- **Integrity is enforced.** The reference files must contain exactly the 97 WSTG v4.2 IDs, and every
  ID must have a matching row in `resources/wstg-checklist.csv`. If you change one, change both.
- **Scripts stay stdlib-only.** No third-party dependencies — the skill must run in offline / network-
  restricted runtimes. This also keeps the "no network calls" property in `SECURITY.md` true.

## Before you open a pull request

Run the validator locally — CI runs the same check and will block merge on failure:

```bash
python3 scripts/validate_skill.py
```

It verifies the frontmatter, the 97-ID count, checklist/reference agreement, and that the scripts
compile. If you added or edited reference content, also sanity-check coverage:

```bash
python3 scripts/coverage_report.py resources/wstg-checklist.csv
```

## Pull request process

1. Fork the repository and create a branch (`git checkout -b fix/short-description`).
2. Make your change; run `validate_skill.py` until it passes.
3. Commit with DCO sign-off (`git commit -s`).
4. Open a PR describing **what** changed and **why**. If you touched `references/**`, state whether it
   adapts upstream OWASP WSTG and confirm the CC BY-SA / attribution requirements are met.
5. Keep PRs focused — one logical change per PR is easier to review than a sweeping edit.

## Reporting security issues

Do not use public issues or pull requests for security reports. Follow `SECURITY.md`.
