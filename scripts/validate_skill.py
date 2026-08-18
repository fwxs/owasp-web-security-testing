#!/usr/bin/env python3
"""Validate structural integrity of the owasp-web-security-testing skill.

Checks (stdlib only):
  1. SKILL.md has valid frontmatter: name (lowercase/hyphen, <=64, no reserved
     words) and a non-empty description <=1024 chars.
  2. Every `references/...md` path mentioned in SKILL.md exists on disk.
  3. The reference files together contain exactly 97 unique WSTG IDs.
  4. wstg-checklist.csv has one row per WSTG ID (97) with the expected columns.
  5. All Python scripts compile.

Exit code 0 = pass, 1 = failure. Intended for CI and pre-commit use.
"""
import csv
import glob
import py_compile
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors = []


def check(cond, msg):
    if not cond:
        errors.append(msg)


# 1. Frontmatter
skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
fm = re.match(r"^---\n(.*?)\n---\n", skill, re.S)
check(fm is not None, "SKILL.md: missing YAML frontmatter")
if fm:
    name = re.search(r"^name:\s*(.+)$", fm.group(1), re.M)
    desc = re.search(r"^description:\s*(.+)$", fm.group(1), re.M)
    check(name is not None, "SKILL.md: missing name")
    check(desc is not None, "SKILL.md: missing description")
    if name:
        n = name.group(1).strip()
        check(re.fullmatch(r"[a-z0-9-]{1,64}", n) is not None,
              f"SKILL.md: name '{n}' must be lowercase/hyphen, <=64 chars")
        check("claude" not in n and "anthropic" not in n,
              "SKILL.md: name contains a reserved word")
    if desc:
        d = desc.group(1).strip()
        check(0 < len(d) <= 1024,
              f"SKILL.md: description length {len(d)} not in 1..1024")

# 2. Referenced files exist
for rel in sorted(set(re.findall(r"references/[0-9a-z-]+\.md", skill))):
    check((ROOT / rel).exists(), f"SKILL.md references missing file: {rel}")

# 3. 97 unique WSTG IDs across references
ids = set()
for f in glob.glob(str(ROOT / "references" / "*.md")):
    ids.update(re.findall(r"^## (WSTG-[A-Z]{4}-\d{2})$",
                          Path(f).read_text(encoding="utf-8"), re.M))
check(len(ids) == 97, f"references: expected 97 unique WSTG IDs, found {len(ids)}")

# 4. Checklist rows
cl = ROOT / "resources" / "wstg-checklist.csv"
if cl.exists():
    rows = list(csv.DictReader(cl.open(encoding="utf-8")))
    check(len(rows) == 97,
          f"checklist: expected 97 rows, found {len(rows)}")
    expected_cols = {"id", "category", "name", "status",
                     "result", "severity", "evidence", "notes"}
    if rows:
        check(expected_cols.issubset(rows[0].keys()),
              f"checklist: missing columns {expected_cols - set(rows[0].keys())}")
    cl_ids = {r["id"] for r in rows}
    check(cl_ids == ids,
          "checklist IDs do not match reference IDs "
          f"(only in checklist: {sorted(cl_ids - ids)}; "
          f"only in refs: {sorted(ids - cl_ids)})")
else:
    errors.append("resources/wstg-checklist.csv missing")

# 5. Scripts compile
for s in glob.glob(str(ROOT / "scripts" / "*.py")):
    try:
        py_compile.compile(s, doraise=True)
    except py_compile.PyCompileError as e:
        errors.append(f"script does not compile: {Path(s).name}: {e}")

if errors:
    print("VALIDATION FAILED:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
print(f"OK: frontmatter valid, {len(ids)} WSTG IDs, checklist matches, scripts compile.")
sys.exit(0)
