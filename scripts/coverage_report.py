#!/usr/bin/env python3
"""Summarize WSTG assessment coverage from the checklist CSV.

Usage:
    python3 coverage_report.py path/to/wstg-checklist.csv

Prints per-category coverage, confirmed findings by severity, and the list of
tests still not started. Standard library only (csv, sys, collections) — no
external dependencies, so it runs anywhere Python 3 does, including offline /
network-restricted runtimes.
"""
import csv
import sys
from collections import defaultdict, Counter

STATUSES = ("done", "in-progress", "n/a", "not-started")
SEV_ORDER = ("critical", "high", "medium", "low", "info")


def load(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def main(path):
    rows = load(path)
    if not rows:
        print("Checklist is empty.")
        return 1

    by_cat = defaultdict(Counter)
    findings = []
    not_started = []
    for r in rows:
        cat = r.get("category", "?").strip()
        status = (r.get("status") or "not-started").strip().lower()
        if status not in STATUSES:
            status = "not-started"
        by_cat[cat][status] += 1
        if (r.get("result") or "").strip().lower() == "fail":
            findings.append(r)
        if status == "not-started":
            not_started.append(r)

    total = len(rows)
    done = sum(c["done"] + c["n/a"] for c in by_cat.values())
    print("=" * 64)
    print("WSTG COVERAGE SUMMARY")
    print("=" * 64)
    print(f"Tests considered (done + n/a): {done}/{total} "
          f"({done * 100 // total}%)\n")

    hdr = f"{'Category':<34}{'done':>5}{'prog':>6}{'n/a':>5}{'todo':>6}"
    print(hdr)
    print("-" * len(hdr))
    for cat in sorted(by_cat):
        c = by_cat[cat]
        print(f"{cat:<34}{c['done']:>5}{c['in-progress']:>6}"
              f"{c['n/a']:>5}{c['not-started']:>6}")

    print("\n" + "=" * 64)
    print(f"CONFIRMED FINDINGS: {len(findings)}")
    print("=" * 64)
    if findings:
        sev = Counter((f.get("severity") or "unrated").strip().lower()
                      for f in findings)
        for s in SEV_ORDER:
            if sev.get(s):
                print(f"  {s:<10}{sev[s]}")
        for s in sorted(k for k in sev if k not in SEV_ORDER):
            print(f"  {s:<10}{sev[s]}")
        print()
        for f in findings:
            s = (f.get("severity") or "unrated").strip()
            print(f"  [{s:<8}] {f['id']}  {f.get('name','')}")
    else:
        print("  none recorded")

    print("\n" + "=" * 64)
    print(f"NOT STARTED: {len(not_started)}")
    print("=" * 64)
    for r in not_started:
        print(f"  {r['id']}  {r.get('name','')}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
