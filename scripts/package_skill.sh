#!/usr/bin/env bash
# Package the skill's essential, distributable files into a zip for upload
# (claude.ai Settings > Capabilities > Skills, or the /v1/skills API).
#
# Usage: scripts/package_skill.sh [output.zip]
# Default output: dist/owasp-web-security-testing.zip

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${1:-dist/owasp-web-security-testing.zip}"
mkdir -p "$(dirname "$OUT")"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"

FILES=(
  SKILL.md
  references
  resources/wstg-checklist.csv
  resources/report-template.md
  scripts/coverage_report.py
  LICENSE
  LICENSE-DOCS
  NOTICE
)

for f in "${FILES[@]}"; do
  if [ ! -e "$f" ]; then
    echo "error: missing expected file: $f" >&2
    exit 1
  fi
done

rm -f "$OUT"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/scripts" "$STAGE/resources"
cp SKILL.md LICENSE LICENSE-DOCS NOTICE "$STAGE/"
cp -R references "$STAGE/"
cp resources/wstg-checklist.csv resources/report-template.md "$STAGE/resources/"
cp scripts/coverage_report.py "$STAGE/scripts/"

(cd "$STAGE" && zip -rq "$OUT" .)

echo "Packaged: $OUT"
unzip -l "$OUT"
