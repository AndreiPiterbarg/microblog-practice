#!/usr/bin/env bash
# Run pip-audit, skipping every advisory marked "# pip-audit: <IDs> not exploitable"
# in requirements.txt. The comments are the single source of truth.
set -euo pipefail
cd "$(dirname "$0")/.."

ids=$(grep -oE '# pip-audit:.*' requirements.txt \
    | grep -oE '((PYSEC|GHSA|CVE)-[A-Za-z0-9-]+[, ]+)+not exploitable' \
    | grep -oE '(PYSEC|GHSA|CVE)-[A-Za-z0-9-]+' | sort -u || true)

args=()
for id in $ids; do
    args+=(--ignore-vuln "$id")
done

exec uvx --python 3.11 pip-audit -r requirements.txt "${args[@]}" "$@"
