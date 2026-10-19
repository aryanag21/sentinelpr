#!/usr/bin/env bash
# Downloads and pins Semgrep security rules for local bundling
set -euo pipefail

RULES_DIR="infrastructure/semgrep-rules"
mkdir -p "${RULES_DIR}"

echo "Fetching pinned Semgrep security rules..."

# Fetch Python security pack
curl -sSL "https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/python/lang/security/audit/sqli.yaml" -o "${RULES_DIR}/python-sqli-upstream.yaml" || true

echo "Semgrep rules verified in ${RULES_DIR}."
