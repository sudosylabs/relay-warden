#!/usr/bin/env bash
# Syntax-check the admin UI script shipped in the binary.
# Syntax alone does not prove browser interaction works. The HTTP integration
# suite covers the API; a browser interaction test remains separate coverage.
set -euo pipefail
cd "$(dirname "$0")/.."
node --check web/admin.js
node --check web/navigation.mjs
node --test scripts/tests/navigation.test.mjs
echo "admin UI syntax OK"
