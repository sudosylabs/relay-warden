#!/usr/bin/env bash
# Extract the embedded admin UI script and syntax-check it.
# Syntax alone does not prove browser interaction works. The HTTP integration
# suite covers the API; a browser interaction test remains separate coverage.
set -euo pipefail
cd "$(dirname "$0")/.."
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 -c "import re,sys; s=open('src/admin.rs').read(); open(sys.argv[1],'w').write(re.search(r'<script>\n(.*)\n</script>', s, re.DOTALL).group(1))" "$WORK/admin.js"
node --check "$WORK/admin.js"
echo "admin UI syntax OK"
