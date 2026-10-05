#!/usr/bin/env bash
# Extract the embedded admin UI script and syntax-check it.
# Syntax alone does not prove the UI works; interaction is covered by the
# admin integration suite (tests/admin.rs).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -c "import re; s=open('src/admin.rs').read(); open('/tmp/warden_admin_ui.js','w').write(re.search(r'<script>\n(.*)\n</script>', s, re.DOTALL).group(1))"
node --check /tmp/warden_admin_ui.js
echo "admin UI syntax OK"
