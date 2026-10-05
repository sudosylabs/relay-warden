#!/usr/bin/env bash
# Generate THIRD_PARTY_NOTICES.md from the locked dependency tree.
# Review the output before release: a scanner lists declared licences, it
# does not replace reading the exceptions documented at the top of the file.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="THIRD_PARTY_NOTICES.md"
TOOL="cargo metadata $(cargo --version | head -n1)"

cargo metadata --locked --format-version 1 > /dev/null # fail fast offline-safe

python3 - "$OUT" <<'EOF'
import json, subprocess, sys
out = sys.argv[1]
meta = json.loads(subprocess.run(
    ["cargo", "metadata", "--locked", "--format-version", "1"],
    check=True, capture_output=True, text=True).stdout)
rows = []
members = set(meta.get("workspace_members", []))
for pkg in meta["packages"]:
    if pkg["id"] in members:
        continue
    lic = pkg.get("license") or "unspecified"
    repo = pkg.get("repository") or ""
    rows.append((pkg["name"], pkg["version"], lic, repo))
rows.sort()
with open(out, "w") as f:
    f.write("# Third-party notices\n\n")
    f.write("Relay Warden's original code is Apache-2.0 (Sudosy Labs contributors),\n")
    f.write("see `LICENSE-APACHE`. This file lists linked third-party crates from\n")
    f.write("`Cargo.lock` plus additional notices that a manifest scan cannot see.\n\n")
    f.write("## Additional notices (reviewed, not scanner-generated)\n\n")
    f.write("- `iroh-relay` (n0-computer/iroh v1.3.0, MIT OR Apache-2.0): portions of\n")
    f.write("  the relay protocol derive from Tailscale code under BSD-3-Clause;\n")
    f.write("  see `licenses/upstream/iroh-relay-LICENSE-BSD3`. Upstream copyright\n")
    f.write("  (N0, INC.) notices are preserved in `licenses/upstream/`.\n")
    f.write("- `src/relay.rs` adapts the Axum embedding pattern from upstream's\n")
    f.write("  `iroh-relay/tests/relay_axum.rs` (same MIT OR Apache-2.0 + BSD-3\n")
    f.write("  terms as above); original Sudosy Labs code surrounds the pattern.\n\n")
    f.write("## Locked dependency licences\n\n")
    f.write("Regenerate with `scripts/gen-notices.sh` after any dependency change\n")
    f.write("and review diffs before release.\n\n")
    f.write("Review the table below before every release: every entry must name\n")
    f.write("a permissive licence, none may read `unspecified`, and any new\n")
    f.write("additional-terms case (like the Tailscale BSD-3 portion inside\n")
    f.write("`iroh-relay`) must be vendored under `licenses/` like the above.\n")
    f.write(f"({len(rows)} third-party crates at generation time.)\n\n")
    f.write("| crate | version | licence (declared) | repository |\n")
    f.write("|---|---|---|---|\n")
    for name, version, lic, repo in rows:
        f.write(f"| {name} | {version} | {lic} | {repo} |\n")
print(f"wrote {out} ({len(rows)} crates)")
EOF
