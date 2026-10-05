#!/usr/bin/env bash
# Package a tested release archive from a prebuilt binary directory.
#
# Usage: scripts/package.sh <version> <target> <bindir> <outdir>
#   version: validated SemVer without leading v (e.g. 0.1.0)
#   target:  Rust target triple (e.g. x86_64-unknown-linux-gnu)
#   bindir:  directory containing the `relay-warden` executable to package
#   outdir:  where the archive, manifest and checksums are written
#
# Verifies the binary reports the expected version, stages executable +
# config/systemd/proxy examples + licences + build metadata, and checksums
# the final bytes. Pure staging logic: safe to run anywhere for drills.
set -euo pipefail
VERSION="$1"; TARGET="$2"; BINDIR="$3"; OUTDIR="$4"
cd "$(dirname "$0")/.."

BIN="$BINDIR/relay-warden"
test -x "$BIN" || { echo "missing executable: $BIN" >&2; exit 1; }
REPORTED="$("$BIN" --version | awk '{print $2}')"
test "$REPORTED" = "$VERSION" || { echo "binary reports $REPORTED, expected $VERSION" >&2; exit 1; }

NAME="relay-warden-v${VERSION}-${TARGET}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME"
install -m 0755 "$BIN" "$STAGE/$NAME/relay-warden"
cp LICENSE-APACHE THIRD_PARTY_NOTICES.md "$STAGE/$NAME/"
mkdir -p "$STAGE/$NAME/licenses/upstream"
cp licenses/upstream/* "$STAGE/$NAME/licenses/upstream/"
cp deploy/config.production.example.toml "$STAGE/$NAME/warden.example.toml"
cp deploy/relay-warden.service deploy/caddy.example deploy/nginx.example "$STAGE/$NAME/"
cat > "$STAGE/$NAME/INSTALL.md" <<EOF
# relay-warden $VERSION ($TARGET)
See docs/OPERATIONS.md in the source tree for full instructions.
Quick start: create admin secret, copy warden.example.toml, run the binary,
open the admin interface through an SSH tunnel, approve endpoints.
EOF
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
cat > "$STAGE/$NAME/BUILD.txt" <<EOF
version=$VERSION
target=$TARGET
commit=$COMMIT
rust=$(rustc --version 2>/dev/null || echo unknown)
EOF

mkdir -p "$OUTDIR"
tar -C "$STAGE" -czf "$OUTDIR/$NAME.tar.gz" "$NAME"
(cd "$OUTDIR" && sha256sum "$NAME.tar.gz" > SHA256SUMS)
echo "packaged $OUTDIR/$NAME.tar.gz"
