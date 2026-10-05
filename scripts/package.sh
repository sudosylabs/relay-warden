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
test "$("$BIN" --version)" = "relay-warden $VERSION" || { echo "binary/version mismatch" >&2; exit 1; }
HOST="$(rustc -vV | sed -n 's/host: //p')"
test "$TARGET" = "$HOST" || { echo "native packaging only: $TARGET != $HOST" >&2; exit 1; }

NAME="relay-warden-v${VERSION}-${TARGET}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME"
install -m 0755 "$BIN" "$STAGE/$NAME/relay-warden"
cp LICENSE-APACHE THIRD_PARTY_NOTICES.md "$STAGE/$NAME/"
python3 scripts/dependency-licenses.py --target "$TARGET" --output "$STAGE/$NAME/DEPENDENCY_LICENSES.txt"
mkdir -p "$STAGE/$NAME/licenses/upstream"
cp licenses/upstream/* "$STAGE/$NAME/licenses/upstream/"
cp deploy/config.production.example.toml "$STAGE/$NAME/warden.example.toml"
cp deploy/relay-warden.service deploy/caddy.example deploy/nginx.example "$STAGE/$NAME/"
printf '# Installation\n\nFollow [the installation guide](docs/INSTALL.md) included in this archive.\n' > "$STAGE/$NAME/INSTALL.md"
mkdir -p "$STAGE/$NAME/docs"
cp docs/INSTALL.md docs/OPERATIONS.md docs/CONFIGURATION.md docs/API.md "$STAGE/$NAME/docs/"
python3 - "$VERSION" "$TARGET" "$STAGE/$NAME/BUILD.json" <<'PY'
import json, platform, subprocess, sys
version, target, output = sys.argv[1:]
info = dict(version=version, target=target,
            commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()),
            rust=subprocess.check_output(['rustc', '--version'], text=True).strip(),
            system=platform.platform(), libc=platform.libc_ver())
with open(output, 'w') as f:
    json.dump(info, f, indent=2)
    f.write('\n')
PY

mkdir -p "$OUTDIR"
COPYFILE_DISABLE=1 tar -C "$STAGE" -czf "$OUTDIR/$NAME.tar.gz" "$NAME"
python3 - "$OUTDIR" "$NAME.tar.gz" <<'PY'
import hashlib, pathlib, sys
folder, name = pathlib.Path(sys.argv[1]), sys.argv[2]
with open(folder / name, 'rb') as f:
    digest = hashlib.file_digest(f, 'sha256').hexdigest()
(folder / 'SHA256SUMS').write_text(f'{digest}  {name}\n')
PY
python3 scripts/release.py inspect "$OUTDIR/$NAME.tar.gz" --version "$VERSION" --target "$TARGET"
echo "packaged $OUTDIR/$NAME.tar.gz"
