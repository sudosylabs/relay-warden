#!/usr/bin/env bash
# The same checks gate pull requests and each native release build.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/check-ui.sh
python3 -m unittest discover -s scripts/tests -v
python3 scripts/check-docs.py
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
bash scripts/gen-notices.sh "$WORK/THIRD_PARTY_NOTICES.md"
cmp THIRD_PARTY_NOTICES.md "$WORK/THIRD_PARTY_NOTICES.md"
