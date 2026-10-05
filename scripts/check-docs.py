"""Check local documentation links and TOML examples without external requests."""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors = []
for doc in [ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md",
            ROOT / "CODE_OF_CONDUCT.md", *sorted((ROOT / "docs").glob("*.md"))]:
    for match in re.finditer(r"\[[^\]]+\]\(([^\s)]+)(?:\s+[^)]*)?\)", doc.read_text()):
        target = match.group(1).split("#", 1)[0]
        if not target or re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):
            continue
        if not (doc.parent / target).exists():
            errors.append(f"{doc.relative_to(ROOT)}: missing link {target}")
for example in (ROOT / "deploy").glob("*.toml"):
    try:
        with example.open("rb") as f:
            config = tomllib.load(f)
        for key in ("db_path", "admin_token_file", "default_rx_bps", "default_tx_bps", "quota_budget_bytes"):
            if key not in config:
                errors.append(f"{example.name}: missing production guard input {key}")
    except tomllib.TOMLDecodeError as e:
        errors.append(f"{example.name}: {e}")
if errors:
    raise SystemExit("\n".join(errors))
print("Documentation links and configuration examples OK.")
