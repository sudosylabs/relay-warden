"""Bundle original licence/notice texts from the locked target dependency sources.

This deliberately includes normal/build/dev dependencies in the resolved target
graph: extra notices are safer than claiming this is an exact linker inventory.
Review the bundle when changing dependencies; a file scan is not a legal audit.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def license_files(package):
    root = Path(package["manifest_path"]).parent
    paths = set()
    if package.get("license_file"):
        paths.add(root / package["license_file"])
    # Include nested vendored crypto and Unicode licences, not only root texts.
    for path in root.rglob("*"):
        if path.is_file() and re.match(r"^(licen[cs]e|copying|copyright|notice|unlicense)([._-]|$)", path.name, re.I):
            paths.add(path)
    return sorted(paths)


def generate(target, output):
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target], text=True))
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    pending = list(meta["workspace_members"])
    reachable = set()
    while pending:
        ident = pending.pop()
        if ident in reachable:
            continue
        reachable.add(ident)
        pending.extend(d["pkg"] for d in nodes[ident]["deps"])
    packages = sorted((p for p in meta["packages"] if p["id"] in reachable
                       and p["id"] not in meta["workspace_members"]),
                      key=lambda p: (p["name"], p["version"]))
    sections = [f"Dependency licence texts — locked target graph: {target}\n"
                "Includes build/test dependencies, upstream texts and versioned exceptions.\n"]
    overrides = json.loads((ROOT / "licenses/dependency-overrides.json").read_text())
    for package in packages:
        if not package.get("license") and not package.get("license_file"):
            raise ValueError(f"unspecified licence: {package['name']}")
        root = Path(package["manifest_path"]).parent
        sections.append(f"\n{'=' * 72}\n{package['name']} {package['version']}\n"
                        f"Declared licence: {package.get('license', 'see licence file')}\n"
                        f"Source: {package.get('repository') or package.get('source')}\n")
        files = license_files(package)
        override = overrides.get(f"{package['name']}@{package['version']}")
        if not files:
            if not override:
                raise ValueError(f"no licence texts/override: {package['name']} {package['version']}")
            vcs = json.loads((root / ".cargo_vcs_info.json").read_text())
            if vcs['git']['sha1'] != override['source_commit']:
                raise ValueError(f"override source changed: {package['name']}")
            text = (ROOT / override['file']).read_text(encoding='utf-8')
            sections.append(f"Selected licence: {override['selection']}\n"
                            f"Text source: {override['source']}\n"
                            f"{override.get('note', '')}\n\n{text}\n")
        for path in files:
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"licence path outside package: {path.name}")
            sections.append(f"\n--- {path.relative_to(root)} ---\n{path.read_text(encoding='utf-8')}\n")
    Path(output).write_text("".join(sections), encoding="utf-8")
    print(f"Bundled licence texts for {len(packages)} dependencies ({target}).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    generate(args.target, args.output)
