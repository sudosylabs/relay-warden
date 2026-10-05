"""Release contracts shared by local packaging and GitHub Actions (Python 3.11+)."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path, PurePosixPath

TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")
SEMVER = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
REQUIRED = {"relay-warden", "warden.example.toml", "relay-warden.service",
            "caddy.example", "nginx.example", "INSTALL.md", "LICENSE-APACHE",
            "THIRD_PARTY_NOTICES.md", "DEPENDENCY_LICENSES.txt", "BUILD.json",
            "licenses/upstream/iroh-LICENSE-MIT", "licenses/upstream/iroh-LICENSE-APACHE",
            "licenses/upstream/iroh-relay-LICENSE-BSD3", "docs/OPERATIONS.md",
            "docs/CONFIGURATION.md", "docs/API.md", "docs/INSTALL.md"}


def metadata(tag=None):
    with open("Cargo.toml", "rb") as f:
        version = tomllib.load(f)["package"]["version"]
    if not re.fullmatch(SEMVER, version):
        raise ValueError(f"unsupported version: {version}")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"tag {tag} must match v{version}")
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    return {"version": version, "sha": sha, "prerelease": str("-" in version).lower()}


def inspect(archive, version=None, target=None, sha=None):
    """Reject unsafe archives and incomplete packages without extracting them."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        names = [m.name.rstrip("/") for m in members]
        if len(names) != len(set(names)):
            raise ValueError("duplicate archive entries")
        roots = set()
        files = {}
        for m in members:
            path = PurePosixPath(m.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError(f"unsafe archive path: {m.name}")
            if not (m.isfile() or m.isdir()):
                raise ValueError(f"links/special files not allowed: {m.name}")
            roots.add(path.parts[0])
            if m.isfile():
                files["/".join(path.parts[1:])] = m
        if len(roots) != 1 or files.keys() != REQUIRED:
            raise ValueError(f"archive content mismatch, missing: {sorted(REQUIRED - files.keys())}, unexpected: {sorted(files.keys() - REQUIRED)}")
        if not files["relay-warden"].mode & 0o111:
            raise ValueError("server is not executable")
        info = json.load(tar.extractfile(files["BUILD.json"]))
        for key, value in (("version", version), ("target", target), ("commit", sha)):
            if value is not None and info.get(key) != value:
                raise ValueError(f"archive {key} mismatch: {info.get(key)} != {value}")
        root = next(iter(roots))
        expected = f"relay-warden-v{info['version']}-{info['target']}"
        if root != expected or Path(archive).name != expected + ".tar.gz":
            raise ValueError("archive name/root disagrees with build metadata")
        if not re.fullmatch(SEMVER, info["version"]):
            raise ValueError("invalid package version")
        return info


def digest(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def collect(source, destination, version, sha):
    source, destination = Path(source), Path(destination)
    expected_dirs = {f"package-{t}" for t in TARGETS}
    if {p.name for p in source.iterdir()} != expected_dirs:
        raise ValueError("expected exactly two named target artifacts")
    assets = []
    for target in TARGETS:
        folder = source / f"package-{target}"
        name = f"relay-warden-v{version}-{target}.tar.gz"
        if {p.name for p in folder.iterdir()} != {name, "SHA256SUMS"}:
            raise ValueError(f"unexpected files in {folder}")
        archive = folder / name
        check = f"{digest(archive)}  {name}\n"
        if (folder / "SHA256SUMS").read_text() != check:
            raise ValueError(f"checksum mismatch: {name}")
        info = inspect(archive, version, target, sha)
        if info.get('dirty') is not False:
            raise ValueError('release artifacts must come from a clean source checkout')
        assets.append((archive, check))
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("asset destination must be empty")
    for archive, _ in assets:
        shutil.copyfile(archive, destination / archive.name)
    (destination / "SHA256SUMS").write_text("".join(check for _, check in assets))


def publish(folder, version, sha):
    """Stage only a draft. Refuse published releases and different-source drafts."""
    folder = Path(folder)
    names = [f"relay-warden-v{version}-{t}.tar.gz" for t in TARGETS]
    if {p.name for p in folder.iterdir()} != set(names + ["SHA256SUMS"]):
        raise ValueError("unexpected publication assets")
    for target, name in zip(TARGETS, names):
        info = inspect(folder / name, version, target, sha)
        if info.get('dirty') is not False:
            raise ValueError('cannot publish an uncommitted-source artifact')
    checks = "".join(f"{digest(folder / name)}  {name}\n" for name in names)
    if (folder / "SHA256SUMS").read_text() != checks:
        raise ValueError("publication checksum mismatch")
    tag = f"v{version}"
    marker = f"Source commit: {sha}"
    # A failed view is not assumed to mean 'not found': list errors fail closed.
    releases = json.loads(subprocess.check_output(
        ["gh", "release", "list", "--limit", "1000", "--json", "tagName"], text=True))
    if any(r["tagName"] == tag for r in releases):
        existing = json.loads(subprocess.check_output(
            ["gh", "release", "view", tag, "--json", "isDraft,body"], text=True))
        if not existing["isDraft"] or marker not in existing["body"].splitlines():
            raise ValueError("release already published or draft belongs to a different source")
    else:
        args = ["gh", "release", "create", tag, "--verify-tag", "--draft",
                "--title", tag, "--notes", f"{marker}\n\nDraft: add release notes and review both Linux archives before publishing."]
        if "-" in version:
            args.append("--prerelease")
        subprocess.run(args, check=True)
    subprocess.run(["gh", "release", "upload", tag,
                    *(str(folder / n) for n in names + ["SHA256SUMS"]), "--clobber"], check=True)
    # Confirm all uploads, including retries, before telling the maintainer it's ready.
    assets = json.loads(subprocess.check_output(
        ["gh", "release", "view", tag, "--json", "assets"], text=True))["assets"]
    expected = {n: (folder / n).stat().st_size for n in names + ["SHA256SUMS"]}
    actual = {a["name"]: a["size"] for a in assets}
    if actual != expected:
        raise ValueError("draft assets differ from the verified bundle; review before publishing")
    print(f"Draft {tag} staged; not published.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("metadata").add_argument("--tag")
    for command in ("inspect", "collect", "publish"):
        c = sub.add_parser(command)
        c.add_argument("path", type=Path)
        if command == "collect":
            c.add_argument("destination", type=Path)
        for name in ("version", "sha"):
            c.add_argument(f"--{name}", required=command != "inspect")
        if command == "inspect":
            c.add_argument("--target")
    args = p.parse_args()
    if args.command == "metadata":
        for k, v in metadata(args.tag).items():
            print(f"{k}={v}")
    elif args.command == "inspect":
        inspect(args.path, args.version, args.target, args.sha)
    elif args.command == "collect":
        collect(args.path, args.destination, args.version, args.sha)
    else:
        publish(args.path, args.version, args.sha)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as e:
        raise SystemExit(str(e)) from e
