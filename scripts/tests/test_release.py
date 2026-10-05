import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release", ROOT / "scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sha = "a" * 40
        self.version = "0.1.0"

    def archive(self, folder, target, missing=None, unsafe=False, executable=True, dirty=False):
        folder.mkdir(parents=True, exist_ok=True)
        name = f"relay-warden-v{self.version}-{target}"
        archive = folder / f"{name}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for path in sorted(release.REQUIRED - {missing}):
                data = b"example"
                if path == "BUILD.json":
                    data = json.dumps(dict(version=self.version, target=target, commit=self.sha, dirty=dirty)).encode()
                member = tarfile.TarInfo(f"{name}/{path}")
                member.size = len(data)
                member.mode = 0o755 if path == "relay-warden" and executable else 0o644
                tar.addfile(member, io.BytesIO(data))
            if unsafe:
                member = tarfile.TarInfo("../outside")
                tar.addfile(member, io.BytesIO(b""))
        (folder / "SHA256SUMS").write_text(f"{release.digest(archive)}  {archive.name}\n")
        return archive

    def bundle(self):
        source = self.root / "artifacts"
        for target in release.TARGETS:
            self.archive(source / f"package-{target}", target)
        dest = self.root / "dist"
        release.collect(source, dest, self.version, self.sha)
        return source, dest

    def test_metadata_tag_matches_and_prerelease(self):
        with patch.object(release.subprocess, "check_output", return_value=self.sha + "\n"):
            self.assertEqual(release.metadata("v0.1.0"),
                             dict(version="0.1.0", sha=self.sha, prerelease="false"))
            with self.assertRaises(ValueError):
                release.metadata("v0.2.0")
            with patch.object(release.tomllib, 'load', return_value={'package': {'version': '0.1.0-rc.1'}}):
                self.assertEqual(release.metadata('v0.1.0-rc.1')['prerelease'], 'true')

    def test_package_requires_every_file_and_executable(self):
        target = release.TARGETS[0]
        good = self.archive(self.root / "good", target)
        self.assertEqual(release.inspect(good, self.version, target, self.sha)["commit"], self.sha)
        for missing in release.REQUIRED:
            with self.subTest(missing=missing):
                bad = self.archive(self.root / "bad", target, missing=missing)
                with self.assertRaises(ValueError):
                    release.inspect(bad)
        bad = self.archive(self.root / "bad", target, executable=False)
        with self.assertRaisesRegex(ValueError, "executable"):
            release.inspect(bad)

    def test_rejects_traversal_and_wrong_commit(self):
        bad = self.archive(self.root / "bad", release.TARGETS[0], unsafe=True)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            release.inspect(bad)
        good = self.archive(self.root / "good", release.TARGETS[0])
        with self.assertRaisesRegex(ValueError, "commit mismatch"):
            release.inspect(good, sha="b" * 40)

    def test_collect_checks_both_targets_and_manifest(self):
        source, dest = self.bundle()
        names = [f"relay-warden-v0.1.0-{t}.tar.gz" for t in release.TARGETS]
        self.assertEqual({p.name for p in dest.iterdir()}, set(names + ["SHA256SUMS"]))
        self.assertEqual((dest / "SHA256SUMS").read_text(),
                         "".join(f"{release.digest(dest / n)}  {n}\n" for n in names))
        (source / f"package-{release.TARGETS[1]}" / "SHA256SUMS").write_text("bad checksum")
        with self.assertRaisesRegex(ValueError, "checksum"):
            release.collect(source, self.root / "rejected", self.version, self.sha)
        self.assertFalse((self.root / "rejected").exists())

    def test_uncommitted_source_is_rejected_even_with_valid_checksums(self):
        source = self.root / 'artifacts'
        for target in release.TARGETS:
            self.archive(source / f'package-{target}', target, dirty=True)
        with self.assertRaisesRegex(ValueError, 'clean source'):
            release.collect(source, self.root / 'dist', self.version, self.sha)
        self.assertFalse((self.root / 'dist').exists())

    def test_published_or_different_source_release_is_untouched(self):
        _, dest = self.bundle()
        for existing in (dict(isDraft=False, body=f"Source commit: {self.sha}"),
                         dict(isDraft=True, body="Source commit: different")):
            with patch.object(release.subprocess, "check_output", side_effect=[
                    '[{"tagName":"v0.1.0"}]', json.dumps(existing)]), \
                    patch.object(release.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    release.publish(dest, self.version, self.sha)
                run.assert_not_called()

    def test_new_draft_uploads_exact_assets_with_unsplit_notes(self):
        _, dest = self.bundle()
        assets = dict(assets=[dict(name=p.name, size=p.stat().st_size) for p in dest.iterdir()])
        with patch.object(release.subprocess, "check_output", side_effect=['[]', json.dumps(assets)]), \
                patch.object(release.subprocess, "run") as run:
            release.publish(dest, self.version, self.sha)
        create, upload = [call.args[0] for call in run.call_args_list]
        self.assertEqual(create[:4], ['gh', 'release', 'create', 'v0.1.0'])
        self.assertIn('--verify-tag', create)
        self.assertIn('--draft', create)
        self.assertTrue(create[create.index('--notes') + 1].startswith(f"Source commit: {self.sha}\n"))
        self.assertEqual(upload, ['gh', 'release', 'upload', 'v0.1.0',
                         *(str(dest / f'relay-warden-v0.1.0-{t}.tar.gz') for t in release.TARGETS),
                         str(dest / 'SHA256SUMS'), '--clobber'])

    def test_same_source_draft_resumes_without_creating_release(self):
        _, dest = self.bundle()
        assets = dict(assets=[dict(name=p.name, size=p.stat().st_size) for p in dest.iterdir()])
        with patch.object(release.subprocess, "check_output", side_effect=[
                '[{"tagName":"v0.1.0"}]',
                json.dumps(dict(isDraft=True, body=f"Source commit: {self.sha}")),
                json.dumps(assets)]), patch.object(release.subprocess, "run") as run:
            release.publish(dest, self.version, self.sha)
        self.assertEqual(len(run.call_args_list), 1)
        self.assertEqual(run.call_args.args[0][:3], ['gh', 'release', 'upload'])

    def test_smoke_prestart_failure_does_not_signal_process_group(self):
        result = subprocess.run(['bash', str(ROOT / 'scripts/smoke.sh'),
                                 str(self.root / 'missing.tar.gz'), '/missing-client'],
                                capture_output=True, text=True, start_new_session=True, timeout=10)
        self.assertGreater(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
