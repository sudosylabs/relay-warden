import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('licenses', ROOT / 'scripts/dependency-licenses.py')
licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licenses)


class LicenseTests(unittest.TestCase):
    def test_unknown_missing_texts_fail_instead_of_creating_empty_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'licenses').mkdir()
            (root / 'licenses/dependency-overrides.json').write_text('{}')
            (root / 'dep').mkdir()
            package = dict(id='dep', name='new-dependency', version='1.0.0',
                           license='MIT', manifest_path=str(root / 'dep/Cargo.toml'))
            meta = dict(workspace_members=['app'], packages=[package],
                        resolve=dict(nodes=[dict(id='app', deps=[dict(pkg='dep')]),
                                            dict(id='dep', deps=[])]))
            with patch.object(licenses, 'ROOT', root), \
                    patch.object(licenses.subprocess, 'check_output', return_value=json.dumps(meta)):
                with self.assertRaisesRegex(ValueError, 'no licence texts/override'):
                    licenses.generate('x86_64-unknown-linux-gnu', root / 'bundle.txt')
            self.assertFalse((root / 'bundle.txt').exists())

    def test_collects_nested_notices_and_unlicense(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.toml').touch()
            (root / 'LICENSE-MIT').write_text('root copyright')
            (root / 'vendored').mkdir()
            (root / 'vendored/NOTICE').write_text('nested attribution')
            (root / 'UNLICENSE').write_text('public domain dedication')
            (root / 'unrelated.rs').write_text('not a licence')
            files = licenses.license_files(dict(manifest_path=str(root / 'Cargo.toml')))
            self.assertEqual({p.relative_to(root).as_posix() for p in files},
                             {'LICENSE-MIT', 'UNLICENSE', 'vendored/NOTICE'})

    def test_versioned_overrides_have_actual_texts_and_immutable_sources(self):
        overrides = json.loads((ROOT / 'licenses/dependency-overrides.json').read_text())
        for package, override in overrides.items():
            with self.subTest(package=package):
                self.assertIn('@', package)
                self.assertEqual(len(override['source_commit']), 40)
                self.assertIn(override['source_commit'], override['source'])
                self.assertIn(override['selection'], {'MIT', 'Apache-2.0'})
                text = (ROOT / override['file']).read_text()
                self.assertTrue('Permission is hereby granted' in text or 'Apache License' in text)


if __name__ == '__main__':
    unittest.main()
