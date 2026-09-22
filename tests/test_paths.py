import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sec_review.core import ReviewError
from sec_review.paths import select_resource_root, select_tools_root, runs_root


class RuntimePathTests(unittest.TestCase):
    def resources(self, root: Path) -> Path:
        for relative in (
            'config/tools.lock.json', 'config/semgrep.yaml',
            'config/gitleaks.toml', 'config/trivy.yaml',
            'prompts/hunter.md', 'prompts/verifier.md',
            'examples/vulnerable/app.py', 'examples/fixed/app.py',
            'tests/test_demo_app.py',
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}' if path.suffix == '.json' else 'fixture')
        return root

    def test_source_resources_win_over_installed_share(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            source = self.resources(base / 'source')
            installed = self.resources(base / 'data/share/commitscope')
            self.assertEqual(select_resource_root(source, base / 'data'), source)
            self.assertNotEqual(source, installed)

    def test_incomplete_installed_resources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory).resolve()
            (data / 'share/commitscope/config').mkdir(parents=True)
            with self.assertRaises(ReviewError):
                select_resource_root(None, data)

    def test_symlinked_installed_resources_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real = self.resources(base / 'real')
            share = base / 'data/share'
            share.mkdir(parents=True)
            (share / 'commitscope').symlink_to(real, target_is_directory=True)
            with self.assertRaises(ReviewError):
                select_resource_root(None, base / 'data')

    def test_absolute_home_override_owns_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve() / 'cs-home'
            root = select_tools_root(None, {'COMMITSCOPE_HOME': str(home)}, 'Linux', Path('/home/test'))
            self.assertEqual(root, home / 'tools')

    def test_relative_and_empty_home_overrides_are_rejected(self):
        for value in ('', 'relative/path'):
            with self.subTest(value=value), self.assertRaises(ReviewError):
                select_tools_root(None, {'COMMITSCOPE_HOME': value}, 'Linux', Path('/home/test'))

    def test_symlinked_home_override_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            real = base / 'real'
            real.mkdir()
            alias = base / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ReviewError):
                select_tools_root(None, {'COMMITSCOPE_HOME': str(alias)}, 'Linux', base)

    def test_platform_cache_defaults_and_source_compatibility(self):
        self.assertEqual(select_tools_root(Path('/src'), {}, 'Linux', Path('/home/u')), Path('/src/.tools'))
        self.assertEqual(select_tools_root(None, {'XDG_CACHE_HOME': '/cache'}, 'Linux', Path('/home/u')), Path('/cache/commitscope/tools'))
        self.assertEqual(select_tools_root(None, {}, 'Darwin', Path('/Users/u')), Path('/Users/u/Library/Caches/CommitScope/tools'))

    def test_runs_are_relative_to_operator_working_directory(self):
        self.assertEqual(runs_root(Path('/work')), Path('/work/.runs'))
