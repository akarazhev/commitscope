import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sec_review.core import ReviewError
from sec_review.resources import load_resource_manifest, validate_resource_root


RESOURCE_FILES = (
    "config/tools.lock.json",
    "config/hunter.schema.json",
    "prompts/hunter.md",
    "examples/vulnerable/app.py",
    "tests/test_demo_app.py",
    "config/claude-settings.json",
    "config/claude.version",
    "config/empty-mcp.json",
    "config/sdist-manifest.json",
)


def write_resource_root(root: Path) -> Path:
    for relative in RESOURCE_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"resource: {relative}\n")
    resources = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in RESOURCE_FILES
    ]
    manifest = root / "config/resource-manifest.json"
    manifest.write_text(json.dumps({"schema_version": "1.0", "resources": resources}))
    return root


class ResourceManifestTests(unittest.TestCase):
    def test_complete_resource_root_is_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_resource_root(Path(directory).resolve())

            self.assertEqual(validate_resource_root(root), root)
            self.assertEqual(set(load_resource_manifest(root)), set(RESOURCE_FILES))

    def test_incomplete_resource_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_resource_root(Path(directory).resolve())
            (root / "prompts/hunter.md").unlink()

            with self.assertRaises(ReviewError):
                validate_resource_root(root)

    def test_symlinked_resource_in_every_category_is_rejected(self):
        categories = {
            "config": "config/tools.lock.json",
            "schema": "config/hunter.schema.json",
            "prompt": "prompts/hunter.md",
            "fixture": "examples/vulnerable/app.py",
            "fixture test": "tests/test_demo_app.py",
            "Claude settings": "config/claude-settings.json",
            "Claude version": "config/claude.version",
            "Claude MCP": "config/empty-mcp.json",
        }
        for category, relative in categories.items():
            with self.subTest(category=category), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root = write_resource_root(base / "root")
                target = root / relative
                outside = base / "outside"
                outside.write_bytes(target.read_bytes())
                target.unlink()
                target.symlink_to(outside)

                with self.assertRaises(ReviewError):
                    validate_resource_root(root)

    def test_undeclared_resource_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_resource_root(Path(directory).resolve())
            (root / "config/undeclared.json").write_text("{}\n")

            with self.assertRaises(ReviewError):
                validate_resource_root(root)

    def test_undeclared_dangling_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_resource_root(Path(directory).resolve())
            (root / "prompts/dangling.md").symlink_to(root / "missing.md")

            with self.assertRaises(ReviewError):
                validate_resource_root(root)

    def test_undeclared_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = write_resource_root(base / "root")
            outside = base / "outside-directory"
            outside.mkdir()
            (root / "examples/linked-directory").symlink_to(outside, target_is_directory=True)

            with self.assertRaises(ReviewError):
                validate_resource_root(root)

    def test_corrupt_declared_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_resource_root(Path(directory).resolve())
            (root / "config/tools.lock.json").write_text("changed\n")

            with self.assertRaises(ReviewError):
                validate_resource_root(root)

    def test_cache_directories_and_bytecode_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_resource_root(Path(directory).resolve())
            cache = root / "config/__pycache__"
            cache.mkdir()
            (cache / "ignored.txt").write_text("ignored\n")
            (root / "config/ignored.pyc").write_bytes(b"ignored")

            self.assertEqual(validate_resource_root(root), root)

    def test_symlinked_cache_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = write_resource_root(base / "root")
            outside = base / "outside-cache"
            outside.mkdir()
            (root / "config/__pycache__").symlink_to(outside, target_is_directory=True)

            with self.assertRaises(ReviewError):
                validate_resource_root(root)

    def test_dangling_bytecode_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write_resource_root(Path(directory).resolve())
            (root / "config/ignored.pyc").symlink_to(root / "missing.pyc")

            with self.assertRaises(ReviewError):
                validate_resource_root(root)

    def test_loader_rejects_unknown_keys_duplicate_paths_and_unsafe_paths(self):
        invalid_manifests = (
            {
                "schema_version": "1.0",
                "resources": [],
                "unexpected": True,
            },
            {
                "schema_version": "1.0",
                "resources": [
                    {"path": "config/a", "sha256": "0" * 64},
                    {"path": "config/a", "sha256": "0" * 64},
                ],
            },
            {
                "schema_version": "1.0",
                "resources": [{"path": "../outside", "sha256": "0" * 64}],
            },
        )
        for value in invalid_manifests:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                manifest = root / "config/resource-manifest.json"
                manifest.parent.mkdir()
                manifest.write_text(json.dumps(value))

                with self.assertRaises(ReviewError):
                    load_resource_manifest(root)


if __name__ == "__main__":
    unittest.main()
