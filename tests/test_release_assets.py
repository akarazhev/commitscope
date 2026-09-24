"""Contracts for the files handed to the token-bearing PyPI publish job."""

import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_release_assets import compare_build, verify


class ReleaseAssetTests(unittest.TestCase):
    tag = "v2.4.2"
    version = "2.4.2"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.wheel = self.directory / f"commitscope-{self.version}-py3-none-any.whl"
        self.sdist = self.directory / f"commitscope-{self.version}.tar.gz"
        self.sums = self.directory / f"SHA256SUMS-{self.version}.txt"
        self.write_wheel()
        self.write_sdist()
        self.write_sums()

    def metadata(self, version):
        return f"Metadata-Version: 2.1\nName: commitscope\nVersion: {version}\n\n"

    def write_wheel(self, version=None):
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr(
                f"commitscope-{self.version}.dist-info/METADATA",
                self.metadata(version or self.version),
            )

    def write_sdist(self, version=None):
        payload = self.metadata(version or self.version).encode()
        with tarfile.open(self.sdist, "w:gz") as archive:
            member = tarfile.TarInfo(f"commitscope-{self.version}/PKG-INFO")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))

    def write_sums(self):
        self.sums.write_text("".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in (self.wheel, self.sdist)
        ))

    def test_accepts_exact_release_files(self):
        verify(self.directory, self.tag)

    def test_rejects_extra_file(self):
        (self.directory / "notes.txt").write_text("extra")
        with self.assertRaises(ValueError):
            verify(self.directory, self.tag)

    def test_rejects_missing_file(self):
        self.sdist.unlink()
        with self.assertRaises(ValueError):
            verify(self.directory, self.tag)

    def test_rejects_duplicate_checksum_entry(self):
        first = self.sums.read_text().splitlines(keepends=True)[0]
        self.sums.write_text(self.sums.read_text() + first)
        with self.assertRaises(ValueError):
            verify(self.directory, self.tag)

    def test_rejects_wrong_checksum_filename(self):
        self.sums.write_text(self.sums.read_text().replace(self.wheel.name, "other.whl"))
        with self.assertRaises(ValueError):
            verify(self.directory, self.tag)

    def test_rejects_changed_digest(self):
        text = self.sums.read_text()
        self.sums.write_text(("0" if text[0] != "0" else "1") + text[1:])
        with self.assertRaises(ValueError):
            verify(self.directory, self.tag)

    def test_rejects_wrong_wheel_version_even_with_matching_hash(self):
        self.write_wheel("2.4.0")
        self.write_sums()
        with self.assertRaises(ValueError):
            verify(self.directory, self.tag)

    def test_rejects_wrong_sdist_version_even_with_matching_hash(self):
        self.write_sdist("2.4.0")
        self.write_sums()
        with self.assertRaises(ValueError):
            verify(self.directory, self.tag)

    def test_rejects_symlinked_release_asset(self):
        self.sums.unlink()
        self.sums.symlink_to(self.wheel)
        with self.assertRaises(ValueError):
            verify(self.directory, self.tag)

    def test_rejects_non_release_tag(self):
        with self.assertRaises(ValueError):
            verify(self.directory, "v2.4.2-rc1")

    def test_rebuild_comparison_accepts_equivalent_contents_with_different_archives(self):
        rebuilt = self.directory / "rebuilt"
        rebuilt.mkdir()
        with zipfile.ZipFile(rebuilt / self.wheel.name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                f"commitscope-{self.version}.dist-info/METADATA",
                self.metadata(self.version),
            )
        with tarfile.open(rebuilt / self.sdist.name, "w:gz") as archive:
            payload = self.metadata(self.version).encode()
            member = tarfile.TarInfo(f"commitscope-{self.version}/PKG-INFO")
            member.mode = 0o600
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        self.assertNotEqual(self.wheel.read_bytes(), (rebuilt / self.wheel.name).read_bytes())
        self.assertNotEqual(self.sdist.read_bytes(), (rebuilt / self.sdist.name).read_bytes())
        compare_build(self.directory, rebuilt, self.tag)

    def test_rebuild_comparison_rejects_changed_content(self):
        rebuilt = self.directory / "rebuilt"
        rebuilt.mkdir()
        with zipfile.ZipFile(rebuilt / self.wheel.name, "w") as archive:
            archive.writestr(
                f"commitscope-{self.version}.dist-info/METADATA",
                self.metadata(self.version) + "Changed: yes\n",
            )
        (rebuilt / self.sdist.name).write_bytes(self.sdist.read_bytes())
        with self.assertRaisesRegex(ValueError, "different contents"):
            compare_build(self.directory, rebuilt, self.tag)

    def test_rebuild_comparison_rejects_duplicate_members(self):
        rebuilt = self.directory / "rebuilt"
        rebuilt.mkdir()
        (rebuilt / self.wheel.name).write_bytes(self.wheel.read_bytes())
        (rebuilt / self.sdist.name).write_bytes(self.sdist.read_bytes())
        with zipfile.ZipFile(rebuilt / self.wheel.name, "a") as archive:
            archive.writestr(f"commitscope-{self.version}.dist-info/METADATA", "duplicate")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            compare_build(self.directory, rebuilt, self.tag)


class PublishWorkflowTests(unittest.TestCase):
    def test_rebuild_uses_default_archive_epoch(self):
        import sec_review_build

        workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text()
        self.assertIn(f"SOURCE_DATE_EPOCH: '{sec_review_build.TAR_EPOCH}'", workflow)

    def test_pypi_publish_has_separate_read_only_preparation_and_oidc_job(self):
        workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text()
        self.assertIn("types: [published]", workflow)
        self.assertIn("!github.event.release.prerelease", workflow)
        self.assertIn("!github.event.release.draft", workflow)
        self.assertIn("  prepare:\n", workflow)
        self.assertIn("  publish:\n", workflow)
        prepare, publish = workflow.split("  publish:\n", 1)
        self.assertIn("permissions:\n  contents: read", prepare)
        self.assertNotIn("id-token: write", prepare)
        self.assertIn("gh release download", prepare)
        self.assertIn("scripts/verify_release_assets.py", prepare)
        self.assertIn("--compare-dir rebuilt", prepare)
        self.assertIn("needs: prepare", publish)
        self.assertIn("environment: pypi", publish)
        self.assertIn("id-token: write", publish)
        self.assertIn("actions/download-artifact@", publish)
        self.assertIn("pypa/gh-action-pypi-publish@", publish)
        self.assertNotIn("actions/checkout@", publish)
        for forbidden in ("skip-existing", "TWINE_PASSWORD", "PYPI_API_TOKEN",
                          "pull_request_target", "workflow_dispatch"):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
