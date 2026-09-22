import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PDF_ROOT = ROOT / "docs/security-review-pdfs"
PDF_NAMES = tuple(
    f"{language}/{name}"
    for language in ("en", "ru")
    for name in (
        f"security-review-methodology-{language}.pdf",
        f"security-review-playbook-{language}-legacy.pdf",
        f"commitscope-user-guide-{language}.pdf",
    )
)
EPOCH = "1790035200"


def run(*args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, **kwargs)


class PdfTests(unittest.TestCase):
    def test_sources_pdfs_and_font_are_exact_distribution_inputs(self):
        manifest = json.loads((ROOT / "config/sdist-manifest.json").read_text())["files"]
        expected = list(PDF_NAMES) + [
            "source/content-en.json", "source/content-ru.json",
            "fonts/NotoSans-Regular.ttf", "fonts/OFL.txt", "fonts/README.md", "README.md",
        ]
        for relative in expected:
            with self.subTest(path=relative):
                path = PDF_ROOT / relative
                self.assertTrue(path.is_file(), relative)
                self.assertIn(path.relative_to(ROOT).as_posix(), manifest)
                if (ROOT / ".git").exists() and shutil.which("git"):
                    result = run("git", "check-ignore", "--no-index", str(path), cwd=ROOT)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("pdfinfo") and shutil.which("pdftotext"), "Poppler required for PDF inspection")
    def test_pdf_metadata_text_and_acceptance_contract(self):
        for relative in PDF_NAMES:
            with self.subTest(pdf=relative):
                path = PDF_ROOT / relative
                self.assertTrue(path.is_file(), relative)
                info = run("pdfinfo", str(path))
                self.assertEqual(info.returncode, 0, info.stderr)
                self.assertRegex(info.stdout, r"Pages:\s+[1-9][0-9]*")
                self.assertRegex(info.stdout, r"Page size:\s+595\.\d+ x 841\.\d+ pts \(A4\)")
                self.assertIn("2.4.0", info.stdout)
                text = run("pdftotext", "-layout", str(path), "-")
                self.assertEqual(text.returncode, 0, text.stderr)
                self.assertNotIn("\ufffd", text.stdout)
                if "user-guide" in relative:
                    for state in ("READY_FOR_HUMAN_REVIEW", "FINDINGS_REQUIRE_TRIAGE", "INCOMPLETE"):
                        self.assertIn(state, text.stdout)
                    self.assertIn("Hunter", text.stdout)
                    self.assertIn("Verifier", text.stdout)
                    if relative.startswith("en/"):
                        self.assertIn("Hunter and Verifier are mandatory", text.stdout)
                        self.assertIn("SCANNERS_VERIFIED_AI_NOT_RUN is not completed corporate acceptance", " ".join(text.stdout.split()))
                    else:
                        self.assertIn("Hunter и Verifier обязательны", text.stdout)
                        self.assertIn("SCANNERS_VERIFIED_AI_NOT_RUN не означает завершенную корпоративную проверку", " ".join(text.stdout.split()))
                    self.assertNotRegex(text.stdout.lower(), r"ai is optional|optional ai|ии необязателен")
                if "legacy" in relative:
                    pages = text.stdout.split("\f")
                    label = "LEGACY STARTER KIT 1.0" if relative.startswith("en/") else "УСТАРЕВШИЙ STARTER KIT 1.0"
                    self.assertIn(label, pages[0])
                    for page in filter(str.strip, pages):
                        self.assertIn(label, page)
                        self.assertIn("2.4.0", page)

    def test_source_editions_match_current_and_legacy_contract(self):
        for language in ("en", "ru"):
            path = PDF_ROOT / f"source/content-{language}.json"
            self.assertTrue(path.is_file())
            source = json.loads(path.read_text())
            self.assertEqual(source["version"], "2.4.0")
            self.assertEqual(source["language"], language)
            self.assertEqual(set(source["documents"]), {"methodology", "user-guide", "playbook"})
            self.assertTrue(source["documents"]["playbook"]["legacy"])

    def test_clean_builds_are_deterministic_and_honor_epoch(self):
        script = ROOT / "scripts/build_pdfs.py"
        self.assertTrue(script.is_file())
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("ReportLab is an optional documentation build dependency")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for destination, epoch in (("a", EPOCH), ("b", EPOCH), ("c", "1790121600")):
                result = run(sys.executable, "-I", str(script), "--output-dir", str(root / destination), env={**os.environ, "SOURCE_DATE_EPOCH": epoch})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for relative in PDF_NAMES:
                a = (root / "a" / relative).read_bytes()
                self.assertEqual(a, (root / "b" / relative).read_bytes())
                self.assertEqual(a, (PDF_ROOT / relative).read_bytes())
                self.assertNotEqual(a, (root / "c" / relative).read_bytes())


class ChecksumTests(unittest.TestCase):
    def test_checked_in_checksums_match_exact_source_manifest(self):
        script = ROOT / "scripts/update_checksums.py"
        self.assertTrue(script.is_file())
        result = run(sys.executable, "-I", str(script), "--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = json.loads((ROOT / "config/sdist-manifest.json").read_text())["files"]
        expected = "".join(f"{hashlib.sha256((ROOT / name).read_bytes()).hexdigest()}  {name}\n" for name in sorted(names) if name != "SHA256SUMS")
        self.assertEqual((ROOT / "SHA256SUMS").read_text(), expected)

    def test_check_is_read_only_and_detects_digest_and_name_changes(self):
        script = ROOT / "scripts/update_checksums.py"
        self.assertTrue(script.is_file())
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(Path(directory))
            self.assertEqual(self.invoke(root).returncode, 0)
            checksums = root / "SHA256SUMS"
            original = checksums.read_bytes()
            (root / "payload.txt").write_text("changed")
            result = self.invoke(root, "--check")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(checksums.read_bytes(), original)
            self.assertEqual(self.invoke(root).returncode, 0)
            valid = checksums.read_text()
            for invalid in (valid + "0" * 64 + "  extra.txt\n", "", valid.upper()):
                checksums.write_text(invalid)
                self.assertNotEqual(self.invoke(root, "--check").returncode, 0)
                self.assertEqual(checksums.read_text(), invalid)

    def test_symlinked_files_parents_and_checksum_destination_are_rejected(self):
        self.assertTrue((ROOT / "scripts/update_checksums.py").is_file())
        for target in ("payload.txt", "config", "SHA256SUMS"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                root = self.fixture(base / "root")
                self.assertEqual(self.invoke(root).returncode, 0)
                original = root / target
                outside = base / "outside"
                original.rename(outside)
                original.symlink_to(outside, target_is_directory=outside.is_dir())
                result = self.invoke(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("symbolic-link", result.stdout + result.stderr)

    def fixture(self, root):
        (root / "scripts").mkdir(parents=True)
        (root / "config").mkdir()
        for relative in ("scripts/update_checksums.py", "sec_review_build.py"):
            shutil.copy2(ROOT / relative, root / relative)
        (root / "payload.txt").write_text("sample\n")
        (root / "SHA256SUMS").write_text("")
        (root / "config/sdist-manifest.json").write_text(json.dumps({"schema_version": "1.0", "files": ["payload.txt", "SHA256SUMS", "config/sdist-manifest.json"]}))
        return root

    def invoke(self, root, *args):
        return run(sys.executable, "-I", str(root / "scripts/update_checksums.py"), *args)


if __name__ == "__main__":
    unittest.main()
