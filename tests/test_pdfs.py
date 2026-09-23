import hashlib
import copy
import json
import importlib.util
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock


ROOT = Path(__file__).resolve().parents[1]
BUILDER_SPEC = importlib.util.spec_from_file_location("build_pdfs", ROOT / "scripts/build_pdfs.py")
build_pdfs = importlib.util.module_from_spec(BUILDER_SPEC)
BUILDER_SPEC.loader.exec_module(build_pdfs)
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
    @staticmethod
    def converted_pair():
        active = {
            "id": "methodology", "title": "Example", "subject": "Example", "footer": "Example",
            "references": [{"id": "S1", "title": "NIST SSDF 1.1",
                            "url": "https://csrc.nist.gov/pubs/sp/800/218/final",
                            "checked": "2026-09-23"}],
            "chapters": [{"id": "m01", "title": "Decision", "sections": [{
                "id": "scope", "heading": "Scope", "blocks": [{"id": "claim",
                "type": "paragraph", "text": "Reviewed scope [S1].", "citations": ["S1"]}]
            }]}],
        }
        en = {"language": "en", "version": "2.4.0", "documents": {"methodology": active}}
        ru = copy.deepcopy(en)
        ru["language"] = "ru"
        ru["documents"]["methodology"]["chapters"][0]["title"] = "Решение"
        return en, ru

    def test_active_source_ids_and_citations_are_validated(self):
        en, ru = self.converted_pair()
        build_pdfs.validate_source(en, "en")
        build_pdfs.validate_pair(en, ru)
        for change in ("duplicate", "unknown citation", "http URL", "unknown type"):
            with self.subTest(change=change):
                bad = copy.deepcopy(en)
                document = bad["documents"]["methodology"]
                block = document["chapters"][0]["sections"][0]["blocks"][0]
                if change == "duplicate":
                    document["chapters"][0]["sections"][0]["blocks"].append(copy.deepcopy(block))
                elif change == "unknown citation":
                    block["citations"] = ["S9"]
                elif change == "http URL":
                    document["references"][0]["url"] = "http://example.invalid/source"
                else:
                    block["type"] = "missing"
                with self.assertRaises(ValueError):
                    build_pdfs.validate_source(bad, "en")

    def test_english_russian_structure_must_match(self):
        en, ru = self.converted_pair()
        ru["documents"]["methodology"]["chapters"][0]["sections"] = []
        with self.assertRaises(ValueError):
            build_pdfs.validate_pair(en, ru)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "pdfs"
            with self.assertRaises(ValueError):
                build_pdfs.build_pair(en, ru, output)
            self.assertFalse(output.exists())

    @unittest.skipUnless(shutil.which("pdftotext") and shutil.which("pdftoppm"), "Poppler required")
    def test_semantic_blocks_render_literal_text_wrapped_table_and_figure(self):
        en, ru = self.converted_pair()
        label = "Граница доверия между рабочей станцией сотрудника и внешним сервисом Anthropic"
        for source in (en, ru):
            document = source["documents"]["methodology"]
            blocks = document["chapters"][0]["sections"][0]["blocks"]
            blocks[0]["text"] = "A & B < C [S1]"
            blocks.extend([
                {"id": "comparison", "type": "table", "caption": "Table 1. Comparison" if source["language"] == "en" else "Таблица 1. Сравнение",
                 "headers": ["Criterion", "Result", "Evidence"] if source["language"] == "en" else ["Критерий", "Результат", "Доказательство"],
                 "rows": [[f"Row {i}", "A long explanatory cell that must wrap instead of shrinking below nine points.", "Auditable observation"] for i in range(30)]},
                {"id": "wide-comparison", "type": "table", "caption": "Table 2. Wide comparison" if source["language"] == "en" else "Таблица 2. Широкое сравнение",
                 "headers": ["Option", "Coverage", "Repeatability", "Privacy", "Burden", "Evidence"],
                 "rows": [["Local", "Combined", "Recorded", "Approved transfer", "Employee time", "Protected run"]]},
                {"id": "boundary", "type": "diagram", "kind": "boundary",
                 "caption": "Figure 1. Trust boundary" if source["language"] == "en" else "Рисунок 1. Граница доверия",
                 "nodes": [{"id": "local", "label": "Employee workstation" if source["language"] == "en" else label},
                           {"id": "external", "label": "Anthropic service" if source["language"] == "en" else "Сервис Anthropic"}],
                 "edges": [{"from": "local", "to": "external"}]},
            ])
        build_pdfs.pdfmetrics.registerFont(build_pdfs.TTFont("NotoSans", str(PDF_ROOT / "fonts/NotoSans-Regular.ttf")))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "pdfs"
            build_pdfs.build_pair(en, ru, output)
            for language in ("en", "ru"):
                pdf = output / language / f"security-review-methodology-{language}.pdf"
                extracted = run("pdftotext", "-layout", str(pdf), "-")
                self.assertEqual(extracted.returncode, 0, extracted.stderr)
                self.assertIn("A & B < C", extracted.stdout)
                self.assertGreaterEqual(extracted.stdout.count("Criterion" if language == "en" else "Критерий"), 2)
                self.assertIn("Figure 1. Trust boundary" if language == "en" else "Рисунок 1. Граница доверия", extracted.stdout)
                self.assertIn("https://csrc.nist.gov/pubs/sp/800/218/final", extracted.stdout)
                self.assertIn("(1/2)", extracted.stdout)
                self.assertIn("(2/2)", extracted.stdout)
                for page in extracted.stdout.split("\f"):
                    if "Wide comparison (1/2)" in page or "Широкое сравнение (1/2)" in page:
                        self.assertIn("Repeatability", page)
                self.assertNotIn("\ufffd", extracted.stdout)
                if language == "ru":
                    self.assertIn("Граница доверия между", extracted.stdout)
                preview = Path(directory) / f"{language}-preview"
                rendered = run("pdftoppm", "-f", "1", "-l", "1", "-r", "120", "-png", "-singlefile", str(pdf), str(preview))
                self.assertEqual(rendered.returncode, 0, rendered.stderr)
                self.assertTrue(preview.with_suffix(".png").is_file())
                if os.environ.get("COMMITSCOPE_PDF_QA_DIR"):
                    qa = Path(os.environ["COMMITSCOPE_PDF_QA_DIR"])
                    qa.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(pdf, qa / pdf.name)
                links = run("pdfinfo", "-url", str(pdf))
                if links.returncode == 0:
                    self.assertIn("https://csrc.nist.gov/pubs/sp/800/218/final", links.stdout)

    def test_decision_diagram_reserves_space_for_four_outcomes(self):
        block = {"kind": "decision", "nodes": [
            {"id": "root", "label": "Result"},
            {"id": "ready", "label": "Ready for review"},
            {"id": "findings", "label": "Findings require triage"},
            {"id": "incomplete", "label": "Incomplete"},
        ]}
        style = build_pdfs.ParagraphStyle("diagram-test", fontName="Helvetica", fontSize=9, leading=12)
        diagram = build_pdfs.DiagramFlowable(block, style)
        diagram.wrap(507, 700)
        self.assertGreater(diagram.height, diagram.box_heights[0] + max(diagram.box_heights[1:3]) + diagram.box_heights[3] + 30)

    def test_boundary_diagram_draws_both_cross_boundary_flows(self):
        block = {"kind": "boundary", "nodes": [
            {"id": "snapshot", "label": "Snapshot"}, {"id": "evidence", "label": "Evidence"},
            {"id": "hunter", "label": "Hunter"}, {"id": "verifier", "label": "Verifier"},
        ], "edges": [{"from": "snapshot", "to": "hunter"}, {"from": "evidence", "to": "verifier"}]}
        style = build_pdfs.ParagraphStyle("boundary-test", fontName="Helvetica", fontSize=9, leading=12)
        diagram = build_pdfs.DiagramFlowable(block, style)
        diagram.wrap(507, 700)
        diagram.canv = MagicMock()
        diagram._box = lambda *args: None
        arrows = []
        diagram._arrow = lambda *args: arrows.append(args)
        diagram.draw()
        self.assertEqual(len(arrows), 2)

    @unittest.skipUnless(shutil.which("pdftotext"), "Poppler required")
    def test_methodology_has_sourced_bilingual_argument_and_figures(self):
        sources = [json.loads((PDF_ROOT / f"source/content-{language}.json").read_text()) for language in ("en", "ru")]
        build_pdfs.validate_pair(*sources)
        expected_figures = {"practice-map", "comparison", "trust-boundary", "finding-lifecycle", "rollout"}
        for source in sources:
            language = source["language"]
            document = source["documents"]["methodology"]
            self.assertEqual([chapter["id"] for chapter in document["chapters"]], [f"m{i:02d}" for i in range(1, 9)])
            self.assertTrue({f"S{i}" for i in range(1, 8)}.issubset({ref["id"] for ref in document["references"]}))
            blocks = [block for chapter in document["chapters"] for section in chapter["sections"] for block in section["blocks"]]
            self.assertTrue(expected_figures.issubset({block["id"] for block in blocks}))
            boundary = next(block for block in blocks if block["id"] == "trust-boundary")
            outgoing = {edge["from"] for edge in boundary["edges"]}
            self.assertFalse(any("private/" in node["label"] for node in boundary["nodes"] if node["id"] in outgoing))
            self.assertFalse(re.search(r"\b\d+(?:\.\d+)?%|\$\d+", json.dumps(document, ensure_ascii=False)))
            pdf = PDF_ROOT / language / f"security-review-methodology-{language}.pdf"
            extracted = run("pdftotext", "-layout", str(pdf), "-")
            self.assertEqual(extracted.returncode, 0, extracted.stderr)
            self.assertIn("2026-09-23", extracted.stdout)
            self.assertIn("Figure 1" if language == "en" else "Рисунок 1", extracted.stdout)
            self.assertIn("https://csrc.nist.gov/pubs/sp/800/218/final", extracted.stdout)
            pages = extracted.stdout.split("\f")
            for chapter, caption in (("02 / International practice", "Figure 1"),
                                     ("05 / Architecture and trust", "Figure 2"),
                                     ("06 / From hypothesis to fix", "Figure 3"),
                                     ("07 / Controlled adoption", "Figure 4")) if language == "en" else (
                                     ("02 / Мировая практика", "Рисунок 1"),
                                     ("05 / Архитектура и доверие", "Рисунок 2"),
                                     ("06 / От гипотезы до исправления", "Рисунок 3"),
                                     ("07 / Контролируемое внедрение", "Рисунок 4")):
                self.assertTrue(any(chapter in page and caption in page for page in pages), chapter)

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
                        self.assertIn("Claude Code 2.1.259 or newer", text.stdout)
                        self.assertIn("Bearer/Basic authorization values", text.stdout)
                        self.assertIn("SCANNERS_VERIFIED_AI_NOT_RUN is not completed corporate acceptance", " ".join(text.stdout.split()))
                    else:
                        self.assertIn("Hunter и Verifier обязательны", text.stdout)
                        self.assertIn("Claude Code 2.1.259 или новее", text.stdout)
                        self.assertIn("Bearer/Basic", text.stdout)
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
