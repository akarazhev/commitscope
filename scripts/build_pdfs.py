#!/usr/bin/env python3
"""Build the tracked bilingual documents with ReportLab 4.4.10."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = ROOT / "docs/security-review-pdfs"
DEFAULT_EPOCH = "1790035200"
INK = colors.HexColor("#202A31")
ACCENT = colors.HexColor("#087D76")
LEGACY = colors.HexColor("#8E332C")
BLOCK_TYPES = {"paragraph", "callout", "code", "table", "diagram"}
DIAGRAM_KINDS = {"flow", "boundary", "lanes", "cycle", "decision"}


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be nonempty text")
    return value


def _unique(value: object, seen: set[str], label: str) -> str:
    identifier = _nonempty(value, label)
    if identifier in seen:
        raise ValueError(f"duplicate {label}: {identifier}")
    seen.add(identifier)
    return identifier


def validate_source(source: dict, language: str) -> None:
    if source.get("language") != language or not isinstance(source.get("documents"), dict):
        raise ValueError("invalid PDF source language or documents")
    for kind, document in source["documents"].items():
        for field in ("title", "subject", "footer"):
            _nonempty(document.get(field), f"{kind} {field}")
        if "chapters" not in document:
            pages = document.get("pages")
            if not isinstance(pages, list) or not pages:
                raise ValueError(f"{kind} must have pages or chapters")
            for page in pages:
                _nonempty(page.get("title"), "page title")
                if not isinstance(page.get("sections"), list):
                    raise ValueError("legacy page sections must be a list")
            continue
        if kind == "playbook" or not isinstance(document["chapters"], list) or not document["chapters"]:
            raise ValueError(f"invalid chapters for {kind}")
        if document.get("id") != kind:
            raise ValueError(f"invalid document ID for {kind}")
        seen: set[str] = set()
        references = document.get("references")
        if not isinstance(references, list):
            raise ValueError("references must be a list")
        reference_ids = set()
        for reference in references:
            reference_ids.add(_unique(reference.get("id"), seen, "reference ID"))
            _nonempty(reference.get("title"), "reference title")
            url = _nonempty(reference.get("url"), "reference URL")
            if not url.startswith("https://"):
                raise ValueError("reference URL must use HTTPS")
            _nonempty(reference.get("checked"), "reference check date")
        for chapter in document["chapters"]:
            _unique(chapter.get("id"), seen, "chapter ID")
            _nonempty(chapter.get("title"), "chapter title")
            sections = chapter.get("sections")
            if not isinstance(sections, list) or not sections:
                raise ValueError("chapter needs sections")
            for section in sections:
                _unique(section.get("id"), seen, "section ID")
                _nonempty(section.get("heading"), "section heading")
                blocks = section.get("blocks")
                if not isinstance(blocks, list) or not blocks:
                    raise ValueError("section needs blocks")
                for block in blocks:
                    _unique(block.get("id"), seen, "block ID")
                    block_type = block.get("type")
                    if block_type not in BLOCK_TYPES:
                        raise ValueError(f"unsupported block type: {block_type}")
                    citations = block.get("citations", [])
                    if not isinstance(citations, list) or any(ref not in reference_ids for ref in citations):
                        raise ValueError("unknown citation ID")
                    if block_type in {"paragraph", "callout", "code"}:
                        _nonempty(block.get("text"), f"{block_type} text")
                    elif block_type == "table":
                        headers, rows = block.get("headers"), block.get("rows")
                        if not isinstance(headers, list) or len(headers) < 2 or any(not isinstance(cell, str) or not cell.strip() for cell in headers):
                            raise ValueError("table needs at least two headers")
                        if not isinstance(rows, list) or not rows or any(not isinstance(row, list) or len(row) != len(headers) or any(not isinstance(cell, str) for cell in row) for row in rows):
                            raise ValueError("table rows must match headers")
                        _nonempty(block.get("caption"), "table caption")
                    elif block_type == "diagram":
                        if block.get("kind") not in DIAGRAM_KINDS:
                            raise ValueError("unsupported diagram kind")
                        _nonempty(block.get("caption"), "diagram caption")
                        nodes = block.get("nodes")
                        if not isinstance(nodes, list) or not nodes:
                            raise ValueError("diagram needs nodes")
                        node_ids = set()
                        for node in nodes:
                            _unique(node.get("id"), node_ids, "diagram node ID")
                            _nonempty(node.get("label"), "diagram node label")
                        for edge in block.get("edges", []):
                            if edge.get("from") not in node_ids or edge.get("to") not in node_ids:
                                raise ValueError("diagram edge references unknown node")


def _structure(document: dict) -> tuple:
    if "chapters" not in document:
        return ("legacy", tuple(tuple(sorted(section)) for page in document["pages"] for section in page["sections"]),
                tuple(len(page["sections"]) for page in document["pages"]))
    return ("chapters", tuple(reference["id"] for reference in document["references"]), tuple(
        (chapter["id"], tuple((section["id"], tuple(
            (block["id"], block["type"], block.get("kind"), tuple(block.get("citations", [])),
             tuple(node["id"] for node in block.get("nodes", [])),
             tuple((edge["from"], edge["to"]) for edge in block.get("edges", [])))
            for block in section["blocks"])) for section in chapter["sections"]))
        for chapter in document["chapters"]))


def validate_pair(en: dict, ru: dict) -> None:
    validate_source(en, "en")
    validate_source(ru, "ru")
    if en.get("version") != ru.get("version") or set(en["documents"]) != set(ru["documents"]):
        raise ValueError("English and Russian PDF sources differ in version or documents")
    for kind in en["documents"]:
        if _structure(en["documents"][kind]) != _structure(ru["documents"][kind]):
            raise ValueError(f"English and Russian {kind} structure differs")


def build_pair(en: dict, ru: dict, output: Path) -> None:
    validate_pair(en, ru)
    for source in (en, ru):
        for kind in source["documents"]:
            build_document(source, kind, output)


def build_document(source: dict, kind: str, output: Path) -> None:
    content = source["documents"][kind]
    language = source["language"]
    version = source["version"]
    legacy = content.get("legacy", False)
    accent = LEGACY if legacy else ACCENT
    title = content["title"]
    if kind == "user-guide":
        filename = f"commitscope-user-guide-{language}.pdf"
    else:
        suffix = "-legacy" if legacy else ""
        filename = f"security-review-{kind}-{language}{suffix}.pdf"
    destination = output / language / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    styles = {
        "title": ParagraphStyle("title", fontName="NotoSans", fontSize=25, leading=32, textColor=INK, spaceAfter=16),
        "heading": ParagraphStyle("heading", fontName="NotoSans", fontSize=13, leading=18, textColor=accent, spaceBefore=13, spaceAfter=7, keepWithNext=True),
        "body": ParagraphStyle("body", fontName="NotoSans", fontSize=10, leading=15, textColor=INK, spaceAfter=9),
        "code": ParagraphStyle("code", fontName="NotoSans", fontSize=8.5, leading=13, textColor=INK, backColor=colors.HexColor("#F0F4F5"), borderPadding=9, spaceBefore=6, spaceAfter=13, alignment=TA_LEFT),
    }

    def decorate(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(accent)
        canvas.setLineWidth(2)
        canvas.line(44, A4[1] - 40, A4[0] - 44, A4[1] - 40)
        canvas.setFont("NotoSans", 8)
        canvas.setFillColor(accent)
        canvas.drawString(44, A4[1] - 30, f"CommitScope / {version} / {language.upper()}")
        canvas.setFont("NotoSans", 7.5)
        footer = content["footer"]
        canvas.drawString(44, 31, footer)
        canvas.drawRightString(A4[0] - 44, 31, str(doc.page))
        canvas.restoreState()

    story = []
    for index, page in enumerate(content["pages"]):
        if index:
            story.append(PageBreak())
        story.append(Paragraph(escape(page["title"]), styles["title"]))
        for section in page["sections"]:
            if "heading" in section:
                story.append(Paragraph(escape(section["heading"]), styles["heading"]))
            for paragraph in section.get("paragraphs", []):
                story.append(Paragraph(escape(paragraph), styles["body"]))
            if "code" in section:
                code = "<br/>".join(escape(line).replace(" ", "&#160;") for line in section["code"].splitlines())
                story.append(Paragraph(code, styles["code"]))
        story.append(Spacer(1, 4))

    descriptor, temporary = tempfile.mkstemp(prefix=f".{filename}.", dir=destination.parent)
    os.close(descriptor)
    try:
        document = SimpleDocTemplate(
            temporary, pagesize=A4, rightMargin=44, leftMargin=44,
            topMargin=62, bottomMargin=57, title=f"{title} | CommitScope {version}",
            author="CommitScope contributors", subject=content["subject"],
            creator="CommitScope PDF builder", invariant=1, pageCompression=1,
        )
        document.build(story, onFirstPage=decorate, onLaterPages=decorate)
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    print(destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DOCUMENTS)
    args = parser.parse_args()
    os.environ.setdefault("SOURCE_DATE_EPOCH", DEFAULT_EPOCH)
    if not os.environ["SOURCE_DATE_EPOCH"].isdigit():
        parser.error("SOURCE_DATE_EPOCH must be a non-negative integer")
    pdfmetrics.registerFont(TTFont("NotoSans", str(DOCUMENTS / "fonts/NotoSans-Regular.ttf")))
    en = json.loads((DOCUMENTS / "source/content-en.json").read_text(encoding="utf-8"))
    ru = json.loads((DOCUMENTS / "source/content-ru.json").read_text(encoding="utf-8"))
    build_pair(en, ru, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
