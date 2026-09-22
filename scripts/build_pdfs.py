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
    for language in ("en", "ru"):
        source = json.loads((DOCUMENTS / f"source/content-{language}.json").read_text(encoding="utf-8"))
        for kind in ("methodology", "user-guide", "playbook"):
            build_document(source, kind, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
