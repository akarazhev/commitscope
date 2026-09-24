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
from reportlab.platypus import CondPageBreak, Flowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = ROOT / "docs/security-review-pdfs"
DEFAULT_EPOCH = "1790035200"
INK = colors.HexColor("#202A31")
ACCENT = colors.HexColor("#087D76")
LEGACY = colors.HexColor("#8E332C")
BLOCK_TYPES = {"paragraph", "callout", "code", "table", "diagram"}
DIAGRAM_KINDS = {"flow", "boundary", "lanes", "grid", "cycle", "decision"}


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


class DiagramFlowable(Flowable):
    def __init__(self, block: dict, label_style: ParagraphStyle):
        super().__init__()
        self.block = block
        self.label_style = label_style

    def wrap(self, avail_width, avail_height):
        self.width = min(avail_width, 507)
        self.paragraphs = [Paragraph(escape(node["label"]), self.label_style) for node in self.block["nodes"]]
        kind = self.block["kind"]
        full_width = self.width - 50
        column_width = full_width / 2
        self.box_heights = []
        for index, paragraph in enumerate(self.paragraphs):
            box_width = full_width if kind == "decision" and index == 0 else (
                column_width if kind in {"boundary", "lanes", "grid", "decision"} else full_width
            )
            self.box_heights.append(max(43, paragraph.wrap(box_width - 20, 1000)[1] + 18))
        if kind == "boundary":
            half = (len(self.box_heights) + 1) // 2
            self.height = max(sum(self.box_heights[:half]), sum(self.box_heights[half:])) + max(0, half - 1) * 14 + 38
        elif kind in {"lanes", "grid"}:
            rows = [self.box_heights[index:index + 2] for index in range(0, len(self.box_heights), 2)]
            self.height = sum(max(row) for row in rows) + max(0, len(rows) - 1) * 20 + 20
        elif kind == "decision" and len(self.box_heights) > 1:
            rows = [self.box_heights[index:index + 2] for index in range(1, len(self.box_heights), 2)]
            self.height = self.box_heights[0] + sum(max(row) for row in rows) + len(rows) * 34 + 20
        else:
            self.height = sum(self.box_heights) + max(0, len(self.box_heights) - 1) * 21 + 20
        return self.width, self.height

    def _box(self, index: int, x: float, top: float, width: float) -> None:
        height = self.box_heights[index]
        y = top - height
        self.canv.setFillColor(colors.HexColor("#EDF4F3") if index % 2 == 0 else colors.HexColor("#F4F3EF"))
        self.canv.setStrokeColor(ACCENT if index % 2 == 0 else INK)
        self.canv.roundRect(x, y, width, height, 3, stroke=1, fill=1)
        paragraph = self.paragraphs[index]
        _, text_height = paragraph.wrap(width - 20, height - 12)
        paragraph.drawOn(self.canv, x + 10, y + (height - text_height) / 2)

    def _arrow(self, x1: float, y1: float, x2: float, y2: float) -> None:
        self.canv.setStrokeColor(INK)
        self.canv.setFillColor(INK)
        self.canv.setLineWidth(1.1)
        self.canv.line(x1, y1, x2, y2)
        if abs(y2 - y1) >= abs(x2 - x1):
            direction = -1 if y2 < y1 else 1
            path = self.canv.beginPath()
            path.moveTo(x2, y2)
            path.lineTo(x2 - 4, y2 - direction * 6)
            path.lineTo(x2 + 4, y2 - direction * 6)
        else:
            direction = 1 if x2 > x1 else -1
            path = self.canv.beginPath()
            path.moveTo(x2, y2)
            path.lineTo(x2 - direction * 6, y2 - 4)
            path.lineTo(x2 - direction * 6, y2 + 4)
        path.close()
        self.canv.drawPath(path, stroke=0, fill=1)

    def draw(self):
        kind = self.block["kind"]
        top = self.height - 10
        if kind == "boundary":
            width = (self.width - 50) / 2
            half = (len(self.box_heights) + 1) // 2
            centers = {}
            for column, indices in enumerate((range(half), range(half, len(self.box_heights)))):
                y = top - 20
                x = 10 if column == 0 else self.width - width - 10
                for index in indices:
                    self._box(index, x, y, width)
                    centers[self.block["nodes"][index]["id"]] = (x + width / 2, y - self.box_heights[index] / 2)
                    y -= self.box_heights[index] + 14
            self.canv.setDash(3, 3)
            self.canv.setStrokeColor(LEGACY)
            self.canv.line(self.width / 2, 5, self.width / 2, self.height - 5)
            self.canv.setDash()
            for edge in self.block.get("edges", []):
                source_x, source_y = centers[edge["from"]]
                target_x, target_y = centers[edge["to"]]
                if source_x < target_x:
                    self._arrow(width + 12, source_y, self.width - width - 12, target_y)
                elif source_x > target_x:
                    self._arrow(self.width - width - 12, source_y, width + 12, target_y)
                else:
                    self._arrow(source_x, source_y - 18, target_x, target_y + 18)
        elif kind in {"lanes", "grid"}:
            width = (self.width - 50) / 2
            y = top
            for first in range(0, len(self.box_heights), 2):
                row = range(first, min(first + 2, len(self.box_heights)))
                row_height = max(self.box_heights[index] for index in row)
                for index in row:
                    x = 10 if index % 2 == 0 else self.width - width - 10
                    self._box(index, x, y, width)
                if kind == "lanes" and first + 2 < len(self.box_heights):
                    self._arrow(self.width / 2, y - row_height - 2,
                                self.width / 2, y - row_height - 17)
                y -= row_height + 20
        elif kind == "decision" and len(self.box_heights) > 1:
            root_width = self.width - 50
            self._box(0, 25, top, root_width)
            branch_width = (self.width - 50) / 2
            root_bottom = top - self.box_heights[0]
            previous_bottom = root_bottom
            for first in range(1, len(self.box_heights), 2):
                row = list(range(first, min(first + 2, len(self.box_heights))))
                branch_top = previous_bottom - 34
                for index in row:
                    x = (self.width - branch_width) / 2 if len(row) == 1 else (10 if index == first else self.width - branch_width - 10)
                    self._box(index, x, branch_top, branch_width)
                    self._arrow(self.width / 2, root_bottom - 3, x + branch_width / 2, branch_top + 3)
                previous_bottom = branch_top - max(self.box_heights[index] for index in row)
        else:
            width = self.width - 50
            y = top
            for index in range(len(self.box_heights)):
                self._box(index, 25, y, width)
                y -= self.box_heights[index]
                if index + 1 < len(self.box_heights):
                    self._arrow(self.width / 2, y - 2, self.width / 2, y - 17)
                    y -= 21
            if kind == "cycle" and len(self.box_heights) > 1:
                self.canv.setStrokeColor(LEGACY)
                self.canv.line(14, self.height - 30, 14, max(20, y + 15))
                self._arrow(14, self.height - 30, 25, self.height - 30)


def render_paragraph(block: dict, styles: dict, references: dict) -> list:
    return [Paragraph(escape(block["text"]), styles["body"])]


def render_callout(block: dict, styles: dict, references: dict) -> list:
    cell = Paragraph(escape(block["text"]), styles["body"])
    table = Table([[cell]], colWidths=[507], hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EDF4F3")),
                               ("LINEBEFORE", (0, 0), (0, -1), 3, ACCENT),
                               ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                               ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    return [table, Spacer(1, 8)]


def render_code(block: dict, styles: dict, references: dict) -> list:
    markup = "<br/>".join(escape(line).replace(" ", "&#160;") for line in block["text"].splitlines())
    return [KeepTogether([Paragraph(markup, styles["code"])])]


def render_table(block: dict, styles: dict, references: dict) -> list:
    headers, rows = block["headers"], block["rows"]
    groups = [list(range(start, min(start + 3, len(headers)))) for start in range(1, len(headers), 3)]
    result = []
    for group_index, group in enumerate(groups):
        columns = [0] + group
        caption = block["caption"] if len(groups) == 1 else f"{block['caption']} ({group_index + 1}/{len(groups)})"
        result.append(Paragraph(escape(caption), styles["table_caption"]))
        data = [[Paragraph(escape(headers[index]), styles["table_head"]) for index in columns]]
        data.extend([[Paragraph(escape(row[index]), styles["table_cell"]) for index in columns] for row in rows])
        widths = [507 * (0.27 if index == 0 else 0.73 / len(group)) for index in columns]
        table = Table(data, colWidths=widths, repeatRows=1, splitByRow=1, hAlign="LEFT")
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), INK),
                                   ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F4F7F6")]),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("LINEBELOW", (0, 0), (-1, 0), 1, ACCENT),
                                   ("LINEBELOW", (0, 1), (-1, -1), 0.25, colors.HexColor("#D4DDDA")),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                                   ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        result.extend([table, Spacer(1, 10)])
    return result


def render_diagram(block: dict, styles: dict, references: dict) -> list:
    return [KeepTogether([DiagramFlowable(block, styles["figure_label"]),
                          Paragraph(escape(block["caption"]), styles["caption"])])]


def render_block(block: dict, styles: dict, references: dict) -> list:
    renderer = {"paragraph": render_paragraph, "callout": render_callout,
                "code": render_code, "table": render_table, "diagram": render_diagram}.get(block["type"])
    if renderer is None:
        raise ValueError(f"unsupported block type: {block['type']}")
    return renderer(block, styles, references)


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
        "title": ParagraphStyle("title", fontName="NotoSans", fontSize=25, leading=32, textColor=INK, spaceAfter=16, keepWithNext=True),
        "heading": ParagraphStyle("heading", fontName="NotoSans", fontSize=13, leading=18, textColor=accent, spaceBefore=13, spaceAfter=7, keepWithNext=True),
        "body": ParagraphStyle("body", fontName="NotoSans", fontSize=10, leading=15, textColor=INK, spaceAfter=9),
        "code": ParagraphStyle("code", fontName="NotoSans", fontSize=8.5, leading=13, textColor=INK, backColor=colors.HexColor("#F0F4F5"), borderPadding=9, spaceBefore=6, spaceAfter=13, alignment=TA_LEFT),
        "chapter": ParagraphStyle("chapter", fontName="NotoSans", fontSize=17, leading=23, textColor=accent, spaceBefore=18, spaceAfter=9, keepWithNext=True),
        "caption": ParagraphStyle("caption", fontName="NotoSans", fontSize=9, leading=13, textColor=INK, spaceBefore=5, spaceAfter=8),
        "table_caption": ParagraphStyle("table_caption", fontName="NotoSans", fontSize=9, leading=13, textColor=INK, spaceBefore=5, spaceAfter=8, keepWithNext=True),
        "table_head": ParagraphStyle("table_head", fontName="NotoSans", fontSize=9, leading=12, textColor=colors.white),
        "table_cell": ParagraphStyle("table_cell", fontName="NotoSans", fontSize=9, leading=13, textColor=INK),
        "figure_label": ParagraphStyle("figure_label", fontName="NotoSans", fontSize=9.5, leading=13, textColor=INK),
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
    if "chapters" in content:
        story.append(Paragraph(escape(title), styles["title"]))
        references = {reference["id"]: reference for reference in content["references"]}
        for chapter in content["chapters"]:
            first_section = chapter["sections"][0]
            first_blocks = first_section["blocks"]
            if kind == "user-guide":
                lead_types = {block["type"] for block in first_blocks[:2]}
                reserve = 380 if "diagram" in lead_types else 400 if "table" in lead_types else 360
                story.append(CondPageBreak(reserve))
            keep_count = 0 if kind == "user-guide" else (1 if first_blocks[0]["type"] == "diagram" else (
                2 if len(first_blocks) > 1 and first_blocks[1]["type"] == "diagram" else 0))
            beginning = [Paragraph(escape(chapter["title"]), styles["chapter"]),
                         Paragraph(escape(first_section["heading"]), styles["heading"])]
            for block in first_blocks[:keep_count]:
                beginning.extend(render_block(block, styles, references))
            story.append(KeepTogether(beginning) if keep_count else beginning[0])
            if not keep_count:
                story.append(beginning[1])
            for section_index, section in enumerate(chapter["sections"]):
                if section_index:
                    story.append(Paragraph(escape(section["heading"]), styles["heading"]))
                for block in section["blocks"][keep_count if section_index == 0 else 0:]:
                    story.extend(render_block(block, styles, references))
        if references:
            heading = "Sources and verification date" if language == "en" else "Источники и дата проверки"
            reference_story = [Paragraph(heading, styles["chapter"])]
            for reference in references.values():
                url = escape(reference["url"], {'"': "&quot;"})
                title_text = escape(reference["title"])
                markup = f"[{escape(reference['id'])}] {title_text}. <link href=\"{url}\" color=\"#087D76\">{url}</link> ({escape(reference['checked'])})"
                reference_story.append(Paragraph(markup, styles["body"]))
            story.extend([KeepTogether(reference_story)] if kind == "user-guide" else reference_story)
    else:
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
