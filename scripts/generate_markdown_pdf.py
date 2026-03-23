#!/usr/bin/env python3
"""
Generate a simple PDF from a markdown file using ReportLab.

Usage:
  python scripts/generate_markdown_pdf.py --in path/to/report.md --out path/to/report.pdf
"""
from __future__ import annotations

import argparse
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer


def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle(name="H1", parent=s["Heading1"], fontSize=16, spaceAfter=8))
    s.add(ParagraphStyle(name="H2", parent=s["Heading2"], fontSize=13, spaceAfter=6))
    s.add(ParagraphStyle(name="H3", parent=s["Heading3"], fontSize=11, spaceAfter=4))
    s.add(
        ParagraphStyle(
            name="CodeBlock",
            parent=s["Code"],
            fontName="Courier",
            fontSize=8,
            backColor=colors.HexColor("#f4f4f4"),
            leftIndent=6,
            rightIndent=6,
            leading=9,
            spaceAfter=6,
        )
    )
    s.add(ParagraphStyle(name="BulletLine", parent=s["Normal"], leftIndent=12, spaceAfter=2))
    return s


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def md_to_story(md_text: str):
    s = styles()
    story = []
    in_code = False
    code_lines = []

    for raw in md_text.splitlines():
        line = raw.rstrip("\n")
        if line.strip().startswith("```"):
            if in_code:
                story.append(Preformatted("\n".join(code_lines), s["CodeBlock"]))
                story.append(Spacer(1, 0.05 * inch))
                code_lines = []
            in_code = not in_code
            continue
        if in_code:
            code_lines.append(line)
            continue

        if line.startswith("# "):
            story.append(Paragraph(esc(line[2:].strip()), s["H1"]))
            story.append(Spacer(1, 0.06 * inch))
        elif line.startswith("## "):
            story.append(Paragraph(esc(line[3:].strip()), s["H2"]))
            story.append(Spacer(1, 0.05 * inch))
        elif line.startswith("### "):
            story.append(Paragraph(esc(line[4:].strip()), s["H3"]))
            story.append(Spacer(1, 0.04 * inch))
        elif line.strip().startswith("- "):
            story.append(Paragraph("• " + esc(line.strip()[2:]), s["BulletLine"]))
        elif line.strip():
            story.append(Paragraph(esc(line.strip()), s["Normal"]))
            story.append(Spacer(1, 0.03 * inch))
        else:
            story.append(Spacer(1, 0.03 * inch))

    if code_lines:
        story.append(Preformatted("\n".join(code_lines), s["CodeBlock"]))
    return story


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert markdown to PDF")
    ap.add_argument("--in", dest="input_path", required=True, help="Input markdown file")
    ap.add_argument("--out", dest="output_path", required=True, help="Output PDF file")
    args = ap.parse_args()

    in_path = Path(args.input_path)
    out_path = Path(args.output_path)
    if not in_path.exists():
        print(f"Missing input file: {in_path}")
        return 1

    md_text = in_path.read_text(encoding="utf-8", errors="replace")
    story = md_to_story(md_text)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    doc.build(story)
    print(f"PDF written: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

