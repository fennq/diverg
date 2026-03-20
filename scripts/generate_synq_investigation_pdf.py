#!/usr/bin/env python3
"""
Generate Synq Investigation Report PDF and merge with Security Scan PDF.
Reads investigation/SYNQ_Investigation_Report.md, builds full report, then appends
content/SYNQ_Security_Scan_Report.pdf. Output: investigation/SYNQ_Investigation_Report.pdf (combined).
Do not commit investigation/ to repo.
"""
import json
import re
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, PageBreak,
)

BASE = Path(__file__).parent.parent
INV_DIR = BASE / "investigation"
CONTENT_DIR = BASE / "content"
MD_PATH = INV_DIR / "SYNQ_Investigation_Report.md"
SCAN_PDF_PATH = CONTENT_DIR / "SYNQ_Security_Scan_Report.pdf"
OUTPUT_PATH = INV_DIR / "SYNQ_Investigation_Report.pdf"

WALLETS = [
    "6fMGqiSN23mbbQ18DJaHXfLYz5xs3fdQtiGVzpeQPfWQ",
    "UteVevXPVWM6NtohF87ysipmqdfeCDuAQXf5rTNkzyR",
    "AABBP7za3DqZwxbHh8jx7cwdpQHeSSdtDq81Uz3g96b8",
    "ETvz4wgkp98ip8vabLHmyEypU1urvoCK558vPUFfipq7",
    "By946UgiAUnq4KcJh15Z2fRKVz2ScvUQRj4nqPXHTc2w",
    "9uHphoGiwR3kvwAMr7SfCQWH5Pe3nADW19rjeeMh9pYM",
    "4LciDVUKQ8n9DC4F8qEt5bAgpPPhovQfG7RCPxoNbRSX",
    "8LvxZoN1b6rNV9wkmXaitteRpm1pLHskyNduj35ekAHz",
]
TOKEN_MINT = "3So5XbQpL9uxfFXvDSJpzeGFLo8K4NGddv2cBhRPpump"


def build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading1"],
        fontSize=14,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="Subsection",
        parent=styles["Heading2"],
        fontSize=11,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="Evidence",
        parent=styles["Normal"],
        fontSize=8,
        fontName="Courier",
        backColor=colors.HexColor("#f5f5f5"),
        borderPadding=6,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="BulletText",
        parent=styles["Normal"],
        fontSize=9,
        leftIndent=12,
        spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="Small",
        parent=styles["Normal"],
        fontSize=8,
        spaceAfter=2,
    ))
    return styles


def md_to_reportlab_html(text):
    """Escape and convert **bold** to <b> for ReportLab Paragraph."""
    for c in ("&", "<", ">"):
        text = text.replace(c, {"&": "&amp;", "<": "&lt;", ">": "&gt;"}[c])
    # **word** -> <b>word</b> (non-greedy)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    return text


def md_to_flowables(md_text, styles):
    """Turn markdown into a list of flowables (paragraphs, preformatted)."""
    flowables = []
    in_code = False
    code_lines = []
    for line in md_text.splitlines():
        if line.strip().startswith("```"):
            if in_code:
                flowables.append(Preformatted("\n".join(code_lines), styles["Evidence"]))
                flowables.append(Spacer(1, 0.1 * inch))
                code_lines = []
            in_code = not in_code
            continue
        if in_code:
            code_lines.append(line)
            continue
        if line.startswith("# "):
            flowables.append(Paragraph(md_to_reportlab_html(line[2:].strip()), styles["Title"]))
            flowables.append(Spacer(1, 0.15 * inch))
        elif line.startswith("## "):
            flowables.append(Paragraph(md_to_reportlab_html(line[3:].strip()), styles["Section"]))
            flowables.append(Spacer(1, 0.1 * inch))
        elif line.startswith("### "):
            flowables.append(Paragraph(md_to_reportlab_html(line[4:].strip()), styles["Subsection"]))
            flowables.append(Spacer(1, 0.06 * inch))
        elif line.strip().startswith("|") and "---" not in line and "|" in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if parts:
                flowables.append(Paragraph(md_to_reportlab_html(" | ".join(parts)), styles["Small"]))
        elif line.strip():
            t = md_to_reportlab_html(line.strip())
            flowables.append(Paragraph(t, styles["Normal"]))
            flowables.append(Spacer(1, 0.04 * inch))
    if code_lines:
        flowables.append(Preformatted("\n".join(code_lines), styles["Evidence"]))
    return flowables


def add_wallet_table(story, styles, wallet, index):
    short = wallet[:8] + "..." + wallet[-8:] if len(wallet) > 20 else wallet
    story.append(Paragraph(f"Wallet {index} — {short}", styles["Subsection"]))
    data = [
        ["Resource", "URL"],
        ["Solscan", f"https://solscan.io/account/{wallet}"],
        ["Arkham", f"https://platform.arkhamintelligence.com/explorer/address/{wallet}"],
        ["Bubblemaps", f"https://bubblemaps.io/solana/{wallet}"],
    ]
    t = Table(data, colWidths=[1.2 * inch, 5.3 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Paragraph("CEX / apps / flows / social: [Fill from tools]", styles["Small"]))
    story.append(Spacer(1, 0.15 * inch))


def merge_pdfs(pdf_paths, output_path):
    """Merge multiple PDFs into one. Requires pypdf (PdfWriter)."""
    try:
        from pypdf import PdfWriter
    except ImportError:
        print("Install pypdf to merge PDFs: pip install pypdf")
        return False
    writer = PdfWriter()
    for p in pdf_paths:
        if Path(p).exists():
            writer.append(str(p))
        else:
            print(f"Skip missing: {p}")
    writer.write(str(output_path))
    writer.close()
    return True


def main():
    INV_DIR.mkdir(exist_ok=True)
    if not MD_PATH.exists():
        print(f"Missing {MD_PATH}; run investigation doc creation first.")
        return
    md_text = MD_PATH.read_text(encoding="utf-8", errors="replace")
    styles = build_styles()
    story = md_to_flowables(md_text, styles)
    # Add separator and note before appended scan
    story.append(PageBreak())
    story.append(Paragraph("— End of Investigation Report —", styles["Section"]))
    story.append(Paragraph(
        "The following section is the full Diverg Security Scan report (SYNQ_Security_Scan_Report.pdf).",
        styles["Normal"],
    ))
    story.append(PageBreak())

    # Build investigation PDF to a temp file so we can merge with scan
    investigation_only_path = INV_DIR / "SYNQ_Investigation_Report_part1.pdf"
    doc = SimpleDocTemplate(
        str(investigation_only_path),
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    doc.build(story)
    print(f"Investigation PDF built: {investigation_only_path}")

    # Merge with Security Scan PDF if present
    if SCAN_PDF_PATH.exists():
        merge_ok = merge_pdfs([investigation_only_path, SCAN_PDF_PATH], OUTPUT_PATH)
        if merge_ok:
            investigation_only_path.unlink(missing_ok=True)
            print(f"Combined PDF written to: {OUTPUT_PATH} (investigation + security scan)")
        else:
            # No pypdf: leave part1 as-is and copy to output name
            import shutil
            shutil.copy(investigation_only_path, OUTPUT_PATH)
            print(f"PDF written to: {OUTPUT_PATH} (investigation only; install pypdf to merge scan)")
    else:
        import shutil
        shutil.copy(investigation_only_path, OUTPUT_PATH)
        investigation_only_path.unlink(missing_ok=True)
        print(f"PDF written to: {OUTPUT_PATH} (investigation only; {SCAN_PDF_PATH} not found)")


if __name__ == "__main__":
    main()
