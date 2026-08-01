from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.units import inch
import datetime

severity_colors = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#ef4444"),
    "Medium": colors.HexColor("#f97316"),
    "Low": colors.HexColor("#eab308"),
    "Informational": colors.HexColor("#3b82f6")
}


def generate_pdf(audit_data, output_path="audit_report.pdf"):

    doc = SimpleDocTemplate(output_path, pagesize=A4)

    styles = getSampleStyleSheet()

    story = []

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=22,
        textColor=colors.HexColor("#38bdf8"),
        spaceAfter=15
    )

    story.append(
        Paragraph(
            "AI Powered Smart Contract Audit Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 0.3 * inch))

    summary = [

        [
            "Total Findings",
            "Risk Score"
        ],

        [
            str(audit_data["total_vulnerabilities"]),
            f'{audit_data["risk_score"]}/10'
        ]

    ]

    table = Table(summary, colWidths=[2.5 * inch, 2.5 * inch])

    table.setStyle(TableStyle([

        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),

        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#0f172a")),

        ("TEXTCOLOR", (0, 1), (-1, 1), colors.white),

        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),

        ("ALIGN", (0, 0), (-1, -1), "CENTER"),

        ("PADDING", (0, 0), (-1, -1), 8)

    ]))

    story.append(table)

    story.append(Spacer(1, 0.3 * inch))

    story.append(
        Paragraph(
            "<b>Executive Summary</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            audit_data["summary"],
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 0.3 * inch))

    story.append(
        Paragraph(
            "<b>Merged Security Findings</b>",
            styles["Heading2"]
        )
    )

    for finding in audit_data["merged_findings"]:

        severity = finding["severity"]

        color = severity_colors.get(severity, colors.gray)

        detected_by = ", ".join(finding["detected_by"])

        data = [

            ["Name", finding["name"]],

            ["Severity", severity],

            ["Confidence", finding["confidence"]],

            ["Detected By", detected_by],

            ["Description", finding["description"]],

            ["why_this_matters", finding["why_this_matters"]],

            ["Recommendation", finding["fix"]],

            ["Corrected Code", finding["fixed_code"]]

        ]

        t = Table(

            data,

            colWidths=[1.6 * inch, 4.4 * inch]

        )

        t.setStyle(TableStyle([

            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1e293b")),

            ("TEXTCOLOR", (0, 0), (0, -1), colors.white),

            ("BACKGROUND", (1, 1), (1, 1), color),

            ("TEXTCOLOR", (1, 1), (1, 1), colors.white),

            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),

            ("VALIGN", (0, 0), (-1, -1), "TOP"),

            ("PADDING", (0, 0), (-1, -1), 6)

        ]))

        story.append(t)

        story.append(Spacer(1, 0.2 * inch))

    doc.build(story)

    return output_path