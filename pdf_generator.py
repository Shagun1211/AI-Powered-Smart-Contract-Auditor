from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
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
        'Title',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor("#38bdf8"),
        spaceAfter=10
    )
    story.append(Paragraph("Smart Contract Audit Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles['Normal']
    ))
    story.append(Spacer(1, 0.3 * inch))

  
    summary_data = [
        ["Total Vulnerabilities", "Risk Score", "Slither Findings", "AI Findings"],
        [
            str(audit_data["total_vulnerabilities"]),
            f"{audit_data['risk_score']}/10",
            str(len(audit_data["slither_findings"])),
            str(len(audit_data["llm_analysis"]["additional_vulnerabilities"]))
        ]
    ]
    summary_table = Table(summary_data, colWidths=[1.5*inch]*4)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#38bdf8")),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0,1), (-1,1), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 11),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#334155")),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))


    story.append(Paragraph("Overall Assessment", styles['Heading2']))
    story.append(Paragraph(audit_data["summary"], styles['Normal']))
    story.append(Spacer(1, 0.3 * inch))


    story.append(Paragraph("Slither Static Analysis Findings", styles['Heading2']))
    for finding in audit_data["slither_findings"]:
        color = severity_colors.get(finding["severity"], colors.gray)
        data = [
            ["Detector", finding["detector"]],
            ["Severity", finding["severity"]],
            ["Confidence", finding["confidence"]],
            ["Description", finding["description"]]
        ]
        t = Table(data, colWidths=[1.5*inch, 4.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#94a3b8")),
            ('BACKGROUND', (1,1), (1,1), color),
            ('TEXTCOLOR', (1,1), (1,1), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#334155")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.2 * inch))


    story.append(Paragraph("AI Analysis Findings", styles['Heading2']))
    for vuln in audit_data["llm_analysis"]["additional_vulnerabilities"]:
        color = severity_colors.get(vuln["severity"], colors.gray)
        data = [
            ["Name", vuln["name"]],
            ["Severity", vuln["severity"]],
            ["Description", vuln["description"]],
            ["Fix", vuln["fix"]],
            ["Fixed Code", vuln["fixed_code"]]
        ]
        t = Table(data, colWidths=[1.5*inch, 4.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#94a3b8")),
            ('BACKGROUND', (1,1), (1,1), color),
            ('TEXTCOLOR', (1,1), (1,1), colors.white),
            ('BACKGROUND', (1,4), (1,4), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (1,4), (1,4), colors.HexColor("#38bdf8")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#334155")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.2 * inch))

    doc.build(story)
    return output_path