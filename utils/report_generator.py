# NEW: Generate a detailed PDF that matches the HTML threat report
def generate_detailed_threat_pdf(log_data, filename, output_dir="reports"):
    today = datetime.now()
    year = str(today.year)
    month = today.strftime('%B')
    day = str(today.day)
    output_path = os.path.join(output_dir, year, month, day)
    os.makedirs(output_path, exist_ok=True)
    pdf_path = os.path.join(output_path, f"detailed_{filename.replace('.log','').replace('.txt','')}_threat_report.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []
    # Title and meta
    elements.append(Paragraph("Threat Report", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated on: <b>{today.strftime('%Y-%m-%d %H:%M:%S')}</b>", styles['Normal']))
    elements.append(Paragraph(f"Log File: <b>{filename}</b>", styles['Normal']))
    elements.append(Spacer(1, 16))
    # Summary
    summary_data = [
        ['Total Logs', str(log_data.get('total_logs', 'N/A'))],
        ['Total Threats', str(log_data.get('total_threats', 'N/A'))],
        ['Unique IPs', str(log_data.get('unique_ips', 'N/A'))]
    ]
    table = Table(summary_data, colWidths=[120, 200])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 16))
    # Threats Table (by IP)
    elements.append(Paragraph("Detected Threats (By IP)", styles['Heading2']))
    threat_ip_summary = log_data.get('threat_ip_summary', {})
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    small_style = ParagraphStyle('small', fontSize=7, leading=8, alignment=TA_LEFT)
    header = ['#', 'IP', 'Paths', 'Location', 'Count', 'Reason', 'Threat Level', 'Time Duration']
    threat_table_data = [header]
    MAX_LINES = 10  # Limit lines per cell to avoid LayoutError
    def make_paragraphs(text, style, max_lines=MAX_LINES):
        lines = text.split('<br/>') if '<br/>' in text else text.split('\n')
        if len(lines) > max_lines:
            lines = lines[:max_lines] + ['...']
        return Paragraph('<br/>'.join(lines), style)

    for idx, (ip, info) in enumerate(threat_ip_summary.items(), 1):
        # Wrap long content in Paragraphs and split lines, limit lines
        paths_list = [f"<b>{p}</b> <font color='orange'>(Status: {d['status']}, x{d['count']})</font>" for p, d in info['paths'].items()]
        paths = '<br/>'.join(paths_list)
        reasons = '<br/>'.join(info.get('reasons', []))
        levels = '<br/>'.join(info.get('threat_levels', []))
        threat_table_data.append([
            make_paragraphs(str(idx), small_style, 1),
            make_paragraphs(ip, small_style, 1),
            make_paragraphs(paths, small_style),
            make_paragraphs(info.get('location', ''), small_style, 2),
            make_paragraphs(str(info.get('count', '')), small_style, 1),
            make_paragraphs(reasons, small_style),
            make_paragraphs(levels, small_style),
            make_paragraphs(info.get('time_duration', ''), small_style, 2)
        ])
    table = Table(threat_table_data, colWidths=[20, 70, 120, 60, 40, 80, 60, 60], repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('LEADING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 16))
    # Top Threat IPs
    elements.append(Paragraph("Top Threat IPs", styles['Heading2']))
    top_threats = log_data.get('top_threats', {})
    if top_threats:
        top_threat_data = [[ip, str(count)] for ip, count in top_threats.items()]
        table = Table([['IP Address', 'Threat Count']] + top_threat_data, colWidths=[120, 80])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 10))
    # Top URLs
    elements.append(Paragraph("Top URLs", styles['Heading2']))
    top_urls = log_data.get('top_urls', {})
    if top_urls:
        from reportlab.lib.styles import ParagraphStyle
        url_style = ParagraphStyle('url', fontSize=8, leading=10)
        url_data = [[Paragraph(str(url), url_style), Paragraph(str(count), url_style)] for url, count in top_urls.items()]
        table = Table([['URL', 'Count']] + url_data, colWidths=[320, 60])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('LEADING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 10))
    # Top User Agents
    elements.append(Paragraph("Top User Agents", styles['Heading2']))
    top_agents = log_data.get('top_agents', {})
    if top_agents:
        agent_style = ParagraphStyle('agent', fontSize=8, leading=10)
        agent_data = [[Paragraph(str(agent), agent_style), Paragraph(str(count), agent_style)] for agent, count in top_agents.items()]
        table = Table([['User Agent', 'Count']] + agent_data, colWidths=[180, 40])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('LEADING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 10))
    # Top Countries
    elements.append(Paragraph("Top Countries", styles['Heading2']))
    geo_data = log_data.get('geo_data', {})
    from reportlab.lib.styles import ParagraphStyle
    country_style = ParagraphStyle('country', fontSize=9, leading=11)
    if geo_data:
        country_style = ParagraphStyle('country', fontSize=9, leading=11)
        country_data = [[Paragraph(str(country), country_style), Paragraph(str(ip), country_style)] for ip, country in geo_data.items()]
        table = Table([['Country', 'IP']] + country_data, colWidths=[140, 120])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('LEADING', (0, 0), (-1, -1), 11),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 10))
    doc.build(elements)
    return pdf_path
# utils/report_generator.py
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
import matplotlib.pyplot as plt

def generate_chart(data, chart_path):
    labels = list(data.keys())
    sizes = list(data.values())

    if not labels or not sizes:
        return None

    plt.figure(figsize=(5, 5))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title("Top Threat IP Distribution")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()
    return chart_path

def generate_pdf_report(data, output_dir="reports"):
    today = datetime.now()
    year = str(today.year)
    month = today.strftime('%B')
    day = str(today.day)

    output_path = os.path.join(output_dir, year, month, day)
    os.makedirs(output_path, exist_ok=True)

    filename = os.path.join(output_path, "threat_report.pdf")
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("📄 <b>Threat Intelligence Report</b>", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"🕒 Date: {today.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Summary:</b>", styles['Heading2']))
    summary_data = [
        ['Total Logs', str(data.get('total_logs', 'N/A'))],
        ['Total Threats', str(data.get('total_threats', 'N/A'))],
        ['Unique IPs', str(data.get('unique_ips', 'N/A'))]
    ]
    table = Table(summary_data, colWidths=[150, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("<b>Top Threat IPs:</b>", styles['Heading2']))
    top_threat_data = [[ip, str(count)] for ip, count in data.get('top_threats', {}).items()]
    if top_threat_data:
        table = Table([['IP Address', 'Threat Count']] + top_threat_data, colWidths=[250, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        # Generate and embed threat pie chart
        chart_path = os.path.join(output_path, "threat_chart.png")
        if generate_chart(data['top_threats'], chart_path):
            elements.append(Image(chart_path, width=400, height=300))
            elements.append(Spacer(1, 20))

    elements.append(Paragraph("<b>AI Predicted Threat IPs:</b>", styles['Heading2']))
    ai_threat_data = [[ip, str(score)] for ip, score in data.get('ai_threats', {}).items()]
    if ai_threat_data:
        table = Table([['IP Address', 'AI Risk Score']] + ai_threat_data, colWidths=[250, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ]))
        elements.append(table)

    doc.build(elements)
    return filename
