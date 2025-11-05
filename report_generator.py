import whois
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from io import BytesIO
import json
import datetime

def get_whois_info(domain):
    """
    Fetch WHOIS data for domain.
    Returns: dict with registrar, creation_date, abuse_contact, etc.
    """
    try:
        w = whois.whois(domain)
        return {
            'domain': domain,
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'updated_date': w.updated_date,
            'expiration_date': w.expiration_date,
            'abuse_contact': getattr(w, 'abuse_contact', None) or getattr(w, 'emails', [None])[0],
            'hoster': getattr(w, 'registrar', 'Unknown'),
            'name_servers': getattr(w, 'name_servers', [])
        }
    except Exception as e:
        return {'domain': domain, 'error': str(e)}

def generate_takedown_report(scan_data, output_path=None):
    """
    Generate PDF takedown report with evidence, timestamps, WHOIS, abuse contacts.
    scan_data: dict from scan result (url, score, reasons, features, feeds, timestamp)
    Returns: BytesIO for file or saves to path.
    """
    if output_path:
        doc = SimpleDocTemplate(output_path, pagesize=letter)
    else:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        buffer.seek(0)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CustomTitle', fontSize=18, alignment=1, spaceAfter=30))
    styles.add(ParagraphStyle(name='CustomHeading', fontSize=14, spaceAfter=12))
    styles.add(ParagraphStyle(name='CustomBody', fontSize=10, spaceAfter=6))

    story = []

    # Title
    title = Paragraph("PhishGuard Takedown Report", styles['CustomTitle'])
    story.append(title)
    story.append(Spacer(1, 0.2 * inch))

    # Report Info
    report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info_table = Table([
        ['Report Generated:', report_date],
        ['Target URL:', scan_data.get('url', 'Unknown')],
        ['Phishing Score:', f"{scan_data.get('score', 0):.2f}"],
        ['Confidence:', f"{scan_data.get('confidence', 0):.2f}%"],
        ['Classification:', 'Phishing' if scan_data.get('phishing', False) else 'Suspicious']
    ], colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.3 * inch))

    # Evidence: Reasons
    story.append(Paragraph("Detection Evidence", styles['CustomHeading']))
    reasons = scan_data.get('reason_codes', [])
    if reasons:
        reasons_list = Paragraph('<br/>'.join([f"• {r}" for r in reasons]), styles['CustomBody'])
        story.append(reasons_list)
    else:
        story.append(Paragraph("No specific reasons recorded.", styles['CustomBody']))
    story.append(Spacer(1, 0.2 * inch))

    # Features Summary
    story.append(Paragraph("Key Features Analyzed", styles['CustomHeading']))
    features = json.loads(scan_data.get('features', '{}'))
    feature_table_data = [['Feature', 'Value', 'Risk Level']]
    for key, value in list(features.items())[:10]:  # Top 10
        risk = 'High' if isinstance(value, (int, float)) and value > 0.5 else 'Low'  # Simplified
        feature_table_data.append([key, str(value), risk])
    feature_table = Table(feature_table_data, colWidths=[1.5*inch, 2*inch, 1.5*inch])
    feature_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(feature_table)
    story.append(Spacer(1, 0.2 * inch))

    # Threat Feeds
    story.append(Paragraph("Threat Intelligence Feeds", styles['CustomHeading']))
    feeds = json.loads(scan_data.get('feeds_data', '[]'))
    if feeds:
        feed_table_data = [['Feed', 'Status', 'Timestamp']]
        for feed in feeds:
            status = 'Blocked' if feed.get('data', {}).get('phishing') or feed.get('data', {}).get('threat_type') else 'Clean'
            ts = datetime.datetime.fromtimestamp(feed['data'].get('timestamp', 0)).strftime("%Y-%m-%d %H:%M:%S")
            feed_table_data.append([feed['name'], status, ts])
        feed_table = Table(feed_table_data, colWidths=[2*inch, 2*inch, 2*inch])
        feed_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(feed_table)
    else:
        story.append(Paragraph("No feed data available.", styles['CustomBody']))
    story.append(Spacer(1, 0.2 * inch))

    # WHOIS and Abuse Contacts
    story.append(Paragraph("Domain WHOIS Information", styles['CustomHeading']))
    domain = urlparse(scan_data.get('url', '')).netloc
    whois_info = get_whois_info(domain)
    whois_table_data = [['Field', 'Value']]
    for key, value in whois_info.items():
        if key != 'error':
            whois_table_data.append([key.replace('_', ' ').title(), str(value)])
    whois_table = Table(whois_table_data, colWidths=[2*inch, 4*inch])
    whois_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(whois_table)

    # Abuse Contact Highlight
    if whois_info.get('abuse_contact'):
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(f"<b>Recommended Action:</b> Contact abuse team at {whois_info['abuse_contact']} to report phishing.", styles['CustomBody']))

    story.append(Spacer(1, 0.3 * inch))

    # Footer
    footer = Paragraph("Generated by PhishGuard - Do not share without authorization.", styles['CustomBody'])
    story.append(footer)

    doc.build(story)

    if output_path:
        return True
    else:
        return buffer

def submit_report(scan_data, email_to=None):
    """
    Optional: Submit report via email (requires smtplib config).
    For now, placeholder - implement with user SMTP details.
    """
    if not email_to:
        return {'status': 'Submission not configured', 'message': 'Email submission requires SMTP setup.'}
    
    # Placeholder: In production, use smtplib to send PDF attachment
    return {'status': 'Submitted', 'message': f'Report sent to {email_to}'}  # Simulate
