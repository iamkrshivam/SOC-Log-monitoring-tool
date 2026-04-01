import os
import io
from datetime import datetime, timedelta

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from .models import db, Device, Alert, NetworkLog, AuditLog


def generate_weekly_report():
    """Generate a weekly PDF security report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
        title="CampusSOC Weekly Security Report"
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#1a2332'),
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#6c757d'),
        spaceAfter=20,
        alignment=TA_CENTER
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#0d6efd'),
        spaceBefore=20,
        spaceAfter=8,
        fontName='Helvetica-Bold'
    )
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=4
    )
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.grey,
        alignment=TA_CENTER
    )

    story = []
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    # Header / Title Block
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("CampusSOC", title_style))
    story.append(Paragraph("Weekly Security Monitoring Report", subtitle_style))
    story.append(Paragraph(
        f"Report Period: {week_ago.strftime('%B %d, %Y')} – {now.strftime('%B %d, %Y')} (UTC)",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0d6efd')))
    story.append(Spacer(1, 0.2*inch))

    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))

    total_devices = Device.query.count()
    total_alerts = Alert.query.filter(Alert.timestamp >= week_ago).count()
    high_risk = Device.query.filter_by(risk_level='High').count()
    medium_risk = Device.query.filter_by(risk_level='Medium').count()
    open_alerts = Alert.query.filter_by(status='Open').count()
    resolved_alerts = Alert.query.filter(Alert.timestamp >= week_ago, Alert.status == 'Resolved').count()

    summary_data = [
        ['Metric', 'Value'],
        ['Total Devices Monitored', str(total_devices)],
        ['Total Alerts This Week', str(total_alerts)],
        ['Open Alerts', str(open_alerts)],
        ['Resolved Alerts', str(resolved_alerts)],
        ['High-Risk Devices', str(high_risk)],
        ['Medium-Risk Devices', str(medium_risk)],
    ]

    summary_table = Table(summary_data, colWidths=[3.5*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d6efd')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.2*inch))

    # Alert Breakdown by Type
    story.append(Paragraph("Alert Breakdown by Type", heading_style))

    from sqlalchemy import func
    alert_types = db.session.query(
        Alert.alert_type,
        func.count(Alert.id).label('count')
    ).filter(Alert.timestamp >= week_ago).group_by(Alert.alert_type).all()

    if alert_types:
        at_data = [['Alert Type', 'Count', 'Severity']]
        severity_map = {
            'Port Scan': 'Medium', 'Brute Force': 'High',
            'Malware Domain': 'High', 'ARP Spoofing': 'Critical',
            'Suspicious Outbound': 'Medium', 'DDoS Behavior': 'High'
        }
        for at, count in alert_types:
            at_data.append([at, str(count), severity_map.get(at, 'Medium')])

        at_table = Table(at_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        at_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#343a40')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(at_table)
    else:
        story.append(Paragraph("No alerts recorded this week.", normal_style))

    story.append(Spacer(1, 0.2*inch))

    # High-Risk Devices
    story.append(Paragraph("High-Risk Devices", heading_style))

    high_risk_devices = Device.query.filter_by(risk_level='High').order_by(Device.risk_score.desc()).limit(10).all()
    if high_risk_devices:
        hr_data = [['IP Address', 'Risk Score', 'Last Seen', 'Total Connections']]
        for d in high_risk_devices:
            hr_data.append([
                d.ip_address,
                str(d.risk_score),
                d.last_seen.strftime('%Y-%m-%d %H:%M') if d.last_seen else 'N/A',
                str(d.total_connections)
            ])

        hr_table = Table(hr_data, colWidths=[2*inch, 1.2*inch, 2*inch, 1.5*inch])
        hr_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc3545')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fff5f5'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(hr_table)
    else:
        story.append(Paragraph("No high-risk devices detected this week.", normal_style))

    story.append(Spacer(1, 0.2*inch))

    # Top DNS Queries
    story.append(Paragraph("Top DNS Queries", heading_style))

    from .models import DnsLog
    from sqlalchemy import func as sqlfunc
    top_dns = db.session.query(
        DnsLog.query.label('domain'),
        sqlfunc.count(DnsLog.id).label('count')
    ).filter(DnsLog.timestamp >= week_ago).group_by(DnsLog.query).order_by(
        sqlfunc.count(DnsLog.id).desc()
    ).limit(10).all()

    if top_dns:
        dns_data = [['Domain', 'Query Count', 'Malicious']]
        for row in top_dns:
            is_mal = DnsLog.query.filter_by(query=row.domain, is_malicious=True).first()
            dns_data.append([row.domain or 'N/A', str(row.count), 'YES' if is_mal else 'No'])

        dns_table = Table(dns_data, colWidths=[3.5*inch, 1.5*inch, 1.5*inch])
        dns_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6610f2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(dns_table)
    else:
        story.append(Paragraph("No DNS data available this week.", normal_style))

    story.append(Spacer(1, 0.2*inch))

    # Threat Summary
    story.append(Paragraph("Threat Summary & Recommendations", heading_style))

    threat_text = []
    if high_risk > 0:
        threat_text.append(f"• <b>{high_risk} high-risk device(s)</b> detected. Immediate investigation recommended.")
    if total_alerts > 0:
        critical = Alert.query.filter(Alert.timestamp >= week_ago, Alert.severity == 'Critical').count()
        if critical > 0:
            threat_text.append(f"• <b>{critical} CRITICAL alert(s)</b> logged — priority response required.")
    if not threat_text:
        threat_text.append("• No significant threats detected this week. Continue monitoring.")

    threat_text.append("• Ensure all endpoint devices are running up-to-date antivirus software.")
    threat_text.append("• Review and update firewall rules quarterly.")
    threat_text.append("• Conduct user security awareness training regularly.")

    for t in threat_text:
        story.append(Paragraph(t, normal_style))

    story.append(Spacer(1, 0.3*inch))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dee2e6')))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(
        f"Generated by CampusSOC | {now.strftime('%Y-%m-%d %H:%M:%S')} UTC | CONFIDENTIAL",
        footer_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer
