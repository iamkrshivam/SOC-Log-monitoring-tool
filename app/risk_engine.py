from .models import db, Device, Alert


RISK_WEIGHTS = {
    'Port Scan': 30,
    'Brute Force': 35,
    'Malware Domain': 50,
    'Suspicious Outbound': 25,
    'ARP Spoofing': 40,
    'DDoS Behavior': 60,
    'Multiple Alerts': 20,
}

RISK_LEVELS = [
    (0, 20, 'Safe'),
    (21, 60, 'Medium'),
    (61, float('inf'), 'High'),
]


def calculate_risk_score(device_ip):
    """Calculate and update risk score for a device."""
    device = Device.query.filter_by(ip_address=device_ip).first()
    if not device:
        return 0

    alerts = Alert.query.filter_by(device_ip=device_ip, status='Open').all()
    score = 0

    alert_types_seen = set()
    for alert in alerts:
        weight = RISK_WEIGHTS.get(alert.alert_type, 10)
        score += weight
        alert_types_seen.add(alert.alert_type)

    # Bonus for multiple distinct alert types
    if len(alert_types_seen) > 2:
        score += RISK_WEIGHTS['Multiple Alerts']

    # Cap at 100
    score = min(score, 100)

    # Determine level
    risk_level = 'Safe'
    for low, high, level in RISK_LEVELS:
        if low <= score <= high:
            risk_level = level
            break

    device.risk_score = score
    device.risk_level = risk_level
    device.is_flagged = risk_level in ('Medium', 'High')
    db.session.commit()

    return score


def recalculate_all_devices():
    """Recalculate risk scores for all devices."""
    devices = Device.query.all()
    for device in devices:
        calculate_risk_score(device.ip_address)


def get_risk_badge_class(risk_level):
    """Return Bootstrap badge class for risk level."""
    return {
        'Safe': 'success',
        'Medium': 'warning',
        'High': 'danger',
    }.get(risk_level, 'secondary')


def get_risk_color(risk_level):
    """Return color hex for risk level."""
    return {
        'Safe': '#28a745',
        'Medium': '#ffc107',
        'High': '#dc3545',
    }.get(risk_level, '#6c757d')
