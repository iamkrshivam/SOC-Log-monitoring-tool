from datetime import datetime, timedelta
from collections import defaultdict
from flask import current_app

from .models import db, NetworkLog, Alert, Device
from .log_parser import _create_alert


def run_ddos_detection():
    """Detect DDoS-like behavior from recent traffic data."""
    window_seconds = current_app.config.get('DDOS_WINDOW_SECONDS', 60)
    conn_threshold = current_app.config.get('DDOS_CONNECTION_THRESHOLD', 500)
    syn_threshold = current_app.config.get('DDOS_SYN_THRESHOLD', 300)

    cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)

    # Query recent network logs
    recent_logs = NetworkLog.query.filter(NetworkLog.timestamp >= cutoff).all()

    if not recent_logs:
        return

    # Count connections per source IP
    ip_conn_count = defaultdict(int)
    ip_syn_count = defaultdict(int)
    ip_traffic_bytes = defaultdict(int)

    for log in recent_logs:
        if log.src_ip:
            ip_conn_count[log.src_ip] += 1
            ip_traffic_bytes[log.src_ip] += (log.bytes_sent or 0)
            # SYN detection: short duration + small bytes = likely SYN
            if log.conn_state in ('S0', 'S1', 'REJ') or (log.duration and log.duration < 0.1):
                ip_syn_count[log.src_ip] += 1

    flagged = []

    for ip, count in ip_conn_count.items():
        if count >= conn_threshold:
            severity = 'High' if count >= conn_threshold * 2 else 'Medium'
            desc = (f"High connection rate detected: {count} connections in {window_seconds}s "
                    f"(threshold: {conn_threshold})")
            _ensure_device(ip)
            _create_alert(ip, 'DDoS Behavior', severity, desc, proto='TCP')
            flagged.append(ip)
            current_app.logger.warning(f"DDoS detected from {ip}: {count} connections")

    for ip, count in ip_syn_count.items():
        if count >= syn_threshold and ip not in flagged:
            desc = (f"High SYN packet rate: {count} SYN packets in {window_seconds}s "
                    f"(threshold: {syn_threshold})")
            _ensure_device(ip)
            _create_alert(ip, 'DDoS Behavior', 'High', desc, proto='TCP')
            flagged.append(ip)
            current_app.logger.warning(f"SYN flood detected from {ip}: {count} SYNs")

    if flagged:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"DDoS detection DB error: {e}")


def _ensure_device(ip_address):
    """Make sure device exists before creating alert."""
    device = Device.query.filter_by(ip_address=ip_address).first()
    if not device:
        device = Device(ip_address=ip_address, first_seen=datetime.utcnow())
        db.session.add(device)
        db.session.flush()
    return device


def get_traffic_spike_summary(minutes=60):
    """Return per-minute traffic counts for spike visualization."""
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    logs = NetworkLog.query.filter(NetworkLog.timestamp >= cutoff).all()

    minute_counts = defaultdict(int)
    for log in logs:
        if log.timestamp:
            key = log.timestamp.strftime('%H:%M')
            minute_counts[key] += 1

    return dict(sorted(minute_counts.items()))
