import os
import re
import json
from datetime import datetime
from flask import current_app

from .models import db, Device, Alert, NetworkLog, DnsLog
from .risk_engine import calculate_risk_score

# Known malicious domains (sample - in production, load from threat intel feed)
MALICIOUS_DOMAINS = {
    'malware.example.com', 'c2.badactor.net', 'phish.test.org',
    'botnet.evil.com', 'trojan.domain.ru'
}

# Suspicious ports
SUSPICIOUS_PORTS = {4444, 1337, 31337, 8080, 9090, 12345, 6666}


def _get_or_create_device(ip_address):
    """Get existing device or create new one."""
    device = Device.query.filter_by(ip_address=ip_address).first()
    if not device:
        device = Device(ip_address=ip_address, first_seen=datetime.utcnow())
        db.session.add(device)
        db.session.flush()
    device.last_seen = datetime.utcnow()
    return device


def parse_zeek_conn_log(log_path=None):
    """Parse Zeek conn.log and store network connections."""
    if log_path is None:
        log_path = current_app.config.get('ZEEK_LOG_PATH', '/opt/zeek/logs/current/conn.log')

    if not os.path.exists(log_path):
        current_app.logger.info(f"Zeek log not found: {log_path}")
        return 0

    parsed = 0
    try:
        with open(log_path, 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.strip().split('\t')
                if len(parts) < 20:
                    continue
                try:
                    ts = float(parts[0])
                    src_ip = parts[2]
                    src_port = int(parts[3]) if parts[3].isdigit() else None
                    dst_ip = parts[4]
                    dst_port = int(parts[5]) if parts[5].isdigit() else None
                    proto = parts[6]
                    service = parts[7] if parts[7] != '-' else None
                    duration = float(parts[8]) if parts[8] != '-' else 0.0
                    orig_bytes = int(parts[9]) if parts[9].isdigit() else 0
                    resp_bytes = int(parts[10]) if parts[10].isdigit() else 0
                    conn_state = parts[11]

                    # Validate IPs
                    if not src_ip or not dst_ip:
                        continue

                    # Store log
                    log_entry = NetworkLog(
                        timestamp=datetime.utcfromtimestamp(ts),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=proto,
                        duration=duration,
                        bytes_sent=orig_bytes,
                        bytes_received=resp_bytes,
                        conn_state=conn_state,
                        service=service
                    )
                    db.session.add(log_entry)

                    # Update device
                    device = _get_or_create_device(src_ip)
                    device.total_connections += 1
                    device.bytes_sent += orig_bytes
                    device.bytes_received += resp_bytes

                    # Check suspicious ports
                    if dst_port in SUSPICIOUS_PORTS:
                        _create_alert(src_ip, 'Suspicious Outbound', 'Medium',
                                      f"Connection to suspicious port {dst_port} on {dst_ip}",
                                      src_port, dst_ip, dst_port, proto)
                    parsed += 1

                except (ValueError, IndexError):
                    continue

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error parsing Zeek conn log: {e}")

    return parsed


def parse_zeek_dns_log(log_path=None):
    """Parse Zeek dns.log for malicious domain lookups."""
    if log_path is None:
        base = os.path.dirname(current_app.config.get('ZEEK_LOG_PATH', '/opt/zeek/logs/current/conn.log'))
        log_path = os.path.join(base, 'dns.log')

    if not os.path.exists(log_path):
        return 0

    parsed = 0
    try:
        with open(log_path, 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.strip().split('\t')
                if len(parts) < 10:
                    continue
                try:
                    ts = float(parts[0])
                    src_ip = parts[2]
                    query = parts[9] if parts[9] != '-' else ''
                    qtype = parts[13] if len(parts) > 13 else 'A'
                    rcode = parts[15] if len(parts) > 15 else 'NOERROR'

                    is_malicious = query.lower() in MALICIOUS_DOMAINS

                    dns_entry = DnsLog(
                        timestamp=datetime.utcfromtimestamp(ts),
                        src_ip=src_ip,
                        query=query,
                        query_type=qtype,
                        response_code=rcode,
                        is_malicious=is_malicious,
                        category='malware' if is_malicious else 'normal'
                    )
                    db.session.add(dns_entry)

                    if is_malicious:
                        _get_or_create_device(src_ip)
                        _create_alert(src_ip, 'Malware Domain', 'High',
                                      f"DNS query for known malicious domain: {query}",
                                      None, None, 53, 'UDP')
                    parsed += 1

                except (ValueError, IndexError):
                    continue

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error parsing Zeek DNS log: {e}")

    return parsed


def parse_suricata_fast_log(log_path=None):
    """Parse Suricata fast.log for IDS alerts."""
    if log_path is None:
        log_path = current_app.config.get('SURICATA_LOG_PATH', '/var/log/suricata/fast.log')

    if not os.path.exists(log_path):
        current_app.logger.info(f"Suricata log not found: {log_path}")
        return 0

    # Pattern: MM/DD/YYYY-HH:MM:SS.uuuuuu  [**] [gid:sid:rev] msg [**] [Classification: x] [Priority: n] {PROTO} src_ip:port -> dst_ip:port
    pattern = re.compile(
        r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\].*?\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)'
    )

    ALERT_TYPE_MAP = {
        'scan': 'Port Scan',
        'port scan': 'Port Scan',
        'brute': 'Brute Force',
        'brute force': 'Brute Force',
        'ssh': 'Brute Force',
        'malware': 'Malware Domain',
        'trojan': 'Malware Domain',
        'arp': 'ARP Spoofing',
        'spoof': 'ARP Spoofing',
        'suspicious': 'Suspicious Outbound',
        'c2': 'Suspicious Outbound',
        'command': 'Suspicious Outbound',
    }

    SEVERITY_MAP = {
        'Port Scan': 'Medium',
        'Brute Force': 'High',
        'Malware Domain': 'High',
        'ARP Spoofing': 'Critical',
        'Suspicious Outbound': 'Medium',
    }

    parsed = 0
    try:
        with open(log_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                m = pattern.match(line)
                if not m:
                    continue
                try:
                    ts_str, msg, proto, src_ip, src_port, dst_ip, dst_port = m.groups()
                    ts = datetime.strptime(ts_str.split('.')[0], '%m/%d/%Y-%H:%M:%S')

                    # Classify alert type
                    alert_type = 'Suspicious Outbound'
                    msg_lower = msg.lower()
                    for keyword, atype in ALERT_TYPE_MAP.items():
                        if keyword in msg_lower:
                            alert_type = atype
                            break

                    severity = SEVERITY_MAP.get(alert_type, 'Medium')

                    _get_or_create_device(src_ip)
                    _create_alert(src_ip, alert_type, severity, msg,
                                  int(src_port), dst_ip, int(dst_port), proto,
                                  raw_data=line)
                    parsed += 1

                except (ValueError, IndexError):
                    continue

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error parsing Suricata log: {e}")

    return parsed


def _create_alert(src_ip, alert_type, severity, description,
                  src_port=None, dst_ip=None, dst_port=None, proto=None, raw_data=None):
    """Create an alert record."""
    # Avoid duplicate alerts in last 5 minutes
    from datetime import timedelta
    recent = Alert.query.filter_by(
        device_ip=src_ip,
        alert_type=alert_type,
    ).filter(Alert.timestamp >= datetime.utcnow() - timedelta(minutes=5)).first()

    if recent:
        return recent

    alert = Alert(
        device_ip=src_ip,
        alert_type=alert_type,
        severity=severity,
        description=description,
        source_port=src_port,
        dest_ip=dst_ip,
        dest_port=dst_port,
        protocol=proto,
        raw_data=raw_data,
        status='Open'
    )
    db.session.add(alert)
    db.session.flush()

    # Update risk score
    try:
        calculate_risk_score(src_ip)
    except Exception:
        pass

    return alert


def parse_and_store_logs():
    """Main entry point to parse all logs."""
    zeek_parsed = parse_zeek_conn_log()
    dns_parsed = parse_zeek_dns_log()
    suricata_parsed = parse_suricata_fast_log()

    try:
        from flask import current_app
        current_app.logger.info(f"Log parse complete: Zeek={zeek_parsed}, DNS={dns_parsed}, Suricata={suricata_parsed}")
    except Exception:
        pass
