import os
import shutil
import gzip
from datetime import datetime, timedelta
from flask import current_app

from .models import db, NetworkLog, Alert, DnsLog, AuditLog, RetentionPolicy
from .audit_logger import log_audit


def get_retention_policy():
    """Get current retention policy from DB."""
    policy = RetentionPolicy.query.first()
    if not policy:
        policy = RetentionPolicy(retention_days=7, auto_cleanup_enabled=True)
        db.session.add(policy)
        db.session.commit()
    return policy


def archive_old_logs(cutoff_date, backup_dir):
    """Archive old records to a compressed file."""
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    archive_path = os.path.join(backup_dir, f'log_archive_{timestamp}.txt.gz')

    old_logs = NetworkLog.query.filter(NetworkLog.timestamp < cutoff_date).all()
    old_alerts = Alert.query.filter(Alert.timestamp < cutoff_date).all()

    with gzip.open(archive_path, 'wt') as f:
        f.write(f"# CampusSOC Archive - {timestamp}\n")
        f.write(f"# Cutoff: {cutoff_date}\n\n")

        f.write("## NETWORK LOGS\n")
        for log in old_logs:
            f.write(f"{log.timestamp} | {log.src_ip}:{log.src_port} -> {log.dst_ip}:{log.dst_port} "
                    f"| {log.protocol} | {log.bytes_sent}B/{log.bytes_received}B\n")

        f.write("\n## ALERTS\n")
        for alert in old_alerts:
            f.write(f"{alert.timestamp} | {alert.alert_type} | {alert.severity} | "
                    f"{alert.device_ip} | {alert.description}\n")

    return archive_path, len(old_logs), len(old_alerts)


def run_weekly_cleanup():
    """Scheduled weekly log cleanup."""
    policy = get_retention_policy()
    if not policy.auto_cleanup_enabled:
        current_app.logger.info("Auto cleanup disabled, skipping.")
        return

    retention_days = policy.retention_days
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    backup_dir = current_app.config.get('BACKUP_PATH',
                                         os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backups'))

    try:
        # Archive first
        archive_path, net_count, alert_count = archive_old_logs(cutoff_date, backup_dir)
        current_app.logger.info(f"Archived {net_count} net logs, {alert_count} alerts to {archive_path}")

        # Delete old records
        NetworkLog.query.filter(NetworkLog.timestamp < cutoff_date).delete()
        DnsLog.query.filter(DnsLog.timestamp < cutoff_date).delete()
        Alert.query.filter(Alert.timestamp < cutoff_date, Alert.status.in_(['Resolved', 'False Positive'])).delete()

        policy.last_cleanup = datetime.utcnow()
        db.session.commit()

        log_audit('SYSTEM', 'AUTO_CLEANUP', f"Deleted logs older than {retention_days} days. "
                                             f"Archived {net_count} net logs, {alert_count} alerts.", 'scheduler')
        current_app.logger.info("Weekly cleanup completed.")

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Cleanup error: {e}")


def manual_cleanup(username, client_ip, retention_days=None):
    """SuperAdmin manual log deletion."""
    policy = get_retention_policy()
    if retention_days is None:
        retention_days = policy.retention_days

    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    backup_dir = current_app.config.get('BACKUP_PATH',
                                         os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backups'))

    archive_path, net_count, alert_count = archive_old_logs(cutoff_date, backup_dir)

    NetworkLog.query.filter(NetworkLog.timestamp < cutoff_date).delete()
    DnsLog.query.filter(DnsLog.timestamp < cutoff_date).delete()
    Alert.query.filter(Alert.timestamp < cutoff_date, Alert.status.in_(['Resolved', 'False Positive'])).delete()

    policy.last_cleanup = datetime.utcnow()
    db.session.commit()

    log_audit(username, 'MANUAL_CLEANUP',
              f"Manual deletion: removed logs older than {retention_days} days. "
              f"Archived {net_count} net logs, {alert_count} alerts.",
              client_ip)

    return net_count, alert_count, archive_path


def clean_old_backups(max_backups=10):
    """Keep only the most recent N backups."""
    backup_dir = current_app.config.get('BACKUP_PATH',
                                         os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backups'))
    if not os.path.exists(backup_dir):
        return

    files = sorted(
        [f for f in os.listdir(backup_dir) if f.endswith('.gz')],
        reverse=True
    )

    for old_file in files[max_backups:]:
        os.remove(os.path.join(backup_dir, old_file))
