import logging
import os
from datetime import datetime
from flask import current_app

# Setup file-based audit logger
def get_audit_file_logger():
    logger = logging.getLogger('campus_soc_audit')
    if not logger.handlers:
        logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        handler = logging.FileHandler(os.path.join(logs_dir, 'audit.log'))
        handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def log_audit(username, action, detail='', ip_address='', status='Success'):
    """Log audit event to both database and file."""
    # File log (always works)
    try:
        file_logger = get_audit_file_logger()
        file_logger.info(f"USER={username} | ACTION={action} | DETAIL={detail} | IP={ip_address} | STATUS={status}")
    except Exception:
        pass

    # Database log
    try:
        from .models import db, AuditLog
        entry = AuditLog(
            username=username,
            action=action,
            detail=detail,
            ip_address=ip_address,
            status=status,
            timestamp=datetime.utcnow()
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        try:
            current_app.logger.error(f"Failed to write audit log to DB: {e}")
        except Exception:
            pass
