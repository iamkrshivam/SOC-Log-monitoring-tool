import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'campus-soc-change-this-in-production-2024')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'sqlite:///{BASE_DIR}/campus_soc.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Network
    ALLOWED_SUBNET = os.environ.get('ALLOWED_SUBNET', '10.0.0.0/8')
    BYPASS_SUBNET_CHECK = os.environ.get('BYPASS_SUBNET_CHECK', 'false').lower() == 'true'

    # Log paths
    ZEEK_LOG_PATH = os.environ.get('ZEEK_LOG_PATH', '/opt/zeek/logs/current/conn.log')
    SURICATA_LOG_PATH = os.environ.get('SURICATA_LOG_PATH', '/var/log/suricata/fast.log')
    AUDIT_LOG_PATH = os.path.join(BASE_DIR, 'logs', 'audit.log')
    BACKUP_PATH = os.path.join(BASE_DIR, 'backups')

    # Retention
    LOG_RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS', 7))

    # DDoS thresholds
    DDOS_CONNECTION_THRESHOLD = int(os.environ.get('DDOS_CONNECTION_THRESHOLD', 500))
    DDOS_SYN_THRESHOLD = int(os.environ.get('DDOS_SYN_THRESHOLD', 300))
    DDOS_WINDOW_SECONDS = int(os.environ.get('DDOS_WINDOW_SECONDS', 60))

    # Rate limiting
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URL = "memory://"


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    BYPASS_SUBNET_CHECK = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
