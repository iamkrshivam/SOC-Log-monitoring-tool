from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')  # superadmin, analyst, viewer
    force_password_change = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} [{self.role}]>'


class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    mac_address = db.Column(db.String(20))
    hostname = db.Column(db.String(128))
    device_type = db.Column(db.String(64))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(10), default='Safe')  # Safe, Medium, High
    total_connections = db.Column(db.Integer, default=0)
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_received = db.Column(db.BigInteger, default=0)
    is_flagged = db.Column(db.Boolean, default=False)
    alerts = db.relationship('Alert', backref='device', lazy='dynamic', foreign_keys='Alert.device_ip',
                             primaryjoin='Device.ip_address==Alert.device_ip')

    def __repr__(self):
        return f'<Device {self.ip_address} [{self.risk_level}]>'


class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    device_ip = db.Column(db.String(45), db.ForeignKey('devices.ip_address'), nullable=False, index=True)
    alert_type = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(10), nullable=False)  # Low, Medium, High, Critical
    description = db.Column(db.Text)
    source_port = db.Column(db.Integer)
    dest_ip = db.Column(db.String(45))
    dest_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    status = db.Column(db.String(20), default='Open')  # Open, Investigating, Resolved, False Positive
    assigned_to = db.Column(db.String(64))
    resolved_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    raw_data = db.Column(db.Text)

    def __repr__(self):
        return f'<Alert {self.alert_type} [{self.severity}] {self.device_ip}>'


class NetworkLog(db.Model):
    __tablename__ = 'network_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    duration = db.Column(db.Float)
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_received = db.Column(db.BigInteger, default=0)
    conn_state = db.Column(db.String(10))
    service = db.Column(db.String(32))

    def __repr__(self):
        return f'<NetworkLog {self.src_ip}->{self.dst_ip}>'


class DnsLog(db.Model):
    __tablename__ = 'dns_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    query = db.Column(db.String(256))
    query_type = db.Column(db.String(10))
    response_code = db.Column(db.String(20))
    is_malicious = db.Column(db.Boolean, default=False)
    category = db.Column(db.String(64))

    def __repr__(self):
        return f'<DnsLog {self.src_ip} -> {self.query}>'


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    username = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(128), nullable=False)
    detail = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    status = db.Column(db.String(20), default='Success')  # Success, Failed

    def __repr__(self):
        return f'<AuditLog {self.username}: {self.action}>'


class RetentionPolicy(db.Model):
    __tablename__ = 'retention_policy'
    id = db.Column(db.Integer, primary_key=True)
    retention_days = db.Column(db.Integer, default=7)
    auto_cleanup_enabled = db.Column(db.Boolean, default=True)
    last_cleanup = db.Column(db.DateTime)
    updated_by = db.Column(db.String(64))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<RetentionPolicy {self.retention_days} days>'


class TrafficStats(db.Model):
    __tablename__ = 'traffic_stats'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    total_connections = db.Column(db.Integer, default=0)
    total_bytes = db.Column(db.BigInteger, default=0)
    unique_devices = db.Column(db.Integer, default=0)
    alert_count = db.Column(db.Integer, default=0)
    high_risk_count = db.Column(db.Integer, default=0)
    interval_minutes = db.Column(db.Integer, default=5)
