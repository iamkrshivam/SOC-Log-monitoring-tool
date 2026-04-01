import os
from datetime import datetime, timedelta
from functools import wraps

from flask import (Blueprint, render_template, redirect, url_for, flash,
                   request, jsonify, send_file, abort, current_app)
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, NumberRange
from sqlalchemy import func

from .models import db, Device, Alert, NetworkLog, DnsLog, AuditLog, User, RetentionPolicy
from .risk_engine import recalculate_all_devices, get_risk_badge_class
from .report_generator import generate_weekly_report
from .cleanup_manager import manual_cleanup, get_retention_policy
from .audit_logger import log_audit
from .subnet_guard import check_subnet
from . import limiter

main_bp = Blueprint('main', __name__)


# ─── Role Decorators ──────────────────────────────────────────────────────────

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if current_user.role not in roles:
                flash('Insufficient permissions.', 'danger')
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

superadmin_required = role_required('superadmin')
analyst_required = role_required('superadmin', 'analyst')


# ─── Before Request: Subnet Check ─────────────────────────────────────────────

@main_bp.before_request
def subnet_check():
    return check_subnet(current_app)


# ─── Error Handlers ───────────────────────────────────────────────────────────

@main_bp.app_errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@main_bp.app_errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


# ─── Dashboard ────────────────────────────────────────────────────────────────

@main_bp.route('/')
@main_bp.route('/dashboard')
@login_required
def dashboard():
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    day_ago = now - timedelta(hours=24)

    stats = {
        'total_devices': Device.query.count(),
        'total_alerts': Alert.query.count(),
        'open_alerts': Alert.query.filter_by(status='Open').count(),
        'high_risk': Device.query.filter_by(risk_level='High').count(),
        'medium_risk': Device.query.filter_by(risk_level='Medium').count(),
        'alerts_today': Alert.query.filter(Alert.timestamp >= day_ago).count(),
        'alerts_week': Alert.query.filter(Alert.timestamp >= week_ago).count(),
        'critical_alerts': Alert.query.filter_by(severity='Critical', status='Open').count(),
    }

    # Recent alerts
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()

    # Top risk devices
    top_devices = Device.query.order_by(Device.risk_score.desc()).limit(5).all()

    # Alert trend (last 24h by hour)
    alert_trend = []
    for i in range(24):
        hour_start = now - timedelta(hours=24-i)
        hour_end = hour_start + timedelta(hours=1)
        count = Alert.query.filter(
            Alert.timestamp >= hour_start,
            Alert.timestamp < hour_end
        ).count()
        alert_trend.append({'hour': hour_start.strftime('%H:00'), 'count': count})

    # Alert type distribution
    alert_types = db.session.query(
        Alert.alert_type,
        func.count(Alert.id).label('count')
    ).group_by(Alert.alert_type).all()

    # Traffic last 60 min
    from .ddos_detector import get_traffic_spike_summary
    traffic_data = get_traffic_spike_summary(60)

    return render_template('dashboard.html',
                           stats=stats,
                           recent_alerts=recent_alerts,
                           top_devices=top_devices,
                           alert_trend=alert_trend,
                           alert_types=alert_types,
                           traffic_data=traffic_data,
                           get_risk_badge_class=get_risk_badge_class)


# ─── Devices ──────────────────────────────────────────────────────────────────

@main_bp.route('/devices')
@login_required
def devices():
    page = request.args.get('page', 1, type=int)
    risk_filter = request.args.get('risk', '')
    search = request.args.get('search', '')

    query = Device.query
    if risk_filter:
        query = query.filter_by(risk_level=risk_filter)
    if search:
        query = query.filter(Device.ip_address.contains(search) |
                             Device.hostname.contains(search))

    devices_page = query.order_by(Device.risk_score.desc()).paginate(page=page, per_page=25)
    return render_template('devices.html',
                           devices=devices_page,
                           risk_filter=risk_filter,
                           search=search,
                           get_risk_badge_class=get_risk_badge_class)


@main_bp.route('/devices/<int:device_id>')
@login_required
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    alerts = Alert.query.filter_by(device_ip=device.ip_address).order_by(Alert.timestamp.desc()).limit(50).all()
    return render_template('device_detail.html', device=device, alerts=alerts,
                           get_risk_badge_class=get_risk_badge_class)


# ─── Alerts ───────────────────────────────────────────────────────────────────

@main_bp.route('/alerts')
@login_required
@analyst_required
def alerts():
    page = request.args.get('page', 1, type=int)
    severity_filter = request.args.get('severity', '')
    status_filter = request.args.get('status', '')
    type_filter = request.args.get('type', '')

    query = Alert.query
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if type_filter:
        query = query.filter_by(alert_type=type_filter)

    alerts_page = query.order_by(Alert.timestamp.desc()).paginate(page=page, per_page=30)

    alert_types = db.session.query(Alert.alert_type).distinct().all()
    alert_types = [a[0] for a in alert_types]

    return render_template('alerts.html',
                           alerts=alerts_page,
                           severity_filter=severity_filter,
                           status_filter=status_filter,
                           type_filter=type_filter,
                           alert_types=alert_types)


@main_bp.route('/alerts/<int:alert_id>/update', methods=['POST'])
@login_required
@analyst_required
def update_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    new_status = request.form.get('status')
    notes = request.form.get('notes', '')

    valid_statuses = ['Open', 'Investigating', 'Resolved', 'False Positive']
    if new_status not in valid_statuses:
        flash('Invalid status.', 'danger')
        return redirect(url_for('main.alerts'))

    old_status = alert.status
    alert.status = new_status
    alert.notes = notes
    alert.assigned_to = current_user.username
    if new_status == 'Resolved':
        alert.resolved_at = datetime.utcnow()

    db.session.commit()
    log_audit(current_user.username, 'ALERT_UPDATE',
              f"Alert #{alert_id} status: {old_status} -> {new_status}", request.remote_addr)
    flash(f'Alert #{alert_id} updated to {new_status}.', 'success')
    return redirect(url_for('main.alerts'))


# ─── Reports ──────────────────────────────────────────────────────────────────

@main_bp.route('/reports')
@login_required
def reports():
    # List available backup archives
    backup_dir = current_app.config.get('BACKUP_PATH',
                                         os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backups'))
    archives = []
    if os.path.exists(backup_dir):
        for f in sorted(os.listdir(backup_dir), reverse=True):
            if f.endswith('.gz'):
                full_path = os.path.join(backup_dir, f)
                archives.append({
                    'name': f,
                    'size': os.path.getsize(full_path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(full_path))
                })

    return render_template('reports.html', archives=archives)


@main_bp.route('/reports/download-pdf')
@login_required
def download_report_pdf():
    log_audit(current_user.username, 'REPORT_DOWNLOAD', 'Weekly PDF report downloaded', request.remote_addr)
    try:
        buffer = generate_weekly_report()
        filename = f"campussoc_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
        return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')
    except Exception as e:
        current_app.logger.error(f"Report generation error: {e}")
        flash('Error generating report. Please try again.', 'danger')
        return redirect(url_for('main.reports'))


# ─── Settings (SuperAdmin only) ───────────────────────────────────────────────

@main_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@superadmin_required
def settings():
    policy = get_retention_policy()
    users = User.query.order_by(User.username).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_retention':
            new_days = request.form.get('retention_days', type=int)
            if new_days and 1 <= new_days <= 365:
                old_days = policy.retention_days
                policy.retention_days = new_days
                policy.updated_by = current_user.username
                policy.updated_at = datetime.utcnow()
                db.session.commit()
                log_audit(current_user.username, 'SETTINGS_CHANGE',
                          f"Retention policy changed: {old_days} -> {new_days} days", request.remote_addr)
                flash(f'Retention policy updated to {new_days} days.', 'success')
            else:
                flash('Invalid retention days (1-365).', 'danger')

        elif action == 'toggle_auto_cleanup':
            policy.auto_cleanup_enabled = not policy.auto_cleanup_enabled
            db.session.commit()
            state = 'enabled' if policy.auto_cleanup_enabled else 'disabled'
            log_audit(current_user.username, 'SETTINGS_CHANGE',
                      f"Auto cleanup {state}", request.remote_addr)
            flash(f'Auto cleanup {state}.', 'success')

        elif action == 'manual_cleanup':
            try:
                net_count, alert_count, archive_path = manual_cleanup(
                    current_user.username, request.remote_addr, policy.retention_days
                )
                flash(f'Manual cleanup complete. Archived {net_count} network logs and {alert_count} alerts.', 'success')
            except Exception as e:
                current_app.logger.error(f"Manual cleanup error: {e}")
                flash(f'Cleanup error: {e}', 'danger')

        elif action == 'recalculate_risk':
            recalculate_all_devices()
            log_audit(current_user.username, 'RISK_RECALC', 'Manual risk score recalculation', request.remote_addr)
            flash('Risk scores recalculated for all devices.', 'success')

        elif action == 'update_subnet':
            new_subnet = request.form.get('allowed_subnet', '').strip()
            if new_subnet:
                import ipaddress
                try:
                    ipaddress.ip_network(new_subnet, strict=False)
                    current_app.config['ALLOWED_SUBNET'] = new_subnet
                    log_audit(current_user.username, 'SETTINGS_CHANGE',
                              f"Allowed subnet changed to {new_subnet}", request.remote_addr)
                    flash(f'Allowed subnet updated to {new_subnet}.', 'success')
                except ValueError:
                    flash('Invalid subnet format.', 'danger')

        return redirect(url_for('main.settings'))

    return render_template('settings.html', policy=policy, users=users, audit_logs=audit_logs)


@main_bp.route('/settings/users/add', methods=['POST'])
@login_required
@superadmin_required
def add_user():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    role = request.form.get('role', 'viewer')
    password = request.form.get('password', '')

    if not username or not password:
        flash('Username and password are required.', 'danger')
        return redirect(url_for('main.settings'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'danger')
        return redirect(url_for('main.settings'))

    if role not in ('superadmin', 'analyst', 'viewer'):
        role = 'viewer'

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    log_audit(current_user.username, 'USER_CREATED',
              f"Created user '{username}' with role '{role}'", request.remote_addr)
    flash(f"User '{username}' created successfully.", 'success')
    return redirect(url_for('main.settings'))


@main_bp.route('/settings/users/<int:user_id>/role', methods=['POST'])
@login_required
@superadmin_required
def change_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')

    if new_role not in ('superadmin', 'analyst', 'viewer'):
        flash('Invalid role.', 'danger')
        return redirect(url_for('main.settings'))

    if user.id == current_user.id:
        flash('Cannot change your own role.', 'danger')
        return redirect(url_for('main.settings'))

    old_role = user.role
    user.role = new_role
    db.session.commit()
    log_audit(current_user.username, 'ROLE_CHANGE',
              f"User '{user.username}' role changed: {old_role} -> {new_role}", request.remote_addr)
    flash(f"Role for '{user.username}' updated to {new_role}.", 'success')
    return redirect(url_for('main.settings'))


@main_bp.route('/settings/users/<int:user_id>/deactivate', methods=['POST'])
@login_required
@superadmin_required
def deactivate_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot deactivate your own account.', 'danger')
        return redirect(url_for('main.settings'))
    user.is_active = not user.is_active
    db.session.commit()
    state = 'activated' if user.is_active else 'deactivated'
    log_audit(current_user.username, 'USER_STATUS',
              f"User '{user.username}' {state}", request.remote_addr)
    flash(f"User '{user.username}' {state}.", 'success')
    return redirect(url_for('main.settings'))


# ─── API Endpoints (for Chart.js) ─────────────────────────────────────────────

@main_bp.route('/api/stats')
@login_required
def api_stats():
    now = datetime.utcnow()
    day_ago = now - timedelta(hours=24)

    # Hourly alert counts
    hourly = []
    for i in range(24):
        h_start = now - timedelta(hours=24-i)
        h_end = h_start + timedelta(hours=1)
        count = Alert.query.filter(Alert.timestamp >= h_start, Alert.timestamp < h_end).count()
        hourly.append({'hour': h_start.strftime('%H:00'), 'count': count})

    # Risk distribution
    risk_dist = {
        'Safe': Device.query.filter_by(risk_level='Safe').count(),
        'Medium': Device.query.filter_by(risk_level='Medium').count(),
        'High': Device.query.filter_by(risk_level='High').count(),
    }

    return jsonify({
        'hourly_alerts': hourly,
        'risk_distribution': risk_dist,
        'total_devices': Device.query.count(),
        'open_alerts': Alert.query.filter_by(status='Open').count(),
    })


@main_bp.route('/api/traffic')
@login_required
def api_traffic():
    from .ddos_detector import get_traffic_spike_summary
    data = get_traffic_spike_summary(60)
    return jsonify({'labels': list(data.keys()), 'data': list(data.values())})
