import ipaddress
from functools import wraps
from flask import request, abort, current_app


def get_real_ip():
    """Get the real client IP, handling proxies."""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr


def is_ip_allowed(ip_str, subnet_str):
    """Check if IP is within allowed subnet."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Always allow loopback
        if ip.is_loopback:
            return True
        subnet = ipaddress.ip_network(subnet_str, strict=False)
        return ip in subnet
    except ValueError:
        return False


def subnet_required(f):
    """Decorator to restrict access to allowed subnet."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_app.config.get('BYPASS_SUBNET_CHECK', False):
            return f(*args, **kwargs)

        client_ip = get_real_ip()
        allowed_subnet = current_app.config.get('ALLOWED_SUBNET', '10.0.0.0/8')

        if not is_ip_allowed(client_ip, allowed_subnet):
            current_app.logger.warning(f"Blocked access from unauthorized IP: {client_ip}")
            abort(403)

        return f(*args, **kwargs)
    return decorated_function


def check_subnet(app):
    """Flask before_request handler for subnet checking."""
    client_ip = get_real_ip()
    allowed_subnet = app.config.get('ALLOWED_SUBNET', '10.0.0.0/8')

    if app.config.get('BYPASS_SUBNET_CHECK', False):
        return None

    # Skip subnet check for static files
    if request.path.startswith('/static/'):
        return None

    if not is_ip_allowed(client_ip, allowed_subnet):
        app.logger.warning(f"Blocked access from unauthorized IP: {client_ip}")
        abort(403)

    return None
