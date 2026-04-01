import os
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler

from .models import db, User
from .config import config

login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)
scheduler = BackgroundScheduler()


def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')

    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.config.from_object(config[config_name])

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    login_manager.session_protection = 'strong'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from .auth import auth_bp
    from .routes import main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # Context processor: inject open alert count into all templates
    @app.context_processor
    def inject_globals():
        from .models import Alert
        def open_alert_count():
            try:
                return Alert.query.filter_by(status='Open').count()
            except Exception:
                return 0
        return dict(open_alert_count=open_alert_count)

    # Start scheduler
    with app.app_context():
        db.create_all()
        _start_scheduler(app)

    return app


def _start_scheduler(app):
    from .cleanup_manager import run_weekly_cleanup
    from .log_parser import parse_and_store_logs
    from .ddos_detector import run_ddos_detection

    if not scheduler.running:
        # Weekly cleanup
        scheduler.add_job(
            func=lambda: _run_with_context(app, run_weekly_cleanup),
            trigger='interval',
            weeks=1,
            id='weekly_cleanup',
            replace_existing=True
        )
        # Log parsing every 5 minutes
        scheduler.add_job(
            func=lambda: _run_with_context(app, parse_and_store_logs),
            trigger='interval',
            minutes=5,
            id='log_parser',
            replace_existing=True
        )
        # DDoS detection every minute
        scheduler.add_job(
            func=lambda: _run_with_context(app, run_ddos_detection),
            trigger='interval',
            minutes=1,
            id='ddos_detector',
            replace_existing=True
        )
        scheduler.start()


def _run_with_context(app, func):
    with app.app_context():
        try:
            func()
        except Exception as e:
            app.logger.error(f"Scheduler job error [{func.__name__}]: {e}")
