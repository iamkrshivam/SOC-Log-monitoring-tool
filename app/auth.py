import re
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

from .models import db, User
from .audit_logger import log_audit
from . import limiter

auth_bp = Blueprint('auth', __name__)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')


def validate_password_complexity(password):
    """Ensure password meets complexity requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "OK"


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        client_ip = request.remote_addr

        if user and user.is_active and user.check_password(form.password.data):
            login_user(user, remember=False)
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_audit(user.username, 'LOGIN', 'Successful login', client_ip, 'Success')

            if user.force_password_change:
                flash('You must change your password before continuing.', 'warning')
                return redirect(url_for('auth.change_password'))

            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            log_audit(form.username.data, 'LOGIN', 'Failed login attempt', client_ip, 'Failed')
            flash('Invalid username or password.', 'danger')

    return render_template('login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    log_audit(current_user.username, 'LOGOUT', 'User logged out', request.remote_addr)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html', form=form)

        if form.new_password.data != form.confirm_password.data:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html', form=form)

        valid, msg = validate_password_complexity(form.new_password.data)
        if not valid:
            flash(msg, 'danger')
            return render_template('change_password.html', form=form)

        current_user.set_password(form.new_password.data)
        current_user.force_password_change = False
        db.session.commit()
        log_audit(current_user.username, 'PASSWORD_CHANGE', 'Password changed', request.remote_addr)
        flash('Password changed successfully.', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html', form=form)
