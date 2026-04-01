#!/usr/bin/env python3
"""Initialize the CampusSOC database with default data."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.models import db, User, RetentionPolicy
from app.audit_logger import log_audit


def init_database():
    app = create_app('development')
    with app.app_context():
        print("[*] Creating database tables...")
        db.create_all()

        # Create default superadmin
        if not User.query.filter_by(username='superadmin').first():
            superadmin = User(
                username='superadmin',
                email='admin@campus.edu',
                role='superadmin',
                force_password_change=True,
                is_active=True
            )
            superadmin.set_password('Admin@123')
            db.session.add(superadmin)
            print("[+] Created default superadmin (password: Admin@123)")
        else:
            print("[=] superadmin user already exists, skipping.")

        # Create default analyst
        if not User.query.filter_by(username='analyst').first():
            analyst = User(
                username='analyst',
                email='analyst@campus.edu',
                role='analyst',
                force_password_change=True,
                is_active=True
            )
            analyst.set_password('Analyst@123')
            db.session.add(analyst)
            print("[+] Created default analyst (password: Analyst@123)")

        # Create default viewer
        if not User.query.filter_by(username='viewer').first():
            viewer = User(
                username='viewer',
                email='viewer@campus.edu',
                role='viewer',
                force_password_change=True,
                is_active=True
            )
            viewer.set_password('Viewer@123')
            db.session.add(viewer)
            print("[+] Created default viewer (password: Viewer@123)")

        # Initialize retention policy
        if not RetentionPolicy.query.first():
            policy = RetentionPolicy(
                retention_days=7,
                auto_cleanup_enabled=True,
                updated_by='system'
            )
            db.session.add(policy)
            print("[+] Initialized default retention policy (7 days)")

        db.session.commit()
        print("[*] Database initialization complete.")
        print()
        print("=" * 50)
        print("  DEFAULT CREDENTIALS (CHANGE IMMEDIATELY!)")
        print("=" * 50)
        print("  SuperAdmin: superadmin / Admin@123")
        print("  Analyst:    analyst   / Analyst@123")
        print("  Viewer:     viewer    / Viewer@123")
        print("=" * 50)


if __name__ == '__main__':
    init_database()
