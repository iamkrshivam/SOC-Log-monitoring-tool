#!/usr/bin/env python3
"""CampusSOC Application Entry Point."""

import os
import ssl
from app import create_app

app = create_app(os.environ.get('FLASK_ENV', 'production'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'

    # HTTPS with self-signed cert in production
    ssl_context = None
    cert_file = os.path.join(os.path.dirname(__file__), 'certs', 'campus_soc.crt')
    key_file = os.path.join(os.path.dirname(__file__), 'certs', 'campus_soc.key')

    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = (cert_file, key_file)
        print(f"[*] Starting CampusSOC with HTTPS on port {port}")
    else:
        print(f"[*] Starting CampusSOC on port {port} (HTTP mode - run generate_certs.sh for HTTPS)")

    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        ssl_context=ssl_context
    )
