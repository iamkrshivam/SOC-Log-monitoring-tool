# CampusSOC — Campus Security Operations Center

**Final Secure Edition | Cybersecurity Final Year Project**

A lightweight, legally compliant Mini-SOC platform for campus network security monitoring.

---

## Features

- Real-time network metadata monitoring (Zeek + Suricata)
- Automated attack detection: Port Scan, Brute Force, ARP Spoofing, Malware DNS, DDoS
- Risk scoring engine with color-coded risk levels (Safe / Medium / High)
- Role-based access control (SuperAdmin / Analyst / Viewer)
- Subnet-restricted dashboard access
- Weekly PDF security reports
- Automated + manual log cleanup with archival
- CSRF protection, rate limiting, secure sessions
- Full admin audit logging
- Professional dark dashboard UI (Bootstrap 5 + Chart.js)

---

## Quick Start (Development)

```bash
# 1. Clone / copy project
cd campus_soc_final

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize database
python init_db.py

# 5. Run in dev mode (no HTTPS, subnet bypass ON)
FLASK_ENV=development python run.py
```

Visit: http://localhost:5000  
Login: `superadmin` / `Admin@123`

---

## Production Deployment (Ubuntu 22.04)

### Step 1: System Update

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Run Automated Installer

```bash
# Set your network interface and allowed subnet
export NETWORK_INTERFACE=eth0
export ALLOWED_SUBNET=192.168.1.0/24

sudo bash install.sh
```

The installer will:
- Install all Python dependencies
- Create a system user (`campussoc`)
- Generate self-signed SSL certificate
- Initialize the database
- Configure UFW firewall
- Configure logrotate
- Install and enable the systemd service
- Attempt to install Zeek and Suricata

### Step 3: Configure Zeek

```bash
# Edit node configuration
sudo nano /opt/zeek/etc/node.cfg

# Set your network interface:
# [zeek]
# type=standalone
# host=localhost
# interface=eth0

# Start Zeek
sudo /opt/zeek/bin/zeekctl deploy

# Enable on boot
sudo systemctl enable zeek 2>/dev/null || true
```

### Step 4: Configure Suricata

```bash
# Update suricata.yaml with your interface
sudo nano /etc/suricata/suricata.yaml

# Update rules
sudo suricata-update

# Start Suricata
sudo systemctl start suricata
sudo systemctl enable suricata
```

### Step 5: Update Environment

```bash
sudo nano /opt/campus_soc_final/.env
```

```ini
FLASK_ENV=production
SECRET_KEY=your-very-long-random-secret-key-here
ALLOWED_SUBNET=192.168.1.0/24
ZEEK_LOG_PATH=/opt/zeek/logs/current/conn.log
SURICATA_LOG_PATH=/var/log/suricata/fast.log
LOG_RETENTION_DAYS=7
```

### Step 6: Firewall

```bash
# Show current rules
sudo ufw status verbose

# Allow access from specific IP only
sudo ufw allow from 192.168.1.100 to any port 5000

# Check status
sudo ufw status
```

### Step 7: Service Management

```bash
# Start
sudo systemctl start campus_soc

# Stop
sudo systemctl stop campus_soc

# Restart
sudo systemctl restart campus_soc

# Status
sudo systemctl status campus_soc

# Logs
sudo journalctl -u campus_soc -f

# Enable on boot
sudo systemctl enable campus_soc
```

---

## HTTPS Setup

Self-signed certificate is auto-generated during install.

To use a real certificate (Let's Encrypt):

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d campussoc.yourdomain.edu

# Update .env or run.py to point to new cert paths
CERT_FILE=/etc/letsencrypt/live/campussoc.yourdomain.edu/fullchain.pem
KEY_FILE=/etc/letsencrypt/live/campussoc.yourdomain.edu/privkey.pem
```

Or with Nginx as reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name campussoc.yourdomain.edu;

    ssl_certificate /etc/letsencrypt/live/.../fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

---

## Backup & Restore

### Manual Backup

```bash
# Backup database
cp /opt/campus_soc_final/campus_soc.db /opt/campus_soc_final/backups/db_backup_$(date +%Y%m%d).db

# Backup entire app
tar -czf /opt/backups/campussoc_$(date +%Y%m%d).tar.gz /opt/campus_soc_final/
```

### Restore

```bash
# Restore database
sudo systemctl stop campus_soc
cp /opt/campus_soc_final/backups/db_backup_YYYYMMDD.db /opt/campus_soc_final/campus_soc.db
sudo systemctl start campus_soc
```

---

## Log Rotation

Logrotate is configured at: `/etc/logrotate.d/campussoc`

Manual rotation:
```bash
sudo logrotate -f /etc/logrotate.d/campussoc
```

---

## User Roles

| Feature              | SuperAdmin | Analyst | Viewer |
|----------------------|------------|---------|--------|
| View Dashboard       | ✓          | ✓       | ✓      |
| View Devices         | ✓          | ✓       | ✓      |
| View Alerts          | ✓          | ✓       | ✗      |
| Update Alert Status  | ✓          | ✓       | ✗      |
| Download Reports     | ✓          | ✓       | ✓      |
| Delete Logs          | ✓          | ✗       | ✗      |
| Manage Users         | ✓          | ✗       | ✗      |
| Change Settings      | ✓          | ✗       | ✗      |

---

## Legal Compliance

- **No HTTPS decryption** — only metadata is captured
- **No deep packet inspection** — Zeek processes connection metadata only
- **No personal data stored** — only IP addresses and network statistics
- **Audit trails** — all admin actions are logged
- **Data retention** — configurable, default 7 days with archival
- Compliant with passive network monitoring standards

---

## Technology Stack

- **Backend:** Python 3, Flask, SQLAlchemy, APScheduler
- **Security:** Flask-Login, Flask-WTF (CSRF), Flask-Limiter
- **Database:** SQLite (default) / PostgreSQL-ready
- **Network:** Zeek IDS + Suricata IPS
- **Frontend:** Bootstrap 5, Chart.js
- **Reports:** ReportLab PDF
- **Deployment:** Gunicorn + Systemd

---

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM       | 4 GB    | 8 GB        |
| CPU       | 2 cores | 4 cores     |
| Storage   | 20 GB   | 50+ GB      |
| OS        | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |

---

## Troubleshooting

**Service won't start:**
```bash
sudo journalctl -u campus_soc --no-pager -n 50
```

**Can't access dashboard:**
- Check subnet restriction in `.env` (ALLOWED_SUBNET)
- Set `BYPASS_SUBNET_CHECK=true` for testing
- Check firewall: `sudo ufw status`

**No alerts showing:**
- Verify Zeek/Suricata are running
- Check log paths in `.env`
- Test log parser: `python3 -c "from app import create_app; app = create_app('development'); app.app_context().push(); from app.log_parser import parse_and_store_logs; parse_and_store_logs()"`

---

*CampusSOC — Final Year Cybersecurity Project | Legally Compliant Campus Network Security Monitoring*
