#!/usr/bin/env bash
# ============================================================
#  CampusSOC — Automated Installation Script
#  Ubuntu Server 22.04 LTS
#  Run as: sudo bash install.sh
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/campus_soc_final"
APP_USER="campussoc"
SERVICE_NAME="campus_soc"
IFACE="${NETWORK_INTERFACE:-eth0}"
SUBNET="${ALLOWED_SUBNET:-10.0.0.0/8}"

banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║     CampusSOC Installation Script     ║"
    echo "  ║     Ubuntu 22.04 LTS — Secure Edition ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

log_ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
log_info() { echo -e "  ${CYAN}[*]${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "  ${RED}[✗]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root (sudo bash install.sh)"
        exit 1
    fi
}

install_system_deps() {
    log_info "Updating system packages..."
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv \
        build-essential libssl-dev libffi-dev python3-dev \
        curl wget git \
        openssl \
        ufw \
        logrotate \
        net-tools \
        > /dev/null 2>&1
    log_ok "System dependencies installed."
}

create_app_user() {
    if ! id "$APP_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /bin/false "$APP_USER"
        log_ok "Created system user: $APP_USER"
    else
        log_info "User $APP_USER already exists."
    fi
}

setup_directories() {
    log_info "Setting up application directories..."
    mkdir -p "$INSTALL_DIR"/{logs,backups,certs,static/{css,js},templates}
    chown -R "$APP_USER:$APP_USER" "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"
    chmod 700 "$INSTALL_DIR/certs"
    log_ok "Directories created."
}

copy_application() {
    log_info "Copying application files..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp -r "$SCRIPT_DIR/"* "$INSTALL_DIR/"
    chown -R "$APP_USER:$APP_USER" "$INSTALL_DIR"
    log_ok "Application files copied."
}

setup_virtualenv() {
    log_info "Creating Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
    "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
    chown -R "$APP_USER:$APP_USER" "$INSTALL_DIR/venv"
    log_ok "Python virtual environment ready."
}

generate_ssl_certs() {
    log_info "Generating self-signed SSL certificate..."
    local CERT_DIR="$INSTALL_DIR/certs"
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CERT_DIR/campus_soc.key" \
        -out "$CERT_DIR/campus_soc.crt" \
        -sha256 -days 365 \
        -nodes \
        -subj "/C=IN/ST=Campus/L=University/O=CampusSOC/OU=Security/CN=campussoc.local" \
        2>/dev/null
    chmod 600 "$CERT_DIR/campus_soc.key"
    chmod 644 "$CERT_DIR/campus_soc.crt"
    chown "$APP_USER:$APP_USER" "$CERT_DIR"/*
    log_ok "SSL certificate generated."
}

generate_secret_key() {
    log_info "Generating secret key..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > "$INSTALL_DIR/.env" <<EOF
FLASK_ENV=production
SECRET_KEY=$SECRET_KEY
ALLOWED_SUBNET=$SUBNET
ZEEK_LOG_PATH=/opt/zeek/logs/current/conn.log
SURICATA_LOG_PATH=/var/log/suricata/fast.log
LOG_RETENTION_DAYS=7
EOF
    chmod 600 "$INSTALL_DIR/.env"
    chown "$APP_USER:$APP_USER" "$INSTALL_DIR/.env"
    log_ok "Environment configuration created."
}

init_database() {
    log_info "Initializing database..."
    cd "$INSTALL_DIR"
    sudo -u "$APP_USER" "$INSTALL_DIR/venv/bin/python" init_db.py
    log_ok "Database initialized."
}

install_systemd_service() {
    log_info "Installing systemd service..."
    cp "$INSTALL_DIR/services/campus_soc.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    log_ok "Systemd service installed and enabled."
}

configure_firewall() {
    log_info "Configuring UFW firewall..."
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    # Allow SSH
    ufw allow ssh > /dev/null 2>&1
    # Allow CampusSOC HTTPS (port 5000)
    ufw allow from "$SUBNET" to any port 5000 proto tcp > /dev/null 2>&1
    # Allow Zeek/Suricata to run
    ufw allow in on "$IFACE" > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1
    log_ok "Firewall configured. Only $SUBNET can access port 5000."
}

setup_logrotate() {
    log_info "Configuring log rotation..."
    cat > /etc/logrotate.d/campussoc <<EOF
$INSTALL_DIR/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        systemctl reload $SERVICE_NAME 2>/dev/null || true
    endscript
}
EOF
    log_ok "Log rotation configured."
}

install_zeek() {
    log_info "Installing Zeek..."
    if command -v zeek &>/dev/null; then
        log_info "Zeek already installed."
        return
    fi
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
        > /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL 'https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key' \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg 2>/dev/null
    apt-get update -qq
    apt-get install -y -qq zeek > /dev/null 2>&1 || {
        log_warn "Zeek installation failed. Install manually: https://docs.zeek.org/en/master/install.html"
        return
    }

    # Configure Zeek interface
    sed -i "s/^interface=.*/interface=$IFACE/" /opt/zeek/etc/node.cfg 2>/dev/null || true
    log_ok "Zeek installed. Interface: $IFACE"
}

install_suricata() {
    log_info "Installing Suricata..."
    if command -v suricata &>/dev/null; then
        log_info "Suricata already installed."
        return
    fi
    add-apt-repository ppa:oisf/suricata-stable -y > /dev/null 2>&1
    apt-get update -qq
    apt-get install -y -qq suricata > /dev/null 2>&1 || {
        log_warn "Suricata installation failed. Install manually: https://suricata.io/download/"
        return
    }

    # Configure interface
    sed -i "s/interface: .*/interface: $IFACE/" /etc/suricata/suricata.yaml 2>/dev/null || true

    systemctl enable suricata > /dev/null 2>&1
    log_ok "Suricata installed. Interface: $IFACE"
}

start_service() {
    log_info "Starting CampusSOC service..."
    systemctl start "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_ok "CampusSOC service is running!"
    else
        log_warn "Service may not have started. Check: journalctl -u $SERVICE_NAME"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  CampusSOC Installation Complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Dashboard: ${CYAN}https://$(hostname -I | awk '{print $1}'):5000${NC}"
    echo ""
    echo -e "  Default credentials (CHANGE IMMEDIATELY):"
    echo -e "  ${YELLOW}SuperAdmin: superadmin / Admin@123${NC}"
    echo ""
    echo -e "  Manage service:"
    echo -e "    Start:   ${CYAN}sudo systemctl start $SERVICE_NAME${NC}"
    echo -e "    Stop:    ${CYAN}sudo systemctl stop $SERVICE_NAME${NC}"
    echo -e "    Restart: ${CYAN}sudo systemctl restart $SERVICE_NAME${NC}"
    echo -e "    Logs:    ${CYAN}sudo journalctl -u $SERVICE_NAME -f${NC}"
    echo ""
    echo -e "  Next steps:"
    echo -e "  1. Change the default superadmin password"
    echo -e "  2. Configure Zeek: /opt/zeek/etc/node.cfg"
    echo -e "  3. Configure Suricata: /etc/suricata/suricata.yaml"
    echo -e "  4. Update .env: $INSTALL_DIR/.env"
    echo ""
}

# ─── Main Execution ──────────────────────────────────────── #

banner
check_root

log_info "Starting installation... Network interface: $IFACE, Subnet: $SUBNET"
echo ""

install_system_deps
create_app_user
setup_directories
copy_application
setup_virtualenv
generate_ssl_certs
generate_secret_key
init_database
install_systemd_service
configure_firewall
setup_logrotate
install_zeek
install_suricata
start_service
print_summary
