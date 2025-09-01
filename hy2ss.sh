#!/bin/bash

# ==========================================================
# Hysteria2 & Shadowsocks (IPv6) Management Script (v1.0)
# 项目地址：https://github.com/everett7623/hy2ipv6
# 优化与开发方案：根据用户提供的详细需求进行构建
# ==========================================================

# --- Global Variables & Constants ---
SCRIPT_VERSION="1.1.0-alpha"
PROJECT_REPO="https://github.com/everett7623/hy2ipv6"
HY2_SERVICE_NAME="hysteria2"
SS_SERVICE_NAME="shadowsocks-ipv6"
HY2_CONFIG_DIR="/etc/hysteria2"
SS_CONFIG_DIR="/etc/shadowsocks-ipv6"
BACKUP_DIR="/var/backups/hy2ss_scripts"
LOG_FILE="/var/log/hy2ss_script.log" # 脚本自身运行日志

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Helper Functions ---

# Function to print messages with colors
print_msg() {
    local type="$1"
    local message="$2"
    case "$type" in
        "INFO") echo -e "${CYAN}[INFO]${NC} $message" | tee -a "$LOG_FILE" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "$LOG_FILE" ;;
        "WARN") echo -e "${YELLOW}[WARNING]${NC} $message" | tee -a "$LOG_FILE" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE" ;;
        "PROMPT") echo -e "${BLUE}[PROMPT]${NC} $message" | tee -a "$LOG_FILE" ;;
        "DEBUG") [ "$DEBUG_MODE" = "true" ] && echo -e "${PURPLE}[DEBUG]${NC} $message" | tee -a "$LOG_FILE" ;;
        *) echo "$message" | tee -a "$LOG_FILE" ;;
    esac
}

# Check if script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_msg "ERROR" "Please run this script as root."
        exit 1
    fi
}

# Detect OS and package manager
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION_ID=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VERSION_ID=$(lsb_release -sr)
    elif [ -f /etc/redhat-release ]; then
        OS=$(awk '{print tolower($1)}' /etc/redhat-release)
        VERSION_ID=$(grep -oE '[0-9.]+' /etc/redhat-release | head -n1)
    else
        OS=$(uname -s)
    fi

    case "$OS" in
        "ubuntu"|"debian")
            PKG_MANAGER="apt"
            ;;
        "centos"|"rhel"|"fedora")
            PKG_MANAGER="yum" # or dnf for newer Fedora
            if [ "$OS" = "fedora" ]; then PKG_MANAGER="dnf"; fi
            ;;
        *)
            print_msg "ERROR" "Unsupported operating system: $OS. Exiting."
            exit 1
            ;;
    esac
    print_msg "INFO" "Detected OS: $OS $VERSION_ID with package manager: $PKG_MANAGER"
}

# Install necessary dependencies
install_dependencies() {
    print_msg "INFO" "Checking and installing dependencies..."
    local pkgs=""
    case "$PKG_MANAGER" in
        "apt")
            pkgs="curl wget jq openssl systemd-timesyncd net-tools iproute2 ufw"
            apt update -qq >/dev/log 2>&1
            apt install -y $pkgs >/dev/log 2>&1
            ;;
        "yum"|"dnf")
            pkgs="curl wget jq openssl systemd-timesyncd net-tools iproute firewall-cmd"
            # For CentOS/RHEL, net-tools might be replaced by iproute2 tools (ss, ip)
            $PKG_MANAGER install -y $pkgs >/dev/log 2>&1
            ;;
    esac

    if [ $? -ne 0 ]; then
        print_msg "ERROR" "Failed to install one or more dependencies. Please check your internet connection and package manager logs."
        exit 1
    fi
    print_msg "SUCCESS" "All dependencies checked and installed."
}

# Check IPv6 connectivity
check_ipv6_connectivity() {
    print_msg "INFO" "Checking IPv6 connectivity..."
    if ! ping6 -c 3 google.com >/dev/null 2>&1; then
        print_msg "WARN" "IPv6 connectivity not detected or unstable. Hysteria2/Shadowsocks (IPv6) might not work as expected."
        read -p "$(print_msg "PROMPT" "Do you want to continue anyway? (y/N): ")" choice
        case "$choice" in
            y|Y ) print_msg "INFO" "Continuing despite IPv6 warning." ;;
            * ) print_msg "ERROR" "IPv6 connectivity is crucial for this script. Exiting." ; exit 1 ;;
        esac
    else
        print_msg "SUCCESS" "IPv6 connectivity confirmed."
    fi
    # Get server IPv6 address
    SERVER_IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d '/' -f1 | head -n 1)
    if [ -z "$SERVER_IPV6" ]; then
        print_msg "WARN" "Could not automatically detect server's global IPv6 address. This might indicate issues or require manual input."
    else
        print_msg "INFO" "Server IPv6: $SERVER_IPV6"
    fi
    SERVER_IPV4=$(curl -s4 api.ip.sb/ip || wget -qO- -t1 -T2 ipv4.ip.sb)
}

# Detect and configure firewall
configure_firewall() {
    print_msg "INFO" "Detecting firewall..."
    if command -v ufw &>/dev/null; then
        FIREWALL_CMD="ufw"
        if ufw status | grep -q "inactive"; then
            print_msg "WARN" "UFW is inactive. Enabling UFW and setting default rules."
            ufw allow ssh >/dev/null 2>&1 # Allow SSH by default
            ufw enable -y >/dev/null 2>&1
        fi
        ufw allow "$1"/tcp comment "Allow $2 service" >/dev/null 2>&1
        ufw allow "$1"/udp comment "Allow $2 service" >/dev/null 2>&1
        print_msg "SUCCESS" "UFW rule added for port $1 ($2)."
    elif command -v firewall-cmd &>/dev/null; then
        FIREWALL_CMD="firewalld"
        if ! systemctl is-active --quiet firewalld; then
            print_msg "WARN" "Firewalld is inactive. Starting and enabling Firewalld."
            systemctl start firewalld >/dev/log 2>&1
            systemctl enable firewalld >/dev/log 2>&1
        fi
        firewall-cmd --permanent --add-port="$1"/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$1"/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        print_msg "SUCCESS" "Firewalld rule added for port $1 ($2)."
    else
        print_msg "WARN" "No common firewall detected (ufw or firewalld). Please ensure required ports are open manually."
    fi
}

# Generate a random port
generate_random_port() {
    shuf -i 10000-65535 -n 1
}

# Validate port input
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        return 0 # Valid
    else
        print_msg "ERROR" "Invalid port number: $port. Must be between 1 and 65535."
        return 1 # Invalid
    fi
}

# Input validation for domain
validate_domain() {
    local domain="$1"
    if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0 # Valid
    else
        print_msg "ERROR" "Invalid domain format: $domain."
        return 1 # Invalid
    fi
}

# --- Service Specific Functions ---

# Function to get service status
get_service_status() {
    local service="$1"
    systemctl is-active --quiet "$service"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${RED}已停止${NC}"
    fi
}

# Placeholder for Hysteria2 (Self-signed) installation
install_hysteria2_self_signed_cert() {
    print_msg "INFO" "Starting Hysteria2 (Self-signed Certificate) installation..."
    # --- Configuration ---
    local PORT=$(generate_random_port)
    while ! validate_port "$PORT" || lsof -i :"$PORT" >/dev/null 2>&1; do
        print_msg "WARN" "Port $PORT is either invalid or already in use. Generating a new one."
        PORT=$(generate_random_port)
    done
    read -p "$(print_msg "PROMPT" "Enter Hysteria2 port (default: $PORT): ")" HY2_PORT
    HY2_PORT=${HY2_PORT:-$PORT}
    while ! validate_port "$HY2_PORT" || lsof -i :"$HY2_PORT" >/dev/null 2>&1; do
        print_msg "ERROR" "Invalid or occupied port: $HY2_PORT. Please enter a different one."
        read -p "$(print_msg "PROMPT" "Enter Hysteria2 port: ")" HY2_PORT
    done

    read -p "$(print_msg "PROMPT" "Enter Hysteria2 password (default: random): ")" HY2_PASSWORD
    HY2_PASSWORD=${HY2_PASSWORD:-$(openssl rand -base64 16)}

    # --- Download Hysteria2 binary ---
    print_msg "INFO" "Downloading Hysteria2..."
    # Example: Adjust URL based on actual Hysteria2 releases and architecture
    local ARCH=$(uname -m)
    local HY2_DOWNLOAD_URL=""
    case "$ARCH" in
        "x86_64") HY2_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v2.x.x/hysteria-linux-amd64" ;; # REPLACE WITH ACTUAL URL
        "aarch64") HY2_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v2.x.x/hysteria-linux-arm64" ;; # REPLACE WITH ACTUAL URL
        *) print_msg "ERROR" "Unsupported architecture: $ARCH"; return 1 ;;
    esac

    wget -qO /usr/local/bin/hysteria2 "$HY2_DOWNLOAD_URL"
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to download Hysteria2 binary."; return 1; fi
    chmod +x /usr/local/bin/hysteria2
    print_msg "SUCCESS" "Hysteria2 binary downloaded and made executable."

    # --- Generate Self-Signed Certificate ---
    print_msg "INFO" "Generating self-signed TLS certificate..."
    mkdir -p "$HY2_CONFIG_DIR"
    openssl genrsa -out "$HY2_CONFIG_DIR/server.key" 2048 >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$HY2_CONFIG_DIR/server.key" -out "$HY2_CONFIG_DIR/server.crt" -subj "/CN=example.com" >/dev/null 2>&1 # Common Name is not critical for self-signed
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to generate self-signed certificate."; return 1; fi
    print_msg "SUCCESS" "Self-signed certificate generated."

    # --- Create Hysteria2 Configuration ---
    print_msg "INFO" "Creating Hysteria2 configuration file..."
    cat <<EOF > "$HY2_CONFIG_DIR/config.json"
{
  "listen": ":$HY2_PORT",
  "obfs": "none",
  "up_mbps": 100,
  "down_mbps": 100,
  "auth": {
    "$HY2_PASSWORD": {
      "mode": "password"
    }
  },
  "tls": {
    "cert": "$HY2_CONFIG_DIR/server.crt",
    "key": "$HY2_CONFIG_DIR/server.key"
  }
}
EOF
    # Placeholder for more advanced configuration (e.g., obfs, traffic limits)
    print_msg "SUCCESS" "Hysteria2 configuration created."

    # --- Create Systemd Service ---
    print_msg "INFO" "Creating Systemd service for Hysteria2..."
    cat <<EOF > "/etc/systemd/system/$HY2_SERVICE_NAME.service"
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria2 --config $HY2_CONFIG_DIR/config.json server
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$HY2_SERVICE_NAME" >/dev/null 2>&1
    systemctl start "$HY2_SERVICE_NAME" >/dev/null 2>&1
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to start Hysteria2 service. Check logs: journalctl -u $HY2_SERVICE_NAME"; return 1; fi
    print_msg "SUCCESS" "Hysteria2 Systemd service created and started."

    # --- Configure Firewall ---
    configure_firewall "$HY2_PORT" "Hysteria2"

    print_msg "SUCCESS" "Hysteria2 (Self-signed) installed successfully!"
    print_msg "INFO" "--- Hysteria2 Configuration Details ---"
    print_msg "INFO" "Server Address: $SERVER_IPV4 (for IPv4 clients), $SERVER_IPV6 (for IPv6 clients)"
    print_msg "INFO" "Port: $HY2_PORT"
    print_msg "INFO" "Password: $HY2_PASSWORD"
    print_msg "INFO" "Obfuscation: none"
    print_msg "INFO" "Certificate Mode: Self-signed"
    print_msg "INFO" "---------------------------------------"
}

# Placeholder for Hysteria2 (ACME) installation
install_hysteria2_acme_cert() {
    print_msg "INFO" "Starting Hysteria2 (ACME Certificate) installation..."
    print_msg "WARN" "This feature requires a domain and Cloudflare API Token."

    local DOMAIN=""
    while true; do
        read -p "$(print_msg "PROMPT" "Enter your domain (e.g., example.com): ")" DOMAIN
        if validate_domain "$DOMAIN"; then break; fi
    done

    read -p "$(print_msg "PROMPT" "Enter your Cloudflare Global API Key: ")" CF_API_KEY
    read -p "$(print_msg "PROMPT" "Enter your Cloudflare Email: ")" CF_EMAIL

    local PORT=$(generate_random_port)
    while ! validate_port "$PORT" || lsof -i :"$PORT" >/dev/null 2>&1; do
        print_msg "WARN" "Port $PORT is either invalid or already in use. Generating a new one."
        PORT=$(generate_random_port)
    done
    read -p "$(print_msg "PROMPT" "Enter Hysteria2 port (default: $PORT): ")" HY2_PORT
    HY2_PORT=${HY2_PORT:-$PORT}
    while ! validate_port "$HY2_PORT" || lsof -i :"$HY2_PORT" >/dev/null 2>&1; do
        print_msg "ERROR" "Invalid or occupied port: $HY2_PORT. Please enter a different one."
        read -p "$(print_msg "PROMPT" "Enter Hysteria2 port: ")" HY2_PORT
    done

    read -p "$(print_msg "PROMPT" "Enter Hysteria2 password (default: random): ")" HY2_PASSWORD
    HY2_PASSWORD=${HY2_PASSWORD:-$(openssl rand -base64 16)}

    # --- Install acme.sh ---
    print_msg "INFO" "Installing acme.sh for certificate management..."
    if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
        curl https://get.acme.sh | sh >/dev/log 2>&1
        if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to install acme.sh."; return 1; fi
        print_msg "SUCCESS" "acme.sh installed."
        # Source acme.sh config to make it available in current shell
        # . "$HOME/.acme.sh/acme.sh.env"
    else
        print_msg "INFO" "acme.sh already installed."
    fi

    # --- Issue Certificate ---
    print_msg "INFO" "Issuing TLS certificate for $DOMAIN using Cloudflare DNS-01 challenge..."
    export CF_Key="$CF_API_KEY"
    export CF_Email="$CF_EMAIL"
    ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --dns dns_cf --keylength ec-256 --force
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to issue certificate with acme.sh. Check acme.sh logs."; return 1; fi
    
    mkdir -p "$HY2_CONFIG_DIR"
    # Install/Copy certificate
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
    --fullchain-file "$HY2_CONFIG_DIR/fullchain.pem" \
    --key-file "$HY2_CONFIG_DIR/privkey.pem" \
    --reloadcmd "systemctl reload $HY2_SERVICE_NAME" # This will be used by acme.sh for auto-renewal
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to install certificate."; return 1; fi
    
    unset CF_Key CF_Email # Unset sensitive variables
    print_msg "SUCCESS" "TLS certificate issued and installed."

    # --- Download Hysteria2 binary (same as self-signed for now) ---
    print_msg "INFO" "Downloading Hysteria2..."
    local ARCH=$(uname -m)
    local HY2_DOWNLOAD_URL=""
    case "$ARCH" in
        "x86_64") HY2_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v2.x.x/hysteria-linux-amd64" ;; # REPLACE WITH ACTUAL URL
        "aarch64") HY2_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v2.x.x/hysteria-linux-arm64" ;; # REPLACE WITH ACTUAL URL
        *) print_msg "ERROR" "Unsupported architecture: $ARCH"; return 1 ;;
    esac

    wget -qO /usr/local/bin/hysteria2 "$HY2_DOWNLOAD_URL"
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to download Hysteria2 binary."; return 1; fi
    chmod +x /usr/local/bin/hysteria2
    print_msg "SUCCESS" "Hysteria2 binary downloaded and made executable."

    # --- Create Hysteria2 Configuration ---
    print_msg "INFO" "Creating Hysteria2 configuration file..."
    cat <<EOF > "$HY2_CONFIG_DIR/config.json"
{
  "listen": ":$HY2_PORT",
  "obfs": "none",
  "up_mbps": 100,
  "down_mbps": 100,
  "auth": {
    "$HY2_PASSWORD": {
      "mode": "password"
    }
  },
  "tls": {
    "cert": "$HY2_CONFIG_DIR/fullchain.pem",
    "key": "$HY2_CONFIG_DIR/privkey.pem",
    "acme": {
        "domains": ["$DOMAIN"]
    }
  }
}
EOF
    print_msg "SUCCESS" "Hysteria2 configuration created."

    # --- Create Systemd Service ---
    print_msg "INFO" "Creating Systemd service for Hysteria2..."
    cat <<EOF > "/etc/systemd/system/$HY2_SERVICE_NAME.service"
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria2 --config $HY2_CONFIG_DIR/config.json server
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$HY2_SERVICE_NAME" >/dev/null 2>&1
    systemctl start "$HY2_SERVICE_NAME" >/dev/null 2>&1
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to start Hysteria2 service. Check logs: journalctl -u $HY2_SERVICE_NAME"; return 1; fi
    print_msg "SUCCESS" "Hysteria2 Systemd service created and started."

    # --- Configure Firewall ---
    configure_firewall "$HY2_PORT" "Hysteria2"

    print_msg "SUCCESS" "Hysteria2 (ACME) installed successfully!"
    print_msg "INFO" "--- Hysteria2 Configuration Details ---"
    print_msg "INFO" "Domain: $DOMAIN"
    print_msg "INFO" "Port: $HY2_PORT"
    print_msg "INFO" "Password: $HY2_PASSWORD"
    print_msg "INFO" "Obfuscation: none"
    print_msg "INFO" "Certificate Mode: ACME (Let's Encrypt) - Auto-renewed"
    print_msg "INFO" "---------------------------------------"
}

# Placeholder for Shadowsocks (IPv6) installation
install_shadowsocks_ipv6() {
    print_msg "INFO" "Starting Shadowsocks (IPv6 only) installation..."

    if [ -z "$SERVER_IPV6" ]; then
        print_msg "ERROR" "No global IPv6 address detected for this server. Cannot install Shadowsocks (IPv6)."
        return 1
    fi

    local PORT=$(generate_random_port)
    while ! validate_port "$PORT" || lsof -i :"$PORT" >/dev/null 2>&1; do
        print_msg "WARN" "Port $PORT is either invalid or already in use. Generating a new one."
        PORT=$(generate_random_port)
    done
    read -p "$(print_msg "PROMPT" "Enter Shadowsocks port (default: $PORT): ")" SS_PORT
    SS_PORT=${SS_PORT:-$PORT}
    while ! validate_port "$SS_PORT" || lsof -i :"$SS_PORT" >/dev/null 2>&1; do
        print_msg "ERROR" "Invalid or occupied port: $SS_PORT. Please enter a different one."
        read -p "$(print_msg "PROMPT" "Enter Shadowsocks port: ")" SS_PORT
    done

    read -p "$(print_msg "PROMPT" "Enter Shadowsocks password (default: random): ")" SS_PASSWORD
    SS_PASSWORD=${SS_PASSWORD:-$(openssl rand -base64 16)}

    # Encryption method selection
    print_msg "PROMPT" "Select Shadowsocks encryption method:"
    echo "  1. 2022-blake3-aes-256-gcm"
    echo "  2. chacha20-ietf-poly1305 (default)"
    read -p "Enter choice (1 or 2): " ENCRYPTION_CHOICE
    local SS_METHOD="chacha20-ietf-poly1305"
    case "$ENCRYPTION_CHOICE" in
        1) SS_METHOD="2022-blake3-aes-256-gcm" ;;
        2) SS_METHOD="chacha20-ietf-poly1305" ;;
        *) print_msg "WARN" "Invalid choice, defaulting to chacha20-ietf-poly1305." ;;
    esac

    # --- Install Shadowsocks-libev or similar (placeholder) ---
    print_msg "INFO" "Installing Shadowsocks-libev..."
    # This part would typically involve installing from a repository or compiling.
    # For simplicity, we'll assume a ss-server binary exists or will be installed.
    # Example for Debian/Ubuntu: apt install -y shadowsocks-libev
    # For this template, we'll assume a pre-compiled binary or a method that places `ss-server` in PATH
    
    case "$PKG_MANAGER" in
        "apt")
            apt install -y shadowsocks-libev >/dev/log 2>&1
            ;;
        "yum"|"dnf")
            print_msg "ERROR" "Shadowsocks-libev installation for CentOS/Fedora might require EPEL or manual compilation. Please adapt."
            return 1
            ;;
    esac
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to install shadowsocks-libev. Please check package manager logs."; return 1; fi
    print_msg "SUCCESS" "Shadowsocks-libev installed."

    # --- Create Shadowsocks Configuration ---
    print_msg "INFO" "Creating Shadowsocks configuration file..."
    mkdir -p "$SS_CONFIG_DIR"
    cat <<EOF > "$SS_CONFIG_DIR/config.json"
{
  "server": "::",
  "server_port": $SS_PORT,
  "password": "$SS_PASSWORD",
  "method": "$SS_METHOD",
  "timeout": 300,
  "mode": "tcp_and_udp",
  "fast_open": true,
  "ipv6_only": true
}
EOF
    print_msg "SUCCESS" "Shadowsocks configuration created."

    # --- Create Systemd Service ---
    print_msg "INFO" "Creating Systemd service for Shadowsocks (IPv6)..."
    cat <<EOF > "/etc/systemd/system/$SS_SERVICE_NAME.service"
[Unit]
Description=Shadowsocks IPv6 Server
After=network.target

[Service]
ExecStart=/usr/bin/ss-server -c $SS_CONFIG_DIR/config.json -u
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$SS_SERVICE_NAME" >/dev/null 2>&1
    systemctl start "$SS_SERVICE_NAME" >/dev/null 2>&1
    if [ $? -ne 0 ]; then print_msg "ERROR" "Failed to start Shadowsocks (IPv6) service. Check logs: journalctl -u $SS_SERVICE_NAME"; return 1; fi
    print_msg "SUCCESS" "Shadowsocks (IPv6) Systemd service created and started."

    # --- Configure Firewall ---
    configure_firewall "$SS_PORT" "Shadowsocks IPv6"

    print_msg "SUCCESS" "Shadowsocks (IPv6) installed successfully!"
    print_msg "INFO" "--- Shadowsocks (IPv6) Configuration Details ---"
    print_msg "INFO" "Server Address: [$SERVER_IPV6]"
    print_msg "INFO" "Port: $SS_PORT"
    print_msg "INFO" "Password: $SS_PASSWORD"
    print_msg "INFO" "Method: $SS_METHOD"
    print_msg "INFO" "---------------------------------------"

    # Generate SS URI (example, might need adjustment based on method)
    local ENCODED_PASSWORD=$(echo -n "$SS_PASSWORD" | base64 -w 0)
    local SS_URI="ss://${SS_METHOD}:${ENCODED_PASSWORD}@[$SERVER_IPV6]:${SS_PORT}#MySSIPv6"
    print_msg "INFO" "Shadowsocks URI: $SS_URI"
    # Placeholder for QR code generation (requires qrencode or similar)
}

# --- Management & Maintenance Functions ---

# Service management (start/stop/restart/log)
manage_services() {
    clear
    print_msg "INFO" "--- 服务管理 ---"
    echo -e "  1. 启动 Hysteria2"
    echo -e "  2. 停止 Hysteria2"
    echo -e "  3. 重启 Hysteria2"
    echo -e "  4. 查看 Hysteria2 日志"
    echo -e "------------------------"
    echo -e "  5. 启动 Shadowsocks (IPv6)"
    echo -e "  6. 停止 Shadowsocks (IPv6)"
    echo -e "  7. 重启 Shadowsocks (IPv6)"
    echo -e "  8. 查看 Shadowsocks (IPv6) 日志"
    echo -e "------------------------"
    echo -e "  0. 返回主菜单"
    echo "=========================================================="
    read -p "$(print_msg "PROMPT" "请选择一个操作 (0-8): ")" choice

    case "$choice" in
        1) systemctl start "$HY2_SERVICE_NAME" && print_msg "SUCCESS" "Hysteria2 已启动." || print_msg "ERROR" "Hysteria2 启动失败." ;;
        2) systemctl stop "$HY2_SERVICE_NAME" && print_msg "SUCCESS" "Hysteria2 已停止." || print_msg "ERROR" "Hysteria2 停止失败." ;;
        3) systemctl restart "$HY2_SERVICE_NAME" && print_msg "SUCCESS" "Hysteria2 已重启." || print_msg "ERROR" "Hysteria2 重启失败." ;;
        4) journalctl -u "$HY2_SERVICE_NAME" -f ;;
        5) systemctl start "$SS_SERVICE_NAME" && print_msg "SUCCESS" "Shadowsocks (IPv6) 已启动." || print_msg "ERROR" "Shadowsocks (IPv6) 启动失败." ;;
        6) systemctl stop "$SS_SERVICE_NAME" && print_msg "SUCCESS" "Shadowsocks (IPv6) 已停止." || print_msg "ERROR" "Shadowsocks (IPv6) 停止失败." ;;
        7) systemctl restart "$SS_SERVICE_NAME" && print_msg "SUCCESS" "Shadowsocks (IPv6) 已重启." || print_msg "ERROR" "Shadowsocks (IPv6) 重启失败." ;;
        8) journalctl -u "$SS_SERVICE_NAME" -f ;;
        0) return ;;
        *) print_msg "ERROR" "无效的选择，请重新输入。" ;;
    esac
    read -p "$(print_msg "PROMPT" "按任意键继续...")"
}

# Show configuration information
show_config_info() {
    clear
    print_msg "INFO" "--- 配置信息 ---"

    if systemctl is-active --quiet "$HY2_SERVICE_NAME"; then
        print_msg "INFO" "Hysteria2 (运行中):"
        if [ -f "$HY2_CONFIG_DIR/config.json" ]; then
            cat "$HY2_CONFIG_DIR/config.json" | jq .
            # More specific parsing for key details
            print_msg "INFO" "Port: $(jq -r '.listen' "$HY2_CONFIG_DIR/config.json" | cut -d':' -f2)"
            print_msg "INFO" "Password: $(jq -r '.auth | keys[0]' "$HY2_CONFIG_DIR/config.json")"
            if jq -e '.tls.acme' "$HY2_CONFIG_DIR/config.json" >/dev/null 2>&1; then
                print_msg "INFO" "Certificate Mode: ACME (${GREEN}已自动续期${NC})"
                print_msg "INFO" "Domain: $(jq -r '.tls.acme.domains[0]' "$HY2_CONFIG_DIR/config.json")"
            else
                print_msg "INFO" "Certificate Mode: Self-signed (${YELLOW}请注意证书有效期${NC})"
            fi
        else
            print_msg "WARN" "Hysteria2 配置文件未找到：$HY2_CONFIG_DIR/config.json"
        fi
        echo ""
    else
        print_msg "WARN" "Hysteria2 未安装或已停止."
    fi

    if systemctl is-active --quiet "$SS_SERVICE_NAME"; then
        print_msg "INFO" "Shadowsocks (IPv6) (运行中):"
        if [ -f "$SS_CONFIG_DIR/config.json" ]; then
            cat "$SS_CONFIG_DIR/config.json" | jq .
            print_msg "INFO" "Port: $(jq -r '.server_port' "$SS_CONFIG_DIR/config.json")"
            print_msg "INFO" "Password: $(jq -r '.password' "$SS_CONFIG_DIR/config.json")"
            print_msg "INFO" "Method: $(jq -r '.method' "$SS_CONFIG_DIR/config.json")"
            local SS_URI_DISPLAY="ss://$(echo -n "$(jq -r '.method' "$SS_CONFIG_DIR/config.json"):$(jq -r '.password' "$SS_CONFIG_DIR/config.json")" | base64 -w 0)@[$SERVER_IPV6]:$(jq -r '.server_port' "$SS_CONFIG_DIR/config.json")#MySSIPv6"
            print_msg "INFO" "Shadowsocks URI: $SS_URI_DISPLAY"
        else
            print_msg "WARN" "Shadowsocks (IPv6) 配置文件未找到：$SS_CONFIG_DIR/config.json"
        fi
        echo ""
    else
        print_msg "WARN" "Shadowsocks (IPv6) 未安装或已停止."
    fi
    echo "=========================================================="
    read -p "$(print_msg "PROMPT" "按任意键返回主菜单...")"
}

# Uninstall service
uninstall_service() {
    clear
    print_msg "INFO" "--- 卸载服务 ---"
    echo -e "  1. 卸载 Hysteria2"
    echo -e "  2. 卸载 Shadowsocks (仅 IPv6)"
    echo -e "  3. 卸载所有服务 (Hysteria2 & Shadowsocks)"
    echo -e "  0. 返回主菜单"
    echo "=========================================================="
    read -p "$(print_msg "PROMPT" "请选择一个操作 (0-3): ")" choice

    case "$choice" in
        1)
            print_msg "INFO" "正在卸载 Hysteria2..."
            systemctl stop "$HY2_SERVICE_NAME" >/dev/null 2>&1
            systemctl disable "$HY2_SERVICE_NAME" >/dev/null 2>&1
            rm -f "/etc/systemd/system/$HY2_SERVICE_NAME.service"
            rm -rf "$HY2_CONFIG_DIR"
            rm -f "/usr/local/bin/hysteria2"
            systemctl daemon-reload >/dev/null 2>&1
            # TODO: Clean firewall rules for Hysteria2 port
            # TODO: Remove acme.sh certs if ACME was used
            print_msg "SUCCESS" "Hysteria2 已卸载."
            ;;
        2)
            print_msg "INFO" "正在卸载 Shadowsocks (IPv6)..."
            systemctl stop "$SS_SERVICE_NAME" >/dev/null 2>&1
            systemctl disable "$SS_SERVICE_NAME" >/dev/null 2>&1
            rm -f "/etc/systemd/system/$SS_SERVICE_NAME.service"
            rm -rf "$SS_CONFIG_DIR"
            # TODO: This assumes ss-server was installed via package manager. If not, needs removal.
            case "$PKG_MANAGER" in
                "apt") apt remove -y shadowsocks-libev >/dev/log 2>&1 ;;
            esac
            systemctl daemon-reload >/dev/null 2>&1
            # TODO: Clean firewall rules for Shadowsocks port
            print_msg "SUCCESS" "Shadowsocks (IPv6) 已卸载."
            ;;
        3)
            print_msg "INFO" "正在卸载所有服务..."
            # Call option 1 and 2 logic here
            uninstall_service_sub_option 1 # Simulate calling Hysteria2 uninstall
            uninstall_service_sub_option 2 # Simulate calling Shadowsocks uninstall
            print_msg "SUCCESS" "所有相关服务已卸载."
            ;;
        0) return ;;
        *) print_msg "ERROR" "无效的选择，请重新输入。" ;;
    esac
    read -p "$(print_msg "PROMPT" "按任意键继续...")"
}

# Helper for uninstall_service (avoids recursion, just executes the logic)
uninstall_service_sub_option() {
    local opt="$1"
    if [ "$opt" -eq 1 ]; then # Hysteria2
        systemctl stop "$HY2_SERVICE_NAME" >/dev/null 2>&1
        systemctl disable "$HY2_SERVICE_NAME" >/dev/null 2>&1
        rm -f "/etc/systemd/system/$HY2_SERVICE_NAME.service"
        rm -rf "$HY2_CONFIG_DIR"
        rm -f "/usr/local/bin/hysteria2"
        # Optional: remove acme.sh certs and script if it's the only one using it
    elif [ "$opt" -eq 2 ]; then # Shadowsocks
        systemctl stop "$SS_SERVICE_NAME" >/dev/null 2>&1
        systemctl disable "$SS_SERVICE_NAME" >/dev/null 2>&1
        rm -f "/etc/systemd/system/$SS_SERVICE_NAME.service"
        rm -rf "$SS_CONFIG_DIR"
        case "$PKG_MANAGER" in
            "apt") apt remove -y shadowsocks-libev >/dev/log 2>&1 ;;
        esac
    fi
    systemctl daemon-reload >/dev/null 2>&1
}


# Backup configuration
backup_config() {
    clear
    print_msg "INFO" "--- 备份配置 ---"
    mkdir -p "$BACKUP_DIR"
    local TIMESTAMP=$(date +"%Y%m%d%H%M%S")
    local BACKUP_FILE="$BACKUP_DIR/hy2ss_config_backup_${TIMESTAMP}.tar.gz"

    print_msg "INFO" "正在创建备份到: $BACKUP_FILE"
    tar -czf "$BACKUP_FILE" "$HY2_CONFIG_DIR" "$SS_CONFIG_DIR" "/etc/systemd/system/$HY2_SERVICE_NAME.service" "/etc/systemd/system/$SS_SERVICE_NAME.service" "$HOME/.acme.sh" 2>/dev/null
    if [ $? -eq 0 ]; then
        print_msg "SUCCESS" "配置备份成功！文件位于: $BACKUP_FILE"
        print_msg "INFO" "备份内容包括：Hysteria2配置、Shadowsocks配置、Systemd服务文件 (如存在) 和 acme.sh证书 (如存在)."
    else
        print_msg "ERROR" "配置备份失败，请检查相关目录和文件是否存在以及权限。"
    fi

    # Placeholder for remote backup (e.g., rsync, S3 API)
    # read -p "$(print_msg "PROMPT" "是否上传到远程存储？(y/N): ")" upload_choice
    # if [[ "$upload_choice" =~ ^[yY]$ ]]; then
    #     print_msg "WARN" "远程存储功能尚未实现。"
    # fi
    echo "=========================================================="
    read -p "$(print_msg "PROMPT" "按任意键返回主菜单...")"
}

# System diagnostics
system_diagnostics() {
    clear
    print_msg "INFO" "--- 系统诊断 ---"
    echo "服务器时间: $(date)"
    echo "操作系统: $OS $VERSION_ID"
    echo "内核版本: $(uname -r)"
    echo "CPU 架构: $(uname -m)"

    print_msg "INFO" "网络连通性检查 (Google.com):"
    ping -c 4 google.com >/dev/null 2>&1 && print_msg "SUCCESS" "IPv4 Reachable." || print_msg "ERROR" "IPv4 Unreachable."
    ping6 -c 4 google.com >/dev/null 2>&1 && print_msg "SUCCESS" "IPv6 Reachable." || print_msg "ERROR" "IPv6 Unreachable."

    echo ""
    print_msg "INFO" "Hysteria2 服务状态:"
    if systemctl is-active --quiet "$HY2_SERVICE_NAME"; then
        print_msg "SUCCESS" "Hysteria2 运行中."
        systemctl status "$HY2_SERVICE_NAME" --no-pager | grep -E "Active:|Memory:|CPU:"
        local HY2_CURRENT_PORT=$(jq -r '.listen' "$HY2_CONFIG_DIR/config.json" | cut -d':' -f2 2>/dev/null)
        if [ -n "$HY2_CURRENT_PORT" ]; then
            ss -tulnp | grep ":$HY2_CURRENT_PORT " >/dev/null 2>&1 && print_msg "SUCCESS" "Hysteria2 端口 $HY2_CURRENT_PORT 正在监听." || print_msg "ERROR" "Hysteria2 端口 $HY2_CURRENT_PORT 未监听."
            # Check firewall for Hysteria2 port
            if command -v ufw &>/dev/null; then
                ufw status | grep "$HY2_CURRENT_PORT" | grep "ALLOW" >/dev/null 2>&1 && print_msg "SUCCESS" "UFW 允许 Hysteria2 端口 $HY2_CURRENT_PORT." || print_msg "WARN" "UFW 可能未允许 Hysteria2 端口 $HY2_CURRENT_PORT."
            elif command -v firewall-cmd &>/dev/null; then
                firewall-cmd --query-port="$HY2_CURRENT_PORT"/tcp >/dev/null 2>&1 && print_msg "SUCCESS" "Firewalld 允许 Hysteria2 端口 $HY2_CURRENT_PORT." || print_msg "WARN" "Firewalld 可能未允许 Hysteria2 端口 $HY2_CURRENT_PORT."
            fi
        fi
    else
        print_msg "WARN" "Hysteria2 未运行或未安装."
    fi

    echo ""
    print_msg "INFO" "Shadowsocks (IPv6) 服务状态:"
    if systemctl is-active --quiet "$SS_SERVICE_NAME"; then
        print_msg "SUCCESS" "Shadowsocks (IPv6) 运行中."
        systemctl status "$SS_SERVICE_NAME" --no-pager | grep -E "Active:|Memory:|CPU:"
        local SS_CURRENT_PORT=$(jq -r '.server_port' "$SS_CONFIG_DIR/config.json" 2>/dev/null)
        if [ -n "$SS_CURRENT_PORT" ]; then
            ss -tulnp | grep ":$SS_CURRENT_PORT " | grep "::" >/dev/null 2>&1 && print_msg "SUCCESS" "Shadowsocks IPv6 端口 $SS_CURRENT_PORT 正在监听." || print_msg "ERROR" "Shadowsocks IPv6 端口 $SS_CURRENT_PORT 未监听."
            # Check firewall for Shadowsocks port
            if command -v ufw &>/dev/null; then
                ufw status | grep "$SS_CURRENT_PORT" | grep "ALLOW" >/dev/null 2>&1 && print_msg "SUCCESS" "UFW 允许 Shadowsocks 端口 $SS_CURRENT_PORT." || print_msg "WARN" "UFW 可能未允许 Shadowsocks 端口 $SS_CURRENT_PORT."
            elif command -v firewall-cmd &>/dev/null; then
                firewall-cmd --query-port="$SS_CURRENT_PORT"/tcp >/dev/null 2>&1 && print_msg "SUCCESS" "Firewalld 允许 Shadowsocks 端口 $SS_CURRENT_PORT." || print_msg "WARN" "Firewalld 可能未允许 Shadowsocks 端口 $SS_CURRENT_PORT."
            fi
        fi
    else
        print_msg "WARN" "Shadowsocks (IPv6) 未运行或未安装."
    fi

    echo ""
    print_msg "INFO" "磁盘空间使用情况:"
    df -h / | awk 'NR==2 {print "根目录使用: " $5 " (" $4 " free)"}'

    echo ""
    print_msg "INFO" "内存使用情况:"
    free -h | awk 'NR==2 {print "总内存: " $2 ", 已用: " $3 ", 可用: " $4}'

    echo "=========================================================="
    read -p "$(print_msg "PROMPT" "按任意键返回主菜单...")"
}

# --- Main Menu Display ---
display_menu() {
    clear
    local hy2_status=$(get_service_status "$HY2_SERVICE_NAME")
    local ss_status=$(get_service_status "$SS_SERVICE_NAME")

    echo -e "${GREEN}Hysteria2 & Shadowsocks (IPv6) Management Script (v$SCRIPT_VERSION)${NC}"
    echo -e "项目地址：${BLUE}$PROJECT_REPO${NC}"
    echo ""
    echo -e " 服务器IP: $SERVER_IPV4 (IPv4) / $SERVER_IPV6 (IPv6)"
    echo -e " 服务状态: Hysteria2: $hy2_status | Shadowsocks(IPv6): $ss_status"
    echo "=========================================================="
    echo -e " ${PURPLE}安装选项:${NC}"
    echo -e "   1. 安装 Hysteria2 (自签名证书模式，无需域名解析)"
    echo -e "   2. 安装 Hysteria2 (ACME 证书模式，需域名 & Cloudflare API)"
    echo -e "   3. 安装 Shadowsocks (仅 IPv6)"
    echo ""
    echo -e " ${PURPLE}管理与维护:${NC}"
    echo -e "   4. 服务管理 (启动/停止/日志)"
    echo -e "   5. 显示配置信息"
    echo -e "   6. 卸载服务"
    echo -e "   7. 备份配置"
    echo -e "   8. 系统诊断"
    echo ""
    echo -e "   0. ${RED}退出脚本${NC}"
    echo "=========================================================="
    read -p "$(print_msg "PROMPT" "请输入您的选择 (0-8): ")" choice
}

# --- Main Script Execution ---
main() {
    check_root
    detect_os
    install_dependencies
    check_ipv6_connectivity

    while true; do
        display_menu
        case "$choice" in
            1) install_hysteria2_self_signed_cert ;;
            2) install_hysteria2_acme_cert ;;
            3) install_shadowsocks_ipv6 ;;
            4) manage_services ;;
            5) show_config_info ;;
            6) uninstall_service ;;
            7) backup_config ;;
            8) system_diagnostics ;;
            0)
                print_msg "INFO" "Exiting script. Goodbye!"
                exit 0
                ;;
            *)
                print_msg "ERROR" "无效的选择，请重新输入。"
                read -p "$(print_msg "PROMPT" "按任意键继续...")"
                ;;
        esac
    done
}

# Call the main function
main
