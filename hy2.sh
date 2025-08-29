#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 一键安装脚本
# 作者: Jensfrank
# 版本: 1.0.0
# 更新日期: 2025-08-29

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 日志级别
LOG_LEVEL=${LOG_LEVEL:-"INFO"}

# 日志函数
log_debug() {
    [[ "$LOG_LEVEL" == "DEBUG" ]] && echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $1${NC}"
}

log_info() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1${NC}"
}

# 全局变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HYSTERIA_CONFIG_DIR="/etc/hysteria"
CF_CONFIG_DIR="/etc/cloudflared"
HYSTERIA_SERVICE_FILE="/etc/systemd/system/hysteria-server.service"
CLOUDFLARED_SERVICE_FILE="/etc/systemd/system/cloudflared.service"

# 默认配置
DEFAULT_PORT=443
DEFAULT_OBFS_PASSWORD=""
DEFAULT_AUTH_PASSWORD=""
TUNNEL_NAME=""
CF_DOMAIN=""
CF_UUID=""

# 检测系统信息
detect_system() {
    log_info "检测系统信息..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        VER=$(lsb_release -sr)
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS=$(echo $DISTRIB_ID | tr '[:upper:]' '[:lower:]')
        VER=$DISTRIB_RELEASE
    else
        log_error "无法检测操作系统"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            log_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "系统: $OS $VER"
    log_info "架构: $ARCH"
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        exit 1
    fi
}

# 检查网络连接
check_network() {
    log_info "检查网络连接..."
    
    # 检查 IPv4 连接
    if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log_info "IPv4 网络连接正常"
        IPV4_AVAILABLE=true
    else
        log_warn "IPv4 网络连接不可用"
        IPV4_AVAILABLE=false
    fi
    
    # 检查 IPv6 连接
    if ping6 -c 1 -W 5 2001:4860:4860::8888 >/dev/null 2>&1; then
        log_info "IPv6 网络连接正常"
        IPV6_AVAILABLE=true
    else
        log_warn "IPv6 网络连接不可用"
        IPV6_AVAILABLE=false
    fi
    
    if [[ "$IPV4_AVAILABLE" == false && "$IPV6_AVAILABLE" == false ]]; then
        log_error "网络连接不可用"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    log_info "安装系统依赖..."
    
    case $OS in
        ubuntu|debian)
            apt update
            apt install -y curl wget unzip systemd
            ;;
        centos|rhel|fedora)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y curl wget unzip systemd
            else
                yum install -y curl wget unzip systemd
            fi
            ;;
        *)
            log_error "不支持的操作系统: $OS"
            exit 1
            ;;
    esac
}

# 下载文件函数
download_file() {
    local url="$1"
    local output="$2"
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        log_debug "尝试下载 $url (第 $((retry_count + 1)) 次)"
        
        if curl -L -o "$output" "$url" --connect-timeout 10 --max-time 300; then
            log_debug "下载成功: $output"
            return 0
        else
            log_warn "下载失败，重试中..."
            ((retry_count++))
            sleep 2
        fi
    done
    
    log_error "下载失败: $url"
    return 1
}

# 安装 Hysteria2
install_hysteria() {
    log_info "开始安装 Hysteria2..."
    
    # 获取最新版本
    local latest_version
    if ! latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); then
        log_error "获取 Hysteria2 最新版本失败"
        return 1
    fi
    
    log_info "最新版本: $latest_version"
    
    # 下载 Hysteria2
    local download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
    if ! download_file "$download_url" "/usr/local/bin/hysteria"; then
        return 1
    fi
    
    chmod +x /usr/local/bin/hysteria
    
    # 创建配置目录
    mkdir -p "$HYSTERIA_CONFIG_DIR"
    
    log_info "Hysteria2 安装完成"
    return 0
}

# 生成 Hysteria2 配置
generate_hysteria_config() {
    log_info "生成 Hysteria2 配置..."
    
    # 获取服务器 IP
    local server_ip
    if [[ "$IPV6_AVAILABLE" == true ]]; then
        server_ip=$(curl -s -6 ifconfig.me || curl -s -6 icanhazip.com)
        if [[ -z "$server_ip" ]]; then
            log_warn "获取 IPv6 地址失败，尝试获取 IPv4 地址"
            server_ip=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com)
        fi
    else
        server_ip=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com)
    fi
    
    if [[ -z "$server_ip" ]]; then
        log_error "无法获取服务器 IP 地址"
        return 1
    fi
    
    log_info "服务器 IP: $server_ip"
    
    # 生成随机密码
    if [[ -z "$DEFAULT_AUTH_PASSWORD" ]]; then
        DEFAULT_AUTH_PASSWORD=$(openssl rand -base64 32)
    fi
    
    if [[ -z "$DEFAULT_OBFS_PASSWORD" ]]; then
        DEFAULT_OBFS_PASSWORD=$(openssl rand -base64 16)
    fi
    
    # 生成配置文件
    cat > "$HYSTERIA_CONFIG_DIR/config.yaml" << EOF
listen: :$DEFAULT_PORT

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: $DEFAULT_AUTH_PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true

bandwidth:
  up: 1 gbps
  down: 1 gbps

ignoreClientBandwidth: false

udpIdleTimeout: 60s
udpHopInterval: 30s

resolver:
  type: https
  https:
    addr: 8.8.8.8:443
    timeout: 10s

acl:
  inline:
    - reject(geoip:cn)

obfs:
  type: salamander
  salamander:
    password: $DEFAULT_OBFS_PASSWORD
EOF
    
    log_info "Hysteria2 配置生成完成"
    return 0
}

# 生成自签名证书
generate_certificates() {
    log_info "生成自签名证书..."
    
    # 生成私钥
    openssl genrsa -out "$HYSTERIA_CONFIG_DIR/server.key" 2048
    
    # 生成证书
    openssl req -new -x509 -key "$HYSTERIA_CONFIG_DIR/server.key" \
        -out "$HYSTERIA_CONFIG_DIR/server.crt" -days 3650 \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=hysteria.local"
    
    # 设置权限
    chmod 600 "$HYSTERIA_CONFIG_DIR/server.key"
    chmod 644 "$HYSTERIA_CONFIG_DIR/server.crt"
    
    log_info "证书生成完成"
    return 0
}

# 创建 systemd 服务
create_hysteria_service() {
    log_info "创建 Hysteria2 systemd 服务..."
    
    cat > "$HYSTERIA_SERVICE_FILE" << EOF
[Unit]
Description=Hysteria Server Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable hysteria-server
    
    log_info "Hysteria2 服务创建完成"
    return 0
}

# 安装 Cloudflared
install_cloudflared() {
    log_info "开始安装 Cloudflared..."
    
    # 下载并安装 cloudflared
    case $OS in
        ubuntu|debian)
            if ! download_file "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb" "/tmp/cloudflared.deb"; then
                return 1
            fi
            dpkg -i /tmp/cloudflared.deb
            rm -f /tmp/cloudflared.deb
            ;;
        centos|rhel|fedora)
            if ! download_file "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.rpm" "/tmp/cloudflared.rpm"; then
                return 1
            fi
            rpm -i /tmp/cloudflared.rpm
            rm -f /tmp/cloudflared.rpm
            ;;
        *)
            # 通用安装方法
            if ! download_file "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}" "/usr/local/bin/cloudflared"; then
                return 1
            fi
            chmod +x /usr/local/bin/cloudflared
            ;;
    esac
    
    log_info "Cloudflared 安装完成"
    return 0
}

# 配置 Cloudflare Tunnel
configure_cloudflare_tunnel() {
    log_info "配置 Cloudflare Tunnel..."
    
    # 创建配置目录
    mkdir -p "$CF_CONFIG_DIR"
    
    # 生成随机隧道名称
    if [[ -z "$TUNNEL_NAME" ]]; then
        TUNNEL_NAME="hysteria-$(openssl rand -hex 4)"
    fi
    
    log_info "隧道名称: $TUNNEL_NAME"
    
    # 登录到 Cloudflare（需要用户手动操作）
    echo -e "${YELLOW}请在浏览器中完成 Cloudflare 登录...${NC}"
    cloudflared tunnel login
    
    # 创建隧道
    log_info "创建 Cloudflare 隧道..."
    cloudflared tunnel create "$TUNNEL_NAME"
    
    # 获取隧道 UUID
    CF_UUID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
    if [[ -z "$CF_UUID" ]]; then
        log_error "无法获取隧道 UUID"
        return 1
    fi
    
    log_info "隧道 UUID: $CF_UUID"
    
    # 生成域名
    CF_DOMAIN="${TUNNEL_NAME}.cfargotunnel.com"
    log_info "隧道域名: $CF_DOMAIN"
    
    # 创建配置文件
    cat > "$CF_CONFIG_DIR/config.yml" << EOF
tunnel: $CF_UUID
credentials-file: /root/.cloudflared/$CF_UUID.json

ingress:
  - hostname: $CF_DOMAIN
    service: https://localhost:$DEFAULT_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
    
    # 创建 DNS 记录
    log_info "创建 DNS 记录..."
    cloudflared tunnel route dns "$TUNNEL_NAME" "$CF_DOMAIN"
    
    # 保存配置信息
    echo "$CF_DOMAIN" > "$CF_CONFIG_DIR/domain.txt"
    echo "$CF_UUID" > "$CF_CONFIG_DIR/uuid.txt"
    echo "$TUNNEL_NAME" > "$CF_CONFIG_DIR/name.txt"
    
    log_info "Cloudflare Tunnel 配置完成"
    return 0
}

# 创建 Cloudflared 服务
create_cloudflared_service() {
    log_info "创建 Cloudflared systemd 服务..."
    
    # 检测 cloudflared 的安装位置
    local cloudflared_path
    if [ -f "/usr/bin/cloudflared" ]; then
        cloudflared_path="/usr/bin/cloudflared"
    elif [ -f "/usr/local/bin/cloudflared" ]; then
        cloudflared_path="/usr/local/bin/cloudflared"
    else
        cloudflared_path="cloudflared"  # 使用 PATH 中的版本
    fi
    
    # 创建 systemd 服务文件
    cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
User=root
ExecStart=$cloudflared_path tunnel --config $CF_CONFIG_DIR/config.yml run
Restart=always
RestartSec=5
KillMode=mixed
KillSignal=SIGINT
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载 systemd 并启用服务
    systemctl daemon-reload
    systemctl enable cloudflared
    systemctl start cloudflared
    
    log_info "Cloudflared 服务创建完成"
    return 0
}

# 检查服务状态
check_service_status() {
    local service_name="$1"
    if systemctl is-active --quiet "$service_name"; then
        log_info "$service_name 服务运行正常"
        return 0
    else
        log_error "$service_name 服务未运行"
        return 1
    fi
}

# 启动所有服务
start_services() {
    log_info "启动服务..."
    
    # 启动 Hysteria2
    systemctl start hysteria-server
    if ! check_service_status "hysteria-server"; then
        log_error "Hysteria2 服务启动失败"
        return 1
    fi
    
    # 启动 Cloudflared
    systemctl start cloudflared
    if ! check_service_status "cloudflared"; then
        log_error "Cloudflared 服务启动失败"
        return 1
    fi
    
    log_info "所有服务启动成功"
    return 0
}

# 显示配置信息
show_config() {
    log_info "安装完成！配置信息如下："
    
    echo -e "${GREEN}==================== Hysteria2 配置 ====================${NC}"
    echo -e "${CYAN}服务器地址:${NC} $CF_DOMAIN"
    echo -e "${CYAN}端口:${NC} $DEFAULT_PORT"
    echo -e "${CYAN}认证密码:${NC} $DEFAULT_AUTH_PASSWORD"
    echo -e "${CYAN}混淆密码:${NC} $DEFAULT_OBFS_PASSWORD"
    echo -e "${CYAN}协议:${NC} hysteria2"
    echo -e "${CYAN}传输层安全:${NC} TLS"
    echo -e "${CYAN}SNI:${NC} $CF_DOMAIN"
    echo -e "${CYAN}跳过证书验证:${NC} true"
    
    echo -e "\n${GREEN}==================== 客户端配置示例 ====================${NC}"
    cat << EOF
{
  "server": "$CF_DOMAIN:$DEFAULT_PORT",
  "auth": "$DEFAULT_AUTH_PASSWORD",
  "obfs": {
    "type": "salamander",
    "salamander": {
      "password": "$DEFAULT_OBFS_PASSWORD"
    }
  },
  "tls": {
    "sni": "$CF_DOMAIN",
    "insecure": true
  },
  "bandwidth": {
    "up": "100 mbps",
    "down": "100 mbps"
  },
  "socks5": {
    "listen": "127.0.0.1:1080"
  },
  "http": {
    "listen": "127.0.0.1:8080"
  }
}
EOF
    
    echo -e "\n${GREEN}==================== 管理命令 ====================${NC}"
    echo -e "${CYAN}查看 Hysteria2 状态:${NC} systemctl status hysteria-server"
    echo -e "${CYAN}查看 Cloudflared 状态:${NC} systemctl status cloudflared"
    echo -e "${CYAN}重启 Hysteria2:${NC} systemctl restart hysteria-server"
    echo -e "${CYAN}重启 Cloudflared:${NC} systemctl restart cloudflared"
    echo -e "${CYAN}查看 Hysteria2 日志:${NC} journalctl -u hysteria-server -f"
    echo -e "${CYAN}查看 Cloudflared 日志:${NC} journalctl -u cloudflared -f"
}

# 卸载函数
uninstall() {
    log_info "开始卸载 Hysteria2 和 Cloudflare Tunnel..."
    
    # 停止服务
    systemctl stop hysteria-server 2>/dev/null
    systemctl stop cloudflared 2>/dev/null
    
    # 禁用服务
    systemctl disable hysteria-server 2>/dev/null
    systemctl disable cloudflared 2>/dev/null
    
    # 删除服务文件
    rm -f "$HYSTERIA_SERVICE_FILE"
    rm -f "$CLOUDFLARED_SERVICE_FILE"
    
    # 删除二进制文件
    rm -f /usr/local/bin/hysteria
    rm -f /usr/local/bin/cloudflared
    
    # 删除配置目录
    rm -rf "$HYSTERIA_CONFIG_DIR"
    rm -rf "$CF_CONFIG_DIR"
    rm -rf /root/.cloudflared
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    log_info "卸载完成"
}

# 重新安装函数
reinstall() {
    log_info "开始重新安装..."
    uninstall
    sleep 2
    main install
}

# 显示帮助信息
show_help() {
    echo -e "${GREEN}Hysteria2 + IPv6 + Cloudflare Tunnel 一键安装脚本${NC}"
    echo -e "${GREEN}版本: 2.0.0${NC}"
    echo -e "${GREEN}作者: everett7623${NC}"
    echo ""
    echo -e "${CYAN}使用方法:${NC}"
    echo -e "  $0 [选项]"
    echo ""
    echo -e "${CYAN}选项:${NC}"
    echo -e "  install     安装 Hysteria2 和 Cloudflare Tunnel"
    echo -e "  uninstall   卸载 Hysteria2 和 Cloudflare Tunnel"
    echo -e "  reinstall   重新安装"
    echo -e "  status      查看服务状态"
    echo -e "  config      显示配置信息"
    echo -e "  help        显示此帮助信息"
    echo ""
    echo -e "${CYAN}环境变量:${NC}"
    echo -e "  LOG_LEVEL   日志级别 (DEBUG, INFO, WARN, ERROR)"
    echo -e "  DEFAULT_PORT   Hysteria2 端口 (默认: 443)"
    echo ""
    echo -e "${CYAN}示例:${NC}"
    echo -e "  $0 install"
    echo -e "  LOG_LEVEL=DEBUG $0 install"
    echo -e "  DEFAULT_PORT=8443 $0 install"
}

# 查看状态
show_status() {
    log_info "服务状态:"
    
    echo -e "\n${CYAN}Hysteria2 服务状态:${NC}"
    systemctl status hysteria-server --no-pager
    
    echo -e "\n${CYAN}Cloudflared 服务状态:${NC}"
    systemctl status cloudflared --no-pager
}

# 清理函数
cleanup_and_exit() {
    local exit_code=${1:-0}
    log_debug "清理临时文件..."
    rm -f /tmp/cloudflared.deb /tmp/cloudflared.rpm
    exit $exit_code
}

# 信号处理
trap 'cleanup_and_exit 130' INT
trap 'cleanup_and_exit 143' TERM

# 主安装函数
install_all() {
    log_info "开始安装 Hysteria2 + Cloudflare Tunnel..."
    
    # 检查系统
    detect_system
    check_root
    check_network
    
    # 安装依赖
    install_dependencies
    
    # 安装 Hysteria2
    if ! install_hysteria; then
        log_error "Hysteria2 安装失败"
        cleanup_and_exit 1
    fi
    
    # 生成证书
    if ! generate_certificates; then
        log_error "证书生成失败"
        cleanup_and_exit 1
    fi
    
    # 生成配置
    if ! generate_hysteria_config; then
        log_error "Hysteria2 配置生成失败"
        cleanup_and_exit 1
    fi
    
    # 创建服务
    if ! create_hysteria_service; then
        log_error "Hysteria2 服务创建失败"
        cleanup_and_exit 1
    fi
    
    # 安装 Cloudflared
    if ! install_cloudflared; then
        log_error "Cloudflared 安装失败"
        cleanup_and_exit 1
    fi
    
    # 配置 Cloudflare Tunnel
    if ! configure_cloudflare_tunnel; then
        log_error "Cloudflare Tunnel 配置失败"
        cleanup_and_exit 1
    fi
    
    # 创建 Cloudflared 服务
    if ! create_cloudflared_service; then
        log_error "Cloudflared 服务创建失败"
        cleanup_and_exit 1
    fi
    
    # 启动服务
    if ! start_services; then
        log_error "服务启动失败"
        cleanup_and_exit 1
    fi
    
    # 显示配置
    show_config
    
    log_info "安装完成！"
}

# 主函数
main() {
    case "${1:-install}" in
        install)
            install_all
            ;;
        uninstall)
            uninstall
            ;;
        reinstall)
            reinstall
            ;;
        status)
            show_status
            ;;
        config)
            show_config
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            cleanup_and_exit 1
            ;;
    esac
    cleanup_and_exit 0
}

# 运行主函数
main "$@"
