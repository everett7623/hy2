#!/bin/bash
# Hysteria2 + Cloudflare Tunnel 一键安装脚本 (IPv6 Only VPS)
# GitHub: https://github.com/everett7623/hy2ipv6
# 增强版 - 支持完善的卸载和重试机制

set -e

# ========= 基础配置 =========
PORT=443 # Hysteria2 服务端口
PASSWORD=$(openssl rand -base64 16) # 自动生成 Hysteria2 密码
SNI=www.bing.com   # 可改成任意域名伪装，用于 Hysteria2 TLS SNI 和客户端配置
TUNNEL_NAME=hy2-tunnel # Cloudflare Tunnel 的名称

# 全局变量
CF_CONFIG_DIR="/etc/cloudflared"
HYSTERIA_CONFIG_DIR="/etc/hysteria"
SCRIPT_LOG="/var/log/hysteria_install.log"

# 日志函数
log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "\033[32m$msg\033[0m" | tee -a "$SCRIPT_LOG"
}

log_warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1"
    echo -e "\033[33m$msg\033[0m" | tee -a "$SCRIPT_LOG"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "\033[31m$msg\033[0m" | tee -a "$SCRIPT_LOG"
}

# 显示帮助信息
show_help() {
    echo "Hysteria2 + Cloudflare Tunnel 安装脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  install     安装 Hysteria2 + Cloudflare Tunnel"
    echo "  uninstall   完全卸载所有组件"
    echo "  reinstall   卸载后重新安装"
    echo "  status      查看服务状态"
    echo "  config      显示客户端配置"
    echo "  -h, --help  显示此帮助信息"
    echo ""
}

# 检测系统类型
check_system() {
    if [ -f /etc/debian_version ]; then
        log_info "检测到 Debian/Ubuntu 系统"
        return 0
    elif [ -f /etc/redhat-release ]; then
        log_error "暂不支持 RedHat/CentOS 系统"
        exit 1
    else
        log_warn "无法确定系统类型，假设为 Debian/Ubuntu"
    fi
}

# 检查是否为 root 用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "请使用 root 用户运行此脚本"
        exit 1
    fi
}

# 检查 IPv6 连通性
check_ipv6() {
    log_info "检查 IPv6 连通性..."
    if ping6 -c 1 google.com &> /dev/null; then
        log_info "IPv6 连通性正常"
    else
        log_warn "IPv6 连通性检查失败，但继续安装"
    fi
}

# 服务状态检查函数
check_service_status() {
    local service_name="$1"
    local max_attempts=15
    local attempt=1
    
    log_info "检查服务 $service_name 状态..."
    while [ $attempt -le $max_attempts ]; do
        if systemctl is-active --quiet "$service_name"; then
            log_info "✅ $service_name 服务运行正常"
            return 0
        fi
        log_info "等待服务启动... ($attempt/$max_attempts)"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log_error "❌ $service_name 服务启动失败"
    log_error "请检查日志：journalctl -u $service_name --no-pager -n 20"
    return 1
}

# 完全卸载 Hysteria2
uninstall_hysteria() {
    log_info "卸载 Hysteria2..."
    
    # 停止并禁用服务
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        systemctl stop hysteria-server
        log_info "Hysteria2 服务已停止"
    fi
    
    if systemctl is-enabled --quiet hysteria-server 2>/dev/null; then
        systemctl disable hysteria-server
        log_info "Hysteria2 服务已禁用"
    fi
    
    # 删除服务文件
    if [ -f "/etc/systemd/system/hysteria-server.service" ]; then
        rm -f /etc/systemd/system/hysteria-server.service
        log_info "删除 Hysteria2 服务文件"
    fi
    
    # 删除二进制文件
    if [ -f "/usr/local/bin/hysteria2" ]; then
        rm -f /usr/local/bin/hysteria2
        log_info "删除 Hysteria2 二进制文件"
    fi
    
    # 删除配置目录
    if [ -d "$HYSTERIA_CONFIG_DIR" ]; then
        rm -rf "$HYSTERIA_CONFIG_DIR"
        log_info "删除 Hysteria2 配置目录"
    fi
    
    systemctl daemon-reload
    log_info "Hysteria2 卸载完成"
}

# 完全卸载 Cloudflare Tunnel
uninstall_cloudflared() {
    log_info "卸载 Cloudflare Tunnel..."
    
    # 停止并禁用所有可能的 cloudflared 服务
    for service in cloudflared cloudflared-tunnel@${TUNNEL_NAME} cloudflared@${TUNNEL_NAME}; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" 2>/dev/null || true
            log_info "停止服务: $service"
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            systemctl disable "$service" 2>/dev/null || true
            log_info "禁用服务: $service"
        fi
    done
    
    # 删除所有可能的服务文件
    for service_file in /etc/systemd/system/cloudflared*.service /lib/systemd/system/cloudflared*.service; do
        if [ -f "$service_file" ]; then
            rm -f "$service_file"
            log_info "删除服务文件: $service_file"
        fi
    done
    
    # 使用 cloudflared service uninstall (如果可用)
    if command -v cloudflared &> /dev/null; then
        cloudflared service uninstall 2>/dev/null || true
        log_info "执行 cloudflared service uninstall"
    fi
    
    # 删除现有隧道
    if command -v cloudflared &> /dev/null; then
        local existing_tunnels
        existing_tunnels=$(cloudflared tunnel list --json 2>/dev/null | grep -o "\"name\":\"$TUNNEL_NAME\"" | wc -l)
        
        if [ "$existing_tunnels" -gt 0 ]; then
            log_info "删除现有隧道: $TUNNEL_NAME"
            cloudflared tunnel delete "$TUNNEL_NAME" 2>/dev/null || true
        fi
    fi
    
    # 删除 cloudflared 二进制文件和包
    if command -v cloudflared &> /dev/null; then
        if dpkg -l | grep -q cloudflared; then
            apt remove -y cloudflared 2>/dev/null || true
            log_info "卸载 cloudflared 软件包"
        fi
        
        # 删除可能残留的二进制文件
        for bin_path in /usr/local/bin/cloudflared /usr/bin/cloudflared /opt/cloudflared/cloudflared; do
            if [ -f "$bin_path" ]; then
                rm -f "$bin_path"
                log_info "删除二进制文件: $bin_path"
            fi
        done
    fi
    
    # 删除配置目录
    if [ -d "$CF_CONFIG_DIR" ]; then
        rm -rf "$CF_CONFIG_DIR"
        log_info "删除 Cloudflare 配置目录: $CF_CONFIG_DIR"
    fi
    
    # 删除用户家目录下的配置
    if [ -d "/root/.cloudflared" ]; then
        rm -rf /root/.cloudflared
        log_info "删除用户 Cloudflare 配置目录"
    fi
    
    systemctl daemon-reload
    log_info "Cloudflare Tunnel 卸载完成"
}

# 完全卸载所有组件
uninstall_all() {
    log_info "开始完全卸载..."
    
    uninstall_hysteria
    uninstall_cloudflared
    
    # 清理日志文件
    if [ -f "$SCRIPT_LOG" ]; then
        rm -f "$SCRIPT_LOG"
    fi
    
    log_info "✅ 完全卸载成功！"
}

# 检查组件安装状态
check_installation_status() {
    local hysteria_installed=false
    local cloudflared_installed=false
    
    # 检查 Hysteria2
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hysteria_installed=true
        log_info "检测到 Hysteria2 正在运行"
    elif [ -f "/usr/local/bin/hysteria2" ] || [ -d "$HYSTERIA_CONFIG_DIR" ]; then
        log_warn "检测到 Hysteria2 残留文件"
    fi
    
    # 检查 Cloudflared
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        cloudflared_installed=true
        log_info "检测到 Cloudflared 正在运行"
    elif command -v cloudflared &> /dev/null || [ -d "$CF_CONFIG_DIR" ]; then
        log_warn "检测到 Cloudflared 残留文件"
    fi
    
    if $hysteria_installed && $cloudflared_installed; then
        return 0 # 都已安装
    elif $hysteria_installed || $cloudflared_installed; then
        return 1 # 部分安装
    else
        return 2 # 未安装
    fi
}

# 安全的 UUID 获取函数
get_tunnel_uuid() {
    local uuid=""
    
    if [ -d "/root/.cloudflared" ]; then
        # 查找最新创建的 JSON 文件
        local json_file=$(find /root/.cloudflared -name "*.json" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
        
        if [ -n "$json_file" ] && [ -f "$json_file" ]; then
            uuid=$(basename "$json_file" .json)
            if [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
                echo "$uuid"
                return 0
            fi
        fi
    fi
    
    # 尝试从隧道列表获取
    uuid=$(cloudflared tunnel list --json 2>/dev/null | grep -A 5 "\"name\":\"$TUNNEL_NAME\"" | grep -oE '"id":"[0-9a-f-]{36}"' | cut -d':' -f2 | tr -d '"' | head -1)
    
    if [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo "$uuid"
        return 0
    fi
    
    log_error "无法获取有效的隧道 UUID"
    return 1
}

# 原子化安装 Hysteria2（要么成功要么回滚）
install_hysteria_atomic() {
    local temp_dir=$(mktemp -d)
    local rollback_needed=false
    
    log_info "原子化安装 Hysteria2..."
    
    # 创建临时安装标记
    echo "Installing Hysteria2..." > "${temp_dir}/hysteria_install_flag"
    
    # 下载并安装 Hysteria2
    if ! bash <(curl -fsSL https://get.hy2.sh); then
        log_error "Hysteria2 安装失败"
        rm -rf "$temp_dir"
        return 1
    fi
    rollback_needed=true
    
    # 创建配置目录
    mkdir -p "$HYSTERIA_CONFIG_DIR"
    
    # 生成 Hysteria2 配置文件
    cat > "$HYSTERIA_CONFIG_DIR/config.yaml" <<EOF
listen: :$PORT

tls:
  insecure: true
  sni: $SNI

auth:
  type: password
  password: $PASSWORD

masq:
  type: wireguard
EOF
    
    chmod 600 "$HYSTERIA_CONFIG_DIR/config.yaml"
    
    # 创建 Hysteria2 Systemd 服务文件
    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria2 server -c $HYSTERIA_CONFIG_DIR/config.yaml
Restart=always
RestartSec=3
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF
    
    # 重载并启动服务
    systemctl daemon-reload
    systemctl enable hysteria-server
    
    if ! systemctl start hysteria-server; then
        log_error "Hysteria2 服务启动失败，开始回滚"
        uninstall_hysteria
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 验证服务状态
    if ! check_service_status "hysteria-server"; then
        log_error "Hysteria2 服务验证失败，开始回滚"
        uninstall_hysteria
        rm -rf "$temp_dir"
        return 1
    fi
    
    rm -rf "$temp_dir"
    log_info "Hysteria2 原子化安装成功"
    return 0
}

# 原子化安装 Cloudflare Tunnel（要么成功要么回滚）
install_cloudflared_atomic() {
    local temp_dir=$(mktemp -d)
    local rollback_needed=false
    
    log_info "原子化安装 Cloudflare Tunnel..."
    
    # 创建临时安装标记
    echo "Installing Cloudflared..." > "${temp_dir}/cloudflared_install_flag"
    
    # 检测系统架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) CLOUDFLARED_ARCH="amd64" ;;
        aarch64) CLOUDFLARED_ARCH="arm64" ;;
        armv7l) CLOUDFLARED_ARCH="arm" ;;
        *)
            log_error "不支持的系统架构: $ARCH"
            rm -rf "$temp_dir"
            return 1
            ;;
    esac
    
    # 下载并安装 cloudflared
    CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CLOUDFLARED_ARCH}.deb"
    
    if ! wget -q "$CLOUDFLARED_URL" -O "${temp_dir}/cloudflared-linux.deb"; then
        log_error "cloudflared 下载失败"
        rm -rf "$temp_dir"
        return 1
    fi
    
    if ! apt install -y "${temp_dir}/cloudflared-linux.deb"; then
        log_error "cloudflared 安装失败"
        rm -rf "$temp_dir"
        return 1
    fi
    rollback_needed=true
    
    # Cloudflare 登录授权
    log_info "请在浏览器中完成 Cloudflare 登录授权..."
    if ! timeout 300 cloudflared tunnel login; then
        log_error "Cloudflare 登录授权失败或超时"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 创建配置目录
    mkdir -p "$CF_CONFIG_DIR"
    
    # 生成个性化的隧道域名
    RANDOM_SUFFIX=$(openssl rand -hex 4)
    CF_TUNNEL_DOMAIN="hy2-${RANDOM_SUFFIX}.cfargotunnel.com"
    
    # 创建隧道
    log_info "创建隧道: $TUNNEL_NAME"
    if ! cloudflared tunnel create "$TUNNEL_NAME"; then
        log_error "创建隧道失败"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 获取隧道 UUID
    UUID=$(get_tunnel_uuid)
    if [ -z "$UUID" ]; then
        log_error "无法获取隧道 UUID"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    log_info "隧道 UUID: $UUID"
    
    # 复制凭证文件
    CREDENTIALS_FILE="/root/.cloudflared/$UUID.json"
    if [ -f "$CREDENTIALS_FILE" ]; then
        cp "$CREDENTIALS_FILE" "$CF_CONFIG_DIR/"
        chmod 600 "$CF_CONFIG_DIR/$UUID.json"
    else
        log_error "找不到隧道凭证文件: $CREDENTIALS_FILE"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 生成配置文件
    cat > "$CF_CONFIG_DIR/config.yml" <<EOF
tunnel: $UUID
credentials-file: $CF_CONFIG_DIR/$UUID.json

ingress:
  - hostname: $CF_TUNNEL_DOMAIN
    service: https://localhost:$PORT
  - service: http_status:404
EOF
    
    chmod 600 "$CF_CONFIG_DIR/config.yml"
    
    # 安装系统服务
    if ! cloudflared service install --config "$CF_CONFIG_DIR/config.yml"; then
        log_error "Cloudflare Tunnel 服务安装失败"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 启动服务
    if ! systemctl enable --now cloudflared; then
        log_error "Cloudflare Tunnel 服务启动失败"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 验证服务状态
    if ! check_service_status "cloudflared"; then
        log_error "Cloudflare Tunnel 服务验证失败"
        if $rollback_needed; then uninstall_cloudflared; fi
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 保存域名信息到文件
    echo "$CF_TUNNEL_DOMAIN" > "$CF_CONFIG_DIR/domain.txt"
    echo "$UUID" > "$CF_CONFIG_DIR/uuid.txt"
    
    rm -rf "$temp_dir"
    log_info "Cloudflare Tunnel 原子化安装成功"
    return 0
}

# 主安装函数
install_all() {
    log_info "=== 开始安装 Hysteria2 + Cloudflare Tunnel ==="
    
    # 前置检查
    check_root
    check_system
    check_ipv6
    
    # 检查现有安装
    check_installation_status
    local install_status=$?
    
    if [ $install_status -eq 0 ]; then
        log_warn "检测到完整安装，建议先卸载"
        read -p "是否继续安装？(y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_info "安装已取消"
            exit 0
        fi
    elif [ $install_status -eq 1 ]; then
        log_warn "检测到部分安装或残留文件，建议先完全卸载"
        read -p "是否先执行完全卸载？(Y/n): " confirm
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            uninstall_all
            log_info "卸载完成，3秒后继续安装..."
            sleep 3
        fi
    fi
    
    # 更新系统
    log_info "更新系统并安装依赖..."
    apt update -y
    apt install -y curl wget unzip socat net-tools iputils-ping dnsutils
    
    # 原子化安装 Hysteria2
    if ! install_hysteria_atomic; then
        log_error "Hysteria2 安装失败"
        exit 1
    fi
    
    # 原子化安装 Cloudflare Tunnel
    if ! install_cloudflared_atomic; then
        log_error "Cloudflare Tunnel 安装失败，回滚 Hysteria2"
        uninstall_hysteria
        exit 1
    fi
    
    # 获取 IPv6 地址
    IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    if [ -z "$IPV6" ]; then
        IPV6="未找到IPv6地址"
        log_warn "未找到 IPv6 地址"
    fi
    
    # 从保存的文件读取信息
    if [ -f "$CF_CONFIG_DIR/domain.txt" ]; then
        CF_TUNNEL_DOMAIN=$(cat "$CF_CONFIG_DIR/domain.txt")
    else
        CF_TUNNEL_DOMAIN="域名获取失败"
    fi
    
    if [ -f "$CF_CONFIG_DIR/uuid.txt" ]; then
        UUID=$(cat "$CF_CONFIG_DIR/uuid.txt")
    else
        UUID="UUID获取失败"
    fi
    
    show_config
    log_info "✅ 安装完成！"
}

# 显示服务状态
show_status() {
    log_info "=== 服务状态 ==="
    
    echo "Hysteria2 服务状态:"
    systemctl status hysteria-server --no-pager -l || echo "Hysteria2 服务未运行"
    
    echo -e "\nCloudflare Tunnel 服务状态:"
    systemctl status cloudflared --no-pager -l || echo "Cloudflare Tunnel 服务未运行"
    
    echo -e "\n服务日志 (最近10行):"
    echo "--- Hysteria2 日志 ---"
    journalctl -u hysteria-server --no-pager -n 10 || echo "无日志"
    
    echo "--- Cloudflared 日志 ---"
    journalctl -u cloudflared --no-pager -n 10 || echo "无日志"
}

# 显示客户端配置
show_config() {
    # 获取信息
    if [ -f "$HYSTERIA_CONFIG_DIR/config.yaml" ]; then
        PASSWORD=$(grep "password:" "$HYSTERIA_CONFIG_DIR/config.yaml" | awk '{print $2}')
    else
        PASSWORD="配置文件不存在"
    fi
    
    if [ -f "$CF_CONFIG_DIR/domain.txt" ]; then
        CF_TUNNEL_DOMAIN=$(cat "$CF_CONFIG_DIR/domain.txt")
    else
        CF_TUNNEL_DOMAIN="域名文件不存在"
    fi
    
    IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)
    if [ -z "$IPV6" ]; then
        IPV6="未找到IPv6地址"
    fi
    
    echo -e "\n======================================================="
    echo -e "🎉 Hysteria2 + Cloudflare Tunnel 配置信息"
    echo -e "======================================================="
    echo "📌 VPS IPv6 地址: [$IPV6]:$PORT"
    echo "🔐 Hysteria2 密码: $PASSWORD"
    echo "🌐 Cloudflare Tunnel 域名: $CF_TUNNEL_DOMAIN"
    echo "🔧 SNI: $SNI"
    echo "---"
    
    echo -e "\n📎 Clash Meta 配置:"
    cat <<EOL
- name: 🌐 Hy2-CF-Tunnel
  type: hysteria2
  server: $CF_TUNNEL_DOMAIN
  port: 443
  password: "$PASSWORD"
  sni: "$SNI"
  skip-cert-verify: true

- name: 🌐 Hy2-Direct-IPv6
  type: hysteria2
  server: "$IPV6"
  port: $PORT
  password: "$PASSWORD"
  sni: "$SNI"
  skip-cert-verify: true
EOL
    
    echo -e "\n📎 Sing-box 配置:"
    cat <<EOL
{
  "type": "hysteria2",
  "tag": "Hy2-CF-Tunnel",
  "server": "$CF_TUNNEL_DOMAIN",
  "server_port": 443,
  "password": "$PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "$SNI",
    "insecure": true
  }
},
{
  "type": "hysteria2",
  "tag": "Hy2-Direct-IPv6",
  "server": "$IPV6",
  "server_port": $PORT,
  "password": "$PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "$SNI",
    "insecure": true
  }
}
EOL
    
    echo -e "\n🔧 管理命令:"
    echo "查看服务状态: $0 status"
    echo "显示配置: $0 config"
    echo "重新安装: $0 reinstall"
    echo "完全卸载: $0 uninstall"
    echo -e "======================================================="
}

# 主函数
main() {
    # 创建日志目录
    touch "$SCRIPT_LOG"
    
    case "${1:-install}" in
        "install")
            install_all
            ;;
        "uninstall")
            uninstall_all
            ;;
        "reinstall")
            log_info "执行重新安装..."
            uninstall_all
            sleep 2
            install_all
            ;;
        "status")
            show_status
            ;;
        "config")
            show_config
            ;;
        "-h"|"--help"|"help")
            show_help
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"
