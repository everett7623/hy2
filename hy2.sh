#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks (IPv6) Management Script
# 作者：编程大师 (AI)
# 版本：v1.0
# GitHub: https://github.com/everett7623/hy2ipv6
# 博客: https://seedloc.com
# 论坛: https://nodeloc.com
#====================================================================================

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 脚本信息
SCRIPT_VERSION="1.0"
GITHUB_REPO="https://github.com/everett7623/hy2ipv6"
BLOG_URL="https://seedloc.com"
FORUM_URL="https://nodeloc.com"

# 系统变量
ARCH=""
OS=""
IPV4=""
IPV6=""
HYSTERIA2_CONFIG_PATH="/etc/hysteria2/config.yaml"
SHADOWSOCKS_CONFIG_PATH="/etc/shadowsocks-rust/config.json"

# 显示标题
show_header() {
    clear
    echo -e "${CYAN}================================================${NC}"
    echo -e "${WHITE}Hysteria2 & Shadowsocks (IPv6) Management Script (v${SCRIPT_VERSION})${NC}"
    echo -e "${BLUE}项目地址：${GITHUB_REPO}${NC}"
    echo -e "${BLUE}博客地址：${BLOG_URL}${NC}"
    echo -e "${BLUE}论坛地址：${FORUM_URL}${NC}"
    echo -e "${YELLOW}服务器 IPv4: ${IPV4:-"未检测到"}${NC}"
    echo -e "${YELLOW}服务器 IPv6: ${IPV6:-"未检测到"}${NC}"
    
    # 检查服务状态
    if systemctl is-active --quiet hysteria2 2>/dev/null; then
        echo -e "${GREEN}Hysteria2 状态: 运行中${NC}"
    elif [[ -f "$HYSTERIA2_CONFIG_PATH" ]]; then
        echo -e "${YELLOW}Hysteria2 状态: 已安装但未运行${NC}"
    else
        echo -e "${RED}Hysteria2 状态: 未安装${NC}"
    fi
    
    if systemctl is-active --quiet shadowsocks-rust 2>/dev/null; then
        echo -e "${GREEN}Shadowsocks 状态: 运行中${NC}"
    elif [[ -f "$SHADOWSOCKS_CONFIG_PATH" ]]; then
        echo -e "${YELLOW}Shadowsocks 状态: 已安装但未运行${NC}"
    else
        echo -e "${RED}Shadowsocks 状态: 未安装${NC}"
    fi
    
    echo -e "${CYAN}================================================${NC}"
}

# 日志函数
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $1"; }

# 进度显示函数
show_progress() {
    local duration=$1
    local message=$2
    local progress=0
    local bar_length=40
    
    echo -n -e "${CYAN}$message${NC} ["
    while [[ $progress -le $duration ]]; do
        local filled=$((progress * bar_length / duration))
        local empty=$((bar_length - filled))
        printf "%${filled}s" | tr ' ' '='
        printf "%${empty}s" | tr ' ' ' '
        printf "] %d%%\r" $((progress * 100 / duration))
        sleep 0.1
        ((progress++))
    done
    echo ""
}

# 检查系统架构和操作系统
check_system() {
    log_info "检查系统信息..."
    
    # 检查架构
    case $(uname -m) in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *) 
            log_error "不支持的系统架构: $(uname -m)"
            exit 1
            ;;
    esac
    
    # 检查操作系统
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
    else
        log_error "无法检测操作系统"
        exit 1
    fi
    
    case $OS in
        ubuntu|debian|centos|rhel|fedora|rocky|alma)
            log_info "检测到支持的操作系统: $OS"
            ;;
        *)
            log_warn "未明确支持的操作系统: $OS，脚本可能无法正常工作"
            ;;
    esac
    
    log_info "系统架构: $ARCH"
    log_info "操作系统: $OS"
}

# 检查内存
check_memory() {
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    log_info "系统内存: ${total_mem}MB"
    
    if [[ $total_mem -lt 500 ]]; then
        log_warn "检测到低内存VPS (${total_mem}MB)，将启用内存优化模式"
        return 1
    fi
    return 0
}

# 检查网络连接
check_network() {
    log_info "检查网络连接性..."
    
    # 检查IPv4
    if timeout 5 curl -4 -s https://ipv4.icanhazip.com >/dev/null 2>&1; then
        IPV4=$(timeout 5 curl -4 -s https://ipv4.icanhazip.com 2>/dev/null || echo "获取失败")
        log_info "IPv4 地址: $IPV4"
    else
        log_warn "IPv4 连接不可用"
    fi
    
    # 检查IPv6
    if timeout 5 curl -6 -s https://ipv6.icanhazip.com >/dev/null 2>&1; then
        IPV6=$(timeout 5 curl -6 -s https://ipv6.icanhazip.com 2>/dev/null || echo "获取失败")
        log_info "IPv6 地址: $IPV6"
    else
        log_warn "IPv6 连接不可用"
    fi
    
    # 检查网络类型
    if [[ -n "$IPV4" && "$IPV4" != "获取失败" ]] && [[ -n "$IPV6" && "$IPV6" != "获取失败" ]]; then
        log_info "检测到双栈网络"
    elif [[ -n "$IPV6" && "$IPV6" != "获取失败" ]]; then
        log_info "检测到IPv6 only网络"
    elif [[ -n "$IPV4" && "$IPV4" != "获取失败" ]]; then
        log_info "检测到IPv4 only网络"
    else
        log_error "网络连接异常，请检查网络配置"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    log_info "检查并安装依赖..."
    
    local packages=()
    
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            packages=(curl wget jq openssl ca-certificates gnupg lsb-release)
            for pkg in "${packages[@]}"; do
                if ! dpkg -l | grep -q "^ii.*$pkg"; then
                    log_info "安装 $pkg..."
                    apt-get install -y "$pkg" >/dev/null 2>&1
                fi
            done
            ;;
        centos|rhel|fedora|rocky|alma)
            if command -v dnf >/dev/null 2>&1; then
                dnf update -y -q
                packages=(curl wget jq openssl ca-certificates)
            else
                yum update -y -q
                packages=(curl wget jq openssl ca-certificates)
            fi
            for pkg in "${packages[@]}"; do
                if ! rpm -q "$pkg" >/dev/null 2>&1; then
                    log_info "安装 $pkg..."
                    if command -v dnf >/dev/null 2>&1; then
                        dnf install -y "$pkg" >/dev/null 2>&1
                    else
                        yum install -y "$pkg" >/dev/null 2>&1
                    fi
                fi
            done
            ;;
    esac
    
    log_info "依赖安装完成"
}

# 检查防火墙
check_firewall() {
    local firewall_status="未检测到防火墙"
    
    if systemctl is-active --quiet ufw 2>/dev/null; then
        firewall_status="UFW 活跃"
    elif systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall_status="Firewalld 活跃"
    fi
    
    log_info "防火墙状态: $firewall_status"
}

# 配置防火墙规则
configure_firewall() {
    local port=$1
    local protocol=${2:-"tcp"}
    
    if systemctl is-active --quiet ufw 2>/dev/null; then
        ufw allow "$port/$protocol" >/dev/null 2>&1
        log_info "UFW: 已开放 $port/$protocol"
    elif systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --add-port="$port/$protocol" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        log_info "Firewalld: 已开放 $port/$protocol"
    fi
}

# 生成随机密码
generate_password() {
    local length=${1:-16}
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-${length}
}

# 安装Hysteria2
install_hysteria2() {
    log_info "开始安装 Hysteria2..."
    
    # 检查是否已安装
    if systemctl list-unit-files | grep -q hysteria2; then
        log_warn "Hysteria2 已安装，如需重新安装请先卸载"
        return 1
    fi
    
    # 获取最新版本
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name' | sed 's/v//')
    if [[ -z "$latest_version" ]]; then
        log_error "无法获取 Hysteria2 最新版本"
        return 1
    fi
    
    log_info "最新版本: $latest_version"
    
    # 下载二进制文件
    local download_url="https://github.com/apernet/hysteria/releases/download/app/v${latest_version}/hysteria-linux-${ARCH}"
    log_info "下载 Hysteria2..."
    
    if ! wget -q --show-progress "$download_url" -O /tmp/hysteria2; then
        log_error "下载失败"
        return 1
    fi
    
    # 安装
    chmod +x /tmp/hysteria2
    mv /tmp/hysteria2 /usr/local/bin/hysteria2
    
    # 创建配置目录
    mkdir -p /etc/hysteria2
    
    # 生成自签名证书
    log_info "生成自签名证书..."
    openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/hysteria2/private.key \
        -out /etc/hysteria2/cert.crt -days 3650 -subj "/CN=hysteria2" >/dev/null 2>&1
    
    # 获取SNI域名
    local sni_domain="amd.com"
    echo ""
    read -p "请输入用于 SNI 伪装的域名 (回车默认 amd.com): " input_sni
    if [[ -n "$input_sni" ]]; then
        sni_domain="$input_sni"
    fi
    
    # 生成配置文件
    local password
    password=$(generate_password 16)
    local port=443
    
    cat > "$HYSTERIA2_CONFIG_PATH" << EOF
listen: :$port
tls:
  cert: /etc/hysteria2/cert.crt
  key: /etc/hysteria2/private.key

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://$sni_domain
    rewriteHost: true

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 67108864
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 134217728
EOF
    
    # 创建systemd服务
    cat > /etc/systemd/system/hysteria2.service << EOF
[Unit]
Description=Hysteria2 Server
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria2 server -c /etc/hysteria2/config.yaml
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # 启用并启动服务
    systemctl daemon-reload
    systemctl enable hysteria2 >/dev/null 2>&1
    systemctl start hysteria2
    
    # 配置防火墙
    configure_firewall "$port" "tcp"
    configure_firewall "$port" "udp"
    
    if systemctl is-active --quiet hysteria2; then
        log_info "Hysteria2 安装成功并已启动"
        
        # 显示配置信息
        echo ""
        echo -e "${GREEN}=== Hysteria2 配置信息 ===${NC}"
        echo -e "${CYAN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
        echo "hysteria2://${password}@${IPV4:-$IPV6}:${port}/?insecure=true&sni=${sni_domain}#🌟Hysteria2-$(date +%m%d)"
        echo ""
        echo -e "${CYAN}⚔️ Clash Meta 配置:${NC}"
        echo "- { name: '🌟Hysteria2-$(date +%m%d)', type: hysteria2, server: ${IPV4:-$IPV6}, port: ${port}, password: ${password}, sni: ${sni_domain}, skip-cert-verify: true, up: 50, down: 100 }"
        echo ""
        echo -e "${CYAN}🌊 Surge 配置:${NC}"
        echo "🌟Hysteria2-$(date +%m%d) = hysteria2, ${IPV4:-$IPV6}, ${port}, password=${password}, sni=${sni_domain}, skip-cert-verify=true"
        echo ""
        
        read -n 1 -s -r -p "按任意键继续..."
    else
        log_error "Hysteria2 启动失败"
        return 1
    fi
}

# 安装Shadowsocks
install_shadowsocks() {
    log_info "开始安装 Shadowsocks..."
    
    # 检查IPv6支持
    if [[ -z "$IPV6" || "$IPV6" == "获取失败" ]]; then
        log_error "Shadowsocks 需要IPv6支持，但当前服务器不支持IPv6"
        log_error "Shadowsocks不支持纯IPv4机器，因为IPv4的SS容易被封禁"
        return 1
    fi
    
    # 检查是否已安装
    if systemctl list-unit-files | grep -q shadowsocks-rust; then
        log_warn "Shadowsocks 已安装，如需重新安装请先卸载"
        return 1
    fi
    
    # 获取最新版本
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | jq -r '.tag_name' | sed 's/v//')
    if [[ -z "$latest_version" ]]; then
        log_error "无法获取 Shadowsocks 最新版本"
        return 1
    fi
    
    log_info "最新版本: $latest_version"
    
    # 下载二进制文件
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.x86_64-unknown-linux-gnu.tar.xz"
    if [[ "$ARCH" == "arm64" ]]; then
        download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.aarch64-unknown-linux-gnu.tar.xz"
    fi
    
    log_info "下载 Shadowsocks..."
    
    if ! wget -q --show-progress "$download_url" -O /tmp/shadowsocks.tar.xz; then
        log_error "下载失败"
        return 1
    fi
    
    # 解压安装
    cd /tmp
    tar -xf shadowsocks.tar.xz
    mv ssserver /usr/local/bin/
    chmod +x /usr/local/bin/ssserver
    
    # 创建配置目录
    mkdir -p /etc/shadowsocks-rust
    
    # 生成配置文件
    local password
    password=$(generate_password 16)
    local port=8388
    local method="2022-blake3-aes-256-gcm"
    
    cat > "$SHADOWSOCKS_CONFIG_PATH" << EOF
{
    "server": "[::]",
    "server_port": $port,
    "method": "$method",
    "password": "$password",
    "timeout": 300,
    "fast_open": true,
    "mode": "tcp_and_udp"
}
EOF
    
    # 创建systemd服务
    cat > /etc/systemd/system/shadowsocks-rust.service << EOF
[Unit]
Description=Shadowsocks-Rust Server
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks-rust/config.json
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # 启用并启动服务
    systemctl daemon-reload
    systemctl enable shadowsocks-rust >/dev/null 2>&1
    systemctl start shadowsocks-rust
    
    # 配置防火墙
    configure_firewall "$port" "tcp"
    configure_firewall "$port" "udp"
    
    if systemctl is-active --quiet shadowsocks-rust; then
        log_info "Shadowsocks 安装成功并已启动"
        
        # 显示配置信息
        echo ""
        echo -e "${GREEN}=== Shadowsocks 配置信息 ===${NC}"
        echo -e "${CYAN}服务器地址:${NC} [$IPV6]"
        echo -e "${CYAN}端口:${NC} $port"
        echo -e "${CYAN}加密方式:${NC} $method"
        echo -e "${CYAN}密码:${NC} $password"
        echo ""
        echo -e "${CYAN}🚀 分享链接:${NC}"
        local ss_link=$(echo -n "${method}:${password}@[${IPV6}]:${port}" | base64 -w 0)
        echo "ss://${ss_link}#🌟SS-IPv6-$(date +%m%d)"
        echo ""
        
        read -n 1 -s -r -p "按任意键继续..."
    else
        log_error "Shadowsocks 启动失败"
        return 1
    fi
    
    # 清理临时文件
    rm -f /tmp/shadowsocks*
}

# 服务管理菜单
service_management() {
    while true; do
        show_header
        echo -e "${CYAN}=== 服务管理 ===${NC}"
        echo " 1. 管理 Hysteria2"
        echo " 2. 管理 Shadowsocks"
        echo " 3. 返回主菜单"
        echo -e "${CYAN}================================================${NC}"
        
        read -p "请选择操作 [1-3]: " choice
        
        case $choice in
            1) manage_hysteria2 ;;
            2) manage_shadowsocks ;;
            3) return ;;
            *) log_error "无效选择，请重试" ;;
        esac
    done
}

# 管理Hysteria2
manage_hysteria2() {
    while true; do
        show_header
        echo -e "${CYAN}=== Hysteria2 管理 ===${NC}"
        
        if systemctl is-active --quiet hysteria2 2>/dev/null; then
            echo -e "${GREEN}当前状态: 运行中${NC}"
            echo " 1. 停止服务"
            echo " 2. 重启服务"
            echo " 3. 查看配置"
            echo " 4. 查看日志"
            echo " 5. 返回上级菜单"
        elif [[ -f "$HYSTERIA2_CONFIG_PATH" ]]; then
            echo -e "${YELLOW}当前状态: 已安装但未运行${NC}"
            echo " 1. 启动服务"
            echo " 2. 查看配置"
            echo " 3. 查看日志"
            echo " 4. 返回上级菜单"
        else
            echo -e "${RED}当前状态: 未安装${NC}"
            echo " 1. 返回上级菜单"
        fi
        
        echo -e "${CYAN}================================================${NC}"
        read -p "请选择操作: " choice
        
        if systemctl is-active --quiet hysteria2 2>/dev/null; then
            case $choice in
                1)
                    systemctl stop hysteria2
                    log_info "Hysteria2 已停止"
                    read -n 1 -s -r -p "按任意键继续..."
                    ;;
                2)
                    systemctl restart hysteria2
                    log_info "Hysteria2 已重启"
                    read -n 1 -s -r -p "按任意键继续..."
                    ;;
                3) show_hysteria2_config ;;
                4) show_hysteria2_logs ;;
                5) return ;;
                *) log_error "无效选择，请重试" ;;
            esac
        elif [[ -f "$HYSTERIA2_CONFIG_PATH" ]]; then
            case $choice in
                1)
                    systemctl start hysteria2
                    log_info "Hysteria2 已启动"
                    read -n 1 -s -r -p "按任意键继续..."
                    ;;
                2) show_hysteria2_config ;;
                3) show_hysteria2_logs ;;
                4) return ;;
                *) log_error "无效选择，请重试" ;;
            esac
        else
            case $choice in
                1) return ;;
                *) log_error "无效选择，请重试" ;;
            esac
        fi
    done
}

# 显示Hysteria2配置
show_hysteria2_config() {
    if [[ ! -f "$HYSTERIA2_CONFIG_PATH" ]]; then
        log_error "配置文件不存在"
        return
    fi
    
    echo -e "${GREEN}=== Hysteria2 配置信息 ===${NC}"
    
    local password=$(grep -A1 "auth:" "$HYSTERIA2_CONFIG_PATH" | grep "password:" | sed 's/.*password: //')
    local port=$(grep "listen:" "$HYSTERIA2_CONFIG_PATH" | sed 's/.*://')
    local sni_domain=$(grep -A3 "masquerade:" "$HYSTERIA2_CONFIG_PATH" | grep "url:" | sed 's|.*https://||' | sed 's|/.*||')
    
    echo -e "${CYAN}服务器地址:${NC} ${IPV4:-$IPV6}"
    echo -e "${CYAN}端口:${NC} $port"
    echo -e "${CYAN}密码:${NC} $password"
    echo -e "${CYAN}SNI域名:${NC} $sni_domain"
    echo ""
    echo -e "${CYAN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo "hysteria2://${password}@${IPV4:-$IPV6}:${port}/?insecure=true&sni=${sni_domain}#🌟Hysteria2-$(date +%m%d)"
    echo ""
    echo -e "${CYAN}⚔️ Clash Meta 配置:${NC}"
    echo "- { name: '🌟Hysteria2-$(date +%m%d)', type: hysteria2, server: ${IPV4:-$IPV6}, port: ${port}, password: ${password}, sni: ${sni_domain}, skip-cert-verify: true, up: 50, down: 100 }"
    echo ""
    echo -e "${CYAN}🌊 Surge 配置:${NC}"
    echo "🌟Hysteria2-$(date +%m%d) = hysteria2, ${IPV4:-$IPV6}, ${port}, password=${password}, sni=${sni_domain}, skip-cert-verify=true"
    echo ""
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 显示Hysteria2日志
show_hysteria2_logs() {
    echo -e "${GREEN}=== Hysteria2 日志 (最近50行) ===${NC}"
    journalctl -u hysteria2 -n 50 --no-pager
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
}

# 管理Shadowsocks
manage_shadowsocks() {
    while true; do
        show_header
        echo -e "${CYAN}=== Shadowsocks 管理 ===${NC}"
        
        if systemctl is-active --quiet shadowsocks-rust 2>/dev/null; then
            echo -e "${GREEN}当前状态: 运行中${NC}"
            echo " 1. 停止服务"
            echo " 2. 重启服务"
            echo " 3. 查看配置"
            echo " 4. 查看日志"
            echo " 5. 返回上级菜单"
        elif [[ -f "$SHADOWSOCKS_CONFIG_PATH" ]]; then
            echo -e "${YELLOW}当前状态: 已安装但未运行${NC}"
            echo " 1. 启动服务"
            echo " 2. 查看配置"
            echo " 3. 查看日志"
            echo " 4. 返回上级菜单"
        else
            echo -e "${RED}当前状态: 未安装${NC}"
            echo " 1. 返回上级菜单"
        fi
        
        echo -e "${CYAN}================================================${NC}"
        read -p "请选择操作: " choice
        
        if systemctl is-active --quiet shadowsocks-rust 2>/dev/null; then
            case $choice in
                1)
                    systemctl stop shadowsocks-rust
                    log_info "Shadowsocks 已停止"
                    read -n 1 -s -r -p "按任意键继续..."
                    ;;
                2)
                    systemctl restart shadowsocks-rust
                    log_info "Shadowsocks 已重启"
                    read -n 1 -s -r -p "按任意键继续..."
                    ;;
                3) show_shadowsocks_config ;;
                4) show_shadowsocks_logs ;;
                5) return ;;
                *) log_error "无效选择，请重试" ;;
            esac
        elif [[ -f "$SHADOWSOCKS_CONFIG_PATH" ]]; then
            case $choice in
                1)
                    systemctl start shadowsocks-rust
                    log_info "Shadowsocks 已启动"
                    read -n 1 -s -r -p "按任意键继续..."
                    ;;
                2) show_shadowsocks_config ;;
                3) show_shadowsocks_logs ;;
                4) return ;;
                *) log_error "无效选择，请重试" ;;
            esac
        else
            case $choice in
                1) return ;;
                *) log_error "无效选择，请重试" ;;
            esac
        fi
    done
}

# 显示Shadowsocks配置
show_shadowsocks_config() {
    if [[ ! -f "$SHADOWSOCKS_CONFIG_PATH" ]]; then
        log_error "配置文件不存在"
        return
    fi
    
    echo -e "${GREEN}=== Shadowsocks 配置信息 ===${NC}"
    
    local config=$(cat "$SHADOWSOCKS_CONFIG_PATH")
    local password=$(echo "$config" | jq -r '.password')
    local port=$(echo "$config" | jq -r '.server_port')
    local method=$(echo "$config" | jq -r '.method')
    
    echo -e "${CYAN}服务器地址:${NC} [$IPV6]"
    echo -e "${CYAN}端口:${NC} $port"
    echo -e "${CYAN}加密方式:${NC} $method"
    echo -e "${CYAN}密码:${NC} $password"
    echo ""
    echo -e "${CYAN}🚀 分享链接:${NC}"
    local ss_link=$(echo -n "${method}:${password}@[${IPV6}]:${port}" | base64 -w 0)
    echo "ss://${ss_link}#🌟SS-IPv6-$(date +%m%d)"
    echo ""
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 显示Shadowsocks日志
show_shadowsocks_logs() {
    echo -e "${GREEN}=== Shadowsocks 日志 (最近50行) ===${NC}"
    journalctl -u shadowsocks-rust -n 50 --no-pager
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
}

# 卸载服务菜单
uninstall_services() {
    while true; do
        show_header
        echo -e "${CYAN}=== 卸载服务 ===${NC}"
        echo " 1. 卸载 Hysteria2"
        echo " 2. 卸载 Shadowsocks"
        echo " 3. 卸载所有服务"
        echo " 4. 返回主菜单"
        echo -e "${CYAN}================================================${NC}"
        
        read -p "请选择操作 [1-4]: " choice
        
        case $choice in
            1) uninstall_hysteria2 ;;
            2) uninstall_shadowsocks ;;
            3) uninstall_all_services ;;
            4) return ;;
            *) log_error "无效选择，请重试" ;;
        esac
    done
}

# 卸载Hysteria2
uninstall_hysteria2() {
    log_warn "即将卸载 Hysteria2，此操作不可逆！"
    read -p "确认卸载？[y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        log_info "正在卸载 Hysteria2..."
        
        # 停止并禁用服务
        if systemctl is-active --quiet hysteria2 2>/dev/null; then
            systemctl stop hysteria2
        fi
        if systemctl is-enabled --quiet hysteria2 2>/dev/null; then
            systemctl disable hysteria2 >/dev/null 2>&1
        fi
        
        # 删除服务文件
        rm -f /etc/systemd/system/hysteria2.service
        
        # 删除配置和二进制文件
        rm -rf /etc/hysteria2
        rm -f /usr/local/bin/hysteria2
        
        systemctl daemon-reload
        
        log_info "Hysteria2 已完全卸载"
    else
        log_info "取消卸载"
    fi
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 卸载Shadowsocks
uninstall_shadowsocks() {
    log_warn "即将卸载 Shadowsocks，此操作不可逆！"
    read -p "确认卸载？[y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        log_info "正在卸载 Shadowsocks..."
        
        # 停止并禁用服务
        if systemctl is-active --quiet shadowsocks-rust 2>/dev/null; then
            systemctl stop shadowsocks-rust
        fi
        if systemctl is-enabled --quiet shadowsocks-rust 2>/dev/null; then
            systemctl disable shadowsocks-rust >/dev/null 2>&1
        fi
        
        # 删除服务文件
        rm -f /etc/systemd/system/shadowsocks-rust.service
        
        # 删除配置和二进制文件
        rm -rf /etc/shadowsocks-rust
        rm -f /usr/local/bin/ssserver
        
        systemctl daemon-reload
        
        log_info "Shadowsocks 已完全卸载"
    else
        log_info "取消卸载"
    fi
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 卸载所有服务
uninstall_all_services() {
    log_warn "即将卸载所有服务，此操作不可逆！"
    read -p "确认卸载所有服务？[y/N]: " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        uninstall_hysteria2
        uninstall_shadowsocks
        log_info "所有服务已完全卸载"
    else
        log_info "取消卸载"
    fi
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 更新服务菜单
update_services() {
    while true; do
        show_header
        echo -e "${CYAN}=== 更新服务 ===${NC}"
        echo " 1. 更新 Hysteria2"
        echo " 2. 更新 Shadowsocks"
        echo " 3. 更新系统内核"
        echo " 4. 返回主菜单"
        echo -e "${CYAN}================================================${NC}"
        
        read -p "请选择操作 [1-4]: " choice
        
        case $choice in
            1) update_hysteria2 ;;
            2) update_shadowsocks ;;
            3) update_system_kernel ;;
            4) return ;;
            *) log_error "无效选择，请重试" ;;
        esac
    done
}

# 更新Hysteria2
update_hysteria2() {
    if [[ ! -f "/usr/local/bin/hysteria2" ]]; then
        log_error "Hysteria2 未安装"
        read -n 1 -s -r -p "按任意键继续..."
        return
    fi
    
    log_info "检查 Hysteria2 更新..."
    
    # 获取当前版本
    local current_version=$(/usr/local/bin/hysteria2 version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    
    # 获取最新版本
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name' | sed 's/v//')
    
    if [[ "$current_version" == "$latest_version" ]]; then
        log_info "Hysteria2 已是最新版本: $current_version"
        read -n 1 -s -r -p "按任意键继续..."
        return
    fi
    
    log_info "发现新版本: $current_version -> $latest_version"
    read -p "是否更新？[Y/n]: " confirm
    
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "取消更新"
        read -n 1 -s -r -p "按任意键继续..."
        return
    fi
    
    # 下载新版本
    local download_url="https://github.com/apernet/hysteria/releases/download/app/v${latest_version}/hysteria-linux-${ARCH}"
    log_info "下载新版本..."
    
    if wget -q --show-progress "$download_url" -O /tmp/hysteria2_new; then
        # 停止服务
        systemctl stop hysteria2
        
        # 备份并更新
        mv /usr/local/bin/hysteria2 /usr/local/bin/hysteria2.bak
        chmod +x /tmp/hysteria2_new
        mv /tmp/hysteria2_new /usr/local/bin/hysteria2
        
        # 启动服务
        systemctl start hysteria2
        
        if systemctl is-active --quiet hysteria2; then
            log_info "Hysteria2 更新成功"
            rm -f /usr/local/bin/hysteria2.bak
        else
            log_error "更新后启动失败，回滚到原版本"
            mv /usr/local/bin/hysteria2.bak /usr/local/bin/hysteria2
            systemctl start hysteria2
        fi
    else
        log_error "下载失败"
    fi
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 更新Shadowsocks
update_shadowsocks() {
    if [[ ! -f "/usr/local/bin/ssserver" ]]; then
        log_error "Shadowsocks 未安装"
        read -n 1 -s -r -p "按任意键继续..."
        return
    fi
    
    log_info "检查 Shadowsocks 更新..."
    
    # 获取最新版本
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | jq -r '.tag_name' | sed 's/v//')
    
    log_info "最新版本: $latest_version"
    read -p "是否更新到最新版本？[Y/n]: " confirm
    
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "取消更新"
        read -n 1 -s -r -p "按任意键继续..."
        return
    fi
    
    # 下载新版本
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.x86_64-unknown-linux-gnu.tar.xz"
    if [[ "$ARCH" == "arm64" ]]; then
        download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.aarch64-unknown-linux-gnu.tar.xz"
    fi
    
    log_info "下载新版本..."
    
    if wget -q --show-progress "$download_url" -O /tmp/shadowsocks_new.tar.xz; then
        # 停止服务
        systemctl stop shadowsocks-rust
        
        # 解压并更新
        cd /tmp
        tar -xf shadowsocks_new.tar.xz
        
        # 备份并更新
        mv /usr/local/bin/ssserver /usr/local/bin/ssserver.bak
        mv ssserver /usr/local/bin/
        chmod +x /usr/local/bin/ssserver
        
        # 启动服务
        systemctl start shadowsocks-rust
        
        if systemctl is-active --quiet shadowsocks-rust; then
            log_info "Shadowsocks 更新成功"
            rm -f /usr/local/bin/ssserver.bak /tmp/shadowsocks_new.tar.xz
        else
            log_error "更新后启动失败，回滚到原版本"
            mv /usr/local/bin/ssserver.bak /usr/local/bin/ssserver
            systemctl start shadowsocks-rust
        fi
    else
        log_error "下载失败"
    fi
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 更新系统内核
update_system_kernel() {
    log_warn "系统内核更新可能需要重启服务器"
    read -p "是否继续？[y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "取消更新"
        read -n 1 -s -r -p "按任意键继续..."
        return
    fi
    
    log_info "正在更新系统内核..."
    
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get upgrade -y linux-image-generic linux-headers-generic
            ;;
        centos|rhel|fedora|rocky|alma)
            if command -v dnf >/dev/null 2>&1; then
                dnf update -y kernel
            else
                yum update -y kernel
            fi
            ;;
    esac
    
    log_info "内核更新完成"
    log_warn "建议重启服务器以使用新内核"
    read -p "是否现在重启？[y/N]: " reboot_confirm
    
    if [[ "$reboot_confirm" =~ ^[Yy]$ ]]; then
        log_info "系统将在5秒后重启..."
        sleep 5
        reboot
    fi
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 系统优化菜单
system_optimization() {
    while true; do
        show_header
        echo -e "${CYAN}=== 系统优化 ===${NC}"
        echo " 1. 创建/管理 Swap"
        echo " 2. 优化网络参数"
        echo " 3. 优化系统限制"
        echo " 4. 清理系统垃圾"
        echo " 5. 返回主菜单"
        echo -e "${CYAN}================================================${NC}"
        
        read -p "请选择操作 [1-5]: " choice
        
        case $choice in
            1) manage_swap ;;
            2) optimize_network ;;
            3) optimize_system_limits ;;
            4) clean_system ;;
            5) return ;;
            *) log_error "无效选择，请重试" ;;
        esac
    done
}

# 管理Swap
manage_swap() {
    local swap_size=$(free -h | awk '/^Swap:/{print $2}' | sed 's/B//')
    local mem_size=$(free -m | awk '/^Mem:/{print $2}')
    
    echo -e "${GREEN}=== Swap 管理 ===${NC}"
    echo -e "${CYAN}当前 Swap 大小:${NC} $swap_size"
    echo -e "${CYAN}系统内存大小:${NC} ${mem_size}MB"
    echo ""
    
    if [[ "$swap_size" == "0" ]]; then
        echo "检测到系统没有 Swap，是否创建？"
        read -p "[Y/n]: " create_swap
        
        if [[ ! "$create_swap" =~ ^[Nn]$ ]]; then
            # 计算推荐的swap大小
            local recommended_swap
            if [[ $mem_size -lt 1024 ]]; then
                recommended_swap=1024  # 小于1GB内存，创建1GB swap
            elif [[ $mem_size -lt 2048 ]]; then
                recommended_swap=2048  # 1-2GB内存，创建2GB swap
            else
                recommended_swap=$mem_size  # 大于2GB内存，创建与内存相等的swap
            fi
            
            echo "推荐 Swap 大小: ${recommended_swap}MB"
            read -p "请输入 Swap 大小 (MB) [${recommended_swap}]: " input_size
            
            local swap_size_mb=${input_size:-$recommended_swap}
            
            log_info "正在创建 ${swap_size_mb}MB 的 Swap 文件..."
            
            # 创建swap文件
            dd if=/dev/zero of=/swapfile bs=1M count="$swap_size_mb" status=progress
            chmod 600 /swapfile
            mkswap /swapfile
            swapon /swapfile
            
            # 添加到fstab
            if ! grep -q "/swapfile" /etc/fstab; then
                echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
            fi
            
            log_info "Swap 创建成功"
        fi
    else
        echo "检测到已有 Swap，是否重新创建？"
        read -p "[y/N]: " recreate_swap
        
        if [[ "$recreate_swap" =~ ^[Yy]$ ]]; then
            # 关闭现有swap
            swapoff -a
            rm -f /swapfile
            sed -i '/swapfile/d' /etc/fstab
            
            # 重新创建
            manage_swap
            return
        fi
    fi
    
    read -n 1 -s -r -p "按任意键继续..."
}

# 优化网络参数
optimize_network() {
    log_info "正在优化网络参数..."
    
    # 备份原配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d_%H%M%S)
    
    # 网络优化参数
    cat >> /etc/sysctl.conf << EOF

# 网络优化参数
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_default = 1048576
net.core.rmem_max = 16777216
net.core.wmem_default = 1048576
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 4096
net.ipv4.tcp_rmem = 4096 1048576 2097152
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_collapse = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_frto = 0
net.ipv4.tcp_mtu_probing = 0
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    
    # 应用配置
    sysctl -p >/dev/null 2>&1
    
    log_info "网络参数优化完成"
    read -n 1 -s -r -p "按任意键继续..."
}

# 优化系统限制
optimize_system_limits() {
    log_info "正在优化系统限制..."
    
    # 备份原配置
    cp /etc/security/limits.conf /etc/security/limits.conf.bak.$(date +%Y%m%d_%H%M%S)
    
    # 添加优化参数
    cat >> /etc/security/limits.conf << EOF

# 系统限制优化
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
root soft nofile 1000000
root hard nofile 1000000
root soft nproc 1000000
root hard nproc 1000000
EOF
    
    # 添加systemd服务限制
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/limits.conf << EOF
[Manager]
DefaultLimitNOFILE=1000000
DefaultLimitNPROC=1000000
EOF
    
    log_info "系统限制优化完成"
    log_warn "建议重启系统使所有更改生效"
    read -n 1 -s -r -p "按任意键继续..."
}

# 清理系统垃圾
clean_system() {
    log_info "正在清理系统垃圾..."
    
    case $OS in
        ubuntu|debian)
            apt-get autoremove -y >/dev/null 2>&1
            apt-get autoclean -y >/dev/null 2>&1
            apt-get clean -y >/dev/null 2>&1
            ;;
        centos|rhel|fedora|rocky|alma)
            if command -v dnf >/dev/null 2>&1; then
                dnf autoremove -y >/dev/null 2>&1
                dnf clean all >/dev/null 2>&1
            else
                yum autoremove -y >/dev/null 2>&1
                yum clean all >/dev/null 2>&1
            fi
            ;;
    esac
    
    # 清理日志文件
    journalctl --vacuum-time=7d >/dev/null 2>&1
    
    # 清理临时文件
    rm -rf /tmp/*
    rm -rf /var/tmp/*
    
    # 清理缓存
    if command -v free >/dev/null 2>&1; then
        sync && echo 3 > /proc/sys/vm/drop_caches
    fi
    
    log_info "系统垃圾清理完成"
    read -n 1 -s -r -p "按任意键继续..."
}

# 查看日志菜单
view_logs() {
    while true; do
        show_header
        echo -e "${CYAN}=== 查看日志 ===${NC}"
        echo " 1. 查看 Hysteria2 日志"
        echo " 2. 查看 Shadowsocks 日志"
        echo " 3. 查看系统日志"
        echo " 4. 返回主菜单"
        echo -e "${CYAN}================================================${NC}"
        
        read -p "请选择操作 [1-4]: " choice
        
        case $choice in
            1) show_hysteria2_logs ;;
            2) show_shadowsocks_logs ;;
            3) show_system_logs ;;
            4) return ;;
            *) log_error "无效选择，请重试" ;;
        esac
    done
}

# 显示系统日志
show_system_logs() {
    echo -e "${GREEN}=== 系统日志 (最近50行) ===${NC}"
    journalctl -n 50 --no-pager
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
}

# 主菜单
main_menu() {
    while true; do
        show_header
        echo " 1. 安装 Hysteria2(自签名证书模式，无需域名解析)"
        echo " 2. 安装 Shadowsocks (仅 IPv6)"
        echo " 3. 服务管理"
        echo " 4. 卸载服务"
        echo " 5. 更新服务"
        echo " 6. 系统优化"
        echo " 7. 查看日志"
        echo " 8. 退出脚本"
        echo -e "${CYAN}================================================${NC}"
        
        read -p "请选择操作 [1-8]: " choice
        
        case $choice in
            1) install_hysteria2 ;;
            2) install_shadowsocks ;;
            3) service_management ;;
            4) uninstall_services ;;
            5) update_services ;;
            6) system_optimization ;;
            7) view_logs ;;
            8) 
                echo -e "${GREEN}感谢使用 Hysteria2 & Shadowsocks 管理脚本！${NC}"
                exit 0
                ;;
            *) log_error "无效选择，请重试" ;;
        esac
    done
}

# 脚本入口
main() {
    # 检查是否为root用户
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用 root 用户运行此脚本"
        exit 1
    fi
    
    # 初始化检查
    check_system
    check_memory
    install_dependencies
    check_network
    check_firewall
    
    # 显示系统信息
    log_info "系统初始化完成"
    sleep 2
    
    # 启动主菜单
    main_menu
}

# 脚本开始执行
main "$@"
