#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 菜单式安装脚本
# 版本: 6.1 (全面优化修复版)
# 作者: Jensfrank & AI Assistant 优化增强
# 项目: hy2ipv6

# --- 脚本行为设置 ---
# set -e: 命令失败时立即退出
# set -u: 变量未定义时立即退出
# set -o pipefail: 管道中任何命令失败都视为整个管道失败
set -euo pipefail

# --- 脚本配置与变量 ---

# 颜色定义 (使用 readonly 确保不会被修改)
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BG_PURPLE='\033[45m'
readonly ENDCOLOR='\033[0m'

# 全局变量声明
OS_TYPE=""
ARCH=""
DOMAIN=""
CF_TOKEN=""
HY_PASSWORD=""
ACME_EMAIL=""
FAKE_URL=""
CF_ZONE_ID=""
CF_ACCOUNT_ID=""
TUNNEL_ID=""
readonly TUNNEL_NAME="hysteria-tunnel" # Tunnel 名称保持固定，便于管理
IPV4_ADDR=""
IPV6_ADDR=""
CLOUDFLARED_PATH=""

# 配置目录常量
readonly HY2_CONFIG_DIR="/etc/hysteria2"
readonly CF_CONFIG_DIR="/etc/cloudflared"
readonly CERTS_DIR="${HY2_CONFIG_DIR}/certs"
readonly INSTALL_INFO_FILE="${HY2_CONFIG_DIR}/install_info.env"
readonly TUNNEL_INFO_FILE="${CF_CONFIG_DIR}/tunnel_info.env"

# --- 日志与输出函数 ---

log_message() {
    local level="$1"
    local message="$2"
    # 使用追加重定向，并确保即使日志文件目录不存在或不可写也不会导致脚本退出
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> /var/log/hysteria2_install.log 2>/dev/null || true
}

info_echo() {
    echo -e "${BLUE}[INFO]${ENDCOLOR} $1"
    log_message "INFO" "$1"
}

success_echo() {
    echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"
    log_message "SUCCESS" "$1"
}

error_echo() {
    # 错误信息输出到 stderr
    echo -e "${RED}[ERROR]${ENDCOLOR} $1" >&2
    log_message "ERROR" "$1"
}

warning_echo() {
    echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"
    log_message "WARNING" "$1"
}

debug_echo() {
    # 仅在 DEBUG 环境变量为 "true" 时输出
    if [[ "${DEBUG:-}" == "true" ]]; then
        echo -e "${CYAN}[DEBUG]${ENDCOLOR} $1"
        log_message "DEBUG" "$1"
    fi
}

# --- 错误处理函数 ---

cleanup_on_error() {
    local exit_code=$?
    # 仅在脚本因错误退出时执行 (exit_code 非 0)
    if [[ $exit_code -ne 0 ]]; then
        error_echo "安装过程中发生错误 (退出码: $exit_code)"
        error_echo "详细信息请检查日志文件: /var/log/hysteria2_install.log"
        
        # 尝试清理可能存在的半成品安装
        info_echo "正在尝试清理..."
        systemctl stop hysteria-server cloudflared 2>/dev/null || true
        systemctl disable hysteria-server cloudflared 2>/dev/null || true
    fi
}

# 注册 trap，在脚本退出时执行 cleanup_on_error
trap cleanup_on_error EXIT

# --- 验证函数 ---

validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ || ${#domain} -gt 253 ]]; then
        error_echo "域名格式无效: $domain"
        return 1
    fi
    return 0
}

validate_email() {
    local email="$1"
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        error_echo "邮箱格式无效: $email"
        return 1
    fi
    return 0
}

validate_password() {
    local password="$1"
    
    # 修复：对于弱密码或短密码，只警告不中断脚本
    if [[ ${#password} -lt 8 ]]; then
        warning_echo "密码长度少于8位，建议使用更强的密码"
        # 不返回 1，允许用户使用
    fi
    
    if [[ ${#password} -gt 128 ]]; then
        error_echo "密码过长 (最大128字符)"
        return 1 # 这是硬性错误，必须中断
    fi
    
    # 检查密码强度
    local strength_score=0
    [[ "$password" =~ [A-Z] ]] && ((strength_score++))
    [[ "$password" =~ [a-z] ]] && ((strength_score++))
    [[ "$password" =~ [0-9] ]] && ((strength_score++))
    [[ "$password" =~ [^a-zA-Z0-9] ]] && ((strength_score++))
    
    if [[ $strength_score -lt 3 ]]; then
        warning_echo "密码强度较弱，建议包含大小写字母、数字和特殊字符"
    fi
    
    return 0 # 验证通过
}

# --- 显示函数优化 ---

show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-未检测到}"
    local ipv6_display="${IPV6_ADDR:-未检测到}"
    
    # 检查服务状态
    local hy2_status="未安装"
    local cf_status="未安装"
    
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hy2_status="${GREEN}运行中${ENDCOLOR}"
    elif systemctl list-unit-files hysteria-server.service &>/dev/null; then
        hy2_status="${RED}已停止${ENDCOLOR}"
    fi
    
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        cf_status="${GREEN}运行中${ENDCOLOR}"
    elif systemctl list-unit-files cloudflared.service &>/dev/null; then
        cf_status="${RED}已停止${ENDCOLOR}"
    fi
    
    echo -e "${BG_PURPLE} Hysteria2 & Cloudflare Tunnel 管理脚本 (v6.1) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器信息:${ENDCOLOR}"
    echo -e " ├─ IPv4: ${GREEN}${ipv4_display}${ENDCOLOR}"
    echo -e " └─ IPv6: ${GREEN}${ipv6_display}${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务状态:${ENDCOLOR}"
    echo -e " ├─ Hysteria2: ${hy2_status}"
    echo -e " └─ Cloudflared: ${cf_status}"
    echo
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
    echo -e " ${CYAN}安装选项:${ENDCOLOR}"
    echo -e " ${CYAN}1.${ENDCOLOR} 安装 Hysteria2 (直连模式) - 适合 VPS 直接访问"
    echo -e " ${CYAN}2.${ENDCOLOR} 安装 Hysteria2 + Cloudflare Tunnel - 适合被墙IP"
    echo
    echo -e " ${CYAN}卸载选项:${ENDCOLOR}"
    echo -e " ${CYAN}3.${ENDCOLOR} 卸载 Hysteria2 服务"
    echo -e " ${CYAN}4.${ENDCOLOR} 卸载 Hysteria2 + Cloudflare Tunnel"
    echo -e " ${CYAN}5.${ENDCOLOR} 完全清理 (删除所有组件和配置)"
    echo
    echo -e " ${CYAN}管理选项:${ENDCOLOR}"
    echo -e " ${CYAN}6.${ENDCOLOR} 服务管理 (启动/停止/重启/日志)"
    echo -e " ${CYAN}7.${ENDCOLOR} 显示配置信息"
    echo -e " ${CYAN}8.${ENDCOLOR} 连通性测试"
    echo -e " ${CYAN}9.${ENDCOLOR} 更新组件"
    echo
    echo -e " ${CYAN}0.${ENDCOLOR} 退出脚本"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
}

# --- 网络检测优化 ---

detect_network() {
    info_echo "检测网络配置..."
    
    # 并发检测IPv4和IPv6，提高效率
    IPV4_ADDR=$(timeout 10 curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null) &
    IPV4_PID=$!
    IPV6_ADDR=$(timeout 10 curl -6 -s --max-time 5 https://api64.ipify.org 2>/dev/null) &
    IPV6_PID=$!
    wait $IPV4_PID
    wait $IPV6_PID
    
    if [[ -z "$IPV4_ADDR" && -z "$IPV6_ADDR" ]]; then
        error_echo "无法检测到公网IP地址，请检查网络连接"
        exit 1
    fi
    
    debug_echo "IPv4: ${IPV4_ADDR:-N/A}, IPv6: ${IPV6_ADDR:-N/A}"
}

check_domain_resolution() {
    local domain="$1"
    info_echo "检查域名解析..."
    
    if ! nslookup "$domain" >/dev/null 2>&1; then
        warning_echo "域名 '$domain' 当前无法解析，请确保DNS设置正确"
        read -rp "是否继续安装? (y/N): " confirm
        [[ "$confirm" =~ ^[yY]$ ]] || { info_echo "安装已取消"; return 1; }
    else
        success_echo "域名解析正常"
    fi
    return 0
}

# --- 系统检测增强 ---

detect_system() {
    if [[ ! -f /etc/os-release ]]; then
        error_echo "无法检测操作系统，不支持当前系统"
        exit 1
    fi
    
    source /etc/os-release
    OS_TYPE="$ID"
    
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;; # Hysteria release file uses "arm"
        *) 
            error_echo "不支持的架构: $ARCH (仅支持 amd64, arm64, arm)"
            exit 1
            ;;
    esac
    
    # 健壮性修复：移除对 bc 的依赖
    local version_major
    version_major=$(echo "$VERSION_ID" | cut -d. -f1)
    case "$OS_TYPE" in
        ubuntu) [[ "$version_major" -lt 18 ]] && warning_echo "Ubuntu 版本过低，建议 18.04+" ;;
        debian) [[ "$version_major" -lt 9 ]] && warning_echo "Debian 版本过低，建议 9+" ;;
        centos|rhel) [[ "$version_major" -lt 7 ]] && warning_echo "系统版本过低，建议 7+" ;;
    esac
    
    info_echo "系统检测完成: $PRETTY_NAME ($ARCH)"
}

# --- 依赖安装优化 ---

install_dependencies() {
    info_echo "检查并安装依赖..."
    local pkgs_to_install=()
    
    # 定义基础包和对应需要检查的命令
    declare -A pkgs=(
        ["curl"]="curl" ["wget"]="wget" ["unzip"]="unzip" ["jq"]="jq"
        ["openssl"]="openssl"
    )
    
    # 根据系统类型添加网络工具包
    case "$OS_TYPE" in
        ubuntu|debian)
            pkgs["netcat-openbsd"]="nc"; pkgs["dnsutils"]="nslookup"; pkgs["iproute2"]="ss"
            ;;
        *) # CentOS/Fedora/etc.
            pkgs["nc"]="nc"; pkgs["bind-utils"]="nslookup"; pkgs["iproute"]="ss"
            ;;
    esac
    
    # 检查缺失的包
    for pkg in "${!pkgs[@]}"; do
        command -v "${pkgs[$pkg]}" &>/dev/null || pkgs_to_install+=("$pkg")
    done
    
    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
        info_echo "需要安装: ${pkgs_to_install[*]}"
        case "$OS_TYPE" in
            ubuntu|debian)
                apt-get update -qq && apt-get install -y "${pkgs_to_install[@]}"
                ;;
            centos|rhel|fedora|rocky|almalinux)
                command -v dnf &>/dev/null && dnf install -y "${pkgs_to_install[@]}" || yum install -y "${pkgs_to_install[@]}"
                ;;
            *)
                error_echo "不支持的操作系统: $OS_TYPE"
                exit 1
                ;;
        esac
        # 检查安装是否成功
        if [[ $? -ne 0 ]]; then
            error_echo "依赖安装失败，请检查包管理器"
            exit 1
        fi
    fi
    
    success_echo "依赖检查完成"
}

# --- 端口检查增强 ---

check_port_443() {
    info_echo "检查端口 443 占用情况..."
    # 使用更精确的 grep 模式
    if ss -ulnp | grep -q ":443\s"; then
        error_echo "UDP 443 端口已被占用:"
        ss -ulnp | grep ":443\s"
        error_echo "请先释放该端口"
        exit 1
    fi
    
    if ss -tlnp | grep -q ":443\s"; then
        warning_echo "TCP 443 端口已被占用，可能与 Web 服务器冲突:"
        ss -tlnp | grep ":443\s"
        read -rp "是否继续? (y/N): " confirm
        [[ "$confirm" =~ ^[yY]$ ]] || { info_echo "安装已取消"; exit 1; }
    fi
    
    success_echo "端口检查通过"
}

# --- 防火墙配置增强 ---

configure_firewall() {
    info_echo "配置防火墙..."
    
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        info_echo "检测到 UFW，正在开放 UDP 443 端口..."
        ufw allow 443/udp comment "Hysteria2" >/dev/null
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        info_echo "检测到 firewalld，正在开放 UDP 443 端口..."
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    elif command -v iptables &>/dev/null; then
         # 检查规则是否已存在
        if ! iptables -C INPUT -p udp --dport 443 -j ACCEPT >/dev/null 2>&1; then
            info_echo "使用 iptables 开放 UDP 443 端口..."
            iptables -I INPUT -p udp --dport 443 -j ACCEPT
        else
            info_echo "iptables 规则已存在"
        fi
    else
        warning_echo "未检测到主流防火墙工具，请手动开放 UDP 443 端口"
        return
    fi
    
    success_echo "防火墙配置完成"
}

# --- 用户输入优化 ---

get_user_input() {
    # 确保从终端读取输入
    exec </dev/tty
    
    while true; do
        read -rp "请输入您的域名: " DOMAIN
        validate_domain "$DOMAIN" && break
    done
    
    while true; do
        read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD; echo
        if [[ -z "$HY_PASSWORD" ]]; then
            HY_PASSWORD=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
            info_echo "自动生成强密码: $HY_PASSWORD"
            break
        else
            validate_password "$HY_PASSWORD" && break
        fi
    done
    
    while true; do
        read -rp "请输入 ACME 邮箱 (默认: user@example.com): " input_email
        ACME_EMAIL="${input_email:-user@example.com}"
        validate_email "$ACME_EMAIL" && break
    done
    
    read -rp "请输入伪装网址 (默认: https://www.bing.com): " input_fake_url
    FAKE_URL="${input_fake_url:-https://www.bing.com}"
    
    if [[ ! "$FAKE_URL" =~ ^https?:// ]]; then
        warning_echo "伪装网址格式不规范，已自动添加 https://"
        FAKE_URL="https://$FAKE_URL"
    fi
}

get_user_input_with_cf() {
    get_user_input
    
    echo
    warning_echo "获取 Cloudflare API Token 方法:"
    echo "1. 访问: https://dash.cloudflare.com/profile/api-tokens"
    echo "2. 点击 'Create Token' -> 使用 'Create Custom Token'"
    echo "3. 权限设置:"
    echo "   - Zone:Zone:Read"
    echo "   - Zone:DNS:Edit"
    echo "   - Account:Cloudflare Tunnel:Edit"
    echo "4. Zone Resources: Include - Specific zone - 选择您的域名"
    echo "5. Account Resources: Include - Your Account"
    echo
    
    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN; echo
        [[ -n "$CF_TOKEN" ]] || { error_echo "Token 不能为空"; continue; }
        
        info_echo "正在验证 Token..."
        # 修复：直接使用用户输入的域名查询，让 CF API 自动匹配 Zone
        local api_result
        api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
            -H "Authorization: Bearer $CF_TOKEN" \
            -H "Content-Type: application/json")
        
        if echo "$api_result" | jq -e '.success==true and .result[0].id' >/dev/null 2>&1; then
            CF_ZONE_ID=$(echo "$api_result" | jq -r '.result[0].id')
            CF_ACCOUNT_ID=$(echo "$api_result" | jq -r '.result[0].account.id')
            success_echo "Token 验证成功 (Zone: $(echo "$api_result" | jq -r '.result[0].name'))"
            break
        else
            error_echo "Token 验证失败！"
            echo "$api_result" | jq '.errors' 2>/dev/null || echo "请检查 Token 权限和网络连接。"
        fi
    done
}

# --- 安装函数优化 ---

install_hysteria2() {
    info_echo "开始安装 Hysteria2..."
    local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    
    local release_info
    release_info=$(curl -s "$api_url") || { error_echo "无法获取 Hysteria2 版本信息"; exit 1; }
    
    local version
    version=$(echo "$release_info" | jq -r '.tag_name')
    info_echo "最新版本: $version"
    
    local filename="hysteria-linux-$ARCH"
    local dl_url
    dl_url=$(echo "$release_info" | jq -r ".assets[] | select(.name==\"$filename\") | .browser_download_url")
    
    [[ -n "$dl_url" && "$dl_url" != "null" ]] || { error_echo "无法找到适合 $ARCH 架构的 Hysteria2 版本"; exit 1; }
    
    info_echo "正在下载: $dl_url"
    local temp_file="/tmp/hysteria_binary"
    wget -q --show-progress -O "$temp_file" "$dl_url" || { error_echo "Hysteria2 下载失败"; exit 1; }
    
    install -m 755 "$temp_file" /usr/local/bin/hysteria
    rm -f "$temp_file"
    
    # 验证安装
    /usr/local/bin/hysteria version &>/dev/null || { error_echo "Hysteria2 安装后验证失败"; exit 1; }
    success_echo "Hysteria2 安装完成 ($(/usr/local/bin/hysteria version | head -n1))"
}

install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        CLOUDFLARED_PATH=$(command -v cloudflared)
        info_echo "Cloudflared 已安装: $CLOUDFLARED_PATH ($(cloudflared --version))"
        return 0
    fi
    
    info_echo "开始安装 Cloudflared..."
    case "$OS_TYPE" in
        ubuntu|debian)
            curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
            echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main' | tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
            apt-get update -qq && apt-get install -y cloudflared
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &>/dev/null; then
                dnf config-manager --add-repo https://pkg.cloudflare.com/cloudflared-ascii.repo >/dev/null
                dnf install -y cloudflared
            else
                yum-config-manager --add-repo https://pkg.cloudflare.com/cloudflared-ascii.repo >/dev/null
                yum install -y cloudflared
            fi
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE"
            exit 1
            ;;
    esac
    
    [[ $? -eq 0 ]] || { error_echo "Cloudflared 安装失败"; exit 1; }
    CLOUDFLARED_PATH=$(command -v cloudflared)
    success_echo "Cloudflared 安装完成 ($(cloudflared --version))"
}

# --- 证书管理优化 ---

install_acme_and_cert() {
    info_echo "开始申请 SSL 证书 (Let's Encrypt)..."
    
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        info_echo "安装 acme.sh..."
        curl -s https://get.acme.sh | sh -s email="$ACME_EMAIL" || { error_echo "acme.sh 安装失败"; exit 1; }
    fi
    
    # 使用环境变量传递 API Token
    export CF_Token="$CF_TOKEN"
    
    info_echo "正在申请证书，这可能需要1-2分钟..."
    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --ecc; then
        error_echo "证书申请失败！请检查 Cloudflare API Token 权限和域名是否正确托管。"
        exit 1
    fi
    
    mkdir -p "$CERTS_DIR"
    if ! ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
        --fullchain-file "${CERTS_DIR}/fullchain.cer" \
        --key-file "${CERTS_DIR}/private.key"; then
        error_echo "证书安装到指定目录失败"; exit 1;
    fi
    
    # 设置正确的权限
    chmod 600 "${CERTS_DIR}/private.key"
    success_echo "SSL 证书申请并安装完成"
}

generate_self_signed_cert() {
    info_echo "生成自签名证书..."
    mkdir -p "$CERTS_DIR"
    
    # 注释：-pkcs8 -pass pass: 是一个生成无密码 PKCS#8 格式私钥的技巧
    openssl genpkey -algorithm RSA -out "${CERTS_DIR}/private.key" -pkcs8 -pass pass: >/dev/null 2>&1
    
    openssl req -new -x509 -key "${CERTS_DIR}/private.key" \
        -out "${CERTS_DIR}/fullchain.cer" \
        -days 3650 \
        -subj "/CN=$DOMAIN" \
        -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1
    
    chmod 600 "${CERTS_DIR}/private.key"
    success_echo "自签名证书生成完成"
}

# --- 配置生成优化 ---

generate_hysteria_config() {
    info_echo "生成 Hysteria2 配置文件..."
    mkdir -p "$HY2_CONFIG_DIR"
    
    # 优先使用 IPv6 监听
    local listen_addr=$([[ -n "$IPV6_ADDR" ]] && echo "[::]:443" || echo "0.0.0.0:443")
    info_echo "Hysteria2 将监听于: $listen_addr"
    
    cat > "${HY2_CONFIG_DIR}/config.yaml" << EOF
# Hysteria2 Server Configuration
# Generated by script on $(date)

listen: $listen_addr

tls:
  cert: ${CERTS_DIR}/fullchain.cer
  key: ${CERTS_DIR}/private.key

auth:
  type: password
  password: $HY_PASSWORD

masquerade:
  type: proxy
  proxy:
    url: $FAKE_URL
    rewriteHost: true

# Performance tuning
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

# Bandwidth (adjust as needed)
bandwidth:
  up: 1 gbps
  down: 1 gbps

log:
  level: info
  timestamp: true
EOF
    
    success_echo "Hysteria2 配置生成完成: ${HY2_CONFIG_DIR}/config.yaml"
}

# --- Cloudflare Tunnel 设置优化 ---

setup_cloudflared_tunnel() {
    info_echo "设置 Cloudflare Tunnel..."
    
    # 登录授权，增加超时
    info_echo "即将打开浏览器进行授权，请在5分钟内完成操作"
    read -rp "按回车键继续..."
    timeout 300 cloudflared tunnel login || { error_echo "Cloudflared 登录失败或超时"; exit 1; }
    
    info_echo "登录成功，等待凭证同步..." && sleep 5
    
    # 检查并创建隧道
    local existing_tunnel_id
    existing_tunnel_id=$(cloudflared tunnel list -o json 2>/dev/null | jq -r ".[] | select(.name==\"$TUNNEL_NAME\") | .id")
    
    if [[ -z "$existing_tunnel_id" ]]; then
        info_echo "创建新隧道: $TUNNEL_NAME"
        # 从输出中提取 Tunnel ID
        TUNNEL_ID=$(cloudflared tunnel create "$TUNNEL_NAME" | grep -oE '[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}')
        [[ -n "$TUNNEL_ID" ]] || { error_echo "创建隧道失败"; exit 1; }
        success_echo "隧道创建成功: $TUNNEL_ID"
    else
        TUNNEL_ID="$existing_tunnel_id"
        info_echo "使用现有隧道: $TUNNEL_ID"
    fi
    
    # 移动凭证文件到标准位置
    mkdir -p "$CF_CONFIG_DIR"
    local credential_file="/root/.cloudflared/${TUNNEL_ID}.json"
    if [[ -f "$credential_file" ]]; then
        mv "$credential_file" "${CF_CONFIG_DIR}/" || { error_echo "移动隧道凭证失败"; exit 1; }
    elif [[ ! -f "${CF_CONFIG_DIR}/${TUNNEL_ID}.json" ]]; then
        error_echo "找不到隧道凭证文件，请重新尝试登录"
        exit 1
    fi
    
    # 保存隧道信息
    echo "TUNNEL_ID=$TUNNEL_ID" > "$TUNNEL_INFO_FILE"
    echo "TUNNEL_NAME_PERSIST=$TUNNEL_NAME" >> "$TUNNEL_INFO_FILE"
    
    # 生成 Cloudflared 配置
    local service_addr=$([[ -n "$IPV6_ADDR" ]] && echo "udp://[::1]:443" || echo "udp://127.0.0.1:443")
    cat > "${CF_CONFIG_DIR}/config.yml" << EOF
# Cloudflare Tunnel Configuration
tunnel: $TUNNEL_ID
credentials-file: ${CF_CONFIG_DIR}/${TUNNEL_ID}.json
protocol: quic
loglevel: info

ingress:
  - hostname: $DOMAIN
    service: $service_addr
    originRequest:
      noHappyEyeballs: true # Important for UDP proxying
  - service: http_status:404
EOF
    
    # 设置 DNS 记录
    info_echo "设置 DNS 记录，将 $DOMAIN 指向隧道..."
    cloudflared tunnel route dns "$TUNNEL_ID" "$DOMAIN" || { error_echo "DNS 记录设置失败"; exit 1; }
    
    success_echo "Cloudflare Tunnel 设置完成"
}

# --- 系统服务优化 ---

create_systemd_services() {
    info_echo "创建 Systemd 服务..."
    
    # Hysteria2 服务
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config ${HY2_CONFIG_DIR}/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576

# Security Hardening
# 注释：这些配置增强了服务的安全性，限制其权限
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${HY2_CONFIG_DIR}
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF
    
    # Cloudflared 服务 (如果需要)
    if [[ -n "$CLOUDFLARED_PATH" ]]; then
        source "$TUNNEL_INFO_FILE"
        cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target hysteria-server.service
BindsTo=hysteria-server.service # 确保与 hysteria-server 一同启停

[Service]
Type=simple
ExecStart=$CLOUDFLARED_PATH tunnel --config ${CF_CONFIG_DIR}/config.yml run ${TUNNEL_ID}
Restart=always
RestartSec=5

# Security Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${CF_CONFIG_DIR}
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    success_echo "Systemd 服务创建/更新完成"
}

# --- 服务启动优化 ---

start_services() {
    info_echo "启动服务..."
    
    systemctl enable --now hysteria-server || { error_echo "启动 Hysteria2 服务失败"; exit 1; }
    
    # 健壮性检查：等待 Hysteria2 绑定端口
    info_echo "等待 Hysteria2 启动..."
    for ((i=0; i<10; i++)); do
        if ss -ulnp | grep -q ":443.*hysteria"; then
            success_echo "Hysteria2 启动成功，已监听 UDP 443"
            break
        fi
        sleep 1
    done
    if ! ss -ulnp | grep -q ":443.*hysteria"; then
        error_echo "Hysteria2 启动超时或失败！"
        journalctl -u hysteria-server -n 20 --no-pager
        exit 1
    fi
    
    # 启动 Cloudflared (如果需要)
    if [[ -f /etc/systemd/system/cloudflared.service ]]; then
        systemctl enable --now cloudflared || { error_echo "启动 Cloudflared 服务失败"; exit 1; }
        info_echo "等待 Cloudflared 连接到 Cloudflare 网络 (约15秒)..."
        sleep 15
        if journalctl -u cloudflared --since="1m ago" | grep -q "Connected to"; then
            success_echo "Cloudflared 连接成功"
        else
            warning_echo "Cloudflared 可能尚未连接，请稍后通过服务管理菜单查看日志"
        fi
    fi
}

# --- 信息保存优化 ---

save_install_info() {
    local mode="$1"
    mkdir -p "$HY2_CONFIG_DIR"
    
    # 保存安装信息
    cat > "$INSTALL_INFO_FILE" << EOF
# Hysteria2 Installation Information
INSTALL_DATE=$(date)
MODE=$mode
DOMAIN=$DOMAIN
HY_PASSWORD=$HY_PASSWORD
ACME_EMAIL=$ACME_EMAIL
FAKE_URL=$FAKE_URL
IPV4_ADDR=$IPV4_ADDR
IPV6_ADDR=$IPV6_ADDR
SCRIPT_VERSION=6.1
EOF
    
    if [[ "$mode" == "tunnel" ]]; then
        echo "CF_ZONE_ID=$CF_ZONE_ID" >> "$INSTALL_INFO_FILE"
        echo "CF_ACCOUNT_ID=$CF_ACCOUNT_ID" >> "$INSTALL_INFO_FILE"
        source "$TUNNEL_INFO_FILE"
        echo "TUNNEL_ID=$TUNNEL_ID" >> "$INSTALL_INFO_FILE"
    fi
    success_echo "安装信息已保存到 $INSTALL_INFO_FILE"
}

save_client_info() {
    local mode="$1"
    mkdir -p "$HY2_CONFIG_DIR"
    
    local server_addr insecure
    if [[ "$mode" == "direct" ]]; then
        server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
        insecure="true"
    else
        server_addr="$DOMAIN"
        insecure="false"
    fi
    
    # 生成分享链接
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}&insecure=${insecure}#${DOMAIN}-${mode^}"
    
    # 生成客户端配置
    cat > "${HY2_CONFIG_DIR}/client_info.txt" << EOF
# Hysteria2 客户端配置信息
# 生成时间: $(date)
# 模式: ${mode^}

═══════════════════════════════════════════════════════════════
                          连接信息                              
═══════════════════════════════════════════════════════════════

服务器地址: $server_addr
端口: 443
密码: $HY_PASSWORD
TLS SNI: $DOMAIN
跳过证书验证: $insecure

═══════════════════════════════════════════════════════════════
                        快速导入链接                            
═══════════════════════════════════════════════════════════════

分享链接 (V2RayN / Nekobox / Clash Verge 等):
$share_link

═══════════════════════════════════════════════════════════════
                        Clash Meta 配置                         
═══════════════════════════════════════════════════════════════

proxies:
  - name: '${DOMAIN}-${mode^}'
    type: hysteria2
    server: '${server_addr}'
    port: 443
    password: '${HY_PASSWORD}'
    sni: '${DOMAIN}'
    skip-cert-verify: $insecure
    alpn:
      - h3

EOF

    # 附加注意事项
    if [[ "$mode" == "direct" ]]; then
        cat >> "${HY2_CONFIG_DIR}/client_info.txt" << EOF
═══════════════════════════════════════════════════════════════
                        注意事项                                
═══════════════════════════════════════════════════════════════
⚠️ 直连模式使用自签名证书，客户端必须开启 "跳过证书验证"
⚠️ 建议仅在测试或可信网络环境中使用直连模式
✅ 推荐使用 Cloudflare Tunnel 模式以获得更好的安全性
EOF
    else
        cat >> "${HY2_CONFIG_DIR}/client_info.txt" << EOF
═══════════════════════════════════════════════════════════════
                        注意事项                                
═══════════════════════════════════════════════════════════════
✅ 使用 Let's Encrypt 有效证书，安全性更高
⏰ DNS 记录全球同步可能需要几分钟，请耐心等待
🔄 如连接失败，请清除客户端或本地系统 DNS 缓存后重试
📶 Cloudflare Tunnel 能有效隐藏服务器真实IP，增强抗封锁能力
EOF
    fi
    
    # 复制到用户目录，方便访问
    cp "${HY2_CONFIG_DIR}/client_info.txt" /root/hysteria2_client_info.txt
    
    info_echo "客户端配置信息已保存到:"
    echo "  - ${HY2_CONFIG_DIR}/client_info.txt"
    echo "  - /root/hysteria2_client_info.txt"
}

# --- 连通性测试增强 ---

test_connectivity() {
    info_echo "开始全面连通性测试..."
    
    if [[ ! -f "$INSTALL_INFO_FILE" ]]; then
        error_echo "未找到安装信息，无法进行测试"
        return 1
    fi
    source "$INSTALL_INFO_FILE"
    
    # 1. 服务状态
    echo -e "\n${CYAN}1. 服务状态检查:${ENDCOLOR}"
    systemctl is-active --quiet hysteria-server && success_echo "  [✓] Hysteria2 服务: 运行中" || error_echo "  [✗] Hysteria2 服务: 未运行"
    if [[ "$MODE" == "tunnel" ]]; then
        systemctl is-active --quiet cloudflared && success_echo "  [✓] Cloudflared 服务: 运行中" || error_echo "  [✗] Cloudflared 服务: 未运行"
    fi
    
    # 2. 端口监听
    echo -e "\n${CYAN}2. 端口监听检查:${ENDCOLOR}"
    ss -ulnp | grep -q ":443.*hysteria" && success_echo "  [✓] Hysteria2 正在监听 UDP 443 端口" || error_echo "  [✗] Hysteria2 未监听 UDP 443 端口"
    
    # 3. 配置文件
    echo -e "\n${CYAN}3. 配置文件检查:${ENDCOLOR}"
    [[ -f "${HY2_CONFIG_DIR}/config.yaml" ]] && success_echo "  [✓] Hysteria2 配置文件存在" || error_echo "  [✗] Hysteria2 配置文件不存在"
    [[ -f "${CERTS_DIR}/fullchain.cer" && -f "${CERTS_DIR}/private.key" ]] && success_echo "  [✓] TLS 证书文件存在" || error_echo "  [✗] TLS 证书文件不存在"
    
    # 4. 域名解析
    echo -e "\n${CYAN}4. 域名解析检查:${ENDCOLOR}"
    if nslookup "$DOMAIN" &>/dev/null; then
        success_echo "  [✓] 域名 '$DOMAIN' 解析正常"
        echo "    解析到: $(nslookup "$DOMAIN" | awk '/^Address: / { print $2 }' | tail -1)"
    else
        error_echo "  [✗] 域名 '$DOMAIN' 解析失败"
    fi
    
    # 5. Cloudflare Tunnel 连接
    if [[ "$MODE" == "tunnel" ]]; then
        echo -e "\n${CYAN}5. Cloudflare Tunnel 连接检查:${ENDCOLOR}"
        if journalctl -u cloudflared --since="5m ago" | grep -q "Connected to"; then
            success_echo "  [✓] Tunnel 已成功连接到 Cloudflare 网络"
        else
            warning_echo "  [!] Tunnel 连接状态未知或最近没有连接成功的日志"
        fi
    fi
    
    echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
    success_echo "连通性测试完成。请根据上面的结果进行诊断。"
}

# --- 清理函数优化 ---

cleanup_previous_installation() {
    info_echo "检查并清理旧的安装..."
    
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true
    
    if command -v cloudflared &>/dev/null && [[ -f "$TUNNEL_INFO_FILE" ]]; then
        source "$TUNNEL_INFO_FILE"
        if [[ -n "${TUNNEL_NAME_PERSIST:-}" ]]; then
            info_echo "删除旧的 Cloudflare Tunnel: ${TUNNEL_NAME_PERSIST}"
            cloudflared tunnel delete -f "$TUNNEL_NAME_PERSIST" 2>/dev/null || true
        fi
    fi
    
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    
    rm -rf "$HY2_CONFIG_DIR" "$CF_CONFIG_DIR" /root/.cloudflared
    
    success_echo "旧环境清理完成"
}

# --- 安装流程整合 ---

run_install() {
    local mode="$1" # "direct" or "tunnel"
    
    # 准备工作
    cleanup_previous_installation
    detect_system
    install_dependencies
    check_port_443
    detect_network
    
    CLOUDFLARED_PATH="" # 重置
    
    if [[ "$mode" == "direct" ]]; then
        get_user_input
        install_hysteria2
        generate_self_signed_cert
    else # tunnel mode
        echo -e "\n${YELLOW}Cloudflare Tunnel 模式需要域名 NS 已托管至 Cloudflare。${ENDCOLOR}"
        read -rp "确认已完成此操作并继续安装? (Y/n): " confirm
        [[ ! "$confirm" =~ ^[nN]$ ]] || { info_echo "安装已取消"; return 0; }
        
        install_cloudflared
        get_user_input_with_cf
        install_hysteria2
        install_acme_and_cert
        setup_cloudflared_tunnel
    fi
    
    # 通用步骤
    generate_hysteria_config
    create_systemd_services
    configure_firewall
    start_services
    
    # 收尾工作
    save_install_info "$mode"
    save_client_info "$mode"
    show_installation_result "$mode"
}

# --- 其他管理功能 ---

# 安装结果显示
show_installation_result() {
    clear
    echo -e "${BG_PURPLE} 安装完成 ${ENDCOLOR}\n"
    if [[ -f "${HY2_CONFIG_DIR}/client_info.txt" ]]; then
        cat "${HY2_CONFIG_DIR}/client_info.txt"
    else
        error_echo "未找到客户端配置信息"
    fi
    echo
    read -rp "按回车键返回主菜单..."
}

# 服务管理
service_management() {
    # 内部函数，减少重复代码
    _service_op() {
        local op="$1"
        info_echo "${op}ing services..."
        # 确保停止顺序正确
        if [[ "$op" == "stop" || "$op" == "restart" ]]; then
            systemctl "$op" cloudflared 2>/dev/null || true
        fi
        systemctl "$op" hysteria-server
        # 确保启动顺序正确
        if [[ "$op" == "start" || "$op" == "restart" ]]; then
            systemctl "$op" cloudflared 2>/dev/null || true
        fi
        success_echo "操作完成"
        sleep 1
    }

    while true; do
        clear
        echo -e "${BG_PURPLE} 服务管理 ${ENDCOLOR}\n"
        systemctl status hysteria-server cloudflared --no-pager
        echo -e "\n${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
        echo " 1. 启动服务    2. 停止服务    3. 重启服务"
        echo " 4. Hysteria2 日志  5. Cloudflared 日志  0. 返回主菜单"
        echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
        read -rp "请选择操作: " choice
        case $choice in
            1) _service_op "start" ;;
            2) _service_op "stop" ;;
            3) _service_op "restart" ;;
            4) journalctl -u hysteria-server -f --no-pager ;;
            5) journalctl -u cloudflared -f --no-pager 2>/dev/null || { error_echo "Cloudflared 未安装"; sleep 2; } ;;
            0) return ;;
            *) error_echo "无效选择" && sleep 1 ;;
        esac
    done
}

# 显示配置信息
show_config_info() {
    clear
    if [[ ! -f "${HY2_CONFIG_DIR}/client_info.txt" ]]; then
        error_echo "未找到配置信息，请先安装 Hysteria2"
    else
        echo -e "${BG_PURPLE} 配置信息 ${ENDCOLOR}\n"
        cat "${HY2_CONFIG_DIR}/client_info.txt"
    fi
    read -rp "按回车键返回主菜单..."
}

# 组件更新
update_components() {
    info_echo "开始更新组件..."
    # Hysteria2 更新
    if command -v hysteria &>/dev/null; then
        info_echo "正在更新 Hysteria2..."
        systemctl stop hysteria-server 2>/dev/null || true
        install_hysteria2 # 复用安装函数
        systemctl start hysteria-server 2>/dev/null || true
    fi
    # Cloudflared 更新
    if command -v cloudflared &>/dev/null; then
        info_echo "正在更新 Cloudflared..."
        systemctl stop cloudflared 2>/dev/null || true
        # 使用包管理器更新
        case "$OS_TYPE" in
            ubuntu|debian) apt-get update -qq && apt-get install --only-upgrade -y cloudflared ;;
            *) command -v dnf &>/dev/null && dnf update -y cloudflared || yum update -y cloudflared ;;
        esac
        systemctl start cloudflared 2>/dev/null || true
    fi
    success_echo "组件更新完成"
    read -rp "按回车键返回主菜单..."
}

# 卸载
uninstall_all() {
    local mode=${1:-all} # "all" or "hy2_only"
    
    warning_echo "即将卸载，此操作不可逆！"
    read -rp "确定继续? (y/N): " confirm
    [[ "$confirm" =~ ^[yY]$ ]] || { info_echo "操作已取消"; return; }
    
    info_echo "开始卸载..."
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true

    rm -f /etc/systemd/system/hysteria-server.service /usr/local/bin/hysteria
    rm -rf "$HY2_CONFIG_DIR" /root/hysteria2_client_info.txt
    
    # 移除证书
    if [[ -f "$INSTALL_INFO_FILE" ]]; then
        source "$INSTALL_INFO_FILE"
        if [[ -n "$DOMAIN" ]] && [[ -f ~/.acme.sh/acme.sh ]]; then
            ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc 2>/dev/null || true
        fi
    fi

    if [[ "$mode" == "all" ]]; then
        if command -v cloudflared &>/dev/null && [[ -f "$TUNNEL_INFO_FILE" ]]; then
            source "$TUNNEL_INFO_FILE"
            cloudflared tunnel delete -f "${TUNNEL_NAME_PERSIST}" 2>/dev/null || true
        fi
        rm -f /etc/systemd/system/cloudflared.service
        rm -rf "$CF_CONFIG_DIR" /root/.cloudflared
    fi
    
    systemctl daemon-reload
    success_echo "卸载完成"
    read -rp "按回车键返回主菜单..."
}

# 完全清理
complete_cleanup() {
    warning_echo "即将完全清理所有相关组件和包！"
    read -rp "确定继续? (y/N): " confirm
    [[ "$confirm" =~ ^[yY]$ ]] || { info_echo "操作已取消"; return; }

    uninstall_all "all" # 先执行标准卸载
    
    if command -v cloudflared &>/dev/null; then
        info_echo "正在卸载 Cloudflared 软件包..."
        case "$OS_TYPE" in
            ubuntu|debian)
                apt-get purge -y cloudflared &>/dev/null
                rm -f /etc/apt/sources.list.d/cloudflared.list /usr/share/keyrings/cloudflare-main.gpg
                ;;
            *)
                command -v dnf &>/dev/null && dnf remove -y cloudflared &>/dev/null || yum remove -y cloudflared &>/dev/null
                rm -f /etc/yum.repos.d/cloudflared-ascii.repo
                ;;
        esac
    fi
    
    rm -f /var/log/hysteria2_install.log
    success_echo "完全清理完成"
    read -rp "按回车键返回主菜单..."
}

# --- 主菜单逻辑 ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限运行，请使用 'sudo ./script.sh'"
        exit 1
    fi
}

main() {
    check_root
    # 首次运行时检测网络
    [[ -z "$IPV4_ADDR" && -z "$IPV6_ADDR" ]] && detect_network

    while true; do
        # 确保输入来自终端
        exec </dev/tty
        show_menu
        read -rp "请选择操作 [0-9]: " choice
        
        case $choice in
            1) run_install "direct" ;;
            2) run_install "tunnel" ;;
            3) uninstall_all "hy2_only" ;;
            4) uninstall_all "all" ;;
            5) complete_cleanup ;;
            6) service_management ;;
            7) show_config_info ;;
            8) test_connectivity; read -rp "按回车键返回..." ;;
            9) update_components ;;
            0) echo "感谢使用！"; exit 0 ;;
            *) error_echo "无效选择，请输入 0-9"; sleep 1 ;;
        esac
    done
}

# --- 脚本入口 ---
main "$@"
