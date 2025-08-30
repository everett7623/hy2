#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 菜单式安装脚本
# 版本: 5.0 (优化版)
# 作者: Jensfrank & AI Assistant 优化增强
# 项目: hy2ipv6

# 严格错误处理
set -euo pipefail

# --- 脚本配置与变量 ---

# 颜色定义
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BG_PURPLE='\033[45m'
readonly ENDCOLOR='\033[0m'

# 全局变量
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
readonly TUNNEL_NAME="hysteria-tunnel"
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
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> /var/log/hysteria2_install.log 2>/dev/null || true
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
    echo -e "${RED}[ERROR]${ENDCOLOR} $1" >&2
    log_message "ERROR" "$1"
}

warning_echo() { 
    echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"
    log_message "WARNING" "$1"
}

debug_echo() {
    if [[ "${DEBUG:-}" == "true" ]]; then
        echo -e "${CYAN}[DEBUG]${ENDCOLOR} $1"
        log_message "DEBUG" "$1"
    fi
}

# --- 错误处理函数 ---

cleanup_on_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        error_echo "安装过程中发生错误 (退出码: $exit_code)"
        error_echo "请检查日志文件: /var/log/hysteria2_install.log"
        
        # 清理可能的半完成安装
        systemctl stop hysteria-server cloudflared 2>/dev/null || true
        systemctl disable hysteria-server cloudflared 2>/dev/null || true
    fi
}

trap cleanup_on_error EXIT

# --- 验证函数 ---

validate_domain() {
    local domain="$1"
    
    # 基本格式检查
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        error_echo "域名格式无效: $domain"
        return 1
    fi
    
    # 长度检查
    if [[ ${#domain} -gt 253 ]]; then
        error_echo "域名过长 (最大253字符): $domain"
        return 1
    fi
    
    # 禁止的域名
    local forbidden_domains=("localhost" "127.0.0.1" "0.0.0.0" "255.255.255.255")
    for forbidden in "${forbidden_domains[@]}"; do
        if [[ "$domain" == "$forbidden" ]]; then
            error_echo "不允许使用的域名: $domain"
            return 1
        fi
    done
    
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
    
    if [[ ${#password} -lt 8 ]]; then
        warning_echo "密码长度少于8位，建议使用更强的密码"
        return 1
    fi
    
    if [[ ${#password} -gt 128 ]]; then
        error_echo "密码过长 (最大128字符)"
        return 1
    fi
    
    # 检查密码强度
    local has_upper=0 has_lower=0 has_digit=0 has_special=0
    
    [[ "$password" =~ [A-Z] ]] && has_upper=1
    [[ "$password" =~ [a-z] ]] && has_lower=1
    [[ "$password" =~ [0-9] ]] && has_digit=1
    [[ "$password" =~ [^a-zA-Z0-9] ]] && has_special=1
    
    local strength_score=$((has_upper + has_lower + has_digit + has_special))
    
    if [[ $strength_score -lt 3 ]]; then
        warning_echo "密码强度较弱，建议包含大小写字母、数字和特殊字符"
    fi
    
    return 0
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
    elif systemctl list-unit-files | grep -q hysteria-server; then
        hy2_status="${RED}已停止${ENDCOLOR}"
    fi
    
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        cf_status="${GREEN}运行中${ENDCOLOR}"
    elif systemctl list-unit-files | grep -q cloudflared; then
        cf_status="${RED}已停止${ENDCOLOR}"
    fi
    
    echo -e "${BG_PURPLE} Hysteria2 & Cloudflare Tunnel 管理脚本 (v6.0) ${ENDCOLOR}"
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
    
    # 并发检测IPv4和IPv6
    {
        IPV4_ADDR=$(timeout 10 curl -4 -s --max-time 5 ip.sb 2>/dev/null) || IPV4_ADDR=""
    } &
    {
        IPV6_ADDR=$(timeout 10 curl -6 -s --max-time 5 ip.sb 2>/dev/null) || IPV6_ADDR=""
    } &
    wait
    
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
        warning_echo "域名 '$domain' 无法解析，请确保DNS设置正确"
        read -rp "是否继续安装? (y/N): " confirm
        if [[ "$confirm" != "y" ]]; then
            info_echo "安装已取消"
            return 1
        fi
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
    
    # 架构检测
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *) 
            error_echo "不支持的架构: $ARCH"
            error_echo "支持的架构: x86_64, aarch64, armv7l"
            exit 1
            ;;
    esac
    
    # 系统版本检查
    case "$OS_TYPE" in
        ubuntu)
            if [[ $(echo "$VERSION_ID < 18.04" | bc 2>/dev/null || echo 1) -eq 1 ]]; then
                warning_echo "Ubuntu 版本过低，建议升级到 18.04 或更高版本"
            fi
            ;;
        debian)
            if [[ $(echo "$VERSION_ID < 9" | bc 2>/dev/null || echo 1) -eq 1 ]]; then
                warning_echo "Debian 版本过低，建议升级到 9 或更高版本"
            fi
            ;;
        centos|rhel)
            if [[ $(echo "$VERSION_ID < 7" | bc 2>/dev/null || echo 1) -eq 1 ]]; then
                warning_echo "系统版本过低，建议升级"
            fi
            ;;
    esac
    
    info_echo "系统检测完成: $PRETTY_NAME ($ARCH)"
}

# --- 依赖安装优化 ---

install_dependencies() {
    info_echo "检查并安装依赖..."
    
    local base_pkgs=("curl" "wget" "unzip" "jq" "openssl" "cron")
    local net_pkgs=()
    
    # 根据系统类型添加网络工具
    case "$OS_TYPE" in
        ubuntu|debian)
            net_pkgs=("netcat-openbsd" "dnsutils" "iproute2")
            ;;
        centos|rhel|fedora|rocky|almalinux)
            net_pkgs=("nc" "bind-utils" "iproute")
            ;;
        *)
            net_pkgs=("nc" "bind-utils" "iproute2")
            ;;
    esac
    
    local all_pkgs=("${base_pkgs[@]}" "${net_pkgs[@]}")
    local install_list=()
    
    # 检查缺失的包
    for pkg in "${all_pkgs[@]}"; do
        local check_cmd="$pkg"
        case "$pkg" in
            netcat-openbsd) check_cmd="nc" ;;
            dnsutils) check_cmd="nslookup" ;;
            bind-utils) check_cmd="nslookup" ;;
            iproute|iproute2) check_cmd="ss" ;;
        esac
        
        if ! command -v "$check_cmd" &>/dev/null; then
            install_list+=("$pkg")
        fi
    done
    
    # 如果有需要安装的包
    if [[ ${#install_list[@]} -gt 0 ]]; then
        info_echo "需要安装: ${install_list[*]}"
        
        case "$OS_TYPE" in
            ubuntu|debian)
                apt-get update -qq || {
                    error_echo "apt-get update 失败"
                    exit 1
                }
                apt-get install -y "${install_list[@]}" || {
                    error_echo "依赖安装失败"
                    exit 1
                }
                ;;
            centos|rhel|fedora|rocky|almalinux)
                if command -v dnf &>/dev/null; then
                    dnf install -y "${install_list[@]}" || {
                        error_echo "依赖安装失败"
                        exit 1
                    }
                else
                    yum install -y "${install_list[@]}" || {
                        error_echo "依赖安装失败"
                        exit 1
                    }
                fi
                ;;
            *)
                error_echo "不支持的操作系统: $OS_TYPE"
                exit 1
                ;;
        esac
    fi
    
    success_echo "依赖检查完成"
}

# --- 端口检查增强 ---

check_port_443() {
    info_echo "检查端口占用..."
    
    # 检查UDP 443端口
    if ss -ulnp | grep -q ":443 "; then
        error_echo "UDP 443 端口已被占用:"
        ss -ulnp | grep ":443 " | while read -r line; do
            echo "  $line"
        done
        error_echo "请先释放端口或更改其他服务端口"
        exit 1
    fi
    
    # 检查TCP 443端口（可能与其他服务冲突）
    if ss -tlnp | grep -q ":443 "; then
        warning_echo "TCP 443 端口已被占用，可能与 Web 服务器冲突:"
        ss -tlnp | grep ":443 " | while read -r line; do
            echo "  $line"
        done
        read -rp "是否继续? (y/N): " confirm
        if [[ "$confirm" != "y" ]]; then
            info_echo "安装已取消"
            exit 1
        fi
    fi
    
    success_echo "端口检查通过"
}

# --- 防火墙配置增强 ---

configure_firewall() {
    info_echo "配置防火墙..."
    
    local firewall_configured=false
    
    # UFW (Ubuntu/Debian 常用)
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        info_echo "检测到 UFW，添加规则..."
        ufw allow 443/udp comment "Hysteria2" >/dev/null 2>&1 || true
        firewall_configured=true
    fi
    
    # firewalld (CentOS/RHEL/Fedora 常用)
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        info_echo "检测到 firewalld，添加规则..."
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        firewall_configured=true
    fi
    
    # iptables (备用)
    if ! $firewall_configured && command -v iptables &>/dev/null; then
        info_echo "使用 iptables 添加规则..."
        # 检查规则是否已存在
        if ! iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -p udp --dport 443 -j ACCEPT
        fi
        
        # 尝试保存规则
        if command -v iptables-save &>/dev/null; then
            case "$OS_TYPE" in
                ubuntu|debian)
                    if command -v netfilter-persistent &>/dev/null; then
                        netfilter-persistent save >/dev/null 2>&1 || true
                    fi
                    ;;
                centos|rhel|fedora)
                    if command -v iptables-services &>/dev/null; then
                        service iptables save >/dev/null 2>&1 || true
                    fi
                    ;;
            esac
        fi
        firewall_configured=true
    fi
    
    if $firewall_configured; then
        success_echo "防火墙配置完成"
    else
        warning_echo "未检测到防火墙或配置失败，请手动开放 UDP 443 端口"
    fi
}

# --- 用户输入优化 ---

get_user_input() {
    exec </dev/tty
    
    while true; do
        read -rp "请输入您的域名: " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            error_echo "域名不能为空"
            continue
        fi
        
        if validate_domain "$DOMAIN"; then
            break
        fi
    done
    
    while true; do
        read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD
        echo
        
        if [[ -z "$HY_PASSWORD" ]]; then
            HY_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-16)
            info_echo "自动生成强密码: $HY_PASSWORD"
            break
        else
            if validate_password "$HY_PASSWORD"; then
                break
            fi
        fi
    done
    
    while true; do
        local default_email="user$(shuf -i 1000-9999 -n 1)@gmail.com"
        read -rp "请输入 ACME 邮箱 (默认: ${default_email}): " input_email
        ACME_EMAIL="${input_email:-$default_email}"
        
        if validate_email "$ACME_EMAIL"; then
            break
        fi
    done
    
    read -rp "请输入伪装网址 (默认: https://www.bing.com): " input_fake_url
    FAKE_URL="${input_fake_url:-https://www.bing.com}"
    
    # 验证伪装网址格式
    if [[ ! "$FAKE_URL" =~ ^https?:// ]]; then
        warning_echo "伪装网址格式可能有误，已自动添加 https://"
        FAKE_URL="https://$FAKE_URL"
    fi
}

get_user_input_with_cf() {
    get_user_input
    
    echo
    warning_echo "获取 Cloudflare API Token 方法:"
    echo "1. 访问: https://dash.cloudflare.com/profile/api-tokens"
    echo "2. 点击 'Create Token' -> 使用 'Custom token' 模板"
    echo "3. 权限设置:"
    echo "   - Zone:Zone:Read, Zone:DNS:Edit"
    echo "   - Account:Cloudflare Tunnel:Edit"
    echo "4. Zone Resources: Include - Specific zone - 选择您的域名"
    echo "5. Account Resources: Include - All accounts"
    echo
    
    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN
        echo
        
        if [[ -z "$CF_TOKEN" ]]; then
            error_echo "Token 不能为空"
            continue
        fi
        
        info_echo "验证 Token..."
        local root_domain
        root_domain=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
        
        local api_result
        api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" \
            -H "Authorization: Bearer $CF_TOKEN" \
            -H "Content-Type: application/json")
        
        if echo "$api_result" | jq -e '.success==true and .result[0].id' >/dev/null 2>&1; then
            CF_ZONE_ID=$(echo "$api_result" | jq -r '.result[0].id')
            CF_ACCOUNT_ID=$(echo "$api_result" | jq -r '.result[0].account.id')
            success_echo "Token 验证成功 (Zone ID: ${CF_ZONE_ID:0:8}...)"
            break
        else
            error_echo "Token 验证失败！"
            echo "$api_result" | jq '.errors[]' 2>/dev/null || echo "请检查 Token 权限设置"
            echo
        fi
    done
}

# --- 安装函数优化 ---

install_hysteria2() {
    info_echo "安装 Hysteria2..."
    
    local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    local release_info
    
    release_info=$(curl -s "$api_url") || {
        error_echo "无法获取 Hysteria2 版本信息"
        exit 1
    }
    
    local version
    version=$(echo "$release_info" | jq -r '.tag_name')
    info_echo "最新版本: $version"
    
    # 构建下载文件名
    local filename="hysteria-linux-$ARCH"
    
    local dl_url
    dl_url=$(echo "$release_info" | jq -r ".assets[] | select(.name==\"$filename\") | .browser_download_url")
    
    if [[ -z "$dl_url" || "$dl_url" == "null" ]]; then
        error_echo "无法找到适合 $ARCH 架构的 Hysteria2 版本"
        exit 1
    fi
    
    # 下载并安装
    local temp_file="/tmp/hysteria2_${version}_${ARCH}"
    
    if ! wget -q --show-progress -O "$temp_file" "$dl_url"; then
        error_echo "Hysteria2 下载失败"
        exit 1
    fi
    
    # 验证下载的文件
    if [[ ! -s "$temp_file" ]]; then
        error_echo "下载的文件为空"
        exit 1
    fi
    
    # 安装
    install -m 755 "$temp_file" /usr/local/bin/hysteria
    rm -f "$temp_file"
    
    # 验证安装
    if ! /usr/local/bin/hysteria version >/dev/null 2>&1; then
        error_echo "Hysteria2 安装验证失败"
        exit 1
    fi
    
    success_echo "Hysteria2 安装完成 ($version)"
}

install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        CLOUDFLARED_PATH=$(command -v cloudflared)
        info_echo "Cloudflared 已安装: $CLOUDFLARED_PATH"
        return 0
    fi
    
    info_echo "安装 Cloudflared..."
    
    case "$OS_TYPE" in
        ubuntu|debian)
            # 添加官方仓库
            curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | \
                tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
            
            echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main' | \
                tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
            
            apt-get update -qq
            apt-get install -y cloudflared
            ;;
        centos|rhel|fedora|rocky|almalinux)
            # 添加官方仓库
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
    
    CLOUDFLARED_PATH=$(command -v cloudflared)
    if [[ -z "$CLOUDFLARED_PATH" ]]; then
        error_echo "Cloudflared 安装失败"
        exit 1
    fi
    
    success_echo "Cloudflared 安装完成"
}

# --- 证书管理优化 ---

install_acme_and_cert() {
    info_echo "申请 SSL 证书..."
    
    # 安装 acme.sh
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        info_echo "安装 acme.sh..."
        curl -s https://get.acme.sh | sh -s email="$ACME_EMAIL" || {
            error_echo "acme.sh 安装失败"
            exit 1
        }
    fi
    
    # 设置环境变量
    export CF_Token="$CF_TOKEN"
    
    # 申请证书
    info_echo "申请证书，这可能需要几分钟..."
    
    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --ecc; then
        error_echo "证书申请失败"
        error_echo "可能的原因:"
        echo "1. Cloudflare API Token 权限不足"
        echo "2. 域名未托管在 Cloudflare"
        echo "3. DNS API 调用限制"
        exit 1
    fi
    
    # 安装证书
    mkdir -p "$CERTS_DIR"
    
    if ! ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
        --fullchain-file "${CERTS_DIR}/fullchain.cer" \
        --key-file "${CERTS_DIR}/private.key"; then
        error_echo "证书安装失败"
        exit 1
    fi
    
    chmod 600 "${CERTS_DIR}/private.key"
    chmod 644 "${CERTS_DIR}/fullchain.cer"
    
    success_echo "SSL 证书申请完成"
}

generate_self_signed_cert() {
    info_echo "生成自签名证书..."
    
    mkdir -p "$CERTS_DIR"
    
    # 生成私钥
    openssl genpkey -algorithm RSA -out "${CERTS_DIR}/private.key" -pkcs8 -pass pass: 2>/dev/null
    
    # 生成证书请求和自签名证书
    openssl req -new -x509 -key "${CERTS_DIR}/private.key" \
        -out "${CERTS_DIR}/fullchain.cer" \
        -days 3650 \
        -subj "/CN=$DOMAIN/O=Hysteria2/C=US" \
        -addext "subjectAltName=DNS:$DOMAIN" 2>/dev/null
    
    chmod 600 "${CERTS_DIR}/private.key"
    chmod 644 "${CERTS_DIR}/fullchain.cer"
    
    success_echo "自签名证书生成完成"
}

# --- 配置生成优化 ---

generate_hysteria_config() {
    info_echo "生成 Hysteria2 配置..."
    
    mkdir -p "$HY2_CONFIG_DIR"
    
    # 确定监听地址
    local listen_addr
    if [[ -n "$IPV6_ADDR" ]]; then
        listen_addr="[::]:443"
        info_echo "使用 IPv6 监听地址"
    else
        listen_addr="0.0.0.0:443"
        info_echo "使用 IPv4 监听地址"
    fi
    
    # 生成配置文件
    cat > "${HY2_CONFIG_DIR}/config.yaml" << EOF
# Hysteria2 服务端配置
# 生成时间: $(date)

listen: $listen_addr

# TLS 配置
tls:
  cert: ${CERTS_DIR}/fullchain.cer
  key: ${CERTS_DIR}/private.key

# 认证配置
auth:
  type: password
  password: $HY_PASSWORD

# 流量伪装
masquerade:
  type: proxy
  proxy:
    url: $FAKE_URL
    rewriteHost: true

# 性能优化
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

# 带宽限制 (可根据需要调整)
bandwidth:
  up: 1 gbps
  down: 1 gbps

# 日志配置
log:
  level: info
  timestamp: true
EOF
    
    success_echo "Hysteria2 配置生成完成"
}

# --- Cloudflare Tunnel 设置优化 ---

setup_cloudflared_tunnel() {
    info_echo "设置 Cloudflare Tunnel..."
    
    # 检查域名解析
    check_domain_resolution "$DOMAIN" || return 1
    
    warning_echo "即将打开浏览器进行授权，请确保您能访问浏览器"
    read -rp "按回车键继续..." dummy
    
    # 登录授权
    if ! timeout 300 cloudflared tunnel login; then
        error_echo "Cloudflared 登录失败或超时"
        error_echo "请检查网络连接和浏览器访问"
        exit 1
    fi
    
    info_echo "登录成功，等待凭证同步..."
    sleep 5
    
    # 检查是否已存在隧道
    local existing_tunnels
    existing_tunnels=$(cloudflared tunnel list -o json 2>/dev/null || echo "[]")
    TUNNEL_ID=$(echo "$existing_tunnels" | jq -r ".[] | select(.name==\"$TUNNEL_NAME\") | .id")
    
    if [[ -z "$TUNNEL_ID" || "$TUNNEL_ID" == "null" ]]; then
        info_echo "创建新隧道: $TUNNEL_NAME"
        local create_output
        create_output=$(cloudflared tunnel create "$TUNNEL_NAME" 2>&1)
        
        TUNNEL_ID=$(echo "$create_output" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1)
        
        if [[ -z "$TUNNEL_ID" ]]; then
            error_echo "创建隧道失败"
            echo "$create_output"
            exit 1
        fi
        
        success_echo "隧道创建成功: $TUNNEL_ID"
    else
        info_echo "使用现有隧道: $TUNNEL_ID"
    fi
    
    # 确保配置目录存在
    mkdir -p "$CF_CONFIG_DIR"
    
    # 移动凭证文件
    local credential_file="/root/.cloudflared/${TUNNEL_ID}.json"
    local target_credential="/etc/cloudflared/${TUNNEL_ID}.json"
    
    if [[ -f "$credential_file" ]]; then
        mv "$credential_file" "$target_credential" || {
            error_echo "移动隧道凭证失败"
            exit 1
        }
    elif [[ ! -f "$target_credential" ]]; then
        error_echo "找不到隧道凭证文件"
        exit 1
    fi
    
    # 保存隧道信息
    cat > "$TUNNEL_INFO_FILE" << EOF
TUNNEL_ID=$TUNNEL_ID
TUNNEL_NAME_PERSIST=$TUNNEL_NAME
DOMAIN=$DOMAIN
CREATED_AT=$(date)
EOF
    
    # 确定服务地址
    local service_addr
    if [[ -n "$IPV6_ADDR" ]]; then
        service_addr="udp://[::1]:443"
    else
        service_addr="udp://127.0.0.1:443"
    fi
    
    # 生成 Cloudflared 配置
    cat > "${CF_CONFIG_DIR}/config.yml" << EOF
# Cloudflare Tunnel 配置
# 生成时间: $(date)

tunnel: $TUNNEL_ID
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json

# 协议设置
protocol: quic

# 日志配置
loglevel: info

# 路由配置
ingress:
  - hostname: $DOMAIN
    service: $service_addr
    originRequest:
      # UDP 特定配置
      noHappyEyeballs: true
      keepAliveTimeout: 30s
      tcpKeepAlive: 30s
  - service: http_status:404
EOF
    
    # 设置 DNS 记录
    info_echo "设置 DNS 记录..."
    if ! cloudflared tunnel route dns "$TUNNEL_ID" "$DOMAIN"; then
        error_echo "DNS 记录设置失败"
        exit 1
    fi
    
    success_echo "Cloudflare Tunnel 设置完成"
}

# --- 系统服务优化 ---

create_systemd_services() {
    info_echo "创建系统服务..."
    
    # Hysteria2 服务
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
Documentation=https://hysteria.network/
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/hysteria server --config ${HY2_CONFIG_DIR}/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
RestartPreventExitStatus=23
LimitNOFILE=1000000
StandardOutput=journal
StandardError=journal

# 安全设置
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
        if [[ -f "$TUNNEL_INFO_FILE" ]]; then
            source "$TUNNEL_INFO_FILE"
        fi
        
        cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
Documentation=https://developers.cloudflare.com/cloudflare-one/connections/connect-apps
After=network.target hysteria-server.service
Wants=network.target
BindsTo=hysteria-server.service

[Service]
Type=simple
User=root
Group=root
ExecStart=$CLOUDFLARED_PATH tunnel --config ${CF_CONFIG_DIR}/config.yml run ${TUNNEL_ID}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
RestartPreventExitStatus=23
StandardOutput=journal
StandardError=journal

# 安全设置
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
    success_echo "系统服务创建完成"
}

# --- 服务启动优化 ---

start_services() {
    info_echo "启动服务..."
    
    # 启动 Hysteria2
    systemctl enable hysteria-server
    systemctl start hysteria-server
    
    # 等待 Hysteria2 启动
    info_echo "等待 Hysteria2 启动..."
    local max_wait=30
    for ((i=1; i<=max_wait; i++)); do
        if ss -ulnp | grep -q ":443.*hysteria"; then
            success_echo "Hysteria2 启动成功"
            break
        fi
        
        if [[ $i -eq $max_wait ]]; then
            error_echo "Hysteria2 启动超时！"
            error_echo "服务日志:"
            journalctl -u hysteria-server -n 20 --no-pager
            exit 1
        fi
        
        sleep 1
    done
    
    # 启动 Cloudflared (如果需要)
    if [[ -f /etc/systemd/system/cloudflared.service ]]; then
        systemctl enable cloudflared
        systemctl start cloudflared
        
        info_echo "等待 Cloudflared 连接..."
        sleep 10
        
        # 检查连接状态
        if journalctl -u cloudflared --since="30s ago" | grep -q "Connected to"; then
            success_echo "Cloudflared 连接成功"
        else
            warning_echo "Cloudflared 可能未完全连接，请稍后检查"
        fi
    fi
}

# --- 信息保存优化 ---

save_install_info() {
    local mode="$1"
    
    mkdir -p "$HY2_CONFIG_DIR"
    
    # 保存安装信息
    cat > "$INSTALL_INFO_FILE" << EOF
# Hysteria2 安装信息
INSTALL_DATE=$(date)
MODE=$mode
DOMAIN=$DOMAIN
HY_PASSWORD=$HY_PASSWORD
ACME_EMAIL=$ACME_EMAIL
FAKE_URL=$FAKE_URL
IPV4_ADDR=$IPV4_ADDR
IPV6_ADDR=$IPV6_ADDR
SCRIPT_VERSION=6.0
EOF
    
    if [[ "$mode" == "tunnel" ]]; then
        cat >> "$INSTALL_INFO_FILE" << EOF
CF_ZONE_ID=$CF_ZONE_ID
CF_ACCOUNT_ID=$CF_ACCOUNT_ID
TUNNEL_ID=$TUNNEL_ID
EOF
    fi
    
    success_echo "安装信息已保存"
}

save_client_info() {
    local mode="$1"
    
    mkdir -p "$HY2_CONFIG_DIR"
    
    local server_addr
    if [[ "$mode" == "direct" ]]; then
        server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    else
        server_addr="$DOMAIN"
    fi
    
    local insecure
    if [[ "$mode" == "direct" ]]; then
        insecure="true"
    else
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

分享链接 (V2RayN / Nekobox / Clash Verge):
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

═══════════════════════════════════════════════════════════════
                        V2Ray 核心配置                          
═══════════════════════════════════════════════════════════════

{
  "outbounds": [
    {
      "protocol": "hysteria2",
      "settings": {
        "servers": [
          {
            "address": "$server_addr",
            "port": 443,
            "password": "$HY_PASSWORD"
          }
        ]
      },
      "streamSettings": {
        "network": "h3",
        "security": "tls",
        "tlsSettings": {
          "serverName": "$DOMAIN",
          "allowInsecure": $insecure
        }
      }
    }
  ]
}

═══════════════════════════════════════════════════════════════
                        注意事项                                
═══════════════════════════════════════════════════════════════
EOF

    if [[ "$mode" == "direct" ]]; then
        cat >> "${HY2_CONFIG_DIR}/client_info.txt" << EOF

⚠️  直连模式使用自签名证书，客户端必须开启 "跳过证书验证"
⚠️  建议仅在测试环境或特殊情况下使用直连模式
✅  推荐使用 Cloudflare Tunnel 模式以获得更好的安全性
EOF
    else
        cat >> "${HY2_CONFIG_DIR}/client_info.txt" << EOF

✅  使用 Let's Encrypt 有效证书，安全性更高
⏰  DNS 记录全球同步可能需要几分钟，请耐心等待
🔄  如连接失败，请清除客户端 DNS 缓存后重试
📶  Cloudflare Tunnel 可能提供更好的连接稳定性
EOF
    fi
    
    # 复制到用户目录
    cp "${HY2_CONFIG_DIR}/client_info.txt" /root/hysteria2_client_info.txt
    
    info_echo "客户端配置信息已保存到:"
    echo "  - ${HY2_CONFIG_DIR}/client_info.txt"
    echo "  - /root/hysteria2_client_info.txt"
}

# --- 连通性测试增强 ---

test_connectivity() {
    info_echo "开始全面连通性测试..."
    
    # 检查安装状态
    if [[ ! -f /etc/systemd/system/hysteria-server.service ]]; then
        error_echo "Hysteria2 服务未安装"
        return 1
    fi
    
    # 加载配置信息
    if [[ -f "$INSTALL_INFO_FILE" ]]; then
        source "$INSTALL_INFO_FILE"
    fi
    
    local test_passed=0
    local test_total=0
    
    # 测试1: 服务状态
    echo
    info_echo "1. 检查服务状态..."
    ((test_total++))
    
    if systemctl is-active --quiet hysteria-server; then
        success_echo "  ✓ Hysteria2 服务: 运行中"
        ((test_passed++))
    else
        error_echo "  ✗ Hysteria2 服务: 未运行"
        journalctl -u hysteria-server -n 5 --no-pager | sed 's/^/    /'
    fi
    
    if [[ "$MODE" == "tunnel" ]]; then
        if systemctl is-active --quiet cloudflared; then
            success_echo "  ✓ Cloudflared 服务: 运行中"
        else
            error_echo "  ✗ Cloudflared 服务: 未运行"
            journalctl -u cloudflared -n 5 --no-pager | sed 's/^/    /'
        fi
    fi
    
    # 测试2: 端口监听
    echo
    info_echo "2. 检查端口监听..."
    ((test_total++))
    
    if ss -ulnp | grep -q ":443.*hysteria"; then
        success_echo "  ✓ Hysteria2 正在监听 UDP 443 端口"
        ((test_passed++))
    else
        error_echo "  ✗ Hysteria2 未监听 UDP 443 端口"
        ss -ulnp | grep ":443" | sed 's/^/    当前占用: /' || echo "    无进程监听 443 端口"
    fi
    
    # 测试3: 配置文件
    echo
    info_echo "3. 检查配置文件..."
    ((test_total++))
    
    local config_valid=true
    
    if [[ ! -f "${HY2_CONFIG_DIR}/config.yaml" ]]; then
        error_echo "  ✗ Hysteria2 配置文件不存在"
        config_valid=false
    fi
    
    if [[ ! -f "${CERTS_DIR}/fullchain.cer" || ! -f "${CERTS_DIR}/private.key" ]]; then
        error_echo "  ✗ TLS 证书文件不存在"
        config_valid=false
    fi
    
    if $config_valid; then
        success_echo "  ✓ 配置文件完整"
        ((test_passed++))
    fi
    
    # 测试4: 域名解析
    if [[ -n "$DOMAIN" ]]; then
        echo
        info_echo "4. 检查域名解析..."
        ((test_total++))
        
        if nslookup "$DOMAIN" >/dev/null 2>&1; then
            success_echo "  ✓ 域名 '$DOMAIN' 解析正常"
            
            # 显示解析结果
            local resolved_ip
            resolved_ip=$(nslookup "$DOMAIN" | awk '/^Address: / { print $2 }' | tail -1)
            if [[ -n "$resolved_ip" ]]; then
                echo "    解析到: $resolved_ip"
            fi
            ((test_passed++))
        else
            error_echo "  ✗ 域名 '$DOMAIN' 解析失败"
        fi
    fi
    
    # 测试5: Cloudflare Tunnel 连接
    if [[ "$MODE" == "tunnel" ]]; then
        echo
        info_echo "5. 检查 Cloudflare Tunnel 连接..."
        ((test_total++))
        
        if journalctl -u cloudflared --since="2m ago" | grep -q "Connected to"; then
            success_echo "  ✓ Tunnel 已成功连接到 Cloudflare"
            ((test_passed++))
        else
            warning_echo "  ⚠ Tunnel 连接状态未知"
            info_echo "    最近日志:"
            journalctl -u cloudflared -n 3 --no-pager | sed 's/^/      /'
        fi
    fi
    
    # 测试6: 网络连通性测试
    echo
    info_echo "6. 网络连通性测试..."
    ((test_total++))
    
    local test_host="8.8.8.8"
    if timeout 5 nc -u -z "$test_host" 53 2>/dev/null; then
        success_echo "  ✓ UDP 网络连通性正常"
        ((test_passed++))
    else
        warning_echo "  ⚠ UDP 网络连通性测试失败"
    fi
    
    # 显示测试结果
    echo
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
    if [[ $test_passed -eq $test_total ]]; then
        success_echo "连通性测试完成: $test_passed/$test_total 项通过 ✅"
    else
        warning_echo "连通性测试完成: $test_passed/$test_total 项通过"
        if [[ $test_passed -lt $((test_total / 2)) ]]; then
            error_echo "多项测试失败，服务可能无法正常工作"
        fi
    fi
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
}

# --- 清理函数优化 ---

cleanup_previous_installation() {
    info_echo "检查并清理旧安装..."
    
    # 停止服务
    for service in hysteria-server cloudflared; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            info_echo "停止服务: $service"
            systemctl stop "$service" || true
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            systemctl disable "$service" || true
        fi
    done
    
    # 删除隧道 (如果存在)
    if command -v cloudflared &>/dev/null && [[ -f "$TUNNEL_INFO_FILE" ]]; then
        source "$TUNNEL_INFO_FILE"
        if [[ -n "${TUNNEL_NAME_PERSIST:-}" ]]; then
            info_echo "删除旧隧道..."
            cloudflared tunnel delete -f "$TUNNEL_NAME_PERSIST" 2>/dev/null || true
        fi
    fi
    
    # 删除系统服务文件
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    
    # 删除配置目录
    rm -rf "$HY2_CONFIG_DIR" "$CF_CONFIG_DIR" /root/.cloudflared
    
    success_echo "旧环境清理完成"
}

complete_cleanup() {
    warning_echo "即将完全清理所有组件和配置文件..."
    echo "这将删除:"
    echo "  - Hysteria2 服务和配置"
    echo "  - Cloudflare Tunnel 和配置"
    echo "  - SSL 证书"
    echo "  - 系统服务文件"
    echo "  - 所有相关日志"
    echo
    
    read -rp "确定继续? 此操作不可逆转 (y/N): " confirm
    if [[ "$confirm" != "y" ]]; then
        info_echo "操作已取消"
        return 0
    fi
    
    info_echo "开始完全清理..."
    
    # 加载配置信息
    if [[ -f "$INSTALL_INFO_FILE" ]]; then
        source "$INSTALL_INFO_FILE"
    fi
    
    if [[ -f "$TUNNEL_INFO_FILE" ]]; then
        source "$TUNNEL_INFO_FILE"
    fi
    
    # 停止并删除服务
    for service in hysteria-server cloudflared; do
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
    done
    
    # 删除隧道
    if command -v cloudflared &>/dev/null && [[ -n "${TUNNEL_NAME_PERSIST:-$TUNNEL_NAME}" ]]; then
        cloudflared tunnel delete -f "${TUNNEL_NAME_PERSIST:-$TUNNEL_NAME}" 2>/dev/null || true
    fi
    
    # 删除系统文件
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /etc/systemd/system/cloudflared.service
    rm -f /usr/local/bin/hysteria
    systemctl daemon-reload
    
    # 删除 SSL 证书
    if [[ -n "$DOMAIN" ]] && command -v ~/.acme.sh/acme.sh &>/dev/null; then
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc 2>/dev/null || true
    fi
    
    # 删除配置目录
    rm -rf "$HY2_CONFIG_DIR" "$CF_CONFIG_DIR" /root/.cloudflared
    
    # 删除客户端配置文件
    rm -f /root/hysteria2_client_info.txt
    
    # 卸载 Cloudflared 包
    case "$OS_TYPE" in
        ubuntu|debian)
            apt-get purge -y cloudflared >/dev/null 2>&1 || true
            rm -f /etc/apt/sources.list.d/cloudflared.list
            rm -f /usr/share/keyrings/cloudflare-main.gpg
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &>/dev/null; then
                dnf remove -y cloudflared >/dev/null 2>&1 || true
            else
                yum remove -y cloudflared >/dev/null 2>&1 || true
            fi
            rm -f /etc/yum.repos.d/cloudflared-ascii.repo
            ;;
    esac
    
    # 清理日志
    rm -f /var/log/hysteria2_install.log
    
    success_echo "完全清理完成！所有组件和配置已删除。"
    read -rp "按回车键返回主菜单..."
}

# --- 安装结果显示优化 ---

show_installation_result() {
    local mode="$1"
    
    clear
    echo -e "${BG_PURPLE} 安装完成 ${ENDCOLOR}"
    echo
    
    if [[ -f "${HY2_CONFIG_DIR}/client_info.txt" ]]; then
        cat "${HY2_CONFIG_DIR}/client_info.txt"
    else
        error_echo "无法找到客户端配置信息"
        return 1
    fi
    
    echo
    echo -e "${YELLOW}下一步操作:${ENDCOLOR}"
    echo "1. 复制上述配置信息到您的客户端"
    echo "2. 如使用分享链接，请直接导入客户端"
    echo "3. 如手动配置，请参考上述详细参数"
    
    if [[ "$mode" == "tunnel" ]]; then
        echo "4. 等待 2-5 分钟让 DNS 记录全球同步"
        echo "5. 如连接失败，请清除客户端 DNS 缓存"
    fi
    
    echo
    read -rp "按回车键返回主菜单..."
}

# --- 服务管理增强 ---

service_management() {
    while true; do
        clear
        echo -e "${BG_PURPLE} 服务管理 ${ENDCOLOR}"
        echo
        
        # 显示详细服务状态
        echo -e "${CYAN}服务状态:${ENDCOLOR}"
        
        # Hysteria2 状态
        if systemctl is-active --quiet hysteria-server 2>/dev/null; then
            echo -e "${GREEN}✓ Hysteria2   : 运行中${ENDCOLOR}"
            local uptime
            uptime=$(systemctl show hysteria-server --property=ActiveEnterTimestamp --value)
            if [[ -n "$uptime" && "$uptime" != "n/a" ]]; then
                echo "  启动时间: $uptime"
            fi
        elif systemctl list-unit-files | grep -q hysteria-server; then
            echo -e "${RED}✗ Hysteria2   : 已停止${ENDCOLOR}"
        else
            echo -e "${YELLOW}? Hysteria2   : 未安装${ENDCOLOR}"
        fi
        
        # Cloudflared 状态
        if systemctl is-active --quiet cloudflared 2>/dev/null; then
            echo -e "${GREEN}✓ Cloudflared : 运行中${ENDCOLOR}"
        elif systemctl list-unit-files | grep -q cloudflared; then
            echo -e "${RED}✗ Cloudflared : 已停止${ENDCOLOR}"
        else
            echo -e "${YELLOW}? Cloudflared : 未安装${ENDCOLOR}"
        fi
        
        # 端口占用情况
        echo
        echo -e "${CYAN}端口状态:${ENDCOLOR}"
        if ss -ulnp | grep -q ":443"; then
            ss -ulnp | grep ":443" | while read -r line; do
                echo "  UDP 443: $line"
            done
        else
            echo -e "${YELLOW}  UDP 443: 未被占用${ENDCOLOR}"
        fi
        
        echo
        echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${ENDCOLOR}"
        echo -e " ${CYAN}操作选项:${ENDCOLOR}"
        echo -e " ${CYAN}1.${ENDCOLOR} 启动所有服务      ${CYAN}2.${ENDCOLOR} 停止所有服务"
        echo -e " ${CYAN}3.${ENDCOLOR} 重启所有服务      ${CYAN}4.${ENDCOLOR} 重新加载配置"
        echo
        echo -e " ${CYAN}日志查看:${ENDCOLOR}"
        echo -e " ${CYAN}5.${ENDCOLOR} Hysteria2 实时日志 ${CYAN}6.${ENDCOLOR} Cloudflare 实时日志"
        echo -e " ${CYAN}7.${ENDCOLOR} Hysteria2 历史日志 ${CYAN}8.${ENDCOLOR} Cloudflare 历史日志"
        echo
        echo -e " ${CYAN}高级操作:${ENDCOLOR}"
        echo -e " ${CYAN}9.${ENDCOLOR} 服务状态详情      ${CYAN}10.${ENDCOLOR} 性能监控"
        echo
        echo -e " ${CYAN}0.${ENDCOLOR} 返回主菜单"
        echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${ENDCOLOR}"

        read -rp "请选择操作 [0-10]: " choice
        case $choice in
            1)
                info_echo "启动服务..."
                systemctl start hysteria-server
                if [[ -f /etc/systemd/system/cloudflared.service ]]; then
                    sleep 2
                    systemctl start cloudflared
                fi
                success_echo "服务启动完成"
                sleep 2
                ;;
            2)
                info_echo "停止服务..."
                if [[ -f /etc/systemd/system/cloudflared.service ]]; then
                    systemctl stop cloudflared
                fi
                systemctl stop hysteria-server
                success_echo "服务停止完成"
                sleep 2
                ;;
            3)
                info_echo "重启服务..."
                if [[ -f /etc/systemd/system/cloudflared.service ]]; then
                    systemctl stop cloudflared
                fi
                systemctl restart hysteria-server
                sleep 3
                if [[ -f /etc/systemd/system/cloudflared.service ]]; then
                    systemctl start cloudflared
                fi
                success_echo "服务重启完成"
                sleep 2
                ;;
            4)
                info_echo "重新加载配置..."
                systemctl daemon-reload
                systemctl reload-or-restart hysteria-server
                if [[ -f /etc/systemd/system/cloudflared.service ]]; then
                    systemctl reload-or-restart cloudflared
                fi
                success_echo "配置重新加载完成"
                sleep 2
                ;;
            5)
                echo -e "${CYAN}Hysteria2 实时日志 (Ctrl+C 退出):${ENDCOLOR}"
                journalctl -u hysteria-server -f --no-pager
                ;;
            6)
                if [[ -f /etc/systemd/system/cloudflared.service ]]; then
                    echo -e "${CYAN}Cloudflare 实时日志 (Ctrl+C 退出):${ENDCOLOR}"
                    journalctl -u cloudflared -f --no-pager
                else
                    error_echo "Cloudflared 服务未安装"
                    sleep 2
                fi
                ;;
            7)
                echo -e "${CYAN}Hysteria2 历史日志:${ENDCOLOR}"
                journalctl -u hysteria-server -n 50 --no-pager
                read -rp "按回车键继续..."
                ;;
            8)
                if [[ -f /etc/systemd/system/cloudflared.service ]]; then
                    echo -e "${CYAN}Cloudflare 历史日志:${ENDCOLOR}"
                    journalctl -u cloudflared -n 50 --no-pager
                    read -rp "按回车键继续..."
                else
                    error_echo "Cloudflared 服务未安装"
                    sleep 2
                fi
                ;;
            9)
                show_service_details
                read -rp "按回车键继续..."
                ;;
            10)
                show_performance_monitor
                read -rp "按回车键继续..."
                ;;
            0)
                return
                ;;
            *)
                error_echo "无效选择"
                sleep 1
                ;;
        esac
    done
}

show_service_details() {
    clear
    echo -e "${BG_PURPLE} 服务状态详情 ${ENDCOLOR}"
    echo
    
    # Hysteria2 详情
    echo -e "${CYAN}Hysteria2 服务详情:${ENDCOLOR}"
    if systemctl list-unit-files | grep -q hysteria-server; then
        systemctl status hysteria-server --no-pager | head -20
    else
        echo "服务未安装"
    fi
    
    echo
    echo -e "${CYAN}Cloudflared 服务详情:${ENDCOLOR}"
    if systemctl list-unit-files | grep -q cloudflared; then
        systemctl status cloudflared --no-pager | head -20
    else
        echo "服务未安装"
    fi
}

show_performance_monitor() {
    clear
    echo -e "${BG_PURPLE} 性能监控 ${ENDCOLOR}"
    echo
    
    # 系统资源使用
    echo -e "${CYAN}系统资源:${ENDCOLOR}"
    echo "CPU 使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
    echo "内存使用: $(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)", $3*100/$2, $3, $2}')"
    echo "磁盘使用: $(df -h / | awk 'NR==2{print $5 " (" $3 "/" $2 ")"}')"
    
    echo
    echo -e "${CYAN}网络连接:${ENDCOLOR}"
    
    # 显示 Hysteria2 连接数
    local hy2_connections
    hy2_connections=$(ss -u | grep ":443" | wc -l)
    echo "Hysteria2 活跃连接: $hy2_connections"
    
    # 网络流量统计
    if command -v vnstat &>/dev/null; then
        echo
        vnstat -i eth0 --oneline 2>/dev/null | head -1 || echo "网络统计不可用"
    fi
    
    echo
    echo -e "${CYAN}进程信息:${ENDCOLOR}"
    
    # Hysteria2 进程信息
    local hy2_pid
    hy2_pid=$(pgrep -f "hysteria.*server" 2>/dev/null || echo "")
    if [[ -n "$hy2_pid" ]]; then
        echo "Hysteria2 PID: $hy2_pid"
        ps -p "$hy2_pid" -o pid,ppid,cmd,pmem,pcpu --no-headers 2>/dev/null || true
    fi
    
    # Cloudflared 进程信息
    local cf_pid
    cf_pid=$(pgrep -f cloudflared 2>/dev/null || echo "")
    if [[ -n "$cf_pid" ]]; then
        echo "Cloudflared PID: $cf_pid"
        ps -p "$cf_pid" -o pid,ppid,cmd,pmem,pcpu --no-headers 2>/dev/null || true
    fi
}

# --- 卸载函数优化 ---

uninstall_hysteria_only() {
    warning_echo "将卸载 Hysteria2 服务，但保留 Cloudflared (如已安装)"
    echo "这将删除:"
    echo "  - Hysteria2 服务和配置文件"
    echo "  - SSL 证书"
    echo "  - 客户端配置信息"
    echo
    
    read -rp "确定继续? (y/N): " confirm
    if [[ "$confirm" != "y" ]]; then
        info_echo "操作已取消"
        return 0
    fi
    
    info_echo "卸载 Hysteria2..."
    
    # 加载配置信息
    if [[ -f "$INSTALL_INFO_FILE" ]]; then
        source "$INSTALL_INFO_FILE"
    fi
    
    # 停止并禁用服务
    systemctl stop hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    
    # 删除系统服务文件
    rm -f /etc/systemd/system/hysteria-server.service
    systemctl daemon-reload
    
    # 删除程序文件
    rm -f /usr/local/bin/hysteria
    
    # 删除配置目录
    rm -rf "$HY2_CONFIG_DIR"
    
    # 删除客户端配置
    rm -f /root/hysteria2_client_info.txt
    
    # 删除 SSL 证书
    if [[ -n "$DOMAIN" ]] && command -v ~/.acme.sh/acme.sh &>/dev/null; then
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc 2>/dev/null || true
    fi
    
    success_echo "Hysteria2 卸载完成"
    read -rp "按回车键返回主菜单..."
}

uninstall_all() {
    warning_echo "将完全卸载 Hysteria2 和 Cloudflare Tunnel"
    echo "这将删除:"
    echo "  - Hysteria2 服务和配置"
    echo "  - Cloudflare Tunnel 和相关配置"
    echo "  - SSL 证书"
    echo "  - 所有客户端配置信息"
    echo
    
    read -rp "确定继续? (y/N): " confirm
    if [[ "$confirm" != "y" ]]; then
        info_echo "操作已取消"
        return 0
    fi
    
    info_echo "卸载所有组件..."
    
    # 加载配置信息
    if [[ -f "$INSTALL_INFO_FILE" ]]; then
        source "$INSTALL_INFO_FILE"
    fi
    
    if [[ -f "$TUNNEL_INFO_FILE" ]]; then
        source "$TUNNEL_INFO_FILE"
    fi
    
    # 停止服务
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true
    
    # 删除系统服务
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    
    # 删除程序文件
    rm -f /usr/local/bin/hysteria
    
    # 删除隧道
    if [[ -n "${TUNNEL_NAME_PERSIST:-}" ]] && command -v cloudflared &>/dev/null; then
        cloudflared tunnel delete -f "${TUNNEL_NAME_PERSIST}" 2>/dev/null || true
    fi
    
    # 删除 SSL 证书
    if [[ -n "$DOMAIN" ]] && command -v ~/.acme.sh/acme.sh &>/dev/null; then
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc 2>/dev/null || true
    fi
    
    # 删除配置目录
    rm -rf "$HY2_CONFIG_DIR" "$CF_CONFIG_DIR" /root/.cloudflared
    
    # 删除客户端配置
    rm -f /root/hysteria2_client_info.txt
    
    success_echo "所有组件卸载完成"
    read -rp "按回车键返回主菜单..."
}

# --- 更新功能 ---

update_components() {
    clear
    echo -e "${BG_PURPLE} 组件更新 ${ENDCOLOR}"
    echo
    
    # 检查当前安装状态
    local hy2_installed=false
    local cf_installed=false
    
    if [[ -f /usr/local/bin/hysteria ]]; then
        hy2_installed=true
        local current_version
        current_version=$(/usr/local/bin/hysteria version 2>/dev/null | head -1 || echo "未知版本")
        echo -e "${CYAN}当前 Hysteria2 版本:${ENDCOLOR} $current_version"
    fi
    
    if command -v cloudflared &>/dev/null; then
        cf_installed=true
        local cf_version
        cf_version=$(cloudflared version 2>/dev/null || echo "未知版本")
        echo -e "${CYAN}当前 Cloudflared 版本:${ENDCOLOR} $cf_version"
    fi
    
    if ! $hy2_installed && ! $cf_installed; then
        error_echo "未检测到已安装的组件"
        read -rp "按回车键返回主菜单..."
        return
    fi
    
    echo
    echo -e "${CYAN}更新选项:${ENDCOLOR}"
    
    if $hy2_installed; then
        echo -e " ${CYAN}1.${ENDCOLOR} 更新 Hysteria2"
    fi
    
    if $cf_installed; then
        echo -e " ${CYAN}2.${ENDCOLOR} 更新 Cloudflared"
    fi
    
    if $hy2_installed && $cf_installed; then
        echo -e " ${CYAN}3.${ENDCOLOR} 更新所有组件"
    fi
    
    echo -e " ${CYAN}0.${ENDCOLOR} 返回主菜单"
    echo
    
    read -rp "请选择操作: " choice
    
    case $choice in
        1)
            if $hy2_installed; then
                update_hysteria2
            else
                error_echo "Hysteria2 未安装"
            fi
            ;;
        2)
            if $cf_installed; then
                update_cloudflared
            else
                error_echo "Cloudflared 未安装"
            fi
            ;;
        3)
            if $hy2_installed && $cf_installed; then
                update_hysteria2
                update_cloudflared
            else
                error_echo "部分组件未安装"
            fi
            ;;
        0)
            return
            ;;
        *)
            error_echo "无效选择"
            sleep 1
            ;;
    esac
    
    read -rp "按回车键返回主菜单..."
}

update_hysteria2() {
    info_echo "更新 Hysteria2..."
    
    # 检查当前版本
    local current_version
    current_version=$(/usr/local/bin/hysteria version 2>/dev/null | head -1 || echo "")
    
    # 获取最新版本
    local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    local latest_version
    latest_version=$(curl -s "$api_url" | jq -r '.tag_name')
    
    if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
        error_echo "无法获取最新版本信息"
        return 1
    fi
    
    info_echo "当前版本: $current_version"
    info_echo "最新版本: $latest_version"
    
    if [[ "$current_version" == *"$latest_version"* ]]; then
        success_echo "已是最新版本，无需更新"
        return 0
    fi
    
    # 停止服务
    systemctl stop hysteria-server
    
    # 备份当前版本
    cp /usr/local/bin/hysteria /usr/local/bin/hysteria.backup
    
    # 安装新版本
    if install_hysteria2; then
        # 重启服务
        systemctl start hysteria-server
        
        # 验证更新
        if systemctl is-active --quiet hysteria-server; then
            success_echo "Hysteria2 更新成功"
            rm -f /usr/local/bin/hysteria.backup
        else
            error_echo "更新后服务启动失败，正在回滚..."
            mv /usr/local/bin/hysteria.backup /usr/local/bin/hysteria
            systemctl start hysteria-server
        fi
    else
        error_echo "更新失败，正在回滚..."
        mv /usr/local/bin/hysteria.backup /usr/local/bin/hysteria
        systemctl start hysteria-server
    fi
}

update_cloudflared() {
    info_echo "更新 Cloudflared..."
    
    # 停止服务
    if systemctl is-active --quiet cloudflared; then
        systemctl stop cloudflared
        local need_restart=true
    else
        local need_restart=false
    fi
    
    # 使用包管理器更新
    case "$OS_TYPE" in
        ubuntu|debian)
            apt-get update -qq
            apt-get upgrade -y cloudflared
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &>/dev/null; then
                dnf upgrade -y cloudflared
            else
                yum update -y cloudflared
            fi
            ;;
    esac
    
    # 重启服务
    if $need_restart; then
        systemctl start cloudflared
    fi
    
    success_echo "Cloudflared 更新完成"
}

# --- 主安装流程 ---

run_install() {
    local mode="$1"
    
    info_echo "开始安装 Hysteria2 ($mode 模式)..."
    
    # 环境检查
    cleanup_previous_installation
    detect_system
    install_dependencies
    check_port_443
    detect_network
    
    # 重置 Cloudflared 路径
    CLOUDFLARED_PATH=""
    
    if [[ "$mode" == "direct" ]]; then
        # 直连模式安装
        get_user_input
        install_hysteria2
        generate_self_signed_cert
        
    else
        # Tunnel 模式安装
        echo -e "${YELLOW}═══════════════════ 重要提示 ═══════════════════${ENDCOLOR}"
        info_echo "Cloudflare Tunnel 模式说明:"
        echo "• 使用 Cloudflare 的全球网络代理流量"
        echo "• 支持被墙 IP 的服务器"
        echo "• 需要域名托管在 Cloudflare"
        echo "• 依赖 QUIC/HTTP3 协议"
        echo "• 首次连接可能需要等待 DNS 同步"
        echo -e "${YELLOW}═══════════════════════════════════════════════════${ENDCOLOR}"
        
        read -rp "理解上述说明并继续安装? (Y/n): " confirm
        if [[ "$confirm" == "n" ]]; then
            info_echo "安装已取消"
            return 0
        fi
        
        install_cloudflared
        get_user_input_with_cf
        install_hysteria2
        install_acme_and_cert
        setup_cloudflared_tunnel
    fi
    
    # 通用配置
    generate_hysteria_config
    create_systemd_services
    configure_firewall
    start_services
    
    # 保存信息
    save_install_info "$mode"
    save_client_info "$mode"
    
    # 显示结果
    show_installation_result "$mode"
}

# --- 配置信息显示优化 ---

show_config_info() {
    clear
    
    if [[ ! -f "${HY2_CONFIG_DIR}/client_info.txt" ]]; then
        error_echo "未找到配置信息，请先安装 Hysteria2"
        read -rp "按回车键返回主菜单..."
        return
    fi
    
    echo -e "${BG_PURPLE} 配置信息 ${ENDCOLOR}"
    echo
    
    # 显示客户端配置
    cat "${HY2_CONFIG_DIR}/client_info.txt"
    
    echo
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
    echo -e " ${CYAN}附加操作:${ENDCOLOR}"
    echo -e " ${CYAN}1.${ENDCOLOR} 重新生成密码      ${CYAN}2.${ENDCOLOR} 修改伪装网址"
    echo -e " ${CYAN}3.${ENDCOLOR} 导出配置到文件    ${CYAN}4.${ENDCOLOR} 生成二维码"
    echo -e " ${CYAN}0.${ENDCOLOR} 返回主菜单"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
    
    read -rp "请选择操作: " choice
    
    case $choice in
        1) regenerate_password ;;
        2) change_fake_url ;;
        3) export_config ;;
        4) generate_qr_code ;;
        0) return ;;
        *) error_echo "无效选择"; sleep 1 ;;
    esac
}

regenerate_password() {
    warning_echo "重新生成密码将断开所有现有连接"
    read -rp "确定继续? (y/N): " confirm
    if [[ "$confirm" != "y" ]]; then
        return
    fi
    
    # 生成新密码
    local new_password
    new_password=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-16)
    
    # 更新配置文件
    if [[ -f "${HY2_CONFIG_DIR}/config.yaml" ]]; then
        sed -i "s/password: .*/password: $new_password/" "${HY2_CONFIG_DIR}/config.yaml"
        
        # 重启服务
        systemctl restart hysteria-server
        
        # 更新安装信息
        if [[ -f "$INSTALL_INFO_FILE" ]]; then
            sed -i "s/HY_PASSWORD=.*/HY_PASSWORD=$new_password/" "$INSTALL_INFO_FILE"
        fi
        
        HY_PASSWORD="$new_password"
        
        # 重新生成客户端配置
        if [[ -f "$INSTALL_INFO_FILE" ]]; then
            source "$INSTALL_INFO_FILE"
            save_client_info "$MODE"
        fi
        
        success_echo "密码已更新: $new_password"
    else
        error_echo "配置文件不存在"
    fi
    
    read -rp "按回车键继续..."
}

change_fake_url() {
    read -rp "请输入新的伪装网址: " new_fake_url
    
    if [[ -z "$new_fake_url" ]]; then
        error_echo "伪装网址不能为空"
        return
    fi
    
    # 验证URL格式
    if [[ ! "$new_fake_url" =~ ^https?:// ]]; then
        new_fake_url="https://$new_fake_url"
        warning_echo "已自动添加 https:// 前缀"
    fi
    
    # 更新配置文件
    if [[ -f "${HY2_CONFIG_DIR}/config.yaml" ]]; then
        sed -i "s|url: .*|url: $new_fake_url|" "${HY2_CONFIG_DIR}/config.yaml"
        
        # 重启服务
        systemctl restart hysteria-server
        
        # 更新安装信息
        if [[ -f "$INSTALL_INFO_FILE" ]]; then
            sed -i "s|FAKE_URL=.*|FAKE_URL=$new_fake_url|" "$INSTALL_INFO_FILE"
        fi
        
        success_echo "伪装网址已更新: $new_fake_url"
    else
        error_echo "配置文件不存在"
    fi
    
    read -rp "按回车键继续..."
}

export_config() {
    local export_dir="/root/hysteria2_export_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$export_dir"
    
    # 导出配置文件
    if [[ -f "${HY2_CONFIG_DIR}/client_info.txt" ]]; then
        cp "${HY2_CONFIG_DIR}/client_info.txt" "$export_dir/"
    fi
    
    if [[ -f "$INSTALL_INFO_FILE" ]]; then
        cp "$INSTALL_INFO_FILE" "$export_dir/"
    fi
    
    if [[ -f "${HY2_CONFIG_DIR}/config.yaml" ]]; then
        cp "${HY2_CONFIG_DIR}/config.yaml" "$export_dir/server_config.yaml"
    fi
    
    # 创建导出说明
    cat > "$export_dir/README.txt" << EOF
Hysteria2 配置导出
导出时间: $(date)

文件说明:
- client_info.txt: 客户端配置信息
- install_info.env: 安装参数记录
- server_config.yaml: 服务端配置文件

注意: 请妥善保管这些配置文件，避免泄露密码信息。
EOF
    
    success_echo "配置已导出到: $export_dir"
    read -rp "按回车键继续..."
}

generate_qr_code() {
    if ! command -v qrencode &>/dev/null; then
        warning_echo "qrencode 未安装，正在安装..."
        case "$OS_TYPE" in
            ubuntu|debian) apt-get install -y qrencode ;;
            *) yum install -y qrencode ;;
        esac
    fi
    
    if [[ -f "${HY2_CONFIG_DIR}/client_info.txt" ]]; then
        local share_link
        share_link=$(grep "hysteria2://" "${HY2_CONFIG_DIR}/client_info.txt" | head -1)
        
        if [[ -n "$share_link" ]]; then
            echo
            info_echo "配置二维码:"
            qrencode -t UTF8 "$share_link"
            echo
            echo "分享链接: $share_link"
        else
            error_echo "未找到分享链接"
        fi
    else
        error_echo "配置文件不存在"
    fi
    
    read -rp "按回车键继续..."
}

# --- 主菜单逻辑优化 ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限运行"
        error_echo "请使用: sudo $0"
        exit 1
    fi
}

# 脚本参数处理
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                export DEBUG=true
                info_echo "调试模式已启用"
                ;;
            --version)
                echo "Hysteria2 安装脚本 v6.0"
                exit 0
                ;;
            --help)
                echo "Hysteria2 + Cloudflare Tunnel 安装脚本"
                echo
                echo "用法: $0 [选项]"
                echo
                echo "选项:"
                echo "  --debug     启用调试模式"
                echo "  --version   显示脚本版本"
                echo "  --help      显示此帮助信息"
                echo
                exit 0
                ;;
            *)
                error_echo "未知参数: $1"
                error_echo "使用 --help 查看帮助信息"
                exit 1
                ;;
        esac
        shift
    done
}

main_menu() {
    # 初始化
    check_root
    detect_network
    
    # 主循环
    while true; do
        exec < /dev/tty
        show_menu
        
        read -rp "请选择操作 [0-9]: " choice
        
        case $choice in
            1)
                info_echo "开始安装 Hysteria2 (直连模式)..."
                run_install "direct"
                ;;
            2)
                info_echo "开始安装 Hysteria2 + Cloudflare Tunnel..."
                run_install "tunnel"
                ;;
            3)
                uninstall_hysteria_only
                ;;
            4)
                uninstall_all
                ;;
            5)
                complete_cleanup
                ;;
            6)
                service_management
                ;;
            7)
                show_config_info
                ;;
            8)
                if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
                    test_connectivity
                    read -rp "按回车键返回主菜单..."
                else
                    error_echo "Hysteria2 服务未安装，请先安装"
                    sleep 2
                fi
                ;;
            9)
                update_components
                ;;
            0)
                info_echo "感谢使用 Hysteria2 安装脚本！"
                exit 0
                ;;
            *)
                error_echo "无效选择，请输入 0-9"
                sleep 1
                ;;
        esac
    done
}

# --- 脚本入口点 ---

# 捕获中断信号
trap 'echo -e "\n${YELLOW}脚本被中断${ENDCOLOR}"; exit 130' INT TERM

# 启动主菜单
main_menu "$@"
