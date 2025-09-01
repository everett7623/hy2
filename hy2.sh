#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 6.2 (重构版 - Hysteria2 全新实现)
# 描述: 此脚本用于在 IPv6-Only 或双栈服务器上快速安装和管理 Hysteria2 和 Shadowsocks 服务。
#       Hysteria2 支持自签名证书和 Cloudflare DNS API 申请的 ACME 证书两种模式。
#       Shadowsocks 仅监听 IPv6 地址。

# --- 脚本行为设置 ---
set -o pipefail

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BG_PURPLE='\033[45m'
ENDCOLOR='\033[0m'

# --- 全局变量 ---
OS_TYPE=""
ARCH=""
IPV4_ADDR=""
IPV6_ADDR=""
# Hysteria2 变量
HY_DOMAIN=""
CF_TOKEN=""
HY_PASSWORD=""
ACME_EMAIL=""
FAKE_URL="https://www.bing.com"
CF_ZONE_ID=""
CF_ACCOUNT_ID=""
# Shadowsocks 变量
SS_PORT=""
SS_PASSWORD=""
SS_METHOD="chacha20-ietf-poly1305"

################################################################################
# 辅助函数 & 系统检测
################################################################################

# --- 消息输出函数 ---
info_echo() { echo -e "${BLUE}[INFO]${ENDCOLOR} $1"; }
success_echo() { echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"; }
error_echo() { echo -e "${RED}[ERROR]${ENDCOLOR} $1" >&2; }
warning_echo() { echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"; }

# --- 通用系统检查函数 ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限运行，请尝试使用 'sudo bash $0'"
        exit 1
    fi
}

detect_system() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        OS_TYPE=$ID
    else
        error_echo "无法检测到操作系统类型。"
        exit 1
    fi

    case $(uname -m) in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) error_echo "不支持的 CPU 架构: $(uname -m)"; exit 1 ;;
    esac
    info_echo "检测到系统: $PRETTY_NAME ($ARCH)"
}

detect_network() {
    IPV4_ADDR=$(timeout 5 curl -4 -s https://api.ipify.org 2>/dev/null || echo "")
    IPV6_ADDR=$(timeout 5 curl -6 -s https://api64.ipify.org 2>/dev/null || echo "")
}

# --- 安装前检查 ---
pre_install_check() {
    local service_name="$1"
    local service_file=""
    case "$service_name" in
        hysteria) service_file="/etc/systemd/system/hysteria-server.service" ;;
        shadowsocks) service_file="/etc/systemd/system/shadowsocks-libev.service" ;;
        *) error_echo "未知的服务名称: $service_name"; return 1 ;;
    esac

    if [[ -f "$service_file" ]]; then
        warning_echo "检测到 ${service_name^} 已安装。"
        read -rp "确定要覆盖安装吗? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            info_echo "操作已取消。"
            return 1
        fi
        # 如果覆盖安装，先执行卸载
        case "$service_name" in
            hysteria) hy2_uninstall ;;
            shadowsocks) ss_uninstall ;;
        esac
    fi
    return 0
}

################################################################################
# Hysteria2 功能模块 (全新实现)
################################################################################

# --- 系统依赖安装 ---
hy2_install_system_deps() {
    info_echo "安装系统依赖包..."
    
    local base_packages=("curl" "wget" "openssl" "ca-certificates" "tar" "unzip")
    
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -y >/dev/null 2>&1
            apt-get install -y "${base_packages[@]}" jq socat >/dev/null 2>&1
            ;;
        "centos" | "rocky" | "almalinux")
            yum install -y epel-release >/dev/null 2>&1
            yum install -y "${base_packages[@]}" jq socat >/dev/null 2>&1
            ;;
        "fedora")
            dnf install -y "${base_packages[@]}" jq socat >/dev/null 2>&1
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE"
            return 1
            ;;
    esac
    
    if ! command -v openssl >/dev/null 2>&1; then
        error_echo "OpenSSL 安装失败"
        return 1
    fi
    
    success_echo "系统依赖安装完成"
    return 0
}

# --- Hysteria2 核心下载安装 ---
hy2_download_and_install() {
    info_echo "下载 Hysteria2 最新版本..."
    
    # 创建临时目录
    local tmp_dir="/tmp/hysteria2_install"
    rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
    cd "$tmp_dir" || return 1
    
    # 获取最新版本号
    local latest_version
    latest_version=$(timeout 10 curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name"' | cut -d '"' -f 4)
    
    if [[ -z "$latest_version" ]]; then
        error_echo "无法获取最新版本信息"
        return 1
    fi
    
    info_echo "最新版本: $latest_version"
    
    # 构建下载链接
    local download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
    
    info_echo "正在下载: $download_url"
    if ! timeout 60 wget -q --show-progress -O hysteria "$download_url"; then
        error_echo "下载失败"
        return 1
    fi
    
    # 验证文件
    if [[ ! -s hysteria ]] || ! file hysteria | grep -q "executable"; then
        error_echo "下载的文件无效"
        return 1
    fi
    
    # 安装到系统
    chmod +x hysteria
    mv hysteria /usr/local/bin/hysteria
    
    # 验证安装
    if ! /usr/local/bin/hysteria version >/dev/null 2>&1; then
        error_echo "Hysteria2 安装验证失败"
        return 1
    fi
    
    local version_info
    version_info=$(/usr/local/bin/hysteria version | head -n 1)
    success_echo "Hysteria2 安装成功: $version_info"
    
    # 清理
    cd / && rm -rf "$tmp_dir"
    return 0
}

# --- 自签名证书生成 ---
hy2_create_self_signed_cert() {
    info_echo "生成自签名 SSL 证书..."
    
    mkdir -p /etc/hysteria2/certs
    
    # 生成私钥和自签名证书
    if ! openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/hysteria2/certs/server.key \
        -out /etc/hysteria2/certs/server.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$HY_DOMAIN" >/dev/null 2>&1; then
        error_echo "证书生成失败"
        return 1
    fi
    
    success_echo "自签名证书生成成功"
    return 0
}

# --- ACME 证书申请 ---
hy2_setup_acme_cert() {
    info_echo "设置 ACME 证书申请..."
    
    # 安装 acme.sh
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        info_echo "安装 acme.sh..."
        curl -s https://get.acme.sh | sh -s email="$ACME_EMAIL" >/dev/null 2>&1
        if [[ ! -f ~/.acme.sh/acme.sh ]]; then
            error_echo "acme.sh 安装失败"
            return 1
        fi
    fi
    
    # 设置 Cloudflare API
    export CF_Token="$CF_TOKEN"
    export CF_Account_ID="$CF_ACCOUNT_ID" 
    export CF_Zone_ID="$CF_ZONE_ID"
    
    # 申请证书
    info_echo "申请 SSL 证书 (域名: $HY_DOMAIN)..."
    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$HY_DOMAIN" \
        --key-file /etc/hysteria2/certs/server.key \
        --fullchain-file /etc/hysteria2/certs/server.crt \
        --force --ecc >/dev/null 2>&1; then
        error_echo "证书申请失败"
        return 1
    fi
    
    success_echo "ACME 证书申请成功"
    return 0
}

# --- 生成配置文件 ---
hy2_create_config() {
    info_echo "生成 Hysteria2 配置文件..."
    
    mkdir -p /etc/hysteria2
    
    cat > /etc/hysteria2/server.yaml << EOF
listen: :443

tls:
  cert: /etc/hysteria2/certs/server.crt
  key: /etc/hysteria2/certs/server.key

auth:
  type: password
  password: ${HY_PASSWORD}

masquerade:
  type: proxy
  proxy:
    url: ${FAKE_URL}
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
EOF

    success_echo "配置文件创建完成"
    return 0
}

# --- 创建系统服务 ---
hy2_create_service() {
    info_echo "创建 systemd 服务..."
    
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
Documentation=https://hysteria.network/
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/server.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    # 配置防火墙
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 443/udp >/dev/null 2>&1
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    
    # 启动服务
    if ! systemctl enable --now hysteria-server; then
        error_echo "服务启动失败"
        return 1
    fi
    
    sleep 3
    
    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "服务运行异常"
        info_echo "错误日志："
        journalctl -u hysteria-server -n 10 --no-pager
        return 1
    fi
    
    success_echo "Hysteria2 服务创建并启动成功"
    return 0
}

# --- 用户输入处理 ---
hy2_get_input_self_signed() {
    echo
    echo -e "${CYAN}=== Hysteria2 自签名证书安装 ===${ENDCOLOR}"
    echo
    
    while [[ -z "$HY_DOMAIN" ]]; do
        read -rp "请输入 SNI 域名 (如: example.com): " HY_DOMAIN
        if [[ -z "$HY_DOMAIN" ]]; then
            warning_echo "域名不能为空"
        fi
    done
    
    read -rsp "请输入连接密码 (留空自动生成): " HY_PASSWORD
    echo
    
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 12)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    return 0
}

hy2_get_input_acme() {
    echo
    echo -e "${CYAN}=== Hysteria2 ACME 证书安装 ===${ENDCOLOR}"
    echo
    
    while [[ -z "$HY_DOMAIN" ]]; do
        read -rp "请输入已托管在 Cloudflare 的域名: " HY_DOMAIN
        if [[ -z "$HY_DOMAIN" ]]; then
            warning_echo "域名不能为空"
        fi
    done
    
    while [[ -z "$CF_TOKEN" ]]; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN
        echo
        if [[ -z "$CF_TOKEN" ]]; then
            warning_echo "API Token 不能为空"
            continue
        fi
        
        # 验证 Token
        info_echo "验证 API Token..."
        local zone_info
        zone_info=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones" \
            -H "Authorization: Bearer $CF_TOKEN" \
            -H "Content-Type: application/json")
        
        if echo "$zone_info" | grep -q '"success":true'; then
            CF_ZONE_ID=$(echo "$zone_info" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)
            CF_ACCOUNT_ID=$(echo "$zone_info" | grep -o '"account":{"id":"[^"]*' | cut -d'"' -f6)
            success_echo "Token 验证成功"
            break
        else
            error_echo "Token 验证失败，请重新输入"
            CF_TOKEN=""
        fi
    done
    
    read -rsp "请输入连接密码 (留空自动生成): " HY_PASSWORD
    echo
    
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 12)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    ACME_EMAIL="admin@$(echo "$HY_DOMAIN" | cut -d. -f2-)"
    read -rp "ACME 邮箱 (默认: $ACME_EMAIL): " input_email
    ACME_EMAIL="${input_email:-$ACME_EMAIL}"
    
    return 0
}

# --- 显示安装结果 ---
hy2_show_result() {
    local cert_type="$1"
    clear
    
    echo -e "${BG_PURPLE} Hysteria2 安装完成！ ${ENDCOLOR}"
    echo
    
    if [[ "$cert_type" == "self-signed" ]]; then
        echo -e "${YELLOW}注意: 使用自签名证书，客户端需要启用 '允许不安全连接' 选项${ENDCOLOR}"
        echo
    fi
    
    echo -e "${PURPLE}=== 连接信息 ===${ENDCOLOR}"
    echo -e "服务器地址: ${GREEN}${IPV4_ADDR:-$IPV6_ADDR}${ENDCOLOR}"
    echo -e "服务器端口: ${GREEN}443${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    
    if [[ "$cert_type" == "self-signed" ]]; then
        echo -e "允许不安全: ${YELLOW}是${ENDCOLOR}"
    else
        echo -e "允许不安全: ${GREEN}否${ENDCOLOR}"
    fi
    
    echo -e "${PURPLE}===================${ENDCOLOR}"
    echo
    
    read -rp "按任意键继续..." -n1
}

# --- 安装主函数 ---
hy2_install_self_signed() {
    pre_install_check "hysteria" || return 1
    
    hy2_get_input_self_signed || return 1
    hy2_install_system_deps || return 1
    hy2_download_and_install || return 1
    hy2_create_self_signed_cert || return 1
    hy2_create_config || return 1
    hy2_create_service || return 1
    hy2_show_result "self-signed"
}

hy2_install_acme() {
    pre_install_check "hysteria" || return 1
    
    hy2_get_input_acme || return 1
    hy2_install_system_deps || return 1
    hy2_download_and_install || return 1
    hy2_setup_acme_cert || return 1
    hy2_create_config || return 1
    hy2_create_service || return 1
    hy2_show_result "acme"
}

# --- Hysteria2 卸载 ---
hy2_uninstall() {
    info_echo "正在卸载 Hysteria2..."
    
    # 停止并禁用服务
    systemctl disable --now hysteria-server >/dev/null 2>&1 || true
    
    # 删除文件
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria2
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    success_echo "Hysteria2 卸载完成"
}

################################################################################
# Shadowsocks (IPv6-Only) 功能模块
################################################################################
ss_check_ipv6() {
    info_echo "检测 IPv6 网络环境..."
    # 使用和全局变量不同的检测方式，确保获取到的是接口上的地址
    local IPV6_ADDR_LOCAL
    IPV6_ADDR_LOCAL=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary\|deprecated" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [[ -z "$IPV6_ADDR_LOCAL" ]]; then
        error_echo "未检测到有效的公网 IPv6 地址！Shadowsocks 安装需要 IPv6 支持。"
        return 1
    fi
    # 优先使用全局检测到的可访问地址
    IPV6_ADDR=${IPV6_ADDR:-$IPV6_ADDR_LOCAL}

    if ! timeout 5 ping6 -c 1 google.com >/dev/null 2>&1; then
        warning_echo "检测到 IPv6 地址 ($IPV6_ADDR)，但似乎无法连接外网。"
        read -rp "是否仍要继续安装？(y/N): " confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            error_echo "安装已取消。"
            return 1
        fi
    fi
    success_echo "IPv6 环境检查通过: $IPV6_ADDR"
}

ss_install_dependencies() {
    info_echo "安装 Shadowsocks 依赖包 (shadowsocks-libev, qrencode)..."
    case "$OS_TYPE" in
        "ubuntu"|"debian")
            apt-get update -qq >/dev/null 2>&1 && apt-get install -y shadowsocks-libev qrencode curl >/dev/null 2>&1
            ;;
        "centos" | "rocky" | "almalinux")
            yum install -y epel-release >/dev/null 2>&1 && yum install -y shadowsocks-libev qrencode curl >/dev/null 2>&1
            ;;
        "fedora")
            dnf install -y shadowsocks-libev qrencode curl >/dev/null 2>&1
            ;;
        *) error_echo "不支持的操作系统: $OS_TYPE"; return 1;;
    esac
    success_echo "依赖包安装完成"
}

ss_generate_config() {
    info_echo "生成 Shadowsocks 配置文件..."
    SS_PORT=$(shuf -i 20000-40000 -n 1)
    SS_PASSWORD=$(openssl rand -base64 16)

    mkdir -p /etc/shadowsocks-libev
    cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "::",
    "server_port": $SS_PORT,
    "password": "$SS_PASSWORD",
    "timeout": 300,
    "method": "$SS_METHOD",
    "mode": "tcp_and_udp",
    "fast_open": true
}
EOF
    success_echo "配置文件生成成功: /etc/shadowsocks-libev/config.json"
}

ss_setup_service() {
    info_echo "创建并启动 Shadowsocks systemd 服务..."
    
    # 创建自定义服务文件（避免依赖包管理器的默认配置）
    cat > /etc/systemd/system/shadowsocks-libev.service << 'EOF'
[Unit]
Description=Shadowsocks-Libev Custom Server Service
Documentation=man:ss-server(1)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/config.json -u
Restart=on-abort
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable shadowsocks-libev >/dev/null 2>&1
    systemctl restart shadowsocks-libev
    sleep 2
    
    if ! systemctl is-active --quiet shadowsocks-libev; then
        error_echo "Shadowsocks 服务启动失败！"
        journalctl -u shadowsocks-libev -n 10 --no-pager
        return 1
    fi

    # 配置防火墙
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then 
        ufw allow "$SS_PORT" >/dev/null 2>&1
    fi
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then 
        firewall-cmd --permanent --add-port="$SS_PORT"/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$SS_PORT"/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi

    success_echo "Shadowsocks 服务已成功启动"
}

ss_display_result() {
    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
    local tag="${country_code}-IPv6-$(date +%m%d)"
    local encoded
    encoded=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)
    local ss_link="ss://${encoded}@[${IPV6_ADDR}]:${SS_PORT}#${tag}"

    clear
    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 安装完成！ ${ENDCOLOR}"
    echo
    echo -e " ${PURPLE}--- Shadowsocks 配置信息 ---${ENDCOLOR}"
    echo -e "   服务器地址: ${GREEN}[$IPV6_ADDR]${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}$SS_PORT${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$SS_PASSWORD${ENDCOLOR}"
    echo -e "   加密方式:   ${GREEN}$SS_METHOD${ENDCOLOR}"
    echo -e "   SS 链接:    ${CYAN}$ss_link${ENDCOLOR}"
    echo -e " ${PURPLE}----------------------------${ENDCOLOR}"
    echo
    
    if command -v qrencode >/dev/null 2>&1; then
        info_echo "二维码 (请最大化终端窗口显示):"
        qrencode -t ANSIUTF8 "$ss_link" 2>/dev/null || echo "二维码生成失败"
    else
        warning_echo "qrencode 未安装，无法显示二维码"
    fi
    
    echo
    read -rp "按任意键继续..." -n1
}

ss_run_install() {
    pre_install_check "shadowsocks" || return
    ss_check_ipv6 && \
    ss_install_dependencies && \
    ss_generate_config && \
    ss_setup_service && \
    ss_display_result || {
        error_echo "Shadowsocks 安装失败。"
        return 1
    }
}

ss_uninstall() {
    info_echo "正在卸载 Shadowsocks..."
    systemctl disable --now shadowsocks-libev >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/shadowsocks-libev.service
    rm -f /etc/shadowsocks-libev/config.json
    systemctl daemon-reload
    success_echo "Shadowsocks 已卸载完成。"
}

################################################################################
# UI 与管理功能
################################################################################

show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-未检测到}"
    local ipv6_display="${IPV6_ADDR:-未检测到}"

    local hy2_status="未安装"
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hy2_status="${GREEN}运行中${ENDCOLOR}"
    elif [[ -f /etc/systemd/system/hysteria-server.service ]]; then
        hy2_status="${RED}已停止${ENDCOLOR}"
    fi

    local ss_status="未安装"
    if systemctl is-active --quiet shadowsocks-libev 2>/dev/null; then
        ss_status="${GREEN}运行中${ENDCOLOR}"
    elif [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        ss_status="${RED}已停止${ENDCOLOR}"
    fi

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v6.2) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}安装选项:${ENDCOLOR}"
    echo -e "   1. 安装 Hysteria2 (${GREEN}自签名证书模式，无需域名解析${ENDCOLOR})"
    echo -e "   2. 安装 Hysteria2 (${YELLOW}ACME 证书模式，需域名 & Cloudflare API${ENDCOLOR})"
    echo -e "   3. 安装 Shadowsocks (仅 IPv6)"
    echo
    echo -e " ${CYAN}管理与维护:${ENDCOLOR}"
    echo -e "   4. 服务管理 (启动/停止/日志)"
    echo -e "   5. 显示配置信息"
    echo -e "   6. 卸载服务"
    echo -e "   7. 备份配置"
    echo -e "   8. 系统诊断"
    echo
    echo -e " ${CYAN}0. 退出脚本${ENDCOLOR}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
}

manage_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}"
        echo " 1. 管理 Hysteria2"
        echo " 2. 管理 Shadowsocks(IPv6)"
        echo " 0. 返回主菜单"
        echo "----------------"
        read -rp "请选择要管理的服务: " service_choice
        case $service_choice in
            1)
                if [[ ! -f /etc/systemd/system/hysteria-server.service ]]; then
                    error_echo "Hysteria2 未安装"; sleep 1.5; continue
                fi
                manage_single_service "hysteria-server" "Hysteria2"
                ;;
            2)
                if [[ ! -f /etc/systemd/system/shadowsocks-libev.service ]]; then
                    error_echo "Shadowsocks 未安装"; sleep 1.5; continue
                fi
                manage_single_service "shadowsocks-libev" "Shadowsocks"
                ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

manage_single_service() {
    local service_name="$1"
    local display_name="$2"
    while true; do
        clear
        echo "正在管理服务: $display_name"
        echo "--------------------------"
        systemctl status "$service_name" -n 5 --no-pager
        echo "--------------------------"
        echo " 1. 启动服务"
        echo " 2. 停止服务"
        echo " 3. 重启服务"
        echo " 4. 查看日志"
        echo " 5. 查看配置"
        echo " 0. 返回上级菜单"
        echo "----------------"
        read -rp "请选择操作: " action
        case $action in
            1) systemctl start "$service_name" && success_echo "服务启动成功" || error_echo "服务启动失败"; sleep 1.5 ;;
            2) systemctl stop "$service_name" && success_echo "服务停止成功" || error_echo "服务停止失败"; sleep 1.5 ;;
            3) systemctl restart "$service_name" && success_echo "服务重启成功" || error_echo "服务重启失败"; sleep 1.5 ;;
            4) 
                clear
                echo "=== $display_name 服务日志 (最近20行) ==="
                journalctl -u "$service_name" -n 20 --no-pager
                read -rp "按任意键继续..." -n1
                ;;
            5)
                clear
                echo "=== $display_name 配置文件 ==="
                case "$service_name" in
                    hysteria-server)
                        if [[ -f /etc/hysteria2/server.yaml ]]; then
                            cat /etc/hysteria2/server.yaml
                        else
                            error_echo "配置文件不存在"
                        fi
                        ;;
                    shadowsocks-libev)
                        if [[ -f /etc/shadowsocks-libev/config.json ]]; then
                            cat /etc/shadowsocks-libev/config.json
                        else
                            error_echo "配置文件不存在"
                        fi
                        ;;
                esac
                read -rp "按任意键继续..." -n1
                ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

show_config_info() {
    while true; do
        clear
        echo -e "${CYAN}=== 显示配置信息 ===${ENDCOLOR}"
        echo " 1. 显示 Hysteria2 连接信息"
        echo " 2. 显示 Shadowsocks 连接信息"
        echo " 0. 返回主菜单"
        echo "----------------"
        read -rp "请选择: " config_choice
        case $config_choice in
            1)
                if [[ ! -f /etc/hysteria2/server.yaml ]]; then
                    error_echo "Hysteria2 未安装"; sleep 1.5; continue
                fi
                show_hysteria2_config
                ;;
            2)
                if [[ ! -f /etc/shadowsocks-libev/config.json ]]; then
                    error_echo "Shadowsocks 未安装"; sleep 1.5; continue
                fi
                show_shadowsocks_config
                ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

show_hysteria2_config() {
    clear
    if [[ ! -f /etc/hysteria2/server.yaml ]]; then
        error_echo "Hysteria2 配置文件不存在"
        return
    fi

    # 从配置文件中提取信息
    local password
    local domain
    password=$(grep "password:" /etc/hysteria2/server.yaml | awk '{print $2}')
    
    # 尝试从证书中获取域名
    if [[ -f /etc/hysteria2/certs/server.crt ]]; then
        domain=$(openssl x509 -in /etc/hysteria2/certs/server.crt -noout -subject | grep -o "CN=[^,]*" | cut -d= -f2)
    fi

    echo -e "${BG_PURPLE} Hysteria2 连接信息 ${ENDCOLOR}"
    echo
    echo -e "${PURPLE}=== 连接信息 ===${ENDCOLOR}"
    echo -e "服务器地址: ${GREEN}${IPV4_ADDR:-$IPV6_ADDR}${ENDCOLOR}"
    echo -e "服务器端口: ${GREEN}443${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}${password}${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}${domain}${ENDCOLOR}"
    
    # 检查是否为自签名证书
    if openssl x509 -in /etc/hysteria2/certs/server.crt -noout -issuer | grep -q "CN=${domain}"; then
        echo -e "证书类型:   ${YELLOW}自签名证书${ENDCOLOR}"
        echo -e "允许不安全: ${YELLOW}是${ENDCOLOR}"
    else
        echo -e "证书类型:   ${GREEN}ACME证书${ENDCOLOR}"
        echo -e "允许不安全: ${GREEN}否${ENDCOLOR}"
    fi
    
    echo -e "${PURPLE}===================${ENDCOLOR}"
    echo
    read -rp "按任意键继续..." -n1
}

show_shadowsocks_config() {
    clear
    if [[ ! -f /etc/shadowsocks-libev/config.json ]]; then
        error_echo "Shadowsocks 配置文件不存在"
        return
    fi

    # 从配置文件中提取信息
    local server_port password method
    server_port=$(grep "server_port" /etc/shadowsocks-libev/config.json | grep -o "[0-9]*")
    password=$(grep "password" /etc/shadowsocks-libev/config.json | cut -d'"' -f4)
    method=$(grep "method" /etc/shadowsocks-libev/config.json | cut -d'"' -f4)

    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
    local tag="${country_code}-IPv6-$(date +%m%d)"
    local encoded
    encoded=$(echo -n "$method:$password" | base64 -w 0)
    local ss_link="ss://${encoded}@[${IPV6_ADDR}]:${server_port}#${tag}"

    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 连接信息 ${ENDCOLOR}"
    echo
    echo -e " ${PURPLE}--- Shadowsocks 配置信息 ---${ENDCOLOR}"
    echo -e "   服务器地址: ${GREEN}[$IPV6_ADDR]${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}$server_port${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$password${ENDCOLOR}"
    echo -e "   加密方式:   ${GREEN}$method${ENDCOLOR}"
    echo -e "   SS 链接:    ${CYAN}$ss_link${ENDCOLOR}"
    echo -e " ${PURPLE}----------------------------${ENDCOLOR}"
    echo

    if command -v qrencode >/dev/null 2>&1; then
        info_echo "二维码 (请最大化终端窗口显示):"
        qrencode -t ANSIUTF8 "$ss_link" 2>/dev/null || echo "二维码生成失败"
    else
        warning_echo "qrencode 未安装，无法显示二维码"
    fi
    
    echo
    read -rp "按任意键继续..." -n1
}

uninstall_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 卸载服务 ===${ENDCOLOR}"
        echo " 1. 卸载 Hysteria2"
        echo " 2. 卸载 Shadowsocks"
        echo " 3. 卸载所有服务"
        echo " 0. 返回主菜单"
        echo "----------------"
        read -rp "请选择要卸载的服务: " uninstall_choice
        case $uninstall_choice in
            1)
                if [[ ! -f /etc/systemd/system/hysteria-server.service ]]; then
                    error_echo "Hysteria2 未安装"; sleep 1.5; continue
                fi
                read -rp "确定要卸载 Hysteria2 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall
                    read -rp "按任意键继续..." -n1
                fi
                ;;
            2)
                if [[ ! -f /etc/systemd/system/shadowsocks-libev.service ]]; then
                    error_echo "Shadowsocks 未安装"; sleep 1.5; continue
                fi
                read -rp "确定要卸载 Shadowsocks 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    ss_uninstall
                    read -rp "按任意键继续..." -n1
                fi
                ;;
            3)
                read -rp "确定要卸载所有服务吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall
                    ss_uninstall
                    success_echo "所有服务已卸载完成"
                    read -rp "按任意键继续..." -n1
                fi
                ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

backup_configs() {
    clear
    local backup_dir="/root/proxy_backup_$(date +%Y%m%d_%H%M%S)"
    
    info_echo "创建配置备份..."
    mkdir -p "$backup_dir"
    
    # 备份 Hysteria2 配置
    if [[ -d /etc/hysteria2 ]]; then
        cp -r /etc/hysteria2 "$backup_dir/"
        success_echo "Hysteria2 配置已备份"
    fi
    
    # 备份 Shadowsocks 配置
    if [[ -f /etc/shadowsocks-libev/config.json ]]; then
        mkdir -p "$backup_dir/shadowsocks-libev"
        cp /etc/shadowsocks-libev/config.json "$backup_dir/shadowsocks-libev/"
        success_echo "Shadowsocks 配置已备份"
    fi
    
    # 备份服务文件
    if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
        cp /etc/systemd/system/hysteria-server.service "$backup_dir/"
    fi
    if [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        cp /etc/systemd/system/shadowsocks-libev.service "$backup_dir/"
    fi
    
    success_echo "备份完成! 备份位置: $backup_dir"
    read -rp "按任意键继续..." -n1
}

system_diagnosis() {
    clear
    echo -e "${CYAN}=== 系统诊断 ===${ENDCOLOR}"
    echo
    
    info_echo "检查系统信息..."
    echo "操作系统: $OS_TYPE ($ARCH)"
    echo "IPv4 地址: ${IPV4_ADDR:-未检测到}"
    echo "IPv6 地址: ${IPV6_ADDR:-未检测到}"
    echo
    
    info_echo "检查端口占用..."
    if command -v netstat >/dev/null 2>&1; then
        echo "监听端口 443 (UDP): $(netstat -ulnp | grep :443 || echo '未占用')"
        if [[ -f /etc/shadowsocks-libev/config.json ]]; then
            local ss_port
            ss_port=$(grep "server_port" /etc/shadowsocks-libev/config.json | grep -o "[0-9]*")
            echo "监听端口 $ss_port: $(netstat -lnp | grep :$ss_port || echo '未占用')"
        fi
    else
        warning_echo "netstat 未安装，无法检查端口占用"
    fi
    echo
    
    info_echo "检查防火墙状态..."
    if command -v ufw >/dev/null 2>&1; then
        ufw status
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --state
    else
        echo "未检测到防火墙"
    fi
    echo
    
    info_echo "检查服务状态..."
    if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
        echo "Hysteria2: $(systemctl is-active hysteria-server)"
    fi
    if [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        echo "Shadowsocks: $(systemctl is-active shadowsocks-libev)"
    fi
    
    echo
    read -rp "按任意键继续..." -n1
}

################################################################################
# 主程序入口
################################################################################

main() {
    # 检查 root 权限
    check_root
    
    # 系统检测
    detect_system
    detect_network
    
    # 主菜单循环
    while true; do
        show_menu
        read -rp "请选择操作 [0-8]: " choice
        case $choice in
            1) hy2_install_self_signed ;;
            2) hy2_install_acme ;;
            3) ss_run_install ;;
            4) manage_services ;;
            5) show_config_info ;;
            6) uninstall_services ;;
            7) backup_configs ;;
            8) system_diagnosis ;;
            0) 
                echo
                success_echo "感谢使用脚本！"
                exit 0 
                ;;
            *)
                error_echo "无效的选择，请重试"
                sleep 1
                ;;
        esac
    done
}

# 脚本入口点
main "$@"
