#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 6.1 (修复版)
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
# Hysteria2 功能模块 (修复版)
################################################################################

# --- 修复的依赖安装函数 ---
hy2_install_dependencies() {
    info_echo "更新软件包索引并安装依赖..."
    
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            # 更新包索引
            apt-get update -y || { error_echo "更新软件包索引失败"; return 1; }
            
            # 安装必要依赖
            local packages=("curl" "wget" "jq" "socat" "openssl" "ca-certificates")
            for package in "${packages[@]}"; do
                info_echo "安装 $package..."
                if ! apt-get install -y "$package"; then
                    error_echo "安装 $package 失败"
                    return 1
                fi
            done
            ;;
        "centos" | "rocky" | "almalinux")
            # 安装 EPEL 仓库
            if ! rpm -q epel-release >/dev/null 2>&1; then
                yum install -y epel-release || { error_echo "安装 EPEL 仓库失败"; return 1; }
            fi
            
            # 安装依赖包
            local packages=("curl" "wget" "jq" "socat" "openssl" "ca-certificates")
            for package in "${packages[@]}"; do
                info_echo "安装 $package..."
                if ! yum install -y "$package"; then
                    error_echo "安装 $package 失败"
                    return 1
                fi
            done
            ;;
        "fedora")
            local packages=("curl" "wget" "jq" "socat" "openssl" "ca-certificates")
            for package in "${packages[@]}"; do
                info_echo "安装 $package..."
                if ! dnf install -y "$package"; then
                    error_echo "安装 $package 失败"
                    return 1
                fi
            done
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE"
            return 1
            ;;
    esac
    
    success_echo "依赖包安装完成"
    return 0
}

# --- 修复的核心安装函数 ---
hy2_install_core() {
    info_echo "正在下载并安装 Hysteria2 核心..."
    
    # 获取最新版本信息
    local latest_release
    latest_release=$(timeout 10 curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" 2>/dev/null)
    
    if [[ -z "$latest_release" ]]; then
        error_echo "无法获取 Hysteria2 版本信息，请检查网络连接"
        return 1
    fi
    
    # 提取下载链接
    local download_url
    download_url=$(echo "$latest_release" | jq -r ".assets[] | select(.name == \"hysteria-linux-$ARCH\") | .browser_download_url" 2>/dev/null)

    if [[ -z "$download_url" || "$download_url" == "null" ]]; then
        error_echo "从 GitHub API 获取 Hysteria2 下载链接失败！架构: $ARCH"
        info_echo "尝试使用备用下载方式..."
        
        # 备用下载方式 - 直接构造下载链接
        local version
        version=$(echo "$latest_release" | jq -r '.tag_name' 2>/dev/null)
        if [[ -n "$version" && "$version" != "null" ]]; then
            download_url="https://github.com/apernet/hysteria/releases/download/${version}/hysteria-linux-${ARCH}"
            info_echo "使用备用下载链接: $download_url"
        else
            error_echo "无法确定版本号"
            return 1
        fi
    fi

    # 下载文件
    info_echo "正在下载 Hysteria2 核心文件..."
    if ! timeout 60 wget -q --show-progress -O /tmp/hysteria "$download_url"; then
        error_echo "下载 Hysteria2 失败，请检查网络连接"
        return 1
    fi

    # 验证下载的文件
    if [[ ! -s /tmp/hysteria ]]; then
        error_echo "下载的文件为空或不存在"
        return 1
    fi

    # 安装文件
    chmod +x /tmp/hysteria
    mv /tmp/hysteria /usr/local/bin/hysteria

    # 验证安装
    if ! /usr/local/bin/hysteria version >/dev/null 2>&1; then
        error_echo "Hysteria2 安装失败，可能是架构不兼容或文件损坏"
        rm -f /usr/local/bin/hysteria
        return 1
    fi

    local version
    version=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1)
    success_echo "Hysteria2 核心安装完成, 版本: $version"
    return 0
}

# --- Hysteria2 证书处理 ---
hy2_generate_self_signed_cert() {
    info_echo "正在生成自签名证书..."
    mkdir -p /etc/hysteria2/certs
    
    if ! openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/hysteria2/certs/private.key \
        -out /etc/hysteria2/certs/fullchain.cer \
        -subj "/CN=$HY_DOMAIN" >/dev/null 2>&1; then
        error_echo "生成自签名证书失败"
        return 1
    fi
    
    success_echo "自签名证书创建成功，用于 SNI: $HY_DOMAIN"
    return 0
}

hy2_install_acme_and_cert() {
    info_echo "正在安装 ACME.sh 并申请 SSL 证书..."
    
    # 安装 acme.sh
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then
        info_echo "正在安装 ACME.sh..."
        if ! curl -s https://get.acme.sh | sh -s email="$ACME_EMAIL"; then
            error_echo "ACME.sh 安装失败"
            return 1
        fi
        # 重新加载环境变量
        source ~/.bashrc
    fi

    # 设置 Cloudflare API 变量
    export CF_Token="$CF_TOKEN"
    export CF_Account_ID="$CF_ACCOUNT_ID"
    export CF_Zone_ID="$CF_ZONE_ID"

    info_echo "正在通过 Cloudflare DNS API 申请证书，此过程可能需要1-2分钟..."
    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$HY_DOMAIN" --server letsencrypt --force --ecc; then
        error_echo "SSL 证书申请失败！请检查域名、API Token 或网络连接。"
        return 1
    fi

    mkdir -p /etc/hysteria2/certs
    if ! ~/.acme.sh/acme.sh --install-cert -d "$HY_DOMAIN" --ecc \
        --fullchain-file /etc/hysteria2/certs/fullchain.cer \
        --key-file /etc/hysteria2/certs/private.key; then
        error_echo "证书安装步骤失败！"
        return 1
    fi
    
    success_echo "SSL 证书申请并安装完成"
    return 0
}

# --- Hysteria2 配置与服务 ---
hy2_generate_config() {
    info_echo "正在生成 Hysteria2 配置文件..."
    mkdir -p /etc/hysteria2
    
    # 同时监听 IPv4 和 IPv6 的所有地址
    local listen_addr="[::]:443"
    
    cat > /etc/hysteria2/config.yaml << EOF
listen: $listen_addr
tls:
  cert: /etc/hysteria2/certs/fullchain.cer
  key: /etc/hysteria2/certs/private.key
auth:
  type: password
  password: "$HY_PASSWORD"
masquerade:
  type: proxy
  proxy:
    url: $FAKE_URL
    rewriteHost: true
EOF
    
    success_echo "Hysteria2 配置文件生成于 /etc/hysteria2/config.yaml"
    return 0
}

hy2_setup_service() {
    info_echo "正在创建并启动 Hysteria2 systemd 服务..."
    
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载 systemd
    systemctl daemon-reload
    
    # 开放防火墙端口
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then 
        ufw allow 443/udp >/dev/null 2>&1
    fi
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then 
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 
        firewall-cmd --reload >/dev/null 2>&1
    fi

    # 启用并启动服务
    if ! systemctl enable hysteria-server; then
        error_echo "启用 Hysteria2 服务失败"
        return 1
    fi
    
    if ! systemctl start hysteria-server; then
        error_echo "启动 Hysteria2 服务失败"
        return 1
    fi
    
    # 等待服务启动
    sleep 3
    
    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "Hysteria2 服务启动失败！请检查日志。"
        info_echo "服务状态："
        systemctl status hysteria-server --no-pager -l
        info_echo "最近日志："
        journalctl -u hysteria-server -n 10 --no-pager
        return 1
    fi
    
    success_echo "Hysteria2 服务已成功启动并设为开机自启"
    return 0
}

# --- Hysteria2 用户输入与结果显示 ---
hy2_get_user_input_self_signed() {
    while true; do
        read -rp "请输入用于 SNI 的域名 (无需解析, e.g., wechat.com): " HY_DOMAIN
        if [[ -n "$HY_DOMAIN" ]]; then
            break
        fi
        error_echo "SNI 域名不能为空"
    done

    read -rsp "请输入 Hysteria 密码 (留空将自动生成): " HY_PASSWORD
    echo
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    return 0
}

hy2_get_user_input_acme() {
    while true; do
        read -rp "请输入您的域名 (必须已托管在 Cloudflare): " HY_DOMAIN
        if [[ -n "$HY_DOMAIN" ]]; then
            break
        fi
        error_echo "域名不能为空"
    done

    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN
        echo
        if [[ -z "$CF_TOKEN" ]]; then 
            warning_echo "Token 不能为空"
            continue
        fi

        local root_domain
        root_domain=$(echo "$HY_DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
        info_echo "正在验证 Cloudflare API Token..."
        
        local api_result
        api_result=$(timeout 10 curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" \
            -H "Authorization: Bearer $CF_TOKEN" \
            -H "Content-Type: application/json" 2>/dev/null)

        if [[ -n "$api_result" ]] && echo "$api_result" | jq -e '.success == true and (.result | length) > 0' > /dev/null 2>&1; then
            CF_ZONE_ID=$(echo "$api_result" | jq -r '.result[0].id')
            CF_ACCOUNT_ID=$(echo "$api_result" | jq -r '.result[0].account.id')
            success_echo "Token 验证成功！Zone ID: $CF_ZONE_ID"
            break
        else
            error_echo "Token 验证失败或权限不足！请检查 Token 是否拥有对 '$root_domain' 的 'Zone:Read' 和 'DNS:Edit' 权限。"
        fi
    done

    read -rsp "请输入 Hysteria 密码 (留空将自动生成): " HY_PASSWORD
    echo
    if [[ -z "$HY_PASSWORD" ]]; then 
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi

    ACME_EMAIL="user$(shuf -i 1000-9999 -n 1)@gmail.com"
    read -rp "请输入用于 ACME 证书的邮箱 (回车默认: ${ACME_EMAIL}): " input_email
    ACME_EMAIL=${input_email:-$ACME_EMAIL}
    return 0
}

hy2_display_result() {
    clear
    local mode="$1"
    local server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    local insecure="false"
    local server_display_addr="$HY_DOMAIN"

    if [[ "$mode" == "self-signed" ]]; then
        success_echo "Hysteria2 (自签名模式) 安装完成！"
        insecure="true (客户端必须勾选)"
        server_display_addr="$server_addr"
    else
        success_echo "Hysteria2 (ACME 模式) 安装完成！"
        info_echo "请确保您的域名 ($HY_DOMAIN) 已正确解析到此服务器的 IP: ${IPV4_ADDR:-$IPV6_ADDR}"
    fi

    echo
    echo -e " ${PURPLE}--- Hysteria2 配置信息 ---${ENDCOLOR}"
    echo -e "   服务器地址: ${GREEN}$server_display_addr${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}443${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "   SNI:        ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "   允许不安全: ${YELLOW}$insecure${ENDCOLOR}"
    echo -e " ${PURPLE}--------------------------${ENDCOLOR}"
    echo
}

# --- Hysteria2 卸载 ---
hy2_uninstall() {
    info_echo "正在卸载 Hysteria2..."
    
    # 停止并禁用服务
    systemctl disable --now hysteria-server >/dev/null 2>&1 || true

    # 如果存在证书，并且acme.sh存在，则尝试吊销
    if [[ -f /etc/hysteria2/certs/fullchain.cer ]] && command -v ~/.acme.sh/acme.sh &> /dev/null; then
        local domain_in_cert
        domain_in_cert=$(openssl x509 -in /etc/hysteria2/certs/fullchain.cer -noout -subject 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p')
        if [[ -n "$domain_in_cert" ]]; then
             info_echo "正在尝试移除 $domain_in_cert 的 ACME 证书..."
             ~/.acme.sh/acme.sh --remove -d "$domain_in_cert" --ecc >/dev/null 2>&1 || true
        fi
    fi

    # 删除文件
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria2
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    success_echo "Hysteria2 卸载完成。"
}

# --- Hysteria2 安装主流程 (修复版) ---
hy2_run_install() {
    local mode="$1" # "self-signed" or "acme"

    # 检查网络连接
    if ! timeout 5 curl -s https://www.google.com >/dev/null 2>&1; then
        warning_echo "网络连接可能存在问题，但继续尝试安装..."
    fi

    # 通用前置步骤
    if ! hy2_install_dependencies; then
        error_echo "依赖安装失败，终止安装。"
        return 1
    fi

    # 根据模式执行特定步骤
    if [[ "$mode" == "self-signed" ]]; then
        if ! hy2_get_user_input_self_signed; then
            return 1
        fi
    elif [[ "$mode" == "acme" ]]; then
        if ! hy2_get_user_input_acme; then
            return 1
        fi
    else
        error_echo "未知的安装模式: $mode"
        return 1
    fi

    # 通用核心安装步骤
    if ! hy2_install_core; then
        error_echo "Hysteria2 核心安装失败，终止安装。"
        return 1
    fi

    # 根据模式生成证书
    if [[ "$mode" == "self-signed" ]]; then
        if ! hy2_generate_self_signed_cert; then
            return 1
        fi
    else
        if ! hy2_install_acme_and_cert; then
            return 1
        fi
    fi

    # 通用后续步骤
    hy2_generate_config
    if ! hy2_setup_service; then
        error_echo "服务启动失败，请检查上述日志。"
        return 1
    fi
    
    hy2_display_result "$mode"
    return 0
}

################################################################################
# Shadowsocks (IPv6-Only) 功能模块 (保持不变)
################################################################################
ss_check_ipv6() {
    info_echo "检测 IPv6 网络环境..."
    # 使用和全局变量不同的检测方式，确保获取到的是接口上的地址
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
            apt-get update -qq && apt-get install -y shadowsocks-libev qrencode curl
            ;;
        "centos" | "rocky" | "almalinux")
            yum install -y epel-release && yum install -y shadowsocks-libev qrencode curl
            ;;
        "fedora")
            dnf install -y shadowsocks-libev qrencode curl
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
    # shadowsocks-libev 的 service 文件通常由包管理器提供，我们只需重启
    systemctl enable shadowsocks-libev >/dev/null 2>&1
    systemctl restart shadowsocks-libev
    sleep 2
    if ! systemctl is-active --quiet shadowsocks-libev; then
        error_echo "Shadowsocks 服务启动失败！"
        journalctl -u shadowsocks-libev -n 10 --no-pager
        return 1
    fi

    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then ufw allow $SS_PORT >/dev/null; fi
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-port=$SS_PORT/tcp >/dev/null 2>&1 && firewall-cmd --permanent --add-port=$SS_PORT/udp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null; fi

    success_echo "Shadowsocks 服务已成功启动"
}

ss_display_result() {
    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code || echo "UN")
    local tag="${country_code}-IPv6-$(date +%m%d)"
    local encoded
    encoded=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)
    local ss_link="ss://${encoded}@[${IPV6_ADDR}]:${SS_PORT}#${tag}"

    clear
    success_echo "Shadowsocks (IPv6) 安装完成！"
    echo
    echo -e " ${PURPLE}--- Shadowsocks 配置信息 ---${ENDCOLOR}"
    echo -e "   服务器地址: ${GREEN}[$IPV6_ADDR]${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}$SS_PORT${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$SS_PASSWORD${ENDCOLOR}"
    echo -e "   加密方式:   ${GREEN}$SS_METHOD${ENDCOLOR}"
    echo -e "   SS 链接:    ${CYAN}$ss_link${ENDCOLOR}"
    echo -e " ${PURPLE}----------------------------${ENDCOLOR}"
    echo
    info_echo "二维码 (请最大化终端窗口显示):"
    qrencode -t ANSIUTF8 "$ss_link"
}

ss_run_install() {
    pre_install_check "shadowsocks" || return
    ss_check_ipv6 && \
    ss_install_dependencies && \
    ss_generate_config && \
    ss_setup_service && \
    ss_display_result || {
        error_echo "Shadowsocks 安装失败。"
    }
}

ss_uninstall() {
    info_echo "正在卸载 Shadowsocks..."
    systemctl disable --now shadowsocks-libev >/dev/null 2>&1 || true
    rm -f /etc/shadowsocks-libev/config.json
    # 不卸载 shadowsocks-libev 包本身，只移除配置
    success_echo "Shadowsocks 配置已移除。"
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

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v6.1) ${ENDCOLOR}"
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
    echo -e "   7. 备份配置 (开发中...)"
    echo -e "   8. 系统诊断 (开发中...)"
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
        echo " 4. 查看最近100条日志"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -rp "请输入操作 [0-4]: " op
        case $op in
            1) systemctl start "$service_name" && success_echo "$display_name 已启动" ;;
            2) systemctl stop "$service_name" && success_echo "$display_name 已停止" ;;
            3) systemctl restart "$service_name" && success_echo "$display_name 已重启" ;;
            4) clear; journalctl -u "$service_name" -n 100 --no-pager -f ;;
            0) return ;;
            *) error_echo "无效操作" ;;
        esac
        if [[ "$op" != "4" ]]; then sleep 1.5; fi
    done
}

show_config_info() {
    clear
    local hy_installed=false
    local ss_installed=false

    # 检查 Hysteria2
    if [[ -f /etc/hysteria2/config.yaml ]]; then
        hy_installed=true
        local hy_pass=$(grep 'password:' /etc/hysteria2/config.yaml | awk '{print $2}' | tr -d '"')
        local hy_sni=$(openssl x509 -in /etc/hysteria2/certs/fullchain.cer -noout -subject 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p')
        local server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
        echo -e "${BG_PURPLE} Hysteria2 配置信息 ${ENDCOLOR}"
        echo -e "  服务器地址: ${GREEN}${server_addr}${ENDCOLOR} 或 ${GREEN}${hy_sni}${ENDCOLOR}"
        echo -e "  端口:       ${GREEN}443${ENDCOLOR}"
        echo -e "  密码:       ${GREEN}${hy_pass}${ENDCOLOR}"
        echo -e "  SNI:        ${GREEN}${hy_sni}${ENDCOLOR}"
        echo
    fi

    # 检查 Shadowsocks
    if [[ -f /etc/shadowsocks-libev/config.json ]] && command -v jq &>/dev/null; then
        ss_installed=true
        local ss_config=$(cat /etc/shadowsocks-libev/config.json)
        local port=$(echo "$ss_config" | jq -r '.server_port')
        local password=$(echo "$ss_config" | jq -r '.password')
        local method=$(echo "$ss_config" | jq -r '.method')
        local ss_ipv6="${IPV6_ADDR:-$(ip -6 addr show scope global | grep inet6 | grep -v "temporary\|deprecated" | awk '{print $2}' | cut -d/ -f1 | head -n1)}"
        
        echo -e "${BG_PURPLE} Shadowsocks (IPv6) 配置信息 ${ENDCOLOR}"
        echo -e "  服务器地址: ${GREEN}[$ss_ipv6]${ENDCOLOR}"
        echo -e "  端口:       ${GREEN}$port${ENDCOLOR}"
        echo -e "  密码:       ${GREEN}$password${ENDCOLOR}"
        echo -e "  加密方式:   ${GREEN}$method${ENDCOLOR}"

        if [[ -n "$ss_ipv6" ]]; then
            local encoded=$(echo -n "$method:$password" | base64 -w 0)
            local ss_link="ss://${encoded}@[${ss_ipv6}]:${port}"
            echo -e "  SS 链接:    ${CYAN}$ss_link${ENDCOLOR}"
            if command -v qrencode &>/dev/null; then
                echo
                info_echo "二维码:"
                qrencode -t ANSIUTF8 "$ss_link"
            fi
        fi
        echo
    fi

    if ! $hy_installed && ! $ss_installed; then
        info_echo "未检测到任何已安装的服务配置。"
    fi
}

uninstall_services() {
    clear
    echo "请选择要卸载的服务:"
    echo " 1. 卸载 Hysteria2"
    echo " 2. 卸载 Shadowsocks (IPv6)"
    echo " 3. 卸载全部"
    echo " 0. 返回"
    echo "--------------------------"
    read -rp "请输入选项: " choice
    case $choice in
        1) hy2_uninstall ;;
        2) ss_uninstall ;;
        3)
            info_echo "将卸载所有服务..."
            hy2_uninstall
            ss_uninstall
            ;;
        0) return ;;
        *) error_echo "无效选择" ;;
    esac
}

################################################################################
# 主函数
################################################################################
main() {
    check_root
    detect_system

    while true; do
        # 每次循环都重新获取网络状态
        detect_network
        # 将 tty 重定向到标准输入，确保 read 命令在任何情况下都能正常工作
        exec < /dev/tty
        show_menu
        read -rp "请选择操作 [0-8]: " main_choice
        case $main_choice in
            1)
                if pre_install_check "hysteria"; then
                    hy2_run_install "self-signed"
                fi
                ;;
            2)
                if pre_install_check "hysteria"; then
                    hy2_run_install "acme"
                fi
                ;;
            3)
                ss_run_install
                ;;
            4)
                manage_services
                ;;
            5)
                show_config_info
                ;;
            6)
                uninstall_services
                ;;
            7|8)
                warning_echo "此功能正在开发中，敬请期待！"
                ;;
            0)
                info_echo "感谢使用! 脚本退出。"
                exit 0
                ;;
            *)
                error_echo "无效选择，请输入 0-8 之间的数字。"
                ;;
        esac
        # 除了退出和管理菜单，其他操作后都暂停等待用户确认
        if [[ "$main_choice" != "4" && "$main_choice" != "0" ]]; then
            echo
            read -rp "按 [Enter] 键返回主菜单..."
        fi
    done
}

# --- 脚本入口 ---
main
