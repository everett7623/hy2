#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 3.1 (修复优化版)

set -e -o pipefail

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
DOMAIN=""
HY_PASSWORD=""
ACME_EMAIL=""
FAKE_URL=""
USE_ACME=false
CF_TOKEN=""
# Shadowsocks 变量
SS_PORT=""
SS_PASSWORD=""
SS_METHOD=""

# --- 辅助函数 ---
info_echo() { echo -e "${BLUE}[INFO]${ENDCOLOR} $1"; }
success_echo() { echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"; }
error_echo() { echo -e "${RED}[ERROR]${ENDCOLOR} $1" >&2; }
warning_echo() { echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"; }

# --- 主菜单 ---
show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-未检测到}"
    local ipv6_display="${IPV6_ADDR:-未检测到}"
    
    # 检测 Hysteria2 服务状态
    local hy2_status="未安装"
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hy2_status="${GREEN}运行中${ENDCOLOR}"
    elif systemctl list-unit-files hysteria-server.service &>/dev/null; then
        hy2_status="${RED}已停止${ENDCOLOR}"
    fi

    # 检测 Shadowsocks 服务状态
    local ss_status="未安装"
    if systemctl is-active --quiet ss-ipv6 2>/dev/null; then
        ss_status="${GREEN}运行中${ENDCOLOR}"
    elif systemctl list-unit-files ss-ipv6.service &>/dev/null; then
        ss_status="${RED}已停止${ENDCOLOR}"
    fi

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v3.1) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}Hysteria2 安装选项:${ENDCOLOR}"
    echo -e "   1. 安装 Hysteria2 (自签名证书)"
    echo -e "   2. 安装 Hysteria2 (Let's Encrypt 证书)"
    echo
    echo -e " ${CYAN}Shadowsocks (IPv6-Only) 安装选项:${ENDCOLOR}"
    echo -e "   3. 安装 Shadowsocks (仅 IPv6)"
    echo
    echo -e " ${CYAN}管理与卸载:${ENDCOLOR}"
    echo -e "   4. 服务管理 (启动/停止/日志)"
    echo -e "   5. 显示配置信息"
    echo -e "   6. 卸载服务"
    echo
    echo -e " ${CYAN}0. 退出脚本${ENDCOLOR}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
}

# --- 通用系统检查函数 ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限运行"
        exit 1
    fi
}

detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_TYPE=$ID
    else
        error_echo "无法检测操作系统"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) error_echo "不支持的架构: $ARCH"; exit 1 ;;
    esac
    info_echo "检测到系统: $PRETTY_NAME ($ARCH)"
}

detect_network() {
    info_echo "检测网络配置..."
    local ipv4_svcs=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ip.sb")
    local ipv6_svcs=("https://api64.ipify.org" "https://ipv6.icanhazip.com" "https://ipv6.ip.sb")

    for svc in "${ipv4_svcs[@]}"; do
        IPV4_ADDR=$(curl -4 -s --connect-timeout 3 "$svc" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
        [[ -n "$IPV4_ADDR" ]] && break
    done

    for svc in "${ipv6_svcs[@]}"; do
        IPV6_ADDR=$(curl -6 -s --connect-timeout 3 "$svc" 2>/dev/null | grep -E '^[0-9a-fA-F:]+$' || true)
        [[ -n "$IPV6_ADDR" ]] && break
    done
    
    if [[ -z "$IPV4_ADDR" && -z "$IPV6_ADDR" ]]; then
        warning_echo "未能检测到任何公网IP地址，部分功能可能受限"
    fi
}

# 通用端口检查函数
check_port() {
    local port=$1
    local protocol=${2:-tcp}
    if [[ "$protocol" == "udp" ]]; then
        if ss -ulnp | grep -q ":$port\s"; then
            error_echo "$protocol $port 端口已被占用"
            ss -ulnp | grep ":$port\s"
            return 1
        fi
    else
        if ss -tlnp | grep -q ":$port\s"; then
            error_echo "$protocol $port 端口已被占用"
            ss -tlnp | grep ":$port\s"
            return 1
        fi
    fi
}

################################################################################
#
# Hysteria2 功能模块
#
################################################################################

hy2_install_dependencies() {
    info_echo "为 Hysteria2 安装依赖..."
    local pkgs_to_install=()
    local required_cmds=("curl" "wget" "jq" "openssl" "nslookup")
    
    case "$OS_TYPE" in
        "ubuntu"|"debian")
            local pkg_map=([curl]="curl" [wget]="wget" [jq]="jq" [openssl]="openssl" [nslookup]="dnsutils")
            ;;
        *)
            local pkg_map=([curl]="curl" [wget]="wget" [jq]="jq" [openssl]="openssl" [nslookup]="bind-utils")
            ;;
    esac

    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            pkgs_to_install+=("${pkg_map[$cmd]}")
        fi
    done

    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
        info_echo "需要安装: ${pkgs_to_install[*]}"
        case "$OS_TYPE" in
            "ubuntu"|"debian") 
                apt-get update -qq && apt-get install -y "${pkgs_to_install[@]}" 
                ;;
            *) 
                if command -v dnf &>/dev/null; then
                    dnf install -y "${pkgs_to_install[@]}"
                else
                    yum install -y "${pkgs_to_install[@]}"
                fi
                ;;
        esac || { error_echo "依赖安装失败"; return 1; }
    fi
}

hy2_get_user_input() {
    exec </dev/tty
    info_echo "开始配置 Hysteria2..."
    
    while true; do
        read -rp "请输入您的域名 (用于SNI): " DOMAIN
        if [[ -n "$DOMAIN" && "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            break
        else
            error_echo "域名格式不正确，请重新输入"
        fi
    done
    
    read -rsp "请输入 Hysteria2 密码 (回车自动生成): " HY_PASSWORD
    echo
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    read -rp "请输入伪装网址 (默认: https://www.bing.com): " FAKE_URL
    FAKE_URL=${FAKE_URL:-https://www.bing.com}
    
    if [[ "$USE_ACME" == true ]]; then
        read -rp "请输入 ACME 邮箱 (默认: user@example.com): " ACME_EMAIL
        ACME_EMAIL=${ACME_EMAIL:-user@example.com}
        
        while true; do
            read -rsp "请输入 Cloudflare API Token (用于 DNS 验证): " CF_TOKEN
            echo
            if [[ -z "$CF_TOKEN" ]]; then
                error_echo "Token 不能为空"
                continue
            fi
            
            info_echo "正在验证 Token..."
            local root_domain=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
            local api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" \
                -H "Authorization: Bearer $CF_TOKEN" \
                -H "Content-Type: application/json")
            
            if echo "$api_result" | jq -e '.success==true and .result[0].id' >/dev/null; then
                success_echo "Token 验证成功"
                break
            else
                error_echo "Token 验证失败！"
                echo "$api_result" | jq '.errors' 2>/dev/null || echo "请检查 Token 权限"
            fi
        done
    fi
}

hy2_install() {
    info_echo "安装 Hysteria2..."
    local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    local dl_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name==\"hysteria-linux-$ARCH\") | .browser_download_url")
    
    if [[ -z "$dl_url" || "$dl_url" == "null" ]]; then
        error_echo "无法获取 Hysteria2 ($ARCH) 下载链接"
        return 1
    fi
    
    wget -qO /usr/local/bin/hysteria "$dl_url" && chmod +x /usr/local/bin/hysteria
    
    # 验证安装
    if /usr/local/bin/hysteria version >/dev/null 2>&1; then
        local version=$(/usr/local/bin/hysteria version | head -n1)
        success_echo "Hysteria2 安装成功 ($version)"
    else
        error_echo "Hysteria2 安装验证失败"
        return 1
    fi
}

hy2_install_acme_cert() {
    info_echo "申请 Let's Encrypt 证书..."
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
    fi
    
    export CF_Token="$CF_TOKEN"
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --ecc
    
    mkdir -p /etc/hysteria2/certs
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
        --fullchain-file /etc/hysteria2/certs/fullchain.cer \
        --key-file /etc/hysteria2/certs/private.key
    
    chmod 600 /etc/hysteria2/certs/private.key
    success_echo "SSL 证书申请成功"
}

hy2_generate_self_signed_cert() {
    info_echo "生成 Hysteria2 自签名证书..."
    mkdir -p /etc/hysteria2/certs
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/hysteria2/certs/private.key \
        -out /etc/hysteria2/certs/fullchain.cer \
        -subj "/CN=$DOMAIN" >/dev/null 2>&1
    chmod 600 /etc/hysteria2/certs/private.key
    success_echo "自签名证书生成成功"
}

hy2_generate_config() {
    info_echo "生成 Hysteria2 配置文件..."
    mkdir -p /etc/hysteria2
    local listen_addr=$([[ -n "$IPV6_ADDR" ]] && echo "[::]:443" || echo "0.0.0.0:443")
    
    cat > /etc/hysteria2/config.yaml << EOF
listen: $listen_addr

tls:
  cert: /etc/hysteria2/certs/fullchain.cer
  key: /etc/hysteria2/certs/private.key

auth:
  type: password
  password: $HY_PASSWORD

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
  maxIdleTimeout: 60s
  keepAlivePeriod: 10s
EOF
}

hy2_create_service() {
    info_echo "创建 Hysteria2 systemd 服务..."
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

hy2_configure_firewall() {
    info_echo "为 Hysteria2 配置防火墙..."
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow 443/udp comment "Hysteria2" >/dev/null
        success_echo "UFW 防火墙已配置"
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null
        success_echo "Firewalld 防火墙已配置"
    else
        warning_echo "未检测到 UFW/Firewalld，请手动开放 UDP 443 端口"
    fi
}

hy2_start_service() {
    info_echo "启动 Hysteria2 服务..."
    systemctl enable --now hysteria-server
    
    # 等待服务启动
    for i in {1..10}; do
        if systemctl is-active --quiet hysteria-server && ss -ulnp | grep -q ":443.*hysteria"; then
            success_echo "Hysteria2 服务启动成功"
            return 0
        fi
        sleep 1
    done
    
    error_echo "Hysteria2 服务启动失败！"
    journalctl -u hysteria-server -n 10 --no-pager
    return 1
}

hy2_save_info() {
    local cert_type="$1"
    local server_addr=$([[ "$cert_type" == "acme" ]] && echo "$DOMAIN" || echo "${IPV4_ADDR:-$IPV6_ADDR}")
    local insecure=$([[ "$cert_type" == "self" ]] && echo "true" || echo "false")
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}&insecure=${insecure}#HY2-${cert_type^}"
    
    cat > /root/hysteria2_info.txt << EOF
# Hysteria2 客户端配置信息 (生成时间: $(date))
================================================================================

服务器地址: $server_addr
端口: 443
密码: $HY_PASSWORD
SNI: $DOMAIN
跳过证书验证: $insecure

分享链接 (V2RayN / NekoBox / V2rayNG):
$share_link

Clash Meta YAML 配置 (标准格式):
- name: 'HY2-${cert_type^}'
  type: hysteria2
  server: '$server_addr'
  port: 443
  up: '200 Mbps'
  down: '1000 Mbps'
  password: '$HY_PASSWORD'
  sni: '$DOMAIN'
  skip-cert-verify: $insecure

Clash Meta YAML 配置 (紧凑格式):
- { name: 'HY2-${cert_type^}', type: hysteria2, server: '$server_addr', port: 443, up: '200 Mbps', down: '1000 Mbps', password: '$HY_PASSWORD', sni: '$DOMAIN', skip-cert-verify: $insecure }

Sing-box JSON 配置:
{
  "type": "hysteria2",
  "tag": "HY2-${cert_type^}",
  "server": "$server_addr",
  "server_port": 443,
  "password": "$HY_PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "$DOMAIN",
    "insecure": $insecure
  }
}

================================================================================
EOF
    
    # 保存安装信息用于卸载
    cat > /etc/hysteria2/install_info.env << EOF
INSTALL_TIME=$(date)
CERT_TYPE=$cert_type
DOMAIN=$DOMAIN
HY_PASSWORD=$HY_PASSWORD
FAKE_URL=$FAKE_URL
SERVER_ADDR=$server_addr
EOF
}

hy2_run_install() {
    local cert_type="$1"
    
    if systemctl list-unit-files hysteria-server.service &>/dev/null; then
        warning_echo "检测到 Hysteria2 已安装，继续将覆盖现有配置"
        read -rp "确定要覆盖吗? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            return 0
        fi
        hy2_uninstall
    fi
    
    USE_ACME=$([[ "$cert_type" == "acme" ]] && echo true || echo false)
    
    # 检查端口
    check_port 443 udp || return 1
    
    # 执行安装流程
    hy2_install_dependencies && hy2_get_user_input && hy2_install || return 1
    
    if $USE_ACME; then 
        hy2_install_acme_cert
    else 
        hy2_generate_self_signed_cert
    fi
    
    hy2_generate_config && hy2_create_service && hy2_configure_firewall && hy2_start_service && hy2_save_info "$cert_type" || return 1
    
    clear
    success_echo "Hysteria2 安装完成！"
    cat /root/hysteria2_info.txt
    
    if [[ "$cert_type" == "self" ]]; then
        echo
        warning_echo "使用自签名证书，客户端需要开启 'skip-cert-verify: true'"
    fi
}

hy2_uninstall() {
    info_echo "开始卸载 Hysteria2..."
    systemctl disable --now hysteria-server 2>/dev/null || true
    rm -f /etc/systemd/system/hysteria-server.service
    systemctl daemon-reload
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria2
    rm -f /root/hysteria2_info.txt
    success_echo "Hysteria2 已卸载"
}

################################################################################
#
# Shadowsocks (IPv6-Only) 功能模块
#
################################################################################

ss_check_ipv6() {
    info_echo "检查 IPv6 环境..."
    if [[ -z "$IPV6_ADDR" ]]; then
        error_echo "未能检测到公网 IPv6 地址！"
        error_echo "Shadowsocks (IPv6-Only) 模式无法安装"
        return 1
    fi
    success_echo "IPv6 环境检查通过: $IPV6_ADDR"
}

ss_install_dependencies() {
    info_echo "为 Shadowsocks 安装依赖..."
    local pkgs_to_install=()
    
    # 检查是否已安装 shadowsocks-libev
    if ! command -v ss-server &>/dev/null; then
        pkgs_to_install+=("shadowsocks-libev")
    fi
    
    # 检查是否已安装 qrencode
    if ! command -v qrencode &>/dev/null; then
        pkgs_to_install+=("qrencode")
    fi

    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
        info_echo "需要安装: ${pkgs_to_install[*]}"
        case "$OS_TYPE" in
            "ubuntu"|"debian") 
                apt-get update -qq && apt-get install -y "${pkgs_to_install[@]}" 
                ;;
            "centos"|"rhel"|"rocky"|"almalinux"|"fedora")
                # EPEL 仓库包含 shadowsocks-libev
                if command -v dnf &>/dev/null; then
                    dnf install -y epel-release && dnf install -y "${pkgs_to_install[@]}"
                else
                    yum install -y epel-release && yum install -y "${pkgs_to_install[@]}"
                fi
                ;;
            *)
                error_echo "不支持的操作系统: $OS_TYPE"
                return 1
                ;;
        esac || { error_echo "依赖安装失败"; return 1; }
    fi
}

ss_get_user_input() {
    exec </dev/tty
    info_echo "开始配置 Shadowsocks (IPv6-Only)..."
    
    # 端口选择
    while true; do
        local default_port=$(shuf -i 20000-65000 -n 1)
        read -rp "请输入 Shadowsocks 端口 (默认: $default_port): " SS_PORT
        SS_PORT=${SS_PORT:-$default_port}
        
        # 验证端口范围
        if [[ "$SS_PORT" -lt 1 || "$SS_PORT" -gt 65535 ]]; then
            error_echo "端口范围必须在 1-65535 之间"
            continue
        fi
        
        # 检查端口占用
        if check_port "$SS_PORT" tcp && check_port "$SS_PORT" udp; then
            break
        else
            warning_echo "端口 $SS_PORT 已被占用，请选择其他端口"
        fi
    done
    
    # 密码设置
    read -rsp "请输入 Shadowsocks 密码 (回车自动生成): " SS_PASSWORD
    echo
    if [[ -z "$SS_PASSWORD" ]]; then
        SS_PASSWORD=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
        info_echo "自动生成密码: $SS_PASSWORD"
    fi

    # 加密方式选择
    info_echo "请选择加密方式 (推荐 AEAD 算法):"
    echo "1. aes-256-gcm (推荐)"
    echo "2. chacha20-ietf-poly1305 (移动设备友好)"
    echo "3. xchacha20-ietf-poly1305 (高安全性)"
    
    while true; do
        read -rp "请选择 [1-3]: " method_choice
        case $method_choice in
            1) SS_METHOD="aes-256-gcm"; break ;;
            2) SS_METHOD="chacha20-ietf-poly1305"; break ;;
            3) SS_METHOD="xchacha20-ietf-poly1305"; break ;;
            *) error_echo "无效选择，请重新输入" ;;
        esac
    done
    
    success_echo "加密方式: $SS_METHOD"
}

ss_generate_config() {
    info_echo "生成 Shadowsocks 配置文件..."
    mkdir -p /etc/shadowsocks-libev
    
    cat > /etc/shadowsocks-libev/ss-ipv6-config.json << EOF
{
    "server": "::",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "reuse_port": true,
    "no_delay": true
}
EOF
}

ss_create_service() {
    info_echo "创建 Shadowsocks systemd 服务..."
    cat > /etc/systemd/system/ss-ipv6.service << EOF
[Unit]
Description=Shadowsocks-libev IPv6-Only Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/ss-ipv6-config.json
Restart=always
RestartSec=5
LimitNOFILE=32768
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

ss_configure_firewall() {
    info_echo "为 Shadowsocks 配置防火墙..."
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "${SS_PORT}/tcp" comment "Shadowsocks TCP" >/dev/null
        ufw allow "${SS_PORT}/udp" comment "Shadowsocks UDP" >/dev/null
        success_echo "UFW 防火墙已配置"
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="${SS_PORT}/tcp" >/dev/null 2>&1
        firewall-cmd --permanent --add-port="${SS_PORT}/udp" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null
        success_echo "Firewalld 防火墙已配置"
    else
        warning_echo "未检测到防火墙，请手动开放端口 $SS_PORT (TCP/UDP)"
    fi
}

ss_start_service() {
    info_echo "启动 Shadowsocks 服务..."
    systemctl enable --now ss-ipv6
    
    # 等待服务启动
    for i in {1..10}; do
        if systemctl is-active --quiet ss-ipv6; then
            success_echo "Shadowsocks 服务启动成功"
            return 0
        fi
        sleep 1
    done
    
    error_echo "Shadowsocks 服务启动失败！"
    journalctl -u ss-ipv6 -n 10 --no-pager
    return 1
}

ss_save_info() {
    # 生成 Shadowsocks 链接
    local method_password_b64=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0)
    local ss_link="ss://${method_password_b64}@[${IPV6_ADDR}]:${SS_PORT}#SS-IPv6-Only"
    
    cat > /root/ss_ipv6_info.txt << EOF
# Shadowsocks (IPv6-Only) 客户端配置信息 (生成时间: $(date))
================================================================================

[重要提示]
此节点仅支持 IPv6，客户端网络也必须支持 IPv6 才能连接！
Shadowsocks 协议相对容易被检测，建议谨慎使用。

[连接信息]
服务器地址: $IPV6_ADDR
端口: $SS_PORT
密码: $SS_PASSWORD
加密方式: $SS_METHOD

[分享链接]
$ss_link

[Clash Meta YAML 配置 (标准格式)]
- name: 'SS-IPv6-Only'
  type: ss
  server: '$IPV6_ADDR'
  port: $SS_PORT
  cipher: '$SS_METHOD'
  password: '$SS_PASSWORD'
  
[Clash Meta YAML 配置 (紧凑格式)]
- { name: 'SS-IPv6-Only', type: ss, server: '$IPV6_ADDR', port: $SS_PORT, cipher: '$SS_METHOD', password: '$SS_PASSWORD' }

[Sing-box JSON 配置]
{
  "type": "shadowsocks",
  "tag": "SS-IPv6-Only",
  "server": "$IPV6_ADDR",
  "server_port": $SS_PORT,
  "method": "$SS_METHOD",
  "password": "$SS_PASSWORD"
}

================================================================================
EOF
    
    # 保存安装信息
    cat > /etc/shadowsocks-libev/install_info.env << EOF
INSTALL_TIME=$(date)
SS_PORT=$SS_PORT
SS_PASSWORD=$SS_PASSWORD
SS_METHOD=$SS_METHOD
IPV6_ADDR=$IPV6_ADDR
EOF
}

ss_run_install() {
    if systemctl list-unit-files ss-ipv6.service &>/dev/null; then
        warning_echo "检测到 Shadowsocks (IPv6) 已安装，继续将覆盖现有配置"
        read -rp "确定要覆盖吗? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            return 0
        fi
        ss_uninstall
    fi

    ss_check_ipv6 && ss_install_dependencies && ss_get_user_input && ss_generate_config && ss_create_service && ss_configure_firewall && ss_start_service && ss_save_info || return 1
    
    clear
    success_echo "Shadowsocks (IPv6-Only) 安装完成！"
    cat /root/ss_ipv6_info.txt
    
    echo
    info_echo "配置二维码:"
    qrencode -t UTF8 "$(grep "ss://" /root/ss_ipv6_info.txt | head -n1)"
}

ss_uninstall() {
    info_echo "开始卸载 Shadowsocks (IPv6)..."
    systemctl disable --now ss-ipv6 2>/dev/null || true
    rm -f /etc/systemd/system/ss-ipv6.service
    systemctl daemon-reload
    rm -rf /etc/shadowsocks-libev
    rm -f /root/ss_ipv6_info.txt
    success_echo "Shadowsocks (IPv6) 已卸载"
}

################################################################################
#
# 统一管理功能
#
################################################################################

manage_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}"
        echo
        
        # 显示服务状态
        if systemctl list-unit-files hysteria-server.service &>/dev/null; then
            if systemctl is-active --quiet hysteria-server; then
                echo -e "${GREEN}✓ Hysteria2: 运行中${ENDCOLOR}"
            else
                echo -e "${RED}✗ Hysteria2: 已停止${ENDCOLOR}"
            fi
        else
            echo -e "${YELLOW}○ Hysteria2: 未安装${ENDCOLOR}"
        fi
        
        if systemctl list-unit-files ss-ipv6.service &>/dev/null; then
            if systemctl is-active --quiet ss-ipv6; then
                echo -e "${GREEN}✓ Shadowsocks(IPv6): 运行中${ENDCOLOR}"
            else
                echo -e "${RED}✗ Shadowsocks(IPv6): 已停止${ENDCOLOR}"
            fi
        else
            echo -e "${YELLOW}○ Shadowsocks(IPv6): 未安装${ENDCOLOR}"
        fi
        
        echo
        echo "1. 管理 Hysteria2"
        echo "2. 管理 Shadowsocks (IPv6)"
        echo "0. 返回主菜单"
        echo
        
        read -rp "请选择要管理的服务: " choice
        case $choice in
            1) 
                if systemctl list-unit-files hysteria-server.service &>/dev/null; then
                    manage_single_service "hysteria-server"
                else
                    error_echo "Hysteria2 未安装"
                    sleep 2
                fi
                ;;
            2) 
                if systemctl list-unit-files ss-ipv6.service &>/dev/null; then
                    manage_single_service "ss-ipv6"
                else
                    error_echo "Shadowsocks (IPv6) 未安装"
                    sleep 2
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
    done
}

manage_single_service() {
    local service_name=$1
    local display_name
    case $service_name in
        "hysteria-server") display_name="Hysteria2" ;;
        "ss-ipv6") display_name="Shadowsocks(IPv6)" ;;
        *) display_name="$service_name" ;;
    esac
    
    while true; do
        clear
        echo -e "${CYAN}=== 管理 $display_name ===${ENDCOLOR}"
        echo
        
        # 显示服务状态
        systemctl status "$service_name" --no-pager --lines=5 2>/dev/null || echo "服务状态异常"
        
        echo
        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 查看日志"
        echo "5. 实时日志"
        echo "0. 返回上级菜单"
        echo
        
        read -rp "请选择操作: " op_choice
        case $op_choice in
            1) 
                systemctl start "$service_name"
                success_echo "$display_name 已启动"
                sleep 2
                ;;
            2) 
                systemctl stop "$service_name"
                success_echo "$display_name 已停止"
                sleep 2
                ;;
            3) 
                systemctl restart "$service_name"
                success_echo "$display_name 已重启"
                sleep 2
                ;;
            4) 
                clear
                echo -e "${CYAN}=== $display_name 服务日志 ===${ENDCOLOR}"
                journalctl -u "$service_name" -n 50 --no-pager
                echo
                read -rp "按回车继续..."
                ;;
            5) 
                echo "按 Ctrl+C 退出日志监控"
                sleep 2
                journalctl -u "$service_name" -f
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

show_config_info() {
    clear
    local hy2_installed=false
    local ss_installed=false
    
    [[ -f /root/hysteria2_info.txt ]] && hy2_installed=true
    [[ -f /root/ss_ipv6_info.txt ]] && ss_installed=true

    if ! $hy2_installed && ! $ss_installed; then
        error_echo "未安装任何服务，无配置信息可显示"
        read -rp "按回车返回主菜单..."
        return
    fi

    echo -e "${CYAN}=== 配置信息显示 ===${ENDCOLOR}"
    echo
    
    if $hy2_installed; then
        echo -e "${PURPLE}--- Hysteria2 配置 ---${ENDCOLOR}"
        cat /root/hysteria2_info.txt
        echo
    fi
    
    if $ss_installed; then
        echo -e "${PURPLE}--- Shadowsocks (IPv6) 配置 ---${ENDCOLOR}"
        cat /root/ss_ipv6_info.txt
        echo
        info_echo "Shadowsocks 配置二维码:"
        local ss_link=$(grep "ss://" /root/ss_ipv6_info.txt | head -n1)
        qrencode -t UTF8 "$ss_link" 2>/dev/null || warning_echo "二维码生成失败"
        echo
    fi
    
    read -rp "按回车返回主菜单..."
}

uninstall_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 卸载菜单 ===${ENDCOLOR}"
        echo
        echo "1. 卸载 Hysteria2"
        echo "2. 卸载 Shadowsocks (IPv6)"
        echo "3. 🔥 完全清理所有组件"
        echo "0. 返回主菜单"
        echo
        
        read -rp "请选择要卸载的服务: " choice
        case $choice in
            1) 
                if systemctl list-unit-files hysteria-server.service &>/dev/null; then
                    warning_echo "即将卸载 Hysteria2..."
                    read -rp "确定继续? (y/N): " confirm
                    if [[ "$confirm" =~ ^[yY]$ ]]; then
                        hy2_uninstall
                        success_echo "Hysteria2 卸载完成"
                    fi
                else
                    error_echo "Hysteria2 未安装"
                fi
                ;;
            2) 
                if systemctl list-unit-files ss-ipv6.service &>/dev/null; then
                    warning_echo "即将卸载 Shadowsocks (IPv6)..."
                    read -rp "确定继续? (y/N): " confirm
                    if [[ "$confirm" =~ ^[yY]$ ]]; then
                        ss_uninstall
                        success_echo "Shadowsocks 卸载完成"
                    fi
                else
                    error_echo "Shadowsocks (IPv6) 未安装"
                fi
                ;;
            3) 
                warning_echo "⚠️  即将卸载所有已安装的服务及其配置！"
                warning_echo "这将删除："
                echo "   - Hysteria2 服务和配置"
                echo "   - Shadowsocks 服务和配置"
                echo "   - 所有客户端配置文件"
                echo
                read -rp "确定要完全清理吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall 2>/dev/null || true
                    ss_uninstall 2>/dev/null || true
                    # 额外清理
                    rm -f /root/hysteria2_info.txt /root/ss_ipv6_info.txt
                    success_echo "完全清理完成"
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
        
        if [[ "$choice" != 0 ]]; then
            read -rp "按回车返回卸载菜单..."
        fi
    done
}

# --- 主函数 ---
main() {
    check_root
    detect_system
    
    while true; do
        # 每次循环都重新检测网络，以更新菜单中的IP显示
        detect_network
        exec </dev/tty
        show_menu
        
        read -rp "请选择操作 [0-6]: " main_choice
        case $main_choice in
            1) 
                hy2_run_install "self"
                read -rp "按回车返回主菜单..."
                ;;
            2) 
                hy2_run_install "acme"
                read -rp "按回车返回主菜单..."
                ;;
            3) 
                ss_run_install
                read -rp "按回车返回主菜单..."
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
            0) 
                info_echo "感谢使用本脚本！"
                exit 0
                ;;
            *) 
                error_echo "无效选择，请重新输入"
                sleep 1
                ;;
        esac
    done
}

# 脚本入口
main
