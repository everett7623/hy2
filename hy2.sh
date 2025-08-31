#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# Sürüm: 4.0 (密码生成逻辑终极修复版)

# --- 脚本行为设置 ---
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
    
    local hy2_status="未安装"
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hy2_status="${GREEN}运行中${ENDCOLOR}"
    elif systemctl list-unit-files hysteria-server.service &>/dev/null; then
        hy2_status="${RED}已停止${ENDCOLOR}"
    fi

    local ss_status="未安装"
    if systemctl is-active --quiet ss-ipv6 2>/dev/null; then
        ss_status="${GREEN}运行中${ENDCOLOR}"
    elif systemctl list-unit-files ss-ipv6.service &>/dev/null; then
        ss_status="${RED}已停止${ENDCOLOR}"
    fi

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v4.0) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}安装选项:${ENDCOLOR}"
    echo -e "   1. 安装 Hysteria2 (自签名证书 - ${GREEN}域名无需解析${ENDCOLOR})"
    echo -e "   2. 安装 Hysteria2 (Let's Encrypt 证书 - ${YELLOW}域名必须解析${ENDCOLOR})"
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

# --- 通用系统检查函数 ---
check_root() { if [[ $EUID -ne 0 ]]; then error_echo "此脚本需要 root 权限运行"; exit 1; fi; }

detect_system() {
    source /etc/os-release; OS_TYPE=$ID
    ARCH=$(uname -m); case $ARCH in x86_64) ARCH="amd64" ;; aarch64|arm64) ARCH="arm64" ;; armv7l) ARCH="arm" ;; *) error_echo "不支持的架构: $ARCH"; exit 1 ;; esac
    info_echo "检测到系统: $PRETTY_NAME ($ARCH)"
}

detect_network() {
    IPV4_ADDR="" && IPV6_ADDR=""
    info_echo "检测网络配置..."
    local ipv4_svcs=("https://api.ipify.org" "https://ipv4.icanhazip.com")
    local ipv6_svcs=("https://api64.ipify.org" "https://ipv6.icanhazip.com")
    for svc in "${ipv4_svcs[@]}"; do IPV4_ADDR=$(curl -4 -s --connect-timeout 3 "$svc" 2>/dev/null | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true); [[ -n "$IPV4_ADDR" ]] && break; done
    for svc in "${ipv6_svcs[@]}"; do IPV6_ADDR=$(curl -6 -s --connect-timeout 3 "$svc" 2>/dev/null | grep -Eo '^[0-9a-fA-F:]+$' || true); [[ -n "$IPV6_ADDR" ]] && break; done
}

check_port() {
    local port=$1; local protocol=${2:-tcp}; local cmd="ss -lntp"
    [[ "$protocol" == "udp" ]] && cmd="ss -lnup"
    if $cmd | grep -q ":$port\s"; then error_echo "端口 $port/$protocol 已被占用"; return 1; fi
    return 0
}


################################################################################
# Hysteria2 功能模块
################################################################################

hy2_display_prerequisites() {
    local mode="$1"
    clear
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e "               ${CYAN}Hysteria2 安装前置条件说明${ENDCOLOR}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo
    if [[ "$mode" == "self" ]]; then
        info_echo "您选择了 [自签名证书] 模式。"
        success_echo "在此模式下，您输入的域名只是一个“标签”，用于证书和客户端连接时的 SNI 字段。"
        success_echo "它【不需要】在公共 DNS 上解析到您服务器的 IP。"
    else
        warning_echo "您选择了 [Let's Encrypt 证书] 模式。"
        warning_echo "在此模式下，您的域名【必须】满足以下条件："
        info_echo "1. 域名的 NS (Name Server) 记录【必须】已指向 Cloudflare 并完成托管。"
        info_echo "2. 域名【必须】能被公网正确访问（证书颁发机构需要验证）。"
        error_echo "如果这些条件未满足，证书申请一定会失败！"
    fi
    echo
    read -rp "您已了解并希望继续吗? (Y/n): " confirm
    if [[ "$confirm" =~ ^[nN]$ ]]; then info_echo "安装已取消。"; return 1; fi
    return 0
}

hy2_install_dependencies() {
    info_echo "为 Hysteria2 安装依赖..."
    local pkgs_to_install=(); declare -A pkg_map
    case "$OS_TYPE" in "ubuntu"|"debian") pkg_map=([curl]="curl" [wget]="wget" [jq]="jq" [openssl]="openssl" [nslookup]="dnsutils" [awk]="gawk") ;; *) pkg_map=([curl]="curl" [wget]="wget" [jq]="jq" [openssl]="openssl" [nslookup]="bind-utils" [awk]="gawk") ;; esac
    for cmd in "${!pkg_map[@]}"; do command -v "$cmd" &>/dev/null || pkgs_to_install+=("${pkg_map[$cmd]}"); done
    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
        info_echo "需要安装: ${pkgs_to_install[*]}"; case "$OS_TYPE" in "ubuntu"|"debian") apt-get update -qq && apt-get install -y "${pkgs_to_install[@]}" ;; *) command -v dnf &>/dev/null && dnf install -y "${pkgs_to_install[@]}" || yum install -y "${pkgs_to_install[@]}" ;; esac || { error_echo "依赖安装失败"; return 1; }
    fi
}

hy2_get_user_input() {
    exec </dev/tty
    info_echo "开始配置 Hysteria2..."
    while true; do read -rp "请输入您的域名 (用于SNI): " DOMAIN; if [[ -n "$DOMAIN" && "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then break; else error_echo "域名格式不正确"; fi; done
    read -rsp "请输入 Hysteria2 密码 (回车自动生成): " HY_PASSWORD; echo
    if [[ -z "$HY_PASSWORD" ]]; then
        # 终极 Bug 修复：使用绝对安全的方式生成密码，只包含字母和数字
        HY_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        info_echo "自动生成安全密码: $HY_PASSWORD"
    fi
    read -rp "请输入伪装网址 (默认: https://www.bing.com): " FAKE_URL; FAKE_URL=${FAKE_URL:-https://www.bing.com}
    if [[ "$USE_ACME" == true ]]; then
        local default_email="user$(shuf -i 1000-9999 -n 1)@gmail.com"; read -rp "请输入 ACME 邮箱 (默认: ${default_email}): " ACME_EMAIL; ACME_EMAIL=${ACME_EMAIL:-$default_email}
        echo; warning_echo "--- 如何创建正确的 Cloudflare API Token ---"; echo "1. 访问 Cloudflare -> 我的个人资料 -> API令牌 -> 创建令牌"; echo "2. 点击“编辑区域 DNS”模板旁的“使用模板”按钮"; echo "3. 在“区域资源”下，选择“包括”->“特定区域”->“${DOMAIN}”"; echo "4. 点击“继续以显示摘要”，然后“创建令牌”"; echo "---------------------------------------------"; echo
        while true; do
            read -rsp "请输入 Cloudflare API Token: " CF_TOKEN; echo; [[ -n "$CF_TOKEN" ]] || { error_echo "Token 不能为空"; continue; }
            info_echo "正在验证 Token..."; local api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json")
            if ! echo "$api_result" | jq -e '.success==true' >/dev/null; then error_echo "Token 无效或网络错误！Cloudflare API 返回失败。"; echo "API 错误信息: $(echo "$api_result" | jq '.errors')";
            elif ! echo "$api_result" | jq -e '.result[0].id' >/dev/null; then error_echo "Token 有效，但在您的账户下找不到域名 '${DOMAIN}'！"; warning_echo "请检查: 1. 域名拼写是否正确。 2. 此域名是否已添加到此 Cloudflare 账户。";
            else success_echo "Token 验证成功 (Zone: $(echo "$api_result" | jq -r '.result[0].name'))"; break; fi
        done
    fi
}

hy2_install() {
    info_echo "安装 Hysteria2..."; local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    local dl_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name==\"hysteria-linux-$ARCH\") | .browser_download_url")
    [[ -n "$dl_url" && "$dl_url" != "null" ]] || { error_echo "无法获取 Hysteria2 ($ARCH) 下载链接"; return 1; }
    wget -qO /usr/local/bin/hysteria "$dl_url" && chmod +x /usr/local/bin/hysteria
    success_echo "Hysteria2 安装成功 ($(/usr/local/bin/hysteria version | head -n1))"
}

hy2_install_acme_cert() {
    info_echo "申请 Let's Encrypt 证书..."; if [[ ! -f ~/.acme.sh/acme.sh ]]; then curl https://get.acme.sh | sh -s email="$ACME_EMAIL"; fi
    export CF_Token="$CF_TOKEN"; ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --ecc
    mkdir -p /etc/hysteria2/certs; ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc --fullchain-file /etc/hysteria2/certs/fullchain.cer --key-file /etc/hysteria2/certs/private.key
    chmod 600 /etc/hysteria2/certs/private.key
}

hy2_generate_self_signed_cert() {
    info_echo "生成 Hysteria2 自签名证书..."; mkdir -p /etc/hysteria2/certs
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/hysteria2/certs/private.key -out /etc/hysteria2/certs/fullchain.cer -subj "/CN=$DOMAIN" >/dev/null 2>&1
    chmod 600 /etc/hysteria2/certs/private.key
}

hy2_generate_config() {
    info_echo "生成 Hysteria2 配置文件..."; mkdir -p /etc/hysteria2; local listen_addr=$([[ -n "$IPV6_ADDR" ]] && echo "[::]:443" || echo "0.0.0.0:443")
    awk -v listen="$listen_addr" -v pass="$HY_PASSWORD" -v url="$FAKE_URL" '
    { gsub(/__LISTEN_ADDR__/, listen); gsub(/__HY_PASSWORD__/, pass); gsub(/__FAKE_URL__/, url); print; }
    ' > /etc/hysteria2/config.yaml << 'EOF'
listen: __LISTEN_ADDR__
tls:
  cert: /etc/hysteria2/certs/fullchain.cer
  key: /etc/hysteria2/certs/private.key
auth:
  type: password
  password: "__HY_PASSWORD__"
masquerade:
  type: proxy
  proxy:
    url: "__FAKE_URL__"
    rewriteHost: true
EOF
    success_echo "配置文件生成完成"
}

hy2_create_service() {
    info_echo "创建 Hysteria2 systemd 服务..."; cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

hy2_configure_firewall() {
    info_echo "为 Hysteria2 配置防火墙..."; if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then ufw allow 443/udp comment "Hysteria2" >/dev/null;
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null; fi
}

hy2_start_service() {
    info_echo "正在启动 Hysteria2 服务..."; systemctl enable --now hysteria-server; sleep 2
    if systemctl is-active --quiet hysteria-server && ss -ulnp | grep -q ":443.*hysteria"; then
        success_echo "Hysteria2 服务启动成功"; return 0;
    else
        error_echo "Hysteria2 服务启动失败！正在显示诊断信息..."; echo "-------------------- Journalctl Log --------------------"; journalctl -u hysteria-server -n 20 --no-pager; echo "------------------------------------------------------"; warning_echo "常见原因: 1. 配置文件(/etc/hysteria2/config.yaml)有误。 2. 证书文件路径不正确。"; return 1;
    fi
}

hy2_save_info() {
    local cert_type="$1"; local server_addr=$([[ "$cert_type" == "acme" ]] && echo "$DOMAIN" || echo "${IPV4_ADDR:-$IPV6_ADDR}"); local insecure=$([[ "$cert_type" == "self" ]] && echo "true" || echo "false")
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}&insecure=${insecure}#HY2-${cert_type^}"
    cat > /root/hysteria2_info.txt << EOF
# Hysteria2 Client Configuration
================================================
[连接信息]
服务器: $server_addr, 端口: 443, 密码: $HY_PASSWORD
SNI: $DOMAIN, 跳过证书验证: $insecure
[分享链接]
$share_link
================================================
EOF
}

hy2_run_install() {
    local cert_type="$1"
    hy2_display_prerequisites "$cert_type" || return 0
    if systemctl list-unit-files hysteria-server.service &>/dev/null; then
        warning_echo "检测到 Hysteria2 已安装，继续将覆盖。"; read -rp "确定吗? (y/N): " confirm && [[ ! "$confirm" =~ ^[yY]$ ]] && return
        hy2_uninstall
    fi
    USE_ACME=$([[ "$cert_type" == "acme" ]] && echo true || echo false)
    check_port 443 udp || return 1
    hy2_install_dependencies && hy2_get_user_input && hy2_install || { error_echo "Hysteria2 准备阶段失败。"; return 1; }
    if $USE_ACME; then hy2_install_acme_cert; else hy2_generate_self_signed_cert; fi
    hy2_generate_config && hy2_create_service && hy2_configure_firewall || { error_echo "Hysteria2 配置阶段失败。"; return 1; }
    if hy2_start_service; then
        hy2_save_info "$cert_type"; clear; success_echo "Hysteria2 安装完成！"; cat /root/hysteria2_info.txt;
    else
        error_echo "Hysteria2 安装失败，服务未能成功启动。请检查上面的错误日志。"; return 1;
    fi
}

hy2_uninstall() {
    info_echo "卸载 Hysteria2..."; systemctl disable --now hysteria-server 2>/dev/null || true
    rm -f /etc/systemd/system/hysteria-server.service /usr/local/bin/hysteria; rm -rf /etc/hysteria2 /root/hysteria2_info.txt
    systemctl daemon-reload
}


################################################################################
# Shadowsocks (IPv6-Only) 功能模块 (无改动)
################################################################################

ss_check_ipv6() {
    info_echo "检查 IPv6 环境..."; if [[ -z "$IPV6_ADDR" ]]; then error_echo "未能检测到公网 IPv6 地址！无法安装 Shadowsocks (IPv6-Only)。"; return 1; fi
    success_echo "IPv6 环境检查通过: $IPV6_ADDR"
}

ss_install_dependencies() {
    info_echo "为 Shadowsocks 安装依赖..."; local pkgs_to_install=(); local deps=("shadowsocks-libev" "qrencode")
    for pkg in "${deps[@]}"; do case "$OS_TYPE" in "ubuntu"|"debian") dpkg -s "$pkg" &>/dev/null || pkgs_to_install+=("$pkg") ;; *) rpm -q "$pkg" &>/dev/null || pkgs_to_install+=("$pkg") ;; esac; done
    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
        info_echo "需要安装: ${pkgs_to_install[*]}"; case "$OS_TYPE" in "ubuntu"|"debian") apt-get update -qq && apt-get install -y "${pkgs_to_install[@]}" ;; *) command -v dnf &>/dev/null && dnf install -y epel-release && dnf install -y "${pkgs_to_install[@]}" || yum install -y epel-release && yum install -y "${pkgs_to_install[@]}" ;; esac || { error_echo "依赖安装失败"; return 1; }
    fi
}

ss_get_user_input() {
    exec </dev/tty; info_echo "开始配置 Shadowsocks (IPv6-Only)..."
    while true; do local default_port=$(shuf -i 20000-65000 -n 1); read -rp "请输入 Shadowsocks 端口 (默认: $default_port): " SS_PORT; SS_PORT=${SS_PORT:-$default_port}; check_port "$SS_PORT" "tcp" && check_port "$SS_PORT" "udp" && break; done
    read -rsp "请输入 Shadowsocks 密码 (回车自动生成): " SS_PASSWORD; echo
    if [[ -z "$SS_PASSWORD" ]]; then SS_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16); info_echo "自动生成安全密码: $SS_PASSWORD"; fi
    info_echo "请选择加密方式:"; echo "1. aes-256-gcm (推荐)"; echo "2. chacha20-ietf-poly1305"; echo "3. xchacha20-ietf-poly1305"
    while true; do read -rp "请选择 [1-3]: " mc; case $mc in 1) SS_METHOD="aes-256-gcm"; break ;; 2) SS_METHOD="chacha20-ietf-poly1305"; break ;; 3) SS_METHOD="xchacha20-ietf-poly1305"; break ;; *) error_echo "无效选择" ;; esac; done
    success_echo "已选择加密方式: $SS_METHOD"
}

ss_generate_config() {
    info_echo "生成 Shadowsocks 配置文件..."; mkdir -p /etc/shadowsocks-libev
    cat > /etc/shadowsocks-libev/ss-ipv6-config.json << EOF
{ "server": "::", "server_port": ${SS_PORT}, "password": "${SS_PASSWORD}", "method": "${SS_METHOD}", "mode": "tcp_and_udp" }
EOF
}

ss_create_service() {
    info_echo "创建 Shadowsocks systemd 服务..."; cat > /etc/systemd/system/ss-ipv6.service << EOF
[Unit]
Description=Shadowsocks-libev IPv6-Only Server
After=network.target
[Service]
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/ss-ipv6-config.json
User=nobody
Group=nogroup
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

ss_configure_firewall() {
    info_echo "为 Shadowsocks 配置防火墙..."; if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then ufw allow "${SS_PORT}" comment "Shadowsocks" >/dev/null;
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-port="${SS_PORT}/tcp" >/dev/null 2>&1; firewall-cmd --permanent --add-port="${SS_PORT}/udp" >/dev/null 2>&1; firewall-cmd --reload >/dev/null; fi
}

ss_start_service() {
    info_echo "启动 Shadowsocks 服务..."; systemctl enable --now ss-ipv6; sleep 2
    if systemctl is-active --quiet ss-ipv6; then success_echo "Shadowsocks 服务启动成功"; return 0; else error_echo "服务启动失败！"; journalctl -u ss-ipv6 -n 10 --no-pager; return 1; fi
}

ss_save_info() {
    local method_password_b64=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0)
    local ss_link="ss://${method_password_b64}@[${IPV6_ADDR}]:${SS_PORT}#SS-IPv6-Only"
    cat > /root/ss_ipv6_info.txt << EOF
# Shadowsocks (IPv6-Only) Client Configuration
================================================
[重要提示]
* 此节点仅支持 IPv6，客户端也必须有 IPv6 网络！
* Shadowsocks 协议易被识别，请谨慎使用。
[分享链接]
${ss_link}
================================================
EOF
}

ss_run_install() {
    if systemctl list-unit-files ss-ipv6.service &>/dev/null; then
        warning_echo "检测到 Shadowsocks (IPv6) 已安装，继续将覆盖。"; read -rp "确定吗? (y/N): " confirm && [[ ! "$confirm" =~ ^[yY]$ ]] && return
        ss_uninstall
    fi
    ss_check_ipv6 && ss_install_dependencies && ss_get_user_input && ss_generate_config && ss_create_service && ss_configure_firewall || { error_echo "Shadowsocks 准备阶段失败。"; return 1; }
    if ss_start_service; then
        ss_save_info; clear; success_echo "Shadowsocks (IPv6-Only) 安装完成！"; cat /root/ss_ipv6_info.txt
        echo; info_echo "配置二维码:"; qrencode -t UTF8 "$(grep "ss://" /root/ss_ipv6_info.txt)"
    else
        error_echo "Shadowsocks 安装失败，服务未能成功启动。"; return 1;
    fi
}

ss_uninstall() {
    info_echo "卸载 Shadowsocks (IPv6)..."; systemctl disable --now ss-ipv6 2>/dev/null || true
    rm -f /etc/systemd/system/ss-ipv6.service; systemctl daemon-reload
    rm -rf /etc/shadowsocks-libev /root/ss_ipv6_info.txt
}


################################################################################
# 统一管理功能
################################################################################

manage_services() {
    while true; do clear; echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}\n"; echo "1. 管理 Hysteria2"; echo "2. 管理 Shadowsocks (IPv6)"; echo "0. 返回主菜单"; read -rp "请选择: " choice
        case $choice in
            1) systemctl list-unit-files hysteria-server.service &>/dev/null && manage_single_service "hysteria-server" || { error_echo "Hysteria2 未安装"; sleep 1; };;
            2) systemctl list-unit-files ss-ipv6.service &>/dev/null && manage_single_service "ss-ipv6" || { error_echo "Shadowsocks (IPv6) 未安装"; sleep 1; };;
            0) return ;; *) error_echo "无效选择" ;;
        esac
    done
}

manage_single_service() {
    local service_name=$1
    while true; do clear; echo -e "${CYAN}=== 管理 $service_name ===${ENDCOLOR}\n"; systemctl status "$service_name" --no-pager
        echo -e "\n1.启动 2.停止 3.重启 4.日志 5.实时日志 0.返回"; read -rp "操作: " op_choice
        case $op_choice in
            1) systemctl start "$service_name"; sleep 1 ;; 2) systemctl stop "$service_name"; sleep 1 ;; 3) systemctl restart "$service_name"; sleep 1 ;;
            4) clear; journalctl -u "$service_name" -n 100 --no-pager; read -rp "按回车继续..." ;; 5) journalctl -u "$service_name" -f ;; 0) return ;; *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

show_config_info() {
    clear
    if [[ ! -f /root/hysteria2_info.txt && ! -f /root/ss_ipv6_info.txt ]]; then error_echo "未安装任何服务。"; return; fi
    if [[ -f /root/hysteria2_info.txt ]]; then echo -e "${PURPLE}--- Hysteria2 配置 ---${ENDCOLOR}" && cat /root/hysteria2_info.txt && echo; fi
    if [[ -f /root/ss_ipv6_info.txt ]]; then echo -e "${PURPLE}--- Shadowsocks (IPv6) 配置 ---${ENDCOLOR}" && cat /root/ss_ipv6_info.txt; echo; info_echo "二维码:"; qrencode -t UTF8 "$(grep "ss://" /root/ss_ipv6_info.txt)" && echo; fi
}

uninstall_services() {
    while true; do clear; echo -e "${CYAN}=== 卸载菜单 ===${ENDCOLOR}\n"; echo "1. 卸载 Hysteria2"; echo "2. 卸载 Shadowsocks (IPv6)"; echo "3. 🔥 完全清理所有组件"; echo "0. 返回主菜单"; read -rp "请选择: " choice
        case $choice in
            1) read -rp "确定要卸载 Hysteria2 吗? (y/N): " c && [[ "$c" =~ ^[yY]$ ]] && hy2_uninstall && success_echo "Hysteria2 卸载完成" ;;
            2) read -rp "确定要卸载 Shadowsocks (IPv6) 吗? (y/N): " c && [[ "$c" =~ ^[yY]$ ]] && ss_uninstall && success_echo "Shadowsocks (IPv6) 卸载完成" ;;
            3) warning_echo "将卸载所有服务及其依赖！"; read -rp "确定吗? (y/N): " c && [[ "$c" =~ ^[yY]$ ]] && { hy2_uninstall; ss_uninstall; success_echo "清理完成"; } ;;
            0) return ;; *) error_echo "无效选择" ;;
        esac; read -rp "按回车返回..."
    done
}

backup_configs() {
    local backup_dir="/root/proxy_backup_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$backup_dir"
    info_echo "正在备份配置到: $backup_dir"; [[ -d /etc/hysteria2 ]] && cp -r /etc/hysteria2 "$backup_dir/"; [[ -d /etc/shadowsocks-libev ]] && cp -r /etc/shadowsocks-libev "$backup_dir/"
    success_echo "备份完成！"
}

diagnose_issues() {
    clear; echo -e "${CYAN}=== 系统诊断 ===${ENDCOLOR}\n"
    echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2), Kernel: $(uname -r)"
    echo "IPv4: ${IPV4_ADDR:-N/A}, IPv6: ${IPV6_ADDR:-N/A}"
    echo -e "\n${YELLOW}--- 防火墙状态 ---${ENDCOLOR}"; command -v ufw &>/dev/null && ufw status | head -n1 || (command -v firewall-cmd &>/dev/null && echo "Firewalld: $(systemctl is-active firewalld)" || echo "未检测到 UFW/Firewalld")
    echo -e "\n${YELLOW}--- 服务状态 ---${ENDCOLOR}"; systemctl list-unit-files hysteria-server.service &>/dev/null && echo "Hysteria2: $(systemctl is-active hysteria-server)" || echo "Hysteria2: 未安装"
    systemctl list-unit-files ss-ipv6.service &>/dev/null && echo "Shadowsocks: $(systemctl is-active ss-ipv6)" || echo "Shadowsocks: 未安装"
}

# --- 主函数 ---
main() {
    check_root
    detect_system
    while true; do
        detect_network
        exec </dev/tty
        show_menu
        read -rp "请选择操作 [0-8]: " main_choice
        case $main_choice in
            1) hy2_run_install "self" ;; 2) hy2_run_install "acme" ;; 3) ss_run_install ;; 4) manage_services ;; 5) show_config_info ;;
            6) uninstall_services ;; 7) backup_configs ;; 8) diagnose_issues ;; 0) info_echo "感谢使用!"; exit 0 ;; *) error_echo "无效选择"; sleep 1 ;;
        esac
        [[ "$main_choice" =~ ^[123578]$ ]] && read -rp "按回车返回主菜单..."
    done
}

# 脚本入口
main
