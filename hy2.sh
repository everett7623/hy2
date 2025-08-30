#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 菜单式安装脚本
# 版本: 4.7 (最终修复版)
# 作者: Jensfrank & AI Assistant 优化
# 项目: hy2ipv6

# -e: 当命令失败时立即退出脚本
# -o pipefail: 管道中的任何命令失败都会导致整个管道失败
set -e -o pipefail

# --- 脚本配置与变量 ---

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BG_PURPLE='\033[45m'
ENDCOLOR='\033[0m'

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

# --- 辅助函数 ---

info_echo() { echo -e "${BLUE}[INFO]${ENDCOLOR} $1"; }
success_echo() { echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"; }
error_echo() { echo -e "${RED}[ERROR]${ENDCOLOR} $1"; }
warning_echo() { echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"; }

# 显示主菜单 (全新UI)
show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-N/A}"
    local ipv6_display="${IPV6_ADDR:-N/A}"
    
    echo -e "${BG_PURPLE} Hysteria2 + IPv6 + Cloudflare Tunnel Management Script (v4.7) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}IPv4:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR}"
    echo -e " ${YELLOW}IPv6:${ENDCOLOR} ${GREEN}${ipv6_display}${ENDCOLOR}"
    echo -e "${PURPLE}----------------------------------------------------------------${ENDCOLOR}"
    echo -e " ${CYAN}1.${ENDCOLOR} 安装 Hysteria2 (直连模式)"
    echo -e " ${CYAN}2.${ENDCOLOR} 安装 Hysteria2 + Cloudflare Tunnel (CDN模式)"
    echo -e "${PURPLE}----------------------------------------------------------------${ENDCOLOR}"
    echo -e " ${CYAN}3.${ENDCOLOR} 卸载 Hysteria2 服务"
    echo -e " ${CYAN}4.${ENDCOLOR} 卸载 Hysteria2 + Cloudflare Tunnel"
    echo -e " ${CYAN}5.${ENDCOLOR} 完全清理 (卸载所有组件)"
    echo -e "${PURPLE}----------------------------------------------------------------${ENDCOLOR}"
    echo -e " ${CYAN}6.${ENDCOLOR} 服务管理"
    echo -e " ${CYAN}7.${ENDCOLOR} 显示配置信息"
    echo -e " ${CYAN}8.${ENDCOLOR} 测试连通性"
    echo -e "${PURPLE}----------------------------------------------------------------${ENDCOLOR}"
    echo -e " ${CYAN}0.${ENDCOLOR} 退出"
    echo
}

# 连通性测试函数
test_connectivity() {
    info_echo "开始连通性测试..."
    
    if [[ ! -f /etc/hysteria2/uninstall_info.env ]]; then
        error_echo "未找到安装信息，无法进行测试。请先完成安装。"
        return 1
    fi
    source /etc/hysteria2/uninstall_info.env

    info_echo "1. 检查核心服务状态..."
    local services_ok=true
    if systemctl is-active --quiet hysteria-server; then
        success_echo "  - Hysteria2 服务: 运行中"
    else
        error_echo "  - Hysteria2 服务: 未运行！"
        services_ok=false
    fi

    if [[ "$MODE" == "tunnel" ]]; then
        if systemctl is-active --quiet cloudflared; then
            success_echo "  - Cloudflared 服务: 运行中"
        else
            error_echo "  - Cloudflared 服务: 未运行！"
            services_ok=false
        fi
    fi
    if ! $services_ok; then return 1; fi

    info_echo "2. 检查端口监听..."
    if ss -ulnp | grep -q ":443.*hysteria"; then
        success_echo "  - Hysteria2 正在监听 UDP 443 端口。"
    else
        error_echo "  - Hysteria2 未监听 UDP 443 端口！"
        return 1
    fi
    
    info_echo "3. 检查域名解析..."
    if [[ -n "$DOMAIN" ]]; then
        if nslookup "$DOMAIN" >/dev/null 2>&1; then
            success_echo "  - 域名 '$DOMAIN' 解析正常。"
        else
            error_echo "  - 域名 '$DOMAIN' 解析失败！请检查您的 DNS 设置。"
        fi
    fi
    
    if [[ "$MODE" == "tunnel" ]]; then
        info_echo "4. 检查 Cloudflare Tunnel 连接..."
        if journalctl -u cloudflared --since="5 minutes ago" | grep -q "Connected to"; then
            success_echo "  - Cloudflare Tunnel 已成功连接到 Cloudflare 网络。"
        else
            warning_echo "  - Cloudflare Tunnel 在最近5分钟内未报告成功连接。"
            journalctl -u cloudflared -n 5 --no-pager
        fi
    fi
    
    echo
    success_echo "连通性测试完成。"
}

# --- 核心功能函数 ---

cleanup_previous_installation() {
    info_echo "正在检查并清理任何可能存在的旧安装..."
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true
    if command -v cloudflared &>/dev/null; then
        cloudflared tunnel delete -f "$TUNNEL_NAME" 2>/dev/null || true
    fi
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    rm -rf /etc/hysteria2 /etc/cloudflared /root/.cloudflared
    success_echo "旧环境清理完成。"
}

complete_cleanup() {
    warning_echo "开始完全清理所有组件..."
    read -rp "确定要完全清理所有安装的内容吗？此操作不可逆 (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then info_echo "取消清理"; return 0; fi
    if [[ -f /etc/hysteria2/uninstall_info.env ]]; then source /etc/hysteria2/uninstall_info.env; fi
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true
    if command -v cloudflared &>/dev/null; then
        cloudflared tunnel delete -f "$TUNNEL_NAME" 2>/dev/null || true
    fi
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    rm -f /usr/local/bin/hysteria
    if [[ -n "$DOMAIN" ]] && command -v ~/.acme.sh/acme.sh &> /dev/null; then
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc 2>/dev/null || true
    fi
    rm -rf /etc/hysteria2 /etc/cloudflared /root/.cloudflared
    info_echo "正在尝试卸载 Cloudflared 软件包..."
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get purge -y cloudflared 2>/dev/null || true
            rm -f /etc/apt/sources.list.d/cloudflared.list /usr/share/keyrings/cloudflare-main.gpg
            ;;
        *)
            yum remove -y cloudflared 2>/dev/null || true
            rm -f /etc/yum.repos.d/cloudflared-ascii.repo
            ;;
    esac
    success_echo "完全清理完成！"
    read -rp "按回车键返回主菜单..."
}

# 1. 环境检查
check_root() { if [[ $EUID -ne 0 ]]; then error_echo "此脚本需要 root 权限运行"; exit 1; fi; }

detect_system() {
    if [[ -f /etc/os-release ]]; then source /etc/os-release; OS_TYPE=$ID; else error_echo "无法检测到操作系统类型"; exit 1; fi
    ARCH=$(uname -m)
    case $ARCH in x86_64) ARCH="amd64" ;; aarch64) ARCH="arm64" ;; *) error_echo "不支持的架构: $ARCH"; exit 1 ;; esac
}

install_dependencies() {
    info_echo "检查并安装依赖包..."
    local packages_to_install=()
    local essential_packages=("curl" "socat" "unzip" "wget" "jq" "net-tools")
    case "$OS_TYPE" in "ubuntu" | "debian") essential_packages+=("netcat-openbsd") ;; *) essential_packages+=("nc") ;; esac
    for pkg in "${essential_packages[@]}"; do
        local cmd_to_check="$pkg"; [[ "$pkg" == "netcat-openbsd" ]] && cmd_to_check="nc"
        if ! command -v "$cmd_to_check" &>/dev/null; then packages_to_install+=("$pkg"); fi
    done
    if [ ${#packages_to_install[@]} -gt 0 ]; then
        info_echo "以下依赖包将被安装: ${packages_to_install[*]}"
        case "$OS_TYPE" in "ubuntu" | "debian") apt-get update -qq; apt-get install -y "${packages_to_install[@]}";; *) yum install -y "${packages_to_install[@]}";; esac
    fi
    success_echo "依赖包检查完成"
}

check_port_443() {
    if ss -ulnp | grep -q ":443 "; then error_echo "UDP 端口 443 已被占用:"; ss -ulnp | grep ":443 "; exit 1; fi
    success_echo "UDP 端口 443 可用。"
}

detect_network() { IPV4_ADDR=$(curl -4 -s ip.sb) || true; IPV6_ADDR=$(curl -6 -s ip.sb) || true; }

configure_firewall() {
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then ufw allow 443/udp >/dev/null;
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1; firewall-cmd --reload >/dev/null;
    elif command -v iptables &>/dev/null; then iptables -I INPUT 1 -p udp --dport 443 -j ACCEPT; fi
    success_echo "防火墙配置完成"
}

# 2. 用户交互与配置
get_user_input() {
    exec < /dev/tty
    read -rp "请输入您的域名: " DOMAIN
    if [[ -z "$DOMAIN" ]]; then error_echo "域名不能为空"; exit 1; fi
    read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD; echo
    if [[ -z "$HY_PASSWORD" ]]; then HY_PASSWORD=$(openssl rand -base64 16); info_echo "自动生成密码: $HY_PASSWORD"; fi
    local default_email="user$(shuf -i 1000-9999 -n 1)@gmail.com"
    read -rp "请输入 ACME 邮箱 (默认: ${default_email}): " input_email; ACME_EMAIL=${input_email:-$default_email}
    read -rp "请输入伪装网址 (默认: https://www.bing.com): " input_fake_url; FAKE_URL=${input_fake_url:-https://www.bing.com}
}

get_user_input_with_cf() {
    get_user_input
    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN; echo
        if [[ -z "$CF_TOKEN" ]]; then warning_echo "Token 不能为空"; continue; fi
        local root_domain=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
        local api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json")
        if echo "$api_result" | jq -e '.success == true and .result[0].id' > /dev/null; then
            CF_ZONE_ID=$(echo "$api_result" | jq -r '.result[0].id'); CF_ACCOUNT_ID=$(echo "$api_result" | jq -r '.result[0].account.id')
            success_echo "Token 验证成功"; break
        else
            error_echo "Token 验证失败或权限不足！"; echo "$api_result" | jq '.errors'
        fi
    done
}

# 3. 安装核心组件
install_hysteria2() {
    info_echo "安装 Hysteria2..."
    local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name == \"hysteria-linux-$ARCH\") | .browser_download_url")
    if [[ -z "$download_url" ]]; then download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-$ARCH\") and (contains(\"avx\") | not)) | .browser_download_url"); fi
    if [[ -z "$download_url" ]]; then error_echo "获取 Hysteria2 下载链接失败"; exit 1; fi
    wget -qO /usr/local/bin/hysteria "$download_url" && chmod +x /usr/local/bin/hysteria
    success_echo "Hysteria2 安装完成"
}

install_cloudflared() {
    if command -v cloudflared &>/dev/null; then CLOUDFLARED_PATH=$(command -v cloudflared); success_echo "Cloudflared 已安装"; return; fi
    info_echo "安装 Cloudflared..."
    case "$OS_TYPE" in "ubuntu" | "debian") curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg|tee /usr/share/keyrings/cloudflare-main.gpg>/dev/null;echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main'|tee /etc/apt/sources.list.d/cloudflared.list; apt-get update -qq && apt-get install -y cloudflared;; *) yum install -y 'dnf-command(config-manager)'>/dev/null 2>&1||true;dnf config-manager --add-repo https://pkg.cloudflare.com/cloudflared-ascii.repo>/dev/null 2>&1;yum install -y cloudflared;; esac
    CLOUDFLARED_PATH=$(command -v cloudflared); if [[ -z "$CLOUDFLARED_PATH" ]]; then error_echo "Cloudflared 安装失败"; exit 1; fi
    success_echo "Cloudflared 安装完成"
}

install_acme_and_cert() {
    info_echo "申请 SSL 证书..."
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then curl https://get.acme.sh | sh -s email="$ACME_EMAIL"; fi
    export CF_Token="$CF_TOKEN"
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --ecc
    mkdir -p /etc/hysteria2/certs
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc --fullchain-file /etc/hysteria2/certs/fullchain.cer --key-file /etc/hysteria2/certs/private.key
    chmod 600 /etc/hysteria2/certs/private.key
    success_echo "证书申请完成"
}

generate_self_signed_cert() {
    info_echo "生成自签名证书..."
    mkdir -p /etc/hysteria2/certs
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/hysteria2/certs/private.key -out /etc/hysteria2/certs/fullchain.cer -subj "/CN=$DOMAIN" 2>/dev/null
    chmod 600 /etc/hysteria2/certs/private.key
    success_echo "自签名证书生成完成"
}

# 4. 配置与服务
generate_hysteria_config() {
    mkdir -p /etc/hysteria2
    local listen_addr=$([[ -n "$IPV4_ADDR" ]] && echo "0.0.0.0:443" || echo "[::]:443")
    cat > /etc/hysteria2/config.yaml << EOF
listen: $listen_addr
tls: { cert: /etc/hysteria2/certs/fullchain.cer, key: /etc/hysteria2/certs/private.key }
auth: { type: password, password: $HY_PASSWORD }
masquerade: { type: proxy, proxy: { url: $FAKE_URL, rewriteHost: true } }
EOF
    success_echo "Hysteria2 配置生成"
}

setup_cloudflared_tunnel() {
    info_echo "设置 Cloudflare Tunnel..."
    warning_echo "请在浏览器中登录并授权您的域名。" && sleep 2
    if ! cloudflared tunnel login; then error_echo "Cloudflared 登录失败"; exit 1; fi
    if ! cloudflared tunnel list -o json | jq -e ".[] | select(.name == \"$TUNNEL_NAME\")" > /dev/null; then
        cloudflared tunnel create "$TUNNEL_NAME" > /dev/null 2>&1
    fi
    TUNNEL_ID=$(cloudflared tunnel list -o json | jq -r ".[] | select(.name == \"$TUNNEL_NAME\") | .id")
    if [[ -z "$TUNNEL_ID" ]]; then error_echo "获取隧道 ID 失败"; exit 1; fi
    mkdir -p /etc/cloudflared/
    
    # [FIXED] 将凭证文件移动到标准配置目录
    mv "/root/.cloudflared/${TUNNEL_ID}.json" "/etc/cloudflared/"
    if [[ ! -f "/etc/cloudflared/${TUNNEL_ID}.json" ]]; then
        error_echo "移动隧道凭证文件失败！"
        exit 1
    fi
    
    local service_addr=$([[ -n "$IPV4_ADDR" ]] && echo "udp://127.0.0.1:443" || echo "udp://[::1]:443")
    cat > /etc/cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json
protocol: quic
ingress:
  - hostname: $DOMAIN
    service: $service_addr
  - service: http_status:404
EOF
    cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN"
    success_echo "Cloudflare Tunnel 配置完成"
}

create_systemd_services() {
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
EOF
    if [[ -n "$CLOUDFLARED_PATH" ]]; then
        cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=hysteria-server.service
BindsTo=hysteria-server.service
[Service]
# [FIXED] 明确指定要运行的隧道 ID
ExecStart=$CLOUDFLARED_PATH tunnel --config /etc/cloudflared/config.yml run $TUNNEL_ID
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
EOF
    fi
}

start_services() {
    systemctl daemon-reload
    systemctl enable --now hysteria-server
    info_echo "等待 Hysteria2 监听 UDP 443..."
    for ((i=1; i<=15; i++)); do
        if ss -ulnp | grep -q ":443.*hysteria"; then
            success_echo "Hysteria2 启动成功"
            if [[ -n "$CLOUDFLARED_PATH" ]]; then
                systemctl enable --now cloudflared
                info_echo "等待 Cloudflared 连接..." && sleep 8
            fi
            return 0
        fi
        echo -n "." && sleep 1
    done
    error_echo "Hysteria2 启动超时！"; journalctl -u hysteria-server -n 20 --no-pager; exit 1
}

save_client_info() {
    local mode="$1"
    mkdir -p /etc/hysteria2
    local server_addr=$([[ "$mode" == "direct" ]] && echo "${IPV4_ADDR:-$IPV6_ADDR}" || echo "$DOMAIN")
    local insecure=$([[ "$mode" == "direct" ]] && echo "true" || echo "false")
    local link_insecure=$([[ "$mode" == "direct" ]] && echo "&insecure=1" || echo "")
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}${link_insecure}#${DOMAIN}-${mode^}"
    cat > /etc/hysteria2/client_info.txt << EOF
# Hysteria2 客户端配置信息 (生成时间: $(date))
---
模式: ${mode^}
服务器地址: $server_addr
端口: 443
密码: $HY_PASSWORD
TLS SNI: $DOMAIN
伪装网址: $FAKE_URL
分享链接: $share_link
Clash.Meta YAML:
- { name: '${DOMAIN}-${mode^}', type: hysteria2, server: '${server_addr}', port: 443, password: '${HY_PASSWORD}', sni: '${DOMAIN}', skip-cert-verify: $insecure, masquerade: '${FAKE_URL}' }
EOF
    cp /etc/hysteria2/client_info.txt /root/hysteria2_client_info.txt
    info_echo "客户端配置信息已保存到 /root/hysteria2_client_info.txt"
}

show_installation_result() {
    clear; cat /etc/hysteria2/client_info.txt
    if [[ "$1" == "direct" ]]; then
        warning_echo "直连模式使用自签名证书, 客户端需开启 'skip-cert-verify' 或 'insecure'"
    else
        warning_echo "DNS 全球同步可能需要几分钟，请耐心等待后再尝试连接。"
    fi
}

# 服务管理菜单
service_management() {
    while true; do
        clear
        systemctl is-active --quiet hysteria-server && echo -e "${GREEN}✓ Hysteria2 : 运行中${ENDCOLOR}" || echo -e "${RED}✗ Hysteria2 : 未运行${ENDCOLOR}"
        if [[ -f /etc/systemd/system/cloudflared.service ]]; then
            systemctl is-active --quiet cloudflared && echo -e "${GREEN}✓ Cloudflared: 运行中${ENDCOLOR}" || echo -e "${RED}✗ Cloudflared: 未运行${ENDCOLOR}"
        fi
        echo -e "${PURPLE}----------------------------------------${ENDCOLOR}"
        read -rp "[1]启动 [2]停止 [3]重启 [4]Hysteria日志 [5]CF日志 [0]返回: " choice
        case $choice in
            1) systemctl start hysteria-server; [[ -f /etc/systemd/system/cloudflared.service ]] && systemctl start cloudflared; sleep 1;;
            2) [[ -f /etc/systemd/system/cloudflared.service ]] && systemctl stop cloudflared; systemctl stop hysteria-server; sleep 1;;
            3) [[ -f /etc/systemd/system/cloudflared.service ]] && systemctl stop cloudflared; systemctl restart hysteria-server; sleep 2; [[ -f /etc/systemd/system/cloudflared.service ]] && systemctl start cloudflared; sleep 1;;
            4) journalctl -u hysteria-server -f --no-pager;;
            5) if [[ -f /etc/systemd/system/cloudflared.service ]]; then journalctl -u cloudflared -f --no-pager; else error_echo "Cloudflared 未安装" && sleep 2; fi;;
            0) return ;;
        esac
    done
}

# 卸载功能
uninstall_hysteria_only() {
    warning_echo "将卸载 Hysteria2 服务，但保留 Cloudflared (如已安装)。"
    read -rp "确定? (y/N): " confirm && [[ "$confirm" != "y" ]] && return 0
    systemctl disable --now hysteria-server 2>/dev/null || true
    rm -f /etc/systemd/system/hysteria-server.service; systemctl daemon-reload
    rm -rf /etc/hysteria2
    success_echo "Hysteria2 已卸载。"
    read -rp "按回车键返回主菜单..."
}

uninstall_all() {
    warning_echo "将卸载 Hysteria2 和 Cloudflare Tunnel..."
    read -rp "确定? (y/N): " confirm && [[ "$confirm" != "y" ]] && return 0
    if [[ -f /etc/hysteria2/uninstall_info.env ]]; then source /etc/hysteria2/uninstall_info.env; fi
    systemctl disable --now hysteria-server cloudflared 2>/dev/null || true
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/cloudflared.service; systemctl daemon-reload
    rm -f /usr/local/bin/hysteria
    if [[ -n "$DOMAIN" ]]; then ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc 2>/dev/null || true; fi
    if [[ -n "$TUNNEL_NAME" ]]; then cloudflared tunnel delete -f "$TUNNEL_NAME" 2>/dev/null || true; fi
    rm -rf /etc/hysteria2 /etc/cloudflared /root/.cloudflared
    success_echo "Hysteria2 和 Cloudflare Tunnel 已卸载。"
    read -rp "按回车键返回主菜单..."
}

# 安装流程
run_install() {
    local mode=$1
    cleanup_previous_installation; detect_system; install_dependencies; check_port_443; detect_network
    CLOUDFLARED_PATH="" 
    if [[ "$mode" == "direct" ]]; then
        get_user_input; install_hysteria2; generate_self_signed_cert
    else
        echo -e "${YELLOW}==================== 重要提示 ====================${ENDCOLOR}"
        info_echo "Cloudflare Tunnel 依赖于 HTTP/3 (QUIC) 协议。"
        success_echo "好消息是: 所有 Cloudflare 区域都已默认开启此功能。"
        warning_echo "如果连接失败，请优先检查客户端 DNS 缓存或等待几分钟。"
        echo -e "${YELLOW}====================================================${ENDCOLOR}"
        read -rp "理解并继续? (Y/n): " confirm
        if [[ "$confirm" == "n" || "$confirm" == "N" ]]; then info_echo "安装已取消"; return 0; fi
        install_cloudflared; get_user_input_with_cf; install_hysteria2; install_acme_and_cert; setup_cloudflared_tunnel
    fi
    generate_hysteria_config; create_systemd_services; configure_firewall; start_services
    save_client_info "$mode"; show_installation_result "$mode"
    read -rp "按回车键返回主菜单..."
}

# 主菜单逻辑
main_menu() {
    check_root; detect_network
    while true; do
        exec < /dev/tty
        show_menu
        read -rp "请选择操作 [0-8]: " choice
        case $choice in
            1) run_install "direct" ;;
            2) run_install "tunnel" ;;
            3) uninstall_hysteria_only ;;
            4) uninstall_all ;;
            5) detect_system; complete_cleanup ;;
            6) service_management ;;
            7) if [[ -f /etc/hysteria2/client_info.txt ]]; then clear; cat /etc/hysteria2/client_info.txt; else error_echo "未找到配置信息"; fi; read -rp "按回车键返回主菜单..." ;;
            8) if [[ -f /etc/hysteria2/uninstall_info.env ]]; then test_connectivity; else error_echo "服务未安装"; fi; read -rp "按回车键返回主菜单..." ;;
            0) exit 0 ;;
            *) error_echo "无效选择" && sleep 1;;
        esac
    done
}

main_menu
