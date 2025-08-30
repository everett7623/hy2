#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 菜单式安装脚本
# 版本: 6.2 (增强网络检测)
# 作者: Jensfrank & AI Assistant 优化增强
# 项目: hy2ipv6

# --- 脚本行为设置 ---
# set -e: 命令失败时立即退出
# set -u: 变量未定义时立即退出
# set -o pipefail: 管道中任何命令失败都视为整个管道失败
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
    echo -e "${RED}[ERROR]${ENDCOLOR} $1" >&2
    log_message "ERROR" "$1"
}

warning_echo() {
    echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"
    log_message "WARNING" "$1"
}

# --- 错误处理函数 ---

cleanup_on_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        error_echo "安装过程中发生错误 (退出码: $exit_code)"
        error_echo "详细信息请检查日志文件: /var/log/hysteria2_install.log"
        info_echo "正在尝试清理..."
        systemctl stop hysteria-server cloudflared 2>/dev/null || true
        systemctl disable hysteria-server cloudflared 2>/dev/null || true
    fi
}

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
    if [[ ${#password} -lt 8 ]]; then
        warning_echo "密码长度少于8位，建议使用更强的密码"
    fi
    if [[ ${#password} -gt 128 ]]; then
        error_echo "密码过长 (最大128字符)"
        return 1
    fi
    local strength_score=0
    [[ "$password" =~ [A-Z] ]] && ((strength_score++))
    [[ "$password" =~ [a-z] ]] && ((strength_score++))
    [[ "$password" =~ [0-9] ]] && ((strength_score++))
    [[ "$password" =~ [^a-zA-Z0-9] ]] && ((strength_score++))
    if [[ $strength_score -lt 3 ]]; then
        warning_echo "密码强度较弱，建议包含大小写字母、数字和特殊字符"
    fi
    return 0
}

# --- 显示函数 ---

show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-未检测到}"
    local ipv6_display="${IPV6_ADDR:-未检测到}"
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
    echo -e "${BG_PURPLE} Hysteria2 & Cloudflare Tunnel 管理脚本 (v6.2) ${ENDCOLOR}"
    echo -e "\n ${YELLOW}服务器信息:${ENDCOLOR}"
    echo -e " ├─ IPv4: ${GREEN}${ipv4_display}${ENDCOLOR}"
    echo -e " └─ IPv6: ${GREEN}${ipv6_display}${ENDCOLOR}"
    echo -e "\n ${YELLOW}服务状态:${ENDCOLOR}"
    echo -e " ├─ Hysteria2: ${hy2_status}"
    echo -e " └─ Cloudflared: ${cf_status}\n"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
    echo -e " ${CYAN}1.${ENDCOLOR} 安装 Hysteria2 (直连模式)"
    echo -e " ${CYAN}2.${ENDCOLOR} 安装 Hysteria2 + Cloudflare Tunnel\n"
    echo -e " ${CYAN}3.${ENDCOLOR} 卸载 Hysteria2 服务"
    echo -e " ${CYAN}4.${ENDCOLOR} 卸载 Hysteria2 + Cloudflare Tunnel"
    echo -e " ${CYAN}5.${ENDCOLOR} 完全清理 (删除所有组件和配置)\n"
    echo -e " ${CYAN}6.${ENDCOLOR} 服务管理"
    echo -e " ${CYAN}7.${ENDCOLOR} 显示配置信息"
    echo -e " ${CYAN}8.${ENDCOLOR} 连通性测试"
    echo -e " ${CYAN}9.${ENDCOLOR} 更新组件\n"
    echo -e " ${CYAN}0.${ENDCOLOR} 退出脚本"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════${ENDCOLOR}"
}

# --- 网络检测 (增强版) ---

detect_network() {
    info_echo "检测网络配置..."
    
    # 定义多个IP检测服务作为备用
    local ipv4_svcs=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip")
    local ipv6_svcs=("https://api64.ipify.org" "https://ipv6.icanhazip.com")

    # 尝试获取 IPv4
    for svc in "${ipv4_svcs[@]}"; do
        IPV4_ADDR=$(timeout 5 curl -4 -s --max-time 3 "$svc" 2>/dev/null || true)
        if [[ -n "$IPV4_ADDR" ]]; then
            info_echo "检测到 IPv4 地址: $IPV4_ADDR (via $svc)"
            break
        fi
    done

    # 尝试获取 IPv6
    for svc in "${ipv6_svcs[@]}"; do
        IPV6_ADDR=$(timeout 5 curl -6 -s --max-time 3 "$svc" 2>/dev/null || true)
        if [[ -n "$IPV6_ADDR" ]]; then
            info_echo "检测到 IPv6 地址: $IPV6_ADDR (via $svc)"
            break
        fi
    done
    
    if [[ -z "$IPV4_ADDR" && -z "$IPV6_ADDR" ]]; then
        error_echo "无法检测到任何公网IP地址，请检查服务器的网络连接和DNS设置"
        exit 1
    fi
}

# --- 系统与依赖 ---

detect_system() {
    source /etc/os-release
    OS_TYPE="$ID"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) error_echo "不支持的架构: $ARCH"; exit 1 ;;
    esac
    info_echo "系统检测: $PRETTY_NAME ($ARCH)"
}

install_dependencies() {
    info_echo "检查并安装依赖..."
    local pkgs_to_install=()
    declare -A pkgs=(["curl"]="curl" ["wget"]="wget" ["jq"]="jq" ["openssl"]="openssl")
    case "$OS_TYPE" in
        ubuntu|debian) pkgs["netcat-openbsd"]="nc"; pkgs["dnsutils"]="nslookup" ;;
        *) pkgs["nc"]="nc"; pkgs["bind-utils"]="nslookup" ;;
    esac
    for pkg in "${!pkgs[@]}"; do
        command -v "${pkgs[$pkg]}" &>/dev/null || pkgs_to_install+=("$pkg")
    done
    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
        info_echo "需要安装: ${pkgs_to_install[*]}"
        case "$OS_TYPE" in
            ubuntu|debian) apt-get update -qq && apt-get install -y "${pkgs_to_install[@]}" ;;
            *) command -v dnf &>/dev/null && dnf install -y "${pkgs_to_install[@]}" || yum install -y "${pkgs_to_install[@]}" ;;
        esac || { error_echo "依赖安装失败"; exit 1; }
    fi
    success_echo "依赖检查完成"
}

# --- 安装前检查 ---

check_port_443() {
    info_echo "检查端口 443 占用情况..."
    if ss -ulnp | grep -q ":443\s"; then
        error_echo "UDP 443 端口已被占用"; ss -ulnp | grep ":443\s"; exit 1;
    fi
}

configure_firewall() {
    info_echo "配置防火墙..."
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow 443/udp comment "Hysteria2" >/dev/null
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    else
        warning_echo "未检测到 UFW/Firewalld，请手动开放 UDP 443 端口"
        return
    fi
    success_echo "防火墙配置完成"
}

# --- 用户输入 ---

get_user_input() {
    exec </dev/tty
    while true; do read -rp "请输入您的域名: " DOMAIN; validate_domain "$DOMAIN" && break; done
    while true; do
        read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD; echo
        if [[ -z "$HY_PASSWORD" ]]; then
            HY_PASSWORD=$(openssl rand -base64 16 | tr -d '=+/' | cut -c1-16)
            info_echo "自动生成密码: $HY_PASSWORD"; break
        else
            validate_password "$HY_PASSWORD" && break
        fi
    done
    while true; do read -rp "请输入 ACME 邮箱 (默认: user@example.com): " e; ACME_EMAIL="${e:-user@example.com}"; validate_email "$ACME_EMAIL" && break; done
    read -rp "请输入伪装网址 (默认: https://www.bing.com): " u; FAKE_URL="${u:-https://www.bing.com}"
}

get_user_input_with_cf() {
    get_user_input
    echo; warning_echo "请准备好有相应权限的 Cloudflare API Token"; echo
    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN; echo
        [[ -n "$CF_TOKEN" ]] || { error_echo "Token 不能为空"; continue; }
        info_echo "正在验证 Token..."
        api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json")
        if echo "$api_result" | jq -e '.success==true and .result[0].id' >/dev/null 2>&1; then
            CF_ZONE_ID=$(echo "$api_result" | jq -r '.result[0].id')
            success_echo "Token 验证成功 (Zone: $(echo "$api_result" | jq -r '.result[0].name'))"; break
        else
            error_echo "Token 验证失败！"; echo "$api_result" | jq '.errors' 2>/dev/null
        fi
    done
}

# --- 核心安装函数 ---

install_hysteria2() {
    info_echo "安装 Hysteria2..."
    api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    release_info=$(curl -s "$api_url")
    version=$(echo "$release_info" | jq -r '.tag_name')
    dl_url=$(echo "$release_info" | jq -r ".assets[] | select(.name==\"hysteria-linux-$ARCH\") | .browser_download_url")
    [[ -n "$dl_url" && "$dl_url" != "null" ]] || { error_echo "无法找到 Hysteria2 $ARCH 版本"; exit 1; }
    wget -q --show-progress -O /usr/local/bin/hysteria "$dl_url"
    chmod +x /usr/local/bin/hysteria
    success_echo "Hysteria2 安装完成 ($(/usr/local/bin/hysteria version | head -n1))"
}

install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        CLOUDFLARED_PATH=$(command -v cloudflared); info_echo "Cloudflared 已安装"; return 0;
    fi
    info_echo "安装 Cloudflared..."
    case "$OS_TYPE" in
        ubuntu|debian)
            curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
            echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main' | tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
            apt-get update -qq && apt-get install -y cloudflared
            ;;
        *)
            pkg_ext=$([[ "$ARCH" == "amd64" ]] && echo "x86_64" || echo "aarch64")
            wget -q "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$ARCH.$([[ "$OS_TYPE" == "centos" ]] && echo "rpm" || echo "deb")" -O cloudflared_pkg
            ([[ "$OS_TYPE" == "centos" ]] && rpm -i cloudflared_pkg || dpkg -i cloudflared_pkg)
            rm -f cloudflared_pkg
            ;;
    esac || { error_echo "Cloudflared 安装失败"; exit 1; }
    CLOUDFLARED_PATH=$(command -v cloudflared)
    success_echo "Cloudflared 安装完成"
}

# --- 证书与配置 ---

handle_certs() {
    local mode="$1"
    mkdir -p "$CERTS_DIR"
    if [[ "$mode" == "direct" ]]; then
        info_echo "生成自签名证书..."
        openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
            -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" \
            -keyout "${CERTS_DIR}/private.key" -out "${CERTS_DIR}/fullchain.cer" >/dev/null 2>&1
    else
        info_echo "申请 Let's Encrypt 证书..."
        curl -s https://get.acme.sh | sh -s email="$ACME_EMAIL"
        export CF_Token="$CF_TOKEN"
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --ecc
        ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
            --fullchain-file "${CERTS_DIR}/fullchain.cer" --key-file "${CERTS_DIR}/private.key"
    fi
    chmod 600 "${CERTS_DIR}/private.key"
    success_echo "证书处理完成"
}

generate_hysteria_config() {
    info_echo "生成 Hysteria2 配置文件..."
    mkdir -p "$HY2_CONFIG_DIR"
    listen_addr=$([[ -n "$IPV6_ADDR" ]] && echo "[::]:443" || echo "0.0.0.0:443")
    cat > "${HY2_CONFIG_DIR}/config.yaml" << EOF
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
EOF
    success_echo "Hysteria2 配置生成完成"
}

setup_cloudflared_tunnel() {
    info_echo "设置 Cloudflare Tunnel..."
    info_echo "即将打开浏览器进行授权..." && read -rp "按回车键继续..."
    timeout 300 cloudflared tunnel login || { error_echo "Cloudflared 登录失败或超时"; exit 1; }
    sleep 5
    TUNNEL_ID=$(cloudflared tunnel list -o json 2>/dev/null | jq -r ".[] | select(.name==\"$TUNNEL_NAME\") | .id")
    if [[ -z "$TUNNEL_ID" ]]; then
        TUNNEL_ID=$(cloudflared tunnel create "$TUNNEL_NAME" | grep -oE '[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}')
    fi
    [[ -n "$TUNNEL_ID" ]] || { error_echo "创建/获取隧道失败"; exit 1; }
    mkdir -p "$CF_CONFIG_DIR"
    mv "/root/.cloudflared/${TUNNEL_ID}.json" "${CF_CONFIG_DIR}/"
    echo "TUNNEL_ID=$TUNNEL_ID" > "$TUNNEL_INFO_FILE"; echo "TUNNEL_NAME_PERSIST=$TUNNEL_NAME" >> "$TUNNEL_INFO_FILE"
    service_addr=$([[ -n "$IPV6_ADDR" ]] && echo "udp://[::1]:443" || echo "udp://127.0.0.1:443")
    cat > "${CF_CONFIG_DIR}/config.yml" << EOF
tunnel: $TUNNEL_ID
credentials-file: ${CF_CONFIG_DIR}/${TUNNEL_ID}.json
protocol: quic
ingress:
  - hostname: $DOMAIN
    service: $service_addr
    originRequest:
      noHappyEyeballs: true
  - service: http_status:404
EOF
    cloudflared tunnel route dns "$TUNNEL_ID" "$DOMAIN"
    success_echo "Cloudflare Tunnel 设置完成"
}

# --- 服务管理 ---

create_systemd_services() {
    info_echo "创建 Systemd 服务..."
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
[Install]
WantedBy=multi-user.target
EOF
    if [[ -n "$CLOUDFLARED_PATH" ]]; then
        source "$TUNNEL_INFO_FILE"
        cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=hysteria-server.service
BindsTo=hysteria-server.service
[Service]
ExecStart=$CLOUDFLARED_PATH tunnel --config ${CF_CONFIG_DIR}/config.yml run ${TUNNEL_ID}
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    fi
    systemctl daemon-reload
}

start_services() {
    info_echo "启动服务..."
    systemctl enable --now hysteria-server
    if [[ -f /etc/systemd/system/cloudflared.service ]]; then
        systemctl enable --now cloudflared
        info_echo "等待 Cloudflared 连接 (约15秒)..." && sleep 15
        journalctl -u cloudflared --since="1m ago" | grep -q "Connected to" && success_echo "Cloudflared 连接成功" || warning_echo "Cloudflared 连接状态未知"
    fi
}

# --- 信息保存与显示 ---

save_and_show_info() {
    local mode="$1"
    mkdir -p "$HY2_CONFIG_DIR"
    server_addr=$([[ "$mode" == "direct" ]] && echo "${IPV4_ADDR:-$IPV6_ADDR}" || echo "$DOMAIN")
    insecure=$([[ "$mode" == "direct" ]] && echo "true" || echo "false")
    share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}&insecure=${insecure}#${DOMAIN}-${mode^}"
    
    # 保存安装信息
    {
        echo "INSTALL_DATE=$(date)"; echo "MODE=$mode"; echo "DOMAIN=$DOMAIN"; echo "HY_PASSWORD=$HY_PASSWORD"
        if [[ "$mode" == "tunnel" ]]; then source "$TUNNEL_INFO_FILE"; echo "TUNNEL_ID=$TUNNEL_ID"; fi
    } > "$INSTALL_INFO_FILE"
    
    # 客户端配置
    client_info_file="/root/hysteria2_client_info.txt"
    {
        echo "模式: ${mode^}"; echo "服务器: $server_addr"; echo "端口: 443"; echo "密码: $HY_PASSWORD"
        echo "SNI: $DOMAIN"; echo "跳过证书验证: $insecure"; echo -e "\n分享链接:\n$share_link\n"
        if [[ "$mode" == "direct" ]]; then echo "⚠️ 注意: 直连模式需客户端开启“跳过证书验证”"; else echo "✅ DNS记录全球同步可能需要几分钟"; fi
    } > "$client_info_file"
    cp "$client_info_file" "${HY2_CONFIG_DIR}/"

    clear
    echo -e "${BG_PURPLE} 安装完成 ${ENDCOLOR}\n"
    cat "$client_info_file"
    read -rp "按回车键返回主菜单..."
}

# --- 主安装流程 ---

run_install() {
    local mode="$1"
    # 清理 -> 检测 -> 依赖 -> 检查 -> 输入
    cleanup_previous_installation; detect_system; install_dependencies; check_port_443
    [[ "$mode" == "direct" ]] && get_user_input || get_user_input_with_cf
    # 安装 -> 证书 -> 配置
    install_hysteria2
    [[ "$mode" == "tunnel" ]] && install_cloudflared
    handle_certs "$mode"
    generate_hysteria_config
    [[ "$mode" == "tunnel" ]] && setup_cloudflared_tunnel
    # 服务 -> 启动 -> 保存
    create_systemd_services; start_services; save_and_show_info "$mode"
}

# --- 其他管理功能 ---

cleanup_previous_installation() {
    info_echo "清理旧的安装..."
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    if command -v cloudflared &>/dev/null && [[ -f "$TUNNEL_INFO_FILE" ]]; then
        source "$TUNNEL_INFO_FILE"
        cloudflared tunnel delete -f "${TUNNEL_NAME_PERSIST}" 2>/dev/null || true
    fi
    rm -rf /etc/systemd/system/{hysteria-server,cloudflared}.service "$HY2_CONFIG_DIR" "$CF_CONFIG_DIR" /root/.cloudflared
    systemctl daemon-reload
}

service_management() {
    while true; do
        clear; echo -e "${BG_PURPLE} 服务管理 ${ENDCOLOR}\n"
        systemctl status hysteria-server cloudflared --no-pager
        echo -e "\n1.启动 2.停止 3.重启 4.Hysteria日志 5.Cloudflared日志 0.返回"
        read -rp "请选择操作: " choice
        case $choice in
            1|2|3) op=$([[ "$choice" == 1 ]] && echo "start" || ([[ "$choice" == 2 ]] && echo "stop" || echo "restart")); systemctl "$op" hysteria-server cloudflared 2>/dev/null || systemctl "$op" hysteria-server; ;;
            4) journalctl -u hysteria-server -f ;;
            5) journalctl -u cloudflared -f 2>/dev/null || { error_echo "Cloudflared未安装"; sleep 1; };;
            0) return ;;
        esac
    done
}

uninstall_all() {
    warning_echo "即将卸载，此操作不可逆！" && read -rp "确定继续? (y/N): " c && [[ ! "$c" =~ ^[yY]$ ]] && return
    cleanup_previous_installation
    rm -f /usr/local/bin/hysteria /root/hysteria2_client_info.txt
    if [[ -f "$INSTALL_INFO_FILE" ]]; then
        source "$INSTALL_INFO_FILE"
        [[ -n "$DOMAIN" && -f ~/.acme.sh/acme.sh ]] && ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc
    fi
    if [[ "$1" == "complete" ]]; then
        info_echo "正在卸载Cloudflared软件包..."
        case "$OS_TYPE" in
            ubuntu|debian) apt-get purge -y cloudflared; rm -f /etc/apt/sources.list.d/cloudflared.list ;;
            *) yum remove -y cloudflared; rm -f /etc/yum.repos.d/cloudflared*.repo ;;
        esac
    fi
    success_echo "卸载完成" && sleep 1
}

# --- 主菜单逻辑 ---

main() {
    [[ $EUID -ne 0 ]] && { error_echo "此脚本需要root权限"; exit 1; }
    detect_network
    while true; do
        exec </dev/tty; show_menu
        read -rp "请选择操作 [0-9]: " choice
        case $choice in
            1) run_install "direct" ;;
            2) run_install "tunnel" ;;
            3) uninstall_all ;;
            4) uninstall_all ;;
            5) uninstall_all "complete" ;;
            6) service_management ;;
            7) clear; cat /root/hysteria2_client_info.txt 2>/dev/null || error_echo "未找到配置"; read -rp "按回车返回..." ;;
            8) test_connectivity; read -rp "按回车返回..." ;;
            9) install_hysteria2; [[ -f /etc/systemd/system/cloudflared.service ]] && install_cloudflared; service_management ;;
            0) echo "感谢使用！"; exit 0 ;;
            *) error_echo "无效选择" && sleep 1 ;;
        esac
    done
}

main "$@"
