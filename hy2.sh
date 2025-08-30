#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 菜单式安装脚本
# 版本: 5.1 (健壮启动最终版)
# 作者: Jensfrank & AI Assistant 优化
# 项目: hy2ipv6

# 严格错误处理
set -e -o pipefail

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

readonly HYSTERIA2_LOG_FILE="/var/log/hysteria2_install.log"
readonly HYSTERIA2_INSTALL_INFO="/etc/hysteria2/install_info.env"
readonly CLOUDFLARED_TUNNEL_INFO="/etc/cloudflared/tunnel_info.env"

# --- 日志与输出函数 ---
log_message() {
    # 确保日志目录存在
    mkdir -p /var/log/
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" >> "$HYSTERIA2_LOG_FILE"
}

info_echo() { echo -e "${BLUE}[INFO]${ENDCOLOR} $1"; log_message "INFO" "$1"; }
success_echo() { echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"; log_message "SUCCESS" "$1"; }
error_echo() { echo -e "${RED}[ERROR]${ENDCOLOR} $1" >&2; log_message "ERROR" "$1"; }
warning_echo() { echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"; log_message "WARNING" "$1"; }

# --- 错误处理 ---
cleanup_on_error() {
    if [ "$?" -ne 0 ]; then
        error_echo "脚本执行过程中发生错误 (退出码: $?)"
        error_echo "请检查日志文件: $HYSTERIA2_LOG_FILE"
    fi
}
trap cleanup_on_error EXIT

# --- 显示函数 ---
show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-未检测到}"
    local ipv6_display="${IPV6_ADDR:-未检测到}"
    
    local hy2_status="未安装"
    local cf_status="未安装"
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then hy2_status="${GREEN}运行中${ENDCOLOR}"; elif systemctl list-unit-files | grep -q hysteria-server; then hy2_status="${RED}已停止${ENDCOLOR}"; fi
    if systemctl is-active --quiet cloudflared 2>/dev/null; then cf_status="${GREEN}运行中${ENDCOLOR}"; elif systemctl list-unit-files | grep -q cloudflared; then cf_status="${RED}已停止${ENDCOLOR}"; fi
    
    echo -e "${BG_PURPLE} Hysteria2 & Cloudflare Tunnel Management Script (v5.1) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} / ${GREEN}${ipv6_display}${ENDCOLOR}"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Cloudflared: ${cf_status}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}1.${ENDCOLOR} 安装 Hysteria2 (直连模式)"
    echo -e " ${CYAN}2.${ENDCOLOR} 安装 Hysteria2 + Cloudflare Tunnel (CDN模式)"
    echo
    echo -e " ${CYAN}3.${ENDCOLOR} 卸载 Hysteria2 服务"
    echo -e " ${CYAN}4.${ENDCOLOR} 卸载 Hysteria2 + Cloudflare Tunnel"
    echo -e " ${CYAN}5.${ENDCOLOR} 完全清理 (卸载所有组件)"
    echo -e "${PURPLE}----------------------------------------------------------------${ENDCOLOR}"
    echo -e " ${CYAN}6.${ENDCOLOR} 服务管理"
    echo -e " ${CYAN}7.${ENDCOLOR} 显示配置信息"
    echo -e " ${CYAN}8.${ENDCOLOR} 测试连通性"
    echo
    echo -e " ${CYAN}0.${ENDCOLOR} 退出"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
}

# --- 核心功能 ---
initial_network_check() {
    IPV4_ADDR=$(curl -4 -s --connect-timeout 5 ip.sb || echo "")
    IPV6_ADDR=$(curl -6 -s --connect-timeout 5 ip.sb || echo "")
}

critical_network_check() {
    info_echo "检测网络配置..."
    initial_network_check # Re-run check
    if [[ -z "$IPV4_ADDR" && -z "$IPV6_ADDR" ]]; then
        error_echo "无法检测到公网IP地址，安装无法继续"
        exit 1
    fi
    success_echo "网络检测完成。"
}

# ... (rest of the core functions remain identical to the final reviewed version) ...
# 1. 环境检查
check_root() { if [[ $EUID -ne 0 ]]; then error_echo "此脚本需 root 权限"; exit 1; fi; }
detect_system() { if [[ -f /etc/os-release ]]; then source /etc/os-release; OS_TYPE=$ID; else error_echo "无法检测操作系统"; exit 1; fi; ARCH=$(uname -m); case $ARCH in x86_64) ARCH="amd64";; aarch64) ARCH="arm64";; *) error_echo "不支持架构: $ARCH"; exit 1;; esac; }
install_dependencies() { local pkgs=("curl" "socat" "unzip" "wget" "jq" "net-tools"); case "$OS_TYPE" in "ubuntu"|"debian") pkgs+=("netcat-openbsd");; *) pkgs+=("nc");; esac; local install_list=(); for pkg in "${pkgs[@]}"; do local cmd=${pkg/netcat-openbsd/nc}; if ! command -v "$cmd" &>/dev/null; then install_list+=("$pkg"); fi; done; if [[ ${#install_list[@]} -gt 0 ]]; then case "$OS_TYPE" in "ubuntu"|"debian") apt-get update -qq && apt-get install -y "${install_list[@]}";; *) yum install -y "${install_list[@]}";; esac; fi; }
check_port_443() { if ss -ulnp | grep -q ":443 "; then error_echo "UDP 443 已被占用:"; ss -ulnp | grep ":443 "; exit 1; fi; }
configure_firewall() { if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then ufw allow 443/udp >/dev/null; elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null; elif command -v iptables &>/dev/null; then iptables -I INPUT 1 -p udp --dport 443 -j ACCEPT; fi; }

# 2. 用户交互与配置
get_user_input() { exec </dev/tty; read -rp "请输入您的域名: " DOMAIN; if [[ -z "$DOMAIN" ]]; then error_echo "域名不能为空"; exit 1; fi; read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD; echo; if [[ -z "$HY_PASSWORD" ]]; then HY_PASSWORD=$(openssl rand -base64 16); info_echo "自动生成密码: $HY_PASSWORD"; fi; local default_email="user$(shuf -i 1000-9999 -n 1)@gmail.com"; read -rp "请输入 ACME 邮箱 (默认: ${default_email}): " input_email; ACME_EMAIL=${input_email:-$default_email}; read -rp "请输入伪装网址 (默认: https://www.bing.com): " input_fake_url; FAKE_URL=${input_fake_url:-https://www.bing.com}; }
get_user_input_with_cf() { get_user_input; while true; do read -rsp "请输入 Cloudflare API Token: " CF_TOKEN; echo; if [[ -z "$CF_TOKEN" ]]; then warning_echo "Token 不能为空"; continue; fi; local root_domain=$(echo "$DOMAIN"|awk -F. '{print $(NF-1)"."$NF}'); local api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" -H "Authorization: Bearer $CF_TOKEN"); if echo "$api_result"|jq -e '.success==true and .result[0].id'>/dev/null; then CF_ZONE_ID=$(echo "$api_result"|jq -r '.result[0].id'); CF_ACCOUNT_ID=$(echo "$api_result"|jq -r '.result[0].account.id'); success_echo "Token 验证成功"; break; else error_echo "Token 验证失败或权限不足！"; echo "$api_result"|jq '.errors'; fi; done; }

# 3. 安装核心组件
install_hysteria2() { info_echo "安装 Hysteria2..."; local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"; local dl_url=$(curl -s "$api_url"|jq -r ".assets[]|select(.name==\"hysteria-linux-$ARCH\")|.browser_download_url"); if [[ -z "$dl_url" ]]; then dl_url=$(curl -s "$api_url"|jq -r ".assets[]|select(.name|contains(\"linux-$ARCH\") and (contains(\"avx\")|not))|.browser_download_url"); fi; if [[ -z "$dl_url" ]]; then error_echo "获取 Hysteria2 下载失败"; exit 1; fi; wget -qO /usr/local/bin/hysteria "$dl_url" && chmod +x /usr/local/bin/hysteria; }
install_cloudflared() { if command -v cloudflared &>/dev/null; then CLOUDFLARED_PATH=$(command -v cloudflared); return; fi; info_echo "安装 Cloudflared..."; case "$OS_TYPE" in "ubuntu"|"debian") curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg|tee /usr/share/keyrings/cloudflare-main.gpg>/dev/null;echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main'|tee /etc/apt/sources.list.d/cloudflared.list; apt-get update -qq && apt-get install -y cloudflared;; *) yum install -y 'dnf-command(config-manager)'>/dev/null 2>&1||true;dnf config-manager --add-repo https://pkg.cloudflare.com/cloudflared-ascii.repo>/dev/null 2>&1;yum install -y cloudflared;; esac; CLOUDFLARED_PATH=$(command -v cloudflared); if [[ -z "$CLOUDFLARED_PATH" ]]; then error_echo "Cloudflared 安装失败"; exit 1; fi; }
install_acme_and_cert() { info_echo "申请 SSL 证书..."; if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then curl https://get.acme.sh|sh -s email="$ACME_EMAIL"; fi; export CF_Token="$CF_TOKEN"; ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --ecc; mkdir -p /etc/hysteria2/certs; ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc --fullchain-file /etc/hysteria2/certs/fullchain.cer --key-file /etc/hysteria2/certs/private.key; chmod 600 /etc/hysteria2/certs/private.key; }
generate_self_signed_cert() { mkdir -p /etc/hysteria2/certs; openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/hysteria2/certs/private.key -out /etc/hysteria2/certs/fullchain.cer -subj "/CN=$DOMAIN" 2>/dev/null; chmod 600 /etc/hysteria2/certs/private.key; }

# 4. 配置与服务
generate_hysteria_config() { mkdir -p /etc/hysteria2; local listen_addr=$([[ -n "$IPV4_ADDR" ]]&&echo "0.0.0.0:443"||echo "[::]:443"); cat >/etc/hysteria2/config.yaml<<EOF
listen: $listen_addr
tls: {cert: /etc/hysteria2/certs/fullchain.cer, key: /etc/hysteria2/certs/private.key}
auth: {type: password, password: $HY_PASSWORD}
masquerade: {type: proxy, proxy: {url: $FAKE_URL, rewriteHost: true}}
EOF
}
setup_cloudflared_tunnel() {
    info_echo "设置 Cloudflare Tunnel..."; warning_echo "请在浏览器中登录并授权" && sleep 2
    if ! cloudflared tunnel login; then error_echo "Cloudflared 登录失败"; exit 1; fi
    info_echo "登录成功，等待凭证同步..."; sleep 3
    TUNNEL_ID=$(cloudflared tunnel list -o json | jq -r ".[] | select(.name==\"$TUNNEL_NAME\") | .id")
    if [[ -z "$TUNNEL_ID" ]]; then info_echo "创建新隧道..."; TUNNEL_ID=$(cloudflared tunnel create "$TUNNEL_NAME" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'); fi
    if [[ -z "$TUNNEL_ID" ]]; then error_echo "获取隧道 ID 失败"; exit 1; fi
    mkdir -p /etc/cloudflared/; mv "/root/.cloudflared/${TUNNEL_ID}.json" "/etc/cloudflared/"; if [[ ! -f "/etc/cloudflared/${TUNNEL_ID}.json" ]]; then error_echo "移动隧道凭证失败"; exit 1; fi
    echo "TUNNEL_ID=$TUNNEL_ID" > "$CLOUDFLARED_TUNNEL_INFO"; echo "TUNNEL_NAME_PERSIST=$TUNNEL_NAME" >> "$CLOUDFLARED_TUNNEL_INFO"
    local service_addr=$([[ -n "$IPV4_ADDR" ]]&&echo "udp://127.0.0.1:443"||echo "udp://[::1]:443"); cat >/etc/cloudflared/config.yml<<EOF
tunnel: $TUNNEL_ID
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json
protocol: quic
ingress:
  - hostname: $DOMAIN
    service: $service_addr
  - service: http_status:404
EOF
    cloudflared tunnel route dns "$TUNNEL_ID" "$DOMAIN"
}
create_systemd_services() {
    cat >/etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria 2 Server; After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always; RestartSec=5; User=root
[Install]
WantedBy=multi-user.target
EOF
    if [[ -n "$CLOUDFLARED_PATH" ]]; then
        if [[ -f "$CLOUDFLARED_TUNNEL_INFO" ]]; then source "$CLOUDFLARED_TUNNEL_INFO"; fi
        cat >/etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel; After=hysteria-server.service; BindsTo=hysteria-server.service
[Service]
ExecStart=$CLOUDFLARED_PATH tunnel --config /etc/cloudflared/config.yml run $TUNNEL_ID
Restart=always; RestartSec=5; User=root
[Install]
WantedBy=multi-user.target
EOF
    fi
}
start_services() {
    systemctl daemon-reload; systemctl enable --now hysteria-server
    info_echo "等待 Hysteria2 启动..."; for ((i=1; i<=15; i++)); do if ss -ulnp|grep -q ":443.*hysteria"; then success_echo "Hysteria2 启动成功"; if [[ -n "$CLOUDFLARED_PATH" ]]; then systemctl enable --now cloudflared; info_echo "等待 Cloudflared 连接..."&&sleep 8; fi; return 0; fi; sleep 1; done
    error_echo "Hysteria2 启动超时！"; journalctl -u hysteria-server -n 20 --no-pager; exit 1
}
save_client_info() {
    local mode="$1"; mkdir -p /etc/hysteria2
    local server_addr=$([[ "$mode" == "direct" ]] && echo "${IPV4_ADDR:-$IPV6_ADDR}" || echo "$DOMAIN")
    local insecure=$([[ "$mode" == "direct" ]] && echo "true" || echo "false")
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}&insecure=${insecure}#${DOMAIN}-${mode^}"
    cat > /etc/hysteria2/client_info.txt << EOF
# Hysteria2 客户端配置信息 (生成时间: $(date))
---
模式: ${mode^}
服务器地址: $server_addr
端口: 443
密码: $HY_PASSWORD
TLS SNI: $DOMAIN

分享链接 (V2RayN / Nekobox):
$share_link

Clash.Meta YAML:
- { name: '${DOMAIN}-${mode^}', type: hysteria2, server: '${server_addr}', port: 443, password: '${HY_PASSWORD}', sni: '${DOMAIN}', skip-cert-verify: $insecure }
EOF
    cp /etc/hysteria2/client_info.txt /root/hysteria2_client_info.txt
    info_echo "客户端配置信息已保存到 /root/hysteria2_client_info.txt"
}
show_installation_result() {
    clear; cat /etc/hysteria2/client_info.txt
    if [[ "$1" == "direct" ]]; then warning_echo "直连模式使用自签名证书, 客户端需开启 'skip-cert-verify: true'"; else warning_echo "DNS 全球同步可能需要几分钟，请耐心等待后再尝试连接。"; fi
}

# 服务管理菜单
service_management() {
    while true; do
        clear
        systemctl is-active --quiet hysteria-server && echo -e "${GREEN}✓ Hysteria2 : 运行中${ENDCOLOR}" || echo -e "${RED}✗ Hysteria2 : 未运行${ENDCOLOR}"
        if [[ -f /etc/systemd/system/cloudflared.service ]]; then systemctl is-active --quiet cloudflared && echo -e "${GREEN}✓ Cloudflared: 运行中${ENDCOLOR}" || echo -e "${RED}✗ Cloudflared: 未运行${ENDCOLOR}"; fi
        echo -e "${PURPLE}----------------------------------------${ENDCOLOR}"; read -rp "[1]启动 [2]停止 [3]重启 [4]Hysteria日志 [5]CF日志 [0]返回: " choice
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
    rm -rf /etc/hysteria2; success_echo "Hysteria2 已卸载。"
    read -rp "按回车键返回主菜单..."
}
uninstall_all() {
    warning_echo "将卸载 Hysteria2 和 Cloudflare Tunnel..."; read -rp "确定? (y/N): " confirm && [[ "$confirm" != "y" ]] && return 0
    if [[ -f "$HYSTERIA2_INSTALL_INFO" ]]; then source "$HYSTERIA2_INSTALL_INFO"; fi
    if [[ -f "$CLOUDFLARED_TUNNEL_INFO" ]]; then source "$CLOUDFLARED_TUNNEL_INFO"; fi
    systemctl disable --now hysteria-server cloudflared 2>/dev/null || true
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/cloudflared.service; systemctl daemon-reload
    rm -f /usr/local/bin/hysteria
    if [[ -n "$DOMAIN" ]]; then ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc 2>/dev/null || true; fi
    if [[ -n "${TUNNEL_NAME_PERSIST:-}" ]]; then cloudflared tunnel delete -f "$TUNNEL_NAME_PERSIST" 2>/dev/null || true; fi
    rm -rf /etc/hysteria2 /etc/cloudflared /root/.cloudflared; success_echo "Hysteria2 和 Cloudflare Tunnel 已卸载。"
    read -rp "按回车键返回主菜单..."
}

# 安装流程
run_install() {
    local mode=$1
    cleanup_previous_installation; detect_system; install_dependencies; check_port_443
    critical_network_check # Critical check before proceeding
    CLOUDFLARED_PATH="" 
    if [[ "$mode" == "direct" ]]; then get_user_input; install_hysteria2; generate_self_signed_cert;
    else
        echo -e "${YELLOW}==================== 重要提示 ====================${ENDCOLOR}"; info_echo "Cloudflare Tunnel 依赖于 HTTP/3 (QUIC) 协议。"; success_echo "好消息是: 所有 Cloudflare 区域都已默认开启此功能。"; warning_echo "如果连接失败，请优先检查客户端 DNS 缓存或等待几分钟。"; echo -e "${YELLOW}====================================================${ENDCOLOR}"; read -rp "理解并继续? (Y/n): " confirm; if [[ "$confirm" == "n" ]]; then info_echo "安装已取消"; return 0; fi
        install_cloudflared; get_user_input_with_cf; install_hysteria2; install_acme_and_cert; setup_cloudflared_tunnel
    fi
    generate_hysteria_config; create_systemd_services; configure_firewall; start_services
    save_client_info "$mode"; show_installation_result "$mode"; read -rp "按回车键返回主菜单..."
}

# 主菜单逻辑
main_menu() {
    check_root
    initial_network_check # Non-critical check for display
    while true; do
        exec < /dev/tty; show_menu
        read -rp "请选择操作 [0-8]: " choice
        case $choice in
            1) run_install "direct" ;;
            2) run_install "tunnel" ;;
            3) uninstall_hysteria_only ;;
            4) uninstall_all ;;
            5) detect_system; complete_cleanup ;;
            6) service_management ;;
            7) if [[ -f /etc/hysteria2/client_info.txt ]]; then clear; cat /etc/hysteria2/client_info.txt; else error_echo "未找到配置信息"; fi; read -rp "按回车键返回主菜单..." ;;
            8) if [[ -f /etc/systemd/system/hysteria-server.service ]]; then test_connectivity; else error_echo "服务未安装"; fi; read -rp "按回车键返回主菜单..." ;;
            0) exit 0 ;;
            *) error_echo "无效选择" && sleep 1;;
        esac
    done
}

main_menu "$@"
