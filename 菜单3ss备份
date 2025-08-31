#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 5.7 (最终整合版)

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
    elif [[ -f /etc/systemd/system/hysteria-server.service ]]; then
        hy2_status="${RED}已停止${ENDCOLOR}"
    fi

    local ss_status="未安装"
    if systemctl is-active --quiet shadowsocks-libev 2>/dev/null; then
        ss_status="${GREEN}运行中${ENDCOLOR}"
    elif [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        ss_status="${RED}已停止${ENDCOLOR}"
    fi

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v5.7) ${ENDCOLOR}"
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

# --- 通用系统检查函数 ---
check_root() { if [[ $EUID -ne 0 ]]; then error_echo "此脚本需要 root 权限运行"; exit 1; fi; }
detect_system() {
    source /etc/os-release; OS_TYPE=$ID
    case $(uname -m) in
        x86_64) ARCH="amd64" ;; aarch64) ARCH="arm64" ;;
        *) error_echo "不支持的 CPU 架构: $(uname -m)"; exit 1 ;;
    esac
    info_echo "检测到系统: $PRETTY_NAME ($ARCH)"
}
detect_network() {
    IPV4_ADDR=$(curl -4 -s --connect-timeout 2 https://api.ipify.org)
    IPV6_ADDR=$(curl -6 -s --connect-timeout 2 https://api64.ipify.org)
}

################################################################################
# Hysteria2 功能模块 (双模式)
################################################################################

# --- 共享函数 ---
hy2_install_dependencies() {
    info_echo "检查并安装 Hysteria2 依赖包 (curl, wget, jq, socat)..."
    local packages=("curl" "wget" "jq" "socat")
    case "$OS_TYPE" in
        "ubuntu" | "debian") apt-get update -qq && apt-get install -y "${packages[@]}" ;;
        *) yum install -y "${packages[@]}" ;;
    esac
    success_echo "依赖包检查完成"
}
hy2_install_core() {
    info_echo "安装 Hysteria2 核心..."
    local download_url
    download_url=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r ".assets[] | select(.name == \"hysteria-linux-$ARCH\") | .browser_download_url")
    if [[ -z "$download_url" ]]; then error_echo "获取 Hysteria2 下载链接失败"; return 1; fi
    
    wget -qO /usr/local/bin/hysteria "$download_url"
    chmod +x /usr/local/bin/hysteria
    
    local version
    version=$(/usr/local/bin/hysteria version | head -n 1)
    if [[ -z "$version" ]]; then error_echo "Hysteria2 安装后无法运行，可能是系统兼容性问题。"; return 1; fi
    success_echo "Hysteria2 安装完成, 版本: $version"
}
hy2_generate_config() {
    info_echo "生成 Hysteria2 配置文件 (监听公网)..."
    mkdir -p /etc/hysteria2
    local listen_addr="[::]:443" # 同时监听 IPv4 和 IPv6
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
    success_echo "Hysteria2 配置文件生成完成"
}
hy2_setup_service() {
    info_echo "创建并启动 Hysteria2 systemd 服务..."
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then ufw allow 443/udp >/dev/null; fi
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null; fi
    systemctl enable --now hysteria-server
    sleep 2
    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "Hysteria2 服务启动失败！"; journalctl -u hysteria-server -n 10; return 1
    fi
    success_echo "Hysteria2 服务已成功启动"
}
hy2_uninstall() {
    info_echo "正在卸载 Hysteria2..."; systemctl disable --now hysteria-server >/dev/null 2>&1 || true
    if [[ -f /etc/hysteria2/certs/fullchain.cer ]]; then
        local domain_in_cert
        domain_in_cert=$(openssl x509 -in /etc/hysteria2/certs/fullchain.cer -noout -subject 2>/dev/null | sed -n 's/.*CN = \([^,]*\).*/\1/p')
        if [[ -n "$domain_in_cert" ]] && command -v ~/.acme.sh/acme.sh &> /dev/null; then
             info_echo "正在尝试移除 $domain_in_cert 的 ACME 证书..."
             ~/.acme.sh/acme.sh --remove -d "$domain_in_cert" --ecc >/dev/null 2>&1 || true
        fi
    fi
    rm -f /etc/systemd/system/hysteria-server.service /usr/local/bin/hysteria
    rm -rf /etc/hysteria2
    systemctl daemon-reload
    success_echo "Hysteria2 卸载完成。"
}

# --- 模式 1: 自签名证书 ---
hy2_get_user_input_self_signed() {
    exec < /dev/tty
    read -rp "请输入用于 SNI 的域名 (无需解析, e.g., wechat.com): " HY_DOMAIN
    if [[ -z "$HY_DOMAIN" ]]; then error_echo "域名不能为空"; return 1; fi
    read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD; echo
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
}
hy2_generate_self_signed_cert() {
    info_echo "正在生成自签名证书..."
    mkdir -p /etc/hysteria2/certs
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/hysteria2/certs/private.key \
        -out /etc/hysteria2/certs/fullchain.cer \
        -subj "/CN=$HY_DOMAIN" >/dev/null 2>&1
    success_echo "自签名证书创建成功"
}
hy2_display_result_self_signed() {
    clear
    local server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    success_echo "Hysteria2 (自签名模式) 安装完成！"
    echo
    echo -e "服务器地址: ${GREEN}$server_addr${ENDCOLOR}"
    echo -e "端口:       ${GREEN}443${ENDCOLOR}"
    echo -e "密码:       ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "SNI:        ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "允许不安全: ${YELLOW}true (客户端必须勾选)${ENDCOLOR}"
}
hy2_run_install_self_signed() {
    hy2_install_dependencies && \
    hy2_get_user_input_self_signed && \
    hy2_install_core && \
    hy2_generate_self_signed_cert && \
    hy2_generate_config && \
    hy2_setup_service && \
    hy2_display_result_self_signed || {
        error_echo "Hysteria2 (自签名模式) 安装失败。"
    }
}

# --- 模式 2: ACME 证书 ---
hy2_get_user_input_acme() {
    exec < /dev/tty
    read -rp "请输入您的域名 (必须已托管在 Cloudflare): " HY_DOMAIN
    if [[ -z "$HY_DOMAIN" ]]; then error_echo "域名不能为空"; return 1; fi
    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN; echo
        if [[ -z "$CF_TOKEN" ]]; then warning_echo "Token 不能为空"; continue; fi
        local root_domain=$(echo "$HY_DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
        local api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json")
        if echo "$api_result" | jq -e '.success == true and .result[0].id' > /dev/null; then
            CF_ZONE_ID=$(echo "$api_result" | jq -r '.result[0].id'); CF_ACCOUNT_ID=$(echo "$api_result" | jq -r '.result[0].account.id'); success_echo "Token 验证成功！"; break
        else
            error_echo "Token 验证失败或权限不足！请检查 Token 是否拥有对 '$root_domain' 的 'Zone:Read' 和 'DNS:Edit' 权限。"
        fi
    done
    read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD; echo
    if [[ -z "$HY_PASSWORD" ]]; then HY_PASSWORD=$(openssl rand -base64 16); info_echo "自动生成密码: $HY_PASSWORD"; fi
    ACME_EMAIL="user$(shuf -i 1000-9999 -n 1)@gmail.com"
    read -rp "请输入 ACME 邮箱 (回车默认: ${ACME_EMAIL}): " input_email
    ACME_EMAIL=${input_email:-$ACME_EMAIL}
}
hy2_install_acme_and_cert() {
    info_echo "安装 ACME.sh 并申请 SSL 证书..."
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then curl https://get.acme.sh | sh -s email="$ACME_EMAIL"; fi
    export CF_Token="$CF_TOKEN"; export CF_Account_ID="$CF_ACCOUNT_ID"; export CF_Zone_ID="$CF_ZONE_ID"
    info_echo "正在通过 DNS API 申请证书，此过程可能需要1-2分钟，请稍候..."
    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$HY_DOMAIN" --server letsencrypt --force --ecc; then
        error_echo "SSL 证书申请失败！请检查 acme.sh 的日志输出。"; return 1
    fi
    mkdir -p /etc/hysteria2/certs
    if ! ~/.acme.sh/acme.sh --install-cert -d "$HY_DOMAIN" --ecc --fullchain-file /etc/hysteria2/certs/fullchain.cer --key-file /etc/hysteria2/certs/private.key; then
        error_echo "证书安装步骤失败！"; return 1
    fi
    success_echo "SSL 证书申请并安装完成"
}
hy2_display_result_acme() {
    clear
    success_echo "Hysteria2 (ACME 模式) 安装完成！"
    echo
    echo -e "服务器地址: ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "端口:       ${GREEN}443${ENDCOLOR}"
    echo -e "密码:       ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "SNI:        ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "允许不安全: ${GREEN}false (客户端不应勾选)${ENDCOLOR}"
    echo
    info_echo "请确保您的域名 ($HY_DOMAIN) 已正确解析到此服务器的 IP: ${IPV4_ADDR:-$IPV6_ADDR}"
}
hy2_run_install_acme() {
    hy2_install_dependencies && \
    hy2_get_user_input_acme && \
    hy2_install_core && \
    hy2_install_acme_and_cert && \
    hy2_generate_config && \
    hy2_setup_service && \
    hy2_display_result_acme || {
        error_echo "Hysteria2 (ACME 模式) 安装失败。"
    }
}

################################################################################
# Shadowsocks (IPv6-Only) 功能模块 (完整替换版)
################################################################################
ss_check_ipv6() {
    info_echo "检测 IPv6 网络环境..."
    IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary\|deprecated" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [[ -z "$IPV6_ADDR" ]]; then
        error_echo "未检测到有效的公网 IPv6 地址！"
        return 1
    fi
    if ! ping6 -c 1 -W 3 google.com >/dev/null 2>&1; then
        warning_echo "检测到 IPv6 地址 ($IPV6_ADDR)，但无法连接外网。"
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
            apt-get update -qq
            apt-get install -y shadowsocks-libev qrencode curl
            ;;
        *)
            yum install -y epel-release
            yum install -y shadowsocks-libev qrencode curl
            ;;
    esac
    success_echo "依赖包安装完成"
}

ss_generate_config() {
    info_echo "生成 Shadowsocks 配置文件..."
    SS_PORT=$(shuf -i 20000-40000 -n 1)
    SS_PASSWORD=$(openssl rand -base64 16)
    SS_METHOD="chacha20-ietf-poly1305"
    
    mkdir -p /etc/shadowsocks-libev
    cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "::",
    "server_port": $SS_PORT,
    "password": "$SS_PASSWORD",
    "timeout": 300,
    "method": "$SS_METHOD",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "ipv6_first": true
}
EOF
    success_echo "配置文件生成成功"
}

ss_setup_service() {
    info_echo "创建并启动 Shadowsocks systemd 服务..."
    # shadowsocks-libev 的 service 文件通常由包管理器提供，我们只需重启
    systemctl enable shadowsocks-libev >/dev/null 2>&1
    systemctl restart shadowsocks-libev
    sleep 2
    if ! systemctl is-active --quiet shadowsocks-libev; then
        error_echo "Shadowsocks 服务启动失败！"
        journalctl -u shadowsocks-libev -n 10
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
    echo -e "端口:       ${GREEN}$SS_PORT${ENDCOLOR}"
    echo -e "密码:       ${GREEN}$SS_PASSWORD${ENDCOLOR}"
    echo -e "加密方式:   ${GREEN}$SS_METHOD${ENDCOLOR}"
    echo -e "SS 链接:    ${CYAN}$ss_link${ENDCOLOR}"
    echo
    info_echo "二维码:"
    qrencode -t ANSIUTF8 "$ss_link"
}

ss_run_install() {
    if [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        warning_echo "检测到 Shadowsocks 已安装。"; read -rp "确定要覆盖安装吗? (y/N): " confirm && [[ ! "$confirm" =~ ^[yY]$ ]] && return
        ss_uninstall
    fi
    
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
# 统一管理功能
################################################################################
manage_services() { while true; do clear; echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}\n1. Hysteria2\n2. Shadowsocks(IPv6)\n0. 返回"; read -rp "选择: " c; case $c in 1) [[ -f /etc/systemd/system/hysteria-server.service ]] && manage_single_service "hysteria-server" || { error_echo "Hysteria2 未安装"; sleep 1; };; 2) [[ -f /etc/systemd/system/shadowsocks-libev.service ]] && manage_single_service "shadowsocks-libev" || { error_echo "Shadowsocks 未安装"; sleep 1; };; 0) return ;; esac; done; }
manage_single_service() { local s=$1; while true; do clear; echo "管理 $s"; systemctl status "$s" -n 5 --no-pager; echo "1.启 2.停 3.重启 4.日志 0.返"; read -rp "> " op; case $op in 1) systemctl start "$s";; 2) systemctl stop "$s";; 3) systemctl restart "$s";; 4) journalctl -u "$s" -n 100 --no-pager;; 0) return;; esac; done; }
show_config_info() { clear; # 此功能待完善
    error_echo "显示配置信息功能正在开发中..."
}
uninstall_services() { clear; echo -e "1. Hysteria2\n2. Shadowsocks (IPv6)\n3. 全部"; read -rp "选择卸载: " c; case $c in 1) hy2_uninstall;; 2) ss_uninstall;; 3) hy2_uninstall; ss_uninstall;; esac; }

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
            1) 
                if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
                    warning_echo "检测到 Hysteria2 已安装。"; read -rp "确定要覆盖安装吗? (y/N): " confirm && [[ ! "$confirm" =~ ^[yY]$ ]] && continue
                fi
                hy2_uninstall # 先清理
                hy2_run_install_self_signed 
                ;;
            2) 
                if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
                    warning_echo "检测到 Hysteria2 已安装。"; read -rp "确定要覆盖安装吗? (y/N): " confirm && [[ ! "$confirm" =~ ^[yY]$ ]] && continue
                fi
                hy2_uninstall # 先清理
                hy2_run_install_acme
                ;;
            3) ss_run_install ;;
            4) manage_services ;;
            5) show_config_info ;;
            6) uninstall_services ;;
            7) warning_echo "开发中..." ;;
            8) warning_echo "开发中..." ;;
            0) info_echo "感谢使用!"; exit 0 ;;
            *) error_echo "无效选择";;
        esac
        read -rp "按回车返回主菜单..."
    done
}

main
