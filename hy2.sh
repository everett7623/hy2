#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks Management Script
# 版本：v1.3.1 完整修复版
# 更新：修复下载超时、IPv6地址处理、服务启动检测
#====================================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

HY2_INSTALL_PATH="/etc/hysteria"
HY2_CERT_PATH="/etc/hysteria/cert"
HY2_CONFIG_PATH="/etc/hysteria/config.yaml"
HY2_SERVICE_PATH="/etc/systemd/system/hysteria.service"
HY2_BINARY_PATH="/usr/local/bin/hysteria"

SS_INSTALL_PATH="/etc/shadowsocks-rust"
SS_CONFIG_PATH="/etc/shadowsocks-rust/config.json"
SS_SERVICE_PATH="/etc/systemd/system/shadowsocks.service"
SS_BINARY_PATH="/usr/local/bin/ssserver"

GITHUB_MIRRORS=(
    "https://github.com"
    "https://mirror.ghproxy.com/https://github.com"
    "https://ghproxy.net/https://github.com"
)

msg() {
    local type="$1"
    local message="$2"
    case "$type" in
        "info") echo -e "${BLUE}[信息]${NC} ${message}" ;;
        "success") echo -e "${GREEN}[成功]${NC} ${message}" ;;
        "warning") echo -e "${YELLOW}[警告]${NC} ${message}" ;;
        "error") echo -e "${RED}[错误]${NC} ${message}" && return 1 ;;
    esac
}

show_progress() {
    local pid=$1
    local spin='-\|/'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        i=$(((i + 1) % 4))
        printf "\r[%c] 正在执行..." "${spin:$i:1}"
        sleep .1
    done
    printf "\r[✓] 操作完成。   \n"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        msg "error" "此脚本需要 root 权限运行。"
        exit 1
    fi
}

fix_hostname_resolution() {
    local hostname
    hostname=$(hostname)
    if sudo -n true 2>&1 | grep -q "unable to resolve host"; then
        if ! grep -q "127.0.0.1\s*${hostname}" /etc/hosts; then
            echo "127.0.0.1 ${hostname}" | sudo tee -a /etc/hosts > /dev/null
            msg "success" "/etc/hosts 已修复"
        fi
    fi
}

check_system() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64 | amd64) arch="amd64" ;;
        aarch64 | arm64) arch="arm64" ;;
        armv7l) arch="armv7" ;;
        *) msg "error" "不支持的架构: ${arch}" && exit 1 ;;
    esac
}

install_dependencies() {
    msg "info" "检查依赖..."
    local pkgs=("curl" "wget" "jq" "openssl" "tar")
    local pkg_manager=""
    
    if command -v apt-get &>/dev/null; then
        pkg_manager="apt-get"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum"
    else
        msg "error" "无法确定包管理器"
        exit 1
    fi

    local missing_pkgs=()
    for pkg in "${pkgs[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            missing_pkgs+=("$pkg")
        fi
    done

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        (sudo "$pkg_manager" update && sudo "$pkg_manager" install -y "${missing_pkgs[@]}") &> /dev/null &
        show_progress $!
    fi
}

get_ips() {
    ipv4=$(timeout 5 curl -s4 ip.sb 2>/dev/null)
    [[ -z "$ipv4" ]] && ipv4=$(timeout 5 curl -s4 ifconfig.me 2>/dev/null)
    [[ -z "$ipv4" ]] && ipv4="N/A"
    
    ipv6=$(timeout 5 curl -s6 ip.sb 2>/dev/null)
    [[ -z "$ipv6" ]] && ipv6=$(timeout 5 curl -s6 ifconfig.me 2>/dev/null)
    [[ -z "$ipv6" ]] && ipv6=$(ip -6 addr show scope global | grep -oP '(?<=inet6 )[0-9a-f:]+(?=/)' | head -1)
    [[ -z "$ipv6" ]] && ipv6="N/A"
}

check_port_available() {
    local port=$1
    if command -v ss &>/dev/null; then
        if ss -tuln | grep -q ":${port} "; then
            msg "warning" "端口 ${port} 已被占用"
            return 1
        fi
    fi
    return 0
}

configure_firewall() {
    local port=$1
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        sudo ufw allow "$port"/tcp >/dev/null 2>&1
        sudo ufw allow "$port"/udp >/dev/null 2>&1
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        sudo firewall-cmd --zone=public --add-port="$port"/tcp --permanent >/dev/null 2>&1
        sudo firewall-cmd --zone=public --add-port="$port"/udp --permanent >/dev/null 2>&1
        sudo firewall-cmd --reload >/dev/null 2>&1
    fi
}

generate_self_signed_cert() {
    local domain=$1
    local cert_path=$2
    local key_path=$3
    
    sudo openssl ecparam -genkey -name prime256v1 -out "${key_path}" 2>/dev/null || return 1
    sudo openssl req -new -x509 -days 36500 \
        -key "${key_path}" \
        -out "${cert_path}" \
        -subj "/CN=${domain}" 2>/dev/null || return 1
    
    sudo chmod 600 "${key_path}"
    sudo chmod 644 "${cert_path}"
    return 0
}

download_with_retry() {
    local url=$1
    local output=$2
    
    for mirror in "${GITHUB_MIRRORS[@]}"; do
        local download_url="${url/https:\/\/github.com/$mirror}"
        if wget --timeout=30 --tries=2 -q --show-progress -O "$output" "$download_url" 2>&1; then
            if [ -f "$output" ] && [ -s "$output" ]; then
                return 0
            fi
        fi
        sleep 2
    done
    return 1
}

install_hy2() {
    msg "info" "开始安装 Hysteria2..."
    
    if [ -f "$HY2_SERVICE_PATH" ]; then
        read -rp "已安装，是否覆盖？(y/N): " overwrite
        [[ ! "$overwrite" =~ ^[yY]$ ]] && return
        sudo systemctl stop hysteria 2>/dev/null
    fi
    
    read -rp "监听端口 (默认 443): " hy2_port
    hy2_port=${hy2_port:-443}
    
    read -rp "连接密码 (留空自动生成): " hy2_password
    if [ -z "$hy2_password" ]; then
        hy2_password=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)
    fi
    
    read -rp "SNI 域名 (默认 www.bing.com): " hy2_sni
    hy2_sni=${hy2_sni:-www.bing.com}
    
    local latest_version
    latest_version=$(curl -s --connect-timeout 10 "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    [[ -z "$latest_version" || "$latest_version" = "null" ]] && latest_version="2.6.4"
    
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="armv7" ;;
    esac
    
    local download_url="https://github.com/apernet/hysteria/releases/download/v${latest_version}/hysteria-linux-${arch}"
    
    if ! download_with_retry "$download_url" "/tmp/hysteria"; then
        msg "error" "下载失败"
        return 1
    fi
    
    sudo install -m 755 /tmp/hysteria "$HY2_BINARY_PATH"
    rm -f /tmp/hysteria
    
    sudo mkdir -p "$HY2_INSTALL_PATH" "$HY2_CERT_PATH"
    
    if ! generate_self_signed_cert "${hy2_sni}" "$HY2_CERT_PATH/cert.crt" "$HY2_CERT_PATH/private.key"; then
        msg "error" "证书生成失败"
        return 1
    fi
    
    cat > /tmp/hy2_config.yaml << EOF
listen: :${hy2_port}
tls:
  cert: ${HY2_CERT_PATH}/cert.crt
  key: ${HY2_CERT_PATH}/private.key
auth:
  type: password
  password: ${hy2_password}
masquerade:
  type: proxy
  proxy:
    url: https://${hy2_sni}
    rewriteHost: true
EOF

    sudo mv /tmp/hy2_config.yaml "$HY2_CONFIG_PATH"
    
    sudo tee "$HY2_SERVICE_PATH" > /dev/null << EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
ExecStart=${HY2_BINARY_PATH} server --config ${HY2_CONFIG_PATH}
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable hysteria 2>/dev/null
    
    if sudo systemctl start hysteria; then
        sleep 3
        if systemctl is-active --quiet hysteria; then
            msg "success" "Hysteria2 安装成功！"
            configure_firewall "$hy2_port"
            echo "${hy2_port}|${hy2_password}|${hy2_sni}" > "${HY2_INSTALL_PATH}/.config_info"
            display_hy2_config
        else
            msg "error" "服务启动失败"
            sudo journalctl -u hysteria -n 30 --no-pager
        fi
    fi
}

display_hy2_config() {
    [ ! -f "$HY2_CONFIG_PATH" ] && return
    
    local port password sni
    if [ -f "${HY2_INSTALL_PATH}/.config_info" ]; then
        IFS='|' read -r port password sni < "${HY2_INSTALL_PATH}/.config_info"
    fi
    
    local server_ip=$ipv4
    [[ "$server_ip" == "N/A" && "$ipv6" != "N/A" ]] && server_ip="[${ipv6}]"
    
    local share_link="hysteria2://${password}@${server_ip}:${port}/?insecure=1&sni=${sni}#Hysteria2"
    
    echo -e "\n${GREEN}=== Hysteria2 配置 ===${NC}"
    echo -e "${YELLOW}分享链接:${NC}"
    echo "${share_link}"
    echo -e "\n${YELLOW}参数:${NC}"
    echo "  服务器: ${server_ip}"
    echo "  端口: ${port}"
    echo "  密码: ${password}"
    echo "  SNI: ${sni}"
    echo "================================"
}

install_ss() {
    msg "info" "开始安装 Shadowsocks..."
    
    get_ips
    
    if [[ "$ipv6" == "N/A" ]]; then
        msg "error" "未检测到 IPv6 地址"
        return 1
    fi
    
    if [ -f "$SS_SERVICE_PATH" ]; then
        read -rp "已安装，是否覆盖？(y/N): " overwrite
        [[ ! "$overwrite" =~ ^[yY]$ ]] && return
        sudo systemctl stop shadowsocks 2>/dev/null
    fi
    
    read -rp "监听端口 (留空随机): " ss_port
    if [ -z "$ss_port" ]; then
        ss_port=$(shuf -i 10000-65000 -n 1)
    fi
    
    read -rp "连接密码 (留空自动生成): " ss_password
    if [ -z "$ss_password" ]; then
        ss_password=$(openssl rand -base64 16)
    fi
    
    echo "加密方式:"
    echo "  1. chacha20-ietf-poly1305 (推荐)"
    echo "  2. aes-256-gcm"
    echo "  3. aes-128-gcm"
    read -rp "选择 [1-3]: " cipher_choice
    
    case "${cipher_choice:-1}" in
        2) local ss_cipher="aes-256-gcm" ;;
        3) local ss_cipher="aes-128-gcm" ;;
        *) local ss_cipher="chacha20-ietf-poly1305" ;;
    esac
    
    local latest_version
    latest_version=$(curl -s --connect-timeout 10 "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    [[ -z "$latest_version" || "$latest_version" = "null" ]] && latest_version="1.23.5"
    
    local arch
    arch=$(uname -m)
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.${arch}-unknown-linux-gnu.tar.xz"
    
    if ! download_with_retry "$download_url" "/tmp/ss.tar.xz"; then
        msg "error" "下载失败"
        return 1
    fi
    
    tar -xf /tmp/ss.tar.xz -C /tmp
    sudo install -m 755 /tmp/ssserver "$SS_BINARY_PATH"
    rm -rf /tmp/ss*
    
    sudo mkdir -p "$SS_INSTALL_PATH"
    
    jq -n \
      --arg server "::" \
      --argjson port "$ss_port" \
      --arg password "$ss_password" \
      --arg method "$ss_cipher" \
      '{
        server: $server,
        server_port: $port,
        password: $password,
        method: $method,
        mode: "tcp_and_udp",
        timeout: 300,
        fast_open: true,
        ipv6_first: true
      }' > /tmp/ss_config.json

    sudo mv /tmp/ss_config.json "$SS_CONFIG_PATH"
    
    sudo tee "$SS_SERVICE_PATH" > /dev/null << 'EOFSERVICE'
[Unit]
Description=Shadowsocks Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks-rust/config.json
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOFSERVICE

    sudo systemctl daemon-reload
    sudo systemctl enable shadowsocks 2>/dev/null
    
    if sudo systemctl start shadowsocks; then
        sleep 5
        if systemctl is-active --quiet shadowsocks; then
            msg "success" "Shadowsocks 安装成功！"
            configure_firewall "$ss_port"
            echo "${ss_port}|${ss_password}|${ss_cipher}" > "${SS_INSTALL_PATH}/.config_info"
            display_ss_config
        else
            msg "error" "服务启动失败"
            sudo journalctl -u shadowsocks -n 30 --no-pager
        fi
    fi
}

display_ss_config() {
    [ ! -f "$SS_CONFIG_PATH" ] && return
    
    local port password cipher
    if [ -f "${SS_INSTALL_PATH}/.config_info" ]; then
        IFS='|' read -r port password cipher < "${SS_INSTALL_PATH}/.config_info"
    else
        port=$(jq -r '.server_port' "$SS_CONFIG_PATH")
        password=$(jq -r '.password' "$SS_CONFIG_PATH")
        cipher=$(jq -r '.method' "$SS_CONFIG_PATH")
    fi
    
    local server_ip=$ipv6
    [[ "$server_ip" == "N/A" ]] && return
    
    local userinfo
    userinfo=$(printf "%s:%s" "${cipher}" "${password}" | base64 -w 0 2>/dev/null || printf "%s:%s" "${cipher}" "${password}" | base64)
    local share_link="ss://${userinfo}@[${server_ip}]:${port}#SS-IPv6"
    
    echo -e "\n${GREEN}=== Shadowsocks 配置 ===${NC}"
    echo -e "${YELLOW}分享链接:${NC}"
    echo "${share_link}"
    echo -e "\n${YELLOW}参数:${NC}"
    echo "  服务器: ${server_ip}"
    echo "  端口: ${port}"
    echo "  密码: ${password}"
    echo "  加密: ${cipher}"
    echo -e "\n${YELLOW}Clash Meta:${NC}"
    echo "- { name: 'SS-IPv6', type: ss, server: '${server_ip}', port: ${port}, cipher: '${cipher}', password: '${password}', udp: true }"
    echo "================================"
}

service_management() {
    clear
    echo "=== 服务管理 ==="
    echo " 1. Hysteria2"
    echo " 2. Shadowsocks"
    echo " 0. 返回"
    read -rp "选择: " choice
    case "$choice" in
        1) manage_hy2 ;;
        2) manage_ss ;;
    esac
}

manage_hy2() {
    [ ! -f "$HY2_SERVICE_PATH" ] && msg "warning" "未安装" && return
    clear
    echo "=== Hysteria2 ==="
    echo " 1. 启动"
    echo " 2. 停止"
    echo " 3. 重启"
    echo " 4. 状态"
    echo " 5. 配置"
    echo " 6. 日志"
    read -rp "选择: " choice
    case "$choice" in
        1) sudo systemctl start hysteria ;;
        2) sudo systemctl stop hysteria ;;
        3) sudo systemctl restart hysteria ;;
        4) systemctl status hysteria --no-pager ;;
        5) display_hy2_config ;;
        6) sudo journalctl -u hysteria -n 50 --no-pager ;;
    esac
    read -n 1 -s -r -p "按任意键..."
}

manage_ss() {
    [ ! -f "$SS_SERVICE_PATH" ] && msg "warning" "未安装" && return
    clear
    echo "=== Shadowsocks ==="
    echo " 1. 启动"
    echo " 2. 停止"
    echo " 3. 重启"
    echo " 4. 状态"
    echo " 5. 配置"
    echo " 6. 日志"
    read -rp "选择: " choice
    case "$choice" in
        1) sudo systemctl start shadowsocks ;;
        2) sudo systemctl stop shadowsocks ;;
        3) sudo systemctl restart shadowsocks ;;
        4) systemctl status shadowsocks --no-pager ;;
        5) display_ss_config ;;
        6) sudo journalctl -u shadowsocks -n 50 --no-pager ;;
    esac
    read -n 1 -s -r -p "按任意键..."
}

uninstall_menu() {
    clear
    echo "=== 卸载 ==="
    echo " 1. Hysteria2"
    echo " 2. Shadowsocks"
    echo " 3. 全部"
    read -rp "选择: " choice
    case "$choice" in
        1) uninstall_hy2 ;;
        2) uninstall_ss ;;
        3) uninstall_hy2; uninstall_ss ;;
    esac
}

uninstall_hy2() {
    read -rp "确认卸载 Hysteria2？(y/N): " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    sudo systemctl stop hysteria 2>/dev/null
    sudo systemctl disable hysteria 2>/dev/null
    sudo rm -f "$HY2_SERVICE_PATH" "$HY2_BINARY_PATH"
    sudo rm -rf "$HY2_INSTALL_PATH"
    sudo systemctl daemon-reload
    msg "success" "已卸载"
}

uninstall_ss() {
    read -rp "确认卸载 Shadowsocks？(y/N): " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    sudo systemctl stop shadowsocks 2>/dev/null
    sudo systemctl disable shadowsocks 2>/dev/null
    sudo rm -f "$SS_SERVICE_PATH" "$SS_BINARY_PATH"
    sudo rm -rf "$SS_INSTALL_PATH"
    sudo systemctl daemon-reload
    msg "success" "已卸载"
}

main_menu() {
    clear
    get_ips
    
    local hy2_status="${RED}未安装${NC}"
    systemctl is-active --quiet hysteria 2>/dev/null && hy2_status="${GREEN}运行中${NC}"
    
    local ss_status="${RED}未安装${NC}"
    systemctl is-active --quiet shadowsocks 2>/dev/null && ss_status="${GREEN}运行中${NC}"

    echo "========================================"
    echo -e "  ${BLUE}Hysteria2 & Shadowsocks (v1.3.1)${NC}"
    echo "========================================"
    echo -e " IPv4: ${YELLOW}${ipv4}${NC}"
    echo -e " IPv6: ${YELLOW}${ipv6}${NC}"
    echo -e " Hysteria2: ${hy2_status}"
    echo -e " Shadowsocks: ${ss_status}"
    echo "========================================"
    echo " 1. 安装 Hysteria2"
    echo " 2. 安装 Shadowsocks (IPv6)"
    echo " 3. 服务管理"
    echo " 4. 卸载"
    echo " 0. 退出"
    echo "========================================"
    
    read -rp "选择: " choice
    case "$choice" in
        1) install_hy2 ;;
        2) install_ss ;;
        3) service_management ;;
        4) uninstall_menu ;;
        0) exit 0 ;;
    esac
}

main() {
    check_root
    fix_hostname_resolution
    check_system
    install_dependencies
    
    while true; do
        main_menu
        read -n 1 -s -r -p "按任意键继续..."
    done
}

main "$@"
