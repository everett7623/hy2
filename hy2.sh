#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 6.3.0 (全新重写Hysteria2部分)
# 描述: 此脚本用于在 IPv6-Only 或双栈服务器上快速安装和管理 Hysteria2 和 Shadowsocks 服务。
#       Hysteria2 支持自签名证书模式。
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
HY_PASSWORD=""
HY_PORT="443"
FAKE_URL="https://www.bing.com"
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

# --- 安全输入函数 ---
safe_read() {
    local prompt="$1"
    local var_name="$2"
    local input
    
    # 清理输入缓冲区
    while read -t 0; do
        read -r discard
    done
    
    echo -n -e "$prompt"
    if read -r input </dev/tty 2>/dev/null; then
        # 清理输入，去除控制字符和首尾空格
        input=$(echo "$input" | tr -d '[:cntrl:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        eval "$var_name='$input'"
        return 0
    else
        # 如果 /dev/tty 不可用，使用标准输入
        if read -r input; then
            input=$(echo "$input" | tr -d '[:cntrl:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            eval "$var_name='$input'"
            return 0
        fi
    fi
    return 1
}

# --- 安全密码输入函数 ---
safe_read_password() {
    local prompt="$1"
    local var_name="$2"
    local input
    
    # 清理输入缓冲区
    while read -t 0; do
        read -r discard
    done
    
    echo -n -e "$prompt"
    if read -s -r input </dev/tty 2>/dev/null; then
        input=$(echo "$input" | tr -d '[:cntrl:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        eval "$var_name='$input'"
        echo  # 换行
        return 0
    else
        if read -s -r input; then
            input=$(echo "$input" | tr -d '[:cntrl:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            eval "$var_name='$input'"
            echo
            return 0
        fi
    fi
    return 1
}

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
    info_echo "检测网络环境..."
    IPV4_ADDR=$(timeout 5 curl -4 -s https://api.ipify.org 2>/dev/null || echo "")
    IPV6_ADDR=$(timeout 5 curl -6 -s https://api64.ipify.org 2>/dev/null || echo "")
    
    # 清理可能的输入污染
    exec </dev/tty 2>/dev/null || true
}

# --- 安装前检查 ---
pre_install_check() {
    local service_name="$1"
    local service_file=""
    case "$service_name" in
        hysteria) service_file="/etc/systemd/system/hysteria2.service" ;;
        shadowsocks) service_file="/etc/systemd/system/shadowsocks-libev.service" ;;
        *) error_echo "未知的服务名称: $service_name"; return 1 ;;
    esac

    if [[ -f "$service_file" ]]; then
        warning_echo "检测到 ${service_name^} 已安装。"
        local confirm
        safe_read "确定要覆盖安装吗? (y/N): " confirm
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
# Hysteria2 功能模块 (全新重写)
################################################################################

# --- 安装依赖包 ---
hy2_install_deps() {
    info_echo "安装必要依赖包..."
    
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y curl wget tar openssl coreutils >/dev/null 2>&1
            ;;
        "centos" | "rocky" | "almalinux" | "rhel")
            yum install -y curl wget tar openssl coreutils >/dev/null 2>&1
            ;;
        "fedora")
            dnf install -y curl wget tar openssl coreutils >/dev/null 2>&1
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE"
            return 1
            ;;
    esac
    
    if ! command -v curl >/dev/null 2>&1; then
        error_echo "curl 安装失败"
        return 1
    fi
    
    success_echo "依赖包安装完成"
    return 0
}

# --- 下载 Hysteria2 二进制文件 ---
hy2_download_binary() {
    info_echo "下载 Hysteria2 最新版本..."
    
    local download_dir="/tmp/hysteria2"
    rm -rf "$download_dir" && mkdir -p "$download_dir"
    
    # 获取最新版本号
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name"' | head -n1 | cut -d '"' -f4)
    
    if [[ -z "$latest_version" ]]; then
        error_echo "无法获取最新版本信息"
        return 1
    fi
    
    info_echo "最新版本: $latest_version"
    
    # 下载对应架构的二进制文件
    local download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
    
    info_echo "正在下载二进制文件..."
    if ! curl -L -o "$download_dir/hysteria" "$download_url"; then
        error_echo "下载失败"
        return 1
    fi
    
    # 验证文件并安装
    if [[ ! -s "$download_dir/hysteria" ]]; then
        error_echo "下载的文件为空"
        return 1
    fi
    
    chmod +x "$download_dir/hysteria"
    mv "$download_dir/hysteria" /usr/local/bin/hysteria2
    
    # 验证安装
    if ! /usr/local/bin/hysteria2 version >/dev/null 2>&1; then
        error_echo "Hysteria2 二进制文件验证失败"
        return 1
    fi
    
    success_echo "Hysteria2 下载安装完成"
    rm -rf "$download_dir"
    return 0
}

# --- 生成自签名证书 ---
hy2_generate_cert() {
    info_echo "生成自签名SSL证书..."
    
    local cert_dir="/etc/hysteria2"
    mkdir -p "$cert_dir"
    
    # 生成证书
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout "$cert_dir/private.key" \
        -out "$cert_dir/cert.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$HY_DOMAIN" >/dev/null 2>&1
    
    if [[ ! -f "$cert_dir/cert.pem" ]] || [[ ! -f "$cert_dir/private.key" ]]; then
        error_echo "证书生成失败"
        return 1
    fi
    
    success_echo "自签名证书生成完成"
    return 0
}

# --- 生成配置文件 ---
hy2_generate_config() {
    info_echo "生成 Hysteria2 配置文件..."
    
    local config_file="/etc/hysteria2/config.yaml"
    
    cat > "$config_file" << EOF
listen: :$HY_PORT

tls:
  cert: /etc/hysteria2/cert.pem
  key: /etc/hysteria2/private.key

auth:
  type: password
  password: $HY_PASSWORD

masquerade:
  type: proxy
  proxy:
    url: $FAKE_URL
    rewriteHost: true

bandwidth:
  up: 1 gbps
  down: 1 gbps
EOF
    
    if [[ ! -f "$config_file" ]]; then
        error_echo "配置文件生成失败"
        return 1
    fi
    
    success_echo "配置文件生成完成"
    return 0
}

# --- 创建系统服务 ---
hy2_create_systemd_service() {
    info_echo "创建 systemd 服务..."
    
    local service_file="/etc/systemd/system/hysteria2.service"
    
    cat > "$service_file" << EOF
[Unit]
Description=Hysteria2 Server
Documentation=https://hysteria.network/
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/hysteria2 server -c /etc/hysteria2/config.yaml
WorkingDirectory=/etc/hysteria2
Environment=HYSTERIA_LOG_LEVEL=info
Restart=on-failure
RestartSec=10
KillMode=mixed
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hysteria2

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    if ! systemctl enable hysteria2 >/dev/null 2>&1; then
        error_echo "服务启用失败"
        return 1
    fi
    
    success_echo "systemd 服务创建完成"
    return 0
}

# --- 配置防火墙 ---
hy2_setup_firewall() {
    info_echo "配置防火墙规则..."
    
    # UFW (Ubuntu/Debian)
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$HY_PORT"/udp >/dev/null 2>&1
    fi
    
    # Firewalld (CentOS/RHEL/Rocky)
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$HY_PORT"/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    
    success_echo "防火墙配置完成"
    return 0
}

# --- 启动服务 ---
hy2_start_service() {
    info_echo "启动 Hysteria2 服务..."
    
    if ! systemctl start hysteria2; then
        error_echo "服务启动失败，检查日志:"
        journalctl -u hysteria2 --no-pager -n 20
        return 1
    fi
    
    sleep 3
    
    if ! systemctl is-active --quiet hysteria2; then
        error_echo "服务运行异常，请检查配置"
        journalctl -u hysteria2 --no-pager -n 10
        return 1
    fi
    
    success_echo "Hysteria2 服务启动成功"
    return 0
}

# --- 用户输入 ---
hy2_get_user_input() {
    echo
    echo -e "${CYAN}=== Hysteria2 自签名证书安装配置 ===${ENDCOLOR}"
    echo
    
    # 输入 SNI 域名
    while [[ -z "$HY_DOMAIN" ]]; do
        safe_read "请输入 SNI 伪装域名 (例如: wechat.com): " HY_DOMAIN
        if [[ -z "$HY_DOMAIN" ]]; then
            warning_echo "域名不能为空，请重新输入"
        fi
    done
    
    # 输入连接密码
    safe_read_password "请输入连接密码 (回车自动生成): " HY_PASSWORD
    
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    # 确认端口 (默认443)
    local port_input
    safe_read "请输入监听端口 (默认443): " port_input
    if [[ -n "$port_input" ]] && [[ "$port_input" =~ ^[0-9]+$ ]] && [[ "$port_input" -ge 1 ]] && [[ "$port_input" -le 65535 ]]; then
        HY_PORT="$port_input"
    fi
    
    info_echo "配置确认:"
    echo "  - SNI 域名: $HY_DOMAIN"
    echo "  - 连接密码: $HY_PASSWORD"
    echo "  - 监听端口: $HY_PORT"
    echo
    
    local confirm
    safe_read "确认开始安装? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        info_echo "安装已取消"
        return 1
    fi
    
    return 0
}

# --- 生成客户端配置 ---
hy2_generate_client_configs() {
    local server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    local country_code
    country_code=$(curl -s --connect-timeout 3 https://ipapi.co/country_code 2>/dev/null || echo "XX")
    local server_name="Hysteria2-${country_code}-$(date +%m%d)"
    
    echo
    echo "============================================"
    echo -e "${CYAN}📱 Hysteria2 客户端配置${ENDCOLOR}"
    echo "============================================"
    echo
    
    # 1. 原生配置文件
    echo -e "${YELLOW}1. Hysteria2 原生客户端配置 (config.yaml):${ENDCOLOR}"
    echo "-------------------------------------------"
    cat << EOF
server: $server_addr:$HY_PORT
auth: $HY_PASSWORD
tls:
  sni: $HY_DOMAIN
  insecure: true
bandwidth:
  up: 100 mbps
  down: 100 mbps
socks5:
  listen: 127.0.0.1:1080
http:
  listen: 127.0.0.1:8080
EOF
    echo
    
    # 2. 分享链接
    echo -e "${YELLOW}2. 通用分享链接 (适用于 V2rayN, Clash 等):${ENDCOLOR}"
    echo "-------------------------------------------"
    local password_b64=$(printf "%s" "$HY_PASSWORD" | base64 | tr -d '\n')
    local share_link="hysteria2://${password_b64}@${server_addr}:${HY_PORT}/?insecure=1&sni=${HY_DOMAIN}#${server_name}"
    echo "$share_link"
    echo
    
    # 3. Clash Meta 配置
    echo -e "${YELLOW}3. Clash Meta 配置 (添加到 proxies 部分):${ENDCOLOR}"
    echo "-------------------------------------------"
    cat << EOF
  - name: "$server_name"
    type: hysteria2
    server: $server_addr
    port: $HY_PORT
    password: $HY_PASSWORD
    sni: $HY_DOMAIN
    skip-cert-verify: true
    up: 100
    down: 100
EOF
    echo
    
    # 4. Surge 配置
    echo -e "${YELLOW}4. Surge 配置 (添加到 [Proxy] 部分):${ENDCOLOR}"
    echo "-------------------------------------------"
    echo "$server_name = hysteria2, $server_addr, $HY_PORT, password=$HY_PASSWORD, sni=$HY_DOMAIN, skip-cert-verify=true"
    echo
    
    echo "============================================"
    echo -e "${GREEN}配置信息已生成完毕！${ENDCOLOR}"
    echo "============================================"
}

# --- 显示安装结果 ---
hy2_show_install_result() {
    clear
    echo
    echo -e "${BG_PURPLE}                                    ${ENDCOLOR}"
    echo -e "${BG_PURPLE}   🎉 Hysteria2 安装完成！           ${ENDCOLOR}"
    echo -e "${BG_PURPLE}                                    ${ENDCOLOR}"
    echo
    
    echo -e "${PURPLE}=== 服务器信息 ===${ENDCOLOR}"
    echo -e "服务器地址: ${GREEN}${IPV4_ADDR:-$IPV6_ADDR}${ENDCOLOR}"
    echo -e "监听端口:   ${GREEN}$HY_PORT${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "证书类型:   ${YELLOW}自签名证书${ENDCOLOR}"
    echo -e "${PURPLE}==================${ENDCOLOR}"
    
    hy2_generate_client_configs
    
    echo
    echo -e "${YELLOW}注意事项:${ENDCOLOR}"
    echo "• 自签名证书需要客户端启用 '跳过证书验证' 或 '允许不安全连接'"
    echo "• 服务管理命令: systemctl {start|stop|restart|status} hysteria2"
    echo "• 配置文件位置: /etc/hysteria2/config.yaml"
    echo
    
    local dummy
    safe_read "按 Enter 键返回主菜单..." dummy
}

# --- Hysteria2 主安装函数 ---
hy2_install() {
    # 预检查
    pre_install_check "hysteria" || return 1
    
    # 用户输入
    hy2_get_user_input || return 1
    
    # 开始安装流程
    info_echo "开始 Hysteria2 安装流程..."
    
    hy2_install_deps || return 1
    hy2_download_binary || return 1
    hy2_generate_cert || return 1
    hy2_generate_config || return 1
    hy2_create_systemd_service || return 1
    hy2_setup_firewall || return 1
    hy2_start_service || return 1
    
    hy2_show_install_result
}

# --- Hysteria2 卸载 ---
hy2_uninstall() {
    info_echo "正在卸载 Hysteria2..."
    
    # 停止并禁用服务
    systemctl disable --now hysteria2 >/dev/null 2>&1 || true
    
    # 删除文件
    rm -f /etc/systemd/system/hysteria2.service
    rm -f /usr/local/bin/hysteria2
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
    local IPV6_ADDR_LOCAL
    IPV6_ADDR_LOCAL=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary\|deprecated" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [[ -z "$IPV6_ADDR_LOCAL" ]]; then
        error_echo "未检测到有效的公网 IPv6 地址！Shadowsocks 安装需要 IPv6 支持。"
        return 1
    fi
    IPV6_ADDR=${IPV6_ADDR:-$IPV6_ADDR_LOCAL}

    if ! timeout 5 ping6 -c 1 google.com >/dev/null 2>&1; then
        warning_echo "检测到 IPv6 地址 ($IPV6_ADDR)，但似乎无法连接外网。"
        local confirm
        safe_read "是否仍要继续安装？(y/N): " confirm
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
    success_echo "依赖包安装完成。"
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

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then 
        ufw allow "$SS_PORT" >/dev/null 2>&1
    fi
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then 
        firewall-cmd --permanent --add-port="$SS_PORT"/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$SS_PORT"/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi

    success_echo "Shadowsocks 服务已成功启动。"
}

generate_ss_configs() {
    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
    local tag="${country_code}-IPv6-$(date +%m%d)"
    local encoded
    encoded=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)
    local ss_link="ss://${encoded}@[${IPV6_ADDR}]:${SS_PORT}#${tag}"

    echo "# ========== Shadowsocks 客户端配置 =========="
    echo
    echo -e "${CYAN}🚀 SS 分享链接 (通用):${ENDCOLOR}"
    echo "$ss_link"
    echo

    echo -e "${CYAN}⚔️ Clash Meta 紧凑格式 (添加到 proxies 列表):${ENDCOLOR}"
    echo "  - { name: '$tag', type: ss, server: '${IPV6_ADDR}', port: $SS_PORT, password: '$SS_PASSWORD', cipher: $SS_METHOD }"
    echo
    
    echo "# =========================================="
}

ss_display_result() {
    clear
    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 安装完成！ ${ENDCOLOR}"
    echo
    echo -e " ${PURPLE}--- Shadowsocks 基本配置信息 ---${ENDCOLOR}"
    echo -e "   服务器地址: ${GREEN}[$IPV6_ADDR]${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}$SS_PORT${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$SS_PASSWORD${ENDCOLOR}"
    echo -e "   加密方式:   ${GREEN}$SS_METHOD${ENDCOLOR}"
    echo -e " ${PURPLE}-----------------------------------${ENDCOLOR}"
    echo
    
    generate_ss_configs

    if command -v qrencode >/dev/null 2>&1; then
        info_echo "二维码 (请最大化终端窗口显示):"
        qrencode -t ANSIUTF8 "$ss_link" 2>/dev/null || echo "二维码生成失败。"
    else
        warning_echo "qrencode 未安装，无法显示二维码。"
    fi
    
    echo
    local dummy
    safe_read "按 Enter 返回主菜单..." dummy
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
    if systemctl is-active --quiet hysteria2 2>/dev/null; then
        hy2_status="${GREEN}运行中${ENDCOLOR}"
    elif [[ -f /etc/systemd/system/hysteria2.service ]]; then
        hy2_status="${RED}已停止${ENDCOLOR}"
    fi

    local ss_status="未安装"
    if systemctl is-active --quiet shadowsocks-libev 2>/dev/null; then
        ss_status="${GREEN}运行中${ENDCOLOR}"
    elif [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        ss_status="${RED}已停止${ENDCOLOR}"
    fi

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v6.3.0) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}安装选项:${ENDCOLOR}"
    echo -e "   1. 安装 Hysteria2 (${GREEN}自签名证书模式，无需域名解析${ENDCOLOR})"
    echo -e "   2. 安装 Shadowsocks (仅 IPv6)"
    echo
    echo -e " ${CYAN}管理与维护:${ENDCOLOR}"
    echo -e "   3. 服务管理 (启动/停止/日志)"
    echo -e "   4. 显示配置信息"
    echo -e "   5. 卸载服务"
    echo -e "   6. 备份配置"
    echo -e "   7. 系统诊断"
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
        local service_choice
        safe_read "请选择要管理的服务: " service_choice
        case $service_choice in
            1)
                if [[ ! -f /etc/systemd/system/hysteria2.service ]]; then
                    error_echo "Hysteria2 未安装"; sleep 1.5; continue
                fi
                manage_single_service "hysteria2" "Hysteria2"
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
        echo " 4. 查看完整日志"
        echo " 5. 查看配置文件"
        echo " 0. 返回上级菜单"
        echo "----------------"
        local action
        safe_read "请选择操作: " action
        case $action in
            1) systemctl start "$service_name" && success_echo "服务启动成功" || error_echo "服务启动失败"; sleep 1.5 ;;
            2) systemctl stop "$service_name" && success_echo "服务停止成功" || error_echo "服务停止失败"; sleep 1.5 ;;
            3) systemctl restart "$service_name" && success_echo "服务重启成功" || error_echo "服务重启失败"; sleep 1.5 ;;
            4) 
                clear
                journalctl -u "$service_name" --no-pager -e
                local dummy
                safe_read "按 Enter 继续..." dummy
                ;;
            5)
                clear
                echo "=== $display_name 配置文件 ==="
                case "$service_name" in
                    hysteria2)
                        if [[ -f /etc/hysteria2/config.yaml ]]; then cat /etc/hysteria2/config.yaml; else error_echo "配置文件不存在"; fi ;;
                    shadowsocks-libev)
                        if [[ -f /etc/shadowsocks-libev/config.json ]]; then cat /etc/shadowsocks-libev/config.json; else error_echo "配置文件不存在"; fi ;;
                esac
                local dummy
                safe_read "按 Enter 继续..." dummy
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
        local config_choice
        safe_read "请选择: " config_choice
        case $config_choice in
            1) if [[ ! -f /etc/hysteria2/config.yaml ]]; then error_echo "Hysteria2 未安装"; sleep 1.5; else show_hysteria2_config; fi ;;
            2) if [[ ! -f /etc/shadowsocks-libev/config.json ]]; then error_echo "Shadowsocks 未安装"; sleep 1.5; else show_shadowsocks_config; fi ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

show_hysteria2_config() {
    clear
    local password port domain
    
    # 从配置文件读取信息
    if [[ -f /etc/hysteria2/config.yaml ]]; then
        password=$(grep "password:" /etc/hysteria2/config.yaml | awk '{print $2}')
        port=$(grep "listen:" /etc/hysteria2/config.yaml | awk '{print $2}' | cut -d: -f2)
        domain=$(openssl x509 -in /etc/hysteria2/cert.pem -noout -subject 2>/dev/null | grep -o "CN=[^,]*" | cut -d= -f2)
    fi

    echo -e "${BG_PURPLE} Hysteria2 连接信息 ${ENDCOLOR}"
    echo
    echo -e "${PURPLE}=== 基本连接信息 ===${ENDCOLOR}"
    echo -e "服务器地址: ${GREEN}${IPV4_ADDR:-$IPV6_ADDR}${ENDCOLOR}"
    echo -e "服务器端口: ${GREEN}${port:-443}${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}${password}${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}${domain}${ENDCOLOR}"
    echo -e "证书类型:   ${YELLOW}自签名证书${ENDCOLOR}"
    echo -e "允许不安全: ${YELLOW}是${ENDCOLOR}"
    echo -e "${PURPLE}========================${ENDCOLOR}"
    echo
    
    # 重新设置变量用于生成配置
    HY_PASSWORD="$password"
    HY_DOMAIN="$domain"
    HY_PORT="${port:-443}"
    
    hy2_generate_client_configs
    
    local dummy
    safe_read "按 Enter 继续..." dummy
}

show_shadowsocks_config() {
    clear
    local server_port password method
    server_port=$(jq -r '.server_port' /etc/shadowsocks-libev/config.json)
    password=$(jq -r '.password' /etc/shadowsocks-libev/config.json)
    method=$(jq -r '.method' /etc/shadowsocks-libev/config.json)

    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 连接信息 ${ENDCOLOR}"
    echo
    echo -e " ${PURPLE}--- Shadowsocks 基本配置信息 ---${ENDCOLOR}"
    echo -e "   服务器地址: ${GREEN}[$IPV6_ADDR]${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}$server_port${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$password${ENDCOLOR}"
    echo -e "   加密方式:   ${GREEN}$method${ENDCOLOR}"
    echo -e " ${PURPLE}-----------------------------------${ENDCOLOR}"
    echo

    SS_PORT="$server_port"
    SS_PASSWORD="$password"
    SS_METHOD="$method"
    
    generate_ss_configs

    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${CYAN}📱 二维码 (请最大化终端窗口显示):${ENDCOLOR}"
        local encoded
        encoded=$(echo -n "$method:$password" | base64 -w 0)
        local ss_link="ss://${encoded}@[${IPV6_ADDR}]:${server_port}#${IPV6_ADDR}"
        qrencode -t ANSIUTF8 "$ss_link" 2>/dev/null || echo "二维码生成失败。"
    else
        warning_echo "qrencode 未安装，无法显示二维码。"
    fi
    
    echo
    local dummy
    safe_read "按 Enter 继续..." dummy
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
        local uninstall_choice
        safe_read "请选择要卸载的服务: " uninstall_choice
        case $uninstall_choice in
            1)
                if [[ ! -f /etc/systemd/system/hysteria2.service ]]; then error_echo "Hysteria2 未安装"; sleep 1.5; continue; fi
                local confirm
                safe_read "确定要卸载 Hysteria2 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then hy2_uninstall; success_echo "Hysteria2 卸载完成。"; sleep 2; fi
                ;;
            2)
                if [[ ! -f /etc/systemd/system/shadowsocks-libev.service ]]; then error_echo "Shadowsocks 未安装"; sleep 1.5; continue; fi
                local confirm
                safe_read "确定要卸载 Shadowsocks 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then ss_uninstall; success_echo "Shadowsocks 卸载完成。"; sleep 2; fi
                ;;
            3)
                local confirm
                safe_read "确定要卸载所有已安装的服务吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    if [[ -f /etc/systemd/system/hysteria2.service ]]; then hy2_uninstall; fi
                    if [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then ss_uninstall; fi
                    success_echo "所有服务已卸载完成。"; sleep 2
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
    local backed_up=false
    
    mkdir -p "$backup_dir"
    
    if [[ -d /etc/hysteria2 ]]; then
        cp -r /etc/hysteria2 "$backup_dir/"; backed_up=true
    fi
    if [[ -d /etc/shadowsocks-libev ]]; then
        cp -r /etc/shadowsocks-libev "$backup_dir/"; backed_up=true
    fi
    if [[ -f /etc/systemd/system/hysteria2.service ]]; then
        cp /etc/systemd/system/hysteria2.service "$backup_dir/"; backed_up=true
    fi
    if [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        cp /etc/systemd/system/shadowsocks-libev.service "$backup_dir/"; backed_up=true
    fi
    
    if $backed_up; then
        success_echo "备份完成! 备份位置: $backup_dir"
    else
        warning_echo "未找到任何配置文件进行备份。"
        rm -d "$backup_dir"
    fi
    
    local dummy
    safe_read "按 Enter 继续..." dummy
}

system_diagnosis() {
    clear
    echo -e "${CYAN}=== 系统诊断 ===${ENDCOLOR}"
    echo
    
    info_echo "系统信息:"
    echo "  操作系统: $OS_TYPE ($ARCH)"
    echo "  IPv4 地址: ${IPV4_ADDR:-未检测到}"
    echo "  IPv6 地址: ${IPV6_ADDR:-未检测到}"
    echo
    
    info_echo "端口占用 (需要 net-tools):"
    if command -v netstat >/dev/null 2>&1; then
        echo "  - 端口 443 (UDP): $(netstat -ulnp | grep :443 || echo '未占用')"
        if [[ -f /etc/shadowsocks-libev/config.json ]]; then
            local ss_port=$(jq -r '.server_port' /etc/shadowsocks-libev/config.json)
            echo "  - SS 端口 ${ss_port}: $(netstat -anp | grep :${ss_port} || echo '未占用')"
        fi
    else
        warning_echo "  net-tools (netstat) 未安装，无法检查端口。"
    fi
    echo
    
    info_echo "防火墙状态:"
    if command -v ufw >/dev/null 2>&1; then ufw status | sed 's/^/  /';
    elif command -v firewall-cmd >/dev/null 2>&1; then echo "  - $(firewall-cmd --state)";
    else echo "  未检测到 ufw 或 firewalld。"; fi
    echo
    
    info_echo "服务状态:"
    if [[ -f /etc/systemd/system/hysteria2.service ]]; then
        echo "  - Hysteria2: $(systemctl is-active hysteria2)"
    else echo "  - Hysteria2: 未安装"; fi
    if [[ -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        echo "  - Shadowsocks: $(systemctl is-active shadowsocks-libev)"
    else echo "  - Shadowsocks: 未安装"; fi
    
    echo
    local dummy
    safe_read "按 Enter 继续..." dummy
}

################################################################################
# 主程序入口
################################################################################

main() {
    check_root
    detect_system
    detect_network
    
    exec </dev/tty 2>/dev/null || true
    while read -t 0.1 -n 1000 discard 2>/dev/null; do :; done
    
    while true; do
        show_menu
        local choice
        safe_read "请选择操作 [0-7]: " choice
        
        choice=$(echo "$choice" | tr -cd '0-9')
        
        case $choice in
            1) hy2_install ;;
            2) ss_run_install ;;
            3) manage_services ;;
            4) show_config_info ;;
            5) uninstall_services ;;
            6) backup_configs ;;
            7) system_diagnosis ;;
            0) echo; success_echo "感谢使用脚本！"; exit 0 ;;
            *) error_echo "无效的选择 '$choice'，请输入 0-7 之间的数字"; sleep 1 ;;
        esac
    done
}

# 脚本入口点
main "$@"
