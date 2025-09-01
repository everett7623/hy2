#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 1.0.3
# 描述: 此脚本用于在 IPv6-Only 或双栈服务器上快速安装和管理 Hysteria2 和 Shadowsocks 服务。
#       Hysteria2 使用自签名证书模式，无需域名。
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
HAS_IPV4=false
HAS_IPV6=false
# Hysteria2 变量
HY_DOMAIN=""
HY_PASSWORD=""
FAKE_URL="https://www.bing.com"
HY_SERVER_IP_CHOICE="" # "ipv4" or "ipv6" for Hysteria2 client config
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
    
    echo -n "$prompt"
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
    
    echo -n "$prompt"
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
    
    # Try to get public IPv4
    IPV4_ADDR=$(timeout 5 curl -4 -s https://api.ipify.org 2>/dev/null || echo "")
    if [[ -n "$IPV4_ADDR" ]]; then
        HAS_IPV4=true
        info_echo "检测到公网 IPv4 地址: $IPV4_ADDR"
    else
        warning_echo "未检测到公网 IPv4 地址。"
        IPV4_ADDR="N/A" # Set to N/A if not found
    fi

    # Try to get public IPv6
    IPV6_ADDR=$(timeout 5 curl -6 -s https://api64.ipify.org 2>/dev/null || echo "")
    if [[ -n "$IPV6_ADDR" ]]; then
        HAS_IPV6=true
        info_echo "通过 api64.ipify.org 检测到公网 IPv6 地址: $IPV6_ADDR"
    else
        # If curl -6 fails, try local detection
        local_ipv6=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary\|deprecated" | awk '{print $2}' | cut -d/ -f1 | head -n1 || echo "")
        if [[ -n "$local_ipv6" ]]; then
            # Verify if local IPv6 is actually routable (ping google.com)
            if timeout 5 ping6 -c 1 google.com >/dev/null 2>&1; then
                IPV6_ADDR="$local_ipv6"
                HAS_IPV6=true
                info_echo "本地检测到可路由公网 IPv6 地址: $IPV6_ADDR"
            else
                warning_echo "本地检测到 IPv6 地址 ($local_ipv6)，但无法连接外网，视为不可用。"
                IPV6_ADDR="N/A"
            fi
        else
            warning_echo "未检测到公网 IPv6 地址。"
            IPV6_ADDR="N/A"
        fi
    fi
    
    # Clean possible input pollution
    exec </dev/tty 2>/dev/null || true
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
# Hysteria2 功能模块 (自签名专用)
################################################################################

# --- 系统依赖安装 ---
hy2_install_system_deps() {
    info_echo "安装系统依赖包..."
    
    local base_packages=("curl" "wget" "openssl" "ca-certificates" "tar" "unzip")
    
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -y >/dev/null 2>&1
            apt-get install -y "${base_packages[@]}" >/dev/null 2>&1
            ;;
        "centos" | "rocky" | "almalinux")
            yum install -y epel-release >/dev/null 2>&1
            yum install -y "${base_packages[@]}" >/dev/null 2>&1
            ;;
        "fedora")
            dnf install -y "${base_packages[@]}" >/dev/null 2>&1
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
    
    local tmp_dir="/tmp/hysteria2_install"
    rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
    cd "$tmp_dir" || return 1
    
    local latest_version
    latest_version=$(timeout 10 curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name"' | cut -d '"' -f 4)
    
    if [[ -z "$latest_version" ]]; then
        error_echo "无法获取最新版本信息"
        return 1
    fi
    
    info_echo "最新版本: $latest_version"
    
    local download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
    
    info_echo "正在下载: $download_url"
    if ! timeout 60 wget -q --show-progress -O hysteria "$download_url"; then
        error_echo "下载失败"
        return 1
    fi
    
    if [[ ! -s hysteria ]] || ! file hysteria | grep -q "executable"; then
        error_echo "下载的文件无效"
        return 1
    fi
    
    chmod +x hysteria
    mv hysteria /usr/local/bin/hysteria
    
    if ! /usr/local/bin/hysteria version >/dev/null 2>&1; then
        error_echo "Hysteria2 安装验证失败"
        return 1
    fi
    
    local version_info
    version_info=$(/usr/local/bin/hysteria version | head -n 1)
    success_echo "Hysteria2 安装成功: $version_info"
    
    cd / && rm -rf "$tmp_dir"
    return 0
}

# --- 自签名证书生成 ---
hy2_create_self_signed_cert() {
    info_echo "生成自签名 SSL 证书..."
    
    mkdir -p /etc/hysteria2/certs
    
    if ! openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/hysteria2/certs/server.key \
        -out /etc/hysteria2/certs/server.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$HY_DOMAIN" >/dev/null 2>&1; then
        error_echo "证书生成失败"
        return 1
    fi
    
    success_echo "自签名证书生成成功"
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
hy2_get_input() {
    echo
    echo -e "${CYAN}=== Hysteria2 自签名证书安装 ===${ENDCOLOR}"
    echo
    
    # SNI 伪装域名
    while true; do
        safe_read "请输入用于 SNI 伪装的域名 (任意有效域名即可，留空默认 amd.com): " HY_DOMAIN
        if [[ -z "$HY_DOMAIN" ]]; then
            HY_DOMAIN="amd.com"
            info_echo "SNI 域名默认为 amd.com"
            break
        elif [[ "$HY_DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            warning_echo "请输入一个有效的域名格式"
        fi
    done

    # 密码
    safe_read_password "请输入连接密码 (留空自动生成): " HY_PASSWORD
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 12)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi

    # IP 地址选择
    if $HAS_IPV4 && $HAS_IPV6; then
        echo
        info_echo "您的服务器同时拥有 IPv4 ($IPV4_ADDR) 和 IPv6 ($IPV6_ADDR) 地址。"
        local ip_choice_valid=false
        while ! $ip_choice_valid; do
            safe_read "请选择 Hysteria2 客户端连接使用的 IP 类型 (1=IPv4, 2=IPv6, 留空默认 IPv4): " ip_choice
            case "$ip_choice" in
                1|"") HY_SERVER_IP_CHOICE="ipv4"; ip_choice_valid=true; info_echo "Hysteria2 将优先使用 IPv4 地址。";;
                2) HY_SERVER_IP_CHOICE="ipv6"; ip_choice_valid=true; info_echo "Hysteria2 将优先使用 IPv6 地址。";;
                *) error_echo "无效选择，请重新输入。";;
            esac
        done
    elif $HAS_IPV4; then
        HY_SERVER_IP_CHOICE="ipv4"
        info_echo "服务器仅有 IPv4 地址，Hysteria2 将使用 IPv4。"
    elif $HAS_IPV6; then
        HY_SERVER_IP_CHOICE="ipv6"
        info_echo "服务器仅有 IPv6 地址，Hysteria2 将使用 IPv6。"
    else
        error_echo "无法检测到有效的公网 IP 地址，Hysteria2 无法安装。"
        return 1
    fi
    
    return 0
}

# --- 生成多种客户端配置格式 ---
generate_hy2_configs() {
    local server_addr_for_config=""
    local display_ip_for_info=""

    if [[ "$HY_SERVER_IP_CHOICE" == "ipv6" ]]; then
        server_addr_for_config="[$IPV6_ADDR]" # IPv6地址需要用方括号括起来
        display_ip_for_info="$IPV6_ADDR"
    elif [[ "$HY_SERVER_IP_CHOICE" == "ipv4" ]]; then
        server_addr_for_config="$IPV4_ADDR"
        display_ip_for_info="$IPV4_ADDR"
    else # Fallback, should not happen if logic is correct
        warning_echo "Hysteria2 IP选择逻辑异常，使用默认IP: ${IPV4_ADDR:-$IPV6_ADDR}"
        server_addr_for_config="${IPV4_ADDR:-[$IPV6_ADDR]}" # Use brackets if it's IPv6
        display_ip_for_info="${IPV4_ADDR:-$IPV6_ADDR}"
    fi

    # When generating links, strip brackets for hostname part
    local display_ip_for_link=$(echo "$server_addr_for_config" | sed 's/\[//;s/\]//')

    # 生成随机标识
    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
    local server_name="🌟Hysteria2-${country_code}-$(date +%m%d)"
    # 自签名模式下，insecure 必须为 true
    local hy2_link="hysteria2://$HY_PASSWORD@$display_ip_for_link:443/?insecure=true&sni=$HY_DOMAIN#$server_name"
    
    echo -e "${PURPLE}Hysteria2配置信息：${ENDCOLOR}"
    echo
    
    # 1. V2rayN / NekoBox / Shadowrocket 配置 (通用链接)
    echo -e "${CYAN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${ENDCOLOR}"
    echo "$hy2_link"
    echo
    
    # 2. Clash Meta 配置
    echo -e "${CYAN}⚔️ Clash Meta 配置:${ENDCOLOR}"
    echo "  - { name: '$server_name', type: hysteria2, server: $display_ip_for_link, port: 443, password: $HY_PASSWORD, sni: $HY_DOMAIN, skip-cert-verify: true, up: 50, down: 100 }"
    echo
    
    # 3. Surge 配置
    echo -e "${CYAN}🌊 Surge 配置:${ENDCOLOR}"
    echo "$server_name = hysteria2, $display_ip_for_link, 443, password=$HY_PASSWORD, sni=$HY_DOMAIN, skip-cert-verify=true"
    echo
}

# --- 显示安装结果 ---
hy2_show_result() {
    clear
    
    echo -e "${BG_PURPLE} Hysteria2 安装完成！ ${ENDCOLOR}"
    echo
    echo -e "${YELLOW}注意: 使用自签名证书，客户端需要启用 '允许不安全连接' 选项${ENDCOLOR}"
    echo
    
    echo -e "${PURPLE}=== 基本连接信息 ===${ENDCOLOR}"
    echo -e "服务器地址: ${GREEN}$( [ "$HY_SERVER_IP_CHOICE" == "ipv6" ] && echo "[$IPV6_ADDR]" || echo "$IPV4_ADDR" )${ENDCOLOR}"
    echo -e "服务器端口: ${GREEN}443${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "允许不安全: ${YELLOW}是${ENDCOLOR}"
    echo -e "${PURPLE}========================${ENDCOLOR}"
    echo
    
    # 生成多种客户端配置
    generate_hy2_configs
    
    local dummy
    safe_read "按 Enter 继续..." dummy
}

# --- 安装主函数 ---
hy2_install() {
    pre_install_check "hysteria" || return 1
    
    hy2_get_input || return 1
    hy2_install_system_deps || return 1
    hy2_download_and_install || return 1
    hy2_create_self_signed_cert || return 1
    hy2_create_config || return 1
    hy2_create_service || return 1
    hy2_show_result
}

# --- Hysteria2 卸载 ---
hy2_uninstall() {
    info_echo "正在卸载 Hysteria2..."
    
    systemctl disable --now hysteria-server >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria2
    systemctl daemon-reload
    
    success_echo "Hysteria2 卸载完成"
}

# --- Hysteria2 应用程序更新 ---
hy2_update() {
    info_echo "检查 Hysteria2 应用程序更新..."
    if [[ ! -f /usr/local/bin/hysteria ]]; then
        error_echo "Hysteria2 未安装，无法更新。"
        local dummy
        safe_read "按 Enter 继续..." dummy
        return 1
    fi

    local current_version
    current_version=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1 | awk '{print $NF}')
    if [[ -z "$current_version" ]]; then
        warning_echo "无法获取当前 Hysteria2 版本，尝试重新安装最新版本。"
        hy2_install || { error_echo "Hysteria2 更新失败。"; return 1; }
        return 0
    fi
    info_echo "当前 Hysteria2 版本: $current_version"

    local latest_version
    latest_version=$(timeout 10 curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name"' | cut -d '"' -f 4)

    if [[ -z "$latest_version" ]]; then
        error_echo "无法获取 Hysteria2 最新版本信息。"
        local dummy
        safe_read "按 Enter 继续..." dummy
        return 1
    fi
    info_echo "Hysteria2 最新版本: $latest_version"

    if [[ "$latest_version" == "$current_version" ]]; then
        info_echo "Hysteria2 已经是最新版本，无需更新。"
    else
        info_echo "发现新版本 ($latest_version)，正在更新 Hysteria2..."
        
        systemctl stop hysteria-server >/dev/null 2>&1 || true
        
        local tmp_dir="/tmp/hysteria2_update"
        rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
        cd "$tmp_dir" || return 1
        
        local download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
        
        info_echo "正在下载: $download_url"
        if ! timeout 60 wget -q --show-progress -O hysteria "$download_url"; then
            error_echo "下载失败"
            cd / && rm -rf "$tmp_dir"
            systemctl start hysteria-server >/dev/null 2>&1 || true
            local dummy
            safe_read "按 Enter 继续..." dummy
            return 1
        fi
        
        if [[ ! -s hysteria ]] || ! file hysteria | grep -q "executable"; then
            error_echo "下载的文件无效"
            cd / && rm -rf "$tmp_dir"
            systemctl start hysteria-server >/dev/null 2>&1 || true
            local dummy
            safe_read "按 Enter 继续..." dummy
            return 1
        fi
        
        chmod +x hysteria
        mv hysteria /usr/local/bin/hysteria
        
        systemctl start hysteria-server
        sleep 3
        
        if systemctl is-active --quiet hysteria-server; then
            success_echo "Hysteria2 更新并启动成功！新版本: $(/usr/local/bin/hysteria version | head -n 1)"
        else
            error_echo "Hysteria2 更新成功但服务启动失败。请检查日志。"
            journalctl -u hysteria-server -n 10 --no-pager
        fi
        cd / && rm -rf "$tmp_dir"
    fi
    local dummy
    safe_read "按 Enter 继续..." dummy
    return 0
}


################################################################################
# Shadowsocks (IPv6-Only) 功能模块
################################################################################
ss_check_ipv6() {
    info_echo "检测 IPv6 网络环境以安装 Shadowsocks..."
    if ! $HAS_IPV6; then
        if $HAS_IPV4; then
            error_echo "检测到您的服务器仅有 IPv4 地址 ($IPV4_ADDR)。Shadowsocks 服务在此脚本中仅支持 IPv6 或双栈 IPv6 优先模式，无法在 IPv4 Only 环境下安装。"
        else
            error_echo "未检测到任何有效的公网 IP 地址，Shadowsocks 无法安装。"
        fi
        local dummy
        safe_read "按 Enter 返回主菜单..." dummy
        return 1
    fi
    # 如果有 IPv6，确保它在全局变量中被正确设置 (在 detect_network 已经做了大部分工作)
    if [[ -z "$IPV6_ADDR" || "$IPV6_ADDR" == "N/A" ]]; then
        error_echo "尽管检测到 IPv6 能力，但未能获取到一个可用的公网 IPv6 地址。Shadowsocks 安装失败。"
        local dummy
        safe_read "按 Enter 返回主菜单..." dummy
        return 1
    fi

    # 再次确认 IPv6 连通性
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
    return 0
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
    if ! command -v ss-server >/dev/null 2>&1; then
        error_echo "shadowsocks-libev 安装失败。"
        return 1
    fi
    success_echo "依赖包安装完成"
    return 0
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
    return 0
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
        ufw allow "$SS_PORT"/tcp >/dev/null 2>&1
        ufw allow "$SS_PORT"/udp >/dev/null 2>&1
    fi
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then 
        firewall-cmd --permanent --add-port="$SS_PORT"/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$SS_PORT"/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi

    success_echo "Shadowsocks 服务已成功启动"
    return 0
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
    
    # 检查 Shadowsocks 监听状态
    info_echo "检查 Shadowsocks 监听状态 (::表示监听所有IPv4/IPv6，确保 IPv6 地址可用):"
    local listening_status=""
    if command -v ss >/dev/null 2>&1; then
        listening_status=$(ss -ltunp | grep ":$SS_PORT" | grep "::")
    elif command -v netstat >/dev/null 2>&1; then
        listening_status=$(netstat -ltunp | grep ":$SS_PORT" | grep "::")
    else
        warning_echo "需要安装 'ss' 或 'netstat' 来检查端口监听状态。"
    fi

    if [[ -n "$listening_status" ]]; then
        success_echo "Shadowsocks 正在监听端口 $SS_PORT on :: (IPv6/IPv4双栈或IPv6)."
        echo -e "$listening_status"
    else
        error_echo "Shadowsocks 未检测到在端口 $SS_PORT on :: (IPv6) 监听。请检查配置和防火墙。"
    fi
    echo

    if command -v qrencode >/dev/null 2>&1; then
        info_echo "二维码 (请最大化终端窗口显示):"
        qrencode -t ANSIUTF8 "$ss_link" 2>/dev/null || echo "二维码生成失败"
    else
        warning_echo "qrencode 未安装，无法显示二维码"
    fi
    
    echo
    local dummy
    safe_read "按 Enter 继续..." dummy
    return 0
}

ss_run_install() {
    # 优先检查 IPv6 可用性
    ss_check_ipv6 || return 1
    
    pre_install_check "shadowsocks" || return 1
    
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

# --- Shadowsocks 应用程序更新 (通过系统包管理器) ---
ss_update() {
    info_echo "检查 Shadowsocks (shadowsocks-libev) 应用程序更新..."
    if [[ ! -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        error_echo "Shadowsocks 未安装，无法更新。"
        local dummy
        safe_read "按 Enter 继续..." dummy
        return 1
    fi

    local ss_is_active=false
    systemctl is-active --quiet shadowsocks-libev && ss_is_active=true

    info_echo "正在通过系统包管理器更新 shadowsocks-libev..."
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y --only-upgrade shadowsocks-libev >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                success_echo "Shadowsocks (shadowsocks-libev) 更新完成。"
            else
                error_echo "Shadowsocks (shadowsocks-libev) 更新失败。"
                local dummy
                safe_read "按 Enter 继续..." dummy
                return 1
            fi
            ;;
        "centos" | "rocky" | "almalinux")
            yum update -y shadowsocks-libev >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                success_echo "Shadowsocks (shadowsocks-libev) 更新完成。"
            else
                error_echo "Shadowsocks (shadowsocks-libev) 更新失败。"
                local dummy
                safe_read "按 Enter 继续..." dummy
                return 1
            fi
            ;;
        "fedora")
            dnf update -y shadowsocks-libev >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                success_echo "Shadowsocks (shadowsocks-libev) 更新完成。"
            else
                error_echo "Shadowsocks (shadowsocks-libev) 更新失败。"
                local dummy
                safe_read "按 Enter 继续..." dummy
                return 1
            fi
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE，无法自动更新 Shadowsocks 包。"
            local dummy
            safe_read "按 Enter 继续..." dummy
            return 1
            ;;
    esac

    if $ss_is_active; then
        info_echo "Shadowsocks 服务正在运行，尝试重启服务..."
        systemctl restart shadowsocks-libev && success_echo "Shadowsocks 服务重启成功。" || error_echo "Shadowsocks 服务重启失败。"
    else
        info_echo "Shadowsocks 服务未运行，无需重启。"
    fi

    local dummy
    safe_read "按 Enter 继续..." dummy
    return 0
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

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v1.0.3) ${ENDCOLOR}"
    echo "项目地址：https://github.com/everett7623/hy2ipv6"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}==========================================================${ENDCOLOR}"
    echo -e "1. 安装 Hysteria2 (自签名证书模式，无需域名解析)"
    echo -e "2. 安装 Shadowsocks (仅 IPv6)"
    echo -e "3. 服务管理 (启动/停止/日志/显示连接配置)"
    echo -e "4. 卸载服务"
    echo -e "5. 更新系统内核"
    echo -e "6. 更新 Hysteria2 应用"
    echo -e "7. 更新 Shadowsocks (系统包)"
    echo -e "0. 退出脚本"    
    echo -e "${PURPLE}==========================================================${ENDCOLOR}"
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
        echo " 5. 显示连接配置"
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
                echo "=== $display_name 服务日志 (最近20行) ==="
                journalctl -u "$service_name" -n 20 --no-pager
                local dummy
                safe_read "按 Enter 继续..." dummy
                ;;
            5) # New option to show connection config within service management
                case "$service_name" in
                    hysteria-server) show_hysteria2_config ;;
                    shadowsocks-libev) show_shadowsocks_config ;;
                esac
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
        local dummy
        safe_read "按 Enter 继续..." dummy
        return
    fi

    local password
    local domain
    password=$(grep "password:" /etc/hysteria2/server.yaml | awk '{print $2}')
    
    if [[ -f /etc/hysteria2/certs/server.crt ]]; then
        domain=$(openssl x509 -in /etc/hysteria2/certs/server.crt -noout -subject | grep -o "CN=[^,]*" | cut -d= -f2)
    fi

    echo -e "${BG_PURPLE} Hysteria2 连接信息 ${ENDCOLOR}"
    echo
    echo -e "${YELLOW}注意: 使用自签名证书，客户端需要启用 '允许不安全连接' 选项${ENDCOLOR}"
    echo
    
    echo -e "${PURPLE}=== 基本连接信息 ===${ENDCOLOR}"
    # 这里根据安装时的选择，重新获取 HY_SERVER_IP_CHOICE
    if [[ -z "$HY_SERVER_IP_CHOICE" ]]; then
        # If script restarted, try to infer from network status
        if $HAS_IPV4; then HY_SERVER_IP_CHOICE="ipv4"; fi
        if $HAS_IPV6; then HY_SERVER_IP_CHOICE="ipv6"; fi # Prioritize IPv6 if both exist and choice wasn't explicitly saved
    fi

    echo -e "服务器地址: ${GREEN}$( [ "$HY_SERVER_IP_CHOICE" == "ipv6" ] && echo "[$IPV6_ADDR]" || echo "$IPV4_ADDR" )${ENDCOLOR}"
    echo -e "服务器端口: ${GREEN}443${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}${password}${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}${domain}${ENDCOLOR}"
    echo -e "证书类型:   ${YELLOW}自签名证书${ENDCOLOR}"
    echo -e "允许不安全: ${YELLOW}是${ENDCOLOR}"
    echo -e "${PURPLE}========================${ENDCOLOR}"
    echo
    
    # Update global variables for generate_hy2_configs
    HY_PASSWORD="$password"
    HY_DOMAIN="$domain"
    
    generate_hy2_configs
    
    local dummy
    safe_read "按 Enter 继续..." dummy
}

show_shadowsocks_config() {
    clear
    if [[ ! -f /etc/shadowsocks-libev/config.json ]]; then
        error_echo "Shadowsocks 配置文件不存在"
        local dummy
        safe_read "按 Enter 继续..." dummy
        return
    fi

    local server_port password method
    server_port=$(grep "server_port" /etc/shadowsocks-libev/config.json | grep -o "[0-9]*")
    password=$(grep "password" /etc/shadowsocks-libev/config.json | cut -d'"' -f4)
    method=$(grep "method" /etc/shadowsocks-libev/config.json | cut -d'"' -f4)

    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 连接信息 ${ENDCOLOR}"
    echo
    echo -e " ${PURPLE}--- Shadowsocks 基本配置信息 ---${ENDCOLOR}"
    echo -e "   服务器地址: ${GREEN}[$IPV6_ADDR]${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}$server_port${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$password${ENDCOLOR}"
    echo -e "   加密方式:   ${GREEN}$method${ENDCOLOR}"
    echo -e " ${PURPLE}-----------------------------------${ENDCOLOR}"
    echo

    # 检查 Shadowsocks 监听状态
    info_echo "检查 Shadowsocks 监听状态 (::表示监听所有IPv4/IPv6，确保 IPv6 地址可用):"
    local listening_status=""
    if command -v ss >/dev/null 2>&1; then
        listening_status=$(ss -ltunp | grep ":$server_port" | grep "::")
    elif command -v netstat >/dev/null 2>&1; then
        listening_status=$(netstat -ltunp | grep ":$server_port" | grep "::")
    else
        warning_echo "需要安装 'ss' 或 'netstat' 来检查端口监听状态。"
    fi

    if [[ -n "$listening_status" ]]; then
        success_echo "Shadowsocks 正在监听端口 $server_port on :: (IPv6/IPv4双栈或IPv6)."
        echo -e "$listening_status"
    else
        error_echo "Shadowsocks 未检测到在端口 $server_port on :: (IPv6) 监听。请检查配置和防火墙。"
    fi
    echo

    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${CYAN}📱 二维码 (请最大化终端窗口显示):${ENDCOLOR}"
        local country_code
        country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
        local tag="${country_code}-IPv6-$(date +%m%d)"
        local encoded
        encoded=$(echo -n "$method:$password" | base64 -w 0)
        local ss_link="ss://${encoded}@[${IPV6_ADDR}]:${server_port}#${tag}"
        qrencode -t ANSIUTF8 "$ss_link" 2>/dev/null || echo "二维码生成失败"
    else
        warning_echo "qrencode 未安装，无法显示二维码"
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
                if [[ ! -f /etc/systemd/system/hysteria-server.service ]]; then
                    error_echo "Hysteria2 未安装"; sleep 1.5; continue
                fi
                local confirm
                safe_read "确定要卸载 Hysteria2 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall
                    local dummy
                    safe_read "按 Enter 继续..." dummy
                fi
                ;;
            2)
                if [[ ! -f /etc/systemd/system/shadowsocks-libev.service ]]; then
                    error_echo "Shadowsocks 未安装"; sleep 1.5; continue
                fi
                local confirm
                safe_read "确定要卸载 Shadowsocks 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    ss_uninstall
                    local dummy
                    safe_read "按 Enter 继续..." dummy
                fi
                ;;
            3)
                local confirm
                safe_read "确定要卸载所有服务吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall
                    ss_uninstall
                    success_echo "所有服务已卸载完成"
                    local dummy
                    safe_read "按 Enter 继续..." dummy
                fi
                ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

# --- 更新系统内核功能 (原 update_kernel) ---
update_system_kernel() {
    clear
    info_echo "尝试更新系统内核..."
    
    local reboot_required=false
    
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            info_echo "正在更新 Debian/Ubuntu 内核和系统..."
            apt-get update -y >/dev/null 2>&1
            apt-get upgrade -y >/dev/null 2>&1
            # 检查是否有新的内核版本可用或已安装
            # More robust check for new kernel version
            if apt-get list --upgradable | grep -q "linux-image"; then
                reboot_required=true
            fi
            success_echo "Debian/Ubuntu 系统更新完成。"
            ;;
        "centos" | "rocky" | "almalinux")
            info_echo "正在更新 CentOS/Rocky/AlmaLinux 内核和系统..."
            yum update -y >/dev/null 2>&1
            # 检查是否有新的内核版本可用或已安装
            if rpm -q kernel | grep -qv "$(uname -r)"; then
                 reboot_required=true
            fi
            success_echo "CentOS/Rocky/AlmaLinux 系统更新完成。"
            ;;
        "fedora")
            info_echo "正在更新 Fedora 内核和系统..."
            dnf update -y >/dev/null 2>&1
            # 检查是否有新的内核版本可用或已安装
            if rpm -q kernel | grep -qv "$(uname -r)"; then
                reboot_required=true
            fi
            success_echo "Fedora 系统更新完成。"
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE，无法自动更新内核。"
            local dummy
            safe_read "按 Enter 继续..." dummy
            return 1
            ;;
    esac

    if $reboot_required; then
        warning_echo "内核已更新，系统可能需要重启才能生效！"
        local confirm
        safe_read "是否立即重启系统? (y/N): " confirm
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            info_echo "系统将在 5 秒后重启..."
            sleep 5
            reboot
        else
            info_echo "请在方便的时候手动重启系统以应用新的内核。"
        fi
    else
        info_echo "内核未更新或无需重启。"
    fi
    local dummy
    safe_read "按 Enter 继续..." dummy
    return 0
}


################################################################################
# 主程序入口
################################################################################

main() {
    check_root
    detect_system
    detect_network
    
    exec </dev/tty 2>/dev/null || true
    while read -t 0.1 -n 1000 discard 2>/dev/null; do
        true
    done
    
    while true; do
        show_menu
        local choice
        safe_read "请选择操作 [0-7]: " choice
        
        choice=$(echo "$choice" | tr -cd '0-9')
        
        case $choice in
            1) hy2_install ;;
            2) ss_run_install ;;
            3) manage_services ;; # This will lead to the sub-menu for managing individual services
            4) uninstall_services ;; # This will lead to the sub-menu for uninstalling individual services
            5) update_system_kernel ;; # Update OS kernel
            6) hy2_update ;; # Update Hysteria2 application
            7) ss_update ;; # Update Shadowsocks application
            0) 
                echo
                success_echo "感谢使用脚本！"
                exit 0 
                ;;
            "")
                warning_echo "请输入一个有效的数字选项 (0-7)"
                sleep 1
                ;;
            *)
                error_echo "无效的选择 '$choice'，请输入 0-7 之间的数字"
                sleep 1
                ;;
        esac
    done
}

# 脚本入口点
main "$@"
