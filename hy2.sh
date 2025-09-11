#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 1.0.20
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
SS_METHOD="chacha20-ietf-poly1305" # 默认加密方式
SS_SERVER_IP_CHOICE="" # "ipv4" or "ipv6" for Shadowsocks client config

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
    # 局部重定向，避免影响整个脚本
    while read -t 0; do
        read -r discard
    done
    
    echo -n "$prompt"
    # 尝试从 /dev/tty 读取，如果失败则回退到标准输入 (此脚本为交互式，通常 /dev/tty 可用)
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
        # Verify if this IPv6 is actually routable (ping google.com)
        if timeout 5 ping6 -c 1 google.com >/dev/null 2>&1; then
            HAS_IPV6=true
            info_echo "通过 api64.ipify.org 检测到可路由公网 IPv6 地址: $IPV6_ADDR"
        else
            warning_echo "通过 api64.ipify.org 检测到 IPv6 地址 ($IPV6_ADDR)，但无法连接外网，尝试本地检测。"
            IPV6_ADDR="N/A" # Clear for re-attempt
        fi
    fi

    # If IPV6_ADDR is still not set or not routable via curl, try local detection
    if ! $HAS_IPV6; then
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
    
    # 移除全局 exec 重定向，避免干扰后续输入
    # exec </dev/tty 2>/dev/null || true # <--- 已移除
}

# --- 检查并建议创建 Swap (仅提示，不强制中断) ---
check_and_create_swap() {
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))
    local swap_file="/swapfile"
    local swap_size_mb=1024 # 1GB swap

    if (( total_ram_mb < 512 )); then
        local current_swap_mb=$(free -m | grep Swap | awk '{print $2}')
        if (( current_swap_mb == 0 )); then
            warning_echo "检测到系统内存 ($total_ram_mb MB) 较低且无 Swap 空间。在执行安装操作前，建议创建 Swap 文件以避免内存不足。"
            if [ -f "$swap_file" ] && grep -q "$swap_file" /etc/fstab; then
                info_echo "已检测到现有 Swap 文件 ($swap_file) 且已配置永久启用，无需操作。"
                return 0
            fi
            local confirm
            safe_read "是否创建 ${swap_size_mb}MB 的 Swap 文件? (y/N): " confirm
            if [[ "$confirm" =~ ^[yY]$ ]]; then
                info_echo "正在创建 ${swap_size_mb}MB Swap 文件..."
                dd if=/dev/zero of=$swap_file bs=1M count=$swap_size_mb >/dev/null 2>&1 || { error_echo "Swap 文件创建失败"; return 1; }
                chmod 600 "$swap_file"
                mkswap "$swap_file" >/dev/null 2>&1 || { error_echo "mkswap 失败"; rm -f "$swap_file"; return 1; }
                swapon "$swap_file" || { error_echo "swapon失败"; rm -f "$swap_file"; return 1; }
                
                if ! grep -q "$swap_file" /etc/fstab; then
                    echo "$swap_file none swap sw 0 0" >> /etc/fstab
                fi
                success_echo "Swap 文件创建并启用成功。"
            else
                info_echo "用户选择不创建 Swap 文件。请注意在后续安装时可能需要手动创建。"
            fi
        fi
    fi
    return 0
}

# --- 强制检查并创建 Swap (在服务安装前调用，低内存时强制) ---
enforce_swap_if_low_memory() {
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))
    local swap_file="/swapfile"
    local swap_size_mb=1024 # 1GB swap

    if (( total_ram_mb < 512 )); then
        local current_swap_mb=$(free -m | grep Swap | awk '{print $2}')
        if (( current_swap_mb == 0 )); then
            error_echo "检测到系统内存 ($total_ram_mb MB) 极低且无 Swap 空间。"
            warning_echo "强烈建议创建 ${swap_size_mb}MB 的 Swap 文件以确保安装成功和系统稳定性。否则安装可能会失败甚至导致服务闪退。"
            local confirm
            safe_read "是否立即创建 Swap 文件? (y/N): " confirm
            if [[ "$confirm" =~ ^[yY]$ ]]; then
                info_echo "正在创建 ${swap_size_mb}MB Swap 文件..."
                dd if=/dev/zero of=$swap_file bs=1M count=$swap_size_mb >/dev/null 2>&1 || { error_echo "Swap 文件创建失败"; return 1; }
                chmod 600 "$swap_file"
                mkswap "$swap_file" >/dev/null 2>&1 || { error_echo "mkswap 失败"; rm -f "$swap_file"; return 1; }
                swapon "$swap_file" || { error_echo "swapon失败"; rm -f "$swap_file"; return 1; }
                
                if ! grep -q "$swap_file" /etc/fstab; then
                    echo "$swap_file none swap sw 0 0" >> /etc/fstab
                fi
                success_echo "Swap 文件创建并启用成功。"
                return 0 # Swap created successfully
            else
                error_echo "用户拒绝创建 Swap 文件。安装已取消，建议在充足内存或有 Swap 的环境下重试。"
                local dummy
                safe_read "按 Enter 返回主菜单..." dummy
                return 1 # 用户拒绝，阻止安装继续
            fi
        else
            info_echo "检测到系统内存 ($total_ram_mb MB) 较低，但已存在 ${current_swap_mb}MB Swap 空间，可以继续安装。"
            return 0 # Swap 存在，继续
        fi
    fi
    return 0 # 内存充足，无需 Swap
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
    local install_log="/tmp/hy2_install_deps.log" # Hysteria2依赖安装日志

    case "$OS_TYPE" in
        "ubuntu" | "debian")
            info_echo "正在更新 apt 包列表 (日志输出到 $install_log)..."
            if ! apt-get update -qq >"$install_log" 2>&1; then
                error_echo "apt update 失败。请检查日志: $install_log"
                cat "$install_log" >&2
                # 尝试修复 Debian/Ubuntu 的源问题
                change_debian_apt_sources || { error_echo "尝试修复 APT 源失败。请手动检查并修复 /etc/apt/sources.list 文件。"; return 1; }
                if ! apt-get update -qq >"$install_log" 2>&1; then # 换源后再次尝试更新
                    error_echo "换源后 apt update 仍然失败。请检查日志: $install_log"
                    cat "$install_log" >&2
                    return 1
                fi
            fi
            info_echo "正在安装基本依赖: ${base_packages[*]} (日志输出到 $install_log)..."
            if ! apt-get install -y "${base_packages[@]}" >"$install_log" 2>&1; then
                error_echo "基本依赖安装失败。请检查日志: $install_log"
                cat "$install_log" >&2
                return 1
            fi
            ;;
        "centos" | "rocky" | "almalinux")
            info_echo "正在安装 EPEL 仓库 (日志输出到 $install_log)..."
            if ! yum install -y epel-release >"$install_log" 2>&1; then
                error_echo "EPEL 仓库安装失败。请检查日志: $install_log"
                cat "$install_log" >&2
                return 1
            fi
            info_echo "正在安装基本依赖: ${base_packages[*]} (日志输出到 $install_log)..."
            if ! yum install -y "${base_packages[@]}" >"$install_log" 2>&1; then
                error_echo "基本依赖安装失败。请检查日志: $install_log"
                cat "$install_log" >&2
                return 1
            fi
            ;;
        "fedora")
            info_echo "正在安装基本依赖: ${base_packages[*]} (日志输出到 $install_log)..."
            if ! dnf install -y "${base_packages[@]}" >"$install_log" 2>&1; then
                error_echo "基本依赖安装失败。请检查日志: $install_log"
                cat "$install_log" >&2
                return 1
            fi
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE"
            return 1
            ;;
    esac
    
    if ! command -v openssl >/dev/null 2>&1; then
        error_echo "OpenSSL 安装失败或未找到。"
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
        success_echo "ufw 防火墙已尝试放行 Hysteria2 端口 (443/udp)。"
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        success_echo "firewalld 防火墙已尝试放行 Hysteria2 端口 (443/udp)。"
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
        local dummy
        safe_read "按 Enter 返回主菜单..." dummy
        return 1
    fi
    
    return 0
}

# --- 生成多种客户端配置格式 ---
generate_hy2_configs() {
    local hy2_server_addr_for_uri=""        # E.g., 192.0.2.1 or [2001:db8::1]
    local hy2_server_addr_for_config_field="" # E.g., 192.0.2.1 or 2001:db8::1 (raw IPv6)

    if [[ "$HY_SERVER_IP_CHOICE" == "ipv6" ]]; then
        # Ensure IPV6_ADDR is valid before using
        if [[ "$IPV6_ADDR" == "N/A" ]]; then
            error_echo "Hysteria2配置生成失败: 未检测到有效的IPv6地址。"
            return 1
        fi
        hy2_server_addr_for_uri="[$IPV6_ADDR]"
        hy2_server_addr_for_config_field="$IPV6_ADDR"
    elif [[ "$HY_SERVER_IP_CHOICE" == "ipv4" ]]; then
        # Ensure IPV4_ADDR is valid before using
        if [[ "$IPV4_ADDR" == "N/A" ]]; then
            error_echo "Hysteria2配置生成失败: 未检测到有效的IPv4地址。"
            return 1
        fi
        hy2_server_addr_for_uri="$IPV4_ADDR"
        hy2_server_addr_for_config_field="$IPV4_ADDR"
    else
        # Fallback if HY_SERVER_IP_CHOICE is not set correctly or IPs are N/A
        error_echo "Hysteria2配置生成失败：IP选择逻辑异常或无可用IP地址。"
        return 1
    fi

    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
    local server_name="🌟Hysteria2-${country_code}-$(date +%m%d)"
    
    # For V2rayN/NekoBox/Shadowrocket link (URI standard: IPv6 needs brackets)
    local hy2_link_uri="hysteria2://$HY_PASSWORD@$hy2_server_addr_for_uri:443/?insecure=true&sni=$HY_DOMAIN#$server_name"
    
    echo -e "${PURPLE}Hysteria2配置信息：${ENDCOLOR}"
    echo
    
    echo -e "${CYAN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${ENDCOLOR}"
    echo "$hy2_link_uri"
    echo
    
    echo -e "${CYAN}⚔️ Clash Meta 配置:${ENDCOLOR}"
    # Clash Meta 'server' field expects raw IP (no brackets for IPv6)
    echo "  - { name: '$server_name', type: hysteria2, server: $hy2_server_addr_for_config_field, port: 443, password: $HY_PASSWORD, sni: $HY_DOMAIN, skip-cert-verify: true, up: 50, down: 100 }"
    echo
    
    echo -e "${CYAN}🌊 Surge 配置:${ENDCOLOR}"
    # Surge 'server' field expects raw IP (no brackets for IPv6)
    echo "$server_name = hysteria2, $hy2_server_addr_for_config_field, 443, password=$HY_PASSWORD, sni=$HY_DOMAIN, skip-cert-verify=true"
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
    # Display the chosen IP address, with brackets if IPv6
    local display_ip_for_info=""
    if [[ "$HY_SERVER_IP_CHOICE" == "ipv6" ]]; then
        display_ip_for_info="[$IPV6_ADDR]"
    else # Default to ipv4 if choice is not ipv6 or not set
        display_ip_for_info="$IPV4_ADDR"
    fi
    echo -e "服务器地址: ${GREEN}$display_ip_for_info${ENDCOLOR}"
    echo -e "服务器端口: ${GREEN}443${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "允许不安全: ${YELLOW}是${ENDCOLOR}"
    echo -e "${PURPLE}========================${ENDCOLOR}"
    echo
    
    # Generate various client configurations
    generate_hy2_configs
    
    local dummy
    safe_read "按 Enter 继续..." dummy
    return 0
}

# --- 安装主函数 ---
hy2_install() {
    pre_install_check "hysteria" || return 1
    
    # 在安装 Hysteria2 之前，强制检查并确保有足够的 Swap (如果内存低)
    enforce_swap_if_low_memory || return 1 
    
    hy2_get_input || return 1
    hy2_install_system_deps || return 1
    hy2_download_and_install || return 1
    hy2_create_self_signed_cert || return 1
    hy2_create_config || return 1
    hy2_create_service || return 1

    # 持久化 Hysteria2 配置变量
    mkdir -p /etc/hysteria2
    echo "HY_PASSWORD='$HY_PASSWORD'" > /etc/hysteria2/hy2_vars.conf
    echo "HY_DOMAIN='$HY_DOMAIN'" >> /etc/hysteria2/hy2_vars.conf
    echo "HY_SERVER_IP_CHOICE='$HY_SERVER_IP_CHOICE'" >> /etc/hysteria2/hy2_vars.conf
    echo "FAKE_URL='$FAKE_URL'" >> /etc/hysteria2/hy2_vars.conf
    chmod 600 /etc/hysteria2/hy2_vars.conf # 保护敏感信息
    success_echo "Hysteria2 配置变量已保存至 /etc/hysteria2/hy2_vars.conf"

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
        error_echo "Hysteria2 未安装，无法更新。请先进行安装。"
        local dummy
        safe_read "按 Enter 继续..." dummy
        return 1
    fi

    local current_version_full
    local current_version
    # 尝试更健壮地获取当前版本号 (例如：从 "Hysteria2 v2.6.2 (built from ...)" 中提取 "v2.6.2")
    current_version_full=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1)
    current_version=$(echo "$current_version_full" | grep -oE '(app/)?v[0-9]+\.[0-9]+\.[0-9]+')
    
    if [[ -n "$current_version" ]]; then
        info_echo "当前 Hysteria2 版本: $current_version"
    else
        warning_echo "无法获取当前 Hysteria2 版本信息。"
    fi

    local latest_version
    latest_version=$(timeout 10 curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name"' | cut -d '"' -f 4)

    if [[ -z "$latest_version" ]]; then
        error_echo "无法获取 Hysteria2 最新版本信息。"
        local dummy
        safe_read "按 Enter 继续..." dummy
        return 1
    fi
    info_echo "Hysteria2 最新版本: $latest_version"

    local perform_update=false

    if [[ -z "$current_version" ]]; then
        # 如果无法获取当前版本，询问用户是否强制更新
        warning_echo "由于无法检测当前版本，将尝试下载并替换最新版本，但不会修改现有配置。"
        local confirm_update
        safe_read "是否仍要下载并替换最新版本 ($latest_version)？ (y/N): " confirm_update
        if [[ "$confirm_update" =~ ^[yY]$ ]]; then
            perform_update=true
        else
            info_echo "操作已取消。"
            local dummy; safe_read "按 Enter 继续..." dummy
            return 0
        fi
    elif [[ "$latest_version" == "$current_version" ]]; then
        info_echo "Hysteria2 已经是最新版本，无需更新。"
        local dummy; safe_read "按 Enter 继续..." dummy
        return 0
    else # 当前版本已知且低于最新版本
        info_echo "发现新版本 ($latest_version)，正在更新 Hysteria2..."
        perform_update=true
    fi

    if $perform_update; then
        info_echo "正在更新 Hysteria2..."
        
        systemctl stop hysteria-server >/dev/null 2>&1 || true
        
        local tmp_dir="/tmp/hysteria2_update"
        rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
        cd "$tmp_dir" || { error_echo "无法进入临时目录进行更新。"; return 1; }
        
        local download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
        
        info_echo "正在下载: $download_url"
        if ! timeout 60 wget -q --show-progress -O hysteria "$download_url"; then
            error_echo "下载失败"
            cd / && rm -rf "$tmp_dir"
            systemctl start hysteria-server >/dev/null 2>&1 || true
            local dummy; safe_read "按 Enter 继续..." dummy
            return 1
        fi
        
        if [[ ! -s hysteria ]] || ! file hysteria | grep -q "executable"; then
            error_echo "下载的文件无效"
            cd / && rm -rf "$tmp_dir"
            systemctl start hysteria-server >/dev/null 2>&1 || true
            local dummy; safe_read "按 Enter 继续..." dummy
            return 1
        fi
        
        chmod +x hysteria
        mv hysteria /usr/local/bin/hysteria
        
        systemctl start hysteria-server
        sleep 3
        
        if systemctl is-active --quiet hysteria-server; then
            success_echo "Hysteria2 更新并启动成功！新版本: $(/usr/local/bin/hysteria version 2>/dev/null | head -n 1)"
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

# --- 尝试修复 Debian/Ubuntu 的 APT 源 ---
change_debian_apt_sources() {
    if [[ "$OS_TYPE" == "ubuntu" || "$OS_TYPE" == "debian" ]]; then
        warning_echo "检测到 APT 源更新失败，尝试更换为阿里云镜像源..."
        local sources_list="/etc/apt/sources.list"
        local sources_list_backup="${sources_list}.bak.$(date +%Y%m%d%H%M%S)"

        if [[ -f "$sources_list" ]]; then
            cp "$sources_list" "$sources_list_backup"
            info_echo "已备份原有 sources.list 到 $sources_list_backup"
        fi

        local codename=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)
        if [[ -z "$codename" ]]; then
            warning_echo "无法获取系统代号，无法自动更换 APT 源。"
            return 1
        fi

        # 根据系统代号生成新的阿里云源配置
        # 注意：这里使用 https 协议，需要确保 ca-certificates 和 apt-transport-https (或直接 curl) 已安装
        cat > "$sources_list" <<EOF
deb https://mirrors.aliyun.com/debian/ $codename main contrib non-free
deb-src https://mirrors.aliyun.com/debian/ $codename main contrib non-free

deb https://mirrors.aliyun.com/debian/ $codename-updates main contrib non-free
deb-src https://mirrors.aliyun.com/debian/ $codename-updates main contrib non-free

deb https://mirrors.aliyun.com/debian/ $codename-backports main contrib non-free
deb-src https://mirrors.aliyun.com/debian/ $codename-backports main contrib non-free

deb https://mirrors.aliyun.com/debian-security/ $codename-security main contrib non-free
deb-src https://mirrors.aliyun.com/debian-security/ $codename-security main contrib non-free
EOF
        
        info_echo "APT 源已更换为阿里云镜像源。现在尝试再次更新 apt 包列表..."
        if apt-get update -qq; then
            success_echo "APT 源更新成功。"
            return 0
        else
            error_echo "更换阿里云源后 apt update 仍然失败。请手动检查并修复 /etc/apt/sources.list 文件。"
            return 1
        fi
    fi
    return 0 # 非 Debian/Ubuntu 系统直接返回
}


# --- Shadowsocks 用户输入处理 (强制 IPv6 作为客户端配置IP) ---
ss_get_input() {
    echo
    echo -e "${CYAN}=== Shadowsocks 安装参数设置 ===${ENDCOLOR}"
    echo
    
    # 密码
    safe_read_password "请输入连接密码 (留空自动生成): " SS_PASSWORD
    if [[ -z "$SS_PASSWORD" ]]; then
        SS_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $SS_PASSWORD"
    fi

    # IP 地址选择 (根据检测到的网络环境，强制使用 IPv6 作为客户端配置IP)
    if $HAS_IPV6 && [[ "$IPV6_ADDR" != "N/A" ]]; then
        SS_SERVER_IP_CHOICE="ipv6"
        info_echo "检测到公网 IPv6 地址 (${IPV6_ADDR})。"
        if $HAS_IPV4 && [[ "$IPV4_ADDR" != "N/A" ]]; then
            info_echo "服务器同时拥有 IPv4 地址 (${IPV4_ADDR})。根据要求，Shadowsocks 客户端配置将强制使用 IPv6 地址。"
        else
            info_echo "服务器为纯 IPv6 环境，Shadowsocks 客户端配置将使用 IPv6 地址。"
        fi
    elif $HAS_IPV4 && [[ "$IPV4_ADDR" != "N/A" ]]; then
        # This branch should ideally be caught by ss_check_ipv6 earlier and prevent reaching here.
        # But as a safeguard, reiterate the refusal for IPv4-only setup.
        error_echo "检测到您的服务器仅有 IPv4 地址 ($IPV4_ADDR)。"
        error_echo "${RED}Shadowsocks 服务在此脚本中仅支持 IPv6 或双栈 IPv6 优先模式，无法在 IPv4 Only 环境下安装。${ENDCOLOR}"
        local dummy
        safe_read "按 Enter 返回主菜单..." dummy
        return 1
    else
        error_echo "未检测到任何有效的公网 IP 地址，Shadowsocks 无法安装。"
        local dummy
        safe_read "按 Enter 返回主菜单..." dummy
        return 1
    fi
    
    return 0
}


ss_check_ipv6() {
    info_echo "检测 IPv6 网络环境以安装 Shadowsocks..."
    if ! $HAS_IPV6 || [[ "$IPV6_ADDR" == "N/A" ]]; then # If no routable IPv6 detected
        if $HAS_IPV4; then # If only IPv4 is present
            error_echo "检测到您的服务器仅有 IPv4 地址 ($IPV4_ADDR)。"
            error_echo "${RED}Shadowsocks 服务在此脚本中仅支持 IPv6 或双栈 IPv6 优先模式，无法在 IPv4 Only 环境下安装。${ENDCOLOR}"
        else # No IPv4 and no IPv6 detected
            error_echo "未检测到任何有效的公网 IP 地址，Shadowsocks 无法安装。"
        fi
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

    # 新增：针对纯IPv6服务器的NAT64/DNS64提示，并在纯IPv6环境下强烈建议Hysteria2
    if ! $HAS_IPV4 && $HAS_IPV6; then # 确定是纯IPv6且IPv6可用
        warning_echo "${RED}⚠️ 重要警告：您的服务器是纯 IPv6 环境。Shadowsocks 服务端虽然能监听 IPv6，但要访问 IPv4-Only 网站，您的网络必须提供 DNS64 和 NAT64 功能。${ENDCOLOR}"
        warning_echo "${RED}   如果您的 VPS 提供商没有提供这些功能，Shadowsocks 将无法访问纯 IPv4 网站，这可能导致连接问题。${ENDCOLOR}"
        warning_echo "${BLUE}   强烈建议您考虑安装 Hysteria2 (主菜单选项 1)，其在纯 IPv6 环境下通常表现更稳定，不易受 IPv4 限制。${ENDCOLOR}"
        local confirm_ss_ipv6_only
        safe_read "${YELLOW}您确定仍要在纯 IPv6 环境下继续安装 Shadowsocks 吗? (y/N): ${ENDCOLOR}" confirm_ss_ipv6_only
        if [[ ! "$confirm_ss_ipv6_only" =~ ^[yY]$ ]]; then
            info_echo "Shadowsocks 安装已取消，推荐您尝试安装 Hysteria2。"
            local dummy
            safe_read "按 Enter 返回主菜单..." dummy
            return 1 # User cancelled SS installation
        fi

        info_echo "   如果您不确定 NAT64/DNS64，请咨询您的 VPS 提供商或查阅相关文档。"
        info_echo "   您可以尝试运行 'ping ipv4.google.com' 或 'curl -4 https://ip.p3terx.com' 来验证 IPv4 连通性。"
        echo
        local dummy
        safe_read "按 Enter 继续..." dummy
    fi
    return 0
}

ss_install_dependencies() {
    info_echo "安装 Shadowsocks 依赖包 (shadowsocks-libev, qrencode)..."
    
    local install_log="/tmp/ss_install_deps.log"
    rm -f "$install_log" # 清理旧日志

    case "$OS_TYPE" in
        "ubuntu"|"debian")
            info_echo "正在更新 apt 包列表 (日志输出到 $install_log)..."
            if ! apt-get update -qq >"$install_log" 2>&1; then
                error_echo "apt update 失败。请检查日志: $install_log"
                cat "$install_log" >&2
                # 尝试修复 Debian/Ubuntu 的源问题
                change_debian_apt_sources || { error_echo "尝试修复 APT 源失败。请手动检查并修复 /etc/apt/sources.list 文件。"; return 1; }
                if ! apt-get update -qq >"$install_log" 2>&1; then # 换源后再次尝试更新
                    error_echo "换源后 apt update 仍然失败。请检查日志: $install_log"
                    cat "$install_log" >&2
                    return 1
                fi
            fi
            info_echo "正在安装 Shadowsocks (shadowsocks-libev, qrencode) 和 curl (日志输出到 $install_log)..."
            if ! apt-get install -y shadowsocks-libev qrencode curl >"$install_log" 2>&1; then
                error_echo "shadowsocks-libev 或 qrencode 安装失败。请检查日志: $install_log"
                cat "$install_log" >&2
                return 1
            fi
            ;;
        "centos" | "rocky" | "almalinux")
            info_echo "正在安装 EPEL 仓库 (日志输出到 $install_log)..."
            if ! yum install -y epel-release >"$install_log" 2>&1; then
                error_echo "EPEL 仓库安装失败。请检查日志: $install_log"
                cat "$install_log" >&2
                return 1
            fi
            info_echo "正在安装 Shadowsocks (shadowsocks-libev, qrencode) 和 curl (日志输出到 $install_log)..."
            # 修正：确保在 RHEL-based 系统上安装 shadowsocks-libev 和 qrencode
            if ! yum install -y shadowsocks-libev qrencode curl >"$install_log" 2>&1; then
                error_echo "Shadowsocks 或 qrencode 安装失败。请检查日志: $install_log"
                cat "$install_log" >&2
                return 1
            fi
            ;;
        "fedora")
            info_echo "正在安装 Shadowsocks (shadowsocks-libev, qrencode) 和 curl (日志输出到 $install_log)..."
            if ! dnf install -y shadowsocks-libev qrencode curl >"$install_log" 2>&1; then
                error_echo "shadowsocks-libev 或 qrencode 安装失败。请检查日志: $install_log"
                cat "$install_log" >&2
                return 1
            fi
            ;;
        *) error_echo "不支持的操作系统: $OS_TYPE"; return 1;;
    esac

    # 再次确认 ss-server 命令是否存在，确保安装成功
    if ! command -v ss-server >/dev/null 2>&1; then
        error_echo "shadowsocks-libev 未能成功安装或无法找到 ss-server 命令。请检查安装日志 ($install_log)。"
        cat "$install_log" >&2
        return 1
    fi
    success_echo "依赖包安装完成"
    return 0
}

ss_generate_config() {
    info_echo "生成 Shadowsocks 配置文件..."
    SS_PORT=$(shuf -i 20000-40000 -n 1)
    # SS_PASSWORD 和 SS_METHOD 已经在 ss_get_input 中获取或生成

    mkdir -p /etc/shadowsocks-libev
    # Removed the JSON comment '#' from the "server" line, as it caused a JSON parsing error.
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
        info_echo "错误日志："
        journalctl -u shadowsocks-libev -n 10 --no-pager
        return 1
    fi

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then 
        ufw allow "$SS_PORT"/tcp >/dev/null 2>&1
        ufw allow "$SS_PORT"/udp >/dev/null 2>&1
        success_echo "ufw 防火墙已配置放行 Shadowsocks 端口 ($SS_PORT/tcp, $SS_PORT/udp)。"
    fi
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then 
        firewall-cmd --permanent --add-port="$SS_PORT"/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$SS_PORT"/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        success_echo "firewalld 防火墙已配置放行 Shadowsocks 端口 ($SS_PORT/tcp, $SS_PORT/udp)。"
    fi

    success_echo "Shadowsocks 服务已成功启动"
    return 0
}

# --- 生成多种 Shadowsocks 客户端配置格式 ---
generate_ss_configs() {
    local ss_server_addr_for_uri=""
    local ss_server_addr_for_config_field=""
    
    # 根据全局变量 SS_SERVER_IP_CHOICE 决定客户端配置中的服务器地址
    if [[ "$SS_SERVER_IP_CHOICE" == "ipv6" ]]; then
        if [[ "$IPV6_ADDR" == "N/A" ]]; then
            error_echo "Shadowsocks配置生成失败: 未检测到有效的IPv6地址，但选择了IPv6作为客户端连接IP。"
            return 1
        fi
        ss_server_addr_for_uri="[$IPV6_ADDR]"
        ss_server_addr_for_config_field="$IPV6_ADDR"
    elif [[ "$SS_SERVER_IP_CHOICE" == "ipv4" ]]; then
        if [[ "$IPV4_ADDR" == "N/A" ]]; then
            error_echo "Shadowsocks配置生成失败: 未检测到有效的IPv4地址，但选择了IPv4作为客户端连接IP。"
            return 1
        fi
        ss_server_addr_for_uri="$IPV4_ADDR"
        ss_server_addr_for_config_field="$IPV4_ADDR"
    else
        error_echo "Shadowsocks配置生成失败：IP选择逻辑异常或未设置客户端连接IP类型。"
        return 1
    fi

    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
    local server_name="🚀Shadowsocks-${country_code}-$(date +%m%d)"
    local encoded_password_method
    encoded_password_method=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)

    # Shadowsocks URI (ss://)
    local ss_link_uri="ss://${encoded_password_method}@${ss_server_addr_for_uri}:${SS_PORT}#${server_name}"

    echo -e "${PURPLE}Shadowsocks客户端配置：${ENDCOLOR}" # 更改标题以区分
    echo
    
    echo -e "${CYAN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${ENDCOLOR}"
    echo "$ss_link_uri"
    echo
    
    echo -e "${CYAN}⚔️ Clash Meta 配置:${ENDCOLOR}"
    # Clash Meta 'server' field expects raw IP (no brackets for IPv6)
    echo "  - { name: '$server_name', type: ss, server: '$ss_server_addr_for_config_field', port: $SS_PORT, password: '$SS_PASSWORD', cipher: '$SS_METHOD', udp: true }"
    echo
    
    echo -e "${CYAN}🌊 Surge 配置:${ENDCOLOR}"
    # Surge 'server' field expects raw IP (no brackets for IPv6)
    echo "$server_name = ss, $ss_server_addr_for_config_field, $SS_PORT, encrypt-method=$SS_METHOD, password=$SS_PASSWORD, udp-relay=true"
    echo
}

# --- 显示 Shadowsocks 安装结果 ---
ss_display_result() {
    clear
    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 安装完成！ ${ENDCOLOR}"
    echo
    echo -e " ${PURPLE}--- Shadowsocks 基本配置信息 ---${ENDCOLOR}"
    local display_ip_for_info=""
    # 这里使用 SS_SERVER_IP_CHOICE 来决定显示哪个IP
    if [[ "$SS_SERVER_IP_CHOICE" == "ipv6" ]]; then
        display_ip_for_info="[$IPV6_ADDR]"
    else # 此时 SS_SERVER_IP_CHOICE 必定是 ipv4
        display_ip_for_info="$IPV4_ADDR"
    fi
    echo -e "   服务器地址: ${GREEN}$display_ip_for_info${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}$SS_PORT${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$SS_PASSWORD${ENDCOLOR}"
    echo -e "   加密方式:   ${GREEN}$SS_METHOD${ENDCOLOR}"
    echo -e " ${PURPLE}-----------------------------------${ENDCOLOR}"
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
        success_echo "Shadowsocks 正在监听端口 $SS_PORT on :: (IPv6/IPv4双栈或IPv6)。"
        echo -e "$listening_status"
    else
        error_echo "Shadowsocks 未检测到在端口 $SS_PORT on :: (IPv6) 监听。请检查配置和防火墙。"
        info_echo "可能的日志信息："
        journalctl -u shadowsocks-libev -n 5 --no-pager
    fi
    echo

    # 针对纯IPv6服务器的NAT64/DNS64提示
    if ! $HAS_IPV4; then # 如果没有IPv4，即为纯IPv6环境
        warning_echo "⚠️ 重要提示：您的服务器是纯 IPv6 环境。为了 Shadowsocks 能访问 IPv4-Only 网站，"
        warning_echo "   您的网络必须提供 DNS64 和 NAT64 功能。否则，Shadowsocks 将只能访问 IPv6 目标。"
        info_echo "   如果您不确定，请咨询您的 VPS 提供商或查阅相关文档。"
        info_echo "   您可以尝试运行 'ping ipv4.google.com' 或 'curl -4 https://ip.p3terx.com' 来验证 IPv4 连通性。"
        echo
    fi

    # 直接调用 generate_ss_configs，它将使用 ss_generate_config 设置的全局变量和 SS_SERVER_IP_CHOICE
    generate_ss_configs

    if command -v qrencode >/dev/null 2>&1; then
        # 重新生成用于二维码的链接，确保与 generate_ss_configs 中的链接一致
        local country_code
        country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
        local server_name="🚀Shadowsocks-${country_code}-$(date +%m%d)"
        local encoded_password_method
        encoded_password_method=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)
        
        local ss_qr_link_ip_display=""
        if [[ "$SS_SERVER_IP_CHOICE" == "ipv6" ]]; then
            ss_qr_link_ip_display="[$IPV6_ADDR]"
        else
            ss_qr_link_ip_display="$IPV4_ADDR"
        fi
        local ss_link_uri="ss://${encoded_password_method}@${ss_qr_link_ip_display}:${SS_PORT}#${server_name}"
        
        info_echo "二维码 (请最大化终端窗口显示):"
        qrencode -t ANSIUTF8 "$ss_link_uri" 2>/dev/null || echo "二维码生成失败"
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
    
    # 在安装 Shadowsocks 之前，强制检查并确保有足够的 Swap (如果内存低)
    enforce_swap_if_low_memory || return 1

    pre_install_check "shadowsocks" || return 1
    
    ss_get_input || return 1 # 新增：获取 Shadowsocks 用户输入，设置 SS_SERVER_IP_CHOICE
    
    if ss_install_dependencies && \
       ss_generate_config && \
       ss_setup_service; then

        # 持久化 Shadowsocks 配置变量
        mkdir -p /etc/shadowsocks-libev
        echo "SS_PORT='$SS_PORT'" > /etc/shadowsocks-libev/ss_vars.conf
        echo "SS_PASSWORD='$SS_PASSWORD'" >> /etc/shadowsocks-libev/ss_vars.conf
        echo "SS_METHOD='$SS_METHOD'" >> /etc/shadowsocks-libev/ss_vars.conf
        echo "SS_SERVER_IP_CHOICE='$SS_SERVER_IP_CHOICE'" >> /etc/shadowsocks-libev/ss_vars.conf
        chmod 600 /etc/shadowsocks-libev/ss_vars.conf # 保护敏感信息
        success_echo "Shadowsocks 配置变量已保存至 /etc/shadowsocks-libev/ss_vars.conf"

        ss_display_result
    else
        error_echo "Shadowsocks 安装失败。"
        local dummy
        safe_read "按 Enter 返回主菜单..." dummy
        return 1
    fi
}

ss_uninstall() {
    info_echo "正在卸载 Shadowsocks..."
    systemctl disable --now shadowsocks-libev >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/shadowsocks-libev.service
    rm -f /etc/shadowsocks-libev/config.json
    rm -f /etc/shadowsocks-libev/ss_vars.conf # 移除持久化配置文件
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
    local update_log="/tmp/ss_update_deps.log"
    rm -f "$update_log"

    case "$OS_TYPE" in
        "ubuntu" | "debian")
            info_echo "正在更新 apt 包列表 (日志输出到 $update_log)..."
            if ! apt-get update -qq >"$update_log" 2>&1; then
                error_echo "apt update 失败。请检查日志: $update_log"
                cat "$update_log" >&2
                # 尝试修复 Debian/Ubuntu 的源问题
                change_debian_apt_sources || { error_echo "尝试修复 APT 源失败。请手动检查并修复 /etc/apt/sources.list 文件。"; return 1; }
                if ! apt-get update -qq >"$update_log" 2>&1; then # 换源后再次尝试更新
                    error_echo "换源后 apt update 仍然失败。请检查日志: $update_log"
                    cat "$update_log" >&2
                    return 1
                fi
            fi
            info_echo "正在更新 shadowsocks-libev (日志输出到 $update_log)..."
            if ! apt-get install -y --only-upgrade shadowsocks-libev >"$update_log" 2>&1; then
                error_echo "Shadowsocks (shadowsocks-libev) 更新失败。请检查日志: $update_log"
                cat "$update_log" >&2
                local dummy; safe_read "按 Enter 继续..." dummy
                return 1
            fi
            success_echo "Shadowsocks (shadowsocks-libev) 更新完成。"
            ;;
        "centos" | "rocky" | "almalinux")
            info_echo "正在更新 shadowsocks-libev (日志输出到 $update_log)..."
            if ! yum update -y shadowsocks-libev >"$update_log" 2>&1; then
                error_echo "Shadowsocks (shadowsocks-libev) 更新失败。请检查日志: $update_log"
                cat "$update_log" >&2
                local dummy; safe_read "按 Enter 继续..." dummy
                return 1
            fi
            success_echo "Shadowsocks (shadowsocks-libev) 更新完成。"
            ;;
        "fedora")
            info_echo "正在更新 shadowsocks-libev (日志输出到 $update_log)..."
            if ! dnf update -y shadowsocks-libev >"$update_log" 2>&1; then
                error_echo "Shadowsocks (shadowsocks-libev) 更新失败。请检查日志: $update_log"
                cat "$update_log" >&2
                local dummy; safe_read "按 Enter 继续..." dummy
                return 1
            fi
            success_echo "Shadowsocks (shadowsocks-libev) 更新完成。"
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

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v1.0.19) ${ENDCOLOR}"
    echo -e "${YELLOW}项目地址：${CYAN}https://github.com/everett7623/hy2ipv6${ENDCOLOR}"
    echo -e "${YELLOW}博客地址：${CYAN}https://seedloc.com${ENDCOLOR}"
    echo -e "${YELLOW}论坛地址：${CYAN}https://nodeloc.com${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}==========================================================${ENDCOLOR}"

    # New recommendation logic for pure IPv6 machines
    if ! $HAS_IPV4 && $HAS_IPV6; then # Pure IPv6 machine
        echo -e "${BG_YELLOW}${RED}⚠️ 纯 IPv6 服务器特别提示：${ENDCOLOR}"
        echo -e "${BG_YELLOW}${BLUE}推荐优先安装 Hysteria2 (选项 1)。${ENDCOLOR}"
        echo -e "${BG_YELLOW}${BLUE}Hysteria2 在纯 IPv6 环境下通常表现更稳定，不易受 IPv4 限制。${ENDCOLOR}"
        echo -e "${BG_YELLOW}${BLUE}Shadowsocks (选项 2) 在纯 IPv6 环境下可能需要额外的 DNS64/NAT64 配置才能访问 IPv4 网站，且可能不稳定。${ENDCOLOR}"
        echo
    fi

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
    if [[ ! -f /etc/hysteria2/hy2_vars.conf ]]; then
        error_echo "Hysteria2 配置变量文件不存在，请先安装 Hysteria2。"
        local dummy
        safe_read "按 Enter 继续..." dummy
        return
    fi

    # 从持久化文件中加载配置变量
    source /etc/hysteria2/hy2_vars.conf

    echo -e "${BG_PURPLE} Hysteria2 连接信息 ${ENDCOLOR}"
    echo
    echo -e "${YELLOW}注意: 使用自签名证书，客户端需要启用 '允许不安全连接' 选项${ENDCOLOR}"
    echo
    
    echo -e "${PURPLE}=== 基本连接信息 ===${ENDCOLOR}"
    local display_ip_for_info=""
    if [[ "$HY_SERVER_IP_CHOICE" == "ipv6" ]]; then
        display_ip_for_info="[$IPV6_ADDR]"
    else # Default to ipv4 if choice is not ipv6 or not set
        display_ip_for_info="$IPV4_ADDR"
    fi
    echo -e "服务器地址: ${GREEN}$display_ip_for_info${ENDCOLOR}"
    echo -e "服务器端口: ${GREEN}443${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "允许不安全: ${YELLOW}是${ENDCOLOR}"
    echo -e "${PURPLE}========================${ENDCOLOR}"
    echo
    
    generate_hy2_configs
    
    local dummy
    safe_read "按 Enter 继续..." dummy
    return 0
}

show_shadowsocks_config() {
    clear
    if [[ ! -f /etc/shadowsocks-libev/ss_vars.conf ]]; then
        error_echo "Shadowsocks 配置变量文件不存在，请先安装 Shadowsocks。"
        local dummy
        safe_read "按 Enter 继续..." dummy
        return
    fi

    # 从持久化文件中加载配置变量
    source /etc/shadowsocks-libev/ss_vars.conf

    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 连接信息 ${ENDCOLOR}"
    echo
    echo -e " ${PURPLE}--- Shadowsocks 基本配置信息 ---${ENDCOLOR}"
    local display_ip_for_info=""
    # 直接使用加载的 SS_SERVER_IP_CHOICE
    if [[ "$SS_SERVER_IP_CHOICE" == "ipv6" ]]; then
        display_ip_for_info="[$IPV6_ADDR]"
    elif [[ "$SS_SERVER_IP_CHOICE" == "ipv4" ]]; then
        display_ip_for_info="$IPV4_ADDR"
    else
        display_ip_for_info="N/A (IP选择逻辑异常)"
    fi
    echo -e "   服务器地址: ${GREEN}$display_ip_for_info${ENDCOLOR}"
    echo -e "   端口:       ${GREEN}$SS_PORT${ENDCOLOR}"
    echo -e "   密码:       ${GREEN}$SS_PASSWORD${ENDCOLOR}"
    echo -e "   加密方式:   ${GREEN}$SS_METHOD${ENDCOLOR}"
    echo -e " ${PURPLE}-----------------------------------${ENDCOLOR}"
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
        success_echo "Shadowsocks 正在监听端口 $SS_PORT on :: (IPv6/IPv4双栈或IPv6)。"
        echo -e "$listening_status"
    else
        error_echo "Shadowsocks 未检测到在端口 $SS_PORT on :: (IPv6) 监听。请检查配置和防火墙。"
        info_echo "可能的日志信息："
        journalctl -u shadowsocks-libev -n 5 --no-pager
    fi
    echo

    # 针对纯IPv6服务器的NAT64/DNS64提示
    if ! $HAS_IPV4; then # 如果没有IPv4，即为纯IPv6环境
        warning_echo "⚠️ 重要提示：您的服务器是纯 IPv6 环境。为了 Shadowsocks 能访问 IPv4-Only 网站，"
        warning_echo "   您的网络必须提供 DNS64 和 NAT64 功能。否则，Shadowsocks 将只能访问 IPv6 目标。"
        info_echo "   如果您不确定，请咨询您的 VPS 提供商或查阅相关文档。"
        info_echo "   您可以尝试运行 'ping ipv4.google.com' 或 'curl -4 https://ip.p3terx.com' 来验证 IPv4 连通性。"
        echo
    fi

    generate_ss_configs

    if command -v qrencode >/dev/null 2>&1; then
        # 重新生成用于二维码的链接，确保与 generate_ss_configs 中的链接一致
        local country_code
        country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
        local server_name="🚀Shadowsocks-${country_code}-$(date +%m%d)"
        local encoded_password_method
        encoded_password_method=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)
        
        local ss_qr_link_ip_display=""
        if [[ "$SS_SERVER_IP_CHOICE" == "ipv6" ]]; then
            ss_qr_link_ip_display="[$IPV6_ADDR]"
        else
            ss_qr_link_ip_display="$IPV4_ADDR"
        fi
        local ss_link_uri="ss://${encoded_password_method}@${ss_qr_link_ip_display}:${SS_PORT}#${server_name}"
        
        info_echo "二维码 (请最大化终端窗口显示):"
        qrencode -t ANSIUTF8 "$ss_link_uri" 2>/dev/null || echo "二维码生成失败"
    else
        warning_echo "qrencode 未安装，无法显示二维码"
    fi
    
    echo
    local dummy
    safe_read "按 Enter 继续..." dummy
    return 0
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
            # 使用与 ss_install_dependencies 类似的日志记录和换源逻辑
            local kernel_update_log="/tmp/kernel_update.log"
            if ! apt-get update -qq >"$kernel_update_log" 2>&1; then
                error_echo "apt update 失败。请检查日志: $kernel_update_log"
                cat "$kernel_update_log" >&2
                change_debian_apt_sources || { error_echo "尝试修复 APT 源失败。请手动检查并修复 /etc/apt/sources.list 文件。"; return 1; }
                if ! apt-get update -qq >"$kernel_update_log" 2>&1; then
                    error_echo "换源后 apt update 仍然失败。请检查日志: $kernel_update_log"
                    cat "$kernel_update_log" >&2
                    return 1
                fi
            fi
            if ! apt-get upgrade -y >"$kernel_update_log" 2>&1; then
                error_echo "apt upgrade 失败。请检查日志: $kernel_update_log"
                cat "$kernel_update_log" >&2
                return 1
            fi
            
            # 检查是否有新的内核版本可用或已安装
            if apt-get list --upgradable | grep -q "linux-image"; then
                reboot_required=true
            fi
            success_echo "Debian/Ubuntu 系统更新完成。"
            ;;
        "centos" | "rocky" | "almalinux")
            info_echo "正在更新 CentOS/Rocky/AlmaLinux 内核和系统..."
            local kernel_update_log="/tmp/kernel_update.log"
            if ! yum update -y >"$kernel_update_log" 2>&1; then
                error_echo "yum update 失败。请检查日志: $kernel_update_log"
                cat "$kernel_update_log" >&2
                return 1
            fi
            # 检查是否有新的内核版本可用或已安装
            if rpm -q kernel | grep -qv "$(uname -r)"; then
                 reboot_required=true
            fi
            success_echo "CentOS/Rocky/AlmaLinux 系统更新完成。"
            ;;
        "fedora")
            info_echo "正在更新 Fedora 内核和系统..."
            local kernel_update_log="/tmp/kernel_update.log"
            if ! dnf update -y >"$kernel_update_log" 2>&1; then
                error_echo "dnf update 失败。请检查日志: $kernel_update_log"
                cat "$kernel_update_log" >&2
                return 1
            fi
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
    check_and_create_swap # Call swap creation early (non-blocking suggestion)
    
    # 移除冗余的输入缓冲区清理
    # while read -t 0.1 -n 1000 discard 2>/dev/null; do
    #     true
    # done
    
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
