#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks (IPv6) Management Script 自动化部署脚本
# 作者：Jensfrank (Optimized by Gemini)
# 版本：v2.1
# GitHub: https://github.com/everett7623/hy2
# 博客: https://seedloc.com
# 论坛: https://nodeloc.com
#====================================================================================

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
SS_METHOD="chacha20-ietf-poly135" # 默认加密方式

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
    
    # Clean possible input pollution
    exec </dev/tty 2>/dev/null || true
}

# --- 检查并建议创建 Swap (仅提示，不强制中断) ---
check_and_create_swap() {
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))
    
    if (( total_ram_mb < 512 )); then
        local current_swap_mb=$(free -m | grep Swap | awk '{print $2}')
        if (( current_swap_mb == 0 )); then
            warning_echo "检测到系统内存 ($total_ram_mb MB) 较低且无 Swap 空间。建议创建 Swap 以避免服务因内存不足而崩溃。"
            local confirm
            safe_read "是否进入 '系统优化' 菜单创建 Swap? (y/N): " confirm
            if [[ "$confirm" =~ ^[yY]$ ]]; then
                manage_swap
            fi
        fi
    fi
    return 0
}

# --- 强制检查并创建 Swap (在服务安装前调用，低内存时强制) ---
enforce_swap_if_low_memory() {
    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))

    if (( total_ram_mb < 512 )); then
        local current_swap_mb=$(free -m | grep Swap | awk '{print $2}')
        if (( current_swap_mb == 0 )); then
            error_echo "检测到系统内存 ($total_ram_mb MB) 极低且无 Swap 空间。"
            warning_echo "强烈建议创建 Swap 文件以确保安装成功和系统稳定性。否则安装可能会失败甚至导致服务闪退。"
            local confirm
            safe_read "是否立即创建 1GB 的 Swap 文件? (Y/n): " confirm
            if [[ ! "$confirm" =~ ^[nN]$ ]]; then
                create_swap_file 1024
                return $? # 返回 create_swap_file 的执行结果
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
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
        ufw allow 443/udp >/dev/null 2>&1
        success_echo "ufw 防火墙已尝试放行 Hysteria2 端口 (443/udp)。"
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
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

    # 优先使用安装时用户选择的IP类型，如果脚本重启后直接查看配置，则动态判断
    local chosen_ip_type=${HY_SERVER_IP_CHOICE:-"default"}
    
    if [[ "$chosen_ip_type" == "ipv6" ]] && $HAS_IPV6; then
        hy2_server_addr_for_uri="[$IPV6_ADDR]"
        hy2_server_addr_for_config_field="$IPV6_ADDR"
    elif [[ "$chosen_ip_type" == "ipv4" ]] && $HAS_IPV4; then
        hy2_server_addr_for_uri="$IPV4_ADDR"
        hy2_server_addr_for_config_field="$IPV4_ADDR"
    elif $HAS_IPV4; then # Fallback to IPv4 if available
        hy2_server_addr_for_uri="$IPV4_ADDR"
        hy2_server_addr_for_config_field="$IPV4_ADDR"
    elif $HAS_IPV6; then # Fallback to IPv6 if only IPv6 is available
        hy2_server_addr_for_uri="[$IPV6_ADDR]"
        hy2_server_addr_for_config_field="$IPV6_ADDR"
    else
        error_echo "Hysteria2配置生成失败：无可用IP地址。"
        return 1
    fi

    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
    local server_name="🌟Hysteria2-${country_code}-$(date +%m%d)"
    
    local hy2_link_uri="hysteria2://$HY_PASSWORD@$hy2_server_addr_for_uri:443/?insecure=true&sni=$HY_DOMAIN#$server_name"
    
    echo -e "${PURPLE}Hysteria2配置信息：${ENDCOLOR}"
    echo
    
    echo -e "${CYAN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${ENDCOLOR}"
    echo "$hy2_link_uri"
    echo
    
    echo -e "${CYAN}⚔️ Clash Meta 配置:${ENDCOLOR}"
    echo "- { name: '$server_name', type: hysteria2, server: $hy2_server_addr_for_config_field, port: 443, password: $HY_PASSWORD, sni: $HY_DOMAIN, skip-cert-verify: true, up: 50, down: 100 }"
    echo
    
    echo -e "${CYAN}🌊 Surge 配置:${ENDCOLOR}"
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
    show_hysteria2_config quiet # Call the unified display function
}

# --- 安装主函数 ---
hy2_install() {
    pre_install_check "hysteria" || return 1
    enforce_swap_if_low_memory || return 1 
    
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


################################################################################
# Shadowsocks (IPv6) 功能模块
# 使用 shadowsocks-libev 包，因其广泛存在于各发行版仓库，易于维护。
################################################################################

ss_check_ipv6() {
    info_echo "检测 IPv6 网络环境以安装 Shadowsocks..."
    if ! $HAS_IPV6 || [[ "$IPV6_ADDR" == "N/A" ]]; then
        if $HAS_IPV4; then
            error_echo "检测到您的服务器仅有 IPv4 地址 ($IPV4_ADDR)。Shadowsocks 服务在此脚本中仅支持 IPv6 或双栈 IPv6 优先模式，无法在 IPv4 Only 环境下安装。"
        else
            error_echo "未检测到任何有效的公网 IP 地址，Shadowsocks 无法安装。"
        fi
        local dummy
        safe_read "按 Enter 返回主菜单..." dummy
        return 1
    fi

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
    
    local install_log="/tmp/ss_install_deps.log"
    rm -f "$install_log" # 清理旧日志

    case "$OS_TYPE" in
        "ubuntu"|"debian")
            info_echo "正在更新 apt 包列表 (日志输出到 $install_log)..."
            if ! apt-get update -qq >"$install_log" 2>&1; then
                error_echo "apt update 失败。请检查日志: $install_log"; cat "$install_log" >&2
                change_debian_apt_sources || { error_echo "尝试修复 APT 源失败。"; return 1; }
                if ! apt-get update -qq >"$install_log" 2>&1; then 
                    error_echo "换源后 apt update 仍然失败。请检查日志: $install_log"; cat "$install_log" >&2; return 1
                fi
            fi
            info_echo "正在安装 shadowsocks-libev, qrencode, curl (日志输出到 $install_log)..."
            if ! apt-get install -y shadowsocks-libev qrencode curl >"$install_log" 2>&1; then
                error_echo "依赖安装失败。请检查日志: $install_log"; cat "$install_log" >&2; return 1
            fi
            ;;
        "centos" | "rocky" | "almalinux")
            info_echo "正在安装 EPEL 仓库 (日志输出到 $install_log)..."
            if ! yum install -y epel-release >"$install_log" 2>&1; then
                error_echo "EPEL 仓库安装失败。请检查日志: $install_log"; cat "$install_log" >&2; return 1
            fi
            info_echo "正在安装 shadowsocks-libev, qrencode, curl (日志输出到 $install_log)..."
            if ! yum install -y shadowsocks-libev qrencode curl >"$install_log" 2>&1; then
                error_echo "依赖安装失败。请检查日志: $install_log"; cat "$install_log" >&2; return 1
            fi
            ;;
        "fedora")
            info_echo "正在安装 shadowsocks-libev, qrencode, curl (日志输出到 $install_log)..."
            if ! dnf install -y shadowsocks-libev qrencode curl >"$install_log" 2>&1; then
                error_echo "依赖安装失败。请检查日志: $install_log"; cat "$install_log" >&2; return 1
            fi
            ;;
        *) error_echo "不支持的操作系统: $OS_TYPE"; return 1;;
    esac

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
    
    # 使用 shadowsocks-libev 包自带的服务文件模板，更标准
    if [ -f /lib/systemd/system/shadowsocks-libev-server@.service ]; then
        systemctl enable shadowsocks-libev-server@config.service >/dev/null 2>&1
        systemctl restart shadowsocks-libev-server@config.service
    else # Fallback for older systems or different package structures
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
    fi
    sleep 2
    
    if ! systemctl is-active --quiet shadowsocks-libev-server@config.service && ! systemctl is-active --quiet shadowsocks-libev; then
        error_echo "Shadowsocks 服务启动失败！"
        info_echo "错误日志："
        journalctl -u shadowsocks-libev* -n 10 --no-pager
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
    local ss_server_addr_for_uri="[$IPV6_ADDR]"        
    local ss_server_addr_for_config_field="$IPV6_ADDR"

    local country_code
    country_code=$(curl -s --connect-timeout 2 https://ipapi.co/country_code 2>/dev/null || echo "UN")
    local server_name="🌟Shadowsocks-${country_code}-$(date +%m%d)"
    local encoded_password_method
    encoded_password_method=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)

    local ss_link_uri="ss://${encoded_password_method}@${ss_server_addr_for_uri}:${SS_PORT}#${server_name}"

    echo -e "${PURPLE}Shadowsocks配置信息：${ENDCOLOR}"
    echo
    
    echo -e "${CYAN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${ENDCOLOR}"
    echo "$ss_link_uri"
    echo
    
    echo -e "${CYAN}⚔️ Clash Meta 配置:${ENDCOLOR}"
    echo "- { name: '$server_name', type: ss, server: '$ss_server_addr_for_config_field', port: $SS_PORT, password: '$SS_PASSWORD', cipher: '$SS_METHOD', udp: true }"
    echo
    
    echo -e "${CYAN}🌊 Surge 配置:${ENDCOLOR}"
    echo "$server_name = ss, $ss_server_addr_for_config_field, $SS_PORT, encrypt-method=$SS_METHOD, password=$SS_PASSWORD, udp-relay=true"
    echo
    
    if command -v qrencode >/dev/null 2>&1; then
        info_echo "二维码 (请最大化终端窗口显示):"
        qrencode -t ANSIUTF8 "$ss_link_uri" 2>/dev/null || echo "二维码生成失败"
    else
        warning_echo "qrencode 未安装，无法显示二维码"
    fi
}

# --- 显示 Shadowsocks 安装结果 ---
ss_show_result() {
    clear
    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 安装完成！ ${ENDCOLOR}"
    echo
    show_shadowsocks_config quiet
}

ss_install() {
    ss_check_ipv6 || return 1
    enforce_swap_if_low_memory || return 1
    pre_install_check "shadowsocks" || return 1
    
    ss_install_dependencies && \
    ss_generate_config && \
    ss_setup_service && \
    ss_show_result || {
        error_echo "Shadowsocks 安装失败。"
        local dummy
        safe_read "按 Enter 返回主菜单..." dummy
        return 1
    }
}

ss_uninstall() {
    info_echo "正在卸载 Shadowsocks..."
    systemctl disable --now shadowsocks-libev-server@config.service >/dev/null 2>&1 || true
    systemctl disable --now shadowsocks-libev >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/shadowsocks-libev.service
    rm -rf /etc/shadowsocks-libev
    systemctl daemon-reload
    success_echo "Shadowsocks 已卸载完成。"
}

################################################################################
# 更新模块
################################################################################

update_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 更新服务 ===${ENDCOLOR}"
        echo " 1. 更新 Hysteria2 (从 GitHub 获取最新版)"
        echo " 2. 更新 Shadowsocks (通过系统包管理器)"
        echo " 3. 更新系统内核及所有软件包"
        echo " 0. 返回主菜单"
        echo "----------------"
        local choice
        safe_read "请选择操作: " choice
        case $choice in
            1) hy2_update ;;
            2) ss_update ;;
            3) update_system_kernel ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

hy2_update() {
    info_echo "检查 Hysteria2 应用程序更新..."
    if [[ ! -f /usr/local/bin/hysteria ]]; then
        error_echo "Hysteria2 未安装，无法更新。请先进行安装。"; sleep 2; return 1;
    fi

    local current_version
    current_version=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "未知")
    info_echo "当前 Hysteria2 版本: $current_version"

    local latest_version
    latest_version=$(timeout 10 curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name"' | cut -d '"' -f 4)

    if [[ -z "$latest_version" ]]; then
        error_echo "无法获取 Hysteria2 最新版本信息。"; sleep 2; return 1;
    fi
    info_echo "Hysteria2 最新版本: $latest_version"

    if [[ "$latest_version" == "$current_version" ]]; then
        info_echo "Hysteria2 已经是最新版本，无需更新。"; sleep 2; return 0;
    fi
    
    info_echo "发现新版本 ($latest_version)，正在更新 Hysteria2..."
    systemctl stop hysteria-server >/dev/null 2>&1
    hy2_download_and_install || { 
        error_echo "Hysteria2 更新失败，正在尝试恢复服务..."; 
        systemctl start hysteria-server;
        sleep 2;
        return 1;
    }
    systemctl start hysteria-server
    sleep 2
    if systemctl is-active --quiet hysteria-server; then
        success_echo "Hysteria2 更新并启动成功！新版本: $(/usr/local/bin/hysteria version 2>/dev/null | head -n 1)"
    else
        error_echo "Hysteria2 更新成功但服务启动失败。请检查日志。"
        journalctl -u hysteria-server -n 10 --no-pager
    fi

    local dummy; safe_read "按 Enter 继续..." dummy
}

ss_update() {
    info_echo "检查 Shadowsocks (shadowsocks-libev) 应用程序更新..."
    if ! command -v ss-server >/dev/null 2>&1; then
        error_echo "Shadowsocks 未安装，无法更新。"; sleep 2; return 1;
    fi

    local ss_is_active=false
    if systemctl is-active --quiet shadowsocks-libev-server@config.service || systemctl is-active --quiet shadowsocks-libev; then
        ss_is_active=true
    fi

    info_echo "正在通过系统包管理器更新 shadowsocks-libev..."
    local update_log="/tmp/ss_update_deps.log"; rm -f "$update_log"

    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -qq >"$update_log" 2>&1
            apt-get install -y --only-upgrade shadowsocks-libev >>"$update_log" 2>&1
            ;;
        "centos" | "rocky" | "almalinux")
            yum update -y shadowsocks-libev >"$update_log" 2>&1
            ;;
        "fedora")
            dnf update -y shadowsocks-libev >"$update_log" 2>&1
            ;;
        *) error_echo "不支持的操作系统: $OS_TYPE"; sleep 2; return 1;;
    esac

    if grep -qE "Err:|Error:|Fail|fail" "$update_log"; then
        error_echo "Shadowsocks (shadowsocks-libev) 更新失败。请检查日志: $update_log"
        cat "$update_log" >&2
    else
        success_echo "Shadowsocks (shadowsocks-libev) 更新完成。"
    fi

    if $ss_is_active; then
        info_echo "尝试重启 Shadowsocks 服务..."
        if systemctl restart shadowsocks-libev-server@config.service || systemctl restart shadowsocks-libev; then
            success_echo "Shadowsocks 服务重启成功。"
        else
            error_echo "Shadowsocks 服务重启失败。"
        fi
    fi
    local dummy; safe_read "按 Enter 继续..." dummy
}

update_system_kernel() {
    clear
    info_echo "尝试更新系统内核及所有软件包..."
    
    local reboot_required=false
    local update_log="/tmp/kernel_update.log"; rm -f "$update_log"

    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -qq >"$update_log" 2>&1
            apt-get dist-upgrade -y >>"$update_log" 2>&1
            if [ -f /var/run/reboot-required ]; then reboot_required=true; fi
            ;;
        "centos" | "rocky" | "almalinux" | "fedora")
            yum update -y >"$update_log" 2>&1
            if rpm -q kernel | grep -qv "$(uname -r)"; then reboot_required=true; fi
            ;;
        *) error_echo "不支持的操作系统: $OS_TYPE"; sleep 2; return 1;;
    esac
    
    if grep -qE "Err:|Error:|Fail|fail" "$update_log"; then
        error_echo "系统更新失败。请检查日志: $update_log"
        cat "$update_log" >&2
    else
        success_echo "系统更新完成。"
    fi

    if $reboot_required; then
        warning_echo "内核已更新，系统需要重启才能生效！"
        local confirm
        safe_read "是否立即重启系统? (y/N): " confirm
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            info_echo "系统将在 5 秒后重启..."; sleep 5; reboot
        else
            info_echo "请在方便的时候手动重启系统以应用新的内核。"
        fi
    else
        info_echo "系统更新完成，无需重启。"
    fi
    local dummy; safe_read "按 Enter 继续..." dummy
}

################################################################################
# 系统优化模块
################################################################################

system_optimization_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== 系统优化 ===${ENDCOLOR}"
        echo " 1. 创建/管理 Swap (虚拟内存)"
        echo -e "    ${YELLOW}说明: 当物理内存不足时，使用硬盘空间作为内存，防止服务因内存不足而崩溃。${ENDCOLOR}"
        echo " 2. 优化网络参数 (BBR + TCP优化)"
        echo -e "    ${YELLOW}说明: 启用 Google BBR 拥塞控制算法并调整TCP参数，提升网络吞吐量和速度。${ENDCOLOR}"
        echo " 3. 优化系统限制 (ulimit)"
        echo -e "    ${YELLOW}说明: 提高系统对最大打开文件数的限制，对高并发服务至关重要。${ENDCOLOR}"
        echo " 4. 清理系统垃圾"
        echo -e "    ${YELLOW}说明: 清理包缓存、旧内核和无用依赖，释放磁盘空间。${ENDCOLOR}"
        echo " 0. 返回主菜单"
        echo "----------------"
        local choice
        safe_read "请选择操作: " choice
        case $choice in
            1) manage_swap ;;
            2) optimize_network ;;
            3) optimize_limits ;;
            4) clean_system ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

create_swap_file() {
    local swap_size_mb="$1"
    local swap_file="/swapfile"
    
    info_echo "正在创建 ${swap_size_mb}MB Swap 文件..."
    fallocate -l "${swap_size_mb}M" "$swap_file" >/dev/null 2>&1 || {
        warning_echo "fallocate 失败, 尝试使用 dd 创建 (速度较慢)..."
        dd if=/dev/zero of=$swap_file bs=1M count=$swap_size_mb >/dev/null 2>&1
    } || { error_echo "Swap 文件创建失败"; return 1; }
    
    chmod 600 "$swap_file"
    mkswap "$swap_file" >/dev/null 2>&1 || { error_echo "mkswap 失败"; rm -f "$swap_file"; return 1; }
    swapon "$swap_file" || { error_echo "swapon失败"; rm -f "$swap_file"; return 1; }
    
    if ! grep -q "$swap_file" /etc/fstab; then
        echo "$swap_file none swap sw 0 0" >> /etc/fstab
    fi
    success_echo "Swap 文件创建并启用成功。"
    return 0
}

manage_swap() {
    clear
    local current_swap=$(swapon --show --noheadings | awk '{print $1}')
    if [[ -z "$current_swap" ]]; then
        info_echo "当前系统没有活动的 Swap。"
        local size
        safe_read "请输入要创建的 Swap 大小 (MB, 推荐 1024): " size
        if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -gt 0 ]; then
            create_swap_file "$size"
        else
            error_echo "无效的输入。"
        fi
    else
        info_echo "检测到活动的 Swap 文件: $current_swap"
        free -h
        local confirm
        safe_read "是否要删除此 Swap 文件? (y/N): " confirm
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            info_echo "正在删除 Swap..."
            swapoff "$current_swap" || { error_echo "Swap 停用失败"; sleep 2; return 1; }
            sed -i "\|$current_swap|d" /etc/fstab
            rm -f "$current_swap"
            success_echo "Swap 删除成功。"
        fi
    fi
    local dummy; safe_read "按 Enter 继续..." dummy
}

optimize_network() {
    clear
    info_echo "正在应用网络优化配置 (BBR + TCP Tuning)..."
    local sysctl_conf="/etc/sysctl.d/99-custom-network.conf"
    
    cat > "$sysctl_conf" << EOF
# Enable BBR congestion control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Recommended TCP/IP stack tuning
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 16384 16777216
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fastopen=3
EOF
    
    # 应用配置
    sysctl -p "$sysctl_conf" >/dev/null 2>&1
    
    # 验证 BBR 是否启用
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        success_echo "网络优化配置已应用。BBR 已成功启用。"
    else
        error_echo "网络优化配置应用失败或 BBR 不支持。可能需要更新内核。"
    fi
    local dummy; safe_read "按 Enter 继续..." dummy
}

optimize_limits() {
    clear
    info_echo "正在优化系统文件描述符限制 (ulimit)..."
    local limits_conf="/etc/security/limits.d/99-custom-limits.conf"
    
    cat > "$limits_conf" << EOF
# Increase file descriptor limits for all users
* soft nofile 65536
* hard nofile 65536
root soft nofile 65536
root hard nofile 65536
EOF
    
    success_echo "系统限制配置已写入 $limits_conf。"
    warning_echo "此项配置需要重新登录或重启系统才能完全生效。"
    local dummy; safe_read "按 Enter 继续..." dummy
}

clean_system() {
    clear
    info_echo "正在清理系统垃圾..."
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get autoremove -y >/dev/null 2>&1
            apt-get clean -y >/dev/null 2>&1
            ;;
        "centos" | "rocky" | "almalinux" | "fedora")
            yum autoremove -y >/dev/null 2>&1
            yum clean all >/dev/null 2>&1
            ;;
        *) error_echo "不支持的操作系统: $OS_TYPE"; sleep 2; return 1;;
    esac
    
    info_echo "正在清理旧的 journald 日志 (保留最近7天)..."
    journalctl --vacuum-time=7d >/dev/null 2>&1
    
    success_echo "系统垃圾清理完成。"
    local dummy; safe_read "按 Enter 继续..." dummy
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
    if systemctl is-active --quiet shadowsocks-libev-server@config.service 2>/dev/null || systemctl is-active --quiet shadowsocks-libev 2>/dev/null; then
        ss_status="${GREEN}运行中${ENDCOLOR}"
    elif [[ -f /etc/shadowsocks-libev/config.json ]]; then
        ss_status="${RED}已停止${ENDCOLOR}"
    fi

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v2.1) ${ENDCOLOR}"
    echo -e "${YELLOW}项目地址：${CYAN}https://github.com/everett7623/hy2${ENDCOLOR}"
    echo -e "${YELLOW}博客地址：${CYAN}https://seedloc.com${ENDCOLOR}"
    echo -e "${YELLOW}论坛地址：${CYAN}https://nodeloc.com${ENDCOLOR}"
    echo
    echo -e " 服务器 IPv4:  ${GREEN}${ipv4_display}${ENDCOLOR}"
    echo -e " 服务器 IPv6:  ${GREEN}${ipv6_display}${ENDCOLOR}"
    echo -e " Hysteria2 状态: ${hy2_status}"
    echo -e " Shadowsocks 状态: ${ss_status}"
    echo -e "${PURPLE}================================================${ENDCOLOR}"
    echo -e " 1. 安装 Hysteria2 (自签模式，无需域名解析)"
    echo -e " 2. 安装 Shadowsocks (仅 IPv6)"
    echo -e " 3. 服务管理"
    echo -e " 4. 卸载服务"
    echo -e " 5. 更新服务"
    echo -e " 6. 系统优化"
    echo -e " 0. 退出脚本"
    echo -e "${PURPLE}================================================${ENDCOLOR}"
}

manage_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}"
        echo " 1. 管理 Hysteria2"
        echo " 2. 管理 Shadowsocks"
        echo " 0. 返回主菜单"
        echo "----------------"
        local choice
        safe_read "请选择要管理的服务: " choice
        case $choice in
            1)
                if [[ ! -f /etc/systemd/system/hysteria-server.service ]]; then
                    error_echo "Hysteria2 未安装"; sleep 1.5; continue
                fi
                manage_single_service "hysteria-server" "Hysteria2"
                ;;
            2)
                if [[ ! -f /etc/shadowsocks-libev/config.json ]]; then
                    error_echo "Shadowsocks 未安装"; sleep 1.5; continue
                fi
                local ss_service_name="shadowsocks-libev"
                if systemctl list-unit-files | grep -q "shadowsocks-libev-server@"; then
                    ss_service_name="shadowsocks-libev-server@config.service"
                fi
                manage_single_service "$ss_service_name" "Shadowsocks"
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
        echo " 4. 查看实时日志"
        echo " 5. 显示连接配置"
        echo " 0. 返回上级菜单"
        echo "----------------"
        local action
        safe_read "请选择操作: " action
        case $action in
            1) systemctl start "$service_name" && success_echo "服务启动成功" || error_echo "服务启动失败"; sleep 1.5 ;;
            2) systemctl stop "$service_name" && success_echo "服务停止成功" || error_echo "服务停止失败"; sleep 1.5 ;;
            3) systemctl restart "$service_name" && success_echo "服务重启成功" || error_echo "服务重启失败"; sleep 1.5 ;;
            4) clear; journalctl -u "$service_name" -f -n 20 ;;
            5)
                case "$display_name" in
                    Hysteria2) show_hysteria2_config ;;
                    Shadowsocks) show_shadowsocks_config ;;
                esac
                ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}

show_hysteria2_config() {
    local quiet_mode=$1
    [[ -z "$quiet_mode" ]] && clear
    
    if [[ ! -f /etc/hysteria2/server.yaml ]]; then
        error_echo "Hysteria2 配置文件不存在"; sleep 2; return;
    fi

    HY_PASSWORD=$(grep "password:" /etc/hysteria2/server.yaml | awk '{print $2}')
    if [[ -f /etc/hysteria2/certs/server.crt ]]; then
        HY_DOMAIN=$(openssl x509 -in /etc/hysteria2/certs/server.crt -noout -subject | grep -o "CN=[^,]*" | cut -d= -f2)
    else
        HY_DOMAIN="<无法读取>"
    fi

    generate_hy2_configs
    
    [[ -z "$quiet_mode" ]] && local dummy && safe_read "按 Enter 继续..." dummy
}

show_shadowsocks_config() {
    local quiet_mode=$1
    [[ -z "$quiet_mode" ]] && clear
    
    if [[ ! -f /etc/shadowsocks-libev/config.json ]]; then
        error_echo "Shadowsocks 配置文件不存在"; sleep 2; return;
    fi

    SS_PORT=$(grep "server_port" /etc/shadowsocks-libev/config.json | grep -o "[0-9]*")
    SS_PASSWORD=$(grep "password" /etc/shadowsocks-libev/config.json | cut -d'"' -f4)
    SS_METHOD=$(grep "method" /etc/shadowsocks-libev/config.json | cut -d'"' -f4)

    generate_ss_configs

    [[ -z "$quiet_mode" ]] && local dummy && safe_read "按 Enter 继续..." dummy
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
        local choice
        safe_read "请选择要卸载的服务: " choice
        case $choice in
            1)
                safe_read "确定要卸载 Hysteria2 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall; success_echo "操作完成"; sleep 2;
                fi
                ;;
            2)
                safe_read "确定要卸载 Shadowsocks 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    ss_uninstall; success_echo "操作完成"; sleep 2;
                fi
                ;;
            3)
                safe_read "确定要卸载所有服务吗? 这将清除所有相关配置！ (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall
                    ss_uninstall
                    success_echo "所有服务已卸载完成"; sleep 2;
                fi
                ;;
            0) return ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
    done
}


################################################################################
# 主程序入口
################################################################################

main() {
    check_root
    detect_system
    detect_network
    check_and_create_swap
    
    # 清理可能存在的输入污染
    exec </dev/tty 2>/dev/null || true
    while read -t 0.1 -n 1000 discard 2>/dev/null; do true; done
    
    while true; do
        show_menu
        local choice
        safe_read "${YELLOW}请选择操作 [0-6]:${ENDCOLOR} " choice
        
        case $choice in
            1) hy2_install ;;
            2) ss_install ;;
            3) manage_services ;;
            4) uninstall_services ;;
            5) update_menu ;;
            6) system_optimization_menu ;;
            0) echo; success_echo "感谢使用脚本！"; exit 0 ;;
            *) error_echo "无效的选择，请输入 0-6 之间的数字"; sleep 1 ;;
        esac
    done
}

# 脚本入口点
main "$@"
