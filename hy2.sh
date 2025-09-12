#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本 - 优化版
# 版本: 2.0.0
# 描述: 此脚本用于在 IPv6-Only 或双栈服务器上快速安装和管理 Hysteria2 和 Shadowsocks 服务。
#       Hysteria2 使用自签名证书模式，无需域名。
#       Shadowsocks 仅监听 IPv6 地址。

# --- 脚本行为设置 ---
set -euo pipefail

# --- 颜色定义 ---
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BG_PURPLE='\033[45m'
readonly ENDCOLOR='\033[0m'

# --- 全局变量 ---
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_DIR="/var/log/hy2ss"
readonly TEMP_DIR="/tmp/hy2ss_install"
readonly MAX_RETRIES=3
readonly TIMEOUT_DURATION=30

# 系统信息
OS_TYPE=""
ARCH=""
IPV4_ADDR=""
IPV6_ADDR=""
HAS_IPV4=false
HAS_IPV6=false

# Hysteria2 变量
HY_DOMAIN=""
HY_PASSWORD=""
HY_SERVER_IP_CHOICE=""
readonly FAKE_URL="https://www.bing.com"

# Shadowsocks 变量
SS_PORT=""
SS_PASSWORD=""
readonly SS_METHOD="chacha20-ietf-poly1305"

# 下载镜像列表 (按优先级排序)
readonly GITHUB_MIRRORS=(
    "https://github.com"
    "https://mirror.ghproxy.com/https://github.com"
    "https://ghproxy.net/https://github.com"
)

readonly API_MIRRORS=(
    "https://api.github.com"
    "https://mirror.ghproxy.com/https://api.github.com"
)

################################################################################
# 日志和工具函数
################################################################################

# 创建日志目录
setup_logging() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR"
        chmod 755 "$LOG_DIR"
    fi
}

# 日志记录函数
log_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/install.log"
}

# 消息输出函数
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

# 清理函数
cleanup_on_exit() {
    local exit_code=$?
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        error_echo "脚本异常退出，退出码: $exit_code"
        error_echo "请检查日志文件: $LOG_DIR/install.log"
    fi
    
    # 清理输入缓冲区
    exec </dev/tty 2>/dev/null || true
    while read -t 0.1 -n 1000 discard 2>/dev/null; do
        true
    done
}

trap cleanup_on_exit EXIT

# 重试执行函数
retry_command() {
    local max_attempts="$1"
    local delay="$2"
    shift 2
    local cmd="$*"
    
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if eval "$cmd"; then
            return 0
        fi
        
        if [[ $attempt -lt $max_attempts ]]; then
            warning_echo "命令执行失败 (尝试 $attempt/$max_attempts)，${delay}秒后重试..."
            sleep "$delay"
        fi
        
        ((attempt++))
    done
    
    error_echo "命令在 $max_attempts 次尝试后仍然失败: $cmd"
    return 1
}

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查端口是否被占用
check_port() {
    local port="$1"
    if command_exists ss; then
        ss -tuln | grep -q ":$port "
    elif command_exists netstat; then
        netstat -tuln | grep -q ":$port "
    else
        # 尝试绑定端口进行测试
        timeout 1 bash -c "echo >/dev/tcp/localhost/$port" 2>/dev/null
    fi
}

# 安全输入函数
safe_read() {
    local prompt="$1"
    local var_name="$2"
    local default_value="${3:-}"
    local input
    
    # 清理输入缓冲区
    while read -t 0; do
        read -r discard
    done
    
    while true; do
        if [[ -n "$default_value" ]]; then
            echo -n "$prompt (默认: $default_value): "
        else
            echo -n "$prompt: "
        fi
        
        if read -r input </dev/tty 2>/dev/null || read -r input; then
            # 清理输入
            input=$(echo "$input" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -d '\r\n')
            
            # 如果输入为空且有默认值，使用默认值
            if [[ -z "$input" && -n "$default_value" ]]; then
                input="$default_value"
            fi
            
            # 验证输入不为空或包含有效字符
            if [[ -n "$input" ]]; then
                eval "$var_name='$input'"
                return 0
            elif [[ -z "$default_value" ]]; then
                warning_echo "输入不能为空，请重新输入"
                continue
            fi
        else
            error_echo "读取输入失败"
            return 1
        fi
    done
}

# 安全密码输入函数
safe_read_password() {
    local prompt="$1"
    local var_name="$2"
    local input
    
    while read -t 0; do
        read -r discard
    done
    
    echo -n "$prompt: "
    if read -s -r input </dev/tty 2>/dev/null || read -s -r input; then
        input=$(echo "$input" | tr -d '\r\n')
        eval "$var_name='$input'"
        echo
        return 0
    else
        echo
        error_echo "密码读取失败"
        return 1
    fi
}

################################################################################
# 系统检测和初始化
################################################################################

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限运行，请尝试使用 'sudo bash $0'"
        exit 1
    fi
}

# 系统检测
detect_system() {
    info_echo "检测系统环境..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_TYPE=$ID
        info_echo "检测到操作系统: $PRETTY_NAME"
    else
        error_echo "无法检测到操作系统类型"
        exit 1
    fi

    case $(uname -m) in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) 
            error_echo "不支持的 CPU 架构: $(uname -m)"
            exit 1 
            ;;
    esac
    
    info_echo "系统架构: $ARCH"
    
    # 检查必要的系统命令
    local missing_commands=()
    for cmd in curl wget openssl systemctl; do
        if ! command_exists "$cmd"; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        error_echo "缺少必要的系统命令: ${missing_commands[*]}"
        info_echo "请先安装这些命令后再运行脚本"
        exit 1
    fi
}

# 增强的网络检测
detect_network() {
    info_echo "检测网络环境..."
    
    # IPv4 检测 - 使用多个服务进行检测
    local ipv4_services=(
        "https://api.ipify.org"
        "https://ipv4.icanhazip.com"
        "https://checkip.amazonaws.com"
    )
    
    for service in "${ipv4_services[@]}"; do
        if IPV4_ADDR=$(timeout 10 curl -4 -s "$service" 2>/dev/null); then
            if [[ -n "$IPV4_ADDR" && "$IPV4_ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                HAS_IPV4=true
                info_echo "检测到公网 IPv4 地址: $IPV4_ADDR"
                break
            fi
        fi
    done
    
    if ! $HAS_IPV4; then
        warning_echo "未检测到公网 IPv4 地址"
        IPV4_ADDR="N/A"
    fi

    # IPv6 检测 - 使用多个服务进行检测
    local ipv6_services=(
        "https://api64.ipify.org"
        "https://ipv6.icanhazip.com"
        "https://checkipv6.amazonaws.com"
    )
    
    for service in "${ipv6_services[@]}"; do
        if IPV6_ADDR=$(timeout 10 curl -6 -s "$service" 2>/dev/null); then
            if [[ -n "$IPV6_ADDR" && "$IPV6_ADDR" =~ ^[0-9a-fA-F:]+$ ]]; then
                # 验证 IPv6 连通性
                if timeout 5 ping6 -c 1 google.com >/dev/null 2>&1; then
                    HAS_IPV6=true
                    info_echo "检测到可路由公网 IPv6 地址: $IPV6_ADDR"
                    break
                fi
            fi
        fi
    done

    # 如果在线检测失败，尝试本地检测
    if ! $HAS_IPV6; then
        local local_ipv6
        local_ipv6=$(ip -6 addr show scope global | grep -v temporary | grep -v deprecated | awk '/inet6/ {print $2}' | cut -d/ -f1 | head -n1)
        if [[ -n "$local_ipv6" ]]; then
            if timeout 5 ping6 -c 1 google.com >/dev/null 2>&1; then
                IPV6_ADDR="$local_ipv6"
                HAS_IPV6=true
                info_echo "本地检测到可路由公网 IPv6 地址: $IPV6_ADDR"
            fi
        fi
    fi
    
    if ! $HAS_IPV6; then
        warning_echo "未检测到可用的 IPv6 地址"
        IPV6_ADDR="N/A"
    fi
    
    # 网络连通性测试
    info_echo "测试网络连通性..."
    local connectivity_ok=false
    
    if timeout 10 curl -s https://www.google.com >/dev/null 2>&1; then
        connectivity_ok=true
    elif timeout 10 curl -s https://www.baidu.com >/dev/null 2>&1; then
        connectivity_ok=true
    fi
    
    if ! $connectivity_ok; then
        warning_echo "网络连通性测试失败，可能影响后续下载"
    else
        success_echo "网络连通性正常"
    fi
}

# 智能 Swap 管理
manage_swap() {
    local total_ram_kb
    total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))
    local current_swap_mb
    current_swap_mb=$(free -m | grep Swap | awk '{print $2}')
    
    info_echo "系统内存: ${total_ram_mb}MB，当前 Swap: ${current_swap_mb}MB"
    
    # 如果内存小于 1GB 且无 Swap，建议创建
    if [[ $total_ram_mb -lt 1024 && $current_swap_mb -eq 0 ]]; then
        warning_echo "检测到系统内存较低且无 Swap 空间"
        
        local confirm
        safe_read "是否创建 1GB Swap 文件以确保安装稳定性？" confirm "y"
        
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            create_swap_file
        else
            warning_echo "跳过 Swap 创建，安装过程中如遇到内存不足问题请手动创建"
        fi
    fi
}

create_swap_file() {
    local swap_file="/swapfile"
    local swap_size_mb=1024
    
    info_echo "创建 ${swap_size_mb}MB Swap 文件..."
    
    if dd if=/dev/zero of="$swap_file" bs=1M count=$swap_size_mb status=progress 2>/dev/null; then
        chmod 600 "$swap_file"
        
        if mkswap "$swap_file" >/dev/null 2>&1 && swapon "$swap_file"; then
            # 添加到 /etc/fstab 以便永久生效
            if ! grep -q "$swap_file" /etc/fstab; then
                echo "$swap_file none swap sw 0 0" >> /etc/fstab
            fi
            success_echo "Swap 文件创建并启用成功"
        else
            error_echo "Swap 文件启用失败"
            rm -f "$swap_file"
        fi
    else
        error_echo "Swap 文件创建失败"
    fi
}

################################################################################
# 网络下载和包管理
################################################################################

# 智能下载函数
smart_download() {
    local url="$1"
    local output_file="$2"
    local description="${3:-文件}"
    
    info_echo "下载 $description..."
    
    # 尝试不同的下载工具
    local download_tools=("curl" "wget")
    local download_success=false
    
    for tool in "${download_tools[@]}"; do
        if command_exists "$tool"; then
            case "$tool" in
                curl)
                    if retry_command $MAX_RETRIES 5 "curl -fsSL --connect-timeout $TIMEOUT_DURATION -o '$output_file' '$url'"; then
                        download_success=true
                        break
                    fi
                    ;;
                wget)
                    if retry_command $MAX_RETRIES 5 "wget -q --timeout=$TIMEOUT_DURATION -O '$output_file' '$url'"; then
                        download_success=true
                        break
                    fi
                    ;;
            esac
        fi
    done
    
    if ! $download_success; then
        error_echo "$description 下载失败"
        return 1
    fi
    
    # 验证下载的文件
    if [[ ! -s "$output_file" ]]; then
        error_echo "下载的文件为空"
        rm -f "$output_file"
        return 1
    fi
    
    success_echo "$description 下载完成"
    return 0
}

# 获取 GitHub 最新版本
get_github_latest_version() {
    local repo="$1"
    local version=""
    
    for api_url in "${API_MIRRORS[@]}"; do
        local url="${api_url}/repos/${repo}/releases/latest"
        
        if version=$(timeout 10 curl -s "$url" 2>/dev/null | grep '"tag_name"' | cut -d '"' -f 4); then
            if [[ -n "$version" ]]; then
                echo "$version"
                return 0
            fi
        fi
    done
    
    error_echo "无法获取 $repo 的最新版本信息"
    return 1
}

# 包管理器操作
update_package_list() {
    local log_file="$LOG_DIR/package_update.log"
    
    case "$OS_TYPE" in
        ubuntu|debian)
            info_echo "更新 apt 包列表..."
            if ! apt-get update -qq >"$log_file" 2>&1; then
                warning_echo "apt 更新失败，尝试修复源配置..."
                fix_debian_sources
                retry_command 2 5 "apt-get update -qq >'$log_file' 2>&1"
            fi
            ;;
        centos|rocky|almalinux)
            info_echo "更新 yum 缓存..."
            retry_command 2 5 "yum makecache fast >'$log_file' 2>&1"
            ;;
        fedora)
            info_echo "更新 dnf 缓存..."
            retry_command 2 5 "dnf makecache >'$log_file' 2>&1"
            ;;
    esac
}

install_packages() {
    local packages=("$@")
    local log_file="$LOG_DIR/package_install.log"
    
    info_echo "安装软件包: ${packages[*]}"
    
    case "$OS_TYPE" in
        ubuntu|debian)
            if ! apt-get install -y "${packages[@]}" >"$log_file" 2>&1; then
                error_echo "软件包安装失败，请检查日志: $log_file"
                return 1
            fi
            ;;
        centos|rocky|almalinux)
            # 先确保 EPEL 源可用
            if ! rpm -q epel-release >/dev/null 2>&1; then
                yum install -y epel-release >"$log_file" 2>&1 || true
            fi
            if ! yum install -y "${packages[@]}" >"$log_file" 2>&1; then
                error_echo "软件包安装失败，请检查日志: $log_file"
                return 1
            fi
            ;;
        fedora)
            if ! dnf install -y "${packages[@]}" >"$log_file" 2>&1; then
                error_echo "软件包安装失败，请检查日志: $log_file"
                return 1
            fi
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE"
            return 1
            ;;
    esac
    
    success_echo "软件包安装完成"
}

# 修复 Debian/Ubuntu 源
fix_debian_sources() {
    if [[ "$OS_TYPE" != "ubuntu" && "$OS_TYPE" != "debian" ]]; then
        return 0
    fi
    
    local sources_list="/etc/apt/sources.list"
    local backup_file="${sources_list}.bak.$(date +%s)"
    
    warning_echo "备份并修复 apt 源配置..."
    
    if [[ -f "$sources_list" ]]; then
        cp "$sources_list" "$backup_file"
        info_echo "原配置已备份到: $backup_file"
    fi
    
    local codename
    codename=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2)
    
    if [[ -z "$codename" ]]; then
        error_echo "无法获取系统版本代号"
        return 1
    fi
    
    # 生成新的源配置
    cat > "$sources_list" <<EOF
deb https://mirrors.ustc.edu.cn/${OS_TYPE}/ $codename main contrib non-free
deb-src https://mirrors.ustc.edu.cn/${OS_TYPE}/ $codename main contrib non-free

deb https://mirrors.ustc.edu.cn/${OS_TYPE}/ $codename-updates main contrib non-free
deb-src https://mirrors.ustc.edu.cn/${OS_TYPE}/ $codename-updates main contrib non-free

deb https://mirrors.ustc.edu.cn/${OS_TYPE}/ $codename-backports main contrib non-free
deb-src https://mirrors.ustc.edu.cn/${OS_TYPE}/ $codename-backports main contrib non-free

deb https://mirrors.ustc.edu.cn/${OS_TYPE}-security/ $codename-security main contrib non-free
deb-src https://mirrors.ustc.edu.cn/${OS_TYPE}-security/ $codename-security main contrib non-free
EOF
    
    success_echo "apt 源已修复为中科大镜像"
}

################################################################################
# Hysteria2 安装模块
################################################################################

# 安装前检查
hy2_pre_install_check() {
    info_echo "Hysteria2 安装前检查..."
    
    # 检查是否已安装
    if systemctl list-unit-files | grep -q "hysteria-server.service"; then
        warning_echo "检测到 Hysteria2 已安装"
        local confirm
        safe_read "是否要重新安装 Hysteria2？" confirm "n"
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            return 1
        fi
        hy2_uninstall
    fi
    
    # 检查端口占用
    if check_port 443; then
        warning_echo "端口 443 已被占用"
        local confirm
        safe_read "是否继续安装？这可能导致服务冲突" confirm "n"
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            return 1
        fi
    fi
    
    return 0
}

# 获取用户输入
hy2_get_user_input() {
    echo
    echo -e "${CYAN}=== Hysteria2 配置 ===${ENDCOLOR}"
    echo
    
    # SNI 域名配置
    safe_read "请输入 SNI 伪装域名" HY_DOMAIN "amd.com"
    
    # 验证域名格式
    if [[ ! "$HY_DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        error_echo "域名格式无效"
        return 1
    fi
    
    # 密码配置
    safe_read_password "请输入连接密码 (留空自动生成)" HY_PASSWORD
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    # IP 选择
    if $HAS_IPV4 && $HAS_IPV6; then
        echo
        info_echo "检测到 IPv4 ($IPV4_ADDR) 和 IPv6 ($IPV6_ADDR)"
        safe_read "请选择客户端连接方式 (1=IPv4, 2=IPv6)" ip_choice "1"
        case "$ip_choice" in
            1) HY_SERVER_IP_CHOICE="ipv4" ;;
            2) HY_SERVER_IP_CHOICE="ipv6" ;;
            *) error_echo "无效选择"; return 1 ;;
        esac
    elif $HAS_IPV4; then
        HY_SERVER_IP_CHOICE="ipv4"
        info_echo "将使用 IPv4 连接"
    elif $HAS_IPV6; then
        HY_SERVER_IP_CHOICE="ipv6"
        info_echo "将使用 IPv6 连接"
    else
        error_echo "无可用的公网 IP 地址"
        return 1
    fi
    
    return 0
}

# 下载并安装 Hysteria2
hy2_download_install() {
    info_echo "下载并安装 Hysteria2..."
    
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # 获取最新版本
    local latest_version
    if ! latest_version=$(get_github_latest_version "apernet/hysteria"); then
        return 1
    fi
    
    info_echo "最新版本: $latest_version"
    
    # 尝试不同的下载镜像
    local download_success=false
    local binary_file="hysteria"
    
    for mirror in "${GITHUB_MIRRORS[@]}"; do
        local download_url="${mirror}/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
        
        info_echo "尝试从 $mirror 下载..."
        if smart_download "$download_url" "$binary_file" "Hysteria2 二进制文件"; then
            download_success=true
            break
        fi
    done
    
    if ! $download_success; then
        error_echo "所有下载镜像均失败"
        return 1
    fi
    
    # 验证下载的文件
    if ! file "$binary_file" | grep -q "executable"; then
        error_echo "下载的文件不是有效的可执行文件"
        return 1
    fi
    
    # 安装二进制文件
    chmod +x "$binary_file"
    mv "$binary_file" /usr/local/bin/hysteria
    
    # 验证安装
    if ! /usr/local/bin/hysteria version >/dev/null 2>&1; then
        error_echo "Hysteria2 安装验证失败"
        return 1
    fi
    
    success_echo "Hysteria2 安装成功"
    return 0
}

# 生成自签名证书
hy2_generate_cert() {
    info_echo "生成自签名证书..."
    
    local cert_dir="/etc/hysteria2/certs"
    mkdir -p "$cert_dir"
    
    # 生成私钥和证书
    if ! openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$cert_dir/server.key" \
        -out "$cert_dir/server.crt" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$HY_DOMAIN" \
        >/dev/null 2>&1; then
        error_echo "证书生成失败"
        return 1
    fi
    
    # 设置适当的权限
    chmod 600 "$cert_dir/server.key"
    chmod 644 "$cert_dir/server.crt"
    
    success_echo "自签名证书生成完成"
    return 0
}

# 生成配置文件
hy2_create_config() {
    info_echo "生成 Hysteria2 配置文件..."
    
    local config_dir="/etc/hysteria2"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/server.yaml" <<EOF
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
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024

bandwidth:
  up: 1 gbps
  down: 1 gbps
EOF

    # 设置配置文件权限
    chmod 600 "$config_dir/server.yaml"
    
    success_echo "配置文件生成完成"
    return 0
}

# 创建系统服务
hy2_create_service() {
    info_echo "创建 Hysteria2 系统服务..."
    
    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria 2 Server
Documentation=https://hysteria.network/
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/server.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    # 配置防火墙
    configure_firewall 443 "udp" "Hysteria2"
    
    # 启动并启用服务
    if ! systemctl enable --now hysteria-server; then
        error_echo "服务启动失败"
        return 1
    fi
    
    # 等待服务启动
    sleep 3
    
    # 验证服务状态
    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "服务运行异常"
        info_echo "错误日志："
        journalctl -u hysteria-server -n 10 --no-pager
        return 1
    fi
    
    success_echo "Hysteria2 服务创建并启动成功"
    return 0
}

# 配置防火墙
configure_firewall() {
    local port="$1"
    local protocol="$2"
    local service_name="$3"
    
    info_echo "配置防火墙规则 ($service_name: $port/$protocol)..."
    
    # UFW (Ubuntu/Debian)
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$port/$protocol" >/dev/null 2>&1 && \
        success_echo "UFW 防火墙规则已添加" || \
        warning_echo "UFW 防火墙规则添加失败"
    fi
    
    # Firewalld (CentOS/RHEL/Fedora)
    if command_exists firewall-cmd && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="$port/$protocol" >/dev/null 2>&1 && \
        firewall-cmd --reload >/dev/null 2>&1 && \
        success_echo "Firewalld 防火墙规则已添加" || \
        warning_echo "Firewalld 防火墙规则添加失败"
    fi
    
    # Iptables (通用)
    if command_exists iptables && ! command_exists ufw && ! systemctl is-active --quiet firewalld; then
        iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT >/dev/null 2>&1 && \
        info_echo "Iptables 规则已添加（临时，重启后失效）" || \
        warning_echo "Iptables 规则添加失败"
    fi
}

# 生成客户端配置
hy2_generate_client_configs() {
    local server_addr_uri=""
    local server_addr_field=""

    if [[ "$HY_SERVER_IP_CHOICE" == "ipv6" ]]; then
        if [[ "$IPV6_ADDR" == "N/A" ]]; then
            error_echo "IPv6 地址无效"
            return 1
        fi
        server_addr_uri="[$IPV6_ADDR]"
        server_addr_field="$IPV6_ADDR"
    else
        if [[ "$IPV4_ADDR" == "N/A" ]]; then
            error_echo "IPv4 地址无效"
            return 1
        fi
        server_addr_uri="$IPV4_ADDR"
        server_addr_field="$IPV4_ADDR"
    fi

    local country_code
    country_code=$(timeout 5 curl -s https://ipapi.co/country_code 2>/dev/null || echo "XX")
    local server_name="Hysteria2-${country_code}-$(date +%m%d)"
    
    echo -e "${PURPLE}=== Hysteria2 客户端配置 ===${ENDCOLOR}"
    echo
    
    # 分享链接
    local hy2_link="hysteria2://$HY_PASSWORD@$server_addr_uri:443/?insecure=true&sni=$HY_DOMAIN#$server_name"
    echo -e "${CYAN}分享链接 (V2rayN/NekoBox/Shadowrocket):${ENDCOLOR}"
    echo "$hy2_link"
    echo
    
    # Clash Meta 配置
    echo -e "${CYAN}Clash Meta 配置:${ENDCOLOR}"
    cat <<EOF
  - name: '$server_name'
    type: hysteria2
    server: $server_addr_field
    port: 443
    password: $HY_PASSWORD
    sni: $HY_DOMAIN
    skip-cert-verify: true
    up: 100
    down: 100
EOF
    echo
    
    # Surge 配置
    echo -e "${CYAN}Surge 配置:${ENDCOLOR}"
    echo "$server_name = hysteria2, $server_addr_field, 443, password=$HY_PASSWORD, sni=$HY_DOMAIN, skip-cert-verify=true"
    echo
    
    # 原始配置
    echo -e "${CYAN}原始配置文件:${ENDCOLOR}"
    cat <<EOF
server: $server_addr_field:443
auth: $HY_PASSWORD
tls:
  sni: $HY_DOMAIN
  insecure: true
bandwidth:
  up: 100 mbps
  down: 100 mbps
EOF
    echo
}

# 显示安装结果
hy2_show_result() {
    clear
    echo -e "${BG_PURPLE} Hysteria2 安装完成！ ${ENDCOLOR}"
    echo
    echo -e "${YELLOW}重要提示: 使用自签名证书，客户端需启用 '允许不安全连接' 选项${ENDCOLOR}"
    echo
    
    echo -e "${PURPLE}=== 基本连接信息 ===${ENDCOLOR}"
    local display_ip=""
    if [[ "$HY_SERVER_IP_CHOICE" == "ipv6" ]]; then
        display_ip="[$IPV6_ADDR]"
    else
        display_ip="$IPV4_ADDR"
    fi
    
    echo -e "服务器地址: ${GREEN}$display_ip${ENDCOLOR}"
    echo -e "服务器端口: ${GREEN}443${ENDCOLOR}"
    echo -e "连接密码:   ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "SNI 域名:   ${GREEN}$HY_DOMAIN${ENDCOLOR}"
    echo -e "证书验证:   ${YELLOW}跳过 (自签名)${ENDCOLOR}"
    echo -e "${PURPLE}========================${ENDCOLOR}"
    echo
    
    hy2_generate_client_configs
    
    local dummy
    safe_read "按 Enter 继续" dummy
}

# Hysteria2 主安装函数
hy2_install() {
    info_echo "开始安装 Hysteria2..."
    
    if ! hy2_pre_install_check; then
        return 1
    fi
    
    if ! hy2_get_user_input; then
        return 1
    fi
    
    # 安装基础依赖
    update_package_list
    install_packages curl wget openssl ca-certificates || return 1
    
    # 执行安装步骤
    hy2_download_install && \
    hy2_generate_cert && \
    hy2_create_config && \
    hy2_create_service && \
    hy2_show_result || {
        error_echo "Hysteria2 安装失败"
        hy2_uninstall
        return 1
    }
}

# Hysteria2 卸载
hy2_uninstall() {
    info_echo "卸载 Hysteria2..."
    
    systemctl disable --now hysteria-server >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria2
    systemctl daemon-reload
    
    success_echo "Hysteria2 卸载完成"
}

# Hysteria2 更新
hy2_update() {
    info_echo "检查 Hysteria2 更新..."
    
    if [[ ! -f /usr/local/bin/hysteria ]]; then
        error_echo "Hysteria2 未安装"
        return 1
    fi

    local current_version
    current_version=$(/usr/local/bin/hysteria version 2>/dev/null | head -n 1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    
    local latest_version
    if ! latest_version=$(get_github_latest_version "apernet/hysteria"); then
        return 1
    fi

    info_echo "当前版本: $current_version"
    info_echo "最新版本: $latest_version"

    if [[ "$latest_version" == "$current_version" ]]; then
        success_echo "Hysteria2 已是最新版本"
        return 0
    fi

    info_echo "发现新版本，开始更新..."
    
    systemctl stop hysteria-server >/dev/null 2>&1 || true
    
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # 下载新版本
    local download_success=false
    for mirror in "${GITHUB_MIRRORS[@]}"; do
        local download_url="${mirror}/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
        
        if smart_download "$download_url" "hysteria_new" "Hysteria2 新版本"; then
            download_success=true
            break
        fi
    done
    
    if ! $download_success; then
        error_echo "下载新版本失败"
        systemctl start hysteria-server >/dev/null 2>&1 || true
        return 1
    fi
    
    # 验证并替换
    if file hysteria_new | grep -q "executable"; then
        chmod +x hysteria_new
        mv hysteria_new /usr/local/bin/hysteria
        
        systemctl start hysteria-server
        sleep 3
        
        if systemctl is-active --quiet hysteria-server; then
            success_echo "Hysteria2 更新成功: $latest_version"
        else
            error_echo "更新后服务启动失败"
            journalctl -u hysteria-server -n 10 --no-pager
            return 1
        fi
    else
        error_echo "下载的文件无效"
        systemctl start hysteria-server >/dev/null 2>&1 || true
        return 1
    fi
}

################################################################################
# Shadowsocks 安装模块
################################################################################

# Shadowsocks IPv6 检查
ss_check_ipv6() {
    info_echo "检查 IPv6 环境..."
    
    if ! $HAS_IPV6 || [[ "$IPV6_ADDR" == "N/A" ]]; then
        if $HAS_IPV4; then
            error_echo "仅检测到 IPv4 地址，Shadowsocks 需要 IPv6 支持"
        else
            error_echo "未检测到任何可用的 IP 地址"
        fi
        return 1
    fi

    # 再次验证 IPv6 连通性
    if ! timeout 5 ping6 -c 1 google.com >/dev/null 2>&1; then
        warning_echo "IPv6 连通性测试失败，但将继续安装"
    fi
    
    success_echo "IPv6 环境检查通过: $IPV6_ADDR"
    return 0
}

# Shadowsocks 安装前检查
ss_pre_install_check() {
    info_echo "Shadowsocks 安装前检查..."
    
    # 检查 IPv6 支持
    if ! ss_check_ipv6; then
        return 1
    fi
    
    # 检查是否已安装
    if systemctl list-unit-files | grep -q "shadowsocks-libev.service"; then
        warning_echo "检测到 Shadowsocks 已安装"
        local confirm
        safe_read "是否要重新安装 Shadowsocks？" confirm "n"
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            return 1
        fi
        ss_uninstall
    fi
    
    return 0
}

# 安装 Shadowsocks 依赖
ss_install_dependencies() {
    info_echo "安装 Shadowsocks 依赖包..."
    
    update_package_list
    
    local packages=("shadowsocks-libev" "qrencode" "curl")
    
    # 某些发行版可能需要额外的包
    case "$OS_TYPE" in
        ubuntu|debian)
            packages+=("libsodium23" "libmbedtls12")
            ;;
        centos|rocky|almalinux)
            packages+=("libsodium" "mbedtls")
            ;;
    esac
    
    if ! install_packages "${packages[@]}"; then
        return 1
    fi

    # 验证 ss-server 命令存在
    if ! command_exists ss-server; then
        error_echo "ss-server 命令未找到，可能安装失败"
        return 1
    fi
    
    success_echo "依赖包安装完成"
    return 0
}

# 生成 Shadowsocks 配置
ss_generate_config() {
    info_echo "生成 Shadowsocks 配置..."
    
    # 生成随机端口 (避免常用端口)
    SS_PORT=$(shuf -i 20000-40000 -n 1)
    
    # 确保端口未被占用
    local attempts=0
    while check_port "$SS_PORT" && [[ $attempts -lt 10 ]]; do
        SS_PORT=$(shuf -i 20000-40000 -n 1)
        ((attempts++))
    done
    
    # 生成强密码
    SS_PASSWORD=$(openssl rand -base64 24)

    local config_dir="/etc/shadowsocks-libev"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/config.json" <<EOF
{
    "server": "::",
    "server_port": $SS_PORT,
    "password": "$SS_PASSWORD",
    "timeout": 300,
    "method": "$SS_METHOD",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "reuse_port": true,
    "no_delay": true
}
EOF

    chmod 600 "$config_dir/config.json"
    success_echo "配置文件生成完成"
    return 0
}

# 创建 Shadowsocks 服务
ss_setup_service() {
    info_echo "创建 Shadowsocks 系统服务..."
    
    cat > /etc/systemd/system/shadowsocks-libev.service <<'EOF'
[Unit]
Description=Shadowsocks-Libev Server Service
Documentation=man:ss-server(1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/config.json -u
Restart=on-failure
RestartSec=5s
User=nobody
Group=nogroup
LimitNOFILE=32768
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    # 配置防火墙
    configure_firewall "$SS_PORT" "tcp" "Shadowsocks-TCP"
    configure_firewall "$SS_PORT" "udp" "Shadowsocks-UDP"
    
    # 启动服务
    if ! systemctl enable --now shadowsocks-libev; then
        error_echo "服务启动失败"
        return 1
    fi
    
    sleep 3
    
    if ! systemctl is-active --quiet shadowsocks-libev; then
        error_echo "服务运行异常"
        info_echo "错误日志："
        journalctl -u shadowsocks-libev -n 10 --no-pager
        return 1
    fi

    success_echo "Shadowsocks 服务创建并启动成功"
    return 0
}

# 生成 Shadowsocks 客户端配置
ss_generate_client_configs() {
    local server_addr_uri="[$IPV6_ADDR]"
    local server_addr_field="$IPV6_ADDR"

    local country_code
    country_code=$(timeout 5 curl -s https://ipapi.co/country_code 2>/dev/null || echo "XX")
    local server_name="Shadowsocks-${country_code}-$(date +%m%d)"
    
    local encoded_auth
    encoded_auth=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)
    
    echo -e "${PURPLE}=== Shadowsocks 客户端配置 ===${ENDCOLOR}"
    echo
    
    # 分享链接
    local ss_link="ss://${encoded_auth}@${server_addr_uri}:${SS_PORT}#${server_name}"
    echo -e "${CYAN}分享链接 (V2rayN/NekoBox/Shadowrocket):${ENDCOLOR}"
    echo "$ss_link"
    echo
    
    # Clash Meta 配置
    echo -e "${CYAN}Clash Meta 配置:${ENDCOLOR}"
    cat <<EOF
  - name: '$server_name'
    type: ss
    server: '$server_addr_field'
    port: $SS_PORT
    password: '$SS_PASSWORD'
    cipher: '$SS_METHOD'
    udp: true
EOF
    echo
    
    # Surge 配置
    echo -e "${CYAN}Surge 配置:${ENDCOLOR}"
    echo "$server_name = ss, $server_addr_field, $SS_PORT, encrypt-method=$SS_METHOD, password=$SS_PASSWORD, udp-relay=true"
    echo
    
    # 原始配置
    echo -e "${CYAN}原始配置信息:${ENDCOLOR}"
    cat <<EOF
服务器地址: $IPV6_ADDR
端口: $SS_PORT
密码: $SS_PASSWORD
加密方式: $SS_METHOD
插件: 无
EOF
    echo
}

# 显示 Shadowsocks 安装结果
ss_display_result() {
    clear
    echo -e "${BG_PURPLE} Shadowsocks (IPv6) 安装完成！ ${ENDCOLOR}"
    echo
    
    echo -e "${PURPLE}=== 基本连接信息 ===${ENDCOLOR}"
    echo -e "服务器地址: ${GREEN}[$IPV6_ADDR]${ENDCOLOR}"
    echo -e "端口:       ${GREEN}$SS_PORT${ENDCOLOR}"
    echo -e "密码:       ${GREEN}$SS_PASSWORD${ENDCOLOR}"
    echo -e "加密方式:   ${GREEN}$SS_METHOD${ENDCOLOR}"
    echo -e "${PURPLE}========================${ENDCOLOR}"
    echo

    # 检查服务状态
    info_echo "检查服务监听状态..."
    if command_exists ss; then
        local listen_info
        listen_info=$(ss -tlnp | grep ":$SS_PORT" | head -1)
        if [[ -n "$listen_info" ]]; then
            success_echo "服务正在监听端口 $SS_PORT"
            echo "$listen_info"
        else
            warning_echo "未检测到端口监听，请检查服务状态"
        fi
    fi
    echo
    
    ss_generate_client_configs
    
    # 生成二维码
    if command_exists qrencode; then
        local encoded_auth
        encoded_auth=$(echo -n "$SS_METHOD:$SS_PASSWORD" | base64 -w 0)
        local ss_link="ss://${encoded_auth}@[${IPV6_ADDR}]:${SS_PORT}#Shadowsocks-$(date +%m%d)"
        
        info_echo "二维码:"
        qrencode -t ANSIUTF8 "$ss_link" 2>/dev/null || warning_echo "二维码生成失败"
    fi
    
    echo
    local dummy
    safe_read "按 Enter 继续" dummy
}

# Shadowsocks 主安装函数
ss_install() {
    info_echo "开始安装 Shadowsocks..."
    
    if ! ss_pre_install_check; then
        return 1
    fi
    
    if ! ss_install_dependencies; then
        return 1
    fi
    
    ss_generate_config && \
    ss_setup_service && \
    ss_display_result || {
        error_echo "Shadowsocks 安装失败"
        ss_uninstall
        return 1
    }
}

# Shadowsocks 卸载
ss_uninstall() {
    info_echo "卸载 Shadowsocks..."
    
    systemctl disable --now shadowsocks-libev >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/shadowsocks-libev.service
    rm -rf /etc/shadowsocks-libev
    systemctl daemon-reload
    
    success_echo "Shadowsocks 卸载完成"
}

# Shadowsocks 更新
ss_update() {
    info_echo "更新 Shadowsocks..."
    
    if [[ ! -f /etc/systemd/system/shadowsocks-libev.service ]]; then
        error_echo "Shadowsocks 未安装"
        return 1
    fi

    local was_active=false
    systemctl is-active --quiet shadowsocks-libev && was_active=true

    info_echo "通过包管理器更新 shadowsocks-libev..."
    update_package_list
    
    case "$OS_TYPE" in
        ubuntu|debian)
            apt-get install -y --only-upgrade shadowsocks-libev
            ;;
        centos|rocky|almalinux)
            yum update -y shadowsocks-libev
            ;;
        fedora)
            dnf update -y shadowsocks-libev
            ;;
        *)
            error_echo "不支持的操作系统"
            return 1
            ;;
    esac

    if $was_active; then
        systemctl restart shadowsocks-libev
        sleep 2
        if systemctl is-active --quiet shadowsocks-libev; then
            success_echo "Shadowsocks 更新并重启成功"
        else
            error_echo "更新后服务启动失败"
            return 1
        fi
    else
        success_echo "Shadowsocks 更新完成"
    fi
}

################################################################################
# 服务管理和用户界面
################################################################################

# 显示服务状态
get_service_status() {
    local service="$1"
    
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo -e "${GREEN}运行中${ENDCOLOR}"
    elif systemctl list-unit-files | grep -q "$service"; then
        echo -e "${RED}已停止${ENDCOLOR}"
    else
        echo "未安装"
    fi
}

# 主菜单
show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-未检测到}"
    local ipv6_display="${IPV6_ADDR:-未检测到}"

    local hy2_status
    hy2_status=$(get_service_status "hysteria-server.service")
    
    local ss_status
    ss_status=$(get_service_status "shadowsocks-libev.service")

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks 管理脚本 v2.0.0 ${ENDCOLOR}"
    echo -e "${YELLOW}项目地址: ${CYAN}https://github.com/everett7623/hy2ipv6${ENDCOLOR}"
    echo
    echo -e "服务器 IPv4: ${GREEN}${ipv4_display}${ENDCOLOR}"
    echo -e "服务器 IPv6: ${GREEN}${ipv6_display}${ENDCOLOR}"
    echo -e "Hysteria2 状态: ${hy2_status}"
    echo -e "Shadowsocks 状态: ${ss_status}"
    echo -e "${PURPLE}================================================${ENDCOLOR}"
    echo " 1. 安装 Hysteria2"
    echo " 2. 安装 Shadowsocks (IPv6)"
    echo " 3. 服务管理"
    echo " 4. 卸载服务"
    echo " 5. 更新服务"
    echo " 6. 系统优化"
    echo " 7. 查看日志"
    echo " 0. 退出脚本"
    echo -e "${PURPLE}================================================${ENDCOLOR}"
}

# 服务管理菜单
manage_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}"
        echo " 1. 管理 Hysteria2"
        echo " 2. 管理 Shadowsocks"
        echo " 0. 返回主菜单"
        echo
        
        local choice
        safe_read "请选择要管理的服务" choice "0"
        
        case $choice in
            1)
                if ! systemctl list-unit-files | grep -q "hysteria-server.service"; then
                    error_echo "Hysteria2 未安装"
                    sleep 2
                    continue
                fi
                manage_single_service "hysteria-server" "Hysteria2"
                ;;
            2)
                if ! systemctl list-unit-files | grep -q "shadowsocks-libev.service"; then
                    error_echo "Shadowsocks 未安装"
                    sleep 2
                    continue
                fi
                manage_single_service "shadowsocks-libev" "Shadowsocks"
                ;;
            0) return ;;
            *) warning_echo "无效选择" ;;
        esac
    done
}

# 单个服务管理
manage_single_service() {
    local service_name="$1"
    local display_name="$2"
    
    while true; do
        clear
        echo -e "${CYAN}=== $display_name 服务管理 ===${ENDCOLOR}"
        echo
        
        # 显示服务状态
        echo "服务状态:"
        systemctl status "$service_name" --no-pager -l | head -10
        echo
        
        echo " 1. 启动服务"
        echo " 2. 停止服务"
        echo " 3. 重启服务"
        echo " 4. 查看实时日志"
        echo " 5. 显示配置信息"
        echo " 0. 返回上级菜单"
        echo
        
        local action
        safe_read "请选择操作" action "0"
        
        case $action in
            1)
                systemctl start "$service_name" && \
                success_echo "服务启动成功" || error_echo "服务启动失败"
                sleep 2
                ;;
            2)
                systemctl stop "$service_name" && \
                success_echo "服务停止成功" || error_echo "服务停止失败"
                sleep 2
                ;;
            3)
                systemctl restart "$service_name" && \
                success_echo "服务重启成功" || error_echo "服务重启失败"
                sleep 2
                ;;
            4)
                clear
                info_echo "实时日志 (按 Ctrl+C 退出):"
                journalctl -u "$service_name" -f
                ;;
            5)
                show_service_config "$service_name" "$display_name"
                ;;
            0) return ;;
            *) warning_echo "无效选择" ;;
        esac
    done
}

# 显示服务配置
show_service_config() {
    local service_name="$1"
    local display_name="$2"
    
    clear
    echo -e "${BG_PURPLE} $display_name 配置信息 ${ENDCOLOR}"
    echo
    
    case "$service_name" in
        hysteria-server)
            show_hysteria_config
            ;;
        shadowsocks-libev)
            show_shadowsocks_config
            ;;
    esac
    
    local dummy
    safe_read "按 Enter 继续" dummy
}

# 显示 Hysteria2 配置
show_hysteria_config() {
    if [[ ! -f /etc/hysteria2/server.yaml ]]; then
        error_echo "配置文件不存在"
        return
    fi

    local password domain
    password=$(grep "password:" /etc/hysteria2/server.yaml | awk '{print $2}')
    domain=$(openssl x509 -in /etc/hysteria2/certs/server.crt -noout -subject 2>/dev/null | grep -o "CN=[^,]*" | cut -d= -f2)

    # 更新全局变量
    HY_PASSWORD="$password"
    HY_DOMAIN="$domain"
    
    echo -e "${PURPLE}=== 基本信息 ===${ENDCOLOR}"
    echo -e "服务器地址: ${GREEN}$([[ "$HY_SERVER_IP_CHOICE" == "ipv6" ]] && echo "[$IPV6_ADDR]" || echo "$IPV4_ADDR")${ENDCOLOR}"
    echo -e "端口: ${GREEN}443${ENDCOLOR}"
    echo -e "密码: ${GREEN}$password${ENDCOLOR}"
    echo -e "SNI: ${GREEN}$domain${ENDCOLOR}"
    echo -e "证书: ${YELLOW}自签名${ENDCOLOR}"
    echo
    
    hy2_generate_client_configs
}

# 显示 Shadowsocks 配置
show_shadowsocks_config() {
    if [[ ! -f /etc/shadowsocks-libev/config.json ]]; then
        error_echo "配置文件不存在"
        return
    fi

    local server_port password method
    server_port=$(grep "server_port" /etc/shadowsocks-libev/config.json | grep -o "[0-9]*")
    password=$(grep "password" /etc/shadowsocks-libev/config.json | cut -d'"' -f4)
    method=$(grep "method" /etc/shadowsocks-libev/config.json | cut -d'"' -f4)

    # 更新全局变量
    SS_PASSWORD="$password"
    SS_PORT="$server_port"
    SS_METHOD="$method"

    echo -e "${PURPLE}=== 基本信息 ===${ENDCOLOR}"
    echo -e "服务器地址: ${GREEN}[$IPV6_ADDR]${ENDCOLOR}"
    echo -e "端口: ${GREEN}$server_port${ENDCOLOR}"
    echo -e "密码: ${GREEN}$password${ENDCOLOR}"
    echo -e "加密方式: ${GREEN}$method${ENDCOLOR}"
    echo

    # 检查监听状态
    info_echo "端口监听状态:"
    if command_exists ss; then
        ss -tlnp | grep ":$server_port" | head -3
    elif command_exists netstat; then
        netstat -tlnp | grep ":$server_port" | head -3
    fi
    echo

    ss_generate_client_configs
}

# 卸载服务菜单
uninstall_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 卸载服务 ===${ENDCOLOR}"
        echo " 1. 卸载 Hysteria2"
        echo " 2. 卸载 Shadowsocks"
        echo " 3. 卸载所有服务"
        echo " 0. 返回主菜单"
        echo
        
        local choice
        safe_read "请选择要卸载的服务" choice "0"
        
        case $choice in
            1)
                if ! systemctl list-unit-files | grep -q "hysteria-server.service"; then
                    error_echo "Hysteria2 未安装"
                    sleep 2
                    continue
                fi
                local confirm
                safe_read "确定要卸载 Hysteria2 吗？" confirm "n"
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall
                    success_echo "Hysteria2 卸载完成"
                    sleep 2
                fi
                ;;
            2)
                if ! systemctl list-unit-files | grep -q "shadowsocks-libev.service"; then
                    error_echo "Shadowsocks 未安装"
                    sleep 2
                    continue
                fi
                local confirm
                safe_read "确定要卸载 Shadowsocks 吗？" confirm "n"
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    ss_uninstall
                    success_echo "Shadowsocks 卸载完成"
                    sleep 2
                fi
                ;;
            3)
                local confirm
                safe_read "确定要卸载所有服务吗？" confirm "n"
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    hy2_uninstall
                    ss_uninstall
                    success_echo "所有服务卸载完成"
                    sleep 2
                fi
                ;;
            0) return ;;
            *) warning_echo "无效选择" ;;
        esac
    done
}

# 更新服务菜单
update_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 更新服务 ===${ENDCOLOR}"
        echo " 1. 更新 Hysteria2"
        echo " 2. 更新 Shadowsocks"
        echo " 3. 更新系统内核"
        echo " 0. 返回主菜单"
        echo
        
        local choice
        safe_read "请选择更新项目" choice "0"
        
        case $choice in
            1)
                hy2_update
                local dummy
                safe_read "按 Enter 继续" dummy
                ;;
            2)
                ss_update
                local dummy
                safe_read "按 Enter 继续" dummy
                ;;
            3)
                update_system_kernel
                ;;
            0) return ;;
            *) warning_echo "无效选择" ;;
        esac
    done
}

# 系统优化菜单
system_optimization() {
    while true; do
        clear
        echo -e "${CYAN}=== 系统优化 ===${ENDCOLOR}"
        echo " 1. 创建/管理 Swap"
        echo " 2. 优化网络参数"
        echo " 3. 优化系统限制"
        echo " 4. 清理系统垃圾"
        echo " 0. 返回主菜单"
        echo
        
        local choice
        safe_read "请选择优化项目" choice "0"
        
        case $choice in
            1) manage_swap_interactive ;;
            2) optimize_network ;;
            3) optimize_limits ;;
            4) clean_system ;;
            0) return ;;
            *) warning_echo "无效选择" ;;
        esac
    done
}

# 交互式 Swap 管理
manage_swap_interactive() {
    clear
    local current_swap_mb
    current_swap_mb=$(free -m | grep Swap | awk '{print $2}')
    
    echo -e "${CYAN}=== Swap 管理 ===${ENDCOLOR}"
    echo "当前 Swap 大小: ${current_swap_mb}MB"
    echo
    
    if [[ $current_swap_mb -eq 0 ]]; then
        info_echo "未检测到 Swap 空间"
        local confirm
        safe_read "是否创建 1GB Swap 文件？" confirm "y"
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            create_swap_file
        fi
    else
        info_echo "Swap 已存在"
        local confirm
        safe_read "是否要重新创建 Swap？" confirm "n"
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            # 禁用现有 Swap
            swapoff -a
            rm -f /swapfile
            sed -i '/swapfile/d' /etc/fstab
            create_swap_file
        fi
    fi
    
    local dummy
    safe_read "按 Enter 继续" dummy
}

# 网络优化
optimize_network() {
    info_echo "优化网络参数..."
    
    # 备份原始配置
    if [[ ! -f /etc/sysctl.conf.bak ]]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi
    
    cat >> /etc/sysctl.conf <<EOF

# Network optimizations for proxy services
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_slow_start_after_idle = 0
EOF

    sysctl -p
    success_echo "网络参数优化完成"
    
    local dummy
    safe_read "按 Enter 继续" dummy
}

# 系统限制优化
optimize_limits() {
    info_echo "优化系统限制..."
    
    # 备份原始配置
    if [[ ! -f /etc/security/limits.conf.bak ]]; then
        cp /etc/security/limits.conf /etc/security/limits.conf.bak
    fi
    
    cat >> /etc/security/limits.conf <<EOF

# Optimizations for proxy services
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
EOF

    success_echo "系统限制优化完成"
    
    local dummy
    safe_read "按 Enter 继续" dummy
}

# 清理系统
clean_system() {
    info_echo "清理系统垃圾..."
    
    # 清理包缓存
    case "$OS_TYPE" in
        ubuntu|debian)
            apt-get autoremove -y >/dev/null 2>&1
            apt-get autoclean >/dev/null 2>&1
            ;;
        centos|rocky|almalinux)
            yum autoremove -y >/dev/null 2>&1
            yum clean all >/dev/null 2>&1
            ;;
        fedora)
            dnf autoremove -y >/dev/null 2>&1
            dnf clean all >/dev/null 2>&1
            ;;
    esac
    
    # 清理日志
    journalctl --vacuum-time=7d >/dev/null 2>&1
    
    # 清理临时文件
    rm -rf /tmp/* /var/tmp/* >/dev/null 2>&1
    
    # 清理脚本临时文件
    rm -rf "$TEMP_DIR" >/dev/null 2>&1
    
    success_echo "系统清理完成"
    
    local dummy
    safe_read "按 Enter 继续" dummy
}

# 更新系统内核
update_system_kernel() {
    clear
    info_echo "更新系统内核和软件包..."
    
    local update_log="$LOG_DIR/system_update.log"
    local reboot_required=false
    
    case "$OS_TYPE" in
        ubuntu|debian)
            info_echo "更新 Debian/Ubuntu 系统..."
            if ! apt-get update -qq >"$update_log" 2>&1; then
                fix_debian_sources
                apt-get update -qq >"$update_log" 2>&1
            fi
            
            if apt-get upgrade -y >>"$update_log" 2>&1; then
                success_echo "系统更新完成"
                if apt list --upgradable 2>/dev/null | grep -q "linux-"; then
                    reboot_required=true
                fi
            else
                error_echo "系统更新失败，请检查日志: $update_log"
                return 1
            fi
            ;;
        centos|rocky|almalinux)
            info_echo "更新 CentOS/Rocky/AlmaLinux 系统..."
            if yum update -y >"$update_log" 2>&1; then
                success_echo "系统更新完成"
                if rpm -q kernel | grep -v "$(uname -r)" >/dev/null 2>&1; then
                    reboot_required=true
                fi
            else
                error_echo "系统更新失败，请检查日志: $update_log"
                return 1
            fi
            ;;
        fedora)
            info_echo "更新 Fedora 系统..."
            if dnf update -y >"$update_log" 2>&1; then
                success_echo "系统更新完成"
                if rpm -q kernel | grep -v "$(uname -r)" >/dev/null 2>&1; then
                    reboot_required=true
                fi
            else
                error_echo "系统更新失败，请检查日志: $update_log"
                return 1
            fi
            ;;
    esac

    if $reboot_required; then
        warning_echo "内核已更新，建议重启系统"
        local confirm
        safe_read "是否立即重启？" confirm "n"
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            info_echo "系统将在 5 秒后重启..."
            sleep 5
            reboot
        fi
    fi
    
    local dummy
    safe_read "按 Enter 继续" dummy
}

# 查看日志菜单
view_logs() {
    while true; do
        clear
        echo -e "${CYAN}=== 查看日志 ===${ENDCOLOR}"
        echo " 1. Hysteria2 日志"
        echo " 2. Shadowsocks 日志"
        echo " 3. 安装日志"
        echo " 4. 系统日志"
        echo " 0. 返回主菜单"
        echo
        
        local choice
        safe_read "请选择要查看的日志" choice "0"
        
        case $choice in
            1)
                clear
                info_echo "Hysteria2 服务日志 (最近50行):"
                journalctl -u hysteria-server -n 50 --no-pager
                local dummy
                safe_read "按 Enter 继续" dummy
                ;;
            2)
                clear
                info_echo "Shadowsocks 服务日志 (最近50行):"
                journalctl -u shadowsocks-libev -n 50 --no-pager
                local dummy
                safe_read "按 Enter 继续" dummy
                ;;
            3)
                clear
                info_echo "安装日志:"
                if [[ -f "$LOG_DIR/install.log" ]]; then
                    tail -50 "$LOG_DIR/install.log"
                else
                    warning_echo "未找到安装日志"
                fi
                local dummy
                safe_read "按 Enter 继续" dummy
                ;;
            4)
                clear
                info_echo "系统日志 (最近30行):"
                journalctl -n 30 --no-pager
                local dummy
                safe_read "按 Enter 继续" dummy
                ;;
            0) return ;;
            *) warning_echo "无效选择" ;;
        esac
    done
}

################################################################################
# 主程序
################################################################################

# 初始化
initialize() {
    check_root
    setup_logging
    detect_system
    detect_network
    
    # 清理输入缓冲区
    exec </dev/tty 2>/dev/null || true
    while read -t 0.1 -n 1000 discard 2>/dev/null; do
        true
    done
}

# 主函数
main() {
    initialize
    
    while true; do
        show_menu
        local choice
        safe_read "请选择操作" choice "0"
        
        case $choice in
            1) hy2_install ;;
            2) ss_install ;;
            3) manage_services ;;
            4) uninstall_services ;;
            5) update_services ;;
            6) system_optimization ;;
            7) view_logs ;;
            0) 
                success_echo "感谢使用，再见！"
                exit 0 
                ;;
            *)
                warning_echo "无效选择，请输入 0-7"
                sleep 1
                ;;
        esac
    done
}

# 脚本入口
main "$@"
