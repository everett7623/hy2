#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks Management Script
# 作者：Jensfrank
# 版本：v1.2
# GitHub: https://github.com/everett7623/hy2
# 博客: https://seedloc.com
# 论坛: https://nodeloc.com
# 更新：增加了主机名解析问题的自动检测与修复功能。
# 时间：2025-10-11
#====================================================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 全局变量 ---
HY2_INSTALL_PATH="/etc/hysteria"
HY2_CERT_PATH="/etc/hysteria/cert"
HY2_CONFIG_PATH="/etc/hysteria/config.yaml"
HY2_SERVICE_PATH="/etc/systemd/system/hysteria.service"
HY2_BINARY_PATH="/usr/local/bin/hysteria"

SS_INSTALL_PATH="/etc/shadowsocks-rust"
SS_CONFIG_PATH="/etc/shadowsocks-rust/config.json"
SS_SERVICE_PATH="/etc/systemd/system/shadowsocks.service"
SS_BINARY_PATH="/usr/local/bin/ssserver"

# --- 辅助函数 ---

# 显示消息
msg() {
    local type="$1"
    local message="$2"
    case "$type" in
        "info") echo -e "${BLUE}[信息]${NC} ${message}" ;;
        "success") echo -e "${GREEN}[成功]${NC} ${message}" ;;
        "warning") echo -e "${YELLOW}[警告]${NC} ${message}" ;;
        "error") echo -e "${RED}[错误]${NC} ${message}" && exit 1 ;;
    esac
}

# 进度条
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

# 权限检查
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        msg "error" "此脚本需要 root 权限运行。请使用 sudo。"
    fi
}

# === 新增功能：修复主机名解析问题 ===
fix_hostname_resolution() {
    local hostname
    hostname=$(hostname)
    if ! sudo -n true 2>&1 | grep -q "unable to resolve host ${hostname}"; then
        return # 如果没有错误，直接返回
    fi

    # 如果 sudo 命令因主机名解析失败，则尝试修复
    if ! grep -q "127.0.0.1\s*${hostname}" /etc/hosts; then
        msg "warning" "检测到主机名解析问题 (unable to resolve host ${hostname})。"
        read -rp "是否尝试自动向 /etc/hosts 文件添加 '127.0.0.1 ${hostname}' 来修复此问题？(Y/n): " fix_hosts
        if [[ -z "$fix_hosts" || "$fix_hosts" =~ ^[yY]$ ]]; then
            echo "127.0.0.1 ${hostname}" | sudo tee -a /etc/hosts > /dev/null
            msg "success" "/etc/hosts 文件已修复。sudo 警告将不再出现。"
        fi
    fi
}


# 系统检查
check_system() {
    local os_release=""
    local arch
    arch=$(uname -m)

    if [ -f /etc/os-release ]; then
        os_release=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
    fi

    case "$arch" in
        x86_64 | amd64) arch="amd64" ;;
        aarch64 | arm64) arch="arm64" ;;
        *) msg "error" "不支持的系统架构: ${arch}" ;;
    esac

    case "$os_release" in
        ubuntu | debian | centos) ;;
        *) msg "warning" "当前系统为 ${os_release}，可能存在兼容性问题。" ;;
    esac
}

# 依赖安装
install_dependencies() {
    msg "info" "正在检查并安装必要的依赖..."
    local pkgs=("curl" "wget" "jq" "openssl")
    local pkg_manager=""
    
    if command -v apt-get &>/dev/null; then
        pkg_manager="apt-get"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum"
    else
        msg "error" "无法确定包管理器。请手动安装: ${pkgs[*]}"
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
        msg "success" "依赖已安装。"
    else
        msg "info" "所有依赖项均已安装。"
    fi
}

# 获取 IP 地址
get_ips() {
    ipv4=$(curl -s4 ip.sb)
    ipv6=$(curl -s6 ip.sb)
    [[ -z "$ipv4" ]] && ipv4="N/A"
    [[ -z "$ipv6" ]] && ipv6="N/A"
}

# 防火墙配置
configure_firewall() {
    local port=$1
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        sudo ufw allow "$port"/tcp >/dev/null
        sudo ufw allow "$port"/udp >/dev/null
        msg "info" "已在 ufw 中开放端口 ${port}。"
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        sudo firewall-cmd --zone=public --add-port="$port"/tcp --permanent >/dev/null
        sudo firewall-cmd --zone=public --add-port="$port"/udp --permanent >/dev/null
        sudo firewall-cmd --reload >/dev/null
        msg "info" "已在 firewalld 中开放端口 ${port}。"
    fi
}

# --- Hysteria2 安装功能（修复版）---

install_hy2() {
    msg "info" "开始安装 Hysteria2..."
    
    # 检测现有安装
    if [ -f "$HY2_SERVICE_PATH" ]; then
        msg "warning" "检测到 Hysteria2 已安装。"
        read -rp "是否覆盖安装？(y/N): " overwrite
        [[ ! "$overwrite" =~ ^[yY]$ ]] && return
        sudo systemctl stop hysteria 2>/dev/null
    fi
    
    # 交互式配置收集
    echo -e "\n${BLUE}=== 配置参数 ===${NC}"
    
    # 端口配置
    while true; do
        read -rp "请输入监听端口 [1-65535] (默认 443): " hy2_port
        hy2_port=${hy2_port:-443}
        if [[ "$hy2_port" =~ ^[0-9]+$ ]] && [ "$hy2_port" -ge 1 ] && [ "$hy2_port" -le 65535 ]; then
            break
        else
            msg "warning" "无效端口，请输入 1-65535 之间的数字。"
        fi
    done
    
    # 密码配置
    read -rp "请输入连接密码 (留空自动生成): " hy2_password
    if [ -z "$hy2_password" ]; then
        hy2_password=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)
        msg "info" "已自动生成密码: ${hy2_password}"
    fi
    
    # SNI 伪装配置
    read -rp "请输入 SNI 伪装域名 (默认 amd.com): " hy2_sni
    hy2_sni=${hy2_sni:-amd.com}
    
    # 混淆密码（可选）
    read -rp "是否启用混淆 (obfs)？(y/N): " enable_obfs
    local obfs_password=""
    if [[ "$enable_obfs" =~ ^[yY]$ ]]; then
        read -rp "请输入混淆密码 (留空自动生成): " obfs_password
        if [ -z "$obfs_password" ]; then
            obfs_password=$(openssl rand -base64 12 | tr -d '/+=' | head -c 12)
            msg "info" "已自动生成混淆密码: ${obfs_password}"
        fi
    fi
    
    # 速率限制配置
    read -rp "是否限制每用户带宽？(y/N): " enable_bandwidth_limit
    local bandwidth_up="0"
    local bandwidth_down="0"
    if [[ "$enable_bandwidth_limit" =~ ^[yY]$ ]]; then
        read -rp "请输入上传限制 (Mbps，0 为不限制): " bandwidth_up
        bandwidth_up=${bandwidth_up:-0}
        read -rp "请输入下载限制 (Mbps，0 为不限制): " bandwidth_down
        bandwidth_down=${bandwidth_down:-0}
    fi
    
    # 开始安装
    echo -e "\n${BLUE}=== 开始安装 ===${NC}"
    
    # 获取最新版本
    msg "info" "获取 Hysteria2 最新版本..."
    local latest_version
    latest_version=$(curl -s --connect-timeout 10 "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    
    if [ -z "$latest_version" ] || [ "$latest_version" = "null" ]; then
        msg "warning" "无法从 GitHub 获取版本信息，尝试使用镜像源..."
        latest_version=$(curl -s --connect-timeout 10 "https://api.github.com/repos/apernet/hysteria/releases" | jq -r '.[0].tag_name' | sed 's/v//')
    fi
    
    if [ -z "$latest_version" ] || [ "$latest_version" = "null" ]; then
        msg "error" "无法获取 Hysteria2 版本信息，请检查网络连接。"
    fi
    
    msg "info" "最新版本: v${latest_version}"
    
    # 确定系统架构
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l) arch="armv7" ;;
        *) msg "error" "不支持的系统架构: ${arch}" ;;
    esac
    
    # 下载二进制文件
    local download_url="https://github.com/apernet/hysteria/releases/download/v${latest_version}/hysteria-linux-${arch}"
    msg "info" "下载 Hysteria2 二进制文件..."
    
    if ! wget -q --show-progress --timeout=30 -O "/tmp/hysteria" "$download_url"; then
        msg "error" "下载失败，请检查网络连接或稍后重试。"
    fi
    
    sudo install -m 755 /tmp/hysteria "$HY2_BINARY_PATH"
    rm -f /tmp/hysteria
    msg "success" "二进制文件安装完成。"
    
    # 创建目录结构
    sudo mkdir -p "$HY2_INSTALL_PATH" "$HY2_CERT_PATH"
    
    # 生成自签证书（修复：统一使用 cert.crt 和 private.key）
    msg "info" "生成自签证书..."
    local cert_domain=${hy2_sni}
    
    sudo openssl ecparam -genkey -name prime256v1 -out "$HY2_CERT_PATH/private.key" 2>/dev/null
    sudo openssl req -new -x509 -days 36500 \
        -key "$HY2_CERT_PATH/private.key" \
        -out "$HY2_CERT_PATH/cert.crt" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=${cert_domain}" 2>/dev/null
    
    sudo chmod 600 "$HY2_CERT_PATH/private.key"
    sudo chmod 644 "$HY2_CERT_PATH/cert.crt"
    
    # 生成配置文件
    msg "info" "生成配置文件..."
    
    cat > /tmp/hy2_config.yaml << EOF
# Hysteria2 服务器配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

listen: :${hy2_port}

tls:
  cert: ${HY2_CERT_PATH}/cert.crt
  key: ${HY2_CERT_PATH}/private.key

auth:
  type: password
  password: ${hy2_password}

EOF

    # 添加混淆配置
    if [ -n "$obfs_password" ]; then
        cat >> /tmp/hy2_config.yaml << EOF
obfs:
  type: salamander
  salamander:
    password: ${obfs_password}

EOF
    fi

    # 添加带宽限制
    if [[ "$bandwidth_up" != "0" || "$bandwidth_down" != "0" ]]; then
        cat >> /tmp/hy2_config.yaml << EOF
bandwidth:
  up: ${bandwidth_up} mbps
  down: ${bandwidth_down} mbps

EOF
    fi

    # 添加其他配置
    cat >> /tmp/hy2_config.yaml << EOF
masquerade:
  type: proxy
  proxy:
    url: https://${hy2_sni}
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false
EOF

    sudo mv /tmp/hy2_config.yaml "$HY2_CONFIG_PATH"
    sudo chmod 644 "$HY2_CONFIG_PATH"
    
    # 创建 systemd 服务
    msg "info" "创建系统服务..."
    
    sudo tee "$HY2_SERVICE_PATH" > /dev/null << EOF
[Unit]
Description=Hysteria2 Proxy Server
Documentation=https://hysteria.network
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${HY2_BINARY_PATH} server --config ${HY2_CONFIG_PATH}
WorkingDirectory=${HY2_INSTALL_PATH}
Environment="HYSTERIA_LOG_LEVEL=info"
Restart=on-failure
RestartSec=10s
LimitNPROC=10000
LimitNOFILE=1000000

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${HY2_INSTALL_PATH}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # 重载并启动服务
    sudo systemctl daemon-reload
    sudo systemctl enable hysteria 2>/dev/null
    
    msg "info" "启动 Hysteria2 服务..."
    if sudo systemctl start hysteria; then
        sleep 2
        if systemctl is-active --quiet hysteria; then
            msg "success" "Hysteria2 安装成功并已启动！"
        else
            msg "error" "服务启动后异常退出，查看日志："
            sudo journalctl -u hysteria -n 30 --no-pager
            return 1
        fi
    else
        msg "error" "服务启动失败，查看日志："
        sudo journalctl -u hysteria -n 30 --no-pager
        return 1
    fi
    
    # 配置防火墙
    configure_firewall "$hy2_port"
    
    # 保存配置信息用于显示
    echo "${hy2_port}|${hy2_password}|${hy2_sni}|${obfs_password}" > "${HY2_INSTALL_PATH}/.config_info"
    
    # 显示配置信息
    echo
    display_hy2_config
}

display_hy2_config() {
    if [ ! -f "$HY2_CONFIG_PATH" ]; then
        msg "warning" "配置文件不存在。"
        return
    fi
    
    # 读取配置
    local port password sni obfs_password
    if [ -f "${HY2_INSTALL_PATH}/.config_info" ]; then
        IFS='|' read -r port password sni obfs_password < "${HY2_INSTALL_PATH}/.config_info"
    else
        port=$(grep -oP '(?<=listen: :)\d+' "$HY2_CONFIG_PATH")
        password=$(grep -oP '(?<=password: ).*' "$HY2_CONFIG_PATH" | head -1)
        sni=$(grep -oP '(?<=CN=).*' "$HY2_CERT_PATH/cert.crt" 2>/dev/null || echo "amd.com")
        obfs_password=$(grep -oP '(?<=password: ).*' "$HY2_CONFIG_PATH" | tail -1)
        [ "$obfs_password" = "$password" ] && obfs_password=""
    fi
    
    local server_ip=$ipv4
    local server_name
    server_name=$(hostname -s 2>/dev/null || echo "Server")
    
    # IP 地址处理
    if [[ "$server_ip" == "N/A" ]] && [[ "$ipv6" != "N/A" ]]; then
        server_ip="[${ipv6}]"
    elif [[ "$server_ip" == "N/A" ]]; then
        msg "error" "无法获取服务器公网 IP 地址！"
        return
    fi
    
    # 构建分享链接
    local share_link="hysteria2://${password}@${server_ip}:${port}/?insecure=true&sni=${sni}"
    [ -n "$obfs_password" ] && share_link="${share_link}&obfs=salamander&obfs-password=${obfs_password}"
    share_link="${share_link}#🌟Hysteria2-${server_name}"
    
    # 显示配置信息
    echo -e "\n${GREEN}### Hysteria2配置信息：${NC}"
    echo -e "🚀 ${YELLOW}V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${share_link}"
    echo
    echo -e "⚔️ ${YELLOW}Clash Meta 配置:${NC}"
    local clash_config="- { name: '🌟Hysteria2-${server_name}', type: hysteria2, server: ${server_ip}, port: ${port}, password: ${password}, sni: ${sni}, skip-cert-verify: true"
    if [ -n "$obfs_password" ]; then
        clash_config="${clash_config}, obfs: salamander, obfs-password: ${obfs_password}"
    fi
    clash_config="${clash_config}, up: 50, down: 100 }"
    echo "${clash_config}"
    echo
    echo -e "🌊 ${YELLOW}Surge 配置:${NC}"
    local surge_config="🌟Hysteria2-${server_name} = hysteria2, ${server_ip}, ${port}, password=${password}, sni=${sni}, skip-cert-verify=true"
    [ -n "$obfs_password" ] && surge_config="${surge_config}, obfs=salamander, obfs-password=${obfs_password}"
    echo -e "${surge_config}"
    echo -e "-----------------------------------\n"
}

# --- Shadowsocks 安装功能（修复版）---

install_ss() {
    msg "info" "开始安装 Shadowsocks-rust (IPv6 Only)..."
    
    # IPv6 检查
    if [[ "$ipv6" == "N/A" ]]; then
        msg "error" "未检测到 IPv6 地址！"
        echo "Shadowsocks 仅支持 IPv6 模式需要服务器具有 IPv6 地址。"
        read -rp "是否继续安装（将配置为监听所有 IPv6 地址）？(y/N): " continue_install
        [[ ! "$continue_install" =~ ^[yY]$ ]] && return
    fi
    
    # 检测现有安装
    if [ -f "$SS_SERVICE_PATH" ]; then
        msg "warning" "检测到 Shadowsocks 已安装。"
        read -rp "是否覆盖安装？(y/N): " overwrite
        [[ ! "$overwrite" =~ ^[yY]$ ]] && return
        sudo systemctl stop shadowsocks 2>/dev/null
    fi
    
    # 交互式配置收集
    echo -e "\n${BLUE}=== 配置参数 ===${NC}"
    
    # 端口配置
    while true; do
        read -rp "请输入监听端口 [1024-65535] (留空随机): " ss_port
        if [ -z "$ss_port" ]; then
            ss_port=$(shuf -i 10000-65000 -n 1)
            msg "info" "已随机生成端口: ${ss_port}"
            break
        elif [[ "$ss_port" =~ ^[0-9]+$ ]] && [ "$ss_port" -ge 1024 ] && [ "$ss_port" -le 65535 ]; then
            break
        else
            msg "warning" "无效端口，请输入 1024-65535 之间的数字。"
        fi
    done
    
    # 密码配置
    read -rp "请输入连接密码 (留空自动生成): " ss_password
    if [ -z "$ss_password" ]; then
        ss_password=$(openssl rand -base64 16)
        msg "info" "已自动生成密码: ${ss_password}"
    fi
    
    # 加密方式选择
    echo "请选择加密方式："
    local ciphers=("chacha20-ietf-poly1305" "aes-256-gcm" "aes-128-gcm" "2022-blake3-aes-128-gcm" "2022-blake3-aes-256-gcm")
    local cipher_descriptions=(
        "ChaCha20 (推荐，兼容性好)"
        "AES-256-GCM (安全)"
        "AES-128-GCM (快速)"
        "2022版 AES-128 (新标准)"
        "2022版 AES-256 (最安全)"
    )
    
    for i in "${!ciphers[@]}"; do
        echo "  $((i+1)). ${ciphers[$i]} - ${cipher_descriptions[$i]}"
    done
    
    read -rp "请选择 [1-${#ciphers[@]}] (默认 1): " cipher_choice
    cipher_choice=${cipher_choice:-1}
    
    if [[ "$cipher_choice" =~ ^[0-9]+$ ]] && [ "$cipher_choice" -ge 1 ] && [ "$cipher_choice" -le ${#ciphers[@]} ]; then
        local ss_cipher="${ciphers[$((cipher_choice-1))]}"
    else
        local ss_cipher="${ciphers[0]}"
    fi
    msg "info" "已选择加密方式: ${ss_cipher}"
    
    # 2022 版本需要特殊密码格式
    if [[ "$ss_cipher" =~ ^2022 ]]; then
        msg "info" "检测到 2022 版加密，生成符合规范的密码..."
        if [[ "$ss_cipher" =~ 128 ]]; then
            ss_password=$(openssl rand -base64 16)
        else
            ss_password=$(openssl rand -base64 32)
        fi
        msg "info" "已生成符合 SS2022 规范的密码"
    fi
    
    # 传输模式选择
    echo "请选择传输模式："
    echo "  1. TCP + UDP (推荐)"
    echo "  2. 仅 TCP"
    echo "  3. 仅 UDP"
    read -rp "请选择 [1-3] (默认 1): " mode_choice
    mode_choice=${mode_choice:-1}
    
    case "$mode_choice" in
        2) local ss_mode="tcp_only" ;;
        3) local ss_mode="udp_only" ;;
        *) local ss_mode="tcp_and_udp" ;;
    esac
    
    # 开始安装
    echo -e "\n${BLUE}=== 开始安装 ===${NC}"
    
    # 获取最新版本
    msg "info" "获取 shadowsocks-rust 最新版本..."
    local latest_version
    latest_version=$(curl -s --connect-timeout 10 "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    
    if [ -z "$latest_version" ] || [ "$latest_version" = "null" ]; then
        msg "error" "无法获取 shadowsocks-rust 版本信息，请检查网络连接。"
    fi
    
    msg "info" "最新版本: v${latest_version}"
    
    # 确定系统架构
    local arch
    arch=$(uname -m)
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.${arch}-unknown-linux-gnu.tar.xz"
    
    # 下载并解压
    msg "info" "下载 shadowsocks-rust..."
    if ! wget -q --show-progress --timeout=30 -O /tmp/ss.tar.xz "$download_url"; then
        msg "error" "下载失败，请检查网络连接或稍后重试。"
    fi
    
    msg "info" "解压文件..."
    tar -xf /tmp/ss.tar.xz -C /tmp
    sudo install -m 755 /tmp/ssserver "$SS_BINARY_PATH"
    rm -rf /tmp/ss*
    msg "success" "二进制文件安装完成。"
    
    # 创建目录
    sudo mkdir -p "$SS_INSTALL_PATH"
    
    # 生成配置文件（修复：移除 JSON 逗号问题）
    msg "info" "生成配置文件..."
    
    cat > /tmp/ss_config.json << EOF
{
    "server": "::",
    "server_port": ${ss_port},
    "password": "${ss_password}",
    "method": "${ss_cipher}",
    "mode": "${ss_mode}",
    "timeout": 300,
    "fast_open": true,
    "no_delay": true,
    "nameserver": "1.1.1.1",
    "ipv6_first": true
}
EOF

    sudo mv /tmp/ss_config.json "$SS_CONFIG_PATH"
    sudo chmod 644 "$SS_CONFIG_PATH"
    
    # 创建 systemd 服务
    msg "info" "创建系统服务..."
    
    sudo tee "$SS_SERVICE_PATH" > /dev/null << EOF
[Unit]
Description=Shadowsocks-rust Server
Documentation=https://github.com/shadowsocks/shadowsocks-rust
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${SS_BINARY_PATH} -c ${SS_CONFIG_PATH}
WorkingDirectory=${SS_INSTALL_PATH}
Environment="RUST_LOG=info"
Restart=on-failure
RestartSec=10s
LimitNOFILE=1000000

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${SS_INSTALL_PATH}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # 重载并启动服务
    sudo systemctl daemon-reload
    sudo systemctl enable shadowsocks 2>/dev/null
    
    msg "info" "启动 Shadowsocks 服务..."
    if sudo systemctl start shadowsocks; then
        sleep 2
        if systemctl is-active --quiet shadowsocks; then
            msg "success" "Shadowsocks 安装成功并已启动！"
        else
            msg "error" "服务启动后异常退出，查看日志："
            sudo journalctl -u shadowsocks -n 30 --no-pager
            return 1
        fi
    else
        msg "error" "服务启动失败，查看日志："
        sudo journalctl -u shadowsocks -n 30 --no-pager
        return 1
    fi
    
    # 配置防火墙
    configure_firewall "$ss_port"
    
    # 保存配置信息
    echo "${ss_port}|${ss_password}|${ss_cipher}|${ss_mode}" > "${SS_INSTALL_PATH}/.config_info"
    
    # 显示配置信息
    echo
    display_ss_config
}

display_ss_config() {
    if [ ! -f "$SS_CONFIG_PATH" ]; then
        msg "warning" "配置文件不存在。"
        return
    fi
    
    # 读取配置
    local port password cipher mode
    if [ -f "${SS_INSTALL_PATH}/.config_info" ]; then
        IFS='|' read -r port password cipher mode < "${SS_INSTALL_PATH}/.config_info"
    else
        port=$(jq -r '.server_port' "$SS_CONFIG_PATH")
        password=$(jq -r '.password' "$SS_CONFIG_PATH")
        cipher=$(jq -r '.method' "$SS_CONFIG_PATH")
        mode=$(jq -r '.mode' "$SS_CONFIG_PATH")
    fi
    
    local server_ip=$ipv6
    local server_name
    server_name=$(hostname -s 2>/dev/null || echo "Server")
    
    if [[ "$server_ip" == "N/A" ]]; then
        msg "error" "无法获取 IPv6 地址！"
        return
    fi
    
    # 构建分享链接
    local userinfo
    userinfo=$(echo -n "${cipher}:${password}" | base64 -w 0)
    local share_link="ss://${userinfo}@[${server_ip}]:${port}#🌟SS-IPv6-${server_name}"
    
    # 显示配置信息
    echo -e "\n${GREEN}### Shadowsocks配置信息：${NC}"
    echo -e "🚀 ${YELLOW}V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${share_link}"
    echo
    echo -e "⚔️ ${YELLOW}Clash Meta 配置:${NC}"
    echo "- { name: '🌟SS-IPv6-${server_name}', type: ss, server: '${server_ip}', port: ${port}, cipher: '${cipher}', password: '${password}', udp: true }"
    echo -e "-----------------------------------\n"
}

# --- 管理菜单 ---

service_management() {
    clear
    echo "=== 服务管理 ==="
    echo " 1. 管理 Hysteria2"
    echo " 2. 管理 Shadowsocks"
    echo " 0. 返回主菜单"
    echo "================"
    read -rp "请输入选项: " choice
    case "$choice" in
        1) manage_hy2_menu ;;
        2) manage_ss_menu ;;
        0) ;;
        *) msg "warning" "无效输入。" ;;
    esac
}

manage_hy2_menu() {
    if ! [ -f "$HY2_SERVICE_PATH" ]; then
        msg "warning" "Hysteria2 未安装。"
        return
    fi
    clear
    echo "=== Hysteria2 管理 ==="
    echo " 1. 启动服务"
    echo " 2. 停止服务"
    echo " 3. 重启服务"
    echo " 4. 查看状态"
    echo " 5. 查看配置"
    echo " 0. 返回"
    echo "======================"
    read -rp "请输入选项: " choice
    case "$choice" in
        1) sudo systemctl start hysteria && msg "success" "Hysteria2 已启动。" ;;
        2) sudo systemctl stop hysteria && msg "success" "Hysteria2 已停止。" ;;
        3) sudo systemctl restart hysteria && msg "success" "Hysteria2 已重启。" ;;
        4) systemctl status hysteria --no-pager ;;
        5) display_hy2_config ;;
        0) ;;
        *) msg "warning" "无效输入。" ;;
    esac
}

manage_ss_menu() {
    if ! [ -f "$SS_SERVICE_PATH" ]; then
        msg "warning" "Shadowsocks 未安装。"
        return
    fi
    clear
    echo "=== Shadowsocks 管理 ==="
    echo " 1. 启动服务"
    echo " 2. 停止服务"
    echo " 3. 重启服务"
    echo " 4. 查看状态"
    echo " 5. 查看配置"
    echo " 0. 返回"
    echo "======================"
    read -rp "请输入选项: " choice
    case "$choice" in
        1) sudo systemctl start shadowsocks && msg "success" "Shadowsocks 已启动。" ;;
        2) sudo systemctl stop shadowsocks && msg "success" "Shadowsocks 已停止。" ;;
        3) sudo systemctl restart shadowsocks && msg "success" "Shadowsocks 已重启。" ;;
        4) systemctl status shadowsocks --no-pager ;;
        5) display_ss_config ;;
        0) ;;
        *) msg "warning" "无效输入。" ;;
    esac
}

# --- 卸载 ---
uninstall_menu() {
    clear
    echo "=== 卸载服务 ==="
    echo " 1. 卸载 Hysteria2"
    echo " 2. 卸载 Shadowsocks"
    echo " 3. 卸载所有服务"
    echo " 0. 返回主菜单"
    echo "================"
    read -rp "请输入选项: " choice
    case "$choice" in
        1) uninstall_hy2 ;;
        2) uninstall_ss ;;
        3) uninstall_hy2; uninstall_ss ;;
        0) ;;
        *) msg "warning" "无效输入。" ;;
    esac
}

uninstall_hy2() {
    sudo systemctl stop hysteria
    sudo systemctl disable hysteria
    sudo rm -f "$HY2_SERVICE_PATH"
    sudo rm -f "$HY2_BINARY_PATH"
    sudo rm -rf "$HY2_INSTALL_PATH"
    sudo systemctl daemon-reload
    msg "success" "Hysteria2 已成功卸载。"
}

uninstall_ss() {
    sudo systemctl stop shadowsocks
    sudo systemctl disable shadowsocks
    sudo rm -f "$SS_SERVICE_PATH"
    sudo rm -f "$SS_BINARY_PATH"
    sudo rm -rf "$SS_INSTALL_PATH"
    sudo systemctl daemon-reload
    msg "success" "Shadowsocks 已成功卸载。"
}

# --- 更新 ---
update_menu() {
    clear
    echo "=== 更新服务 ==="
    echo " 1. 更新 Hysteria2"
    echo " 2. 更新 Shadowsocks"
    echo " 3. 更新系统 (apt/yum)"
    echo " 0. 返回主菜单"
    echo "================"
    read -rp "请输入选项: " choice
    case "$choice" in
        1) update_hy2 ;;
        2) update_ss ;;
        3) update_system ;;
        0) ;;
        *) msg "warning" "无效输入。" ;;
    esac
}

update_hy2() {
    msg "info" "正在更新 Hysteria2..."
    sudo systemctl stop hysteria
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
    esac
    local download_url="https://github.com/apernet/hysteria/releases/download/v${latest_version}/hysteria-linux-${arch}"
    (sudo wget -q -O "$HY2_BINARY_PATH" "$download_url" && sudo chmod +x "$HY2_BINARY_PATH") &> /dev/null &
    show_progress $!
    sudo systemctl start hysteria
    msg "success" "Hysteria2 已更新至最新版本。"
}

update_ss() {
    msg "info" "正在更新 Shadowsocks..."
    sudo systemctl stop shadowsocks
    local latest_version
    latest_version=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    local arch
    arch=$(uname -m)
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.${arch}-unknown-linux-gnu.tar.xz"
    (wget -q -O /tmp/ss.tar.xz "$download_url" && tar -xf /tmp/ss.tar.xz -C /tmp && sudo mv /tmp/ssserver "$SS_BINARY_PATH" && rm -rf /tmp/ss*) &> /dev/null &
    show_progress $!
    sudo systemctl start shadowsocks
    msg "success" "Shadowsocks 已更新至最新版本。"
}

update_system() {
    msg "info" "正在更新系统软件包..."
    if command -v apt-get &>/dev/null; then
        (sudo apt-get update && sudo apt-get upgrade -y) &
        show_progress $!
    elif command -v yum &>/dev/null; then
        (sudo yum update -y) &
        show_progress $!
    else
        msg "error" "不支持的包管理器。"
        return
    fi
    msg "success" "系统更新完成。"
}

# --- 系统优化 ---
optimize_menu() {
    clear
    echo "=== 系统优化 ==="
    echo " 1. 创建/管理 Swap"
    echo " 2. 优化网络参数 (BBR)"
    echo " 3. 优化系统限制"
    echo " 4. 清理系统垃圾"
    echo " 0. 返回主菜单"
    echo "================"
    read -rp "请输入选项: " choice
    case "$choice" in
        1) manage_swap ;;
        2) optimize_network ;;
        3) optimize_limits ;;
        4) clean_system ;;
        0) ;;
        *) msg "warning" "无效输入。" ;;
    esac
}

manage_swap() {
    if free | awk '/Swap/ {exit $2>0?0:1}'; then
        msg "info" "检测到已存在 Swap。"
        read -rp "是否需要移除现有 Swap？ (y/N): " remove_swap
        if [[ "$remove_swap" =~ ^[yY]$ ]]; then
            local swap_path
            swap_path=$(grep -oP '^\S+' /proc/swaps | tail -n1)
            sudo swapoff -a && sudo rm -f "$swap_path"
            sudo sed -i "\|$swap_path|d" /etc/fstab
            msg "success" "Swap 已移除。"
        fi
        return
    fi
    
    read -rp "请输入要创建的 Swap 大小 (MB, 建议 512): " swap_size
    [[ -z "$swap_size" ]] && swap_size=512
    sudo fallocate -l "${swap_size}M" /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    msg "success" "${swap_size}MB 的 Swap 已创建并激活。"
}

optimize_network() {
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        msg "info" "正在启用 BBR..."
        echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.conf
        sudo sysctl -p >/dev/null
        msg "success" "BBR 已启用。"
    else
        msg "info" "BBR 已启用。"
    fi
}

optimize_limits() {
    msg "info" "正在优化系统文件描述符限制..."
    local limits_conf="/etc/security/limits.conf"
    if ! grep -q "^\* soft nofile 65536" "$limits_conf"; then
        echo "* soft nofile 65536" | sudo tee -a "$limits_conf"
        echo "* hard nofile 65536" | sudo tee -a "$limits_conf"
        msg "success" "系统限制已优化，重新登录 Shell 后生效。"
    else
        msg "info" "系统限制已是优化状态。"
    fi
}

clean_system() {
    msg "info" "正在清理系统缓存..."
    if command -v apt-get &>/dev/null; then
        (sudo apt-get autoremove -y && sudo apt-get clean -y) &
        show_progress $!
    elif command -v yum &>/dev/null; then
        (sudo yum clean all) &
        show_progress $!
    fi
    msg "success" "系统垃圾已清理。"
}

# --- 主菜单 ---
main_menu() {
    clear
    get_ips
    
    local hy2_status="${RED}未安装${NC}"
    if systemctl is-active --quiet hysteria; then
        hy2_status="${GREEN}运行中${NC}"
    elif [ -f "$HY2_SERVICE_PATH" ]; then
        hy2_status="${YELLOW}已安装但未运行${NC}"
    fi
    
    local ss_status="${RED}未安装${NC}"
    if systemctl is-active --quiet shadowsocks; then
        ss_status="${GREEN}运行中${NC}"
    elif [ -f "$SS_SERVICE_PATH" ]; then
        ss_status="${YELLOW}已安装但未运行${NC}"
    fi

    echo "===================================================================================="
    echo -e "          ${BLUE}Hysteria2 & Shadowsocks Management Script (v1.1)${NC}"
    echo " 项目地址：https://github.com/everett7623/hy2"
    echo " 博客地址：https://seedloc.com"
    echo " 论坛地址：https://nodeloc.com"
    echo "===================================================================================="
    echo -e " 服务器 IPv4:      ${YELLOW}${ipv4}${NC}"
    echo -e " 服务器 IPv6:      ${YELLOW}${ipv6}${NC}"
    echo -e " Hysteria 2 状态:  ${hy2_status}"
    echo -e " Shadowsocks 状态: ${ss_status}"
    echo "===================================================================================="
    echo " 1. 安装 Hysteria2 (自签证书，无需域名)"
    echo " 2. 安装 Shadowsocks (仅 IPv6)"
    echo "------------------------------------------------------------------------------------"
    echo " 3. 服务管理"
    echo " 4. 卸载服务"
    echo " 5. 更新服务"
    echo " 6. 系统优化"
    echo "------------------------------------------------------------------------------------"
    echo " 0. 退出脚本"
    echo "===================================================================================="
    
    read -rp "请输入选项 [0-6]: " choice
    case "$choice" in
        1) install_hy2 ;;
        2) install_ss ;;
        3) service_management ;;
        4) uninstall_menu ;;
        5) update_menu ;;
        6) optimize_menu ;;
        0) exit 0 ;;
        *) msg "warning" "无效输入，请输入数字 0-6" ;;
    esac
}

# --- 脚本入口 ---
main() {
    check_root
    fix_hostname_resolution # <-- 在这里调用修复功能
    check_system
    install_dependencies
    
    while true; do
        main_menu
        read -n 1 -s -r -p "按任意键返回主菜单..."
    done
}

main "$@"
