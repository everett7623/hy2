#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks (IPv6) Management Script
# 作者：Jensfrank
# 版本：v1.0
# GitHub: https://github.com/everett7623/hy2ipv6
# 博客: https://seedloc.com
# 论坛: https://nodeloc.com
#====================================================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 全局变量 ---
HY2_CONFIG_PATH="/etc/hysteria/config.yaml"
HY2_CERT_PATH="/etc/hysteria/cert.pem"
HY2_KEY_PATH="/etc/hysteria/private.key"
SS_CONFIG_PATH="/etc/shadowsocks/config.json"
HY2_STATUS=""
SS_STATUS=""
IPV4_ADDR=""
IPV6_ADDR=""

# --- 辅助函数 ---

# 带颜色的输出
color_echo() {
    echo -e "${!1}${2}${NC}"
}

# 检查root权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        color_echo RED "错误: 此脚本必须以 root 权限运行。"
        exit 1
    fi
}

# 检查操作系统和架构
check_os_arch() {
    color_echo BLUE "正在检查系统兼容性..."
    OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
    ARCH=$(uname -m)

    case "$OS_ID" in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            ;;
        centos|almalinux|rocky)
            PKG_MANAGER="yum"
            ;;
        *)
            color_echo RED "不支持的操作系统: $OS_ID"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        *)
            color_echo RED "不支持的系统架构: $ARCH"
            exit 1
            ;;
    esac
    color_echo GREEN "系统兼容性检查通过。"
}

# 安装依赖
install_dependencies() {
    color_echo BLUE "正在检查并安装必要的依赖..."
    DEPS="curl wget jq openssl socat unzip"
    
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        # 更新源并静默安装
        if ! sudo $PKG_MANAGER update -qq >/dev/null 2>&1; then
            color_echo YELLOW "apt源更新失败，请检查网络或更换源。"
        fi
        for dep in $DEPS; do
            if ! dpkg -s "$dep" >/dev/null 2>&1; then
                NEEDS_INSTALL="$NEEDS_INSTALL $dep"
            fi
        done
        if [ -n "$NEEDS_INSTALL" ]; then
            sudo $PKG_MANAGER install -y -qq $NEEDS_INSTALL >/dev/null 2>&1
        fi
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        for dep in $DEPS; do
            if ! rpm -q "$dep" >/dev/null 2>&1; then
                NEEDS_INSTALL="$NEEDS_INSTALL $dep"
            fi
        done
        if [ -n "$NEEDS_INSTALL" ]; then
            sudo $PKG_MANAGER install -y $NEEDS_INSTALL >/dev/null 2>&1
        fi
    fi
    color_echo GREEN "依赖项已准备就绪。"
}

# 获取公网IP地址
get_public_ips() {
    IPV4_ADDR=$(curl -s4m8 https://api.ip.sb/ip || curl -s4m8 https://api.ipify.org)
    IPV6_ADDR=$(curl -s6m8 https://api.ip.sb/ip || curl -s6m8 https://api.ipify.org)
    [ -z "$IPV4_ADDR" ] && IPV4_ADDR="N/A"
    [ -z "$IPV6_ADDR" ] && IPV6_ADDR="N/A"
}

# 检查服务状态
check_status() {
    if systemctl is-active --quiet hysteria-server; then
        HY2_STATUS="${GREEN}运行中${NC}"
    else
        HY2_STATUS="${RED}未安装或未运行${NC}"
    fi

    if systemctl is-active --quiet shadowsocks-server; then
        SS_STATUS="${GREEN}运行中${NC}"
    else
        SS_STATUS="${RED}未安装或未运行${NC}"
    fi
}

# 检查并配置防火墙
configure_firewall() {
    local port=$1
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        if ! ufw status | grep -qw "$port"; then
            read -p "检测到 ufw 防火墙，是否需要自动开放端口 $port (UDP/TCP)? [Y/n]: " choice
            choice=${choice:-Y}
            if [[ "$choice" =~ ^[Yy]$ ]]; then
                ufw allow "$port" >/dev/null 2>&1
                ufw reload >/dev/null 2>&1
                color_echo GREEN "ufw 端口 $port 已开放。"
            fi
        fi
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        if ! firewall-cmd --list-ports --permanent | grep -qw "$port/tcp" || ! firewall-cmd --list-ports --permanent | grep -qw "$port/udp"; then
            read -p "检测到 firewalld 防火墙，是否需要自动开放端口 $port (UDP/TCP)? [Y/n]: " choice
            choice=${choice:-Y}
            if [[ "$choice" =~ ^[Yy]$ ]]; then
                firewall-cmd --add-port="$port/tcp" --permanent >/dev/null 2>&1
                firewall-cmd --add-port="$port/udp" --permanent >/dev/null 2>&1
                firewall-cmd --reload >/dev/null 2>&1
                color_echo GREEN "firewalld 端口 $port 已开放。"
            fi
        fi
    fi
}

# 进度条
show_progress() {
    local pid=$!
    local spin='-\|/'
    local i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r  [%c] 正在执行..." "${spin:$i:1}"
        sleep 0.1
    done
    printf "\r  [✓] 操作完成    \n"
}

# 暂停脚本
pause() {
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

# --- Hysteria2 功能 ---

install_hysteria2() {
    color_echo BLUE "--- 开始安装 Hysteria2 ---"
    if systemctl list-units --type=service | grep -q "hysteria-server"; then
        color_echo YELLOW "Hysteria2 已安装，请先卸载再执行安装。"
        return
    fi

    local port
    while true; do
        read -p "请输入 Hysteria2 监听的端口 [1-65535]: " port
        [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && break
        color_echo RED "无效的端口号，请输入 1-65535 之间的数字。"
    done

    read -p "请输入用于 SNI 伪装的域名 (回车默认 amd.com): " sni
    sni=${sni:-amd.com}

    local password
    read -p "请输入 Hysteria2 的连接密码 (回车自动生成): " password
    password=${password:-$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)}

    color_echo BLUE "正在从 GitHub 获取最新 Hysteria2 版本..."
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name | sed 's/v//')
    DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v${LATEST_VERSION}/hysteria-linux-${ARCH}"

    color_echo BLUE "正在下载 Hysteria2 v${LATEST_VERSION}..."
    (curl -L -o /usr/local/bin/hysteria "$DOWNLOAD_URL") &> /dev/null &
    show_progress
    chmod +x /usr/local/bin/hysteria

    color_echo BLUE "正在生成自签名证书..."
    mkdir -p /etc/hysteria
    openssl ecparam -genkey -name prime256v1 -out "$HY2_KEY_PATH" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$HY2_KEY_PATH" -out "$HY2_CERT_PATH" -subj "/CN=bing.com" >/dev/null 2>&1

    color_echo BLUE "正在创建 Hysteria2 配置文件..."
    cat > "$HY2_CONFIG_PATH" << EOF
listen: :${port}
protocol: wechat-video
auth:
  type: string
  string: ${password}
tls:
  cert: ${HY2_CERT_PATH}
  key: ${HY2_KEY_PATH}
masquerade:
  type: proxy
  proxy:
    url: https://${sni}
    rewriteHost: true
bandwidth:
  up: 50 mbit
  down: 100 mbit
EOF

    color_echo BLUE "正在创建 Hysteria2 systemd 服务..."
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria2 Service (Server)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config ${HY2_CONFIG_PATH}
WorkingDirectory=/etc/hysteria
User=root
Group=root
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
Restart=on-failure
RestartSec=10s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now hysteria-server >/dev/null 2>&1
    
    sleep 2 # 等待服务启动
    if systemctl is-active --quiet hysteria-server; then
        color_echo GREEN "Hysteria2 安装并启动成功！"
        configure_firewall "$port"
        display_hysteria2_config
    else
        color_echo RED "Hysteria2 启动失败，请检查日志！"
        journalctl -u hysteria-server --no-pager -n 20
    fi
}

display_hysteria2_config() {
    if [ ! -f "$HY2_CONFIG_PATH" ]; then
        color_echo YELLOW "Hysteria2 配置文件不存在。"
        return
    fi
    
    local port=$(grep -oP '(?<=listen: :)\d+' "$HY2_CONFIG_PATH")
    local password=$(grep -oP '(?<=string: )\S+' "$HY2_CONFIG_PATH")
    local sni=$(grep -oP '(?<=url: https://)\S+' "$HY2_CONFIG_PATH")
    local server_addr=${IPV4_ADDR}
    if [ "$server_addr" == "N/A" ]; then
        server_addr="[${IPV6_ADDR}]"
    fi
    
    local share_link="hysteria2://${password}@${server_addr}:${port}/?insecure=true&sni=${sni}#🌟Hysteria2-$(hostname)"
    local clash_config="- { name: '🌟Hysteria2-$(hostname)', type: hysteria2, server: ${server_addr}, port: ${port}, password: ${password}, sni: ${sni}, skip-cert-verify: true, up: 50, down: 100 }"
    local surge_config="🌟Hysteria2-$(hostname) = hysteria2, ${server_addr}, ${port}, password=${password}, sni=${sni}, skip-cert-verify=true"

    echo ""
    color_echo GREEN "============== Hysteria2 配置信息 =============="
    color_echo YELLOW "🚀 V2rayN / NekoBox / Shadowrocket 分享链接:"
    echo "$share_link"
    color_echo YELLOW "⚔️ Clash Meta 配置:"
    echo "$clash_config"
    color_echo YELLOW "🌊 Surge 配置:"
    echo "$surge_config"
    color_echo GREEN "=============================================="
    echo ""
}

# --- Shadowsocks 功能 ---

install_shadowsocks() {
    color_echo BLUE "--- 开始安装 Shadowsocks (仅 IPv6) ---"
    
    if [ "$IPV6_ADDR" == "N/A" ]; then
        color_echo RED "错误: 检测到服务器无 IPv6 地址，无法安装 Shadowsocks。"
        color_echo YELLOW "此脚本的 Shadowsocks 仅支持 IPv6-Only 或双栈服务器。"
        return
    fi
    
    if systemctl list-units --type=service | grep -q "shadowsocks-server"; then
        color_echo YELLOW "Shadowsocks 已安装，请先卸载再执行安装。"
        return
    fi

    local port
    while true; do
        read -p "请输入 Shadowsocks 监听的端口 [1-65535]: " port
        [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && break
        color_echo RED "无效的端口号，请输入 1-65535 之间的数字。"
    done
    
    local password
    read -p "请输入 Shadowsocks 的连接密码 (回车自动生成): " password
    password=${password:-$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)}

    color_echo BLUE "正在从 GitHub 获取最新 Shadowsocks-rust 版本..."
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r .tag_name | sed 's/v//')
    DOWNLOAD_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${LATEST_VERSION}/shadowsocks-v${LATEST_VERSION}.${ARCH}-unknown-linux-gnu.tar.xz"

    color_echo BLUE "正在下载 Shadowsocks-rust v${LATEST_VERSION}..."
    (curl -L "$DOWNLOAD_URL" | tar -Jx -C /usr/local/bin ssserver) &> /dev/null &
    show_progress
    chmod +x /usr/local/bin/ssserver
    
    color_echo BLUE "正在创建 Shadowsocks 配置文件..."
    mkdir -p /etc/shadowsocks
    cat > "$SS_CONFIG_PATH" << EOF
{
    "server": "[::]",
    "server_port": ${port},
    "password": "${password}",
    "method": "2022-blake3-aes-128-gcm",
    "mode": "tcp_and_udp"
}
EOF

    color_echo BLUE "正在创建 Shadowsocks systemd 服务..."
    cat > /etc/systemd/system/shadowsocks-server.service << EOF
[Unit]
Description=Shadowsocks-rust Service (Server)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c ${SS_CONFIG_PATH}
User=root
Group=root
Restart=on-failure
RestartSec=10s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now shadowsocks-server >/dev/null 2>&1
    
    sleep 2
    if systemctl is-active --quiet shadowsocks-server; then
        color_echo GREEN "Shadowsocks 安装并启动成功！"
        configure_firewall "$port"
        display_shadowsocks_config
    else
        color_echo RED "Shadowsocks 启动失败，请检查日志！"
        journalctl -u shadowsocks-server --no-pager -n 20
    fi
}

display_shadowsocks_config() {
    if [ ! -f "$SS_CONFIG_PATH" ]; then
        color_echo YELLOW "Shadowsocks 配置文件不存在。"
        return
    fi
    
    local port=$(jq -r '.server_port' "$SS_CONFIG_PATH")
    local password=$(jq -r '.password' "$SS_CONFIG_PATH")
    local method=$(jq -r '.method' "$SS_CONFIG_PATH")
    
    local encoded_part=$(echo -n "${method}:${password}" | base64 -w 0)
    local share_link="ss://${encoded_part}@[${IPV6_ADDR}]:${port}#🌟Shadowsocks-$(hostname)"

    echo ""
    color_echo GREEN "============= Shadowsocks 配置信息 ============="
    color_echo YELLOW "协议类型: Shadowsocks"
    color_echo YELLOW "服务器地址 (IPv6): ${IPV6_ADDR}"
    color_echo YELLOW "端口: ${port}"
    color_echo YELLOW "密码: ${password}"
    color_echo YELLOW "加密方法: ${method}"
    echo ""
    color_echo YELLOW "🚀 SS 分享链接:"
    echo "${share_link}"
    color_echo GREEN "=============================================="
    echo ""
}

# --- 管理菜单 ---

manage_hysteria2() {
    while true; do
        clear
        check_status
        echo "--- Hysteria2 服务管理 ---"
        echo -e "当前状态: $HY2_STATUS"
        echo "--------------------------"
        echo " 1. 启动 Hysteria2"
        echo " 2. 停止 Hysteria2"
        echo " 3. 重启 Hysteria2"
        echo " 4. 查看 Hysteria2 状态"
        echo " 5. 查看 Hysteria2 日志"
        echo " 6. 显示配置信息"
        echo " 7. 返回上一级"
        read -p "请输入选项 [1-7]: " choice
        
        case "$choice" in
            1) systemctl start hysteria-server; color_echo GREEN "Hysteria2 已启动。"; pause ;;
            2) systemctl stop hysteria-server; color_echo GREEN "Hysteria2 已停止。"; pause ;;
            3) systemctl restart hysteria-server; color_echo GREEN "Hysteria2 已重启。"; pause ;;
            4) systemctl status hysteria-server --no-pager; pause ;;
            5) journalctl -u hysteria-server -f --no-pager; pause ;;
            6) display_hysteria2_config; pause ;;
            7) break ;;
            *) color_echo RED "无效输入"; sleep 1 ;;
        esac
    done
}

manage_shadowsocks() {
    while true; do
        clear
        check_status
        echo "--- Shadowsocks 服务管理 ---"
        echo -e "当前状态: $SS_STATUS"
        echo "--------------------------"
        echo " 1. 启动 Shadowsocks"
        echo " 2. 停止 Shadowsocks"
        echo " 3. 重启 Shadowsocks"
        echo " 4. 查看 Shadowsocks 状态"
        echo " 5. 查看 Shadowsocks 日志"
        echo " 6. 显示配置信息"
        echo " 7. 返回上一级"
        read -p "请输入选项 [1-7]: " choice
        
        case "$choice" in
            1) systemctl start shadowsocks-server; color_echo GREEN "Shadowsocks 已启动。"; pause ;;
            2) systemctl stop shadowsocks-server; color_echo GREEN "Shadowsocks 已停止。"; pause ;;
            3) systemctl restart shadowsocks-server; color_echo GREEN "Shadowsocks 已重启。"; pause ;;
            4) systemctl status shadowsocks-server --no-pager; pause ;;
            5) journalctl -u shadowsocks-server -f --no-pager; pause ;;
            6) display_shadowsocks_config; pause ;;
            7) break ;;
            *) color_echo RED "无效输入"; sleep 1 ;;
        esac
    done
}

manage_menu() {
    while true; do
        clear
        echo "--- 服务管理 ---"
        echo " 1. 管理 Hysteria2"
        echo " 2. 管理 Shadowsocks"
        echo " 0. 返回主菜单"
        read -p "请输入选项 [0-2]: " choice
        
        case "$choice" in
            1) manage_hysteria2 ;;
            2) manage_shadowsocks ;;
            0) break ;;
            *) color_echo RED "无效输入"; sleep 1 ;;
        esac
    done
}

# --- 卸载菜单 ---

uninstall_hysteria2() {
    color_echo YELLOW "确定要卸载 Hysteria2 吗? [y/N]"
    read -r choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        systemctl stop hysteria-server >/dev/null 2>&1
        systemctl disable hysteria-server >/dev/null 2>&1
        rm -f /etc/systemd/system/hysteria-server.service
        systemctl daemon-reload
        rm -rf /etc/hysteria
        rm -f /usr/local/bin/hysteria
        color_echo GREEN "Hysteria2 卸载完成。"
    else
        color_echo BLUE "卸载操作已取消。"
    fi
}

uninstall_shadowsocks() {
    color_echo YELLOW "确定要卸载 Shadowsocks 吗? [y/N]"
    read -r choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        systemctl stop shadowsocks-server >/dev/null 2>&1
        systemctl disable shadowsocks-server >/dev/null 2>&1
        rm -f /etc/systemd/system/shadowsocks-server.service
        systemctl daemon-reload
        rm -rf /etc/shadowsocks
        rm -f /usr/local/bin/ssserver
        color_echo GREEN "Shadowsocks 卸载完成。"
    else
        color_echo BLUE "卸载操作已取消。"
    fi
}

uninstall_menu() {
    while true; do
        clear
        echo "--- 卸载服务 ---"
        echo " 1. 卸载 Hysteria2"
        echo " 2. 卸载 Shadowsocks"
        echo " 3. 卸载所有服务"
        echo " 0. 返回主菜单"
        read -p "请输入选项 [0-3]: " choice
        
        case "$choice" in
            1) uninstall_hysteria2; pause; break ;;
            2) uninstall_shadowsocks; pause; break ;;
            3) uninstall_hysteria2; uninstall_shadowsocks; pause; break ;;
            0) break ;;
            *) color_echo RED "无效输入"; sleep 1 ;;
        esac
    done
}

# --- 更新菜单 ---

update_service() {
    local service_name=$1
    local repo=$2
    local binary_name=$3
    local download_pattern=$4
    
    color_echo BLUE "正在从 GitHub 获取最新 ${service_name} 版本..."
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/${repo}/releases/latest" | jq -r .tag_name | sed 's/v//')
    DOWNLOAD_URL=$(printf "$download_pattern" "$LATEST_VERSION" "$ARCH")
    
    color_echo BLUE "正在下载 ${service_name} v${LATEST_VERSION}..."
    
    if [[ "$DOWNLOAD_URL" == *.tar.xz ]]; then
        (curl -L "$DOWNLOAD_URL" | tar -Jx -C /usr/local/bin "$binary_name") &> /dev/null &
    else
        (curl -L -o "/usr/local/bin/${binary_name}" "$DOWNLOAD_URL") &> /dev/null &
    fi
    show_progress
    chmod +x "/usr/local/bin/${binary_name}"
    
    color_echo GREEN "${service_name} 已更新到最新版本 v${LATEST_VERSION}。"
    systemctl restart "${service_name,,}-server"
    color_echo GREEN "服务已重启。"
}

update_kernel() {
    color_echo RED "注意: 更新内核可能导致系统不稳定，请谨慎操作！"
    read -p "确定要更新系统内核吗? [y/N]: " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        color_echo BLUE "正在安装 ELRepo (用于CentOS) 或 mainline (用于Ubuntu/Debian)..."
        if [[ "$PKG_MANAGER" == "yum" ]]; then
            rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org >/dev/null 2>&1
            $PKG_MANAGER install -y https://www.elrepo.org/elrepo-release-$(rpm -E %{rhel}).elrepo.noarch.rpm >/dev/null 2>&1
            $PKG_MANAGER --enablerepo=elrepo-kernel install -y kernel-ml >/dev/null 2>&1
            grub2-set-default 0
            color_echo GREEN "新内核已安装，请重启服务器以生效。"
        elif [[ "$PKG_MANAGER" == "apt-get" ]]; then
            add-apt-repository -y ppa:cappelikan/ppa >/dev/null 2>&1
            $PKG_MANAGER update >/dev/null 2>&1
            $PKG_MANAGER install -y mainline >/dev/null 2>&1
            color_echo GREEN "内核更新工具 mainline 已安装。"
            color_echo YELLOW "请手动运行 'mainline' 命令来选择并安装新内核。"
        fi
    else
        color_echo BLUE "内核更新操作已取消。"
    fi
}

update_menu() {
    while true; do
        clear
        echo "--- 更新服务 ---"
        echo " 1. 更新 Hysteria2"
        echo " 2. 更新 Shadowsocks"
        echo " 3. 更新系统内核"
        echo " 0. 返回主菜单"
        read -p "请输入选项 [0-3]: " choice
        
        case "$choice" in
            1) 
                update_service "Hysteria2" "apernet/hysteria" "hysteria" "https://github.com/apernet/hysteria/releases/download/v%s/hysteria-linux-%s"
                pause
                break
                ;;
            2) 
                update_service "Shadowsocks" "shadowsocks/shadowsocks-rust" "ssserver" "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v%s/shadowsocks-v%s.%s-unknown-linux-gnu.tar.xz"
                pause
                break
                ;;
            3) update_kernel; pause; break ;;
            0) break ;;
            *) color_echo RED "无效输入"; sleep 1 ;;
        esac
    done
}

# --- 系统优化 ---
manage_swap() {
    if [ -n "$(swapon --show)" ]; then
        color_echo GREEN "检测到 Swap 已存在。"
        read -p "是否要移除现有 Swap? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            swapoff -a
            sed -i '/swap/d' /etc/fstab
            rm -f /swapfile
            color_echo GREEN "Swap 已移除。"
        fi
    else
        color_echo YELLOW "未检测到 Swap。"
        read -p "是否要创建 1GB 的 Swap? (适用于小内存VPS) [Y/n]: " choice
        choice=${choice:-Y}
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            fallocate -l 1G /swapfile
            chmod 600 /swapfile
            mkswap /swapfile
            swapon /swapfile
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
            color_echo GREEN "1GB Swap 创建成功。"
        fi
    fi
}

optimize_network() {
    if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        color_echo GREEN "网络参数已优化 (BBR)。"
        return
    fi
    read -p "是否要启用 BBR 网络优化? [Y/n]: " choice
    choice=${choice:-Y}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        cat >> /etc/sysctl.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
        sysctl -p >/dev/null 2>&1
        color_echo GREEN "BBR 已启用。"
    fi
}

optimize_limits() {
    if grep -q "\* soft nofile 65536" /etc/security/limits.conf; then
        color_echo GREEN "系统限制已优化。"
        return
    fi
    read -p "是否要优化系统文件句柄数限制? [Y/n]: " choice
    choice=${choice:-Y}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        cat >> /etc/security/limits.conf << EOF
* soft nofile 65536
* hard nofile 65536
EOF
        color_echo GREEN "系统限制已优化。"
    fi
}

clean_system() {
    read -p "是否要清理系统垃圾 (旧内核、缓存等)? [Y/n]: " choice
    choice=${choice:-Y}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        if [[ "$PKG_MANAGER" == "apt-get" ]]; then
            apt-get autoremove -y && apt-get clean -y
        elif [[ "$PKG_MANAGER" == "yum" ]]; then
            yum autoremove -y && yum clean all -y
        fi
        color_echo GREEN "系统垃圾清理完成。"
    fi
}

optimize_menu() {
    while true; do
        clear
        echo "--- 系统优化 ---"
        echo " 1. 创建/管理 Swap (小内存VPS推荐)"
        echo " 2. 优化网络参数 (启用BBR)"
        echo " 3. 优化系统限制 (ulimit)"
        echo " 4. 清理系统垃圾"
        echo " 0. 返回主菜单"
        read -p "请输入选项 [0-4]: " choice
        
        case "$choice" in
            1) manage_swap; pause; break ;;
            2) optimize_network; pause; break ;;
            3) optimize_limits; pause; break ;;
            4) clean_system; pause; break ;;
            0) break ;;
            *) color_echo RED "无效输入"; sleep 1 ;;
        esac
    done
}


# --- 主菜单 ---

main_menu() {
    while true; do
        clear
        # 实时获取状态和IP
        get_public_ips
        check_status
        
        echo "Hysteria2 & Shadowsocks (IPv6) Management Script (v1.0)"
        echo "项目地址：https://github.com/everett7623/hy2ipv6"
        echo "博客地址：https://seedloc.com"
        echo "论坛地址：https://nodeloc.com"
        echo ""
        echo -e "服务器 IPv4:  $IPV4_ADDR"
        echo -e "服务器 IPv6:  $IPV6_ADDR"
        echo -e "Hysteria2 状态: $HY2_STATUS"
        echo -e "Shadowsocks 状态: $SS_STATUS"
        echo ""
        echo "================================================================"
        echo " 1. 安装 Hysteria2 (自签模式，无需域名解析)"
        echo " 2. 安装 Shadowsocks (仅 IPv6)"
        echo " 3. 服务管理 (启动/停止/重启/查看日志/配置)"
        echo " 4. 卸载服务"
        echo " 5. 更新服务 (更新核心程序)"
        echo " 6. 系统优化 (Swap/BBR/ulimit/清理)"
        echo " 0. 退出脚本"
        echo "================================================================"
        
        read -p "请输入选项 [0-6]: " choice
        
        case "$choice" in
            1) install_hysteria2; pause ;;
            2) install_shadowsocks; pause ;;
            3) manage_menu ;;
            4) uninstall_menu ;;
            5) update_menu ;;
            6) optimize_menu ;;
            0) exit 0 ;;
            *) color_echo RED "无效输入，请输入 0-6 之间的数字。"; sleep 1 ;;
        esac
    done
}

# --- 脚本入口 ---

main() {
    check_root
    check_os_arch
    install_dependencies
    main_menu
}

main
