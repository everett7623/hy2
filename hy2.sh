#!/bin.bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks Management Script
# 作者：Jensfrank
# 版本：v1.0
# GitHub: https://github.com/everett7623/hy2
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

# 系统检查
check_system() {
    local os_release=""
    local arch=$(uname -m)

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
    local pkgs=("curl" "wget" "jq" "qrencode" "openssl")
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

# --- Hysteria2 功能 ---

install_hy2() {
    msg "info" "开始安装 Hysteria2..."
    
    # 提示输入信息
    read -rp "请输入 Hysteria2 监听端口 (默认 443): " hy2_port
    [[ -z "$hy2_port" ]] && hy2_port=443
    
    read -rp "请输入 Hysteria2 连接密码 (默认随机生成): " hy2_password
    [[ -z "$hy2_password" ]] && hy2_password=$(openssl rand -base64 16)

    read -rp "请输入用于 SNI 伪装的域名 (回车默认 amd.com): " hy2_sni
    [[ -z "$hy2_sni" ]] && hy2_sni="amd.com"

    # 下载并安装
    msg "info" "正在从 GitHub 获取最新版本的 Hysteria2..."
    local latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    local arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
    esac
    local download_url="https://github.com/apernet/hysteria/releases/download/v${latest_version}/hysteria-linux-${arch}"

    (sudo wget -O "$HY2_BINARY_PATH" "$download_url" && sudo chmod +x "$HY2_BINARY_PATH") &> /dev/null &
    show_progress $!
    
    # 创建目录和证书
    sudo mkdir -p "$HY2_CERT_PATH"
    openssl ecparam -genkey -name prime256v1 -out "$HY2_CERT_PATH/private.key" &> /dev/null
    openssl req -new -x509 -days 3650 -key "$HY2_CERT_PATH/private.key" -out "$HY2_CERT_PATH/public.crt" -subj "/CN=bing.com" &> /dev/null
    
    # 创建配置文件
    cat > "$HY2_CONFIG_PATH" << EOF
listen: :${hy2_port}
tls:
  cert: ${HY2_CERT_PATH}/public.crt
  key: ${HY2_CERT_PATH}/private.key
obfs:
  type: password
  password: ${hy2_password}
EOF

    # 创建 systemd 服务
    cat > "$HY2_SERVICE_PATH" << EOF
[Unit]
Description=Hysteria 2 Service
After=network.target

[Service]
Type=simple
ExecStart=${HY2_BINARY_PATH} server --config ${HY2_CONFIG_PATH}
WorkingDirectory=${HY2_INSTALL_PATH}
Restart=on-failure
RestartSec=5s
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # 启动服务
    sudo systemctl daemon-reload
    sudo systemctl enable --now hysteria
    
    # 配置防火墙
    configure_firewall "$hy2_port"

    msg "success" "Hysteria2 安装并启动成功！"
    display_hy2_config
}

display_hy2_config() {
    local port=$(grep -oP '(?<=listen: :)\d+' "$HY2_CONFIG_PATH")
    local password=$(grep -oP '(?<=password: ).*' "$HY2_CONFIG_PATH")
    local sni=$(grep -oP '(?<=sni: ).*' "$HY2_CONFIG_PATH" 2>/dev/null || echo "amd.com")
    local server_ip=$ipv4

    if [[ "$server_ip" == "N/A" && "$ipv6" != "N/A" ]]; then
        server_ip="[${ipv6}]"
    fi

    local share_link="hysteria2://${password}@${server_ip}:${port}/?insecure=true&sni=${sni}#🌟Hysteria2-$(hostname)"
    
    echo -e "\n--- ${GREEN}Hysteria2 配置信息${NC} ---"
    echo -e "🚀 ${YELLOW}V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${share_link}"
    echo
    echo -e "⚔️ ${YELLOW}Clash Meta 配置:${NC}"
    echo -e "- { name: '🌟Hysteria2-$(hostname)', type: hysteria2, server: ${server_ip}, port: ${port}, password: ${password}, sni: ${sni}, skip-cert-verify: true, up: 50, down: 100 }"
    echo
    echo -e "🌊 ${YELLOW}Surge 配置:${NC}"
    echo -e "🌟Hysteria2-$(hostname) = hysteria2, ${server_ip}, ${port}, password=${password}, sni=${sni}, skip-cert-verify=true"
    echo -e "-----------------------------------\n"
}

# --- Shadowsocks 功能 ---

install_ss() {
    if [[ "$ipv6" == "N/A" ]]; then
        msg "error" "未检测到 IPv6 地址，Shadowsocks (仅IPv6) 无法安装。"
        return
    fi
    msg "info" "开始安装 Shadowsocks (仅 IPv6)..."

    read -rp "请输入 Shadowsocks 监听端口 (默认随机): " ss_port
    [[ -z "$ss_port" ]] && ss_port=$(shuf -i 10000-65535 -n 1)

    read -rp "请输入 Shadowsocks 密码 (默认随机): " ss_password
    [[ -z "$ss_password" ]] && ss_password=$(openssl rand -base64 12)

    local ciphers=("chacha20-ietf-poly1305" "aes-256-gcm" "aes-128-gcm")
    echo "请选择加密方式:"
    select ss_cipher in "${ciphers[@]}"; do
        [[ -n "$ss_cipher" ]] && break || echo "无效选择，请重试。"
    done

    msg "info" "正在从 GitHub 获取最新版本的 shadowsocks-rust..."
    local latest_version=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    local arch=$(uname -m)
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.${arch}-unknown-linux-gnu.tar.xz"

    (wget -O /tmp/ss.tar.xz "$download_url" && tar -xf /tmp/ss.tar.xz -C /tmp && sudo mv /tmp/ssserver "$SS_BINARY_PATH" && rm -rf /tmp/ss* ) &> /dev/null &
    show_progress $!

    # 创建目录和配置文件
    sudo mkdir -p "$SS_INSTALL_PATH"
    cat > "$SS_CONFIG_PATH" << EOF
{
    "server": "::",
    "server_port": ${ss_port},
    "password": "${ss_password}",
    "method": "${ss_cipher}",
    "mode": "tcp_and_udp"
}
EOF

    # 创建 systemd 服务
    cat > "$SS_SERVICE_PATH" << EOF
[Unit]
Description=Shadowsocks-rust server
After=network.target

[Service]
User=root
ExecStart=${SS_BINARY_PATH} -c ${SS_CONFIG_PATH}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    # 启动服务
    sudo systemctl daemon-reload
    sudo systemctl enable --now shadowsocks

    # 配置防火墙
    configure_firewall "$ss_port"

    msg "success" "Shadowsocks 安装并启动成功！"
    display_ss_config
}

display_ss_config() {
    local port=$(jq -r '.server_port' "$SS_CONFIG_PATH")
    local password=$(jq -r '.password' "$SS_CONFIG_PATH")
    local cipher=$(jq -r '.method' "$SS_CONFIG_PATH")
    local encoded_part=$(echo -n "${cipher}:${password}" | base64 | tr -d '\n')
    local share_link="ss://${encoded_part}@[${ipv6}]:${port}#🌟SS-IPv6-$(hostname)"

    echo -e "\n--- ${GREEN}Shadowsocks 配置信息${NC} ---"
    echo -e "🚀 ${YELLOW}V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${share_link}"
    echo
    echo -e "⚔️ ${YELLOW}Clash Meta 配置:${NC}"
    echo -e "- { name: '🌟SS-IPv6-$(hostname)', type: ss, server: '${ipv6}', port: ${port}, cipher: '${cipher}', password: '${password}', udp: true}"
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
    if ! systemctl list-units --type=service | grep -q "hysteria.service"; then
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
        4) systemctl status hysteria ;;
        5) display_hy2_config ;;
        0) ;;
        *) msg "warning" "无效输入。" ;;
    esac
}

manage_ss_menu() {
    if ! systemctl list-units --type=service | grep -q "shadowsocks.service"; then
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
        4) systemctl status shadowsocks ;;
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
    echo " 3. 更新系统内核 (慎用)"
    echo " 0. 返回主菜单"
    echo "================"
    read -rp "请输入选项: " choice
    case "$choice" in
        1) update_hy2 ;;
        2) update_ss ;;
        3) update_kernel ;;
        0) ;;
        *) msg "warning" "无效输入。" ;;
    esac
}

update_hy2() {
    msg "info" "正在更新 Hysteria2..."
    sudo systemctl stop hysteria
    local latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    local arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
    esac
    local download_url="https://github.com/apernet/hysteria/releases/download/v${latest_version}/hysteria-linux-${arch}"
    (sudo wget -O "$HY2_BINARY_PATH" "$download_url" && sudo chmod +x "$HY2_BINARY_PATH") &> /dev/null &
    show_progress $!
    sudo systemctl start hysteria
    msg "success" "Hysteria2 已更新至最新版本。"
}

update_ss() {
    msg "info" "正在更新 Shadowsocks..."
    sudo systemctl stop shadowsocks
    local latest_version=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r '.tag_name' | sed 's/v//')
    local arch=$(uname -m)
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${latest_version}/shadowsocks-v${latest_version}.${arch}-unknown-linux-gnu.tar.xz"
    (wget -O /tmp/ss.tar.xz "$download_url" && tar -xf /tmp/ss.tar.xz -C /tmp && sudo mv /tmp/ssserver "$SS_BINARY_PATH" && rm -rf /tmp/ss*) &> /dev/null &
    show_progress $!
    sudo systemctl start shadowsocks
    msg "success" "Shadowsocks 已更新至最新版本。"
}

update_kernel() {
    msg "warning" "更新内核是高风险操作，可能导致服务器无法启动。"
    read -rp "您确定要继续吗？(y/N): " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        if command -v apt-get &>/dev/null; then
            (sudo apt-get update && sudo apt-get dist-upgrade -y) &
            show_progress $!
        elif command -v yum &>/dev/null; then
            (sudo yum update -y) &
            show_progress $!
        else
            msg "error" "不支持的包管理器。"
            return
        fi
        msg "success" "内核及系统更新完成，建议重启服务器。"
    else
        msg "info" "操作已取消。"
    fi
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
            sudo swapoff -a && sudo rm -f /swapfile
            msg "success" "Swap 已移除。"
        fi
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
        sudo sysctl -p
        msg "success" "BBR 已启用。"
    else
        msg "info" "BBR 已启用。"
    fi
}

optimize_limits() {
    msg "info" "正在优化系统文件描述符限制..."
    local limits_conf="/etc/security/limits.conf"
    if ! grep -q "* soft nofile 65536" "$limits_conf"; then
        echo "* soft nofile 65536" | sudo tee -a "$limits_conf"
        echo "* hard nofile 65536" | sudo tee -a "$limits_conf"
        msg "success" "系统限制已优化。"
    else
        msg "info" "系统限制已是优化状态。"
    fi
}

clean_system() {
    msg "info" "正在清理系统缓存..."
    if command -v apt-get &>/dev/null; then
        (sudo apt-get autoremove -y && sudo apt-get clean) &
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
    fi
    
    local ss_status="${RED}未安装${NC}"
    if systemctl is-active --quiet shadowsocks; then
        ss_status="${GREEN}运行中${NC}"
    fi

    echo "===================================================================================="
    echo -e "          ${BLUE}Hysteria2 & Shadowsocks Management Script (v1.0)${NC}"
    echo " 项目地址：https://github.com/everett7623/hy2"
    echo " 博客地址：https://seedloc.com"
    echo " 论坛地址：https://nodeloc.com"
    echo "===================================================================================="
    echo -e " 服务器 IPv4:  ${YELLOW}${ipv4}${NC}"
    echo -e " 服务器 IPv6:  ${YELLOW}${ipv6}${NC}"
    echo -e " Hysteria 2 状态: ${hy2_status}"
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
    check_system
    install_dependencies
    
    while true; do
        main_menu
        read -rp "按 Enter 键返回主菜单..."
    done
}

main "$@"
