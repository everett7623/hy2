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
HY2_SERVICE_PATH="/etc/systemd/system/hysteria2.service"
HY2_BINARY_PATH="/usr/local/bin/hysteria"
SS_CONFIG_PATH="/etc/shadowsocks/config.json"
SS_SERVICE_PATH="/etc/systemd/system/shadowsocks.service"
SS_BINARY_PATH="/usr/local/bin/ssserver"

OS_NAME=""
OS_ARCH=""
SERVER_IPV4=""
SERVER_IPV6=""
HAS_IPV6=false

# --- 基础功能函数 ---

# 检查是否以root用户运行
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误：此脚本必须以 root 用户权限运行。${NC}"
        echo -e "${YELLOW}请尝试使用 'sudo -i' 或 'sudo su' 命令切换到 root 用户后再执行。${NC}"
        exit 1
    fi
}

# 系统兼容性检查
check_system() {
    OS_NAME=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
    OS_ARCH=$(uname -m)

    echo -e "${BLUE}正在检测系统信息...${NC}"
    echo -e "操作系统: ${YELLOW}$OS_NAME${NC}"
    echo -e "架构: ${YELLOW}$OS_ARCH${NC}"

    case "$OS_NAME" in
        ubuntu|debian|centos)
            # 支持的系统
            ;;
        *)
            echo -e "${RED}错误：不支持的操作系统。目前仅支持 Ubuntu, Debian, CentOS。${NC}"
            exit 1
            ;;
    esac

    case "$OS_ARCH" in
        x86_64|aarch64)
            # 支持的架构
            ;;
        *)
            echo -e "${RED}错误：不支持的系统架构。目前仅支持 x86_64 和 aarch64 (ARM64)。${NC}"
            exit 1
            ;;
    esac
}

# 安装依赖
install_dependencies() {
    echo -e "${BLUE}正在检查并安装必要的依赖...${NC}"
    if [[ "$OS_NAME" == "centos" ]]; then
        yum install -y curl wget jq unzip socat qrencode > /dev/null 2>&1
    else
        apt-get update > /dev/null 2>&1
        apt-get install -y curl wget jq unzip socat qrencode > /dev/null 2>&1
    fi
    echo -e "${GREEN}依赖已安装完毕。${NC}"
}

# 获取IP地址和网络连通性
get_network_info() {
    SERVER_IPV4=$(curl -s -m 4 https://api.ipify.org)
    if [ -z "$SERVER_IPV4" ]; then
        SERVER_IPV4="N/A"
    fi

    # 优先获取全局单播地址，排除临时地址和本地地址
    SERVER_IPV6=$(ip -6 addr show scope global | grep 'inet6' | awk '{print $2}' | cut -d'/' -f1 | head -n 1)
    if [ -z "$SERVER_IPV6" ]; then
        SERVER_IPV6="N/A"
        HAS_IPV6=false
    else
        # 测试IPv6连通性
        if curl -s -m 4 -g "[$SERVER_IPV6]" "https://www.google.com" > /dev/null; then
            HAS_IPV6=true
        else
            HAS_IPV6=false
            SERVER_IPV6="N/A (无法连接)"
        fi
    fi
}

# 检查服务状态
check_services_status() {
    if systemctl is-active --quiet hysteria2; then
        HY2_STATUS="${GREEN}运行中${NC}"
    else
        if [ -f "$HY2_CONFIG_PATH" ]; then
            HY2_STATUS="${YELLOW}已安装但未运行${NC}"
        else
            HY2_STATUS="${RED}未安装${NC}"
        fi
    fi

    if systemctl is-active --quiet shadowsocks; then
        SS_STATUS="${GREEN}运行中${NC}"
    else
        if [ -f "$SS_CONFIG_PATH" ]; then
            SS_STATUS="${YELLOW}已安装但未运行${NC}"
        else
            SS_STATUS="${RED}未安装${NC}"
        fi
    fi
}

# --- Hysteria2 功能函数 ---
install_hysteria2() {
    if [ -f "$HY2_CONFIG_PATH" ]; then
        echo -e "${YELLOW}Hysteria2 已安装，无需重复安装。${NC}"
        return
    fi

    echo -e "${BLUE}开始安装 Hysteria2...${NC}"

    # 获取最新版本号
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name | sed 's/v//')
    if [ -z "$LATEST_VERSION" ]; then
        echo -e "${RED}获取 Hysteria2 最新版本失败，请检查网络或稍后再试。${NC}"
        exit 1
    fi
    echo -e "Hysteria2 最新版本: ${GREEN}${LATEST_VERSION}${NC}"

    # 设置安装参数
    read -p "请输入 Hysteria2 的监听端口 [默认: 随机4-5位端口]: " HY2_PORT
    [ -z "$HY2_PORT" ] && HY2_PORT=$(shuf -i 10000-65535 -n 1)
    echo -e "端口: ${YELLOW}$HY2_PORT${NC}"

    read -p "请输入 Hysteria2 的连接密码 [默认: 随机16位密码]: " HY2_PASSWORD
    [ -z "$HY2_PASSWORD" ] && HY2_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)
    echo -e "密码: ${YELLOW}$HY2_PASSWORD${NC}"

    read -p "请输入用于 SNI 伪装的域名 [回车默认: amd.com]: " HY2_SNI
    [ -z "$HY2_SNI" ] && HY2_SNI="amd.com"
    echo -e "SNI: ${YELLOW}$HY2_SNI${NC}"
    
    # 下载并安装
    ARCH_SUFFIX=""
    if [[ "$OS_ARCH" == "x86_64" ]]; then
        ARCH_SUFFIX="amd64"
    elif [[ "$OS_ARCH" == "aarch64" ]]; then
        ARCH_SUFFIX="arm64"
    fi
    
    DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v${LATEST_VERSION}/hysteria-linux-${ARCH_SUFFIX}"
    echo -e "${BLUE}正在从 ${DOWNLOAD_URL} 下载...${NC}"
    wget -q -O $HY2_BINARY_PATH $DOWNLOAD_URL
    if [ $? -ne 0 ]; then
        echo -e "${RED}Hysteria2 下载失败，请检查网络或稍后再试。${NC}"
        exit 1
    fi
    chmod +x $HY2_BINARY_PATH

    # 创建配置文件
    mkdir -p /etc/hysteria
    cat > $HY2_CONFIG_PATH <<EOF
listen: :${HY2_PORT}

tls:
  cert: /etc/hysteria/cert.pem
  key: /etc/hysteria/key.pem

auth:
  type: password
  password: ${HY2_PASSWORD}

masquerade:
  type: proxy
  proxy:
    url: https://${HY2_SNI}
    rewriteHost: true
EOF

    # 生成自签名证书
    $HY2_BINARY_PATH --config $HY2_CONFIG_PATH cert --self-signed --host $HY2_SNI --cert /etc/hysteria/cert.pem --key /etc/hysteria/key.pem

    # 创建 systemd 服务
    cat > $HY2_SERVICE_PATH <<EOF
[Unit]
Description=Hysteria2 Service
After=network.target

[Service]
Type=simple
ExecStart=${HY2_BINARY_PATH} server --config ${HY2_CONFIG_PATH}
WorkingDirectory=/etc/hysteria
User=root
Group=root
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    # 配置防火墙
    configure_firewall $HY2_PORT

    # 启动服务
    systemctl daemon-reload
    systemctl enable hysteria2
    systemctl start hysteria2

    if systemctl is-active --quiet hysteria2; then
        echo -e "${GREEN}Hysteria2 安装并启动成功！${NC}"
        display_hysteria2_config
    else
        echo -e "${RED}Hysteria2 启动失败，请运行 'journalctl -u hysteria2' 查看日志。${NC}"
    fi
}

display_hysteria2_config() {
    if [ ! -f "$HY2_CONFIG_PATH" ]; then
        echo -e "${RED}Hysteria2 未安装，无法显示配置。${NC}"
        return
    fi
    
    HY2_PORT=$(grep -oP '(?<=listen: :)\d+' $HY2_CONFIG_PATH)
    HY2_PASSWORD=$(grep -oP '(?<=password: ).*' $HY2_CONFIG_PATH)
    HY2_SNI=$(grep -oP '(?<=url: https://).*' $HY2_CONFIG_PATH)
    DISPLAY_IP=$SERVER_IPV4
    if [[ "$DISPLAY_IP" == "N/A" ]]; then
        DISPLAY_IP="[$SERVER_IPV6]"
    fi

    SHARE_LINK="hysteria2://${HY2_PASSWORD}@${DISPLAY_IP}:${HY2_PORT}/?insecure=true&sni=${HY2_SNI}#Hysteria2"
    CLASH_META_CONFIG="- { name: 'Hysteria2', type: hysteria2, server: ${DISPLAY_IP}, port: ${HY2_PORT}, password: ${HY2_PASSWORD}, sni: ${HY2_SNI}, skip-cert-verify: true, up: 50, down: 100 }"
    SURGE_CONFIG="Hysteria2 = hysteria2, ${DISPLAY_IP}, ${HY2_PORT}, password=${HY2_PASSWORD}, sni=${HY2_SNI}, skip-cert-verify=true"

    echo -e "\n--- ${GREEN}Hysteria2 配置信息${NC} ---"
    echo -e "🚀 ${YELLOW}V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${GREEN}${SHARE_LINK}${NC}"
    echo ""
    echo -e "⚔️ ${YELLOW}Clash Meta 配置:${NC}"
    echo -e "${GREEN}${CLASH_META_CONFIG}${NC}"
    echo ""
    echo -e "🌊 ${YELLOW}Surge 配置:${NC}"
    echo -e "${GREEN}${SURGE_CONFIG}${NC}"
    echo -e "-------------------------------------\n"
}

uninstall_hysteria2() {
    if [ ! -f "$HY2_CONFIG_PATH" ]; then
        echo -e "${YELLOW}Hysteria2 未安装。${NC}"
        return
    fi
    
    echo -e "${RED}警告：这将永久删除 Hysteria2 及其所有配置。${NC}"
    read -p "确定要卸载 Hysteria2 吗? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "${BLUE}卸载已取消。${NC}"
        return
    fi

    systemctl stop hysteria2
    systemctl disable hysteria2
    rm -f $HY2_SERVICE_PATH
    rm -rf /etc/hysteria
    rm -f $HY2_BINARY_PATH
    systemctl daemon-reload
    
    echo -e "${GREEN}Hysteria2 已成功卸载。${NC}"
}

# --- Shadowsocks 功能函数 ---
install_shadowsocks() {
    if [ "$HAS_IPV6" = false ]; then
        echo -e "${RED}错误：未检测到可用的 IPv6 连接。Shadowsocks (仅IPv6模式) 无法安装。${NC}"
        return
    fi
    if [ -f "$SS_CONFIG_PATH" ]; then
        echo -e "${YELLOW}Shadowsocks 已安装，无需重复安装。${NC}"
        return
    fi

    echo -e "${BLUE}开始安装 Shadowsocks (仅 IPv6)...${NC}"

    # 获取最新版本号
    LATEST_SS_VERSION=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r .tag_name | sed 's/v//')
    if [ -z "$LATEST_SS_VERSION" ]; then
        echo -e "${RED}获取 shadowsocks-rust 最新版本失败，请检查网络或稍后再试。${NC}"
        exit 1
    fi
    echo -e "shadowsocks-rust 最新版本: ${GREEN}${LATEST_SS_VERSION}${NC}"

    # 设置安装参数
    read -p "请输入 Shadowsocks 的监听端口 [默认: 随机4-5位端口]: " SS_PORT
    [ -z "$SS_PORT" ] && SS_PORT=$(shuf -i 10000-65535 -n 1)
    echo -e "端口: ${YELLOW}$SS_PORT${NC}"

    read -p "请输入 Shadowsocks 的连接密码 [默认: 随机16位密码]: " SS_PASSWORD
    [ -z "$SS_PASSWORD" ] && SS_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)
    echo -e "密码: ${YELLOW}$SS_PASSWORD${NC}"
    
    SS_METHOD="2022-blake3-aes-128-gcm"
    echo -e "加密方式: ${YELLOW}$SS_METHOD${NC}"

    # 下载并安装
    ARCH_SUFFIX=""
    if [[ "$OS_ARCH" == "x86_64" ]]; then
        ARCH_SUFFIX="x86_64-unknown-linux-gnu"
    elif [[ "$OS_ARCH" == "aarch64" ]]; then
        ARCH_SUFFIX="aarch64-unknown-linux-gnu"
    fi

    DOWNLOAD_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${LATEST_SS_VERSION}/shadowsocks-v${LATEST_SS_VERSION}.${ARCH_SUFFIX}.tar.xz"
    echo -e "${BLUE}正在从 ${DOWNLOAD_URL} 下载...${NC}"
    wget -qO- $DOWNLOAD_URL | tar -xJ -C /usr/local/bin ssserver
    if [ ! -f "$SS_BINARY_PATH" ]; then
        echo -e "${RED}Shadowsocks 下载或解压失败，请检查网络或稍后再试。${NC}"
        exit 1
    fi
    chmod +x $SS_BINARY_PATH

    # 创建配置文件
    mkdir -p /etc/shadowsocks
    cat > $SS_CONFIG_PATH <<EOF
{
    "server": "[::]",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}"
}
EOF

    # 创建 systemd 服务
    cat > $SS_SERVICE_PATH <<EOF
[Unit]
Description=Shadowsocks-rust Service
After=network.target

[Service]
Type=simple
ExecStart=${SS_BINARY_PATH} -c ${SS_CONFIG_PATH}
User=root
Group=root
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    # 配置防火墙
    configure_firewall $SS_PORT

    # 启动服务
    systemctl daemon-reload
    systemctl enable shadowsocks
    systemctl start shadowsocks

    if systemctl is-active --quiet shadowsocks; then
        echo -e "${GREEN}Shadowsocks 安装并启动成功！${NC}"
        display_shadowsocks_config
    else
        echo -e "${RED}Shadowsocks 启动失败，请运行 'journalctl -u shadowsocks' 查看日志。${NC}"
    fi
}

display_shadowsocks_config() {
    if [ ! -f "$SS_CONFIG_PATH" ]; then
        echo -e "${RED}Shadowsocks 未安装，无法显示配置。${NC}"
        return
    fi
    
    SS_PORT=$(jq -r '.server_port' $SS_CONFIG_PATH)
    SS_PASSWORD=$(jq -r '.password' $SS_CONFIG_PATH)
    SS_METHOD=$(jq -r '.method' $SS_CONFIG_PATH)

    # 编码分享链接
    SS_INFO=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 | tr -d '\n')
    SHARE_LINK="ss://${SS_INFO}@[${SERVER_IPV6}]:${SS_PORT}#Shadowsocks_IPv6"

    echo -e "\n--- ${GREEN}Shadowsocks (IPv6) 配置信息${NC} ---"
    echo -e "服务器地址: ${YELLOW}${SERVER_IPV6}${NC}"
    echo -e "端口: ${YELLOW}${SS_PORT}${NC}"
    echo -e "密码: ${YELLOW}${SS_PASSWORD}${NC}"
    echo -e "加密方式: ${YELLOW}${SS_METHOD}${NC}"
    echo ""
    echo -e "🚀 ${YELLOW}SS 分享链接 (点击复制):${NC}"
    echo -e "${GREEN}${SHARE_LINK}${NC}"
    echo ""
    echo -e "📋 ${YELLOW}二维码分享 (请扫描终端显示的二维码):${NC}"
    qrencode -t ansiutf8 "${SHARE_LINK}"
    echo -e "-------------------------------------\n"
}

uninstall_shadowsocks() {
    if [ ! -f "$SS_CONFIG_PATH" ]; then
        echo -e "${YELLOW}Shadowsocks 未安装。${NC}"
        return
    fi
    
    echo -e "${RED}警告：这将永久删除 Shadowsocks 及其所有配置。${NC}"
    read -p "确定要卸载 Shadowsocks 吗? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "${BLUE}卸载已取消。${NC}"
        return
    fi
    
    systemctl stop shadowsocks
    systemctl disable shadowsocks
    rm -f $SS_SERVICE_PATH
    rm -rf /etc/shadowsocks
    rm -f $SS_BINARY_PATH
    systemctl daemon-reload
    
    echo -e "${GREEN}Shadowsocks 已成功卸载。${NC}"
}

# --- 其他管理功能 ---
configure_firewall() {
    PORT=$1
    if systemctl is-active --quiet ufw; then
        if ufw status | grep -qw "$PORT"; then
            echo -e "${YELLOW}防火墙 (ufw) 规则已存在，跳过。${NC}"
        else
            ufw allow $PORT/tcp > /dev/null 2>&1
            ufw allow $PORT/udp > /dev/null 2>&1
            echo -e "${GREEN}已在 ufw 中放行端口 ${PORT} (TCP/UDP)。${NC}"
        fi
    elif systemctl is-active --quiet firewalld; then
        if firewall-cmd --list-ports | grep -qw "$PORT/tcp"; then
            echo -e "${YELLOW}防火墙 (firewalld) 规则已存在，跳过。${NC}"
        else
            firewall-cmd --permanent --add-port=$PORT/tcp > /dev/null 2>&1
            firewall-cmd --permanent --add-port=$PORT/udp > /dev/null 2>&1
            firewall-cmd --reload > /dev/null 2>&1
            echo -e "${GREEN}已在 firewalld 中放行端口 ${PORT} (TCP/UDP)。${NC}"
        fi
    fi
}

# --- 菜单功能 ---
show_main_menu() {
    clear
    get_network_info
    check_services_status
    
    echo "=========================================================================="
    echo " Hysteria2 & Shadowsocks (IPv6) Management Script (v1.0)"
    echo " 项目地址：https://github.com/everett7623/hy2ipv6"
    echo " 博客地址：https://seedloc.com"
    echo " 论坛地址：https://nodeloc.com"
    echo "=========================================================================="
    echo -e " 服务器 IPv4:  ${YELLOW}${SERVER_IPV4}${NC}"
    echo -e " 服务器 IPv6:  ${YELLOW}${SERVER_IPV6}${NC}"
    echo -e " Hysteria2 状态: ${HY2_STATUS}"
    echo -e " Shadowsocks 状态: ${SS_STATUS}"
    echo "=========================================================================="
    echo -e " ${BLUE}1.${NC} 安装 Hysteria2 (自签名证书模式，无需域名)"
    echo -e " ${BLUE}2.${NC} 安装 Shadowsocks (仅 IPv6)"
    echo " ------------------------------------------------------------------------"
    echo -e " ${BLUE}3.${NC} 服务管理 (启动、停止、重启、日志、配置)"
    echo -e " ${BLUE}4.${NC} 卸载服务"
    echo -e " ${BLUE}5.${NC} 更新服务"
    echo -e " ${BLUE}6.${NC} 系统优化"
    echo "=========================================================================="
    echo -e " ${BLUE}0.${NC} 退出脚本"
    echo "=========================================================================="
    read -p "请输入选项 [0-6]: " choice
    
    case $choice in
        1) install_hysteria2 ;;
        2) install_shadowsocks ;;
        3) show_service_management_menu ;;
        4) show_uninstall_menu ;;
        5) echo "更新功能待开发..." ;; # 占位
        6) echo "系统优化功能待开发..." ;; # 占位
        0) exit 0 ;;
        *) echo -e "${RED}无效的选项，请输入 0-6 之间的数字。${NC}" ;;
    esac
    
    read -p "按 Enter 返回主菜单..."
}

show_service_management_menu() {
    clear
    echo "==================== 服务管理 ===================="
    echo -e " ${BLUE}1.${NC} 管理 Hysteria2"
    echo -e " ${BLUE}2.${NC} 管理 Shadowsocks"
    echo " --------------------------------------------------"
    echo -e " ${BLUE}0.${NC} 返回主菜单"
    echo "=================================================="
    read -p "请输入选项 [0-2]: " sub_choice
    
    case $sub_choice in
        1) manage_service "hysteria2" ;;
        2) manage_service "shadowsocks" ;;
        0) return ;;
        *) echo -e "${RED}无效的选项。${NC}" ;;
    esac
}

manage_service() {
    SERVICE_NAME=$1
    CONFIG_PATH=""
    if [ "$SERVICE_NAME" == "hysteria2" ]; then
        CONFIG_PATH=$HY2_CONFIG_PATH
    else
        CONFIG_PATH=$SS_CONFIG_PATH
    fi

    if [ ! -f "$CONFIG_PATH" ]; then
        echo -e "${RED}${SERVICE_NAME} 未安装。${NC}"
        read -p "按 Enter 返回..."
        show_service_management_menu
        return
    fi
    
    clear
    echo "==================== 管理 ${SERVICE_NAME} ===================="
    echo -e " ${BLUE}1.${NC} 启动服务"
    echo -e " ${BLUE}2.${NC} 停止服务"
    echo -e " ${BLUE}3.${NC} 重启服务"
    echo -e " ${BLUE}4.${NC} 查看日志"
    echo -e " ${BLUE}5.${NC} 显示配置信息"
    echo " --------------------------------------------------"
    echo -e " ${BLUE}0.${NC} 返回上一级菜单"
    echo "======================================================="
    read -p "请输入选项 [0-5]: " action
    
    case $action in
        1) systemctl start $SERVICE_NAME && echo -e "${GREEN}${SERVICE_NAME} 已启动。${NC}" || echo -e "${RED}启动失败。${NC}" ;;
        2) systemctl stop $SERVICE_NAME && echo -e "${GREEN}${SERVICE_NAME} 已停止。${NC}" || echo -e "${RED}停止失败。${NC}" ;;
        3) systemctl restart $SERVICE_NAME && echo -e "${GREEN}${SERVICE_NAME} 已重启。${NC}" || echo -e "${RED}重启失败。${NC}" ;;
        4) journalctl -u $SERVICE_NAME -f --no-pager ;;
        5) 
            if [ "$SERVICE_NAME" == "hysteria2" ]; then
                display_hysteria2_config
            else
                display_shadowsocks_config
            fi
            ;;
        0) show_service_management_menu ;;
        *) echo -e "${RED}无效的选项。${NC}" ;;
    esac
    read -p "按 Enter 返回..."
    manage_service $SERVICE_NAME
}


show_uninstall_menu() {
    clear
    echo "==================== 卸载服务 ===================="
    echo -e " ${RED}1. 卸载 Hysteria2${NC}"
    echo -e " ${RED}2. 卸载 Shadowsocks${NC}"
    echo -e " ${RED}3. 卸载所有服务${NC}"
    echo " --------------------------------------------------"
    echo -e " ${BLUE}0. 返回主菜单${NC}"
    echo "=================================================="
    read -p "请输入选项 [0-3]: " uninstall_choice

    case $uninstall_choice in
        1) uninstall_hysteria2 ;;
        2) uninstall_shadowsocks ;;
        3) 
            uninstall_hysteria2
            uninstall_shadowsocks
            ;;
        0) return ;;
        *) echo -e "${RED}无效的选项。${NC}" ;;
    esac
}

# --- 脚本主入口 ---
main() {
    check_root
    check_system
    install_dependencies
    
    while true; do
        show_main_menu
    done
}

main
