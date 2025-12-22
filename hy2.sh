#!/bin/bash
#====================================================================================
# 项目：Hysteria2 Management Script
# 作者：Jensfrank
# 版本：v1.1 (优化刷新机制版)
# GitHub: https://github.com/everett7623/hy2
# Seeloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
#
# 更新日期: 2025-12-22
# 描述: 修复菜单反复刷新卡顿问题，增加 IP 缓存机制。
#====================================================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'

# --- 全局变量 ---
HY_DIR="/etc/hysteria"
HY_BIN="/usr/local/bin/hysteria"
HY_CONFIG="${HY_DIR}/config.yaml"
HY_CERT="${HY_DIR}/server.crt"
HY_KEY="${HY_DIR}/server.key"
SERVICE_FILE="/etc/systemd/system/hysteria-server.service"

# --- IP缓存变量 ---
IPV4=""
IPV6=""

# --- 检查 Root 权限 ---
[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 用户运行此脚本！${PLAIN}" && exit 1

# --- 辅助函数：日志输出 ---
log_info() { echo -e "${GREEN}[INFO] $1${PLAIN}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${PLAIN}"; }
log_err() { echo -e "${RED}[ERROR] $1${PLAIN}"; }

# --- 1. 系统检查与环境准备 ---
check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /etc/proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    else
        log_err "不支持的操作系统，脚本退出。"
        exit 1
    fi

    arch=$(uname -m)
    if [[ $arch == "x86_64" ]]; then
        arch="amd64"
    elif [[ $arch == "aarch64" ]]; then
        arch="arm64"
    else
        log_err "不支持的 CPU 架构: $arch"
        exit 1
    fi
}

install_dependencies() {
    log_info "正在更新系统并安装依赖..."
    if [[ $release == "centos" ]]; then
        yum update -y
        yum install -y curl wget openssl tar jq
    else
        apt update -y
        apt install -y curl wget openssl tar jq
    fi
    
    local total_mem=$(free -m | awk '/Mem:/ { print $2 }')
    local total_swap=$(free -m | awk '/Swap:/ { print $2 }')
    
    if [ "$total_mem" -le 512 ] && [ "$total_swap" -eq 0 ]; then
        log_warn "检测到系统内存小于 512MB 且未开启 Swap，正在创建 1GB Swap..."
        dd if=/dev/zero of=/swapfile bs=1M count=1024
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
        log_info "Swap 创建成功。"
    fi
}

# --- 2. Hysteria2 安装核心 ---
install_hy2() {
    check_sys
    install_dependencies
    
    mkdir -p ${HY_DIR}

    log_info "正在查询 Hysteria2 最新版本..."
    local version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name)
    if [[ -z "$version" || "$version" == "null" ]]; then
        log_err "无法获取版本信息，请检查网络连接。"
        exit 1
    fi
    log_info "检测到最新版本: ${version}"
    
    local download_url="https://github.com/apernet/hysteria/releases/download/${version}/hysteria-linux-${arch}"
    
    log_info "正在下载: ${download_url}"
    wget -O ${HY_BIN} ${download_url}
    if [[ $? -ne 0 ]]; then
        log_err "下载失败！"
        exit 1
    fi
    chmod +x ${HY_BIN}
    log_info "Hysteria2 主程序安装成功。"

    generate_cert
    configure_hy2
    create_service
    enable_bbr_silent
    configure_firewall
    
    log_info "安装完成！正在启动服务..."
    systemctl enable hysteria-server
    systemctl start hysteria-server
    
    show_config
}

generate_cert() {
    log_info "正在生成自签名证书 (SNI: amd.com)..."
    openssl req -x509 -nodes -newkey rsa:2048 -keyout ${HY_KEY} -out ${HY_CERT} -days 3650 -subj "/CN=amd.com"
    chmod 644 ${HY_CERT}
    chmod 600 ${HY_KEY}
}

configure_hy2() {
    read -p "请输入监听端口 (默认: 443): " input_port
    PORT=${input_port:-443}
    
    local random_pass=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    read -p "请输入连接密码 (默认随机: ${random_pass}): " input_pass
    PASSWORD=${input_pass:-$random_pass}
    
    SNI="amd.com"

    cat > ${HY_CONFIG} <<EOF
listen: :${PORT}

tls:
  cert: ${HY_CERT}
  key: ${HY_KEY}

auth:
  type: password
  password: "${PASSWORD}"

masquerade: 
  type: proxy
  proxy:
    url: https://${SNI}/ 
    rewriteHost: true

ignoreClientBandwidth: false
EOF
    log_info "配置文件已生成: ${HY_CONFIG}"
}

create_service() {
    cat > ${SERVICE_FILE} <<EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${HY_DIR}
ExecStart=${HY_BIN} server -c ${HY_CONFIG}
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

configure_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        ufw allow ${PORT}/tcp
        ufw allow ${PORT}/udp
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=${PORT}/tcp
        firewall-cmd --permanent --add-port=${PORT}/udp
        firewall-cmd --reload
    else
        iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
        iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
    fi
}

enable_bbr_silent() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
}

# --- 3. 配置查看与输出 (IP 缓存优化版) ---
get_ip() {
    # 只有当变量为空时才获取，避免每次刷新菜单都卡顿
    if [[ -z "$IPV4" ]]; then
        IPV4=$(curl -s4m 2 ip.sb) || IPV4="N/A"
    fi
    if [[ -z "$IPV6" ]]; then
        IPV6=$(curl -s6m 2 ip.sb) || IPV6="N/A"
    fi
}

show_config() {
    if [[ ! -f ${HY_CONFIG} ]]; then
        log_err "未找到配置文件，请先安装。"
        return
    fi
    
    local port=$(grep "^listen:" ${HY_CONFIG} | awk '{print $2}' | sed 's/://')
    local password=$(grep "password:" ${HY_CONFIG} | awk '{print $2}' | tr -d '"')
    local sni="amd.com"
    
    get_ip # 确保有IP
    local server_ip=$IPV4
    if [[ "$IPV4" == "N/A" ]]; then server_ip="[$IPV6]"; fi
    
    local node_name="🌟Hysteria2-Jensfrank"
    local hy2_link="hysteria2://${password}@${server_ip}:${port}/?insecure=1&sni=${sni}#${node_name}"

    echo -e "\n${BLUE}================================================================${PLAIN}"
    echo -e "${GREEN}### Hysteria2 配置信息：${PLAIN}"
    echo -e "${YELLOW}地址 (IP):${PLAIN} ${server_ip}"
    echo -e "${YELLOW}端口 (Port):${PLAIN} ${port}"
    echo -e "${YELLOW}密码 (Password):${PLAIN} ${password}"
    echo -e "${YELLOW}SNI (伪装):${PLAIN} ${sni}"
    echo -e "${BLUE}================================================================${PLAIN}"
    
    echo -e "\n${GREEN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${PLAIN}"
    echo -e "${hy2_link}"
    
    echo -e "\n${GREEN}⚔️ Clash Meta 配置:${PLAIN}"
    echo -e "- { name: '${node_name}', type: hysteria2, server: ${IPV4}, port: ${port}, password: ${password}, sni: ${sni}, skip-cert-verify: true, up: 50, down: 100 }"
    
    echo -e "\n${GREEN}🌊 Surge 配置:${PLAIN}"
    echo -e "${node_name} = hysteria2, ${IPV4}, ${port}, password=${password}, sni=${sni}, skip-cert-verify=true"
    echo -e "${BLUE}================================================================${PLAIN}"
}

# --- 4. 管理功能 ---
uninstall_hy2() {
    read -p "确定要卸载 Hysteria2 吗? [y/N]: " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        systemctl stop hysteria-server
        systemctl disable hysteria-server
        rm -f ${SERVICE_FILE}
        systemctl daemon-reload
        rm -f ${HY_BIN}
        rm -rf ${HY_DIR}
        log_info "Hysteria2 已彻底卸载。"
    fi
}

update_hy2() {
    install_hy2
}

service_manage() {
    echo -e "-------------------------"
    echo -e " 1. 启动服务"
    echo -e " 2. 停止服务"
    echo -e " 3. 重启服务"
    echo -e " 4. 查看日志"
    echo -e "-------------------------"
    read -p "请选择: " opt
    case $opt in
        1) systemctl start hysteria-server && log_info "服务已启动";;
        2) systemctl stop hysteria-server && log_info "服务已停止";;
        3) systemctl restart hysteria-server && log_info "服务已重启";;
        4) journalctl -u hysteria-server -f -n 50;;
        *) echo "无效选择";;
    esac
}

system_optimize() {
    log_info "正在进行系统网络优化..."
    enable_bbr_silent
    if ! grep -q "soft nofile 512000" /etc/security/limits.conf; then
        echo "* soft nofile 512000" >> /etc/security/limits.conf
        echo "* hard nofile 512000" >> /etc/security/limits.conf
    fi
    echo "ulimit -SHn 512000" >> /etc/profile
    log_info "优化完成！建议重启服务器生效。"
}

# --- 5. 主菜单 ---
show_menu() {
    clear
    # 首次进入菜单时获取IP，之后直接使用缓存变量
    if [[ -z "$IPV4" ]]; then
        echo -e "${YELLOW}正在获取服务器信息，请稍候...${PLAIN}"
        get_ip
        clear
    fi
    
    # 检查运行状态
    if systemctl is-active --quiet hysteria-server; then
        status="${GREEN}运行中${PLAIN}"
    else
        status="${RED}未运行 / 未安装${PLAIN}"
    fi

    echo -e "Hysteria2 Management Script (v1.1)"
    echo -e "项目地址：https://github.com/everett7623/hy2"
    echo -e "博客地址：https://seedloc.com"
    echo -e "VPS博客： https://vpsknow.com"
    echo -e "论坛地址：https://nodeloc.com"
    echo -e "------------------------------------------------"
    echo -e "服务器 IPv4: ${IPV4}"
    echo -e "服务器 IPv6: ${IPV6}"
    echo -e "Hysteria 2 状态: ${status}"
    echo -e "------------------------------------------------"
    echo -e " 1. 安装 Hysteria2 (自签模式，无需域名解析)"
    echo -e " 2. 服务管理 (启动/停止/日志)"
    echo -e " 3. 卸载服务"
    echo -e " 4. 更新服务"
    echo -e " 5. 查看配置链接"
    echo -e " 6. 系统优化 (BBR + Limits)"
    echo -e " 0. 退出脚本"
    echo -e "------------------------------------------------"
    read -p " 请输入数字 [0-6]: " num

    case "$num" in
        1) install_hy2 ;;
        2) service_manage ;;
        3) uninstall_hy2 ;;
        4) update_hy2 ;;
        5) show_config ;;
        6) system_optimize ;;
        0) exit 0 ;;
        *) echo -e "${RED}请输入正确的数字 [0-6]${PLAIN}" ;;
    esac
    
    if [[ "$num" != "0" ]]; then
        echo -e ""
        read -p "按回车键返回主菜单..."
        show_menu
    fi
}

# --- 入口 ---
show_menu
