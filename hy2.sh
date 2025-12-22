#!/bin/bash
#====================================================================================
# 项目：Hysteria2 & Shadowsocks Management Script
# 作者：Jensfrank
# 版本：v1.1 Stable
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2025-12-22
#====================================================================================

# --- 全局配置 ---
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 变量定义
HY2_CONFIG_DIR="/etc/hysteria"
HY2_CONFIG_FILE="$HY2_CONFIG_DIR/config.yaml"
HY2_SERVICE="hysteria-server.service"

SS_DIR="/etc/shadowsocks-rust"
SS_CONFIG_FILE="$SS_DIR/config.json"
SS_SERVICE="shadowsocks-rust.service"
SS_BIN="/usr/local/bin/ssserver"

# --- 辅助函数 ---

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

pause() {
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用 root 权限运行此脚本: sudo bash $0"
        exit 1
    fi
}

check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        CMD="yum"
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        CMD="apt"
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        CMD="apt"
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        CMD="yum"
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        CMD="apt"
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        CMD="apt"
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        CMD="yum"
        release="centos"
    else
        log_error "不支持的操作系统"
        exit 1
    fi
    
    # 检查架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_SS="x86_64";;
        aarch64) ARCH_SS="aarch64";;
        *) log_error "不支持的架构: $ARCH"; exit 1;;
    esac
}

install_base() {
    log_info "正在安装基础依赖..."
    if [[ "$CMD" == "apt" ]]; then
        apt update -y
        apt install -y wget curl tar gzip jq openssl ca-certificates ufw
    else
        yum install -y wget curl tar gzip jq openssl ca-certificates firewalld
    fi
}

get_ip() {
    IPV4=$(curl -s4m 5 ip.sb || curl -s4m 5 ifconfig.me || echo "N/A")
    IPV6=$(curl -s6m 5 ip.sb || curl -s6m 5 ifconfig.me || echo "N/A")
}

check_ipv6_connectivity() {
    if [[ "$IPV6" == "N/A" ]]; then
        return 1
    fi
    ping6 -c 1 google.com >/dev/null 2>&1
    return $?
}

enable_bbr() {
    if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
        log_info "开启 BBR..."
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
}

open_port() {
    local port=$1
    local protocol=$2 # tcp or udp
    
    if command -v ufw >/dev/null 2>&1 && systemctl is-active ufw >/dev/null 2>&1; then
        ufw allow "$port/$protocol" >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --zone=public --add-port="$port/$protocol" --permanent >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    # iptables fallback
    iptables -I INPUT -p "$protocol" --dport "$port" -j ACCEPT >/dev/null 2>&1
}

# --- Hysteria2 模块 ---

install_hy2() {
    log_info "=== 安装 Hysteria2 ==="
    
    # 使用官方脚本安装二进制文件
    bash <(curl -fsSL https://get.hy2.sh/)
    
    mkdir -p $HY2_CONFIG_DIR
    
    # 生成自签证书
    log_info "生成自签名证书 (SNI: amd.com)..."
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$HY2_CONFIG_DIR/server.key" \
        -out "$HY2_CONFIG_DIR/server.crt" \
        -subj "/CN=amd.com" -days 3650 >/dev/null 2>&1
    
    chmod 644 "$HY2_CONFIG_DIR/server.crt"
    chmod 600 "$HY2_CONFIG_DIR/server.key"

    # 生成随机配置
    local port=$(shuf -i 20000-50000 -n 1)
    local password=$(openssl rand -base64 16 | tr -d '+/=')
    
    cat > $HY2_CONFIG_FILE <<EOF
listen: :$port

tls:
  cert: $HY2_CONFIG_DIR/server.crt
  key: $HY2_CONFIG_DIR/server.key

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com/
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
EOF

    open_port "$port" "udp"
    
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server
    
    log_info "Hysteria2 安装完成！"
    show_hy2_info
}

show_hy2_info() {
    if [[ ! -f $HY2_CONFIG_FILE ]]; then
        log_error "Hysteria2 未安装。"
        return
    fi
    
    local port=$(grep "listen:" $HY2_CONFIG_FILE | awk -F: '{print $NF}')
    local password=$(grep "password:" $HY2_CONFIG_FILE | awk '{print $2}')
    local sni="amd.com"
    local ip=${IPV4}
    [[ "$ip" == "N/A" ]] && ip=${IPV6}
    
    echo -e "\n${CYAN}=== Hysteria2 配置信息 ===${NC}"
    echo -e "地址(IP): ${GREEN}${ip}${NC}"
    echo -e "端口(Port): ${GREEN}${port}${NC}"
    echo -e "密码(Password): ${GREEN}${password}${NC}"
    echo -e "伪装域名(SNI): ${GREEN}${sni}${NC}"
    
    local share_link="hysteria2://${password}@${ip}:${port}/?insecure=1&sni=${sni}#Hysteria2-${ip}"
    
    echo -e "\n${YELLOW}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${share_link}"
    
    echo -e "\n${YELLOW}⚔️ Clash Meta 配置:${NC}"
    echo -e "- { name: 'Hysteria2-${ip}', type: hysteria2, server: ${ip}, port: ${port}, password: ${password}, sni: ${sni}, skip-cert-verify: true, up: 50, down: 100 }"
    
    echo -e "\n${YELLOW}🌊 Surge 配置:${NC}"
    echo -e "Hysteria2-${ip} = hysteria2, ${ip}, ${port}, password=${password}, sni=${sni}, skip-cert-verify=true"
    pause
}

# --- Shadowsocks Rust 模块 ---

install_ss() {
    log_info "=== 安装 Shadowsocks-Rust (IPv6 Only) ==="
    
    if [[ "$IPV6" == "N/A" ]]; then
        log_error "未检测到 IPv6 地址，无法安装 IPv6 版 Shadowsocks。"
        pause
        return
    fi
    
    # 获取最新版本
    local latest_version=$(curl -s https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | jq -r .tag_name)
    local clean_version=${latest_version#v}
    log_info "检测到最新版本: ${latest_version}"
    
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${latest_version}/shadowsocks-v${clean_version}.${ARCH_SS}-unknown-linux-gnu.tar.xz"
    
    cd /tmp
    wget -O ss.tar.xz "$download_url"
    if [[ $? -ne 0 ]]; then
        log_error "下载失败，请检查网络。"
        return
    fi
    
    tar -xf ss.tar.xz
    mv ssserver $SS_BIN
    chmod +x $SS_BIN
    rm ss.tar.xz
    
    mkdir -p $SS_DIR
    
    # 生成配置
    local port=$(shuf -i 20000-50000 -n 1)
    local password=$(openssl rand -base64 16 | tr -d '+/=')
    
    cat > $SS_CONFIG_FILE <<EOF
{
    "server": "::",
    "server_port": $port,
    "password": "$password",
    "method": "chacha20-ietf-poly1305",
    "timeout": 300,
    "mode": "tcp_and_udp"
}
EOF

    # 创建服务文件
    cat > /etc/systemd/system/$SS_SERVICE <<EOF
[Unit]
Description=Shadowsocks-Rust Server
After=network.target

[Service]
ExecStart=$SS_BIN -c $SS_CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    open_port "$port" "tcp"
    open_port "$port" "udp"
    
    systemctl daemon-reload
    systemctl enable $SS_SERVICE >/dev/null 2>&1
    systemctl restart $SS_SERVICE
    
    log_info "Shadowsocks 安装完成！"
    show_ss_info
}

show_ss_info() {
    if [[ ! -f $SS_CONFIG_FILE ]]; then
        log_error "Shadowsocks 未安装。"
        return
    fi
    
    local port=$(jq -r .server_port $SS_CONFIG_FILE)
    local password=$(jq -r .password $SS_CONFIG_FILE)
    local method=$(jq -r .method $SS_CONFIG_FILE)
    
    # 构建 SS 链接
    local user_info="${method}:${password}"
    local user_info_b64=$(echo -n "$user_info" | base64 | tr -d '\n')
    local ss_link="ss://${user_info_b64}@[${IPV6}]:${port}#SS-IPv6"
    
    echo -e "\n${CYAN}=== Shadowsocks 配置信息 ===${NC}"
    echo -e "地址(IPv6): ${GREEN}${IPV6}${NC}"
    echo -e "端口(Port): ${GREEN}${port}${NC}"
    echo -e "密码(Pass): ${GREEN}${password}${NC}"
    echo -e "加密(Method): ${GREEN}${method}${NC}"
    
    echo -e "\n${YELLOW}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${ss_link}"
    
    echo -e "\n${YELLOW}⚔️ Clash Meta 配置:${NC}"
    echo -e "- { name: 'SS-IPv6', type: ss, server: '${IPV6}', port: ${port}, cipher: '${method}', password: '${password}', udp: true }"
    pause
}

# --- 管理功能 ---

uninstall_all() {
    log_warn "确定要卸载所有服务吗？[y/N]"
    read -r confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        systemctl stop hysteria-server $SS_SERVICE
        systemctl disable hysteria-server $SS_SERVICE
        rm -rf $HY2_CONFIG_DIR $SS_DIR /etc/systemd/system/$SS_SERVICE $SS_BIN
        bash <(curl -fsSL https://get.hy2.sh/) --remove
        log_info "卸载完成。"
    else
        log_info "已取消。"
    fi
    pause
}

system_optimize() {
    echo -e "${CYAN}正在进行系统优化...${NC}"
    enable_bbr
    
    # 增加文件描述符限制
    if ! grep -q "soft nofile 65535" /etc/security/limits.conf; then
        echo "* soft nofile 65535" >> /etc/security/limits.conf
        echo "* hard nofile 65535" >> /etc/security/limits.conf
    fi
    
    # 内存优化：检测内存大小
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $total_mem -lt 1024 ]]; then
        log_warn "检测到小内存VPS (${total_mem}MB)，正在优化 GOGC..."
        # 对于 Go 程序 (Hysteria)
        if ! grep -q "GOGC" /etc/profile; then
            echo "export GOGC=50" >> /etc/profile
        fi
        log_info "优化完成。部分设置重启生效。"
    fi
    pause
}

# --- 菜单界面 ---

show_menu() {
    clear
    check_sys
    get_ip
    
    local hy2_status
    if systemctl is-active hysteria-server >/dev/null 2>&1; then
        hy2_status="${GREEN}运行中${NC}"
    else
        hy2_status="${RED}未运行/未安装${NC}"
    fi

    local ss_status
    if systemctl is-active $SS_SERVICE >/dev/null 2>&1; then
        ss_status="${GREEN}运行中${NC}"
    else
        ss_status="${RED}未运行/未安装${NC}"
    fi

    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Hysteria2 & Shadowsocks Management Script (${VERSION})           ║${NC}"
    echo -e "${CYAN}║     更新日期: $UPDATE_DATE                                       ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e " 项目地址: https://github.com/everett7623/hy2"
    echo -e " 博客地址: https://seedloc.com"
    echo -e " VPS博客:  https://vpsknow.com"
    echo -e " 论坛地址: https://nodeloc.com"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    echo -e " 服务器 IPv4: ${YELLOW}${IPV4}${NC}"
    echo -e " 服务器 IPv6: ${YELLOW}${IPV6}${NC}"
    echo -e " Hysteria 2 状态: ${hy2_status}"
    echo -e " Shadowsocks 状态: ${ss_status}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    echo -e " 1. 安装 Hysteria2 (自签模式，无需域名解析)"
    echo -e " 2. 安装 Shadowsocks (仅 IPv6)"
    echo -e " 3. 查看 Hysteria2 配置"
    echo -e " 4. 查看 Shadowsocks 配置"
    echo -e " 5. 卸载服务"
    echo -e " 6. 系统优化 (BBR + 内存优化)"
    echo -e " 0. 退出脚本"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    
    echo -n " 请输入数字 [0-6]: "
}

main() {
    check_root
    install_base
    
    while true; do
        show_menu
        read -r choice
        case "$choice" in
            1) install_hy2 ;;
            2) install_ss ;;
            3) show_hy2_info ;;
            4) show_ss_info ;;
            5) uninstall_all ;;
            6) system_optimize ;;
            0) exit 0 ;;
            *) 
               log_error "无效输入，请重新输入"
               sleep 1
               ;;
        esac
    done
}

main
