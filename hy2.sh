#!/bin/bash
#====================================================================================
# 项目：Hysteria2 Management Script
# 作者：Jensfrank
# 版本：v1.0
# GitHub: https://github.com/everett7623/hy2
# Seeloc博客: https://seedloc.com
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
}

install_base() {
    # 静默安装依赖，不输出过多信息
    if [[ "$CMD" == "apt" ]]; then
        apt update -y >/dev/null 2>&1
        apt install -y wget curl tar gzip jq openssl ca-certificates ufw >/dev/null 2>&1
    else
        yum install -y wget curl tar gzip jq openssl ca-certificates firewalld >/dev/null 2>&1
    fi
}

get_ip() {
    IPV4=$(curl -s4m 5 ip.sb || curl -s4m 5 ifconfig.me || echo "N/A")
    IPV6=$(curl -s6m 5 ip.sb || curl -s6m 5 ifconfig.me || echo "N/A")
}

enable_bbr() {
    if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
}

open_port() {
    local port=$1
    local protocol=$2 # tcp or udp
    
    # 尝试多种防火墙工具
    if command -v ufw >/dev/null 2>&1 && systemctl is-active ufw >/dev/null 2>&1; then
        ufw allow "$port/$protocol" >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --zone=public --add-port="$port/$protocol" --permanent >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    # iptables 保底
    iptables -I INPUT -p "$protocol" --dport "$port" -j ACCEPT >/dev/null 2>&1
}

# --- Hysteria2 核心功能 ---

install_hy2() {
    log_info "=== 开始安装 Hysteria2 (自签模式) ==="
    
    enable_bbr
    install_base

    # 下载并安装 Hysteria2
    if ! bash <(curl -fsSL https://get.hy2.sh/); then
        log_error "安装脚本下载或执行失败，请检查网络。"
        pause
        return
    fi
    
    mkdir -p $HY2_CONFIG_DIR
    
    # 生成自签证书
    log_info "正在生成自签名证书 (SNI: amd.com)..."
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$HY2_CONFIG_DIR/server.key" \
        -out "$HY2_CONFIG_DIR/server.crt" \
        -subj "/CN=amd.com" -days 3650 >/dev/null 2>&1
    
    chmod 644 "$HY2_CONFIG_DIR/server.crt"
    chmod 600 "$HY2_CONFIG_DIR/server.key"

    # 生成随机配置
    local port=$(shuf -i 20000-50000 -n 1)
    local password=$(openssl rand -base64 16 | tr -d '+/=')
    
    # 写入配置文件
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

    # 放行端口
    open_port "$port" "udp"
    
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server
    
    sleep 2
    if systemctl is-active --quiet hysteria-server; then
        log_info "Hysteria2 安装并启动成功！"
        show_config
    else
        log_error "Hysteria2 启动失败，请检查日志 (journalctl -u hysteria-server)"
        pause
    fi
}

show_config() {
    if [[ ! -f $HY2_CONFIG_FILE ]]; then
        log_error "Hysteria2 配置文件不存在，请先安装。"
        pause
        return
    fi
    
    # 从配置文件读取信息
    local port=$(grep "listen:" $HY2_CONFIG_FILE | awk -F: '{print $NF}')
    local password=$(grep "password:" $HY2_CONFIG_FILE | awk '{print $2}')
    local sni="amd.com"
    local ip=${IPV4}
    [[ "$ip" == "N/A" ]] && ip=${IPV6}
    local date_tag=$(date +%m%d)
    local name="Hysteria2-${ip}"
    
    echo -e "\n${CYAN}### Hysteria2 配置信息：${NC}"
    
    local share_link="hysteria2://${password}@${ip}:${port}/?insecure=1&sni=${sni}#${name}"
    
    echo -e "${GREEN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${YELLOW}${share_link}${NC}"
    echo ""
    
    echo -e "${GREEN}⚔️ Clash Meta 配置:${NC}"
    echo -e "${BLUE}- { name: '${name}', type: hysteria2, server: ${ip}, port: ${port}, password: ${password}, sni: ${sni}, skip-cert-verify: true, up: 50, down: 100 }${NC}"
    echo ""
    
    echo -e "${GREEN}🌊 Surge 配置:${NC}"
    echo -e "${BLUE}${name} = hysteria2, ${ip}, ${port}, password=${password}, sni=${sni}, skip-cert-verify=true${NC}"
    
    pause
}

service_manager() {
    while true; do
        clear
        echo -e "${CYAN}============== 服务管理 ==============${NC}"
        echo -e " 1. 启动 Hysteria2"
        echo -e " 2. 停止 Hysteria2"
        echo -e " 3. 重启 Hysteria2"
        echo -e " 4. 查看运行状态"
        echo -e " 5. 查看配置信息"
        echo -e " 0. 返回主菜单"
        echo -e "${CYAN}======================================${NC}"
        read -p "请选择操作 [0-5]: " sub_choice
        
        case $sub_choice in
            1) systemctl start hysteria-server && log_info "已发送启动命令" ;;
            2) systemctl stop hysteria-server && log_warn "已发送停止命令" ;;
            3) systemctl restart hysteria-server && log_info "已发送重启命令" ;;
            4) systemctl status hysteria-server --no-pager ;;
            5) show_config; return ;;
            0) return ;;
            *) log_error "无效输入" ;;
        esac
        [ "$sub_choice" != "5" ] && [ "$sub_choice" != "0" ] && pause
    done
}

uninstall_hy2() {
    log_warn "⚠️  警告：这将彻底卸载 Hysteria2 并删除所有配置文件。"
    read -p "确认继续? (y/n): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        systemctl stop hysteria-server
        systemctl disable hysteria-server
        bash <(curl -fsSL https://get.hy2.sh/) --remove
        rm -rf $HY2_CONFIG_DIR
        log_info "Hysteria2 已卸载。"
    else
        log_info "操作已取消。"
    fi
    pause
}

update_hy2() {
    log_info "正在更新 Hysteria2..."
    # 官方脚本会自动处理更新
    bash <(curl -fsSL https://get.hy2.sh/)
    systemctl restart hysteria-server
    log_info "更新完成并已重启服务。"
    pause
}

system_optimization() {
    log_info "正在进行系统优化..."
    
    # BBR
    enable_bbr
    
    # 文件描述符限制
    if ! grep -q "soft nofile 65535" /etc/security/limits.conf; then
        echo "* soft nofile 65535" >> /etc/security/limits.conf
        echo "* hard nofile 65535" >> /etc/security/limits.conf
        ulimit -n 65535
    fi
    
    # 内存优化：针对小内存机器调整 GOGC
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $total_mem -lt 1024 ]]; then
        log_warn "检测到小内存VPS (${total_mem}MB)，优化 Go 垃圾回收机制..."
        if ! grep -q "GOGC" /etc/profile; then
            echo "export GOGC=50" >> /etc/profile
            export GOGC=50
        fi
    fi
    
    log_info "系统优化完成。"
    pause
}

# --- 主菜单 ---

show_menu() {
    clear
    check_sys
    get_ip
    
    local hy2_status
    if systemctl is-active --quiet hysteria-server; then
        hy2_status="${GREEN}运行中${NC}"
    else
        hy2_status="${RED}未安装/未运行${NC}"
    fi

    echo -e "Hysteria2 Management Script (${VERSION}) "
    echo -e "项目地址：https://github.com/everett7623/hy2"
    echo -e "博客地址：https://seedloc.com"
    echo -e "VPS博客：https://vpsknow.com"
    echo -e "论坛地址：https://nodeloc.com"
    echo ""
    echo -e "服务器 IPv4:  ${YELLOW}${IPV4}${NC}"
    echo -e "服务器 IPv6:  ${YELLOW}${IPV6}${NC}"
    echo -e "Hysteria 2 状态: ${hy2_status}"
    echo ""
    echo -e "${CYAN}================================================${NC}"
    echo -e " 1. 安装 Hysteria2(自签模式，无需域名解析)"
    echo -e " 2. 服务管理"
    echo -e " 3. 卸载服务"
    echo -e " 4. 更新服务"
    echo -e " 5. 系统优化"
    echo -e "   0.退出脚本"
    echo -e "${CYAN}================================================${NC}"
    
    echo -n " 请输入数字 [0-5]: "
}

main() {
    check_root
    
    while true; do
        show_menu
        read -r choice
        case "$choice" in
            1) install_hy2 ;;
            2) service_manager ;;
            3) uninstall_hy2 ;;
            4) update_hy2 ;;
            5) system_optimization ;;
            0) exit 0 ;;
            *) 
               log_error "无效输入，请重新输入"
               sleep 1
               ;;
        esac
    done
}

main
