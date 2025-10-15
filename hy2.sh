#!/bin/bash
#====================================================================================
# 项目：Hysteria2 & Shadowsocks Management Script
# 作者：Jensfrank
# 版本：v1.0
# GitHub: https://github.com/everett7623/hy2
# 博客: https://seedloc.com
# 论坛: https://nodeloc.com
#====================================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
VERSION="v1.0"
HY2_CONFIG_DIR="/etc/hysteria"
HY2_CONFIG_FILE="$HY2_CONFIG_DIR/config.yaml"
HY2_SERVICE="hysteria-server.service"
SS_CONFIG_DIR="/etc/shadowsocks"
SS_CONFIG_FILE="$SS_CONFIG_DIR/config.json"
SS_SERVICE="shadowsocks-rust.service"

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以 root 用户运行"
        exit 1
    fi
}

# 检测系统信息
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "无法检测操作系统"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            log_error "不支持的系统架构: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "检测到系统: $OS $OS_VERSION ($ARCH)"
}

# 检查内存
check_memory() {
    total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [[ $total_mem -lt 500 ]]; then
        log_warn "检测到系统内存较小 (${total_mem}MB)，已优化安装过程"
        LOW_MEM=true
    else
        LOW_MEM=false
    fi
}

# 安装依赖
install_dependencies() {
    log_info "正在安装必要的依赖..."
    
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y curl wget tar gzip jq openssl >/dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y curl wget tar gzip jq openssl >/dev/null 2>&1
            ;;
        *)
            log_error "不支持的操作系统: $OS"
            exit 1
            ;;
    esac
    
    if [[ $? -eq 0 ]]; then
        log_success "依赖安装完成"
    else
        log_error "依赖安装失败"
        exit 1
    fi
}

# 获取服务器IP
get_server_ip() {
    IPV4=$(curl -s4m8 ip.sb 2>/dev/null || echo "N/A")
    IPV6=$(curl -s6m8 ip.sb 2>/dev/null || echo "N/A")
}

# 检查IPv6连接性
check_ipv6() {
    if [[ "$IPV6" == "N/A" ]]; then
        log_warn "服务器不支持 IPv6 连接"
        return 1
    fi
    
    # 测试IPv6连接
    if curl -s6m5 --connect-timeout 5 http://ipv6.google.com >/dev/null 2>&1; then
        log_success "IPv6 连接正常"
        return 0
    else
        log_warn "IPv6 连接可能存在问题"
        return 1
    fi
}

# 检查服务状态
check_service_status() {
    local service=$1
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}运行中${NC}"
    elif systemctl is-enabled --quiet $service 2>/dev/null; then
        echo -e "${YELLOW}已安装(未运行)${NC}"
    else
        echo -e "${RED}未安装${NC}"
    fi
}

# 配置防火墙
configure_firewall() {
    local port=$1
    local protocol=${2:-tcp}
    
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        log_info "检测到 UFW 防火墙，正在配置..."
        ufw allow $port/$protocol comment "Proxy Service" >/dev/null 2>&1
        log_success "UFW 防火墙规则已添加"
    elif command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
        log_info "检测到 FirewallD，正在配置..."
        firewall-cmd --permanent --add-port=$port/$protocol >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        log_success "FirewallD 规则已添加"
    fi
}

# 生成随机密码
generate_password() {
    openssl rand -base64 16 | tr -d "=+/" | cut -c1-16
}

# 生成随机端口
generate_port() {
    shuf -i 10000-65000 -n 1
}

# 安装 Hysteria2
install_hysteria2() {
    echo -e "\n${CYAN}================================${NC}"
    echo -e "${CYAN}   安装 Hysteria2${NC}"
    echo -e "${CYAN}================================${NC}\n"
    
    if systemctl is-active --quiet $HY2_SERVICE; then
        log_warn "Hysteria2 已经安装并运行中"
        return
    fi
    
    log_info "开始安装 Hysteria2..."
    
    # 下载安装脚本
    log_info "正在下载 Hysteria2..."
    bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1
    
    if [[ $? -ne 0 ]]; then
        log_error "Hysteria2 安装失败"
        return 1
    fi
    
    # 创建配置目录
    mkdir -p $HY2_CONFIG_DIR
    
    # 生成证书
    log_info "正在生成自签名证书..."
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout $HY2_CONFIG_DIR/server.key \
        -out $HY2_CONFIG_DIR/server.crt \
        -subj "/CN=amd.com" -days 36500 >/dev/null 2>&1
    
    # 生成配置
    local PASSWORD=$(generate_password)
    local PORT=$(generate_port)
    
    cat > $HY2_CONFIG_FILE <<EOF
listen: :$PORT

tls:
  cert: $HY2_CONFIG_DIR/server.crt
  key: $HY2_CONFIG_DIR/server.key

auth:
  type: password
  password: $PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

bandwidth:
  up: 1 gbps
  down: 1 gbps

ignoreClientBandwidth: false
EOF
    
    # 配置防火墙
    configure_firewall $PORT udp
    
    # 启动服务
    systemctl enable hysteria-server.service >/dev/null 2>&1
    systemctl start hysteria-server.service
    
    if systemctl is-active --quiet $HY2_SERVICE; then
        log_success "Hysteria2 安装成功！"
        echo ""
        show_hysteria2_config
    else
        log_error "Hysteria2 启动失败"
        return 1
    fi
}

# 显示 Hysteria2 配置
show_hysteria2_config() {
    if [[ ! -f $HY2_CONFIG_FILE ]]; then
        log_error "Hysteria2 配置文件不存在"
        return 1
    fi
    
    local PASSWORD=$(grep "password:" $HY2_CONFIG_FILE | awk '{print $2}')
    local PORT=$(grep "listen:" $HY2_CONFIG_FILE | awk -F: '{print $NF}')
    local SERVER_IP=$IPV4
    [[ "$SERVER_IP" == "N/A" ]] && SERVER_IP=$IPV6
    
    local SHARE_LINK="hysteria2://${PASSWORD}@${SERVER_IP}:${PORT}/?insecure=true&sni=amd.com#🌟Hysteria2-$(date +%m%d)"
    
    echo -e "${CYAN}=== Hysteria2 配置信息 ===${NC}"
    echo -e "${GREEN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${YELLOW}${SHARE_LINK}${NC}"
    echo ""
    echo -e "${GREEN}⚔️ Clash Meta 配置:${NC}"
    echo -e "- { name: '🌟Hysteria2-$(date +%m%d)', type: hysteria2, server: ${SERVER_IP}, port: ${PORT}, password: ${PASSWORD}, sni: amd.com, skip-cert-verify: true, up: 50, down: 100 }"
    echo ""
    echo -e "${GREEN}🌊 Surge 配置:${NC}"
    echo -e "🌟Hysteria2-$(date +%m%d) = hysteria2, ${SERVER_IP}, ${PORT}, password=${PASSWORD}, sni=amd.com, skip-cert-verify=true"
    echo ""
}

# 安装 Shadowsocks
install_shadowsocks() {
    echo -e "\n${CYAN}================================${NC}"
    echo -e "${CYAN}   安装 Shadowsocks (IPv6)${NC}"
    echo -e "${CYAN}================================${NC}\n"
    
    # 检查IPv4
    if [[ "$IPV6" == "N/A" ]]; then
        log_error "此服务器不支持 IPv6，无法安装 Shadowsocks (IPv6 Only)"
        log_warn "提示: Shadowsocks IPv4 容易被封禁，建议使用支持 IPv6 的服务器"
        echo -e "\n按任意键返回主菜单..."
        read -n 1
        return 1
    fi
    
    if systemctl is-active --quiet $SS_SERVICE; then
        log_warn "Shadowsocks 已经安装并运行中"
        return
    fi
    
    log_info "开始安装 Shadowsocks..."
    
    # 获取最新版本
    local LATEST_VERSION=$(curl -s https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | jq -r .tag_name | sed 's/v//')
    
    if [[ -z "$LATEST_VERSION" ]]; then
        log_error "无法获取 Shadowsocks 最新版本"
        return 1
    fi
    
    log_info "正在下载 Shadowsocks v${LATEST_VERSION}..."
    
    local DOWNLOAD_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${LATEST_VERSION}/shadowsocks-v${LATEST_VERSION}.x86_64-unknown-linux-gnu.tar.xz"
    
    # 下载并解压
    cd /tmp
    wget -q --show-progress "$DOWNLOAD_URL" -O shadowsocks.tar.xz
    
    if [[ $? -ne 0 ]]; then
        log_error "下载失败"
        return 1
    fi
    
    tar -xf shadowsocks.tar.xz
    mv ssserver /usr/local/bin/
    chmod +x /usr/local/bin/ssserver
    rm -f shadowsocks.tar.xz
    
    # 创建配置目录
    mkdir -p $SS_CONFIG_DIR
    
    # 生成配置
    local PASSWORD=$(generate_password)
    local PORT=$(generate_port)
    
    cat > $SS_CONFIG_FILE <<EOF
{
    "server": "::",
    "server_port": $PORT,
    "password": "$PASSWORD",
    "timeout": 300,
    "method": "chacha20-ietf-poly1305",
    "mode": "tcp_and_udp",
    "fast_open": true
}
EOF
    
    # 创建 systemd 服务
    cat > /etc/systemd/system/$SS_SERVICE <<EOF
[Unit]
Description=Shadowsocks-Rust Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c $SS_CONFIG_FILE
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # 配置防火墙
    configure_firewall $PORT tcp
    configure_firewall $PORT udp
    
    # 启动服务
    systemctl daemon-reload
    systemctl enable $SS_SERVICE >/dev/null 2>&1
    systemctl start $SS_SERVICE
    
    if systemctl is-active --quiet $SS_SERVICE; then
        log_success "Shadowsocks 安装成功！"
        echo ""
        show_shadowsocks_config
    else
        log_error "Shadowsocks 启动失败"
        return 1
    fi
}

# 显示 Shadowsocks 配置
show_shadowsocks_config() {
    if [[ ! -f $SS_CONFIG_FILE ]]; then
        log_error "Shadowsocks 配置文件不存在"
        return 1
    fi
    
    local PASSWORD=$(jq -r .password $SS_CONFIG_FILE)
    local PORT=$(jq -r .server_port $SS_CONFIG_FILE)
    local METHOD=$(jq -r .method $SS_CONFIG_FILE)
    
    # 生成分享链接
    local USER_INFO="${METHOD}:${PASSWORD}"
    local ENCODED=$(echo -n "$USER_INFO" | base64 -w 0)
    local SHARE_LINK="ss://${ENCODED}@[${IPV6}]:${PORT}#🌟SS-IPv6-$(date +%m%d)"
    
    echo -e "${CYAN}=== Shadowsocks 配置信息 ===${NC}"
    echo -e "${GREEN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${YELLOW}${SHARE_LINK}${NC}"
    echo ""
    echo -e "${GREEN}⚔️ Clash Meta 配置:${NC}"
    echo -e "- { name: '🌟SS-IPv6-$(date +%m%d)', type: ss, server: '${IPV6}', port: ${PORT}, cipher: '${METHOD}', password: '${PASSWORD}', udp: true }"
    echo ""
}

# 服务管理菜单
service_management() {
    while true; do
        clear
        echo -e "${CYAN}================================${NC}"
        echo -e "${CYAN}      服务管理${NC}"
        echo -e "${CYAN}================================${NC}"
        echo ""
        echo " 1. 启动 Hysteria2"
        echo " 2. 停止 Hysteria2"
        echo " 3. 重启 Hysteria2"
        echo " 4. 查看 Hysteria2 状态"
        echo " 5. 查看 Hysteria2 配置"
        echo ""
        echo " 6. 启动 Shadowsocks"
        echo " 7. 停止 Shadowsocks"
        echo " 8. 重启 Shadowsocks"
        echo " 9. 查看 Shadowsocks 状态"
        echo " 10. 查看 Shadowsocks 配置"
        echo ""
        echo " 0. 返回主菜单"
        echo -e "${CYAN}================================${NC}"
        echo -n "请选择操作 [0-10]: "
        read choice
        
        case $choice in
            1) systemctl start $HY2_SERVICE && log_success "Hysteria2 已启动" ;;
            2) systemctl stop $HY2_SERVICE && log_success "Hysteria2 已停止" ;;
            3) systemctl restart $HY2_SERVICE && log_success "Hysteria2 已重启" ;;
            4) systemctl status $HY2_SERVICE ;;
            5) show_hysteria2_config ;;
            6) systemctl start $SS_SERVICE && log_success "Shadowsocks 已启动" ;;
            7) systemctl stop $SS_SERVICE && log_success "Shadowsocks 已停止" ;;
            8) systemctl restart $SS_SERVICE && log_success "Shadowsocks 已重启" ;;
            9) systemctl status $SS_SERVICE ;;
            10) show_shadowsocks_config ;;
            0) break ;;
            *) log_error "无效选项" ;;
        esac
        
        [[ $choice != 0 ]] && { echo ""; read -p "按回车键继续..."; }
    done
}

# 卸载服务菜单
uninstall_menu() {
    while true; do
        clear
        echo -e "${CYAN}================================${NC}"
        echo -e "${CYAN}      卸载服务${NC}"
        echo -e "${CYAN}================================${NC}"
        echo ""
        echo " 1. 卸载 Hysteria2"
        echo " 2. 卸载 Shadowsocks"
        echo " 3. 卸载所有服务"
        echo ""
        echo " 0. 返回主菜单"
        echo -e "${CYAN}================================${NC}"
        echo -n "请选择操作 [0-3]: "
        read choice
        
        case $choice in
            1) uninstall_hysteria2 ;;
            2) uninstall_shadowsocks ;;
            3) 
                uninstall_hysteria2
                uninstall_shadowsocks
                log_success "所有服务已卸载"
                ;;
            0) break ;;
            *) log_error "无效选项" ;;
        esac
        
        [[ $choice != 0 ]] && { echo ""; read -p "按回车键继续..."; }
    done
}

# 卸载 Hysteria2
uninstall_hysteria2() {
    log_info "正在卸载 Hysteria2..."
    systemctl stop $HY2_SERVICE 2>/dev/null
    systemctl disable $HY2_SERVICE 2>/dev/null
    rm -rf $HY2_CONFIG_DIR
    rm -f /etc/systemd/system/$HY2_SERVICE
    bash <(curl -fsSL https://get.hy2.sh/) --remove >/dev/null 2>&1
    systemctl daemon-reload
    log_success "Hysteria2 已卸载"
}

# 卸载 Shadowsocks
uninstall_shadowsocks() {
    log_info "正在卸载 Shadowsocks..."
    systemctl stop $SS_SERVICE 2>/dev/null
    systemctl disable $SS_SERVICE 2>/dev/null
    rm -rf $SS_CONFIG_DIR
    rm -f /etc/systemd/system/$SS_SERVICE
    rm -f /usr/local/bin/ssserver
    systemctl daemon-reload
    log_success "Shadowsocks 已卸载"
}

# 更新服务菜单
update_menu() {
    while true; do
        clear
        echo -e "${CYAN}================================${NC}"
        echo -e "${CYAN}      更新服务${NC}"
        echo -e "${CYAN}================================${NC}"
        echo ""
        echo " 1. 更新 Hysteria2"
        echo " 2. 更新 Shadowsocks"
        echo " 3. 更新系统内核"
        echo ""
        echo " 0. 返回主菜单"
        echo -e "${CYAN}================================${NC}"
        echo -n "请选择操作 [0-3]: "
        read choice
        
        case $choice in
            1) update_hysteria2 ;;
            2) update_shadowsocks ;;
            3) update_kernel ;;
            0) break ;;
            *) log_error "无效选项" ;;
        esac
        
        [[ $choice != 0 ]] && { echo ""; read -p "按回车键继续..."; }
    done
}

# 更新 Hysteria2
update_hysteria2() {
    log_info "正在更新 Hysteria2..."
    bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1
    systemctl restart $HY2_SERVICE
    log_success "Hysteria2 更新完成"
}

# 更新 Shadowsocks
update_shadowsocks() {
    log_info "正在更新 Shadowsocks..."
    uninstall_shadowsocks
    install_shadowsocks
}

# 更新系统内核
update_kernel() {
    log_warn "更新系统内核可能需要重启服务器"
    read -p "是否继续? (y/n): " confirm
    if [[ $confirm == "y" ]]; then
        case $OS in
            ubuntu|debian)
                apt-get update && apt-get upgrade -y
                ;;
            centos|rhel|fedora)
                yum update -y
                ;;
        esac
        log_success "系统更新完成，建议重启服务器"
    fi
}

# 系统优化
system_optimization() {
    log_info "正在优化系统参数..."
    
    cat >> /etc/sysctl.conf <<EOF
# 网络优化
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
net.core.netdev_max_backlog=250000
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_slow_start_after_idle=0
EOF
    
    sysctl -p >/dev/null 2>&1
    log_success "系统优化完成"
    
    echo ""
    read -p "按回车键继续..."
}

# 主菜单
main_menu() {
    while true; do
        clear
        get_server_ip
        
        echo -e "${CYAN}================================${NC}"
        echo -e "${CYAN}Hysteria2 & Shadowsocks Management Script ($VERSION)${NC}"
        echo -e "${CYAN}================================${NC}"
        echo -e "项目地址: ${BLUE}https://github.com/everett7623/hy2${NC}"
        echo -e "博客地址: ${BLUE}https://seedloc.com${NC}"
        echo -e "论坛地址: ${BLUE}https://nodeloc.com${NC}"
        echo -e "${CYAN}================================${NC}"
        echo -e "服务器 IPv4: ${GREEN}$IPV4${NC}"
        echo -e "服务器 IPv6: ${GREEN}$IPV6${NC}"
        echo ""
        echo -e "Hysteria2 状态: $(check_service_status $HY2_SERVICE)"
        echo -e "Shadowsocks 状态: $(check_service_status $SS_SERVICE)"
        echo -e "${CYAN}================================${NC}"
        echo ""
        echo " 1. 安装 Hysteria2 (自签模式，无需域名解析)"
        echo " 2. 安装 Shadowsocks (仅 IPv6)"
        echo " 3. 服务管理"
        echo " 4. 卸载服务"
        echo " 5. 更新服务"
        echo " 6. 系统优化"
        echo ""
        echo " 0. 退出脚本"
        echo -e "${CYAN}================================${NC}"
        echo -n "请选择操作 [0-6]: "
        read choice
        
        case $choice in
            1) install_hysteria2 ;;
            2) install_shadowsocks ;;
            3) service_management ;;
            4) uninstall_menu ;;
            5) update_menu ;;
            6) system_optimization ;;
            0) 
                log_info "感谢使用，再见！"
                exit 0
                ;;
            *)
                log_error "无效选项，请重新选择"
                ;;
        esac
        
        [[ $choice != 0 ]] && { echo ""; read -p "按回车键继续..."; }
    done
}

# 主程序入口
main() {
    check_root
    detect_system
    check_memory
    install_dependencies
    main_menu
}

# 执行主程序
main
