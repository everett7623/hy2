#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks (IPv6) Management Script
# 作者：Jensfrank
# 版本：v2.0
# GitHub: https://github.com/everett7623/hy2ipv6
# 博客: https://seedloc.com
# 论坛: https://nodeloc.com
#====================================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 配置文件路径
HYSTERIA2_CONFIG_FILE="/etc/hysteria2/config.yaml"
SHADOWSOCKS_CONFIG_FILE="/etc/shadowsocks-rust/config.json"
SHADOWSOCKS_IPV4_CONFIG_FILE="/etc/shadowsocks-rust/config-ipv4.json"

# 打印消息函数
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# 检测系统信息
detect_system() {
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
        PM="yum"
    elif cat /etc/issue | grep -Eqi "debian"; then
        OS="debian"
        PM="apt"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        OS="ubuntu"
        PM="apt"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        OS="centos"
        PM="yum"
    elif cat /proc/version | grep -Eqi "debian"; then
        OS="debian"
        PM="apt"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        OS="ubuntu"
        PM="apt"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        OS="centos"
        PM="yum"
    else
        print_message $RED "不支持的操作系统"
        exit 1
    fi
}

# 检查IPv6支持
check_ipv6() {
    if ip -6 addr show | grep -q "inet6.*global"; then
        IPV6_AVAILABLE=true
        SERVER_IPV6=$(ip -6 addr show | grep "inet6.*global" | awk '{print $2}' | cut -d'/' -f1 | head -1)
    else
        IPV6_AVAILABLE=false
        SERVER_IPV6=""
    fi
    
    SERVER_IPV4=$(curl -s4 ifconfig.me 2>/dev/null || echo "N/A")
}

# 安装依赖
install_dependencies() {
    print_message $BLUE "正在安装依赖包..."
    
    if [[ $PM == "apt" ]]; then
        apt update
        apt install -y curl wget unzip jq
    elif [[ $PM == "yum" ]]; then
        yum update -y
        yum install -y curl wget unzip jq
    fi
}

# 生成随机密码
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-16
}

# 生成随机端口
generate_port() {
    shuf -i 10000-65000 -n 1
}

# 安装Hysteria2
install_hysteria2() {
    print_message $CYAN "开始安装 Hysteria2..."
    
    # 下载并安装
    bash <(curl -fsSL https://get.hy2.sh/)
    
    # 生成配置
    local port=$(generate_port)
    local password=$(generate_password)
    local sni_domain="www.bing.com"
    
    # 创建配置文件
    cat > "$HYSTERIA2_CONFIG_FILE" << EOF
listen: :$port

tls:
  cert: /etc/hysteria2/server.crt
  key: /etc/hysteria2/server.key

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true

bandwidth:
  up: 1 gbps
  down: 1 gbps
EOF

    # 生成自签名证书
    openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/hysteria2/server.key -out /etc/hysteria2/server.crt -days 3650 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=$sni_domain"
    
    # 启动服务
    systemctl enable hysteria2
    systemctl start hysteria2
    
    if systemctl is-active --quiet hysteria2; then
        print_message $GREEN "Hysteria2 安装成功！"
        show_hysteria2_config "$port" "$password" "$sni_domain"
    else
        print_message $RED "Hysteria2 安装失败！"
        return 1
    fi
}

# 显示Hysteria2配置信息
show_hysteria2_config() {
    local port=$1
    local password=$2
    local sni_domain=$3
    local server_ip=${SERVER_IPV6:-$SERVER_IPV4}
    
    print_message $CYAN "
================================================
Hysteria2 配置信息
================================================"
    
    echo -e "${YELLOW}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${WHITE}hysteria2://${password}@${server_ip}:${port}/?insecure=true&sni=${sni_domain}#🌟Hysteria2-$(date +%m%d)${NC}"
    echo
    
    echo -e "${YELLOW}⚔️ Clash Meta 配置:${NC}"
    echo -e "${WHITE}- { name: '🌟Hysteria2-$(date +%m%d)', type: hysteria2, server: ${server_ip}, port: ${port}, password: ${password}, sni: ${sni_domain}, skip-cert-verify: true, up: 50, down: 100 }${NC}"
    echo
    
    echo -e "${YELLOW}🌊 Surge 配置:${NC}"
    echo -e "${WHITE}🌟Hysteria2-$(date +%m%d) = hysteria2, ${server_ip}, ${port}, password=${password}, sni=${sni_domain}, skip-cert-verify=true${NC}"
    echo
    
    echo -e "${CYAN}💡 连接建议:${NC}"
    echo -e "${WHITE}• 推荐使用 V2rayN 4.0+ 或 NekoBox 客户端${NC}"
    echo -e "${WHITE}• 如遇连接问题，请检查防火墙设置${NC}"
    echo -e "${WHITE}• 建议启用客户端的自动重连功能${NC}"
    echo
}

# 安装Shadowsocks
install_shadowsocks() {
    # 检查IPv6支持
    if ! $IPV6_AVAILABLE; then
        print_message $RED "错误：Shadowsocks 只支持 IPv6 only 或双栈 IPv6 的 VPS"
        print_message $YELLOW "当前服务器不支持 IPv6，建议使用 Hysteria2"
        return 1
    fi
    
    print_message $CYAN "开始安装 Shadowsocks (IPv6优先)..."
    
    # 安装shadowsocks-rust
    if [[ $PM == "apt" ]]; then
        apt update
        apt install -y shadowsocks-rust
    elif [[ $PM == "yum" ]]; then
        yum install -y epel-release
        yum install -y shadowsocks-rust
    fi
    
    # 如果包管理器没有，则手动安装
    if ! command -v ssserver &> /dev/null; then
        print_message $BLUE "通过二进制文件安装 shadowsocks-rust..."
        wget -O /tmp/shadowsocks-rust.tar.xz "https://github.com/shadowsocks/shadowsocks-rust/releases/latest/download/shadowsocks-v1.15.3.x86_64-unknown-linux-gnu.tar.xz"
        tar -xf /tmp/shadowsocks-rust.tar.xz -C /tmp/
        cp /tmp/ssserver /usr/local/bin/
        chmod +x /usr/local/bin/ssserver
    fi
    
    # 生成配置
    local port=$(generate_port)
    local password=$(generate_password)
    local method="chacha20-ietf-poly1305"
    
    # 创建配置目录
    mkdir -p /etc/shadowsocks-rust
    
    # 创建IPv6主配置文件
    cat > "$SHADOWSOCKS_CONFIG_FILE" << EOF
{
    "server": "::",
    "server_port": $port,
    "password": "$password",
    "method": "$method",
    "timeout": 60,
    "fast_open": true,
    "reuse_port": true,
    "no_delay": true,
    "mode": "tcp_and_udp"
}
EOF

    # 如果是双栈环境，创建IPv4备用配置
    if [[ -n "$SERVER_IPV4" && "$SERVER_IPV4" != "N/A" ]]; then
        local ipv4_port=$((port + 1000))
        cat > "$SHADOWSOCKS_IPV4_CONFIG_FILE" << EOF
{
    "server": "0.0.0.0",
    "server_port": $ipv4_port,
    "password": "$password",
    "method": "$method",
    "timeout": 60,
    "fast_open": true,
    "reuse_port": true,
    "no_delay": true,
    "mode": "tcp_and_udp"
}
EOF
        print_message $BLUE "已创建IPv4备用配置，端口: $ipv4_port"
    fi

    # 创建systemd服务文件
    cat > /etc/systemd/system/shadowsocks-rust.service << EOF
[Unit]
Description=Shadowsocks-Rust Server (IPv6)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c $SHADOWSOCKS_CONFIG_FILE
Restart=always
RestartSec=3
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    # 如果有IPv4备用配置，创建备用服务
    if [[ -f "$SHADOWSOCKS_IPV4_CONFIG_FILE" ]]; then
        cat > /etc/systemd/system/shadowsocks-rust-ipv4-backup.service << EOF
[Unit]
Description=Shadowsocks-Rust Server (IPv4 Backup)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c $SHADOWSOCKS_IPV4_CONFIG_FILE
Restart=always
RestartSec=3
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    fi

    # 重载systemd并启动服务
    systemctl daemon-reload
    systemctl enable shadowsocks-rust
    systemctl start shadowsocks-rust
    
    if [[ -f "$SHADOWSOCKS_IPV4_CONFIG_FILE" ]]; then
        systemctl enable shadowsocks-rust-ipv4-backup
        systemctl start shadowsocks-rust-ipv4-backup
    fi
    
    # 检查服务状态
    if systemctl is-active --quiet shadowsocks-rust; then
        print_message $GREEN "Shadowsocks 安装成功！"
        show_shadowsocks_config "$port" "$password" "$method"
        
        # 运行诊断
        diagnose_shadowsocks
    else
        print_message $RED "Shadowsocks 安装失败！"
        return 1
    fi
}

# 显示Shadowsocks配置信息 - 参考Hysteria2的三种导出格式
show_shadowsocks_config() {
    local port=$1
    local password=$2
    local method=$3
    
    print_message $CYAN "
================================================
Shadowsocks 配置信息 (IPv6 优先)
================================================"
    
    # IPv6 配置 (主要配置)
    if $IPV6_AVAILABLE && [[ -n "$SERVER_IPV6" ]]; then
        echo -e "${YELLOW}🚀 V2rayN / NekoBox / Shadowrocket 分享链接 (IPv6 推荐):${NC}"
        local ss_link_ipv6=$(echo -n "${method}:${password}@[${SERVER_IPV6}]:${port}" | base64 -w 0)
        echo -e "${WHITE}ss://${ss_link_ipv6}#🌟SS-IPv6-$(date +%m%d)${NC}"
        echo
        
        echo -e "${YELLOW}⚔️ Clash Meta 配置 (IPv6):${NC}"
        echo -e "${WHITE}- { name: '🌟SS-IPv6-$(date +%m%d)', type: ss, server: ${SERVER_IPV6}, port: ${port}, cipher: ${method}, password: ${password}, udp: true }${NC}"
        echo
        
        echo -e "${YELLOW}🌊 Surge 配置 (IPv6):${NC}"
        echo -e "${WHITE}🌟SS-IPv6-$(date +%m%d) = ss, ${SERVER_IPV6}, ${port}, encrypt-method=${method}, password=${password}, udp-relay=true${NC}"
        echo
    fi
    
    # IPv4 配置 (备用配置，仅双栈环境)
    if [[ -n "$SERVER_IPV4" && "$SERVER_IPV4" != "N/A" ]]; then
        local ipv4_port=$((port + 1000))
        echo -e "${YELLOW}🚀 V2rayN / NekoBox / Shadowrocket 分享链接 (IPv4 备用):${NC}"
        local ss_link_ipv4=$(echo -n "${method}:${password}@${SERVER_IPV4}:${ipv4_port}" | base64 -w 0)
        echo -e "${WHITE}ss://${ss_link_ipv4}#🌟SS-IPv4-$(date +%m%d)${NC}"
        echo
        
        echo -e "${YELLOW}⚔️ Clash Meta 配置 (IPv4 备用):${NC}"
        echo -e "${WHITE}- { name: '🌟SS-IPv4-$(date +%m%d)', type: ss, server: ${SERVER_IPV4}, port: ${ipv4_port}, cipher: ${method}, password: ${password}, udp: true }${NC}"
        echo
        
        echo -e "${YELLOW}🌊 Surge 配置 (IPv4 备用):${NC}"
        echo -e "${WHITE}🌟SS-IPv4-$(date +%m%d) = ss, ${SERVER_IPV4}, ${ipv4_port}, encrypt-method=${method}, password=${password}, udp-relay=true${NC}"
        echo
    fi
    
    echo -e "${CYAN}💡 使用说明:${NC}"
    echo -e "${WHITE}• Shadowsocks 专为 IPv6 环境优化，抗封锁能力更强${NC}"
    echo -e "${WHITE}• 优先使用 IPv6 配置，性能更佳${NC}"
    echo -e "${WHITE}• 双栈环境提供 IPv4 备用配置${NC}"
    echo -e "${WHITE}• 如遇连接问题，请检查客户端 IPv6 支持${NC}"
    echo -e "${WHITE}• 建议客户端启用 UDP 转发以获得更好性能${NC}"
    echo
}

# 诊断Shadowsocks连接问题
diagnose_shadowsocks() {
    print_message $CYAN "正在诊断 Shadowsocks 连接..."
    
    # 检查服务状态
    echo -e "${BLUE}1. 服务状态检查:${NC}"
    if systemctl is-active --quiet shadowsocks-rust; then
        echo -e "${GREEN}  ✓ IPv6 主服务运行正常${NC}"
    else
        echo -e "${RED}  ✗ IPv6 主服务未运行${NC}"
    fi
    
    if systemctl is-active --quiet shadowsocks-rust-ipv4-backup 2>/dev/null; then
        echo -e "${GREEN}  ✓ IPv4 备用服务运行正常${NC}"
    else
        echo -e "${YELLOW}  - IPv4 备用服务未配置或未运行${NC}"
    fi
    
    # 检查端口监听
    echo -e "${BLUE}2. 端口监听检查:${NC}"
    local port=$(grep server_port "$SHADOWSOCKS_CONFIG_FILE" | cut -d':' -f2 | tr -d ' ",')
    if ss -tuln | grep -q ":$port "; then
        echo -e "${GREEN}  ✓ 端口 $port 正在监听${NC}"
    else
        echo -e "${RED}  ✗ 端口 $port 未监听${NC}"
    fi
    
    # 检查防火墙
    echo -e "${BLUE}3. 防火墙检查:${NC}"
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            echo -e "${YELLOW}  ! UFW 防火墙已启用，请确保端口已开放${NC}"
        else
            echo -e "${GREEN}  ✓ UFW 防火墙未启用${NC}"
        fi
    elif command -v firewall-cmd &> /dev/null; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            echo -e "${YELLOW}  ! Firewalld 已启用，请确保端口已开放${NC}"
        else
            echo -e "${GREEN}  ✓ Firewalld 未启用${NC}"
        fi
    else
        echo -e "${GREEN}  ✓ 未检测到常见防火墙${NC}"
    fi
    
    # 检查网络连通性
    echo -e "${BLUE}4. 网络连通性检查:${NC}"
    if $IPV6_AVAILABLE; then
        echo -e "${GREEN}  ✓ IPv6 网络可用${NC}"
    else
        echo -e "${RED}  ✗ IPv6 网络不可用${NC}"
    fi
    
    if [[ -n "$SERVER_IPV4" && "$SERVER_IPV4" != "N/A" ]]; then
        echo -e "${GREEN}  ✓ IPv4 网络可用${NC}"
    else
        echo -e "${YELLOW}  - IPv4 网络不可用${NC}"
    fi
    
    echo
}

# 管理Hysteria2
manage_hysteria2() {
    while true; do
        clear
        print_message $CYAN "
=== Hysteria2 管理 ==="
        echo -e " 1. 启动服务"
        echo -e " 2. 停止服务"
        echo -e " 3. 重启服务"
        echo -e " 4. 查看状态"
        echo -e " 5. 查看日志"
        echo -e " 6. 显示配置"
        echo -e " 0. 返回上级菜单"
        echo
        
        read -p "请选择操作 [0-6]: " choice
        
        case $choice in
            1)
                systemctl start hysteria2
                print_message $GREEN "Hysteria2 服务已启动"
                ;;
            2)
                systemctl stop hysteria2
                print_message $YELLOW "Hysteria2 服务已停止"
                ;;
            3)
                systemctl restart hysteria2
                print_message $GREEN "Hysteria2 服务已重启"
                ;;
            4)
                systemctl status hysteria2
                ;;
            5)
                journalctl -u hysteria2 --no-pager -n 20
                ;;
            6)
                if [[ -f "$HYSTERIA2_CONFIG_FILE" ]]; then
                    local port=$(grep "listen:" "$HYSTERIA2_CONFIG_FILE" | cut -d':' -f3)
                    local password=$(grep "password:" "$HYSTERIA2_CONFIG_FILE" | awk '{print $2}')
                    local sni_domain="www.bing.com"
                    show_hysteria2_config "$port" "$password" "$sni_domain"
                else
                    print_message $RED "配置文件不存在"
                fi
                ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac
        
        if [[ $choice != 6 ]]; then
            read -p "按回车键继续..."
        fi
    done
}

# 管理Shadowsocks
manage_shadowsocks() {
    while true; do
        clear
        print_message $CYAN "
=== Shadowsocks 管理 ==="
        echo -e " 1. 启动服务"
        echo -e " 2. 停止服务"
        echo -e " 3. 重启服务"
        echo -e " 4. 查看状态"
        echo -e " 5. 查看日志"
        echo -e " 6. 显示配置"
        echo -e " 7. 诊断连接"
        echo -e " 0. 返回上级菜单"
        echo
        
        read -p "请选择操作 [0-7]: " choice
        
        case $choice in
            1)
                systemctl start shadowsocks-rust
                if [[ -f "$SHADOWSOCKS_IPV4_CONFIG_FILE" ]]; then
                    systemctl start shadowsocks-rust-ipv4-backup
                fi
                print_message $GREEN "Shadowsocks 服务已启动"
                ;;
            2)
                systemctl stop shadowsocks-rust
                if [[ -f "$SHADOWSOCKS_IPV4_CONFIG_FILE" ]]; then
                    systemctl stop shadowsocks-rust-ipv4-backup
                fi
                print_message $YELLOW "Shadowsocks 服务已停止"
                ;;
            3)
                systemctl restart shadowsocks-rust
                if [[ -f "$SHADOWSOCKS_IPV4_CONFIG_FILE" ]]; then
                    systemctl restart shadowsocks-rust-ipv4-backup
                fi
                print_message $GREEN "Shadowsocks 服务已重启"
                ;;
            4)
                echo -e "${BLUE}IPv6 主服务状态:${NC}"
                systemctl status shadowsocks-rust
                if [[ -f "$SHADOWSOCKS_IPV4_CONFIG_FILE" ]]; then
                    echo -e "${BLUE}IPv4 备用服务状态:${NC}"
                    systemctl status shadowsocks-rust-ipv4-backup
                fi
                ;;
            5)
                echo -e "${BLUE}IPv6 主服务日志:${NC}"
                journalctl -u shadowsocks-rust --no-pager -n 10
                if [[ -f "$SHADOWSOCKS_IPV4_CONFIG_FILE" ]]; then
                    echo -e "${BLUE}IPv4 备用服务日志:${NC}"
                    journalctl -u shadowsocks-rust-ipv4-backup --no-pager -n 10
                fi
                ;;
            6)
                if [[ -f "$SHADOWSOCKS_CONFIG_FILE" ]]; then
                    local port=$(grep server_port "$SHADOWSOCKS_CONFIG_FILE" | cut -d':' -f2 | tr -d ' ",')
                    local password=$(grep password "$SHADOWSOCKS_CONFIG_FILE" | cut -d'"' -f4)
                    local method=$(grep method "$SHADOWSOCKS_CONFIG_FILE" | cut -d'"' -f4)
                    show_shadowsocks_config "$port" "$password" "$method"
                else
                    print_message $RED "配置文件不存在"
                fi
                ;;
            7)
                diagnose_shadowsocks
                ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac
        
        if [[ $choice != 6 && $choice != 7 ]]; then
            read -p "按回车键继续..."
        fi
    done
}

# 服务管理菜单
service_management() {
    while true; do
        clear
        print_message $CYAN "
=== 服务管理 ==="
        echo -e " 1. 管理 Hysteria2"
        echo -e " 2. 管理 Shadowsocks"
        echo -e " 0. 返回主菜单"
        echo
        
        read -p "请选择操作 [0-2]: " choice
        
        case $choice in
            1) manage_hysteria2 ;;
            2) manage_shadowsocks ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac
    done
}

# 卸载Hysteria2
uninstall_hysteria2() {
    print_message $YELLOW "正在卸载 Hysteria2..."
    
    # 停止并禁用服务
    systemctl stop hysteria2 2>/dev/null
    systemctl disable hysteria2 2>/dev/null
    
    # 删除文件
    rm -rf /etc/hysteria2/
    rm -f /etc/systemd/system/hysteria2.service
    rm -f /usr/local/bin/hysteria
    
    # 重载systemd
    systemctl daemon-reload
    
    print_message $GREEN "Hysteria2 已成功卸载"
}

# 卸载Shadowsocks
uninstall_shadowsocks() {
    print_message $YELLOW "正在卸载 Shadowsocks..."
    
    # 停止并禁用服务
    systemctl stop shadowsocks-rust 2>/dev/null
    systemctl disable shadowsocks-rust 2>/dev/null
    systemctl stop shadowsocks-rust-ipv4-backup 2>/dev/null
    systemctl disable shadowsocks-rust-ipv4-backup 2>/dev/null
    
    # 删除文件
    rm -rf /etc/shadowsocks-rust/
    rm -f /etc/systemd/system/shadowsocks-rust.service
    rm -f /etc/systemd/system/shadowsocks-rust-ipv4-backup.service
    rm -f /usr/local/bin/ssserver
    
    # 重载systemd
    systemctl daemon-reload
    
    print_message $GREEN "Shadowsocks 已成功卸载"
}

# 卸载服务菜单
uninstall_services() {
    while true; do
        clear
        print_message $CYAN "
=== 卸载服务 ==="
        echo -e " 1. 卸载 Hysteria2"
        echo -e " 2. 卸载 Shadowsocks"
        echo -e " 3. 卸载所有服务"
        echo -e " 0. 返回主菜单"
        echo
        
        read -p "请选择操作 [0-3]: " choice
        
        case $choice in
            1) 
                read -p "确认卸载 Hysteria2？(y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    uninstall_hysteria2
                fi
                ;;
            2) 
                read -p "确认卸载 Shadowsocks？(y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    uninstall_shadowsocks
                fi
                ;;
            3) 
                read -p "确认卸载所有服务？(y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    uninstall_hysteria2
                    uninstall_shadowsocks
                fi
                ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac
        
        if [[ $choice != 0 ]]; then
            read -p "按回车键继续..."
        fi
    done
}

# 主菜单
main_menu() {
    while true; do
        clear
        print_message $CYAN "
================================================
    Hysteria2 & Shadowsocks 管理脚本 v2.0
================================================"
        
        echo -e " 1. 安装 Hysteria2(自签名证书模式，无需域名解析)"
        echo -e " 2. 安装 Shadowsocks (IPv6 only/双栈IPv6优先)"
        echo -e " 3. 服务管理"
        echo -e " 4. 卸载服务"
        echo -e " 5. 系统信息"
        echo -e " 0. 退出脚本"
        echo
        
        read -p "请选择操作 [0-5]: " choice
        
        case $choice in
            1) install_hysteria2 ;;
            2) install_shadowsocks ;;
            3) service_management ;;
            4) uninstall_services ;;
            5) 
                print_message $CYAN "系统信息:"
                echo -e "${WHITE}操作系统: $OS${NC}"
                echo -e "${WHITE}包管理器: $PM${NC}"
                echo -e "${WHITE}IPv4 地址: $SERVER_IPV4${NC}"
                echo -e "${WHITE}IPv6 地址: $SERVER_IPV6${NC}"
                echo -e "${WHITE}IPv6 支持: $IPV6_AVAILABLE${NC}"
                ;;
            0) 
                print_message $GREEN "感谢使用，再见！"
                exit 0
                ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac
        
        if [[ $choice != 3 && $choice != 4 && $choice != 5 && $choice != 0 ]]; then
            read -p "按回车键继续..."
        fi
    done
}

# 主函数
main() {
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        print_message $RED "此脚本需要root权限运行"
        exit 1
    fi
    
    # 初始化
    detect_system
    check_ipv6
    install_dependencies
    
    # 显示主菜单
    main_menu
}

# 运行主函数
main "$@"
