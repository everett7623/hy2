#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks (IPv6) Management Script
# 作者：Jensfrank
# 版本：v1.0
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

# 全局变量
SCRIPT_VERSION="v1.0"
HYSTERIA2_CONFIG_FILE="/etc/hysteria2/config.yaml"
SHADOWSOCKS_CONFIG_FILE="/etc/shadowsocks-libev/config.json"
LOG_FILE="/var/log/hy2ipv6.log"

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# 打印带颜色的消息
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
    log "$message"
}

# 显示进度条
show_progress() {
    local duration=$1
    local message=$2
    echo -ne "${BLUE}${message}${NC}"
    for ((i=0; i<=duration; i++)); do
        echo -ne "."
        sleep 0.1
    done
    echo -e " ${GREEN}完成${NC}"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_message $RED "错误：此脚本需要root权限运行"
        print_message $YELLOW "请使用 sudo 运行此脚本"
        exit 1
    fi
}

# 检测系统信息
detect_system() {
    print_message $BLUE "正在检测系统信息..."

    # 检测操作系统
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$NAME
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        OS_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
        OS_NAME="CentOS"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        OS_VERSION=$(cat /etc/debian_version)
        OS_NAME="Debian"
    else
        print_message $RED "无法检测操作系统"
        exit 1
    fi

    # 标准化操作系统名称
    case $OS in
        ubuntu|Ubuntu) OS="ubuntu" ;;
        debian|Debian) OS="debian" ;;
        centos|CentOS|"rhel"|"Red Hat"*) OS="centos" ;;
        fedora|Fedora) OS="fedora" ;;
        *)
            # 尝试从 NAME 字段识别
            case $OS_NAME in
                *Ubuntu*|*ubuntu*) OS="ubuntu" ;;
                *Debian*|*debian*) OS="debian" ;;
                *CentOS*|*centos*|*"Red Hat"*) OS="centos" ;;
                *Fedora*|*fedora*) OS="fedora" ;;
            esac
            ;;
    esac

    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *)
            print_message $YELLOW "检测到架构: $ARCH，将尝试使用 amd64 版本"
            ARCH="amd64"
            ;;
    esac

    print_message $GREEN "系统检测完成: $OS_NAME ($OS) $OS_VERSION, 架构: $ARCH"
}

# 版本比较函数
version_compare() {
    local version1=$1
    local operator=$2
    local version2=$3

    # 简单的版本比较，支持 x.y 格式
    local v1_major=$(echo $version1 | cut -d. -f1)
    local v1_minor=$(echo $version1 | cut -d. -f2 2>/dev/null || echo 0)
    local v2_major=$(echo $version2 | cut -d. -f1)
    local v2_minor=$(echo $version2 | cut -d. -f2 2>/dev/null || echo 0)

    # 转换为数字进行比较
    local v1_num=$((v1_major * 100 + v1_minor))
    local v2_num=$((v2_major * 100 + v2_minor))

    case $operator in
        "<") [[ $v1_num -lt $v2_num ]] ;;
        "<=") [[ $v1_num -le $v2_num ]] ;;
        ">") [[ $v1_num -gt $v2_num ]] ;;
        ">=") [[ $v1_num -ge $v2_num ]] ;;
        "="|"==") [[ $v1_num -eq $v2_num ]] ;;
        *) return 1 ;;
    esac
}

# 检查系统兼容性
check_system_compatibility() {
    print_message $BLUE "正在检查系统兼容性..."

    case $OS in
        ubuntu)
            if version_compare "$OS_VERSION" "<" "18.04"; then
                print_message $YELLOW "Ubuntu 版本较低 ($OS_VERSION)，建议使用 18.04 或更高版本"
                print_message $YELLOW "将尝试继续安装，但可能遇到兼容性问题"
            fi
            PACKAGE_MANAGER="apt"
            ;;
        debian)
            # Debian 版本号可能是 9.x 或 bookworm 等格式
            local debian_major=$(echo $OS_VERSION | grep -oE '^[0-9]+' || echo "0")
            if [[ $debian_major -lt 9 ]] && [[ "$OS_VERSION" != *"bookworm"* ]] && [[ "$OS_VERSION" != *"bullseye"* ]]; then
                print_message $YELLOW "Debian 版本较低 ($OS_VERSION)，建议使用 9 或更高版本"
                print_message $YELLOW "将尝试继续安装，但可能遇到兼容性问题"
            fi
            PACKAGE_MANAGER="apt"
            ;;
        centos|rhel)
            PACKAGE_MANAGER="yum"
            if command -v dnf >/dev/null 2>&1; then
                PACKAGE_MANAGER="dnf"
            fi
            ;;
        fedora)
            PACKAGE_MANAGER="dnf"
            ;;
        *)
            print_message $YELLOW "检测到未明确支持的操作系统: $OS ($OS_NAME)"
            print_message $YELLOW "将尝试使用通用配置继续安装"

            # 尝试确定包管理器
            if command -v apt >/dev/null 2>&1; then
                PACKAGE_MANAGER="apt"
                print_message $BLUE "检测到 APT 包管理器，将使用 Debian/Ubuntu 配置"
            elif command -v dnf >/dev/null 2>&1; then
                PACKAGE_MANAGER="dnf"
                print_message $BLUE "检测到 DNF 包管理器，将使用 Fedora 配置"
            elif command -v yum >/dev/null 2>&1; then
                PACKAGE_MANAGER="yum"
                print_message $BLUE "检测到 YUM 包管理器，将使用 CentOS/RHEL 配置"
            else
                print_message $RED "无法确定包管理器，安装可能失败"
                read -p "是否继续安装? (y/N): " continue_install
                if [[ ! $continue_install =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            fi
            ;;
    esac

    print_message $GREEN "系统兼容性检查完成: $OS_NAME $OS_VERSION ($ARCH)"
    print_message $BLUE "使用包管理器: $PACKAGE_MANAGER"
}

# 检查内存并创建swap
check_memory() {
    local mem_total=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    print_message $BLUE "检测到系统内存: ${mem_total}MB"

    if [[ $mem_total -lt 500 ]]; then
        print_message $YELLOW "检测到小内存VPS (${mem_total}MB < 500MB)"
        print_message $BLUE "建议创建swap以提高系统稳定性"
        read -p "是否创建1GB swap? (y/n): " create_swap
        if [[ $create_swap =~ ^[Yy]$ ]]; then
            create_swap_file
        fi
    fi
}

# 创建swap文件
create_swap_file() {
    if [[ -f /swapfile ]]; then
        print_message $YELLOW "Swap文件已存在"
        return
    fi

    print_message $BLUE "正在创建1GB swap文件..."
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576 >/dev/null 2>&1
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    print_message $GREEN "Swap创建完成"
}

# 检查IPv6连接性
check_ipv6() {
    print_message $BLUE "正在检查IPv6连接性..."

    if ip -6 addr show | grep -q "inet6.*global"; then
        IPV6_AVAILABLE=true
        SERVER_IPV6=$(ip -6 addr show scope global | grep "inet6" | awk '{print $2}' | cut -d'/' -f1 | head -n1)
        print_message $GREEN "IPv6可用: $SERVER_IPV6"
    else
        IPV6_AVAILABLE=false
        print_message $YELLOW "IPv6不可用"
    fi

    # 测试IPv6连通性
    if $IPV6_AVAILABLE; then
        if ping -6 -c 1 2001:4860:4860::8888 >/dev/null 2>&1; then
            print_message $GREEN "IPv6连通性测试通过"
        else
            print_message $YELLOW "IPv6连通性测试失败，可能影响服务正常运行"
        fi
    fi
}

# 检查IPv4连接性
check_ipv4() {
    print_message $BLUE "正在检查IPv4连接性..."

    SERVER_IPV4=$(curl -s -4 --max-time 10 ifconfig.me 2>/dev/null || echo "N/A")
    if [[ "$SERVER_IPV4" != "N/A" ]]; then
        print_message $GREEN "IPv4可用: $SERVER_IPV4"
    else
        print_message $YELLOW "IPv4不可用或检测失败"
    fi
}

# 安装依赖
install_dependencies() {
    print_message $BLUE "正在安装必要依赖..."

    case $PACKAGE_MANAGER in
        apt)
            apt update >/dev/null 2>&1
            apt install -y curl wget unzip tar xz-utils jq bc iproute2 lsof file netcat-openbsd qrencode >/dev/null 2>&1
            ;;
        yum|dnf)
            $PACKAGE_MANAGER update -y >/dev/null 2>&1
            $PACKAGE_MANAGER install -y curl wget unzip tar xz jq bc iproute lsof file nc qrencode >/dev/null 2>&1
            ;;
    esac

    print_message $GREEN "依赖安装完成"
}

# 检查防火墙状态
check_firewall() {
    print_message $BLUE "正在检查防火墙状态..."

    if systemctl is-active --quiet ufw; then
        FIREWALL="ufw"
        print_message $YELLOW "检测到UFW防火墙正在运行"
    elif systemctl is-active --quiet firewalld; then
        FIREWALL="firewalld"
        print_message $YELLOW "检测到Firewalld防火墙正在运行"
    else
        FIREWALL="none"
        print_message $GREEN "未检测到活动的防火墙"
    fi
}

# 配置防火墙规则
configure_firewall() {
    local port=$1
    local service_name=$2

    if [[ "$FIREWALL" == "ufw" ]]; then
        ufw allow $port/tcp >/dev/null 2>&1
        ufw allow $port/udp >/dev/null 2>&1
        print_message $GREEN "UFW防火墙已允许端口 $port TCP/UDP ($service_name)"
    elif [[ "$FIREWALL" == "firewalld" ]]; then
        firewall-cmd --permanent --add-port=$port/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=$port/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        print_message $GREEN "Firewalld防火墙已允许端口 $port TCP/UDP ($service_name)"
    else
        print_message $BLUE "未检测到防火墙，请手动为 $service_name 开放端口 $port TCP/UDP"
    fi
}

# 诊断Shadowsocks连接问题
diagnose_shadowsocks() {
    print_message $BLUE "正在诊断Shadowsocks连接问题..."

    # 检查服务状态
    if ! systemctl is-active --quiet shadowsocks-libev; then
        print_message $RED "Shadowsocks 服务未运行"
        print_message $YELLOW "查看服务日志:"
        journalctl -u shadowsocks-libev --no-pager -n 5
    else
        print_message $GREEN "Shadowsocks 服务运行正常"
    fi

    local port=$(grep server_port $SHADOWSOCKS_CONFIG_FILE | cut -d':' -f2 | tr -d ' ,')

    # 检查端口监听
    print_message $BLUE "检查端口监听状态:"
    if ss -tuln | grep -q ":$port"; then
        print_message $GREEN "端口 $port 正在监听"
    else
        print_message $YELLOW "未检测到端口 $port 监听"
    fi

    # 检查防火墙状态
    print_message $BLUE "检查防火墙状态:"
    if [[ "$FIREWALL" == "ufw" ]]; then
        ufw status | grep -q "$port" || print_message $YELLOW "防火墙规则可能未正确配置"
    elif [[ "$FIREWALL" == "firewalld" ]]; then
        firewall-cmd --list-ports | grep -q "$port" || print_message $YELLOW "防火墙规则可能未正确配置"
    fi

    # 网络连通性测试
    print_message $BLUE "进行网络连通性测试..."
    if $IPV6_AVAILABLE && [[ -n "$SERVER_IPV6" ]]; then
        if timeout 5 bash -c "</dev/tcp/[$SERVER_IPV6]/$port" 2>/dev/null; then
            print_message $GREEN "IPv6 端口 $port 连通性正常"
        else
            print_message $RED "IPv6 端口 $port 连通性测试失败"
        fi
    fi
}

# 检查服务状态
check_hysteria2_status() {
    if systemctl is-active --quiet hysteria2; then
        echo -e "${GREEN}运行中${NC}"
    elif [[ -f "$HYSTERIA2_CONFIG_FILE" ]]; then
        echo -e "${YELLOW}已安装但未运行${NC}"
    else
        echo -e "${RED}未安装${NC}"
    fi
}

check_shadowsocks_status() {
    if systemctl is-active --quiet shadowsocks-libev; then
        echo -e "${GREEN}运行中${NC}"
    elif [[ -f "$SHADOWSOCKS_CONFIG_FILE" ]]; then
        echo -e "${YELLOW}已安装但未运行${NC}"
    else
        echo -e "${RED}未安装${NC}"
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

# 安装Hysteria2
install_hysteria2() {
    print_message $BLUE "开始安装 Hysteria2..."

    # 检查是否已安装
    if [[ -f "$HYSTERIA2_CONFIG_FILE" ]]; then
        print_message $YELLOW "Hysteria2 已安装，如需重新安装请先卸载"
        return
    fi

    # 获取SNI域名
    read -p "请输入用于 SNI 伪装的域名 (回车默认 amd.com): " sni_domain
    sni_domain=${sni_domain:-amd.com}

    # 生成配置参数
    local port=$(generate_port)
    local password=$(generate_password)

    # 下载Hysteria2
    show_progress 20 "正在下载 Hysteria2"
    local download_url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${ARCH}"
    curl -L -o /usr/local/bin/hysteria2 "$download_url" >/dev/null 2>&1

    if [[ $? -ne 0 ]]; then
        print_message $RED "Hysteria2 下载失败"
        return 1
    fi

    chmod +x /usr/local/bin/hysteria2

    # 创建配置目录
    mkdir -p /etc/hysteria2

    # 生成自签名证书
    show_progress 10 "正在生成自签名证书"
    openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/hysteria2/server.key \
        -out /etc/hysteria2/server.crt -days 365 \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=$sni_domain" >/dev/null 2>&1

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
  up: 50 mbps
  down: 100 mbps
EOF

    # 创建systemd服务
    cat > /etc/systemd/system/hysteria2.service << EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria2 server -c /etc/hysteria2/config.yaml
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

    # 启动服务
    systemctl daemon-reload
    systemctl enable hysteria2 >/dev/null 2>&1
    systemctl start hysteria2

    # 配置防火墙
    configure_firewall "$port" "Hysteria2"

    if systemctl is-active --quiet hysteria2; then
        print_message $GREEN "Hysteria2 安装成功！"
        show_hysteria2_config "$port" "$password" "$sni_domain"
    else
        print_message $RED "Hysteria2 启动失败"
        return 1
    fi
}

# 显示Hysteria2配置信息
show_hysteria2_config() {
    local port=$1
    local password=$2
    local sni_domain=$3
    local server_ip=${SERVER_IPV4:-$SERVER_IPV6}

    print_message $CYAN "
================================================
Hysteria2 配置信息
================================================"

    echo -e "${YELLOW}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${WHITE}hysteria2://${password}@${server_ip}:${port}/?insecure=true&sni=${sni_domain}#🌟Hysteria2-$(date +%m%d)${NC}"
    echo

    echo -e "${YELLOW}⚔️ Clash Meta 配置:${NC}"
    echo -e "${WHITE}- { name: 'Hysteria2-$(date +%m%d)', type: hysteria2, server: ${server_ip}, port: ${port}, password: ${password}, sni: ${sni_domain}, skip-cert-verify: true, up: 50, down: 100 }${NC}"
    echo

    echo -e "${YELLOW}🌊 Surge 配置:${NC}"
    echo -e "${WHITE}Hysteria2-$(date +%m%d) = hysteria2, ${server_ip}, ${port}, password=${password}, sni=${sni_domain}, skip-cert-verify=true${NC}"
    echo
}


# 显示Shadowsocks配置信息 (仅IPv6)
show_shadowsocks_config() {
    local port=$1
    local password=$2
    local method=$3

    print_message $CYAN "
================================================
Shadowsocks 配置信息 (仅 IPv6)
================================================"

    if $IPV6_AVAILABLE && [[ -n "$SERVER_IPV6" ]]; then
        echo -e "${YELLOW}🚀 V2rayN / NekoBox / Shadowrocket 分享链接 (IPv6):${NC}"
        local ss_link_ipv6=$(echo -n "${method}:${password}@[${SERVER_IPV6}]:${port}" | base64 -w 0)
        echo -e "${WHITE}ss://${ss_link_ipv6}#🌟SS-IPv6-$(date +%m%d)${NC}"
        echo

        echo -e "${YELLOW}⚔️ Clash Meta 配置 (IPv6):${NC}"
        echo -e "${WHITE}- { name: '🌟SS-IPv6-$(date +%m%d)', type: ss, server: '${SERVER_IPV6}', port: ${port}, cipher: ${method}, password: '${password}', udp: true }${NC}"
        echo

        echo -e "${YELLOW}🌊 Surge 配置 (IPv6):${NC}"
        echo -e "${WHITE}🌟SS-IPv6-$(date +%m%d) = ss, ${SERVER_IPV6}, ${port}, encrypt-method=${method}, password=${password}, udp-relay=true${NC}"
        echo

        if command -v qrencode >/dev/null 2>&1; then
            echo -e "${YELLOW} 二维码 (SS链接):${NC}"
            qrencode -t ANSIUTF8 "$ss_link_ipv6"
        fi
        echo
    else
        print_message $RED "IPv6 地址不可用，无法生成配置信息"
        return
    fi

    echo -e "${CYAN}💡 连接建议:${NC}"
    echo -e "${WHITE}• 此配置仅支持 IPv6，请确保您的客户端和网络环境支持 IPv6。${NC}"
    echo -e "${WHITE}• 如遇超时问题，请检查防火墙和端口开放情况。${NC}"
    echo -e "${WHITE}• 建议客户端启用 UDP 转发以获得更好性能。${NC}"
    echo
}


# 安装Shadowsocks
install_shadowsocks() {
    print_message $BLUE "开始安装 Shadowsocks (仅IPv6)..."

    # 检查IPv6可用性
    if ! $IPV6_AVAILABLE; then
        print_message $RED "错误：此Shadowsocks安装模式仅支持有IPv6的服务器。"
        print_message $YELLOW "建议使用 Hysteria2，它支持 IPv4 环境。"
        return 1
    fi

    # 检查是否已安装
    if [[ -f "$SHADOWSOCKS_CONFIG_FILE" ]]; then
        print_message $YELLOW "Shadowsocks 已安装，如需重新安装请先卸载。"
        return
    fi

    # 安装shadowsocks-libev
    print_message $BLUE "正在安装 shadowsocks-libev..."
    case $PACKAGE_MANAGER in
        apt)
            apt update >/dev/null 2>&1
            apt install -y shadowsocks-libev >/dev/null 2>&1
            ;;
        yum|dnf)
            $PACKAGE_MANAGER install -y epel-release >/dev/null 2>&1
            $PACKAGE_MANAGER install -y shadowsocks-libev >/dev/null 2>&1
            ;;
    esac

    # 生成配置参数
    local port=$(generate_port)
    local password=$(generate_password)
    local method="chacha20-ietf-poly1305"

    # 创建配置目录
    mkdir -p /etc/shadowsocks-libev

    # 创建IPv6主配置文件
    cat > "$SHADOWSOCKS_CONFIG_FILE" << EOF
{
    "server": "::",
    "server_port": $port,
    "password": "$password",
    "timeout": 300,
    "method": "$method",
    "mode": "tcp_and_udp",
    "no_delay": true
}
EOF

    # 启动服务
    systemctl enable shadowsocks-libev >/dev/null 2>&1
    systemctl restart shadowsocks-libev

    # 等待服务启动
    sleep 2

    # 配置防火墙
    configure_firewall "$port" "Shadowsocks"

    # 检查服务状态
    if systemctl is-active --quiet shadowsocks-libev; then
        print_message $GREEN "✅ Shadowsocks (仅IPv6) 安装完成！"
        show_shadowsocks_config "$port" "$password" "$method"

        # 运行连接诊断
        print_message $BLUE "正在进行连接诊断..."
        sleep 2
        diagnose_shadowsocks
    else
        print_message $RED "Shadowsocks 启动失败"
        print_message $YELLOW "正在查看错误日志..."
        journalctl -u shadowsocks-libev --no-pager -n 10
        return 1
    fi
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
        echo -e " 5. 查看配置"
        echo -e " 6. 查看日志"
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
                if [[ -f "$HYSTERIA2_CONFIG_FILE" ]]; then
                    cat "$HYSTERIA2_CONFIG_FILE"
                else
                    print_message $RED "配置文件不存在"
                fi
                ;;
            6)
                journalctl -u hysteria2 -f
                ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac

        if [[ $choice != 4 && $choice != 6 ]]; then
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
        echo -e " 5. 查看配置"
        echo -e " 6. 查看日志"
        echo -e " 7. 诊断连接问题"
        echo -e " 8. 显示配置信息"
        echo -e " 0. 返回上级菜单"
        echo

        read -p "请选择操作 [0-8]: " choice

        case $choice in
            1)
                systemctl start shadowsocks-libev
                print_message $GREEN "Shadowsocks 服务已启动"
                ;;
            2)
                systemctl stop shadowsocks-libev
                print_message $YELLOW "Shadowsocks 服务已停止"
                ;;
            3)
                systemctl restart shadowsocks-libev
                print_message $GREEN "Shadowsocks 服务已重启"
                ;;
            4)
                systemctl status shadowsocks-libev
                ;;
            5)
                if [[ -f "$SHADOWSOCKS_CONFIG_FILE" ]]; then
                    echo -e "${YELLOW}Shadowsocks 配置:${NC}"
                    cat "$SHADOWSOCKS_CONFIG_FILE"
                else
                    print_message $RED "配置文件不存在"
                fi
                ;;
            6)
                echo -e "${YELLOW}Shadowsocks 服务日志:${NC}"
                journalctl -u shadowsocks-libev -n 20 --no-pager
                ;;
            7)
                diagnose_shadowsocks
                ;;
            8)
                if [[ -f "$SHADOWSOCKS_CONFIG_FILE" ]]; then
                    local port=$(grep server_port "$SHADOWSOCKS_CONFIG_FILE" | cut -d':' -f2 | tr -d ' ,')
                    local password=$(grep password "$SHADOWSOCKS_CONFIG_FILE" | cut -d'"' -f4)
                    local method=$(grep method "$SHADOWSOCKS_CONFIG_FILE" | cut -d'"' -f4)
                    show_shadowsocks_config "$port" "$password" "$method"
                else
                    print_message $RED "配置文件不存在"
                fi
                ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac

        if [[ $choice != 4 && $choice != 6 ]]; then
            read -p "按回车键继续..."
        fi
    done
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
            1) uninstall_hysteria2 ;;
            2) uninstall_shadowsocks ;;
            3) uninstall_all_services ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac

        read -p "按回车键继续..."
    done
}

# 卸载Hysteria2
uninstall_hysteria2() {
    print_message $YELLOW "正在卸载 Hysteria2..."

    systemctl stop hysteria2 >/dev/null 2>&1
    systemctl disable hysteria2 >/dev/null 2>&1
    rm -f /etc/systemd/system/hysteria2.service
    rm -f /usr/local/bin/hysteria2
    rm -rf /etc/hysteria2
    systemctl daemon-reload

    print_message $GREEN "Hysteria2 卸载完成"
}

# 卸载Shadowsocks
uninstall_shadowsocks() {
    print_message $YELLOW "正在卸载 Shadowsocks..."

    # 停止并禁用服务
    systemctl stop shadowsocks-libev >/dev/null 2>&1
    systemctl disable shadowsocks-libev >/dev/null 2>&1

    # 删除配置文件和目录
    rm -rf /etc/shadowsocks-libev
    systemctl daemon-reload

    print_message $GREEN "Shadowsocks 卸载完成"
}

# 卸载所有服务
uninstall_all_services() {
    print_message $YELLOW "正在卸载所有服务..."
    uninstall_hysteria2
    uninstall_shadowsocks
    print_message $GREEN "所有服务卸载完成"
}

# 更新服务菜单
update_services() {
    while true; do
        clear
        print_message $CYAN "
=== 更新服务 ==="
        echo -e " 1. 更新 Hysteria2"
        echo -e " 2. 更新 Shadowsocks"
        echo -e " 3. 更新系统内核"
        echo -e " 0. 返回主菜单"
        echo

        read -p "请选择操作 [0-3]: " choice

        case $choice in
            1) update_hysteria2 ;;
            2) update_shadowsocks ;;
            3) update_kernel ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac

        read -p "按回车键继续..."
    done
}

# 更新Hysteria2
update_hysteria2() {
    print_message $BLUE "正在更新 Hysteria2..."

    if [[ ! -f "$HYSTERIA2_CONFIG_FILE" ]]; then
        print_message $RED "Hysteria2 未安装"
        return
    fi

    systemctl stop hysteria2

    local download_url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${ARCH}"
    curl -L -o /usr/local/bin/hysteria2 "$download_url" >/dev/null 2>&1

    if [[ $? -eq 0 ]]; then
        chmod +x /usr/local/bin/hysteria2
        systemctl start hysteria2
        print_message $GREEN "Hysteria2 更新完成"
    else
        print_message $RED "Hysteria2 更新失败"
    fi
}

# 更新Shadowsocks
update_shadowsocks() {
    print_message $BLUE "正在更新 Shadowsocks..."

    if [[ ! -f "$SHADOWSOCKS_CONFIG_FILE" ]]; then
        print_message $RED "Shadowsocks 未安装"
        return
    fi

    # 停止服务
    systemctl stop shadowsocks-libev >/dev/null 2>&1

    # 通过包管理器更新
    case $PACKAGE_MANAGER in
        apt)
            apt update >/dev/null 2>&1
            apt upgrade -y shadowsocks-libev >/dev/null 2>&1
            ;;
        yum|dnf)
            $PACKAGE_MANAGER update -y shadowsocks-libev >/dev/null 2>&1
            ;;
    esac

    if [[ $? -eq 0 ]]; then
        # 重启服务
        systemctl start shadowsocks-libev
        print_message $GREEN "Shadowsocks 更新完成"
    else
        print_message $RED "Shadowsocks 更新失败"
    fi
}


# 更新系统内核
update_kernel() {
    print_message $BLUE "正在更新系统内核..."

    case $PACKAGE_MANAGER in
        apt)
            apt update && apt upgrade -y
            ;;
        yum|dnf)
            $PACKAGE_MANAGER update -y
            ;;
    esac

    print_message $GREEN "系统内核更新完成，建议重启系统"
}

# 系统优化菜单
system_optimization() {
    while true; do
        clear
        print_message $CYAN "
=== 系统优化 ==="
        echo -e " 1. 创建/管理 Swap"
        echo -e " 2. 优化网络参数 (BBR)"
        echo -e " 3. 优化系统限制"
        echo -e " 4. 清理系统垃圾"
        echo -e " 0. 返回主菜单"
        echo

        read -p "请选择操作 [0-4]: " choice

        case $choice in
            1) manage_swap ;;
            2) optimize_network ;;
            3) optimize_limits ;;
            4) clean_system ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac

        read -p "按回车键继续..."
    done
}

# 管理Swap
manage_swap() {
    print_message $BLUE "当前Swap状态:"
    free -h | grep -i swap
    echo

    if [[ -f /swapfile ]]; then
        echo -e " 1. 删除现有Swap"
        echo -e " 2. 重新创建Swap"
        echo -e " 3. 返回"
        read -p "请选择操作 [1-3]: " swap_choice

        case $swap_choice in
            1)
                swapoff /swapfile
                rm -f /swapfile
                sed -i '/\/swapfile/d' /etc/fstab
                print_message $GREEN "Swap已删除"
                ;;
            2)
                swapoff /swapfile
                rm -f /swapfile
                sed -i '/\/swapfile/d' /etc/fstab
                create_swap_file
                ;;
            3) return ;;
        esac
    else
        read -p "是否创建1GB Swap? (y/n): " create_swap
        if [[ $create_swap =~ ^[Yy]$ ]]; then
            create_swap_file
        fi
    fi
}

# 优化网络参数
optimize_network() {
    print_message $BLUE "正在优化网络参数 (启用 BBR)..."

    cat > /etc/sysctl.conf << EOF
# System Optimization
fs.file-max = 1024000
fs.inotify.max_user_instances = 8192

# Network Optimization (BBR)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.netdev_max_backlog = 262144
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.somaxconn = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_mtu_probing = 1
EOF

    sysctl -p >/dev/null 2>&1
    print_message $GREEN "网络参数优化完成"
}

# 优化系统限制
optimize_limits() {
    print_message $BLUE "正在优化系统限制..."

    cat > /etc/security/limits.conf << EOF
# System Limits Optimization
* soft nofile 1024000
* hard nofile 1024000
* soft nproc 65536
* hard nproc 65536
EOF

    print_message $GREEN "系统限制优化完成。请重新登录以使设置生效。"
}

# 清理系统垃圾
clean_system() {
    print_message $BLUE "正在清理系统垃圾..."

    case $PACKAGE_MANAGER in
        apt)
            apt autoremove -y >/dev/null 2>&1
            apt autoclean >/dev/null 2>&1
            ;;
        yum|dnf)
            $PACKAGE_MANAGER autoremove -y >/dev/null 2>&1
            $PACKAGE_MANAGER clean all >/dev/null 2>&1
            ;;
    esac

    # 清理日志
    journalctl --vacuum-time=7d >/dev/null 2>&1

    # 清理临时文件
    rm -rf /tmp/* >/dev/null 2>&1

    print_message $GREEN "系统垃圾清理完成"
}

# 显示主菜单
show_main_menu() {
    clear
    print_message $CYAN "
Hysteria2 & Shadowsocks (IPv6) Management Script ($SCRIPT_VERSION)
项目地址：https://github.com/everett7623/hy2ipv6
博客地址：https://seedloc.com
论坛地址：https://nodeloc.com

服务器 IPv4: ${SERVER_IPV4:-N/A}
服务器 IPv6: ${SERVER_IPV6:-N/A}
Hysteria2 状态: $(check_hysteria2_status)
Shadowsocks 状态: $(check_shadowsocks_status)

================================================"
    echo -e " 1. 安装 Hysteria2 (自签证书，无需域名)"
    echo -e " 2. 安装 Shadowsocks (仅限 IPv6)"
    echo -e " 3. 服务管理"
    echo -e " 4. 卸载服务"
    echo -e " 5. 更新服务"
    echo -e " 6. 系统优化"
    echo -e " 0. 退出脚本"
    echo -e "================================================"
}

# 主函数
main() {
    # 检查root权限
    check_root

    # 创建日志文件
    touch "$LOG_FILE"

    # 系统初始化检查
    detect_system
    check_system_compatibility
    install_dependencies
    check_memory
    check_ipv4
    check_ipv6
    check_firewall

    # 主循环
    while true; do
        show_main_menu
        read -p "请选择操作 [0-6]: " choice

        case $choice in
            1) install_hysteria2 ;;
            2) install_shadowsocks ;;
            3) service_management ;;
            4) uninstall_services ;;
            5) update_services ;;
            6) system_optimization ;;
            0)
                print_message $GREEN "感谢使用！"
                exit 0
                ;;
            *)
                print_message $RED "无效选择，请重新输入"
                ;;
        esac

        if [[ $choice -ne 3 && $choice -ne 4 && $choice -ne 5 && $choice -ne 6 ]]; then
            read -p "按回车键继续..."
        fi
    done
}

# 运行主函数
main "$@"
