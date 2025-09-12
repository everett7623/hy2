#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks (IPv6) Management Script
# 作者：Jensfrank
# 版本：v1.1
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
SCRIPT_VERSION="v1.1"
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
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$NAME
    else
        print_message $RED "无法检测操作系统"
        exit 1
    fi
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) ARCH="amd64" ;;
    esac
    print_message $GREEN "系统检测完成: $OS_NAME ($OS) $OS_VERSION, 架构: $ARCH"
}

# 检查系统兼容性
check_system_compatibility() {
    print_message $BLUE "正在检查系统兼容性..."
    case $OS in
        ubuntu|debian) PACKAGE_MANAGER="apt" ;;
        centos|rhel|fedora) PACKAGE_MANAGER="yum"
                           if command -v dnf >/dev/null 2>&1; then PACKAGE_MANAGER="dnf"; fi ;;
        *)
            print_message $RED "不支持的操作系统: $OS_NAME"
            exit 1
            ;;
    esac
    print_message $GREEN "系统兼容性检查完成。使用包管理器: $PACKAGE_MANAGER"
}

# 检查IPv6连接性
check_ipv6() {
    print_message $BLUE "正在检查IPv6连接性..."
    SERVER_IPV6=$(ip -6 addr show scope global | grep "inet6" | awk '{print $2}' | cut -d'/' -f1 | head -n1)
    if [[ -n "$SERVER_IPV6" ]]; then
        IPV6_AVAILABLE=true
        print_message $GREEN "IPv6可用: $SERVER_IPV6"
    else
        IPV6_AVAILABLE=false
        print_message $YELLOW "IPv6不可用"
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
            apt install -y curl wget unzip tar jq iproute2 lsof qrencode >/dev/null 2>&1
            ;;
        yum|dnf)
            $PACKAGE_MANAGER install -y curl wget unzip tar jq iproute lsof qrencode >/dev/null 2>&1
            ;;
    esac
    print_message $GREEN "依赖安装完成"
}

# 检查防火墙状态并配置
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

configure_firewall() {
    local port=$1
    local service_name=$2
    if [[ "$FIREWALL" == "none" ]]; then
        print_message $YELLOW "未检测到防火墙，请手动为 $service_name 开放端口 $port TCP/UDP"
        return
    fi
    
    print_message $BLUE "正在为 $service_name 配置防火墙端口 $port ..."
    if [[ "$FIREWALL" == "ufw" ]]; then
        ufw allow $port/tcp >/dev/null 2>&1
        ufw allow $port/udp >/dev/null 2>&1
    elif [[ "$FIREWALL" == "firewalld" ]]; then
        firewall-cmd --permanent --add-port=$port/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=$port/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    print_message $GREEN "防火墙配置完成"
}

# 诊断Shadowsocks连接问题
diagnose_shadowsocks() {
    print_message $BLUE "正在诊断Shadowsocks连接问题..."
    if ! systemctl is-active --quiet shadowsocks-libev; then
        print_message $RED "Shadowsocks 服务未运行"
        journalctl -u shadowsocks-libev --no-pager -n 5
        return
    else
        print_message $GREEN "Shadowsocks 服务运行正常"
    fi

    local port=$(jq -r .server_port $SHADOWSOCKS_CONFIG_FILE)
    if ss -tuln | grep -q ":$port"; then
        print_message $GREEN "端口 $port 正在监听"
    else
        print_message $RED "未检测到端口 $port 监听"
    fi

    if $IPV6_AVAILABLE && ! timeout 5 bash -c "</dev/tcp/[$SERVER_IPV6]/$port" 2>/dev/null; then
        print_message $RED "IPv6 端口 $port 连通性测试失败"
    else
        print_message $GREEN "IPv6 端口 $port 连通性测试成功"
    fi
}

# 检查服务状态
check_hysteria2_status() {
    if systemctl is-active --quiet hysteria2; then echo -e "${GREEN}运行中${NC}"; else echo -e "${RED}未运行${NC}"; fi
}

check_shadowsocks_status() {
    if systemctl is-active --quiet shadowsocks-libev; then echo -e "${GREEN}运行中${NC}"; else echo -e "${RED}未运行${NC}"; fi
}

# 生成随机密码
generate_password() {
    openssl rand -base64 16
}

# 生成随机端口
generate_port() {
    shuf -i 10000-65000 -n 1
}

# 安装Hysteria2
install_hysteria2() {
    print_message $BLUE "开始安装 Hysteria2..."
    if [[ -f "$HYSTERIA2_CONFIG_FILE" ]]; then
        print_message $YELLOW "Hysteria2 已安装，如需重新安装请先卸载"
        return
    fi
    read -p "请输入用于 SNI 伪装的域名 (回车默认 amd.com): " sni_domain
    sni_domain=${sni_domain:-amd.com}
    local port=$(generate_port)
    local password=$(generate_password)
    show_progress 20 "正在下载 Hysteria2"
    curl -L -o /usr/local/bin/hysteria2 "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${ARCH}" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then print_message $RED "Hysteria2 下载失败"; return 1; fi
    chmod +x /usr/local/bin/hysteria2
    mkdir -p /etc/hysteria2
    openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/hysteria2/server.key -out /etc/hysteria2/server.crt -days 365 -subj "/CN=$sni_domain" >/dev/null 2>&1
    cat > "$HYSTERIA2_CONFIG_FILE" << EOF
listen: :$port
tls:
  cert: /etc/hysteria2/server.crt
  key: /etc/hysteria2/server.key
auth: {type: password, password: $password}
masquerade: {type: proxy, proxy: {url: https://www.bing.com, rewriteHost: true}}
EOF
    cat > /etc/systemd/system/hysteria2.service << EOF
[Unit]
Description=Hysteria2 Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria2 server -c $HYSTERIA2_CONFIG_FILE
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now hysteria2
    configure_firewall "$port" "Hysteria2"
    if systemctl is-active --quiet hysteria2; then
        print_message $GREEN "Hysteria2 安装成功！"
        show_hysteria2_config "$port" "$password" "$sni_domain"
    else
        print_message $RED "Hysteria2 启动失败"
    fi
}

# 显示Hysteria2配置
show_hysteria2_config() {
    local port=$1
    local password=$2
    local sni_domain=$3
    local server_ip=${SERVER_IPV4:-$SERVER_IPV6}
    print_message $CYAN "\n================ Hysteria2 配置 ================"
    echo -e "${YELLOW}分享链接:${NC} ${WHITE}hysteria2://${password}@${server_ip}:${port}/?insecure=true&sni=${sni_domain}#Hy2-${server_ip}${NC}"
    echo -e "${YELLOW}Clash Meta:${NC} ${WHITE}- { name: 'Hy2-${server_ip}', type: hysteria2, server: ${server_ip}, port: ${port}, password: ${password}, sni: ${sni_domain}, skip-cert-verify: true }${NC}"
}

# 显示Shadowsocks配置
show_shadowsocks_config() {
    if [[ ! -f "$SHADOWSOCKS_CONFIG_FILE" ]]; then print_message $RED "Shadowsocks 配置文件不存在"; return; fi
    local port=$(jq -r .server_port $SHADOWSOCKS_CONFIG_FILE)
    local password=$(jq -r .password $SHADOWSOCKS_CONFIG_FILE)
    local method=$(jq -r .method $SHADOWSOCKS_CONFIG_FILE)
    local tag="SS-IPv6"
    local encoded=$(echo -n "${method}:${password}@[${SERVER_IPV6}]:${port}" | base64 -w 0)
    local ss_link="ss://${encoded}#${tag}"
    print_message $CYAN "\n============== Shadowsocks (IPv6) 配置 =============="
    echo -e "${YELLOW}地址:${NC} ${WHITE}$SERVER_IPV6${NC}"
    echo -e "${YELLOW}端口:${NC} ${WHITE}$port${NC}"
    echo -e "${YELLOW}密码:${NC} ${WHITE}$password${NC}"
    echo -e "${YELLOW}加密:${NC} ${WHITE}$method${NC}\n"
    echo -e "${YELLOW}SS链接:${NC} ${WHITE}$ss_link${NC}\n"
    echo -e "${YELLOW}Clash Meta:${NC} ${WHITE}- { name: '${tag}', type: ss, server: '${SERVER_IPV6}', port: ${port}, cipher: ${method}, password: '${password}', udp: true }${NC}\n"
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${YELLOW}二维码 (SS链接):${NC}"
        qrencode -t ANSIUTF8 "$ss_link"
    fi
}

# 安装Shadowsocks (新版)
install_shadowsocks() {
    print_message $BLUE "开始安装 Shadowsocks (仅IPv6)..."
    if ! $IPV6_AVAILABLE; then
        print_message $RED "错误：未检测到IPv6地址，无法继续安装。"
        return 1
    fi
    if [[ -f "$SHADOWSOCKS_CONFIG_FILE" ]]; then
        print_message $YELLOW "Shadowsocks 已安装，如需重新安装请先卸载。"
        return
    fi

    print_message $BLUE "正在安装 shadowsocks-libev..."
    case $PACKAGE_MANAGER in
        apt)
            apt install -y shadowsocks-libev >/dev/null 2>&1
            ;;
        yum|dnf)
            # CentOS 7 needs EPEL for ss-libev
            if [[ "$OS" == "centos" && ${OS_VERSION%%.*} -eq 7 ]]; then
                 $PACKAGE_MANAGER install -y epel-release >/dev/null 2>&1
            fi
            $PACKAGE_MANAGER install -y shadowsocks-libev >/dev/null 2>&1
            ;;
    esac
    if ! command -v ss-server >/dev/null 2>&1; then
        print_message $RED "Shadowsocks-libev 安装失败，请检查软件源。"
        return 1
    fi
    
    local port=$(generate_port)
    local password=$(generate_password)
    local method="chacha20-ietf-poly1305"

    print_message $BLUE "正在写入配置文件..."
    cat > "$SHADOWSOCKS_CONFIG_FILE" <<EOF
{
    "server":"::",
    "server_port":$port,
    "password":"$password",
    "timeout":300,
    "method":"$method",
    "mode":"tcp_and_udp",
    "no_delay": true
}
EOF

    print_message $BLUE "正在启动并设置开机自启..."
    systemctl enable --now shadowsocks-libev >/dev/null 2>&1
    sleep 2
    
    configure_firewall "$port" "Shadowsocks"

    if systemctl is-active --quiet shadowsocks-libev; then
        print_message $GREEN "✅ Shadowsocks (仅IPv6) 安装成功！"
        show_shadowsocks_config
        diagnose_shadowsocks
    else
        print_message $RED "Shadowsocks 启动失败，请检查日志！"
        journalctl -u shadowsocks-libev -n 10 --no-pager
    fi
}

# 服务管理
service_management() {
    clear
    print_message $CYAN "=== 服务管理 ==="
    echo -e " 1. 管理 Hysteria2\n 2. 管理 Shadowsocks\n 0. 返回主菜单"
    read -p "请选择操作 [0-2]: " choice
    case $choice in
        1) manage_service "hysteria2" ;;
        2) manage_service "shadowsocks-libev" "Shadowsocks" ;;
        0) return ;;
        *) print_message $RED "无效选择" ;;
    esac
}

manage_service() {
    local service_name=$1
    local display_name=${2:-$service_name}
    while true; do
        clear
        print_message $CYAN "=== $display_name 管理 ==="
        echo -e " 1. 启动服务\n 2. 停止服务\n 3. 重启服务\n 4. 查看状态\n 5. 查看日志"
        if [[ "$service_name" == "shadowsocks-libev" ]]; then
            echo -e " 6. 显示配置信息\n 7. 诊断连接"
        fi
        echo -e " 0. 返回上级菜单"
        read -p "请选择操作: " choice
        case $choice in
            1) systemctl start $service_name; print_message $GREEN "服务已启动" ;;
            2) systemctl stop $service_name; print_message $YELLOW "服务已停止" ;;
            3) systemctl restart $service_name; print_message $GREEN "服务已重启" ;;
            4) systemctl status $service_name ;;
            5) journalctl -u $service_name -f --no-pager ;;
            6) if [[ "$service_name" == "shadowsocks-libev" ]]; then show_shadowsocks_config; fi ;;
            7) if [[ "$service_name" == "shadowsocks-libev" ]]; then diagnose_shadowsocks; fi ;;
            0) break ;;
            *) print_message $RED "无效选择" ;;
        esac
        read -n 1 -s -r -p "按任意键继续..."
    done
}

# 卸载服务
uninstall_services() {
    clear
    print_message $CYAN "=== 卸载服务 ==="
    echo -e " 1. 卸载 Hysteria2\n 2. 卸载 Shadowsocks\n 3. 卸载所有\n 0. 返回主菜单"
    read -p "请选择操作 [0-3]: " choice
    case $choice in
        1) uninstall_hysteria2 ;;
        2) uninstall_shadowsocks ;;
        3) uninstall_hysteria2; uninstall_shadowsocks ;;
        0) return ;;
        *) print_message $RED "无效选择" ;;
    esac
    read -n 1 -s -r -p "按任意键继续..."
}

uninstall_hysteria2() {
    print_message $YELLOW "正在卸载 Hysteria2..."
    systemctl disable --now hysteria2 >/dev/null 2>&1
    rm -f /etc/systemd/system/hysteria2.service /usr/local/bin/hysteria2
    rm -rf /etc/hysteria2
    systemctl daemon-reload
    print_message $GREEN "Hysteria2 卸载完成"
}

uninstall_shadowsocks() {
    print_message $YELLOW "正在卸载 Shadowsocks..."
    systemctl disable --now shadowsocks-libev >/dev/null 2>&1
    rm -rf /etc/shadowsocks-libev
    # Optionally remove the package
    read -p "是否彻底卸载 shadowsocks-libev 软件包? (y/N): " remove_package
    if [[ $remove_package =~ ^[Yy]$ ]]; then
        case $PACKAGE_MANAGER in
            apt) apt remove -y shadowsocks-libev ;;
            yum|dnf) $PACKAGE_MANAGER remove -y shadowsocks-libev ;;
        esac
    fi
    print_message $GREEN "Shadowsocks 卸载完成"
}

# 主菜单
show_main_menu() {
    clear
    print_message $CYAN "
Hysteria2 & Shadowsocks (IPv6) Management Script ($SCRIPT_VERSION)
================================================
服务器 IPv4: ${SERVER_IPV4:-N/A}
服务器 IPv6: ${SERVER_IPV6:-N/A}
Hysteria2 状态: $(check_hysteria2_status)
Shadowsocks 状态: $(check_shadowsocks_status)
================================================
 1. 安装 Hysteria2 (自签证书)
 2. 安装 Shadowsocks (仅限 IPv6)
 3. 服务管理
 4. 卸载服务
 0. 退出脚本
================================================"
}

# 主函数
main() {
    check_root
    touch "$LOG_FILE"
    detect_system
    check_system_compatibility
    install_dependencies
    check_ipv4
    check_ipv6
    check_firewall

    while true; do
        show_main_menu
        read -p "请选择操作 [0-4]: " choice
        case $choice in
            1) install_hysteria2 ;;
            2) install_shadowsocks ;;
            3) service_management ;;
            4) uninstall_services ;;
            0) print_message $GREEN "感谢使用！"; exit 0 ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac
        if [[ $choice -ne 3 && $choice -ne 4 ]]; then
            read -n 1 -s -r -p "按任意键返回主菜单..."
        fi
    done
}

main "$@"
