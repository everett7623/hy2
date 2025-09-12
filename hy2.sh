#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks Management Script
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
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 全局变量
SCRIPT_VERSION="v2.0"
HYSTERIA2_CONFIG_FILE="/etc/hysteria2/config.yaml"
LOG_FILE="/var/log/hysteria2_manager.log"

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
        armv7l) ARCH="armv7" ;;
        *) 
            print_message $YELLOW "检测到未知架构: $ARCH，将尝试使用 amd64 版本"
            ARCH="amd64"
            ;;
    esac
    print_message $GREEN "系统检测完成: $OS_NAME ($OS) $OS_VERSION, 架构: $ARCH"
}

# 检查系统兼容性
check_system_compatibility() {
    print_message $BLUE "正在检查系统兼容性..."
    case $OS in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            ;;
        centos|rhel|fedora)
            PACKAGE_MANAGER="yum"
            if command -v dnf >/dev/null 2>&1; then
                PACKAGE_MANAGER="dnf"
            fi
            ;;
        *)
            print_message $RED "检测到未明确支持的操作系统: $OS_NAME"
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
        print_message $GREEN "IPv6可用: $SERVER_IPV6"
    else
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
            apt install -y curl wget unzip tar >/dev/null 2>&1
            ;;
        yum|dnf)
            $PACKAGE_MANAGER install -y curl wget unzip tar >/dev/null 2>&1
            ;;
    esac
    print_message $GREEN "依赖安装完成"
}

# 检查并配置防火墙
configure_firewall() {
    local port=$1
    local service_name="Hysteria2"
    local firewall_tool=""

    if systemctl is-active --quiet ufw; then
        firewall_tool="ufw"
        print_message $YELLOW "检测到UFW防火墙正在运行"
    elif systemctl is-active --quiet firewalld; then
        firewall_tool="firewalld"
        print_message $YELLOW "检测到Firewalld防火墙正在运行"
    else
        print_message $YELLOW "未检测到活动的防火墙，请手动为 $service_name 开放端口 $port (TCP/UDP)"
        return
    fi
    
    print_message $BLUE "正在为 $service_name 配置防火墙端口 $port ..."
    if [[ "$firewall_tool" == "ufw" ]]; then
        ufw allow $port/tcp >/dev/null 2>&1
        ufw allow $port/udp >/dev/null 2>&1
    elif [[ "$firewall_tool" == "firewalld" ]]; then
        firewall-cmd --permanent --add-port=$port/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=$port/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    print_message $GREEN "防火墙配置完成"
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
        print_message $YELLOW "Hysteria2 已安装，如需重新安装请先卸载。"
        return
    fi

    read -p "请输入用于 SNI 伪装的域名 (回车默认 amd.com): " sni_domain
    sni_domain=${sni_domain:-amd.com}
    
    local port=$(generate_port)
    local password=$(generate_password)
    
    show_progress 20 "正在下载 Hysteria2"
    local download_url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${ARCH}"
    curl -L -o /usr/local/bin/hysteria2 "$download_url" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        print_message $RED "Hysteria2 下载失败，请检查网络或 GitHub 连接。"
        return 1
    fi
    chmod +x /usr/local/bin/hysteria2
    
    mkdir -p /etc/hysteria2
    show_progress 10 "正在生成自签名证书"
    openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/hysteria2/server.key \
        -out /etc/hysteria2/server.crt -days 365 \
        -subj "/CN=$sni_domain" >/dev/null 2>&1
    
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
EOF
    
    cat > /etc/systemd/system/hysteria2.service << EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria2 server -c /etc/hysteria2/config.yaml
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable --now hysteria2 >/dev/null 2>&1
    
    configure_firewall "$port"
    
    if systemctl is-active --quiet hysteria2; then
        print_message $GREEN "Hysteria2 安装成功！"
        show_hysteria2_config "$port" "$password" "$sni_domain"
    else
        print_message $RED "Hysteria2 启动失败，请检查日志！"
        journalctl -u hysteria2 -n 10 --no-pager
    fi
}

# 显示Hysteria2配置信息
show_hysteria2_config() {
    local port=$1
    local password=$2
    local sni_domain=$3
    local server_ip=${SERVER_IPV4:-$SERVER_IPV6}
    
    if [[ -z "$server_ip" || "$server_ip" == "N/A" ]]; then
        print_message $RED "错误：无法获取服务器公网IP地址。"
        return
    fi

    print_message $CYAN "
================================================
Hysteria2 配置信息
================================================"
    
    echo -e "${YELLOW}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${WHITE}hysteria2://${password}@${server_ip}:${port}/?insecure=true&sni=${sni_domain}#Hy2-${server_ip}${NC}"
    echo
    
    echo -e "${YELLOW}⚔️ Clash Meta 配置:${NC}"
    echo -e "${WHITE}- { name: 'Hy2-${server_ip}', type: hysteria2, server: ${server_ip}, port: ${port}, password: '${password}', sni: ${sni_domain}, skip-cert-verify: true }${NC}"
    echo
    
    echo -e "${YELLOW}🌊 Surge 配置:${NC}"
    echo -e "${WHITE}Hy2-${server_ip} = hysteria2, ${server_ip}, ${port}, password=${password}, sni=${sni_domain}, skip-cert-verify=true${NC}"
    echo
}

# 管理Hysteria2
manage_hysteria2() {
    while true; do
        clear
        print_message $CYAN "=== Hysteria2 管理 ==="
        echo -e " 1. 启动服务\n 2. 停止服务\n 3. 重启服务\n 4. 查看状态\n 5. 查看配置\n 6. 查看日志\n 7. 显示分享信息\n 0. 返回主菜单"
        echo
        read -p "请选择操作 [0-7]: " choice
        
        case $choice in
            1) systemctl start hysteria2; print_message $GREEN "Hysteria2 服务已启动" ;;
            2) systemctl stop hysteria2; print_message $YELLOW "Hysteria2 服务已停止" ;;
            3) systemctl restart hysteria2; print_message $GREEN "Hysteria2 服务已重启" ;;
            4) systemctl status hysteria2 ;;
            5) if [[ -f "$HYSTERIA2_CONFIG_FILE" ]]; then cat "$HYSTERIA2_CONFIG_FILE"; else print_message $RED "配置文件不存在"; fi ;;
            6) journalctl -u hysteria2 -f --no-pager ;;
            7) 
                if [[ -f "$HYSTERIA2_CONFIG_FILE" ]]; then
                    local port=$(grep -oP 'listen: :(\K[0-9]+)' "$HYSTERIA2_CONFIG_FILE")
                    local password=$(grep -oP 'password: \K.*' "$HYSTERIA2_CONFIG_FILE")
                    local sni_domain=$(openssl x509 -in /etc/hysteria2/server.crt -noout -subject | grep -oP 'CN = \K.*')
                    show_hysteria2_config "$port" "$password" "$sni_domain"
                else
                    print_message $RED "未安装 Hysteria2，无法显示配置。"
                fi
                ;;
            0) break ;;
            *) print_message $RED "无效选择，请重新输入" ;;
        esac
        read -n 1 -s -r -p "按任意键继续..."
    done
}

# 卸载Hysteria2
uninstall_hysteria2() {
    print_message $YELLOW "确定要卸载 Hysteria2 吗? 这将删除所有相关文件。"
    read -p "请输入 (y/N) 进行确认: " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_message $BLUE "操作已取消。"
        return
    fi

    print_message $YELLOW "正在卸载 Hysteria2..."
    systemctl disable --now hysteria2 >/dev/null 2>&1
    rm -f /etc/systemd/system/hysteria2.service
    rm -f /usr/local/bin/hysteria2
    rm -rf /etc/hysteria2
    systemctl daemon-reload
    print_message $GREEN "Hysteria2 卸载完成。"
}

# 更新Hysteria2
update_hysteria2() {
    print_message $BLUE "正在更新 Hysteria2..."
    if [[ ! -f "$HYSTERIA2_CONFIG_FILE" ]]; then
        print_message $RED "Hysteria2 未安装，无法更新。"
        return
    fi
    
    systemctl stop hysteria2
    local download_url="https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${ARCH}"
    curl -L -o /usr/local/bin/hysteria2 "$download_url" >/dev/null 2>&1
    
    if [[ $? -eq 0 ]]; then
        chmod +x /usr/local/bin/hysteria2
        systemctl start hysteria2
        print_message $GREEN "Hysteria2 更新完成。"
    else
        print_message $RED "Hysteria2 更新失败。"
    fi
}

# 更新系统内核
update_kernel() {
    print_message $BLUE "正在更新系统软件包和内核..."
    case $PACKAGE_MANAGER in
        apt) apt update && apt upgrade -y ;;
        yum|dnf) $PACKAGE_MANAGER update -y ;;
    esac
    print_message $GREEN "系统更新完成，如果内核已升级，建议重启系统。"
}

# 显示主菜单
show_main_menu() {
    clear
    print_message $CYAN "
Hysteria2 Management Script ($SCRIPT_VERSION)
================================================
项目地址：https://github.com/everett7623/hy2ipv6
博客地址: https://seedloc.com
论坛地址: https://nodeloc.com
服务器 IPv4: ${SERVER_IPV4:-N/A}
服务器 IPv6: ${SERVER_IPV6:-N/A}
Hysteria2 状态: $(check_hysteria2_status)
================================================
 1. 安装 Hysteria2
 2. 管理 Hysteria2
 3. 卸载 Hysteria2
 4. 更新 Hysteria2
 5. 更新系统内核
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
    
    while true; do
        show_main_menu
        read -p "请选择操作 [0-5]: " choice
        
        case $choice in
            1) install_hysteria2 ;;
            2) manage_hysteria2 ;;
            3) uninstall_hysteria2 ;;
            4) update_hysteria2 ;;
            5) update_kernel ;;
            0) 
                print_message $GREEN "感谢使用！"
                exit 0
                ;;
            *) 
                print_message $RED "无效选择，请重新输入"
                ;;
        esac
        
        if [[ $choice -ne 2 ]]; then
             read -n 1 -s -r -p "按任意键返回主菜单..."
        fi
    done
}

main "$@"
