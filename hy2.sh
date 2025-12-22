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

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置文件路径
HY2_CONFIG="/etc/hysteria/config.yaml"
HY2_DIR="/etc/hysteria"
HY2_BIN="/usr/local/bin/hysteria"
HY2_SERVICE="/etc/systemd/system/hysteria-server.service"

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本必须以 root 权限运行${NC}"
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
        echo -e "${RED}无法检测操作系统${NC}"
        exit 1
    fi

    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            echo -e "${RED}不支持的架构: $ARCH${NC}"
            exit 1
            ;;
    esac
}

# 获取 IP 地址
get_ip() {
    IPV4=$(curl -s4m8 ip.sb 2>/dev/null || echo "N/A")
    IPV6=$(curl -s6m8 ip.sb 2>/dev/null || echo "N/A")
}

# 检查 Hysteria2 状态
check_hysteria_status() {
    if [[ -f $HY2_BIN ]] && systemctl is-active --quiet hysteria-server; then
        echo -e "${GREEN}运行中${NC}"
    elif [[ -f $HY2_BIN ]]; then
        echo -e "${YELLOW}已安装但未运行${NC}"
    else
        echo -e "${RED}未安装${NC}"
    fi
}

# 启用 BBR
enable_bbr() {
    echo -e "${BLUE}正在启用 BBR 拥塞控制...${NC}"
    
    if lsmod | grep -q bbr; then
        echo -e "${GREEN}BBR 已经启用${NC}"
        return
    fi
    
    # 修改 sysctl 配置
    cat >> /etc/sysctl.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    
    sysctl -p > /dev/null 2>&1
    
    if lsmod | grep -q bbr; then
        echo -e "${GREEN}BBR 启用成功${NC}"
    else
        echo -e "${YELLOW}BBR 启用可能需要重启系统${NC}"
    fi
}

# 配置防火墙
configure_firewall() {
    local port=$1
    
    echo -e "${BLUE}正在配置防火墙...${NC}"
    
    if command -v ufw &> /dev/null; then
        ufw allow $port/tcp > /dev/null 2>&1
        ufw allow $port/udp > /dev/null 2>&1
        echo -e "${GREEN}UFW 防火墙规则已添加${NC}"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=$port/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=$port/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        echo -e "${GREEN}FirewallD 防火墙规则已添加${NC}"
    else
        echo -e "${YELLOW}未检测到防火墙，跳过配置${NC}"
    fi
}

# 安装依赖
install_dependencies() {
    echo -e "${BLUE}正在安装必要依赖...${NC}"
    
    case $OS in
        ubuntu|debian)
            apt-get update > /dev/null 2>&1
            apt-get install -y curl wget tar openssl > /dev/null 2>&1
            ;;
        centos|rhel|rocky|alma)
            yum install -y curl wget tar openssl > /dev/null 2>&1
            ;;
        *)
            echo -e "${RED}不支持的操作系统: $OS${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${GREEN}依赖安装完成${NC}"
}

# 生成随机密码
generate_password() {
    openssl rand -base64 16 | tr -d "=+/" | cut -c1-16
}

# 生成随机端口
generate_port() {
    shuf -i 10000-65000 -n 1
}

# 生成自签名证书
generate_self_signed_cert() {
    echo -e "${BLUE}正在生成自签名证书...${NC}"
    
    mkdir -p $HY2_DIR
    
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout $HY2_DIR/server.key \
        -out $HY2_DIR/server.crt \
        -subj "/CN=amd.com" \
        -days 36500 > /dev/null 2>&1
    
    chmod 600 $HY2_DIR/server.key
    
    echo -e "${GREEN}证书生成完成${NC}"
}

# 安装 Hysteria2
install_hysteria() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  开始安装 Hysteria2${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    # 检测系统
    detect_system
    
    # 安装依赖
    install_dependencies
    
    # 启用 BBR
    enable_bbr
    
    # 生成配置参数
    PASSWORD=$(generate_password)
    PORT=$(generate_port)
    SNI="amd.com"
    
    # 生成证书
    generate_self_signed_cert
    
    # 下载 Hysteria2
    echo -e "${BLUE}正在下载 Hysteria2...${NC}"
    
    LATEST_VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    
    if [[ -z "$LATEST_VERSION" ]]; then
        echo -e "${RED}无法获取最新版本信息${NC}"
        exit 1
    fi
    
    DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/app%2Fv${LATEST_VERSION}/hysteria-linux-${ARCH}"
    
    wget -O $HY2_BIN $DOWNLOAD_URL > /dev/null 2>&1
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}下载失败${NC}"
        exit 1
    fi
    
    chmod +x $HY2_BIN
    echo -e "${GREEN}Hysteria2 下载完成 (v${LATEST_VERSION})${NC}"
    
    # 创建配置文件
    echo -e "${BLUE}正在创建配置文件...${NC}"
    
    cat > $HY2_CONFIG <<EOF
listen: :$PORT

tls:
  cert: $HY2_DIR/server.crt
  key: $HY2_DIR/server.key

auth:
  type: password
  password: $PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true

bandwidth:
  up: 50 mbps
  down: 100 mbps
EOF
    
    echo -e "${GREEN}配置文件创建完成${NC}"
    
    # 创建 systemd 服务
    echo -e "${BLUE}正在创建系统服务...${NC}"
    
    cat > $HY2_SERVICE <<EOF
[Unit]
Description=Hysteria Server
After=network.target

[Service]
Type=simple
ExecStart=$HY2_BIN server -c $HY2_CONFIG
Restart=on-failure
RestartSec=10s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable hysteria-server > /dev/null 2>&1
    systemctl start hysteria-server
    
    # 配置防火墙
    configure_firewall $PORT
    
    # 显示配置信息
    sleep 2
    clear
    show_config
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}  Hysteria2 安装完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# 显示配置信息
show_config() {
    if [[ ! -f $HY2_CONFIG ]]; then
        echo -e "${RED}配置文件不存在${NC}"
        return
    fi
    
    PASSWORD=$(grep "password:" $HY2_CONFIG | awk '{print $2}')
    PORT=$(grep "listen:" $HY2_CONFIG | sed 's/listen: ://')
    SNI="amd.com"
    
    get_ip
    SERVER_IP=${IPV4}
    
    if [[ "$SERVER_IP" == "N/A" ]]; then
        SERVER_IP=${IPV6}
    fi
    
    # 生成节点名称
    COUNTRY_CODE=$(echo $SERVER_IP | xargs -I {} curl -s "https://ipapi.co/{}/country_code/" 2>/dev/null || echo "XX")
    DATE_STR=$(date +%m%d)
    NODE_NAME="🌟Hysteria2-${COUNTRY_CODE}-${DATE_STR}"
    
    # 生成分享链接
    SHARE_LINK="hysteria2://${PASSWORD}@${SERVER_IP}:${PORT}/?insecure=true&sni=${SNI}#${NODE_NAME}"
    
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  Hysteria2 配置信息${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "${YELLOW}服务器地址:${NC} ${SERVER_IP}"
    echo -e "${YELLOW}端口:${NC} ${PORT}"
    echo -e "${YELLOW}密码:${NC} ${PASSWORD}"
    echo -e "${YELLOW}SNI:${NC} ${SNI}"
    echo -e "\n${PURPLE}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${NC}"
    echo -e "${GREEN}${SHARE_LINK}${NC}"
    
    echo -e "\n${PURPLE}⚔️ Clash Meta 配置:${NC}"
    echo -e "${GREEN}- { name: '${NODE_NAME}', type: hysteria2, server: ${SERVER_IP}, port: ${PORT}, password: ${PASSWORD}, sni: ${SNI}, skip-cert-verify: true, up: 50, down: 100 }${NC}"
    
    echo -e "\n${PURPLE}🌊 Surge 配置:${NC}"
    echo -e "${GREEN}${NODE_NAME} = hysteria2, ${SERVER_IP}, ${PORT}, password=${PASSWORD}, sni=${SNI}, skip-cert-verify=true${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# 管理菜单
manage_hysteria() {
    while true; do
        clear
        echo -e "${CYAN}========================================${NC}"
        echo -e "${CYAN}  Hysteria2 管理菜单${NC}"
        echo -e "${CYAN}========================================${NC}"
        echo -e "${GREEN}1.${NC} 启动 Hysteria2"
        echo -e "${GREEN}2.${NC} 停止 Hysteria2"
        echo -e "${GREEN}3.${NC} 重启 Hysteria2"
        echo -e "${GREEN}4.${NC} 查看状态"
        echo -e "${GREEN}5.${NC} 查看配置"
        echo -e "${GREEN}6.${NC} 查看日志"
        echo -e "${GREEN}7.${NC} 修改端口"
        echo -e "${GREEN}8.${NC} 修改密码"
        echo -e "${RED}0.${NC} 返回主菜单"
        echo -e "${CYAN}========================================${NC}"
        read -p "请选择操作 [0-8]: " choice
        
        case $choice in
            1)
                systemctl start hysteria-server
                echo -e "${GREEN}Hysteria2 已启动${NC}"
                sleep 2
                ;;
            2)
                systemctl stop hysteria-server
                echo -e "${YELLOW}Hysteria2 已停止${NC}"
                sleep 2
                ;;
            3)
                systemctl restart hysteria-server
                echo -e "${GREEN}Hysteria2 已重启${NC}"
                sleep 2
                ;;
            4)
                systemctl status hysteria-server
                read -p "按回车键继续..."
                ;;
            5)
                show_config
                read -p "按回车键继续..."
                ;;
            6)
                journalctl -u hysteria-server -n 50 --no-pager
                read -p "按回车键继续..."
                ;;
            7)
                change_port
                ;;
            8)
                change_password
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
    done
}

# 修改端口
change_port() {
    read -p "请输入新端口 (10000-65000): " NEW_PORT
    
    if [[ ! $NEW_PORT =~ ^[0-9]+$ ]] || [[ $NEW_PORT -lt 10000 ]] || [[ $NEW_PORT -gt 65000 ]]; then
        echo -e "${RED}无效端口${NC}"
        sleep 2
        return
    fi
    
    sed -i "s/listen: :.*/listen: :$NEW_PORT/" $HY2_CONFIG
    configure_firewall $NEW_PORT
    systemctl restart hysteria-server
    
    echo -e "${GREEN}端口已修改为 $NEW_PORT${NC}"
    sleep 2
}

# 修改密码
change_password() {
    read -p "请输入新密码 (留空自动生成): " NEW_PASSWORD
    
    if [[ -z "$NEW_PASSWORD" ]]; then
        NEW_PASSWORD=$(generate_password)
    fi
    
    sed -i "s/password: .*/password: $NEW_PASSWORD/" $HY2_CONFIG
    systemctl restart hysteria-server
    
    echo -e "${GREEN}密码已修改为 $NEW_PASSWORD${NC}"
    sleep 2
}

# 卸载 Hysteria2
uninstall_hysteria() {
    echo -e "${YELLOW}确定要卸载 Hysteria2 吗？ (y/n)${NC}"
    read -p "> " confirm
    
    if [[ "$confirm" != "y" ]]; then
        return
    fi
    
    echo -e "${BLUE}正在卸载 Hysteria2...${NC}"
    
    systemctl stop hysteria-server > /dev/null 2>&1
    systemctl disable hysteria-server > /dev/null 2>&1
    
    rm -f $HY2_BIN
    rm -f $HY2_SERVICE
    rm -rf $HY2_DIR
    
    systemctl daemon-reload
    
    echo -e "${GREEN}Hysteria2 已卸载${NC}"
    sleep 2
}

# 更新 Hysteria2
update_hysteria() {
    echo -e "${BLUE}正在检查更新...${NC}"
    
    LATEST_VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    CURRENT_VERSION=$($HY2_BIN version 2>/dev/null | grep -oP 'v\K[0-9.]+' || echo "未知")
    
    echo -e "${YELLOW}当前版本:${NC} $CURRENT_VERSION"
    echo -e "${YELLOW}最新版本:${NC} $LATEST_VERSION"
    
    if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
        echo -e "${GREEN}已是最新版本${NC}"
        sleep 2
        return
    fi
    
    echo -e "${BLUE}正在下载新版本...${NC}"
    
    DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/app%2Fv${LATEST_VERSION}/hysteria-linux-${ARCH}"
    
    wget -O ${HY2_BIN}.new $DOWNLOAD_URL > /dev/null 2>&1
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}下载失败${NC}"
        rm -f ${HY2_BIN}.new
        sleep 2
        return
    fi
    
    systemctl stop hysteria-server
    mv ${HY2_BIN}.new $HY2_BIN
    chmod +x $HY2_BIN
    systemctl start hysteria-server
    
    echo -e "${GREEN}更新完成！${NC}"
    sleep 2
}

# 主菜单
main_menu() {
    while true; do
        clear
        get_ip
        
        echo -e "${PURPLE}========================================${NC}"
        echo -e "${PURPLE}  Hysteria2 Management Script (v1.0)${NC}"
        echo -e "${PURPLE}========================================${NC}"
        echo -e "${CYAN}项目地址:${NC} https://github.com/everett7623/hy2"
        echo -e "${CYAN}博客地址:${NC} https://seedloc.com"
        echo -e "${CYAN}VPS博客:${NC} https://vpsknow.com"
        echo -e "${CYAN}论坛地址:${NC} https://nodeloc.com"
        echo -e "${PURPLE}========================================${NC}"
        echo -e "${YELLOW}服务器 IPv4:${NC} ${IPV4}"
        echo -e "${YELLOW}服务器 IPv6:${NC} ${IPV6}"
        echo -e "${YELLOW}Hysteria 2 状态:${NC} $(check_hysteria_status)"
        echo -e "${PURPLE}========================================${NC}"
        echo -e "${GREEN}1.${NC} 安装 Hysteria2(自签模式，无需域名解析)"
        echo -e "${GREEN}2.${NC} 管理 Hysteria2"
        echo -e "${GREEN}3.${NC} 卸载 Hysteria2"
        echo -e "${GREEN}4.${NC} 更新 Hysteria2 内核"
        echo -e "${RED}0.${NC} 退出脚本"
        echo -e "${PURPLE}========================================${NC}"
        read -p "请选择操作 [0-4]: " choice
        
        case $choice in
            1)
                install_hysteria
                read -p "按回车键继续..."
                ;;
            2)
                if [[ ! -f $HY2_BIN ]]; then
                    echo -e "${RED}Hysteria2 未安装${NC}"
                    sleep 2
                else
                    manage_hysteria
                fi
                ;;
            3)
                uninstall_hysteria
                ;;
            4)
                if [[ ! -f $HY2_BIN ]]; then
                    echo -e "${RED}Hysteria2 未安装${NC}"
                    sleep 2
                else
                    update_hysteria
                fi
                ;;
            0)
                echo -e "${GREEN}感谢使用！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
    done
}

# 脚本入口
check_root
detect_system
main_menu
