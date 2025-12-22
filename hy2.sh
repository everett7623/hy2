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
CYAN='\033[0;36m'
NC='\033[0m'

# 配置路径
HY2_DIR="/etc/hysteria2"
HY2_BIN="/usr/local/bin/hysteria"
HY2_CONFIG="${HY2_DIR}/config.yaml"
HY2_CERT_DIR="${HY2_DIR}/certs"
HY2_SERVICE="/etc/systemd/system/hysteria-server.service"
HY2_INFO="${HY2_DIR}/client_info.txt"

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本需要 root 权限运行${NC}"
        exit 1
    fi
}

# 检测系统信息
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
    else
        echo -e "${RED}无法检测操作系统${NC}"
        exit 1
    fi

    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${NC}"; exit 1 ;;
    esac
}

# 检测网络
get_ip() {
    IPV4=$(curl -s4m8 ip.sb 2>/dev/null || echo "N/A")
    IPV6=$(curl -s6m8 ip.sb 2>/dev/null || echo "N/A")
}

# 检测状态
get_status() {
    if [[ ! -f $HY2_BIN ]]; then
        echo -e "${RED}未安装${NC}"
    elif systemctl is-active --quiet hysteria-server 2>/dev/null; then
        echo -e "${GREEN}已安装 - 运行中${NC}"
    else
        echo -e "${YELLOW}已安装 - 已停止${NC}"
    fi
}

# 安装依赖
install_deps() {
    echo -e "${BLUE}正在安装依赖...${NC}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y curl wget openssl >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget openssl >/dev/null 2>&1
    fi
}

# 启用 BBR
enable_bbr() {
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) != "bbr" ]]; then
        echo -e "${BLUE}正在启用 BBR...${NC}"
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
}

# 生成随机端口
gen_port() {
    shuf -i 10000-65535 -n 1
}

# 生成随机密码
gen_password() {
    openssl rand -base64 16 | tr -d '/+=' | cut -c1-16
}

# 开放防火墙
open_firewall() {
    local port=$1
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $port/tcp >/dev/null 2>&1
        ufw allow $port/udp >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$port/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=$port/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
}

# 下载 Hysteria2
download_hy2() {
    echo -e "${BLUE}正在下载 Hysteria2...${NC}"
    local ver=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    local url="https://github.com/apernet/hysteria/releases/download/${ver}/hysteria-linux-${ARCH}"
    
    if curl -L -o $HY2_BIN $url 2>/dev/null; then
        chmod +x $HY2_BIN
        echo -e "${GREEN}下载成功${NC}"
    else
        echo -e "${RED}下载失败${NC}"
        exit 1
    fi
}

# 生成证书
gen_cert() {
    echo -e "${BLUE}生成自签证书...${NC}"
    mkdir -p $HY2_CERT_DIR
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout ${HY2_CERT_DIR}/server.key \
        -out ${HY2_CERT_DIR}/server.crt \
        -subj "/CN=amd.com" -days 36500 >/dev/null 2>&1
    chmod 600 ${HY2_CERT_DIR}/server.key ${HY2_CERT_DIR}/server.crt
}

# 安装 Hysteria2
install_hy2() {
    echo ""
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}  开始安装 Hysteria2${NC}"
    echo -e "${CYAN}================================${NC}"
    echo ""
    
    if [[ -f $HY2_BIN ]]; then
        echo -e "${YELLOW}已安装 Hysteria2${NC}"
        read -p "是否重新安装？(y/n): " choice
        if [[ $choice != "y" ]]; then
            return
        fi
        systemctl stop hysteria-server 2>/dev/null
        rm -rf $HY2_DIR $HY2_BIN $HY2_SERVICE
    fi
    
    install_deps
    enable_bbr
    download_hy2
    
    # 配置参数
    PORT=$(gen_port)
    PASSWORD=$(gen_password)
    
    echo ""
    read -p "请输入 SNI (默认: amd.com): " SNI
    SNI=${SNI:-amd.com}
    
    mkdir -p $HY2_DIR
    gen_cert
    
    # 生成配置
    cat > $HY2_CONFIG <<EOF
listen: :$PORT

tls:
  cert: ${HY2_CERT_DIR}/server.crt
  key: ${HY2_CERT_DIR}/server.key

auth:
  type: password
  password: $PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://${SNI}/
    rewriteHost: true
EOF
    chmod 600 $HY2_CONFIG
    
    # systemd 服务
    cat > $HY2_SERVICE <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
ExecStart=$HY2_BIN server -c $HY2_CONFIG
Restart=on-failure
RestartSec=10
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    open_firewall $PORT
    
    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl start hysteria-server
    
    sleep 2
    
    if systemctl is-active --quiet hysteria-server; then
        echo ""
        echo -e "${GREEN}================================${NC}"
        echo -e "${GREEN}  安装成功！${NC}"
        echo -e "${GREEN}================================${NC}"
        
        # 获取 IP
        local ip=$(curl -s4m8 ip.sb 2>/dev/null)
        [[ -z $ip ]] && ip=$(curl -s6m8 ip.sb 2>/dev/null)
        
        local name="Hysteria2-VPS"
        
        # 保存配置
        cat > $HY2_INFO <<EOF
服务器: ${ip}
端口: ${PORT}
密码: ${PASSWORD}
SNI: ${SNI}

V2rayN/NekoBox/Shadowrocket:
hysteria2://${PASSWORD}@${ip}:${PORT}/?insecure=1&sni=${SNI}#${name}

Clash Meta:
{ name: '${name}', type: hysteria2, server: ${ip}, port: ${PORT}, password: '${PASSWORD}', sni: '${SNI}', skip-cert-verify: true }

Surge:
${name} = hysteria2, ${ip}, ${PORT}, password=${PASSWORD}, sni=${SNI}, skip-cert-verify=true
EOF
        
        echo ""
        cat $HY2_INFO
    else
        echo -e "${RED}启动失败${NC}"
        journalctl -u hysteria-server -n 20 --no-pager
    fi
    
    echo ""
    echo -e "${YELLOW}按回车返回菜单...${NC}"
    read
}

# 管理功能
manage_hy2() {
    if [[ ! -f $HY2_BIN ]]; then
        echo ""
        echo -e "${RED}请先安装 Hysteria2${NC}"
        sleep 2
        return
    fi
    
    while true; do
        clear
        echo ""
        echo -e "${CYAN}================================${NC}"
        echo -e "${CYAN}  Hysteria2 管理${NC}"
        echo -e "${CYAN}================================${NC}"
        echo ""
        echo " 1. 启动服务"
        echo " 2. 停止服务"
        echo " 3. 重启服务"
        echo " 4. 查看状态"
        echo " 5. 查看配置"
        echo " 6. 查看日志"
        echo " 0. 返回主菜单"
        echo ""
        read -p "请选择 [0-6]: " choice
        
        case $choice in
            1)
                systemctl start hysteria-server
                echo ""
                echo -e "${GREEN}已启动${NC}"
                sleep 2
                ;;
            2)
                systemctl stop hysteria-server
                echo ""
                echo -e "${GREEN}已停止${NC}"
                sleep 2
                ;;
            3)
                systemctl restart hysteria-server
                echo ""
                echo -e "${GREEN}已重启${NC}"
                sleep 2
                ;;
            4)
                clear
                systemctl status hysteria-server --no-pager
                echo ""
                read -p "按回车继续..."
                ;;
            5)
                clear
                if [[ -f $HY2_INFO ]]; then
                    echo ""
                    cat $HY2_INFO
                else
                    echo ""
                    echo -e "${RED}配置文件不存在${NC}"
                fi
                echo ""
                read -p "按回车继续..."
                ;;
            6)
                clear
                journalctl -u hysteria-server -n 50 --no-pager
                echo ""
                read -p "按回车继续..."
                ;;
            0)
                break
                ;;
            *)
                echo ""
                echo -e "${RED}无效选择${NC}"
                sleep 1
                ;;
        esac
    done
}

# 卸载
uninstall_hy2() {
    if [[ ! -f $HY2_BIN ]]; then
        echo -e "${RED}未安装 Hysteria2${NC}"
        sleep 2
        return
    fi
    
    echo ""
    echo -e "${RED}警告: 将删除所有配置${NC}"
    read -p "确认卸载？(yes/no): " choice
    
    if [[ $choice == "yes" ]]; then
        systemctl stop hysteria-server 2>/dev/null
        systemctl disable hysteria-server 2>/dev/null
        rm -f $HY2_SERVICE $HY2_BIN
        rm -rf $HY2_DIR
        systemctl daemon-reload
        echo -e "${GREEN}卸载完成${NC}"
    else
        echo -e "${YELLOW}已取消${NC}"
    fi
    
    sleep 2
}

# 显示菜单
show_menu() {
    clear
    get_ip
    
    echo -e "${BLUE}======================================${NC}"
    echo -e "${CYAN}Hysteria2 Management Script (v1.0)${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo "项目地址: https://github.com/everett7623/hy2"
    echo "作者: Jensfrank"
    echo "Seeloc博客: https://seedloc.com"
    echo "VPSknow网站: https://vpsknow.com"
    echo "Nodeloc论坛: https://nodeloc.com"
    echo "更新日期: 2025-12-22"
    echo ""
    echo -e "服务器 IPv4: ${CYAN}${IPV4}${NC}"
    echo -e "服务器 IPv6: ${CYAN}${IPV6}${NC}"
    echo -e "Hysteria 2 状态: $(get_status)"
    echo -e "${BLUE}======================================${NC}"
    echo ""
    echo " 1. 安装 Hysteria2 (自签模式，无需域名解析)"
    echo " 2. 管理 Hysteria2"
    echo " 3. 卸载 Hysteria2"
    echo " 0. 退出脚本"
    echo ""
    echo -e "${BLUE}======================================${NC}"
}

# 主函数
main() {
    check_root
    detect_system
    
    while true; do
        show_menu
        
        echo ""
        read -p "请选择操作 [0-3]: " choice
        
        case $choice in
            1) install_hy2 ;;
            2) manage_hy2 ;;
            3) uninstall_hy2 ;;
            0) echo ""; echo -e "${GREEN}再见！${NC}"; exit 0 ;;
            *) echo ""; echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# 启动
main
