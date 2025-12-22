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
# 更新内容：修复死循环问题、清理特殊字符、优化交互逻辑
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

# 辅助函数：按任意键继续
pause_next() {
    echo ""
    echo -e "${YELLOW}按回车键继续...${NC}"
    read -r
}

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
    IPV4=$(curl -s4m5 ip.sb 2>/dev/null || echo "N/A")
    IPV6=$(curl -s6m5 ip.sb 2>/dev/null || echo "N/A")
}

# 检测安装状态
get_status() {
    if [[ ! -f $HY2_BIN ]]; then
        echo -e "${RED}未安装${NC}"
    elif systemctl is-active --quiet hysteria-server 2>/dev/null; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${YELLOW}已安装 (已停止)${NC}"
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
        ufw allow "$port"/tcp >/dev/null 2>&1
        ufw allow "$port"/udp >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port="$port"/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
}

# 下载 Hysteria2
download_hy2() {
    echo -e "${BLUE}正在获取最新版本信息...${NC}"
    # 增加超时和错误处理
    local ver
    ver=$(curl -s --connect-timeout 5 https://api.github.com/repos/apernet/hysteria/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [[ -z "$ver" ]]; then
        echo -e "${RED}获取版本失败，可能是网络问题或 API 限制。${NC}"
        return 1
    fi

    echo -e "${BLUE}发现最新版本: ${ver}${NC}"
    local url="https://github.com/apernet/hysteria/releases/download/${ver}/hysteria-linux-${ARCH}"
    
    echo -e "${BLUE}正在下载...${NC}"
    if curl -L -o "$HY2_BIN" "$url"; then
        chmod +x "$HY2_BIN"
        echo -e "${GREEN}下载成功${NC}"
        return 0
    else
        echo -e "${RED}下载失败${NC}"
        return 1
    fi
}

# 生成证书
gen_cert() {
    echo -e "${BLUE}生成自签证书...${NC}"
    mkdir -p "$HY2_CERT_DIR"
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "${HY2_CERT_DIR}/server.key" \
        -out "${HY2_CERT_DIR}/server.crt" \
        -subj "/CN=amd.com" -days 36500 >/dev/null 2>&1
    chmod 600 "${HY2_CERT_DIR}/server.key" "${HY2_CERT_DIR}/server.crt"
}

# 安装流程
install_hy2() {
    echo ""
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}  开始安装 Hysteria2${NC}"
    echo -e "${CYAN}================================${NC}"
    
    if [[ -f $HY2_BIN ]]; then
        echo -e "${YELLOW}检测到已安装 Hysteria2${NC}"
        read -p "是否强制重新安装？(y/n): " choice
        if [[ $choice != "y" ]]; then
            return
        fi
        systemctl stop hysteria-server 2>/dev/null
        rm -rf $HY2_DIR $HY2_BIN $HY2_SERVICE
    fi
    
    install_deps
    enable_bbr
    
    if ! download_hy2; then
        echo -e "${RED}安装中止。${NC}"
        pause_next
        return
    fi
    
    # 配置参数
    PORT=$(gen_port)
    PASSWORD=$(gen_password)
    
    echo ""
    read -p "请输入 SNI (回车默认: amd.com): " input_sni
    SNI=${input_sni:-amd.com}
    
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
    
    open_firewall "$PORT"
    
    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl start hysteria-server
    
    sleep 2
    
    if systemctl is-active --quiet hysteria-server; then
        echo ""
        echo -e "${GREEN}安装成功！${NC}"
        
        local ip
        ip=$(curl -s4m5 ip.sb 2>/dev/null)
        [[ -z $ip ]] && ip=$(curl -s6m5 ip.sb 2>/dev/null)
        
        local name="Hysteria2-VPS"
        
        # 保存配置信息到文件
        cat > $HY2_INFO <<EOF
服务器 IP: ${ip}
端口: ${PORT}
密码: ${PASSWORD}
SNI: ${SNI}

--- 客户端配置链接 ---

v2rayN / NekoBox / Shadowrocket:
hysteria2://${PASSWORD}@${ip}:${PORT}/?insecure=1&sni=${SNI}#${name}

Clash Meta:
{ name: '${name}', type: hysteria2, server: ${ip}, port: ${PORT}, password: '${PASSWORD}', sni: '${SNI}', skip-cert-verify: true }
EOF
        
        echo -e "${CYAN}--- 配置详情 ---${NC}"
        cat $HY2_INFO
    else
        echo -e "${RED}启动失败，请检查日志${NC}"
        journalctl -u hysteria-server -n 20 --no-pager
    fi
    
    pause_next
}

# 管理菜单
manage_hy2() {
    if [[ ! -f $HY2_BIN ]]; then
        echo -e "${RED}请先安装 Hysteria2${NC}"
        pause_next
        return
    fi
    
    while true; do
        clear
        echo -e "${CYAN}================================${NC}"
        echo -e "${CYAN}  Hysteria2 管理面板${NC}"
        echo -e "${CYAN}================================${NC}"
        echo " 1. 启动服务"
        echo " 2. 停止服务"
        echo " 3. 重启服务"
        echo " 4. 查看运行状态"
        echo " 5. 查看连接配置"
        echo " 6. 查看运行日志"
        echo " 0. 返回主菜单"
        echo ""
        read -p "请选择 [0-6]: " choice
        
        case $choice in
            1) systemctl start hysteria-server; echo -e "${GREEN}指令已发送${NC}"; pause_next ;;
            2) systemctl stop hysteria-server; echo -e "${GREEN}指令已发送${NC}"; pause_next ;;
            3) systemctl restart hysteria-server; echo -e "${GREEN}指令已发送${NC}"; pause_next ;;
            4) systemctl status hysteria-server --no-pager; pause_next ;;
            5) 
               if [[ -f $HY2_INFO ]]; then cat "$HY2_INFO"; else echo "配置文件不存在"; fi
               pause_next 
               ;;
            6) journalctl -u hysteria-server -n 50 --no-pager; pause_next ;;
            0) break ;;
            *) echo -e "${RED}无效输入${NC}"; sleep 1 ;;
        esac
    done
}

# 卸载
uninstall_hy2() {
    if [[ ! -f $HY2_BIN ]]; then
        echo -e "${RED}未安装 Hysteria2${NC}"
        pause_next
        return
    fi
    
    echo -e "${RED}警告: 将删除所有配置和程序${NC}"
    read -p "确认卸载？(输入 y 确认): " choice
    
    if [[ $choice == "y" ]]; then
        systemctl stop hysteria-server 2>/dev/null
        systemctl disable hysteria-server 2>/dev/null
        rm -f $HY2_SERVICE $HY2_BIN
        rm -rf $HY2_DIR
        systemctl daemon-reload
        echo -e "${GREEN}卸载完成${NC}"
    else
        echo -e "${YELLOW}已取消${NC}"
    fi
    pause_next
}

# 主菜单
show_menu() {
    clear
    # 获取IP时不显示错误信息，避免刷屏
    IPV4=$(curl -s4m2 ip.sb 2>/dev/null || echo "N/A")
    
    echo -e "${BLUE}======================================${NC}"
    echo -e "${CYAN}Hysteria2 管理脚本 (v1.0 Fix)${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo "作者: Jensfrank"
    echo "状态: $(get_status)"
    echo -e "IPv4: ${CYAN}${IPV4}${NC}"
    echo ""
    echo " 1. 安装 Hysteria2"
    echo " 2. 管理 Hysteria2 (启动/停止/日志)"
    echo " 3. 卸载 Hysteria2"
    echo " 0. 退出脚本"
    echo ""
    echo -e "${BLUE}======================================${NC}"
}

# 主循环
main() {
    check_root
    detect_system
    
    while true; do
        show_menu
        read -p "请输入选项 [0-3]: " choice
        case $choice in
            1) install_hy2 ;;
            2) manage_hy2 ;;
            3) uninstall_hy2 ;;
            0) echo -e "${GREEN}退出脚本${NC}"; exit 0 ;;
            *) echo -e "${RED}无效选项，请重新输入${NC}"; sleep 1 ;;
        esac
    done
}

# 执行入口
main
