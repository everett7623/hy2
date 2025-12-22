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

# 强制设置 PATH 确保命令可用
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

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

# 辅助函数：按任意键继续 (兼容版)
pause_next() {
    echo ""
    echo -e "${YELLOW}按回车键继续...${NC}"
    read -r dummy_var
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
    else
        echo -e "${RED}无法检测操作系统${NC}"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${NC}"; exit 1 ;;
    esac
}

# 检测状态
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
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
}

# 下载 Hysteria2
download_hy2() {
    echo -e "${BLUE}正在获取最新版本...${NC}"
    local ver
    ver=$(curl -s --connect-timeout 5 https://api.github.com/repos/apernet/hysteria/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [[ -z "$ver" ]]; then
        echo -e "${RED}获取版本失败，使用默认备用版本。${NC}"
        # 如果获取失败，可以手动指定一个版本，或者提示用户检查网络
        return 1
    fi

    echo -e "${BLUE}最新版本: ${ver}${NC}"
    local url="https://github.com/apernet/hysteria/releases/download/${ver}/hysteria-linux-${ARCH}"
    
    if curl -L -o "$HY2_BIN" "$url"; then
        chmod +x "$HY2_BIN"
        return 0
    else
        return 1
    fi
}

# 生成随机字符串
gen_rand() {
    openssl rand -base64 16 | tr -d '/+=' | cut -c1-16
}

# 生成证书
gen_cert() {
    mkdir -p "$HY2_CERT_DIR"
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "${HY2_CERT_DIR}/server.key" \
        -out "${HY2_CERT_DIR}/server.crt" \
        -subj "/CN=bing.com" -days 36500 >/dev/null 2>&1
    chmod 600 "${HY2_CERT_DIR}/server.key" "${HY2_CERT_DIR}/server.crt"
}

# 安装函数
install_hy2() {
    install_deps
    enable_bbr
    
    if ! download_hy2; then
        echo -e "${RED}下载失败，请检查网络连接${NC}"
        pause_next
        return
    fi
    
    local port=$(shuf -i 10000-65535 -n 1)
    local password=$(gen_rand)
    
    echo ""
    # 修改：不使用 read -p，防止兼容性问题
    echo -n "请输入 SNI (回车默认 bing.com): "
    read -r sni_input
    local sni=${sni_input:-bing.com}
    
    mkdir -p "$HY2_DIR"
    gen_cert
    
    # 写入配置
    cat > "$HY2_CONFIG" <<EOF
listen: :$port

tls:
  cert: ${HY2_CERT_DIR}/server.crt
  key: ${HY2_CERT_DIR}/server.key

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://${sni}/
    rewriteHost: true
EOF
    chmod 600 "$HY2_CONFIG"
    
    # 写入服务
    cat > "$HY2_SERVICE" <<EOF
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
    
    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl start hysteria-server
    
    # 获取IP
    local ip=$(curl -s4m5 ip.sb || curl -s6m5 ip.sb)
    
    # 生成信息文件
    cat > "$HY2_INFO" <<EOF
服务器IP: ${ip}
端口: ${port}
密码: ${password}
SNI: ${sni}

链接:
hysteria2://${password}@${ip}:${port}/?insecure=1&sni=${sni}#Hysteria2
EOF

    echo ""
    echo -e "${GREEN}安装完成！${NC}"
    cat "$HY2_INFO"
    pause_next
}

# 管理函数
manage_hy2() {
    while true; do
        clear
        echo -e "${CYAN}--- 管理菜单 ---${NC}"
        echo "1. 启动"
        echo "2. 停止"
        echo "3. 重启"
        echo "4. 日志"
        echo "5. 配置信息"
        echo "0. 返回"
        echo ""
        # 修改：不使用 read -p
        echo -n "请选择: "
        read -r m_choice
        
        case $m_choice in
            1) systemctl start hysteria-server; echo "已启动"; pause_next ;;
            2) systemctl stop hysteria-server; echo "已停止"; pause_next ;;
            3) systemctl restart hysteria-server; echo "已重启"; pause_next ;;
            4) journalctl -u hysteria-server -n 20 --no-pager; pause_next ;;
            5) [[ -f $HY2_INFO ]] && cat "$HY2_INFO" || echo "无配置"; pause_next ;;
            0) break ;;
            *) echo "无效"; sleep 1 ;;
        esac
    done
}

# 卸载
uninstall_hy2() {
    echo -n "确认卸载? (y/n): "
    read -r confirm
    if [[ "$confirm" == "y" ]]; then
        systemctl stop hysteria-server
        systemctl disable hysteria-server
        rm -rf "$HY2_DIR" "$HY2_SERVICE" "$HY2_BIN"
        systemctl daemon-reload
        echo "卸载完成"
    fi
    pause_next
}

# 主循环
main() {
    check_root
    while true; do
        clear
        echo -e "${BLUE}=== Hysteria2 脚本 (v1.0 Stable) ===${NC}"
        echo -e "状态: $(get_status)"
        echo ""
        echo " 1. 安装"
        echo " 2. 管理"
        echo " 3. 卸载"
        echo " 0. 退出"
        echo ""
        
        # 核心修改：使用 echo -n + read -r 避免兼容性问题
        echo -n "请输入选项 [0-3]: "
        read -r choice
        
        # 增加判空处理，防止直接回车导致死循环
        if [[ -z "$choice" ]]; then
            continue
        fi
        
        case $choice in
            1) install_hy2 ;;
            2) manage_hy2 ;;
            3) uninstall_hy2 ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选项，请重新输入${NC}"; sleep 1 ;;
        esac
    done
}

main
