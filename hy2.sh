#!/bin/bash
#====================================================================================
# 项目：Hysteria2 Management Script
# 作者：Jensfrank
# 版本：v1.0.1 (修复IP获取问题)
# GitHub: https://github.com/everett7623/hy2
# Seeloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
#
# 更新日期: 2025-12-22
#====================================================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

# --- 变量定义 ---
HY_BIN="/usr/local/bin/hysteria"
HY_CONFIG="/etc/hysteria/config.yaml"
HY_CERT_DIR="/etc/hysteria/cert"
SERVICE_FILE="/etc/systemd/system/hysteria-server.service"

# --- 基础检查 ---
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 请使用 root 权限运行此脚本 (sudo bash hy2.sh)${PLAIN}"
        exit 1
    fi
}

check_sys() {
    if [ -f /etc/redhat-release ]; then
        RELEASE="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        RELEASE="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        RELEASE="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        RELEASE="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        RELEASE="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        RELEASE="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        RELEASE="centos"
    else
        echo -e "${RED}未检测到支持的系统版本，脚本可能无法正常运行。${PLAIN}"
    fi
}

install_dependencies() {
    # 静默安装，减少干扰
    if [ "${RELEASE}" == "centos" ]; then
        yum update -y >/dev/null 2>&1
        yum install -y curl wget openssl jq >/dev/null 2>&1
    else
        apt update -y >/dev/null 2>&1
        apt install -y curl wget openssl jq >/dev/null 2>&1
    fi
}

# --- 获取 IP (修复版) ---
get_ip() {
    # 尝试源 1: ip.sb (添加 User-Agent 避免 403)
    IPV4=$(curl -s4m8 --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://ip.sb)
    # 如果返回结果包含 html 标签或为空，说明被拦截，切换备用源
    if [[ "$IPV4" == *"html"* ]] || [[ -z "$IPV4" ]]; then
        IPV4=$(curl -s4m8 https://api.ipify.org)
    fi

    IPV6=$(curl -s6m8 --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://ip.sb)
    if [[ "$IPV6" == *"html"* ]] || [[ -z "$IPV6" ]]; then
        IPV6=$(curl -s6m8 https://api64.ipify.org)
    fi
    
    [[ -z "$IPV4" ]] && IPV4="N/A"
    [[ -z "$IPV6" ]] && IPV6="N/A"
}

# --- 安装 Hysteria 2 ---
install_hy2() {
    echo -e "${YELLOW}正在安装依赖...${PLAIN}"
    install_dependencies
    
    # 1. 下载核心
    echo -e "${YELLOW}正在下载 Hysteria2 核心...${PLAIN}"
    LAST_VERSION=$(curl -Ls "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$LAST_VERSION" ]]; then
        echo -e "${RED}无法获取 Hysteria2 最新版本，请检查网络连接。${PLAIN}"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${LAST_VERSION}/hysteria-linux-amd64" ;;
        aarch64) DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${LAST_VERSION}/hysteria-linux-arm64" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac

    wget -O "$HY_BIN" "$DOWNLOAD_URL"
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载失败，请检查网络。${PLAIN}"
        exit 1
    fi
    chmod +x "$HY_BIN"
    echo -e "${GREEN}Hysteria2 核心安装成功 ($LAST_VERSION)${PLAIN}"

    # 2. 创建配置目录
    mkdir -p /etc/hysteria
    mkdir -p "$HY_CERT_DIR"

    # 3. 生成自签证书
    echo -e "${YELLOW}正在生成自签名证书 (有效期 10 年)...${PLAIN}"
    openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -sha256 \
        -keyout "$HY_CERT_DIR/server.key" -out "$HY_CERT_DIR/server.crt" \
        -subj "/C=US/ST=California/L=San Francisco/O=Hysteria/OU=IT/CN=bing.com" >/dev/null 2>&1
    
    # 4. 配置参数交互
    echo -e "\n${SKYBLUE}--- 配置 Hysteria2 ---${PLAIN}"
    
    read -p "请输入监听端口 [默认 443]: " PORT
    [[ -z "$PORT" ]] && PORT="443"
    
    read -p "请设置连接密码 [留空自动生成]: " PASSWORD
    if [[ -z "$PASSWORD" ]]; then
        PASSWORD=$(openssl rand -base64 12)
        echo -e "已生成随机密码: ${GREEN}$PASSWORD${PLAIN}"
    fi
    
    SNI="amd.com"

    # 5. 写入配置文件 (YAML)
    cat > "$HY_CONFIG" <<EOF
listen: :$PORT

tls:
  cert: $HY_CERT_DIR/server.crt
  key: $HY_CERT_DIR/server.key

auth:
  type: password
  password: "$PASSWORD"

bandwidth:
  up: 50 mbps
  down: 100 mbps

masquerade:
  type: proxy
  proxy:
    url: https://$SNI/
    rewriteHost: true
EOF

    # 6. 配置 Systemd 服务
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=$HY_BIN server -c $HY_CONFIG
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # 7. 启动服务
    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server

    sleep 2
    if systemctl is-active --quiet hysteria-server; then
        echo -e "${GREEN}Hysteria2 安装并启动成功！${PLAIN}"
        show_config
    else
        echo -e "${RED}服务启动失败，请检查日志: journalctl -u hysteria-server -n 20${PLAIN}"
    fi
}

# --- 显示配置 ---
show_config() {
    if [ ! -f "$HY_CONFIG" ]; then
        echo -e "${RED}未找到配置文件，请先安装。${PLAIN}"
        return
    fi

    PORT=$(grep "listen:" "$HY_CONFIG" | awk -F: '{print $NF}' | tr -d ' ')
    PASSWORD=$(grep "password:" "$HY_CONFIG" | awk -F'"' '{print $2}')
    SNI="amd.com"
    
    HOST_IP="$IPV4"
    if [[ "$HOST_IP" == "N/A" ]]; then
        HOST_IP="[$IPV6]"
    fi
    
    NODE_NAME="🌟Hysteria2-$(date +%m%d)"
    SHARE_LINK="hysteria2://${PASSWORD}@${HOST_IP}:${PORT}/?insecure=1&sni=${SNI}#${NODE_NAME}"

    echo -e "\n${SKYBLUE}================ 配置信息 =================${PLAIN}"
    echo -e "${YELLOW}### Hysteria2配置信息：${PLAIN}"
    
    echo -e "\n${GREEN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${PLAIN}"
    echo -e "$SHARE_LINK"

    echo -e "\n${GREEN}⚔️ Clash Meta 配置:${PLAIN}"
    echo -e "- { name: '${NODE_NAME}', type: hysteria2, server: ${HOST_IP}, port: ${PORT}, password: ${PASSWORD}, sni: ${SNI}, skip-cert-verify: true, up: 50, down: 100 }"

    echo -e "\n${GREEN}🌊 Surge 配置:${PLAIN}"
    echo -e "${NODE_NAME} = hysteria2, ${HOST_IP}, ${PORT}, password=${PASSWORD}, sni=${SNI}, skip-cert-verify=true"
    
    echo -e "${SKYBLUE}===========================================${PLAIN}"
    echo -e "提示：由于使用自签证书，客户端必须开启 ${RED}允许不安全连接(insecure/skip-cert-verify)${PLAIN}"
    echo ""
    read -p "按回车键返回主菜单..."
}

# --- 管理功能 ---
manage_hy2() {
    echo -e "\n${SKYBLUE}--- 管理 Hysteria2 ---${PLAIN}"
    echo -e "1. 查看配置信息"
    echo -e "2. 重启服务"
    echo -e "3. 停止服务"
    echo -e "4. 查看运行日志"
    echo -e "0. 返回主菜单"
    read -p "请选择: " opt
    case $opt in
        1) show_config ;;
        2) systemctl restart hysteria-server && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
        3) systemctl stop hysteria-server && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
        4) journalctl -u hysteria-server -n 20 --no-pager ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}" ;;
    esac
}

# --- 卸载 ---
uninstall_hy2() {
    echo -e "${RED}确定要卸载 Hysteria2 吗？[y/N]${PLAIN}"
    read -r -p "" confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        systemctl stop hysteria-server
        systemctl disable hysteria-server
        rm -f "$SERVICE_FILE"
        rm -f "$HY_BIN"
        rm -rf /etc/hysteria
        systemctl daemon-reload
        echo -e "${GREEN}Hysteria2 已彻底卸载。${PLAIN}"
    else
        echo "已取消。"
    fi
}

# --- 主菜单 ---
main_menu() {
    clear
    check_root
    check_sys
    get_ip
    
    if [ -f "$HY_BIN" ]; then
        if systemctl is-active --quiet hysteria-server; then
             STATUS="${GREEN}已安装 (运行中)${PLAIN}"
        else
             STATUS="${RED}已安装 (未运行)${PLAIN}"
        fi
    else
        STATUS="${RED}未安装${PLAIN}"
    fi

    echo -e "Hysteria2 Management Script (v1.0.1)"
    echo -e "项目地址：https://github.com/everett7623/hy2"
    echo -e "作者：Jensfrank"
    echo -e "GitHub: https://github.com/everett7623/hy2"
    echo -e "Seeloc博客: https://seedloc.com"
    echo -e "VPSknow网站：https://vpsknow.com"
    echo -e "Nodeloc论坛: https://nodeloc.com"
    echo -e "更新日期: 2025-12-22"
    echo ""
    echo -e "服务器 IPv4: ${SKYBLUE}$IPV4${PLAIN}"
    echo -e "服务器 IPv6: ${SKYBLUE}$IPV6${PLAIN}"
    echo -e "Hysteria 2 状态: $STATUS"
    echo ""
    echo -e "================================================"
    echo -e " 1. 安装 Hysteria2 (自签模式，无需域名解析)"
    echo -e " 2. 管理 Hysteria2"
    echo -e " 3. 卸载 Hysteria2"
    echo -e " 0. 退出脚本"
    echo -e "================================================"
    read -p "请输入选项 [0-3]: " choice

    case $choice in
        1) install_hy2 ;;
        2) manage_hy2 ;;
        3) uninstall_hy2 ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效输入，请重试${PLAIN}"; sleep 1; main_menu ;;
    esac
    
    main_menu
}

main_menu
