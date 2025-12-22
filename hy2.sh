#!/bin/bash
#====================================================================================
# 项目：Hysteria2 Management Script
# 作者：Jensfrank
# 版本：v1.0.4 (纯净版：移除IP自动检测，彻底解决刷屏问题)
# GitHub: https://github.com/everett7623/hy2
# Seeloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2025-12-22
#====================================================================================

# --- 自动修复 Windows 换行符 ---
if grep -q $'\r' "$0"; then
    sed -i 's/\r$//' "$0"
    exec "$0" "$@"
fi

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
    else
        echo -e "${RED}未检测到支持的系统版本${PLAIN}"
    fi
}

install_dependencies() {
    if [ "${RELEASE}" == "centos" ]; then
        yum update -y >/dev/null 2>&1
        yum install -y curl wget openssl jq >/dev/null 2>&1
    else
        apt update -y >/dev/null 2>&1
        apt install -y curl wget openssl jq >/dev/null 2>&1
    fi
}

# --- 安装 Hysteria 2 ---
install_hy2() {
    echo -e "${YELLOW}正在安装依赖...${PLAIN}"
    install_dependencies
    
    echo -e "${YELLOW}正在下载 Hysteria2 核心...${PLAIN}"
    LAST_VERSION=$(curl -Ls "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$LAST_VERSION" ]]; then
        echo -e "${RED}无法获取版本，请检查网络。${PLAIN}"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${LAST_VERSION}/hysteria-linux-amd64" ;;
        aarch64) DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${LAST_VERSION}/hysteria-linux-arm64" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac

    wget -O "$HY_BIN" "$DOWNLOAD_URL"
    chmod +x "$HY_BIN"
    
    mkdir -p /etc/hysteria
    mkdir -p "$HY_CERT_DIR"

    echo -e "${YELLOW}生成自签名证书...${PLAIN}"
    openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -sha256 \
        -keyout "$HY_CERT_DIR/server.key" -out "$HY_CERT_DIR/server.crt" \
        -subj "/C=US/ST=California/L=San Francisco/O=Hysteria/OU=IT/CN=bing.com" >/dev/null 2>&1
    
    echo -e "\n${SKYBLUE}--- 配置 Hysteria2 ---${PLAIN}"
    read -r -p "请输入监听端口 [默认 443]: " PORT
    [[ -z "$PORT" ]] && PORT="443"
    
    read -r -p "请设置连接密码 [留空自动生成]: " PASSWORD
    if [[ -z "$PASSWORD" ]]; then
        PASSWORD=$(openssl rand -base64 12)
    fi
    SNI="amd.com"

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

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    
    echo -e "${GREEN}安装完成！${PLAIN}"
    read -r -p "按回车键查看配置..." temp
    show_config
}

# --- 显示配置 ---
show_config() {
    if [ ! -f "$HY_CONFIG" ]; then
        echo -e "${RED}未找到配置文件。${PLAIN}"
        read -r -p "按回车返回..." temp
        return
    fi

    PORT=$(grep "listen:" "$HY_CONFIG" | awk -F: '{print $NF}' | tr -d ' ')
    PASSWORD=$(grep "password:" "$HY_CONFIG" | awk -F'"' '{print $2}')
    SNI="amd.com"
    
    # 既然去除了自动获取IP，这里尝试用简单命令获取本地IP，或者提示用户手动填写
    # 尝试获取本机 IP (仅作为显示参考)
    HOST_IP=$(hostname -I | awk '{print $1}')
    if [[ -z "$HOST_IP" ]]; then HOST_IP="请手动填入服务器IP"; fi
    
    NODE_NAME="🌟Hysteria2-$(date +%m%d)"
    SHARE_LINK="hysteria2://${PASSWORD}@${HOST_IP}:${PORT}/?insecure=1&sni=${SNI}#${NODE_NAME}"

    echo -e "\n${SKYBLUE}================ 配置信息 =================${PLAIN}"
    echo -e "${GREEN}🚀 分享链接:${PLAIN} $SHARE_LINK"
    echo -e "${GREEN}⚔️ Clash Meta:${PLAIN} { name: '${NODE_NAME}', type: hysteria2, server: ${HOST_IP}, port: ${PORT}, password: ${PASSWORD}, sni: ${SNI}, skip-cert-verify: true, up: 50, down: 100 }"
    echo -e "${GREEN}🌊 Surge:${PLAIN} ${NODE_NAME} = hysteria2, ${HOST_IP}, ${PORT}, password=${PASSWORD}, sni=${SNI}, skip-cert-verify=true"
    echo -e "${SKYBLUE}===========================================${PLAIN}"
    echo -e "注意：如果IP显示为内网IP，请在客户端中替换为您的公网IP。"
    echo ""
    read -r -p "按回车键返回主菜单..." temp
}

# --- 管理功能 ---
manage_hy2() {
    clear
    echo -e "\n${SKYBLUE}--- 管理 Hysteria2 ---${PLAIN}"
    echo -e "1. 查看配置"
    echo -e "2. 重启服务"
    echo -e "3. 停止服务"
    echo -e "4. 查看日志"
    echo -e "0. 返回"
    read -r -p "请选择: " opt
    case $opt in
        1) show_config ;;
        2) systemctl restart hysteria-server && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
        3) systemctl stop hysteria-server && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
        4) journalctl -u hysteria-server -n 20 --no-pager; read -r -p "按回车继续..." temp ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}" ;;
    esac
}

# --- 卸载 ---
uninstall_hy2() {
    read -r -p "确定卸载? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        systemctl stop hysteria-server
        systemctl disable hysteria-server
        rm -f "$SERVICE_FILE" "$HY_BIN"
        rm -rf /etc/hysteria
        systemctl daemon-reload
        echo -e "${GREEN}已卸载。${PLAIN}"
        sleep 1
    fi
}

# --- 主菜单 ---
main_menu() {
    while true; do
        clear
        if [ -f "$HY_BIN" ]; then
            if systemctl is-active --quiet hysteria-server; then
                STATUS="${GREEN}运行中${PLAIN}"
            else
                STATUS="${RED}已停止${PLAIN}"
            fi
        else
            STATUS="${RED}未安装${PLAIN}"
        fi

        echo -e "Hysteria2 Management Script (v1.0.4)"
        echo -e "项目地址：https://github.com/everett7623/hy2"
        echo -e "作者：Jensfrank"
        echo -e "Seeloc博客: https://seedloc.com"
        echo -e "VPSknow网站：https://vpsknow.com"
        echo -e "Nodeloc论坛: https://nodeloc.com"
        echo -e "更新日期: 2025-12-22"
        echo -e "------------------------------------------------"
        echo -e "状态: $STATUS"
        echo -e "------------------------------------------------"
        echo -e " 1. 安装 Hysteria2"
        echo -e " 2. 管理 Hysteria2"
        echo -e " 3. 卸载 Hysteria2"
        echo -e " 0. 退出"
        echo -e "------------------------------------------------"
        
        # 关键修改：如果读取失败（比如因为脚本传输错误导致的EOF），直接退出脚本，防止死循环
        read -r -p "请输入选项: " choice || exit 0

        [[ -z "$choice" ]] && continue

        case $choice in
            1) install_hy2 ;;
            2) manage_hy2 ;;
            3) uninstall_hy2 ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入错误...${PLAIN}"; sleep 1 ;;
        esac
    done
}

# --- 脚本入口 ---
check_root
check_sys
main_menu
