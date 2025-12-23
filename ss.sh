#!/bin/bash
#====================================================================================
# 项目：Shadowsocks-Rust Management Script
# 作者：Jensfrank
# 版本：v1.0.0
# GitHub: https://github.com/shadowsocks/shadowsocks-rust
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
SS_BIN="/usr/local/bin/ssserver"
SS_CONFIG="/etc/shadowsocks-rust/config.json"
SERVICE_FILE="/etc/systemd/system/shadowsocks-server.service"

# --- 基础检查 ---
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 请使用 root 权限运行此脚本 (sudo bash ss.sh)${PLAIN}"
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

# --- IPv6 环境检测 (核心安全检查) ---
check_ipv6_env() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    # 检测是否存在全局 IPv6 地址
    HAS_IPV6=$(ip -6 addr show scope global)
    
    if [[ -n "$HAS_IPV6" ]]; then
        echo -e "${GREEN}检测到 IPv6 地址，环境符合 Shadowsocks 使用建议。${PLAIN}"
    else
        echo -e "${RED}==========================================================${PLAIN}"
        echo -e "${RED}警告：未检测到公网 IPv6 地址！${PLAIN}"
        echo -e "${RED}Shadowsocks 协议特征明显，在纯 IPv4 环境下极易被防火墙识别并封锁 IP。${PLAIN}"
        echo -e "${YELLOW}强烈建议仅在 双栈(IPv4+IPv6) 或 纯IPv6 的 VPS 上使用此脚本。${PLAIN}"
        echo -e "${RED}==========================================================${PLAIN}"
        
        read -r -p "是否强制继续安装？(风险自负) [y/N]: " force < /dev/tty
        if [[ ! "$force" =~ ^[yY]$ ]]; then
            echo "已取消安装。"
            exit 1
        fi
        echo -e "${YELLOW}您选择了强制继续，请注意 IP 被封风险。${PLAIN}"
    fi
}

install_dependencies() {
    echo -e "${YELLOW}正在安装依赖...${PLAIN}"
    if [ "${RELEASE}" == "centos" ]; then
        yum update -y >/dev/null 2>&1
        yum install -y curl wget jq tar xz >/dev/null 2>&1
    else
        apt update -y >/dev/null 2>&1
        apt install -y curl wget jq tar xz-utils >/dev/null 2>&1
    fi
}

# --- 安装 Shadowsocks-Rust ---
install_ss() {
    check_ipv6_env
    install_dependencies
    
    echo -e "${YELLOW}正在获取 Shadowsocks-Rust 最新版本...${PLAIN}"
    LAST_VERSION=$(curl -Ls "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$LAST_VERSION" ]]; then
        echo -e "${RED}无法获取版本信息，请检查网络。${PLAIN}"
        exit 1
    fi
    
    ARCH=$(uname -m)
    # 构建下载文件名
    case $ARCH in
        x86_64)  FILE_ARCH="x86_64-unknown-linux-gnu" ;;
        aarch64) FILE_ARCH="aarch64-unknown-linux-gnu" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac
    
    DOWNLOAD_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${LAST_VERSION}/shadowsocks-${LAST_VERSION}.${FILE_ARCH}.tar.xz"
    
    echo -e "${YELLOW}正在下载: $DOWNLOAD_URL${PLAIN}"
    wget -O ss-rust.tar.xz "$DOWNLOAD_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载失败。${PLAIN}"
        exit 1
    fi

    echo -e "${YELLOW}解压安装中...${PLAIN}"
    tar -xf ss-rust.tar.xz
    chmod +x ssserver
    mv ssserver /usr/local/bin/
    rm -f ss-rust.tar.xz sslocal ssmanager ssurl # 清理不用的文件
    
    mkdir -p /etc/shadowsocks-rust

    echo -e "\n${SKYBLUE}--- 配置 Shadowsocks ---${PLAIN}"
    
    # 默认端口设为 28888 (与 Hy2 区分)
    read -r -p "请输入端口 [默认 28888]: " PORT < /dev/tty
    [[ -z "$PORT" ]] && PORT="28888"
    
    read -r -p "请设置密码 [留空自动生成]: " PASSWORD < /dev/tty
    if [[ -z "$PASSWORD" ]]; then
        PASSWORD=$(openssl rand -base64 16)
    fi
    
    # 加密方式默认 aes-256-gcm (最稳妥)
    METHOD="aes-256-gcm"

    # 生成配置文件 (监听 :: 表示同时监听 v4 和 v6)
    cat > "$SS_CONFIG" <<EOF
{
    "server": "::",
    "server_port": $PORT,
    "password": "$PASSWORD",
    "method": "$METHOD",
    "mode": "tcp_and_udp",
    "timeout": 300
}
EOF

    # 配置 Systemd
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Shadowsocks-Rust Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ssserver -c $SS_CONFIG
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable shadowsocks-server
    systemctl start shadowsocks-server
    
    echo -e "${GREEN}Shadowsocks-Rust 安装并启动成功！${PLAIN}"
    read -r -p "按回车键查看配置..." temp < /dev/tty
    show_config
}

# --- 显示配置 ---
show_config() {
    if [ ! -f "$SS_CONFIG" ]; then
        echo -e "${RED}未找到配置文件。${PLAIN}"
        read -r -p "按回车返回..." temp < /dev/tty
        return
    fi

    # 解析 JSON (简单解析，不依赖复杂 jq 语法以防万一)
    PORT=$(grep '"server_port"' "$SS_CONFIG" | awk -F: '{print $2}' | tr -d ' ,')
    PASSWORD=$(grep '"password"' "$SS_CONFIG" | awk -F'"' '{print $4}')
    METHOD=$(grep '"method"' "$SS_CONFIG" | awk -F'"' '{print $4}')
    
    # 获取本机 IP (优先显示 IPv6，因为这是 SS 的推荐环境)
    IPV6=$(ip -6 addr show scope global | grep inet6 | head -n 1 | awk '{print $2}' | cut -d/ -f1)
    IPV4=$(hostname -I | awk '{print $1}')
    
    if [[ -n "$IPV6" ]]; then
        HOST_IP="[$IPV6]" # IPv6 需要加括号
        SHOW_IP="$IPV6"
    else
        HOST_IP="$IPV4"
        SHOW_IP="$IPV4"
    fi
    
    NODE_NAME="🌟SS-Rust-$(date +%m%d)"
    
    # 生成 SIP002 链接 ss://base64(method:password)@ip:port#name
    CREDENTIALS=$(echo -n "${METHOD}:${PASSWORD}" | base64 -w 0)
    SS_LINK="ss://${CREDENTIALS}@${HOST_IP}:${PORT}#${NODE_NAME}"

    echo -e "\n${SKYBLUE}================ 配置信息 =================${PLAIN}"
    echo -e "服务器 IP: ${GREEN}${SHOW_IP}${PLAIN}"
    echo -e "端口: ${GREEN}${PORT}${PLAIN}"
    echo -e "密码: ${GREEN}${PASSWORD}${PLAIN}"
    echo -e "加密: ${GREEN}${METHOD}${PLAIN}"
    echo -e "-------------------------------------------"
    echo -e "${GREEN}🚀 SS 分享链接 (SIP002):${PLAIN}"
    echo -e "$SS_LINK"
    echo -e ""
    echo -e "${GREEN}⚔️ Clash Meta 配置:${PLAIN}"
    echo -e "- { name: '${NODE_NAME}', type: ss, server: '${SHOW_IP}', port: ${PORT}, cipher: ${METHOD}, password: '${PASSWORD}', udp: true }"
    echo -e ""
    echo -e "${GREEN}🌊 Surge 配置:${PLAIN}"
    echo -e "${NODE_NAME} = ss, ${SHOW_IP}, ${PORT}, encrypt-method=${METHOD}, password=${PASSWORD}, udp-relay=true"
    echo -e "${SKYBLUE}===========================================${PLAIN}"
    echo -e "注意：如果您的客户端不支持 IPv6，请手动将链接中的 IP 替换为 IPv4 地址。"
    echo ""
    read -r -p "按回车键返回主菜单..." temp < /dev/tty
}

# --- 管理功能 ---
manage_ss() {
    clear
    echo -e "\n${SKYBLUE}--- 管理 Shadowsocks ---${PLAIN}"
    echo -e "1. 查看配置"
    echo -e "2. 重启服务"
    echo -e "3. 停止服务"
    echo -e "4. 查看日志"
    echo -e "0. 返回"
    read -r -p "请选择: " opt < /dev/tty
    case $opt in
        1) show_config ;;
        2) systemctl restart shadowsocks-server && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
        3) systemctl stop shadowsocks-server && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
        4) journalctl -u shadowsocks-server -n 20 --no-pager; read -r -p "按回车继续..." temp < /dev/tty ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}" ;;
    esac
}

# --- 卸载 ---
uninstall_ss() {
    read -r -p "确定卸载? [y/N]: " confirm < /dev/tty
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        systemctl stop shadowsocks-server
        systemctl disable shadowsocks-server
        rm -f "$SERVICE_FILE" "/usr/local/bin/ssserver"
        rm -rf /etc/shadowsocks-rust
        systemctl daemon-reload
        echo -e "${GREEN}已卸载。${PLAIN}"
        sleep 1
    fi
}

# --- 主菜单 ---
main_menu() {
    while true; do
        clear
        if [ -f "$SS_BIN" ]; then
            if systemctl is-active --quiet shadowsocks-server; then
                STATUS="${GREEN}运行中${PLAIN}"
            else
                STATUS="${RED}已停止${PLAIN}"
            fi
        else
            STATUS="${RED}未安装${PLAIN}"
        fi

        echo -e "Shadowsocks-Rust Management Script (v1.0.0)"
        echo -e "项目地址：https://github.com/shadowsocks/shadowsocks-rust"
        echo -e "作者：Jensfrank"
        echo -e "建议环境：IPv6 / 双栈 (纯 IPv4 慎用)"
        echo -e "------------------------------------------------"
        echo -e "状态: $STATUS"
        echo -e "------------------------------------------------"
        echo -e " 1. 安装 Shadowsocks-Rust"
        echo -e " 2. 管理 Shadowsocks-Rust"
        echo -e " 3. 卸载 Shadowsocks-Rust"
        echo -e " 0. 退出"
        echo -e "------------------------------------------------"
        
        read -r -p "请输入选项: " choice < /dev/tty

        case $choice in
            1) install_ss ;;
            2) manage_ss ;;
            3) uninstall_ss ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入错误...${PLAIN}"; sleep 1 ;;
        esac
    done
}

# --- 脚本入口 ---
check_root
check_sys
main_menu
