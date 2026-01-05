#!/bin/bash
#====================================================================================
# 项目：Shadowsocks-Rust Management Script
# 作者：Jensfrank
# 版本：v1.0.2 (Format Aligned with Hy2 v1.1.1 & Added QX Support)
# GitHub: https://github.com/shadowsocks/shadowsocks-rust
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-1-5
#====================================================================================

# --- 【核心优化】修复交互输入问题 ---
if [ ! -t 0 ]; then
    if [ -c /dev/tty ]; then
        exec < /dev/tty
    fi
fi

# --- 自动修复 Windows 换行符 ---
if [ -f "$0" ] && grep -q $'\r' "$0"; then
    sed -i 's/\r$//' "$0"
    exec "$0" "$@"
fi

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'

# --- 变量定义 ---
SS_BIN="/usr/local/bin/ssserver"
SS_CONFIG="/etc/shadowsocks-rust/config.json"
SERVICE_FILE="/etc/systemd/system/shadowsocks-server.service"

# --- 基础检查 ---
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 请使用 root 权限运行此脚本 (sudo bash ...)${PLAIN}"
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
    HAS_IPV6=$(ip -6 addr show scope global)
    
    if [[ -n "$HAS_IPV6" ]]; then
        echo -e "${GREEN}检测到 IPv6 地址，环境符合 Shadowsocks 使用建议。${PLAIN}"
    else
        echo -e "${RED}==========================================================${PLAIN}"
        echo -e "${RED}警告：未检测到公网 IPv6 地址！${PLAIN}"
        echo -e "${RED}Shadowsocks 协议特征明显，在纯 IPv4 环境下极易被防火墙识别并封锁 IP。${PLAIN}"
        echo -e "${YELLOW}强烈建议仅在 双栈(IPv4+IPv6) 或 纯IPv6 的 VPS 上使用此脚本。${PLAIN}"
        echo -e "${RED}==========================================================${PLAIN}"
        
        read -r -p "是否强制继续安装？(风险自负) [y/N]: " force
        if [[ ! "$force" =~ ^[yY]$ ]]; then
            echo "已取消安装。"
            exit 1
        fi
        echo -e "${YELLOW}您选择了强制继续，请注意 IP 被封风险。${PLAIN}"
    fi
}

install_dependencies() {
    echo -e "${YELLOW}正在更新源并安装依赖...${PLAIN}"
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
    
    echo -e "${GREEN}检测到最新版本: ${LAST_VERSION}${PLAIN}"

    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  FILE_ARCH="x86_64-unknown-linux-gnu" ;;
        aarch64) FILE_ARCH="aarch64-unknown-linux-gnu" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac
    
    DOWNLOAD_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${LAST_VERSION}/shadowsocks-${LAST_VERSION}.${FILE_ARCH}.tar.xz"
    
    echo -e "${YELLOW}正在下载核心文件...${PLAIN}"
    wget -q --show-progress -O ss-rust.tar.xz "$DOWNLOAD_URL"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载失败。${PLAIN}"
        exit 1
    fi

    echo -e "${YELLOW}解压安装中...${PLAIN}"
    tar -xf ss-rust.tar.xz
    chmod +x ssserver
    mv ssserver /usr/local/bin/
    rm -f ss-rust.tar.xz sslocal ssmanager ssurl
    
    mkdir -p /etc/shadowsocks-rust

    echo -e "\n${SKYBLUE}--- 配置 Shadowsocks ---${PLAIN}"
    
    # 默认端口设为 28888 (与 Hy2 区分)
    read -r -p "请输入端口 [默认 28888]: " PORT
    [[ -z "$PORT" ]] && PORT="28888"
    
    read -r -p "请设置密码 [留空自动生成]: " PASSWORD
    if [[ -z "$PASSWORD" ]]; then
        PASSWORD=$(openssl rand -base64 16)
    fi
    
    # 加密方式默认 aes-256-gcm (最稳妥)
    METHOD="aes-256-gcm"

    # 生成配置文件
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
    show_config
}

# --- 显示配置 (完全对齐 Hy2 v1.1.1 风格) ---
show_config() {
    if [ ! -f "$SS_CONFIG" ]; then
        echo -e "${RED}未找到配置文件。${PLAIN}"
        read -r -p "按回车返回..." temp
        return
    fi

    # 解析 JSON
    PORT=$(grep '"server_port"' "$SS_CONFIG" | awk -F: '{print $2}' | tr -d ' ,')
    PASSWORD=$(grep '"password"' "$SS_CONFIG" | awk -F'"' '{print $4}')
    METHOD=$(grep '"method"' "$SS_CONFIG" | awk -F'"' '{print $4}')
    
    # 获取本机 IP
    IPV6=$(ip -6 addr show scope global | grep inet6 | head -n 1 | awk '{print $2}' | cut -d/ -f1)
    IPV4=$(curl -s4m8 https://ip.gs)
    if [[ -z "$IPV4" ]]; then IPV4=$(hostname -I | awk '{print $1}'); fi
    
    # 优先显示 IPv6 (SS 推荐环境)
    if [[ -n "$IPV6" ]]; then
        HOST_IP="[$IPV6]"
        SHOW_IP="$IPV6"
        IP_TYPE="IPv6 (推荐)"
    else
        HOST_IP="$IPV4"
        SHOW_IP="$IPV4"
        IP_TYPE="IPv4"
    fi
    
    NODE_NAME="SS-Rust-$(date +%m%d)"
    
    # SIP002 链接
    CREDENTIALS=$(echo -n "${METHOD}:${PASSWORD}" | base64 -w 0)
    SS_LINK="ss://${CREDENTIALS}@${HOST_IP}:${PORT}#${NODE_NAME}"

    # 二维码链接
    ENCODED_LINK=$(echo -n "$SS_LINK" | jq -sRr @uri)
    QR_API="https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${ENCODED_LINK}"

    echo -e ""
    # 1. 基础配置
    echo -e "${GREEN}Shadowsocks 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "  ${BOLD}服务器IP${PLAIN}: ${YELLOW}${SHOW_IP} (${IP_TYPE})${PLAIN}"
    echo -e "  ${BOLD}端口Port${PLAIN}: ${YELLOW}${PORT}${PLAIN}"
    echo -e "  ${BOLD}密码Pass${PLAIN}: ${YELLOW}${PASSWORD}${PLAIN}"
    echo -e "  ${BOLD}加密方式${PLAIN}: ${YELLOW}${METHOD}${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # 2. 分享链接
    echo -e "${GREEN} 分享链接 (SIP002 标准):${PLAIN}"
    echo -e "  ${SS_LINK}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # 3. 二维码
    echo -e "${GREEN} 二维码链接:${PLAIN}"
    echo -e "  ${QR_API}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # 4. Clash Meta
    echo -e "${GREEN} Clash Meta / Stash 配置:${PLAIN}"
    echo -e "  - { name: '${NODE_NAME}', type: ss, server: '${SHOW_IP}', port: ${PORT}, cipher: ${METHOD}, password: '${PASSWORD}', udp: true }"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # 5. Surge (Surge SS格式)
    echo -e "${GREEN} Surge / Surfboard 配置:${PLAIN}"
    echo -e "  ${NODE_NAME} = ss, ${SHOW_IP}, ${PORT}, encrypt-method=${METHOD}, password=${PASSWORD}, udp-relay=true"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # 6. Loon (Loon SS格式：使用 Shadowsocks 关键字，密码带引号)
    echo -e "${GREEN} Loon 配置:${PLAIN}"
    echo -e "  ${NODE_NAME} = Shadowsocks, ${SHOW_IP}, ${PORT}, ${METHOD}, \"${PASSWORD}\", udp=true"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # 7. Quantumult X (特有优势)
    echo -e "${GREEN} Quantumult X 配置:${PLAIN}"
    echo -e "  shadowsocks=${SHOW_IP}:${PORT}, method=${METHOD}, password=${PASSWORD}, fast-open=false, udp-relay=true, tag=${NODE_NAME}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # 8. Sing-box
    echo -e "${GREEN} Sing-box 配置 (Outbound):${PLAIN}"
    echo -e "  { \"type\": \"shadowsocks\", \"tag\": \"${NODE_NAME}\", \"server\": \"${SHOW_IP}\", \"server_port\": ${PORT}, \"method\": \"${METHOD}\", \"password\": \"${PASSWORD}\" }"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${YELLOW}注意: 如果客户端不支持 IPv6，请手动将链接中的 IP 替换为 IPv4 地址。${PLAIN}"
    echo ""
    read -r -p "按回车键返回主菜单..." temp
}

# --- 管理功能 ---
manage_ss() {
    clear
    echo -e "\n${SKYBLUE}--- 管理 Shadowsocks ---${PLAIN}"
    echo -e "1. 查看配置 (全客户端兼容)"
    echo -e "2. 重启服务"
    echo -e "3. 停止服务"
    echo -e "4. 查看日志"
    echo -e "0. 返回"
    read -r -p "请选择: " opt
    case $opt in
        1) show_config ;;
        2) systemctl restart shadowsocks-server && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
        3) systemctl stop shadowsocks-server && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
        4) journalctl -u shadowsocks-server -n 20 --no-pager; read -r -p "按回车继续..." temp ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}" ;;
    esac
}

# --- 卸载 ---
uninstall_ss() {
    read -r -p "确定卸载? [y/N]: " confirm
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

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN} Shadowsocks-Rust Management Script v1.0.2${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/shadowsocks/shadowsocks-rust${PLAIN}"
        echo -e " 作者    : ${YELLOW}Jensfrank${PLAIN}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " Seedloc博客 : https://seedloc.com"
        echo -e " VPSknow网站 : https://vpsknow.com"
        echo -e " Nodeloc论坛 : https://nodeloc.com"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: $STATUS"
        echo -e " 推荐环境: ${YELLOW}IPv6 / 双栈${PLAIN} (纯IPv4慎用)"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 安装 Shadowsocks-Rust"
        echo -e " 2. 管理 Shadowsocks-Rust (查看配置)"
        echo -e " 3. 卸载 Shadowsocks-Rust"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        
        read -r -p "请输入选项: " choice

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
