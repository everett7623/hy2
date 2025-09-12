#!/bin/bash

#====================================================================================
# 项目：Hysteria2 & Shadowsocks (IPv6) 自动化部署管理脚本
# 作者：编程大师 (AI)
# 版本：v1.0
# GitHub: https://github.com/everett7623/hy2ipv6
# 博客: https://seedloc.com
# 论坛: https://nodeloc.com
#====================================================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 全局变量 ---
HY2_CONFIG_PATH="/etc/hysteria/config.json"
HY2_CERT_PATH="/etc/hysteria/cert.pem"
HY2_KEY_PATH="/etc/hysteria/private.key"
HY2_BIN_PATH="/usr/local/bin/hysteria"
SS_CONFIG_PATH="/etc/shadowsocks/config.json"
SS_BIN_PATH="/usr/local/bin/ssserver"

# --- 脚本初始化与环境检查 ---

# 检查是否以 root 权限运行
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误：此脚本必须以 root 权限运行。请尝试使用 'sudo'。${NC}"
        exit 1
    fi
}

# 检查操作系统和架构
check_os_arch() {
    OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
    ARCH=$(uname -m)
    echo -e "${GREEN}正在检测系统环境...${NC}"
    
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) echo -e "${RED}错误：不支持的系统架构: $ARCH ${NC}"; exit 1 ;;
    esac

    case "$OS_ID" in
        ubuntu|debian) PKG_MANAGER="apt-get" ;;
        centos|almalinux|rocky) PKG_MANAGER="yum" ;;
        *) echo -e "${RED}错误：不支持的操作系统: $OS_ID ${NC}"; exit 1 ;;
    esac
    echo -e "${GREEN}系统检测完成: $OS_ID ($ARCH) 使用 $PKG_MANAGER ${NC}"
}

# 安装依赖
install_dependencies() {
    echo -e "${YELLOW}正在检查并安装必要的依赖...${NC}"
    DEPS="curl wget jq openssl net-tools ufw firewalld"
    
    # 更新软件包列表
    $PKG_MANAGER update -y > /dev/null 2>&1

    for dep in $DEPS; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${YELLOW}正在安装 $dep ...${NC}"
            if [[ "$PKG_MANAGER" == "apt-get" ]]; then
                $PKG_MANAGER install -y $dep > /dev/null 2>&1
            elif [[ "$PKG_MANAGER" == "yum" ]]; then
                 # firewalld 在 CentOS 上通常是默认的，但 ufw 不是
                if [[ "$dep" == "ufw" && "$OS_ID" == "centos" ]]; then
                    continue 
                fi
                $PKG_MANAGER install -y $dep > /dev/null 2>&1
            fi
        fi
    done
    echo -e "${GREEN}所有依赖项已安装。${NC}"
}

# 获取服务器 IP 地址
fetch_ips() {
    IPV4=$(curl -s -4 --max-time 5 https://ifconfig.co)
    IPV6=$(curl -s -6 --max-time 5 https://ifconfig.co)
}

# 检查 IPv6 可用性
check_ipv6_support() {
    if [[ -z "$IPV6" ]]; then
        IPV6_SUPPORT="不支持"
    else
        IPV6_SUPPORT="支持"
    fi
}

# 检查防火墙状态
check_firewall() {
    if systemctl is-active --quiet firewalld; then
        FIREWALL="firewalld"
    elif systemctl is-active --quiet ufw; then
        FIREWALL="ufw"
    else
        FIREWALL="none"
    fi
}

# --- 服务状态检查 ---

is_service_active() {
    systemctl is-active --quiet $1
}

get_service_status() {
    if is_service_active $1; then
        echo -e "${GREEN}已安装并正在运行${NC}"
    elif [ -f "/etc/systemd/system/$1.service" ]; then
        echo -e "${YELLOW}已安装但未运行${NC}"
    else
        echo -e "${RED}未安装${NC}"
    fi
}

# --- 安装 Hysteria2 ---

install_hysteria2() {
    if [ -f "$HY2_BIN_PATH" ]; then
        echo -e "${YELLOW}Hysteria2 已安装，无需重复操作。${NC}"
        return
    fi
    
    echo -e "${BLUE}--- 开始安装 Hysteria2 ---${NC}"

    # 获取用户输入
    read -p "请输入 Hysteria2 的监听端口 [默认: 随机 40000-65535]: " HY2_PORT
    [[ -z "$HY2_PORT" ]] && HY2_PORT=$(shuf -i 40000-65535 -n 1)

    read -p "请输入 Hysteria2 的连接密码 [默认: 随机生成]: " HY2_PASSWORD
    [[ -z "$HY2_PASSWORD" ]] && HY2_PASSWORD=$(openssl rand -base64 16)

    read -p "请输入用于 SNI 伪装的域名 (任意有效域名) [默认: amd.com]: " HY2_SNI
    [[ -z "$HY2_SNI" ]] && HY2_SNI="amd.com"

    # 下载并安装 Hysteria2
    echo -e "${YELLOW}正在从 GitHub 下载最新版本的 Hysteria2...${NC}"
    LATEST_URL=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r ".assets[] | select(.name | contains(\"linux-${ARCH}\")) | .browser_download_url")
    wget -qO "$HY2_BIN_PATH" "$LATEST_URL"
    chmod +x "$HY2_BIN_PATH"

    if [ ! -f "$HY2_BIN_PATH" ]; then
        echo -e "${RED}Hysteria2 下载失败，请检查网络或 GitHub API 访问。${NC}"
        exit 1
    fi
    
    # 生成自签名证书
    echo -e "${YELLOW}正在生成自签名证书...${NC}"
    mkdir -p /etc/hysteria
    openssl ecparam -genkey -name prime256v1 -out "$HY2_KEY_PATH"
    openssl req -new -x509 -days 3650 -key "$HY2_KEY_PATH" -out "$HY2_CERT_PATH" -subj "/C=US/ST=CA/L=Los Angeles/O=Example Inc/OU=IT/CN=example.com"
    
    # 创建配置文件
    echo -e "${YELLOW}正在创建配置文件...${NC}"
    cat > "$HY2_CONFIG_PATH" <<EOF
{
  "listen": ":${HY2_PORT}",
  "tls": {
    "cert": "${HY2_CERT_PATH}",
    "key": "${HY2_KEY_PATH}"
  },
  "auth": {
    "type": "password",
    "password": "${HY2_PASSWORD}"
  },
  "masquerade": {
      "type": "proxy",
      "proxy": {
          "url": "https://bing.com",
          "rewriteHost": true
      }
  }
}
EOF

    # 创建 Systemd 服务文件
    echo -e "${YELLOW}正在创建 Systemd 服务...${NC}"
    cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria2 Service
After=network.target

[Service]
Type=simple
ExecStart=${HY2_BIN_PATH} server --config ${HY2_CONFIG_PATH}
WorkingDirectory=/etc/hysteria
User=root
Group=root
Environment="GOMAXPROCS=4"
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # 配置防火墙
    read -p "是否需要自动配置防火墙以开放端口 ${HY2_PORT}? (y/n) [默认: y]: " CONFIGURE_FIREWALL
    if [[ "$CONFIGURE_FIREWALL" == "y" || -z "$CONFIGURE_FIREWALL" ]]; then
        if [[ "$FIREWALL" == "ufw" ]]; then
            ufw allow ${HY2_PORT}/udp
            echo -e "${GREEN}UFW 规则已添加: 允许 ${HY2_PORT}/udp${NC}"
        elif [[ "$FIREWALL" == "firewalld" ]]; then
            firewall-cmd --add-port=${HY2_PORT}/udp --permanent
            firewall-cmd --reload
            echo -e "${GREEN}Firewalld 规则已添加: 允许 ${HY2_PORT}/udp${NC}"
        else
            echo -e "${YELLOW}未检测到活动的防火墙，请手动开放 UDP 端口 ${HY2_PORT}。${NC}"
        fi
    fi

    # 启动服务
    echo -e "${YELLOW}正在启动 Hysteria2 服务...${NC}"
    systemctl daemon-reload
    systemctl enable hysteria > /dev/null 2>&1
    systemctl start hysteria
    
    echo -e "${GREEN}--- Hysteria2 安装完成！ ---${NC}"
    show_hysteria2_config
}

# --- 安装 Shadowsocks ---
install_shadowsocks() {
    if [ -f "$SS_BIN_PATH" ]; then
        echo -e "${YELLOW}Shadowsocks 已安装，无需重复操作。${NC}"
        return
    fi
    
    if [[ "$IPV6_SUPPORT" == "不支持" ]]; then
        echo -e "${RED}错误：此服务器不支持 IPv6，无法安装 Shadowsocks (仅 IPv6 模式)。${NC}"
        return
    fi

    echo -e "${BLUE}--- 开始安装 Shadowsocks (仅 IPv6) ---${NC}"

    # 获取用户输入
    read -p "请输入 Shadowsocks 的监听端口 [默认: 随机 10000-30000]: " SS_PORT
    [[ -z "$SS_PORT" ]] && SS_PORT=$(shuf -i 10000-30000 -n 1)

    read -p "请输入 Shadowsocks 的连接密码 [默认: 随机生成]: " SS_PASSWORD
    [[ -z "$SS_PASSWORD" ]] && SS_PASSWORD=$(openssl rand -base64 16)

    echo "请选择加密方式:"
    echo " 1) 2022-blake3-aes-128-gcm (推荐)"
    echo " 2) aes-256-gcm"
    echo " 3) chacha20-ietf-poly1305"
    read -p "请输入选项 [默认: 1]: " SS_METHOD_CHOICE
    case "$SS_METHOD_CHOICE" in
        2) SS_METHOD="aes-256-gcm" ;;
        3) SS_METHOD="chacha20-ietf-poly1305" ;;
        *) SS_METHOD="2022-blake3-aes-128-gcm" ;;
    esac

    # 下载并安装 shadowsocks-rust
    echo -e "${YELLOW}正在从 GitHub 下载最新版本的 shadowsocks-rust...${NC}"
    SS_LATEST_URL=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r ".assets[] | select(.name | contains(\"${ARCH}\") and contains(\"gnu\")) | .browser_download_url")
    wget -qO shadowsocks.tar.xz "$SS_LATEST_URL"
    tar -xf shadowsocks.tar.xz
    mv ssserver "$SS_BIN_PATH"
    chmod +x "$SS_BIN_PATH"
    rm shadowsocks.tar.xz

    if [ ! -f "$SS_BIN_PATH" ]; then
        echo -e "${RED}Shadowsocks 下载失败，请检查网络或 GitHub API 访问。${NC}"
        exit 1
    fi

    # 创建配置文件
    echo -e "${YELLOW}正在创建配置文件...${NC}"
    mkdir -p /etc/shadowsocks
    cat > "$SS_CONFIG_PATH" <<EOF
{
    "server": "::",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "mode": "tcp_and_udp"
}
EOF

    # 创建 Systemd 服务文件
    echo -e "${YELLOW}正在创建 Systemd 服务...${NC}"
    cat > /etc/systemd/system/shadowsocks.service <<EOF
[Unit]
Description=Shadowsocks-rust Server Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=${SS_BIN_PATH} -c ${SS_CONFIG_PATH}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    # 配置防火墙
    read -p "是否需要自动配置防火墙以开放端口 ${SS_PORT}? (y/n) [默认: y]: " CONFIGURE_FIREWALL
    if [[ "$CONFIGURE_FIREWALL" == "y" || -z "$CONFIGURE_FIREWALL" ]]; then
        if [[ "$FIREWALL" == "ufw" ]]; then
            ufw allow ${SS_PORT}
            echo -e "${GREEN}UFW 规则已添加: 允许 TCP/UDP ${SS_PORT}${NC}"
        elif [[ "$FIREWALL" == "firewalld" ]]; then
            firewall-cmd --add-port=${SS_PORT}/tcp --permanent
            firewall-cmd --add-port=${SS_PORT}/udp --permanent
            firewall-cmd --reload
            echo -e "${GREEN}Firewalld 规则已添加: 允许 TCP/UDP ${SS_PORT}${NC}"
        else
            echo -e "${YELLOW}未检测到活动的防火墙，请手动开放 TCP/UDP 端口 ${SS_PORT}。${NC}"
        fi
    fi

    # 启动服务
    echo -e "${YELLOW}正在启动 Shadowsocks 服务...${NC}"
    systemctl daemon-reload
    systemctl enable shadowsocks > /dev/null 2>&1
    systemctl start shadowsocks
    
    echo -e "${GREEN}--- Shadowsocks 安装完成！ ---${NC}"
    show_shadowsocks_config
}


# --- 配置信息显示 ---
show_hysteria2_config() {
    if [ ! -f "$HY2_CONFIG_PATH" ]; then
        echo -e "${RED}Hysteria2 未安装或配置文件不存在。${NC}"
        return
    fi
    
    HY2_PORT=$(jq -r '.listen' "$HY2_CONFIG_PATH" | cut -d: -f2)
    HY2_PASSWORD=$(jq -r '.auth.password' "$HY2_CONFIG_PATH")
    HY2_SNI="amd.com" # SNI from installation, can be hardcoded or retrieved if stored

    SERVER_IP=$IPV4
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$IPV6
    fi
    
    SHARE_LINK="hysteria2://${HY2_PASSWORD}@${SERVER_IP}:${HY2_PORT}/?insecure=1&sni=${HY2_SNI}#Hysteria2-${SERVER_IP}"
    CLASH_META="- { name: 'Hysteria2-${SERVER_IP}', type: hysteria2, server: ${SERVER_IP}, port: ${HY2_PORT}, password: ${HY2_PASSWORD}, sni: ${HY2_SNI}, skip-cert-verify: true }"
    SURGE="Hysteria2-${SERVER_IP} = hysteria2, ${SERVER_IP}, ${HY2_PORT}, password=${HY2_PASSWORD}, sni=${HY2_SNI}, skip-cert-verify=true"

    echo -e "\n${BLUE}================ Hysteria2 配置信息 ================${NC}"
    echo -e "🚀 ${GREEN}V2rayN / NekoBox 分享链接:${NC}"
    echo -e "${YELLOW}${SHARE_LINK}${NC}"
    echo -e "\n⚔️ ${GREEN}Clash Meta 配置:${NC}"
    echo -e "${YELLOW}${CLASH_META}${NC}"
    echo -e "\n🌊 ${GREEN}Surge 配置:${NC}"
    echo -e "${YELLOW}${SURGE}${NC}"
    echo -e "${BLUE}====================================================${NC}"
}

show_shadowsocks_config() {
    if [ ! -f "$SS_CONFIG_PATH" ]; then
        echo -e "${RED}Shadowsocks 未安装或配置文件不存在。${NC}"
        return
    fi

    SS_PORT=$(jq -r '.server_port' "$SS_CONFIG_PATH")
    SS_PASSWORD=$(jq -r '.password' "$SS_CONFIG_PATH")
    SS_METHOD=$(jq -r '.method' "$SS_CONFIG_PATH")
    
    # Base64 encode for ss link
    BASE64_USER_INFO=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 | tr -d '\n')
    SHARE_LINK="ss://${BASE64_USER_INFO}@\[${IPV6}\]:${SS_PORT}#Shadowsocks-IPv6"

    echo -e "\n${BLUE}============== Shadowsocks (IPv6) 配置信息 ==============${NC}"
    echo -e "服务器地址: ${IPV6}"
    echo -e "端口: ${SS_PORT}"
    echo -e "密码: ${SS_PASSWORD}"
    echo -e "加密方式: ${SS_METHOD}"
    echo -e "\n🚀 ${GREEN}SS 分享链接 (仅限支持 IPv6 的客户端):${NC}"
    echo -e "${YELLOW}${SHARE_LINK}${NC}"
    echo -e "${BLUE}==========================================================${NC}"
}


# --- 服务管理 ---
manage_service_menu() {
    clear
    echo -e "${BLUE}=== 服务管理 ===${NC}"
    echo -e " 1. 管理 Hysteria2"
    echo -e " 2. 管理 Shadowsocks"
    echo -e " 3. 返回主菜单"
    read -p "请输入选项: " choice

    case "$choice" in
        1) manage_single_service "Hysteria2" "hysteria" ;;
        2) manage_single_service "Shadowsocks" "shadowsocks" ;;
        3) ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
}

manage_single_service() {
    SERVICE_NAME=$1
    SERVICE_FILE=$2
    
    if [ ! -f "/etc/systemd/system/${SERVICE_FILE}.service" ]; then
        echo -e "${RED}${SERVICE_NAME} 未安装。${NC}"
        read -p "按回车键返回..."
        return
    fi

    clear
    echo -e "${BLUE}=== 管理 ${SERVICE_NAME} ===${NC}"
    echo -e " 1. 启动服务"
    echo -e " 2. 停止服务"
    echo -e " 3. 重启服务"
    echo -e " 4. 查看状态"
    echo -e " 5. 查看配置信息"
    echo -e " 6. 返回上一级"
    read -p "请输入选项: " choice

    case "$choice" in
        1) systemctl start $SERVICE_FILE; echo -e "${GREEN}${SERVICE_NAME} 已启动。${NC}" ;;
        2) systemctl stop $SERVICE_FILE; echo -e "${GREEN}${SERVICE_NAME} 已停止。${NC}" ;;
        3) systemctl restart $SERVICE_FILE; echo -e "${GREEN}${SERVICE_NAME} 已重启。${NC}" ;;
        4) systemctl status $SERVICE_FILE ;;
        5) 
            if [[ "$SERVICE_NAME" == "Hysteria2" ]]; then
                show_hysteria2_config
            else
                show_shadowsocks_config
            fi
            ;;
        6) return ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
    read -p "按回车键继续..."
    manage_single_service "$SERVICE_NAME" "$SERVICE_FILE"
}

# --- 卸载服务 ---
uninstall_menu() {
    clear
    echo -e "${BLUE}=== 卸载服务 ===${NC}"
    echo -e " 1. 卸载 Hysteria2"
    echo -e " 2. 卸载 Shadowsocks"
    echo -e " 3. 卸载所有服务"
    echo -e " 4. 返回主菜单"
    read -p "请输入选项: " choice
    
    case "$choice" in
        1) uninstall_hysteria2 ;;
        2) uninstall_shadowsocks ;;
        3) uninstall_hysteria2; uninstall_shadowsocks ;;
        4) ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
}

uninstall_hysteria2() {
    echo -e "${YELLOW}正在卸载 Hysteria2...${NC}"
    systemctl stop hysteria
    systemctl disable hysteria
    rm -f /etc/systemd/system/hysteria.service
    rm -f "$HY2_BIN_PATH"
    rm -rf /etc/hysteria
    systemctl daemon-reload
    echo -e "${GREEN}Hysteria2 卸载完成。${NC}"
    read -p "按回车键继续..."
}

uninstall_shadowsocks() {
    echo -e "${YELLOW}正在卸载 Shadowsocks...${NC}"
    systemctl stop shadowsocks
    systemctl disable shadowsocks
    rm -f /etc/systemd/system/shadowsocks.service
    rm -f "$SS_BIN_PATH"
    rm -rf /etc/shadowsocks
    systemctl daemon-reload
    echo -e "${GREEN}Shadowsocks 卸载完成。${NC}"
    read -p "按回车键继续..."
}

# --- 更新服务 ---
update_menu() {
    clear
    echo -e "${BLUE}=== 更新服务 ===${NC}"
    echo -e " 1. 更新 Hysteria2"
    echo -e " 2. 更新 Shadowsocks"
    echo -e " 3. 更新系统软件包"
    echo -e " 4. 返回主菜单"
    read -p "请输入选项: " choice

    case "$choice" in
        1) update_service "Hysteria2" "hysteria" ;;
        2) update_service "Shadowsocks" "shadowsocks-rust" ;;
        3) $PKG_MANAGER update && $PKG_MANAGER upgrade -y; echo -e "${GREEN}系统更新完成。${NC}";;
        4) ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
    read -p "按回车键继续..."
}

update_service() {
    SERVICE_NAME=$1
    REPO=$2
    
    if [[ "$SERVICE_NAME" == "Hysteria2" ]]; then
        BIN_PATH=$HY2_BIN_PATH
        LATEST_URL=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r ".assets[] | select(.name | contains(\"linux-${ARCH}\")) | .browser_download_url")
        wget -qO "$BIN_PATH" "$LATEST_URL"
        chmod +x "$BIN_PATH"
        systemctl restart hysteria
        echo -e "${GREEN}Hysteria2 已更新到最新版本。${NC}"
    elif [[ "$SERVICE_NAME" == "Shadowsocks" ]]; then
        BIN_PATH=$SS_BIN_PATH
        LATEST_URL=$(curl -s "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | jq -r ".assets[] | select(.name | contains(\"${ARCH}\") and contains(\"gnu\")) | .browser_download_url")
        wget -qO shadowsocks.tar.xz "$LATEST_URL"
        tar -xf shadowsocks.tar.xz
        mv ssserver "$BIN_PATH"
        chmod +x "$BIN_PATH"
        rm shadowsocks.tar.xz
        systemctl restart shadowsocks
        echo -e "${GREEN}Shadowsocks 已更新到最新版本。${NC}"
    fi
}


# --- 系统优化 ---
optimize_system_menu() {
    clear
    echo -e "${BLUE}=== 系统优化 ===${NC}"
    echo -e " 1. BBR + FQ 网络优化"
    echo -e " 2. 优化系统文件描述符限制"
    echo -e " 3. 清理系统垃圾"
    echo -e " 4. 返回主菜单"
    read -p "请输入选项: " choice

    case "$choice" in
        1) enable_bbr ;;
        2) optimize_limits ;;
        3) clean_junk ;;
        4) ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
    read -p "按回车键继续..."
}

enable_bbr() {
    echo -e "${YELLOW}正在启用 BBR + FQ...${NC}"
    cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system
    echo -e "${GREEN}BBR + FQ 已启用。${NC}"
}

optimize_limits() {
    echo -e "${YELLOW}正在优化文件描述符限制...${NC}"
    cat > /etc/security/limits.d/99-optimizations.conf <<EOF
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
root soft nofile 1048576
root hard nofile 1048576
root soft nproc 1048576
root hard nproc 1048576
EOF
    echo -e "${GREEN}文件描述符限制已优化，请重新登录以使更改生效。${NC}"
}

clean_junk() {
    echo -e "${YELLOW}正在清理系统垃圾...${NC}"
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        apt-get autoremove -y && apt-get clean -y
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        yum autoremove -y && yum clean all
    fi
    echo -e "${GREEN}系统垃圾清理完成。${NC}"
}

# --- 查看日志 ---
view_logs() {
    clear
    echo -e "${BLUE}=== 查看日志 ===${NC}"
    echo " 1. 查看 Hysteria2 日志"
    echo " 2. 查看 Shadowsocks 日志"
    echo " 3. 返回主菜单"
    read -p "请输入选项: " choice
    case "$choice" in
        1) journalctl -u hysteria -f --no-pager ;;
        2) journalctl -u shadowsocks -f --no-pager ;;
        3) ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
}


# --- 主菜单 ---
main_menu() {
    clear
    # 获取最新信息
    fetch_ips
    check_ipv6_support
    HY2_STATUS=$(get_service_status hysteria)
    SS_STATUS=$(get_service_status shadowsocks)

    echo -e "${BLUE}Hysteria2 & Shadowsocks (IPv6) Management Script (v1.0)${NC}"
    echo -e "项目地址：${YELLOW}https://github.com/everett7623/hy2ipv6${NC}"
    echo -e "博客地址：${YELLOW}https://seedloc.com${NC}"
    echo -e "论坛地址：${YELLOW}https://nodeloc.com${NC}"
    echo -e "--------------------------------------------------------"
    echo -e "服务器 IPv4: ${GREEN}${IPV4:-未分配或检测失败}${NC}"
    echo -e "服务器 IPv6: ${GREEN}${IPV6:-未分配或检测失败}${NC}"
    echo -e "Hysteria2 状态: ${HY2_STATUS}"
    echo -e "Shadowsocks 状态: ${SS_STATUS}"
    echo -e "${BLUE}========================================================${NC}"
    echo -e " 1. 安装 Hysteria2 (自签名证书模式)"
    echo -e " 2. 安装 Shadowsocks (仅 IPv6)"
    echo -e " 3. 服务管理"
    echo -e " 4. 卸载服务"
    echo -e " 5. 更新服务"
    echo -e " 6. 系统优化"
    echo -e " 7. 查看日志"
    echo -e " 8. 退出脚本"
    echo -e "${BLUE}========================================================${NC}"
    read -p "请输入选项 [1-8]: " user_choice

    case $user_choice in
        1) install_hysteria2; read -p "按回车键返回主菜单..."; main_menu ;;
        2) install_shadowsocks; read -p "按回车键返回主菜单..."; main_menu ;;
        3) manage_service_menu; main_menu ;;
        4) uninstall_menu; main_menu ;;
        5) update_menu; main_menu ;;
        6) optimize_system_menu; main_menu ;;
        7) view_logs; main_menu ;;
        8) echo -e "${GREEN}感谢使用，脚本已退出。${NC}"; exit 0 ;;
        *) echo -e "${RED}无效输入，请输入 1 到 8 之间的数字。${NC}"; sleep 2; main_menu ;;
    esac
}

# --- 脚本执行入口 ---
main() {
    check_root
    check_os_arch
    install_dependencies
    check_firewall
    main_menu
}

# 运行主函数
main
