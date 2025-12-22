#!/bin/bash
#====================================================================================
# 项目：Hysteria2 Management Script
# 作者：Jensfrank
# 版本：v1.0
# GitHub: https://github.com/everett7623/hy2
# Seeloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
#
# 更新日期: 2025-12-22
# 描述: 打造一款「功能闭环、兼容广泛、交互友好、稳定可靠」的 Hysteria2 自动化管理脚本
#====================================================================================

# --- 颜色定义 ---
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
PLAIN='\033[0m'

# --- 基础路径与变量 ---
HY_BIN_PATH="/usr/local/bin/hysteria"
HY_CONF_DIR="/etc/hysteria2"
HY_CONF_PATH="${HY_CONF_DIR}/config.yaml"
HY_CERT_DIR="${HY_CONF_DIR}/certs"
SYSTEMD_FILE="/etc/systemd/system/hysteria-server.service"

# --- 核心检测函数 ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[错误] 请使用 root 权限运行此脚本！${PLAIN}"
        exit 1
    fi
}

check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    else
        echo -e "${RED}[错误] 不支持的操作系统！脚本仅支持 Ubuntu 18.04+, Debian 9+, CentOS 7+${PLAIN}"
        exit 1
    fi
    
    # 架构检测
    arch=$(uname -m)
    case $arch in
        x86_64) hy_arch="amd64" ;;
        aarch64) hy_arch="arm64" ;;
        armv7l) hy_arch="arm" ;;
        *) echo -e "${RED}[错误] 不支持的 CPU 架构: ${arch}${PLAIN}"; exit 1 ;;
    esac
}

check_mem() {
    mem_total=$(free -m | awk '/Mem:/ { print $2 }')
    if [[ $mem_total -lt 256 ]]; then
        echo -e "${RED}[错误] 系统内存低于 256MB，无法稳定运行 Hysteria2，安装中止。${PLAIN}"
        exit 1
    elif [[ $mem_total -lt 512 ]]; then
        echo -e "${YELLOW}[警告] 系统内存 (${mem_total}MB) 较小，建议仅供个人轻量使用。${PLAIN}"
        sleep 2
    fi
}

install_base() {
    echo -e "${BLUE}[进度] 正在更新系统源并安装依赖...${PLAIN}"
    if [[ "${release}" == "centos" ]]; then
        yum install -y wget curl tar openssl jq net-tools
        systemctl stop firewalld 2>/dev/null
        systemctl disable firewalld 2>/dev/null
    else
        apt-get update
        apt-get install -y wget curl tar openssl jq net-tools
    fi
    
    if ! command -v openssl &> /dev/null; then
        echo -e "${RED}[错误] OpenSSL 安装失败，请手动检查源！${PLAIN}"
        exit 1
    fi
}

get_ip() {
    local_ipv4=$(curl -s4m8 https://ip.sb)
    local_ipv6=$(curl -s6m8 https://ip.sb)
    
    [[ -z "${local_ipv4}" ]] && local_ipv4="N/A"
    [[ -z "${local_ipv6}" ]] && local_ipv6="N/A"
}

get_status() {
    if [[ ! -f ${HY_BIN_PATH} ]]; then
        status="${RED}未安装${PLAIN}"
        status_code=0
    else
        if systemctl is-active hysteria-server &>/dev/null; then
            status="${GREEN}运行中${PLAIN}"
            status_code=1
        else
            status="${YELLOW}已安装-已停止${PLAIN}"
            status_code=2
        fi
    fi
}

# --- BBR 优化 ---
check_and_enable_bbr() {
    echo -e "${BLUE}[进度] 检查系统 BBR 状态...${PLAIN}"
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        echo -e "${GREEN}[信息] BBR 已开启，无需重复配置。${PLAIN}"
    else
        echo -e "${YELLOW}[信息] BBR 未开启，正在尝试开启...${PLAIN}"
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p &>/dev/null
        echo -e "${GREEN}[成功] BBR 加速已启用。${PLAIN}"
    fi
}

# --- 防火墙配置 ---
open_ports() {
    local port=$1
    echo -e "${BLUE}[进度] 配置防火墙开放端口: ${port}...${PLAIN}"
    
    if command -v ufw &>/dev/null && systemctl is-active ufw &>/dev/null; then
        ufw allow "${port}"/tcp
        ufw allow "${port}"/udp
        ufw reload
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --zone=public --add-port="${port}"/tcp --permanent
        firewall-cmd --zone=public --add-port="${port}"/udp --permanent
        firewall-cmd --reload
    else
        # iptables fallback provided mainly for CentOS 7 basic envs
        if command -v iptables &>/dev/null; then
            iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT
            iptables -I INPUT -p udp --dport "${port}" -j ACCEPT
        fi
    fi
}

# --- 安装核心逻辑 ---
install_hy2() {
    check_mem
    install_base
    check_and_enable_bbr
    
    mkdir -p ${HY_CONF_DIR} ${HY_CERT_DIR}

    # 下载 Hysteria2
    echo -e "${BLUE}[进度] 正在查询 Hysteria2 最新版本...${PLAIN}"
    # 获取 GitHub 最新 Release
    local latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r .tag_name)
    if [[ -z "${latest_version}" || "${latest_version}" == "null" ]]; then
        echo -e "${RED}[错误] 无法获取最新版本信息，请检查网络连接。${PLAIN}"
        exit 1
    fi
    
    echo -e "${BLUE}[进度] 正在下载版本: ${latest_version} (架构: ${hy_arch})...${PLAIN}"
    wget -O ${HY_BIN_PATH} "https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${hy_arch}"
    
    if [[ ! -f ${HY_BIN_PATH} ]]; then
         echo -e "${RED}[错误] 下载失败！请检查 GitHub 连接。${PLAIN}"
         exit 1
    fi
    chmod +x ${HY_BIN_PATH}

    # 生成自签证书
    echo -e "${BLUE}[进度] 生成自签名证书 (有效期 10 年)...${PLAIN}"
    openssl req -x509 -newkey rsa:4096 -nodes -sha256 -keyout ${HY_CERT_DIR}/server.key -out ${HY_CERT_DIR}/server.crt -days 3650 -subj "/CN=www.bing.com" &>/dev/null
    
    # 配置参数
    read -p "请输入 SNI 伪装域名 (默认: amd.com): " input_sni
    local sni=${input_sni:-"amd.com"}
    
    # 随机端口 (排除常用端口)
    while true; do
        local port=$(shuf -i 10000-65535 -n 1)
        if ! netstat -tuln | grep -q ":$port "; then
            break
        fi
    done
    
    # 生成随机密码
    local password=$(tr -dc 'A-Za-z0-9!@#%^&*' < /dev/urandom | head -c 16)

    # 写入配置文件
    cat > ${HY_CONF_PATH} <<EOF
server: :${port}

tls:
  cert: ${HY_CERT_DIR}/server.crt
  key: ${HY_CERT_DIR}/server.key

auth:
  type: password
  password: ${password}

masquerade:
  type: proxy
  proxy:
    url: https://${sni}/
    rewriteHost: true

ignoreClientBandwidth: false
EOF
    chmod 600 ${HY_CONF_PATH}

    # 写入 Systemd 服务
    cat > ${SYSTEMD_FILE} <<EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
ExecStart=${HY_BIN_PATH} server -c ${HY_CONF_PATH}
WorkingDirectory=${HY_BIN_PATH%/*}
User=root
Group=root
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    # 启动服务
    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl restart hysteria-server
    
    open_ports ${port}
    
    if systemctl is-active hysteria-server &>/dev/null; then
        echo -e "${GREEN}[成功] Hysteria2 安装并启动成功！${PLAIN}"
        show_config
    else
        echo -e "${RED}[错误] 服务启动失败，请查看日志: journalctl -u hysteria-server -n 20${PLAIN}"
    fi
}

# --- 显示配置 ---
show_config() {
    if [[ ! -f ${HY_CONF_PATH} ]]; then
        echo -e "${RED}[错误] 配置文件不存在！${PLAIN}"
        return
    fi
    
    local port=$(grep "server:" ${HY_CONF_PATH} | awk '{print $2}' | tr -d ':')
    local password=$(grep "password:" ${HY_CONF_PATH} | awk '{print $2}')
    local sni=$(grep "url:" ${HY_CONF_PATH} | awk -F'[/:]' '{print $4}')
    local ip=${local_ipv4}
    if [[ "${ip}" == "N/A" ]]; then ip=${local_ipv6}; fi
    
    local name="Hysteria2-VPS-${port}"
    
    echo ""
    echo -e "${BLUE}================== 客户端配置信息 ==================${PLAIN}"
    echo -e "${YELLOW}服务器 IP  :${PLAIN} ${ip}"
    echo -e "${YELLOW}端口 (Port):${PLAIN} ${port}"
    echo -e "${YELLOW}密码 (Pass):${PLAIN} ${password}"
    echo -e "${YELLOW}SNI 伪装   :${PLAIN} ${sni}"
    echo -e "${BLUE}----------------------------------------------------${PLAIN}"
    
    # URL Encoding for V2RayN/Neko
    local share_link="hysteria2://${password}@${ip}:${port}/?insecure=1&sni=${sni}#${name}"
    
    echo -e "${GREEN}🚀 V2rayN / NekoBox / Shadowrocket 分享链接:${PLAIN}"
    echo -e "${CYAN}${share_link}${PLAIN}"
    echo ""
    
    echo -e "${GREEN}🐱 Clash Meta (Mihomo) 配置:${PLAIN}"
    echo -e "${CYAN}{ name: '${name}', type: hysteria2, server: ${ip}, port: ${port}, password: '${password}', sni: '${sni}', skip-cert-verify: true, up: 50, down: 100 }${PLAIN}"
    echo ""
    
    echo -e "${GREEN}⚡ Surge 配置:${PLAIN}"
    echo -e "${CYAN}${name} = hysteria2, ${ip}, ${port}, password=${password}, sni=${sni}, skip-cert-verify=true${PLAIN}"
    echo -e "${BLUE}====================================================${PLAIN}"
    echo -e "提示: 已默认允许自签证书 (skip-cert-verify: true)，请确保客户端已开启此选项。"
    echo ""
}

# --- 管理功能 ---
manage_hy2() {
    echo -e "
    ${GREEN}1.${PLAIN} 启动服务
    ${GREEN}2.${PLAIN} 停止服务
    ${GREEN}3.${PLAIN} 重启服务
    ${GREEN}4.${PLAIN} 查看运行状态
    ${GREEN}5.${PLAIN} 查看/复制 客户端配置
    ${GREEN}6.${PLAIN} 修改 SNI 伪装域名
    ${GREEN}7.${PLAIN} 修改 端口 (Port)
    ${GREEN}8.${PLAIN} 查看实时日志 (Ctrl+C 退出)
    ${GREEN}0.${PLAIN} 返回主菜单
    "
    read -p "请选择操作 [0-8]: " sub_opt
    case $sub_opt in
        1) systemctl start hysteria-server && echo -e "${GREEN}服务已启动${PLAIN}" ;;
        2) systemctl stop hysteria-server && echo -e "${GREEN}服务已停止${PLAIN}" ;;
        3) systemctl restart hysteria-server && echo -e "${GREEN}服务已重启${PLAIN}" ;;
        4) systemctl status hysteria-server ;;
        5) get_ip; show_config ;;
        6) 
            read -p "请输入新的 SNI 域名: " new_sni
            sed -i "s|url: https://.*/|url: https://${new_sni}/|" ${HY_CONF_PATH}
            systemctl restart hysteria-server
            echo -e "${GREEN}SNI 修改成功并重启服务。${PLAIN}"
            get_ip; show_config
            ;;
        7) 
            read -p "请输入新的端口 (10000-65535): " new_port
            # 获取旧端口用于防火墙清理（简单处理，建议保留旧规则或复杂清理）
            old_port=$(grep "server:" ${HY_CONF_PATH} | awk '{print $2}' | tr -d ':')
            sed -i "s|server: :${old_port}|server: :${new_port}|" ${HY_CONF_PATH}
            systemctl restart hysteria-server
            open_ports ${new_port}
            echo -e "${GREEN}端口修改成功并重启服务 (记得放行新端口)。${PLAIN}"
            get_ip; show_config
            ;;
        8) journalctl -u hysteria-server -f ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}" ;;
    esac
}

# --- 卸载功能 ---
uninstall_hy2() {
    echo -e "${RED}⚠️  警告：该操作将彻底卸载 Hysteria2 并清理所有配置文件！${PLAIN}"
    read -p "确认卸载？(输入 y 确认): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi
    
    echo -e "${BLUE}[进度] 停止服务...${PLAIN}"
    systemctl stop hysteria-server
    systemctl disable hysteria-server
    
    echo -e "${BLUE}[进度] 删除文件...${PLAIN}"
    rm -f ${SYSTEMD_FILE}
    rm -f ${HY_BIN_PATH}
    rm -rf ${HY_CONF_DIR}
    
    systemctl daemon-reload
    echo -e "${GREEN}[成功] Hysteria2 已彻底卸载。${PLAIN}"
    status_code=0
}

# --- 主菜单 ---
menu() {
    clear
    check_root
    check_sys
    get_ip
    get_status
    
    echo -e "
    ====================================================================================
    ${GREEN}Hysteria2 Management Script${PLAIN} ${YELLOW}[${version}]${PLAIN}
    ${GREEN}作者${PLAIN}: Jensfrank
    ${GREEN}项目${PLAIN}: https://github.com/everett7623/hy2
    ${GREEN}社区${PLAIN}: Seeloc博客 | VPSknow网站 | Nodeloc论坛
    ${GREEN}更新${PLAIN}: 2025-12-22
    ====================================================================================
    系统信息:
    IPv4: ${CYAN}${local_ipv4}${PLAIN}
    IPv6: ${CYAN}${local_ipv6}${PLAIN}
    状态: ${status}
    ====================================================================================
    
    ${GREEN}1.${PLAIN} 安装 Hysteria2 (自签证书模式)
    ${GREEN}2.${PLAIN} 管理 Hysteria2 (启动/停止/配置/日志)
    ${GREEN}3.${PLAIN} 卸载 Hysteria2
    ${GREEN}0.${PLAIN} 退出脚本
    
    ====================================================================================
    "
    read -p "请输入选项 [0-3]: " choice
    case $choice in
        1) 
            if [[ $status_code -eq 0 ]]; then
                install_hy2
            else
                echo -e "${YELLOW}Hysteria2 已安装，请先卸载或直接管理。${PLAIN}"
                sleep 2
            fi
            ;;
        2) 
            if [[ $status_code -eq 0 ]]; then
                echo -e "${RED}请先安装 Hysteria2！${PLAIN}"
                sleep 2
            else
                manage_hy2
            fi
            ;;
        3) uninstall_hy2 ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效选项，请重新输入。${PLAIN}"; sleep 1 ;;
    esac
}

# --- 脚本入口 ---
version="v1.0"
while true; do
    menu
    read -p "按回车键继续..."
done
