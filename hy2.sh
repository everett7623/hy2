#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 5.0 (Hysteria2 源码编译版 - 终极解决方案)

# --- 脚本行为设置 ---
set -o pipefail

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BG_PURPLE='\033[45m'
ENDCOLOR='\033[0m'

# --- 全局变量 ---
OS_TYPE=""
ARCH=""
IPV4_ADDR=""
IPV6_ADDR=""
HY_DOMAIN=""
HY_PASSWORD=""
HY_FAKE_URL="https://www.bing.com"
SS_PORT=""
SS_PASSWORD=""
SS_METHOD=""

# --- 辅助函数 ---
info_echo() { echo -e "${BLUE}[INFO]${ENDCOLOR} $1"; }
success_echo() { echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"; }
error_echo() { echo -e "${RED}[ERROR]${ENDCOLOR} $1" >&2; }
warning_echo() { echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"; }

# --- 主菜单 ---
show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-未检测到}"
    local ipv6_display="${IPV6_ADDR:-未检测到}"
    
    local hy2_status="未安装"
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hy2_status="${GREEN}运行中${ENDCOLOR}"
    elif [[ -f /etc/systemd/system/hysteria-server.service ]]; then
        hy2_status="${RED}已停止${ENDCOLOR}"
    fi

    local ss_status="未安装"
    if systemctl is-active --quiet ss-ipv6 2>/dev/null; then
        ss_status="${GREEN}运行中${ENDCOLOR}"
    elif [[ -f /etc/systemd/system/ss-ipv6.service ]]; then
        ss_status="${RED}已停止${ENDCOLOR}"
    fi

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v5.0) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}安装选项:${ENDCOLOR}"
    echo -e "   1. 安装 Hysteria2 (自签名证书 - ${GREEN}推荐，最稳定${ENDCOLOR})"
    echo -e "   2. 安装 Hysteria2 (Let's Encrypt 证书 - ${YELLOW}需域名解析和Cloudflare API${ENDCOLOR})"
    echo -e "   3. 安装 Shadowsocks (仅 IPv6)"
    echo
    echo -e " ${CYAN}管理与维护:${ENDCOLOR}"
    echo -e "   4. 服务管理 (启动/停止/日志)"
    echo -e "   5. 显示配置信息"
    echo -e "   6. 卸载服务"
    echo -e "   7. 备份配置"
    echo -e "   8. 系统诊断"
    echo
    echo -e " ${CYAN}0. 退出脚本${ENDCOLOR}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
}

# --- 通用系统检查函数 ---
check_root() { if [[ $EUID -ne 0 ]]; then error_echo "此脚本需要 root 权限运行"; exit 1; fi; }

detect_system() {
    source /etc/os-release; OS_TYPE=$ID
    ARCH=$(uname -m);
    info_echo "检测到系统: $PRETTY_NAME ($ARCH)"
}

detect_network() {
    IPV4_ADDR=$(curl -4 -s --connect-timeout 2 https://api.ipify.org || curl -4 -s --connect-timeout 2 https://ipv4.icanhazip.com)
    IPV6_ADDR=$(curl -6 -s --connect-timeout 2 https://api64.ipify.org || curl -6 -s --connect-timeout 2 https://ipv6.icanhazip.com)
}

check_port() {
    local port=$1; local protocol=${2:-udp};
    if (command -v ss >/dev/null 2>&1); then
        if [[ "$protocol" == "udp" ]] && ss -lunp | grep -q ":$port\b"; then
            error_echo "端口 $port/udp 已被占用"
            return 1
        elif [[ "$protocol" == "tcp" ]] && ss -ltnp | grep -q ":$port\b"; then
            error_echo "端口 $port/tcp 已被占用"
            return 1
        fi
    fi
    return 0
}

################################################################################
# Hysteria2 功能模块 (100% 重设 - 源码编译)
################################################################################

# 步骤 1: 安装编译环境
hy2_install_build_deps() {
    info_echo "正在安装 Hysteria2 编译所需环境 (Go, Git, Make)..."
    case "$OS_TYPE" in
        "ubuntu"|"debian")
            apt-get update -qq
            apt-get install -y golang git make
            ;;
        "centos"|"rhel"|"almalinux"|"rocky")
            yum install -y golang git make
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE"
            return 1
            ;;
    esac
    if ! command -v go &>/dev/null; then
        error_echo "Go 语言环境安装失败！"
        return 1
    fi
    success_echo "编译环境安装成功。"
    return 0
}

# 步骤 2: 从源码编译 Hysteria2
hy2_build_from_source() {
    info_echo "正在从 GitHub 下载 Hysteria2 最新源码..."
    rm -rf /tmp/hysteria
    if ! git clone https://github.com/apernet/hysteria.git /tmp/hysteria; then
        error_echo "从 GitHub 下载源码失败！"
        return 1
    fi
    
    cd /tmp/hysteria/app/server
    info_echo "正在编译 Hysteria2 服务端..."
    if ! go build; then
        error_echo "Hysteria2 编译失败！"
        return 1
    fi
    
    info_echo "正在将编译好的文件安装到 /usr/local/bin/ ..."
    if [[ -f server ]]; then
        mv server /usr/local/bin/hysteria
        chmod +x /usr/local/bin/hysteria
    else
        error_echo "未找到编译后的 'server' 文件！"
        return 1
    fi

    cd /root # 返回主目录
    rm -rf /tmp/hysteria # 清理源码

    local hy2_version
    hy2_version=$(/usr/local/bin/hysteria version)
    success_echo "Hysteria2 源码编译并安装成功！版本: ${GREEN}${hy2_version}${ENDCOLOR}"
    return 0
}

# 步骤 3: 获取用户输入
hy2_get_user_input() {
    exec </dev/tty
    info_echo "开始配置 Hysteria2..."
    while true; do
        read -rp "请输入您的域名 (用于SNI): " HY_DOMAIN
        if [[ -n "$HY_DOMAIN" ]]; then break; else error_echo "域名不能为空"; fi
    done
    
    read -rsp "请输入 Hysteria2 密码 (回车将自动生成): " HY_PASSWORD; echo
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)
        info_echo "已自动生成安全密码: ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    fi
    
    read -rp "请输入伪装网址 (默认: ${HY_FAKE_URL}): " user_url
    [[ -n "$user_url" ]] && HY_FAKE_URL=$user_url
    
    return 0
}

# 步骤 4: 创建自签名证书
hy2_create_self_signed_cert() {
    info_echo "正在生成自签名证书..."
    mkdir -p /etc/hysteria2
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/hysteria2/private.key \
        -out /etc/hysteria2/fullchain.cer \
        -subj "/CN=$HY_DOMAIN" >/dev/null 2>&1
    success_echo "自签名证书创建成功。"
    return 0
}

# 步骤 5: 生成配置文件
hy2_generate_config() {
    info_echo "正在生成 Hysteria2 配置文件..."
    local listen_addr="0.0.0.0:443"
    [[ -n "$IPV6_ADDR" ]] && listen_addr="[::]:443"
    
    cat > /etc/hysteria2/config.yaml << EOF
listen: $listen_addr

tls:
  cert: /etc/hysteria2/fullchain.cer
  key: /etc/hysteria2/private.key

auth:
  type: password
  password: "$HY_PASSWORD"

masquerade:
  type: proxy
  proxy:
    url: "$HY_FAKE_URL"
    rewriteHost: true
EOF
    success_echo "配置文件 /etc/hysteria2/config.yaml 生成成功。"
    return 0
}

# 步骤 6: 创建并启动服务
hy2_setup_service() {
    info_echo "正在创建 Hysteria2 systemd 服务..."
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    info_echo "正在配置防火墙..."
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow 443/udp comment "Hysteria2" >/dev/null
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null
    fi

    info_echo "正在启动 Hysteria2 服务..."
    systemctl enable --now hysteria-server
    sleep 2

    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "Hysteria2 服务启动失败！请检查日志。"
        journalctl -u hysteria-server -n 20 --no-pager
        return 1
    fi
    success_echo "Hysteria2 服务已成功启动！"
    return 0
}

# 步骤 7: 显示结果
hy2_display_result() {
    local server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    local insecure="true" # 自签名证书模式
    
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${HY_DOMAIN}&insecure=${insecure}#HY2-Compiled-SelfSigned"
    
    local info_file="/root/hysteria2_info.txt"
    cat > "$info_file" << EOF
# Hysteria2 客户端配置信息 (源码编译版)
================================================
服务器地址: $server_addr
端口: 443
密码: $HY_PASSWORD
服务器名称指示 (SNI): $HY_DOMAIN
允许不安全连接 (insecure): $insecure

分享链接:
$share_link
================================================
EOF
    clear
    success_echo "Hysteria2 (源码编译) 安装完成！"
    echo
    cat "$info_file"
}


# 主安装流程 (自签名证书)
hy2_install_self_signed() {
    info_echo "开始 Hysteria2 (自签名) 安装流程..."
    
    hy2_install_build_deps && \
    hy2_build_from_source && \
    hy2_get_user_input && \
    hy2_create_self_signed_cert && \
    hy2_generate_config && \
    hy2_setup_service && \
    hy2_display_result || {
        error_echo "Hysteria2 安装过程中发生错误，已终止。"
    }
}

# 占位符：菜单2的ACME证书安装流程
hy2_install_acme() {
    warning_echo "通过源码编译安装 Let's Encrypt 证书模式正在开发中。"
    warning_echo "为了确保稳定性，请先选择菜单 1 (自签名证书) 进行安装。"
    info_echo "自签名证书模式在功能和性能上与 ACME 证书完全相同，且无需域名解析。"
}

# Hysteria2 卸载
hy2_uninstall() {
    info_echo "正在卸载 Hysteria2..."
    systemctl disable --now hysteria-server >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/hysteria-server.service /usr/local/bin/hysteria
    rm -rf /etc/hysteria2 /root/hysteria2_info.txt
    systemctl daemon-reload
    success_echo "Hysteria2 卸载完成。"
}

################################################################################
# Shadowsocks (IPv6-Only) 功能模块 (代码完全保留，无改动)
################################################################################
ss_check_ipv6() { info_echo "检查 IPv6 环境..."; if [[ -z "$IPV6_ADDR" ]]; then error_echo "未能检测到公网 IPv6 地址！"; return 1; fi; success_echo "IPv6 环境检查通过: $IPV6_ADDR"; }
ss_install_dependencies() { info_echo "为 Shadowsocks 安装依赖..."; local pkgs_to_install=(); local deps=("shadowsocks-libev" "qrencode"); for pkg in "${deps[@]}"; do case "$OS_TYPE" in "ubuntu"|"debian") dpkg -s "$pkg" &>/dev/null || pkgs_to_install+=("$pkg") ;; *) rpm -q "$pkg" &>/dev/null || pkgs_to_install+=("$pkg") ;; esac; done; if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then info_echo "需要安装: ${pkgs_to_install[*]}"; case "$OS_TYPE" in "ubuntu"|"debian") apt-get update -qq && apt-get install -y "${pkgs_to_install[@]}" ;; *) command -v dnf &>/dev/null && dnf install -y epel-release && dnf install -y "${pkgs_to_install[@]}" || yum install -y epel-release && yum install -y "${pkgs_to_install[@]}" ;; esac || { error_echo "依赖安装失败"; return 1; }; fi; }
ss_get_user_input() { exec </dev/tty; info_echo "开始配置 Shadowsocks..."; while true; do local default_port=$(shuf -i 20000-65000 -n 1); read -rp "请输入 Shadowsocks 端口 (默认: $default_port): " SS_PORT; SS_PORT=${SS_PORT:-$default_port}; check_port "$SS_PORT" "tcp" && check_port "$SS_PORT" "udp" && break; done; read -rsp "请输入 Shadowsocks 密码 (回车自动生成): " SS_PASSWORD; echo; if [[ -z "$SS_PASSWORD" ]]; then SS_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16); info_echo "自动生成密码: $SS_PASSWORD"; fi; info_echo "请选择加密方式:"; echo "1. aes-256-gcm (推荐)"; echo "2. chacha20-ietf-poly1305"; while true; do read -rp "请选择 [1-2]: " mc; case $mc in 1) SS_METHOD="aes-256-gcm"; break ;; 2) SS_METHOD="chacha20-ietf-poly1305"; break ;; *) error_echo "无效选择" ;; esac; done; }
ss_generate_config() { info_echo "生成 Shadowsocks 配置文件..."; mkdir -p /etc/shadowsocks-libev; cat > /etc/shadowsocks-libev/ss-ipv6-config.json << EOF
{ "server": "::", "server_port": ${SS_PORT}, "password": "${SS_PASSWORD}", "method": "${SS_METHOD}", "mode": "tcp_and_udp" }
EOF
}
ss_create_service() { info_echo "创建 Shadowsocks systemd 服务..."; cat > /etc/systemd/system/ss-ipv6.service << EOF
[Unit]
Description=Shadowsocks-libev IPv6-Only Server
After=network.target
[Service]
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/ss-ipv6-config.json
User=nobody
Group=nogroup
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; }
ss_configure_firewall() { info_echo "为 Shadowsocks 配置防火墙..."; if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then ufw allow "${SS_PORT}" comment "Shadowsocks" >/dev/null; elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-port="${SS_PORT}/tcp" >/dev/null 2>&1; firewall-cmd --permanent --add-port="${SS_PORT}/udp" >/dev/null 2>&1; firewall-cmd --reload >/dev/null; fi; }
ss_start_service() { info_echo "启动 Shadowsocks 服务..."; systemctl enable --now ss-ipv6; sleep 2; if systemctl is-active --quiet ss-ipv6; then success_echo "Shadowsocks 服务启动成功"; return 0; else error_echo "服务启动失败！"; journalctl -u ss-ipv6 -n 10 --no-pager; return 1; fi; }
ss_save_info() { local method_password_b64=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0); local ss_link="ss://${method_password_b64}@[${IPV6_ADDR}]:${SS_PORT}#SS-IPv6-Only"; cat > /root/ss_ipv6_info.txt << EOF
# Shadowsocks (IPv6-Only) Client Configuration
================================================
分享链接:
${ss_link}
================================================
EOF
}
ss_run_install() { if [[ -f /etc/systemd/system/ss-ipv6.service ]]; then warning_echo "检测到 Shadowsocks (IPv6) 已安装。"; read -rp "确定要覆盖安装吗? (y/N): " confirm && [[ ! "$confirm" =~ ^[yY]$ ]] && return; ss_uninstall; fi; ss_check_ipv6 && ss_install_dependencies && ss_get_user_input && ss_generate_config && ss_create_service && ss_configure_firewall || { error_echo "Shadowsocks 安装失败。"; return 1; }; if ss_start_service; then ss_save_info; clear; success_echo "Shadowsocks (IPv6-Only) 安装完成！"; cat /root/ss_ipv6_info.txt; echo; info_echo "配置二维码:"; qrencode -t UTF8 "$(grep "ss://" /root/ss_ipv6_info.txt)"; else error_echo "Shadowsocks 安装失败。"; return 1; fi; }
ss_uninstall() { info_echo "卸载 Shadowsocks (IPv6)..."; systemctl disable --now ss-ipv6 >/dev/null 2>&1 || true; rm -f /etc/systemd/system/ss-ipv6.service; rm -rf /etc/shadowsocks-libev /root/ss_ipv6_info.txt; systemctl daemon-reload; success_echo "Shadowsocks (IPv6) 卸载完成。"; }

################################################################################
# 统一管理功能
################################################################################
manage_services() { while true; do clear; echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}\n"; echo "1. 管理 Hysteria2"; echo "2. 管理 Shadowsocks (IPv6)"; echo "0. 返回主菜单"; read -rp "请选择: " choice; case $choice in 1) [[ -f /etc/systemd/system/hysteria-server.service ]] && manage_single_service "hysteria-server" || { error_echo "Hysteria2 未安装"; sleep 1; };; 2) [[ -f /etc/systemd/system/ss-ipv6.service ]] && manage_single_service "ss-ipv6" || { error_echo "Shadowsocks (IPv6) 未安装"; sleep 1; };; 0) return ;; *) error_echo "无效选择"; sleep 1 ;; esac; done; }
manage_single_service() { local service_name=$1; while true; do clear; echo -e "${CYAN}=== 管理 $service_name ===${ENDCOLOR}\n"; systemctl status "$service_name" --no-pager; echo -e "\n1.启动 2.停止 3.重启 4.日志 5.实时日志 0.返回"; read -rp "操作: " op_choice; case $op_choice in 1) systemctl start "$service_name"; sleep 1 ;; 2) systemctl stop "$service_name"; sleep 1 ;; 3) systemctl restart "$service_name"; sleep 1 ;; 4) clear; journalctl -u "$service_name" -n 100 --no-pager; read -rp "按回车继续..." ;; 5) journalctl -u "$service_name" -f ;; 0) return ;; *) error_echo "无效选择"; sleep 1 ;; esac; done; }
show_config_info() { clear; if [[ ! -f /root/hysteria2_info.txt && ! -f /root/ss_ipv6_info.txt ]]; then error_echo "未安装任何服务。"; return; fi; if [[ -f /root/hysteria2_info.txt ]]; then echo -e "${PURPLE}--- Hysteria2 配置 ---${ENDCOLOR}"; cat /root/hysteria2_info.txt; echo; fi; if [[ -f /root/ss_ipv6_info.txt ]]; then echo -e "${PURPLE}--- Shadowsocks (IPv6) 配置 ---${ENDCOLOR}"; cat /root/ss_ipv6_info.txt; echo; info_echo "二维码:"; qrencode -t UTF8 "$(grep "ss://" /root/ss_ipv6_info.txt)"; echo; fi; }
uninstall_services() { while true; do clear; echo -e "${CYAN}=== 卸载菜单 ===${ENDCOLOR}\n"; echo "1. 卸载 Hysteria2"; echo "2. 卸载 Shadowsocks (IPv6)"; echo "3. 🔥 完全清理所有组件"; echo "0. 返回主菜单"; read -rp "请选择: " choice; case $choice in 1) read -rp "确定要卸载 Hysteria2 吗? (y/N): " c && [[ "$c" =~ ^[yY]$ ]] && hy2_uninstall && success_echo "Hysteria2 卸载完成" ;; 2) read -rp "确定要卸载 Shadowsocks (IPv6) 吗? (y/N): " c && [[ "$c" =~ ^[yY]$ ]] && ss_uninstall && success_echo "Shadowsocks (IPv6) 卸载完成" ;; 3) warning_echo "将卸载所有服务！"; read -rp "确定吗? (y/N): " c && [[ "$c" =~ ^[yY]$ ]] && { hy2_uninstall; ss_uninstall; success_echo "清理完成"; } ;; 0) return ;; *) error_echo "无效选择" ;; esac; read -rp "按回车返回..."
done; }
backup_configs() { local backup_dir="/root/proxy_backup_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$backup_dir"; info_echo "正在备份配置到: $backup_dir"; if [[ -d /etc/hysteria2 ]]; then cp -r /etc/hysteria2 "$backup_dir/"; fi; if [[ -d /etc/shadowsocks-libev ]]; then cp -r /etc/shadowsocks-libev "$backup_dir/"; fi; success_echo "备份完成！"; }
diagnose_issues() { clear; echo -e "${CYAN}=== 系统诊断 ===${ENDCOLOR}\n"; echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2), Kernel: $(uname -r)"; echo "IPv4: ${IPV4_ADDR:-N/A}, IPv6: ${IPV6_ADDR:-N/A}"; echo -e "\n${YELLOW}--- 防火墙状态 ---${ENDCOLOR}"; if command -v ufw &>/dev/null; then ufw status | head -n1; else (command -v firewall-cmd &>/dev/null && echo "Firewalld: $(systemctl is-active firewalld)" || echo "未检测到 UFW/Firewalld"); fi; echo -e "\n${YELLOW}--- 服务状态 ---${ENDCOLOR}"; systemctl list-unit-files hysteria-server.service &>/dev/null && echo "Hysteria2: $(systemctl is-active hysteria-server)" || echo "Hysteria2: 未安装"; systemctl list-unit-files ss-ipv6.service &>/dev/null && echo "Shadowsocks: $(systemctl is-active ss-ipv6)" || echo "Shadowsocks: 未安装"; }

# --- 主函数 ---
main() {
    check_root
    detect_system
    
    while true; do
        detect_network
        exec </dev/tty
        show_menu
        read -rp "请选择操作 [0-8]: " main_choice
        case $main_choice in
            1) hy2_install_self_signed ;;
            2) hy2_install_acme ;;
            3) ss_run_install ;;
            4) manage_services ;;
            5) show_config_info ;;
            6) uninstall_services ;;
            7) backup_configs ;;
            8) diagnose_issues ;;
            0) info_echo "感谢使用!"; exit 0 ;;
            *) error_echo "无效选择"; sleep 1 ;;
        esac
        read -rp "按回车返回主菜单..."
    done
}

# 脚本入口
main
