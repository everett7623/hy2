#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 5.2 (Hysteria2 源码编译终极版 - 标准构建流程)

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

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v5.2) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}安装选项:${ENDCOLOR}"
    echo -e "   1. 安装 Hysteria2 (源码编译 - ${GREEN}终极方案，解决一切兼容性问题${ENDCOLOR})"
    echo -e "   2. 安装 Hysteria2 (Let's Encrypt - ${YELLOW}开发中...${ENDCOLOR})"
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
        fi
    fi
    return 0
}

################################################################################
# Hysteria2 功能模块 (100% 重设 - 标准构建流程)
################################################################################

# 步骤 1: 安装编译环境
hy2_install_build_deps() {
    info_echo "正在安装 Hysteria2 编译所需环境 (Go, Git, Make)..."
    case "$OS_TYPE" in
        "ubuntu"|"debian")
            apt-get update -qq && apt-get install -y golang git make
            ;;
        "centos"|"rhel"|"almalinux"|"rocky")
            yum install -y golang git make
            ;;
        *)
            error_echo "不支持的操作系统: $OS_TYPE"; return 1 ;;
    esac
    if ! command -v go &>/dev/null; then error_echo "Go 语言环境安装失败！"; return 1; fi
    success_echo "编译环境安装成功。"
    return 0
}

# 步骤 2: 从源码编译 Hysteria2 (标准构建流程)
hy2_build_from_source() {
    info_echo "正在从 GitHub 下载 Hysteria2 最新源码..."
    rm -rf /tmp/hysteria
    if ! git clone https://github.com/apernet/hysteria.git /tmp/hysteria; then
        error_echo "从 GitHub 下载源码失败！"; return 1
    fi
    
    cd /tmp/hysteria
    
    info_echo "正在使用标准流程编译 Hysteria2..."
    # --- 【核心修正】---
    # 不再进入子目录，直接从项目根目录构建目标
    # -o 参数指定输出文件名为 hysteria
    if ! go build -o hysteria ./cmd/hysteria; then
        error_echo "Hysteria2 编译失败！请检查上面的 Go 编译错误信息。"; return 1
    fi
    
    info_echo "正在将编译好的文件安装到 /usr/local/bin/ ..."
    if [[ -f hysteria ]]; then
        mv hysteria /usr/local/bin/hysteria
        chmod +x /usr/local/bin/hysteria
    else
        error_echo "未找到编译后的 'hysteria' 文件！"; return 1
    fi

    cd /root # 返回主目录
    rm -rf /tmp/hysteria # 清理源码

    local hy2_version
    hy2_version=$(/usr/local/bin/hysteria version | head -n 1)
    if [[ -z "$hy2_version" ]]; then
        error_echo "Hysteria2 已编译，但无法运行！这可能是未知的系统问题。"
        return 1
    fi
    success_echo "Hysteria2 源码编译并安装成功！版本: ${GREEN}${hy2_version}${ENDCOLOR}"
    return 0
}

# 步骤 3: 获取用户输入
hy2_get_user_input() {
    exec </dev/tty
    info_echo "开始配置 Hysteria2..."
    read -rp "请输入您的域名 (用于SNI): " HY_DOMAIN
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
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null
    fi
    info_echo "正在启动 Hysteria2 服务..."
    systemctl enable --now hysteria-server
    sleep 2
    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "Hysteria2 服务启动失败！请检查日志。"; journalctl -u hysteria-server -n 20 --no-pager; return 1
    fi
    success_echo "Hysteria2 服务已成功启动！"
    return 0
}

# 步骤 7: 显示结果
hy2_display_result() {
    local server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${HY_DOMAIN}&insecure=true#HY2-Compiled"
    local info_file="/root/hysteria2_info.txt"
    cat > "$info_file" << EOF
# Hysteria2 客户端配置信息 (源码编译版)
================================================
服务器地址: $server_addr
端口: 443
密码: $HY_PASSWORD
SNI: $HY_DOMAIN
跳过证书验证: true
分享链接: $share_link
================================================
EOF
    clear
    success_echo "Hysteria2 (源码编译) 安装完成！"
    echo; cat "$info_file"
}

# 主安装流程
hy2_run_install() {
    info_echo "开始 Hysteria2 安装流程..."
    if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
        warning_echo "检测到 Hysteria2 已安装。"; read -rp "确定要覆盖安装吗? (y/N): " confirm && [[ ! "$confirm" =~ ^[yY]$ ]] && return
        hy2_uninstall
    fi
    
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
# Shadowsocks (IPv6-Only) 功能模块 (代码完全保留)
################################################################################
ss_check_ipv6() { info_echo "检查 IPv6 环境..."; if [[ -z "$IPV6_ADDR" ]]; then error_echo "未能检测到公网 IPv6 地址！"; return 1; fi; success_echo "IPv6 环境检查通过: $IPV6_ADDR"; }
ss_install_dependencies() { info_echo "为 Shadowsocks 安装依赖..."; local pkgs=("shadowsocks-libev" "qrencode"); case "$OS_TYPE" in "ubuntu"|"debian") apt-get update -qq && apt-get install -y "${pkgs[@]}" ;; *) yum install -y epel-release && yum install -y "${pkgs[@]}" ;; esac || { error_echo "依赖安装失败"; return 1; } }
ss_get_user_input() { exec </dev/tty; info_echo "开始配置 Shadowsocks..."; read -rp "请输入 Shadowsocks 端口 [1024-65535]: " SS_PORT; read -rsp "请输入 Shadowsocks 密码 (回车自动生成): " SS_PASSWORD; echo; if [[ -z "$SS_PASSWORD" ]]; then SS_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16); info_echo "自动生成密码: $SS_PASSWORD"; fi; SS_METHOD="aes-256-gcm"; }
ss_generate_config() { mkdir -p /etc/shadowsocks-libev; cat > /etc/shadowsocks-libev/ss-ipv6-config.json << EOF
{ "server": "::", "server_port": ${SS_PORT}, "password": "${SS_PASSWORD}", "method": "${SS_METHOD}", "mode": "tcp_and_udp" }
EOF
}
ss_create_service() { cat > /etc/systemd/system/ss-ipv6.service << EOF
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
ss_start_service() { systemctl enable --now ss-ipv6; sleep 2; if systemctl is-active --quiet ss-ipv6; then success_echo "Shadowsocks 服务启动成功"; return 0; else error_echo "服务启动失败！"; journalctl -u ss-ipv6 -n 10 --no-pager; return 1; fi; }
ss_save_info() { local b64=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0); local link="ss://${b64}@[${IPV6_ADDR}]:${SS_PORT}#SS-IPv6"; cat > /root/ss_ipv6_info.txt << EOF
# Shadowsocks (IPv6-Only) 配置
================================================
链接: ${link}
================================================
EOF
}
ss_run_install() { if [[ -f /etc/systemd/system/ss-ipv6.service ]]; then warning_echo "Shadowsocks 已安装。"; read -rp "要覆盖吗? (y/N): " c && [[ ! "$c" =~ ^[yY]$ ]] && return; ss_uninstall; fi; ss_check_ipv6 && ss_install_dependencies && ss_get_user_input && ss_generate_config && ss_create_service || { error_echo "SS 安装失败。"; return 1; }; if ss_start_service; then ss_save_info; clear; success_echo "SS 安装完成！"; cat /root/ss_ipv6_info.txt; info_echo "二维码:"; qrencode -t UTF8 "$link"; else error_echo "SS 安装失败。"; return 1; fi; }
ss_uninstall() { systemctl disable --now ss-ipv6 >/dev/null 2>&1 || true; rm -f /etc/systemd/system/ss-ipv6.service /etc/shadowsocks-libev/ss-ipv6-config.json /root/ss_ipv6_info.txt; success_echo "SS 卸载完成。"; }

################################################################################
# 统一管理功能
################################################################################
manage_services() { # ... (内容无变化)
while true; do clear; echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}\n1. Hysteria2\n2. Shadowsocks (IPv6)\n0. 返回"; read -rp "选择: " choice; case $choice in 1) [[ -f /etc/systemd/system/hysteria-server.service ]] && manage_single_service "hysteria-server" || { error_echo "H2 未安装"; sleep 1; };; 2) [[ -f /etc/systemd/system/ss-ipv6.service ]] && manage_single_service "ss-ipv6" || { error_echo "SS 未安装"; sleep 1; };; 0) return ;; *) error_echo "无效" ;; esac; done; }
manage_single_service() { local s=$1; while true; do clear; echo -e "${CYAN}=== 管理 $s ===${ENDCOLOR}\n"; systemctl status "$s" --no-pager; echo -e "\n1.启动 2.停止 3.重启 4.日志 0.返回"; read -rp "操作: " op; case $op in 1) systemctl start "$s" ;; 2) systemctl stop "$s" ;; 3) systemctl restart "$s" ;; 4) clear; journalctl -u "$s" -n 100 --no-pager; read -rp "回车继续..." ;; 0) return ;; *) error_echo "无效" ;; esac; sleep 1; done; }
show_config_info() { clear; if [[ -f /root/hysteria2_info.txt ]]; then echo -e "${PURPLE}--- Hysteria2 配置 ---${ENDCOLOR}"; cat /root/hysteria2_info.txt; fi; if [[ -f /root/ss_ipv6_info.txt ]]; then echo -e "\n${PURPLE}--- SS (IPv6) 配置 ---${ENDCOLOR}"; cat /root/ss_ipv6_info.txt; info_echo "二维码:"; qrencode -t UTF8 "$(grep 'ss://' /root/ss_ipv6_info.txt)"; fi; }
uninstall_services() { clear; echo -e "${CYAN}=== 卸载 ===${ENDCOLOR}\n1. Hysteria2\n2. Shadowsocks (IPv6)\n3. 全部\n0. 返回"; read -rp "选择: " choice; case $choice in 1) hy2_uninstall ;; 2) ss_uninstall ;; 3) hy2_uninstall; ss_uninstall ;; 0) return ;; *) error_echo "无效" ;; esac; }

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
            1) hy2_run_install ;;
            2) warning_echo "开发中..." ;;
            3) ss_run_install ;;
            4) manage_services ;;
            5) show_config_info ;;
            6) uninstall_services ;;
            7) info_echo "备份功能待定..." ;;
            8) info_echo "诊断功能待定..." ;;
            0) info_echo "感谢使用!"; exit 0 ;;
            *) error_echo "无效选择";;
        esac
        read -rp "按回车返回主菜单..."
    done
}

main
