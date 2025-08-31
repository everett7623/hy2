#!/bin/bash

# Hysteria2 + IPv6 安装脚本
# 版本: 2.0 (纯净版)

set -e -o pipefail

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
DOMAIN=""
HY_PASSWORD=""
ACME_EMAIL=""
FAKE_URL=""
IPV4_ADDR=""
IPV6_ADDR=""
USE_ACME=false

# --- 辅助函数 ---
info_echo() { echo -e "${BLUE}[INFO]${ENDCOLOR} $1"; }
success_echo() { echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"; }
error_echo() { echo -e "${RED}[ERROR]${ENDCOLOR} $1"; }
warning_echo() { echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"; }

# 显示主菜单
show_menu() {
    clear
    local ipv4_display="${IPV4_ADDR:-N/A}"
    local ipv6_display="${IPV6_ADDR:-N/A}"
    
    echo -e "${BG_PURPLE} Pure Hysteria2 Management Script (v6.0) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} / ${GREEN}${ipv6_display}${ENDCOLOR}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}1.${ENDCOLOR} 安装 Hysteria2 (自签名证书)"
    echo -e " ${CYAN}2.${ENDCOLOR} 安装 Hysteria2 (Let's Encrypt 证书)"
    echo
    echo -e " ${CYAN}3.${ENDCOLOR} 卸载 Hysteria2 服务"
    echo -e " ${CYAN}4.${ENDCOLOR} 完全清理 (卸载所有组件)"
    echo -e "${PURPLE}----------------------------------------------------------------${ENDCOLOR}"
    echo -e " ${CYAN}5.${ENDCOLOR} 服务管理"
    echo -e " ${CYAN}6.${ENDCOLOR} 显示配置信息"
    echo -e " ${CYAN}7.${ENDCOLOR} 测试连通性"
    echo -e " ${CYAN}8.${ENDCOLOR} 更新 Hysteria2"
    echo
    echo -e " ${CYAN}0.${ENDCOLOR} 退出"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
}

# --- 系统检查函数 ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限"
        exit 1
    fi
}

detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_TYPE=$ID
    else
        error_echo "无法检测操作系统"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *) 
            error_echo "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    info_echo "检测到系统: $OS_TYPE ($ARCH)"
}

detect_network() {
    info_echo "检测网络配置..."
    IPV4_ADDR=$(curl -4 -s --connect-timeout 5 ip.sb 2>/dev/null || true)
    IPV6_ADDR=$(curl -6 -s --connect-timeout 5 ip.sb 2>/dev/null || true)
    
    if [[ -n "$IPV4_ADDR" ]]; then
        success_echo "检测到 IPv4: $IPV4_ADDR"
    fi
    
    if [[ -n "$IPV6_ADDR" ]]; then
        success_echo "检测到 IPv6: $IPV6_ADDR"
    fi
    
    if [[ -z "$IPV4_ADDR" && -z "$IPV6_ADDR" ]]; then
        error_echo "无法获取服务器IP地址"
        exit 1
    fi
}

install_dependencies() {
    info_echo "安装系统依赖..."
    local pkgs=("curl" "wget" "unzip" "openssl" "net-tools")
    
    case "$OS_TYPE" in
        "ubuntu"|"debian")
            pkgs+=("netcat-openbsd")
            apt-get update -qq
            apt-get install -y "${pkgs[@]}"
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            pkgs+=("nc")
            if command -v dnf &>/dev/null; then
                dnf install -y "${pkgs[@]}"
            else
                yum install -y "${pkgs[@]}"
            fi
            ;;
        *)
            warning_echo "未知操作系统，尝试通用包管理器..."
            ;;
    esac
}

check_port_443() {
    info_echo "检查端口 443..."
    if ss -ulnp | grep -q ":443 "; then
        error_echo "UDP 443 端口已被占用:"
        ss -ulnp | grep ":443 "
        exit 1
    fi
    success_echo "端口 443 可用"
}

configure_firewall() {
    info_echo "配置防火墙..."
    
    # UFW
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow 443/udp >/dev/null
        success_echo "UFW 防火墙已配置"
    # firewalld
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null
        success_echo "firewalld 防火墙已配置"
    # iptables
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT 1 -p udp --dport 443 -j ACCEPT
        # 尝试保存规则
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        success_echo "iptables 防火墙已配置"
    else
        warning_echo "未检测到防火墙，请手动开放 UDP 443 端口"
    fi
}

# --- 用户输入函数 ---
get_user_input() {
    exec </dev/tty
    
    echo
    info_echo "开始配置 Hysteria2..."
    
    # 域名输入
    while true; do
        read -rp "请输入您的域名: " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            error_echo "域名不能为空"
            continue
        fi
        if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            error_echo "域名格式不正确"
            continue
        fi
        break
    done
    
    # 密码输入
    read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD
    echo
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    # 伪装网址
    read -rp "请输入伪装网址 (默认: https://www.bing.com): " input_fake_url
    FAKE_URL=${input_fake_url:-https://www.bing.com}
    
    # 证书选择
    if [[ "$USE_ACME" == true ]]; then
        local default_email="user$(shuf -i 1000-9999 -n 1)@gmail.com"
        read -rp "请输入 ACME 邮箱 (默认: ${default_email}): " input_email
        ACME_EMAIL=${input_email:-$default_email}
        
        while true; do
            read -rsp "请输入 Cloudflare API Token (用于 DNS 验证): " CF_TOKEN
            echo
            if [[ -z "$CF_TOKEN" ]]; then
                error_echo "API Token 不能为空"
                continue
            fi
            
            # 验证 Token
            local root_domain=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
            local api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" \
                -H "Authorization: Bearer $CF_TOKEN")
            
            if echo "$api_result" | jq -e '.success==true and .result[0].id' >/dev/null; then
                success_echo "API Token 验证成功"
                break
            else
                error_echo "API Token 验证失败！"
                echo "$api_result" | jq '.errors' 2>/dev/null || echo "请检查 Token 权限"
            fi
        done
    fi
}

# --- 安装函数 ---
install_hysteria2() {
    info_echo "安装 Hysteria2..."
    
    local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    local dl_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name==\"hysteria-linux-$ARCH\") | .browser_download_url")
    
    if [[ -z "$dl_url" ]]; then
        # 尝试备用匹配
        dl_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-$ARCH\") and (contains(\"avx\") | not)) | .browser_download_url")
    fi
    
    if [[ -z "$dl_url" ]]; then
        error_echo "无法获取 Hysteria2 下载链接"
        exit 1
    fi
    
    wget -qO /usr/local/bin/hysteria "$dl_url"
    chmod +x /usr/local/bin/hysteria
    
    # 验证安装
    if /usr/local/bin/hysteria version >/dev/null 2>&1; then
        success_echo "Hysteria2 安装成功"
    else
        error_echo "Hysteria2 安装失败"
        exit 1
    fi
}

install_acme_and_cert() {
    info_echo "申请 Let's Encrypt SSL 证书..."
    
    # 安装 acme.sh
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
        source ~/.bashrc 2>/dev/null || true
    fi
    
    # 设置 Cloudflare API
    export CF_Token="$CF_TOKEN"
    
    # 申请证书
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --ecc
    
    # 安装证书
    mkdir -p /etc/hysteria2/certs
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
        --fullchain-file /etc/hysteria2/certs/fullchain.cer \
        --key-file /etc/hysteria2/certs/private.key
    
    chmod 600 /etc/hysteria2/certs/private.key
    success_echo "SSL 证书申请成功"
}

generate_self_signed_cert() {
    info_echo "生成自签名证书..."
    mkdir -p /etc/hysteria2/certs
    
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/hysteria2/certs/private.key \
        -out /etc/hysteria2/certs/fullchain.cer \
        -subj "/CN=$DOMAIN" 2>/dev/null
    
    chmod 600 /etc/hysteria2/certs/private.key
    success_echo "自签名证书生成成功"
}

generate_hysteria_config() {
    info_echo "生成 Hysteria2 配置..."
    mkdir -p /etc/hysteria2
    
    # 优先使用 IPv6，回退到 IPv4
    local listen_addr
    if [[ -n "$IPV6_ADDR" ]]; then
        listen_addr="[::]:443"
    else
        listen_addr="0.0.0.0:443"
    fi
    
    cat > /etc/hysteria2/config.yaml << EOF
# Hysteria2 服务端配置
listen: $listen_addr

# TLS 配置
tls:
  cert: /etc/hysteria2/certs/fullchain.cer
  key: /etc/hysteria2/certs/private.key

# 认证配置
auth:
  type: password
  password: $HY_PASSWORD

# 伪装配置
masquerade:
  type: proxy
  proxy:
    url: $FAKE_URL
    rewriteHost: true

# 性能优化 (可选)
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 60s
  keepAlivePeriod: 10s
  disablePathMTUDiscovery: false

# 带宽限制 (可选，单位: bps)
# bandwidth:
#   up: 1000000000    # 1 Gbps 上传
#   down: 1000000000  # 1 Gbps 下载
EOF

    success_echo "Hysteria2 配置生成完成"
}

create_systemd_service() {
    info_echo "创建 systemd 服务..."
    
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
Documentation=https://hysteria.network/
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
User=root
Group=root

# 安全设置
NoNewPrivileges=true
LimitNOFILE=1000000
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    success_echo "systemd 服务创建完成"
}

start_hysteria_service() {
    info_echo "启动 Hysteria2 服务..."
    systemctl enable hysteria-server
    systemctl start hysteria-server
    
    # 等待服务启动
    for ((i=1; i<=15; i++)); do
        if systemctl is-active --quiet hysteria-server; then
            if ss -ulnp | grep -q ":443.*hysteria"; then
                success_echo "Hysteria2 服务启动成功"
                return 0
            fi
        fi
        sleep 1
    done
    
    error_echo "Hysteria2 服务启动失败！"
    journalctl -u hysteria-server -n 20 --no-pager
    exit 1
}

save_config_info() {
    local cert_type="$1"
    mkdir -p /etc/hysteria2
    
    # 确定服务器地址
    local server_addr
    if [[ "$cert_type" == "acme" ]]; then
        server_addr="$DOMAIN"
    else
        server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    fi
    
    # 确定是否需要跳过证书验证
    local insecure=$([[ "$cert_type" == "self" ]] && echo "true" || echo "false")
    
    # 生成分享链接
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}&insecure=${insecure}#Pure-HY2-${cert_type^}"
    
    cat > /etc/hysteria2/client_info.txt << EOF
# Hysteria2 客户端配置信息 (生成时间: $(date))
# 证书类型: $cert_type
================================================================================

服务器地址: $server_addr
端口: 443
密码: $HY_PASSWORD
TLS SNI: $DOMAIN
跳过证书验证: $insecure

分享链接 (V2RayN / NekoBox / V2rayNG):
$share_link

Clash Meta YAML 配置 (标准格式):
- name: 'Pure-HY2-${cert_type^}'
  type: hysteria2
  server: '$server_addr'
  port: 443
  password: '$HY_PASSWORD'
  sni: '$DOMAIN'
  skip-cert-verify: $insecure

Clash Meta YAML 配置 (紧凑格式):
- { name: 'Pure-HY2-${cert_type^}', type: hysteria2, server: '$server_addr', port: 443, password: '$HY_PASSWORD', sni: '$DOMAIN', skip-cert-verify: $insecure }

Sing-box JSON 配置:
{
  "type": "hysteria2",
  "tag": "Pure-HY2-${cert_type^}",
  "server": "$server_addr",
  "server_port": 443,
  "password": "$HY_PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "$DOMAIN",
    "insecure": $insecure
  }
}

Xray/V2Ray VLESS 备用 (如果支持):
vless://$(uuidgen)@${server_addr}:443?encryption=none&security=tls&sni=${DOMAIN}&type=tcp&headerType=none#Pure-HY2-Fallback

================================================================================
EOF

    # 保存安装信息
    cat > /etc/hysteria2/install_info.env << EOF
# 安装信息
INSTALL_TIME=$(date)
CERT_TYPE=$cert_type
DOMAIN=$DOMAIN
HY_PASSWORD=$HY_PASSWORD
FAKE_URL=$FAKE_URL
SERVER_ADDR=$server_addr
MODE=pure
EOF

    cp /etc/hysteria2/client_info.txt /root/hysteria2_client_info.txt
    success_echo "配置信息已保存到 /root/hysteria2_client_info.txt"
}

# --- 测试功能 ---
test_connectivity() {
    info_echo "开始连通性测试..."
    
    if [[ ! -f /etc/systemd/system/hysteria-server.service ]]; then
        error_echo "Hysteria2 服务未安装"
        return 1
    fi
    
    # 检查服务状态
    info_echo "1. 检查服务状态..."
    if systemctl is-active --quiet hysteria-server; then
        success_echo "  ✓ Hysteria2 服务: 运行中"
    else
        error_echo "  ✗ Hysteria2 服务: 未运行！"
        return 1
    fi
    
    # 检查端口监听
    info_echo "2. 检查端口监听..."
    if ss -ulnp | grep -q ":443.*hysteria"; then
        success_echo "  ✓ Hysteria2 正在监听 UDP 443 端口"
    else
        error_echo "  ✗ Hysteria2 未监听 UDP 443 端口！"
        return 1
    fi
    
    # 检查证书
    info_echo "3. 检查证书文件..."
    if [[ -f /etc/hysteria2/certs/fullchain.cer && -f /etc/hysteria2/certs/private.key ]]; then
        success_echo "  ✓ 证书文件存在"
        
        # 检查证书有效期
        local cert_end_date=$(openssl x509 -in /etc/hysteria2/certs/fullchain.cer -noout -enddate | cut -d= -f2)
        local cert_end_timestamp=$(date -d "$cert_end_date" +%s)
        local current_timestamp=$(date +%s)
        local days_left=$(( (cert_end_timestamp - current_timestamp) / 86400 ))
        
        if [[ $days_left -gt 0 ]]; then
            success_echo "  ✓ 证书有效期: $days_left 天"
        else
            error_echo "  ✗ 证书已过期！"
        fi
    else
        error_echo "  ✗ 证书文件缺失！"
        return 1
    fi
    
    # 检查域名解析
    if [[ -n "$DOMAIN" ]]; then
        info_echo "4. 检查域名解析..."
        if nslookup "$DOMAIN" >/dev/null 2>&1; then
            success_echo "  ✓ 域名 '$DOMAIN' 解析正常"
        else
            warning_echo "  ⚠ 域名 '$DOMAIN' 解析失败"
        fi
    fi
    
    # 网络连通性测试
    info_echo "5. 测试外部连通性..."
    if curl -s --connect-timeout 5 ip.sb >/dev/null; then
        success_echo "  ✓ 外网连接正常"
    else
        warning_echo "  ⚠ 外网连接异常"
    fi
    
    echo
    success_echo "连通性测试完成"
}

# --- 服务管理 ---
service_management() {
    while true; do
        clear
        echo -e "${CYAN}=== 服务管理菜单 ===${ENDCOLOR}"
        echo
        
        # 显示服务状态
        echo -e "${CYAN}当前服务状态:${ENDCOLOR}"
        if systemctl is-active --quiet hysteria-server; then
            echo -e "${GREEN}  ✓ Hysteria2: 运行中${ENDCOLOR}"
        else
            echo -e "${RED}  ✗ Hysteria2: 未运行${ENDCOLOR}"
        fi
        
        echo
        echo -e " ${CYAN}1.${ENDCOLOR} 启动服务"
        echo -e " ${CYAN}2.${ENDCOLOR} 停止服务"
        echo -e " ${CYAN}3.${ENDCOLOR} 重启服务"
        echo -e " ${CYAN}4.${ENDCOLOR} 查看日志"
        echo -e " ${CYAN}5.${ENDCOLOR} 查看实时日志"
        echo -e " ${CYAN}0.${ENDCOLOR} 返回主菜单"
        echo

        read -rp "请选择操作 [0-5]: " choice
        case $choice in
            1)
                systemctl start hysteria-server
                sleep 2
                ;;
            2)
                systemctl stop hysteria-server
                sleep 1
                ;;
            3)
                systemctl restart hysteria-server
                sleep 2
                ;;
            4)
                journalctl -u hysteria-server -n 50 --no-pager
                read -rp "按回车键继续..."
                ;;
            5)
                echo "按 Ctrl+C 退出日志监控"
                sleep 2
                journalctl -u hysteria-server -f --no-pager
                ;;
            0)
                return
                ;;
            *)
                error_echo "无效选择"
                sleep 1
                ;;
        esac
    done
}

# --- 卸载函数 ---
uninstall_hysteria() {
    warning_echo "即将卸载 Hysteria2 服务..."
    read -rp "确定继续? (y/N): " confirm
    if [[ "$confirm" != "y" ]]; then
        info_echo "取消卸载"
        return 0
    fi
    
    # 停止并禁用服务
    systemctl disable --now hysteria-server 2>/dev/null || true
    
    # 删除服务文件
    rm -f /etc/systemd/system/hysteria-server.service
    systemctl daemon-reload
    
    # 删除二进制文件
    rm -f /usr/local/bin/hysteria
    
    # 删除配置目录
    rm -rf /etc/hysteria2
    
    success_echo "Hysteria2 已完全卸载"
    read -rp "按回车键返回主菜单..."
}

complete_cleanup() {
    warning_echo "即将完全清理所有组件和配置..."
    read -rp "确定继续? (y/N): " confirm
    if [[ "$confirm" != "y" ]]; then
        info_echo "取消清理"
        return 0
    fi
    
    # 读取安装信息
    if [[ -f /etc/hysteria2/install_info.env ]]; then
        source /etc/hysteria2/install_info.env
    fi
    
    # 停止服务
    systemctl disable --now hysteria-server 2>/dev/null || true
    
    # 删除服务文件
    rm -f /etc/systemd/system/hysteria-server.service
    systemctl daemon-reload
    
    # 删除二进制文件
    rm -f /usr/local/bin/hysteria
    
    # 清理证书 (如果是 Let's Encrypt)
    if [[ "$CERT_TYPE" == "acme" && -n "$DOMAIN" ]] && command -v ~/.acme.sh/acme.sh &>/dev/null; then
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --ecc 2>/dev/null || true
        info_echo "Let's Encrypt 证书已移除"
    fi
    
    # 删除配置目录
    rm -rf /etc/hysteria2
    rm -f /root/hysteria2_client_info.txt
    
    success_echo "完全清理完成！"
    read -rp "按回车键返回主菜单..."
}

update_hysteria2() {
    info_echo "更新 Hysteria2..."
    
    if [[ ! -f /usr/local/bin/hysteria ]]; then
        error_echo "Hysteria2 未安装"
        return 1
    fi
    
    # 获取当前版本
    local current_version=$(/usr/local/bin/hysteria version 2>/dev/null | head -n1 || echo "未知")
    info_echo "当前版本: $current_version"
    
    # 下载最新版本
    local api_url="https://api.github.com/repos/apernet/hysteria/releases/latest"
    local latest_version=$(curl -s "$api_url" | jq -r '.tag_name')
    local dl_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name==\"hysteria-linux-$ARCH\") | .browser_download_url")
    
    if [[ -z "$dl_url" ]]; then
        error_echo "无法获取下载链接"
        return 1
    fi
    
    info_echo "最新版本: $latest_version"
    
    # 停止服务
    systemctl stop hysteria-server
    
    # 备份当前版本
    cp /usr/local/bin/hysteria /usr/local/bin/hysteria.backup
    
    # 下载新版本
    if wget -qO /usr/local/bin/hysteria "$dl_url"; then
        chmod +x /usr/local/bin/hysteria
        
        # 启动服务
        systemctl start hysteria-server
        
        # 验证更新
        if systemctl is-active --quiet hysteria-server; then
            success_echo "Hysteria2 更新成功"
            rm -f /usr/local/bin/hysteria.backup
        else
            error_echo "更新后服务启动失败，恢复旧版本"
            mv /usr/local/bin/hysteria.backup /usr/local/bin/hysteria
            systemctl start hysteria-server
        fi
    else
        error_echo "下载新版本失败"
        systemctl start hysteria-server
    fi
    
    read -rp "按回车键返回主菜单..."
}

# --- 安装流程 ---
cleanup_previous_installation() {
    if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
        info_echo "检测到已有安装，清理旧配置..."
        systemctl disable --now hysteria-server 2>/dev/null || true
        rm -f /etc/systemd/system/hysteria-server.service
        systemctl daemon-reload
        rm -rf /etc/hysteria2
        success_echo "旧配置清理完成"
    fi
}

run_install() {
    local cert_type="$1"
    
    info_echo "开始安装 Pure Hysteria2 (证书类型: $cert_type)..."
    
    # 设置证书类型标志
    if [[ "$cert_type" == "acme" ]]; then
        USE_ACME=true
    else
        USE_ACME=false
    fi
    
    # 执行安装步骤
    cleanup_previous_installation
    detect_system
    install_dependencies
    check_port_443
    detect_network
    get_user_input
    install_hysteria2
    
    # 证书处理
    if [[ "$cert_type" == "acme" ]]; then
        install_acme_and_cert
    else
        generate_self_signed_cert
    fi
    
    # 配置和启动
    generate_hysteria_config
    create_systemd_service
    configure_firewall
    start_hysteria_service
    save_config_info "$cert_type"
    show_installation_result "$cert_type"
    
    read -rp "按回车键返回主菜单..."
}

show_installation_result() {
    local cert_type="$1"
    clear
    
    echo -e "${GREEN}========================================${ENDCOLOR}"
    echo -e "${GREEN}    Pure Hysteria2 安装完成！${ENDCOLOR}"
    echo -e "${GREEN}========================================${ENDCOLOR}"
    echo
    
    cat /etc/hysteria2/client_info.txt
    
    echo
    if [[ "$cert_type" == "self" ]]; then
        warning_echo "使用自签名证书，客户端需要开启 'skip-cert-verify: true'"
        warning_echo "推荐客户端: V2rayN, NekoBox, Clash Meta"
    else
        success_echo "使用 Let's Encrypt 证书，无需跳过证书验证"
        info_echo "DNS 解析可能需要几分钟同步，请耐心等待"
    fi
    
    echo
    info_echo "配置文件位置: /etc/hysteria2/config.yaml"
    info_echo "客户端信息: /root/hysteria2_client_info.txt"
    info_echo "服务管理: systemctl {start|stop|restart|status} hysteria-server"
}

# --- 信息显示 ---
show_config_info() {
    if [[ -f /etc/hysteria2/client_info.txt ]]; then
        clear
        cat /etc/hysteria2/client_info.txt
    else
        error_echo "未找到配置信息，请先安装 Hysteria2"
    fi
    read -rp "按回车键返回主菜单..."
}

# --- 主函数 ---
main_menu() {
    check_root
    detect_network
    
    while true; do
        exec </dev/tty
        show_menu
        
        read -rp "请选择操作 [0-8]: " choice
        case $choice in
            1)
                run_install "self"
                ;;
            2)
                run_install "acme"
                ;;
            3)
                uninstall_hysteria
                ;;
            4)
                complete_cleanup
                ;;
            5)
                service_management
                ;;
            6)
                show_config_info
                ;;
            7)
                if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
                    test_connectivity
                else
                    error_echo "Hysteria2 服务未安装"
                fi
                read -rp "按回车键返回主菜单..."
                ;;
            8)
                update_hysteria2
                ;;
            0)
                info_echo "感谢使用 Pure Hysteria2 脚本!"
                exit 0
                ;;
            *)
                error_echo "无效选择，请重新输入"
                sleep 1
                ;;
        esac
    done
}

# 脚本入口
main_menu
