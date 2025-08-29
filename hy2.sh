#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 一键安装脚本
# 版本: 1.0
# 作者: Jensfrank
# 项目: hy2ipv6

set -e -o pipefail

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ENDCOLOR='\033[0m'

# 辅助函数
info_echo() {
    echo -e "${BLUE}[INFO]${ENDCOLOR} $1"
}

success_echo() {
    echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"
}

error_echo() {
    echo -e "${RED}[ERROR]${ENDCOLOR} $1"
}

warning_echo() {
    echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"
}

# 全局变量
IPV6_ADDR=""
IPV4_ADDR=""
DOMAIN=""
CF_TOKEN=""
HY_PASSWORD=""
ACME_EMAIL="admin@example.com"
FAKE_URL="https://www.google.com"
OS_TYPE=""
ARCH=""

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限运行"
        exit 1
    fi
}

# 检测系统信息
detect_system() {
    info_echo "检测系统信息..."
    
    if [[ -f /etc/debian_version ]]; then
        OS_TYPE="debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS_TYPE="rhel"
    else
        error_echo "不支持的操作系统，仅支持 Debian/Ubuntu/CentOS/RHEL"
        exit 1
    fi
    
    case $(uname -m) in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        *)
            error_echo "不支持的架构: $(uname -m)"
            exit 1
            ;;
    esac
    
    success_echo "系统信息: $OS_TYPE, 架构: $ARCH"
}

# 安装依赖包
install_dependencies() {
    info_echo "检查并安装依赖包..."
    
    local packages=("curl" "socat" "unzip" "wget" "jq")
    
    for package in "${packages[@]}"; do
        if ! command -v "$package" &> /dev/null; then
            info_echo "安装 $package..."
            case "$OS_TYPE" in
                "debian")
                    apt-get update -qq
                    apt-get install -y "$package"
                    ;;
                "rhel")
                    yum install -y "$package"
                    ;;
            esac
        fi
    done
    
    success_echo "依赖包检查完成"
}

# 检测网络环境
detect_network() {
    info_echo "检测网络环境..."
    
    # 检测 IPv6
    IPV6_ADDR=$(curl -6 --connect-timeout 10 -s ip.sb 2>/dev/null || echo "")
    
    # 检测 IPv4
    IPV4_ADDR=$(curl -4 --connect-timeout 10 -s ip.sb 2>/dev/null || echo "")
    
    if [[ -n "$IPV6_ADDR" ]]; then
        success_echo "检测到 IPv6 地址: $IPV6_ADDR"
        if [[ -n "$IPV4_ADDR" ]]; then
            info_echo "检测到 IPv4 地址: $IPV4_ADDR (IPv6 优先模式)"
        else
            info_echo "当前为 IPv6 Only 环境"
        fi
    elif [[ -n "$IPV4_ADDR" ]]; then
        success_echo "检测到 IPv4 地址: $IPV4_ADDR (仅 IPv4 模式)"
    else
        error_echo "未能检测到公网 IP 地址"
        exit 1
    fi
}

# 获取用户输入
get_user_input() {
    echo
    info_echo "开始配置参数..."
    
    # 域名输入
    while [[ -z "$DOMAIN" ]]; do
        read -p "请输入您的域名: " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            warning_echo "域名不能为空，请重新输入"
        fi
    done
    
    # Cloudflare Token 输入与验证
    while true; do
        read -p "请输入 Cloudflare API Token: " CF_TOKEN
        if [[ -z "$CF_TOKEN" ]]; then
            warning_echo "Token 不能为空，请重新输入"
            continue
        fi
        
        info_echo "验证 Cloudflare Token..."
        local verify_result
        verify_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
            -H "Authorization: Bearer $CF_TOKEN" \
            -H "Content-Type: application/json")
        
        if echo "$verify_result" | jq -r '.success' | grep -q "true"; then
            success_echo "Token 验证成功"
            break
        else
            error_echo "Token 验证失败，请检查 Token 是否正确或权限是否足够"
            warning_echo "Token 需要包含 Zone:Read, DNS:Edit, Zone Settings:Read 权限"
        fi
    done
    
    # Hysteria 密码
    read -p "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    # ACME 邮箱
    read -p "请输入 ACME 邮箱 (回车使用默认): " input_email
    if [[ -n "$input_email" ]]; then
        ACME_EMAIL="$input_email"
    fi
    
    # 伪装网址
    read -p "请输入伪装网址 (回车使用默认): " input_fake
    if [[ -n "$input_fake" ]]; then
        FAKE_URL="$input_fake"
    fi
}

# 获取最新版本和下载链接
get_latest_version() {
    local repo="$1"
    local binary_name="$2"
    
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local release_info
    release_info=$(curl -s "$api_url")
    
    if [[ "$binary_name" == "hysteria" ]]; then
        echo "$release_info" | jq -r ".assets[] | select(.name | contains(\"linux-$ARCH\")) | .browser_download_url" | head -1
    elif [[ "$binary_name" == "cloudflared" ]]; then
        echo "$release_info" | jq -r ".assets[] | select(.name | contains(\"linux-$ARCH\")) | .browser_download_url" | head -1
    fi
}

# 安装 Hysteria2
install_hysteria2() {
    info_echo "安装 Hysteria2..."
    
    local download_url
    download_url=$(get_latest_version "apernet/hysteria" "hysteria")
    
    if [[ -z "$download_url" ]]; then
        error_echo "获取 Hysteria2 下载链接失败"
        exit 1
    fi
    
    cd /tmp
    wget -O hysteria2.tar.gz "$download_url"
    tar -xzf hysteria2.tar.gz
    
    # 查找解压后的二进制文件
    local binary_file
    binary_file=$(find . -name "hysteria" -type f | head -1)
    
    if [[ -z "$binary_file" ]]; then
        error_echo "未找到 Hysteria2 二进制文件"
        exit 1
    fi
    
    mv "$binary_file" /usr/local/bin/hysteria
    chmod +x /usr/local/bin/hysteria
    
    # 验证安装
    if ! hysteria version &> /dev/null; then
        error_echo "Hysteria2 安装验证失败"
        exit 1
    fi
    
    success_echo "Hysteria2 安装完成"
}

# 安装 Cloudflared
install_cloudflared() {
    info_echo "安装 Cloudflared..."
    
    local download_url
    download_url=$(get_latest_version "cloudflare/cloudflared" "cloudflared")
    
    if [[ -z "$download_url" ]]; then
        error_echo "获取 Cloudflared 下载链接失败"
        exit 1
    fi
    
    cd /tmp
    wget -O cloudflared "$download_url"
    mv cloudflared /usr/local/bin/
    chmod +x /usr/local/bin/cloudflared
    
    # 验证安装
    if ! cloudflared version &> /dev/null; then
        error_echo "Cloudflared 安装验证失败"
        exit 1
    fi
    
    success_echo "Cloudflared 安装完成"
}

# 安装 ACME.sh 并申请证书
install_acme_and_cert() {
    info_echo "安装 ACME.sh 并申请 SSL 证书..."
    
    # 安装 acme.sh
    curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
    source ~/.bashrc
    
    # 设置 Cloudflare API Token
    export CF_Token="$CF_TOKEN"
    
    # 申请证书
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN"
    
    # 安装证书
    mkdir -p /etc/hysteria2/certs
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
        --fullchain-file /etc/hysteria2/certs/fullchain.cer \
        --key-file /etc/hysteria2/certs/private.key
    
    # 验证证书文件
    if [[ ! -f "/etc/hysteria2/certs/fullchain.cer" ]] || [[ ! -f "/etc/hysteria2/certs/private.key" ]]; then
        error_echo "证书文件生成失败"
        exit 1
    fi
    
    success_echo "SSL 证书申请完成"
}

# 生成 Hysteria2 配置
generate_hysteria_config() {
    info_echo "生成 Hysteria2 配置..."
    
    mkdir -p /etc/hysteria2
    
    cat > /etc/hysteria2/config.yaml << EOF
listen: :443

tls:
  cert: /etc/hysteria2/certs/fullchain.cer
  key: /etc/hysteria2/certs/private.key

auth:
  type: password
  password: $HY_PASSWORD

masquerade:
  type: proxy
  proxy:
    url: $FAKE_URL

bandwidth:
  up: 1 gbps
  down: 1 gbps
EOF

    success_echo "Hysteria2 配置文件生成完成"
}

# 创建 systemd 服务
create_systemd_services() {
    info_echo "创建 systemd 服务..."
    
    # 创建 Hysteria2 服务
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria2/config.yaml
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    # 创建 Cloudflared 服务
    cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel --edge-ip-version 6 --url https://localhost:443 --no-autoupdate
Restart=always
RestartSec=5
User=root
Environment=TUNNEL_TOKEN=$CF_TOKEN

[Install]
WantedBy=multi-user.target
EOF

    success_echo "systemd 服务文件创建完成"
}

# 启动服务
start_services() {
    info_echo "启动服务..."
    
    systemctl daemon-reload
    systemctl enable hysteria-server cloudflared
    systemctl start hysteria-server
    systemctl start cloudflared
    
    # 健康检查
    sleep 3
    if systemctl is-active hysteria-server &> /dev/null && systemctl is-active cloudflared &> /dev/null; then
        success_echo "所有服务启动成功"
    else
        error_echo "服务启动检查失败"
        warning_echo "请使用以下命令检查服务状态："
        warning_echo "  systemctl status hysteria-server"
        warning_echo "  systemctl status cloudflared"
        warning_echo "或查看日志："
        warning_echo "  journalctl -u hysteria-server"
        warning_echo "  journalctl -u cloudflared"
        exit 1
    fi
}

# 显示安装结果
show_installation_result() {
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${ENDCOLOR}"
    echo -e "${GREEN}║                        安装成功！                              ║${ENDCOLOR}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${ENDCOLOR}"
    echo -e "${GREEN}║  服务器地址: ${ENDCOLOR}$DOMAIN                                     ${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  端口:       ${ENDCOLOR}443                                          ${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  密码:       ${ENDCOLOR}$HY_PASSWORD                                ${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  协议:       ${ENDCOLOR}hysteria2                                   ${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  TLS:        ${ENDCOLOR}启用                                        ${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  伪装网址:   ${ENDCOLOR}$FAKE_URL                                   ${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${ENDCOLOR}"
    echo -e "${GREEN}║  管理命令: hy2-manage [start|stop|restart|status|log|uninstall] ║${ENDCOLOR}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${ENDCOLOR}"
    echo
    
    # 生成客户端配置
    echo -e "${BLUE}客户端配置 JSON:${ENDCOLOR}"
    echo "{"
    echo "  \"server\": \"$DOMAIN:443\","
    echo "  \"auth\": \"$HY_PASSWORD\","
    echo "  \"tls\": {"
    echo "    \"sni\": \"$DOMAIN\""
    echo "  },"
    echo "  \"bandwidth\": {"
    echo "    \"up\": \"100 mbps\","
    echo "    \"down\": \"100 mbps\""
    echo "  }"
    echo "}"
}

# 安装管理脚本
install_management_script() {
    info_echo "安装管理脚本..."
    cp "$0" /usr/local/bin/hy2-manage
    chmod +x /usr/local/bin/hy2-manage
    success_echo "管理脚本已安装到 /usr/local/bin/hy2-manage"
}

# 管理功能
manage_service() {
    case "$1" in
        "start")
            systemctl start hysteria-server cloudflared
            success_echo "服务已启动"
            ;;
        "stop")
            systemctl stop hysteria-server cloudflared
            success_echo "服务已停止"
            ;;
        "restart")
            systemctl restart hysteria-server cloudflared
            success_echo "服务已重启"
            ;;
        "status")
            echo "Hysteria2 状态:"
            systemctl status hysteria-server --no-pager
            echo
            echo "Cloudflared 状态:"
            systemctl status cloudflared --no-pager
            ;;
        "log")
            echo "实时查看 Hysteria2 日志 (Ctrl+C 退出):"
            journalctl -u hysteria-server -f
            ;;
        "uninstall")
            uninstall_all
            ;;
        *)
            echo "用法: hy2-manage [start|stop|restart|status|log|uninstall]"
            exit 1
            ;;
    esac
}

# 完全卸载
uninstall_all() {
    warning_echo "开始完全卸载 Hysteria2 和相关组件..."
    
    read -p "确定要完全卸载吗？此操作不可逆 (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info_echo "取消卸载"
        exit 0
    fi
    
    # 停止并禁用服务
    info_echo "停止服务..."
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true
    
    # 删除 systemd 服务文件
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    
    # 删除二进制文件
    rm -f /usr/local/bin/hysteria
    rm -f /usr/local/bin/cloudflared
    
    # 删除配置文件
    rm -rf /etc/hysteria2
    
    # 吊销并删除证书
    if [[ -f ~/.acme.sh/acme.sh ]]; then
        info_echo "删除 SSL 证书..."
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" 2>/dev/null || true
    fi
    
    # 删除管理脚本自身
    rm -f /usr/local/bin/hy2-manage
    
    success_echo "Hysteria2 已完全卸载"
    success_echo "感谢使用！"
}

# 主安装流程
main_install() {
    clear
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${ENDCOLOR}"
    echo -e "${GREEN}║             Hysteria2 + IPv6 + Cloudflare Tunnel               ║${ENDCOLOR}"
    echo -e "${GREEN}║                        一键安装脚本                             ║${ENDCOLOR}"
    echo -e "${GREEN}║                     Version: 1.0                               ║${ENDCOLOR}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${ENDCOLOR}"
    echo
    
    check_root
    detect_system
    install_dependencies
    detect_network
    get_user_input
    
    info_echo "开始安装组件..."
    install_hysteria2
    install_cloudflared
    install_acme_and_cert
    generate_hysteria_config
    create_systemd_services
    start_services
    install_management_script
    
    show_installation_result
}

# 主入口
if [[ $# -eq 0 ]]; then
    # 无参数，执行安装
    main_install
else
    # 有参数，执行管理功能
    manage_service "$1"
fi
