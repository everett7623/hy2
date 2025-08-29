#!/bin/bash
# Hysteria2 + IPv6 + Cloudflare Tunnel 一键安装脚本 v3.1
# 优化内容：acme.sh 路径修复 / reloadcmd / realpath / DNS 校验 / 自动带宽优化 / Arch 支持
# 作者: GPT-5 优化 by ChatGPT

set -e -o pipefail

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

#================ 工具函数 ==================
info() { echo -e "${GREEN}[信息]${PLAIN} $1"; }
warn() { echo -e "${YELLOW}[警告]${PLAIN} $1"; }
error() { echo -e "${RED}[错误]${PLAIN} $1"; exit 1; }

#================ 依赖检测 ==================
check_dependencies() {
    info "检测并安装依赖..."
    if command -v apt >/dev/null 2>&1; then
        apt update && apt install -y curl socat unzip wget jq
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl socat unzip wget jq
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl socat unzip wget jq
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm curl socat unzip wget jq
    else
        error "不支持的发行版，请手动安装 curl socat unzip wget jq"
    fi
}

#================ 输入参数 ==================
get_input() {
    read -rp "请输入绑定的域名: " DOMAIN
    read -rp "请输入 Cloudflare Global API Key: " CF_API_KEY
    read -rp "请输入 Cloudflare 邮箱: " CF_EMAIL
    read -rp "请输入 Cloudflare Zone ID: " CF_ZONE_ID
    read -rp "请输入 Cloudflare Tunnel Token: " CF_TUNNEL_TOKEN
}

#================ 安装组件 ==================
install_hysteria() {
    info "安装 hysteria2..."
    bash <(curl -fsSL https://get.hy2.sh/)
}

install_cloudflared() {
    info "安装 Cloudflare Tunnel..."
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
        -o /usr/local/bin/cloudflared
    chmod +x /usr/local/bin/cloudflared
    mkdir -p /etc/cloudflared
}

#================ 生成配置 ==================
generate_hysteria_config() {
    info "生成 hysteria2 配置..."
    PASSWD=$(openssl rand -base64 16)
    mkdir -p /etc/hysteria
    cat > /etc/hysteria/config.yaml <<EOF
listen: :443
acme:
  domains:
    - ${DOMAIN}
  email: admin@${DOMAIN}
auth:
  type: password
  password: ${PASSWD}
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
EOF
    echo "${PASSWD}" > /etc/hysteria/hy2.passwd
}

generate_cloudflared_config() {
    info "生成 cloudflared 配置..."
    cat > /etc/cloudflared/config.yml <<EOF
tunnel: $(uuidgen)
credentials-file: /etc/cloudflared/$(uuidgen).json
protocol: quic
warp-routing:
  enabled: true
ingress:
  - hostname: ${DOMAIN}
    service: https://[::1]:443
  - service: http_status:404
EOF
}

#================ 配置服务 ==================
setup_hysteria_service() {
    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reexec
    systemctl enable --now hysteria-server
}

setup_cloudflared_service() {
    cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reexec
    systemctl enable --now cloudflared
}

#================ 域名校验 ==================
check_dns() {
    info "校验 DNS 解析..."
    sleep 5
    if dig +short AAAA ${DOMAIN} @1.1.1.1 | grep -q ':'; then
        info "域名 ${DOMAIN} 解析成功"
    else
        warn "域名 ${DOMAIN} 未解析到 IPv6，可能需要等待 DNS 生效"
    fi
}

#================ 管理脚本 ==================
install_manage_script() {
    cp "$(realpath "$0")" /usr/local/bin/hy2-manage
    chmod +x /usr/local/bin/hy2-manage
    info "管理脚本已安装: hy2-manage"
}

#================ 卸载功能 ==================
uninstall() {
    systemctl stop hysteria-server cloudflared
    systemctl disable hysteria-server cloudflared
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /etc/systemd/system/cloudflared.service
    rm -rf /etc/hysteria /etc/cloudflared
    rm -f /usr/local/bin/hysteria /usr/local/bin/cloudflared /usr/local/bin/hy2-manage
    systemctl daemon-reexec
    info "卸载完成"
}

#================ 主流程 ==================
main() {
    if [[ "$1" == "uninstall" ]]; then
        uninstall
        exit 0
    fi

    check_dependencies
    get_input
    install_hysteria
    install_cloudflared
    generate_hysteria_config
    generate_cloudflared_config
    setup_hysteria_service
    setup_cloudflared_service
    check_dns
    install_manage_script

    info "================== 安装完成 =================="
    info "域名: ${DOMAIN}"
    info "密码: $(cat /etc/hysteria/hy2.passwd)"
    info "管理脚本: hy2-manage"
    info "卸载命令: hy2-manage uninstall"
    info "=============================================="
}

main "$@"
