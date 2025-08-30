#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 菜单式安装脚本
# 版本: 4.0 (菜单版 + 连通性修复)
# 作者: Jensfrank
# 项目: hy2ipv6

# -e: 当命令失败时立即退出脚本
# -o pipefail: 管道中的任何命令失败都会导致整个管道失败
set -e -o pipefail

# --- 脚本配置与变量 ---

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
ENDCOLOR='\033[0m'

# 全局变量
OS_TYPE=""
ARCH=""
DOMAIN=""
CF_TOKEN=""
HY_PASSWORD=""
ACME_EMAIL=""
FAKE_URL=""
CF_ZONE_ID=""
CF_ACCOUNT_ID=""
TUNNEL_ID=""
readonly TUNNEL_NAME="hysteria-tunnel" # 使用 readonly 定义常量
IPV4_ADDR=""
IPV6_ADDR=""
CLOUDFLARED_PATH=""

# --- 辅助函数 ---

info_echo() { echo -e "${BLUE}[INFO]${ENDCOLOR} $1"; }
success_echo() { echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"; }
error_echo() { echo -e "${RED}[ERROR]${ENDCOLOR} $1"; }
warning_echo() { echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"; }

# 显示主菜单
show_menu() {
    clear
    echo -e "${PURPLE}╔════════════════════════════════════════════════════════════════╗${ENDCOLOR}"
    echo -e "${PURPLE}║             Hysteria2 + IPv6 + Cloudflare Tunnel               ║${ENDCOLOR}"
    echo -e "${PURPLE}║                      菜单式安装脚本 (v4.0)                      ║${ENDCOLOR}"
    echo -e "${PURPLE}╠════════════════════════════════════════════════════════════════╣${ENDCOLOR}"
    echo -e "${PURPLE}║                                                                ║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}1.${ENDCOLOR} 安装 Hysteria2 (直连模式)                          ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}2.${ENDCOLOR} 安装 Hysteria2 + Cloudflare Tunnel (CDN模式)       ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}3.${ENDCOLOR} 卸载 Hysteria2 (保留Cloudflare)                    ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}4.${ENDCOLOR} 卸载 Hysteria2 + Cloudflare Tunnel                 ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}5.${ENDCOLOR} 完全清理 (卸载所有组件和脚本)                      ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}6.${ENDCOLOR} 服务管理 (启动/停止/重启/状态/日志)                ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}7.${ENDCOLOR} 显示配置信息                                      ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}8.${ENDCOLOR} 测试连通性                                        ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║  ${CYAN}0.${ENDCOLOR} 退出                                              ${PURPLE}║${ENDCOLOR}"
    echo -e "${PURPLE}║                                                                ║${ENDCOLOR}"
    echo -e "${PURPLE}╚════════════════════════════════════════════════════════════════╝${ENDCOLOR}"
    echo
}

# 连通性测试函数
test_connectivity() {
    info_echo "开始连通性测试..."
    
    # 检查服务状态
    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "Hysteria2 服务未运行！"
        return 1
    fi
    
    # 检查端口监听
    if ! ss -ulnp | grep -q ":443.*hysteria"; then
        error_echo "Hysteria2 未监听 UDP 443 端口！"
        return 1
    fi
    
    success_echo "Hysteria2 服务状态: 正常"
    
    # 检查防火墙规则
    info_echo "检查防火墙配置..."
    
    # 检查 iptables 是否阻止了 UDP 443
    if command -v iptables &>/dev/null; then
        if iptables -L INPUT -n | grep -q "DROP.*443"; then
            warning_echo "检测到防火墙可能阻止了端口 443"
            echo "尝试添加防火墙规则..."
            iptables -I INPUT -p udp --dport 443 -j ACCEPT
            iptables -I INPUT -p tcp --dport 443 -j ACCEPT
        fi
    fi
    
    # 检查 ufw
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        warning_echo "检测到 UFW 防火墙活跃，添加规则..."
        ufw allow 443/udp
        ufw allow 443/tcp
    fi
    
    # 检查 firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        warning_echo "检测到 firewalld 活跃，添加规则..."
        firewall-cmd --permanent --add-port=443/udp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    fi
    
    # 测试本地连接
    info_echo "测试本地 UDP 连接..."
    if timeout 5 nc -u -z 127.0.0.1 443 2>/dev/null; then
        success_echo "本地 UDP 443 端口可达"
    else
        warning_echo "本地 UDP 443 端口连接失败"
    fi
    
    # 如果配置了域名，测试外部连接
    if [[ -f /etc/hysteria2/config.yaml ]]; then
        local domain_from_config=$(grep -o 'hysteria2://.*@[^:]*' /etc/hysteria2/client_info.txt 2>/dev/null | cut -d'@' -f2 || echo "")
        if [[ -n "$domain_from_config" ]]; then
            info_echo "测试域名解析: $domain_from_config"
            if nslookup "$domain_from_config" >/dev/null 2>&1; then
                success_echo "域名解析正常"
            else
                error_echo "域名解析失败！"
            fi
        fi
    fi
    
    # 检查 Cloudflare Tunnel 状态
    if systemctl is-active --quiet cloudflared; then
        info_echo "检查 Cloudflare Tunnel 连接状态..."
        if journalctl -u cloudflared --since="2 minutes ago" | grep -q "Connected to"; then
            success_echo "Cloudflare Tunnel 连接正常"
        else
            warning_echo "Cloudflare Tunnel 可能未正常连接"
            echo "最近的 Cloudflared 日志:"
            journalctl -u cloudflared -n 5 --no-pager
        fi
    fi
    
    echo
    info_echo "连通性测试完成。如果仍有问题，请检查："
    echo "1. 客户端配置是否正确"
    echo "2. 域名是否正确解析到 Cloudflare"
    echo "3. Cloudflare Token 权限是否充足"
    echo "4. 网络环境是否支持 UDP 协议"
}

# --- 核心功能函数 ---

# 自动清理旧安装的函数
cleanup_previous_installation() {
    info_echo "正在检查并清理任何可能存在的旧安装..."
    
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true
    
    if command -v cloudflared &>/dev/null; then
        cloudflared tunnel delete -f "$TUNNEL_NAME" 2>/dev/null || true
    fi
    
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    
    rm -f /usr/local/bin/hysteria /usr/local/bin/hy2-manage
    rm -rf /etc/hysteria2 /etc/cloudflared /root/.cloudflared
    
    success_echo "旧环境清理完成。"
}

# 完全清理函数
complete_cleanup() {
    warning_echo "开始完全清理所有组件..."
    read -rp "确定要完全清理所有安装的内容吗？此操作不可逆 (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info_echo "取消清理"
        return 0
    fi
    
    # 停止并禁用服务
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true
    
    # 删除隧道
    if command -v cloudflared &>/dev/null; then
        if [[ -f /etc/hysteria2/uninstall_info.env ]]; then
            source /etc/hysteria2/uninstall_info.env
            cloudflared tunnel delete -f "$TUNNEL_NAME" 2>/dev/null || true
        fi
        cloudflared tunnel delete -f "hysteria-tunnel" 2>/dev/null || true
    fi
    
    # 清理服务文件
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    
    # 清理二进制文件
    rm -f /usr/local/bin/hysteria
    rm -f /usr/local/bin/hy2-manage
    
    # 清理证书
    if [[ -d /root/.acme.sh ]] && [[ -n "$DOMAIN" ]]; then
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" 2>/dev/null || true
    fi
    
    # 清理配置目录
    rm -rf /etc/hysteria2
    rm -rf /etc/cloudflared
    rm -rf /root/.cloudflared
    
    # 卸载 cloudflared
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get purge -y cloudflared 2>/dev/null || true
            rm -f /etc/apt/sources.list.d/cloudflared.list
            rm -f /usr/share/keyrings/cloudflare-main.gpg
            ;;
        "centos" | "rhel" | "fedora" | "almalinux" | "rocky")
            yum remove -y cloudflared 2>/dev/null || true
            rm -f /etc/yum.repos.d/cloudflared-ascii.repo
            ;;
    esac
    
    # 删除脚本自身
    warning_echo "即将删除此脚本文件..."
    sleep 2
    success_echo "完全清理完成！脚本将自动退出。"
    
    # 获取脚本路径并删除
    SCRIPT_PATH=$(readlink -f "$0")
    exec rm "$SCRIPT_PATH"
}

# 1. 环境检查
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限运行"
        exit 1
    fi
}

detect_system() {
    info_echo "检测系统信息..."
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_TYPE=$ID
    elif [[ -f /etc/debian_version ]]; then
        OS_TYPE="debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS_TYPE="rhel"
    else
        error_echo "无法检测到操作系统类型"
        exit 1
    fi

    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) error_echo "不支持的架构: $ARCH"; exit 1 ;;
    esac
    success_echo "系统信息: $OS_TYPE, 架构: $ARCH"
}

install_dependencies() {
    info_echo "检查并安装依赖包..."
    local packages=("curl" "socat" "unzip" "wget" "jq" "net-tools" "netcat-openbsd")
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -qq
            for pkg in "${packages[@]}"; do
                if ! dpkg -s "$pkg" >/dev/null 2>&1; then
                    apt-get install -y "$pkg" 2>/dev/null || {
                        if [[ "$pkg" == "netcat-openbsd" ]]; then
                            apt-get install -y netcat || apt-get install -y nc
                        fi
                    }
                fi
            done
            ;;
        "centos" | "rhel" | "fedora" | "almalinux" | "rocky")
            for pkg in "${packages[@]}"; do
                local rpm_pkg="$pkg"
                [[ "$pkg" == "netcat-openbsd" ]] && rpm_pkg="nc"
                if ! rpm -q "$rpm_pkg" >/dev/null 2>&1; then
                    yum install -y "$rpm_pkg"
                fi
            done
            ;;
        *) error_echo "不支持的包管理器"; exit 1 ;;
    esac
    success_echo "依赖包检查完成"
}

check_port_443() {
    info_echo "检查端口 443 是否可用..."
    
    # 更全面的端口检查
    local tcp_443=$(ss -tlnp | grep ":443 " || echo "")
    local udp_443=$(ss -ulnp | grep ":443 " || echo "")
    
    if [[ -n "$tcp_443" ]]; then
        error_echo "TCP 端口 443 已被占用:"
        echo "$tcp_443"
        warning_echo "请停止占用该端口的服务后重试。"
        exit 1
    fi
    
    if [[ -n "$udp_443" ]] && ! echo "$udp_443" | grep -q "hysteria"; then
        error_echo "UDP 端口 443 已被其他进程占用:"
        echo "$udp_443"
        warning_echo "请停止占用该端口的服务后重试。"
        exit 1
    fi
    
    success_echo "端口 443 可用。"
}

detect_network() {
    info_echo "检测网络环境..."
    IPV4_ADDR=$(curl -4 --connect-timeout 10 -s ip.sb || echo "")
    IPV6_ADDR=$(curl -6 --connect-timeout 10 -s ip.sb || echo "")

    if [[ -n "$IPV6_ADDR" ]]; then
        success_echo "检测到 IPv6 地址: $IPV6_ADDR"
        if [[ -n "$IPV4_ADDR" ]]; then
            info_echo "检测到 IPv4 地址: $IPV4_ADDR (双栈网络)"
        else
            info_echo "当前为 IPv6 Only 环境"
        fi
    elif [[ -n "$IPV4_ADDR" ]]; then
        success_echo "检测到 IPv4 地址: $IPV4_ADDR (仅 IPv4 模式)"
    else
        error_echo "未能检测到公网 IP 地址, 脚本无法继续"
        exit 1
    fi
}

# 配置防火墙规则
configure_firewall() {
    info_echo "配置防火墙规则..."
    
    # 检查并配置 iptables
    if command -v iptables &>/dev/null; then
        # 清除可能冲突的规则
        iptables -D INPUT -p udp --dport 443 -j DROP 2>/dev/null || true
        iptables -D INPUT -p tcp --dport 443 -j DROP 2>/dev/null || true
        
        # 添加允许规则
        iptables -I INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
        
        # 保存规则
        case "$OS_TYPE" in
            "ubuntu" | "debian")
                if command -v iptables-save &>/dev/null; then
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                fi
                ;;
            "centos" | "rhel" | "fedora" | "almalinux" | "rocky")
                if command -v iptables-save &>/dev/null; then
                    iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
                fi
                ;;
        esac
    fi
    
    # 检查 ufw
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        info_echo "配置 UFW 防火墙..."
        ufw allow 443/udp
        ufw allow 443/tcp
    fi
    
    # 检查 firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        info_echo "配置 firewalld 防火墙..."
        firewall-cmd --permanent --add-port=443/udp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    fi
    
    success_echo "防火墙配置完成"
}

# 2. 用户交互与配置
get_user_input() {
    echo
    info_echo "开始配置参数..."
    exec < /dev/tty
    
    read -rp "请输入您的域名 (例如: hy2.example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then error_echo "域名不能为空"; exit 1; fi
    
    read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD
    echo
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    local default_email="user$(shuf -i 1000-9999 -n 1)@gmail.com"
    local default_fake_url="https://www.bing.com"
    read -rp "请输入 ACME 邮箱 (回车默认: ${default_email}): " input_email
    ACME_EMAIL=${input_email:-$default_email}
    read -rp "请输入伪装网址 (回车默认: ${default_fake_url}): " input_fake_url
    FAKE_URL=${input_fake_url:-$default_fake_url}
}

get_user_input_with_cf() {
    get_user_input
    
    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN
        echo
        if [[ -z "$CF_TOKEN" ]]; then warning_echo "Token 不能为空"; continue; fi
        
        info_echo "正在通过域名验证 Cloudflare Token 权限..."
        local root_domain
        root_domain=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
        local api_result
        api_result=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$root_domain" \
            -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json")
        
        if echo "$api_result" | jq -e '.success == true and .result[0].id' > /dev/null; then
            CF_ZONE_ID=$(echo "$api_result" | jq -r '.result[0].id')
            CF_ACCOUNT_ID=$(echo "$api_result" | jq -r '.result[0].account.id')
            success_echo "Token 验证成功, 域名 ($DOMAIN) 的 Zone ID: $CF_ZONE_ID"
            break
        else
            error_echo "Token 验证失败或权限不足！"
            warning_echo "请确保 Token 拥有对根域名 '$root_domain' 的 'Zone:Read' 和 'DNS:Edit' 权限。"
            echo "$api_result" | jq '.errors'
        fi
    done
}

# 3. 安装核心组件
install_hysteria2() {
    info_echo "安装 Hysteria2..."
    local download_url
    download_url=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r ".assets[] | select(.name == \"hysteria-linux-$ARCH\") | .browser_download_url")
    
    if [[ -z "$download_url" ]]; then
        warning_echo "精确文件名匹配失败，尝试模糊匹配..."
        download_url=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r ".assets[] | select(.name | contains(\"linux-$ARCH\") and (contains(\"avx\") | not)) | .browser_download_url")
    fi

    if [[ -z "$download_url" ]]; then error_echo "获取 Hysteria2 下载链接失败"; exit 1; fi
    
    info_echo "下载 Hysteria2 从: $download_url"
    wget -qO /usr/local/bin/hysteria "$download_url"
    chmod +x /usr/local/bin/hysteria
    
    if ! command -v hysteria &> /dev/null; then error_echo "Hysteria2 安装验证失败"; exit 1; fi
    success_echo "Hysteria2 安装完成, 版本: $(hysteria --version | head -n 1)"
}

install_cloudflared() {
    info_echo "安装 Cloudflared..."
    if command -v cloudflared &> /dev/null; then
        success_echo "Cloudflared 已安装, 版本: $(cloudflared --version | head -n 1)"
        CLOUDFLARED_PATH=$(command -v cloudflared)
        return
    fi

    case "$OS_TYPE" in
        "ubuntu" | "debian")
            curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
            echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main' | tee /etc/apt/sources.list.d/cloudflared.list
            apt-get update -qq && apt-get install -y cloudflared
            ;;
        "centos" | "rhel" | "fedora" | "almalinux" | "rocky")
            yum install -y 'dnf-command(config-manager)' >/dev/null 2>&1 || true
            dnf config-manager --add-repo https://pkg.cloudflare.com/cloudflared-ascii.repo >/dev/null 2>&1
            yum install -y cloudflared
            ;;
        *) error_echo "暂不支持为 $OS_TYPE 自动安装 cloudflared，请手动安装后重试。"; exit 1 ;;
    esac

    CLOUDFLARED_PATH=$(command -v cloudflared)
    if [[ -z "$CLOUDFLARED_PATH" ]]; then error_echo "Cloudflared 安装失败或未找到可执行文件"; exit 1; fi
    success_echo "Cloudflared 安装完成, 版本: $(cloudflared --version | head -n 1)"
}

install_acme_and_cert() {
    info_echo "安装 ACME.sh 并申请 SSL 证书..."
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then
        curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
    fi
    
    rm -rf "/root/.acme.sh/${DOMAIN}_ecc"
    
    export CF_Token="$CF_TOKEN"
    export CF_Account_ID="$CF_ACCOUNT_ID"
    export CF_Zone_ID="$CF_ZONE_ID"
    
    info_echo "正在使用 Let's Encrypt 申请 SSL 证书..."
    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force --debug 2; then
        error_echo "SSL 证书申请失败！请检查上面的 acme.sh debug 日志。"
        exit 1
    fi
    
    info_echo "安装证书到指定目录..."
    mkdir -p /etc/hysteria2/certs
    if ! ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
        --fullchain-file /etc/hysteria2/certs/fullchain.cer \
        --key-file /etc/hysteria2/certs/private.key; then
        error_echo "证书安装步骤失败！"
        exit 1
    fi
    
    if [[ ! -s "/etc/hysteria2/certs/fullchain.cer" ]] || [[ ! -s "/etc/hysteria2/certs/private.key" ]]; then
        error_echo "证书文件安装失败或为空"
        exit 1
    fi
    
    chmod 600 /etc/hysteria2/certs/private.key
    success_echo "SSL 证书申请并安装完成"
}

# 生成自签证书（用于直连模式）
generate_self_signed_cert() {
    info_echo "生成自签名证书用于直连模式..."
    mkdir -p /etc/hysteria2/certs
    
    # 生成自签名证书
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/hysteria2/certs/private.key \
        -out /etc/hysteria2/certs/fullchain.cer \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN" 2>/dev/null
    
    chmod 600 /etc/hysteria2/certs/private.key
    success_echo "自签名证书生成完成"
}

# 4. 配置与服务
generate_hysteria_config() {
    info_echo "生成 Hysteria2 配置..."
    mkdir -p /etc/hysteria2
    
    local listen_addr
    if [[ -n "$IPV4_ADDR" ]]; then
        listen_addr="0.0.0.0:443"
        info_echo "检测到 IPv4，Hysteria2 监听地址: 0.0.0.0:443"
    else
        listen_addr="[::]:443"
        info_echo "纯 IPv6 环境，Hysteria2 监听地址: [::]:443"
    fi
    
    cat > /etc/hysteria2/config.yaml << EOF
listen: $listen_addr
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
    rewriteHost: true
bandwidth:
  up: 1 gbps
  down: 1 gbps
EOF
    success_echo "Hysteria2 配置文件生成完成"
}

setup_cloudflared_tunnel() {
    info_echo "设置 Cloudflare Tunnel..."
    
    warning_echo "--- 浏览器授权 ---"
    warning_echo "请在接下来打开的浏览器窗口中登录并授权您的域名。"
    warning_echo "授权完成后，您可以关闭浏览器标签页返回此终端继续。"
    sleep 3
    if ! cloudflared tunnel login; then error_echo "Cloudflared 登录失败"; exit 1; fi
    
    if ! cloudflared tunnel list -o json | jq -e ".[] | select(.name == \"$TUNNEL_NAME\")" > /dev/null; then
        info_echo "创建新的隧道: $TUNNEL_NAME"
        cloudflared tunnel create "$TUNNEL_NAME" > /dev/null 2>&1
    else
        info_echo "检测到已存在的隧道: $TUNNEL_NAME"
    fi

    TUNNEL_ID=$(cloudflared tunnel list -o json | jq -r ".[] | select(.name == \"$TUNNEL_NAME\") | .id")
    if [[ -z "$TUNNEL_ID" ]]; then error_echo "创建或获取隧道 ID 失败！"; exit 1; fi
    success_echo "隧道已就绪, ID: $TUNNEL_ID"
    
    mkdir -p /etc/cloudflared/
    
    local service_addr
    if [[ -n "$IPV4_ADDR" ]]; then
        service_addr="udp://127.0.0.1:443"
        info_echo "配置 Cloudflare Tunnel 连接到本地 IPv4 地址"
    else
        service_addr="udp://[::1]:443"
        info_echo "配置 Cloudflare Tunnel 连接到本地 IPv6 地址"
    fi
    
    cat > /etc/cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
protocol: quic
ingress:
  - hostname: $DOMAIN
    service: $service_addr
  - service: http_status:404
EOF
    success_echo "隧道配置文件创建完成"
    
    info_echo "创建 DNS 记录指向隧道..."
    cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN"
    success_echo "DNS 记录配置完成"
}

create_systemd_services() {
    info_echo "创建 systemd 服务..."
    
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
EOF

    success_echo "Hysteria2 systemd 服务文件创建完成"
}

create_cloudflared_service() {
    info_echo "创建 Cloudflared systemd 服务..."
    
    cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target hysteria-server.service
# BindsTo 建立强依赖：如果 hysteria-server 停止，cloudflared 也会被停止。
BindsTo=hysteria-server.service
[Service]
Type=simple
ExecStart=$CLOUDFLARED_PATH tunnel --edge-ip-version auto --config /etc/cloudflared/config.yml --no-autoupdate run
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
EOF
    success_echo "Cloudflared systemd 服务文件创建完成"
}

start_hysteria_service() {
    info_echo "启动 Hysteria2 服务..."
    systemctl daemon-reload
    systemctl enable --now hysteria-server
    
    # 等待服务启动并检查端口
    local port_check_timeout=15
    local port_found=false
    info_echo "正在等待 Hysteria2 监听 UDP 端口 443 (最长 ${port_check_timeout} 秒)..."
    for ((i=1; i<=port_check_timeout; i++)); do
        if ss -ulnp | grep -q ":443.*hysteria"; then
            port_found=true
            break
        fi
        echo -n "."
        sleep 1
    done
    echo

    if [[ "$port_found" != true ]]; then
        error_echo "Hysteria2 未能成功监听 UDP 端口 443！"
        error_echo "请检查端口是否被占用或配置是否有误。"
        journalctl -u hysteria-server -n 20 --no-pager
        exit 1
    fi
    success_echo "Hysteria2 服务启动成功并监听 UDP 端口 443"
}

start_cloudflared_service() {
    info_echo "启动 Cloudflared 服务..."
    systemctl enable --now cloudflared
    info_echo "等待 Cloudflared 隧道连接 (10秒)..."
    sleep 10
    
    if ! systemctl is-active --quiet cloudflared; then
        error_echo "Cloudflared 服务启动失败！请检查日志："
        journalctl -u cloudflared -n 20 --no-pager
        exit 1
    fi
    
    if journalctl -u cloudflared --since="60 seconds ago" | grep -q "Connected to"; then
        success_echo "Cloudflared 隧道已成功连接到 Cloudflare 网络"
    else
        warning_echo "Cloudflared 日志中未检测到成功的连接信息。"
        warning_echo "节点可能仍可使用，但建议使用菜单选项检查详细日志。"
    fi
}

# 保存客户端配置信息
save_client_info() {
    local mode="$1"
    mkdir -p /etc/hysteria2
    
    local server_addr="$DOMAIN"
    if [[ "$mode" == "direct" ]]; then
        # 直连模式使用服务器IP
        server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    fi
    
    local share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}&insecure=1#${DOMAIN}-${mode}"
    if [[ "$mode" == "tunnel" ]]; then
        share_link="hysteria2://${HY_PASSWORD}@${DOMAIN}:443?sni=${DOMAIN}#${DOMAIN}-CDN"
    fi
    
    cat > /etc/hysteria2/client_info.txt << EOF
服务器地址: $server_addr
端口: 443
密码: $HY_PASSWORD
TLS SNI: $DOMAIN
伪装网址: $FAKE_URL
模式: $mode

分享链接:
$share_link

Clash.Meta YAML:
- { name: '${DOMAIN}-${mode}', type: hysteria2, server: '${server_addr}', port: 443, password: '${HY_PASSWORD}', sni: '${DOMAIN}', skip-cert-verify: $([ "$mode" == "direct" ] && echo "true" || echo "false"), masquerade: '${FAKE_URL}' }
EOF

    cat > /etc/hysteria2/uninstall_info.env <<EOF
DOMAIN=$DOMAIN
TUNNEL_NAME=$TUNNEL_NAME
MODE=$mode
EOF
}

# 5. 显示结果
show_installation_result() {
    local mode="$1"
    local server_addr="$DOMAIN"
    
    if [[ "$mode" == "direct" ]]; then
        server_addr="${IPV4_ADDR:-$IPV6_ADDR}"
    fi
    
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${ENDCOLOR}"
    echo -e "${GREEN}║                        安装成功！                              ║${ENDCOLOR}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${ENDCOLOR}"
    echo -e "${GREEN}║  模式:       ${YELLOW}$(printf "%-47s" "$([[ $mode == "direct" ]] && echo "直连模式" || echo "CDN模式 (Cloudflare Tunnel)")")${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  服务器地址: ${YELLOW}$(printf "%-47s" "$server_addr")${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  端口:       ${YELLOW}$(printf "%-47s" "443")${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  密码:       ${YELLOW}$(printf "%-47s" "$HY_PASSWORD")${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  TLS SNI:    ${YELLOW}$(printf "%-47s" "$DOMAIN")${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}║  伪装网址:   ${YELLOW}$(printf "%-47s" "$FAKE_URL")${GREEN}║${ENDCOLOR}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${ENDCOLOR}"
    echo
    
    local share_link
    if [[ "$mode" == "direct" ]]; then
        share_link="hysteria2://${HY_PASSWORD}@${server_addr}:443?sni=${DOMAIN}&insecure=1#${DOMAIN}-Direct"
        echo -e "${BLUE}分享链接 (直连模式, V2RayN / Nekobox):${ENDCOLOR}"
        echo -e "${YELLOW}${share_link}${ENDCOLOR}"
        echo
        echo -e "${BLUE}Clash.Meta YAML 配置:${ENDCOLOR}"
        echo -e "${YELLOW}- { name: '${DOMAIN}-Direct', type: hysteria2, server: '${server_addr}', port: 443, password: '${HY_PASSWORD}', sni: '${DOMAIN}', skip-cert-verify: true, masquerade: '${FAKE_URL}' }${ENDCOLOR}"
    else
        share_link="hysteria2://${HY_PASSWORD}@${DOMAIN}:443?sni=${DOMAIN}#${DOMAIN}-CDN"
        echo -e "${BLUE}分享链接 (CDN模式, V2RayN / Nekobox):${ENDCOLOR}"
        echo -e "${YELLOW}${share_link}${ENDCOLOR}"
        echo
        echo -e "${BLUE}Clash.Meta YAML 配置:${ENDCOLOR}"
        echo -e "${YELLOW}- { name: '${DOMAIN}-CDN', type: hysteria2, server: '${DOMAIN}', port: 443, password: '${HY_PASSWORD}', sni: '${DOMAIN}', masquerade: '${FAKE_URL}' }${ENDCOLOR}"
    fi
    echo
    
    if [[ "$mode" == "direct" ]]; then
        warning_echo "注意: 直连模式使用自签名证书，客户端需要开启 'skip-cert-verify' 或 'insecure' 选项"
    fi
}

# 服务管理菜单
service_management() {
    while true; do
        clear
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${ENDCOLOR}"
        echo -e "${CYAN}║                          服务管理                              ║${ENDCOLOR}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${ENDCOLOR}"
        echo -e "${CYAN}║  ${YELLOW}1.${ENDCOLOR} 启动服务                                            ${CYAN}║${ENDCOLOR}"
        echo -e "${CYAN}║  ${YELLOW}2.${ENDCOLOR} 停止服务                                            ${CYAN}║${ENDCOLOR}"
        echo -e "${CYAN}║  ${YELLOW}3.${ENDCOLOR} 重启服务                                            ${CYAN}║${ENDCOLOR}"
        echo -e "${CYAN}║  ${YELLOW}4.${ENDCOLOR} 查看服务状态                                        ${CYAN}║${ENDCOLOR}"
        echo -e "${CYAN}║  ${YELLOW}5.${ENDCOLOR} 查看 Hysteria2 日志                                 ${CYAN}║${ENDCOLOR}"
        echo -e "${CYAN}║  ${YELLOW}6.${ENDCOLOR} 查看 Cloudflared 日志                               ${CYAN}║${ENDCOLOR}"
        echo -e "${CYAN}║  ${YELLOW}0.${ENDCOLOR} 返回主菜单                                          ${CYAN}║${ENDCOLOR}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${ENDCOLOR}"
        echo
        
        read -rp "请选择操作 [0-6]: " choice
        
        case $choice in
            1)
                info_echo "启动服务..."
                systemctl start hysteria-server
                if systemctl is-active --quiet cloudflared; then
                    systemctl start cloudflared
                fi
                success_echo "服务启动完成"
                read -rp "按回车键继续..."
                ;;
            2)
                info_echo "停止服务..."
                systemctl stop cloudflared hysteria-server 2>/dev/null || true
                success_echo "服务停止完成"
                read -rp "按回车键继续..."
                ;;
            3)
                info_echo "重启服务..."
                systemctl stop cloudflared 2>/dev/null || true
                systemctl restart hysteria-server
                sleep 3
                if systemctl list-unit-files | grep -q cloudflared.service; then
                    systemctl start cloudflared
                    sleep 2
                fi
                success_echo "服务重启完成"
                read -rp "按回车键继续..."
                ;;
            4)
                echo -e "${BLUE}服务状态:${ENDCOLOR}"
                systemctl is-active --quiet hysteria-server && echo -e "${GREEN}✓ Hysteria2   : 运行中${ENDCOLOR}" || echo -e "${RED}✗ Hysteria2   : 未运行${ENDCOLOR}"
                if systemctl list-unit-files | grep -q cloudflared.service; then
                    systemctl is-active --quiet cloudflared && echo -e "${GREEN}✓ Cloudflared : 运行中${ENDCOLOR}" || echo -e "${RED}✗ Cloudflared : 未运行${ENDCOLOR}"
                fi
                echo
                echo -e "${BLUE}端口监听状态:${ENDCOLOR}"
                ss -ulnp | grep ":443" || echo "未检测到 UDP 443 端口监听"
                echo
                read -rp "按回车键继续..."
                ;;
            5)
                info_echo "显示 Hysteria2 最近日志 (按 q 退出)..."
                journalctl -u hysteria-server -n 50 --no-pager
                read -rp "按回车键继续..."
                ;;
            6)
                if systemctl list-unit-files | grep -q cloudflared.service; then
                    info_echo "显示 Cloudflared 最近日志 (按 q 退出)..."
                    journalctl -u cloudflared -n 50 --no-pager
                else
                    warning_echo "Cloudflared 服务未安装"
                fi
                read -rp "按回车键继续..."
                ;;
            0)
                return
                ;;
            *)
                error_echo "无效选择，请重试"
                sleep 1
                ;;
        esac
    done
}

# 显示配置信息
show_config_info() {
    if [[ ! -f /etc/hysteria2/client_info.txt ]]; then
        error_echo "未找到配置信息文件，请先安装服务"
        return 1
    fi
    
    clear
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${ENDCOLOR}"
    echo -e "${GREEN}║                        配置信息                                ║${ENDCOLOR}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${ENDCOLOR}"
    echo
    cat /etc/hysteria2/client_info.txt
    echo
    read -rp "按回车键继续..."
}

# 卸载功能
uninstall_hysteria_only() {
    warning_echo "开始卸载 Hysteria2 (保留 Cloudflare)..."
    read -rp "确定要卸载 Hysteria2 吗？(y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info_echo "取消卸载"
        return 0
    fi
    
    systemctl stop hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    
    rm -f /etc/systemd/system/hysteria-server.service
    systemctl daemon-reload
    
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria2
    
    success_echo "Hysteria2 已卸载 (Cloudflare 组件保留)"
    read -rp "按回车键继续..."
}

uninstall_all() {
    if [[ -f /etc/hysteria2/uninstall_info.env ]]; then
        source /etc/hysteria2/uninstall_info.env
    fi
    
    warning_echo "开始卸载 Hysteria2 和 Cloudflare Tunnel..."
    read -rp "确定要完全卸载吗？此操作不可逆 (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info_echo "取消卸载"
        return 0
    fi
    
    systemctl stop hysteria-server cloudflared 2>/dev/null || true
    systemctl disable hysteria-server cloudflared 2>/dev/null || true
    
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/cloudflared.service
    systemctl daemon-reload
    
    rm -f /usr/local/bin/hysteria
    
    if [[ -n "$DOMAIN" ]] && command -v ~/.acme.sh/acme.sh &> /dev/null; then
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" --debug 2 || true
    fi
    
    if [[ -n "$TUNNEL_NAME" ]] && command -v cloudflared &>/dev/null; then
        cloudflared tunnel delete -f "$TUNNEL_NAME" 2>/dev/null || true
    fi
    
    rm -rf /etc/hysteria2 /etc/cloudflared /root/.cloudflared
    
    success_echo "Hysteria2 和 Cloudflare Tunnel 已完全卸载"
    warning_echo "Cloudflared 本体未卸载, 您可使用包管理器手动移除"
    read -rp "按回车键继续..."
}

# 安装 Hysteria2 (直连模式)
install_hysteria_direct() {
    info_echo "开始安装 Hysteria2 (直连模式)..."
    
    detect_system
    install_dependencies
    check_port_443
    detect_network
    get_user_input
    
    read -rp "配置确认完成，是否开始安装？ (Y/n): " confirm
    if [[ "$confirm" == "n" || "$confirm" == "N" ]]; then
        info_echo "安装已取消"
        return 0
    fi
    
    install_hysteria2
    generate_self_signed_cert
    generate_hysteria_config
    create_systemd_services
    configure_firewall
    start_hysteria_service
    save_client_info "direct"
    show_installation_result "direct"
    
    read -rp "按回车键返回主菜单..."
}

# 安装 Hysteria2 + Cloudflare Tunnel
install_hysteria_with_tunnel() {
    info_echo "开始安装 Hysteria2 + Cloudflare Tunnel..."
    
    detect_system
    install_dependencies
    check_port_443
    install_cloudflared
    detect_network
    get_user_input_with_cf
    
    read -rp "配置确认完成，是否开始安装？ (Y/n): " confirm
    if [[ "$confirm" == "n" || "$confirm" == "N" ]]; then
        info_echo "安装已取消"
        return 0
    fi
    
    install_hysteria2
    install_acme_and_cert
    generate_hysteria_config
    setup_cloudflared_tunnel
    create_systemd_services
    create_cloudflared_service
    configure_firewall
    start_hysteria_service
    start_cloudflared_service
    save_client_info "tunnel"
    show_installation_result "tunnel"
    
    read -rp "按回车键返回主菜单..."
}

# 主菜单逻辑
main_menu() {
    while true; do
        show_menu
        read -rp "请选择操作 [0-8]: " choice
        
        case $choice in
            1)
                cleanup_previous_installation
                install_hysteria_direct
                ;;
            2)
                cleanup_previous_installation
                install_hysteria_with_tunnel
                ;;
            3)
                uninstall_hysteria_only
                ;;
            4)
                uninstall_all
                ;;
            5)
                detect_system
                complete_cleanup
                ;;
            6)
                service_management
                ;;
            7)
                show_config_info
                ;;
            8)
                if ! command -v hysteria &>/dev/null; then
                    error_echo "Hysteria2 未安装，无法进行连通性测试"
                    read -rp "按回车键继续..."
                else
                    test_connectivity
                    read -rp "按回车键继续..."
                fi
                ;;
            0)
                info_echo "退出脚本"
                exit 0
                ;;
            *)
                error_echo "无效选择，请重试"
                sleep 1
                ;;
        esac
    done
}

# 检查是否为管理命令调用
if [[ $# -gt 0 ]]; then
    case "$1" in
        "menu")
            check_root
            main_menu
            ;;
        "test")
            check_root
            detect_system
            test_connectivity
            ;;
        *)
            echo "用法: $0 [menu|test]"
            echo "  menu - 显示交互菜单"
            echo "  test - 运行连通性测试"
            exit 1
            ;;
    esac
else
    check_root
    main_menu
fi
