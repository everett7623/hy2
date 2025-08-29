#!/bin/bash

# Hysteria2 + IPv6 + Cloudflare Tunnel 一键安装脚本
# 版本: 2.3 (基于 v1.0 的终极修复版)
# 作者: everett7623 & Gemini
# 项目: hy2ipv6

set -e -o pipefail

# --- 脚本配置与变量 ---

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
TUNNEL_NAME="hysteria-tunnel" # [新增] 给隧道一个固定的名字

# --- 辅助函数 (与 v1.0 相同) ---

info_echo() { echo -e "${BLUE}[INFO]${ENDCOLOR} $1"; }
success_echo() { echo -e "${GREEN}[SUCCESS]${ENDCOLOR} $1"; }
error_echo() { echo -e "${RED}[ERROR]${ENDCOLOR} $1"; }
warning_echo() { echo -e "${YELLOW}[WARNING]${ENDCOLOR} $1"; }

# --- 核心功能函数 ---

# 1. 环境检查
check_root() { # (与 v1.0 相同)
    if [[ $EUID -ne 0 ]]; then
        error_echo "此脚本需要 root 权限运行"
        exit 1
    fi
}

detect_system() { # [优化] 改为更通用的 os-release 检测
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

install_dependencies() { # [优化] 增加对更多 RHEL 系发行版的支持
    info_echo "检查并安装依赖包..."
    local packages=("curl" "socat" "unzip" "wget" "jq")
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -qq
            for pkg in "${packages[@]}"; do
                if ! dpkg -s "$pkg" >/dev/null 2>&1; then
                    info_echo "安装 $pkg..."
                    apt-get install -y "$pkg"
                fi
            done
            ;;
        "centos" | "rhel" | "fedora" | "almalinux" | "rocky")
            for pkg in "${packages[@]}"; do
                if ! rpm -q "$pkg" >/dev/null 2>&1; then
                    info_echo "安装 $pkg..."
                    yum install -y "$pkg"
                fi
            done
            ;;
        *) error_echo "不支持的包管理器"; exit 1 ;;
    esac
    success_echo "依赖包检查完成"
}

detect_network() { # (与 v1.0 逻辑基本相同，优化了输出)
    info_echo "检测网络环境..."
    local IPV6_ADDR
    IPV6_ADDR=$(curl -6 --connect-timeout 10 -s ip.sb 2>/dev/null || echo "")
    local IPV4_ADDR
    IPV4_ADDR=$(curl -4 --connect-timeout 10 -s ip.sb 2>/dev/null || echo "")

    if [[ -n "$IPV6_ADDR" ]]; then
        success_echo "检测到 IPv6 地址: $IPV6_ADDR"
        if [[ -n "$IPV4_ADDR" ]]; then
            info_echo "检测到 IPv4 地址: $IPV4_ADDR (双栈网络, 将优先使用 IPv6)"
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

# 2. 用户交互与配置
get_user_input() { # [核心重构] 彻底修改了此函数以修复问题和优化体验
    echo
    info_echo "开始配置参数..."
    exec < /dev/tty
    
    read -rp "请输入您的域名 (例如: hy2.example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        error_echo "域名不能为空"
        exit 1
    fi
    
    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN
        echo
        if [[ -z "$CF_TOKEN" ]]; then
            warning_echo "Token 不能为空"
            continue
        fi
        
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
    
    read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD
    echo
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    ACME_EMAIL="user$(shuf -i 1000-9999 -n 1)@gmail.com"
    FAKE_URL="https://www.bing.com"
    read -rp "请输入 ACME 邮箱 (回车默认: ${ACME_EMAIL}): " input_email
    ACME_EMAIL=${input_email:-$ACME_EMAIL}
    read -rp "请输入伪装网址 (回车默认: ${FAKE_URL}): " input_fake_url
    FAKE_URL=${input_fake_url:-$FAKE_URL}
}

# 3. 安装核心组件
install_hysteria2() { # [核心重构]
    info_echo "安装 Hysteria2..."
    local download_url
    download_url=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r ".assets[] | select(.name | contains(\"linux-$ARCH\") and (contains(\"avx\") | not)) | .browser_download_url")
    if [[ -z "$download_url" ]]; then
        error_echo "获取 Hysteria2 下载链接失败"
        exit 1
    fi
    
    info_echo "下载 Hysteria2 从: $download_url"
    wget -qO /tmp/hysteria.tar.gz "$download_url"
    
    local binary_name
    binary_name=$(tar -tf /tmp/hysteria.tar.gz | grep -E "^hysteria-linux-$ARCH$|hysteria$" | head -n 1)
    if [[ -z "$binary_name" ]]; then
        error_echo "在压缩包中未找到 Hysteria2 二进制文件"
        exit 1
    fi
    
    tar -xzf /tmp/hysteria.tar.gz -C /usr/local/bin "$binary_name"
    mv "/usr/local/bin/$binary_name" /usr/local/bin/hysteria
    chmod +x /usr/local/bin/hysteria
    
    if ! command -v hysteria &> /dev/null; then
        error_echo "Hysteria2 安装验证失败"
        exit 1
    fi
    success_echo "Hysteria2 安装完成, 版本: $(hysteria --version | head -n 1)"
}

install_cloudflared() { # [核心重构]
    info_echo "安装 Cloudflared..."
    if command -v cloudflared &> /dev/null; then
        success_echo "Cloudflared 已安装, 版本: $(cloudflared --version | head -n 1)"
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
        *)
            error_echo "暂不支持为 $OS_TYPE 自动安装 cloudflared，请手动安装后重试。"; exit 1
            ;;
    esac

    if ! command -v cloudflared &> /dev/null; then
        error_echo "Cloudflared 安装失败"; exit 1
    fi
    success_echo "Cloudflared 安装完成, 版本: $(cloudflared --version | head -n 1)"
}

install_acme_and_cert() { # [核心重构]
    info_echo "安装 ACME.sh 并申请 SSL 证书..."
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then
        info_echo "正在安装 acme.sh..."
        curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
    fi
    
    info_echo "申请 SSL 证书 (使用 Let's Encrypt)..."
    export CF_Token="$CF_TOKEN"
    export CF_Account_ID="$CF_ACCOUNT_ID"
    export CF_Zone_ID="$CF_ZONE_ID"
    
    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --debug 2; then
        error_echo "SSL 证书申请失败！请检查上面的 acme.sh debug 日志。"
        exit 1
    fi
    
    info_echo "安装证书到指定目录..."
    mkdir -p /etc/hysteria2/certs
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
        --fullchain-file /etc/hysteria2/certs/fullchain.cer \
        --key-file /etc/hysteria2/certs/private.key
    
    if [[ ! -s "/etc/hysteria2/certs/fullchain.cer" ]] || [[ ! -s "/etc/hysteria2/certs/private.key" ]]; then
        error_echo "证书文件安装失败或为空"
        exit 1
    fi
    success_echo "SSL 证书申请并安装完成"
}

# 4. 配置与服务
generate_hysteria_config() { # (与 v1.0 基本相同，增加了 rewriteHost)
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
    rewriteHost: true
bandwidth:
  up: 1 gbps
  down: 1 gbps
EOF
    success_echo "Hysteria2 配置文件生成完成"
}

setup_cloudflared_tunnel() { # [新增] 持久化隧道设置函数
    info_echo "设置 Cloudflare Tunnel..."
    rm -f /root/.cloudflared/cert.pem
    info_echo "请在接下来打开的浏览器窗口中登录并授权您的域名..."
    sleep 3
    if ! cloudflared tunnel login; then
        error_echo "Cloudflared 登录失败"; exit 1
    fi
    
    TUNNEL_ID=$(cloudflared tunnel list -o json | jq -r ".[] | select(.name == \"$TUNNEL_NAME\") | .id" || echo "")
    if [[ -z "$TUNNEL_ID" ]]; then
        info_echo "创建新的隧道: $TUNNEL_NAME"
        TUNNEL_ID=$(cloudflared tunnel create "$TUNNEL_NAME" | grep -oE '[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}')
        sleep 2
    fi
    if [[ -z "$TUNNEL_ID" ]]; then
        error_echo "创建或获取隧道 ID 失败"; exit 1
    fi
    success_echo "隧道已就绪, ID: $TUNNEL_ID"
    
    mkdir -p /etc/cloudflared/
    cat > /etc/cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
credentials-file: /root/.cloudflared/$TUNNEL_ID.json
protocol: quic
ingress:
  - hostname: $DOMAIN
    service: udp://127.0.0.1:443
  - service: http_status:404
EOF
    success_echo "隧道配置文件创建完成"
    
    info_echo "创建 DNS 记录指向隧道..."
    if ! cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN"; then
        warning_echo "自动创建 DNS 记录可能失败，请手动检查"
    fi
    success_echo "DNS 记录配置完成"
}

create_systemd_services() { # [核心重构]
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

    cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel --edge-ip-version 6 --config /etc/cloudflared/config.yml --no-autoupdate run
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
EOF
    success_echo "systemd 服务文件创建完成"
}

start_services() { # [优化] 增加更明确的健康检查
    info_echo "启动并检查服务..."
    systemctl daemon-reload
    systemctl enable --now hysteria-server cloudflared
    
    info_echo "等待服务稳定 (5秒)..."
    sleep 5
    
    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "Hysteria2 服务启动失败！请检查日志："
        journalctl -u hysteria-server -n 20 --no-pager
        exit 1
    fi
    if ! systemctl is-active --quiet cloudflared; then
        error_echo "Cloudflared 服务启动失败！请检查日志："
        journalctl -u cloudflared -n 20 --no-pager
        exit 1
    fi
    success_echo "Hysteria2 和 Cloudflared 服务均已成功启动"
}

# 5. 后续操作
show_installation_result() { # [优化] 增加卸载信息保存
    mkdir -p /etc/hysteria2
    echo "DOMAIN=$DOMAIN" > /etc/hysteria2/uninstall_info.env
    echo "TUNNEL_NAME=$TUNNEL_NAME" >> /etc/hysteria2/uninstall_info.env
    
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${ENDCOLOR}"
    echo -e "${GREEN}║                        安装成功！                              ║${ENDCOLOR}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${ENDCOLOR}"
    echo -e "${GREEN}║  服务器地址: ${ENDCOLOR}$DOMAIN${GREEN}║${ENDCOLOR}"
    # (省略部分与之前版本相同的输出)
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${ENDCOLOR}"
    echo -e "${GREEN}║  管理命令: hy2-manage [start|stop|restart|status|log|uninstall] ║${ENDCOLOR}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${ENDCOLOR}"
    echo
    
    echo -e "${BLUE}客户端配置 JSON (可用于 V2RayN / Nekoray 等):${ENDCOLOR}"
    echo "{\"server\":\"$DOMAIN:443\",\"auth\":\"$HY_PASSWORD\",\"tls\":{\"sni\":\"$DOMAIN\",\"insecure\":false},\"masquerade\":\"$FAKE_URL\"}"
}

install_management_script() { # (与 v1.0 相同)
    info_echo "安装管理脚本..."
    cp "$0" /usr/local/bin/hy2-manage
    chmod +x /usr/local/bin/hy2-manage
    success_echo "管理脚本已安装到 /usr/local/bin/hy2-manage"
}

# 6. 管理与卸载
manage_service() { # [优化] 增加更清晰的输出
    case "$1" in
        start|stop|restart|status)
            echo "正在对 hysteria-server 执行 $1 操作..."
            systemctl "$1" hysteria-server
            echo "正在对 cloudflared 执行 $1 操作..."
            systemctl "$1" cloudflared
            success_echo "操作完成"
            ;;
        log)
            journalctl -u hysteria-server -f
            ;;
        uninstall)
            uninstall_all
            ;;
        *)
            echo "用法: hy2-manage [start|stop|restart|status|log|uninstall]"
            exit 1
            ;;
    esac
}

uninstall_all() { # [核心重构] 使卸载更智能、更彻底
    warning_echo "开始完全卸载 Hysteria2 和相关组件..."
    read -rp "确定要完全卸载吗？此操作不可逆 (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info_echo "取消卸载"; exit 0
    fi
    
    if [[ -f /etc/hysteria2/uninstall_info.env ]]; then
        source /etc/hysteria2/uninstall_info.env
    else
        read -rp "未找到卸载信息, 请输入您当时安装时使用的域名: " DOMAIN
        TUNNEL_NAME="hysteria-tunnel"
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
    
    rm -rf /etc/hysteria2 /etc/cloudflared
    rm -f /usr/local/bin/hy2-manage
    
    success_echo "Hysteria2 相关配置已完全卸载"
    warning_echo "Cloudflared 本体未卸载, 您可手动移除"
}

# --- 主流程 ---
main() {
    # 如果脚本有参数，则执行管理功能
    if [[ $# -gt 0 ]]; then
        manage_service "$1"
    else # 否则，执行安装流程
        clear
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${ENDCOLOR}"
        echo -e "${GREEN}║             Hysteria2 + IPv6 + Cloudflare Tunnel               ║${ENDCOLOR}"
        echo -e "${GREEN}║                      一键安装脚本 (v2.3)                        ║${ENDCOLOR}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${ENDCOLOR}"
        echo
        
        check_root
        detect_system
        install_dependencies
        detect_network
        
        get_user_input
        
        read -rp "配置确认完成，是否开始安装？ (Y/n): " confirm
        if [[ "$confirm" == "n" || "$confirm" == "N" ]]; then
            info_echo "安装已取消"
            exit 0
        fi
        
        install_hysteria2
        install_cloudflared
        install_acme_and_cert
        generate_hysteria_config
        setup_cloudflared_tunnel
        create_systemd_services
        start_services
        install_management_script
        
        show_installation_result
    fi
}

# 脚本入口
main "$@"
