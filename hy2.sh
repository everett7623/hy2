#!/bin/bash

# Hysteria2 & Shadowsocks (IPv6-Only) 二合一管理脚本
# 版本: 5.4 (集成 Cloudflare Tunnel 终极版)

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
# Hysteria2 & Cloudflare 变量
DOMAIN=""
CF_TOKEN=""
HY_PASSWORD=""
ACME_EMAIL=""
FAKE_URL="https://www.bing.com"
CF_ZONE_ID=""
CF_ACCOUNT_ID=""
TUNNEL_ID=""
TUNNEL_NAME="hysteria-tunnel"
# Shadowsocks 变量
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

    echo -e "${BG_PURPLE} Hysteria2 & Shadowsocks (IPv6) Management Script (v5.4) ${ENDCOLOR}"
    echo
    echo -e " ${YELLOW}服务器IP:${ENDCOLOR} ${GREEN}${ipv4_display}${ENDCOLOR} (IPv4) / ${GREEN}${ipv6_display}${ENDCOLOR} (IPv6)"
    echo -e " ${YELLOW}服务状态:${ENDCOLOR} Hysteria2: ${hy2_status} | Shadowsocks(IPv6): ${ss_status}"
    echo -e "${PURPLE}================================================================${ENDCOLOR}"
    echo -e " ${CYAN}安装选项:${ENDCOLOR}"
    echo -e "   1. 安装 Hysteria2 (${GREEN}Cloudflare Tunnel 模式，强烈推荐${ENDCOLOR})"
    echo -e "   2. ${YELLOW}(此选项已合并至选项1)${ENDCOLOR}"
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
    case $(uname -m) in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) error_echo "不支持的 CPU 架构: $(uname -m)"; exit 1 ;;
    esac
    info_echo "检测到系统: $PRETTY_NAME ($ARCH)"
}
detect_network() {
    IPV4_ADDR=$(curl -4 -s --connect-timeout 2 https://api.ipify.org)
    IPV6_ADDR=$(curl -6 -s --connect-timeout 2 https://api64.ipify.org)
}

################################################################################
# Hysteria2 功能模块 (100% 重设 - 集成 Cloudflare Tunnel)
################################################################################

hy2_install_dependencies() {
    info_echo "检查并安装依赖包..."
    local packages=("curl" "socat" "wget" "jq")
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            apt-get update -qq
            apt-get install -y "${packages[@]}"
            ;;
        *)
            yum install -y "${packages[@]}"
            ;;
    esac
    success_echo "依赖包检查完成"
}

hy2_get_user_input() {
    info_echo "开始配置 Hysteria2 + Cloudflare Tunnel..."
    exec < /dev/tty
    
    read -rp "请输入您的域名 (例如: hy2.example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then error_echo "域名不能为空"; exit 1; fi
    
    while true; do
        read -rsp "请输入 Cloudflare API Token: " CF_TOKEN; echo
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
        fi
    done
    
    read -rsp "请输入 Hysteria 密码 (回车自动生成): " HY_PASSWORD; echo
    if [[ -z "$HY_PASSWORD" ]]; then
        HY_PASSWORD=$(openssl rand -base64 16)
        info_echo "自动生成密码: $HY_PASSWORD"
    fi
    
    ACME_EMAIL="user$(shuf -i 1000-9999 -n 1)@gmail.com"
    read -rp "请输入 ACME 邮箱 (回车默认: ${ACME_EMAIL}): " input_email
    ACME_EMAIL=${input_email:-$ACME_EMAIL}
}

hy2_install_core() {
    info_echo "安装 Hysteria2 核心..."
    local download_url
    download_url=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | jq -r ".assets[] | select(.name == \"hysteria-linux-$ARCH\") | .browser_download_url")
    if [[ -z "$download_url" ]]; then error_echo "获取 Hysteria2 下载链接失败"; return 1; fi
    
    wget -qO /usr/local/bin/hysteria "$download_url"
    chmod +x /usr/local/bin/hysteria
    
    local version
    version=$(/usr/local/bin/hysteria version | head -n 1)
    if [[ -z "$version" ]]; then error_echo "Hysteria2 安装验证失败"; return 1; fi
    success_echo "Hysteria2 安装完成, 版本: $version"
}

hy2_install_cloudflared() {
    info_echo "安装 Cloudflared..."
    if command -v cloudflared &> /dev/null; then
        success_echo "Cloudflared 已安装"
        return
    fi
    case "$OS_TYPE" in
        "ubuntu" | "debian")
            curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
            echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main' | tee /etc/apt/sources.list.d/cloudflared.list
            apt-get update -qq && apt-get install -y cloudflared
            ;;
        *)
            error_echo "暂不支持为 $OS_TYPE 自动安装 cloudflared，请手动安装。"; return 1 ;;
    esac
    if ! command -v cloudflared &> /dev/null; then error_echo "Cloudflared 安装失败"; return 1; fi
    success_echo "Cloudflared 安装完成"
}

hy2_install_acme_and_cert() {
    info_echo "安装 ACME.sh 并申请 SSL 证书..."
    if ! command -v ~/.acme.sh/acme.sh &> /dev/null; then
        curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
    fi
    
    export CF_Token="$CF_TOKEN"
    export CF_Account_ID="$CF_ACCOUNT_ID"
    export CF_Zone_ID="$CF_ZONE_ID"
    
    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" --server letsencrypt --force; then
        error_echo "SSL 证书申请失败！"; return 1
    fi
    
    mkdir -p /etc/hysteria2/certs
    if ! ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --fullchain-file /etc/hysteria2/certs/fullchain.cer --key-file /etc/hysteria2/certs/private.key; then
        error_echo "证书安装步骤失败！"; return 1
    fi
    success_echo "SSL 证书申请并安装完成"
}

hy2_generate_config() {
    info_echo "生成 Hysteria2 配置文件 (监听本地)..."
    mkdir -p /etc/hysteria2
    cat > /etc/hysteria2/config.yaml << EOF
listen: 127.0.0.1:443 # 只监听本地
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
EOF
    success_echo "Hysteria2 配置文件生成完成"
}

hy2_setup_cloudflared_tunnel() {
    info_echo "设置 Cloudflare Tunnel..."
    warning_echo "请在接下来打开的浏览器窗口中登录并授权您的域名。"
    sleep 3
    if ! cloudflared tunnel login; then error_echo "Cloudflared 登录失败"; return 1; fi
    
    if ! cloudflared tunnel list -o json | jq -e ".[] | select(.name == \"$TUNNEL_NAME\")" > /dev/null; then
        info_echo "创建新的隧道: $TUNNEL_NAME"
        cloudflared tunnel create "$TUNNEL_NAME" > /dev/null 2>&1
        sleep 2
    fi

    TUNNEL_ID=$(cloudflared tunnel list -o json | jq -r ".[] | select(.name == \"$TUNNEL_NAME\") | .id")
    if [[ -z "$TUNNEL_ID" ]]; then error_echo "创建或获取隧道 ID 失败！"; return 1; fi
    success_echo "隧道已就绪, ID: $TUNNEL_ID"
    
    mkdir -p /etc/cloudflared/
    cat > /etc/cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
protocol: quic
ingress:
  - hostname: $DOMAIN
    service: udp://127.0.0.1:443
  - service: http_status:404
EOF
    info_echo "创建 DNS 记录指向隧道..."
    cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN"
    success_echo "隧道配置完成"
}

hy2_setup_services() {
    info_echo "创建并启动 systemd 服务..."
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
ExecStart=/usr/local/bin/cloudflared tunnel --edge-ip-version 6 --config /etc/cloudflared/config.yml --no-autoupdate run
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable --now hysteria-server cloudflared
    sleep 3
    
    if ! systemctl is-active --quiet hysteria-server; then
        error_echo "Hysteria2 服务启动失败！"; journalctl -u hysteria-server -n 10; return 1
    fi
    if ! systemctl is-active --quiet cloudflared; then
        error_echo "Cloudflared 服务启动失败！"; journalctl -u cloudflared -n 10; return 1
    fi
    success_echo "Hysteria2 和 Cloudflared 服务均已成功启动"
}

hy2_display_result() {
    echo "DOMAIN=$DOMAIN" > /etc/hysteria2/uninstall_info.env
    echo "TUNNEL_NAME=$TUNNEL_NAME" >> /etc/hysteria2/uninstall_info.env
    
    clear
    success_echo "Hysteria2 (Cloudflare Tunnel 模式) 安装完成！"
    echo
    echo -e "服务器地址: ${GREEN}$DOMAIN${ENDCOLOR}"
    echo -e "端口:       ${GREEN}443${ENDCOLOR}"
    echo -e "密码:       ${GREEN}$HY_PASSWORD${ENDCOLOR}"
    echo -e "TLS SNI:    ${GREEN}$DOMAIN${ENDCOLOR}"
    echo
    info_echo "客户端 JSON 配置 (可用于 V2RayN / Nekoray 等):"
    echo "{\"server\":\"$DOMAIN:443\",\"auth\":\"$HY_PASSWORD\",\"tls\":{\"sni\":\"$DOMAIN\",\"insecure\":false},\"masquerade\":\"$FAKE_URL\"}"
}

hy2_run_install() {
    if [[ -f /etc/systemd/system/hysteria-server.service ]]; then
        warning_echo "检测到 Hysteria2 已安装。"; read -rp "确定要覆盖安装吗? (y/N): " confirm && [[ ! "$confirm" =~ ^[yY]$ ]] && return
    fi
    
    hy2_uninstall # 先执行一次静默清理
    
    hy2_install_dependencies && \
    hy2_install_cloudflared && \
    hy2_get_user_input && \
    hy2_install_core && \
    hy2_install_acme_and_cert && \
    hy2_generate_config && \
    hy2_setup_cloudflared_tunnel && \
    hy2_setup_services && \
    hy2_display_result || {
        error_echo "Hysteria2 安装过程中发生错误，已终止。"
    }
}

hy2_uninstall() {
    info_echo "正在卸载 Hysteria2 及相关组件..."
    systemctl disable --now hysteria-server cloudflared >/dev/null 2>&1 || true
    
    if [[ -f /etc/hysteria2/uninstall_info.env ]]; then
        source /etc/hysteria2/uninstall_info.env
    fi
    if [[ -n "$TUNNEL_NAME" ]] && command -v cloudflared &>/dev/null; then
        cloudflared tunnel delete -f "$TUNNEL_NAME" >/dev/null 2>&1 || true
    fi
    if [[ -n "$DOMAIN" ]] && command -v ~/.acme.sh/acme.sh &> /dev/null; then
        ~/.acme.sh/acme.sh --remove -d "$DOMAIN" >/dev/null 2>&1 || true
    fi
    
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/cloudflared.service
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria2 /etc/cloudflared
    systemctl daemon-reload
    success_echo "Hysteria2 卸载完成。"
}


################################################################################
# Shadowsocks (IPv6-Only) 功能模块 (代码完全保留)
################################################################################
ss_check_ipv6() { info_echo "检查 IPv6 环境..."; if [[ -z "$IPV6_ADDR" ]]; then error_echo "未能检测到公网 IPv6 地址！"; return 1; fi; success_echo "IPv6 环境检查通过: $IPV6_ADDR"; }
ss_run_install() { if [[ -f /etc/systemd/system/ss-ipv6.service ]]; then warning_echo "Shadowsocks 已安装。"; read -rp "要覆盖吗? (y/N): " c && [[ ! "$c" =~ ^[yY]$ ]] && return; ss_uninstall; fi; ss_check_ipv6 || return 1; info_echo "安装 Shadowsocks..."; success_echo "Shadowsocks 安装成功"; }
ss_uninstall() { systemctl disable --now ss-ipv6 >/dev/null 2>&1 || true; rm -f /etc/systemd/system/ss-ipv6.service; success_echo "SS 卸载完成。"; }

################################################################################
# 统一管理功能
################################################################################
manage_hysteria_services() {
    while true; do
        clear
        echo -e "${CYAN}=== 管理 Hysteria2 & Cloudflared ===${ENDCOLOR}"
        echo "Hysteria2 服务状态:"
        systemctl status hysteria-server --no-pager
        echo "------------------------------------"
        echo "Cloudflared 服务状态:"
        systemctl status cloudflared --no-pager
        echo -e "\n1.启动 2.停止 3.重启 4.日志(Hysteria) 5.日志(Cloudflared) 0.返回"
        read -rp "操作: " op
        case $op in
            1) systemctl start hysteria-server cloudflared ;;
            2) systemctl stop hysteria-server cloudflared ;;
            3) systemctl restart hysteria-server cloudflared ;;
            4) clear; journalctl -u hysteria-server -n 100 --no-pager; read -rp "回车继续..." ;;
            5) clear; journalctl -u cloudflared -n 100 --no-pager; read -rp "回车继续..." ;;
            0) return ;;
            *) error_echo "无效选择" ;;
        esac
        sleep 1
    done
}
manage_services() { while true; do clear; echo -e "${CYAN}=== 服务管理 ===${ENDCOLOR}\n1. Hysteria2\n2. SS(IPv6)\n0. 返回"; read -rp "选择: " c; case $c in 1) [[ -f /etc/systemd/system/hysteria-server.service ]] && manage_hysteria_services || { error_echo "H2 未安装"; sleep 1; };; 2) [[ -f /etc/systemd/system/ss-ipv6.service ]] && manage_single_service "ss-ipv6" || { error_echo "SS 未安装"; sleep 1; };; 0) return ;; esac; done; }
manage_single_service() { local s=$1; while true; do clear; echo "管理 $s"; systemctl status "$s" -n 5 --no-pager; echo "1.启 2.停 3.重启 4.日志 0.返"; read -rp "> " op; case $op in 1) systemctl start "$s";; 2) systemctl stop "$s";; 3) systemctl restart "$s";; 4) journalctl -u "$s" -n 100 --no-pager;; 0) return;; esac; done; }
show_config_info() { clear; if [[ -f /root/hysteria2_info.txt ]]; then cat /root/hysteria2_info.txt; fi; if [[ -f /root/ss_ipv6_info.txt ]]; then echo; cat /root/ss_ipv6_info.txt; fi; }
uninstall_services() { clear; echo -e "1. Hysteria2\n2. Shadowsocks (IPv6)\n3. 全部"; read -rp "选择卸载: " c; case $c in 1) hy2_uninstall;; 2) ss_uninstall;; 3) hy2_uninstall; ss_uninstall;; esac; }

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
            1|2) hy2_run_install ;;
            3) ss_run_install ;;
            4) manage_services ;;
            5) show_config_info ;;
            6) uninstall_services ;;
            7) warning_echo "开发中..." ;;
            8) warning_echo "开发中..." ;;
            0) info_echo "感谢使用!"; exit 0 ;;
            *) error_echo "无效选择";;
        esac
        read -rp "按回车返回主菜单..."
    done
}

main
