#!/bin/bash
# ============================================================
#  EUserv IPv6-only Hysteria2 一键安装脚本
#  项目地址: https://github.com/everett7623/hy2
#  适用环境: EUserv 免费 IPv6-only VPS
#  版本: v1.0.0
# ============================================================

# ---- 颜色定义 ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ---- 全局变量 ----
HY2_VERSION=""
HY2_CONFIG_DIR="/etc/hysteria"
HY2_BIN="/usr/local/bin/hysteria"
HY2_SERVICE="/etc/systemd/system/hysteria-server.service"
CERT_DIR="/etc/hysteria/certs"
LOG_FILE="/var/log/euserv_hy2_install.log"
SCRIPT_VERSION="1.0.0"

# ---- 工具函数 ----
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }
info()    { echo -e "${GREEN}[INFO]${NC} $*"; log "INFO: $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; log "WARN: $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; log "ERROR: $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; log "SUCCESS: $*"; }
step()    { echo -e "${CYAN}[STEP]${NC} $*"; log "STEP: $*"; }

# ---- Banner ----
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ███████╗██╗   ██╗███████╗███████╗██████╗ ██╗   ██╗    ██╗  ██╗██╗   ██╗██████╗ "
    echo "  ██╔════╝██║   ██║██╔════╝██╔════╝██╔══██╗██║   ██║    ██║  ██║╚██╗ ██╔╝╚════██╗"
    echo "  █████╗  ██║   ██║███████╗█████╗  ██████╔╝██║   ██║    ███████║ ╚████╔╝  █████╔╝"
    echo "  ██╔══╝  ██║   ██║╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝    ██╔══██║  ╚██╔╝  ╚═══██╗"
    echo "  ███████╗╚██████╔╝███████║███████╗██║  ██║ ╚████╔╝     ██║  ██║   ██║  ██████╔╝"
    echo "  ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝      ╚═╝  ╚═╝   ╚═╝  ╚═════╝ "
    echo -e "${NC}"
    echo -e "  ${WHITE}${BOLD}EUserv IPv6-only VPS 专用 Hysteria2 一键脚本${NC}"
    echo -e "  ${DIM}版本: v${SCRIPT_VERSION}  |  项目: github.com/everett7623/hy2${NC}"
    echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ---- 主菜单 ----
show_menu() {
    show_banner
    # 检测状态
    local hy2_status warp_status ipv4_status
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hy2_status="${GREEN}● 运行中${NC}"
    elif [ -f "$HY2_BIN" ]; then
        hy2_status="${YELLOW}● 已安装/未运行${NC}"
    else
        hy2_status="${RED}● 未安装${NC}"
    fi

    if command -v warp-cli &>/dev/null || ip link show warp0 &>/dev/null || ip link show cloudflare-warp &>/dev/null 2>/dev/null; then
        warp_status="${GREEN}● 已安装${NC}"
    else
        warp_status="${RED}● 未安装${NC}"
    fi

    local ipv4_addr
    ipv4_addr=$(curl -4 -s --max-time 3 ip.sb 2>/dev/null || echo "无IPv4")
    local ipv6_addr
    ipv6_addr=$(curl -6 -s --max-time 3 ip.sb 2>/dev/null || ip -6 addr show scope global | grep -oP '(?<=inet6 )[\da-f:]+' | grep -v '^fe80' | head -1 || echo "获取失败")

    echo -e "  ${WHITE}${BOLD}系统状态${NC}"
    echo -e "  ${DIM}┌─────────────────────────────────────────────┐${NC}"
    echo -e "  ${DIM}│${NC}  Hysteria2 状态: $(echo -e $hy2_status)"
    echo -e "  ${DIM}│${NC}  Warp 状态:      $(echo -e $warp_status)"
    echo -e "  ${DIM}│${NC}  IPv6 地址:      ${CYAN}${ipv6_addr}${NC}"
    echo -e "  ${DIM}│${NC}  IPv4(Warp):    ${CYAN}${ipv4_addr}${NC}"
    echo -e "  ${DIM}└─────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "  ${WHITE}${BOLD}━━━ Hysteria2 管理 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}1.${NC} 安装 Hysteria2（自动适配 IPv6 + 自签证书）"
    echo -e "  ${GREEN}2.${NC} 卸载 Hysteria2"
    echo -e "  ${GREEN}3.${NC} 查看配置 / 节点链接"
    echo -e "  ${GREEN}4.${NC} 启动 / 停止 / 重启服务"
    echo -e "  ${GREEN}5.${NC} 查看运行日志"
    echo -e "  ${GREEN}6.${NC} 修改配置（端口 / 密码 / 伪装域名）"
    echo ""
    echo -e "  ${WHITE}${BOLD}━━━ IPv4 出口（Warp）━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${MAGENTA}W.${NC} 调用 F大 Warp 脚本（fscarmen/warp）"
    echo -e "  ${DIM}     为 IPv6-only VPS 添加 IPv4/双栈出口${NC}"
    echo ""
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}0.${NC} 退出脚本"
    echo ""
    echo -ne "  ${WHITE}请输入选项 [0-6/W]:${NC} "
}

# =============================================
#  网络检测
# =============================================
check_network() {
    step "检测网络环境..."

    # 检测 IPv6
    local ipv6_addr
    ipv6_addr=$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6 )[\da-f:]+(?=/)' | grep -v '^fe80' | head -1)
    if [ -z "$ipv6_addr" ]; then
        error "未检测到全局 IPv6 地址，请确认 EUserv VPS 网络配置正常"
        return 1
    fi
    success "检测到 IPv6 地址: ${ipv6_addr}"

    # 检测 IPv4（EUserv 应无 IPv4）
    local ipv4_test
    ipv4_test=$(curl -4 -s --max-time 5 ip.sb 2>/dev/null)
    if [ -n "$ipv4_test" ]; then
        warn "检测到 IPv4 地址: ${ipv4_test}（EUserv 标准为纯 IPv6，如有 IPv4 属正常）"
    else
        info "纯 IPv6 环境确认（EUserv 标准配置）"
    fi

    # IPv6 连通性测试
    if curl -6 -s --max-time 8 https://ipv6.google.com -o /dev/null; then
        success "IPv6 互联网连通性正常"
    else
        warn "IPv6 连接测试超时，可能影响证书申请，请检查防火墙"
    fi

    return 0
}

# =============================================
#  系统初始化
# =============================================
init_system() {
    step "初始化系统环境..."

    # 检测系统
    if [ -f /etc/debian_version ]; then
        OS="debian"
        PKG_MGR="apt-get"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
        PKG_MGR="yum"
    else
        error "不支持的操作系统"
        exit 1
    fi

    info "系统类型: ${OS}"

    # 更新并安装依赖
    step "安装必要依赖..."
    if [ "$OS" = "debian" ]; then
        apt-get update -y >> "$LOG_FILE" 2>&1
        apt-get install -y curl wget openssl qrencode net-tools uuid-runtime >> "$LOG_FILE" 2>&1 || \
        apt-get install -y curl wget openssl net-tools >> "$LOG_FILE" 2>&1
    else
        yum update -y >> "$LOG_FILE" 2>&1
        yum install -y curl wget openssl qrencode net-tools util-linux >> "$LOG_FILE" 2>&1
    fi
    success "依赖安装完成"
}

# =============================================
#  获取 Hysteria2 最新版本
# =============================================
get_latest_version() {
    step "获取 Hysteria2 最新版本..."

    # 方式1: IPv6 直连 GitHub API
    HY2_VERSION=$(curl -6 -s --max-time 10 \
        "https://api.github.com/repos/apernet/hysteria/releases/latest" \
        2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

    # 方式2: IPv4 直连 GitHub API（Warp 环境）
    if [ -z "$HY2_VERSION" ]; then
        HY2_VERSION=$(curl -4 -s --max-time 10 \
            "https://api.github.com/repos/apernet/hysteria/releases/latest" \
            2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    fi

    # 方式3: ghproxy 镜像获取版本
    if [ -z "$HY2_VERSION" ]; then
        HY2_VERSION=$(curl -s --max-time 10 \
            "https://ghproxy.net/https://api.github.com/repos/apernet/hysteria/releases/latest" \
            2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    fi

    # 兜底：内置已知最新稳定版
    if [ -z "$HY2_VERSION" ]; then
        warn "无法获取最新版本，使用内置默认版本 app/v2.6.1"
        HY2_VERSION="app/v2.6.1"
    fi
    success "Hysteria2 版本: ${HY2_VERSION}"
}

# =============================================
#  下载并安装 Hysteria2 二进制
# =============================================
install_hysteria2_binary() {
    step "下载 Hysteria2 二进制文件..."

    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armv7" ;;
        *)
            error "不支持的架构: ${arch}"
            exit 1
            ;;
    esac

    # 从版本号提取纯版本（去掉 app/ 前缀）
    local ver_num="${HY2_VERSION#app/}"
    local download_url="https://github.com/apernet/hysteria/releases/download/${HY2_VERSION}/hysteria-linux-${ARCH}"

    info "下载地址: ${download_url}"
    info "架构: linux-${ARCH}"

    # 尝试多种方式下载
    local tmp_bin="/tmp/hysteria_tmp"
    local downloaded=false

    local mirrors=(
        "${download_url}"
        "https://ghproxy.net/${download_url}"
        "https://gh.con.sh/${download_url}"
        "https://mirror.ghproxy.com/${download_url}"
        "https://ghproxy.cc/${download_url}"
        "https://github.moeyy.xyz/${download_url}"
    )

    for mirror in "${mirrors[@]}"; do
        info "尝试: ${mirror}"
        rm -f "$tmp_bin"
        if curl -L --max-time 120 --progress-bar "$mirror" -o "$tmp_bin" 2>/dev/null && [ -s "$tmp_bin" ]; then
            # 验证是 ELF 二进制而非 HTML 错误页
            if file "$tmp_bin" 2>/dev/null | grep -qiE "ELF|executable"; then
                downloaded=true
                info "下载成功"
                break
            else
                warn "内容异常（非二进制），跳过"
            fi
        fi
    done

    # 最终方案：官方一键安装脚本
    if [ "$downloaded" = false ]; then
        info "尝试官方安装脚本 get.hy2.sh ..."
        if bash <(curl -fsSL https://get.hy2.sh/) 2>/dev/null && [ -f "$HY2_BIN" ]; then
            success "通过官方脚本安装成功"
            return 0
        fi
    fi

    if [ "$downloaded" = false ]; then
        error "所有下载方式均失败，请检查网络或手动安装"
        error "手动下载: ${download_url}"
        return 1
    fi

    # 安装
    chmod +x "$tmp_bin"
    mv "$tmp_bin" "$HY2_BIN"
    success "Hysteria2 二进制安装完成: ${HY2_BIN}"

    # 验证
    if "$HY2_BIN" version &>/dev/null; then
        local installed_ver
        installed_ver=$("$HY2_BIN" version 2>/dev/null | head -1)
        success "版本验证通过: ${installed_ver}"
    else
        error "Hysteria2 二进制验证失败"
        return 1
    fi
}

# =============================================
#  生成自签证书（适配 IPv6）
# =============================================
generate_self_signed_cert() {
    local domain="$1"
    step "生成自签 TLS 证书..."

    mkdir -p "$CERT_DIR"

    # 获取本机 IPv6
    local ipv6_addr
    ipv6_addr=$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6 )[\da-f:]+(?=/)' | grep -v '^fe80' | head -1)

    # 生成证书，SAN 包含域名（如有）和 IPv6
    local san="DNS:${domain}"
    if [ -n "$ipv6_addr" ]; then
        san="${san},IP:${ipv6_addr}"
    fi

    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "${CERT_DIR}/private.key" \
        -out "${CERT_DIR}/cert.crt" \
        -days 36500 \
        -subj "/CN=${domain}" \
        -addext "subjectAltName=${san}" \
        >> "$LOG_FILE" 2>&1

    if [ $? -eq 0 ]; then
        chmod 600 "${CERT_DIR}/private.key"
        success "自签证书生成成功（有效期100年）"
        info "证书路径: ${CERT_DIR}/cert.crt"
        info "私钥路径: ${CERT_DIR}/private.key"
        if [ -n "$ipv6_addr" ]; then
            info "SAN IPv6: ${ipv6_addr}"
        fi
    else
        error "证书生成失败"
        return 1
    fi
}

# =============================================
#  生成配置文件
# =============================================
generate_config() {
    local port="$1"
    local password="$2"
    local masquerade_domain="$3"
    local domain="$4"

    step "生成 Hysteria2 配置文件..."
    mkdir -p "$HY2_CONFIG_DIR"

    cat > "${HY2_CONFIG_DIR}/config.yaml" << EOF
# Hysteria2 配置文件
# EUserv IPv6-only 专用配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

listen: :${port}

tls:
  cert: ${CERT_DIR}/cert.crt
  key: ${CERT_DIR}/private.key

auth:
  type: password
  password: ${password}

masquerade:
  type: proxy
  proxy:
    url: https://${masquerade_domain}
    rewriteHost: true

# 带宽限制（可根据 EUserv 实际带宽调整）
bandwidth:
  up: 100 mbps
  down: 100 mbps

# QUIC 参数优化（IPv6 环境）
quic:
  initStreamReceiveWindow: 26843545
  maxStreamReceiveWindow: 26843545
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s
  disablePathMTUDiscovery: false

# 日志
log:
  level: warn
EOF

    success "配置文件已生成: ${HY2_CONFIG_DIR}/config.yaml"
}

# =============================================
#  创建 systemd 服务
# =============================================
create_service() {
    step "创建 systemd 服务..."

    cat > "$HY2_SERVICE" << 'EOF'
[Unit]
Description=Hysteria2 Server (EUserv IPv6)
Documentation=https://v2.hysteria.network/
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
WorkingDirectory=/etc/hysteria
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hysteria-server

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria-server >> "$LOG_FILE" 2>&1
    success "systemd 服务创建完成"
}

# =============================================
#  防火墙配置（针对 IPv6）
# =============================================
configure_firewall() {
    local port="$1"
    step "配置防火墙规则（IPv6 UDP ${port}）..."

    # UFW
    if command -v ufw &>/dev/null; then
        ufw allow "${port}/udp" >> "$LOG_FILE" 2>&1
        ufw allow "${port}/tcp" >> "$LOG_FILE" 2>&1
        # IPv6 UFW 规则
        ufw allow in on all to any port "${port}" proto udp >> "$LOG_FILE" 2>&1
        info "UFW 规则已添加"
    fi

    # ip6tables（EUserv 重点）
    if command -v ip6tables &>/dev/null; then
        ip6tables -I INPUT -p udp --dport "${port}" -j ACCEPT 2>/dev/null
        ip6tables -I INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null

        # 持久化
        if command -v ip6tables-save &>/dev/null; then
            ip6tables-save > /etc/ip6tables.rules 2>/dev/null
        fi
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save >> "$LOG_FILE" 2>&1
        fi
        info "ip6tables 规则已添加"
    fi

    # iptables（备用）
    if command -v iptables &>/dev/null; then
        iptables -I INPUT -p udp --dport "${port}" -j ACCEPT 2>/dev/null
        iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null
    fi

    success "防火墙配置完成（端口 ${port} UDP/TCP 已放行）"
}

# =============================================
#  生成节点信息
# =============================================
show_node_info() {
    local port password domain

    # 读取配置
    if [ -f "${HY2_CONFIG_DIR}/config.yaml" ]; then
        port=$(grep -oP '(?<=listen: :)\d+' "${HY2_CONFIG_DIR}/config.yaml" 2>/dev/null)
        password=$(grep -oP '(?<=password: ).*' "${HY2_CONFIG_DIR}/config.yaml" 2>/dev/null)
        domain=$(grep -oP '(?<=cert: .*/)[^/]+(?=\.crt)' "${HY2_CONFIG_DIR}/config.yaml" 2>/dev/null || \
                 openssl x509 -in "${CERT_DIR}/cert.crt" -noout -subject 2>/dev/null | grep -oP '(?<=CN = ).*' | head -1)
    fi

    [ -z "$port" ] && port="$(grep -r 'port' "${HY2_CONFIG_DIR}/node.conf" 2>/dev/null | awk -F= '{print $2}')"

    # 获取 IPv6 地址（方括号格式）
    local ipv6_raw ipv6_bracket
    ipv6_raw=$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6 )[\da-f:]+(?=/)' | grep -v '^fe80' | head -1)
    ipv6_bracket="[${ipv6_raw}]"

    # 读取 node.conf（安装时保存）
    local node_conf="${HY2_CONFIG_DIR}/node.conf"
    if [ -f "$node_conf" ]; then
        source "$node_conf" 2>/dev/null
    fi

    local hy2_link="hysteria2://${password}@${ipv6_bracket}:${port}/?insecure=1&sni=${NODE_DOMAIN:-bing.com}#EUserv-HY2"

    echo ""
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}${BOLD}          🎉 Hysteria2 节点信息 (EUserv IPv6)${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${CYAN}服务器 IPv6:${NC}  ${ipv6_raw}"
    echo -e "  ${CYAN}端口:${NC}         ${port}"
    echo -e "  ${CYAN}密码:${NC}         ${password}"
    echo -e "  ${CYAN}SNI:${NC}          ${NODE_DOMAIN:-bing.com}"
    echo -e "  ${CYAN}跳过证书验证:${NC} true（自签证书）"
    echo -e "  ${CYAN}协议:${NC}         UDP / QUIC"
    echo ""
    echo -e "  ${YELLOW}${BOLD}━━━ 节点链接 (复制到客户端) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${WHITE}${hy2_link}${NC}"
    echo ""

    # 二维码
    if command -v qrencode &>/dev/null; then
        echo -e "  ${YELLOW}━━━ 扫码导入 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        qrencode -t ANSIUTF8 -m 2 "${hy2_link}"
        echo ""
    fi

    echo -e "  ${YELLOW}${BOLD}━━━ Clash Meta / Mihomo 单行配置 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    local clash_line="  - {name: 'EUserv-HY2', type: hysteria2, server: '${ipv6_raw}', port: ${port}, password: ${password}, sni: ${NODE_DOMAIN:-bing.com}, skip-cert-verify: true, fast-open: true}"
    echo -e "${WHITE}${clash_line}${NC}"
    echo ""
    echo -e "  ${DIM}⚠ 注意: EUserv 为纯 IPv6 环境，客户端需支持 IPv6 连接${NC}"
    echo -e "  ${DIM}⚠ 若客户端无 IPv6，请先配置 Warp 或使用支持 IPv6 的客户端网络${NC}"
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# =============================================
#  主安装流程
# =============================================
do_install() {
    show_banner
    echo -e "  ${WHITE}${BOLD}开始安装 Hysteria2（EUserv IPv6-only 专用）${NC}"
    echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
    echo ""

    # 检测 root
    if [ "$EUID" -ne 0 ]; then
        error "请以 root 权限运行此脚本"
        exit 1
    fi

    # 初始化日志
    mkdir -p "$(dirname $LOG_FILE)"
    touch "$LOG_FILE"

    # 检测是否已安装
    if [ -f "$HY2_BIN" ] && systemctl is-active --quiet hysteria-server 2>/dev/null; then
        warn "Hysteria2 已在运行中"
        echo -ne "  ${YELLOW}是否重新安装？[y/N]:${NC} "
        read -r reinstall
        [ "${reinstall,,}" != "y" ] && return
        systemctl stop hysteria-server 2>/dev/null
    fi

    # 检测网络
    check_network || exit 1

    # 系统初始化
    init_system

    # ---- 用户配置输入 ----
    echo ""
    echo -e "  ${WHITE}${BOLD}━━━ 配置参数 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 端口
    echo -ne "  ${CYAN}监听端口${NC} ${DIM}[默认: 随机 10000-60000]${NC}: "
    read -r input_port
    if [ -z "$input_port" ]; then
        PORT=$((RANDOM % 50000 + 10000))
        info "随机端口: ${PORT}"
    elif [[ "$input_port" =~ ^[0-9]+$ ]] && [ "$input_port" -ge 1 ] && [ "$input_port" -le 65535 ]; then
        PORT="$input_port"
    else
        error "无效端口，使用随机端口"
        PORT=$((RANDOM % 50000 + 10000))
    fi

    # 密码
    echo -ne "  ${CYAN}连接密码${NC} ${DIM}[默认: 随机生成]${NC}: "
    read -r input_pass
    if [ -z "$input_pass" ]; then
        if command -v uuidgen &>/dev/null; then
            PASSWORD=$(uuidgen | tr -d '-')
        else
            PASSWORD=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' || openssl rand -hex 16)
        fi
        info "随机密码: ${PASSWORD}"
    else
        PASSWORD="$input_pass"
    fi

    # 伪装域名
    echo -ne "  ${CYAN}伪装域名${NC} ${DIM}[默认: bing.com]${NC}: "
    read -r input_domain
    MASQUERADE_DOMAIN="${input_domain:-bing.com}"

    # SNI（用于节点链接）
    echo -ne "  ${CYAN}SNI 域名${NC} ${DIM}[默认: bing.com]${NC}: "
    read -r input_sni
    NODE_DOMAIN="${input_sni:-bing.com}"

    echo ""
    echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
    echo -e "  端口: ${WHITE}${PORT}${NC}  密码: ${WHITE}${PASSWORD}${NC}  伪装: ${WHITE}${MASQUERADE_DOMAIN}${NC}"
    echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
    echo ""

    # ---- 开始安装 ----
    get_latest_version
    install_hysteria2_binary || exit 1
    generate_self_signed_cert "$NODE_DOMAIN" || exit 1
    generate_config "$PORT" "$PASSWORD" "$MASQUERADE_DOMAIN" "$NODE_DOMAIN"
    create_service
    configure_firewall "$PORT"

    # 保存节点信息
    cat > "${HY2_CONFIG_DIR}/node.conf" << EOF
NODE_PORT=${PORT}
NODE_PASSWORD=${PASSWORD}
NODE_DOMAIN=${NODE_DOMAIN}
NODE_MASQUERADE=${MASQUERADE_DOMAIN}
INSTALL_DATE=$(date '+%Y-%m-%d %H:%M:%S')
EOF

    # 启动服务
    step "启动 Hysteria2 服务..."
    systemctl start hysteria-server

    sleep 2
    if systemctl is-active --quiet hysteria-server; then
        success "Hysteria2 服务启动成功！"
    else
        error "服务启动失败，查看日志:"
        journalctl -u hysteria-server -n 20 --no-pager
        return 1
    fi

    # 显示节点信息
    show_node_info
    read -rp "  按 Enter 返回主菜单..." _
}

# =============================================
#  卸载 Hysteria2
# =============================================
do_uninstall() {
    show_banner
    echo -e "  ${RED}${BOLD}卸载 Hysteria2${NC}"
    echo ""
    echo -ne "  ${YELLOW}确认卸载？这将删除所有配置文件 [y/N]:${NC} "
    read -r confirm
    [ "${confirm,,}" != "y" ] && { info "已取消"; return; }

    step "停止服务..."
    systemctl stop hysteria-server 2>/dev/null
    systemctl disable hysteria-server 2>/dev/null

    step "删除文件..."
    rm -f "$HY2_SERVICE"
    rm -f "$HY2_BIN"
    rm -rf "$HY2_CONFIG_DIR"
    systemctl daemon-reload

    success "Hysteria2 已完全卸载"
}

# =============================================
#  服务管理
# =============================================
manage_service() {
    show_banner
    echo -e "  ${WHITE}${BOLD}服务管理${NC}"
    echo ""
    echo -e "  ${GREEN}1.${NC} 启动"
    echo -e "  ${GREEN}2.${NC} 停止"
    echo -e "  ${GREEN}3.${NC} 重启"
    echo -e "  ${GREEN}4.${NC} 查看状态"
    echo -e "  ${GREEN}0.${NC} 返回"
    echo ""
    echo -ne "  ${WHITE}选项:${NC} "
    read -r opt
    case "$opt" in
        1) systemctl start hysteria-server && success "已启动" ;;
        2) systemctl stop hysteria-server && success "已停止" ;;
        3) systemctl restart hysteria-server && success "已重启" ;;
        4) systemctl status hysteria-server ;;
        0) return ;;
    esac
    echo ""
    read -rp "  按 Enter 返回..." _
}

# =============================================
#  查看日志
# =============================================
show_logs() {
    show_banner
    echo -e "  ${WHITE}${BOLD}Hysteria2 运行日志（最近 50 行）${NC}"
    echo -e "  ${DIM}按 Ctrl+C 退出实时查看${NC}"
    echo ""
    journalctl -u hysteria-server -n 50 -f
}

# =============================================
#  修改配置
# =============================================
modify_config() {
    show_banner
    echo -e "  ${WHITE}${BOLD}修改配置${NC}"
    echo ""

    if [ ! -f "${HY2_CONFIG_DIR}/node.conf" ]; then
        error "未找到节点配置，请先安装"
        read -rp "  按 Enter 返回..." _
        return
    fi

    source "${HY2_CONFIG_DIR}/node.conf" 2>/dev/null

    echo -e "  当前端口: ${CYAN}${NODE_PORT}${NC}"
    echo -ne "  新端口 ${DIM}[留空保持不变]${NC}: "
    read -r new_port
    [ -n "$new_port" ] && NODE_PORT="$new_port"

    echo -e "  当前密码: ${CYAN}${NODE_PASSWORD}${NC}"
    echo -ne "  新密码 ${DIM}[留空保持不变]${NC}: "
    read -r new_pass
    [ -n "$new_pass" ] && NODE_PASSWORD="$new_pass"

    echo -e "  当前伪装域名: ${CYAN}${NODE_MASQUERADE}${NC}"
    echo -ne "  新伪装域名 ${DIM}[留空保持不变]${NC}: "
    read -r new_masq
    [ -n "$new_masq" ] && NODE_MASQUERADE="$new_masq"

    # 重新生成配置
    generate_config "$NODE_PORT" "$NODE_PASSWORD" "$NODE_MASQUERADE" "$NODE_DOMAIN"

    # 更新 node.conf
    cat > "${HY2_CONFIG_DIR}/node.conf" << EOF
NODE_PORT=${NODE_PORT}
NODE_PASSWORD=${NODE_PASSWORD}
NODE_DOMAIN=${NODE_DOMAIN}
NODE_MASQUERADE=${NODE_MASQUERADE}
INSTALL_DATE=$(grep INSTALL_DATE "${HY2_CONFIG_DIR}/node.conf" | cut -d= -f2-)
MODIFY_DATE=$(date '+%Y-%m-%d %H:%M:%S')
EOF

    configure_firewall "$NODE_PORT"
    systemctl restart hysteria-server
    sleep 1

    if systemctl is-active --quiet hysteria-server; then
        success "配置已更新并重启服务"
    else
        error "服务重启失败"
    fi

    show_node_info
    read -rp "  按 Enter 返回..." _
}

# =============================================
#  调用 F大 Warp 脚本
# =============================================
run_warp_script() {
    show_banner
    echo -e "  ${MAGENTA}${BOLD}F大 Warp 脚本（fscarmen/warp）${NC}"
    echo -e "  ${DIM}为 EUserv IPv6-only VPS 添加 IPv4 出口${NC}"
    echo ""
    echo -e "  ${WHITE}此脚本将为您：${NC}"
    echo -e "  ${GREEN}•${NC} 安装 Cloudflare Warp"
    echo -e "  ${GREEN}•${NC} 为纯 IPv6 VPS 获得 IPv4 出口能力"
    echo -e "  ${GREEN}•${NC} 支持 WireGuard / Socks5 等多种模式"
    echo ""
    echo -e "  ${YELLOW}${BOLD}━━━ 选择 Warp 安装模式 ━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${GREEN}1.${NC} 交互式菜单（推荐，自行选择模式）"
    echo -e "  ${GREEN}2.${NC} 直接安装 Warp WireGuard 双栈（IPv4+IPv6）"
    echo -e "  ${GREEN}3.${NC} 直接安装 Warp IPv4 单栈（为 IPv6-only 补全 IPv4）"
    echo -e "  ${GREEN}4.${NC} 直接安装 Warp SOCKS5 代理模式"
    echo -e "  ${DIM}   （SOCKS5 运行在 127.0.0.1:40000）${NC}"
    echo -e "  ${GREEN}0.${NC} 返回主菜单"
    echo ""
    echo -ne "  ${WHITE}选项 [0-4]:${NC} "
    read -r warp_opt

    local warp_cmd="wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh"

    case "$warp_opt" in
        0) return ;;
        1)
            echo ""
            info "启动 Warp 交互式菜单..."
            echo ""
            eval "$warp_cmd"
            ;;
        2)
            echo ""
            info "安装 Warp WireGuard 双栈模式..."
            echo ""
            eval "$warp_cmd d"
            ;;
        3)
            echo ""
            info "安装 Warp IPv4 单栈（补全 EUserv IPv4 出口）..."
            echo ""
            eval "$warp_cmd 4"
            ;;
        4)
            echo ""
            info "安装 Warp SOCKS5 代理模式..."
            echo ""
            eval "$warp_cmd s5"
            ;;
        *)
            warn "无效选项"
            sleep 1
            run_warp_script
            return
            ;;
    esac

    echo ""
    echo -e "  ${GREEN}${BOLD}Warp 脚本执行完毕${NC}"
    echo ""
    echo -e "  ${DIM}如安装成功，可通过以下命令验证 IPv4：${NC}"
    echo -e "  ${CYAN}curl -4 ip.sb${NC}"
    echo ""
    read -rp "  按 Enter 返回主菜单..." _
}

# =============================================
#  主入口
# =============================================
main() {
    # 检测 root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} 请以 root 权限运行: sudo bash $0"
        exit 1
    fi

    # 检测系统架构
    local kernel
    kernel=$(uname -r)
    if [[ "$kernel" == *"OpenVZ"* ]] || [ -f /proc/vz/version ]; then
        warn "检测到 OpenVZ 容器环境，UDP 可能受限"
    fi

    while true; do
        show_menu
        read -r choice

        case "${choice,,}" in
            1) do_install ;;
            2) do_uninstall ;;
            3)
                show_banner
                show_node_info
                read -rp "  按 Enter 返回..." _
                ;;
            4) manage_service ;;
            5) show_logs ;;
            6) modify_config ;;
            w) run_warp_script ;;
            0|q|quit|exit)
                echo ""
                echo -e "  ${DIM}感谢使用 EUserv Hysteria2 脚本${NC}"
                echo ""
                exit 0
                ;;
            *)
                warn "无效选项: ${choice}"
                sleep 1
                ;;
        esac
    done
}

main "$@"
