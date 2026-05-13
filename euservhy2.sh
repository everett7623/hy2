#!/bin/bash
# ============================================================
#  EUserv IPv6-only VPS — Hysteria2 一键安装脚本
#  版本：1.2.0
#  网络策略：官方脚本 → IPv6直连 → NAT64 DNS → ghproxy镜像
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

HY2_BIN="/usr/local/bin/hysteria"
HY2_CONF="/etc/hysteria/config.yaml"
HY2_SERVICE="/etc/systemd/system/hysteria-server.service"
CERT_DIR="/etc/hysteria/certs"
LOG_FILE="/var/log/hy2-install.log"

NAT64_DNS1="2001:67c:2b0::4"
NAT64_DNS2="2001:67c:2b0::6"
NAT64_DNS_BACKUP="2a00:1098:2b::1"
DNS_PATCHED=0

info()    { echo -e "${CYAN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERR]${NC}   $*" | tee -a "$LOG_FILE"; restore_dns; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}\n"; }

require_root() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}[ERR]${NC} 请以 root 身份运行"; exit 1; }
}

detect_os() {
    [[ -f /etc/os-release ]] || error "无法检测操作系统"
    source /etc/os-release
    OS_ID="${ID}"; OS_VER="${VERSION_ID}"
    info "操作系统: $OS_ID $OS_VER"
    if [[ "$OS_ID" != "debian" && "$OS_ID" != "ubuntu" ]]; then
        warn "此脚本针对 Debian/Ubuntu，当前系统 $OS_ID 可能不兼容"
    fi
}

# ============================================================
#  NAT64 DNS 临时启用/恢复
#  EUserv纯IPv6机器要访问IPv4资源（如GitHub CDN），
#  NAT64 DNS 把 A 记录地址映射为 64:ff9b::/96 前缀的IPv6地址，
#  流量经公共 NAT64 网关转发到 IPv4 网络，全程无需IPv4接口。
# ============================================================
enable_nat64_dns() {
    [[ $DNS_PATCHED -eq 1 ]] && return
    section "临时启用 NAT64 DNS"
    info "备份 resolv.conf → /etc/resolv.conf.hy2bak"
    cp /etc/resolv.conf /etc/resolv.conf.hy2bak 2>/dev/null || true

    cat > /etc/resolv.conf <<EOF
# Patched by euservhy2.sh — NAT64 DNS for IPv4 reachability
nameserver ${NAT64_DNS1}
nameserver ${NAT64_DNS2}
nameserver ${NAT64_DNS_BACKUP}
EOF
    DNS_PATCHED=1
    ok "NAT64 DNS 启用（安装完成后自动恢复原始配置）"
    sleep 1
}

restore_dns() {
    if [[ $DNS_PATCHED -eq 1 ]] && [[ -f /etc/resolv.conf.hy2bak ]]; then
        cp /etc/resolv.conf.hy2bak /etc/resolv.conf
        DNS_PATCHED=0
        ok "DNS 已恢复原始配置"
    fi
}

# ============================================================
#  获取本机 IPv6 地址
# ============================================================
get_ipv6() {
    local ipv6
    ipv6=$(ip -6 addr show scope global 2>/dev/null \
        | grep -oP '(?<=inet6 )[0-9a-f:]+(?=/)' \
        | grep -v '^fe80' | grep -v '^::1' | head -1)
    [[ -z "$ipv6" ]] && \
        ipv6=$(curl -6 -s --max-time 10 https://api6.ipify.org 2>/dev/null || true)
    [[ -z "$ipv6" ]] && \
        ipv6=$(curl -6 -s --max-time 10 https://v6.ident.me 2>/dev/null || true)
    [[ -z "$ipv6" ]] && error "无法获取本机IPv6地址，请检查网络"
    echo "$ipv6"
}

# ============================================================
#  依赖安装
# ============================================================
install_deps() {
    section "安装依赖"
    apt-get update -y 2>>"$LOG_FILE" || error "apt-get update 失败"
    apt-get install -y curl wget openssl ca-certificates unzip qrencode 2>>"$LOG_FILE" \
        || error "依赖安装失败"
    ok "依赖安装完成"
}

# ============================================================
#  下载 Hysteria2 — 分层策略
#  A. 官方 get.hy2.dev（Cloudflare托管，有AAAA，EUserv可直连）
#  B. IPv6 直连 GitHub release（GitHub有AAAA记录时生效）
#  C. 临时 NAT64 DNS + GitHub（让IPv6机器访问IPv4 CDN节点）
#  D. ghproxy 镜像（Cloudflare，有AAAA）
#  E. bgmi.me 镜像（备用）
# ============================================================
install_hysteria2() {
    section "下载 Hysteria2"

    local arch
    case $(uname -m) in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="armv7" ;;
        *)       error "不支持的架构: $(uname -m)" ;;
    esac

    mkdir -p "$(dirname "$HY2_BIN")"

    _verify_bin() {
        [[ -f "$HY2_BIN" ]] && chmod +x "$HY2_BIN" && "$HY2_BIN" version &>/dev/null
    }

    _try_download() {
        local desc="$1" url="$2"
        info "[${desc}] 尝试: ${url}"
        if curl -fL --progress-bar --max-time 120 -o "${HY2_BIN}.tmp" "$url" 2>>"$LOG_FILE"; then
            mv "${HY2_BIN}.tmp" "$HY2_BIN"
            if _verify_bin; then
                ok "[${desc}] 成功 ✓"
                return 0
            else
                warn "[${desc}] 文件损坏，跳过"
                rm -f "$HY2_BIN"
            fi
        else
            rm -f "${HY2_BIN}.tmp"
            warn "[${desc}] 失败"
        fi
        return 1
    }

    # --- 方案 A：官方安装脚本 ---
    info "[方案A] 官方安装脚本 get.hy2.dev ..."
    if curl -fsSL --max-time 30 https://get.hy2.dev/ 2>>"$LOG_FILE" | bash -s -- --version latest >>"$LOG_FILE" 2>&1; then
        if _verify_bin; then
            ok "[方案A] 官方脚本安装成功 ✓"
            return 0
        fi
    fi
    warn "[方案A] 失败"

    # 获取版本号
    local ver
    ver=$(curl -fsSL --max-time 20 https://api.github.com/repos/apernet/hysteria/releases/latest \
        2>/dev/null | grep -oP '"tag_name":\s*"app/v\K[^"]+' | head -1)
    [[ -z "$ver" ]] && { warn "版本号获取失败，使用 2.6.1"; ver="2.6.1"; }
    info "目标版本: v${ver}"

    local gh_url="https://github.com/apernet/hysteria/releases/download/app%2Fv${ver}/hysteria-linux-${arch}"
    local proxy_url="https://mirror.ghproxy.com/https://github.com/apernet/hysteria/releases/download/app%2Fv${ver}/hysteria-linux-${arch}"
    local bgmi_url="https://bgmi.me/https://github.com/apernet/hysteria/releases/download/app%2Fv${ver}/hysteria-linux-${arch}"

    # --- 方案 B：IPv6 直连 GitHub ---
    _try_download "方案B: IPv6直连GitHub" "$gh_url" && return 0

    # --- 方案 C：NAT64 DNS + GitHub ---
    info "启用 NAT64 DNS 再试..."
    enable_nat64_dns
    sleep 2
    _try_download "方案C: NAT64+GitHub" "$gh_url" && return 0

    # --- 方案 D：ghproxy 镜像 ---
    _try_download "方案D: ghproxy镜像" "$proxy_url" && return 0

    # --- 方案 E：bgmi 镜像 ---
    _try_download "方案E: bgmi镜像" "$bgmi_url" && return 0

    error "所有方案均失败，请查看 $LOG_FILE 或手动上传二进制至 $HY2_BIN"
}

# ============================================================
#  生成自签证书（ECC P-256）
# ============================================================
gen_cert() {
    section "生成 TLS 证书"
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "${CERT_DIR}/private.key" \
        -out    "${CERT_DIR}/cert.crt" \
        -days 3650 -nodes \
        -subj "/CN=euserv-hy2" \
        2>>"$LOG_FILE" || error "证书生成失败"
    chmod 600 "${CERT_DIR}/private.key"
    ok "证书生成完成（10年有效）"
}

gen_password() { openssl rand -hex 16; }

# ============================================================
#  服务端配置
# ============================================================
write_config() {
    local ipv6="$1" port="$2" password="$3"
    section "生成配置文件"
    mkdir -p /etc/hysteria

    cat > "$HY2_CONF" <<EOF
# Hysteria2 Server Config — EUserv IPv6
listen: [::]:${port}

tls:
  cert: ${CERT_DIR}/cert.crt
  key:  ${CERT_DIR}/private.key

auth:
  type: password
  password: "${password}"

bandwidth:
  up: 100 mbps
  down: 100 mbps

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s

masquerade:
  type: proxy
  proxy:
    url: https://news.ycombinator.com
    rewriteHost: true
EOF
    ok "配置写入完成 → $HY2_CONF"
}

tune_kernel() {
    section "内核参数优化"
    cat > /etc/sysctl.d/99-hy2.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 16384
EOF
    sysctl -p /etc/sysctl.d/99-hy2.conf >>"$LOG_FILE" 2>&1 || true
    ok "内核参数优化完成"
}

open_firewall() {
    local port="$1"
    section "防火墙配置"
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${port}/udp" >>"$LOG_FILE" 2>&1
        ok "ufw 放行 ${port}/udp"
    fi
    if command -v ip6tables &>/dev/null; then
        ip6tables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null \
            || ip6tables -I INPUT -p udp --dport "$port" -j ACCEPT
        mkdir -p /etc/iptables
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        ok "ip6tables 放行 IPv6 UDP ${port}"
    fi
}

setup_service() {
    section "配置 systemd 服务"
    cat > "$HY2_SERVICE" <<EOF
[Unit]
Description=Hysteria2 Proxy Server (EUserv IPv6)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${HY2_BIN} server -c ${HY2_CONF}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria-server --quiet 2>>"$LOG_FILE"
    systemctl restart hysteria-server 2>>"$LOG_FILE"
    sleep 3

    if systemctl is-active --quiet hysteria-server; then
        ok "hysteria-server 运行中 ✓"
    else
        warn "服务启动异常，日志："
        journalctl -u hysteria-server -n 30 --no-pager
        error "服务启动失败"
    fi
}

# ============================================================
#  输出客户端配置
# ============================================================
print_result() {
    local ipv6="$1" port="$2" password="$3"
    local uri="hy2://${password}@[${ipv6}]:${port}?insecure=1&sni=euserv-hy2#EUserv-HY2"

    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║      🎉 Hysteria2 安装成功！客户端配置如下       ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}IPv6：    ${NC}${CYAN}${ipv6}${NC}"
    echo -e "  ${BOLD}端口：    ${NC}${CYAN}${port}${NC}"
    echo -e "  ${BOLD}密码：    ${NC}${CYAN}${password}${NC}"
    echo -e "  ${BOLD}协议：    ${NC}${CYAN}Hysteria2 (QUIC/UDP)${NC}"
    echo ""
    echo -e "  ${BOLD}${YELLOW}── 分享链接 ──${NC}"
    echo -e "  ${CYAN}${uri}${NC}"
    echo ""
    if command -v qrencode &>/dev/null; then
        echo -e "  ${BOLD}${YELLOW}── 二维码 ──${NC}"
        qrencode -t ANSIUTF8 "$uri"
        echo ""
    fi
    echo -e "  ${BOLD}${YELLOW}── Clash Meta / Mihomo ──${NC}"
    cat <<EOF

proxies:
  - name: EUserv-HY2
    type: hysteria2
    server: ${ipv6}
    port: ${port}
    password: "${password}"
    skip-cert-verify: true
    sni: euserv-hy2
    udp: true
EOF
    echo ""
    echo -e "  ${YELLOW}⚠ 客户端需要 IPv6 网络才能连接此节点${NC}"
    echo -e "  ${YELLOW}  国内宽带：路由器开启 IPv6 即可${NC}"
    echo -e "  ${YELLOW}  无 IPv6 的客户端：装 WARP 后再连（菜单选项 7）${NC}"
    echo ""
    echo -e "  systemctl {start|stop|restart|status} hysteria-server"
    echo -e "  journalctl -u hysteria-server -f"
    echo ""

    cat > /root/hy2-node-info.txt <<EOF
=== EUserv Hysteria2 节点信息 ===
IPv6    : ${ipv6}
Port    : ${port}
Password: ${password}
URI     : ${uri}

Clash Meta:
proxies:
  - name: EUserv-HY2
    type: hysteria2
    server: ${ipv6}
    port: ${port}
    password: "${password}"
    skip-cert-verify: true
    sni: euserv-hy2
    udp: true
EOF
    ok "节点信息已保存 → /root/hy2-node-info.txt"
}

# ============================================================
#  WARP 安装（fscarmen）
# ============================================================
install_warp() {
    section "安装 WARP（fscarmen 脚本）"
    echo -e "  ${CYAN}https://gitlab.com/fscarmen/warp${NC}"
    echo ""
    echo -e "  ${BOLD}a.${NC} ${YELLOW}添加 IPv4 出口（推荐）${NC} — 给纯IPv6机器加IPv4访问"
    echo -e "  ${BOLD}b.${NC} 添加 IPv6 出口"
    echo -e "  ${BOLD}c.${NC} 全局双栈 WARP"
    echo -e "  ${BOLD}d.${NC} 手动输入参数"
    echo -e "  ${BOLD}0.${NC} 返回"
    echo ""
    read -rp "  请选择 [a/b/c/d/0]: " warp_choice
    [[ "$warp_choice" == "0" ]] && return

    local warp_script
    warp_script=$(mktemp /tmp/warp_XXXXXX.sh)
    info "下载 fscarmen WARP 脚本..."
    if ! wget -q --timeout=30 "https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh" -O "$warp_script"; then
        rm -f "$warp_script"
        error "WARP 脚本下载失败"
    fi
    chmod +x "$warp_script"

    case "$warp_choice" in
        a) bash "$warp_script" -4 ;;
        b) bash "$warp_script" -6 ;;
        c) bash "$warp_script" -d ;;
        d) read -rp "  参数: " args; bash "$warp_script" $args ;;
        *) warn "无效选项" ;;
    esac
    rm -f "$warp_script"
}

# ============================================================
#  卸载
# ============================================================
uninstall_hy2() {
    section "卸载 Hysteria2"
    read -rp "  确认卸载？(y/N): " confirm
    [[ "${confirm,,}" != "y" ]] && { warn "已取消"; return; }
    systemctl stop hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    rm -f "$HY2_SERVICE" "$HY2_BIN"
    rm -rf /etc/hysteria
    rm -f /root/hy2-node-info.txt /etc/sysctl.d/99-hy2.conf
    systemctl daemon-reload
    ok "卸载完成"
}

# ============================================================
#  主安装流程
# ============================================================
do_install() {
    section "EUserv IPv6 Hysteria2 安装"

    info "检测本机 IPv6..."
    local SERVER_IPV6
    SERVER_IPV6=$(get_ipv6)
    ok "IPv6: ${SERVER_IPV6}"

    local PORT
    read -rp "  监听端口 [默认 8443]: " PORT
    PORT=${PORT:-8443}
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
        warn "端口不合法，使用 8443"; PORT=8443
    fi

    install_deps
    install_hysteria2
    restore_dns   # 安装完恢复DNS
    gen_cert "$SERVER_IPV6"
    local PASSWORD; PASSWORD=$(gen_password)
    write_config "$SERVER_IPV6" "$PORT" "$PASSWORD"
    tune_kernel
    open_firewall "$PORT"
    setup_service
    print_result "$SERVER_IPV6" "$PORT" "$PASSWORD"
}

# ============================================================
#  菜单
# ============================================================
show_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    cat <<'BANNER'
 ╔═══════════════════════════════════════════════════╗
 ║    EUserv IPv6 VPS — Hysteria2 管理脚本  v1.2     ║
 ║    NAT64下载策略 | 自签TLS | QUIC优化 | WARP      ║
 ╚═══════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        echo -e "  HY2 状态: ${GREEN}● 运行中${NC}"
    else
        echo -e "  HY2 状态: ${RED}● 未运行${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}1.${NC} 安装 / 重装 Hysteria2"
    echo -e "  ${BOLD}2.${NC} 查看节点信息"
    echo -e "  ${BOLD}3.${NC} 查看服务状态"
    echo -e "  ${BOLD}4.${NC} 重启服务"
    echo -e "  ${BOLD}5.${NC} 实时日志"
    echo -e "  ${BOLD}6.${NC} 卸载 Hysteria2"
    echo -e "  ${BOLD}${YELLOW}7.${NC}${YELLOW} 安装 WARP（fscarmen）${NC}"
    echo -e "  ${BOLD}0.${NC} 退出"
    echo ""
    read -rp "  请选择 [0-7]: " choice

    case "$choice" in
        1) do_install ;;
        2) [[ -f /root/hy2-node-info.txt ]] && cat /root/hy2-node-info.txt || warn "暂无信息，请先安装" ;;
        3) systemctl status hysteria-server --no-pager ;;
        4) systemctl restart hysteria-server && ok "已重启" ;;
        5) journalctl -u hysteria-server -f ;;
        6) uninstall_hy2 ;;
        7) install_warp ;;
        0) exit 0 ;;
        *) warn "无效选项" ;;
    esac
    echo ""
    read -rp "  按 Enter 返回菜单..." _
    show_menu
}

# ============================================================
#  入口
# ============================================================
main() {
    require_root
    detect_os
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    case "${1:-}" in
        --install|-i) do_install ;;
        --uninstall)  uninstall_hy2 ;;
        --warp)       install_warp ;;
        *)            show_menu ;;
    esac
}

main "$@"
