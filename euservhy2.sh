#!/bin/bash
# ============================================================
#  EUserv IPv6-only Hysteria2 一键安装脚本
#  项目地址: https://github.com/everett7623/hy2
#  适用环境: EUserv 免费 IPv6-only VPS
#  版本: v2.0.0
#  更新时间: 2026-07-02
# ============================================================

# ============================================================
# 自举：确保以 bash 运行
# Alpine 等系统默认 sh 为 busybox，不支持 bash 语法
# 注意：仅支持已保存到磁盘后执行，不可通过 curl | sh 管道运行（$0 不是文件路径）
# ============================================================
if [ -z "$BASH_VERSION" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        if [ -f /etc/alpine-release ]; then
            apk add --no-cache bash >/dev/null 2>&1
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y -qq bash >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash >/dev/null 2>&1
        fi
        command -v bash >/dev/null 2>&1 || { echo "错误: 无法安装 bash，请手动安装后重试"; exit 1; }
        exec bash "$0" "$@"
    fi
fi

# --- 修复交互输入 ---
if [ "${EXPORT_LIB_ONLY:-0}" != "1" ] && [ ! -t 0 ]; then
    [ -c /dev/tty ] && exec < /dev/tty
fi

# --- 修复 Windows 换行符 ---
if [ "${EXPORT_LIB_ONLY:-0}" != "1" ] && [ -f "$0" ] && grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0"
    exec bash "$0" "$@"
fi

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
SCRIPT_VERSION="2.0.0"

# NAT64 公共 DNS（纯IPv6机器临时访问IPv4资源）
NAT64_DNS1="2001:67c:2b0::4"
NAT64_DNS2="2001:67c:2b0::6"
NAT64_DNS_BACKUP="2a00:1098:2b::1"
DNS_PATCHED=0

# ---- 工具函数 ----
log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }
info()    { echo -e "${GREEN}[INFO]${NC} $*";    log "INFO: $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*";   log "WARN: $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*";    log "ERROR: $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*";       log "SUCCESS: $*"; }
step()    { echo -e "${CYAN}[STEP]${NC} $*";     log "STEP: $*"; }

# ============================================================
#  获取 hostname 作为节点名称
#  hostname为空时回退到 EUserv-HY2
# ============================================================
#  获取服务器真实 IPv6（排除 WARP/tunnel 等虚拟网卡）
#  问题：WARP 安装后虚拟网卡也有 scope global 的 IPv6，
#        head -1 可能优先取到 WARP 地址 (2606:4700:...) 而非真实地址
# ============================================================
_get_real_ipv6() {
    ip -6 addr show scope global 2>/dev/null | awk '
        /^[0-9]+:/ { iface=$2; sub(/:.*/,"",iface) }
        /inet6/ && iface !~ /wgcf|warp|^tun|^wg|tailscale|zt/ {
            addr=$2; sub(/\/.*/,"",addr)
            if (addr !~ /^fe80/ && addr !~ /^2606:4700:/) { print addr; exit }
        }
    '
}

# ============================================================
get_node_name() {
    local hn
    hn=$(hostname 2>/dev/null | tr -d '\n\r')
    if [[ -z "${hn// /}" ]]; then
        hn="EUserv-HY2"
    fi
    echo "$hn"
}

trim_string() {
    printf '%s' "$1" | tr -d '\r\n\t' | awk '{$1=$1; print}'
}

print_copy_block() {
    printf '%s\n' "$1"
}

uri_encode() {
    local _in="$1"
    if command -v python3 >/dev/null 2>&1; then
        if printf '%s' "$_in" | python3 -c \
            "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''), end='')" 2>/dev/null; then
            return
        fi
    fi
    local _out="" _i=0 _c _hex
    local _len=${#_in}
    while [ $_i -lt $_len ]; do
        _c="${_in:_i:1}"
        case "$_c" in
            [a-zA-Z0-9.~_-]) _out="${_out}${_c}" ;;
            *) _hex=$(printf '%s' "$_c" | od -An -tx1 | awk '{ for (i=1; i<=NF; i++) printf "%%%s", toupper($i) }'); _out="${_out}${_hex}" ;;
        esac
        _i=$((_i + 1))
    done
    printf '%s' "$_out"
}

get_ip_country() {
    local _ip="$1" _code=""
    [ -z "$_ip" ] && return 1
    _code=$(curl -s --connect-timeout 3 --max-time 4 "https://ipapi.co/${_ip}/country/" 2>/dev/null \
        | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]' | awk '/^[A-Z][A-Z]$/ { print; exit }')
    [ -z "$_code" ] && _code=$(curl -s --connect-timeout 3 --max-time 4 "https://ipinfo.io/${_ip}/country" 2>/dev/null \
        | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]' | awk '/^[A-Z][A-Z]$/ { print; exit }')
    [ -n "$_code" ] && printf '%s' "$_code"
}

get_country_code() {
    local _ip="$1" _code=""
    [ -n "$_ip" ] && _code=$(get_ip_country "$_ip" 2>/dev/null || true)
    [ -z "$_code" ] && _code="UN"
    printf '%s' "$_code"
}

get_country_name() {
    case "$1" in
        US) printf 'United States' ;; DE) printf 'Germany' ;; JP) printf 'Japan' ;; SG) printf 'Singapore' ;;
        HK) printf 'Hong Kong' ;; TW) printf 'Taiwan' ;; KR) printf 'South Korea' ;; GB) printf 'United Kingdom' ;;
        FR) printf 'France' ;; NL) printf 'Netherlands' ;; CA) printf 'Canada' ;; AU) printf 'Australia' ;;
        RU) printf 'Russia' ;; IN) printf 'India' ;; VN) printf 'Vietnam' ;; TH) printf 'Thailand' ;;
        UN) printf 'Unknown' ;; *) printf 'Unknown' ;;
    esac
}

get_country_flag() {
    case "$1" in
        US) printf '🇺🇸' ;; DE) printf '🇩🇪' ;; JP) printf '🇯🇵' ;; SG) printf '🇸🇬' ;;
        HK) printf '🇭🇰' ;; TW) printf '🇹🇼' ;; KR) printf '🇰🇷' ;; GB) printf '🇬🇧' ;;
        FR) printf '🇫🇷' ;; NL) printf '🇳🇱' ;; CA) printf '🇨🇦' ;; AU) printf '🇦🇺' ;;
        RU) printf '🇷🇺' ;; IN) printf '🇮🇳' ;; VN) printf '🇻🇳' ;; TH) printf '🇹🇭' ;;
        *) printf '🌐' ;;
    esac
}

generate_node_name() {
    local _country _flag _server _protocol _ip_type
    _country=$(printf '%s' "${1:-UN}" | tr '[:lower:]' '[:upper:]')
    case "$_country" in [A-Z][A-Z]) ;; *) _country="UN" ;; esac
    _flag=$(get_country_flag "$_country")
    _server=$(trim_string "${2:-}")
    [ -z "$_server" ] && _server="EUserv-HY2"
    _protocol=$(trim_string "${3:-EUserv-HY2}")
    _ip_type=$(trim_string "${4:-IPv6}")
    printf '%s %s | %s | %s | %s' "$_flag" "$_country" "$_server" "$_protocol" "$_ip_type" | tr -d '\r\n\t'
}

shell_json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

generate_terminal_qrcode() {
    local _data="$1"
    command -v qrencode >/dev/null 2>&1 || return 1
    qrencode -t ANSIUTF8 -m 2 "$_data"
}

generate_local_qrcode_png() {
    local _data="$1" _dir="/root/singbox-tools/qrcode" _file
    command -v qrencode >/dev/null 2>&1 || return 1
    mkdir -p "$_dir" 2>/dev/null || return 1
    _file="${_dir}/euserv-hy2-ipv6.png"
    qrencode -o "$_file" "$_data" 2>/dev/null || return 1
    printf '%s' "$_file"
}

generate_online_qrcode_url() {
    local _data="$1" _encoded
    _encoded=$(uri_encode "$_data")
    printf 'https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=%s' "$_encoded"
}

valid_domain() {
    echo "$1" | grep -qE '^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:[0-9]{1,5})?$'
}

# ============================================================
#  WARP 状态检测
#  fscarmen WARP 装完后网卡名不固定（warp0/wgcf/wg0/utun等），
#  最可靠的方式是直接 curl -4 看能否拿到 IPv4 地址。
#  网卡检测作为辅助（离线判断用）。
#  返回 "installed" 或 "none"
# ============================================================
check_warp_status() {
    # 主判断：能拿到 IPv4 说明 WARP/NAT64 出口生效
    local ipv4
    ipv4=$(curl -4 -s --max-time 4 ip.sb 2>/dev/null \
        || curl -4 -s --max-time 4 ifconfig.me 2>/dev/null || true)
    if [ -n "$ipv4" ]; then
        echo "installed"
        return
    fi
    # 辅助判断：检测常见 WARP 网卡名（无网络时也能判断）
    if ip link show warp0       &>/dev/null 2>&1 \
    || ip link show wgcf        &>/dev/null 2>&1 \
    || ip link show wg0         &>/dev/null 2>&1 \
    || ip link show cloudflare-warp &>/dev/null 2>&1 \
    || command -v warp-cli      &>/dev/null; then
        echo "installed"
        return
    fi
    echo "none"
}

# ============================================================
#  NAT64 DNS 临时启用 / 恢复
# ============================================================
enable_nat64_dns() {
    [[ $DNS_PATCHED -eq 1 ]] && return
    step "临时启用 NAT64 DNS（用于访问 IPv4 资源）..."
    cp /etc/resolv.conf /etc/resolv.conf.hy2bak 2>/dev/null || true
    cat > /etc/resolv.conf <<EOF
# euservhy2.sh NAT64 临时配置，安装后自动恢复
nameserver ${NAT64_DNS1}
nameserver ${NAT64_DNS2}
nameserver ${NAT64_DNS_BACKUP}
EOF
    DNS_PATCHED=1
    # 设置 trap，脚本被中断时也能恢复 DNS
    trap restore_dns EXIT INT TERM
    success "NAT64 DNS 已启用（安装完成后自动恢复）"
    sleep 1
}

restore_dns() {
    if [[ $DNS_PATCHED -eq 1 ]] && [[ -f /etc/resolv.conf.hy2bak ]]; then
        cp /etc/resolv.conf.hy2bak /etc/resolv.conf
        DNS_PATCHED=0
        # 清除 trap，避免重复触发
        trap - EXIT INT TERM
        success "DNS 已恢复原始配置"
    fi
}

# ============================================================
#  Banne
# ============================================================
show_banner() {
    clea
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

# ============================================================
#  主菜单
#  修复：WARP状态实时检测；节点名显示hostname；菜单重新排序
# ============================================================
show_menu() {
    show_banne

    # ---- 实时状态检测 ----
    local hy2_status warp_status
    local hy2_ver=""
    if [ -f "$HY2_BIN" ]; then
        hy2_ver=$("$HY2_BIN" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        hy2_status="${GREEN}● 运行中${NC}${DIM} ${hy2_ver}${NC}"
    elif [ -f "$HY2_BIN" ]; then
        hy2_status="${YELLOW}● 已安装/未运行${NC}${DIM} ${hy2_ver}${NC}"
    else
        hy2_status="${RED}● 未安装${NC}"
    fi

    # 修复：用 check_warp_status() 统一检测，每次进菜单实时刷新
    if [ "$(check_warp_status)" = "installed" ]; then
        warp_status="${GREEN}● 已安装${NC}"
    else
        warp_status="${RED}● 未安装${NC}"
    fi

    # 修复：IPv4 不写死，实时获取（Warp装好后立即显示）
    local ipv4_addr ipv6_add
    ipv4_addr=$(curl -4 -s --max-time 3 ip.sb 2>/dev/null || echo "无 IPv4")
    ipv6_addr=$(_get_real_ipv6 \
        || echo "获取失败")

    # 修复：节点名实时读取 hostname
    local node_name
    node_name=$(get_node_name)

    echo -e "  ${WHITE}${BOLD}系统状态${NC}"
    echo -e "  ${DIM}┌─────────────────────────────────────────────┐${NC}"
    echo -e "  ${DIM}│${NC}  节点名称:      ${CYAN}${node_name}${NC}"
    echo -e "  ${DIM}│${NC}  Hysteria2:     $(echo -e "$hy2_status")"
    echo -e "  ${DIM}│${NC}  WARP:          $(echo -e "$warp_status")"
    echo -e "  ${DIM}│${NC}  IPv6:          ${CYAN}${ipv6_addr}${NC}"
    echo -e "  ${DIM}│${NC}  IPv4 (WARP):   ${CYAN}${ipv4_addr}${NC}"
    echo -e "  ${DIM}└─────────────────────────────────────────────┘${NC}"
    echo ""

    # ---- 菜单选项（重新排序）----
    echo -e "  ${WHITE}${BOLD}━━━ Hysteria2 管理 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}1.${NC} 安装 / 重装 Hysteria2"
    echo -e "  ${GREEN}2.${NC} 查看节点信息 / 链接"
    echo -e "  ${GREEN}3.${NC} 修改配置（端口 / 密码 / 伪装域名）"
    echo -e "  ${GREEN}4.${NC} 升级 Hysteria2"
    echo -e "  ${GREEN}5.${NC} 服务管理（启动 / 停止 / 重启）"
    echo -e "  ${GREEN}6.${NC} 查看运行日志"
    echo -e "  ${GREEN}7.${NC} 卸载 Hysteria2"
    echo ""
    echo -e "  ${WHITE}${BOLD}━━━ 网络增强 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${MAGENTA}8.${NC} WARP（F大 fscarmen 脚本）— IPv6-only 补全 IPv4"
    echo -e "  ${BLUE}9.${NC} 系统工具（BBR / 系统信息 / 网络测试）"
    echo ""
    echo -e "  ${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}0.${NC} 退出"
    echo ""
    echo -ne "  ${WHITE}请输入选项 [0-9]:${NC} "
}

# ============================================================
#  网络检测
# ============================================================
check_network() {
    step "检测网络环境..."

    local ipv6_add
    ipv6_addr=$(_get_real_ipv6)
    if [ -z "$ipv6_addr" ]; then
        error "未检测到全局 IPv6 地址，请确认 EUserv VPS 网络正常"
        return 1
    fi
    success "IPv6 地址: ${ipv6_addr}"

    local ipv4_test
    ipv4_test=$(curl -4 -s --max-time 5 ip.sb 2>/dev/null)
    if [ -n "$ipv4_test" ]; then
        warn "检测到 IPv4: ${ipv4_test}（EUserv 标准为纯 IPv6）"
    else
        info "纯 IPv6 环境确认（EUserv 标准配置）"
    fi

    if curl -6 -s --max-time 8 https://ipv6.google.com -o /dev/null 2>/dev/null; then
        success "IPv6 互联网连通正常"
    else
        warn "IPv6 连接测试超时，请检查防火墙配置"
    fi
    return 0
}

# ============================================================
#  系统初始化
# ============================================================
init_system() {
    step "初始化系统环境..."

    if ! [ -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
        error "EUserv 专用脚本需要 systemd；其他环境请使用 hy2.sh"
        return 1
    fi

    if [ -f /etc/debian_version ]; then
        OS="debian"; PKG_MGR="apt-get"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"; PKG_MGR="yum"
    else
        error "不支持的操作系统"
        return 1
    fi
    info "系统类型: ${OS}"

    step "安装必要依赖..."
    if [ "$OS" = "debian" ]; then
        apt-get update -y >> "$LOG_FILE" 2>&1
        # 修复：加入 file 包（用于验证二进制ELF格式，防Segfault）
        apt-get install -y curl wget openssl qrencode net-tools uuid-runtime file \
            >> "$LOG_FILE" 2>&1 || \
        apt-get install -y curl wget openssl net-tools file >> "$LOG_FILE" 2>&1
    else
        yum makecache -y >> "$LOG_FILE" 2>&1
        yum install -y curl wget openssl qrencode net-tools util-linux file \
            >> "$LOG_FILE" 2>&1
    fi
    success "依赖安装完成"
}

# ============================================================
#  获取最新版本号
# ============================================================
get_latest_version() {
    step "获取 Hysteria2 最新版本..."

    # 方式1: IPv6 直连 GitHub API
    HY2_VERSION=$(curl -6 -s --max-time 10 \
        "https://api.github.com/repos/apernet/hysteria/releases/latest" \
        2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

    # 方式2: IPv4（Warp 环境）
    if [ -z "$HY2_VERSION" ]; then
        HY2_VERSION=$(curl -4 -s --max-time 10 \
            "https://api.github.com/repos/apernet/hysteria/releases/latest" \
            2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    fi

    # 方式3: ghproxy
    if [ -z "$HY2_VERSION" ]; then
        HY2_VERSION=$(curl -s --max-time 10 \
            "https://ghproxy.net/https://api.github.com/repos/apernet/hysteria/releases/latest" \
            2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    fi

    if [ -z "$HY2_VERSION" ]; then
        warn "无法获取最新版本，使用内置版本 app/v2.9.1"
        HY2_VERSION="app/v2.9.1"
    fi
    success "目标版本: ${HY2_VERSION}"
}

# ============================================================
#  下载并安装 Hysteria2 二进制
#  修复：官方 download.hysteria.network（CF/AAAA）最优先；
#        file命令预检ELF防Segfault；NAT64 DNS兜底
# ============================================================
install_hysteria2_binary() {
    step "下载 Hysteria2 二进制..."

    local arch
    case $(uname -m) in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="arm" ;;
        *)       error "不支持架构: $(uname -m)"; return 1 ;;
    esac
    info "架构: linux-${arch}"

    local tmp_bin
    tmp_bin=$(mktemp /tmp/hysteria-euserv-XXXXXX 2>/dev/null) || {
        error "无法创建下载临时文件"
        return 1
    }
    local ver_tag="${HY2_VERSION}"   # 格式: app/v2.x.x
    local gh_url="https://github.com/apernet/hysteria/releases/download/${ver_tag}/hysteria-linux-${arch}"

    # 修复：验证函数预检ELF格式，避免损坏文件执行产生Segfault
    __verify_bin() {
        local f="$1"
        [ -s "$f" ] || return 1
        if command -v file &>/dev/null; then
            file "$f" 2>/dev/null | grep -qiE "ELF|executable" || return 1
        fi
        chmod +x "$f"
        "$f" version &>/dev/null || return 1
        return 0
    }

    __try_url() {
        local desc="$1" url="$2"
        info "尝试 [${desc}]: ${url}"
        rm -f "$tmp_bin"
        if curl -fL --progress-bar --connect-timeout 15 --max-time 120 \
            -o "$tmp_bin" "$url" 2>>"$LOG_FILE"; then
            if __verify_bin "$tmp_bin"; then
                return 0
            else
                warn "[${desc}] 文件无效（非ELF或无法执行）"
                rm -f "$tmp_bin"
            fi
        else
            warn "[${desc}] 下载失败"
            rm -f "$tmp_bin"
        fi
        return 1
    }

    # ── 方案1：官方 download.hysteria.network（CF托管，有AAAA，最优先）
    __try_url "官方CDN" \
        "https://download.hysteria.network/app/latest/hysteria-linux-${arch}" \
        && { mv "$tmp_bin" "$HY2_BIN"; chmod +x "$HY2_BIN"; success "下载成功（官方CDN）"; return 0; }

    # ── 方案2：IPv6 直连 GitHub
    __try_url "IPv6直连GitHub" "$gh_url" \
        && { mv "$tmp_bin" "$HY2_BIN"; chmod +x "$HY2_BIN"; success "下载成功（GitHub直连）"; return 0; }

    # ── 方案3：临时 NAT64 DNS + GitHub
    info "启用 NAT64 DNS 后重试 GitHub..."
    enable_nat64_dns; sleep 2
    __try_url "NAT64+GitHub" "$gh_url" \
        && { mv "$tmp_bin" "$HY2_BIN"; chmod +x "$HY2_BIN"; success "下载成功（NAT64+GitHub）"; return 0; }

    # ── 方案4：ghproxy.net 镜像
    __try_url "ghproxy.net" \
        "https://ghproxy.net/${gh_url}" \
        && { mv "$tmp_bin" "$HY2_BIN"; chmod +x "$HY2_BIN"; success "下载成功（ghproxy.net）"; return 0; }

    # ── 方案5：mirror.ghproxy.com
    __try_url "mirror.ghproxy.com" \
        "https://mirror.ghproxy.com/${gh_url}" \
        && { mv "$tmp_bin" "$HY2_BIN"; chmod +x "$HY2_BIN"; success "下载成功（mirror.ghproxy）"; return 0; }

    # ── 方案6：gh-proxy.com
    __try_url "gh-proxy.com" \
        "https://gh-proxy.com/${gh_url}" \
        && { mv "$tmp_bin" "$HY2_BIN"; chmod +x "$HY2_BIN"; success "下载成功（gh-proxy.com）"; return 0; }

    error "所有下载方案均失败！"
    error "手动方法：在其他机器下载后 scp 传入："
    error "  https://download.hysteria.network/app/latest/hysteria-linux-${arch}"
    error "  scp hysteria root@[IPv6地址]:${HY2_BIN} && chmod +x ${HY2_BIN}"
    return 1
}

# ============================================================
#  生成自签证书
# ============================================================
generate_self_signed_cert() {
    local domain="$1"
    step "生成自签 TLS 证书..."
    mkdir -p "$CERT_DIR"

    local ipv6_add
    ipv6_addr=$(_get_real_ipv6)

    # 修复：-addext 在 Debian 10 老版 openssl 不支持，加版本判断
    local openssl_ve
    openssl_ver=$(openssl version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 | tr -d '.')
    local san="DNS:${domain}"
    [ -n "$ipv6_addr" ] && san="${san},IP:${ipv6_addr}"

    if [ "${openssl_ver:-0}" -ge 111 ]; then
        # openssl >= 1.1.1 支持 -addext
        openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout "${CERT_DIR}/private.key" \
            -out    "${CERT_DIR}/cert.crt" \
            -days 36500 -subj "/CN=${domain}" \
            -addext "subjectAltName=${san}" \
            >> "$LOG_FILE" 2>&1
    else
        # 旧版 openssl 不加 -addext
        openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout "${CERT_DIR}/private.key" \
            -out    "${CERT_DIR}/cert.crt" \
            -days 36500 -subj "/CN=${domain}" \
            >> "$LOG_FILE" 2>&1
    fi

    if [ $? -eq 0 ]; then
        chmod 600 "${CERT_DIR}/private.key"
        success "自签证书生成成功（有效期100年）"
        [ -n "$ipv6_addr" ] && info "SAN IPv6: ${ipv6_addr}"
    else
        error "证书生成失败"; return 1
    fi
}

# ============================================================
#  生成配置文件
# ============================================================
generate_config() {
    local port="$1" password="$2" masquerade_domain="$3" domain="$4"
    step "生成 Hysteria2 配置文件..."
    mkdir -p "$HY2_CONFIG_DIR"

    cat > "${HY2_CONFIG_DIR}/config.yaml" <<EOF
# Hysteria2 配置 — EUserv IPv6-only
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

listen: :${port}

tls:
  cert: ${CERT_DIR}/cert.crt
  key: ${CERT_DIR}/private.key

auth:
  type: password
  password: "${password}"

masquerade:
  type: proxy
  proxy:
    url: https://${masquerade_domain}
    rewriteHost: true

bandwidth:
  up: 100 mbps
  down: 100 mbps

quic:
  initStreamReceiveWindow: 26843545
  maxStreamReceiveWindow: 26843545
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s
  disablePathMTUDiscovery: false

log:
  level: warn
EOF
    success "配置文件已生成: ${HY2_CONFIG_DIR}/config.yaml"
}

# ============================================================
#  创建 systemd 服务
# ============================================================
create_service() {
    step "创建 systemd 服务..."
    cat > "$HY2_SERVICE" <<'EOF'
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

# ============================================================
#  防火墙（ip6tables 优先）
# ============================================================
configure_firewall() {
    local port="$1"
    step "配置防火墙（IPv6 UDP/TCP ${port}）..."

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${port}/udp" >> "$LOG_FILE" 2>&1
        ufw allow "${port}/tcp" >> "$LOG_FILE" 2>&1
        info "UFW 规则已添加"
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/udp" >> "$LOG_FILE" 2>&1
        firewall-cmd --permanent --add-port="${port}/tcp" >> "$LOG_FILE" 2>&1
        firewall-cmd --reload >> "$LOG_FILE" 2>&1
        info "firewalld 规则已添加"
    fi

    if command -v ip6tables &>/dev/null; then
        ip6tables -C INPUT -p udp --dport "${port}" -j ACCEPT 2>/dev/null \
            || ip6tables -I INPUT -p udp --dport "${port}" -j ACCEPT
        ip6tables -C INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null \
            || ip6tables -I INPUT -p tcp --dport "${port}" -j ACCEPT
        mkdir -p /etc/iptables
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        command -v netfilter-persistent &>/dev/null \
            && netfilter-persistent save >> "$LOG_FILE" 2>&1 || true
        info "ip6tables 规则已添加"
    fi

    if command -v iptables &>/dev/null; then
        iptables -C INPUT -p udp --dport "${port}" -j ACCEPT 2>/dev/null \
            || iptables -I INPUT -p udp --dport "${port}" -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null \
            || iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null || true
    fi

    success "防火墙配置完成（端口 ${port} UDP/TCP）"
}

# ============================================================
#  安全读取 node.conf（避免 source 注入风险）
# ============================================================
_read_node_conf() {
    local _conf="${HY2_CONFIG_DIR}/node.conf"
    NODE_PORT=""; NODE_PASSWORD=""; NODE_DOMAIN=""; NODE_MASQUERADE=""
    [ ! -f "$_conf" ] && return 1
    while IFS='=' read -r _key _val; do
        case "$_key" in
            NODE_PORT)         NODE_PORT="$_val" ;;
            NODE_PASSWORD)     NODE_PASSWORD="$_val" ;;
            NODE_DOMAIN)       NODE_DOMAIN="$_val" ;;
            NODE_MASQUERADE)   NODE_MASQUERADE="$_val" ;;
        esac
    done < "$_conf"
    # 兼容旧版 node.conf（v2.0.1 无 NODE_MASQUERADE），回退默认值
    [ -z "$NODE_DOMAIN" ]     && NODE_DOMAIN="bing.com"
    [ -z "$NODE_MASQUERADE" ] && NODE_MASQUERADE="bing.com"
    [ -n "$NODE_PORT" ] && [ -n "$NODE_PASSWORD" ]
}

# ============================================================
#  显示节点信息
# ============================================================
show_node_info() {
    if ! _read_node_conf; then
        warn "未找到节点配置，请先安装 Hysteria2（选项 1）"
        return
    fi

    # 修复：name 从 hostname 实时读取，不用 node.conf 里的固定值
    local node_name
    node_name=$(get_node_name)

    local ipv6_raw ipv6_bracket
    ipv6_raw=$(_get_real_ipv6)
    if [ -z "$ipv6_raw" ]; then
        warn "未检测到真实公网 IPv6 地址"
        return
    fi
    ipv6_bracket="[${ipv6_raw}]"

    local port="${NODE_PORT}"
    local password="${NODE_PASSWORD}"
    local sni="${NODE_DOMAIN:-bing.com}"

    local country full_node name_encoded hy2_link qr_url qrcode_png safe_ipv6 safe_password safe_sni safe_node
    country=$(get_country_code "$ipv6_raw")
    full_node=$(generate_node_name "$country" "$node_name" "EUserv-HY2" "IPv6")
    name_encoded=$(uri_encode "$full_node")
    local hy2_link="hysteria2://${password}@${ipv6_bracket}:${port}/?insecure=1&sni=${sni}#${name_encoded}"
    qr_url=$(generate_online_qrcode_url "$hy2_link")
    safe_ipv6=$(shell_json_escape "$ipv6_raw")
    safe_password=$(shell_json_escape "$password")
    safe_sni=$(shell_json_escape "$sni")
    safe_node=$(shell_json_escape "$full_node")

    echo ""
    echo -e "${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}${BOLD}          Hysteria2 节点信息 (EUserv IPv6)${NC}"
    echo -e "${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "服务器名称: ${CYAN}${node_name}${NC}"
    echo -e "国家/地区: ${CYAN}${country} / $(get_country_name "$country")${NC}"
    echo -e "IPv6 地址 : ${CYAN}${ipv6_raw}${NC}"
    echo -e "端口 Port : ${CYAN}${port}${NC}"
    echo -e "密码 Pass : ${CYAN}${password}${NC}"
    echo -e "伪装 SNI : ${CYAN}${sni}${NC}"
    echo -e "证书验证 : ${RED}Insecure / Skip Cert Verify = true${NC}"
    echo -e "协议传输 : ${CYAN}UDP / QUIC${NC}"
    echo ""
    echo -e "${YELLOW}${BOLD}━━━ IPv6 节点 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}节点名称:${NC}"
    print_copy_block "$full_node"
    echo ""
    echo -e "${CYAN}URI 分享链接:${NC}"
    print_copy_block "$hy2_link"
    echo ""
    echo -e "${CYAN}Throne URI:${NC}"
    print_copy_block "Throne 暂不支持该协议的 URI 导入格式。"
    echo ""
    echo -e "${CYAN}Mihomo / Clash Meta / Clash Verge 单行配置:${NC}"
    print_copy_block "- {name: \"${safe_node}\", type: hysteria2, server: \"${ipv6_raw}\", port: ${port}, password: \"${safe_password}\", sni: \"${safe_sni}\", skip-cert-verify: true, fast-open: true, udp: true}"
    echo ""
    echo -e "${CYAN}Loon 配置:${NC}"
    print_copy_block "${full_node} = Hysteria2, ${ipv6_raw}, ${port}, \"${password}\", skip-cert-verify=true, sni=${sni}"
    echo ""
    echo -e "${CYAN}Surfboard 配置:${NC}"
    print_copy_block "${full_node} = hysteria2, ${ipv6_raw}, ${port}, password=${password}, sni=${sni}, skip-cert-verify=true"
    echo ""
    echo -e "${CYAN}Shadowrocket 配置:${NC}"
    print_copy_block "$hy2_link"
    echo ""
    echo -e "${CYAN}Quantumult X 配置:${NC}"
    print_copy_block "Quantumult X 暂不支持该协议的配置格式。"
    echo ""

    echo -e "${CYAN}二维码:${NC}"
    if generate_terminal_qrcode "$hy2_link"; then
        success "终端二维码已生成"
        qrcode_png=$(generate_local_qrcode_png "$hy2_link" 2>/dev/null || true)
        [ -n "$qrcode_png" ] && echo -e "本地二维码图片: ${CYAN}${qrcode_png}${NC}"
    else
        warn "未安装 qrencode，跳过终端和本地 PNG 二维码"
    fi
    warn "在线二维码会把节点链接提交给第三方服务，不建议公开节点使用。"
    print_copy_block "$qr_url"
    echo ""
    echo -e "${DIM}EUserv 为纯 IPv6 环境，客户端需支持 IPv6 连接${NC}"
    echo -e "${DIM}国内宽带开启 IPv6 / 手机 4G·5G 可直连；无 IPv6 请先装 WARP（选项 8）${NC}"
    echo ""
    echo -e "${CYAN}Sing-box:${NC}"
    cat <<CFG
{
  "log": {
    "level": "debug",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "udp",
        "tag": "dns_proxy",
        "server": "8.8.8.8",
        "detour": "${safe_node}"
      },
      {
        "type": "udp",
        "tag": "dns_direct",
        "server": "223.5.5.5"
      }
    ],
    "strategy": "ipv4_only",
    "final": "dns_proxy"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": [
        "172.19.0.1/30",
        "fdfe:dcba:9876::1/126"
      ],
      "mtu": 1400,
      "auto_route": true,
      "strict_route": true
    }
  ],
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "${safe_node}",
      "server": "${safe_ipv6}",
      "server_port": ${port},
      "password": "${safe_password}",
      "tls": {
        "enabled": true,
        "server_name": "${safe_sni}",
        "insecure": true
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_version": 6,
        "action": "reject"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct"
      },
      {
        "port": [443, 853],
        "network": "udp",
        "action": "reject"
      }
    ],
    "auto_detect_interface": true,
    "default_domain_resolver": "dns_direct",
    "final": "${safe_node}"
  }
}
CFG
    echo ""
    echo "以上为完整 Sing-box / SFA TUN 客户端配置，可保存为 config.json 导入。"
    echo -e "${WHITE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ============================================================
#  主安装流程
# ============================================================
do_install() {
    show_banne
    echo -e "  ${WHITE}${BOLD}安装 Hysteria2（EUserv IPv6-only 专用）${NC}"
    echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
    echo ""

    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    if [ -f "$HY2_BIN" ] && systemctl is-active --quiet hysteria-server 2>/dev/null; then
        warn "Hysteria2 已在运行中"
        echo -ne "  ${YELLOW}是否重新安装？[y/N]:${NC} "
        read -r reinstall
        [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ] && return
        systemctl stop hysteria-server 2>/dev/null
    fi

    init_system || { read -rp "  按 Enter 返回..." _; return; }
    check_network || { read -rp "  按 Enter 返回..." _; return; }

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
        warn "无效端口，使用随机端口"
        PORT=$((RANDOM % 50000 + 10000))
    fi

    # 密码
    echo -ne "  ${CYAN}连接密码${NC} ${DIM}[默认: 随机生成]${NC}: "
    read -r input_pass
    if [ -z "$input_pass" ]; then
        if command -v uuidgen &>/dev/null; then
            PASSWORD=$(uuidgen | tr -d '-')
        else
            PASSWORD=$(openssl rand -hex 16)
        fi
        info "随机密码: ${PASSWORD}"
    else
        PASSWORD="$input_pass"
    fi
    if echo "$PASSWORD" | grep -qE '["\\$`]|[[:cntrl:]]'; then
        error "密码不能包含引号、反斜杠、美元符、反引号或控制字符"
        read -rp "  按 Enter 返回..." _
        return
    fi

    # 伪装域名
    echo -ne "  ${CYAN}伪装域名${NC} ${DIM}[默认: bing.com]${NC}: "
    read -r input_domain
    MASQUERADE_DOMAIN="${input_domain:-bing.com}"
    if ! valid_domain "$MASQUERADE_DOMAIN"; then
        error "伪装域名格式无效，请输入域名或域名:端口，不要包含协议和路径"
        read -rp "  按 Enter 返回..." _
        return
    fi

    # SNI
    echo -ne "  ${CYAN}SNI 域名${NC} ${DIM}[默认: bing.com]${NC}: "
    read -r input_sni
    NODE_DOMAIN="${input_sni:-bing.com}"
    if ! valid_domain "$NODE_DOMAIN" || echo "$NODE_DOMAIN" | grep -q ':'; then
        error "SNI 格式无效，请输入纯域名"
        read -rp "  按 Enter 返回..." _
        return
    fi

    echo ""
    echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
    echo -e "  端口: ${WHITE}${PORT}${NC}  密码: ${WHITE}${PASSWORD}${NC}"
    echo -e "  伪装: ${WHITE}${MASQUERADE_DOMAIN}${NC}  SNI: ${WHITE}${NODE_DOMAIN}${NC}"
    echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
    echo ""

    get_latest_version
    install_hysteria2_binary || { restore_dns; read -rp "  按 Enter 返回..." _; return; }
    restore_dns  # 安装完立即恢复DNS（如果改过）

    generate_self_signed_cert "$NODE_DOMAIN" || { read -rp "  按 Enter 返回..." _; return; }
    generate_config "$PORT" "$PASSWORD" "$MASQUERADE_DOMAIN" "$NODE_DOMAIN"
    create_service
    configure_firewall "$PORT"

    # 保存节点配置（使用 printf 避免注入）
    {
        printf 'NODE_PORT=%s\n' "$PORT"
        printf 'NODE_PASSWORD=%s\n' "$PASSWORD"
        printf 'NODE_DOMAIN=%s\n' "$NODE_DOMAIN"
        printf 'NODE_MASQUERADE=%s\n' "$MASQUERADE_DOMAIN"
        printf 'INSTALL_DATE=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    } > "${HY2_CONFIG_DIR}/node.conf"

    step "启动 Hysteria2 服务..."
    systemctl start hysteria-server
    sleep 2

    if systemctl is-active --quiet hysteria-server; then
        success "Hysteria2 服务启动成功！"
    else
        error "服务启动失败，日志如下:"
        journalctl -u hysteria-server -n 20 --no-pager
        read -rp "  按 Enter 返回..." _
        return
    fi

    show_node_info
    read -rp "  按 Enter 返回主菜单..." _
}

# ============================================================
#  卸载
# ============================================================
do_uninstall() {
    show_banne
    echo -e "  ${RED}${BOLD}卸载 Hysteria2${NC}"
    echo ""
    echo -ne "  ${YELLOW}确认卸载？将删除所有配置文件 [y/N]:${NC} "
    read -r confirm
    [ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && { info "已取消"; read -rp "  按 Enter 返回..." _; return; }

    systemctl stop hysteria-server 2>/dev/null
    systemctl disable hysteria-server 2>/dev/null
    rm -f "$HY2_SERVICE" "$HY2_BIN"
    rm -rf "$HY2_CONFIG_DIR"
    rm -f /etc/sysctl.d/99-hy2.conf /etc/sysctl.d/99-euserv-bbr.conf
    systemctl daemon-reload
    success "Hysteria2 已完全卸载"
    read -rp "  按 Enter 返回..." _
}

# ============================================================
#  修改配置
# ============================================================
modify_config() {
    show_banne
    echo -e "  ${WHITE}${BOLD}修改配置${NC}"
    echo ""

    if ! _read_node_conf; then
        error "未找到节点配置，请先安装（选项 1）"
        read -rp "  按 Enter 返回..." _; return
    fi

    local config_backup node_backup
    config_backup=$(mktemp /tmp/euserv-hy2-config-XXXXXX 2>/dev/null) || {
        error "无法创建配置备份"
        read -rp "  按 Enter 返回..." _
        return
    }
    node_backup=$(mktemp /tmp/euserv-hy2-node-XXXXXX 2>/dev/null) || {
        rm -f "$config_backup"
        error "无法创建节点配置备份"
        read -rp "  按 Enter 返回..." _
        return
    }
    cp "${HY2_CONFIG_DIR}/config.yaml" "$config_backup"
    cp "${HY2_CONFIG_DIR}/node.conf" "$node_backup"

    echo -e "  当前端口: ${CYAN}${NODE_PORT}${NC}"
    echo -ne "  新端口 ${DIM}[留空保持]${NC}: "
    read -r new_port
    if [ -n "$new_port" ]; then
        if ! echo "$new_port" | grep -qE '^[0-9]+$' || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
            error "端口必须为 1-65535 的整数"
            rm -f "$config_backup" "$node_backup"
            read -rp "  按 Enter 返回..." _
            return
        fi
        NODE_PORT="$new_port"
    fi

    echo -e "  当前密码: ${CYAN}${NODE_PASSWORD}${NC}"
    echo -ne "  新密码 ${DIM}[留空保持]${NC}: "
    read -r new_pass
    if [ -n "$new_pass" ]; then
        if echo "$new_pass" | grep -qE '["\\$`]|[[:cntrl:]]'; then
            error "密码不能包含引号、反斜杠、美元符、反引号或控制字符"
            rm -f "$config_backup" "$node_backup"
            read -rp "  按 Enter 返回..." _
            return
        fi
        NODE_PASSWORD="$new_pass"
    fi

    echo -e "  当前伪装域名: ${CYAN}${NODE_MASQUERADE}${NC}"
    echo -ne "  新伪装域名 ${DIM}[留空保持]${NC}: "
    read -r new_masq
    if [ -n "$new_masq" ]; then
        if ! valid_domain "$new_masq"; then
            error "伪装域名格式无效"
            rm -f "$config_backup" "$node_backup"
            read -rp "  按 Enter 返回..." _
            return
        fi
        NODE_MASQUERADE="$new_masq"
    fi

    echo -e "  当前 SNI: ${CYAN}${NODE_DOMAIN}${NC}"
    echo -ne "  新 SNI ${DIM}[留空保持]${NC}: "
    read -r new_sni
    if [ -n "$new_sni" ]; then
        if ! valid_domain "$new_sni" || echo "$new_sni" | grep -q ':'; then
            error "SNI 格式无效，请输入纯域名"
            rm -f "$config_backup" "$node_backup"
            read -rp "  按 Enter 返回..." _
            return
        fi
        NODE_DOMAIN="$new_sni"
    fi

    generate_config "$NODE_PORT" "$NODE_PASSWORD" "$NODE_MASQUERADE" "$NODE_DOMAIN"

    local prev_date
    prev_date=$(grep "INSTALL_DATE" "${HY2_CONFIG_DIR}/node.conf" | cut -d= -f2-)
    {
        printf 'NODE_PORT=%s\n' "$NODE_PORT"
        printf 'NODE_PASSWORD=%s\n' "$NODE_PASSWORD"
        printf 'NODE_DOMAIN=%s\n' "$NODE_DOMAIN"
        printf 'NODE_MASQUERADE=%s\n' "$NODE_MASQUERADE"
        printf 'INSTALL_DATE=%s\n' "${prev_date}"
        printf 'MODIFY_DATE=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    } > "${HY2_CONFIG_DIR}/node.conf"

    configure_firewall "$NODE_PORT"
    systemctl restart hysteria-server
    sleep 1

    if systemctl is-active --quiet hysteria-server; then
        rm -f "$config_backup" "$node_backup"
        success "配置已更新，服务已重启"
    else
        cp "$config_backup" "${HY2_CONFIG_DIR}/config.yaml"
        cp "$node_backup" "${HY2_CONFIG_DIR}/node.conf"
        systemctl restart hysteria-server 2>/dev/null || true
        rm -f "$config_backup" "$node_backup"
        error "服务重启失败，配置已回滚；请查看日志（选项 6）"
    fi

    show_node_info
    read -rp "  按 Enter 返回..." _
}

# ============================================================
#  升级
# ============================================================
do_upgrade() {
    show_banne
    echo -e "  ${WHITE}${BOLD}升级 Hysteria2${NC}"
    echo ""

    if [ ! -f "$HY2_BIN" ]; then
        error "未检测到 Hysteria2，请先安装（选项 1）"
        read -rp "  按 Enter 返回..." _; return
    fi

    local cur_ve
    cur_ver=$("$HY2_BIN" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    info "当前版本: ${cur_ver:-未知}"

    get_latest_version
    local new_ver="${HY2_VERSION#app/}"
    info "最新版本: ${new_ver}"

    if [ "$cur_ver" = "$new_ver" ]; then
        success "已是最新版本，无需升级"
        read -rp "  按 Enter 返回..." _; return
    fi

    echo ""
    echo -ne "  ${YELLOW}确认升级 ${cur_ver} → ${new_ver}？[y/N]:${NC} "
    read -r confirm
    [ "$confirm" != "y" ] && [ "$confirm" != "Y" ] && { info "已取消"; read -rp "  按 Enter 返回..." _; return; }

    # 设置中断保护：Ctrl+C 或异常退出时自动恢复服务
    __upgrade_recover() {
        warn "升级被中断，正在自动恢复..."
        restore_dns
        if [ -s "${HY2_BIN}.bak" ] && [ ! -s "$HY2_BIN" ]; then
            mv "${HY2_BIN}.bak" "$HY2_BIN" 2>/dev/null
        fi
        systemctl start hysteria-server 2>/dev/null || true
        warn "已尝试恢复旧版本服务，请检查状态"
    }
    trap __upgrade_recover EXIT INT TERM

    systemctl stop hysteria-server 2>/dev/null
    cp "$HY2_BIN" "${HY2_BIN}.bak" 2>/dev/null
    info "旧版本已备份至 ${HY2_BIN}.bak"

    if install_hysteria2_binary; then
        restore_dns
        trap __upgrade_recover EXIT INT TERM  # re-set: restore_dns 内部会清除 trap
        systemctl start hysteria-server; sleep 1
        if systemctl is-active --quiet hysteria-server; then
            local updated_ve
            updated_ver=$("$HY2_BIN" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            success "升级成功！当前版本: ${updated_ver}"
            rm -f "${HY2_BIN}.bak"
        else
            error "升级后服务启动失败，回滚中..."
            mv "${HY2_BIN}.bak" "$HY2_BIN"
            systemctl start hysteria-server
            warn "已回滚至旧版本 ${cur_ver}"
        fi
    else
        restore_dns
        trap __upgrade_recover EXIT INT TERM  # re-set: restore_dns 内部会清除 trap
        error "下载失败，回滚中..."
        mv "${HY2_BIN}.bak" "$HY2_BIN"
        systemctl start hysteria-server
        warn "已回滚至旧版本 ${cur_ver}"
    fi

    # 升级完成（成功或已回滚），清除中断保护
    trap - EXIT INT TERM

    echo ""
    read -rp "  按 Enter 返回..." _
}

# ============================================================
#  服务管理
# ============================================================
manage_service() {
    show_banne
    echo -e "  ${WHITE}${BOLD}服务管理${NC}"
    echo ""
    # 显示当前状态
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        echo -e "  当前状态: ${GREEN}● 运行中${NC}"
    else
        echo -e "  当前状态: ${RED}● 未运行${NC}"
    fi
    echo ""
    echo -e "  ${GREEN}1.${NC} 启动"
    echo -e "  ${GREEN}2.${NC} 停止"
    echo -e "  ${GREEN}3.${NC} 重启"
    echo -e "  ${GREEN}4.${NC} 查看详细状态"
    echo -e "  ${GREEN}0.${NC} 返回"
    echo ""
    echo -ne "  ${WHITE}选项:${NC} "
    read -r opt
    case "$opt" in
        1) systemctl start hysteria-server   && success "已启动" || error "启动失败" ;;
        2) systemctl stop hysteria-server    && success "已停止" || error "停止失败" ;;
        3) systemctl restart hysteria-server && success "已重启" || error "重启失败" ;;
        4) systemctl status hysteria-server --no-pager ;;
        0) return ;;
        *) warn "无效选项" ;;
    esac
    echo ""
    read -rp "  按 Enter 返回..." _
}

# ============================================================
#  查看日志
# ============================================================
show_logs() {
    show_banne
    echo -e "  ${WHITE}${BOLD}Hysteria2 运行日志（最近 50 行）${NC}"
    echo ""
    journalctl -u hysteria-server -n 50 --no-pager
    echo ""
    read -rp "  按 Enter 返回..." _
}

# ============================================================
#  WARP（F大 fscarmen 脚本）
#  修复：执行完后立即重新检测WARP状态并输出，不依赖菜单刷新
# ============================================================
run_warp_script() {
    while true; do
        show_banne
        echo -e "  ${MAGENTA}${BOLD}WARP（F大 fscarmen/warp 脚本）${NC}"
        echo -e "  ${DIM}为 EUserv IPv6-only VPS 添加 IPv4 出口${NC}"
        echo ""

        # 修复：进入WARP菜单也实时显示当前状态
        if [ "$(check_warp_status)" = "installed" ]; then
            echo -e "  WARP 状态: ${GREEN}● 已安装${NC}"
        else
            echo -e "  WARP 状态: ${RED}● 未安装${NC}"
        fi
        echo ""

        echo -e "  ${WHITE}${BOLD}━━━ 选择安装模式 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${GREEN}1.${NC} 交互式菜单（推荐，自行选择模式）"
        echo -e "  ${GREEN}2.${NC} 直接安装 WireGuard 双栈（IPv4+IPv6）"
        echo -e "  ${GREEN}3.${NC} ${YELLOW}直接安装 IPv4 单栈（EUserv 首选，补全 IPv4）${NC}"
        echo -e "  ${GREEN}4.${NC} 直接安装 SOCKS5 代理模式（127.0.0.1:40000）"
        echo -e "  ${GREEN}0.${NC} 返回主菜单"
        echo ""
        echo -ne "  ${WHITE}选项 [0-4]:${NC} "
        read -r warp_opt

        [ "$warp_opt" = "0" ] && return

        # 修复：用 mktemp 避免 /tmp/menu.sh 冲突；wget失败给出明确提示
        local warp_script
        warp_script=$(mktemp /tmp/warp_XXXXXX.sh)
        info "下载 fscarmen WARP 脚本..."
        if ! wget -q --timeout=30 \
            "https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh" \
            -O "$warp_script" 2>>"$LOG_FILE"; then
            rm -f "$warp_script"
            error "WARP 脚本下载失败（GitLab 是否可达？）"
            read -rp "  按 Enter 返回..." _
            continue
        fi
        chmod +x "$warp_script"

        echo ""
        case "$warp_opt" in
            1) bash "$warp_script" ;;
            2) bash "$warp_script" -d ;;
            3) bash "$warp_script" -4 ;;
            4) bash "$warp_script" -s5 ;;
            *) warn "无效选项"; rm -f "$warp_script"; continue ;;
        esac
        rm -f "$warp_script"

        echo ""
        # 操作完成后等待 WARP 接口初始化（最多重试 3 次）
        local _warp_ok=0 _warp_tries=0
        while [ $_warp_tries -lt 3 ]; do
            sleep 3
            if [ "$(check_warp_status)" = "installed" ]; then
                success "WARP 已成功安装并运行 ✓"
                info "验证 IPv4 出口: curl -4 ip.sb"
                _warp_ok=1
                break
            fi
            _warp_tries=$((_warp_tries + 1))
        done
        [ $_warp_ok -eq 0 ] && warn "WARP 网卡未检测到（已等待 $((_warp_tries * 3)) 秒），请稍后重新检查"
        echo ""
        read -rp "  按 Enter 继续..." _
    done
}

# ============================================================
#  系统工具
# ============================================================
system_tools() {
    while true; do
        show_banne
        echo -e "  ${WHITE}${BOLD}系统工具${NC}"
        echo ""

        local cc_algo qdisc bbr_status
        cc_algo=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
        qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
        if [ "$cc_algo" = "bbr" ]; then
            bbr_status="${GREEN}● 已启用 (${cc_algo} + ${qdisc})${NC}"
        else
            bbr_status="${YELLOW}● 未启用 (当前: ${cc_algo})${NC}"
        fi

        echo -e "  ${DIM}┌─────────────────────────────────────────────┐${NC}"
        echo -e "  ${DIM}│${NC}  BBR 状态:  $(echo -e "$bbr_status")"
        echo -e "  ${DIM}│${NC}  内核版本:  ${CYAN}$(uname -r)${NC}"
        echo -e "  ${DIM}│${NC}  系统负载:  ${CYAN}$(uptime | grep -oE 'load average:.*')${NC}"
        echo -e "  ${DIM}│${NC}  内存使用:  ${CYAN}$(free -h | awk '/Mem/{print $3"/"$2}')${NC}"
        echo -e "  ${DIM}│${NC}  磁盘使用:  ${CYAN}$(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')${NC}"
        echo -e "  ${DIM}└─────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  ${WHITE}${BOLD}━━━ BBR ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${GREEN}1.${NC} 开启 BBR + fq"
        echo -e "  ${GREEN}2.${NC} 查看当前拥塞控制算法"
        echo ""
        echo -e "  ${WHITE}${BOLD}━━━ 系统信息 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${GREEN}3.${NC} 查看详细系统信息"
        echo -e "  ${GREEN}4.${NC} 网络连通性测试（IPv4 / IPv6）"
        echo -e "  ${GREEN}5.${NC} 查看端口占用"
        echo ""
        echo -e "  ${YELLOW}0.${NC} 返回主菜单"
        echo ""
        echo -ne "  ${WHITE}选项 [0-5]:${NC} "
        read -r opt

        case "$opt" in
            1)
                step "开启 BBR + fq..."
                local _sysctl_conf="/etc/sysctl.d/99-euserv-bbr.conf"
                mkdir -p /etc/sysctl.d
                modprobe tcp_bbr 2>/dev/null || true
                cat > "$_sysctl_conf" <<EOF
# EUserv Hysteria2 脚本写入 - BBR 优化
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bb
EOF
                sysctl -p "$_sysctl_conf" >> "$LOG_FILE" 2>&1
                local r; r=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
                if [ "$r" = "bbr" ]; then
                    success "BBR 已开启！配置写入 ${_sysctl_conf}，重启后持续生效"
                else
                    warn "BBR 可能未生效，内核可能不支持（OpenVZ 容器等）"
                fi
                echo ""; read -rp "  按 Enter 继续..." _
                ;;
            2)
                echo ""
                echo -e "  ${CYAN}拥塞算法:${NC} $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')"
                echo -e "  ${CYAN}队列算法:${NC} $(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')"
                echo -e "  ${CYAN}可用列表:${NC} $(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | cut -d= -f2)"
                echo ""; read -rp "  按 Enter 继续..." _
                ;;
            3)
                echo ""
                echo -e "  ${WHITE}${BOLD}━━━ 系统详情 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "  ${CYAN}主机名:${NC}   $(hostname)"
                echo -e "  ${CYAN}系统:${NC}     $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"')"
                echo -e "  ${CYAN}内核:${NC}     $(uname -r)"
                echo -e "  ${CYAN}架构:${NC}     $(uname -m)"
                echo -e "  ${CYAN}运行时间:${NC} $(uptime -p 2>/dev/null || uptime)"
                echo -e "  ${CYAN}CPU:${NC}      $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs) ($(nproc)核)"
                echo -e "  ${CYAN}内存:${NC}     $(free -h | awk '/Mem/{print $2" 总 / "$3" 已用 / "$4" 空闲"}')"
                echo -e "  ${CYAN}磁盘:${NC}     $(df -h / | awk 'NR==2{print $2" 总 / "$3" 已用 / "$4" 空闲 ("$5")"}')"
                echo -e "  ${CYAN}IPv6:${NC}     $(_get_real_ipv6)"
                echo ""; read -rp "  按 Enter 继续..." _
                ;;
            4)
                echo ""
                echo -e "  ${WHITE}${BOLD}━━━ 网络连通性测试 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -ne "  IPv4 (ip.sb):    "
                curl -4 -s --max-time 5 ip.sb 2>/dev/null && echo "" || echo -e "${RED}不通${NC}"
                echo -ne "  IPv6 (ip.sb):    "
                curl -6 -s --max-time 5 ip.sb 2>/dev/null && echo "" || echo -e "${RED}不通${NC}"
                echo -ne "  Google IPv6:     "
                curl -6 -s --max-time 5 https://ipv6.google.com -o /dev/null \
                    && echo -e "${GREEN}通${NC}" || echo -e "${RED}不通${NC}"
                echo -ne "  GitHub:          "
                curl -s --max-time 8 https://github.com -o /dev/null \
                    && echo -e "${GREEN}通${NC}" || echo -e "${RED}不通${NC}"
                echo ""; read -rp "  按 Enter 继续..." _
                ;;
            5)
                echo ""
                echo -e "  ${WHITE}${BOLD}━━━ 端口占用 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                ss -tulnp 2>/dev/null | head -25 || netstat -tulnp 2>/dev/null | head -25
                echo ""; read -rp "  按 Enter 继续..." _
                ;;
            0) return ;;
            *) warn "无效选项"; sleep 1 ;;
        esac
    done
}

# ============================================================
#  主入口
# ============================================================
main() {
    [ "$EUID" -ne 0 ] && { echo -e "${RED}[ERROR]${NC} 请以 root 运行: sudo bash $0"; exit 1; }

    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"

    if [[ "$(uname -r)" == *"OpenVZ"* ]] || [ -f /proc/vz/version ]; then
        warn "检测到 OpenVZ 容器环境，UDP 可能受限"
    fi

    while true; do
        show_menu
        read -r choice

        choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')
        case "$choice" in
            1) do_install ;;
            2) show_banner; show_node_info; read -rp "  按 Enter 返回..." _ ;;
            3) modify_config ;;
            4) do_upgrade ;;
            5) manage_service ;;
            6) show_logs ;;
            7) do_uninstall ;;
            8) run_warp_script ;;
            9) system_tools ;;
            0|q|quit|exit)
                echo ""
                echo -e "  ${DIM}感谢使用 EUserv Hysteria2 脚本${NC}"
                echo ""
                exit 0
                ;;
            *) warn "无效选项: ${choice}"; sleep 1 ;;
        esac
    done
}

if [ "${EXPORT_LIB_ONLY:-0}" != "1" ]; then
    main "$@"
fi
