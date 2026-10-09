#!/bin/bash
#====================================================================================
# 项目：Landing Relay Management Script（线路机 + 落地机 / 家宽机）
# 作者：everettlabs
# 版本：v2.0.45
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-10-10
#
# 支持系统: Debian / Ubuntu / CentOS / Rocky / Alma / Fedora / Arch / Alpine
# 支持环境: KVM / 独立服务器 / OpenVZ / LXC（用户态 WireGuard，不依赖内核模块）
# 实现方式: 线路机 = sing-box VLESS REALITY 入站 + WireGuard endpoint 出站
#           落地机 = sing-box WireGuard endpoint 入站 + direct 出站
#           落地机无需 ip_forward / iptables NAT，也不修改任何一端的系统路由
#====================================================================================

# ============================================================
# 自举：确保以 bash 运行
# ============================================================
if [ -z "$BASH_VERSION" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache bash >/dev/null 2>&1
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y -qq bash >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash >/dev/null 2>&1
        fi
        command -v bash >/dev/null 2>&1 || { echo "错误: 无法安装 bash，请手动安装后重试"; exit 1; }
        exec bash "$0" "$@"
    fi
fi

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"

# 线路机经 SSH 在落地机上执行 --remote-* 动作时没有控制终端，
# 此时 exec < /dev/tty 会失败，必须跳过 TTY 修复。
case "${1:-}" in
    --remote-*|--upgrade-noninteractive) LANDING_HEADLESS=1 ;;
    *) LANDING_HEADLESS=0 ;;
esac

[ "${LANDING_LIB_ONLY:-0}" != "1" ] && [ "$LANDING_HEADLESS" = "0" ] && [ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty

if [ -f "$SCRIPT_PATH" ] && grep -q $'\r' "$SCRIPT_PATH" 2>/dev/null; then
    sed -i 's/\r$//' "$SCRIPT_PATH"
    exec bash "$SCRIPT_PATH" "$@"
fi

# ============================================================
# LANDING_LIB_ONLY=1：仅加载函数库，不执行任何副作用（供测试 source）
# ============================================================
[ "${LANDING_LIB_ONLY:-0}" = "1" ] && _LANDING_LIB_ONLY=1 || _LANDING_LIB_ONLY=0

# --- 颜色 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

clear_screen() {
    [ -t 1 ] || return 0
    command -v clear >/dev/null 2>&1 && clear 2>/dev/null && return 0
    printf '\033[2J\033[H'
}

disk_tmp_dir() {
    if [ -d /var/tmp ] && [ -w /var/tmp ]; then
        printf '%s' /var/tmp
    else
        printf '%s' "${TMPDIR:-/tmp}"
    fi
}

# --- 路径 ---
LANDING_BIN="${LANDING_BIN:-/usr/local/bin/landing-server}"
SING_BOX_BIN="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
LANDING_DIR="${LANDING_DIR:-/etc/sing-box}"
LANDING_CONFIG="${LANDING_CONFIG:-${LANDING_DIR}/landing.json}"
LANDING_META="${LANDING_META:-${LANDING_DIR}/landing-meta}"
LANDING_PENDING_DIR="${LANDING_PENDING_DIR:-${LANDING_DIR}/landing-pending}"
SING_BOX_MANAGED_MARKER="${SING_BOX_MANAGED_MARKER:-${LANDING_DIR}/.singbox-tools-managed}"
SYSTEMD_SERVICE="${SYSTEMD_SERVICE:-/etc/systemd/system/landing-server.service}"
OPENRC_SERVICE="${OPENRC_SERVICE:-/etc/init.d/landing-server}"
AUTO_UPDATE_SCRIPT="${AUTO_UPDATE_SCRIPT:-/usr/local/bin/landing-autoupdate.sh}"
AUTO_UPDATE_LOG="${AUTO_UPDATE_LOG:-/var/log/landing-autoupdate.log}"
BBR_SYSCTL_CONF="${BBR_SYSCTL_CONF:-/etc/sysctl.d/99-singbox-tools-bbr.conf}"
LANDING_SCRIPT_URL="${LANDING_SCRIPT_URL:-https://raw.githubusercontent.com/everett7623/hy2/main/landing.sh}"

# --- 隧道参数 ---
# 两端都使用 sing-box 用户态网络栈，这些地址只存在于各自进程内部，
# 不会创建系统网卡，因此不会与 Docker、已有 VPN 或局域网网段冲突。
WG_EXIT_ADDR4="10.233.0.1/32"
WG_EXIT_ADDR6="fdcc:233::1/128"
WG_RELAY_ADDR4="10.233.0.2/32"
WG_RELAY_ADDR6="fdcc:233::2/128"
WG_EXIT_DNS="10.233.0.1"
WG_MTU=1380
WG_KEEPALIVE=25

# --- 运行时变量 ---
RELEASE="unknown"
INIT_SYS="none"
ROLE=""
NAT_MODE=0
IPV4_UNVERIFIED=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
DEFAULT_EGRESS_IPV4=""
WARP_ACTIVE=0
BIND_INTERFACE=""
BIND_FAMILY="v4"
LISTEN_HOST="::"
LISTEN_PORT=""
EXT_PORT=""
UUID=""
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
SHORT_ID=""
SERVER_NAME="www.example.com"
HANDSHAKE_PORT="443"
WG_PRIVATE_KEY=""
WG_PUBLIC_KEY=""
WG_PEER_PUBLIC_KEY=""
WG_PSK=""
WG_PORT=""
EXIT_HOST=""
EXIT_IPV4=""
EXIT_HAS_IPV6=0
SSH_PORT="22"
SSH_USER="root"
PROBE_PORT=""
PROBE_USER=""
PROBE_PASS=""
AUTO_UPDATE=0
MANAGED_SING_BOX=0
CONFIG_SCHEMA=0
LANDING_CONFIG_SCHEMA=1
LAST_VERSION_TAG=""
LAST_EGRESS_IP=""
SING_BOX_STABLE_FALLBACK_TAG="${SING_BOX_STABLE_FALLBACK_TAG:-v1.13.14}"
INSTALL_BACKUP_DIR=""
INSTALL_ROLLBACK_ARMED=0
INSTALL_PREV_INT_TRAP=""
INSTALL_PREV_TERM_TRAP=""
UPGRADE_LOCK_FILE="${UPGRADE_LOCK_FILE:-/var/lock/sing-box-tools-upgrade.lock}"
UPGRADE_LOCK_MODE=""
SSH_CTL_DIR=""
SSH_OPTS=()
REMOTE_STAGE_DIR=""
REMOTE_RESULT=""
LANDING_SCRIPT_SOURCE=""
LANDING_SCRIPT_TMP=""
LANDING_REMOTE_COMMITTABLE=0
REMOTE_PARAM_PUBLIC_KEY=""
REMOTE_PARAM_PSK=""
REMOTE_PARAM_AUTO_UPDATE=1
REMOTE_PARAM_WG_PORT=""
REQUESTED_WG_PORT=""


# ============================================================
# 基础检测
# ============================================================
check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}错误: 请以 root 权限运行${PLAIN}" && exit 1
}

check_sys() {
    if [ -f /etc/alpine-release ]; then
        RELEASE="alpine"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|linuxmint|kali) RELEASE="debian" ;;
            centos|rhel)                  RELEASE="centos" ;;
            fedora)                       RELEASE="fedora" ;;
            rocky|almalinux|ol)           RELEASE="rocky"  ;;
            arch|manjaro|endeavouros)     RELEASE="arch"   ;;
            *)
                case "${ID_LIKE:-}" in
                    *rhel*|*centos*|*fedora*) RELEASE="rocky"  ;;
                    *debian*|*ubuntu*)        RELEASE="debian" ;;
                    *)                        RELEASE="unknown" ;;
                esac
                ;;
        esac
    else
        RELEASE="unknown"
    fi
}

detect_init() {
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        INIT_SYS="systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        INIT_SYS="openrc"
    else
        INIT_SYS="none"
    fi
}

retry_command() {
    local _attempt=1 _max=3 _delay=2
    while [ "$_attempt" -le "$_max" ]; do
        "$@" && return 0
        [ "$_attempt" -ge "$_max" ] && break
        echo -e "${YELLOW}命令执行失败或包管理器被占用，${_delay} 秒后重试 (${_attempt}/${_max})...${PLAIN}" >&2
        sleep "$_delay"
        _attempt=$((_attempt + 1)); _delay=$((_delay * 2))
    done
    return 1
}

install_dependencies() {
    local _cmd _ready=1
    for _cmd in curl tar openssl ip ss; do
        command -v "$_cmd" >/dev/null 2>&1 || _ready=0
    done
    if [ "$_ready" = "1" ]; then
        echo -e "${GREEN}✓ 核心依赖已就绪，跳过软件源刷新${PLAIN}"
        return 0
    fi

    echo -e "${YELLOW}正在补齐必要依赖...${PLAIN}"
    case "$RELEASE" in
        alpine)
            retry_command apk update -q >/dev/null 2>&1
            retry_command apk add --no-cache bash curl wget ca-certificates tar openssl iproute2 procps >/dev/null 2>&1
            apk add --no-cache libqrencode >/dev/null 2>&1 || true
            ;;
        centos)
            retry_command yum install -y curl wget ca-certificates tar openssl iproute procps-ng >/dev/null 2>&1
            yum install -y qrencode >/dev/null 2>&1 || true
            ;;
        fedora|rocky)
            retry_command dnf install -y curl wget ca-certificates tar openssl iproute procps-ng >/dev/null 2>&1
            dnf install -y qrencode >/dev/null 2>&1 || true
            ;;
        arch)
            retry_command pacman -Sy --noconfirm curl wget ca-certificates tar openssl iproute2 procps-ng >/dev/null 2>&1
            pacman -S --noconfirm qrencode >/dev/null 2>&1 || true
            ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                retry_command apt-get update -qq >/dev/null 2>&1
                retry_command apt-get install -y -qq curl wget ca-certificates tar openssl iproute2 procps >/dev/null 2>&1
                apt-get install -y qrencode >/dev/null 2>&1 || true
            else
                echo -e "${RED}无法识别包管理器，请手动安装 curl wget tar openssl iproute2${PLAIN}"
                return 1
            fi
            ;;
    esac

    local _missing=0
    for _cmd in curl tar openssl ip ss; do
        if ! command -v "$_cmd" >/dev/null 2>&1; then
            echo -e "${RED}致命错误: 缺少组件 [ $_cmd ]，请手动安装后重试${PLAIN}"
            _missing=1
        fi
    done
    [ "$_missing" -eq 1 ] && return 1
    return 0
}

# 一键对接依赖 OpenSSH 的连接复用（ControlMaster），dropbear 等客户端不支持。
ensure_ssh_client() {
    if command -v ssh >/dev/null 2>&1 && ssh -V 2>&1 | grep -qi openssh; then
        return 0
    fi
    echo -e "${YELLOW}正在安装 OpenSSH 客户端...${PLAIN}"
    case "$RELEASE" in
        alpine) retry_command apk add --no-cache openssh-client >/dev/null 2>&1 ;;
        centos) retry_command yum install -y openssh-clients >/dev/null 2>&1 ;;
        fedora|rocky) retry_command dnf install -y openssh-clients >/dev/null 2>&1 ;;
        arch) retry_command pacman -Sy --noconfirm openssh >/dev/null 2>&1 ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                retry_command apt-get update -qq >/dev/null 2>&1
                retry_command apt-get install -y -qq openssh-client >/dev/null 2>&1
            fi
            ;;
    esac
    if command -v ssh >/dev/null 2>&1 && ssh -V 2>&1 | grep -qi openssh; then
        return 0
    fi
    echo -e "${RED}无法安装 OpenSSH 客户端，请手动安装 openssh-client 后重试${PLAIN}"
    return 1
}

# ============================================================
# 输入校验
# ============================================================
validate_port() {
    local port="$1"
    [ -z "$port" ] && return 1
    case "$port" in
        *[!0-9]*) return 1 ;;
    esac
    case "$port" in
        0*) return 1 ;;
    esac
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

port_is_listening() {
    local _port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -lntu 2>/dev/null | awk -v port="$_port" '
            NR > 1 { for (i=4; i<=NF; i++) if ($i ~ (":" port "$")) found=1 }
            END { exit(found ? 0 : 1) }
        '
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lntu 2>/dev/null | awk -v port="$_port" '
            NR > 1 { for (i=4; i<=NF; i++) if ($i ~ (":" port "$")) found=1 }
            END { exit(found ? 0 : 1) }
        '
    else
        return 1
    fi
}

tcp_port_is_listening() {
    local _port="$1"
    command -v ss >/dev/null 2>&1 || return 1
    ss -lnt 2>/dev/null | awk -v port="$_port" '
        NR > 1 { for (i=4; i<=NF; i++) if ($i ~ (":" port "$")) found=1 }
        END { exit(found ? 0 : 1) }
    '
}

udp_port_is_listening() {
    local _port="$1"
    command -v ss >/dev/null 2>&1 || return 1
    ss -lnu 2>/dev/null | awk -v port="$_port" '
        NR > 1 { for (i=4; i<=NF; i++) if ($i ~ (":" port "$")) found=1 }
        END { exit(found ? 0 : 1) }
    '
}

generate_random_port() {
    local _attempt=0 _number _port
    while [ "$_attempt" -lt 32 ]; do
        _number=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
        [ -n "$_number" ] || _number=$(($(date +%s) + $$ + _attempt))
        _port=$((10000 + (_number % 55536)))
        if ! port_is_listening "$_port"; then
            printf '%s' "$_port"
            return 0
        fi
        _attempt=$((_attempt + 1))
    done
    return 1
}

validate_uuid() {
    printf '%s\n' "$1" | grep -qE '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
}

validate_reality_key() {
    printf '%s\n' "$1" | grep -qE '^[A-Za-z0-9_-]{43}$'
}

# WireGuard 公私钥与 PSK 均为 32 字节标准 base64（44 字符，末尾一个 =）。
validate_wg_key() {
    printf '%s\n' "$1" | grep -qE '^[A-Za-z0-9+/]{43}=$'
}

validate_short_id() {
    local _short_id="$1" _length
    _length="${#_short_id}"
    [ "$_length" -ge 2 ] && [ "$_length" -le 16 ] || return 1
    [ $((_length % 2)) -eq 0 ] || return 1
    printf '%s\n' "$_short_id" | grep -qE '^[0-9A-Fa-f]+$'
}

validate_probe_secret() {
    printf '%s\n' "$1" | grep -qE '^[0-9a-f]{16,64}$'
}

validate_ssh_user() {
    printf '%s\n' "$1" | grep -qE '^[a-z_][a-z0-9_.-]{0,31}$'
}

validate_server_name() {
    local _name="$1"
    [ -n "$_name" ] || return 1
    [ "${#_name}" -le 253 ] || return 1
    printf '%s\n' "$_name" | awk -F. '
        NF < 2 { exit 1 }
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "" || length($i) > 63 || $i !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) exit 1
            }
        }
    '
}

validate_server_address() {
    local _address="$1"
    [ -n "$_address" ] || return 1
    case "$_address" in
        *[!A-Za-z0-9.:_-]*) return 1 ;;
    esac
    return 0
}

# 落地机地址会同时写入 sing-box 配置与 ssh 命令行，只接受 IPv4、IPv6 或域名。
validate_exit_host() {
    local _host="$1"
    [ -n "$_host" ] || return 1
    case "$_host" in
        -*) return 1 ;;
    esac
    is_valid_ipv4 "$_host" && return 0
    is_valid_ipv6 "$_host" && return 0
    validate_server_name "$_host"
}

reality_target_candidates() {
    printf '%s\n' \
        "www.microsoft.com" \
        "www.apple.com" \
        "www.amazon.com" \
        "www.amd.com" \
        "www.mozilla.org" \
        "www.nvidia.com" \
        "www.samsung.com" \
        "www.cloudflare.com"
}

random_sni() {
    local _number
    _number=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
    [ -z "$_number" ] && _number=$(date +%s)
    case $((_number % 8)) in
        0) echo "www.microsoft.com" ;;
        1) echo "www.apple.com" ;;
        2) echo "www.amazon.com" ;;
        3) echo "www.amd.com" ;;
        4) echo "www.mozilla.org" ;;
        5) echo "www.nvidia.com" ;;
        6) echo "www.samsung.com" ;;
        *) echo "www.cloudflare.com" ;;
    esac
}

reality_target_usable_v4() {
    local _host="$1" _port="${2:-443}" _url
    validate_server_name "$_host" && validate_port "$_port" || return 1
    command -v curl >/dev/null 2>&1 || return 1
    _url="https://${_host}:${_port}/"
    if curl --help all 2>/dev/null | grep -q -- '--tls-max'; then
        curl -4 --noproxy '*' -sSI --connect-timeout 5 --max-time 9 \
            --tlsv1.3 --tls-max 1.3 "$_url" >/dev/null 2>&1
    else
        curl -4 --noproxy '*' -sSI --connect-timeout 5 --max-time 9 \
            "$_url" >/dev/null 2>&1
    fi
}

reality_target_usable_v6() {
    local _host="$1" _port="${2:-443}" _url
    validate_server_name "$_host" && validate_port "$_port" || return 1
    command -v curl >/dev/null 2>&1 || return 1
    _url="https://${_host}:${_port}/"
    if curl --help all 2>/dev/null | grep -q -- '--tls-max'; then
        curl -6 --noproxy '*' -sSI --connect-timeout 5 --max-time 9 \
            --tlsv1.3 --tls-max 1.3 "$_url" >/dev/null 2>&1
    else
        curl -6 --noproxy '*' -sSI --connect-timeout 5 --max-time 9 \
            "$_url" >/dev/null 2>&1
    fi
}

reality_domain_strategy() {
    case "${BIND_FAMILY:-v4}" in
        v6) printf '%s' "ipv6_only" ;;
        *)  printf '%s' "ipv4_only" ;;
    esac
}

reality_target_usable_for_family() {
    case "${BIND_FAMILY:-v4}" in
        v6) reality_target_usable_v6 "$@" ;;
        *)  reality_target_usable_v4 "$@" ;;
    esac
}

select_reality_target() {
    local _port="${1:-443}" _preferred _candidate _selected _tmp
    local _index=0 _checked=0
    _preferred=$(random_sni)
    _tmp=$(mktemp -d 2>/dev/null) || return 1
    for _candidate in "$_preferred" $(reality_target_candidates); do
        [ "$_index" -gt 0 ] && [ "$_candidate" = "$_preferred" ] && continue
        (
            reality_target_usable_for_family "$_candidate" "$_port" \
                && printf '%s' "$_candidate" > "$_tmp/result-${_index}"
        ) &
        _index=$((_index + 1))
    done
    wait || true
    while [ "$_checked" -lt "$_index" ]; do
        if [ -s "$_tmp/result-${_checked}" ]; then
            IFS= read -r _selected < "$_tmp/result-${_checked}"
            rm -f "$_tmp"/result-* 2>/dev/null
            rmdir "$_tmp" 2>/dev/null || true
            printf '%s' "$_selected"
            return 0
        fi
        _checked=$((_checked + 1))
    done
    rm -f "$_tmp"/result-* 2>/dev/null
    rmdir "$_tmp" 2>/dev/null || true
    return 1
}

choose_reality_target() {
    local _port="${1:-443}" _choice _candidate
    validate_port "$_port" || return 1
    while true; do
        echo -e "\n${YELLOW}请选择 REALITY 伪装域名（SNI）来源：${PLAIN}"
        echo "  1. 自动选择大厂域名（推荐，自动探测可达性）"
        echo "  2. 手动输入域名"
        read -r -p "请选择 [1-2，默认 1]: " _choice
        case "${_choice:-1}" in
            1)
                echo -e "${YELLOW}正在按 $(reality_domain_strategy) 策略检测可用大厂 SNI...${PLAIN}"
                if _candidate=$(select_reality_target "$_port"); then
                    SERVER_NAME="$_candidate"
                    echo -e "${GREEN}✓ 已找到可用目标: ${SERVER_NAME}:${_port}${PLAIN}"
                    return 0
                fi
                SERVER_NAME=$(random_sni)
                echo -e "${YELLOW}! 未能自动验证候选目标，请确认 VPS 可访问 ${SERVER_NAME}:${_port}${PLAIN}"
                return 0
                ;;
            2)
                while true; do
                    read -r -p "请输入 SNI 域名 [留空返回]: " _candidate
                    [ -z "$_candidate" ] && break
                    if ! validate_server_name "$_candidate"; then
                        echo -e "${RED}域名格式无效，请输入纯域名（不含协议、路径或端口）${PLAIN}"
                        continue
                    fi
                    echo -e "${YELLOW}正在验证 ${_candidate}:${_port} 的 TLS 1.3 与当前地址族可达性...${PLAIN}"
                    if reality_target_usable_for_family "$_candidate" "$_port"; then
                        SERVER_NAME="$_candidate"
                        echo -e "${GREEN}✓ SNI 验证通过: ${SERVER_NAME}:${_port}${PLAIN}"
                        return 0
                    fi
                    echo -e "${RED}验证失败：目标不支持 TLS 1.3，或当前 VPS 无法按 $(reality_domain_strategy) 访问${PLAIN}"
                done
                ;;
            *)
                echo -e "${RED}无效选项，请输入 1 或 2${PLAIN}"
                ;;
        esac
    done
}

# ============================================================
# 密钥 / 随机值生成
# ============================================================
generate_uuid() {
    local _uuid="" _hex
    if [ -x "$SING_BOX_BIN" ]; then
        _uuid=$("$SING_BOX_BIN" generate uuid 2>/dev/null | grep -E '^[0-9A-Fa-f-]{36}$' | head -1)
    fi
    if ! validate_uuid "$_uuid" && [ -r /proc/sys/kernel/random/uuid ]; then
        _uuid=$(tr -d '[:space:]' < /proc/sys/kernel/random/uuid)
    fi
    if ! validate_uuid "$_uuid"; then
        _hex=$(openssl rand -hex 16 2>/dev/null | tr -d '[:space:]')
        [ "${#_hex}" = "32" ] || return 1
        _uuid=$(printf '%s-%s-%s-%s-%s' \
            "$(printf '%s' "$_hex" | cut -c1-8)" \
            "$(printf '%s' "$_hex" | cut -c9-12)" \
            "$(printf '%s' "$_hex" | cut -c13-16)" \
            "$(printf '%s' "$_hex" | cut -c17-20)" \
            "$(printf '%s' "$_hex" | cut -c21-32)")
    fi
    validate_uuid "$_uuid" || return 1
    printf '%s' "$_uuid"
}

generate_reality_keypair() {
    local _output _private _public
    [ -x "$SING_BOX_BIN" ] || return 1
    _output=$("$SING_BOX_BIN" generate reality-keypair 2>/dev/null) || return 1
    _private=$(printf '%s\n' "$_output" | awk -F':[[:space:]]*' 'tolower($1) ~ /private/ { print $2; exit }')
    _public=$(printf '%s\n' "$_output" | awk -F':[[:space:]]*' 'tolower($1) ~ /public/ { print $2; exit }')
    validate_reality_key "$_private" || return 1
    validate_reality_key "$_public" || return 1
    REALITY_PRIVATE_KEY="$_private"
    REALITY_PUBLIC_KEY="$_public"
}

generate_short_id() {
    local _short_id
    _short_id=$(openssl rand -hex 8 2>/dev/null | tr -d '[:space:]')
    if ! validate_short_id "$_short_id"; then
        _short_id=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    fi
    validate_short_id "$_short_id" || return 1
    printf '%s' "$_short_id"
}

generate_wg_keypair() {
    local _output _private _public
    [ -x "$SING_BOX_BIN" ] || return 1
    _output=$("$SING_BOX_BIN" generate wg-keypair 2>/dev/null) || return 1
    _private=$(printf '%s\n' "$_output" | awk -F':[[:space:]]*' 'tolower($1) ~ /private/ { print $2; exit }' | tr -d '[:space:]')
    _public=$(printf '%s\n' "$_output" | awk -F':[[:space:]]*' 'tolower($1) ~ /public/ { print $2; exit }' | tr -d '[:space:]')
    validate_wg_key "$_private" || return 1
    validate_wg_key "$_public" || return 1
    WG_PRIVATE_KEY="$_private"
    WG_PUBLIC_KEY="$_public"
}

generate_wg_psk() {
    local _psk=""
    if [ -x "$SING_BOX_BIN" ]; then
        _psk=$("$SING_BOX_BIN" generate rand --base64 32 2>/dev/null | tr -d '[:space:]')
    fi
    validate_wg_key "$_psk" || _psk=$(openssl rand -base64 32 2>/dev/null | tr -d '[:space:]')
    validate_wg_key "$_psk" || return 1
    printf '%s' "$_psk"
}

generate_probe_secret() {
    local _secret
    _secret=$(openssl rand -hex 16 2>/dev/null | tr -d '[:space:]')
    validate_probe_secret "$_secret" || _secret=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    validate_probe_secret "$_secret" || return 1
    printf '%s' "$_secret"
}

# ============================================================
# 架构 / URL 构建
# ============================================================
detect_arch() {
    local _machine="${1:-$(uname -m)}"
    case "$_machine" in
        x86_64)        echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armv7)  echo "armv7" ;;
        i386|i686)     echo "386" ;;
        s390x)         echo "s390x" ;;
        *)
            echo -e "${RED}不支持的架构: ${_machine}${PLAIN}" >&2
            return 1
            ;;
    esac
}

singbox_asset_name() {
    local _ver="${1#v}" _arch="$2" _suffix=""
    # Alpine 使用官方 musl 静态构建，避免普通包的 libc 运行时依赖。
    if [ "${RELEASE:-unknown}" = "alpine" ] && version_at_least "$_ver" "1.13.0"; then
        case "$_arch" in
            amd64|arm64|armv7|386) _suffix="-musl" ;;
        esac
    fi
    printf 'sing-box-%s-linux-%s%s.tar.gz\n' "$_ver" "$_arch" "$_suffix"
}

validate_singbox_execution() {
    local _bin="$1" _expected="$2" _output _status=0 _actual
    _output=$("$_bin" version 2>&1) || _status=$?
    _actual=$(printf '%s\n' "$_output" | sed -n 's/^sing-box version \([0-9][0-9.]*\).*$/\1/p' | head -1)
    if [ "$_status" -ne 0 ] || [ "$_actual" != "$_expected" ]; then
        echo -e "${RED}sing-box 执行或版本校验失败（退出码 ${_status}，期望 ${_expected}，得到 ${_actual:-未知}）${PLAIN}" >&2
        printf '%s\n' "$_output" >&2
        case "$_status" in
            137) echo "进程被 SIGKILL 终止，可能触发 VPS 内存限制；请检查 OOM 日志和可用内存。" >&2 ;;
            126|127) echo "请检查系统运行库、CPU 架构及临时目录是否设置 noexec。" >&2 ;;
            132) echo "CPU 不支持该二进制所需的指令集。" >&2 ;;
        esac
        return 1
    fi
}

build_release_url() {
    local _tag="$1" _arch="$2"
    case "$_tag" in
        latest|"") echo -e "${RED}版本标签不能为 latest，请指定具体版本号${PLAIN}" >&2; return 1 ;;
    esac
    case "$_arch" in
        amd64|arm64|armv7|386|s390x) ;;
        *) echo -e "${RED}不支持的架构: ${_arch}${PLAIN}" >&2; return 1 ;;
    esac
    local _ver="${_tag#v}"
    printf 'https://github.com/SagerNet/sing-box/releases/download/v%s/%s\n' \
        "$_ver" "$(singbox_asset_name "$_ver" "$_arch")"
}

version_at_least() {
    awk -v got="$1" -v need="$2" 'BEGIN {
        split(got, g, "."); split(need, n, ".")
        for (i = 1; i <= 3; i++) {
            if ((g[i] + 0) > (n[i] + 0)) exit 0
            if ((g[i] + 0) < (n[i] + 0)) exit 1
        }
        exit 0
    }'
}

normalize_version_tag() {
    local _tag="$1"
    _tag=$(printf '%s' "$_tag" | tr -d '[:space:]' | sed -E 's#^.*/tag/##; s#^.*/download/##; s#[?].*$##')
    [ -n "$_tag" ] || return 1
    case "$_tag" in
        v*) ;;
        *) _tag="v${_tag}" ;;
    esac
    printf '%s\n' "$_tag" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$' || return 1
    printf '%s' "$_tag"
}

set_latest_version_tag() {
    local _candidate _normalized
    for _candidate in "$@"; do
        _normalized=$(normalize_version_tag "$_candidate" 2>/dev/null || true)
        if [ -n "$_normalized" ]; then
            LAST_VERSION_TAG="$_normalized"
            return 0
        fi
    done
    return 1
}

# ============================================================
# 网络检测
# ============================================================
is_valid_ipv4() {
    echo "$1" | awk -F. '
        NF != 4 { exit 1 }
        {
            for (i = 1; i <= 4; i++) {
                if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1
            }
        }
    '
}

# 校验 IPv6 字面量语法。只做“含冒号且全为十六进制”会放行 ::、:、1:2:3:4:5:6:7:8:9
# 这类非法值，而外网探测结果会直接进入分享链接，因此需要完整的分组与 :: 规则校验。
is_valid_ipv6() {
    case "$1" in
        *:*) ;;
        *) return 1 ;;
    esac
    printf '%s' "$1" | awk '
        {
            s = $0
            if (s !~ /^[0-9A-Fa-f:]+$/) exit 1
            if (s ~ /:::/) exit 1
            if (gsub(/::/, "::") > 1) exit 1
            if (s ~ /^:[^:]/ || s ~ /[^:]:$/) exit 1
            n = split(s, g, ":")
            groups = 0
            for (i = 1; i <= n; i++) {
                if (g[i] == "") continue
                if (length(g[i]) > 4) exit 1
                groups++
            }
            if (groups == 0) exit 1
            if (s ~ /::/) { if (groups > 7) exit 1 }
            else if (groups != 8) exit 1
            exit 0
        }
    '
}

get_native_egress_interface() {
    command -v ip >/dev/null 2>&1 || return 1
    local _iface _families _family
    case "${BIND_FAMILY:-v4}" in
        v6) _families="-6 -4" ;;
        *)  _families="-4 -6" ;;
    esac
    for _family in $_families; do
        _iface=$(ip "$_family" route show default 2>/dev/null | awk '
            /default/ {
                for (i = 1; i <= NF; i++) {
                    if ($i == "dev" && $(i + 1) !~ /wgcf|warp|^tun|^wg|tailscale|zt/) {
                        print $(i + 1)
                        exit
                    }
                }
            }
        ')
        if [ -n "$_iface" ]; then
            printf '%s' "$_iface"
            return 0
        fi
    done
    return 1
}

# 公网 IP 探测站。混合不同 ASN，并各放一个免 DNS 的字面量地址端点：
# 单一 CDN 被阻断或 DNS 故障时，探测仍能取到公网地址。
IPV4_PROBE_URLS="${IPV4_PROBE_URLS:-https://api.ipify.org https://1.1.1.1/cdn-cgi/trace https://checkip.amazonaws.com https://ip.gs https://ipv4.icanhazip.com}"
IPV6_PROBE_URLS="${IPV6_PROBE_URLS:-https://api6.ipify.org https://[2606:4700:4700::1111]/cdn-cgi/trace https://ipv6.icanhazip.com}"
# 经隧道验证出口：先用免 DNS 的字面量地址确认隧道本身，再用域名确认 DNS 路径。
TUNNEL_IP_PROBE_URL="${TUNNEL_IP_PROBE_URL:-https://1.1.1.1/cdn-cgi/trace}"
TUNNEL_DNS_PROBE_URLS="${TUNNEL_DNS_PROBE_URLS:-https://api.ipify.org https://checkip.amazonaws.com}"

# 探测响应可能是纯地址，也可能是 Cloudflare trace 的 key=value 多行文本。
extract_probe_ip() {
    awk '
        /^ip=/ { sub(/^ip=/, ""); print; found = 1; exit }
        NR == 1 && $0 !~ /=/ { first = $0 }
        END { if (!found && first != "") print first }
    ' | tr -d ' \t\r\n'
}

get_native_public_ipv4() {
    command -v ip >/dev/null 2>&1 || return 1
    local _iface _local_ip _ip _url
    _iface=$(get_native_egress_interface 2>/dev/null || true)
    [ -n "$_iface" ] || return 1
    _local_ip=$(ip -4 addr show dev "$_iface" scope global 2>/dev/null | awk '
        /inet / { addr=$2; sub(/\/.*/, "", addr); print addr; exit }
    ')
    [ -n "$_local_ip" ] || return 1

    for _url in $IPV4_PROBE_URLS; do
        _ip=$(curl -s4 --interface "$_local_ip" --connect-timeout 3 --max-time 5 "$_url" 2>/dev/null | extract_probe_ip)
        if is_valid_ipv4 "$_ip"; then
            printf '%s' "$_ip"
            return 0
        fi
    done
    return 1
}

get_default_public_ipv6() {
    local _ip _url
    for _url in $IPV6_PROBE_URLS; do
        _ip=$(curl -s6 --connect-timeout 3 --max-time 5 "$_url" 2>/dev/null | extract_probe_ip)
        if is_valid_ipv6 "$_ip"; then
            printf '%s' "$_ip"
            return 0
        fi
    done
    return 1
}

get_default_public_ipv4() {
    local _ip _url
    for _url in $IPV4_PROBE_URLS; do
        _ip=$(curl -s4 --connect-timeout 3 --max-time 5 "$_url" 2>/dev/null | extract_probe_ip)
        if is_valid_ipv4 "$_ip"; then
            printf '%s' "$_ip"
            return 0
        fi
    done
    return 1
}

detect_warp() {
    if command -v ip >/dev/null 2>&1 && ip link show 2>/dev/null | grep -qE '^[0-9]+: (wgcf|warp|wg)[^:]*:'; then
        return 0
    fi
    if command -v warp-cli >/dev/null 2>&1 && warp-cli status 2>/dev/null | grep -qiE 'connected|已连接'; then
        return 0
    fi
    return 1
}

# 是否存在默认 IPv6 路由。用于区分"分到 IPv6 地址但路由已死"的廉价 VPS：
# 这类机器接口上有全局 IPv6，但既连不通外网又无默认路由，必须按纯 IPv4 处理。
has_default_ipv6_route() {
    command -v ip >/dev/null 2>&1 || return 1
    ip -6 route show default 2>/dev/null | grep -q .
}

# 私网 / 共享地址段 IPv4。这类地址不能写进分享链接，
# 命中时必须按 NAT 处理，公网地址交给用户确认。
is_private_ipv4() {
    case "$1" in
        10.*|127.*|169.254.*|192.168.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
        *) return 1 ;;
    esac
}

has_default_ipv4_route() {
    command -v ip >/dev/null 2>&1 || return 1
    ip -4 route show default 2>/dev/null | grep -q .
}

# 原生出站网卡上的全局 IPv4（排除 WARP/隧道网卡）。
# 仅在公网 IP 探测站全部不可达时，作为“本机有 IPv4”的兜底证据。
get_native_local_ipv4() {
    command -v ip >/dev/null 2>&1 || return 1
    local _iface
    _iface=$(get_native_egress_interface 2>/dev/null || true)
    [ -n "$_iface" ] || return 1
    ip -4 addr show dev "$_iface" scope global 2>/dev/null | awk '
        /inet / { addr=$2; sub(/\/.*/, "", addr); print addr; exit }
    '
}

detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    NAT_MODE=0; HAS_IPV4=0; HAS_IPV6=0; PUBLIC_IP=""; PUBLIC_IPV6=""; DEFAULT_EGRESS_IPV4=""; WARP_ACTIVE=0; BIND_INTERFACE=""; BIND_FAMILY="v4"; LISTEN_HOST="::"; IPV4_UNVERIFIED=0
    local _ip _url

    detect_warp && WARP_ACTIVE=1 || true
    DEFAULT_EGRESS_IPV4=$(get_default_public_ipv4 2>/dev/null || true)
    BIND_INTERFACE=$(get_native_egress_interface 2>/dev/null || true)

    local _ipv6_probe="" _ipv6_reachable=0
    for _url in $IPV6_PROBE_URLS; do
        _ip=$(curl -s6 --connect-timeout 3 --max-time 5 "$_url" 2>/dev/null | extract_probe_ip)
        if is_valid_ipv6 "$_ip"; then _ipv6_probe="$_ip"; _ipv6_reachable=1; break; fi
    done

    if command -v ip >/dev/null 2>&1; then
        local _real_ipv6
        _real_ipv6=$(ip -6 addr show scope global 2>/dev/null | awk '
            /^[0-9]+:/ { iface=$2; sub(/:.*/,"",iface) }
            /inet6/ && iface !~ /wgcf|warp|^tun|^wg|tailscale|zt/ {
                addr=$2; sub(/\/.*/,"",addr)
                if (addr !~ /^fe80:/ && addr !~ /^f[cd][0-9a-f][0-9a-f]:/ && addr !~ /^2606:4700:/) { print addr; exit }
            }
        ')
        if [ -n "$_real_ipv6" ] && { [ "$_ipv6_reachable" = "1" ] || has_default_ipv6_route; }; then
            HAS_IPV6=1
            PUBLIC_IPV6="$_real_ipv6"
        else
            HAS_IPV6=0
            PUBLIC_IPV6=""
        fi
    else
        HAS_IPV6="$_ipv6_reachable"
        PUBLIC_IPV6="$_ipv6_probe"
    fi

    _ip=$(get_native_public_ipv4 2>/dev/null || true)
    if is_valid_ipv4 "$_ip"; then
        PUBLIC_IP="$_ip"
        HAS_IPV4=1
    elif [ "$WARP_ACTIVE" = "0" ] && is_valid_ipv4 "$DEFAULT_EGRESS_IPV4"; then
        PUBLIC_IP="$DEFAULT_EGRESS_IPV4"
        HAS_IPV4=1
    else
        local _local_ipv4
        _local_ipv4=$(get_native_local_ipv4 2>/dev/null || true)
        if is_valid_ipv4 "$_local_ipv4" && has_default_ipv4_route; then
            HAS_IPV4=1
            IPV4_UNVERIFIED=1
            if is_private_ipv4 "$_local_ipv4"; then
                NAT_MODE=1
            else
                PUBLIC_IP="$_local_ipv4"
            fi
        fi
    fi

    if [ "$HAS_IPV4" = "1" ] && command -v ip >/dev/null 2>&1; then
        local _real_ipv4
        _real_ipv4=$(ip -4 addr show scope global 2>/dev/null | awk '
            /^[0-9]+:/ { iface=$2; sub(/:.*/,"",iface) }
            /inet / && iface !~ /wgcf|warp|^tun|^wg|tailscale|zt/ { print "1"; exit }
        ')
        [ -z "$_real_ipv4" ] && { HAS_IPV4=0; PUBLIC_IP=""; }
    fi

    if [ "$HAS_IPV4" = "1" ] && [ -n "$PUBLIC_IP" ] && command -v ip >/dev/null 2>&1; then
        local _local_ips
        _local_ips=$(ip addr show 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^127\.' | grep -v '^169\.254\.')
        echo "$_local_ips" | grep -q "^${PUBLIC_IP}$" || NAT_MODE=1
    fi

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && BIND_FAMILY="v6"
    [ "$HAS_IPV6" = "1" ] && [ "$HAS_IPV4" = "1" ] && BIND_FAMILY="v4"
    [ "$HAS_IPV6" = "0" ] && LISTEN_HOST="0.0.0.0"

    if   [ "$NAT_MODE" = "1" ] && [ -z "$PUBLIC_IP" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4 未确认，请手动指定节点地址）"
    elif [ "$NAT_MODE"     = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$BIND_FAMILY"  = "v6" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"     = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv6: ${PUBLIC_IPV6} | IPv4: ${PUBLIC_IP}）"
    elif [ "$HAS_IPV4"     = "1" ]; then echo -e "  机器类型: ${GREEN}标准 IPv4${PLAIN}（IP: ${PUBLIC_IP}）"
    else                                  echo -e "  机器类型: ${RED}无法检测，请手动输入节点地址${PLAIN}"
    fi
    if [ "${IPV4_UNVERIFIED:-0}" = "1" ]; then
        echo -e "  ${YELLOW}提示: 公网 IP 探测站不可达，已按本机默认路由确认 IPv4 可用${PLAIN}"
    fi
    return 0
}

# 落地机只需要知道自己的出口 IPv4 与是否具备 IPv6 出网能力。
detect_exit_egress() {
    EXIT_IPV4=$(get_default_public_ipv4 2>/dev/null || true)
    if [ -n "$(get_default_public_ipv6 2>/dev/null || true)" ]; then
        EXIT_HAS_IPV6=1
    else
        EXIT_HAS_IPV6=0
    fi
}

open_ports() {
    local _port="$1" _proto="${2:-tcp}" _fw_meta="$LANDING_META/firewall" _added4=0
    validate_port "$_port" || { echo -e "${RED}无效的防火墙端口: ${_port}${PLAIN}"; return 1; }
    case "$_proto" in tcp|udp) ;; *) return 1 ;; esac
    mkdir -p "$_fw_meta" 2>/dev/null || {
        echo -e "${RED}无法创建防火墙规则记录目录，已取消放行${PLAIN}"
        return 1
    }
    echo -e "${YELLOW}正在自动放行 ${_proto} 端口 ${_port}...${PLAIN}"

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if ! firewall-cmd --permanent --query-port="${_port}/${_proto}" >/dev/null 2>&1; then
            if ! firewall-cmd --permanent --add-port="${_port}/${_proto}" >/dev/null 2>&1 || \
                ! firewall-cmd --reload >/dev/null 2>&1 || \
                ! firewall-cmd --query-port="${_port}/${_proto}" >/dev/null 2>&1; then
                firewall-cmd --permanent --remove-port="${_port}/${_proto}" >/dev/null 2>&1 || true
                firewall-cmd --reload >/dev/null 2>&1 || true
                echo -e "${RED}firewalld 放行 ${_proto}/${_port} 失败${PLAIN}"
                return 1
            fi
            : > "$_fw_meta/firewalld-${_port}-${_proto}"
        fi
        if ! firewall-cmd --query-port="${_port}/${_proto}" >/dev/null 2>&1; then
            firewall-cmd --reload >/dev/null 2>&1 && firewall-cmd --query-port="${_port}/${_proto}" >/dev/null 2>&1 || {
                echo -e "${RED}firewalld 未能应用 ${_proto}/${_port}${PLAIN}"
                return 1
            }
        fi
        echo -e "  ${GREEN}✓ firewalld 已放行 ${_proto}/${_port}${PLAIN}"
        return 0
    fi

    if command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -qE '^Status:[[:space:]]+active[[:space:]]*$'; then
        if ! LC_ALL=C ufw status 2>/dev/null | grep -qE "^${_port}/${_proto}[[:space:]]+ALLOW"; then
            if ! LC_ALL=C ufw allow "${_port}/${_proto}" >/dev/null || \
                ! LC_ALL=C ufw status 2>/dev/null | grep -qE "^${_port}/${_proto}[[:space:]]+ALLOW"; then
                echo -e "${RED}ufw 放行 ${_proto}/${_port} 失败${PLAIN}"
                return 1
            fi
            : > "$_fw_meta/ufw-${_port}-${_proto}"
        fi
        echo -e "  ${GREEN}✓ ufw 已放行 ${_proto}/${_port}${PLAIN}"
        return 0
    fi

    if command -v iptables >/dev/null 2>&1; then
        if ! iptables -C INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
            if ! iptables -I INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
                ! iptables -C INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                echo -e "${RED}iptables 放行 ${_proto}/${_port} 失败${PLAIN}"
                return 1
            fi
            _added4=1
            : > "$_fw_meta/iptables4-${_port}-${_proto}"
        fi
        if [ "$HAS_IPV6" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
            if ! ip6tables -C INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                if ! ip6tables -I INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
                    ! ip6tables -C INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                    [ "$_added4" = "0" ] || iptables -D INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
                    [ "$_added4" = "0" ] || rm -f "$_fw_meta/iptables4-${_port}-${_proto}"
                    echo -e "${RED}ip6tables 放行 ${_proto}/${_port} 失败${PLAIN}"
                    return 1
                fi
                : > "$_fw_meta/iptables6-${_port}-${_proto}"
            fi
        fi
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || echo -e "  ${YELLOW}! 规则已生效，但持久化保存失败${PLAIN}"
        elif [ -f /etc/sysconfig/iptables ] && command -v service >/dev/null 2>&1; then
            service iptables save >/dev/null 2>&1 || echo -e "  ${YELLOW}! 规则已生效，但持久化保存失败${PLAIN}"
        fi
        echo -e "  ${GREEN}✓ iptables 已放行 ${_proto}/${_port}${PLAIN}"
        return 0
    fi

    echo -e "  ${YELLOW}! 未检测到启用的本机防火墙；请确认云安全组 / 面板防火墙已放行 ${_proto}/${_port}${PLAIN}"
    return 0
}

close_ports() {
    local _port="$1" _proto="${2:-tcp}"
    local _fw_meta="$LANDING_META/firewall"
    validate_port "$_port" || return 0
    case "$_proto" in tcp|udp) ;; *) return 0 ;; esac

    if [ -f "$_fw_meta/firewalld-${_port}-${_proto}" ] && command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${_port}/${_proto}" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        rm -f "$_fw_meta/firewalld-${_port}-${_proto}"
    fi
    if [ -f "$_fw_meta/ufw-${_port}-${_proto}" ] && command -v ufw >/dev/null 2>&1 && LC_ALL=C ufw status 2>/dev/null | grep -qE '^Status:[[:space:]]+active[[:space:]]*$'; then
        ufw delete allow "${_port}/${_proto}" >/dev/null 2>&1 || true
        rm -f "$_fw_meta/ufw-${_port}-${_proto}"
    fi
    if [ -f "$_fw_meta/iptables4-${_port}-${_proto}" ] && command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
        rm -f "$_fw_meta/iptables4-${_port}-${_proto}"
    fi
    if [ -f "$_fw_meta/iptables6-${_port}-${_proto}" ] && command -v ip6tables >/dev/null 2>&1; then
        ip6tables -D INPUT -p "$_proto" --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
        rm -f "$_fw_meta/iptables6-${_port}-${_proto}"
    fi
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif [ -f /etc/sysconfig/iptables ] && command -v service >/dev/null 2>&1; then
        service iptables save >/dev/null 2>&1 || true
    fi
}

role_port() {
    case "$ROLE" in
        exit) printf '%s' "${WG_PORT:-}" ;;
        *) printf '%s' "${LISTEN_PORT:-}" ;;
    esac
}

role_proto() {
    case "$ROLE" in
        exit) printf 'udp' ;;
        *) printf 'tcp' ;;
    esac
}

# ============================================================
# 二进制下载 / 校验
# ============================================================
validate_elf() {
    local _file="$1"
    [ -z "$_file" ] && return 1
    [ -f "$_file" ] || return 1
    [ -s "$_file" ] || return 1
    local _magic
    _magic=$(od -A d -t x1 -N 4 "$_file" 2>/dev/null | awk 'NR==1 { print $2, $3, $4, $5 }')
    [ "$_magic" = "7f 45 4c 46" ] && return 0
    return 1
}

validate_shared_configs_with_bin() {
    local _bin="$1" _config
    [ -x "$_bin" ] || return 1
    for _config in "$LANDING_DIR"/*.json; do
        [ -f "$_config" ] || continue
        if ! "$_bin" check -c "$_config" >/dev/null 2>&1; then
            echo -e "${RED}新核心无法加载共享配置: ${_config}${PLAIN}"
            return 1
        fi
    done
    return 0
}

get_latest_version() {
    echo -e "${YELLOW}正在获取 sing-box 最新稳定版...${PLAIN}"
    LAST_VERSION_TAG=""

    local _candidate _page _url
    _candidate=$(curl -fsSL --connect-timeout 8 --max-time 15 \
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null \
        | awk -F'"' '/"tag_name":/ { print $4; exit }' 2>/dev/null || true)
    set_latest_version_tag "$_candidate" || true

    if [ -z "$LAST_VERSION_TAG" ]; then
        for _url in \
            "https://github.com/SagerNet/sing-box/releases/latest" \
            "https://kkgithub.com/SagerNet/sing-box/releases/latest" \
            "https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/latest"
        do
            _candidate=$(curl -Ls --connect-timeout 8 --max-time 15 -o /dev/null -w "%{url_effective}" "$_url" 2>/dev/null || true)
            set_latest_version_tag "$_candidate" && break
        done
    fi

    if [ -z "$LAST_VERSION_TAG" ]; then
        for _url in \
            "https://github.com/SagerNet/sing-box/releases" \
            "https://kkgithub.com/SagerNet/sing-box/releases"
        do
            _page=$(curl -fsSL --connect-timeout 8 --max-time 15 "$_url" 2>/dev/null || true)
            _candidate=$(printf '%s\n' "$_page" \
                | grep -oE 'SagerNet/sing-box/releases/(tag|download)/v[0-9]+\.[0-9]+\.[0-9]+' \
                | sed -E 's#.*/(tag|download)/##' | head -1)
            set_latest_version_tag "$_candidate" && break
        done
    fi

    if [ -z "$LAST_VERSION_TAG" ]; then
        if set_latest_version_tag "$SING_BOX_STABLE_FALLBACK_TAG"; then
            echo -e "${YELLOW}[WARN] 无法连接 GitHub 获取最新版本，使用内置稳定版 ${LAST_VERSION_TAG}${PLAIN}"
        else
            echo -e "${RED}获取版本失败或版本标签格式异常${PLAIN}"
            LAST_VERSION_TAG=""
            return 1
        fi
    fi

    echo -e "${GREEN}最新版本: ${LAST_VERSION_TAG}${PLAIN}"
}

get_installed_version() {
    [ -x "$SING_BOX_BIN" ] || return 1
    "$SING_BOX_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

download_file() {
    local _url="$1" _dest="$2" _attempt=1 _delay=2
    while [ "$_attempt" -le 3 ]; do
        if command -v curl >/dev/null 2>&1 && curl -fL --connect-timeout 15 --max-time 120 -o "$_dest" "$_url" 2>/dev/null; then return 0; fi
        if command -v wget >/dev/null 2>&1 && wget -q --timeout=60 -O "$_dest" "$_url" 2>/dev/null; then return 0; fi
        rm -f "$_dest"
        [ "$_attempt" -ge 3 ] && break
        sleep "$_delay"; _attempt=$((_attempt + 1)); _delay=$((_delay * 2))
    done
    return 1
}

parse_release_asset_sha256() {
    local _asset="$1"
    awk -v asset="$_asset" '
        /"name":[[:space:]]*"/ {
            name=$0
            sub(/^.*"name":[[:space:]]*"/, "", name)
            sub(/".*$/, "", name)
        }
        name == asset && /"digest":[[:space:]]*"sha256:/ {
            digest=$0
            sub(/^.*"digest":[[:space:]]*"sha256:/, "", digest)
            sub(/".*$/, "", digest)
            print tolower(digest)
            exit
        }
    '
}

get_release_asset_sha256() {
    local _tag="$1" _asset="$2"
    curl -fsSL --connect-timeout 8 --max-time 20 \
        "https://api.github.com/repos/SagerNet/sing-box/releases/tags/${_tag}" 2>/dev/null \
        | parse_release_asset_sha256 "$_asset"
}

verify_archive_sha256() {
    local _file="$1" _expected="$2" _actual
    [ -n "$_expected" ] || return 1
    _actual=$(openssl dgst -sha256 "$_file" 2>/dev/null | awk '{ print tolower($NF) }')
    [ "$_actual" = "$_expected" ]
}

has_free_space_mb() {
    local _path="$1" _required="$2" _available
    command -v df >/dev/null 2>&1 || return 0
    _available=$(df -Pk "$_path" 2>/dev/null | awk 'NR == 2 { print $4; exit }')
    [ -z "$_available" ] && return 0
    [ "$_available" -ge $((_required * 1024)) ]
}

check_download_space() {
    has_free_space_mb "$(disk_tmp_dir)" 160 && has_free_space_mb "$(dirname "$SING_BOX_BIN")" 48 || {
        echo -e "${RED}磁盘空间不足：下载并解压 sing-box 至少需要临时分区 160MB、目标分区 48MB${PLAIN}"
        return 1
    }
}

download_singbox() {
    check_download_space || return 1
    local _arch
    _arch=$(detect_arch) || return 1

    local _ver="${LAST_VERSION_TAG#v}"
    local _asset
    _asset=$(singbox_asset_name "$_ver" "$_arch") || return 1
    local _gh_path="SagerNet/sing-box/releases/download/v${_ver}/${_asset}"
    local _urls=(
        "https://github.com/${_gh_path}"
        "https://gh-proxy.com/https://github.com/${_gh_path}"
        "https://kkgithub.com/${_gh_path}"
        "https://ghproxy.com/https://github.com/${_gh_path}"
    )

    local _tmp_archive _tmp_dir _ok=0 _url _host _expected_sha256
    _expected_sha256=$(get_release_asset_sha256 "$LAST_VERSION_TAG" "$_asset" 2>/dev/null || true)
    if [ -z "$_expected_sha256" ]; then
        echo -e "${YELLOW}! 无法获取 GitHub 官方摘要，本次仅允许官方 GitHub 下载源${PLAIN}"
    fi
    _tmp_dir=$(mktemp -d "$(disk_tmp_dir)/sing-box-XXXXXX") || return 1
    _tmp_archive="${_tmp_dir}/${_asset}"

    for _url in "${_urls[@]}"; do
        _host=$(echo "$_url" | awk -F/ '{print $3}')
        [ -n "$_expected_sha256" ] || [ "$_host" = "github.com" ] || continue
        echo -e "${YELLOW}正在下载 ${_asset}（来源: ${_host}）${PLAIN}"
        rm -f "$_tmp_archive"
        if download_file "$_url" "$_tmp_archive"; then
            if [ -n "$_expected_sha256" ] && ! verify_archive_sha256 "$_tmp_archive" "$_expected_sha256"; then
                echo -e "${RED}  ↳ SHA-256 校验失败，拒绝使用该下载内容${PLAIN}"
                continue
            fi
            if tar -tzf "$_tmp_archive" >/dev/null 2>&1; then
                _ok=1
                break
            fi
            echo -e "${YELLOW}  ↳ 下载内容不是有效压缩包，尝试下一个镜像...${PLAIN}"
            continue
        fi
        echo -e "${YELLOW}  ↳ 失败，尝试下一个镜像...${PLAIN}"
    done

    if [ "$_ok" = "0" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}所有下载源均失败，请检查网络后重试${PLAIN}"
        return 1
    fi

    tar -xzf "$_tmp_archive" -C "$_tmp_dir" || {
        rm -rf "$_tmp_dir"
        echo -e "${RED}解压失败，下载文件可能损坏，请重试${PLAIN}"
        return 1
    }

    local _bin
    _bin=$(find "$_tmp_dir" -type f -name "sing-box" | head -1)
    if [ -z "$_bin" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}未在压缩包中找到 sing-box 二进制${PLAIN}"
        return 1
    fi

    chmod +x "$_bin"
    if ! validate_elf "$_bin"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}二进制 ELF 校验失败（文件损坏或架构不匹配）${PLAIN}"
        return 1
    fi
    if ! validate_singbox_execution "$_bin" "$_ver"; then
        rm -rf "$_tmp_dir"
        return 1
    fi
    if ! validate_shared_configs_with_bin "$_bin"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}为保护现有 sing-box 服务，已拒绝替换共享核心${PLAIN}"
        return 1
    fi

    if ! mv -f "$_bin" "$SING_BOX_BIN" || ! chmod +x "$SING_BOX_BIN"; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}替换 sing-box 二进制失败${PLAIN}"
        return 1
    fi
    MANAGED_SING_BOX=1
    rm -rf "$_tmp_dir"
    echo -e "${GREEN}sing-box 安装完成: $("$SING_BOX_BIN" version 2>/dev/null | head -1)${PLAIN}"
}

ensure_singbox_bin() {
    local _preexisting=0
    if [ -x "$SING_BOX_BIN" ]; then
        _preexisting=1
        local _installed_version
        _installed_version=$(get_installed_version)
        if version_at_least "${_installed_version:-0.0.0}" "1.12.0"; then
            if [ -f "$LANDING_META/config.env" ]; then
                MANAGED_SING_BOX=$(awk -F= '$1 == "MANAGED_SING_BOX" { print $2; exit }' "$LANDING_META/config.env")
                [ "$MANAGED_SING_BOX" = "1" ] || MANAGED_SING_BOX=0
            fi
            return 0
        fi
        echo -e "${YELLOW}现有 sing-box ${_installed_version:-未知版本} 低于脚本最低版本 1.12.0，将安装最新版${PLAIN}"
    fi
    get_latest_version || return 1
    download_singbox || return 1
    if [ "$_preexisting" = "1" ]; then
        MANAGED_SING_BOX=0
    else
        MANAGED_SING_BOX=1
        mkdir -p "$LANDING_DIR" || { echo -e "${RED}无法创建 sing-box 配置目录${PLAIN}"; return 1; }
        { : > "$SING_BOX_MANAGED_MARKER"; } || { echo -e "${RED}无法写入 sing-box 所有权标记${PLAIN}"; return 1; }
        chmod 600 "$SING_BOX_MANAGED_MARKER" || { echo -e "${RED}无法保护 sing-box 所有权标记${PLAIN}"; return 1; }
    fi
    return 0
}

# ============================================================
# URI 与导出辅助
# ============================================================
uri_encode() {
    local _in="$1" _out="" _i _c _hex
    local _len="${#_in}"
    _i=0
    while [ "$_i" -lt "$_len" ]; do
        _c="${_in:$_i:1}"
        case "$_c" in
            [a-zA-Z0-9.~_-]) _out="${_out}${_c}" ;;
            ' ') _out="${_out}%20" ;;
            *) _hex=$(printf '%s' "$_c" | od -An -tx1 | awk '{ for (i=1; i<=NF; i++) printf "%%%s", toupper($i) }'); _out="${_out}${_hex}" ;;
        esac
        _i=$(( _i + 1 ))
    done
    printf '%s' "$_out"
}

trim_string() {
    printf '%s' "$1" | tr -d '\r\n\t' | awk '{$1=$1; print}'
}

print_copy_block() {
    printf '%s\n' "$1"
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
    local _ipv4="$1" _ipv6="$2" _code=""
    [ -n "$_ipv4" ] && _code=$(get_ip_country "$_ipv4" 2>/dev/null || true)
    [ -z "$_code" ] && [ -n "$_ipv6" ] && _code=$(get_ip_country "$_ipv6" 2>/dev/null || true)
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

generate_server_name() {
    local _name
    _name=$(hostname 2>/dev/null | tr -d '\n\r\t')
    _name=$(trim_string "$_name")
    [ -z "$_name" ] && _name="server.$(printf '%06X' "$(( (RANDOM << 1) ^ RANDOM ))")"
    printf '%s' "$_name"
}

generate_node_name() {
    local _country _flag _server _protocol _ip_type
    _country=$(printf '%s' "${1:-UN}" | tr '[:lower:]' '[:upper:]')
    case "$_country" in [A-Z][A-Z]) ;; *) _country="UN" ;; esac
    _flag=$(get_country_flag "$_country")
    _server=$(trim_string "${2:-}")
    [ -z "$_server" ] && _server=$(generate_server_name)
    _protocol=$(trim_string "${3:-VLESS}")
    _ip_type=$(trim_string "${4:-IPv4}")
    printf '%s %s | %s | %s | %s' "$_flag" "$_country" "$_server" "$_protocol" "$_ip_type" | tr -d '\r\n\t'
}

format_ipv6_for_uri() {
    echo "$1" | grep -q ':' && printf '[%s]' "$1" || printf '%s' "$1"
}

format_server_for_yaml() {
    echo "$1" | grep -q ':' && printf "'%s'" "$1" || printf '%s' "$1"
}

yaml_single_quote_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

generate_terminal_qrcode() {
    local _data="$1"
    command -v qrencode >/dev/null 2>&1 || return 1
    qrencode -t ANSIUTF8 -m 2 "$_data"
}

generate_local_qrcode_png() {
    local _data="$1" _protocol="$2" _ip_type="$3" _dir="/root/singbox-tools/qrcode" _slug _file
    command -v qrencode >/dev/null 2>&1 || return 1
    _slug=$(printf '%s' "$_protocol" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')
    mkdir -p "$_dir" 2>/dev/null || return 1
    _file="${_dir}/${_slug}-${_ip_type}.png"
    qrencode -o "$_file" "$_data" 2>/dev/null || return 1
    printf '%s' "$_file"
}

generate_online_qrcode_url() {
    local _data="$1" _encoded
    _encoded=$(uri_encode "$_data")
    printf 'https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=%s' "$_encoded"
}

render_uri() {
    local _server="$1" _port="$2" _uuid="$3" _name="$4" _sni="${5:-$SERVER_NAME}"
    local _public_key="${6:-$REALITY_PUBLIC_KEY}" _short_id="${7:-$SHORT_ID}"
    local _host
    _host=$(format_ipv6_for_uri "$_server")
    local _enc_name _enc_sni
    _enc_name=$(uri_encode "$_name")
    _enc_sni=$(uri_encode "$_sni")
    printf 'vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s\n' \
        "$_uuid" "$_host" "$_port" "$_enc_sni" "$_public_key" "$_short_id" "$_enc_name"
}

# ============================================================
# 配置写入 / 读取
# ============================================================
atomic_write_meta() {
    local _target="$1" _value="$2" _tmp
    _tmp=$(mktemp "${_target}.new.XXXXXX" 2>/dev/null) || return 1
    printf '%s' "$_value" > "$_tmp" && chmod 600 "$_tmp" && mv -f "$_tmp" "$_target" || {
        rm -f "$_tmp"
        return 1
    }
}

install_config_file() {
    local _tmp="$1"
    chmod 600 "$_tmp" && mv -f "$_tmp" "$LANDING_CONFIG" || {
        rm -f "$_tmp"
        return 1
    }
}

# 线路机：VLESS REALITY 入站 + 本机探测入口，全部出站经 WireGuard 进入落地机。
# 域名先经隧道交给落地机解析，再以 IP 进入隧道，CDN 就近解析与家宽出口保持一致。
write_relay_config() {
    local _tmp _reality_strategy _local_strategy _exit_strategy
    _reality_strategy=$(reality_domain_strategy)
    case "${BIND_FAMILY:-v4}" in
        v6) _local_strategy="prefer_ipv6" ;;
        *)  _local_strategy="prefer_ipv4" ;;
    esac
    if [ "${EXIT_HAS_IPV6:-0}" = "1" ]; then
        _exit_strategy="prefer_ipv4"
    else
        _exit_strategy="ipv4_only"
    fi
    mkdir -p "$LANDING_DIR" || return 1
    _tmp=$(mktemp "${LANDING_DIR}/landing.json.new.XXXXXX" 2>/dev/null) || return 1
    if ! cat > "$_tmp" <<CFG
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "local", "tag": "local" },
      { "type": "udp", "tag": "exit-dns", "server": "${WG_EXIT_DNS}", "detour": "wg-out" }
    ],
    "final": "local"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "${LISTEN_HOST}",
      "listen_port": ${LISTEN_PORT},
      "users": [
        {
          "name": "default",
          "uuid": "${UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SERVER_NAME}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${SERVER_NAME}",
            "server_port": ${HANDSHAKE_PORT},
            "domain_resolver": {
              "server": "local",
              "strategy": "${_reality_strategy}"
            }
          },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    {
      "type": "mixed",
      "tag": "probe-in",
      "listen": "127.0.0.1",
      "listen_port": ${PROBE_PORT},
      "users": [
        { "username": "${PROBE_USER}", "password": "${PROBE_PASS}" }
      ]
    }
  ],
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg-out",
      "system": false,
      "mtu": ${WG_MTU},
      "address": ["${WG_RELAY_ADDR4}", "${WG_RELAY_ADDR6}"],
      "private_key": "${WG_PRIVATE_KEY}",
      "peers": [
        {
          "address": "${EXIT_HOST}",
          "port": ${WG_PORT},
          "public_key": "${WG_PEER_PUBLIC_KEY}",
          "pre_shared_key": "${WG_PSK}",
          "allowed_ips": ["0.0.0.0/0", "::/0"],
          "persistent_keepalive_interval": ${WG_KEEPALIVE}
        }
      ]
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "inbound": ["vless-in", "probe-in"], "action": "resolve", "server": "exit-dns", "strategy": "${_exit_strategy}" },
      { "ip_is_private": true, "action": "reject" }
    ],
    "final": "wg-out",
    "default_domain_resolver": { "server": "local", "strategy": "${_local_strategy}" }
  }
}
CFG
    then
        rm -f "$_tmp"
        return 1
    fi
    install_config_file "$_tmp"
}

# 落地机：WireGuard 入站只接受线路机的隧道地址；DNS 交给本机系统解析器，
# 私网与本机回环目标一律拒绝，避免线路机经隧道访问家宽内网或落地机本地服务。
write_exit_config() {
    local _tmp
    mkdir -p "$LANDING_DIR" || return 1
    _tmp=$(mktemp "${LANDING_DIR}/landing.json.new.XXXXXX" 2>/dev/null) || return 1
    if ! cat > "$_tmp" <<CFG
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "local", "tag": "local" }
    ]
  },
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg-in",
      "system": false,
      "mtu": ${WG_MTU},
      "address": ["${WG_EXIT_ADDR4}", "${WG_EXIT_ADDR6}"],
      "private_key": "${WG_PRIVATE_KEY}",
      "listen_port": ${WG_PORT},
      "peers": [
        {
          "public_key": "${WG_PEER_PUBLIC_KEY}",
          "pre_shared_key": "${WG_PSK}",
          "allowed_ips": ["${WG_RELAY_ADDR4}", "${WG_RELAY_ADDR6}"]
        }
      ]
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "inbound": ["wg-in"], "network": "udp", "port": 53, "action": "hijack-dns" },
      { "ip_is_private": true, "action": "reject" }
    ],
    "final": "direct",
    "default_domain_resolver": "local"
  }
}
CFG
    then
        rm -f "$_tmp"
        return 1
    fi
    install_config_file "$_tmp"
}

write_config() {
    case "$ROLE" in
        relay) write_relay_config ;;
        exit) write_exit_config ;;
        *) return 1 ;;
    esac
}

write_meta() {
    local _tmp
    mkdir -p "$LANDING_META" || return 1
    chmod 700 "$LANDING_META" || return 1
    _tmp=$(mktemp "${LANDING_META}/config.env.new.XXXXXX" 2>/dev/null) || return 1
    if ! cat > "$_tmp" <<CFG
ROLE=${ROLE}
LISTEN_PORT=${LISTEN_PORT}
EXT_PORT=${EXT_PORT}
UUID=${UUID}
REALITY_PRIVATE_KEY=${REALITY_PRIVATE_KEY}
REALITY_PUBLIC_KEY=${REALITY_PUBLIC_KEY}
SHORT_ID=${SHORT_ID}
NAT_MODE=${NAT_MODE}
BIND_FAMILY=${BIND_FAMILY}
LISTEN_HOST=${LISTEN_HOST}
SERVER_NAME=${SERVER_NAME}
HANDSHAKE_PORT=${HANDSHAKE_PORT}
WG_PRIVATE_KEY=${WG_PRIVATE_KEY}
WG_PUBLIC_KEY=${WG_PUBLIC_KEY}
WG_PEER_PUBLIC_KEY=${WG_PEER_PUBLIC_KEY}
WG_PSK=${WG_PSK}
WG_PORT=${WG_PORT}
EXIT_HOST=${EXIT_HOST}
EXIT_IPV4=${EXIT_IPV4}
EXIT_HAS_IPV6=${EXIT_HAS_IPV6}
SSH_PORT=${SSH_PORT}
SSH_USER=${SSH_USER}
PROBE_PORT=${PROBE_PORT}
PROBE_USER=${PROBE_USER}
PROBE_PASS=${PROBE_PASS}
AUTO_UPDATE=${AUTO_UPDATE}
MANAGED_SING_BOX=${MANAGED_SING_BOX}
CONFIG_SCHEMA=${LANDING_CONFIG_SCHEMA}
CFG
    then
        rm -f "$_tmp"
        return 1
    fi
    chmod 600 "$_tmp" && mv -f "$_tmp" "$LANDING_META/config.env" || {
        rm -f "$_tmp"
        return 1
    }
    atomic_write_meta "$LANDING_META/public_ip" "$PUBLIC_IP" || return 1
    atomic_write_meta "$LANDING_META/public_ipv6" "$PUBLIC_IPV6" || return 1
}

reset_config_vars() {
    ROLE=""; LISTEN_PORT=""; EXT_PORT=""; UUID=""; REALITY_PRIVATE_KEY=""; REALITY_PUBLIC_KEY=""
    SHORT_ID=""; NAT_MODE=0; BIND_FAMILY="v4"; LISTEN_HOST="::"; SERVER_NAME=""; HANDSHAKE_PORT="443"
    WG_PRIVATE_KEY=""; WG_PUBLIC_KEY=""; WG_PEER_PUBLIC_KEY=""; WG_PSK=""; WG_PORT=""
    EXIT_HOST=""; EXIT_IPV4=""; EXIT_HAS_IPV6=0; SSH_PORT="22"; SSH_USER="root"
    PROBE_PORT=""; PROBE_USER=""; PROBE_PASS=""; AUTO_UPDATE=0; MANAGED_SING_BOX=0; CONFIG_SCHEMA=0
}

# 元数据按“第一个 = 之前为键”逐行解析：WireGuard 密钥以 = 结尾，
# 用 IFS='=' read 拆分会在部分 bash 版本吞掉末尾的 =，导致密钥失效。
load_meta_file() {
    local _file="$1" _line _key _value
    [ -f "$_file" ] || return 1
    while IFS= read -r _line || [ -n "$_line" ]; do
        case "$_line" in
            *=*) ;;
            *) continue ;;
        esac
        _key="${_line%%=*}"
        _value="${_line#*=}"
        case "$_key" in
            ROLE) ROLE="$_value" ;;
            LISTEN_PORT) LISTEN_PORT="$_value" ;;
            EXT_PORT) EXT_PORT="$_value" ;;
            UUID) UUID="$_value" ;;
            REALITY_PRIVATE_KEY) REALITY_PRIVATE_KEY="$_value" ;;
            REALITY_PUBLIC_KEY) REALITY_PUBLIC_KEY="$_value" ;;
            SHORT_ID) SHORT_ID="$_value" ;;
            NAT_MODE) NAT_MODE="$_value" ;;
            BIND_FAMILY) BIND_FAMILY="$_value" ;;
            LISTEN_HOST) LISTEN_HOST="$_value" ;;
            SERVER_NAME) SERVER_NAME="$_value" ;;
            HANDSHAKE_PORT) HANDSHAKE_PORT="$_value" ;;
            WG_PRIVATE_KEY) WG_PRIVATE_KEY="$_value" ;;
            WG_PUBLIC_KEY) WG_PUBLIC_KEY="$_value" ;;
            WG_PEER_PUBLIC_KEY) WG_PEER_PUBLIC_KEY="$_value" ;;
            WG_PSK) WG_PSK="$_value" ;;
            WG_PORT) WG_PORT="$_value" ;;
            EXIT_HOST) EXIT_HOST="$_value" ;;
            EXIT_IPV4) EXIT_IPV4="$_value" ;;
            EXIT_HAS_IPV6) EXIT_HAS_IPV6="$_value" ;;
            SSH_PORT) SSH_PORT="$_value" ;;
            SSH_USER) SSH_USER="$_value" ;;
            PROBE_PORT) PROBE_PORT="$_value" ;;
            PROBE_USER) PROBE_USER="$_value" ;;
            PROBE_PASS) PROBE_PASS="$_value" ;;
            AUTO_UPDATE) AUTO_UPDATE="$_value" ;;
            MANAGED_SING_BOX) MANAGED_SING_BOX="$_value" ;;
            CONFIG_SCHEMA) CONFIG_SCHEMA="$_value" ;;
        esac
    done < "$_file"
    return 0
}

validate_wg_meta() {
    validate_wg_key "$WG_PRIVATE_KEY" || return 1
    validate_wg_key "$WG_PUBLIC_KEY" || return 1
    validate_wg_key "$WG_PEER_PUBLIC_KEY" || return 1
    validate_wg_key "$WG_PSK" || return 1
    validate_port "$WG_PORT" || return 1
    [ -z "$EXIT_IPV4" ] || is_valid_ipv4 "$EXIT_IPV4" || return 1
    case "$EXIT_HAS_IPV6" in 0|1) ;; *) return 1 ;; esac
    return 0
}

validate_relay_meta() {
    validate_port "$LISTEN_PORT" || return 1
    validate_port "$EXT_PORT" || return 1
    validate_uuid "$UUID" || return 1
    validate_reality_key "$REALITY_PRIVATE_KEY" || return 1
    validate_reality_key "$REALITY_PUBLIC_KEY" || return 1
    validate_short_id "$SHORT_ID" || return 1
    validate_server_name "$SERVER_NAME" || return 1
    validate_port "$HANDSHAKE_PORT" || return 1
    case "$NAT_MODE" in 0|1) ;; *) return 1 ;; esac
    case "$BIND_FAMILY" in v4|v6) ;; *) return 1 ;; esac
    case "$LISTEN_HOST" in 0.0.0.0|::) ;; *) return 1 ;; esac
    validate_exit_host "$EXIT_HOST" || return 1
    validate_port "$SSH_PORT" || return 1
    validate_ssh_user "$SSH_USER" || return 1
    validate_port "$PROBE_PORT" || return 1
    validate_probe_secret "$PROBE_USER" || return 1
    validate_probe_secret "$PROBE_PASS" || return 1
    validate_wg_meta
}

read_config() {
    [ -f "$LANDING_CONFIG" ] && [ -f "$LANDING_META/config.env" ] || return 1
    reset_config_vars
    load_meta_file "$LANDING_META/config.env" || return 1
    case "$MANAGED_SING_BOX" in 0|1) ;; *) MANAGED_SING_BOX=0 ;; esac
    case "$AUTO_UPDATE" in 0|1) ;; *) AUTO_UPDATE=0 ;; esac
    case "$CONFIG_SCHEMA" in ''|*[!0-9]*) CONFIG_SCHEMA=0 ;; esac
    case "$ROLE" in
        relay) validate_relay_meta || return 1 ;;
        exit) validate_wg_meta || return 1 ;;
        *) return 1 ;;
    esac
    [ -z "${PUBLIC_IP:-}"   ] && PUBLIC_IP=$(cat "$LANDING_META/public_ip"   2>/dev/null || true)
    [ -z "${PUBLIC_IPV6:-}" ] && PUBLIC_IPV6=$(cat "$LANDING_META/public_ipv6" 2>/dev/null || true)
    return 0
}

# 只读取角色，不做完整校验；用于菜单展示与防止同一台机器混用两种角色。
installed_role() {
    [ -f "$LANDING_META/config.env" ] || return 1
    awk -F= '$1 == "ROLE" { print $2; exit }' "$LANDING_META/config.env"
}

write_wrapper() {
    cat > "$LANDING_BIN" <<WRAPPER || return 1
#!/bin/sh
exec "${SING_BOX_BIN}" run -c "${LANDING_CONFIG}" "\$@"
WRAPPER
    chmod 755 "$LANDING_BIN"
}

check_config() {
    "$SING_BOX_BIN" check -c "$LANDING_CONFIG"
}

backup_current_install() {
    INSTALL_BACKUP_DIR=$(mktemp -d "$(disk_tmp_dir)/landing-backup-XXXXXX") || return 1
    chmod 700 "$INSTALL_BACKUP_DIR" || { discard_install_backup; return 1; }
    [ ! -f "$LANDING_CONFIG" ] || cp -a "$LANDING_CONFIG" "$INSTALL_BACKUP_DIR/config" || { discard_install_backup; return 1; }
    [ ! -d "$LANDING_META" ] || cp -a "$LANDING_META" "$INSTALL_BACKUP_DIR/meta" || { discard_install_backup; return 1; }
    [ ! -f "$SING_BOX_MANAGED_MARKER" ] || cp -a "$SING_BOX_MANAGED_MARKER" "$INSTALL_BACKUP_DIR/managed-marker" || { discard_install_backup; return 1; }
    [ ! -f "$LANDING_BIN" ] || cp -a "$LANDING_BIN" "$INSTALL_BACKUP_DIR/wrapper" || { discard_install_backup; return 1; }
    [ ! -f "$SING_BOX_BIN" ] || cp -a "$SING_BOX_BIN" "$INSTALL_BACKUP_DIR/sing-box" || { discard_install_backup; return 1; }
    [ ! -f "$SYSTEMD_SERVICE" ] || cp -a "$SYSTEMD_SERVICE" "$INSTALL_BACKUP_DIR/systemd-service" || { discard_install_backup; return 1; }
    [ ! -f "$OPENRC_SERVICE" ] || cp -a "$OPENRC_SERVICE" "$INSTALL_BACKUP_DIR/openrc-service" || { discard_install_backup; return 1; }
    service_is_active && : > "$INSTALL_BACKUP_DIR/was-active" || true
    service_is_enabled && : > "$INSTALL_BACKUP_DIR/was-enabled" || true
    arm_install_rollback
    return 0
}

arm_install_rollback() {
    [ "$INSTALL_ROLLBACK_ARMED" = "0" ] || return 0
    INSTALL_PREV_INT_TRAP=$(trap -p INT)
    INSTALL_PREV_TERM_TRAP=$(trap -p TERM)
    trap 'rollback_install_on_signal 130' INT
    trap 'rollback_install_on_signal 143' TERM
    INSTALL_ROLLBACK_ARMED=1
}

disarm_install_rollback() {
    [ "$INSTALL_ROLLBACK_ARMED" = "1" ] || return 0
    trap - INT TERM
    [ -z "$INSTALL_PREV_INT_TRAP" ] || eval "$INSTALL_PREV_INT_TRAP"
    [ -z "$INSTALL_PREV_TERM_TRAP" ] || eval "$INSTALL_PREV_TERM_TRAP"
    INSTALL_PREV_INT_TRAP=""
    INSTALL_PREV_TERM_TRAP=""
    INSTALL_ROLLBACK_ARMED=0
}

rollback_install_on_signal() {
    local _status="$1"
    trap - INT TERM
    echo -e "\n${YELLOW}操作被中断，正在恢复原配置和服务...${PLAIN}" >&2
    if [ "$LANDING_REMOTE_COMMITTABLE" = "1" ]; then
        remote_landing_action --remote-exit-abort >/dev/null 2>&1 || true
        LANDING_REMOTE_COMMITTABLE=0
    fi
    restore_current_install
    ssh_close_master
    cleanup_script_source
    exit "$_status"
}

discard_install_backup() {
    [ -n "$INSTALL_BACKUP_DIR" ] && rm -rf "$INSTALL_BACKUP_DIR"
    INSTALL_BACKUP_DIR=""
    disarm_install_rollback
}

restore_current_install() {
    local _marker
    [ -n "$INSTALL_BACKUP_DIR" ] && [ -d "$INSTALL_BACKUP_DIR" ] || return 0
    service_stop
    service_disable
    for _marker in "$INSTALL_BACKUP_DIR"/meta/firewall/*; do
        [ -f "$_marker" ] || continue
        rm -f "$LANDING_META/firewall/$(basename "$_marker")"
    done
    close_ports "$(role_port)" "$(role_proto)"
    rm -f "$LANDING_CONFIG" "$LANDING_BIN" "$SYSTEMD_SERVICE" "$OPENRC_SERVICE"
    rm -f "$SING_BOX_MANAGED_MARKER"
    rm -rf "$LANDING_META"

    [ -f "$INSTALL_BACKUP_DIR/config" ] && cp -a "$INSTALL_BACKUP_DIR/config" "$LANDING_CONFIG"
    [ -d "$INSTALL_BACKUP_DIR/meta" ] && cp -a "$INSTALL_BACKUP_DIR/meta" "$LANDING_META"
    [ -f "$INSTALL_BACKUP_DIR/managed-marker" ] && cp -a "$INSTALL_BACKUP_DIR/managed-marker" "$SING_BOX_MANAGED_MARKER"
    [ -f "$INSTALL_BACKUP_DIR/wrapper" ] && cp -a "$INSTALL_BACKUP_DIR/wrapper" "$LANDING_BIN"
    # 共享核心可能正被其他协议运行，直接 cp 覆盖会因 Text file busy 失败；
    # 未变化时不动，变化时先复制到同目录临时文件再原子替换。
    if [ -f "$INSTALL_BACKUP_DIR/sing-box" ]; then
        if ! cmp -s "$INSTALL_BACKUP_DIR/sing-box" "$SING_BOX_BIN" 2>/dev/null; then
            cp -a "$INSTALL_BACKUP_DIR/sing-box" "${SING_BOX_BIN}.restore" && \
                mv -f "${SING_BOX_BIN}.restore" "$SING_BOX_BIN" || {
                rm -f "${SING_BOX_BIN}.restore"
                echo -e "${RED}恢复 sing-box 二进制失败，请在“升级 sing-box”中重新安装核心${PLAIN}" >&2
            }
        fi
    elif [ "$MANAGED_SING_BOX" = "1" ]; then
        rm -f "$SING_BOX_BIN"
    fi
    [ -f "$INSTALL_BACKUP_DIR/systemd-service" ] && cp -a "$INSTALL_BACKUP_DIR/systemd-service" "$SYSTEMD_SERVICE"
    [ -f "$INSTALL_BACKUP_DIR/openrc-service" ] && cp -a "$INSTALL_BACKUP_DIR/openrc-service" "$OPENRC_SERVICE"
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    [ -f "$INSTALL_BACKUP_DIR/was-enabled" ] && service_enable >/dev/null 2>&1 || true
    [ -f "$INSTALL_BACKUP_DIR/was-active" ] && service_start >/dev/null 2>&1 || true
    discard_install_backup
    read_config >/dev/null 2>&1 || true
}

close_replaced_install_port() {
    local _old_port="" _old_role=""
    [ -f "$INSTALL_BACKUP_DIR/meta/config.env" ] || return 0
    _old_role=$(awk -F= '$1 == "ROLE" { print $2; exit }' "$INSTALL_BACKUP_DIR/meta/config.env")
    [ "$_old_role" = "$ROLE" ] || return 0
    case "$ROLE" in
        exit) _old_port=$(awk -F= '$1 == "WG_PORT" { print $2; exit }' "$INSTALL_BACKUP_DIR/meta/config.env") ;;
        *) _old_port=$(awk -F= '$1 == "LISTEN_PORT" { print $2; exit }' "$INSTALL_BACKUP_DIR/meta/config.env") ;;
    esac
    validate_port "$_old_port" || return 0
    [ "$_old_port" = "$(role_port)" ] || close_ports "$_old_port" "$(role_proto)"
}

# ============================================================
# 服务管理
# ============================================================
write_systemd_service() {
    cat > "$SYSTEMD_SERVICE" <<SVC || return 1
[Unit]
Description=Landing Relay Server (sing-box WireGuard)
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${LANDING_BIN}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC
    chmod 600 "$SYSTEMD_SERVICE"
}

write_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD' || return 1
#!/sbin/openrc-run

name="landing-server"
description="Landing Relay Server (sing-box WireGuard)"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<SVC || return 1
command="${LANDING_BIN}"
command_args=""
command_background="yes"
pidfile="/var/run/landing-server.pid"
output_log="/var/log/landing-server.log"
error_log="/var/log/landing-server.log"

depend() {
    need net
    after firewall
}
SVC
    chmod +x "$OPENRC_SERVICE"
}

write_service_files() {
    if [ "$INIT_SYS" = "systemd" ]; then
        write_systemd_service
    elif [ "$INIT_SYS" = "openrc" ]; then
        write_openrc_service
    fi
}

service_start() {
    [ -x "$LANDING_BIN" ] && [ -f "$LANDING_CONFIG" ] || {
        echo -e "${RED}家宽中转尚未安装或配置不完整${PLAIN}"
        return 1
    }
    service_is_active && return 0
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start landing-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service landing-server start
    else
        nohup "$LANDING_BIN" >/var/log/landing-server.log 2>&1 &
        echo $! > /var/run/landing-server.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop landing-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service landing-server stop 2>/dev/null
    else
        if [ -f /var/run/landing-server.pid ]; then
            kill "$(cat /var/run/landing-server.pid)" 2>/dev/null || true
            rm -f /var/run/landing-server.pid
        fi
    fi
}

service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart landing-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service landing-server restart
    else
        service_stop; sleep 1; service_start
    fi
}

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable landing-server >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add landing-server default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable landing-server 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del landing-server default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet landing-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service landing-server status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/landing-server.pid ] && kill -0 "$(cat /var/run/landing-server.pid)" 2>/dev/null
    fi
}

service_is_enabled() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-enabled --quiet landing-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update show default 2>/dev/null | grep -qE '(^|[[:space:]])landing-server([[:space:]]|$)'
    else
        return 1
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u landing-server -n 80 --no-pager
    else
        tail -n 80 /var/log/landing-server.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

shared_service_is_active() {
    local _name="$1"
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet "$_name" 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service "$_name" status 2>/dev/null | grep -q "started"
    else
        [ -f "/var/run/${_name}.pid" ] && kill -0 "$(cat "/var/run/${_name}.pid")" 2>/dev/null
    fi
}

shared_service_restart() {
    local _name="$1" _bin="$2"
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart "$_name"
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service "$_name" restart
    else
        [ -x "$_bin" ] || return 1
        if [ -f "/var/run/${_name}.pid" ]; then
            kill "$(cat "/var/run/${_name}.pid")" 2>/dev/null || true
            rm -f "/var/run/${_name}.pid"
        fi
        nohup "$_bin" >"/var/log/${_name}.log" 2>&1 &
        echo $! > "/var/run/${_name}.pid"
    fi
}

service_is_healthy() {
    service_is_active || return 1
    case "$ROLE" in
        exit)
            validate_port "${WG_PORT:-}" || return 1
            udp_port_is_listening "$WG_PORT"
            ;;
        *)
            validate_port "${LISTEN_PORT:-}" || return 1
            tcp_port_is_listening "$LISTEN_PORT"
            ;;
    esac
}

# 带有界轮询的健康检查：最多等 _attempts 秒，首次立即检查。
wait_for_health() {
    local _attempts="${1:-12}" _check="${2:-service_is_healthy}" _i=0
    while [ "$_i" -lt "$_attempts" ]; do
        "$_check" && return 0
        _i=$((_i + 1))
        [ "$_i" -lt "$_attempts" ] && sleep 1
    done
    return 1
}

# ============================================================
# 出口验证（线路机）
# ============================================================
probe_via_tunnel() {
    local _url="$1"
    validate_port "${PROBE_PORT:-}" || return 1
    curl -s --connect-timeout 5 --max-time 10 \
        -x "socks5h://${PROBE_USER}:${PROBE_PASS}@127.0.0.1:${PROBE_PORT}" \
        "$_url" 2>/dev/null | extract_probe_ip
}

# 先用免 DNS 的字面量地址确认隧道已握手，再用域名确认 DNS 路径可用；
# 出口仍是线路机自身 IP 说明流量没有进入隧道，必须判定失败。
verify_exit_egress() {
    local _attempts="${1:-8}" _i=0 _ip="" _dns_ip="" _url
    LAST_EGRESS_IP=""
    while [ "$_i" -lt "$_attempts" ]; do
        _ip=$(probe_via_tunnel "$TUNNEL_IP_PROBE_URL" || true)
        is_valid_ipv4 "$_ip" && break
        _ip=""
        _i=$((_i + 1))
        [ "$_i" -lt "$_attempts" ] && sleep 3
    done
    if [ -z "$_ip" ]; then
        echo -e "${RED}✗ 经 WireGuard 隧道访问外网失败（隧道未握手或落地机无法出网）${PLAIN}"
        echo -e "${YELLOW}  常见原因：落地机面板 / 云防火墙未放行 UDP ${WG_PORT:-?}，或落地机地址填写错误${PLAIN}"
        return 1
    fi
    if [ -n "${PUBLIC_IP:-}" ] && [ "$_ip" = "$PUBLIC_IP" ] && [ "$_ip" != "${EXIT_IPV4:-}" ]; then
        echo -e "${RED}✗ 出口仍是线路机自身 IP (${_ip})，流量没有进入隧道${PLAIN}"
        return 1
    fi
    for _url in $TUNNEL_DNS_PROBE_URLS; do
        _dns_ip=$(probe_via_tunnel "$_url" || true)
        is_valid_ipv4 "$_dns_ip" && break
        _dns_ip=""
    done
    if [ -z "$_dns_ip" ]; then
        echo -e "${RED}✗ 隧道已通，但经落地机解析域名失败，请检查落地机的系统 DNS${PLAIN}"
        return 1
    fi
    LAST_EGRESS_IP="$_ip"
    if [ -n "${EXIT_IPV4:-}" ] && [ "$_ip" != "$EXIT_IPV4" ]; then
        echo -e "${YELLOW}! 出口 IP ${_ip} 与落地机自测 ${EXIT_IPV4} 不一致（落地机可能有多个出口），请留意${PLAIN}"
    fi
    echo -e "${GREEN}✓ 隧道出口验证通过，当前出口 IPv4: ${_ip}${PLAIN}"
    return 0
}

# ============================================================
# SSH 一键对接（线路机 → 落地机）
# ============================================================
ssh_supports_accept_new() {
    ssh -G -o StrictHostKeyChecking=accept-new localhost >/dev/null 2>&1
}

ssh_target() {
    printf '%s@%s' "$SSH_USER" "$EXIT_HOST"
}

ssh_build_opts() {
    SSH_OPTS=(-p "$SSH_PORT" -o "ControlPath=${SSH_CTL_DIR}/cm" -o ConnectTimeout=15
        -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o LogLevel=ERROR)
    # 首次连接自动记录主机指纹（与手动 ssh 首登一致）；已记录的指纹变化时 ssh 会拒绝连接。
    if ssh_supports_accept_new; then
        SSH_OPTS+=(-o StrictHostKeyChecking=accept-new)
    fi
}

# 建立一条复用的主连接：整个对接过程只需输入一次 SSH 密码，
# 密码由 ssh 自己在终端读取，脚本不接触、不保存。
ssh_open_master() {
    ssh_close_master
    SSH_CTL_DIR=$(mktemp -d /tmp/lssh.XXXXXX 2>/dev/null) || {
        echo -e "${RED}无法创建 SSH 控制目录${PLAIN}"
        return 1
    }
    chmod 700 "$SSH_CTL_DIR"
    ssh_build_opts
    echo -e "${YELLOW}正在连接落地机 $(ssh_target)（端口 ${SSH_PORT}）...${PLAIN}"
    echo -e "${DIM}如提示输入密码，请输入落地机 ${SSH_USER} 的 SSH 密码（输入时不显示）；脚本不会读取或保存密码。${PLAIN}"
    if ! ssh "${SSH_OPTS[@]}" -o ControlMaster=yes -o ControlPersist=900 -fN "$(ssh_target)" </dev/null; then
        echo -e "${RED}✗ 无法 SSH 登录落地机，请检查地址、SSH 端口、用户名与密码${PLAIN}"
        ssh_close_master
        return 1
    fi
    if ! ssh "${SSH_OPTS[@]}" -O check "$(ssh_target)" </dev/null >/dev/null 2>&1; then
        echo -e "${RED}✗ SSH 连接建立后立即断开，请重试${PLAIN}"
        ssh_close_master
        return 1
    fi
    echo -e "${GREEN}✓ 已连接落地机${PLAIN}"
    return 0
}

ssh_close_master() {
    if [ -n "$SSH_CTL_DIR" ] && [ -d "$SSH_CTL_DIR" ]; then
        [ "${#SSH_OPTS[@]}" -gt 0 ] && ssh "${SSH_OPTS[@]}" -O exit "$(ssh_target)" </dev/null >/dev/null 2>&1 || true
        rm -rf "$SSH_CTL_DIR"
    fi
    SSH_CTL_DIR=""
}

ssh_run() {
    ssh "${SSH_OPTS[@]}" -o ControlMaster=no -o BatchMode=yes -T "$(ssh_target)" "$@"
}

remote_sudo_prefix() {
    [ "$SSH_USER" = "root" ] && return 0
    printf 'sudo -n '
}

# 落地机上执行的脚本必须与线路机一致：优先使用当前文件，
# 经 bash <(curl ...) 运行时 $0 是管道，改为下载一份完整副本。
resolve_script_source() {
    LANDING_SCRIPT_SOURCE=""
    if [ -f "$SCRIPT_PATH" ] && grep -q 'LANDING_LIB_ONLY' "$SCRIPT_PATH" 2>/dev/null && bash -n "$SCRIPT_PATH" 2>/dev/null; then
        LANDING_SCRIPT_SOURCE="$SCRIPT_PATH"
        return 0
    fi
    LANDING_SCRIPT_TMP=$(mktemp "$(disk_tmp_dir)/landing-src.XXXXXX" 2>/dev/null) || return 1
    if download_file "$LANDING_SCRIPT_URL" "$LANDING_SCRIPT_TMP" && \
        bash -n "$LANDING_SCRIPT_TMP" 2>/dev/null && \
        grep -q 'LANDING_LIB_ONLY' "$LANDING_SCRIPT_TMP" 2>/dev/null; then
        LANDING_SCRIPT_SOURCE="$LANDING_SCRIPT_TMP"
        return 0
    fi
    cleanup_script_source
    echo -e "${RED}无法获取完整的 landing.sh 用于部署落地机${PLAIN}"
    return 1
}

cleanup_script_source() {
    [ -n "$LANDING_SCRIPT_TMP" ] && rm -f "$LANDING_SCRIPT_TMP"
    LANDING_SCRIPT_TMP=""
}

is_valid_remote_stage_dir() {
    printf '%s\n' "$1" | grep -qE '^/tmp/landing-remote\.[A-Za-z0-9]+$'
}

# 先把脚本落盘到落地机临时目录，再以 </dev/null 执行：
# 若直接 bash -s 从 stdin 读脚本，apt 等子进程可能吞掉后续脚本内容。
remote_stage_script() {
    local _out
    REMOTE_STAGE_DIR=""
    [ -n "$LANDING_SCRIPT_SOURCE" ] && [ -f "$LANDING_SCRIPT_SOURCE" ] || return 1
    _out=$(ssh_run 'umask 077; d=$(mktemp -d /tmp/landing-remote.XXXXXX) && cat > "$d/landing.sh" && printf "%s\n" "$d"' < "$LANDING_SCRIPT_SOURCE") || return 1
    _out=$(printf '%s\n' "$_out" | tail -n 1 | tr -d '\r')
    is_valid_remote_stage_dir "$_out" || return 1
    REMOTE_STAGE_DIR="$_out"
}

parse_remote_result() {
    awk '
        /^LANDING_EXIT_RESULT=/ { value=$0; sub(/^LANDING_EXIT_RESULT=/, "", value); last=value }
        END { if (last != "") print last }
    ' | tr -d '\r'
}

# 在落地机上执行 landing.sh 的远程动作；$2 可选为本地参数文件。
remote_landing_action() {
    local _action="$1" _params="${2:-}" _log _rc=0 _sudo
    REMOTE_RESULT=""
    case "$_action" in
        --remote-exit-install|--remote-exit-commit|--remote-exit-abort|--remote-exit-uninstall|--remote-exit-upgrade|--remote-exit-status) ;;
        *) return 1 ;;
    esac
    [ -n "$SSH_CTL_DIR" ] || return 1
    remote_stage_script || { echo -e "${RED}无法把脚本上传到落地机${PLAIN}"; return 1; }
    if [ -n "$_params" ]; then
        ssh_run "cat > '${REMOTE_STAGE_DIR}/params'" < "$_params" || {
            ssh_run "rm -rf '${REMOTE_STAGE_DIR}'" </dev/null >/dev/null 2>&1 || true
            echo -e "${RED}无法把对接参数上传到落地机${PLAIN}"
            return 1
        }
    fi
    _sudo=$(remote_sudo_prefix)
    _log=$(mktemp "$(disk_tmp_dir)/landing-remote-log.XXXXXX" 2>/dev/null) || return 1
    ssh_run "${_sudo}bash '${REMOTE_STAGE_DIR}/landing.sh' ${_action} '${REMOTE_STAGE_DIR}' </dev/null; _rc=\$?; rm -rf '${REMOTE_STAGE_DIR}'; exit \$_rc" \
        </dev/null 2>&1 | tee "$_log"
    _rc=${PIPESTATUS[0]}
    REMOTE_RESULT=$(parse_remote_result < "$_log")
    rm -f "$_log"
    return "$_rc"
}

# 解析落地机返回：公钥|端口|出口IPv4|是否有IPv6
apply_remote_result() {
    local _result="$1" _pub _port _ipv4 _v6
    [ -n "$_result" ] || return 1
    IFS='|' read -r _pub _port _ipv4 _v6 <<EOF
$_result
EOF
    validate_wg_key "$_pub" || return 1
    validate_port "$_port" || return 1
    [ -z "$_ipv4" ] || is_valid_ipv4 "$_ipv4" || return 1
    case "$_v6" in 0|1) ;; *) return 1 ;; esac
    WG_PEER_PUBLIC_KEY="$_pub"
    WG_PORT="$_port"
    EXIT_IPV4="$_ipv4"
    EXIT_HAS_IPV6="$_v6"
}

write_remote_params() {
    local _file
    _file=$(mktemp "$(disk_tmp_dir)/landing-params.XXXXXX" 2>/dev/null) || return 1
    chmod 600 "$_file" || { rm -f "$_file"; return 1; }
    printf 'RELAY_PUBLIC_KEY=%s\nWG_PSK=%s\nAUTO_UPDATE=%s\nWG_PORT=%s\n' \
        "$WG_PUBLIC_KEY" "$WG_PSK" "$AUTO_UPDATE" "$REQUESTED_WG_PORT" > "$_file" || {
        rm -f "$_file"
        return 1
    }
    printf '%s' "$_file"
}

read_remote_params() {
    local _file="$1/params" _line _key _value
    REMOTE_PARAM_PUBLIC_KEY=""
    REMOTE_PARAM_PSK=""
    REMOTE_PARAM_AUTO_UPDATE=1
    REMOTE_PARAM_WG_PORT=""
    [ -f "$_file" ] || return 1
    while IFS= read -r _line || [ -n "$_line" ]; do
        _key="${_line%%=*}"
        _value="${_line#*=}"
        case "$_key" in
            RELAY_PUBLIC_KEY) REMOTE_PARAM_PUBLIC_KEY="$_value" ;;
            WG_PSK) REMOTE_PARAM_PSK="$_value" ;;
            AUTO_UPDATE) REMOTE_PARAM_AUTO_UPDATE="$_value" ;;
            WG_PORT) REMOTE_PARAM_WG_PORT="$_value" ;;
        esac
    done < "$_file"
    rm -f "$_file"
    validate_wg_key "$REMOTE_PARAM_PUBLIC_KEY" || return 1
    validate_wg_key "$REMOTE_PARAM_PSK" || return 1
    [ -z "$REMOTE_PARAM_WG_PORT" ] || validate_port "$REMOTE_PARAM_WG_PORT" || return 1
    case "$REMOTE_PARAM_AUTO_UPDATE" in 0|1) ;; *) REMOTE_PARAM_AUTO_UPDATE=1 ;; esac
    return 0
}

# ============================================================
# 落地机远程动作（由线路机经 SSH 调用）
# ============================================================
# 两阶段提交：落地机先保留旧配置，线路机验证出口成功后再 commit；
# 线路机失败时 abort 恢复旧配置（无旧配置则卸载），不会留下半配置的落地机。
stage_pending_rollback() {
    rm -rf "$LANDING_PENDING_DIR"
    [ -f "$LANDING_CONFIG" ] && [ -d "$LANDING_META" ] || return 0
    mkdir -p "$LANDING_PENDING_DIR" && chmod 700 "$LANDING_PENDING_DIR" && \
        cp -a "$LANDING_CONFIG" "$LANDING_PENDING_DIR/config" && \
        cp -a "$LANDING_META" "$LANDING_PENDING_DIR/meta" || {
        rm -rf "$LANDING_PENDING_DIR"
        return 1
    }
    service_is_active && : > "$LANDING_PENDING_DIR/was-active" || true
    return 0
}

remote_exit_install() {
    local _stage="$1" _old_port=""
    check_root
    check_sys
    detect_init
    echo -e "${SKYBLUE}── 落地机：开始部署 WireGuard 落地端 ──${PLAIN}"
    is_valid_remote_stage_dir "$_stage" || { echo -e "${RED}无效的远程参数目录${PLAIN}"; return 1; }
    read_remote_params "$_stage" || { echo -e "${RED}对接参数无效，已取消${PLAIN}"; return 1; }
    if [ "$(installed_role 2>/dev/null)" = "relay" ]; then
        echo -e "${RED}该机器已部署为线路机（中转端），不能同时作为落地机${PLAIN}"
        return 1
    fi
    install_dependencies || return 1
    echo -e "${YELLOW}正在检测落地机出口...${PLAIN}"
    detect_exit_egress
    if [ -z "$EXIT_IPV4" ]; then
        echo -e "${RED}落地机无法访问 IPv4 外网，不能作为出口${PLAIN}"
        return 1
    fi
    echo -e "${GREEN}✓ 落地机出口 IPv4: ${EXIT_IPV4}${PLAIN}"

    if [ "$(installed_role 2>/dev/null)" = "exit" ]; then
        _old_port=$(awk -F= '$1 == "WG_PORT" { print $2; exit }' "$LANDING_META/config.env" 2>/dev/null)
        validate_port "$_old_port" || _old_port=""
    fi
    stage_pending_rollback || { echo -e "${RED}无法保存落地机现有配置，已取消${PLAIN}"; return 1; }
    backup_current_install || { rm -rf "$LANDING_PENDING_DIR"; echo -e "${RED}无法创建安装备份${PLAIN}"; return 1; }
    if ! ensure_singbox_bin; then
        restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1
    fi

    ROLE="exit"
    HAS_IPV6="$EXIT_HAS_IPV6"
    if [ -n "$REMOTE_PARAM_WG_PORT" ]; then
        if [ "$REMOTE_PARAM_WG_PORT" != "$_old_port" ] && udp_port_is_listening "$REMOTE_PARAM_WG_PORT"; then
            echo -e "${RED}落地机 UDP ${REMOTE_PARAM_WG_PORT} 已被占用，请换一个端口${PLAIN}"
            restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1
        fi
        WG_PORT="$REMOTE_PARAM_WG_PORT"
    elif [ -n "$_old_port" ]; then
        WG_PORT="$_old_port"
    else
        WG_PORT=$(generate_random_port) || { restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1; }
    fi
    if ! generate_wg_keypair; then
        echo -e "${RED}生成 WireGuard 密钥失败${PLAIN}"
        restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1
    fi
    WG_PEER_PUBLIC_KEY="$REMOTE_PARAM_PUBLIC_KEY"
    WG_PSK="$REMOTE_PARAM_PSK"
    AUTO_UPDATE="$REMOTE_PARAM_AUTO_UPDATE"
    PUBLIC_IP="$EXIT_IPV4"
    PUBLIC_IPV6=""

    if ! write_config || ! write_meta || ! write_wrapper || ! check_config; then
        echo -e "${RED}落地端配置写入或校验失败${PLAIN}"
        restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1
    fi
    if ! write_service_files || ! service_enable || ! open_ports "$WG_PORT" udp; then
        restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1
    fi
    if service_is_active; then
        service_restart || { restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1; }
    else
        service_start || { restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1; }
    fi
    if ! wait_for_health; then
        echo -e "${RED}✗ 落地端启动失败，日志如下：${PLAIN}"
        service_logs
        restore_current_install; rm -rf "$LANDING_PENDING_DIR"; return 1
    fi
    discard_install_backup
    if [ "$AUTO_UPDATE" = "1" ]; then
        setup_auto_update quiet || true
    fi
    echo -e "${GREEN}✓ 落地端已启动，监听 UDP ${WG_PORT}${PLAIN}"
    echo "LANDING_EXIT_RESULT=${WG_PUBLIC_KEY}|${WG_PORT}|${EXIT_IPV4}|${EXIT_HAS_IPV6}"
    return 0
}

remote_exit_commit() {
    check_root
    rm -rf "$LANDING_PENDING_DIR"
    echo -e "${GREEN}✓ 落地机配置已确认生效${PLAIN}"
}

remote_exit_abort() {
    check_root
    check_sys
    detect_init
    if [ -d "$LANDING_PENDING_DIR" ] && [ -f "$LANDING_PENDING_DIR/config" ] && [ -d "$LANDING_PENDING_DIR/meta" ]; then
        service_stop
        rm -rf "$LANDING_META"
        cp -a "$LANDING_PENDING_DIR/config" "$LANDING_CONFIG" && \
            cp -a "$LANDING_PENDING_DIR/meta" "$LANDING_META" || {
            echo -e "${RED}落地机旧配置恢复失败，备份保留在 ${LANDING_PENDING_DIR}${PLAIN}"
            return 1
        }
        read_config >/dev/null 2>&1 || true
        if [ -f "$LANDING_PENDING_DIR/was-active" ]; then
            service_start >/dev/null 2>&1 || true
            wait_for_health >/dev/null 2>&1 || echo -e "${YELLOW}! 落地机旧配置已恢复，但服务未能确认启动${PLAIN}"
        fi
        rm -rf "$LANDING_PENDING_DIR"
        echo -e "${YELLOW}已恢复落地机原有配置${PLAIN}"
        return 0
    fi
    uninstall_landing_files
    echo -e "${YELLOW}已清理本次在落地机上的部署${PLAIN}"
}

remote_exit_uninstall() {
    check_root
    check_sys
    detect_init
    if [ "$(installed_role 2>/dev/null)" = "relay" ]; then
        echo -e "${RED}该机器是线路机，拒绝按落地机卸载${PLAIN}"
        return 1
    fi
    uninstall_landing_files
    echo -e "${GREEN}✓ 落地机上的落地端已卸载${PLAIN}"
}

remote_exit_upgrade() {
    check_root
    check_sys
    detect_init
    install_dependencies || return 1
    upgrade_core
}

remote_exit_status() {
    check_root
    check_sys
    detect_init
    if [ "$(installed_role 2>/dev/null)" != "exit" ] || ! read_config >/dev/null 2>&1; then
        echo -e "${RED}✗ 落地机未部署落地端，或配置已损坏${PLAIN}"
        return 1
    fi
    service_is_active && echo -e "  ${GREEN}✓ 落地端服务运行中${PLAIN}" || echo -e "  ${RED}✗ 落地端服务未运行${PLAIN}"
    udp_port_is_listening "$WG_PORT" && echo -e "  ${GREEN}✓ UDP ${WG_PORT} 正在监听${PLAIN}" || echo -e "  ${RED}✗ 未检测到 UDP ${WG_PORT} 监听${PLAIN}"
    detect_exit_egress
    [ -n "$EXIT_IPV4" ] && echo -e "  ${GREEN}✓ 落地机出口 IPv4: ${EXIT_IPV4}${PLAIN}" || echo -e "  ${RED}✗ 落地机无法访问 IPv4 外网${PLAIN}"
    echo -e "  ${DIM}若服务与监听正常但线路机无法握手，请在落地机面板 / 云防火墙放行 UDP ${WG_PORT}${PLAIN}"
}

# ============================================================
# 卸载（两种角色共用，非交互）
# ============================================================
uninstall_landing_files() {
    read_config >/dev/null 2>&1 || ROLE=$(installed_role 2>/dev/null || true)
    if [ -z "$WG_PORT" ] && [ -f "$LANDING_META/config.env" ]; then
        WG_PORT=$(awk -F= '$1 == "WG_PORT" { print $2; exit }' "$LANDING_META/config.env")
        LISTEN_PORT=$(awk -F= '$1 == "LISTEN_PORT" { print $2; exit }' "$LANDING_META/config.env")
        MANAGED_SING_BOX=$(awk -F= '$1 == "MANAGED_SING_BOX" { print $2; exit }' "$LANDING_META/config.env")
    fi
    local _managed_core=0 _other_file=""
    if [ "$MANAGED_SING_BOX" = "1" ] || [ -f "$SING_BOX_MANAGED_MARKER" ]; then
        _managed_core=1
    fi
    if [ "$MANAGED_SING_BOX" = "1" ]; then
        mkdir -p "$LANDING_DIR" 2>/dev/null || true
        : > "$SING_BOX_MANAGED_MARKER" 2>/dev/null || true
    fi
    service_stop
    service_disable
    close_ports "$(role_port)" "$(role_proto)"
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vF "$AUTO_UPDATE_SCRIPT" | crontab - 2>/dev/null || true
    fi
    rm -f "$SYSTEMD_SERVICE" "$OPENRC_SERVICE" "$AUTO_UPDATE_SCRIPT" "$LANDING_BIN"
    rm -f "$LANDING_CONFIG" "$AUTO_UPDATE_LOG"
    rm -rf "$LANDING_META" "$LANDING_PENDING_DIR"
    if [ -d "$LANDING_DIR" ]; then
        _other_file=$(find "$LANDING_DIR" -mindepth 1 -maxdepth 1 ! -name '.singbox-tools-managed' -print -quit 2>/dev/null)
    fi
    if [ -z "$_other_file" ]; then
        rm -f "$SING_BOX_MANAGED_MARKER"
        rmdir "$LANDING_DIR" 2>/dev/null || true
        [ "$_managed_core" = "1" ] && rm -f "$SING_BOX_BIN"
    elif [ "$_managed_core" = "1" ]; then
        echo -e "${YELLOW}检测到 /etc/sing-box 中还有其他协议文件，已保留共享 sing-box 二进制${PLAIN}"
    fi
    rm -f /var/run/landing-server.pid
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    return 0
}

# ============================================================
# 线路机：一键部署
# ============================================================
configure_relay_vless() {
    local _default_port
    _default_port=$(generate_random_port) || { echo -e "${RED}无法生成可用随机端口${PLAIN}"; return 1; }
    echo -e "\n${SKYBLUE}--- 线路机节点参数（VLESS + REALITY + Vision）---${PLAIN}"
    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "请输入本机监听端口 [随机默认 ${_default_port}]: " LISTEN_PORT
        [ -z "$LISTEN_PORT" ] && LISTEN_PORT="$_default_port"
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        read -r -p "请输入对外转发端口 [留空=与监听端口相同]: " EXT_PORT
        [ -z "$EXT_PORT" ] && EXT_PORT="$LISTEN_PORT"
        validate_port "$EXT_PORT" || { echo -e "${RED}对外端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        echo -e "${YELLOW}提示：请确保宿主机已将 TCP ${EXT_PORT} 转发到本机 TCP ${LISTEN_PORT}${PLAIN}"
    else
        read -r -p "请输入节点端口 [随机默认 ${_default_port}]: " LISTEN_PORT
        [ -z "$LISTEN_PORT" ] && LISTEN_PORT="$_default_port"
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        EXT_PORT="$LISTEN_PORT"
    fi
    if port_is_listening "$LISTEN_PORT"; then
        echo -e "${RED}端口 ${LISTEN_PORT} 已被占用，请换一个端口${PLAIN}"
        return 1
    fi
    UUID=$(generate_uuid) || { echo -e "${RED}生成 UUID 失败${PLAIN}"; return 1; }
    HANDSHAKE_PORT="443"
    choose_reality_target "$HANDSHAKE_PORT" || return 1
    echo -e "${YELLOW}正在生成 REALITY 密钥对...${PLAIN}"
    generate_reality_keypair || { echo -e "${RED}生成 REALITY 密钥对失败${PLAIN}"; return 1; }
    SHORT_ID=$(generate_short_id) || { echo -e "${RED}生成 REALITY short ID 失败${PLAIN}"; return 1; }
    echo -e "${GREEN}✓ UUID、REALITY 密钥与 short ID 已生成${PLAIN}"
    return 0
}

prompt_exit_target() {
    local _input _default_host="${EXIT_HOST:-}" _default_port="${SSH_PORT:-22}" _default_user="${SSH_USER:-root}"
    echo -e "\n${SKYBLUE}--- 落地机（家宽机）信息 ---${PLAIN}"
    echo -e "${DIM}落地机需要：能 SSH 登录、有公网 IPv4 出口、可放行一个 UDP 端口。${PLAIN}"
    while true; do
        if [ -n "$_default_host" ]; then
            read -r -p "落地机公网 IP 或域名 [当前 ${_default_host}]: " _input
            [ -z "$_input" ] && _input="$_default_host"
        else
            read -r -p "落地机公网 IP 或域名: " _input
        fi
        _input=$(trim_string "$_input")
        _input="${_input#[}"
        _input="${_input%]}"
        if ! validate_exit_host "$_input"; then
            echo -e "${RED}地址格式无效，请输入纯 IP 或域名（不含端口、协议）${PLAIN}"
            continue
        fi
        if [ -n "${PUBLIC_IP:-}" ] && [ "$_input" = "$PUBLIC_IP" ]; then
            echo -e "${RED}落地机地址与本机相同；请在线路机上运行，并填写另一台落地机的地址${PLAIN}"
            continue
        fi
        break
    done
    EXIT_HOST="$_input"
    while true; do
        read -r -p "落地机 SSH 端口 [默认 ${_default_port}]: " _input
        [ -z "$_input" ] && _input="$_default_port"
        validate_port "$_input" && break
        echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"
    done
    SSH_PORT="$_input"
    while true; do
        read -r -p "落地机 SSH 用户 [默认 ${_default_user}]: " _input
        [ -z "$_input" ] && _input="$_default_user"
        validate_ssh_user "$_input" && break
        echo -e "${RED}用户名格式无效${PLAIN}"
    done
    SSH_USER="$_input"
    [ "$SSH_USER" = "root" ] || echo -e "${YELLOW}提示：非 root 用户需在落地机配置免密 sudo（sudo -n）${PLAIN}"
    echo -e "${DIM}落地机隧道使用一个 UDP 端口。家宽机在路由器后面时，请先在路由器把该 UDP 端口转发到落地机，再在此填写。${PLAIN}"
    while true; do
        if validate_port "${WG_PORT:-}"; then
            read -r -p "落地机 WireGuard UDP 端口 [当前 ${WG_PORT}，输入 0 改为随机]: " _input
            [ -z "$_input" ] && _input="$WG_PORT"
        else
            read -r -p "落地机 WireGuard UDP 端口 [留空随机]: " _input
        fi
        case "$_input" in
            ""|0) REQUESTED_WG_PORT=""; break ;;
        esac
        if validate_port "$_input" && [ "$_input" -ge 1024 ]; then
            REQUESTED_WG_PORT="$_input"
            break
        fi
        echo -e "${RED}端口必须为 1024-65535 的整数${PLAIN}"
    done
    read -r -p "落地机开启每周自动更新 sing-box（推荐）？[Y/n]: " _input
    case "$_input" in
        [nN]*) AUTO_UPDATE=0 ;;
        *) AUTO_UPDATE=1 ;;
    esac
    return 0
}

prepare_probe_inbound() {
    local _port
    while true; do
        _port=$(generate_random_port) || return 1
        [ "$_port" != "$LISTEN_PORT" ] && break
    done
    PROBE_PORT="$_port"
    PROBE_USER=$(generate_probe_secret) || return 1
    PROBE_PASS=$(generate_probe_secret) || return 1
}

deploy_fail() {
    local _message="$1"
    echo -e "${RED}${_message}${PLAIN}"
    if [ "$LANDING_REMOTE_COMMITTABLE" = "1" ]; then
        echo -e "${YELLOW}正在撤销落地机上的本次部署...${PLAIN}"
        remote_landing_action --remote-exit-abort || echo -e "${RED}落地机撤销失败，请在落地机运行本脚本并选择卸载${PLAIN}"
        LANDING_REMOTE_COMMITTABLE=0
    fi
    restore_current_install
    ssh_close_master
    cleanup_script_source
    echo -e "${YELLOW}线路机已恢复到部署前状态${PLAIN}"
    read -r -p "按回车键返回主菜单..." _
    return 1
}

print_deploy_intro() {
    echo -e "${SKYBLUE}===============================================${PLAIN}"
    echo -e "${GREEN}  一键部署：线路机 + 落地机（家宽机）${PLAIN}"
    echo -e "${SKYBLUE}===============================================${PLAIN}"
    echo -e "  客户端 ──VLESS REALITY──▶ ${BOLD}本机（线路机）${PLAIN} ══WireGuard══▶ ${BOLD}落地机${PLAIN} ──▶ 互联网"
    echo -e "  ${DIM}只需在本机操作：脚本会 SSH 登录落地机自动部署，并验证出口 IP。${PLAIN}"
    echo -e "  ${DIM}只有本节点的流量从落地机出网；本机 SSH、系统更新和其他协议保持直连。${PLAIN}"
    echo -e "  ${DIM}两端均不修改系统路由、不开启 ip_forward，失败会自动回滚。${PLAIN}"
    echo -e "${SKYBLUE}-----------------------------------------------${PLAIN}"
}

deploy_landing() {
    local _role _reuse=0 _answer _params="" _remote_ok=0
    clear_screen
    print_deploy_intro
    _role=$(installed_role 2>/dev/null || true)
    if [ "$_role" = "exit" ]; then
        echo -e "${RED}本机已部署为落地机。请在线路机上运行本脚本进行对接。${PLAIN}"
        read -r -p "按回车键返回主菜单..." _
        return 1
    fi
    install_dependencies || { read -r -p "按回车键返回主菜单..." _; return 1; }
    ensure_ssh_client || { read -r -p "按回车键返回主菜单..." _; return 1; }

    if [ "$_role" = "relay" ] && read_config >/dev/null 2>&1; then
        echo -e "${YELLOW}检测到已有家宽中转节点。${PLAIN}"
        read -r -p "保留现有节点参数（客户端无需更新链接）？[Y/n]: " _answer
        case "$_answer" in
            [nN]*) _reuse=0 ;;
            *) _reuse=1 ;;
        esac
    else
        reset_config_vars
    fi
    detect_network
    if [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "0" ]; then
        echo -e "${RED}本机网络不可用，无法部署${PLAIN}"
        read -r -p "按回车键返回主菜单..." _
        return 1
    fi

    prompt_exit_target || return 1

    backup_current_install || {
        echo -e "${RED}无法创建安装备份，已取消操作${PLAIN}"
        read -r -p "按回车键返回主菜单..." _
        return 1
    }
    LANDING_REMOTE_COMMITTABLE=0
    ensure_singbox_bin || { deploy_fail "sing-box 安装失败"; return 1; }
    ROLE="relay"
    if [ "$_reuse" = "0" ]; then
        configure_relay_vless || { deploy_fail "节点参数配置失败"; return 1; }
    fi
    prepare_probe_inbound || { deploy_fail "无法生成本机探测入口参数"; return 1; }
    generate_wg_keypair || { deploy_fail "生成 WireGuard 密钥失败"; return 1; }
    WG_PSK=$(generate_wg_psk) || { deploy_fail "生成 WireGuard 预共享密钥失败"; return 1; }
    resolve_script_source || { deploy_fail "无法准备落地机部署脚本"; return 1; }

    echo ""
    ssh_open_master || { deploy_fail "SSH 连接落地机失败"; return 1; }
    _params=$(write_remote_params) || { deploy_fail "无法生成对接参数"; return 1; }
    echo -e "${YELLOW}正在落地机上部署落地端（首次需下载 sing-box，请稍候）...${PLAIN}"
    if remote_landing_action --remote-exit-install "$_params"; then
        _remote_ok=1
    fi
    rm -f "$_params"
    if [ "$_remote_ok" = "1" ] && apply_remote_result "$REMOTE_RESULT"; then
        LANDING_REMOTE_COMMITTABLE=1
    elif [ "$_remote_ok" = "1" ]; then
        LANDING_REMOTE_COMMITTABLE=1
        deploy_fail "落地机返回结果无效"
        return 1
    else
        deploy_fail "落地机部署失败（落地机已自动恢复原状）"
        return 1
    fi

    echo -e "${YELLOW}正在配置线路机...${PLAIN}"
    if ! write_config || ! write_meta || ! write_wrapper; then
        deploy_fail "线路机配置写入失败"
        return 1
    fi
    if ! check_config; then
        deploy_fail "线路机 sing-box 配置校验失败"
        return 1
    fi
    if ! write_service_files || ! service_enable; then
        deploy_fail "线路机服务注册失败"
        return 1
    fi
    if ! open_ports "$LISTEN_PORT" tcp; then
        deploy_fail "线路机防火墙放行失败"
        return 1
    fi
    if service_is_active; then
        service_restart || { deploy_fail "线路机服务重启失败"; return 1; }
    else
        service_start || { deploy_fail "线路机服务启动失败"; return 1; }
    fi
    if ! wait_for_health; then
        service_logs
        deploy_fail "线路机服务未能正常监听 TCP ${LISTEN_PORT}"
        return 1
    fi
    echo -e "${YELLOW}正在验证隧道与出口 IP（最多约 30 秒）...${PLAIN}"
    if ! verify_exit_egress 8; then
        deploy_fail "出口验证失败"
        return 1
    fi

    remote_landing_action --remote-exit-commit >/dev/null 2>&1 || \
        echo -e "${YELLOW}! 落地机确认步骤未完成，不影响使用${PLAIN}"
    LANDING_REMOTE_COMMITTABLE=0
    ssh_close_master
    cleanup_script_source
    close_replaced_install_port
    discard_install_backup
    echo -e "${GREEN}✓ 部署完成：客户端流量将从落地机 ${LAST_EGRESS_IP} 出网${PLAIN}"
    show_config
}

# 家宽换 IP 或改用 DDNS 域名后，只需修改线路机里的落地机地址，无需 SSH。
update_exit_address() {
    local _input _old_host _was_active=0
    if [ "$(installed_role 2>/dev/null)" != "relay" ] || ! read_config >/dev/null 2>&1; then
        echo -e "${RED}本机不是已部署的线路机${PLAIN}"; sleep 2; return 1
    fi
    _old_host="$EXIT_HOST"
    echo -e "${DIM}当前落地机地址: ${EXIT_HOST}（UDP ${WG_PORT}）${PLAIN}"
    read -r -p "新的落地机公网 IP 或域名 [留空取消]: " _input
    _input=$(trim_string "$_input")
    _input="${_input#[}"
    _input="${_input%]}"
    [ -n "$_input" ] || return 0
    validate_exit_host "$_input" || { echo -e "${RED}地址格式无效${PLAIN}"; sleep 2; return 1; }
    cp -p "$LANDING_CONFIG" "${LANDING_CONFIG}.bak" && cp -p "$LANDING_META/config.env" "$LANDING_META/config.env.bak" || {
        rm -f "${LANDING_CONFIG}.bak" "$LANDING_META/config.env.bak"
        echo -e "${RED}无法备份当前配置，已取消${PLAIN}"; return 1
    }
    service_is_active && _was_active=1 || true
    EXIT_HOST="$_input"
    if write_config && write_meta && check_config && service_restart && wait_for_health && verify_exit_egress 6; then
        rm -f "${LANDING_CONFIG}.bak" "$LANDING_META/config.env.bak"
        echo -e "${GREEN}✓ 落地机地址已更新为 ${EXIT_HOST}${PLAIN}"
        return 0
    fi
    mv -f "${LANDING_CONFIG}.bak" "$LANDING_CONFIG" 2>/dev/null || true
    mv -f "$LANDING_META/config.env.bak" "$LANDING_META/config.env" 2>/dev/null || true
    EXIT_HOST="$_old_host"
    read_config >/dev/null 2>&1 || true
    [ "$_was_active" = "0" ] || service_restart >/dev/null 2>&1 || true
    echo -e "${RED}新地址验证失败，已恢复为 ${_old_host}${PLAIN}"
    return 1
}

# ============================================================
# 节点展示
# ============================================================
export_mihomo_vless() {
    local _server="$1" _port="$2" _node="$3" _yaml_server _safe_node _sni
    _yaml_server=$(format_server_for_yaml "$_server")
    _safe_node=$(yaml_single_quote_escape "$_node")
    _sni=$(yaml_single_quote_escape "$SERVER_NAME")
    printf '%s' "- {name: '${_safe_node}', type: vless, server: ${_yaml_server}, port: ${_port}, uuid: '${UUID}', network: tcp, udp: true, packet-encoding: xudp, tls: true, servername: '${_sni}', flow: xtls-rprx-vision, client-fingerprint: chrome, reality-opts: {public-key: '${REALITY_PUBLIC_KEY}', short-id: '${SHORT_ID}'}}"
}

export_loon_vless() {
    local _server="$1" _port="$2" _node="$3"
    printf '%s = VLESS, %s, %s, "%s", transport=tcp, flow=xtls-rprx-vision, public-key="%s", short-id=%s, udp=true, over-tls=true, sni=%s, skip-cert-verify=true' \
        "$_node" "$_server" "$_port" "$UUID" "$REALITY_PUBLIC_KEY" "$SHORT_ID" "$SERVER_NAME"
}

export_surfboard_vless() {
    printf 'Surfboard 暂无经官方文档确认的 VLESS + REALITY 配置格式，请使用 URI 或 Mihomo 配置。'
}

export_shadowrocket_vless() {
    render_uri "$1" "$2" "$UUID" "$3" "$SERVER_NAME" "$REALITY_PUBLIC_KEY" "$SHORT_ID"
}

export_quantumultx_vless() {
    local _server="$1" _port="$2" _node="$3" _host
    _host=$(format_ipv6_for_uri "$_server")
    printf 'vless=%s:%s, method=none, password=%s, obfs=over-tls, obfs-host=%s, reality-base64-pubkey=%s, reality-hex-shortid=%s, vless-flow=xtls-rprx-vision, udp-relay=true, tag=%s' \
        "$_host" "$_port" "$UUID" "$SERVER_NAME" "$REALITY_PUBLIC_KEY" "$SHORT_ID" "$_node"
}

should_show_output() {
    local _mode="${1:-all}" _section="$2"
    [ "$_mode" = "all" ] || [ "$_mode" = "$_section" ]
}

show_node() {
    local _server="$1" _port="$2" _tag="$3" _mode="${4:-all}" _country="${5:-UN}"
    [ -z "$_server" ] && return
    validate_server_address "$_server" || {
        echo -e "${RED}节点地址格式无效: ${_server}${PLAIN}"
        return 1
    }

    local _ip_type _server_name _node _uri _qr_url _png
    case "$_tag" in
        v6|IPv6|ipv6) _ip_type="IPv6" ;;
        *)            _ip_type="IPv4" ;;
    esac
    _server_name=$(generate_server_name)
    _node=$(generate_node_name "$_country" "$_server_name" "VLESS-Landing" "$_ip_type")

    _uri=$(render_uri "$_server" "$_port" "$UUID" "$_node" "$SERVER_NAME" "$REALITY_PUBLIC_KEY" "$SHORT_ID")
    _qr_url=$(generate_online_qrcode_url "$_uri")

    echo -e "${YELLOW}节点名称:${PLAIN}"
    print_copy_block "$_node"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    if should_show_output "$_mode" "uri"; then
        echo -e "${GREEN}URI 分享链接:${PLAIN}"
        print_copy_block "$_uri"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
    if should_show_output "$_mode" "mihomo"; then
        echo -e "${GREEN}Mihomo / Clash Meta / Clash Verge 单行配置:${PLAIN}"
        print_copy_block "$(export_mihomo_vless "$_server" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
    if should_show_output "$_mode" "surfboard"; then
        echo -e "${GREEN}Surfboard 配置:${PLAIN}"
        print_copy_block "$(export_surfboard_vless)"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
    if should_show_output "$_mode" "shadowrocket"; then
        echo -e "${GREEN}Shadowrocket 配置:${PLAIN}"
        print_copy_block "$(export_shadowrocket_vless "$_server" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
    if should_show_output "$_mode" "loon"; then
        echo -e "${GREEN}Loon 配置:${PLAIN}"
        print_copy_block "$(export_loon_vless "$_server" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
    if should_show_output "$_mode" "quantumult"; then
        echo -e "${GREEN}Quantumult X 配置:${PLAIN}"
        print_copy_block "$(export_quantumultx_vless "$_server" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
    if should_show_output "$_mode" "qrcode"; then
        echo -e "${GREEN}二维码:${PLAIN}"
        if generate_terminal_qrcode "$_uri"; then
            echo -e "${GREEN}[OK] 终端二维码已生成${PLAIN}"
            _png=$(generate_local_qrcode_png "$_uri" "vless-landing" "$_ip_type" 2>/dev/null || true)
            [ -n "$_png" ] && echo -e "本地二维码图片: ${YELLOW}${_png}${PLAIN}"
        else
            echo -e "${YELLOW}[WARN] 未安装 qrencode，跳过终端和本地 PNG 二维码。${PLAIN}"
        fi
        echo -e "${YELLOW}[WARN] 在线二维码会把节点链接提交给第三方服务，不建议公开节点使用。${PLAIN}"
        print_copy_block "$_qr_url"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
}

show_exit_role_info() {
    echo -e "\n${GREEN}本机角色：落地机（家宽机）${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    service_is_active && echo -e "服务状态 : ${GREEN}运行中${PLAIN}" || echo -e "服务状态 : ${RED}已停止${PLAIN}"
    echo -e "监听端口 : ${YELLOW}UDP ${WG_PORT}${PLAIN}"
    [ -n "$EXIT_IPV4" ] && echo -e "出口 IPv4: ${YELLOW}${EXIT_IPV4}${PLAIN}"
    echo -e "${DIM}落地机没有客户端节点；节点链接请在线路机上查看。${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

show_config() {
    local _mode="${1:-all}" _country _manual_addr
    if ! read_config >/dev/null 2>&1; then
        echo -e "${RED}未找到家宽中转配置，请先在线路机执行一键部署${PLAIN}"
        sleep 2
        return 1
    fi
    if [ "$ROLE" = "exit" ]; then
        show_exit_role_info
        read -r -p "按回车键返回主菜单..." _
        return 0
    fi
    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        PUBLIC_IP=$(get_native_public_ipv4 2>/dev/null || get_default_public_ipv4 2>/dev/null || true)
        PUBLIC_IPV6=$(get_default_public_ipv6 2>/dev/null || true)
    fi
    _country=$(get_country_code "$EXIT_IPV4" "")

    echo -e "\n${GREEN}家宽中转节点（VLESS REALITY → WireGuard → 落地机）${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    [ -n "$PUBLIC_IP"   ] && echo -e "线路机 IPv4: ${YELLOW}${PUBLIC_IP}${PLAIN}"
    [ -n "$PUBLIC_IPV6" ] && echo -e "线路机 IPv6: ${YELLOW}${PUBLIC_IPV6}${PLAIN}"
    if [ "$NAT_MODE" = "1" ] && [ "$EXT_PORT" != "$LISTEN_PORT" ]; then
        echo -e "监听端口  : ${YELLOW}${LISTEN_PORT}${PLAIN}  ${RED}← 本机监听${PLAIN}"
        echo -e "对外端口  : ${YELLOW}${EXT_PORT}${PLAIN}  ${RED}← 客户端连接此端口${PLAIN}"
    else
        echo -e "节点端口  : ${YELLOW}${EXT_PORT}${PLAIN}"
    fi
    echo -e "伪装 SNI  : ${YELLOW}${SERVER_NAME}:${HANDSHAKE_PORT}${PLAIN}"
    echo -e "落地机    : ${YELLOW}${EXIT_HOST}${PLAIN}（UDP ${WG_PORT}）"
    echo -e "落地出口  : ${YELLOW}${EXIT_IPV4:-未知}${PLAIN}（${_country} / $(get_country_name "$_country")）"
    echo -e "${DIM}客户端连接线路机，网站看到的是落地机出口 IP。${PLAIN}"
    echo -e "${DIM}提示: 客户端 DNS 须经本节点（Mihomo 开启 fake-ip 或 nameserver 走节点），否则可能泄露本地 DNS。${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    if [ -n "$PUBLIC_IP" ]; then
        echo -e "${YELLOW}▼ IPv4 节点配置${PLAIN}"
        show_node "$PUBLIC_IP" "$EXT_PORT" "v4" "$_mode" "$_country"
    fi
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "${YELLOW}▼ IPv6 节点配置${PLAIN}"
        show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6" "$_mode" "$_country"
    fi
    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        read -r -p "未检测到线路机公网 IP，请手动输入节点地址: " _manual_addr
        if [ -n "$_manual_addr" ]; then
            echo -e "${YELLOW}▼ 手动地址节点配置${PLAIN}"
            show_node "$_manual_addr" "$EXT_PORT" "manual" "$_mode" "$_country"
        fi
    fi
    read -r -p "按回车键返回主菜单..." _
}

# ============================================================
# 诊断
# ============================================================
diagnose_landing() {
    local _confirm
    echo -e "\n${GREEN}家宽中转诊断${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    if [ ! -f "$LANDING_CONFIG" ] && [ ! -f "$LANDING_META/config.env" ]; then
        echo -e "  ${RED}✗ 配置文件与元数据均缺失（未部署或已回滚）${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        return 1
    elif [ ! -f "$LANDING_CONFIG" ]; then
        echo -e "  ${RED}✗ 配置文件缺失: ${LANDING_CONFIG}，请重新部署${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        return 1
    elif [ ! -f "$LANDING_META/config.env" ]; then
        echo -e "  ${RED}✗ 元数据缺失: ${LANDING_META}/config.env，请重新部署${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        return 1
    elif ! read_config >/dev/null 2>&1; then
        echo -e "  ${RED}✗ 元数据校验失败，建议重新部署${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        return 1
    fi

    if check_config >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓ sing-box 配置有效${PLAIN}"
    else
        echo -e "  ${RED}✗ sing-box 配置无效${PLAIN}"
        check_config 2>&1 | sed 's/^/    /'
    fi
    if service_is_active; then
        echo -e "  ${GREEN}✓ 服务运行中${PLAIN}"
    else
        echo -e "  ${RED}✗ 服务未运行${PLAIN}"
    fi

    if [ "$ROLE" = "exit" ]; then
        echo -e "  ${DIM}本机角色: 落地机${PLAIN}"
        udp_port_is_listening "$WG_PORT" && echo -e "  ${GREEN}✓ UDP ${WG_PORT} 正在监听${PLAIN}" || echo -e "  ${RED}✗ 未检测到 UDP ${WG_PORT} 监听${PLAIN}"
        detect_exit_egress
        [ -n "$EXIT_IPV4" ] && echo -e "  ${GREEN}✓ 出口 IPv4: ${EXIT_IPV4}${PLAIN}" || echo -e "  ${RED}✗ 无法访问 IPv4 外网${PLAIN}"
        echo -e "  ${DIM}请确认落地机面板 / 云防火墙已放行 UDP ${WG_PORT}${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        return 0
    fi

    echo -e "  ${DIM}本机角色: 线路机 | 落地机: ${EXIT_HOST} UDP ${WG_PORT}${PLAIN}"
    tcp_port_is_listening "$LISTEN_PORT" && echo -e "  ${GREEN}✓ TCP ${LISTEN_PORT} 正在监听${PLAIN}" || echo -e "  ${RED}✗ 未检测到 TCP ${LISTEN_PORT} 监听${PLAIN}"
    if reality_target_usable_for_family "$SERVER_NAME" "$HANDSHAKE_PORT"; then
        echo -e "  ${GREEN}✓ REALITY 握手目标 ${SERVER_NAME}:${HANDSHAKE_PORT} 可达${PLAIN}"
    else
        echo -e "  ${YELLOW}! REALITY 握手目标 ${SERVER_NAME}:${HANDSHAKE_PORT} 不可达，可重新部署并选择其他 SNI${PLAIN}"
    fi
    if verify_exit_egress 3; then
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        return 0
    fi
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    read -r -p "是否通过 SSH 检查落地机状态（需要落地机 SSH 密码）？[y/N]: " _confirm
    case "$_confirm" in
        [yY]*)
            if resolve_script_source && ssh_open_master; then
                remote_landing_action --remote-exit-status || true
            fi
            ssh_close_master
            cleanup_script_source
            ;;
    esac
    return 1
}

# ============================================================
# 升级 / 卸载 / 工具
# ============================================================
acquire_upgrade_lock() {
    local _lock_dir="${UPGRADE_LOCK_FILE}.d" _owner=""
    mkdir -p "$(dirname "$UPGRADE_LOCK_FILE")" 2>/dev/null || return 1
    if command -v flock >/dev/null 2>&1; then
        exec 8>"$UPGRADE_LOCK_FILE" || return 1
        flock -n 8 || { exec 8>&-; return 1; }
        UPGRADE_LOCK_MODE="flock"
        return 0
    fi
    if ! mkdir "$_lock_dir" 2>/dev/null; then
        _owner=$(cat "$_lock_dir/pid" 2>/dev/null || true)
        # 无 pid 说明持有者在写 pid 前就被杀死；锁目录超过 5 分钟未更新才判定为陈旧并回收。
        if { [ -n "$_owner" ] && ! kill -0 "$_owner" 2>/dev/null; } || \
            { [ -z "$_owner" ] && [ -z "$(find "$_lock_dir" -maxdepth 0 -mmin -5 2>/dev/null)" ]; }; then
            rm -rf "$_lock_dir"
            mkdir "$_lock_dir" 2>/dev/null || return 1
        else
            return 1
        fi
    fi
    printf '%s' "$$" > "$_lock_dir/pid"
    UPGRADE_LOCK_MODE="mkdir"
}

release_upgrade_lock() {
    if [ "$UPGRADE_LOCK_MODE" = "flock" ]; then
        flock -u 8 2>/dev/null || true
        exec 8>&-
    elif [ "$UPGRADE_LOCK_MODE" = "mkdir" ]; then
        rm -rf "${UPGRADE_LOCK_FILE}.d"
    fi
    UPGRADE_LOCK_MODE=""
}

upgrade_core() {
    acquire_upgrade_lock || { echo -e "${YELLOW}另一个 sing-box 升级任务正在运行，请稍后重试${PLAIN}"; return 1; }
    local _status=0
    _upgrade_core_locked || _status=$?
    release_upgrade_lock
    return "$_status"
}

_upgrade_core_locked() {
    [ -f "$LANDING_CONFIG" ] && [ -x "$SING_BOX_BIN" ] || {
        echo -e "${RED}家宽中转尚未部署，请先执行一键部署${PLAIN}"
        return 1
    }
    read_config >/dev/null 2>&1 || { echo -e "${RED}元数据不完整，无法安全升级${PLAIN}"; return 1; }
    get_latest_version || return 1

    local _current_version _latest_version _was_active=0
    local _vless_was_active=0 _anytls_was_active=0 _proxy_was_active=0
    local _restart_failed=0 _was_managed="$MANAGED_SING_BOX"
    _current_version=$(get_installed_version)
    _latest_version="${LAST_VERSION_TAG#v}"
    if [ -n "$_current_version" ] && [ "$_current_version" = "$_latest_version" ]; then
        echo -e "${GREEN}sing-box 已是最新版本 ${_current_version}${PLAIN}"
        return 0
    fi

    cp -p "$SING_BOX_BIN" "${SING_BOX_BIN}.bak" || {
        echo -e "${RED}无法备份现有 sing-box，已取消升级${PLAIN}"
        return 1
    }
    service_is_active && _was_active=1 || true
    shared_service_is_active vless-server && _vless_was_active=1 || true
    shared_service_is_active anytls-server && _anytls_was_active=1 || true
    shared_service_is_active proxy-server && _proxy_was_active=1 || true
    if ! download_singbox; then
        mv -f "${SING_BOX_BIN}.bak" "$SING_BOX_BIN" 2>/dev/null || true
        MANAGED_SING_BOX="$_was_managed"
        return 1
    fi
    MANAGED_SING_BOX="$_was_managed"
    if ! check_config; then
        mv -f "${SING_BOX_BIN}.bak" "$SING_BOX_BIN" 2>/dev/null || true
        echo -e "${RED}新版本不兼容当前配置，已回滚${PLAIN}"
        return 1
    fi
    [ "$_was_active" = "0" ] || service_restart || _restart_failed=1
    [ "$_vless_was_active" = "0" ] || shared_service_restart vless-server /usr/local/bin/vless-server || _restart_failed=1
    [ "$_anytls_was_active" = "0" ] || shared_service_restart anytls-server /usr/local/bin/anytls-server || _restart_failed=1
    [ "$_proxy_was_active" = "0" ] || shared_service_restart proxy-server /usr/local/bin/proxy-server || _restart_failed=1
    if [ "$_was_active" = "1" ] || [ "$_vless_was_active" = "1" ] || [ "$_anytls_was_active" = "1" ] || [ "$_proxy_was_active" = "1" ]; then
        sleep 2
    fi
    [ "$_was_active" = "0" ] || wait_for_health || _restart_failed=1
    [ "$_vless_was_active" = "0" ] || shared_service_is_active vless-server || _restart_failed=1
    [ "$_anytls_was_active" = "0" ] || shared_service_is_active anytls-server || _restart_failed=1
    [ "$_proxy_was_active" = "0" ] || shared_service_is_active proxy-server || _restart_failed=1
    if [ "$_restart_failed" = "1" ]; then
        mv -f "${SING_BOX_BIN}.bak" "$SING_BOX_BIN" 2>/dev/null || true
        [ "$_was_active" = "0" ] || service_restart || true
        [ "$_vless_was_active" = "0" ] || shared_service_restart vless-server /usr/local/bin/vless-server || true
        [ "$_anytls_was_active" = "0" ] || shared_service_restart anytls-server /usr/local/bin/anytls-server || true
        [ "$_proxy_was_active" = "0" ] || shared_service_restart proxy-server /usr/local/bin/proxy-server || true
        echo -e "${RED}升级后共享服务启动失败，已回滚${PLAIN}"
        return 1
    fi
    rm -f "${SING_BOX_BIN}.bak"
    echo -e "${GREEN}✓ sing-box 已从 ${_current_version:-未知版本} 升级到 ${_latest_version}${PLAIN}"
    return 0
}

upgrade_landing() {
    local _status=0 _answer
    if ! install_dependencies; then
        read -r -p "按回车键返回主菜单..." _
        return 1
    fi
    upgrade_core || _status=$?
    if [ "$(installed_role 2>/dev/null)" = "relay" ] && read_config >/dev/null 2>&1; then
        read -r -p "是否同时升级落地机的 sing-box（需要落地机 SSH 密码）？[y/N]: " _answer
        case "$_answer" in
            [yY]*)
                if ensure_ssh_client && resolve_script_source && ssh_open_master; then
                    remote_landing_action --remote-exit-upgrade || _status=1
                else
                    _status=1
                fi
                ssh_close_master
                cleanup_script_source
                ;;
        esac
    fi
    sleep 2
    return "$_status"
}

uninstall_landing() {
    local _confirm _role _clean_remote=0
    _role=$(installed_role 2>/dev/null || true)
    echo -e "${RED}警告：这将删除本机的家宽中转服务、配置和定时更新。${PLAIN}"
    read -r -p "确认卸载？[y/N]: " _confirm
    case "$_confirm" in
        [yY]) ;;
        *) echo "已取消。"; sleep 1; return 0 ;;
    esac
    if [ "$_role" = "relay" ] && read_config >/dev/null 2>&1; then
        read -r -p "同时清理落地机 ${EXIT_HOST} 上的落地端（需要 SSH 密码）？[Y/n]: " _confirm
        case "$_confirm" in
            [nN]*) _clean_remote=0 ;;
            *) _clean_remote=1 ;;
        esac
    fi
    if [ "$_clean_remote" = "1" ]; then
        if ensure_ssh_client && resolve_script_source && ssh_open_master && \
            remote_landing_action --remote-exit-uninstall; then
            :
        else
            echo -e "${YELLOW}! 未能自动清理落地机。可在落地机上运行以下命令手动卸载：${PLAIN}"
            echo "bash <(curl -fsSL ${LANDING_SCRIPT_URL}) uninstall"
        fi
        ssh_close_master
        cleanup_script_source
    fi
    uninstall_landing_files
    echo -e "${GREEN}✓ 家宽中转已从本机卸载${PLAIN}"
    sleep 2
}

setup_auto_update() {
    local _mode="${1:-interactive}"
    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
LOG_FILE=/var/log/landing-autoupdate.log
TMP_SCRIPT=$(mktemp /tmp/landing-update-XXXXXX.sh) || exit 1
trap 'rm -f "$TMP_SCRIPT"' EXIT INT TERM
{
  echo "[$(date '+%F %T')] 开始检查 sing-box 更新"
  curl -fsSL --connect-timeout 15 --max-time 60 \
    https://raw.githubusercontent.com/everett7623/hy2/main/landing.sh -o "$TMP_SCRIPT" || exit 1
  bash -n "$TMP_SCRIPT" || exit 1
  bash "$TMP_SCRIPT" --upgrade-noninteractive
  echo "[$(date '+%F %T')] 更新检查完成"
} >> "$LOG_FILE" 2>&1
AUTOUPDATE_EOF
    chmod +x "$AUTO_UPDATE_SCRIPT"

    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "$AUTO_UPDATE_SCRIPT"; echo "47 4 * * 1 $AUTO_UPDATE_SCRIPT") | crontab -
        echo -e "${GREEN}✓ 已设置每周一 04:47 自动检查 sing-box 更新${PLAIN}"
    else
        echo -e "${YELLOW}系统未安装 crontab，请手动安装 cron 后再设置自动升级${PLAIN}"
    fi
    [ "$_mode" = "quiet" ] || sleep 2
    return 0
}

remove_auto_update() {
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vF "$AUTO_UPDATE_SCRIPT" | crontab - 2>/dev/null || true
    fi
    rm -f "$AUTO_UPDATE_SCRIPT"
    echo -e "${GREEN}✓ 已移除家宽中转自动更新任务${PLAIN}"
    sleep 2
}

show_bbr_status() {
    local _cc _qdisc _avail
    _cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    _qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
    _avail=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true)
    echo -e "\n${GREEN}BBR / TCP 队列状态${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "  拥塞控制算法: ${YELLOW}${_cc:-未知}${PLAIN}"
    echo -e "  默认队列算法: ${YELLOW}${_qdisc:-未知}${PLAIN}"
    echo -e "  可用算法列表: ${SKYBLUE}${_avail:-未知}${PLAIN}"
    if [ "$_cc" = "bbr" ] && [ "$_qdisc" = "fq" ]; then
        echo -e "  标准 BBR 状态: ${GREEN}已启用 (bbr + fq)${PLAIN}"
    elif [ "$_cc" = "bbr" ]; then
        echo -e "  标准 BBR 状态: ${YELLOW}部分启用 (bbr / ${_qdisc:-未知})${PLAIN}"
    else
        echo -e "  标准 BBR 状态: ${RED}未启用${PLAIN}"
    fi
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

enable_standard_bbr() {
    local _kver _kmaj _kmin _old_cc _old_qdisc _cc _qdisc _confirm
    local _dir _tmp _backup="" _rollback_ok=1
    echo -e "\n${GREEN}开启标准 BBR + fq${PLAIN}"
    echo -e "${DIM}仅手动启用，不会在部署时自动修改系统 TCP 参数。${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    _kver=$(uname -r 2>/dev/null || printf '0.0')
    _kmaj=$(printf '%s' "$_kver" | cut -d. -f1)
    _kmin=$(printf '%s' "$_kver" | cut -d. -f2)
    case "$_kmaj" in ''|*[!0-9]*) _kmaj=0 ;; esac
    case "$_kmin" in ''|*[!0-9]*) _kmin=0 ;; esac
    echo -e "  当前内核: ${YELLOW}${_kver}${PLAIN}"
    if [ "$_kmaj" -lt 4 ] || { [ "$_kmaj" -eq 4 ] && [ "$_kmin" -lt 9 ]; }; then
        echo -e "${RED}内核版本低于 4.9，不支持标准 BBR。${PLAIN}"
        return 1
    fi

    _old_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    _old_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
    if [ "$_old_cc" = "bbr" ] && [ "$_old_qdisc" = "fq" ]; then
        echo -e "${GREEN}标准 BBR + fq 已启用，无需重复设置。${PLAIN}"
        return 0
    fi

    read -r -p "确认开启标准 BBR + fq？[y/N]: " _confirm
    case "$_confirm" in
        [yY]) ;;
        *) echo -e "${YELLOW}已取消。${PLAIN}"; return 1 ;;
    esac

    modprobe tcp_bbr 2>/dev/null || true
    _dir=$(dirname "$BBR_SYSCTL_CONF")
    mkdir -p "$_dir" 2>/dev/null || {
        echo -e "${RED}无法创建 sysctl 配置目录: ${_dir}${PLAIN}"
        return 1
    }
    _tmp=$(mktemp "${BBR_SYSCTL_CONF}.new.XXXXXX" 2>/dev/null) || {
        echo -e "${RED}无法创建 BBR 临时配置${PLAIN}"
        return 1
    }
    if [ -f "$BBR_SYSCTL_CONF" ]; then
        _backup=$(mktemp "${BBR_SYSCTL_CONF}.bak.XXXXXX" 2>/dev/null) || {
            rm -f "$_tmp"
            echo -e "${RED}无法备份现有 BBR 配置${PLAIN}"
            return 1
        }
        cp -p "$BBR_SYSCTL_CONF" "$_backup" || {
            rm -f "$_tmp" "$_backup"
            echo -e "${RED}无法备份现有 BBR 配置${PLAIN}"
            return 1
        }
    fi
    if ! cat > "$_tmp" <<EOF
# Sing-box Multi-Protocol Tools - standard BBR tuning
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    then
        rm -f "$_tmp" "$_backup"
        echo -e "${RED}无法写入 BBR 配置${PLAIN}"
        return 1
    fi
    chmod 644 "$_tmp" && mv -f "$_tmp" "$BBR_SYSCTL_CONF" || {
        rm -f "$_tmp" "$_backup"
        echo -e "${RED}无法安装 BBR 配置${PLAIN}"
        return 1
    }

    sysctl -p "$BBR_SYSCTL_CONF" >/dev/null 2>&1 || true
    _cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    _qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
    if [ "$_cc" = "bbr" ] && [ "$_qdisc" = "fq" ]; then
        rm -f "$_backup"
        echo -e "${GREEN}✓ 标准 BBR + fq 已启用，配置写入 ${BBR_SYSCTL_CONF}${PLAIN}"
        return 0
    fi

    if [ -n "$_backup" ] && [ -f "$_backup" ]; then
        mv -f "$_backup" "$BBR_SYSCTL_CONF" 2>/dev/null || _rollback_ok=0
    else
        rm -f "$BBR_SYSCTL_CONF" || _rollback_ok=0
    fi
    [ -z "$_old_qdisc" ] || sysctl -w "net.core.default_qdisc=${_old_qdisc}" >/dev/null 2>&1 || _rollback_ok=0
    [ -z "$_old_cc" ] || sysctl -w "net.ipv4.tcp_congestion_control=${_old_cc}" >/dev/null 2>&1 || _rollback_ok=0
    if [ "$_rollback_ok" = "1" ]; then
        echo -e "${RED}BBR + fq 未完整生效，已恢复修改前的配置与实时参数。${PLAIN}"
    else
        echo -e "${RED}BBR + fq 未完整生效，且自动恢复不完整，请检查 ${BBR_SYSCTL_CONF} 与当前 sysctl。${PLAIN}"
    fi
    return 1
}

show_system_info() {
    echo -e "\n${GREEN}系统信息${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e " 主机名: $(hostname 2>/dev/null)"
    echo -e " 内核  : $(uname -r)"
    echo -e " 架构  : $(uname -m)"
    [ -x "$SING_BOX_BIN" ] && echo -e " 核心  : $("$SING_BOX_BIN" version 2>/dev/null | head -1)"
    echo -e " 内存  : $(awk '/MemAvailable/ {printf "%.0f MB available", $2/1024}' /proc/meminfo 2>/dev/null)"
    echo -e " 磁盘  : $(df -h / 2>/dev/null | awk 'NR==2 {print $3" / "$2" ("$5" used)"}')"
    echo -e " 负载  : $(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    read -r -p "按回车返回..." _
}

server_tools_menu() {
    while true; do
        clear_screen
        local _auto_status="${RED}未启用${PLAIN}"
        if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$AUTO_UPDATE_SCRIPT"; then
            _auto_status="${GREEN}已启用${PLAIN}"
        fi
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  家宽中转工具箱${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 自动更新: ${_auto_status}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 查看系统信息"
        echo -e " 2. 查看服务日志"
        echo -e " 3. 出口检测与诊断"
        echo -e " 4. 查看 BBR / TCP 队列状态"
        echo -e " 5. 开启标准 BBR + fq"
        echo -e " 6. 设置每周自动更新"
        echo -e " 7. 移除自动更新"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-7]: " choice
        case "$choice" in
            1) show_system_info ;;
            2) service_logs; read -r -p "按回车返回..." _ ;;
            3) diagnose_landing; read -r -p "按回车返回..." _ ;;
            4) show_bbr_status; read -r -p "按回车返回..." _ ;;
            5) enable_standard_bbr; read -r -p "按回车返回..." _ ;;
            6) setup_auto_update ;;
            7) remove_auto_update ;;
            0|q|quit|exit) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

manage_landing() {
    if [ ! -f "$LANDING_CONFIG" ] || [ ! -x "$LANDING_BIN" ]; then
        echo -e "${RED}家宽中转尚未部署，请先执行一键部署${PLAIN}"
        sleep 2
        return
    fi
    read_config >/dev/null 2>&1 || true
    while true; do
        clear_screen
        local STATUS
        service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  家宽中转服务管理${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: ${STATUS}"
        echo -e " 1. 启动"
        echo -e " 2. 停止"
        echo -e " 3. 重启"
        echo -e " 4. 查看日志"
        echo -e " 5. 出口检测与诊断"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-5]: " choice
        case "$choice" in
            1)
                if service_start && wait_for_health 6; then
                    echo -e "${GREEN}✓ 已启动${PLAIN}"
                else
                    echo -e "${RED}✗ 启动失败，请查看日志${PLAIN}"
                fi
                sleep 1
                ;;
            2)
                service_stop
                sleep 1
                service_is_active && echo -e "${RED}✗ 服务仍在运行${PLAIN}" || echo -e "${GREEN}✓ 已停止${PLAIN}"
                sleep 1
                ;;
            3)
                if service_restart && wait_for_health 6; then
                    echo -e "${GREEN}✓ 已重启${PLAIN}"
                else
                    echo -e "${RED}✗ 重启失败，请查看日志${PLAIN}"
                fi
                sleep 1
                ;;
            4) service_logs; read -r -p "按回车返回..." _ ;;
            5) diagnose_landing; read -r -p "按回车返回..." _ ;;
            0|q|quit|exit) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 主菜单
# ============================================================
main_menu() {
    while true; do
        clear_screen
        local STATUS _ver_line _role _role_text
        _role=$(installed_role 2>/dev/null || true)
        case "$_role" in
            relay) _role_text="${GREEN}线路机（中转端）${PLAIN}" ;;
            exit)  _role_text="${GREEN}落地机（家宽 / 出口端）${PLAIN}" ;;
            *)     _role_text="${DIM}未部署${PLAIN}" ;;
        esac
        if [ -f "$LANDING_CONFIG" ] && [ -x "$LANDING_BIN" ] && [ -x "$SING_BOX_BIN" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        elif [ -e "$LANDING_CONFIG" ] || [ -e "$LANDING_BIN" ]; then
            STATUS="${YELLOW}安装不完整${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi
        _ver_line=""
        if [ -x "$SING_BOX_BIN" ]; then
            _ver_line=" ($(get_installed_version))"
        fi

        echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
        echo -e "  ${GREEN}${BOLD}Landing Relay Management Script${PLAIN} ${DIM}v2.0.45${PLAIN}"
        echo -e "  ${DIM}线路机 + 落地机 / 家宽机（sing-box WireGuard）${PLAIN}"
        echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
        echo -e "  项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e "  作者    : ${YELLOW}everettlabs${PLAIN}"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e "  Seedloc博客 : https://seedloc.com"
        echo -e "  VPSknow网站 : https://vpsknow.com"
        echo -e "  Nodeloc论坛 : https://nodeloc.com"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e "  本机角色: ${_role_text}"
        echo -e "  当前状态: $STATUS${_ver_line}"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e " 1. 一键部署 / 重新对接（在线路机上运行）"
        echo -e " 2. 查看节点信息 / 链接"
        echo -e " 3. 管理服务（启动 / 停止 / 重启 / 日志）"
        echo -e " 4. 出口检测与诊断"
        echo -e " 5. 更新落地机地址（家宽换 IP / 改用域名）"
        echo -e " 6. 升级 sing-box"
        echo -e " 7. 卸载"
        echo -e " 8. 服务器工具"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}================================================${PLAIN}"

        read -r -p "请输入选项 [0-8]: " choice
        case "$choice" in
            1) deploy_landing ;;
            2) show_config ;;
            3) manage_landing ;;
            4) diagnose_landing; read -r -p "按回车返回..." _ ;;
            5) update_exit_address; read -r -p "按回车返回..." _ ;;
            6) upgrade_landing ;;
            7) uninstall_landing ;;
            8) server_tools_menu ;;
            0|q|quit|exit) exit 0 ;;
            *) echo -e "${RED}无效选项，请输入 0-8${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 入口（LANDING_LIB_ONLY=1 时跳过）
# ============================================================
[ "$_LANDING_LIB_ONLY" = "1" ] && return 0

# 非交互升级，供 cron 使用
if [ "${1:-}" = "--upgrade-noninteractive" ]; then
    check_root
    check_sys
    detect_init
    install_dependencies || exit 1
    upgrade_core
    exit $?
fi

# 落地机远程动作，仅由线路机经 SSH 调用
case "${1:-}" in
    --remote-exit-install) remote_exit_install "${2:-}"; exit $? ;;
    --remote-exit-commit) remote_exit_commit; exit $? ;;
    --remote-exit-abort) remote_exit_abort; exit $? ;;
    --remote-exit-uninstall) remote_exit_uninstall; exit $? ;;
    --remote-exit-upgrade) remote_exit_upgrade; exit $? ;;
    --remote-exit-status) remote_exit_status; exit $? ;;
esac

check_root
check_sys
detect_init
case "${1:-menu}" in
    install|deploy) deploy_landing ;;
    info|node|export|all) show_config ;;
    uri|link) show_config uri ;;
    mihomo|clash) show_config mihomo ;;
    surfboard) show_config surfboard ;;
    shadowrocket) show_config shadowrocket ;;
    loon) show_config loon ;;
    quantumult|quantumultx) show_config quantumult ;;
    qrcode|qr) show_config qrcode ;;
    manage|service|config) manage_landing ;;
    diagnose|check|health) diagnose_landing ;;
    upgrade|update) upgrade_landing ;;
    uninstall|remove) uninstall_landing ;;
    menu|"") main_menu ;;
    *)
        echo -e "${RED}未知命令: ${1}${PLAIN}"
        echo "可用命令: install | info | manage | diagnose | upgrade | uninstall"
        exit 1
        ;;
esac
