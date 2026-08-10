#!/bin/bash
#====================================================================================
# 项目：HTTP/SOCKS Proxy Management Script
# 作者：everettlabs
# 版本：v2.0.24
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-08-10
#
# 支持系统: Debian / Ubuntu / CentOS / Rocky / Alma / Fedora / Arch / Alpine
# 支持环境: 标准 VPS / NAT 机器 / IPv6 单栈 / 双栈机器
# 实现方式: 使用 sing-box >= 1.12.0 原生 mixed 入站（HTTP + SOCKS5 同端口）
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

[ "${PROXY_LIB_ONLY:-0}" != "1" ] && [ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty

if [ -f "$SCRIPT_PATH" ] && grep -q $'\r' "$SCRIPT_PATH" 2>/dev/null; then
    sed -i 's/\r$//' "$SCRIPT_PATH"
    exec bash "$SCRIPT_PATH" "$@"
fi

# ============================================================
# PROXY_LIB_ONLY=1：仅加载函数库，不执行任何副作用（供测试 source）
# ============================================================
[ "${PROXY_LIB_ONLY:-0}" = "1" ] && _PROXY_LIB_ONLY=1 || _PROXY_LIB_ONLY=0

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
PROXY_BIN="${PROXY_BIN:-/usr/local/bin/proxy-server}"
SING_BOX_BIN="${SING_BOX_BIN:-/usr/local/bin/sing-box}"
PROXY_DIR="${PROXY_DIR:-/etc/sing-box}"
PROXY_CONFIG="${PROXY_CONFIG:-${PROXY_DIR}/proxy.json}"
PROXY_META="${PROXY_META:-${PROXY_DIR}/proxy-meta}"
SING_BOX_MANAGED_MARKER="${SING_BOX_MANAGED_MARKER:-${PROXY_DIR}/.singbox-tools-managed}"
SYSTEMD_SERVICE="${SYSTEMD_SERVICE:-/etc/systemd/system/proxy-server.service}"
OPENRC_SERVICE="/etc/init.d/proxy-server"
AUTO_UPDATE_SCRIPT="/usr/local/bin/proxy-autoupdate.sh"
AUTO_UPDATE_LOG="/var/log/proxy-autoupdate.log"

# --- 运行时变量 ---
RELEASE="unknown"
INIT_SYS="none"
NAT_MODE=0
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
PROXY_USER=""
PROXY_PASS=""
NODE_NAME=""
MANAGED_SING_BOX=0
LAST_VERSION_TAG=""
SING_BOX_STABLE_FALLBACK_TAG="${SING_BOX_STABLE_FALLBACK_TAG:-v1.13.14}"
INSTALL_BACKUP_DIR=""
INSTALL_ROLLBACK_ARMED=0
INSTALL_PREV_INT_TRAP=""
INSTALL_PREV_TERM_TRAP=""
UPGRADE_LOCK_FILE="${UPGRADE_LOCK_FILE:-/var/lock/sing-box-tools-upgrade.lock}"
UPGRADE_LOCK_MODE=""


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
        echo -e "${GREEN}[OK] 核心依赖已就绪，跳过软件源刷新${PLAIN}"
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

# ============================================================
# 输入校验 / 随机生成
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

validate_password() {
    local pw="$1"
    local len="${#pw}"
    [ "$len" -lt 8 ]   && return 1
    [ "$len" -gt 128 ] && return 1
    case "$pw" in
        *'"'*)  return 1 ;;
        *'\'*)  return 1 ;;
        *'$'*)  return 1 ;;
        *'`'*)  return 1 ;;
        *' '*)  return 1 ;;
        *'@'*)  return 1 ;;
        *':'*)  return 1 ;;
        *'/'*)  return 1 ;;
        *'?'*)  return 1 ;;
        *'#'*)  return 1 ;;
    esac
    local _has_ctrl
    _has_ctrl=$(printf '%s' "$pw" | od -An -tx1 | tr ' \n' '\n' | { grep -cE '^[01][0-9a-f]$|^7f$' 2>/dev/null || true; })
    [ "${_has_ctrl:-0}" -gt 0 ] 2>/dev/null && return 1
    return 0
}

validate_username() {
    local user="$1"
    local len="${#user}"
    [ "$len" -lt 3 ]   && return 1
    [ "$len" -gt 64 ]  && return 1
    case "$user" in
        *[!A-Za-z0-9._-]*) return 1 ;;
    esac
    return 0
}

validate_server_address() {
    local _address="$1"
    [ -n "$_address" ] || return 1
    case "$_address" in
        *[!A-Za-z0-9.:_-]*) return 1 ;;
    esac
    return 0
}

gen_password() {
    local _pass=""
    if command -v openssl >/dev/null 2>&1; then
        while [ ${#_pass} -lt 20 ]; do
            _pass="${_pass}$(openssl rand -base64 32 2>/dev/null | tr -dc 'A-Za-z0-9')"
        done
    else
        while [ ${#_pass} -lt 20 ]; do
            _pass="${_pass}$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | tr -dc 'A-Za-z0-9')"
        done
    fi
    [ -z "$_pass" ] && _pass="Proxy$(date +%s)"
    printf '%s' "${_pass:0:20}"
}

gen_username() {
    local _user="" _suffix=""
    if command -v openssl >/dev/null 2>&1; then
        _suffix=$(openssl rand -hex 3 2>/dev/null | tr -dc 'a-f0-9')
    else
        _suffix=$(dd if=/dev/urandom bs=3 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
    fi
    [ -z "$_suffix" ] && _suffix=$(printf '%06x' "$(( (RANDOM << 1) ^ RANDOM ))")
    _user="user${_suffix:0:6}"
    printf '%s' "$_user"
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
    printf 'https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz\n' \
        "$_ver" "$_ver" "$_arch"
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

is_valid_ipv6() {
    case "$1" in
        *:*) echo "$1" | grep -qE '^[0-9A-Fa-f:]+$' ;;
        *) return 1 ;;
    esac
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

get_native_public_ipv4() {
    command -v ip >/dev/null 2>&1 || return 1
    local _iface _local_ip _ip _url
    _iface=$(get_native_egress_interface 2>/dev/null || true)
    [ -n "$_iface" ] || return 1
    _local_ip=$(ip -4 addr show dev "$_iface" scope global 2>/dev/null | awk '
        /inet / { addr=$2; sub(/\/.*/, "", addr); print addr; exit }
    ')
    [ -n "$_local_ip" ] || return 1

    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --interface "$_local_ip" --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if is_valid_ipv4 "$_ip"; then
            printf '%s' "$_ip"
            return 0
        fi
    done
    return 1
}

get_default_public_ipv4() {
    local _ip _url
    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
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

check_egress_ip() {
    local _default=""
    [ -z "${DEFAULT_EGRESS_IPV4:-}" ] && DEFAULT_EGRESS_IPV4=$(get_default_public_ipv4 2>/dev/null || true)
    _default="${DEFAULT_EGRESS_IPV4:-}"
    echo -e "${GREEN}出站自检${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    [ -n "${PUBLIC_IP:-}" ] && echo -e "  节点入口 IPv4 : ${YELLOW}${PUBLIC_IP}${PLAIN}"
    [ -n "$_default" ] && echo -e "  默认出站 IPv4 : ${YELLOW}${_default}${PLAIN}"
    [ -n "${BIND_INTERFACE:-}" ] && echo -e "  绑定网卡      : ${GREEN}${BIND_INTERFACE}${PLAIN}"
    if [ -n "${PUBLIC_IP:-}" ] && [ -n "$_default" ] && [ "$PUBLIC_IP" != "$_default" ]; then
        echo -e "${RED}[WARN] 默认出站 IP (${_default}) 与节点 IP (${PUBLIC_IP}) 不一致。${PLAIN}"
        echo -e "${RED}        流媒体（如 Netflix）可能提示 proxy/VPN；已尽量绑定原生网卡出站。${PLAIN}"
    elif [ -n "${PUBLIC_IP:-}" ] && [ -n "$_default" ]; then
        echo -e "  ${GREEN}[OK] 出站 IP 与节点 IP 一致${PLAIN}"
    fi
    if [ -n "${PUBLIC_IP:-}" ] && [ -n "${PUBLIC_IPV6:-}" ]; then
        echo -e "${YELLOW}提示: 流媒体/解锁请优先使用 IPv4 节点，并确保客户端 DNS 走代理（SOCKS5h）。${PLAIN}"
    else
        echo -e "${YELLOW}提示: SOCKS5 客户端必须使用远程 DNS（socks5h），否则易泄露真实 DNS。${PLAIN}"
    fi
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

warn_streaming_egress() {
    check_egress_ip
}

detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    NAT_MODE=0; HAS_IPV4=0; HAS_IPV6=0; PUBLIC_IP=""; PUBLIC_IPV6=""; DEFAULT_EGRESS_IPV4=""; WARP_ACTIVE=0; BIND_INTERFACE=""; BIND_FAMILY="v4"; LISTEN_HOST="::"
    local _ip _url

    detect_warp && WARP_ACTIVE=1 || true
    DEFAULT_EGRESS_IPV4=$(get_default_public_ipv4 2>/dev/null || true)
    BIND_INTERFACE=$(get_native_egress_interface 2>/dev/null || true)

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if is_valid_ipv6 "$_ip"; then PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break; fi
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
        if [ -n "$_real_ipv6" ]; then
            HAS_IPV6=1
            PUBLIC_IPV6="$_real_ipv6"
        else
            HAS_IPV6=0
            PUBLIC_IPV6=""
        fi
    fi

    _ip=$(get_native_public_ipv4 2>/dev/null || true)
    if is_valid_ipv4 "$_ip"; then
        PUBLIC_IP="$_ip"
        HAS_IPV4=1
    elif [ "$WARP_ACTIVE" = "0" ] && is_valid_ipv4 "$DEFAULT_EGRESS_IPV4"; then
        PUBLIC_IP="$DEFAULT_EGRESS_IPV4"
        HAS_IPV4=1
    fi

    if [ "$HAS_IPV4" = "1" ] && command -v ip >/dev/null 2>&1; then
        local _real_ipv4
        _real_ipv4=$(ip -4 addr show scope global 2>/dev/null | awk '
            /^[0-9]+:/ { iface=$2; sub(/:.*/,"",iface) }
            /inet / && iface !~ /wgcf|warp|^tun|^wg|tailscale|zt/ { print "1"; exit }
        ')
        [ -z "$_real_ipv4" ] && { HAS_IPV4=0; PUBLIC_IP=""; }
    fi

    if [ "$HAS_IPV4" = "1" ] && command -v ip >/dev/null 2>&1; then
        local _local_ips
        _local_ips=$(ip addr show 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^127\.' | grep -v '^169\.254\.')
        echo "$_local_ips" | grep -q "^${PUBLIC_IP}$" || NAT_MODE=1
    fi

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && BIND_FAMILY="v6"
    [ "$HAS_IPV6" = "1" ] && [ "$HAS_IPV4" = "1" ] && BIND_FAMILY="v4"
    [ "$HAS_IPV6" = "0" ] && LISTEN_HOST="0.0.0.0"

    if   [ "$NAT_MODE"     = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$BIND_FAMILY"  = "v6" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"     = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv6: ${PUBLIC_IPV6} | IPv4: ${PUBLIC_IP}）"
    elif [ "$HAS_IPV4"     = "1" ]; then echo -e "  机器类型: ${GREEN}标准 IPv4${PLAIN}（IP: ${PUBLIC_IP}）"
    else                                  echo -e "  机器类型: ${RED}无法检测，请手动输入节点地址${PLAIN}"
    fi
    if [ "$WARP_ACTIVE" = "1" ]; then
        echo -e "  WARP 状态: ${YELLOW}已检测到${PLAIN}（仅作为出站，不用于节点入口）"
        [ -n "$DEFAULT_EGRESS_IPV4" ] && echo -e "  默认出口 IPv4: ${YELLOW}${DEFAULT_EGRESS_IPV4}${PLAIN}"
        if [ -z "$PUBLIC_IP" ]; then
            echo -e "  ${RED}未能确认原生 IPv4，已拒绝使用 WARP 出口生成节点${PLAIN}"
        elif [ -n "$DEFAULT_EGRESS_IPV4" ] && [ "$DEFAULT_EGRESS_IPV4" != "$PUBLIC_IP" ]; then
            echo -e "  原生入口 IPv4: ${GREEN}${PUBLIC_IP}${PLAIN}"
            echo -e "  ${RED}注意: 默认出站与节点 IP 不一致，流媒体可能判 VPN；将绑定原生网卡出站${PLAIN}"
        fi
    fi
    if [ -n "$BIND_INTERFACE" ]; then
        echo -e "  出站网卡: ${GREEN}${BIND_INTERFACE}${PLAIN}"
    fi
    return 0
}


open_ports() {
    local _port="$1" _fw_meta="$PROXY_META/firewall" _added4=0
    validate_port "$_port" || { echo -e "${RED}无效的防火墙端口: ${_port}${PLAIN}"; return 1; }
    mkdir -p "$_fw_meta" 2>/dev/null || {
        echo -e "${RED}无法创建防火墙规则记录目录，已取消放行${PLAIN}"
        return 1
    }
    echo -e "${YELLOW}正在自动放行 TCP 端口 ${_port}...${PLAIN}"

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if ! firewall-cmd --permanent --query-port="${_port}/tcp" >/dev/null 2>&1; then
            if ! firewall-cmd --permanent --add-port="${_port}/tcp" >/dev/null 2>&1 || \
                ! firewall-cmd --reload >/dev/null 2>&1 || \
                ! firewall-cmd --query-port="${_port}/tcp" >/dev/null 2>&1; then
                firewall-cmd --permanent --remove-port="${_port}/tcp" >/dev/null 2>&1 || true
                firewall-cmd --reload >/dev/null 2>&1 || true
                echo -e "${RED}firewalld 放行 tcp/${_port} 失败${PLAIN}"
                return 1
            fi
            : > "$_fw_meta/firewalld-${_port}-tcp"
        fi
        if ! firewall-cmd --query-port="${_port}/tcp" >/dev/null 2>&1; then
            firewall-cmd --reload >/dev/null 2>&1 && firewall-cmd --query-port="${_port}/tcp" >/dev/null 2>&1 || {
                echo -e "${RED}firewalld 未能应用 tcp/${_port}${PLAIN}"
                return 1
            }
        fi
        echo -e "  ${GREEN}[OK] firewalld 已放行 tcp/${_port}${PLAIN}"
        return 0
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        if ! ufw status 2>/dev/null | grep -qE "^${_port}/tcp[[:space:]]+ALLOW"; then
            if ! ufw allow "${_port}/tcp" >/dev/null 2>&1 || \
                ! ufw status 2>/dev/null | grep -qE "^${_port}/tcp[[:space:]]+ALLOW"; then
                echo -e "${RED}ufw 放行 tcp/${_port} 失败${PLAIN}"
                return 1
            fi
            : > "$_fw_meta/ufw-${_port}-tcp"
        fi
        echo -e "  ${GREEN}[OK] ufw 已放行 tcp/${_port}${PLAIN}"
        return 0
    fi

    if command -v iptables >/dev/null 2>&1; then
        if ! iptables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
            if ! iptables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
                ! iptables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                echo -e "${RED}iptables 放行 tcp/${_port} 失败${PLAIN}"
                return 1
            fi
            _added4=1
            : > "$_fw_meta/iptables4-${_port}-tcp"
        fi
        if [ "$HAS_IPV6" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
            if ! ip6tables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                if ! ip6tables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
                    ! ip6tables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1; then
                    [ "$_added4" = "0" ] || iptables -D INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
                    [ "$_added4" = "0" ] || rm -f "$_fw_meta/iptables4-${_port}-tcp"
                    echo -e "${RED}ip6tables 放行 tcp/${_port} 失败${PLAIN}"
                    return 1
                fi
                : > "$_fw_meta/iptables6-${_port}-tcp"
            fi
        fi
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || echo -e "  ${YELLOW}! 规则已生效，但持久化保存失败${PLAIN}"
        elif [ -f /etc/sysconfig/iptables ] && command -v service >/dev/null 2>&1; then
            service iptables save >/dev/null 2>&1 || echo -e "  ${YELLOW}! 规则已生效，但持久化保存失败${PLAIN}"
        fi
        echo -e "  ${GREEN}[OK] iptables 已放行 tcp/${_port}${PLAIN}"
        return 0
    fi

    echo -e "  ${YELLOW}! 未检测到启用的本机防火墙；请确认云安全组已放行 tcp/${_port}${PLAIN}"
    return 0
}

close_ports() {
    local _port="$1"
    local _fw_meta="$PROXY_META/firewall"
    validate_port "$_port" || return 0

    if [ -f "$_fw_meta/firewalld-${_port}-tcp" ] && command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="${_port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        rm -f "$_fw_meta/firewalld-${_port}-tcp"
    fi
    if [ -f "$_fw_meta/ufw-${_port}-tcp" ] && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw delete allow "${_port}/tcp" >/dev/null 2>&1 || true
        rm -f "$_fw_meta/ufw-${_port}-tcp"
    fi
    if [ -f "$_fw_meta/iptables4-${_port}-tcp" ] && command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
        rm -f "$_fw_meta/iptables4-${_port}-tcp"
    fi
    if [ -f "$_fw_meta/iptables6-${_port}-tcp" ] && command -v ip6tables >/dev/null 2>&1; then
        ip6tables -D INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || true
        rm -f "$_fw_meta/iptables6-${_port}-tcp"
    fi
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif [ -f /etc/sysconfig/iptables ] && command -v service >/dev/null 2>&1; then
        service iptables save >/dev/null 2>&1 || true
    fi
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
    for _config in "$PROXY_DIR"/*.json; do
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
                | sed -E 's#.*/(tag|download)/##' | awk 'NR==1 { print; exit }')
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
    "$SING_BOX_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | awk 'NR==1 { print; exit }'
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
    local _asset="sing-box-${_ver}-linux-${_arch}.tar.gz"
    local _gh_path="SagerNet/sing-box/releases/download/v${_ver}/${_asset}"
    local _urls=(
        "https://github.com/${_gh_path}"
        "https://ghproxy.com/https://github.com/${_gh_path}"
        "https://kkgithub.com/${_gh_path}"
        "https://gh.api.99988866.xyz/https://github.com/${_gh_path}"
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
    _bin=$(find "$_tmp_dir" -type f -name "sing-box" | awk 'NR==1 { print; exit }')
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
    local _downloaded_version
    _downloaded_version=$("$_bin" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | awk 'NR==1 { print; exit }')
    if [ "$_downloaded_version" != "$_ver" ]; then
        rm -rf "$_tmp_dir"
        echo -e "${RED}sing-box 执行或版本校验失败（期望 ${_ver}，得到 ${_downloaded_version:-未知}）${PLAIN}"
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
    echo -e "${GREEN}sing-box 安装完成: $("$SING_BOX_BIN" version 2>/dev/null | awk 'NR==1 { print; exit }')${PLAIN}"
}

ensure_singbox() {
    local _preexisting=0
    if [ -x "$SING_BOX_BIN" ]; then
        _preexisting=1
        local _installed_version
        _installed_version=$(get_installed_version)
        if version_at_least "${_installed_version:-0.0.0}" "1.12.0"; then
            if [ -f "$PROXY_META/config.env" ]; then
                MANAGED_SING_BOX=$(awk -F= '$1 == "MANAGED_SING_BOX" { print $2; exit }' "$PROXY_META/config.env")
                [ "$MANAGED_SING_BOX" = "1" ] || MANAGED_SING_BOX=0
            fi
            return 0
        fi
        echo -e "${YELLOW}现有 sing-box ${_installed_version:-未知版本} 过旧，将安装最新版${PLAIN}"
    fi
    get_latest_version || return 1
    download_singbox || return 1
    if [ "$_preexisting" = "1" ]; then
        MANAGED_SING_BOX=0
    else
        MANAGED_SING_BOX=1
        mkdir -p "$PROXY_DIR" || { echo -e "${RED}无法创建 sing-box 配置目录${PLAIN}"; return 1; }
        { : > "$SING_BOX_MANAGED_MARKER"; } || { echo -e "${RED}无法写入 sing-box 所有权标记${PLAIN}"; return 1; }
        chmod 600 "$SING_BOX_MANAGED_MARKER" || { echo -e "${RED}无法保护 sing-box 所有权标记${PLAIN}"; return 1; }
    fi
    return 0
}

# ============================================================
# URI / 显示辅助
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
    _protocol=$(trim_string "${3:-Proxy}")
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

should_show_output() {
    local _mode="${1:-all}" _section="$2"
    [ "$_mode" = "all" ] || [ "$_mode" = "$_section" ]
}

# ============================================================
# 配置写入 / 读取
# ============================================================
write_config() {
    mkdir -p "$PROXY_DIR" "$PROXY_META"
    chmod 700 "$PROXY_META"
    local _tmp_config _tmp_meta _outbound_json _user_esc _pass_esc
    _tmp_config=$(mktemp "${PROXY_DIR}/proxy.json.new.XXXXXX" 2>/dev/null) || return 1
    _tmp_meta=$(mktemp "${PROXY_META}/config.env.new.XXXXXX" 2>/dev/null) || {
        rm -f "$_tmp_config"
        return 1
    }
    _user_esc=$(printf '%s' "$PROXY_USER" | sed 's/\\/\\\\/g; s/"/\\"/g')
    _pass_esc=$(printf '%s' "$PROXY_PASS" | sed 's/\\/\\\\/g; s/"/\\"/g')
    [ -z "$BIND_INTERFACE" ] && BIND_INTERFACE=$(get_native_egress_interface 2>/dev/null || true)
    if [ -n "$BIND_INTERFACE" ]; then
        _outbound_json="{ \"type\": \"direct\", \"tag\": \"direct\", \"bind_interface\": \"${BIND_INTERFACE}\" }"
    else
        _outbound_json="{ \"type\": \"direct\", \"tag\": \"direct\" }"
    fi
    if ! cat > "$_tmp_config" <<CFG
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "${LISTEN_HOST}",
      "listen_port": ${LISTEN_PORT},
      "users": [{ "username": "${_user_esc}", "password": "${_pass_esc}" }]
    }
  ],
  "outbounds": [${_outbound_json}]
}
CFG
    then
        rm -f "$_tmp_config" "$_tmp_meta"
        return 1
    fi
    if ! cat > "$_tmp_meta" <<CFG
LISTEN_PORT=${LISTEN_PORT}
EXT_PORT=${EXT_PORT}
PROXY_USER=${PROXY_USER}
PROXY_PASS=${PROXY_PASS}
NAT_MODE=${NAT_MODE}
BIND_FAMILY=${BIND_FAMILY}
BIND_INTERFACE=${BIND_INTERFACE}
LISTEN_HOST=${LISTEN_HOST}
MANAGED_SING_BOX=${MANAGED_SING_BOX}
CFG
    then
        rm -f "$_tmp_config" "$_tmp_meta"
        return 1
    fi
    chmod 600 "$_tmp_config" "$_tmp_meta" || {
        rm -f "$_tmp_config" "$_tmp_meta"
        return 1
    }
    mv -f "$_tmp_meta" "$PROXY_META/config.env" || {
        rm -f "$_tmp_config" "$_tmp_meta"
        return 1
    }
    mv -f "$_tmp_config" "$PROXY_CONFIG" || {
        rm -f "$_tmp_config"
        return 1
    }
    atomic_write_meta "$PROXY_META/public_ip" "$PUBLIC_IP" || return 1
    atomic_write_meta "$PROXY_META/public_ipv6" "$PUBLIC_IPV6" || return 1
}

atomic_write_meta() {
    local _target="$1" _value="$2" _tmp
    _tmp=$(mktemp "${_target}.new.XXXXXX" 2>/dev/null) || return 1
    printf '%s' "$_value" > "$_tmp" && chmod 600 "$_tmp" && mv -f "$_tmp" "$_target" || {
        rm -f "$_tmp"
        return 1
    }
}

read_config() {
    [ -f "$PROXY_CONFIG" ] && [ -f "$PROXY_META/config.env" ] || return 1
    while IFS='=' read -r _key _value; do
        case "$_key" in
            LISTEN_PORT) LISTEN_PORT="$_value" ;;
            EXT_PORT) EXT_PORT="$_value" ;;
            PROXY_USER) PROXY_USER="$_value" ;;
            PROXY_PASS) PROXY_PASS="$_value" ;;
            NAT_MODE) NAT_MODE="$_value" ;;
            BIND_FAMILY) BIND_FAMILY="$_value" ;;
            BIND_INTERFACE) BIND_INTERFACE="$_value" ;;
            LISTEN_HOST) LISTEN_HOST="$_value" ;;
            MANAGED_SING_BOX) MANAGED_SING_BOX="$_value" ;;
        esac
    done < "$PROXY_META/config.env"
    validate_port "$LISTEN_PORT" || return 1
    validate_port "$EXT_PORT" || return 1
    validate_username "$PROXY_USER" || return 1
    validate_password "$PROXY_PASS" || return 1
    case "$NAT_MODE" in 0|1) ;; *) return 1 ;; esac
    case "$BIND_FAMILY" in v4|v6) ;; *) return 1 ;; esac
    case "$LISTEN_HOST" in 0.0.0.0|::) ;; *) LISTEN_HOST="::" ;; esac
    case "$MANAGED_SING_BOX" in 0|1) ;; *) MANAGED_SING_BOX=0 ;; esac
    [ -z "${PUBLIC_IP:-}"   ] && PUBLIC_IP=$(cat "$PROXY_META/public_ip"   2>/dev/null || true)
    [ -z "${PUBLIC_IPV6:-}" ] && PUBLIC_IPV6=$(cat "$PROXY_META/public_ipv6" 2>/dev/null || true)
    return 0
}

show_install_diagnostics() {
    echo -e "${YELLOW}诊断信息:${PLAIN}"
    echo "  sing-box: $SING_BOX_BIN"
    "$SING_BOX_BIN" version 2>&1 | awk 'NR==1 { print; exit }' | sed 's/^/  version : /'
    echo "  config  : $PROXY_CONFIG"
    echo "  wrapper : $PROXY_BIN"
    [ -s "$PROXY_CONFIG" ] || echo -e "  ${RED}配置文件缺失或为空${PLAIN}"
}

write_wrapper() {
    cat > "$PROXY_BIN" <<WRAPPER
#!/bin/sh
exec "${SING_BOX_BIN}" run -c "${PROXY_CONFIG}" "\$@"
WRAPPER
    chmod 755 "$PROXY_BIN"
}

check_config() {
    "$SING_BOX_BIN" check -c "$PROXY_CONFIG"
}

backup_current_install() {
    INSTALL_BACKUP_DIR=$(mktemp -d "$(disk_tmp_dir)/proxy-backup-XXXXXX") || return 1
    [ ! -f "$PROXY_CONFIG" ] || cp -a "$PROXY_CONFIG" "$INSTALL_BACKUP_DIR/config" || { discard_install_backup; return 1; }
    [ ! -d "$PROXY_META" ] || cp -a "$PROXY_META" "$INSTALL_BACKUP_DIR/meta" || { discard_install_backup; return 1; }
    [ ! -f "$SING_BOX_MANAGED_MARKER" ] || cp -a "$SING_BOX_MANAGED_MARKER" "$INSTALL_BACKUP_DIR/managed-marker" || { discard_install_backup; return 1; }
    [ ! -f "$PROXY_BIN" ] || cp -a "$PROXY_BIN" "$INSTALL_BACKUP_DIR/wrapper" || { discard_install_backup; return 1; }
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
    echo -e "\n${YELLOW}安装被中断，正在恢复原配置和服务...${PLAIN}" >&2
    restore_current_install
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
        rm -f "$PROXY_META/firewall/$(basename "$_marker")"
    done
    close_ports "${LISTEN_PORT:-}"
    rm -f "$PROXY_CONFIG" "$PROXY_BIN" "$SYSTEMD_SERVICE" "$OPENRC_SERVICE"
    rm -f "$SING_BOX_MANAGED_MARKER"
    rm -rf "$PROXY_META"

    [ -f "$INSTALL_BACKUP_DIR/config" ] && cp -a "$INSTALL_BACKUP_DIR/config" "$PROXY_CONFIG"
    [ -d "$INSTALL_BACKUP_DIR/meta" ] && cp -a "$INSTALL_BACKUP_DIR/meta" "$PROXY_META"
    [ -f "$INSTALL_BACKUP_DIR/managed-marker" ] && cp -a "$INSTALL_BACKUP_DIR/managed-marker" "$SING_BOX_MANAGED_MARKER"
    [ -f "$INSTALL_BACKUP_DIR/wrapper" ] && cp -a "$INSTALL_BACKUP_DIR/wrapper" "$PROXY_BIN"
    if [ -f "$INSTALL_BACKUP_DIR/sing-box" ]; then
        cp -a "$INSTALL_BACKUP_DIR/sing-box" "$SING_BOX_BIN"
    elif [ "$MANAGED_SING_BOX" = "1" ]; then
        rm -f "$SING_BOX_BIN"
    fi
    [ -f "$INSTALL_BACKUP_DIR/systemd-service" ] && cp -a "$INSTALL_BACKUP_DIR/systemd-service" "$SYSTEMD_SERVICE"
    [ -f "$INSTALL_BACKUP_DIR/openrc-service" ] && cp -a "$INSTALL_BACKUP_DIR/openrc-service" "$OPENRC_SERVICE"
    if [ -f "$PROXY_META/config.env" ]; then
        read_config >/dev/null 2>&1 || true
    fi
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    [ -f "$INSTALL_BACKUP_DIR/was-enabled" ] && service_enable >/dev/null 2>&1 || true
    [ -f "$INSTALL_BACKUP_DIR/was-active" ] && service_start >/dev/null 2>&1 || true
    discard_install_backup
}

close_replaced_install_port() {
    local _old_port=""
    [ -f "$INSTALL_BACKUP_DIR/meta/config.env" ] || return 0
    _old_port=$(awk -F= '$1 == "LISTEN_PORT" { print $2; exit }' "$INSTALL_BACKUP_DIR/meta/config.env")
    validate_port "$_old_port" || return 0
    [ "$_old_port" = "$LISTEN_PORT" ] || close_ports "$_old_port"
}

read_config_live() {
    read_config || return 1
    local _warp_active=0
    if detect_warp; then
        _warp_active=1
        WARP_ACTIVE=1
        local _native_ipv4 _default_ipv4
        _native_ipv4=$(get_native_public_ipv4 2>/dev/null || true)
        _default_ipv4=$(get_default_public_ipv4 2>/dev/null || true)
        DEFAULT_EGRESS_IPV4="$_default_ipv4"
        if is_valid_ipv4 "$_native_ipv4"; then
            PUBLIC_IP="$_native_ipv4"
            printf '%s' "$PUBLIC_IP" > "$PROXY_META/public_ip"
        elif is_valid_ipv4 "$_default_ipv4" && [ "$PUBLIC_IP" = "$_default_ipv4" ]; then
            PUBLIC_IP=""
            : > "$PROXY_META/public_ip"
        fi
    else
        WARP_ACTIVE=0
        DEFAULT_EGRESS_IPV4=$(get_default_public_ipv4 2>/dev/null || true)
    fi
    [ -z "${BIND_INTERFACE:-}" ] && BIND_INTERFACE=$(get_native_egress_interface 2>/dev/null || true)
    if [ -z "${PUBLIC_IP:-}" ] && [ -z "${PUBLIC_IPV6:-}" ]; then
        [ "$_warp_active" = "1" ] || PUBLIC_IP=$(get_default_public_ipv4 2>/dev/null || true)
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]') || true
    fi
}

# ============================================================
# 服务管理
# ============================================================
write_systemd_service() {
    cat > "$SYSTEMD_SERVICE" <<SVC
[Unit]
Description=HTTP/SOCKS Proxy Server (sing-box mixed)
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=${PROXY_BIN}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SVC
    chmod 600 "$SYSTEMD_SERVICE"
}

write_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD'
#!/sbin/openrc-run

name="proxy-server"
description="HTTP/SOCKS Proxy Server"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<SVC
command="${PROXY_BIN}"
command_args=""
command_background="yes"
pidfile="/var/run/proxy-server.pid"
output_log="/var/log/proxy-server.log"
error_log="/var/log/proxy-server.log"

depend() {
    need net
    after firewall
}
SVC
    chmod +x "$OPENRC_SERVICE"
}

service_start() {
    [ -x "$PROXY_BIN" ] && [ -f "$PROXY_CONFIG" ] || {
        echo -e "${RED}HTTP/SOCKS Proxy 尚未安装或配置不完整${PLAIN}"
        return 1
    }
    service_is_active && return 0
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start proxy-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service proxy-server start
    else
        nohup "$PROXY_BIN" >/var/log/proxy-server.log 2>&1 &
        echo $! > /var/run/proxy-server.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop proxy-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service proxy-server stop 2>/dev/null
    else
        if [ -f /var/run/proxy-server.pid ]; then
            kill "$(cat /var/run/proxy-server.pid)" 2>/dev/null || true
            rm -f /var/run/proxy-server.pid
        fi
    fi
}

service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart proxy-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service proxy-server restart
    else
        service_stop; sleep 1; service_start
    fi
}

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable proxy-server >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add proxy-server default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable proxy-server 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del proxy-server default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet proxy-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service proxy-server status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/proxy-server.pid ] && kill -0 "$(cat /var/run/proxy-server.pid)" 2>/dev/null
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
    validate_port "${LISTEN_PORT:-}" || return 1
    command -v ss >/dev/null 2>&1 || return 1
    ss -lnt 2>/dev/null | awk -v port="$LISTEN_PORT" '
        NR > 1 { addr=$4; if (addr ~ (":" port "$")) found=1 }
        END { exit(found ? 0 : 1) }
    '
}

wait_for_health() {
    local _attempts="${1:-12}" _check="${2:-service_is_healthy}" _i=0
    while [ "$_i" -lt "$_attempts" ]; do
        "$_check" && return 0
        _i=$((_i + 1))
        [ "$_i" -lt "$_attempts" ] && sleep 1
    done
    return 1
}

service_is_enabled() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-enabled --quiet proxy-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update show default 2>/dev/null | grep -qE '(^|[[:space:]])proxy-server([[:space:]]|$)'
    else
        return 1
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u proxy-server -n 80 --no-pager
    else
        tail -n 80 /var/log/proxy-server.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

# ============================================================
# 安装 / 修改
# ============================================================
configure_proxy() {
    local _default_port
    _default_port=$(generate_random_port) || { echo -e "${RED}无法生成可用随机端口${PLAIN}"; return 1; }
    echo -e "\n${SKYBLUE}--- 配置 HTTP/SOCKS Proxy（mixed 入站）---${PLAIN}"

    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "请输入本机监听端口 [随机默认 ${_default_port}]: " LISTEN_PORT
        [ -z "$LISTEN_PORT" ] && LISTEN_PORT="$_default_port"
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        read -r -p "请输入对外转发端口 [留空=与监听端口相同]: " EXT_PORT
        [ -z "$EXT_PORT" ] && EXT_PORT="$LISTEN_PORT"
        validate_port "$EXT_PORT" || { echo -e "${RED}对外端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        echo -e "${YELLOW}提示：请确保宿主机已将 TCP ${EXT_PORT} 转发到本机 TCP ${LISTEN_PORT}${PLAIN}"
    else
        read -r -p "请输入端口 [随机默认 ${_default_port}]: " LISTEN_PORT
        [ -z "$LISTEN_PORT" ] && LISTEN_PORT="$_default_port"
        validate_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数（输入值: '${LISTEN_PORT}'）${PLAIN}"; return 1; }
        EXT_PORT="$LISTEN_PORT"
        echo -e "${GREEN}端口: ${LISTEN_PORT}${PLAIN}"
    fi

    read -r -p "请设置用户名 [留空自动生成]: " PROXY_USER
    if [ -z "$PROXY_USER" ]; then
        PROXY_USER=$(gen_username)
        echo -e "${GREEN}自动生成用户名: ${YELLOW}${PROXY_USER}${PLAIN}"
    fi
    validate_username "$PROXY_USER" || { echo -e "${RED}用户名无效（3-64 位，仅字母数字._-）${PLAIN}"; return 1; }

    read -r -p "请设置密码 [留空自动生成]: " PROXY_PASS
    if [ -z "$PROXY_PASS" ]; then
        PROXY_PASS=$(gen_password)
        echo -e "${GREEN}自动生成密码: ${YELLOW}${PROXY_PASS}${PLAIN}"
    fi
    validate_password "$PROXY_PASS" || { echo -e "${RED}密码无效（至少 8 位，且不能含空格/@:#/? 等）${PLAIN}"; return 1; }

    NODE_NAME="Proxy-$(hostname 2>/dev/null | tr -d '\n\r')"
    [ "$NODE_NAME" = "Proxy-" ] && NODE_NAME="Proxy-Node"
    return 0
}

install_proxy() {
    install_dependencies || { read -r -p "按回车键返回主菜单..." _; return; }
    detect_network
    backup_current_install || { echo -e "${RED}无法创建安装备份，已取消操作${PLAIN}"; read -r -p "按回车键返回主菜单..." _; return; }
    ensure_singbox || { restore_current_install; read -r -p "按回车键返回主菜单..." _; return; }
    configure_proxy || { restore_current_install; read -r -p "按回车键返回主菜单..." _; return; }
    write_config || {
        echo -e "${RED}Proxy 配置写入失败${PLAIN}"
        restore_current_install
        read -r -p "按回车键返回主菜单..." _
        return
    }
    write_wrapper
    echo -e "${YELLOW}正在校验 sing-box 配置...${PLAIN}"
    if ! check_config; then
        echo -e "${RED}sing-box 配置校验失败${PLAIN}"
        show_install_diagnostics
        restore_current_install
        read -r -p "按回车键返回主菜单..." _
        return
    fi
    echo -e "${GREEN}[OK] sing-box 配置校验通过${PLAIN}"

    if [ "$INIT_SYS" = "systemd" ]; then
        write_systemd_service
    elif [ "$INIT_SYS" = "openrc" ]; then
        write_openrc_service
    fi

    service_enable || { echo -e "${RED}Proxy 服务开机启动设置失败${PLAIN}"; restore_current_install; return; }
    open_ports "$LISTEN_PORT" || { restore_current_install; return; }
    echo -e "${YELLOW}正在启动 HTTP/SOCKS Proxy 服务...${PLAIN}"
    if service_is_active; then
        service_restart || { restore_current_install; return; }
    else
        service_start || { restore_current_install; return; }
    fi

    if wait_for_health; then
        echo -e "${GREEN}[OK] HTTP/SOCKS Proxy 服务端启动成功${PLAIN}"
    else
        echo -e "${RED}[FAIL] HTTP/SOCKS Proxy 启动失败，请查看日志：${PLAIN}"
        service_logs
        restore_current_install
        echo -e "${YELLOW}已恢复安装前的配置和服务${PLAIN}"
        read -r -p "按回车键返回主菜单..." _tmp
        return
    fi

    close_replaced_install_port
    discard_install_backup
    warn_streaming_egress
    show_config
}

change_port() {
    if [ ! -f "$PROXY_CONFIG" ]; then
        echo -e "${RED}未安装 HTTP/SOCKS Proxy${PLAIN}"; sleep 2; return
    fi
    read_config || { echo -e "${RED}配置或元数据损坏，无法安全修改${PLAIN}"; sleep 2; return; }
    local _old_port="$LISTEN_PORT" _was_active=0
    service_is_active && _was_active=1 || true
    detect_network

    echo -e "\n${YELLOW}修改监听端口，留空则取消。${PLAIN}"
    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "本机监听端口 [当前 ${LISTEN_PORT}]: " _port
        [ -z "$_port" ] && { echo "已取消。"; sleep 1; return; }
        validate_port "$_port" || { echo -e "${RED}端口无效${PLAIN}"; sleep 2; return; }
        LISTEN_PORT="$_port"
        read -r -p "对外转发端口 [当前 ${EXT_PORT}]: " _ext
        if [ -n "$_ext" ]; then
            validate_port "$_ext" || { echo -e "${RED}端口无效${PLAIN}"; sleep 2; return; }
            EXT_PORT="$_ext"
        else
            EXT_PORT="$LISTEN_PORT"
        fi
    else
        read -r -p "端口 [当前 ${LISTEN_PORT}]: " _port
        [ -z "$_port" ] && { echo "已取消。"; sleep 1; return; }
        validate_port "$_port" || { echo -e "${RED}端口无效${PLAIN}"; sleep 2; return; }
        LISTEN_PORT="$_port"
        EXT_PORT="$_port"
    fi

    cp -p "$PROXY_CONFIG" "${PROXY_CONFIG}.bak" 2>/dev/null && \
    cp -p "$PROXY_META/config.env" "$PROXY_META/config.env.bak" 2>/dev/null || {
        rm -f "${PROXY_CONFIG}.bak" "$PROXY_META/config.env.bak"
        echo -e "${RED}无法创建配置备份，已取消修改${PLAIN}"
        return
    }

    if ! write_config || ! check_config; then
        mv -f "${PROXY_CONFIG}.bak" "$PROXY_CONFIG" 2>/dev/null || true
        mv -f "$PROXY_META/config.env.bak" "$PROXY_META/config.env" 2>/dev/null || true
        echo -e "${RED}配置无效，已回滚${PLAIN}"
        sleep 2
        return
    fi
    if ! open_ports "$LISTEN_PORT"; then
        [ "$_old_port" = "$LISTEN_PORT" ] || close_ports "$LISTEN_PORT"
        mv -f "${PROXY_CONFIG}.bak" "$PROXY_CONFIG" 2>/dev/null || true
        mv -f "$PROXY_META/config.env.bak" "$PROXY_META/config.env" 2>/dev/null || true
        read_config || true
        echo -e "${RED}防火墙放行失败，配置已回滚${PLAIN}"
        return
    fi
    [ "$_was_active" = "0" ] || service_restart || true
    if [ "$_was_active" = "1" ] && ! wait_for_health; then
        [ "$_old_port" = "$LISTEN_PORT" ] || close_ports "$LISTEN_PORT"
        mv -f "${PROXY_CONFIG}.bak" "$PROXY_CONFIG" 2>/dev/null || true
        mv -f "$PROXY_META/config.env.bak" "$PROXY_META/config.env" 2>/dev/null || true
        read_config || true
        service_restart || true
        echo -e "${RED}服务重启失败，配置已回滚，请查看日志${PLAIN}"
        service_logs
        return
    fi
    [ "$_old_port" != "$LISTEN_PORT" ] && close_ports "$_old_port"
    rm -f "${PROXY_CONFIG}.bak" "$PROXY_META/config.env.bak"
    echo -e "${GREEN}[OK] 端口已更新为 ${LISTEN_PORT}${PLAIN}"
    show_config
}

change_credentials() {
    if [ ! -f "$PROXY_CONFIG" ]; then
        echo -e "${RED}未安装 HTTP/SOCKS Proxy${PLAIN}"; sleep 2; return
    fi
    read_config || { echo -e "${RED}配置或元数据损坏，无法安全修改${PLAIN}"; sleep 2; return; }
    local _was_active=0
    service_is_active && _was_active=1 || true

    echo -e "\n${YELLOW}修改用户名/密码，留空则保留原值。${PLAIN}"
    read -r -p "用户名 [当前 ${PROXY_USER}]: " _user
    if [ -n "$_user" ]; then
        validate_username "$_user" || { echo -e "${RED}用户名无效${PLAIN}"; sleep 2; return; }
        PROXY_USER="$_user"
    fi
    read -r -p "密码 [留空保留原密码，输入 auto 自动生成]: " _pass
    if [ "$_pass" = "auto" ]; then
        PROXY_PASS=$(gen_password)
        echo -e "${GREEN}自动生成密码: ${YELLOW}${PROXY_PASS}${PLAIN}"
    elif [ -n "$_pass" ]; then
        validate_password "$_pass" || { echo -e "${RED}密码无效${PLAIN}"; sleep 2; return; }
        PROXY_PASS="$_pass"
    fi

    cp -p "$PROXY_CONFIG" "${PROXY_CONFIG}.bak" 2>/dev/null && \
    cp -p "$PROXY_META/config.env" "$PROXY_META/config.env.bak" 2>/dev/null || {
        rm -f "${PROXY_CONFIG}.bak" "$PROXY_META/config.env.bak"
        echo -e "${RED}无法创建配置备份，已取消修改${PLAIN}"
        return
    }
    if ! write_config || ! check_config; then
        mv -f "${PROXY_CONFIG}.bak" "$PROXY_CONFIG" 2>/dev/null || true
        mv -f "$PROXY_META/config.env.bak" "$PROXY_META/config.env" 2>/dev/null || true
        echo -e "${RED}配置无效，已回滚${PLAIN}"
        sleep 2
        return
    fi
    [ "$_was_active" = "0" ] || service_restart || true
    if [ "$_was_active" = "1" ] && ! wait_for_health; then
        mv -f "${PROXY_CONFIG}.bak" "$PROXY_CONFIG" 2>/dev/null || true
        mv -f "$PROXY_META/config.env.bak" "$PROXY_META/config.env" 2>/dev/null || true
        read_config || true
        service_restart || true
        echo -e "${RED}服务重启失败，配置已回滚${PLAIN}"
        return
    fi
    rm -f "${PROXY_CONFIG}.bak" "$PROXY_META/config.env.bak"
    echo -e "${GREEN}[OK] 凭据已更新${PLAIN}"
    show_config
}

# ============================================================
# 客户端导出（无 TLS）
# ============================================================
export_uri_http() {
    local _server="$1" _port="$2" _name="${3:-}"
    local _host _enc_user _enc_pass _enc_name
    _host=$(format_ipv6_for_uri "$_server")
    _enc_user=$(uri_encode "$PROXY_USER")
    _enc_pass=$(uri_encode "$PROXY_PASS")
    if [ -n "$_name" ]; then
        _enc_name=$(uri_encode "$_name")
        printf 'http://%s:%s@%s:%s#%s\n' "$_enc_user" "$_enc_pass" "$_host" "$_port" "$_enc_name"
    else
        printf 'http://%s:%s@%s:%s\n' "$_enc_user" "$_enc_pass" "$_host" "$_port"
    fi
}

export_uri_socks5() {
    local _server="$1" _port="$2" _name="${3:-}"
    local _host _enc_user _enc_pass _enc_name
    _host=$(format_ipv6_for_uri "$_server")
    _enc_user=$(uri_encode "$PROXY_USER")
    _enc_pass=$(uri_encode "$PROXY_PASS")
    if [ -n "$_name" ]; then
        _enc_name=$(uri_encode "$_name")
        printf 'socks5://%s:%s@%s:%s#%s\n' "$_enc_user" "$_enc_pass" "$_host" "$_port" "$_enc_name"
    else
        printf 'socks5://%s:%s@%s:%s\n' "$_enc_user" "$_enc_pass" "$_host" "$_port"
    fi
}

export_mihomo_http() {
    local _server="$1" _port="$2" _node="$3" _yaml_server _user _pass _safe_node
    _yaml_server=$(format_server_for_yaml "$_server")
    _user=$(yaml_single_quote_escape "$PROXY_USER")
    _pass=$(yaml_single_quote_escape "$PROXY_PASS")
    _safe_node=$(yaml_single_quote_escape "$_node")
    printf "%s" "- {name: '${_safe_node}', type: http, server: ${_yaml_server}, port: ${_port}, username: '${_user}', password: '${_pass}'}"
}

export_mihomo_socks() {
    local _server="$1" _port="$2" _node="$3" _yaml_server _user _pass _safe_node
    _yaml_server=$(format_server_for_yaml "$_server")
    _user=$(yaml_single_quote_escape "$PROXY_USER")
    _pass=$(yaml_single_quote_escape "$PROXY_PASS")
    _safe_node=$(yaml_single_quote_escape "$_node")
    printf "%s" "- {name: '${_safe_node}', type: socks5, server: ${_yaml_server}, port: ${_port}, username: '${_user}', password: '${_pass}', udp: true}"
}

export_mihomo_stream_snippet() {
    local _server="$1" _port="$2" _node="$3" _yaml_server _user _pass _safe_node
    _yaml_server=$(format_server_for_yaml "$_server")
    _user=$(yaml_single_quote_escape "$PROXY_USER")
    _pass=$(yaml_single_quote_escape "$PROXY_PASS")
    _safe_node=$(yaml_single_quote_escape "$_node")
    cat <<SNIP
# Mihomo 流媒体 DNS 片段（推荐 SOCKS5 + 远程 DNS / socks5h）
# 说明: nameserver 通过 #节点名 detour，DNS 查询走代理，避免本地 DNS 泄露
proxies:
  - {name: '${_safe_node}', type: socks5, server: ${_yaml_server}, port: ${_port}, username: '${_user}', password: '${_pass}', udp: true}

dns:
  enable: true
  enhanced-mode: redir-host
  nameserver:
    - https://1.1.1.1/dns-query#${_safe_node}
    - https://8.8.8.8/dns-query#${_safe_node}
SNIP
}

show_node() {
    local _server="$1" _port="$2" _tag="$3" _mode="${4:-all}"
    [ -z "$_server" ] && return
    validate_server_address "$_server" || {
        echo -e "${RED}节点地址格式无效: ${_server}${PLAIN}"
        return 1
    }

    local _ip_type _country _server_name _node_http _node_socks _uri_http _uri_socks _png
    case "$_tag" in
        v6|IPv6|ipv6) _ip_type="IPv6" ;;
        *)            _ip_type="IPv4" ;;
    esac
    _country=$(get_country_code "$PUBLIC_IP" "$PUBLIC_IPV6")
    _server_name=$(generate_server_name)
    _node_http=$(generate_node_name "$_country" "$_server_name" "HTTP" "$_ip_type")
    _node_socks=$(generate_node_name "$_country" "$_server_name" "SOCKS5" "$_ip_type")
    _uri_http=$(export_uri_http "$_server" "$_port" "$_node_http")
    _uri_socks=$(export_uri_socks5 "$_server" "$_port" "$_node_socks")

    echo -e "${YELLOW}节点名称 (SOCKS5 推荐):${PLAIN}"
    print_copy_block "$_node_socks"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    if should_show_output "$_mode" "uri"; then
        echo -e "${GREEN}HTTP URI:${PLAIN}"
        print_copy_block "$_uri_http"
        echo -e "${GREEN}SOCKS5 URI:${PLAIN}"
        print_copy_block "$_uri_socks"
        echo -e "${YELLOW}警告: SOCKS5 客户端必须使用远程 DNS（socks5h），否则 DNS 可能泄露。${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "mihomo"; then
        echo -e "${GREEN}Mihomo HTTP 单行:${PLAIN}"
        print_copy_block "$(export_mihomo_http "$_server" "$_port" "$_node_http")"
        echo -e "${GREEN}Mihomo SOCKS5 单行（推荐）:${PLAIN}"
        print_copy_block "$(export_mihomo_socks "$_server" "$_port" "$_node_socks")"
        echo -e "${GREEN}Mihomo 流媒体 DNS 片段（socks5h / redir-host）:${PLAIN}"
        print_copy_block "$(export_mihomo_stream_snippet "$_server" "$_port" "$_node_socks")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "qrcode" || [ "$_mode" = "all" ]; then
        if [ "$_mode" = "all" ] || [ "$_mode" = "qrcode" ]; then
            echo -e "${GREEN}终端二维码 (SOCKS5 URI):${PLAIN}"
            if generate_terminal_qrcode "$_uri_socks"; then
                echo -e "${GREEN}[OK] 终端二维码已生成${PLAIN}"
                _png=$(generate_local_qrcode_png "$_uri_socks" "socks5" "$_ip_type" 2>/dev/null || true)
                [ -n "$_png" ] && echo -e "本地二维码图片: ${YELLOW}${_png}${PLAIN}"
            else
                echo -e "${YELLOW}[WARN] 未安装 qrencode，跳过终端二维码。${PLAIN}"
            fi
            echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        fi
    fi
}

show_config() {
    local _mode="${1:-all}"
    read_config_live || { echo -e "${RED}未找到 HTTP/SOCKS Proxy 配置${PLAIN}"; sleep 2; return; }

    local _country _server_name
    _country=$(get_country_code "$PUBLIC_IP" "$PUBLIC_IPV6")
    _server_name=$(generate_server_name)

    echo -e "\n${GREEN}HTTP/SOCKS Proxy 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "服务器名称: ${YELLOW}${_server_name}${PLAIN}"
    echo -e "国家/地区: ${YELLOW}${_country} / $(get_country_name "$_country")${PLAIN}"
    [ -n "$PUBLIC_IP"   ] && echo -e "IPv4 地址 : ${YELLOW}${PUBLIC_IP}${PLAIN}"
    [ -n "$PUBLIC_IPV6" ] && echo -e "IPv6 地址 : ${YELLOW}${PUBLIC_IPV6}${PLAIN}"
    if [ "$NAT_MODE" = "1" ] && [ "$EXT_PORT" != "$LISTEN_PORT" ]; then
        echo -e "监听端口 : ${YELLOW}${LISTEN_PORT}${PLAIN}  ${RED}<- 本机监听${PLAIN}"
        echo -e "对外端口 : ${YELLOW}${EXT_PORT}${PLAIN}  ${RED}<- 客户端连接此端口${PLAIN}"
    else
        echo -e "端口 Port : ${YELLOW}${EXT_PORT}${PLAIN}"
    fi
    echo -e "用户名    : ${YELLOW}${PROXY_USER}${PLAIN}"
    echo -e "密码      : ${YELLOW}${PROXY_PASS}${PLAIN}"
    echo -e "协议      : ${YELLOW}HTTP + SOCKS5 (mixed)${PLAIN}"
    [ -n "$BIND_INTERFACE" ] && echo -e "出站网卡  : ${YELLOW}${BIND_INTERFACE}${PLAIN}"
    [ "$NAT_MODE" = "1" ] && echo -e "机器类型  : ${YELLOW}NAT 机器${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    warn_streaming_egress

    if [ -n "$PUBLIC_IP" ]; then
        echo -e "${YELLOW}▼ IPv4 节点配置（流媒体优先）:${PLAIN}"
        show_node "$PUBLIC_IP" "$EXT_PORT" "v4" "$_mode"
    fi
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "${YELLOW}▼ IPv6 节点配置${PLAIN}"
        echo -e "${DIM}提示: 双栈场景流媒体解锁请优先使用上方 IPv4 节点${PLAIN}"
        show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6" "$_mode"
    fi

    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        read -r -p "未检测到公网 IP，请手动输入节点地址: " _manual_addr
        if [ -n "$_manual_addr" ]; then
            echo -e "${YELLOW}▼ 手动地址节点配置${PLAIN}"
            show_node "$_manual_addr" "$EXT_PORT" "manual" "$_mode"
        fi
    fi

    read -r -p "按回车键返回主菜单..." _tmp
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
        if [ -n "$_owner" ] && ! kill -0 "$_owner" 2>/dev/null; then
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
    [ -f "$PROXY_CONFIG" ] && [ -x "$SING_BOX_BIN" ] || {
        echo -e "${RED}HTTP/SOCKS Proxy 尚未安装，请先执行安装${PLAIN}"
        return 1
    }
    read_config || { echo -e "${RED}元数据不完整，无法安全升级${PLAIN}"; return 1; }
    get_latest_version || return 1

    local _current_version _latest_version _was_active=0
    local _anytls_was_active=0 _vless_was_active=0
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
    shared_service_is_active anytls-server && _anytls_was_active=1 || true
    shared_service_is_active vless-server && _vless_was_active=1 || true
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
    if [ "$_was_active" = "1" ]; then
        service_restart || _restart_failed=1
    fi
    if [ "$_anytls_was_active" = "1" ]; then
        shared_service_restart anytls-server /usr/local/bin/anytls-server || _restart_failed=1
    fi
    if [ "$_vless_was_active" = "1" ]; then
        shared_service_restart vless-server /usr/local/bin/vless-server || _restart_failed=1
    fi
    if [ "$_was_active" = "1" ] || [ "$_anytls_was_active" = "1" ] || [ "$_vless_was_active" = "1" ]; then
        sleep 2
    fi
    [ "$_was_active" = "0" ] || wait_for_health || _restart_failed=1
    [ "$_anytls_was_active" = "0" ] || shared_service_is_active anytls-server || _restart_failed=1
    [ "$_vless_was_active" = "0" ] || shared_service_is_active vless-server || _restart_failed=1
    if [ "$_restart_failed" = "1" ]; then
        mv -f "${SING_BOX_BIN}.bak" "$SING_BOX_BIN" 2>/dev/null || true
        [ "$_was_active" = "0" ] || service_restart || true
        [ "$_anytls_was_active" = "0" ] || shared_service_restart anytls-server /usr/local/bin/anytls-server || true
        [ "$_vless_was_active" = "0" ] || shared_service_restart vless-server /usr/local/bin/vless-server || true
        echo -e "${RED}升级后共享服务启动失败，已回滚${PLAIN}"
        return 1
    fi
    rm -f "${SING_BOX_BIN}.bak"
    echo -e "${GREEN}[OK] sing-box 已从 ${_current_version:-未知版本} 升级到 ${_latest_version}${PLAIN}"
    return 0
}

upgrade_proxy() {
    if ! install_dependencies; then
        read -r -p "按回车键返回主菜单..." _
        return 1
    fi
    local _status=0
    upgrade_core || _status=$?
    sleep 2
    return "$_status"
}

uninstall_proxy() {
    echo -e "${RED}警告：这将删除 HTTP/SOCKS Proxy 服务、配置和定时更新。${PLAIN}"
    read -r -p "确认卸载 HTTP/SOCKS Proxy？[y/N]: " _confirm
    case "$_confirm" in
        [yY]) ;;
        *) echo "已取消。"; sleep 1; return ;;
    esac

    read_config 2>/dev/null || true
    local _managed_core=0 _other_file=""
    if [ "$MANAGED_SING_BOX" = "1" ] || [ -f "$SING_BOX_MANAGED_MARKER" ]; then
        _managed_core=1
    fi
    if [ "$MANAGED_SING_BOX" = "1" ]; then
        mkdir -p "$PROXY_DIR" 2>/dev/null || true
        : > "$SING_BOX_MANAGED_MARKER" 2>/dev/null || true
    fi
    service_stop
    service_disable
    close_ports "${LISTEN_PORT:-}"
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vF "$AUTO_UPDATE_SCRIPT" | crontab - 2>/dev/null || true
    fi
    rm -f "$SYSTEMD_SERVICE" "$OPENRC_SERVICE" "$AUTO_UPDATE_SCRIPT" "$PROXY_BIN"
    rm -f "$PROXY_CONFIG" "$AUTO_UPDATE_LOG"
    rm -rf "$PROXY_META"
    if [ -d "$PROXY_DIR" ]; then
        _other_file=$(find "$PROXY_DIR" -mindepth 1 -maxdepth 1 ! -name '.singbox-tools-managed' -print -quit 2>/dev/null)
    fi
    if [ -z "$_other_file" ]; then
        rm -f "$SING_BOX_MANAGED_MARKER"
        rmdir "$PROXY_DIR" 2>/dev/null || true
        [ "$_managed_core" = "1" ] && rm -f "$SING_BOX_BIN"
    elif [ "$_managed_core" = "1" ]; then
        echo -e "${YELLOW}检测到 /etc/sing-box 中还有其他文件，已保留共享 sing-box 二进制${PLAIN}"
    fi
    rm -f /var/run/proxy-server.pid
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    echo -e "${GREEN}[OK] HTTP/SOCKS Proxy 已卸载${PLAIN}"
    sleep 2
}

setup_autoupdate() {
    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
LOG_FILE=/var/log/proxy-autoupdate.log
TMP_SCRIPT=$(mktemp /tmp/proxy-update-XXXXXX.sh) || exit 1
trap 'rm -f "$TMP_SCRIPT"' EXIT INT TERM
{
  echo "[$(date '+%F %T')] 开始检查 sing-box 更新"
  curl -fsSL --connect-timeout 15 --max-time 60 \
    https://raw.githubusercontent.com/everett7623/hy2/main/proxy.sh -o "$TMP_SCRIPT" || exit 1
  bash -n "$TMP_SCRIPT" || exit 1
  bash "$TMP_SCRIPT" --upgrade-noninteractive
  echo "[$(date '+%F %T')] 更新检查完成"
} >> "$LOG_FILE" 2>&1
AUTOUPDATE_EOF
    chmod +x "$AUTO_UPDATE_SCRIPT"

    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "$AUTO_UPDATE_SCRIPT"; echo "27 4 * * 1 $AUTO_UPDATE_SCRIPT") | crontab -
        echo -e "${GREEN}[OK] 已设置每周一 04:27 自动检查 sing-box 更新${PLAIN}"
    else
        echo -e "${YELLOW}系统未安装 crontab，请手动安装 cron 后再设置自动升级${PLAIN}"
    fi
    sleep 2
}

remove_autoupdate() {
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vF "$AUTO_UPDATE_SCRIPT" | crontab - 2>/dev/null || true
    fi
    rm -f "$AUTO_UPDATE_SCRIPT"
    echo -e "${GREEN}[OK] 已移除 Proxy 自动更新任务${PLAIN}"
    sleep 2
}

enable_bbr() {
    echo -e "\n${SKYBLUE}--- 一键开启 BBR ---${PLAIN}"

    local _kver _kmaj _kmin
    _kver=$(uname -r)
    _kmaj=$(echo "$_kver" | cut -d. -f1)
    _kmin=$(echo "$_kver" | cut -d. -f2)

    echo -e "  当前内核: ${YELLOW}${_kver}${PLAIN}"

    if [ "$_kmaj" -lt 4 ] || { [ "$_kmaj" -eq 4 ] && [ "$_kmin" -lt 9 ]; }; then
        echo -e "${RED}内核版本过低（< 4.9），不支持 BBR，请升级内核后重试${PLAIN}"
        sleep 3; return
    fi

    local _cur_cc
    _cur_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    echo -e "  当前拥塞控制: ${YELLOW}${_cur_cc:-未知}${PLAIN}"

    local _cc="bbr"
    echo -e "${YELLOW}将启用标准 ${_cc} + fq 队列调度...${PLAIN}"
    modprobe tcp_bbr 2>/dev/null || true

    local _sysctl_conf="/etc/sysctl.d/99-proxy-bbr.conf"
    cat > "$_sysctl_conf" <<EOF
# HTTP/SOCKS Proxy 脚本写入 - 标准 BBR 优化
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = ${_cc}
EOF

    sysctl -p "$_sysctl_conf" >/dev/null 2>&1

    local _result
    _result=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [ "$_result" = "$_cc" ]; then
        echo -e "${GREEN}[OK] 标准 BBR (${_cc}) 已成功启用${PLAIN}"
        echo -e "${GREEN}[OK] 队列调度: $(sysctl -n net.core.default_qdisc 2>/dev/null)${PLAIN}"
        echo -e "${GREEN}[OK] 配置已写入 ${_sysctl_conf}，重启后持续生效${PLAIN}"
    else
        echo -e "${RED}[FAIL] BBR 启用失败，请手动检查内核是否支持 tcp_bbr${PLAIN}"
    fi
    sleep 3
}

diagnose_proxy() {
    echo -e "\n${GREEN}HTTP/SOCKS Proxy 运行诊断${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    if ! read_config; then
        echo -e "  ${RED}[X] 配置或元数据缺失${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
        return 1
    fi
    if check_config >/dev/null 2>&1; then
        echo -e "  ${GREEN}[OK] sing-box 配置有效${PLAIN}"
    else
        echo -e "  ${RED}[X] sing-box 配置无效${PLAIN}"
        check_config 2>&1 | sed 's/^/    /'
    fi
    if service_is_active; then
        echo -e "  ${GREEN}[OK] Proxy 服务运行中${PLAIN}"
    else
        echo -e "  ${RED}[X] Proxy 服务未运行${PLAIN}"
    fi
    if command -v ss >/dev/null 2>&1 && ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:|\])${LISTEN_PORT}$"; then
        echo -e "  ${GREEN}[OK] TCP ${LISTEN_PORT} 正在监听${PLAIN}"
    else
        echo -e "  ${YELLOW}! 未检测到 TCP ${LISTEN_PORT} 监听${PLAIN}"
    fi
    echo -e "  用户名: ${YELLOW}${PROXY_USER}${PLAIN}"
    [ -n "$BIND_INTERFACE" ] && echo -e "  出站网卡: ${YELLOW}${BIND_INTERFACE}${PLAIN}"
    DEFAULT_EGRESS_IPV4=$(get_default_public_ipv4 2>/dev/null || true)
    [ -z "${PUBLIC_IP:-}" ] && PUBLIC_IP=$(cat "$PROXY_META/public_ip" 2>/dev/null || true)
    check_egress_ip
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

show_system_info() {
    echo -e "\n${GREEN}系统信息${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e " 主机名: $(hostname 2>/dev/null)"
    echo -e " 内核  : $(uname -r)"
    echo -e " 架构  : $(uname -m)"
    [ -x "$SING_BOX_BIN" ] && echo -e " 核心  : $("$SING_BOX_BIN" version 2>/dev/null | awk 'NR==1 { print; exit }')"
    echo -e " 内存  : $(awk '/MemAvailable/ {printf "%.0f MB available", $2/1024}' /proc/meminfo 2>/dev/null)"
    echo -e " 磁盘  : $(df -h / 2>/dev/null | awk 'NR==2 {print $3" / "$2" ("$5" used)"}')"
    echo -e " 负载  : $(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    read -r -p "按回车返回..." _tmp
}

server_tools_menu() {
    while true; do
        clear_screen
        local _auto_status="${RED}未启用${PLAIN}"
        if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -qF "$AUTO_UPDATE_SCRIPT"; then
            _auto_status="${GREEN}已启用${PLAIN}"
        fi
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  HTTP/SOCKS Proxy 工具箱${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 自动更新: ${_auto_status}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 查看系统信息"
        echo -e " 2. 查看 Proxy 日志"
        echo -e " 3. 运行状态诊断"
        echo -e " 4. 出站 IP 自检"
        echo -e " 5. 开启 BBR"
        echo -e " 6. 设置每周自动更新"
        echo -e " 7. 移除自动更新"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-7]: " choice
        case "$choice" in
            1) show_system_info ;;
            2) service_logs; read -r -p "按回车返回..." _tmp ;;
            3) diagnose_proxy; read -r -p "按回车返回..." _tmp ;;
            4)
                read_config_live 2>/dev/null || true
                DEFAULT_EGRESS_IPV4=$(get_default_public_ipv4 2>/dev/null || true)
                [ -z "${BIND_INTERFACE:-}" ] && BIND_INTERFACE=$(get_native_egress_interface 2>/dev/null || true)
                check_egress_ip
                read -r -p "按回车返回..." _tmp
                ;;
            5) enable_bbr ;;
            6) setup_autoupdate ;;
            7) remove_autoupdate ;;
            0|q|quit|exit) return ;;
            *) echo -e "${RED}无效选项${PLAIN}"; sleep 1 ;;
        esac
    done
}

manage_proxy() {
    if [ ! -f "$PROXY_CONFIG" ] || [ ! -x "$PROXY_BIN" ]; then
        echo -e "${RED}HTTP/SOCKS Proxy 尚未安装，请先执行安装${PLAIN}"
        sleep 2
        return
    fi
    while true; do
        clear_screen
        local STATUS
        service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  HTTP/SOCKS Proxy 服务管理${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: ${STATUS}"
        echo -e " 1. 启动"
        echo -e " 2. 停止"
        echo -e " 3. 重启"
        echo -e " 4. 查看日志"
        echo -e " 5. 修改端口"
        echo -e " 6. 修改用户名/密码"
        echo -e " 0. 返回"
        read -r -p "请输入选项 [0-6]: " choice
        case "$choice" in
            1)
                if service_start && sleep 1 && service_is_active; then
                    echo -e "${GREEN}[OK] Proxy 已启动${PLAIN}"
                else
                    echo -e "${RED}[FAIL] 启动失败，请查看日志${PLAIN}"
                fi
                sleep 1
                ;;
            2)
                service_stop
                sleep 1
                service_is_active && echo -e "${RED}[FAIL] 服务仍在运行${PLAIN}" || echo -e "${GREEN}[OK] Proxy 已停止${PLAIN}"
                sleep 1
                ;;
            3)
                if service_restart && sleep 1 && service_is_active; then
                    echo -e "${GREEN}[OK] Proxy 已重启${PLAIN}"
                else
                    echo -e "${RED}[FAIL] 重启失败，请查看日志${PLAIN}"
                fi
                sleep 1
                ;;
            4) service_logs; read -r -p "按回车返回..." _tmp ;;
            5) change_port ;;
            6) change_credentials ;;
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
        local STATUS _ver_line
        if [ -f "$PROXY_CONFIG" ] && [ -x "$PROXY_BIN" ] && [ -x "$SING_BOX_BIN" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        elif [ -e "$PROXY_CONFIG" ] || [ -e "$PROXY_BIN" ]; then
            STATUS="${YELLOW}安装不完整${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi
        _ver_line=""
        if [ -x "$SING_BOX_BIN" ]; then
            _ver_line=" ($(get_installed_version))"
        fi

        echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
        echo -e "  ${GREEN}${BOLD}HTTP/SOCKS Proxy Management Script${PLAIN} ${DIM}v2.0.24${PLAIN}"
        echo -e "  ${DIM}适合住宅 IP VPS 解锁场景${PLAIN}"
        echo -e "${SKYBLUE}${BOLD}================================================${PLAIN}"
        echo -e "  项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e "  作者    : ${YELLOW}everettlabs${PLAIN}"
        echo -e "  实现    : ${YELLOW}sing-box 原生 mixed 入站 (HTTP+SOCKS5)${PLAIN}"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e "  Seedloc博客 : https://seedloc.com"
        echo -e "  VPSknow网站 : https://vpsknow.com"
        echo -e "  Nodeloc论坛 : https://nodeloc.com"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e "  当前状态: $STATUS${_ver_line}"
        echo -e "${SKYBLUE}------------------------------------------------${PLAIN}"
        echo -e " 1. 安装 / 重装 HTTP/SOCKS Proxy"
        echo -e " 2. 查看节点信息 / 链接"
        echo -e " 3. 管理服务（启动 / 停止 / 重启 / 改端口 / 改凭据）"
        echo -e " 4. 升级 sing-box"
        echo -e " 5. 卸载 HTTP/SOCKS Proxy"
        echo -e " 6. 服务器工具"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}================================================${PLAIN}"

        read -r -p "请输入选项 [0-6]: " choice
        case "$choice" in
            1) install_proxy ;;
            2) show_config ;;
            3) manage_proxy ;;
            4) upgrade_proxy ;;
            5) uninstall_proxy ;;
            6) server_tools_menu ;;
            0|q|quit|exit) exit 0 ;;
            *) echo -e "${RED}无效选项，请输入 0-6${PLAIN}"; sleep 1 ;;
        esac
    done
}

# 非交互升级，供 cron 使用
if [ "${1:-}" = "--upgrade-noninteractive" ]; then
    check_root
    check_sys
    detect_init
    install_dependencies || exit 1
    upgrade_core
    exit $?
fi

# ============================================================
# 入口（PROXY_LIB_ONLY=1 时跳过）
# ============================================================
[ "$_PROXY_LIB_ONLY" = "1" ] && return 0

check_root
check_sys
detect_init
case "${1:-menu}" in
    install) install_proxy ;;
    info|node|export|all) show_config ;;
    uri|link) show_config uri ;;
    mihomo|clash) show_config mihomo ;;
    qrcode|qr) show_config qrcode ;;
    manage|service|config) manage_proxy ;;
    upgrade|update) upgrade_proxy ;;
    uninstall|remove) uninstall_proxy ;;
    diagnose) diagnose_proxy ;;
    menu|"") main_menu ;;
    *)
        echo -e "${RED}未知命令: ${1}${PLAIN}"
        echo "可用命令: install | info | uri | mihomo | manage | upgrade | uninstall | diagnose | menu"
        exit 1
        ;;
esac
