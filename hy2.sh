#!/bin/bash
#====================================================================================
# 项目：Hysteria2 Management Script
# 作者：everettlabs
# 版本：v2.0.18
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-07-14
#
# 支持系统:
#   Debian 10/11/12+
#   Ubuntu 20.04/22.04/24.04+
#   CentOS 7/8/9
#   Rocky Linux 8/9
#   AlmaLinux 8/9
#   Fedora 38+
#   Arch Linux / Manjaro
#   Alpine Linux 3.x
#
# 支持环境:
#   标准 VPS / 独立服务器
#   NAT 机器（内外端口不同）
#   IPv6 单栈 / 双栈机器
#   低配 VPS（无需 jq，低内存友好）
#
# v1.0.0: 端口跳跃 + BBR/自动更新/防火墙/QR/修改带宽/服务工具
#====================================================================================

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

# --- 颜色 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

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
BOLD='\033[1m'
DIM='\033[2m'

# --- 路径 ---
HY_BIN="/usr/local/bin/hysteria"
HY_CONFIG="/etc/hysteria/config.yaml"
HY_CERT_DIR="/etc/hysteria/cert"
HY_META="/etc/hysteria/meta"
SERVICE_FILE="/etc/systemd/system/hysteria-server.service"
OPENRC_SERVICE="/etc/init.d/hysteria-server"
AUTO_UPDATE_SCRIPT="/usr/local/bin/hy2-autoupdate.sh"
AUTO_UPDATE_LOG="/var/log/hy2-autoupdate.log"
INSTALL_BACKUP_DIR=""
INSTALL_ROLLBACK_ARMED=0
INSTALL_PREV_INT_TRAP=""
INSTALL_PREV_TERM_TRAP=""
UPGRADE_LOCK_FILE="${UPGRADE_LOCK_FILE:-/var/lock/hy2-upgrade.lock}"
UPGRADE_LOCK_MODE=""

# --- 运行时变量 ---
NAT_MODE=0
IPV6_ONLY=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
LISTEN_PORT=""
EXT_PORT=""
PORT_HOP=""  # 端口跳跃，如 "20000:50000"
SNI="amd.com"
BW_UP="50"
BW_DOWN="100"

# ============================================================
# 环境检测
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
    [ "$RELEASE" = "unknown" ] && echo -e "${YELLOW}警告: 未检测到已知系统，将尝试通用安装${PLAIN}"
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

# ============================================================
# 服务管理
# ============================================================

service_start() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start hysteria-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service hysteria-server start
    else
        nohup "$HY_BIN" server -c "$HY_CONFIG" >/var/log/hysteria.log 2>&1 &
        echo $! > /var/run/hysteria.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop hysteria-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service hysteria-server stop 2>/dev/null
    else
        [ -f /var/run/hysteria.pid ] && kill "$(cat /var/run/hysteria.pid)" 2>/dev/null && rm -f /var/run/hysteria.pid
        pkill -f "hysteria server" 2>/dev/null
    fi
}

service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart hysteria-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service hysteria-server restart
    else
        service_stop; sleep 1; service_start
    fi
}

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable hysteria-server >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add hysteria-server default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable hysteria-server 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del hysteria-server default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet hysteria-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service hysteria-server status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/hysteria.pid ] && kill -0 "$(cat /var/run/hysteria.pid)" 2>/dev/null
    fi
}

service_is_healthy() {
    service_is_active || return 1
    valid_port "${LISTEN_PORT:-}" || return 0
    command -v ss >/dev/null 2>&1 || return 0
    ss -lnu 2>/dev/null | awk -v port="$LISTEN_PORT" '
        NR > 1 { addr=$4; if (addr ~ (":" port "$")) found=1 }
        END { exit(found ? 0 : 1) }
    '
}

has_free_space_mb() {
    local _path="$1" _required="$2" _available
    command -v df >/dev/null 2>&1 || return 0
    _available=$(df -Pk "$_path" 2>/dev/null | awk 'NR == 2 { print $4; exit }')
    [ -z "$_available" ] && return 0
    [ "$_available" -ge $((_required * 1024)) ]
}

check_download_space() {
    has_free_space_mb "$(disk_tmp_dir)" 48 && has_free_space_mb "$(dirname "$HY_BIN")" 32 || {
        echo -e "${RED}磁盘空间不足：下载 Hysteria2 至少需要临时分区 48MB、目标分区 32MB${PLAIN}"
        return 1
    }
}

service_is_enabled() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-enabled --quiet hysteria-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update show default 2>/dev/null | grep -qE '(^|[[:space:]])hysteria-server([[:space:]]|$)'
    else
        return 1
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u hysteria-server -n 50 --no-pager
    else
        tail -n 50 /var/log/hysteria.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

setup_systemd_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Hysteria 2 Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${HY_BIN} server -c ${HY_CONFIG}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

setup_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD'
#!/sbin/openrc-run

name="hysteria-server"
description="Hysteria 2 Server"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<EOF
command="${HY_BIN}"
command_args="server -c ${HY_CONFIG}"
command_background=true
pidfile="/var/run/hysteria.pid"
output_log="/var/log/hysteria.log"
error_log="/var/log/hysteria.log"

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$OPENRC_SERVICE"
}

backup_current_install() {
    INSTALL_BACKUP_DIR=$(mktemp -d "$(disk_tmp_dir)/hy2-install-backup-XXXXXX" 2>/dev/null) || return 1
    [ ! -f "$HY_BIN" ] || cp -a "$HY_BIN" "$INSTALL_BACKUP_DIR/bin" || { discard_install_backup; return 1; }
    [ ! -f "$HY_CONFIG" ] || cp -a "$HY_CONFIG" "$INSTALL_BACKUP_DIR/config" || { discard_install_backup; return 1; }
    [ ! -d "$HY_META" ] || cp -a "$HY_META" "$INSTALL_BACKUP_DIR/meta" || { discard_install_backup; return 1; }
    [ ! -d "$HY_CERT_DIR" ] || cp -a "$HY_CERT_DIR" "$INSTALL_BACKUP_DIR/cert" || { discard_install_backup; return 1; }
    [ ! -f "$SERVICE_FILE" ] || cp -a "$SERVICE_FILE" "$INSTALL_BACKUP_DIR/systemd-service" || { discard_install_backup; return 1; }
    [ ! -f "$OPENRC_SERVICE" ] || cp -a "$OPENRC_SERVICE" "$INSTALL_BACKUP_DIR/openrc-service" || { discard_install_backup; return 1; }
    service_is_active && : > "$INSTALL_BACKUP_DIR/was-active" || true
    service_is_enabled && : > "$INSTALL_BACKUP_DIR/was-enabled" || true
    arm_install_rollback
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
    [ -n "$INSTALL_BACKUP_DIR" ] && [ -d "$INSTALL_BACKUP_DIR" ] || return 0
    service_stop
    service_disable
    rm -f "$HY_BIN" "$HY_CONFIG" "$SERVICE_FILE" "$OPENRC_SERVICE"
    rm -rf "$HY_META" "$HY_CERT_DIR"
    [ -f "$INSTALL_BACKUP_DIR/bin" ] && cp -a "$INSTALL_BACKUP_DIR/bin" "$HY_BIN"
    [ -f "$INSTALL_BACKUP_DIR/config" ] && cp -a "$INSTALL_BACKUP_DIR/config" "$HY_CONFIG"
    [ -d "$INSTALL_BACKUP_DIR/meta" ] && cp -a "$INSTALL_BACKUP_DIR/meta" "$HY_META"
    [ -d "$INSTALL_BACKUP_DIR/cert" ] && cp -a "$INSTALL_BACKUP_DIR/cert" "$HY_CERT_DIR"
    [ -f "$INSTALL_BACKUP_DIR/systemd-service" ] && cp -a "$INSTALL_BACKUP_DIR/systemd-service" "$SERVICE_FILE"
    [ -f "$INSTALL_BACKUP_DIR/openrc-service" ] && cp -a "$INSTALL_BACKUP_DIR/openrc-service" "$OPENRC_SERVICE"
    [ "$INIT_SYS" = "systemd" ] && systemctl daemon-reload
    [ -f "$INSTALL_BACKUP_DIR/was-enabled" ] && service_enable >/dev/null 2>&1 || true
    [ -f "$INSTALL_BACKUP_DIR/was-active" ] && service_start >/dev/null 2>&1 || true
    discard_install_backup
}

# ============================================================
# 网络检测
# ============================================================

is_valid_ipv4() {
    echo "$1" | awk -F. 'NF != 4 { exit 1 } { for (i=1; i<=4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1 }'
}

is_valid_ipv6() {
    case "$1" in
        *:*) echo "$1" | grep -qE '^[0-9A-Fa-f:]+$' ;;
        *) return 1 ;;
    esac
}

detect_warp() {
    if command -v ip >/dev/null 2>&1 && ip link show 2>/dev/null | grep -qE '^[0-9]+: (wgcf|warp|wg)[^:]*:'; then
        return 0
    fi
    command -v warp-cli >/dev/null 2>&1 && warp-cli status 2>/dev/null | grep -qiE 'connected|已连接'
}

get_native_public_ipv4() {
    command -v ip >/dev/null 2>&1 || return 1
    local _iface _local_ip _ip _url
    _iface=$(ip -4 route show default 2>/dev/null | awk '/default/ { for(i=1;i<=NF;i++) if($i=="dev" && $(i+1) !~ /wgcf|warp|^tun|^wg|tailscale|zt/) { print $(i+1); exit } }')
    [ -n "$_iface" ] || return 1
    _local_ip=$(ip -4 addr show dev "$_iface" scope global 2>/dev/null | awk '/inet / { sub(/\/.*/, "", $2); print $2; exit }')
    [ -n "$_local_ip" ] || return 1
    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --interface "$_local_ip" --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        is_valid_ipv4 "$_ip" && { printf '%s' "$_ip"; return 0; }
    done
    return 1
}

get_default_public_ipv4() {
    local _ip _url
    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        is_valid_ipv4 "$_ip" && { printf '%s' "$_ip"; return 0; }
    done
    return 1
}

detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    NAT_MODE=0; IPV6_ONLY=0; HAS_IPV4=0; HAS_IPV6=0; PUBLIC_IP=""; PUBLIC_IPV6=""

    local _ip _url
    _ip=$(get_native_public_ipv4 2>/dev/null || true)
    if is_valid_ipv4 "$_ip"; then
        PUBLIC_IP="$_ip"; HAS_IPV4=1
    elif ! detect_warp; then
        _ip=$(get_default_public_ipv4 2>/dev/null || true)
        is_valid_ipv4 "$_ip" && { PUBLIC_IP="$_ip"; HAS_IPV4=1; }
    fi

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if is_valid_ipv6 "$_ip"; then
            PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break
        fi
    done

    # NAT 判断：本机接口 IP 列表里找不到公网 IPv4
    if [ "$HAS_IPV4" = "1" ] && command -v ip >/dev/null 2>&1; then
        local _local_ips
        _local_ips=$(ip addr show 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | grep -v '^127\.' | grep -v '^169\.254\.')
        echo "$_local_ips" | grep -q "^${PUBLIC_IP}$" || NAT_MODE=1
    fi

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && IPV6_ONLY=1

    if   [ "$NAT_MODE"  = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$IPV6_ONLY" = "1" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"  = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv4: ${PUBLIC_IP} | IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV4"  = "1" ]; then echo -e "  机器类型: ${GREEN}标准 IPv4${PLAIN}（IP: ${PUBLIC_IP}）"
    else                               echo -e "  机器类型: ${RED}无法检测，请手动输入${PLAIN}"
    fi
}

# ============================================================
# 依赖安装
# ============================================================

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
    for _cmd in curl openssl ip; do
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
            retry_command apk add --no-cache bash curl wget ca-certificates openssl iproute2 procps >/dev/null 2>&1
            apk add --no-cache libqrencode >/dev/null 2>&1 || true
            ;;
        centos)
            retry_command yum install -y curl wget ca-certificates openssl iproute procps-ng >/dev/null 2>&1
            yum install -y qrencode >/dev/null 2>&1 || true
            ;;
        fedora|rocky)
            retry_command dnf install -y curl wget ca-certificates openssl iproute procps-ng >/dev/null 2>&1
            dnf install -y qrencode >/dev/null 2>&1 || true
            ;;
        arch)
            retry_command pacman -Sy --noconfirm curl wget ca-certificates openssl iproute2 procps-ng >/dev/null 2>&1
            pacman -S --noconfirm qrencode >/dev/null 2>&1 || true
            ;;
        *)
            if command -v apt-get >/dev/null 2>&1; then
                retry_command apt-get update -qq >/dev/null 2>&1
                retry_command apt-get install -y -qq curl wget ca-certificates openssl iproute2 procps >/dev/null 2>&1
                apt-get install -y -qq qrencode >/dev/null 2>&1 || true
            else
                echo -e "${RED}无法识别包管理器，请手动安装 curl、wget、openssl 和 iproute2${PLAIN}"
                return 1
            fi
            ;;
    esac
    for _cmd in curl openssl ip; do
        command -v "$_cmd" >/dev/null 2>&1 || {
            echo -e "${RED}依赖安装失败: 缺少 ${_cmd}${PLAIN}"
            return 1
        }
    done
}

download_file() {
    local _url="$1" _dest="$2" _attempt=1 _delay=2
    while [ "$_attempt" -le 3 ]; do
        if command -v curl >/dev/null 2>&1 && curl -fL --connect-timeout 10 --max-time 120 -o "$_dest" "$_url" 2>/dev/null; then return 0; fi
        if command -v wget >/dev/null 2>&1 && wget -q --timeout=60 -O "$_dest" "$_url" 2>/dev/null; then return 0; fi
        rm -f "$_dest"
        [ "$_attempt" -ge 3 ] && break
        sleep "$_delay"; _attempt=$((_attempt + 1)); _delay=$((_delay * 2))
    done
    return 1
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_positive_number() {
    echo "$1" | grep -qE '^[0-9]+([.][0-9]+)?$' && [ "$1" != "0" ] && [ "$1" != "0.0" ]
}

# ============================================================
# 获取版本 & 下载
#
# 设计说明：
#   Hysteria 官方 GitHub tag 格式为 "app/v2.x.x"
#   下载 URL 需要完整 tag（含 app/ 前缀）
#   版本号对比（当前 vs 最新）使用剥离前缀后的 vX.Y.Z 格式
#
#   因此维护两个变量：
#     LAST_VERSION     — 纯版本号（vX.Y.Z），用于对比和展示
#     LAST_VERSION_TAG — 完整 tag（app/vX.Y.Z），用于构造下载 URL
# ============================================================

get_latest_version() {
    echo -e "${YELLOW}正在获取最新版本...${PLAIN}"

    # 从 GitHub API 获取完整 tag（如 app/v2.6.1）
    local _raw_tag
    _raw_tag=$(curl -Ls --max-time 10 "https://api.github.com/repos/apernet/hysteria/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)

    # 备用：跟随重定向取 URL 末段
    if [ -z "$_raw_tag" ]; then
        _raw_tag=$(curl -Ls --max-time 10 -o /dev/null -w "%{url_effective}" \
            "https://github.com/apernet/hysteria/releases/latest" | sed 's|.*/tag/||')
    fi

    [ -z "$_raw_tag" ] && echo -e "${RED}获取版本失败，请检查网络（可能被 GitHub API 限频）${PLAIN}" && return 1

    # 保留完整 tag 用于下载 URL
    LAST_VERSION_TAG="$_raw_tag"
    # 剥离 app/ 前缀用于版本对比和显示
    LAST_VERSION="${_raw_tag#app/}"

    echo -e "${GREEN}最新版本: ${LAST_VERSION}${PLAIN}"
}

download_hy2() {
    check_download_space || return 1
    local _arch
    case $(uname -m) in
        x86_64)          _arch="amd64"   ;;
        aarch64|arm64)   _arch="arm64"   ;;
        armv7l|armv7)    _arch="arm"     ;;
        s390x)           _arch="s390x"   ;;
        loongarch64)     _arch="loong64" ;;
        *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}" && return 1 ;;
    esac

    # 主源使用完整 tag（含 app/ 前缀），确保 URL 正确
    local _url_github="https://github.com/apernet/hysteria/releases/download/${LAST_VERSION_TAG}/hysteria-linux-${_arch}"
    # 备用：官方永久镜像（始终指向最新版，无需 tag）
    local _url_mirror="https://download.hysteria.network/app/latest/hysteria-linux-${_arch}"

    local _tmp_bin
    _tmp_bin=$(mktemp "$(disk_tmp_dir)/hysteria-XXXXXX" 2>/dev/null) || {
        echo -e "${RED}无法创建下载临时文件${PLAIN}"
        return 1
    }

    echo -e "${YELLOW}正在下载 hysteria-linux-${_arch}...${PLAIN}"

    local _source=""
    if download_file "$_url_github" "$_tmp_bin"; then
        _source="GitHub"
    elif download_file "$_url_mirror" "$_tmp_bin"; then
        _source="官方镜像"
    else
        rm -f "$_tmp_bin"
        echo -e "${RED}下载失败，请检查网络${PLAIN}"
        return 1
    fi

    chmod +x "$_tmp_bin"
    local _downloaded_version
    _downloaded_version=$("$_tmp_bin" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ "$_downloaded_version" != "$LAST_VERSION" ]; then
        rm -f "$_tmp_bin"
        echo -e "${RED}下载的二进制版本校验失败（期望 ${LAST_VERSION}，得到 ${_downloaded_version:-未知}）${PLAIN}"
        return 1
    fi
    mv -f "$_tmp_bin" "$HY_BIN"
    echo -e "${GREEN}下载完成（来源：${_source}）${PLAIN}"
}

# ============================================================
# 端口配置
# ============================================================

configure_nat_port() {
    echo ""
    echo -e "${YELLOW}检测到 NAT 机器，请配置端口信息：${PLAIN}"
    echo -e "${SKYBLUE}说明：${PLAIN}"
    echo -e "  • 监听端口：Hysteria 在本机监听的端口"
    echo -e "  • 对外端口：宿主机转发后，客户端实际连接的端口"
    echo -e "  • 若内外端口一致，两者填相同即可"
    echo ""
    read -r -p "请输入本机监听端口 [默认 18888]: " LISTEN_PORT
    [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="18888"
    valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
    read -r -p "请输入对外端口（客户端连接端口）[留空=与监听端口相同]: " EXT_PORT
    [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
    valid_port "$EXT_PORT" || { echo -e "${RED}对外端口必须为 1-65535 的整数${PLAIN}"; return 1; }
    echo -e "${YELLOW}提示: 请确保宿主机已将 UDP ${EXT_PORT} 转发到本机 UDP ${LISTEN_PORT}${PLAIN}"
}

configure_std_port() {
    # 端口跳跃：服务器同时监听一段端口范围，客户端随机选端口连接
    # Hysteria 2 原生支持，可有效绕过端口封锁
    echo ""
    echo -ne "  ${YELLOW}是否启用端口跳跃（Port Hopping）？[y/N]:${PLAIN} "
    read -r _use_hop
    if [ "$_use_hop" = "y" ] || [ "$_use_hop" = "Y" ]; then
        echo -e "  ${DIM}端口跳跃示例: 20000:50000 → 服务器监听 20000-50000 全部端口${PLAIN}"
        echo -e "  ${DIM}客户端可连接范围内任意端口, 有效绕过单端口封锁${PLAIN}"
        read -r -p "  请输入端口范围 [格式 起始:结束, 如 20000:50000]: " PORT_HOP
        local _hop_start _hop_end
        _hop_start=$(echo "$PORT_HOP" | cut -d: -f1)
        _hop_end=$(echo "$PORT_HOP" | cut -d: -f2)
        if valid_port "$_hop_start" && valid_port "$_hop_end" && [ "$_hop_start" -le "$_hop_end" ]; then
            LISTEN_PORT="$_hop_start"
            EXT_PORT="$LISTEN_PORT"
            echo -e "  ${GREEN}✓ 端口跳跃已启用: ${PORT_HOP}${PLAIN}"
        else
            echo -e "  ${RED}格式错误，将使用默认单端口${PLAIN}"
            PORT_HOP=""
            read -r -p "请输入监听端口 [默认 18888]: " LISTEN_PORT
            [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="18888"
            valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
            EXT_PORT="$LISTEN_PORT"
        fi
    else
        read -r -p "请输入监听端口 [默认 18888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="18888"
        valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return 1; }
        EXT_PORT="$LISTEN_PORT"
    fi
}

# ============================================================
# 防火墙放行端口（ufw / firewalld / iptables 三套兼容）
# ============================================================

open_firewall_port() {
    local _port="$1"
    local _proto="${2:-udp}"

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow "${_port}/${_proto}" >/dev/null 2>&1
        echo -e "  ${GREEN}✓ ufw 已放行 ${_proto}/${_port}${PLAIN}"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${_port}/${_proto}" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "  ${GREEN}✓ firewalld 已放行 ${_proto}/${_port}${PLAIN}"
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p "${_proto}" --dport "${_port}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p "${_proto}" --dport "${_port}" -j ACCEPT 2>/dev/null
        if [ "$HAS_IPV6" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
            ip6tables -C INPUT -p "${_proto}" --dport "${_port}" -j ACCEPT 2>/dev/null || \
                ip6tables -I INPUT -p "${_proto}" --dport "${_port}" -j ACCEPT 2>/dev/null
        fi
        # 尝试持久化
        if [ -f /etc/iptables/rules.v4 ] && command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
        echo -e "  ${GREEN}✓ iptables 已放行 ${_proto}/${_port}${PLAIN}"
    else
        echo -e "  ${YELLOW}⚠ 未检测到防火墙工具，请手动放行 ${_proto}/${_port}${PLAIN}"
    fi
}

# 防火墙端口范围放行（端口跳跃专用）
open_firewall_range() {
    local _start="$1" _end="$2"
    local _proto="${3:-udp}"

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        # ufw 支持端口范围语法
        ufw allow "${_start}:${_end}/${_proto}" >/dev/null 2>&1
        echo -e "  ${GREEN}✓ ufw 已放行 ${_proto}/${_start}:${_end}${PLAIN}"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${_start}-${_end}/${_proto}" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "  ${GREEN}✓ firewalld 已放行 ${_proto}/${_start}-${_end}${PLAIN}"
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p "${_proto}" --dport "${_start}:${_end}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p "${_proto}" --dport "${_start}:${_end}" -j ACCEPT 2>/dev/null
        if [ "$HAS_IPV6" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
            ip6tables -C INPUT -p "${_proto}" --dport "${_start}:${_end}" -j ACCEPT 2>/dev/null || \
                ip6tables -I INPUT -p "${_proto}" --dport "${_start}:${_end}" -j ACCEPT 2>/dev/null
        fi
        if [ -f /etc/iptables/rules.v4 ] && command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
        echo -e "  ${GREEN}✓ iptables 已放行 ${_proto}/${_start}:${_end}${PLAIN}"
    else
        echo -e "  ${YELLOW}⚠ 未检测到防火墙工具，请手动放行 ${_proto}/${_start}-${_end}${PLAIN}"
    fi
}

# ============================================================
# 密码生成（两步法，避免管道截断导致空密码）
# ============================================================

gen_password() {
    local _pass=""
    if command -v openssl >/dev/null 2>&1; then
        # 生成足够长的随机串，tr 过滤后截取 20 位
        # 用循环保证长度充足，避免极端情况下过滤后不足 20 位
        while [ ${#_pass} -lt 20 ]; do
            _pass="${_pass}$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9')"
        done
    else
        while [ ${#_pass} -lt 20 ]; do
            _pass="${_pass}$(tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | dd bs=32 count=1 2>/dev/null)"
        done
    fi
    printf '%s' "${_pass:0:20}"
}

write_hy2_config() {
    local _listen_addr="$1" _config_dir _tmp_config
    _config_dir=$(dirname "$HY_CONFIG")
    _tmp_config=$(mktemp "${_config_dir}/config.yaml.XXXXXX" 2>/dev/null) || return 1
    if ! cat > "$_tmp_config" <<EOF
listen: $_listen_addr

tls:
  cert: $HY_CERT_DIR/server.crt
  key: $HY_CERT_DIR/server.key

auth:
  type: password
  password: "$PASSWORD"

bandwidth:
  up: ${BW_UP} mbps
  down: ${BW_DOWN} mbps

masquerade:
  type: proxy
  proxy:
    url: https://$SNI/
    rewriteHost: true
EOF
    then
        rm -f "$_tmp_config"
        return 1
    fi
    chmod 600 "$_tmp_config" || { rm -f "$_tmp_config"; return 1; }
    mv -f "$_tmp_config" "$HY_CONFIG"
}

# ============================================================
# 安装
# ============================================================

install_hy2() {
    install_dependencies || return
    detect_network
    echo ""
    get_latest_version || return
    backup_current_install || { echo -e "${RED}无法创建重装备份，已取消安装${PLAIN}"; return; }
    download_hy2 || { restore_current_install; return; }

    mkdir -p /etc/hysteria "$HY_CERT_DIR" "$HY_META"

    echo -e "\n${SKYBLUE}--- 配置 Hysteria2 ---${PLAIN}"

    if [ "$NAT_MODE" = "1" ]; then
        configure_nat_port || { restore_current_install; return; }
    else
        configure_std_port || { restore_current_install; return; }
    fi

    # 自动放行端口（端口跳跃时放行整个范围）
    echo -e "${YELLOW}正在配置防火墙...${PLAIN}"
    if [ -n "$PORT_HOP" ]; then
        local _hop_start _hop_end
        _hop_start=$(echo "$PORT_HOP" | cut -d: -f1)
        _hop_end=$(echo "$PORT_HOP" | cut -d: -f2)
        open_firewall_range "$_hop_start" "$_hop_end" "udp"
    else
        open_firewall_port "$LISTEN_PORT" "udp"
    fi

    read -r -p "请设置连接密码 [留空自动生成]: " PASSWORD
    [ -z "$PASSWORD" ] && PASSWORD=$(gen_password)
    echo "$PASSWORD" | grep -qE '["\\$`]|[[:cntrl:]]' && {
        echo -e "${RED}密码不能包含引号、反斜杠、美元符、反引号或控制字符${PLAIN}"
        restore_current_install
        return
    }

    # IPv6 Only：监听双栈
    # PORT_HOP 格式为用户友好的 "起始:结束"（如 20000:50000），
    # 但 Hysteria2 配置 listen 字段要求 "-" 作为端口范围分隔符
    if [ -n "$PORT_HOP" ]; then
        local _hop_cfg
        _hop_cfg=$(echo "$PORT_HOP" | tr ':' '-')
        local LISTEN_ADDR=":${_hop_cfg}"
        if [ "$IPV6_ONLY" = "1" ]; then
            echo -e "${YELLOW}纯 IPv6 机器，将监听 [::]:${_hop_cfg}${PLAIN}"
            LISTEN_ADDR="[::]:${_hop_cfg}"
        fi
    else
        local LISTEN_ADDR=":${LISTEN_PORT}"
        if [ "$IPV6_ONLY" = "1" ]; then
            echo -e "${YELLOW}纯 IPv6 机器，将监听 [::]:${LISTEN_PORT}${PLAIN}"
            LISTEN_ADDR="[::]:${LISTEN_PORT}"
        fi
    fi

    echo -e "${YELLOW}生成自签名证书...${PLAIN}"
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -sha256 \
        -keyout "$HY_CERT_DIR/server.key" -out "$HY_CERT_DIR/server.crt" \
        -subj "/CN=${SNI}" >/dev/null 2>&1 || {
            echo -e "${RED}证书生成失败${PLAIN}"
            restore_current_install
            return
        }
    chmod 600 "$HY_CERT_DIR/server.key"

    BW_UP="50"
    BW_DOWN="100"
    echo ""
    read -r -p "是否使用默认带宽参数 (上行 50 Mbps / 下行 100 Mbps)? [Y/n]: " LOW_BW
    if [[ "$LOW_BW" =~ ^[nN]$ ]]; then
        read -r -p "请输入上行带宽 Mbps [默认 50]: " _up
        read -r -p "请输入下行带宽 Mbps [默认 100]: " _dn
        [[ -n "$_up" ]] && BW_UP="$_up"
        [[ -n "$_dn" ]] && BW_DOWN="$_dn"
        valid_positive_number "$BW_UP" && valid_positive_number "$BW_DOWN" || {
            echo -e "${RED}带宽必须为大于 0 的数字${PLAIN}"
            restore_current_install
            return
        }
    fi

    write_hy2_config "$LISTEN_ADDR" || {
        echo -e "${RED}配置文件写入失败${PLAIN}"
        restore_current_install
        return
    }

    # 保存元数据
    echo "$NAT_MODE"    > "$HY_META/nat_mode"
    echo "$EXT_PORT"    > "$HY_META/ext_port"
    echo "$LISTEN_PORT" > "$HY_META/listen_port"
    [ -n "$PORT_HOP"   ] && echo "$PORT_HOP"   > "$HY_META/port_hop"
    echo "$BW_UP"       > "$HY_META/bw_up"
    echo "$BW_DOWN"     > "$HY_META/bw_down"
    [ -n "$PUBLIC_IP"   ] && echo "$PUBLIC_IP"   > "$HY_META/public_ip"
    [ -n "$PUBLIC_IPV6" ] && echo "$PUBLIC_IPV6" > "$HY_META/public_ipv6"

    if   [ "$INIT_SYS" = "systemd" ]; then setup_systemd_service
    elif [ "$INIT_SYS" = "openrc"  ]; then setup_openrc_service
    fi
    service_enable
    if service_is_active; then
        service_restart
    else
        service_start
    fi

    sleep 2
    echo -e "${YELLOW}验证服务状态...${PLAIN}"
    if service_is_healthy; then
        echo -e "${GREEN}✓ Hysteria2 启动成功${PLAIN}"
        command -v ss >/dev/null 2>&1 && \
            ss -unlp 2>/dev/null | grep -q ":${LISTEN_PORT}" \
            && echo -e "${GREEN}✓ UDP ${LISTEN_PORT} 端口监听正常${PLAIN}" \
            || echo -e "${YELLOW}⚠ 未检测到端口监听，请查看日志${PLAIN}"
    else
        echo -e "${RED}✗ 启动失败，请查看日志${PLAIN}"
        service_logs
        restore_current_install
        return
    fi

    discard_install_backup
    echo -e "${GREEN}安装完成！${PLAIN}"
    show_config
}

# ============================================================
# 升级（保留配置，仅替换二进制）
# 版本对比使用剥离 app/ 前缀后的纯 vX.Y.Z 格式
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

upgrade_hy2() {
    acquire_upgrade_lock || { echo -e "${YELLOW}另一个 Hysteria2 升级任务正在运行，请稍后重试${PLAIN}"; return 1; }
    local _status=0
    _upgrade_hy2_locked || _status=$?
    release_upgrade_lock
    return "$_status"
}

_upgrade_hy2_locked() {
    if [ ! -f "$HY_BIN" ]; then
        echo -e "${RED}未检测到已安装的 Hysteria2，请先安装${PLAIN}"
        sleep 2; return
    fi

    local _cur_ver=""
    _cur_ver=$("$HY_BIN" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo -e "  当前版本: ${YELLOW}${_cur_ver:-未知}${PLAIN}"

    get_latest_version || return
    # LAST_VERSION 已剥离 app/ 前缀（vX.Y.Z），可直接与 _cur_ver 对比

    if [ -n "$_cur_ver" ] && [ "$_cur_ver" = "$LAST_VERSION" ]; then
        echo -e "${GREEN}已是最新版本，无需升级${PLAIN}"
        sleep 2; return
    fi

    echo -e "${YELLOW}开始升级: ${_cur_ver:-未知} → ${LAST_VERSION}${PLAIN}"

    local _was_active=0
    service_is_active && _was_active=1 || true

    # 备份旧二进制，下载/启动失败时回滚
    cp "$HY_BIN" "${HY_BIN}.bak" 2>/dev/null || {
        echo -e "${RED}无法备份当前二进制，取消升级${PLAIN}"
        return
    }

    if download_hy2; then
        [ "$_was_active" = "0" ] || { service_restart; sleep 2; }

        if [ "$_was_active" = "0" ] || service_is_healthy; then
            local _new_ver
            _new_ver=$("$HY_BIN" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            echo -e "${GREEN}✓ 升级成功，当前版本: ${_new_ver:-未知}${PLAIN}"
            rm -f "${HY_BIN}.bak"
        else
            echo -e "${RED}✗ 升级后服务启动失败，回滚中...${PLAIN}"
            mv "${HY_BIN}.bak" "$HY_BIN"
            [ "$_was_active" = "0" ] || service_restart
            echo -e "${YELLOW}已回滚至旧版本 ${_cur_ver}${PLAIN}"
            service_logs
        fi
    else
        echo -e "${RED}✗ 下载失败，回滚中...${PLAIN}"
        mv "${HY_BIN}.bak" "$HY_BIN"
        [ "$_was_active" = "0" ] || service_restart
        echo -e "${YELLOW}已回滚至旧版本 ${_cur_ver}${PLAIN}"
    fi
    sleep 2
}

# ============================================================
# 读取配置变量
# ============================================================

read_config_vars() {
    [ ! -f "$HY_CONFIG" ] && return 1

    LISTEN_PORT=$(grep "^listen:" "$HY_CONFIG" | head -1 | grep -oE '[0-9]+$')
    PASSWORD=$(grep "password:" "$HY_CONFIG" | grep -v "^#" | head -1 \
        | sed 's/.*password:[[:space:]]*//' | tr -d '"' | tr -d "'")
    SNI="amd.com"

    if [ -d "$HY_META" ]; then
        NAT_MODE=$(cat "$HY_META/nat_mode"       2>/dev/null); NAT_MODE=${NAT_MODE:-0}
        EXT_PORT=$(cat "$HY_META/ext_port"       2>/dev/null)
        PUBLIC_IP=$(cat "$HY_META/public_ip"     2>/dev/null)
        PUBLIC_IPV6=$(cat "$HY_META/public_ipv6" 2>/dev/null)
        BW_UP=$(cat "$HY_META/bw_up"             2>/dev/null); BW_UP=${BW_UP:-50}
        BW_DOWN=$(cat "$HY_META/bw_down"         2>/dev/null); BW_DOWN=${BW_DOWN:-100}
        PORT_HOP=$(cat "$HY_META/port_hop"       2>/dev/null)
    fi

    [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
    [[ -z "$NAT_MODE" ]] && NAT_MODE=0

    if detect_warp; then
        local _native_ipv4 _default_ipv4
        _native_ipv4=$(get_native_public_ipv4 2>/dev/null || true)
        _default_ipv4=$(get_default_public_ipv4 2>/dev/null || true)
        if is_valid_ipv4 "$_native_ipv4"; then
            PUBLIC_IP="$_native_ipv4"
            [ ! -d "$HY_META" ] || printf '%s' "$PUBLIC_IP" > "$HY_META/public_ip"
        elif is_valid_ipv4 "$_default_ipv4" && [ "$PUBLIC_IP" = "$_default_ipv4" ]; then
            PUBLIC_IP=""
            [ ! -d "$HY_META" ] || : > "$HY_META/public_ip"
        fi
    fi

    # IP 兜底（元数据为空时重新检测）
    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        detect_warp || PUBLIC_IP=$(get_default_public_ipv4 2>/dev/null || true)
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]')
    fi
}

# ============================================================
# URL encode — 优先 python3，降级纯 bash 逐字节处理
# ============================================================

uri_encode() {
    local _in="$1"
    if command -v python3 >/dev/null 2>&1; then
        if printf '%s' "$_in" | python3 -c \
            "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''), end='')" 2>/dev/null; then
            return
        fi
    fi
    local _out="" _i=0 _c _hex _b
    local _len=${#_in}
    while [ $_i -lt $_len ]; do
        _c="${_in:_i:1}"
        case "$_c" in
            [a-zA-Z0-9.~_-]) _out+="$_c" ;;
            *)
                _hex=$(printf '%s' "$_c" | od -An -tx1 | awk '{ for (i=1; i<=NF; i++) printf "%%%s", toupper($i) }')
                _out="${_out}${_hex}"
                ;;
        esac
        _i=$((_i + 1))
    done
    printf '%s' "$_out"
}

trim_string() {
    printf '%s' "$1" | tr -d '\r\n\t' | awk '{$1=$1; print}'
}

print_copy_block() {
    printf '%s\n' "$1"
}

get_public_ipv4() {
    curl -s4 --connect-timeout 3 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]'
}

get_public_ipv6() {
    curl -s6 --connect-timeout 3 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]'
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
    _protocol=$(trim_string "${3:-Hysteria2}")
    _ip_type=$(trim_string "${4:-IPv4}")
    printf '%s %s | %s | %s | %s' "$_flag" "$_country" "$_server" "$_protocol" "$_ip_type" | tr -d '\r\n\t'
}

format_ipv6_for_uri() {
    echo "$1" | grep -q ':' && printf '[%s]' "$1" || printf '%s' "$1"
}

format_server_for_yaml() {
    echo "$1" | grep -q ':' && printf "'%s'" "$1" || printf '%s' "$1"
}

shell_json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
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

export_uri_hy2() {
    local _server="$1" _port="$2" _node="$3" _host _pass_encoded _sni_encoded _node_encoded
    _host=$(format_ipv6_for_uri "$_server")
    _pass_encoded=$(uri_encode "$PASSWORD")
    _sni_encoded=$(uri_encode "$SNI")
    _node_encoded=$(uri_encode "$_node")
    printf 'hysteria2://%s@%s:%s/?insecure=1&sni=%s#%s' \
        "$_pass_encoded" "$_host" "$_port" "$_sni_encoded" "$_node_encoded"
}

export_mihomo_hy2() {
    local _server="$1" _port="$2" _node="$3" _yaml_server _pass _sni _safe_node
    _yaml_server=$(format_server_for_yaml "$_server")
    _pass=$(yaml_single_quote_escape "$PASSWORD")
    _sni=$(yaml_single_quote_escape "$SNI")
    _safe_node=$(yaml_single_quote_escape "$_node")
    printf '%s' "- {name: '${_safe_node}', type: hysteria2, server: ${_yaml_server}, port: ${_port}, password: '${_pass}', sni: '${_sni}', skip-cert-verify: true, fast-open: true, udp: true}"
}

export_loon_hy2() {
    local _server="$1" _port="$2" _node="$3"
    printf "%s = Hysteria2, %s, %s, '%s', skip-cert-verify=true, sni=%s" "$_node" "$_server" "$_port" "$PASSWORD" "$SNI"
}

export_surfboard_hy2() {
    local _server="$1" _port="$2" _node="$3"
    printf '%s = hysteria2, %s, %s, password=%s, sni=%s, skip-cert-verify=true' "$_node" "$_server" "$_port" "$PASSWORD" "$SNI"
}

# ============================================================
# 展示单个节点（IPv4 或 IPv6）
# $1=IP  $2=Port  $3=标签(v4/v6)
# ============================================================

should_show_output() {
    local _mode="${1:-all}" _section="$2"
    [ "$_mode" = "all" ] || [ "$_mode" = "$_section" ]
}

show_node() {
    local _ip="$1" _port="$2" _tag="$3" _mode="${4:-all}"
    local _ip_type _country _server_name _node _uri _qr_url _png
    case "$_tag" in
        v6|IPv6|ipv6) _ip_type="IPv6" ;;
        *)            _ip_type="IPv4" ;;
    esac
    _country=$(get_country_code "$PUBLIC_IP" "$PUBLIC_IPV6")
    _server_name=$(generate_server_name)
    _node=$(generate_node_name "$_country" "$_server_name" "Hysteria2" "$_ip_type")
    _uri=$(export_uri_hy2 "$_ip" "$_port" "$_node")
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
        print_copy_block "$(export_mihomo_hy2 "$_ip" "$_port" "$_node")"
        [ -n "$PORT_HOP" ] && echo -e "${YELLOW}[WARN] 端口跳跃: ${PORT_HOP}，客户端需按实际支持手动适配。${PLAIN}"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "surfboard"; then
        echo -e "${GREEN}Surfboard 配置:${PLAIN}"
        print_copy_block "$(export_surfboard_hy2 "$_ip" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "shadowrocket"; then
        echo -e "${GREEN}Shadowrocket 配置:${PLAIN}"
        print_copy_block "$_uri"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "loon"; then
        echo -e "${GREEN}Loon 配置:${PLAIN}"
        print_copy_block "$(export_loon_hy2 "$_ip" "$_port" "$_node")"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "quantumult"; then
        echo -e "${GREEN}Quantumult X 配置:${PLAIN}"
        print_copy_block "Quantumult X 暂不支持该协议的配置格式。"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi

    if should_show_output "$_mode" "qrcode"; then
        echo -e "${GREEN}二维码:${PLAIN}"
        if generate_terminal_qrcode "$_uri"; then
            echo -e "${GREEN}[OK] 终端二维码已生成${PLAIN}"
            _png=$(generate_local_qrcode_png "$_uri" "hysteria2" "$_ip_type" 2>/dev/null || true)
            [ -n "$_png" ] && echo -e "本地二维码图片: ${YELLOW}${_png}${PLAIN}"
        else
            echo -e "${YELLOW}[WARN] 未安装 qrencode，跳过终端和本地 PNG 二维码。${PLAIN}"
        fi
        echo -e "${YELLOW}[WARN] 在线二维码会把节点链接提交给第三方服务，不建议公开节点使用。${PLAIN}"
        print_copy_block "$_qr_url"
        echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    fi
}

# ============================================================
# 显示配置
# ============================================================

show_config() {
    local _mode="${1:-all}"
    if [ ! -f "$HY_CONFIG" ]; then
        echo -e "${RED}未找到配置文件${PLAIN}"
        read -r -p "按回车返回..." _tmp
        return
    fi

    read_config_vars

    local _country _server_name
    _country=$(get_country_code "$PUBLIC_IP" "$PUBLIC_IPV6")
    _server_name=$(generate_server_name)

    echo -e ""
    echo -e "${GREEN}Hysteria2 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "服务器名称: ${YELLOW}${_server_name}${PLAIN}"
    echo -e "国家/地区: ${YELLOW}${_country} / $(get_country_name "$_country")${PLAIN}"
    [ -n "$PUBLIC_IP"   ] && echo -e "IPv4 地址 : ${YELLOW}${PUBLIC_IP}${PLAIN}"
    [ -n "$PUBLIC_IPV6" ] && echo -e "IPv6 地址 : ${YELLOW}${PUBLIC_IPV6}${PLAIN}"
    if [ "$NAT_MODE" = "1" ] && [ "$EXT_PORT" != "$LISTEN_PORT" ]; then
        echo -e "监听端口 : ${YELLOW}${LISTEN_PORT}${PLAIN}  ${RED}← 本机监听${PLAIN}"
        echo -e "对外端口 : ${YELLOW}${EXT_PORT}${PLAIN}  ${RED}← 客户端连接此端口${PLAIN}"
    elif [ -n "$PORT_HOP" ]; then
        echo -e "端口跳跃 : ${GREEN}${PORT_HOP}${PLAIN}  ${DIM}(服务器监听全范围)${PLAIN}"
        echo -e "${DIM}客户端可随机选择范围内任意端口连接${PLAIN}"
    else
        echo -e "端口 Port : ${YELLOW}${EXT_PORT}${PLAIN}"
    fi
    echo -e "密码 Pass : ${YELLOW}${PASSWORD}${PLAIN}"
    echo -e "伪装 SNI : ${YELLOW}${SNI}${PLAIN}"
    echo -e "带宽设置 : ${YELLOW}上行 ${BW_UP} Mbps / 下行 ${BW_DOWN} Mbps${PLAIN}"
    echo -e "证书验证 : ${RED}Insecure / Skip Cert Verify = true${PLAIN}"
    [ "$NAT_MODE" = "1" ] && echo -e "机器类型 : ${YELLOW}NAT 机器${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    # IPv4 节点
    if [ -n "$PUBLIC_IP" ]; then
        echo -e "${YELLOW}▼ IPv4 节点${PLAIN}"
        show_node "$PUBLIC_IP" "$EXT_PORT" "v4" "$_mode"
    fi

    # IPv6 节点（双栈或纯 IPv6）
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "${YELLOW}▼ IPv6 节点${PLAIN}"
        show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6" "$_mode"
    fi

    [ "$_mode" = "all" ] && echo -e "${YELLOW}提示: Quantumult X 暂不支持 Hy2 协议。${PLAIN}"
    [ "$NAT_MODE" = "1" ] && \
        echo -e "${YELLOW}NAT 提示: 若无法连接，请确认宿主机已将 UDP ${EXT_PORT} 转发到本机 UDP ${LISTEN_PORT}${PLAIN}"
    echo ""
    read -r -p "按回车键返回主菜单..." _tmp
}

# ============================================================
# 修改密码
# ============================================================

change_password() {
    if [ ! -f "$HY_CONFIG" ]; then
        echo -e "${RED}未找到配置文件，请先安装${PLAIN}"
        sleep 2; return
    fi

    read_config_vars
    echo -e "  当前密码: ${YELLOW}${PASSWORD}${PLAIN}"
    read -r -p "请输入新密码 [留空自动生成]: " NEW_PASS
    [ -z "$NEW_PASS" ] && NEW_PASS=$(gen_password)

    # 校验密码不含破坏 YAML 的特殊字符
    if echo "$NEW_PASS" | grep -qE '["\\$`]'; then
        echo -e "${RED}错误: 密码不能包含特殊字符 (\", \\, \$, \`)${PLAIN}"
        sleep 2
        return
    fi

    # 在配置目录内生成临时文件，确保最终替换为同文件系统原子操作。
    local _config_dir _tmp_cfg _bak_cfg
    _config_dir=$(dirname "$HY_CONFIG")
    _tmp_cfg=$(mktemp "${_config_dir}/config.yaml.new.XXXXXX" 2>/dev/null) || {
        echo -e "${RED}无法创建配置临时文件${PLAIN}"; sleep 2; return
    }
    _bak_cfg=$(mktemp "${_config_dir}/config.yaml.bak.XXXXXX" 2>/dev/null) || {
        rm -f "$_tmp_cfg"; echo -e "${RED}无法创建配置备份${PLAIN}"; sleep 2; return
    }
    cp -p "$HY_CONFIG" "$_bak_cfg" || {
        rm -f "$_tmp_cfg" "$_bak_cfg"; echo -e "${RED}配置备份失败${PLAIN}"; sleep 2; return
    }

    awk -v pw="$NEW_PASS" '
        /^auth:/ { in_auth=1; print; next }
        in_auth && /^[^[:space:]]/ { in_auth=0 }
        in_auth && /^[[:space:]]+password:/ { sub(/password:.*/, "password: \"" pw "\""); }
        { print }
    ' "$HY_CONFIG" > "$_tmp_cfg" && chmod 600 "$_tmp_cfg" && mv -f "$_tmp_cfg" "$HY_CONFIG" || {
        rm -f "$_tmp_cfg" "$_bak_cfg"; echo -e "${RED}配置写入失败${PLAIN}"; sleep 2; return
    }

    if service_restart && service_is_active; then
        rm -f "$_bak_cfg"
        echo -e "${GREEN}密码已更新为: ${NEW_PASS}${PLAIN}"
    else
        mv -f "$_bak_cfg" "$HY_CONFIG"
        service_restart || true
        echo -e "${RED}服务重启失败，配置已回滚${PLAIN}"
        service_logs
    fi
    sleep 2
}

# ============================================================
# 修改带宽
# 使用 awk 重写 bandwidth 块，兼容任意缩进格式
# ============================================================

change_bandwidth() {
    if [ ! -f "$HY_CONFIG" ]; then
        echo -e "${RED}未找到配置文件，请先安装${PLAIN}"
        sleep 2; return
    fi

    read_config_vars
    local _old_bw_up="$BW_UP" _old_bw_down="$BW_DOWN"
    echo -e "  当前带宽: ${YELLOW}上行 ${BW_UP} Mbps / 下行 ${BW_DOWN} Mbps${PLAIN}"
    read -r -p "请输入新的上行带宽 Mbps [留空保持 ${BW_UP}]: " _new_up
    read -r -p "请输入新的下行带宽 Mbps [留空保持 ${BW_DOWN}]: " _new_dn
    [[ -n "$_new_up" ]] && BW_UP="$_new_up"
    [[ -n "$_new_dn" ]] && BW_DOWN="$_new_dn"
    valid_positive_number "$BW_UP" && valid_positive_number "$BW_DOWN" || {
        echo -e "${RED}带宽必须为大于 0 的数字${PLAIN}"
        sleep 2
        return
    }

    # 用同目录临时文件原子替换，并保留可回滚副本。
    local _config_dir _tmp_cfg _bak_cfg
    _config_dir=$(dirname "$HY_CONFIG")
    _tmp_cfg=$(mktemp "${_config_dir}/config.yaml.new.XXXXXX" 2>/dev/null) || {
        echo -e "${RED}无法创建配置临时文件${PLAIN}"; sleep 2; return
    }
    _bak_cfg=$(mktemp "${_config_dir}/config.yaml.bak.XXXXXX" 2>/dev/null) || {
        rm -f "$_tmp_cfg"; echo -e "${RED}无法创建配置备份${PLAIN}"; sleep 2; return
    }
    cp -p "$HY_CONFIG" "$_bak_cfg" || {
        rm -f "$_tmp_cfg" "$_bak_cfg"; echo -e "${RED}配置备份失败${PLAIN}"; sleep 2; return
    }
    awk -v up="${BW_UP}" -v dn="${BW_DOWN}" '
        /^bandwidth:/ { in_bw=1; print; next }
        in_bw && /^[^[:space:]]/ { in_bw=0 }
        in_bw && /^[[:space:]]+up:/ { sub(/up:.*/, "up: " up " mbps"); }
        in_bw && /^[[:space:]]+down:/ { sub(/down:.*/, "down: " dn " mbps"); }
        { print }
    ' "$HY_CONFIG" > "$_tmp_cfg" && chmod 600 "$_tmp_cfg" && mv -f "$_tmp_cfg" "$HY_CONFIG" || {
        rm -f "$_tmp_cfg" "$_bak_cfg"; echo -e "${RED}配置写入失败${PLAIN}"; sleep 2; return
    }

    # 更新元数据
    echo "$BW_UP"   > "$HY_META/bw_up"
    echo "$BW_DOWN" > "$HY_META/bw_down"

    service_restart || true
    sleep 1
    if service_is_active; then
        rm -f "$_bak_cfg"
        echo -e "${GREEN}带宽已更新: 上行 ${BW_UP} Mbps / 下行 ${BW_DOWN} Mbps${PLAIN}"
    else
        mv -f "$_bak_cfg" "$HY_CONFIG"
        printf '%s' "$_old_bw_up" > "$HY_META/bw_up"
        printf '%s' "$_old_bw_down" > "$HY_META/bw_down"
        service_restart || true
        echo -e "${RED}服务重启失败，配置和元数据已回滚${PLAIN}"
        service_logs
    fi
    sleep 2
}

# ============================================================
# 管理子菜单
# ============================================================

manage_hy2() {
    while true; do
        clear_screen
        echo -e "\n${SKYBLUE}--- 管理 Hysteria2 ---${PLAIN}"
        echo -e "1. 查看配置 (全客户端兼容)"
        echo -e "2. 重启服务"
        echo -e "3. 停止服务"
        echo -e "4. 启动服务"
        echo -e "5. 查看日志"
        echo -e "6. 修改密码"
        echo -e "7. 修改带宽"
        echo -e "0. 返回"
        read -r -p "请选择: " opt
        case $opt in
            1) show_config ;;
            2) service_restart && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
            3) service_stop    && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
            4) service_start   && echo -e "${GREEN}服务已启动${PLAIN}" && sleep 1 ;;
            5) service_logs; read -r -p "按回车继续..." _tmp ;;
            6) change_password ;;
            7) change_bandwidth ;;
            0) return ;;
            *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 卸载
# ============================================================

uninstall_hy2() {
    read -r -p "确定卸载 Hysteria2? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return

    service_stop
    service_disable
    rm -f "$SERVICE_FILE" "$OPENRC_SERVICE" "$HY_BIN"
    rm -rf /etc/hysteria

    # 同时清理自动更新
    remove_auto_update_quiet

    echo -e "${GREEN}已卸载完成${PLAIN}"
    sleep 1
}

# ============================================================
# 一键开启标准 BBR 拥塞控制
# 内核 < 4.9：不支持；其余内核仅启用主流稳定的 bbr + fq，不自动尝试实验性或魔改 BBR
# ============================================================

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

    local _sysctl_conf="/etc/sysctl.d/99-hysteria-bbr.conf"
    cat > "$_sysctl_conf" <<EOF
# Hysteria2 脚本写入 - 标准 BBR 优化
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = ${_cc}
EOF

    sysctl -p "$_sysctl_conf" >/dev/null 2>&1

    local _result
    _result=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [ "$_result" = "$_cc" ]; then
        echo -e "${GREEN}✓ 标准 BBR (${_cc}) 已成功启用${PLAIN}"
        echo -e "${GREEN}✓ 队列调度: $(sysctl -n net.core.default_qdisc 2>/dev/null)${PLAIN}"
        echo -e "${GREEN}✓ 配置已写入 ${_sysctl_conf}，重启后持续生效${PLAIN}"
    else
        echo -e "${RED}✗ BBR 启用失败，请手动检查内核是否支持 tcp_bbr${PLAIN}"
    fi
    sleep 3
}

check_bbr_status() {
    local _cc _qdisc
    _cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    _qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    local _avail
    _avail=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)

    echo -e "  拥塞控制算法: ${YELLOW}${_cc:-未知}${PLAIN}"
    echo -e "  队列调度算法: ${YELLOW}${_qdisc:-未知}${PLAIN}"
    echo -e "  可用算法    : ${SKYBLUE}${_avail}${PLAIN}"

    if echo "${_cc:-}" | grep -qi "bbr"; then
        echo -e "  BBR 状态    : ${GREEN}已启用${PLAIN}"
    else
        echo -e "  BBR 状态    : ${RED}未启用${PLAIN}"
    fi
}

# ============================================================
# 定时自动更新（cron，每天凌晨 3 点）
# ============================================================

install_auto_update() {
    echo -e "\n${SKYBLUE}--- 配置自动更新 ---${PLAIN}"

    if [ ! -f "$HY_BIN" ]; then
        echo -e "${RED}未安装 Hysteria2，请先安装${PLAIN}"
        sleep 2; return
    fi

    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
# Hysteria2 自动更新脚本（由 hy2.sh 生成）
HY_BIN="/usr/local/bin/hysteria"
LOG="/var/log/hy2-autoupdate.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
LOCK_FILE="/var/lock/hy2-upgrade.lock"
LOCK_MODE=""

acquire_lock() {
    local _dir="${LOCK_FILE}.d" _owner=""
    mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || return 1
    if command -v flock >/dev/null 2>&1; then
        exec 8>"$LOCK_FILE" || return 1
        flock -n 8 || { exec 8>&-; return 1; }
        LOCK_MODE="flock"; return 0
    fi
    if ! mkdir "$_dir" 2>/dev/null; then
        _owner=$(cat "$_dir/pid" 2>/dev/null || true)
        [ -n "$_owner" ] && ! kill -0 "$_owner" 2>/dev/null || return 1
        rm -rf "$_dir"; mkdir "$_dir" 2>/dev/null || return 1
    fi
    printf '%s' "$$" > "$_dir/pid"
    LOCK_MODE="mkdir"
}

release_lock() {
    [ "$LOCK_MODE" != "flock" ] || { flock -u 8 2>/dev/null || true; exec 8>&-; }
    [ "$LOCK_MODE" != "mkdir" ] || rm -rf "${LOCK_FILE}.d"
    LOCK_MODE=""
}

get_latest() {
    local _raw _ver
    _raw=$(curl -Ls --max-time 15 "https://api.github.com/repos/apernet/hysteria/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)
    # 返回完整 tag 和剥离后版本号，以 "|" 分隔
    printf '%s|%s' "$_raw" "${_raw#app/}"
}

get_current() {
    "$HY_BIN" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

detect_arch() {
    case $(uname -m) in
        x86_64)        echo "amd64"   ;;
        aarch64|arm64) echo "arm64"   ;;
        armv7l|armv7)  echo "arm"     ;;
        s390x)         echo "s390x"   ;;
        loongarch64)   echo "loong64" ;;
        *) echo "" ;;
    esac
}

restart_service() {
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart hysteria-server
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service hysteria-server restart 2>/dev/null
    fi
}

download_file() {
    local _url="$1" _dest="$2" _attempt=1 _delay=2
    while [ "$_attempt" -le 3 ]; do
        if command -v curl >/dev/null 2>&1 && curl -fL --connect-timeout 10 --max-time 120 -o "$_dest" "$_url" 2>/dev/null; then return 0; fi
        if command -v wget >/dev/null 2>&1 && wget -q --timeout=60 -O "$_dest" "$_url" 2>/dev/null; then return 0; fi
        rm -f "$_dest"
        [ "$_attempt" -ge 3 ] && break
        sleep "$_delay"; _attempt=$((_attempt + 1)); _delay=$((_delay * 2))
    done
    return 1
}

disk_tmp_dir() {
    [ -d /var/tmp ] && [ -w /var/tmp ] && { printf '%s' /var/tmp; return; }
    printf '%s' "${TMPDIR:-/tmp}"
}

main() {
    acquire_lock || { echo "[$TIMESTAMP] 另一个升级任务正在运行，跳过本次更新" >> "$LOG"; return; }
    trap release_lock EXIT INT TERM
    local _info _tag _latest _current _arch _url _url_mirror
    local _tmp_bin _backup _was_active=0
    _info=$(get_latest)
    _tag="${_info%%|*}"
    _latest="${_info##*|}"
    _current=$(get_current)
    _arch=$(detect_arch)

    if [ -z "$_latest" ] || [ -z "$_arch" ]; then
        echo "[$TIMESTAMP] 获取版本或架构失败，跳过更新" >> "$LOG"
        return
    fi

    if [ "$_current" = "$_latest" ]; then
        echo "[$TIMESTAMP] 已是最新版本 $_current，无需更新" >> "$LOG"
        return
    fi

    echo "[$TIMESTAMP] 发现新版本: $_current → $_latest，开始更新..." >> "$LOG"

    _url="https://github.com/apernet/hysteria/releases/download/${_tag}/hysteria-linux-${_arch}"
    _url_mirror="https://download.hysteria.network/app/latest/hysteria-linux-${_arch}"
    _tmp_bin=$(mktemp "$(disk_tmp_dir)/hy2-autoupdate-XXXXXX" 2>/dev/null)
    _backup="${HY_BIN}.autoupdate.bak"

    if [ -z "$_tmp_bin" ]; then
        echo "[$TIMESTAMP] 无法创建临时文件，跳过更新" >> "$LOG"
        return
    fi

    if ! download_file "$_url" "$_tmp_bin"; then
        echo "[$TIMESTAMP] GitHub 下载失败，尝试备用镜像..." >> "$LOG"
        download_file "$_url_mirror" "$_tmp_bin" || {
            rm -f "$_tmp_bin"
            echo "[$TIMESTAMP] 更新下载失败，当前版本保持不变" >> "$LOG"
            return
        }
    fi

    chmod +x "$_tmp_bin"
    if ! "$_tmp_bin" version >/dev/null 2>&1; then
        rm -f "$_tmp_bin"
        echo "[$TIMESTAMP] 下载文件校验失败，当前版本保持不变" >> "$LOG"
        return
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet hysteria-server; then
        _was_active=1
    elif command -v rc-service >/dev/null 2>&1 && rc-service hysteria-server status 2>/dev/null | grep -q started; then
        _was_active=1
    fi

    cp "$HY_BIN" "$_backup" 2>/dev/null || {
        rm -f "$_tmp_bin"
        echo "[$TIMESTAMP] 备份当前版本失败，取消更新" >> "$LOG"
        return
    }
    mv -f "$_tmp_bin" "$HY_BIN"

    if [ "$_was_active" -eq 1 ]; then
        restart_service
        sleep 2
        if command -v systemctl >/dev/null 2>&1; then
            systemctl is-active --quiet hysteria-server || {
                mv -f "$_backup" "$HY_BIN"
                restart_service
                echo "[$TIMESTAMP] 新版本启动失败，已回滚至 $_current" >> "$LOG"
                return
            }
        elif command -v rc-service >/dev/null 2>&1; then
            rc-service hysteria-server status 2>/dev/null | grep -q started || {
                mv -f "$_backup" "$HY_BIN"
                restart_service
                echo "[$TIMESTAMP] 新版本启动失败，已回滚至 $_current" >> "$LOG"
                return
            }
        fi
    fi
    rm -f "$_backup"
    echo "[$TIMESTAMP] 更新成功，当前版本: $(get_current)" >> "$LOG"

    # 保留最近 500 行日志
    tail -n 500 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
}

main
AUTOUPDATE_EOF

    chmod +x "$AUTO_UPDATE_SCRIPT"

    # 安装 cron（如未安装）
    if ! command -v crontab >/dev/null 2>&1; then
        echo -e "${YELLOW}正在安装 cron...${PLAIN}"
        case "$RELEASE" in
            alpine) apk add --no-cache dcron >/dev/null 2>&1; rc-update add dcron default >/dev/null 2>&1; rc-service dcron start >/dev/null 2>&1 ;;
            arch)   pacman -Sy --noconfirm cronie >/dev/null 2>&1 ;;
            centos|rocky|fedora) dnf install -y cronie >/dev/null 2>&1 || yum install -y cronie >/dev/null 2>&1 ;;
            *)      apt-get install -y -qq cron >/dev/null 2>&1 ;;
        esac
    fi

    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now cron >/dev/null 2>&1 || \
            systemctl enable --now crond >/dev/null 2>&1 || true
    fi
    command -v crontab >/dev/null 2>&1 || {
        echo -e "${RED}cron 安装失败，无法配置自动更新${PLAIN}"
        sleep 2
        return
    }

    # 写入 crontab（避免重复）
    local _cron_entry="0 3 * * * /bin/bash ${AUTO_UPDATE_SCRIPT} >> ${AUTO_UPDATE_LOG} 2>&1"
    ( crontab -l 2>/dev/null | grep -v "hy2-autoupdate"; echo "$_cron_entry" ) | crontab -

    echo -e "${GREEN}✓ 自动更新已配置${PLAIN}"
    echo -e "  执行时间: ${YELLOW}每天 03:00${PLAIN}"
    echo -e "  更新日志: ${YELLOW}${AUTO_UPDATE_LOG}${PLAIN}"
    echo -e "  更新脚本: ${YELLOW}${AUTO_UPDATE_SCRIPT}${PLAIN}"
    sleep 3
}

remove_auto_update() {
    remove_auto_update_quiet
    echo -e "${GREEN}✓ 自动更新已移除${PLAIN}"
    sleep 2
}

remove_auto_update_quiet() {
    ( crontab -l 2>/dev/null | grep -v "hy2-autoupdate" ) | crontab - 2>/dev/null
    rm -f "$AUTO_UPDATE_SCRIPT"
}

check_auto_update_status() {
    if crontab -l 2>/dev/null | grep -q "hy2-autoupdate"; then
        echo -e "  自动更新: ${GREEN}已启用（每天 03:00）${PLAIN}"
    else
        echo -e "  自动更新: ${RED}未启用${PLAIN}"
    fi

    if [ -f "$AUTO_UPDATE_LOG" ]; then
        echo -e "\n  ${SKYBLUE}最近更新记录（最后5条）:${PLAIN}"
        tail -n 5 "$AUTO_UPDATE_LOG" 2>/dev/null | while IFS= read -r line; do
            echo -e "    ${line}"
        done
    fi
}

view_auto_update_log() {
    echo -e "\n${SKYBLUE}--- 自动更新日志（最近 30 条）---${PLAIN}"
    if [ -f "$AUTO_UPDATE_LOG" ]; then
        tail -n 30 "$AUTO_UPDATE_LOG"
    else
        echo -e "${YELLOW}暂无更新日志${PLAIN}"
    fi
    echo ""
    read -r -p "按回车继续..." _tmp
}

# ============================================================
# 系统信息
# ============================================================

show_system_info() {
    echo -e "\n${SKYBLUE}--- 系统信息 ---${PLAIN}"

    local _os _kernel _arch _cpu_model _cpu_cores
    local _mem_total _mem_free _mem_used _disk _load _uptime_str

    _os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)
    _kernel=$(uname -r)
    _arch=$(uname -m)
    _cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)
    _cpu_cores=$(nproc 2>/dev/null || grep -c "processor" /proc/cpuinfo 2>/dev/null)
    _mem_total=$(awk '/MemTotal/     {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    _mem_free=$(awk  '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    _mem_used=$(( ${_mem_total:-0} - ${_mem_free:-0} ))
    _disk=$(df -h / 2>/dev/null | awk 'NR==2 {print $3" / "$2" ("$5" used)"}')
    _load=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs)
    _uptime_str=$(uptime -p 2>/dev/null || uptime 2>/dev/null | awk -F'up ' '{print $2}' | cut -d, -f1-2)

    echo -e "  系统    : ${YELLOW}${_os}${PLAIN}"
    echo -e "  内核    : ${YELLOW}${_kernel}${PLAIN}"
    echo -e "  架构    : ${YELLOW}${_arch}${PLAIN}"
    echo -e "  CPU     : ${YELLOW}${_cpu_model:-未知} × ${_cpu_cores:-?}${PLAIN}"
    echo -e "  内存    : ${YELLOW}${_mem_used}MB / ${_mem_total}MB${PLAIN}"
    echo -e "  磁盘    : ${YELLOW}${_disk:-未知}${PLAIN}"
    echo -e "  负载    : ${YELLOW}${_load:-未知}${PLAIN}"
    echo -e "  运行时间: ${YELLOW}${_uptime_str:-未知}${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    check_bbr_status
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    check_auto_update_status
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo ""
    read -r -p "按回车返回..." _tmp
}

# ============================================================
# 服务器工具子菜单
# ============================================================

server_tools_menu() {
    while true; do
        clear_screen
        echo -e "\n${SKYBLUE}--- 服务器工具 ---${PLAIN}"
        echo -e "1. 开启标准 BBR + fq"
        echo -e "2. 查看 BBR 状态"
        echo -e "3. 开启自动更新（每天 03:00）"
        echo -e "4. 关闭自动更新"
        echo -e "5. 查看自动更新日志"
        echo -e "6. 系统信息总览"
        echo -e "0. 返回"
        read -r -p "请选择: " opt
        case $opt in
            1) enable_bbr ;;
            2) echo ""; check_bbr_status; echo ""; read -r -p "按回车继续..." _tmp ;;
            3) install_auto_update ;;
            4) remove_auto_update ;;
            5) view_auto_update_log ;;
            6) show_system_info ;;
            0) return ;;
            *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 主菜单
# ============================================================

main_menu() {
    while true; do
        clear_screen

        local STATUS
        if [ -f "$HY_BIN" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi

        local _ver_line=""
        if [ -f "$HY_BIN" ]; then
            local _ver
            _ver=$("$HY_BIN" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            [ -n "$_ver" ] && _ver_line=" (${_ver})"
        fi

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}    Hysteria2 Management Script v2.0.18${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e " 作者    : ${YELLOW}everettlabs${PLAIN}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " Seedloc博客 : https://seedloc.com"
        echo -e " VPSknow网站 : https://vpsknow.com"
        echo -e " Nodeloc论坛 : https://nodeloc.com"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: $STATUS${_ver_line}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 安装 Hysteria2"
        echo -e " 2. 管理 Hysteria2"
        echo -e " 3. 升级 Hysteria2"
        echo -e " 4. 卸载 Hysteria2"
        echo -e " 5. 服务器工具 (BBR / 自动更新 / 系统信息)"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}===============================================${PLAIN}"

        read -r -p "请输入选项 [0-5]: " choice
        case $choice in
            1) install_hy2 ;;
            2) manage_hy2 ;;
            3) upgrade_hy2 ;;
            4) uninstall_hy2 ;;
            5) server_tools_menu ;;
            0|q|quit|exit) exit 0 ;;
            *) echo -e "${RED}无效选项，请输入 0-5${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 入口
# ============================================================

if [ "${EXPORT_LIB_ONLY:-0}" != "1" ]; then
    check_root
    check_sys
    detect_init
    case "${1:-menu}" in
        install) install_hy2 ;;
        info|node|export|all) show_config ;;
        uri|link) show_config uri ;;
        mihomo|clash) show_config mihomo ;;
        surfboard) show_config surfboard ;;
        shadowrocket) show_config shadowrocket ;;
        loon) show_config loon ;;
        quantumult|quantumultx) show_config quantumult ;;
        qrcode|qr) show_config qrcode ;;
        manage|service|config) manage_hy2 ;;
        upgrade|update) upgrade_hy2 ;;
        uninstall|remove) uninstall_hy2 ;;
        menu|"") main_menu ;;
        *)
            echo -e "${RED}未知命令: ${1}${PLAIN}"
            echo "可用命令: install | info | manage | upgrade | uninstall"
            exit 1
            ;;
    esac
fi
