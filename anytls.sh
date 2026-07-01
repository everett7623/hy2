#!/bin/bash
#====================================================================================
# 项目：AnyTLS Management Script
# 作者：Jensfrank
# 版本：v1.0.3
# GitHub: https://github.com/everett7623/hy2
# 更新日期: 2026-07-01
#
# 官方实现: https://github.com/anytls/anytls-go
# 官方 Linux 架构: amd64 / arm64
#====================================================================================

if [ -z "$BASH_VERSION" ]; then
    command -v bash >/dev/null 2>&1 && exec bash "$0" "$@"
    if command -v apk >/dev/null 2>&1; then apk add --no-cache bash >/dev/null 2>&1
    elif command -v apt-get >/dev/null 2>&1; then apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq bash >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then dnf install -y bash >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then yum install -y bash >/dev/null 2>&1
    fi
    command -v bash >/dev/null 2>&1 || { echo "错误: 无法安装 bash"; exit 1; }
    exec bash "$0" "$@"
fi

if [ "${ANYTLS_LIB_ONLY:-0}" != "1" ] && [ ! -t 0 ] && [ -c /dev/tty ]; then
    exec < /dev/tty
fi
if [ "${ANYTLS_LIB_ONLY:-0}" != "1" ] && [ -f "$0" ] && grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0"
    exec bash "$0" "$@"
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; PLAIN='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

ANYTLS_BIN="${ANYTLS_BIN:-/usr/local/bin/anytls-server}"
ANYTLS_DIR="${ANYTLS_DIR:-/etc/anytls}"
ANYTLS_CONFIG="${ANYTLS_CONFIG:-${ANYTLS_DIR}/config.env}"
ANYTLS_META="${ANYTLS_META:-${ANYTLS_DIR}/meta}"
SYSTEMD_SERVICE="${SYSTEMD_SERVICE:-/etc/systemd/system/anytls-server.service}"
OPENRC_SERVICE="${OPENRC_SERVICE:-/etc/init.d/anytls-server}"
PID_FILE="${PID_FILE:-/var/run/anytls-server.pid}"
SERVER_LOG="${SERVER_LOG:-/var/log/anytls-server.log}"
AUTO_UPDATE_SCRIPT="${AUTO_UPDATE_SCRIPT:-/usr/local/bin/anytls-autoupdate.sh}"
AUTO_UPDATE_LOG="${AUTO_UPDATE_LOG:-/var/log/anytls-autoupdate.log}"
BBR_CONFIG="${BBR_CONFIG:-/etc/sysctl.d/99-anytls-bbr.conf}"

RELEASE=""; INIT_SYS="none"; NAT_MODE=0; HAS_IPV4=0; HAS_IPV6=0
PUBLIC_IP=""; PUBLIC_IPV6=""; LISTEN_PORT=""; EXT_PORT=""
PASSWORD=""; BIND_FAMILY="v4"; UPSTREAM_VERSION=""

say_error() { echo -e "${RED}$*${PLAIN}"; }
say_ok()    { echo -e "${GREEN}$*${PLAIN}"; }
say_warn()  { echo -e "${YELLOW}$*${PLAIN}"; }

check_root() {
    [ "$EUID" -eq 0 ] || { say_error "错误: 请以 root 权限运行"; exit 1; }
}

detect_system() {
    if [ -f /etc/alpine-release ]; then RELEASE="alpine"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|linuxmint|kali) RELEASE="debian" ;;
            centos|rhel) RELEASE="centos" ;;
            fedora) RELEASE="fedora" ;;
            rocky|almalinux|ol) RELEASE="rocky" ;;
            arch|manjaro|endeavouros) RELEASE="arch" ;;
            *) case "${ID_LIKE:-}" in *debian*|*ubuntu*) RELEASE="debian" ;; *rhel*|*fedora*) RELEASE="rocky" ;; *) RELEASE="unknown" ;; esac ;;
        esac
    else RELEASE="unknown"
    fi

    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then INIT_SYS="systemd"
    elif command -v rc-service >/dev/null 2>&1; then INIT_SYS="openrc"
    else INIT_SYS="none"
    fi
}

install_dependencies() {
    case "$RELEASE" in
        debian) apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl wget unzip ca-certificates openssl iproute2 procps >/dev/null 2>&1; apt-get install -y -qq qrencode >/dev/null 2>&1 || true ;;
        centos) yum install -y curl wget unzip ca-certificates openssl iproute procps-ng >/dev/null 2>&1; yum install -y qrencode >/dev/null 2>&1 || true ;;
        fedora|rocky) dnf install -y curl wget unzip ca-certificates openssl iproute procps-ng >/dev/null 2>&1; dnf install -y qrencode >/dev/null 2>&1 || true ;;
        arch) pacman -Sy --noconfirm curl wget unzip ca-certificates openssl iproute2 procps-ng >/dev/null 2>&1; pacman -S --noconfirm qrencode >/dev/null 2>&1 || true ;;
        alpine) apk add --no-cache bash curl wget unzip ca-certificates openssl iproute2 procps >/dev/null 2>&1; apk add --no-cache libqrencode >/dev/null 2>&1 || true ;;
        *) say_error "不支持的发行版"; return 1 ;;
    esac
    local cmd
    for cmd in curl wget unzip openssl; do command -v "$cmd" >/dev/null 2>&1 || { say_error "缺少依赖: $cmd"; return 1; }; done
}

validate_port() {
    case "$1" in ''|*[!0-9]*|0*) return 1 ;; esac
    awk -v p="$1" 'BEGIN {exit (p >= 1 && p <= 65535) ? 0 : 1}'
}

validate_password() {
    local len
    len=$(printf '%s' "$1" | awk '{print length}')
    [ "$len" -ge 8 ] && [ "$len" -le 128 ] || return 1
    case "$1" in *[!A-Za-z0-9._~-]*) return 1 ;; esac
}

generate_password() {
    local value=""
    while [ ${#value} -lt 24 ]; do value="${value}$(openssl rand -base64 32 2>/dev/null | tr -dc A-Za-z0-9)"; done
    printf '%s' "${value:0:24}"
}

detect_arch() {
    case "${1:-$(uname -m)}" in x86_64|amd64) echo amd64 ;; aarch64|arm64) echo arm64 ;; *) return 1 ;; esac
}

build_release_url() {
    local version="$1" arch="$2" plain
    echo "$version" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$' || return 1
    case "$arch" in amd64|arm64) ;; *) return 1 ;; esac
    plain=${version#v}
    printf 'https://github.com/anytls/anytls-go/releases/download/%s/anytls_%s_linux_%s.zip' "$version" "$plain" "$arch"
}

validate_elf() {
    local magic
    [ -s "$1" ] || return 1
    magic=$(od -An -tx1 -N 4 "$1" 2>/dev/null | awk 'NR==1 {print $1, $2, $3, $4}')
    [ "$magic" = "7f 45 4c 46" ]
}

uri_encode() {
    local input="$1" output="" index=0 char hex length=${#1}
    while [ "$index" -lt "$length" ]; do
        char="${input:index:1}"
        case "$char" in [A-Za-z0-9._~-]) output="${output}${char}" ;; *) hex=$(printf '%s' "$char" | od -An -tx1 | awk '{for(i=1;i<=NF;i++) printf "%%%s", toupper($i)}'); output="${output}${hex}" ;; esac
        index=$((index + 1))
    done
    printf '%s' "$output"
}

listen_address() {
    [ "$BIND_FAMILY" = "v6" ] && printf '[::]:%s' "$LISTEN_PORT" || printf '0.0.0.0:%s' "$LISTEN_PORT"
}

render_uri() {
    local host="$1" port="$2" password="$3" name="$4"
    echo "$host" | grep -q ':' && host="[$host]"
    printf 'anytls://%s@%s:%s/?insecure=1#%s' "$(uri_encode "$password")" "$host" "$port" "$(uri_encode "$name")"
}

write_config() {
    mkdir -p "$ANYTLS_DIR" "$ANYTLS_META"
    cat > "$ANYTLS_CONFIG" <<EOF
LISTEN_PORT=$LISTEN_PORT
EXT_PORT=$EXT_PORT
PASSWORD=$PASSWORD
NAT_MODE=$NAT_MODE
BIND_FAMILY=$BIND_FAMILY
EOF
    chmod 600 "$ANYTLS_CONFIG"
}

read_config() {
    [ -f "$ANYTLS_CONFIG" ] || return 1
    LISTEN_PORT=$(sed -n 's/^LISTEN_PORT=//p' "$ANYTLS_CONFIG" | tail -1)
    EXT_PORT=$(sed -n 's/^EXT_PORT=//p' "$ANYTLS_CONFIG" | tail -1)
    PASSWORD=$(sed -n 's/^PASSWORD=//p' "$ANYTLS_CONFIG" | tail -1)
    NAT_MODE=$(sed -n 's/^NAT_MODE=//p' "$ANYTLS_CONFIG" | tail -1); NAT_MODE=${NAT_MODE:-0}
    BIND_FAMILY=$(sed -n 's/^BIND_FAMILY=//p' "$ANYTLS_CONFIG" | tail -1); BIND_FAMILY=${BIND_FAMILY:-v4}
    EXT_PORT=${EXT_PORT:-$LISTEN_PORT}
    PUBLIC_IP=$(cat "$ANYTLS_META/public_ip" 2>/dev/null || true)
    PUBLIC_IPV6=$(cat "$ANYTLS_META/public_ipv6" 2>/dev/null || true)
    validate_port "$LISTEN_PORT" && validate_port "$EXT_PORT" && validate_password "$PASSWORD"
}

write_systemd_service() {
    cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=AnyTLS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$ANYTLS_BIN -l $(listen_address) -p $PASSWORD
Restart=on-failure
RestartSec=5s
LimitNOFILE=512000

[Install]
WantedBy=multi-user.target
EOF
    chmod 600 "$SYSTEMD_SERVICE"
}

write_openrc_service() {
    cat > "$OPENRC_SERVICE" <<EOF
#!/sbin/openrc-run
name="anytls-server"
description="AnyTLS Server"
command="$ANYTLS_BIN"
command_args="-l $(listen_address) -p $PASSWORD"
command_background=true
pidfile="$PID_FILE"
output_log="$SERVER_LOG"
error_log="$SERVER_LOG"
depend() { need net; after firewall; }
EOF
    chmod 700 "$OPENRC_SERVICE"
}

service_setup() {
    case "$INIT_SYS" in
        systemd) write_systemd_service; systemctl daemon-reload; systemctl enable anytls-server >/dev/null 2>&1 ;;
        openrc) write_openrc_service; rc-update add anytls-server default >/dev/null 2>&1 ;;
    esac
}

service_start() {
    case "$INIT_SYS" in
        systemd) systemctl start anytls-server ;;
        openrc) rc-service anytls-server start ;;
        *) nohup "$ANYTLS_BIN" -l "$(listen_address)" -p "$PASSWORD" >"$SERVER_LOG" 2>&1 & echo $! > "$PID_FILE" ;;
    esac
}

service_stop() {
    case "$INIT_SYS" in
        systemd) systemctl stop anytls-server 2>/dev/null ;;
        openrc) rc-service anytls-server stop 2>/dev/null ;;
        *) [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null || true; rm -f "$PID_FILE" ;;
    esac
}

service_restart() {
    case "$INIT_SYS" in
        systemd) systemctl restart anytls-server ;;
        openrc) rc-service anytls-server restart ;;
        *) service_stop; sleep 1; service_start ;;
    esac
}
service_active() {
    case "$INIT_SYS" in
        systemd) systemctl is-active --quiet anytls-server ;;
        openrc) rc-service anytls-server status 2>/dev/null | grep -q started ;;
        *) [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null ;;
    esac
}
service_logs() { [ "$INIT_SYS" = systemd ] && journalctl -u anytls-server -n 50 --no-pager || tail -n 50 "$SERVER_LOG" 2>/dev/null; }

detect_network() {
    local ip local4
    PUBLIC_IP=$(curl -s4 --connect-timeout 3 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
    echo "$PUBLIC_IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && HAS_IPV4=1 || { HAS_IPV4=0; PUBLIC_IP=""; }
    PUBLIC_IPV6=$(curl -s6 --connect-timeout 3 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]')
    echo "$PUBLIC_IPV6" | grep -q ':' && HAS_IPV6=1 || { HAS_IPV6=0; PUBLIC_IPV6=""; }
    if [ "$HAS_IPV4" = 1 ] && command -v ip >/dev/null 2>&1; then
        local4=$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1)
        echo "$local4" | grep -qx "$PUBLIC_IP" || NAT_MODE=1
    fi
    [ "$HAS_IPV4" = 0 ] && [ "$HAS_IPV6" = 0 ] && return 1
    ip="$PUBLIC_IP"; [ -z "$ip" ] && ip="$PUBLIC_IPV6"
    say_ok "检测到公网地址: $ip"
}

fetch_latest_version() {
    UPSTREAM_VERSION=$(curl -fsSL --connect-timeout 5 --max-time 15 https://api.github.com/repos/anytls/anytls-go/releases/latest 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)
    echo "$UPSTREAM_VERSION" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

download_server() {
    local version="$1" arch url temp archive candidate
    arch=$(detect_arch) || { say_error "AnyTLS 官方仅提供 amd64/arm64"; return 1; }
    url=$(build_release_url "$version" "$arch") || return 1
    temp=$(mktemp -d /tmp/anytls-XXXXXX 2>/dev/null) || return 1
    archive="$temp/anytls.zip"; candidate="$temp/anytls-server"
    wget -q --timeout=60 -O "$archive" "$url" && unzip -q "$archive" -d "$temp" && validate_elf "$candidate" || { rm -rf "$temp"; return 1; }
    chmod 755 "$candidate"; mv -f "$candidate" "$ANYTLS_BIN"; rm -rf "$temp"
    mkdir -p "$ANYTLS_META"; printf '%s\n' "$version" > "$ANYTLS_META/version"
}

firewall_add() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q active; then ufw allow "$port/tcp" >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --permanent --add-port="$port/tcp" >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1
    elif [ "$BIND_FAMILY" = v6 ] && command -v ip6tables >/dev/null 2>&1; then ip6tables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport "$port" -j ACCEPT
    elif command -v iptables >/dev/null 2>&1; then iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
    else say_warn "请手动放行 TCP $port"; fi
}

choose_config() {
    local input
    read -r -p "监听端口 [8443]: " input; LISTEN_PORT=${input:-8443}; validate_port "$LISTEN_PORT" || return 1
    if [ "$NAT_MODE" = 1 ]; then read -r -p "外网端口 [同监听端口]: " input; EXT_PORT=${input:-$LISTEN_PORT}; validate_port "$EXT_PORT" || return 1; else EXT_PORT="$LISTEN_PORT"; fi
    if [ "$HAS_IPV4" = 1 ] && [ "$HAS_IPV6" = 1 ]; then read -r -p "入站地址 1=IPv6 2=IPv4 [1]: " input; [ "$input" = 2 ] && BIND_FAMILY=v4 || BIND_FAMILY=v6
    elif [ "$HAS_IPV6" = 1 ]; then BIND_FAMILY=v6; else BIND_FAMILY=v4; fi
    read -r -p "密码 [留空自动生成]: " PASSWORD; PASSWORD=${PASSWORD:-$(generate_password)}; validate_password "$PASSWORD"
}

show_node() {
    read_config || return 1
    local host uri name="AnyTLS-$(date +%m%d)"
    [ "$BIND_FAMILY" = v6 ] && host="$PUBLIC_IPV6" || host="$PUBLIC_IP"
    uri=$(render_uri "$host" "$EXT_PORT" "$PASSWORD" "$name")
    echo -e "${CYAN}地址:${PLAIN} $host  ${CYAN}端口:${PLAIN} $EXT_PORT"
    echo -e "${CYAN}密码:${PLAIN} $PASSWORD"
    echo "$uri"
    command -v qrencode >/dev/null 2>&1 && qrencode -t ANSIUTF8 -m 2 "$uri"
    echo "- {name: '$name', type: anytls, server: '$host', port: $EXT_PORT, password: '$PASSWORD', client-fingerprint: chrome, udp: true, idle-session-check-interval: 30, idle-session-timeout: 30, min-idle-session: 0, skip-cert-verify: true}"
}

install_anytls() {
    install_dependencies && detect_network && choose_config && fetch_latest_version || { say_error "安装准备失败"; return 1; }
    local backup=""; [ -f "$ANYTLS_BIN" ] && backup=$(mktemp /tmp/anytls-old-XXXXXX) && cp "$ANYTLS_BIN" "$backup"
    download_server "$UPSTREAM_VERSION" || { say_error "下载或校验失败"; rm -f "$backup"; return 1; }
    write_config; printf '%s\n' "$PUBLIC_IP" > "$ANYTLS_META/public_ip"; printf '%s\n' "$PUBLIC_IPV6" > "$ANYTLS_META/public_ipv6"
    firewall_add "$LISTEN_PORT"; service_setup; service_restart; sleep 2
    if service_active; then rm -f "$backup"; say_ok "AnyTLS 安装成功"; show_node
    else
        if [ -n "$backup" ]; then mv -f "$backup" "$ANYTLS_BIN"; else rm -f "$ANYTLS_BIN"; fi
        service_stop >/dev/null 2>&1 || true
        say_error "启动失败，已回滚或清理失败安装"
        service_logs
        return 1
    fi
}

upgrade_anytls() {
    [ -f "$ANYTLS_BIN" ] && read_config || { say_error "AnyTLS 未安装"; return 1; }
    fetch_latest_version || return 1
    local current backup="${ANYTLS_BIN}.bak" running=0
    current=$(cat "$ANYTLS_META/version" 2>/dev/null || true); [ "$current" = "$UPSTREAM_VERSION" ] && { say_ok "已是最新版本"; return; }
    service_active && running=1; cp "$ANYTLS_BIN" "$backup" || return 1
    if download_server "$UPSTREAM_VERSION" && { [ "$running" = 0 ] || { service_restart && sleep 2 && service_active; }; }; then rm -f "$backup"; say_ok "升级成功"
    else mv -f "$backup" "$ANYTLS_BIN"; printf '%s\n' "$current" > "$ANYTLS_META/version"; [ "$running" = 1 ] && service_restart; say_error "升级失败，已回滚"; fi
}

uninstall_anytls() {
    read -r -p "确认卸载 AnyTLS? [y/N]: " answer; case "$answer" in y|Y) ;; *) return ;; esac
    service_stop; case "$INIT_SYS" in systemd) systemctl disable anytls-server >/dev/null 2>&1; rm -f "$SYSTEMD_SERVICE"; systemctl daemon-reload ;; openrc) rc-update del anytls-server default >/dev/null 2>&1; rm -f "$OPENRC_SERVICE" ;; esac
    rm -f "$ANYTLS_BIN" "$PID_FILE" "$AUTO_UPDATE_SCRIPT"; rm -rf "$ANYTLS_DIR"; say_ok "AnyTLS 已卸载"
}

install_auto_update() {
    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
LOCK_DIR=/var/run/anytls-autoupdate.lock
mkdir "$LOCK_DIR" 2>/dev/null || exit 0
tmp=""
trap 'rm -rf "$LOCK_DIR" "$tmp"' EXIT INT TERM
SCRIPT_URL="https://raw.githubusercontent.com/everett7623/hy2/main/anytls.sh"
tmp=$(mktemp /tmp/anytls-manager-XXXXXX.sh) || exit 1
curl -fsSL --connect-timeout 10 --max-time 60 "$SCRIPT_URL" -o "$tmp" && bash -n "$tmp" || { rm -f "$tmp"; exit 1; }
ANYTLS_LIB_ONLY=1 . "$tmp"
detect_system
upgrade_anytls >> /var/log/anytls-autoupdate.log 2>&1
AUTOUPDATE_EOF
    chmod 700 "$AUTO_UPDATE_SCRIPT"
    command -v crontab >/dev/null 2>&1 || { say_error "缺少 cron"; return 1; }
    (crontab -l 2>/dev/null | grep -v anytls-autoupdate; echo "0 3 * * * /bin/bash $AUTO_UPDATE_SCRIPT") | crontab -
    say_ok "自动更新已启用"
}

manage_menu() {
    while true; do
        echo "1. 查看节点  2. 重启  3. 停止  4. 启动  5. 日志  0. 返回"
        read -r -p "请选择: " choice
        case "$choice" in 1) show_node ;; 2) service_restart ;; 3) service_stop ;; 4) read_config && service_start ;; 5) service_logs ;; 0) return ;; *) say_error "输入错误" ;; esac
    done
}

main_menu() {
    while true; do
        clear
        echo -e "${CYAN}===============================================${PLAIN}"
        echo -e "${GREEN}      AnyTLS Management Script v1.0.3${PLAIN}"
        echo "1. 安装/重装  2. 管理  3. 升级  4. 卸载  5. 自动更新  0. 退出"
        read -r -p "请选择: " choice
        case "$choice" in 1) install_anytls ;; 2) manage_menu ;; 3) upgrade_anytls ;; 4) uninstall_anytls ;; 5) install_auto_update ;; 0) exit 0 ;; *) say_error "输入错误" ;; esac
    done
}

if [ "${ANYTLS_LIB_ONLY:-0}" != "1" ]; then
    check_root
    detect_system
    read_config >/dev/null 2>&1 || true
    main_menu
fi
