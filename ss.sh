#!/bin/bash
#====================================================================================
# 项目：Shadowsocks-Rust Management Script
# 作者：Jensfrank
# 版本：v2.0.1
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-07-03
#
# 支持系统: 完美兼容 Debian, Ubuntu, CentOS, Rocky, Alma, Alpine, Arch 等
# 支持环境: 标准 VPS / NAT 机器 / 极简系统环境 / GLIBC 免疫
#
# v1.0.0: IPv6优先+WARP过滤+IP切换 + 升级/BBR/QR/连接测试
#====================================================================================

# ============================================================
# 自举：确保以 bash 运行
# Alpine 等系统默认 sh 为 busybox，不支持 bash 语法
# 注意：仅支持已保存到磁盘后执行，不可通过 curl | sh 管道运行（$0 不是文件路径）
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

if [ "${EXPORT_LIB_ONLY:-0}" != "1" ] && [ ! -t 0 ]; then
    [ -c /dev/tty ] && exec < /dev/tty
fi

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
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# --- 路径 ---
SS_BIN="/usr/local/bin/ssserver"
SS_CONFIG="/etc/shadowsocks-rust/config.json"
SS_META="/etc/shadowsocks-rust/meta"
SERVICE_FILE="/etc/systemd/system/shadowsocks-server.service"
OPENRC_SERVICE="/etc/init.d/shadowsocks-server"
AUTO_UPDATE_SCRIPT="/usr/local/bin/ss-autoupdate.sh"
AUTO_UPDATE_LOG="/var/log/ss-autoupdate.log"

# --- 运行时变量 ---
NAT_MODE=0
IPV6_ONLY=0
HAS_IPV4=0
HAS_IPV6=0
PUBLIC_IP=""
PUBLIC_IPV6=""
LISTEN_PORT=""
EXT_PORT=""

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

detect_network() {
    echo -e "${YELLOW}正在检测网络环境...${PLAIN}"
    local _ip _url

    # IPv6 优先探测
    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -q ':'; then
            PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break
        fi
    done

    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --connect-timeout 3 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            PUBLIC_IP="$_ip"; HAS_IPV4=1; break
        fi
    done

    # 过滤 WARP/隧道 虚拟 IPv4：纯 IPv6 VPS + WARP 场景下，
    # curl -4 会通过 WARP 拿到 Cloudflare 的 IPv4，但无法用于入站连接
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

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && IPV6_ONLY=1

    if   [ "$NAT_MODE"  = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$IPV6_ONLY" = "1" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"  = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv6: ${PUBLIC_IPV6} | IPv4: ${PUBLIC_IP}）"
    elif [ "$HAS_IPV4"  = "1" ]; then echo -e "  机器类型: ${GREEN}标准 IPv4${PLAIN}（IP: ${PUBLIC_IP}）"
    else                               echo -e "  机器类型: ${RED}无法检测，请手动输入${PLAIN}"
    fi

    if [ "$HAS_IPV6" = "0" ]; then
        echo -e "\n${RED}==========================================================${PLAIN}"
        echo -e "${RED}警告：未检测到公网 IPv6 地址！${PLAIN}"
        echo -e "${RED}Shadowsocks 协议在纯 IPv4 环境下较易被识别并封锁。${PLAIN}"
        echo -e "${YELLOW}建议在 双栈(IPv4+IPv6) 或 纯 IPv6 的 VPS 上使用。${PLAIN}"
        echo -e "${RED}==========================================================${PLAIN}"
        read -r -p "是否强制继续安装？(风险自负) [y/N]: " _force
        [[ ! "$_force" =~ ^[yY]$ ]] && echo "已取消。" && exit 1
    fi
}

# ============================================================
# 防火墙端口放行
# ============================================================

open_ports() {
    local _port=$1
    echo -e "${YELLOW}正在自动放行 Linux 系统防火墙端口 ${_port}...${PLAIN}"

    # firewalld：用 --state 判断运行状态（比 is-active 更可靠）
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${_port}/tcp" >/dev/null 2>&1
        firewall-cmd --permanent --add-port="${_port}/udp" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "  ${GREEN}✓ firewalld 已放行 tcp+udp/${_port}${PLAIN}"
        return
    fi

    # ufw：用 ufw status 判断 active（比 is-active 更可靠）
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow "${_port}/tcp" >/dev/null 2>&1
        ufw allow "${_port}/udp" >/dev/null 2>&1
        echo -e "  ${GREEN}✓ ufw 已放行 tcp+udp/${_port}${PLAIN}"
        return
    fi

    if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
            iptables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1
        iptables -C INPUT -p udp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
            iptables -I INPUT -p udp --dport "${_port}" -j ACCEPT >/dev/null 2>&1
        if [ "$HAS_IPV6" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
            ip6tables -C INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
                ip6tables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1
            ip6tables -C INPUT -p udp --dport "${_port}" -j ACCEPT >/dev/null 2>&1 || \
                ip6tables -I INPUT -p udp --dport "${_port}" -j ACCEPT >/dev/null 2>&1
        fi
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1
        elif [ -f /etc/sysconfig/iptables ] && command -v service >/dev/null 2>&1; then
            service iptables save >/dev/null 2>&1
        fi
        echo -e "  ${GREEN}✓ iptables 已放行 tcp+udp/${_port}${PLAIN}"
    fi
}

# ============================================================
# 服务管理
# ============================================================

service_start() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl start shadowsocks-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service shadowsocks-server start
    else
        nohup "$SS_BIN" -c "$SS_CONFIG" >/var/log/ssserver.log 2>&1 & echo $! > /var/run/ssserver.pid
    fi
}

service_stop() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl stop shadowsocks-server 2>/dev/null
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service shadowsocks-server stop 2>/dev/null
    else
        [ -f /var/run/ssserver.pid ] && kill "$(cat /var/run/ssserver.pid)" 2>/dev/null && rm -f /var/run/ssserver.pid
        pkill -f "ssserver" 2>/dev/null
    fi
}

service_restart() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl restart shadowsocks-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service shadowsocks-server restart
    else
        service_stop
        sleep 1
        service_start
    fi
}

service_enable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable shadowsocks-server >/dev/null 2>&1
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update add shadowsocks-server default >/dev/null 2>&1
    fi
}

service_disable() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl disable shadowsocks-server 2>/dev/null
        systemctl daemon-reload
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-update del shadowsocks-server default 2>/dev/null
    fi
}

service_is_active() {
    if [ "$INIT_SYS" = "systemd" ]; then
        systemctl is-active --quiet shadowsocks-server
    elif [ "$INIT_SYS" = "openrc" ]; then
        rc-service shadowsocks-server status 2>/dev/null | grep -q "started"
    else
        [ -f /var/run/ssserver.pid ] && kill -0 "$(cat /var/run/ssserver.pid)" 2>/dev/null
    fi
}

service_logs() {
    if [ "$INIT_SYS" = "systemd" ]; then
        journalctl -u shadowsocks-server -n 50 --no-pager
    else
        tail -n 50 /var/log/ssserver.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
    fi
}

setup_systemd_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Shadowsocks-Rust Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${SS_BIN} -c ${SS_CONFIG}
Restart=on-failure
RestartSec=5s
LimitNOFILE=512000

[Install]
WantedBy=multi-user.target
EOF
}

setup_openrc_service() {
    cat > "$OPENRC_SERVICE" <<'SVCHEAD'
#!/sbin/openrc-run

name="shadowsocks-server"
description="Shadowsocks-Rust Server"
SVCHEAD
    cat >> "$OPENRC_SERVICE" <<EOF
command="${SS_BIN}"
command_args="-c ${SS_CONFIG}"
command_background=true
pidfile="/var/run/ssserver.pid"
output_log="/var/log/ssserver.log"
error_log="/var/log/ssserver.log"

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$OPENRC_SERVICE"
}

# ============================================================
# 依赖安装
# ============================================================

install_dependencies() {
    echo -e "${YELLOW}正在安装必要依赖...${PLAIN}"

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1
        # qrencode 用于终端内渲染二维码
        apt-get install -y -qq curl wget ca-certificates openssl tar xz-utils iproute2 procps >/dev/null 2>&1
        apt-get install -y -qq qrencode >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl wget ca-certificates openssl tar xz iproute procps-ng >/dev/null 2>&1
        dnf install -y qrencode >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget ca-certificates openssl tar xz iproute procps-ng >/dev/null 2>&1
        yum install -y qrencode >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm curl wget ca-certificates openssl tar xz iproute2 procps-ng >/dev/null 2>&1
        pacman -S --noconfirm qrencode >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
        apk update -q >/dev/null 2>&1
        apk add --no-cache bash curl wget ca-certificates openssl tar xz iproute2 procps >/dev/null 2>&1
        apk add --no-cache libqrencode >/dev/null 2>&1 || true
    fi

    local _missing=0
    for pkg in curl wget openssl tar; do
        if ! command -v $pkg >/dev/null 2>&1; then
            echo -e "${RED}致命错误: 系统中缺少组件 [ $pkg ]${PLAIN}"
            _missing=1
        fi
    done
    [ "$_missing" -eq 1 ] && exit 1
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_json_secret() {
    ! echo "$1" | grep -qE '["\\]|[[:cntrl:]]'
}

# ============================================================
# 获取最新版本 & 下载二进制
# ============================================================

get_latest_version() {
    echo -e "${YELLOW}正在获取最新版本...${PLAIN}"
    LAST_VERSION=$(curl -Ls --max-time 10 \
        "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)

    if [ -z "$LAST_VERSION" ]; then
        LAST_VERSION=$(curl -Ls -o /dev/null -w "%{url_effective}" \
            "https://github.com/shadowsocks/shadowsocks-rust/releases/latest" | sed 's|.*/tag/||')
    fi

    [ -z "$LAST_VERSION" ] && echo -e "${RED}获取版本失败，请检查网络${PLAIN}" && return 1
    echo -e "${GREEN}最新版本: ${LAST_VERSION}${PLAIN}"
}

download_ss() {
    local _arch
    case $(uname -m) in
        x86_64)          _arch="x86_64-unknown-linux-musl" ;;
        aarch64|arm64)   _arch="aarch64-unknown-linux-musl" ;;
        armv7l|armv7)    _arch="armv7-unknown-linux-musl"  ;;
        s390x)           _arch="s390x-unknown-linux-musl"  ;;
        loongarch64)     _arch="loongarch64-unknown-linux-musl" ;;
        *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}" && return 1 ;;
    esac

    echo -e "${SKYBLUE}>>> 已强制使用 musl 静态编译库，彻底免疫一切 GLIBC 报错！ <<<${PLAIN}"

    local _url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${LAST_VERSION}/shadowsocks-${LAST_VERSION}.${_arch}.tar.xz"
    local _tmp_archive _tmp_dir
    _tmp_archive=$(mktemp /tmp/ss-rust-XXXXXX.tar.xz)
    _tmp_dir=$(mktemp -d /tmp/ss-rust-XXXXXX)

    echo -e "${YELLOW}正在下载 shadowsocks-rust ${LAST_VERSION} (${_arch})...${PLAIN}"
    wget -q --show-progress --timeout=30 -O "$_tmp_archive" "$_url" \
        || { echo -e "${RED}下载失败，请检查网络${PLAIN}"; rm -f "$_tmp_archive"; rm -rf "$_tmp_dir"; return 1; }
    tar -xf "$_tmp_archive" -C "$_tmp_dir" ssserver \
        || { echo -e "${RED}解压失败${PLAIN}"; rm -f "$_tmp_archive"; rm -rf "$_tmp_dir"; return 1; }
    chmod +x "$_tmp_dir/ssserver"
    "$_tmp_dir/ssserver" --version >/dev/null 2>&1 \
        || { echo -e "${RED}下载的二进制无效${PLAIN}"; rm -f "$_tmp_archive"; rm -rf "$_tmp_dir"; return 1; }
    mv -f "$_tmp_dir/ssserver" "$SS_BIN"
    rm -f "$_tmp_archive"; rm -rf "$_tmp_dir"
    echo -e "${GREEN}下载完成${PLAIN}"
}

# ============================================================
# 安装
# ============================================================

install_ss() {
    install_dependencies || return
    detect_network
    get_latest_version || return
    download_ss || return

    mkdir -p /etc/shadowsocks-rust "$SS_META"

    echo -e "\n${SKYBLUE}--- 配置 Shadowsocks 协议 ---${PLAIN}"
    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "请输入本机监听端口 [默认 28888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="28888"
        valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return; }
        read -r -p "请输入对外转发端口 [留空=与监听端口相同]: " EXT_PORT
        [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
        valid_port "$EXT_PORT" || { echo -e "${RED}对外端口必须为 1-65535 的整数${PLAIN}"; return; }
    else
        read -r -p "请输入端口 [默认 28888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="28888"
        valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; return; }
        EXT_PORT="$LISTEN_PORT"
    fi

    _select_cipher || return
    _write_config
    _save_meta

    open_ports "$LISTEN_PORT"

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
    if service_is_active; then
        echo -e "${GREEN}✓ Shadowsocks 服务端启动成功${PLAIN}"
    else
        echo -e "${RED}✗ 启动失败，请查看以下日志排查原因：${PLAIN}"
        service_logs
        read -r -p "按回车键返回主菜单..." _tmp
        return
    fi

    show_config
}

# 协议选择（安装 & 修改配置 共用）
_select_cipher() {
    echo -e "\n${YELLOW}请选择要使用的加密协议：${PLAIN}"
    echo -e " 1. ${GREEN}aes-256-gcm${PLAIN} (经典原版协议，100% 兼容全平台，【默认推荐】)"
    echo -e " 2. ${RED}2022-blake3-aes-256-gcm${PLAIN} (SS-2022 协议，强抗封锁，但要求时间极其准确)"
    read -r -p "请输入选项 [1 或 2，默认 1]: " _cipher_opt

    if [ "$_cipher_opt" = "2" ]; then
        METHOD="2022-blake3-aes-256-gcm"
        PASSWORD=$(openssl rand -base64 32 | tr -d ' \n\r')
        echo -e "${YELLOW}已启用 SS-2022，系统已自动生成 32 字节规范密钥 -> ${PASSWORD}${PLAIN}"
        echo -e "${YELLOW}正在尝试同步服务器时间以防连接超时...${PLAIN}"
        command -v timedatectl >/dev/null 2>&1 && timedatectl set-ntp true >/dev/null 2>&1
    else
        METHOD="aes-256-gcm"
        read -r -p "请设置连接密码 [留空自动生成]: " PASSWORD
        [[ -z "$PASSWORD" ]] && PASSWORD=$(openssl rand -base64 16 | tr -d ' \n\r')
        valid_json_secret "$PASSWORD" || {
            echo -e "${RED}密码不能包含双引号、反斜杠或控制字符${PLAIN}"
            return 1
        }
        echo -e "${GREEN}已启用经典 aes-256-gcm 协议，保证最高连通率！${PLAIN}"
    fi
}

# 写入 config.json
_write_config() {
    local LISTEN_ADDR="0.0.0.0"
    [ "$HAS_IPV6" = "1" ] && LISTEN_ADDR="::"

    cat > "$SS_CONFIG" <<EOF
{
    "server": "$LISTEN_ADDR",
    "server_port": $LISTEN_PORT,
    "password": "$PASSWORD",
    "method": "$METHOD",
    "mode": "tcp_and_udp",
    "timeout": 300
}
EOF
}

# 写入 meta 目录
_save_meta() {
    echo "$NAT_MODE"    > "$SS_META/nat_mode"
    echo "$EXT_PORT"    > "$SS_META/ext_port"
    echo "$LISTEN_PORT" > "$SS_META/listen_port"
    echo "$PASSWORD"    > "$SS_META/password"
    echo "$METHOD"      > "$SS_META/method"
    [ -n "$PUBLIC_IP"   ] && echo "$PUBLIC_IP"   > "$SS_META/public_ip"
    [ -n "$PUBLIC_IPV6" ] && echo "$PUBLIC_IPV6" > "$SS_META/public_ipv6"
}

# ============================================================
# 升级（保留配置，仅替换二进制）
# ============================================================

upgrade_ss() {
    if [ ! -f "$SS_BIN" ]; then
        echo -e "${RED}未检测到已安装的 Shadowsocks-Rust，请先安装${PLAIN}"
        sleep 2; return
    fi

    local _cur_raw _cur_ver=""
    _cur_raw=$("$SS_BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$_cur_raw" ] && _cur_ver="v${_cur_raw}"
    echo -e "  当前版本: ${YELLOW}${_cur_ver:-未知}${PLAIN}"

    get_latest_version || return

    if [ -n "$_cur_ver" ] && [ "$_cur_ver" = "$LAST_VERSION" ]; then
        echo -e "${GREEN}已是最新版本，无需升级${PLAIN}"
        sleep 2; return
    fi

    echo -e "${YELLOW}开始升级: ${_cur_ver:-未知} → ${LAST_VERSION}${PLAIN}"

    # 备份旧二进制，下载/启动失败时回滚
    cp "$SS_BIN" "${SS_BIN}.bak" 2>/dev/null || {
        echo -e "${RED}无法备份当前二进制，取消升级${PLAIN}"
        return
    }

    if download_ss; then
        service_restart
        sleep 2

        if service_is_active; then
            local _new_raw _new_ver=""
            _new_raw=$("$SS_BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            [ -n "$_new_raw" ] && _new_ver="v${_new_raw}"
            echo -e "${GREEN}✓ 升级成功，当前版本: ${_new_ver:-未知}${PLAIN}"
            rm -f "${SS_BIN}.bak"
        else
            echo -e "${RED}✗ 升级后服务启动失败，回滚中...${PLAIN}"
            mv "${SS_BIN}.bak" "$SS_BIN"
            service_restart
            echo -e "${YELLOW}已回滚至旧版本 ${_cur_ver}${PLAIN}"
            service_logs
        fi
    else
        echo -e "${RED}✗ 下载失败，回滚中...${PLAIN}"
        mv "${SS_BIN}.bak" "$SS_BIN"
        service_restart
        echo -e "${YELLOW}已回滚至旧版本 ${_cur_ver}${PLAIN}"
    fi
    sleep 2
}

# ============================================================
# 修改配置（端口 / 密码 / 加密方式）
# ============================================================

modify_config() {
    read_config_vars
    if [ -z "$EXT_PORT" ]; then
        echo -e "${RED}未找到有效配置，请先安装${PLAIN}"
        sleep 2; return
    fi

    echo -e "\n${SKYBLUE}--- 修改配置 ---${PLAIN}"
    echo -e "  当前端口: ${YELLOW}${EXT_PORT}${PLAIN}  密码: ${YELLOW}${PASSWORD}${PLAIN}  加密: ${YELLOW}${METHOD}${PLAIN}"
    echo ""
    echo -e " 1. 修改端口"
    echo -e " 2. 修改密码"
    echo -e " 3. 修改加密方式（重新选择协议）"
    echo -e " 0. 返回"
    read -r -p "请选择: " _mod_opt

    case "$_mod_opt" in
        1)
            if [ "$NAT_MODE" = "1" ]; then
                read -r -p "请输入新的本机监听端口: " LISTEN_PORT
                [[ -z "$LISTEN_PORT" ]] && { echo -e "${RED}端口不能为空${PLAIN}"; sleep 1; return; }
                valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; sleep 1; return; }
                read -r -p "请输入新的对外转发端口 [留空=同监听端口]: " EXT_PORT
                [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
                valid_port "$EXT_PORT" || { echo -e "${RED}对外端口必须为 1-65535 的整数${PLAIN}"; sleep 1; return; }
            else
                read -r -p "请输入新端口: " LISTEN_PORT
                [[ -z "$LISTEN_PORT" ]] && { echo -e "${RED}端口不能为空${PLAIN}"; sleep 1; return; }
                valid_port "$LISTEN_PORT" || { echo -e "${RED}端口必须为 1-65535 的整数${PLAIN}"; sleep 1; return; }
                EXT_PORT="$LISTEN_PORT"
            fi
            open_ports "$LISTEN_PORT"
            ;;
        2)
            if echo "$METHOD" | grep -q "2022"; then
                echo -e "${YELLOW}SS-2022 协议需要 32 字节规范密钥，将自动生成${PLAIN}"
                PASSWORD=$(openssl rand -base64 32 | tr -d ' \n\r')
                echo -e "  新密钥: ${GREEN}${PASSWORD}${PLAIN}"
            else
                read -r -p "请输入新密码 [留空自动生成]: " PASSWORD
                [[ -z "$PASSWORD" ]] && PASSWORD=$(openssl rand -base64 16 | tr -d ' \n\r')
                valid_json_secret "$PASSWORD" || {
                    echo -e "${RED}密码不能包含双引号、反斜杠或控制字符${PLAIN}"
                    sleep 1
                    return
                }
                echo -e "  新密码: ${GREEN}${PASSWORD}${PLAIN}"
            fi
            ;;
        3)
            # 保持安装时的 HAS_IPV6 不变（不重新探测，避免网络抖动误降级为纯 IPv4）
            _select_cipher || return
            ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}"; sleep 1; return ;;
    esac

    local _config_backup _meta_backup
    _config_backup=$(mktemp /tmp/ss-config-XXXXXX 2>/dev/null) || {
        echo -e "${RED}无法创建配置备份${PLAIN}"
        return
    }
    _meta_backup=$(mktemp -d /tmp/ss-meta-XXXXXX 2>/dev/null) || {
        rm -f "$_config_backup"
        echo -e "${RED}无法创建元数据备份${PLAIN}"
        return
    }
    cp "$SS_CONFIG" "$_config_backup"
    cp -a "$SS_META"/. "$_meta_backup"/ 2>/dev/null || true

    _write_config
    _save_meta
    service_restart
    sleep 1

    if service_is_active; then
        rm -f "$_config_backup"
        rm -rf "$_meta_backup"
        echo -e "${GREEN}✓ 配置已更新，服务已重启${PLAIN}"
        sleep 1
        show_config
    else
        cp "$_config_backup" "$SS_CONFIG"
        rm -rf "$SS_META"
        mkdir -p "$SS_META"
        cp -a "$_meta_backup"/. "$SS_META"/ 2>/dev/null || true
        service_restart
        rm -f "$_config_backup"
        rm -rf "$_meta_backup"
        echo -e "${RED}✗ 服务重启失败，配置已回滚${PLAIN}"
        service_logs
        read -r -p "按回车继续..." _tmp
    fi
}

# ============================================================
# URL 编码（python3 优先，纯 bash 降级）
# ============================================================

uri_encode() {
    local _in="$1"
    if command -v python3 >/dev/null 2>&1; then
        if printf '%s' "$_in" | python3 -c \
            "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''), end='')" 2>/dev/null; then
            return
        fi
    fi
    local _out="" _i=0 _c _hex _byte
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
    _protocol=$(trim_string "${3:-Shadowsocks}")
    _ip_type=$(trim_string "${4:-IPv4}")
    printf '%s %s | %s | %s | %s' "$_flag" "$_country" "$_server" "$_protocol" "$_ip_type" | tr -d '\r\n\t'
}

format_ipv6_for_uri() {
    echo "$1" | grep -q ':' && printf '[%s]' "$1" || printf '%s' "$1"
}

format_server_for_yaml() {
    echo "$1" | grep -q ':' && printf '"%s"' "$1" || printf '%s' "$1"
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

export_uri_ss() {
    local _server="$1" _port="$2" _node="$3" _host _credentials _node_encoded
    _host=$(format_ipv6_for_uri "$_server")
    _credentials=$(printf "%s:%s" "$METHOD" "$PASSWORD" | base64 | tr -d ' \n\r')
    _node_encoded=$(uri_encode "$_node")
    printf 'ss://%s@%s:%s#%s' "$_credentials" "$_host" "$_port" "$_node_encoded"
}

export_throne_ss() {
    printf 'Throne 暂不支持该协议的 URI 导入格式。'
}

export_mihomo_ss() {
    local _server="$1" _port="$2" _node="$3" _yaml_server _pass _safe_node
    _yaml_server=$(format_server_for_yaml "$_server")
    _pass=$(shell_json_escape "$PASSWORD")
    _safe_node=$(shell_json_escape "$_node")
    printf '%s' "- {name: \"${_safe_node}\", type: ss, server: ${_yaml_server}, port: ${_port}, cipher: ${METHOD}, password: \"${_pass}\", udp: true}"
}

export_singbox_ss() {
    local _server="$1" _port="$2" _safe_server _pass
    _safe_server=$(shell_json_escape "$_server")
    _pass=$(shell_json_escape "$PASSWORD")
    cat <<CFG
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "udp",
        "tag": "dns_proxy",
        "server": "8.8.8.8",
        "detour": "shadowsocks"
      },
      {
        "type": "udp",
        "tag": "dns_direct",
        "server": "223.5.5.5"
      }
    ],
    "strategy": "ipv4_only",
    "cache_capacity": 4096,
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
      "type": "shadowsocks",
      "tag": "shadowsocks",
      "server": "${_safe_server}",
      "server_port": ${_port},
      "method": "${METHOD}",
      "password": "${_pass}"
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
    "final": "shadowsocks"
  }
}
CFG
}

print_singbox_template_note() {
    echo ""
    echo "以上为完整 Sing-box / SFA TUN 客户端配置，可保存为 config.json 导入。"
}

export_loon_ss() {
    local _server="$1" _port="$2" _node="$3"
    printf '%s = Shadowsocks, %s, %s, %s, "%s"' "$_node" "$_server" "$_port" "$METHOD" "$PASSWORD"
}

export_surfboard_ss() {
    local _server="$1" _port="$2" _node="$3"
    printf '%s = ss, %s, %s, encrypt-method=%s, password=%s, udp-relay=true' "$_node" "$_server" "$_port" "$METHOD" "$PASSWORD"
}

export_shadowrocket_ss() {
    export_uri_ss "$1" "$2" "$3"
}

export_quantumultx_ss() {
    local _server="$1" _port="$2" _node="$3"
    printf 'shadowsocks=%s:%s, method=%s, password=%s, fast-open=false, udp-relay=true, tag=%s' "$_server" "$_port" "$METHOD" "$PASSWORD" "$_node"
}

# ============================================================
# 读取配置变量
# ============================================================

read_config_vars() {
    [ ! -f "$SS_CONFIG" ] && return 1

    if [ -d "$SS_META" ]; then
        NAT_MODE=$(cat "$SS_META/nat_mode"       2>/dev/null); NAT_MODE=${NAT_MODE:-0}
        EXT_PORT=$(cat "$SS_META/ext_port"       2>/dev/null)
        LISTEN_PORT=$(cat "$SS_META/listen_port" 2>/dev/null)
        PASSWORD=$(cat "$SS_META/password"       2>/dev/null)
        METHOD=$(cat "$SS_META/method"           2>/dev/null)
        PUBLIC_IP=$(cat "$SS_META/public_ip"     2>/dev/null)
        PUBLIC_IPV6=$(cat "$SS_META/public_ipv6" 2>/dev/null)
    fi

    # 兜底：从配置文件解析
    [[ -z "$EXT_PORT"  ]] && EXT_PORT=$(grep '"server_port"' "$SS_CONFIG" | grep -oE '[0-9]+' | head -1)
    [[ -z "$PASSWORD"  ]] && PASSWORD=$(grep '"password"' "$SS_CONFIG" | awk -F'"' '{print $4}' | head -1)
    [[ -z "$METHOD"    ]] && METHOD=$(grep '"method"' "$SS_CONFIG" | awk -F'"' '{print $4}' | head -1)

    # IP 兜底
    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        PUBLIC_IP=$(curl -s4 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]')
    fi
}

# ============================================================
# 展示单个节点（含终端二维码）
# ============================================================

show_node() {
    local _ip="$1" _port="$2" _tag="$3"
    local _ip_type _country _server_name _node _uri _qr_url _png
    case "$_tag" in
        v6|IPv6|ipv6) _ip_type="IPv6" ;;
        *)            _ip_type="IPv4" ;;
    esac
    _country=$(get_country_code "$PUBLIC_IP" "$PUBLIC_IPV6")
    _server_name=$(generate_server_name)
    _node=$(generate_node_name "$_country" "$_server_name" "Shadowsocks" "$_ip_type")
    _uri=$(export_uri_ss "$_ip" "$_port" "$_node")
    _qr_url=$(generate_online_qrcode_url "$_uri")

    echo -e "${YELLOW}节点名称:${PLAIN}"
    print_copy_block "$_node"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}URI 分享链接:${PLAIN}"
    print_copy_block "$_uri"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Throne URI:${PLAIN}"
    print_copy_block "$(export_throne_ss)"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Mihomo / Clash Meta / Clash Verge 单行配置:${PLAIN}"
    print_copy_block "$(export_mihomo_ss "$_ip" "$_port" "$_node")"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Loon 配置:${PLAIN}"
    print_copy_block "$(export_loon_ss "$_ip" "$_port" "$_node")"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Surfboard 配置:${PLAIN}"
    print_copy_block "$(export_surfboard_ss "$_ip" "$_port" "$_node")"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Shadowrocket 配置:${PLAIN}"
    print_copy_block "$(export_shadowrocket_ss "$_ip" "$_port" "$_node")"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Quantumult X 配置:${PLAIN}"
    print_copy_block "$(export_quantumultx_ss "$_ip" "$_port" "$_node")"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}二维码:${PLAIN}"
    if generate_terminal_qrcode "$_uri"; then
        echo -e "${GREEN}[OK] 终端二维码已生成${PLAIN}"
        _png=$(generate_local_qrcode_png "$_uri" "shadowsocks" "$_ip_type" 2>/dev/null || true)
        [ -n "$_png" ] && echo -e "本地二维码图片: ${YELLOW}${_png}${PLAIN}"
    else
        echo -e "${YELLOW}[WARN] 未安装 qrencode，跳过终端和本地 PNG 二维码。${PLAIN}"
    fi
    echo -e "${YELLOW}[WARN] 在线二维码会把节点链接提交给第三方服务，不建议公开节点使用。${PLAIN}"
    print_copy_block "$_qr_url"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    echo -e "${GREEN}Sing-box:${PLAIN}"
    export_singbox_ss "$_ip" "$_port" "$_node"
    print_singbox_template_note
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

# ============================================================
# 显示配置
# ============================================================

show_config() {
    read_config_vars
    if [ -z "$EXT_PORT" ]; then
        echo -e "${RED}未找到有效配置${PLAIN}"
        read -r -p "按回车返回..." _tmp
        return
    fi

    local _country _server_name
    _country=$(get_country_code "$PUBLIC_IP" "$PUBLIC_IPV6")
    _server_name=$(generate_server_name)

    echo -e "\n${GREEN}Shadowsocks 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "服务器名称: ${YELLOW}${_server_name}${PLAIN}"
    echo -e "国家/地区: ${YELLOW}${_country} / $(get_country_name "$_country")${PLAIN}"
    [ -n "$PUBLIC_IP"   ] && echo -e "IPv4 地址 : ${YELLOW}${PUBLIC_IP}${PLAIN}"
    [ -n "$PUBLIC_IPV6" ] && echo -e "IPv6 地址 : ${YELLOW}${PUBLIC_IPV6}${PLAIN} ${GREEN}(推荐)${PLAIN}"

    if [ "$NAT_MODE" = "1" ] && [ "$EXT_PORT" != "$LISTEN_PORT" ]; then
        echo -e "监听端口 : ${YELLOW}${LISTEN_PORT}${PLAIN}  ${RED}← 本机监听${PLAIN}"
        echo -e "对外端口 : ${YELLOW}${EXT_PORT}${PLAIN}  ${RED}← 客户端连接此端口${PLAIN}"
    else
        echo -e "端口 Port : ${YELLOW}${EXT_PORT}${PLAIN}"
    fi

    echo -e "密码 Pass : ${YELLOW}${PASSWORD}${PLAIN}"
    echo -e "加密方式 : ${YELLOW}${METHOD}${PLAIN}"
    [ "$NAT_MODE" = "1" ] && echo -e "机器类型 : ${YELLOW}NAT 机器${PLAIN}"

    if echo "$METHOD" | grep -q "2022"; then
        echo -e "\n${RED}⚠️ 注意：您开启了 SS-2022 协议，对时间误差极其敏感！${PLAIN}"
        echo -e "${YELLOW}如果配置全对依然连不上（超时），请务必校准您的手机和电脑时间！${PLAIN}"
    fi
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    if [ -n "$PUBLIC_IP" ]; then
        echo -e "${YELLOW}▼ IPv4 节点配置${PLAIN}"
        show_node "$PUBLIC_IP" "$EXT_PORT" "v4"
    fi
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "${YELLOW}▼ IPv6 节点配置${PLAIN}"
        show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6"
    fi

    echo ""
    read -r -p "按回车键返回主菜单..." _tmp
}

# ============================================================
# 连接测试（本机端口监听验证）
# ============================================================

test_connection() {
    read_config_vars
    if [ -z "$LISTEN_PORT" ]; then
        echo -e "${RED}未找到配置，请先安装${PLAIN}"
        read -r -p "按回车继续..." _tmp; return
    fi

    echo -e "\n${SKYBLUE}--- 连接测试 ---${PLAIN}"

    # 服务状态
    echo -ne "  服务状态: "
    if service_is_active; then
        echo -e "${GREEN}运行中${PLAIN}"
    else
        echo -e "${RED}未运行${PLAIN}"
        read -r -p "按回车继续..." _tmp; return
    fi

    # 端口监听检测
    echo -ne "  端口监听 (TCP ${LISTEN_PORT}): "
    if command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -q ":${LISTEN_PORT} " \
            && echo -e "${GREEN}正常${PLAIN}" || echo -e "${RED}未检测到${PLAIN}"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep -q ":${LISTEN_PORT} " \
            && echo -e "${GREEN}正常${PLAIN}" || echo -e "${RED}未检测到${PLAIN}"
    else
        echo -e "${YELLOW}无法检测（ss/netstat 未安装）${PLAIN}"
    fi

    echo -ne "  端口监听 (UDP ${LISTEN_PORT}): "
    if command -v ss >/dev/null 2>&1; then
        ss -ulnp 2>/dev/null | grep -q ":${LISTEN_PORT} " \
            && echo -e "${GREEN}正常${PLAIN}" || echo -e "${RED}未检测到${PLAIN}"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ulnp 2>/dev/null | grep -q ":${LISTEN_PORT} " \
            && echo -e "${GREEN}正常${PLAIN}" || echo -e "${RED}未检测到${PLAIN}"
    else
        echo -e "${YELLOW}无法检测${PLAIN}"
    fi

    # 本机回环测试
    echo -ne "  本机回环连通 (TCP 127.0.0.1:${LISTEN_PORT}): "
    if command -v nc >/dev/null 2>&1; then
        nc -z -w3 127.0.0.1 "$LISTEN_PORT" 2>/dev/null \
            && echo -e "${GREEN}通${PLAIN}" || echo -e "${RED}不通${PLAIN}"
    elif command -v bash >/dev/null 2>&1; then
        (echo >/dev/tcp/127.0.0.1/"$LISTEN_PORT") 2>/dev/null \
            && echo -e "${GREEN}通${PLAIN}" || echo -e "${RED}不通${PLAIN}"
    else
        echo -e "${YELLOW}无法检测${PLAIN}"
    fi

    echo ""
    echo -e "${YELLOW}提示：若本机检测正常但客户端无法连接，请检查云服务商安全组/防火墙是否放行端口 ${LISTEN_PORT}${PLAIN}"
    echo ""
    read -r -p "按回车继续..." _tmp
}

# ============================================================
# 管理子菜单
# ============================================================

manage_ss() {
    while true; do
        clear
        echo -e "\n${SKYBLUE}--- 管理 Shadowsocks ---${PLAIN}"
        echo -e "1. 查看配置 (全客户端兼容)"
        echo -e "2. 重启服务"
        echo -e "3. 停止服务"
        echo -e "4. 启动服务"
        echo -e "5. 查看日志"
        echo -e "6. 修改配置（端口 / 密码 / 加密）"
        echo -e "7. 连接测试"
        echo -e "0. 返回"
        read -r -p "请选择: " opt
        case $opt in
            1) show_config ;;
            2) service_restart && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
            3) service_stop    && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
            4) service_start   && echo -e "${GREEN}服务已启动${PLAIN}" && sleep 1 ;;
            5) service_logs; read -r -p "按回车继续..." _tmp ;;
            6) modify_config ;;
            7) test_connection ;;
            0) return ;;
            *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 卸载
# ============================================================

uninstall_ss() {
    read -r -p "确定卸载? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        service_stop
        service_disable
        rm -f "$SERVICE_FILE" "$OPENRC_SERVICE" "$SS_BIN"
        rm -rf /etc/shadowsocks-rust
        remove_auto_update_quiet
        echo -e "${GREEN}已卸载完成${PLAIN}"
        sleep 1
    fi
}

# ============================================================
# BBR
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
    if [ "$_kmaj" -gt 5 ] || { [ "$_kmaj" -eq 5 ] && [ "$_kmin" -ge 15 ]; }; then
        if modprobe tcp_bbr3 >/dev/null 2>&1 || \
           grep -q "bbr3" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            _cc="bbr3"
        fi
    fi

    echo -e "${YELLOW}将启用 ${_cc} + FQ 队列调度...${PLAIN}"
    modprobe tcp_bbr 2>/dev/null || true

    local _sysctl_conf="/etc/sysctl.d/99-ss-bbr.conf"
    cat > "$_sysctl_conf" <<EOF
# Shadowsocks-Rust 脚本写入 - BBR 优化
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = ${_cc}
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
EOF

    sysctl -p "$_sysctl_conf" >/dev/null 2>&1

    local _result
    _result=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [ "$_result" = "$_cc" ]; then
        echo -e "${GREEN}✓ BBR (${_cc}) 已成功启用${PLAIN}"
        echo -e "${GREEN}✓ 队列调度: $(sysctl -n net.core.default_qdisc 2>/dev/null)${PLAIN}"
        echo -e "${GREEN}✓ 配置已写入 ${_sysctl_conf}，重启后生效${PLAIN}"
    else
        echo -e "${YELLOW}⚠ 回落至 bbr...${PLAIN}"
        sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1
        _result=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
        if [ "$_result" = "bbr" ]; then
            echo -e "${GREEN}✓ BBR 已启用${PLAIN}"
        else
            echo -e "${RED}✗ BBR 启用失败，请手动检查内核模块${PLAIN}"
        fi
    fi
    sleep 3
}

check_bbr_status() {
    local _cc _qdisc
    _cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    _qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)

    echo -e "  拥塞控制算法: ${YELLOW}${_cc:-未知}${PLAIN}"
    echo -e "  队列调度算法: ${YELLOW}${_qdisc:-未知}${PLAIN}"

    if echo "${_cc:-}" | grep -qi "bbr"; then
        echo -e "  BBR 状态: ${GREEN}已启用${PLAIN}"
    else
        echo -e "  BBR 状态: ${RED}未启用${PLAIN}"
    fi

    local _avail
    _avail=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)
    echo -e "  可用算法: ${SKYBLUE}${_avail}${PLAIN}"
}

# ============================================================
# 自动更新
# ============================================================

install_auto_update() {
    echo -e "\n${SKYBLUE}--- 配置自动更新 ---${PLAIN}"

    if [ ! -f "$SS_BIN" ]; then
        echo -e "${RED}未安装 Shadowsocks-Rust，请先安装${PLAIN}"
        sleep 2; return
    fi

    cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'
#!/bin/bash
# Shadowsocks-Rust 自动更新脚本（由 ss.sh 生成）
SS_BIN="/usr/local/bin/ssserver"
LOG="/var/log/ss-autoupdate.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

get_latest() {
    curl -Ls --max-time 15 \
        "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1
}

get_current() {
    local _raw
    _raw=$("$SS_BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$_raw" ] && echo "v${_raw}" || echo ""
}

detect_arch() {
    case $(uname -m) in
        x86_64)        echo "x86_64-unknown-linux-musl"  ;;
        aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
        armv7l|armv7)  echo "armv7-unknown-linux-musl" ;;
        s390x)         echo "s390x-unknown-linux-musl" ;;
        loongarch64)   echo "loongarch64-unknown-linux-musl" ;;
        *) echo "" ;;
    esac
}

restart_service() {
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart shadowsocks-server
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service shadowsocks-server restart 2>/dev/null
    fi
}

main() {
    local _latest _current _arch _url
    local _tmp_a _tmp_dir _candidate _backup _was_active=0
    _latest=$(get_latest)
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

    _url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${_latest}/shadowsocks-${_latest}.${_arch}.tar.xz"
    _tmp_a=$(mktemp /tmp/ss-rust-XXXXXX.tar.xz 2>/dev/null)
    _tmp_dir=$(mktemp -d /tmp/ss-rust-XXXXXX 2>/dev/null)
    if [ -n "$_tmp_a" ] && [ -n "$_tmp_dir" ] && \
       wget -q --timeout=60 -O "$_tmp_a" "$_url" 2>/dev/null && \
       tar -xf "$_tmp_a" -C "$_tmp_dir" ssserver 2>/dev/null; then
        _candidate="$_tmp_dir/ssserver"
        chmod +x "$_candidate"
        if ! "$_candidate" --version >/dev/null 2>&1; then
            rm -f "$_tmp_a"; rm -rf "$_tmp_dir"
            echo "[$TIMESTAMP] 下载文件校验失败，当前版本保持不变" >> "$LOG"
            return
        fi

        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet shadowsocks-server; then
            _was_active=1
        elif command -v rc-service >/dev/null 2>&1 && rc-service shadowsocks-server status 2>/dev/null | grep -q started; then
            _was_active=1
        fi

        _backup="${SS_BIN}.autoupdate.bak"
        cp "$SS_BIN" "$_backup" 2>/dev/null || {
            rm -f "$_tmp_a"; rm -rf "$_tmp_dir"
            echo "[$TIMESTAMP] 备份当前版本失败，取消更新" >> "$LOG"
            return
        }
        mv -f "$_candidate" "$SS_BIN"
        rm -f "$_tmp_a"; rm -rf "$_tmp_dir"

        if [ "$_was_active" -eq 1 ]; then
            restart_service
            sleep 2
            if command -v systemctl >/dev/null 2>&1; then
                systemctl is-active --quiet shadowsocks-server || {
                    mv -f "$_backup" "$SS_BIN"
                    restart_service
                    echo "[$TIMESTAMP] 新版本启动失败，已回滚至 $_current" >> "$LOG"
                    return
                }
            elif command -v rc-service >/dev/null 2>&1; then
                rc-service shadowsocks-server status 2>/dev/null | grep -q started || {
                    mv -f "$_backup" "$SS_BIN"
                    restart_service
                    echo "[$TIMESTAMP] 新版本启动失败，已回滚至 $_current" >> "$LOG"
                    return
                }
            fi
        fi
        rm -f "$_backup"
        echo "[$TIMESTAMP] 更新成功，当前版本: $(get_current)" >> "$LOG"
    else
        rm -f "$_tmp_a"; rm -rf "$_tmp_dir"
        echo "[$TIMESTAMP] 更新下载失败，当前版本保持不变" >> "$LOG"
    fi

    # 保留最近 500 行日志
    tail -n 500 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
}

main
AUTOUPDATE_EOF

    chmod +x "$AUTO_UPDATE_SCRIPT"

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

    local _cron_entry="0 3 * * * /bin/bash ${AUTO_UPDATE_SCRIPT} >> ${AUTO_UPDATE_LOG} 2>&1"
    ( crontab -l 2>/dev/null | grep -v "ss-autoupdate"; echo "$_cron_entry" ) | crontab -

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
    ( crontab -l 2>/dev/null | grep -v "ss-autoupdate" ) | crontab - 2>/dev/null
    rm -f "$AUTO_UPDATE_SCRIPT"
}

check_auto_update_status() {
    if crontab -l 2>/dev/null | grep -q "ss-autoupdate"; then
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
    if [ -f "$AUTO_UPDATE_LOG" ]; then
        echo -e "\n${SKYBLUE}--- 自动更新日志（最近 30 条）---${PLAIN}"
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
    echo -e "  系统: ${YELLOW}$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)${PLAIN}"
    echo -e "  内核: ${YELLOW}$(uname -r)${PLAIN}"
    echo -e "  架构: ${YELLOW}$(uname -m)${PLAIN}"

    local _cpu_model _cpu_cores
    _cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)
    _cpu_cores=$(nproc 2>/dev/null || grep -c "processor" /proc/cpuinfo 2>/dev/null)
    echo -e "  CPU: ${YELLOW}${_cpu_model:-未知} × ${_cpu_cores:-?}${PLAIN}"

    local _mem_total _mem_free _mem_used
    _mem_total=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    _mem_free=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
    _mem_used=$(( ${_mem_total:-0} - ${_mem_free:-0} ))
    echo -e "  内存: ${YELLOW}${_mem_used}MB / ${_mem_total}MB${PLAIN}"

    local _disk
    _disk=$(df -h / 2>/dev/null | awk 'NR==2 {print $3" / "$2" ("$5" used)"}')
    echo -e "  磁盘: ${YELLOW}${_disk:-未知}${PLAIN}"

    local _load
    _load=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | xargs)
    echo -e "  负载: ${YELLOW}${_load:-未知}${PLAIN}"

    local _uptime
    _uptime=$(uptime -p 2>/dev/null || uptime 2>/dev/null | awk -F'up ' '{print $2}' | cut -d, -f1-2)
    echo -e "  运行时间: ${YELLOW}${_uptime:-未知}${PLAIN}"

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
        clear
        echo -e "\n${SKYBLUE}--- 服务器工具 ---${PLAIN}"
        echo -e "1. 一键开启 BBR"
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
        clear

        local STATUS
        if [ -f "$SS_BIN" ]; then
            service_is_active && STATUS="${GREEN}运行中${PLAIN}" || STATUS="${RED}已停止${PLAIN}"
        else
            STATUS="${RED}未安装${PLAIN}"
        fi

        local _ver_line=""
        if [ -f "$SS_BIN" ]; then
            local _ver
            _ver=$("$SS_BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            [ -n "$_ver" ] && _ver_line=" (v${_ver})"
        fi

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN}  Shadowsocks-Rust Management Script v2.0.1${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/everett7623/hy2${PLAIN}"
        echo -e " 作者    : ${YELLOW}Jensfrank${PLAIN}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " Seedloc博客 : https://seedloc.com"
        echo -e " VPSknow网站 : https://vpsknow.com"
        echo -e " Nodeloc论坛 : https://nodeloc.com"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 当前状态: $STATUS${_ver_line}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 安装 Shadowsocks"
        echo -e " 2. 管理 Shadowsocks"
        echo -e " 3. 升级 Shadowsocks"
        echo -e " 4. 卸载 Shadowsocks"
        echo -e " 5. 服务器工具 (BBR / 自动更新 / 系统信息)"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}===============================================${PLAIN}"

        read -r -p "请输入选项 [0-5]: " choice
        case $choice in
            1) install_ss ;;
            2) manage_ss ;;
            3) upgrade_ss ;;
            4) uninstall_ss ;;
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
    main_menu
fi
