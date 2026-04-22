#!/bin/bash
#====================================================================================
# 项目：Shadowsocks-Rust Management Script
# 作者：Jensfrank
# 版本：v3.0.0 (Cipher Selection & Standard Format)
# GitHub: https://github.com/shadowsocks/shadowsocks-rust
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-04-22
#
# 支持系统: 完美兼容 Debian, Ubuntu, CentOS, Rocky, Alma, Alpine, Arch 等
# 支持环境: 标准 VPS / NAT 机器 / 极简系统环境 / GLIBC 免疫
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
            apt-get install -y -qq bash >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash >/dev/null 2>&1
        fi
        exec bash "$0" "$@"
    fi
fi

if [ ! -t 0 ]; then
    [ -c /dev/tty ] && exec < /dev/tty
fi

if [ -f "$0" ] && grep -q $'\r' "$0" 2>/dev/null; then
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

# --- 路径 ---
SS_BIN="/usr/local/bin/ssserver"
SS_CONFIG="/etc/shadowsocks-rust/config.json"
SS_META="/etc/shadowsocks-rust/meta"
SERVICE_FILE="/etc/systemd/system/shadowsocks-server.service"
OPENRC_SERVICE="/etc/init.d/shadowsocks-server"

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

detect_init() {
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
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
    for _url in "https://api.ipify.org" "https://ip.gs" "https://ipv4.icanhazip.com"; do
        _ip=$(curl -s4 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            PUBLIC_IP="$_ip"; HAS_IPV4=1; break
        fi
    done

    for _url in "https://api6.ipify.org" "https://ipv6.icanhazip.com"; do
        _ip=$(curl -s6 --max-time 6 "$_url" 2>/dev/null | tr -d '[:space:]')
        if echo "$_ip" | grep -q ':'; then
            PUBLIC_IPV6="$_ip"; HAS_IPV6=1; break
        fi
    done

    if [ "$HAS_IPV4" = "1" ]; then
        local _local_ips
        _local_ips=$(ip addr show 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '^127\.' | grep -v '^169\.254\.')
        echo "$_local_ips" | grep -q "^${PUBLIC_IP}$" || NAT_MODE=1
    fi

    [ "$HAS_IPV4" = "0" ] && [ "$HAS_IPV6" = "1" ] && IPV6_ONLY=1

    if   [ "$NAT_MODE"  = "1" ]; then echo -e "  机器类型: ${YELLOW}NAT 机器${PLAIN}（公网 IPv4: ${PUBLIC_IP}）"
    elif [ "$IPV6_ONLY" = "1" ]; then echo -e "  机器类型: ${YELLOW}纯 IPv6${PLAIN}（IPv6: ${PUBLIC_IPV6}）"
    elif [ "$HAS_IPV6"  = "1" ]; then echo -e "  机器类型: ${GREEN}双栈${PLAIN}（IPv4: ${PUBLIC_IP} | IPv6: ${PUBLIC_IPV6}）"
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
# 防火墙端口放行 (解决连接超时)
# ============================================================
open_ports() {
    local _port=$1
    echo -e "${YELLOW}正在自动放行 Linux 系统防火墙端口 ${_port}...${PLAIN}"
    
    if systemctl is-active --quiet firewalld 2>/dev/null || command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${_port}/tcp" >/dev/null 2>&1
        firewall-cmd --permanent --add-port="${_port}/udp" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    
    if systemctl is-active --quiet ufw 2>/dev/null || command -v ufw >/dev/null 2>&1; then
        ufw allow "${_port}/tcp" >/dev/null 2>&1
        ufw allow "${_port}/udp" >/dev/null 2>&1
        ufw reload >/dev/null 2>&1
    fi
    
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport "${_port}" -j ACCEPT >/dev/null 2>&1
        iptables -I INPUT -p udp --dport "${_port}" -j ACCEPT >/dev/null 2>&1
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1
        elif command -v service >/dev/null 2>&1 && [ -f /etc/sysconfig/iptables ]; then
            service iptables save >/dev/null 2>&1
        fi
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
    service_stop
    sleep 1
    service_start
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
        journalctl -u shadowsocks-server -n 20 --no-pager
    else
        tail -n 20 /var/log/ssserver.log 2>/dev/null || echo -e "${YELLOW}暂无日志${PLAIN}"
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
# 依赖安装 & 强力防坑机制
# ============================================================

install_dependencies() {
    echo -e "${YELLOW}正在安装必要依赖...${PLAIN}"
    
    if command -v setenforce >/dev/null 2>&1; then
        setenforce 0 2>/dev/null
    fi

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq curl wget openssl tar xz-utils >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl wget openssl tar xz >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget openssl tar xz >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm curl wget openssl tar xz >/dev/null 2>&1
    elif command -v apk >/dev/null 2>&1; then
        apk update -q >/dev/null 2>&1
        apk add --no-cache bash curl wget openssl tar xz >/dev/null 2>&1
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

install_ss() {
    detect_network
    install_dependencies
    
    echo -e "${YELLOW}正在获取 Shadowsocks-Rust 最新版本...${PLAIN}"
    LAST_VERSION=$(curl -Ls --max-time 10 "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1)
    
    if [ -z "$LAST_VERSION" ]; then
        LAST_VERSION=$(curl -Ls -o /dev/null -w "%{url_effective}" "https://github.com/shadowsocks/shadowsocks-rust/releases/latest" | sed 's|.*/tag/||')
    fi
    
    if [ -z "$LAST_VERSION" ]; then
        echo -e "${RED}获取版本失败，请检查网络${PLAIN}"
        exit 1
    fi
    
    echo -e "${GREEN}检测到最新版本: ${LAST_VERSION}${PLAIN}"

    # 强制全部使用 MUSL 版本，不再区分系统，彻底干掉 GLIBC 报错！
    local _arch
    case $(uname -m) in
        x86_64)        _arch="x86_64-unknown-linux-musl" ;;
        aarch64|arm64) _arch="aarch64-unknown-linux-musl" ;;
        *) echo -e "${RED}不支持的架构: $(uname -m)${PLAIN}" && exit 1 ;;
    esac
    
    echo -e "${SKYBLUE}>>> 已强制使用 musl 静态编译库，彻底免疫一切 GLIBC 报错！ <<<${PLAIN}"
    
    local _url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${LAST_VERSION}/shadowsocks-${LAST_VERSION}.${_arch}.tar.xz"
    
    service_stop
    rm -f "$SS_BIN"
    
    echo -e "${YELLOW}正在下载核心文件...${PLAIN}"
    wget -q --show-progress -O /tmp/ss-rust.tar.xz "$_url" || { echo -e "${RED}下载失败${PLAIN}"; exit 1; }
    tar -xf /tmp/ss-rust.tar.xz -C /tmp/ ssserver || { echo -e "${RED}解压失败${PLAIN}"; exit 1; }
    mv /tmp/ssserver "$SS_BIN"
    chmod +x "$SS_BIN"
    rm -f /tmp/ss-rust.tar.xz
    
    mkdir -p /etc/shadowsocks-rust "$SS_META"

    echo -e "\n${SKYBLUE}--- 配置 Shadowsocks 协议 ---${PLAIN}"
    if [ "$NAT_MODE" = "1" ]; then
        read -r -p "请输入本机监听端口 [默认 28888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="28888"
        read -r -p "请输入对外转发端口 [留空=与监听端口相同]: " EXT_PORT
        [[ -z "$EXT_PORT" ]] && EXT_PORT="$LISTEN_PORT"
    else
        read -r -p "请输入端口 [默认 28888]: " LISTEN_PORT
        [[ -z "$LISTEN_PORT" ]] && LISTEN_PORT="28888"
        EXT_PORT="$LISTEN_PORT"
    fi

    echo -e "\n${YELLOW}请选择要使用的加密协议：${PLAIN}"
    echo -e " 1. ${GREEN}aes-256-gcm${PLAIN} (经典原版协议，100% 兼容全平台，保证能通，【默认推荐】)"
    echo -e " 2. ${RED}2022-blake3-aes-256-gcm${PLAIN} (SS-2022 协议，强抗封锁，但要求手机系统时间极其准确)"
    read -r -p "请输入选项 [1 或 2，默认 1]: " _cipher_opt

    if [ "$_cipher_opt" = "2" ]; then
        METHOD="2022-blake3-aes-256-gcm"
        PASSWORD=$(openssl rand -base64 32 | tr -d ' \n\r')
        echo -e "${YELLOW}已启用 SS-2022，系统已自动生成 32 字节规范密钥 -> ${PASSWORD}${PLAIN}"
        
        # 尽力尝试强制时间同步，挽救 SS-2022 超时问题
        echo -e "${YELLOW}正在尝试同步服务器时间以防连接超时...${PLAIN}"
        command -v timedatectl >/dev/null 2>&1 && timedatectl set-ntp true >/dev/null 2>&1
    else
        METHOD="aes-256-gcm"
        read -r -p "请设置连接密码 [留空自动生成]: " PASSWORD
        if [[ -z "$PASSWORD" ]]; then
            PASSWORD=$(openssl rand -base64 16 | tr -d ' \n\r')
        fi
        echo -e "${GREEN}已启用经典 aes-256-gcm 协议，保证最高连通率！${PLAIN}"
    fi

    local LISTEN_ADDR="0.0.0.0"
    if [ "$HAS_IPV6" = "1" ]; then
        LISTEN_ADDR="::"
    fi
    
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

    echo "$NAT_MODE"    > "$SS_META/nat_mode"
    echo "$EXT_PORT"    > "$SS_META/ext_port"
    echo "$LISTEN_PORT" > "$SS_META/listen_port"
    echo "$PASSWORD"    > "$SS_META/password"
    echo "$METHOD"      > "$SS_META/method"
    
    if [ -n "$PUBLIC_IP" ]; then
        echo "$PUBLIC_IP" > "$SS_META/public_ip"
    fi
    if [ -n "$PUBLIC_IPV6" ]; then
        echo "$PUBLIC_IPV6" > "$SS_META/public_ipv6"
    fi

    # 放行防火墙端口
    open_ports "$LISTEN_PORT"

    if [ "$INIT_SYS" = "systemd" ]; then
        setup_systemd_service
    elif [ "$INIT_SYS" = "openrc" ]; then
        setup_openrc_service
    fi
    
    service_enable
    service_start

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

# ============================================================
# URL 编码与展示
# ============================================================

uri_encode() {
    local _in="$1" _out="" _i=0 _c _hex _byte
    local _len=${#_in}
    while [ $_i -lt $_len ]; do
        _c="${_in:_i:1}"
        case "$_c" in
            [a-zA-Z0-9.~_-]) _out+="$_c" ;;
            *)
                _hex=$(printf '%s' "$_c" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')
                for _byte in $_hex; do _out+="%${_byte}"; done
                ;;
        esac
        _i=$((_i + 1))
    done
    echo "$_out"
}

read_config_vars() {
    if [ ! -f "$SS_CONFIG" ]; then
        return 1
    fi
    
    if [ -d "$SS_META" ]; then
        NAT_MODE=$(cat "$SS_META/nat_mode" 2>/dev/null); NAT_MODE=${NAT_MODE:-0}
        EXT_PORT=$(cat "$SS_META/ext_port" 2>/dev/null)
        LISTEN_PORT=$(cat "$SS_META/listen_port" 2>/dev/null)
        PASSWORD=$(cat "$SS_META/password" 2>/dev/null)
        METHOD=$(cat "$SS_META/method" 2>/dev/null)
        PUBLIC_IP=$(cat "$SS_META/public_ip" 2>/dev/null)
        PUBLIC_IPV6=$(cat "$SS_META/public_ipv6" 2>/dev/null)
    fi
    
    if [[ -z "$EXT_PORT" ]]; then
        EXT_PORT=$(grep '"server_port"' "$SS_CONFIG" | grep -oE '[0-9]+' | head -1)
    fi
    if [[ -z "$PASSWORD" ]]; then
        PASSWORD=$(grep '"password"' "$SS_CONFIG" | awk -F'"' '{print $4}' | head -1)
    fi
    if [[ -z "$METHOD" ]]; then
        METHOD=$(grep '"method"' "$SS_CONFIG" | awk -F'"' '{print $4}' | head -1)
    fi
    
    if [ -z "$PUBLIC_IP" ] && [ -z "$PUBLIC_IPV6" ]; then
        PUBLIC_IP=$(curl -s4 --max-time 6 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
        PUBLIC_IPV6=$(curl -s6 --max-time 6 https://api6.ipify.org 2>/dev/null | tr -d '[:space:]')
    fi
}

show_node() {
    local _ip="$1" _port="$2" _tag="$3"
    local _host="$_ip"
    
    if echo "$_ip" | grep -q ':'; then
        _host="[${_ip}]"
    fi
    
    local _node="SS-${_tag}-$(date +%m%d)"
    if echo "$METHOD" | grep -q "2022"; then
        _node="SS22-${_tag}-$(date +%m%d)"
    fi
    
    local _credentials
    _credentials=$(printf "%s:%s" "$METHOD" "$PASSWORD" | base64 | tr -d ' \n\r')
    local _link="ss://${_credentials}@${_host}:${_port}#${_node}"
    
    local _encoded
    _encoded=$(uri_encode "$_link")
    local _qr="https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${_encoded}"

    echo -e "${GREEN} 分享链接 (SIP002 标准):${PLAIN}\n  ${_link}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} 二维码链接:${PLAIN}\n  ${_qr}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Clash Meta / Stash 配置:${PLAIN}"
    echo -e "  - {name: '${_node}', type: ss, server: '${_ip}', port: ${_port}, cipher: ${METHOD}, password: '${PASSWORD}', udp: true }"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Surge / Surfboard 配置:${PLAIN}"
    echo -e "  ${_node} = ss, ${_ip}, ${_port}, encrypt-method=${METHOD}, password=${PASSWORD}, udp-relay=true"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Loon 配置:${PLAIN}"
    echo -e "  ${_node} = Shadowsocks, ${_ip}, ${_port}, ${METHOD}, \"${PASSWORD}\", udp=true"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Quantumult X 配置:${PLAIN}"
    echo -e "  shadowsocks=${_ip}:${_port}, method=${METHOD}, password=${PASSWORD}, fast-open=false, udp-relay=true, tag=${_node}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    echo -e "${GREEN} Sing-box 配置 (Outbound):${PLAIN}"
    echo -e "  { \"type\": \"shadowsocks\", \"tag\": \"${_node}\", \"server\": \"${_ip}\", \"server_port\": ${_port}, \"method\": \"${METHOD}\", \"password\": \"${PASSWORD}\" }"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
}

show_config() {
    read_config_vars
    if [ -z "$EXT_PORT" ]; then
        echo -e "${RED}未找到有效配置${PLAIN}"
        read -r -p "按回车返回..." _tmp
        return
    fi

    echo -e "\n${GREEN}Shadowsocks 配置详情${PLAIN}"
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"
    if [ -n "$PUBLIC_IP" ]; then
        echo -e "  ${BOLD}IPv4地址${PLAIN}: ${YELLOW}${PUBLIC_IP}${PLAIN}"
    fi
    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "  ${BOLD}IPv6地址${PLAIN}: ${YELLOW}${PUBLIC_IPV6} (推荐)${PLAIN}"
    fi
    
    if [ "$NAT_MODE" = "1" ] && [ "$EXT_PORT" != "$LISTEN_PORT" ]; then
        echo -e "  ${BOLD}监听端口${PLAIN}: ${YELLOW}${LISTEN_PORT}${PLAIN}  ${RED}← 本机监听${PLAIN}"
        echo -e "  ${BOLD}对外端口${PLAIN}: ${YELLOW}${EXT_PORT}${PLAIN}  ${RED}← 客户端连接此端口${PLAIN}"
    else
        echo -e "  ${BOLD}端口Port${PLAIN}: ${YELLOW}${EXT_PORT}${PLAIN}"
    fi
    
    echo -e "  ${BOLD}密码Pass${PLAIN}: ${YELLOW}${PASSWORD}${PLAIN}"
    echo -e "  ${BOLD}加密方式${PLAIN}: ${YELLOW}${METHOD}${PLAIN}"
    
    if [ "$NAT_MODE" = "1" ]; then
        echo -e "  ${BOLD}机器类型${PLAIN}: ${YELLOW}NAT 机器${PLAIN}"
    fi
    
    if echo "$METHOD" | grep -q "2022"; then
        echo -e "\n${RED}⚠️ 注意：您开启了 SS-2022 协议，对时间误差极其敏感！${PLAIN}"
        echo -e "${YELLOW}如果配置全对依然连不上（超时），请务必校准您的手机和电脑时间！${PLAIN}"
    fi
    echo -e "${SKYBLUE}─────────────────────────────────────────────${PLAIN}"

    if [ -n "$PUBLIC_IPV6" ]; then
        echo -e "${YELLOW}▼ IPv6 节点配置 (推荐)${PLAIN}"
        show_node "$PUBLIC_IPV6" "$EXT_PORT" "v6"
    fi

    if [ -n "$PUBLIC_IP" ]; then
        echo -e "${YELLOW}▼ IPv4 节点配置${PLAIN}"
        show_node "$PUBLIC_IP" "$EXT_PORT" "v4"
    fi

    echo ""
    read -r -p "按回车键返回主菜单..." _tmp
}

manage_ss() {
    clear
    echo -e "\n${SKYBLUE}--- 管理 Shadowsocks ---${PLAIN}"
    echo -e "1. 查看配置 (全客户端兼容)"
    echo -e "2. 重启服务"
    echo -e "3. 停止服务"
    echo -e "4. 查看日志"
    echo -e "0. 返回"
    read -r -p "请选择: " opt
    case $opt in
        1) show_config ;;
        2) service_restart && echo -e "${GREEN}服务已重启${PLAIN}" && sleep 1 ;;
        3) service_stop    && echo -e "${YELLOW}服务已停止${PLAIN}" && sleep 1 ;;
        4) service_logs; read -r -p "按回车继续..." _tmp ;;
        0) return ;;
        *) echo -e "${RED}输入错误${PLAIN}"; sleep 1 ;;
    esac
}

uninstall_ss() {
    read -r -p "确定卸载? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        service_stop
        service_disable
        rm -f "$SERVICE_FILE" "$OPENRC_SERVICE" "$SS_BIN"
        rm -rf /etc/shadowsocks-rust
        echo -e "${GREEN}已卸载完成${PLAIN}"
        sleep 1
    fi
}

main_menu() {
    while true; do
        clear
        if [ -f "$SS_BIN" ]; then
            if service_is_active; then
                STATUS="${GREEN}运行中${PLAIN}"
            else
                STATUS="${RED}已停止${PLAIN}"
            fi
        else
            STATUS="${RED}未安装${PLAIN}"
        fi

        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e "${GREEN} Shadowsocks-Rust Management Script v3.0.0${PLAIN}"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        echo -e " 项目地址: ${YELLOW}https://github.com/shadowsocks/shadowsocks-rust${PLAIN}"
        echo -e " 作者    : ${YELLOW}Jensfrank${PLAIN}"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 当前状态: $STATUS"
        echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
        echo -e " 1. 安装 Shadowsocks 服务"
        echo -e " 2. 管理 Shadowsocks 配置 (查看节点)"
        echo -e " 3. 卸载 Shadowsocks 服务"
        echo -e " 0. 退出"
        echo -e "${SKYBLUE}===============================================${PLAIN}"
        
        read -r -p "请输入选项: " choice
        case $choice in
            1) install_ss ;;
            2) manage_ss ;;
            3) uninstall_ss ;;
            0) exit 0 ;;
            *) echo -e "${RED}输入错误...${PLAIN}"; sleep 1 ;;
        esac
    done
}

check_root
detect_init
main_menu
