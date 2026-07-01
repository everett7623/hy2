#!/bin/bash
#====================================================================================
# 项目：VPS 代理工具集 — 一键管理入口
# 脚本：Hysteria2 · Shadowsocks · AnyTLS · EUserv IPv6 HY2
# 作者：Jensfrank
# 版本：v1.0.2
# GitHub  : https://github.com/everett7623/hy2
# 博客    : https://seedloc.com
# 测评    : https://vpsknow.com
# 论坛    : https://nodeloc.com
# 更新日期: 2026-06-30
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
[ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty

if [ -f "$0" ] && grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0"
    exec bash "$0" "$@"
fi

# ---- 颜色 ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
CYAN='\033[1;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
PLAIN='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# ---- 脚本地址 ----
BASE_URL="https://raw.githubusercontent.com/everett7623/hy2/main"
HY2_URL="${BASE_URL}/hy2.sh"
SS_URL="${BASE_URL}/ss.sh"
EUSERV_URL="${BASE_URL}/euservhy2.sh"
ANYTLS_URL="${BASE_URL}/anytls.sh"

# ============================================================
# Root 检测
# ============================================================
check_root() {
    [ "$EUID" -ne 0 ] && \
        echo -e "${RED}错误: 请以 root 权限运行${PLAIN}" && exit 1
}

service_active() {
    local _service="$1" _pidfile="$2"
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$_service" 2>/dev/null
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$_service" status 2>/dev/null | grep -q "started"
    else
        [ -f "$_pidfile" ] && kill -0 "$(cat "$_pidfile" 2>/dev/null)" 2>/dev/null
    fi
}

# ============================================================
# 实时状态检测
# ============================================================
get_status() {
    # ---- Hysteria2 ----
    if [ -f "/usr/local/bin/hysteria" ]; then
        local _ver
        _ver=$(/usr/local/bin/hysteria version 2>/dev/null \
            | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if service_active hysteria-server /var/run/hysteria.pid; then
            HY2_STATUS="${GREEN}● 运行中${PLAIN}${DIM} ${_ver}${PLAIN}"
        else
            HY2_STATUS="${YELLOW}● 已停止${PLAIN}${DIM} ${_ver}${PLAIN}"
        fi
    else
        HY2_STATUS="${RED}● 未安装${PLAIN}"
    fi

    # ---- Shadowsocks ----
    if [ -f "/usr/local/bin/ssserver" ]; then
        local _ver
        _ver=$(/usr/local/bin/ssserver --version 2>/dev/null \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if service_active shadowsocks-server /var/run/ssserver.pid; then
            SS_STATUS="${GREEN}● 运行中${PLAIN}${DIM} v${_ver}${PLAIN}"
        else
            SS_STATUS="${YELLOW}● 已停止${PLAIN}${DIM} v${_ver}${PLAIN}"
        fi
    else
        SS_STATUS="${RED}● 未安装${PLAIN}"
    fi

    # ---- EUserv HY2：检测 HY2 运行状态 + IPv6 环境 ----
    local _ipv6 _ipv4
    if command -v ip >/dev/null 2>&1; then
        _ipv6=$(ip -6 addr show scope global 2>/dev/null | awk '
        /^[0-9]+:/ { iface=$2; sub(/:.*/,"",iface) }
        /inet6/ && iface !~ /wgcf|warp|^tun|^wg|tailscale|zt/ {
            addr=$2; sub(/\/.*/,"",addr)
            if (addr !~ /^fe80/ && addr !~ /^2606:4700:/) { print addr; exit }
        }
        ')
    fi
    _ipv4=$(curl -4 -s --max-time 3 ip.sb 2>/dev/null || true)

    if [ -n "$_ipv6" ]; then
        # 有 IPv6：进一步检测 HY2 服务状态
        if [ -f "/usr/local/bin/hysteria" ] && \
           service_active hysteria-server /var/run/hysteria.pid; then
            local _ver
            _ver=$(/usr/local/bin/hysteria version 2>/dev/null \
                | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            EUSERV_STATUS="${GREEN}● HY2 运行中${PLAIN}${DIM} ${_ver}${PLAIN}"
        elif [ -z "$_ipv4" ]; then
            EUSERV_STATUS="${CYAN}● 纯 IPv6 环境${PLAIN}${DIM} 可安装${PLAIN}"
        else
            EUSERV_STATUS="${SKYBLUE}● IPv6 双栈${PLAIN}${DIM} 可安装${PLAIN}"
        fi
    else
        EUSERV_STATUS="${RED}● 无公网 IPv6${PLAIN}${DIM} 不适用${PLAIN}"
    fi

    # ---- AnyTLS ----
    if [ -f "/usr/local/bin/anytls-server" ]; then
        local _ver
        _ver=$(cat /etc/anytls/meta/version 2>/dev/null || true)
        if service_active anytls-server /run/anytls-server.pid; then
            ANYTLS_STATUS="${GREEN}● 运行中${PLAIN}${DIM} ${_ver}${PLAIN}"
        else
            ANYTLS_STATUS="${YELLOW}● 已停止${PLAIN}${DIM} ${_ver}${PLAIN}"
        fi
    else
        ANYTLS_STATUS="${RED}● 未安装${PLAIN}"
    fi

    # ---- 网络信息 ----
    NET_IPV4="${_ipv4:-无}"
    NET_IPV6="${_ipv6:-无}"
}

# ============================================================
# 拉取并执行子脚本
# ============================================================
run_script() {
    local _name="$1" _url="$2"
    echo ""
    echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"
    echo -e "  正在加载 ${BOLD}${_name}${PLAIN} ..."
    echo -e "${SKYBLUE}───────────────────────────────────────────────${PLAIN}"

    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${YELLOW}curl 未安装，正在尝试安装...${PLAIN}"
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache curl ca-certificates >/dev/null 2>&1
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y curl ca-certificates >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y curl ca-certificates >/dev/null 2>&1
        fi
        command -v curl >/dev/null 2>&1 || {
            echo -e "${RED}错误: curl 安装失败，无法下载脚本${PLAIN}"
            sleep 2
            return
        }
    fi

    local _tmp
    _tmp=$(mktemp /tmp/hy2_sub_XXXXXX.sh 2>/dev/null) || {
        echo -e "${RED}错误: 无法创建临时文件${PLAIN}"
        sleep 2
        return
    }
    if curl -fsSL --connect-timeout 15 --max-time 60 "$_url" -o "$_tmp" 2>/dev/null; then
        if ! [ -s "$_tmp" ] || ! bash -n "$_tmp" 2>/dev/null; then
            echo -e "${RED}  ✗ 下载内容无效或脚本语法检查失败${PLAIN}"
            rm -f "$_tmp"
            sleep 3
            return
        fi
        chmod +x "$_tmp"
        bash "$_tmp"
        rm -f "$_tmp"
    else
        rm -f "$_tmp"
        echo -e "${RED}  ✗ 下载失败，请检查网络${PLAIN}"
        echo -e "${YELLOW}  也可直接运行: bash <(curl -fsSL ${_url})${PLAIN}"
        sleep 3
    fi
}

# ============================================================
# 主菜单 Banner
# ============================================================
show_banner() {
    echo -e "${CYAN}"
    echo "  ██╗  ██╗██╗   ██╗██████╗     ████████╗ ██████╗  ██████╗ ██╗     ███████╗"
    echo "  ██║  ██║╚██╗ ██╔╝╚════██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝"
    echo "  ███████║ ╚████╔╝  █████╔╝       ██║   ██║   ██║██║   ██║██║     ███████╗"
    echo "  ██╔══██║  ╚██╔╝  ██╔═══╝        ██║   ██║   ██║██║   ██║██║     ╚════██║"
    echo "  ██║  ██║   ██║   ███████╗        ██║   ╚██████╔╝╚██████╔╝███████╗███████║"
    echo "  ╚═╝  ╚═╝   ╚═╝   ╚══════╝        ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝"
    echo -e "${PLAIN}"
}

# ============================================================
# 主菜单
# ============================================================
main_menu() {
    while true; do
        clear
        show_banner

        get_status

        # ---- 顶部信息栏 ----
        echo -e "${SKYBLUE}${BOLD}  ═══════════════════════════════════════════════════════════════════${PLAIN}"
        echo -e "  ${WHITE}${BOLD}  VPS 代理工具集 · 一键管理入口${PLAIN}  ${DIM}v1.0.2${PLAIN}"
        echo -e "${SKYBLUE}${BOLD}  ═══════════════════════════════════════════════════════════════════${PLAIN}"
        echo -e "  ${DIM}作者${PLAIN}   ${WHITE}Jensfrank${PLAIN}  ${DIM}│${PLAIN}  ${DIM}项目${PLAIN}  ${YELLOW}github.com/everett7623/hy2${PLAIN}"
        echo -e "  ${DIM}博客${PLAIN}   ${SKYBLUE}seedloc.com${PLAIN}     ${DIM}│${PLAIN}  ${DIM}测评${PLAIN}  ${SKYBLUE}vpsknow.com${PLAIN}"
        echo -e "  ${DIM}论坛${PLAIN}   ${SKYBLUE}nodeloc.com${PLAIN}"
        echo -e "${SKYBLUE}  ───────────────────────────────────────────────────────────────────${PLAIN}"

        # ---- 网络信息 ----
        echo -e "  ${DIM}IPv4${PLAIN}   ${WHITE}${NET_IPV4}${PLAIN}"
        echo -e "  ${DIM}IPv6${PLAIN}   ${WHITE}${NET_IPV6}${PLAIN}"
        echo -e "${SKYBLUE}  ───────────────────────────────────────────────────────────────────${PLAIN}"

        # ---- 菜单选项 ----
        echo ""
        echo -e "  ${WHITE}${BOLD}━━━  主要代理协议  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${PLAIN}"
        echo ""
        echo -e "  ${GREEN}${BOLD}1.${PLAIN}  ${BOLD}Hysteria2${PLAIN}                 ${DIM}UDP 超速 · 抗封锁 · 主力节点${PLAIN}"
        echo -e "     ${DIM}状态:${PLAIN} $(echo -e "$HY2_STATUS")"
        echo ""
        echo -e "  ${GREEN}${BOLD}2.${PLAIN}  ${BOLD}Shadowsocks${PLAIN}               ${DIM}SS-2022 · 全平台兼容 · 保底节点${PLAIN}"
        echo -e "     ${DIM}状态:${PLAIN} $(echo -e "$SS_STATUS")"
        echo ""
        echo -e "  ${WHITE}${BOLD}━━━  专用脚本  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${PLAIN}"
        echo ""
        echo -e "  ${MAGENTA}${BOLD}3.${PLAIN}  ${BOLD}EUserv IPv6 专用 HY2${PLAIN}     ${DIM}纯 IPv6 适配 · NAT64 兜底 · WARP 集成${PLAIN}"
        echo -e "     ${DIM}状态:${PLAIN} $(echo -e "$EUSERV_STATUS")"
        echo ""
        echo -e "  ${GREEN}${BOLD}4.${PLAIN}  ${BOLD}AnyTLS${PLAIN}                    ${DIM}TCP 传输 · TLS 指纹规避 · UDP 受限网络${PLAIN}"
        echo -e "     ${DIM}状态:${PLAIN} $(echo -e "$ANYTLS_STATUS")"
        echo ""
        echo -e "${SKYBLUE}  ───────────────────────────────────────────────────────────────────${PLAIN}"
        echo -e "  ${YELLOW}${BOLD}0.${PLAIN}  退出"
        echo ""
        echo -e "${SKYBLUE}  ═══════════════════════════════════════════════════════════════════${PLAIN}"
        echo ""
        echo -ne "  ${WHITE}${BOLD}请输入选项 [0-4]:${PLAIN} "
        read -r choice

        case "$choice" in
            1) run_script "Hysteria2" "$HY2_URL" ;;
            2) run_script "Shadowsocks" "$SS_URL" ;;
            3) run_script "EUserv IPv6 HY2" "$EUSERV_URL" ;;
            4) run_script "AnyTLS" "$ANYTLS_URL" ;;
            0|q|quit|exit)
                echo ""
                echo -e "  ${DIM}感谢使用 HY2 Tools，再见！${PLAIN}"
                echo ""
                exit 0
                ;;
            *)
                echo -e "  ${RED}无效选项，请输入 0-4${PLAIN}"
                sleep 1
                ;;
        esac
    done
}

# ============================================================
# 入口
# ============================================================
check_root
main_menu
