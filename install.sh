#!/bin/bash
#====================================================================================
# 项目：VPS 工具集合入口菜单
# 作者：Jensfrank
# 版本：v1.0.0
# GitHub: https://github.com/everett7623/hy2
# Seedloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2026-05-21
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

# --- 颜色 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'

# --- 脚本地址 ---
BASE_URL="https://raw.githubusercontent.com/everett7623/hy2/main"
HY2_URL="${BASE_URL}/hy2dev.sh"
SS_URL="${BASE_URL}/ssdev.sh"
EUSERV_URL="${BASE_URL}/euservhy2.sh"

# ============================================================
# Root 检测
# ============================================================
check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}错误: 请以 root 权限运行${PLAIN}" && exit 1
}

# ============================================================
# 检测各工具安装状态
# ============================================================
get_status() {
    # Hysteria2
    if [ -f "/usr/local/bin/hysteria" ]; then
        local _ver
        _ver=$(/usr/local/bin/hysteria version 2>/dev/null | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        HY2_STATUS="${GREEN}已安装${PLAIN} ${_ver}"
        if systemctl is-active --quiet hysteria-server 2>/dev/null; then
            HY2_STATUS="${GREEN}运行中${PLAIN} ${_ver}"
        fi
    else
        HY2_STATUS="${RED}未安装${PLAIN}"
    fi

    # Shadowsocks
    if [ -f "/usr/local/bin/ssserver" ]; then
        local _ver
        _ver=$(/usr/local/bin/ssserver --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        SS_STATUS="${GREEN}已安装${PLAIN} v${_ver}"
        if systemctl is-active --quiet shadowsocks-server 2>/dev/null || \
           { [ -f /var/run/ssserver.pid ] && kill -0 "$(cat /var/run/ssserver.pid)" 2>/dev/null; }; then
            SS_STATUS="${GREEN}运行中${PLAIN} v${_ver}"
        fi
    else
        SS_STATUS="${RED}未安装${PLAIN}"
    fi

    # EUserv Hysteria2（用IPv6地址有无判断）
    local _ipv6
    _ipv6=$(ip -6 addr show scope global 2>/dev/null \
        | grep -oP '(?<=inet6 )[\da-f:]+(?=/)' | grep -v '^fe80' | head -1)
    if [ -n "$_ipv6" ]; then
        local _ipv4
        _ipv4=$(curl -4 -s --max-time 3 ip.sb 2>/dev/null)
        if [ -z "$_ipv4" ]; then
            EUSERV_STATUS="${YELLOW}纯 IPv6 环境${PLAIN} ${_ipv6}"
        else
            EUSERV_STATUS="${GREEN}双栈环境${PLAIN}"
        fi
    else
        EUSERV_STATUS="${RED}无公网 IPv6${PLAIN}"
    fi
}

# ============================================================
# 拉取并执行子脚本
# ============================================================
run_script() {
    local _name="$1" _url="$2"
    echo -e "\n${YELLOW}正在加载 ${_name}...${PLAIN}"

    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}错误: curl 未安装，请先安装 curl${PLAIN}"
        sleep 2; return
    fi

    local _tmp
    _tmp=$(mktemp /tmp/hy2_menu_XXXXXX.sh)

    if curl -fsSL --connect-timeout 10 --max-time 30 "$_url" -o "$_tmp" 2>/dev/null; then
        chmod +x "$_tmp"
        bash "$_tmp"
        rm -f "$_tmp"
    else
        rm -f "$_tmp"
        echo -e "${RED}下载失败，请检查网络连接或访问 GitHub 是否正常${PLAIN}"
        echo -e "${YELLOW}也可直接运行：bash <(curl -fsSL ${_url})${PLAIN}"
        sleep 3
    fi
}

# ============================================================
# 主菜单
# ============================================================
main_menu() {
    while true; do
        clear
        get_status

        echo -e "${SKYBLUE}╔═══════════════════════════════════════════════╗${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}     ${BOLD}VPS 代理工具集 — Jensfrank${PLAIN}               ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}╠═══════════════════════════════════════════════╣${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}  项目: github.com/everett7623/hy2              ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}  博客: seedloc.com  |  测评: vpsknow.com       ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}╠═══════════════════════════════════════════════╣${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}                                               ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}  ${GREEN}1.${PLAIN} Hysteria2                               ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}     状态: $(printf '%-36s' "$(echo -e "$HY2_STATUS")")${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}                                               ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}  ${GREEN}2.${PLAIN} Shadowsocks                             ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}     状态: $(printf '%-36s' "$(echo -e "$SS_STATUS")")${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}                                               ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}  ${GREEN}3.${PLAIN} EUserv IPv6 专用 Hysteria2              ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}     状态: $(printf '%-36s' "$(echo -e "$EUSERV_STATUS")")${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}                                               ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}  ${YELLOW}0.${PLAIN} 退出                                   ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}║${PLAIN}                                               ${SKYBLUE}║${PLAIN}"
        echo -e "${SKYBLUE}╚═══════════════════════════════════════════════╝${PLAIN}"
        echo ""
        echo -ne "  ${BOLD}请输入选项 [0-3]:${PLAIN} "
        read -r choice

        case "$choice" in
            1) run_script "Hysteria2" "$HY2_URL" ;;
            2) run_script "Shadowsocks" "$SS_URL" ;;
            3) run_script "EUserv IPv6 Hysteria2" "$EUSERV_URL" ;;
            0|q|quit|exit)
                echo ""
                echo -e "  ${SKYBLUE}感谢使用，再见！${PLAIN}"
                echo ""
                exit 0
                ;;
            *) echo -e "  ${RED}无效选项，请输入 0-3${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 入口
# ============================================================
check_root
main_menu
