#!/bin/bash
# ========================================
# Shadowsocks IPv6 专用安装脚本
# 要求：必须有 IPv6 地址
# 说明：纯IPv4环境易被封禁，脚本将退出
# ========================================

set -e

# ========= 颜色定义 =========
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
ORANGE='\033[0;33m'
NC='\033[0m'

# ========= 配置部分 =========
PORT=$(shuf -i 20000-40000 -n 1)
PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)  # 更简洁的密码
METHOD="chacha20-ietf-poly1305"  # 高性能加密
TIMEOUT=300

# ========= 获取服务器位置和国旗 =========
get_country_flag() {
    local country_code=$(curl -s --connect-timeout 3 https://ipapi.co/country_code || echo "")
    case "$country_code" in
        "US") FLAG="🇺🇸" COUNTRY="美国" ;;
        "JP") FLAG="🇯🇵" COUNTRY="日本" ;;
        "SG") FLAG="🇸🇬" COUNTRY="新加坡" ;;
        "HK") FLAG="🇭🇰" COUNTRY="香港" ;;
        "TW") FLAG="🇹🇼" COUNTRY="台湾" ;;
        "KR") FLAG="🇰🇷" COUNTRY="韩国" ;;
        "DE") FLAG="🇩🇪" COUNTRY="德国" ;;
        "FR") FLAG="🇫🇷" COUNTRY="法国" ;;
        "GB") FLAG="🇬🇧" COUNTRY="英国" ;;
        "CA") FLAG="🇨🇦" COUNTRY="加拿大" ;;
        "AU") FLAG="🇦🇺" COUNTRY="澳大利亚" ;;
        "NL") FLAG="🇳🇱" COUNTRY="荷兰" ;;
        "RU") FLAG="🇷🇺" COUNTRY="俄罗斯" ;;
        "BR") FLAG="🇧🇷" COUNTRY="巴西" ;;
        "IN") FLAG="🇮🇳" COUNTRY="印度" ;;
        "MY") FLAG="🇲🇾" COUNTRY="马来西亚" ;;
        "TH") FLAG="🇹🇭" COUNTRY="泰国" ;;
        "VN") FLAG="🇻🇳" COUNTRY="越南" ;;
        "PH") FLAG="🇵🇭" COUNTRY="菲律宾" ;;
        "ID") FLAG="🇮🇩" COUNTRY="印尼" ;;
        "TR") FLAG="🇹🇷" COUNTRY="土耳其" ;;
        "UA") FLAG="🇺🇦" COUNTRY="乌克兰" ;;
        "ES") FLAG="🇪🇸" COUNTRY="西班牙" ;;
        "IT") FLAG="🇮🇹" COUNTRY="意大利" ;;
        "MD") FLAG="🇲🇩" COUNTRY="摩尔多瓦" ;;
        "HU") FLAG="🇭🇺" COUNTRY="匈牙利" ;;
        "IL") FLAG="🇮🇱" COUNTRY="以色列" ;;
        "AR") FLAG="🇦🇷" COUNTRY="阿根廷" ;;
        "NG") FLAG="🇳🇬" COUNTRY="尼日利亚" ;;
        "ZA") FLAG="🇿🇦" COUNTRY="南非" ;;
        "EG") FLAG="🇪🇬" COUNTRY="埃及" ;;
        "PK") FLAG="🇵🇰" COUNTRY="巴基斯坦" ;;
        "SE") FLAG="🇸🇪" COUNTRY="瑞典" ;;
        "CH") FLAG="🇨🇭" COUNTRY="瑞士" ;;
        "PL") FLAG="🇵🇱" COUNTRY="波兰" ;;
        "IE") FLAG="🇮🇪" COUNTRY="爱尔兰" ;;
        "FI") FLAG="🇫🇮" COUNTRY="芬兰" ;;
        "NO") FLAG="🇳🇴" COUNTRY="挪威" ;;
        "AT") FLAG="🇦🇹" COUNTRY="奥地利" ;;
        "BE") FLAG="🇧🇪" COUNTRY="比利时" ;;
        *) FLAG="🌍" COUNTRY="未知" ;;
    esac
    LOCATION=$(curl -s --connect-timeout 3 https://ipapi.co/city || echo "Unknown")
}

# ========= 检查系统 =========
check_system() {
    if [[ ! -f /etc/debian_version ]] && [[ ! -f /etc/redhat-release ]]; then
        echo -e "${RED}❌ 此脚本仅支持 Debian/Ubuntu/CentOS 系统${NC}"
        exit 1
    fi
}

# ========= 安装依赖 =========
install_dependencies() {
    echo -e "${BLUE}📦 安装必要组件...${NC}"
    
    if [[ -f /etc/debian_version ]]; then
        apt-get update -qq
        apt-get install -y shadowsocks-libev qrencode curl jq net-tools >/dev/null 2>&1
    else
        yum install -y epel-release >/dev/null 2>&1
        yum install -y shadowsocks-libev qrencode curl jq net-tools >/dev/null 2>&1
    fi
    
    echo -e "${GREEN}✓ 组件安装完成${NC}"
}

# ========= IPv6 检测 =========
check_ip_stack() {
    echo -e "${BLUE}🔍 检测网络环境...${NC}"
    
    # 检测 IPv6
    IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary\|deprecated" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [ -n "$IPV6_ADDR" ]; then
        # 验证 IPv6 连通性
        if ping6 -c 1 -W 2 google.com >/dev/null 2>&1; then
            echo -e "${GREEN}✓ IPv6: $IPV6_ADDR${NC}"
            IPV6_SUPPORTED=true
        else
            echo -e "${ORANGE}! IPv6 地址存在但无法连接外网${NC}"
            IPV6_SUPPORTED=false
        fi
    else
        echo -e "${ORANGE}✗ IPv6: 不支持${NC}"
        IPV6_SUPPORTED=false
    fi
    
    # 检查结果 - 必须有 IPv6 才继续
    if [ "$IPV6_SUPPORTED" = false ]; then
        echo -e "\n${RED}════════════════════════════════════════${NC}"
        echo -e "${RED}❌ 未检测到可用的 IPv6 地址${NC}"
        echo -e "${ORANGE}⚠️  此脚本仅支持有 IPv6 的服务器${NC}"
        echo -e "${ORANGE}   纯 IPv4 环境下 Shadowsocks 容易被封${NC}"
        echo -e "${ORANGE}   建议使用支持 IPv6 的 VPS 提供商${NC}"
        echo -e "${RED}════════════════════════════════════════${NC}"
        exit 1
    fi
    
    # 显示网络模式
    echo -e "${GREEN}✓ 网络模式: IPv6${NC}"
}

# ========= 系统优化 =========
optimize_system() {
    echo -e "${BLUE}⚡ 优化系统参数...${NC}"
    
    # BBR 优化
    if ! grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf; then
        cat >> /etc/sysctl.conf <<EOF

# Shadowsocks 优化
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=1200
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=5000
EOF
    fi
    
    sysctl -p >/dev/null 2>&1
    echo -e "${GREEN}✓ 系统优化完成${NC}"
}

# ========= 生成配置文件 =========
generate_config() {
    echo -e "${BLUE}📝 生成配置文件...${NC}"
    
    # 生成标签名
    TAG="${FLAG}${COUNTRY}-IPv6"
    TAG_EN="${FLAG}${LOCATION}-IPv6"
    
    # 生成 SS 配置
    cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "::",
    "server_port": $PORT,
    "password": "$PASSWORD",
    "timeout": $TIMEOUT,
    "method": "$METHOD",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "no_delay": true,
    "reuse_port": true,
    "ipv6_first": true
}
EOF
    
    echo -e "${GREEN}✓ 配置文件生成完成${NC}"
}

# ========= 启动服务 =========
start_service() {
    echo -e "${BLUE}🚀 启动 Shadowsocks 服务...${NC}"
    
    systemctl enable shadowsocks-libev >/dev/null 2>&1
    systemctl restart shadowsocks-libev
    
    # 检查服务状态
    sleep 2
    if systemctl is-active --quiet shadowsocks-libev; then
        echo -e "${GREEN}✓ 服务启动成功${NC}"
    else
        echo -e "${RED}✗ 服务启动失败${NC}"
        journalctl -u shadowsocks-libev -n 10
        exit 1
    fi
}

# ========= 配置防火墙 =========
setup_firewall() {
    echo -e "${BLUE}🔥 配置防火墙规则...${NC}"
    
    # ip6tables 规则
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -I INPUT -p tcp --dport $PORT -j ACCEPT >/dev/null 2>&1
        ip6tables -I INPUT -p udp --dport $PORT -j ACCEPT >/dev/null 2>&1
    fi
    
    # UFW
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $PORT/tcp >/dev/null 2>&1
        ufw allow $PORT/udp >/dev/null 2>&1
    fi
    
    # Firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$PORT/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=$PORT/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    
    echo -e "${GREEN}✓ 防火墙配置完成${NC}"
}

# ========= 生成节点信息 =========
generate_nodes() {
    # IPv6 SS 链接
    ENCODED_V6=$(echo -n "$METHOD:$PASSWORD@[$IPV6_ADDR]:$PORT" | base64 -w 0)
    SS_LINK_V6="ss://$ENCODED_V6#$TAG_EN"
    
    # Clash 配置
    CLASH_V6="- {name: '$TAG', type: ss, server: '$IPV6_ADDR', port: $PORT, cipher: '$METHOD', password: '$PASSWORD', udp: true}"
}

# ========= 输出结果 =========
show_result() {
    clear
    
    # 标题
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        Shadowsocks 安装成功! ✨             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    
    # 服务器信息
    echo -e "\n${CYAN}━━━━━━━━━━━━ 服务器信息 ━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}位置${NC}     ${FLAG} ${COUNTRY} - ${LOCATION}"
    echo -e "${WHITE}IPv6${NC}     ${GREEN}[$IPV6_ADDR]${NC}"
    
    # 连接信息
    echo -e "\n${CYAN}━━━━━━━━━━━━ 连接信息 ━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}端口${NC}     ${GREEN}$PORT${NC}"
    echo -e "${WHITE}密码${NC}     ${GREEN}$PASSWORD${NC}"
    echo -e "${WHITE}加密${NC}     ${GREEN}$METHOD${NC}"
    
    # SS 链接
    echo -e "\n${CYAN}━━━━━━━━━━━━ SS 链接 ━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$SS_LINK_V6${NC}"
    
    # 二维码
    echo -e "\n${CYAN}━━━━━━━━━━━━ 二维码 ━━━━━━━━━━━━${NC}"
    qrencode -t ANSIUTF8 "$SS_LINK_V6"
    
    # Clash 配置
    echo -e "\n${CYAN}━━━━━━━━━━━━ Clash 配置 ━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}$CLASH_V6${NC}"
    
    # 使用说明
    echo -e "\n${CYAN}━━━━━━━━━━━━ 使用说明 ━━━━━━━━━━━━${NC}"
    echo -e "• 推荐使用支持 IPv6 的客户端"
    echo -e "• iOS: Shadowrocket、Quantumult X"
    echo -e "• Android: v2rayNG、Clash for Android"
    echo -e "• Windows/Mac: Clash、ShadowsocksX-NG"
    
    # 优化信息
    echo -e "\n${CYAN}━━━━━━━━━━━━ 优化状态 ━━━━━━━━━━━━${NC}"
    echo -e "✓ BBR 加速已启用"
    echo -e "✓ TCP Fast Open 已启用"
    echo -e "✓ IPv6 优先级已设置"
    echo -e "✓ 防火墙规则已配置"
    
    # 管理命令
    echo -e "\n${CYAN}━━━━━━━━━━━━ 管理命令 ━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}查看状态:${NC} systemctl status shadowsocks-libev"
    echo -e "${WHITE}重启服务:${NC} systemctl restart shadowsocks-libev"
    echo -e "${WHITE}查看日志:${NC} journalctl -u shadowsocks-libev -f"
    echo -e "${WHITE}修改配置:${NC} nano /etc/shadowsocks-libev/config.json"
    
    # 结束
    echo -e "\n${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}🎉 安装完成！请保存以上信息${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}\n"
}

# ========= 主函数 =========
main() {
    echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   Shadowsocks IPv6 专用安装脚本      ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════╝${NC}\n"
    
    check_system
    install_dependencies
    check_ip_stack
    get_country_flag
    optimize_system
    generate_config
    start_service
    setup_firewall
    generate_nodes
    show_result
}

# 执行主函数
main
