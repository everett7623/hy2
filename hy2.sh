#!/bin/bash
#====================================================================================
# 项目：Hysteria2 Management Script
# 作者：Jensfrank
# 版本：v1.0
# GitHub: https://github.com/everett7623/hy2
# Seeloc博客: https://seedloc.com
# VPSknow网站：https://vpsknow.com
# Nodeloc论坛: https://nodeloc.com
# 更新日期: 2025-12-22
#====================================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置路径
HY2_DIR="/etc/hysteria2"
HY2_BIN="/usr/local/bin/hysteria"
HY2_CONFIG="${HY2_DIR}/config.yaml"
HY2_CERT_DIR="${HY2_DIR}/certs"
HY2_SERVICE="/etc/systemd/system/hysteria-server.service"
HY2_INFO="${HY2_DIR}/client_info.txt"

# 检测系统信息
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        echo -e "${RED}无法检测操作系统${NC}"
        exit 1
    fi

    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) echo -e "${RED}不支持的架构: $ARCH${NC}"; exit 1 ;;
    esac
}

# 检查系统兼容性
check_compatibility() {
    case $OS in
        ubuntu)
            if [[ $(echo "$OS_VERSION < 18.04" | bc) -eq 1 ]]; then
                echo -e "${RED}Ubuntu 版本过低，需要 18.04 或更高版本${NC}"
                exit 1
            fi
            ;;
        debian)
            if [[ $OS_VERSION -lt 9 ]]; then
                echo -e "${RED}Debian 版本过低，需要 9 或更高版本${NC}"
                exit 1
            fi
            ;;
        centos|rhel)
            if [[ $OS_VERSION -lt 7 ]]; then
                echo -e "${RED}CentOS/RHEL 版本过低，需要 7 或更高版本${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}不支持的操作系统: $OS${NC}"
            exit 1
            ;;
    esac
}

# 检查内存
check_memory() {
    total_mem=$(free -m | awk 'NR==2 {print $2}')
    if [[ $total_mem -lt 256 ]]; then
        echo -e "${RED}内存不足 256MB，无法安装${NC}"
        exit 1
    elif [[ $total_mem -lt 512 ]]; then
        echo -e "${YELLOW}检测到小内存 VPS (${total_mem}MB)，建议优化配置${NC}"
        sleep 2
    fi
}

# 安装依赖
install_dependencies() {
    echo -e "${BLUE}正在安装必要依赖...${NC}"
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y curl wget openssl ca-certificates >/dev/null 2>&1
            ;;
        centos|rhel)
            yum install -y curl wget openssl ca-certificates >/dev/null 2>&1
            ;;
    esac
}

# 检测网络
detect_network() {
    IPV4=$(curl -s4m8 ip.sb)
    IPV6=$(curl -s6m8 ip.sb)
    [[ -z $IPV4 ]] && IPV4="N/A"
    [[ -z $IPV6 ]] && IPV6="N/A"
}

# 检测 Hysteria2 状态
check_hy2_status() {
    if [[ -f $HY2_BIN ]]; then
        if systemctl is-active --quiet hysteria-server; then
            HY2_STATUS="${GREEN}已安装 - 运行中${NC}"
        else
            HY2_STATUS="${YELLOW}已安装 - 已停止${NC}"
        fi
    else
        HY2_STATUS="${RED}未安装${NC}"
    fi
}

# 生成随机端口
generate_port() {
    while true; do
        PORT=$((RANDOM % 55536 + 10000))
        if ! ss -tulpn | grep -q ":$PORT "; then
            echo $PORT
            return
        fi
    done
}

# 生成随机密码
generate_password() {
    openssl rand -base64 16 | tr -d '/+=' | cut -c1-16
}

# 配置防火墙
configure_firewall() {
    local port=$1
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        ufw allow $port/tcp >/dev/null 2>&1
        ufw allow $port/udp >/dev/null 2>&1
        echo -e "${GREEN}UFW 防火墙已开放端口 $port${NC}"
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=$port/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=$port/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "${GREEN}FirewallD 已开放端口 $port${NC}"
    fi
}

# 启用 BBR
enable_bbr() {
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) != "bbr" ]]; then
        echo -e "${BLUE}正在启用 BBR 加速...${NC}"
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        echo -e "${GREEN}BBR 加速已启用${NC}"
    fi
}

# 下载 Hysteria2
download_hysteria() {
    echo -e "${BLUE}正在下载 Hysteria2 最新版本...${NC}"
    local latest_version=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    local download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${ARCH}"
    
    if curl -L -o $HY2_BIN $download_url; then
        chmod +x $HY2_BIN
        echo -e "${GREEN}Hysteria2 下载成功${NC}"
    else
        echo -e "${RED}下载失败，请检查网络连接${NC}"
        exit 1
    fi
}

# 生成自签证书
generate_cert() {
    echo -e "${BLUE}正在生成自签名证书...${NC}"
    mkdir -p $HY2_CERT_DIR
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout ${HY2_CERT_DIR}/server.key \
        -out ${HY2_CERT_DIR}/server.crt \
        -subj "/CN=amd.com" \
        -days 36500 >/dev/null 2>&1
    chmod 600 ${HY2_CERT_DIR}/server.key ${HY2_CERT_DIR}/server.crt
    echo -e "${GREEN}证书生成成功${NC}"
}

# 安装 Hysteria2
install_hysteria() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Hysteria2 安装程序${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    if [[ -f $HY2_BIN ]]; then
        echo -e "${YELLOW}检测到已安装 Hysteria2，是否重新安装？(y/n)${NC}"
        read -p "请选择: " reinstall
        [[ $reinstall != "y" ]] && return
        uninstall_hysteria
    fi
    
    check_memory
    install_dependencies
    enable_bbr
    
    # 下载程序
    download_hysteria
    
    # 生成配置
    PORT=$(generate_port)
    PASSWORD=$(generate_password)
    
    echo ""
    echo -e "${YELLOW}请输入 SNI 伪装域名 (默认: amd.com):${NC}"
    read -p "SNI: " SNI
    SNI=${SNI:-amd.com}
    
    # 创建配置目录
    mkdir -p $HY2_DIR
    
    # 生成证书
    generate_cert
    
    # 生成配置文件
    cat > $HY2_CONFIG <<EOF
listen: :$PORT

tls:
  cert: ${HY2_CERT_DIR}/server.crt
  key: ${HY2_CERT_DIR}/server.key

auth:
  type: password
  password: $PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
EOF
    chmod 600 $HY2_CONFIG
    
    # 创建 systemd 服务
    cat > $HY2_SERVICE <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
ExecStart=$HY2_BIN server -c $HY2_CONFIG
Restart=on-failure
RestartSec=10
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    # 配置防火墙
    configure_firewall $PORT
    
    # 启动服务
    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl start hysteria-server
    
    if systemctl is-active --quiet hysteria-server; then
        echo ""
        echo -e "${GREEN}================================${NC}"
        echo -e "${GREEN}  Hysteria2 安装成功！${NC}"
        echo -e "${GREEN}================================${NC}"
        echo ""
        
        # 生成客户端配置
        generate_client_config
    else
        echo -e "${RED}服务启动失败，请检查日志: journalctl -u hysteria-server -n 50${NC}"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# 生成客户端配置
generate_client_config() {
    local server_ip=${IPV4}
    [[ $server_ip == "N/A" ]] && server_ip=${IPV6}
    
    local region=$(curl -s https://ipapi.co/${server_ip}/country_name/ | head -1)
    [[ -z $region ]] && region="Unknown"
    local random_suffix=$(openssl rand -hex 2)
    local node_name="🌟Hysteria2-${region}-${random_suffix}"
    
    # V2rayN / NekoBox / Shadowrocket
    local share_link="hysteria2://${PASSWORD}@${server_ip}:${PORT}/?insecure=1&sni=${SNI}#${node_name}"
    
    # Clash Meta
    local clash_config="{ name: '${node_name}', type: hysteria2, server: ${server_ip}, port: ${PORT}, password: '${PASSWORD}', sni: '${SNI}', skip-cert-verify: true, up: 50, down: 100 }"
    
    # Surge
    local surge_config="${node_name} = hysteria2, ${server_ip}, ${PORT}, password=${PASSWORD}, sni=${SNI}, skip-cert-verify=true"
    
    # 保存配置
    cat > $HY2_INFO <<EOF
服务器地址: ${server_ip}
服务器端口: ${PORT}
密码: ${PASSWORD}
SNI: ${SNI}

==================================================
V2rayN / NekoBox / Shadowrocket 分享链接：
==================================================
${share_link}

==================================================
Clash Meta 配置：
==================================================
${clash_config}

==================================================
Surge 配置：
==================================================
${surge_config}
==================================================
EOF
    
    # 显示配置
    cat $HY2_INFO
}

# 管理菜单
manage_hysteria() {
    while true; do
        clear
        echo -e "${BLUE}================================${NC}"
        echo -e "${BLUE}    Hysteria2 管理菜单${NC}"
        echo -e "${BLUE}================================${NC}"
        echo ""
        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 查看运行状态"
        echo "5. 查看客户端配置"
        echo "6. 修改 SNI"
        echo "7. 修改端口"
        echo "8. 重置密码"
        echo "9. 查看日志"
        echo "0. 返回主菜单"
        echo ""
        read -p "请选择操作 [0-9]: " choice
        
        case $choice in
            1) systemctl start hysteria-server && echo -e "${GREEN}服务已启动${NC}" || echo -e "${RED}启动失败${NC}"; sleep 2 ;;
            2) systemctl stop hysteria-server && echo -e "${GREEN}服务已停止${NC}" || echo -e "${RED}停止失败${NC}"; sleep 2 ;;
            3) systemctl restart hysteria-server && echo -e "${GREEN}服务已重启${NC}" || echo -e "${RED}重启失败${NC}"; sleep 2 ;;
            4) show_status ;;
            5) show_config ;;
            6) modify_sni ;;
            7) modify_port ;;
            8) reset_password ;;
            9) journalctl -u hysteria-server -n 50 --no-pager; read -p "按回车键继续..." ;;
            0) break ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# 显示状态
show_status() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Hysteria2 运行状态${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    systemctl status hysteria-server --no-pager
    echo ""
    read -p "按回车键返回..."
}

# 显示配置
show_config() {
    clear
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Hysteria2 客户端配置${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    if [[ -f $HY2_INFO ]]; then
        cat $HY2_INFO
    else
        echo -e "${RED}配置文件不存在${NC}"
    fi
    echo ""
    read -p "按回车键返回..."
}

# 修改 SNI
modify_sni() {
    echo ""
    read -p "请输入新的 SNI: " new_sni
    if [[ -z $new_sni ]]; then
        echo -e "${RED}SNI 不能为空${NC}"
        sleep 2
        return
    fi
    
    sed -i "s/sni: .*/sni: ${new_sni}/" $HY2_INFO
    systemctl restart hysteria-server
    echo -e "${GREEN}SNI 已修改为: ${new_sni}${NC}"
    sleep 2
}

# 修改端口
modify_port() {
    echo ""
    new_port=$(generate_port)
    echo -e "${YELLOW}新端口: ${new_port}${NC}"
    read -p "确认修改？(y/n): " confirm
    [[ $confirm != "y" ]] && return
    
    sed -i "s/listen: .*/listen: :${new_port}/" $HY2_CONFIG
    configure_firewall $new_port
    systemctl restart hysteria-server
    
    # 更新配置信息
    sed -i "s/服务器端口: .*/服务器端口: ${new_port}/" $HY2_INFO
    sed -i "s/:.*\?/:${new_port}\//g" $HY2_INFO
    
    echo -e "${GREEN}端口已修改为: ${new_port}${NC}"
    sleep 2
}

# 重置密码
reset_password() {
    echo ""
    new_password=$(generate_password)
    echo -e "${YELLOW}新密码: ${new_password}${NC}"
    read -p "确认重置？(y/n): " confirm
    [[ $confirm != "y" ]] && return
    
    sed -i "s/password: .*/password: ${new_password}/" $HY2_CONFIG
    systemctl restart hysteria-server
    
    # 更新配置信息
    sed -i "s/密码: .*/密码: ${new_password}/" $HY2_INFO
    sed -i "s/hysteria2:\/\/.*@/hysteria2:\/\/${new_password}@/g" $HY2_INFO
    sed -i "s/password: '.*'/password: '${new_password}'/g" $HY2_INFO
    sed -i "s/password=.*, /password=${new_password}, /g" $HY2_INFO
    
    echo -e "${GREEN}密码已重置为: ${new_password}${NC}"
    sleep 2
}

# 卸载 Hysteria2
uninstall_hysteria() {
    clear
    echo -e "${RED}================================${NC}"
    echo -e "${RED}    卸载 Hysteria2${NC}"
    echo -e "${RED}================================${NC}"
    echo ""
    echo -e "${YELLOW}警告：此操作将完全删除 Hysteria2 及其所有配置${NC}"
    echo ""
    read -p "确认卸载？(yes/no): " confirm
    [[ $confirm != "yes" ]] && return
    
    echo ""
    echo -e "${BLUE}正在卸载...${NC}"
    
    # 停止服务
    systemctl stop hysteria-server >/dev/null 2>&1
    systemctl disable hysteria-server >/dev/null 2>&1
    
    # 删除文件
    rm -f $HY2_SERVICE
    rm -f $HY2_BIN
    rm -rf $HY2_DIR
    
    systemctl daemon-reload
    
    echo -e "${GREEN}Hysteria2 已完全卸载${NC}"
    sleep 2
}

# 主菜单
main_menu() {
    clear
    detect_network
    check_hy2_status
    
    echo -e "${BLUE}Hysteria2 Management Script (v1.0)${NC}"
    echo -e "项目地址：https://github.com/everett7623/hy2"
    echo -e "作者：Jensfrank"
    echo -e "GitHub: https://github.com/everett7623/hy2"
    echo -e "Seeloc博客: https://seedloc.com"
    echo -e "VPSknow网站：https://vpsknow.com"
    echo -e "Nodeloc论坛: https://nodeloc.com"
    echo -e "更新日期: 2025-12-22"
    echo ""
    echo -e "服务器 IPv4: ${IPV4}"
    echo -e "服务器 IPv6: ${IPV6}"
    echo -e "Hysteria 2 状态: ${HY2_STATUS}"
    echo -e "${BLUE}================================================${NC}"
    echo " 1. 安装 Hysteria2(自签模式，无需域名解析)"
    echo " 2. 管理 Hysteria2"
    echo " 3. 卸载 Hysteria2"
    echo " 0. 退出脚本"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    read -p "请选择操作 [0-3]: " choice
    
    case $choice in
        1) install_hysteria ;;
        2) 
            if [[ -f $HY2_BIN ]]; then
                manage_hysteria
            else
                echo -e "${RED}请先安装 Hysteria2${NC}"
                sleep 2
                main_menu
            fi
            ;;
        3) 
            if [[ -f $HY2_BIN ]]; then
                uninstall_hysteria
            else
                echo -e "${RED}未安装 Hysteria2${NC}"
                sleep 2
                main_menu
            fi
            ;;
        0) echo -e "${GREEN}感谢使用！${NC}"; exit 0 ;;
        *) echo -e "${RED}无效选择，请重新输入${NC}"; sleep 1; main_menu ;;
    esac
}

# 脚本入口
detect_system
check_compatibility
main_menu
