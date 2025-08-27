#!/bin/bash
# Hysteria2 + Cloudflare Tunnel 一键安装脚本 (IPv6 Only VPS)
# GitHub: https://github.com/everett7623/hy2ipv6
# 再次修复版本 (解决 Cloudflare Tunnel 服务安装失败问题)

set -e

# ========= 基础配置 =========
PORT=443 # Hysteria2 服务端口
PASSWORD=$(openssl rand -base64 16) # 自动生成 Hysteria2 密码
SNI=www.bing.com   # 可改成任意域名伪装，用于 Hysteria2 TLS SNI 和客户端配置
TUNNEL_NAME=hy2-tunnel # Cloudflare Tunnel 的名称

echo ">>> [1/5] 更新系统并安装必要依赖"
apt update -y
apt install -y curl wget unzip socat net-tools # 添加 net-tools 以确保某些系统工具可用

# ========= 安装 hysteria2 =========
echo ">>> [2/5] 安装 Hysteria2"
# 确保 hysteria2 安装脚本成功执行
bash <(curl -fsSL https://get.hy2.sh) || { echo "Hysteria2 安装失败，请检查网络或重试。"; exit 1; }

mkdir -p /etc/hysteria
cat > /etc/hysteria/config.yaml <<EOF
listen: :$PORT

tls:
  insecure: true # 使用 Cloudflare Tunnel 时，可以设置为 true，由 CF 处理 TLS 证书
  sni: $SNI

auth:
  type: password
  password: $PASSWORD

masq:
  type: wireguard
EOF

# 创建 Hysteria2 Systemd 服务文件
cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria2 server -c /etc/hysteria/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# 重载 Systemd 并启用 Hysteria2 服务
systemctl daemon-reexec
systemctl enable --now hysteria-server || { echo "Hysteria2 服务启动失败，请检查配置。"; exit 1; }
echo "Hysteria2 服务已启动并设置为开机自启。"

# ========= 安装 Cloudflare Tunnel =========
echo ">>> [3/5] 安装 Cloudflare Tunnel (cloudflared)"
# 下载 cloudflared .deb 包
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -O /tmp/cloudflared-linux-amd64.deb
# 使用 apt 安装本地 deb 包，这样可以更好地处理依赖
apt install -y /tmp/cloudflared-linux-amd64.deb || { echo "cloudflared 安装失败，请检查。"; exit 1; }
# 清理下载的 deb 包
rm /tmp/cloudflared-linux-amd64.deb
echo "Cloudflared 已安装。"

# ========= 登录 Cloudflare (手动授权) =========
echo -e "\n>>> [4/5] 请用浏览器打开下面的链接完成 Cloudflare 登录授权："
echo "   这将生成一个 cert.pem 文件在 ~/.cloudflared/ 目录下。"
cloudflared tunnel login || { echo "Cloudflare 登录授权失败，请检查网络或重试。"; exit 1; }
echo "Cloudflare 登录授权成功。"

# ========= 创建 & 启动隧道 =========
echo -e "\n>>> [5/5] 创建并启动 Cloudflare Tunnel"

# 定义 Cloudflare Tunnel 配置文件的系统级目录
CF_CONFIG_DIR="/etc/cloudflared"
mkdir -p "$CF_CONFIG_DIR" # 确保目录存在

# 检查隧道是否已存在，如果存在则跳过创建
if cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
    echo "隧道 '$TUNNEL_NAME' 已存在，跳过创建步骤。"
    # 尝试获取已有隧道的UUID
    UUID=$(cloudflared tunnel list --json | grep -A 5 "\"name\":\"$TUNNEL_NAME\"" | grep -oE '"id":"[0-9a-f-]{36}"' | cut -d':' -f2 | tr -d '"')
    if [ -z "$UUID" ]; then
        echo "无法从现有隧道中获取 UUID，请手动检查或删除旧隧道后再运行。"
        exit 1
    fi
else
    # 创建隧道
    cloudflared tunnel create $TUNNEL_NAME || { echo "创建 Cloudflare Tunnel 失败，请检查。"; exit 1; }
    # 获取隧道 UUID (从 ~/.cloudflared/ 目录下新生成的 JSON 文件中提取)
    UUID=$(cat /root/.cloudflared/*.json | grep -oE '[0-9a-f-]{36}' | head -n1)
fi

# 将隧道凭证文件从用户家目录移动到系统级配置目录
if [ -f "/root/.cloudflared/$UUID.json" ]; then
    mv "/root/.cloudflared/$UUID.json" "$CF_CONFIG_DIR/" || { echo "移动隧道凭证文件失败。"; exit 1; }
    echo "隧道凭证文件已移动至 $CF_CONFIG_DIR/$UUID.json"
else
    echo "警告：未找到隧道凭证文件 /root/.cloudflared/$UUID.json，可能需要手动处理。"
fi


# 自动生成的 CF 隧道域名
# 注意：whoami 在root环境下是root，所以域名会是 hy2.root.cfargotunnel.com
# 如果希望域名更个性化，可以手动修改 CF_TUNNEL_DOMAIN 变量
CF_TUNNEL_DOMAIN="hy2.$(whoami).cfargotunnel.com" 

echo "正在生成 Cloudflare Tunnel 配置文件..."
# 生成 Cloudflare Tunnel 配置文件到系统级目录
cat > "$CF_CONFIG_DIR/config.yml" <<EOF
tunnel: $UUID
credentials-file: $CF_CONFIG_DIR/$UUID.json

ingress:
  - hostname: $CF_TUNNEL_DOMAIN
    service: https://localhost:$PORT # Hysteria2 默认端口
  - service: http_status:404
EOF
echo "Cloudflare Tunnel 配置文件已生成：$CF_CONFIG_DIR/config.yml"


# 安装并启动 Cloudflare Tunnel 为系统服务
echo "正在安装和启动 Cloudflare Tunnel Systemd 服务..."
# 使用 --config 参数明确指定配置文件路径
cloudflared tunnel service install $TUNNEL_NAME --config "$CF_CONFIG_DIR/config.yml" || { echo "Cloudflare Tunnel 服务安装失败。请检查日志：journalctl -u cloudflared-tunnel@$TUNNEL_NAME.service"; exit 1; }
systemctl enable --now cloudflared-tunnel@$TUNNEL_NAME.service || { echo "Cloudflare Tunnel 服务启动失败。请检查日志。"; exit 1; }
systemctl restart cloudflared-tunnel@$TUNNEL_NAME.service # 确保服务在配置更新后重启
echo "Cloudflare Tunnel 服务已启动并设置为开机自启。"

# 检查 Cloudflare Tunnel 服务状态
sleep 5 # 等待服务启动
if systemctl is-active --quiet cloudflared-tunnel@$TUNNEL_NAME.service; then
    echo "Cloudflare Tunnel 服务运行正常。"
else
    echo "警告：Cloudflare Tunnel 服务可能未正常运行。请手动检查：systemctl status cloudflared-tunnel@$TUNNEL_NAME.service"
fi


# ========= 获取 IPv6 =========
# 尝试获取全局IPv6地址，如果获取不到，则可能VPS没有公网IPv6
IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1 || echo "未找到公共IPv6地址")

# ========= 输出信息 =========
echo -e "\n======================================================="
echo -e "✅ Hysteria2 + Cloudflare Tunnel 安装完成！"
echo -e "======================================================="
echo "📌 VPS IPv6 地址 (直连): [$IPV6]:$PORT"
echo "🔐 Hysteria2 密码: $PASSWORD"
echo "🌐 Cloudflare Tunnel 域名 (本地IPv4用户使用): $CF_TUNNEL_DOMAIN"
echo "---"

echo -e "\n📎 Clash Meta 客户端配置示例 (复制粘贴使用):"
cat <<EOL
- name: 🇩🇪DE-Hy2-CF-Tunnel
  type: hysteria2
  server: $CF_TUNNEL_DOMAIN
  port: 443
  password: "$PASSWORD"
  sni: "$SNI"
  skip-cert-verify: true

- name: 🇩🇪DE-Hy2-Direct-IPv6 # 如果本地支持IPv6，可以使用此配置直连
  type: hysteria2
  server: "$IPV6"
  port: $PORT
  password: "$PASSWORD"
  sni: "$SNI"
  skip-cert-verify: true
EOL
echo -e "\n📎 Sing-box 客户端配置示例 (复制粘贴使用):"
cat <<EOL
{
  "type": "hysteria2",
  "tag": "DE-Hy2-CF-Tunnel",
  "server": "$CF_TUNNEL_DOMAIN",
  "server_port": 443,
  "password": "$PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "$SNI",
    "insecure": true
  }
}
,{
  "type": "hysteria2",
  "tag": "DE-Hy2-Direct-IPv6", # 如果本地支持IPv6，可以使用此配置直连
  "server": "$IPV6",
  "server_port": $PORT,
  "password": "$PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "$SNI",
    "insecure": true
  }
}
EOL
echo -e "\n======================================================="
echo "请将以上客户端配置添加到您的 Clash Meta 或 Sing-box 客户端中。"
echo "如果您在本地支持 IPv6，可以尝试使用直连配置以获得更好的性能。"
echo "如果您本地只有 IPv4，则必须使用 Cloudflare Tunnel 域名进行连接。"
echo -e "======================================================="
