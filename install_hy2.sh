#!/bin/bash
# Hysteria2 + Cloudflare Tunnel 一键安装脚本 (IPv6 Only VPS)
# GitHub: https://github.com/everett7623/hy2ipv6

set -e

# ========= 基础配置 =========
PORT=443
PASSWORD=$(openssl rand -base64 16)
SNI=www.bing.com   # 可改成任意域名伪装
TUNNEL_NAME=hy2-tunnel # Cloudflare Tunnel 的名称

echo ">>> [1/5] 安装依赖"
apt update -y
apt install -y curl wget unzip socat

# ========= 安装 hysteria2 =========
echo ">>> [2/5] 安装 Hysteria2"
bash <(curl -fsSL https://get.hy2.sh)

mkdir -p /etc/hysteria
cat > /etc/hysteria/config.yaml <<EOF
listen: :$PORT

tls:
  insecure: true
  sni: $SNI

auth:
  type: password
  password: $PASSWORD

masq:
  type: wireguard
EOF

cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria2 server -c /etc/hysteria/config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl enable --now hysteria-server

# ========= 安装 Cloudflare Tunnel =========
echo ">>> [3/5] 安装 Cloudflare Tunnel (cloudflared)"
# 下载 cloudflared .deb 包
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
# 使用 apt 安装本地 deb 包，这样可以更好地处理依赖
apt install -y ./cloudflared-linux-amd64.deb
# 清理下载的 deb 包
rm cloudflared-linux-amd64.deb

# ========= 登录 Cloudflare (手动扫码) =========
echo ">>> [4/5] 请用浏览器打开下面的链接完成 Cloudflare 登录授权："
cloudflared tunnel login

# ========= 创建 & 启动隧道 =========
echo ">>> [5/5] 创建并启动 Cloudflare Tunnel"
# 创建隧道
cloudflared tunnel create $TUNNEL_NAME

# 获取隧道 UUID (从证书文件中提取)
UUID=$(cat ~/.cloudflared/*.json | grep -oE '[0-9a-f-]{36}' | head -n1)

# 自动生成的 CF 隧道域名
CF_TUNNEL_DOMAIN="hy2.$(whoami).cfargotunnel.com" 

# 生成 Cloudflare Tunnel 配置文件
cat > ~/.cloudflared/config.yml <<EOF
tunnel: $UUID
credentials-file: /root/.cloudflared/$UUID.json

ingress:
  - hostname: $CF_TUNNEL_DOMAIN
    service: https://localhost:$PORT # Hysteria2 默认端口
  - service: http_status:404
EOF

# 安装并启动 Cloudflare Tunnel 为系统服务
cloudflared tunnel service install $TUNNEL_NAME
systemctl enable --now cloudflared-tunnel@$TUNNEL_NAME.service
systemctl restart cloudflared-tunnel@$TUNNEL_NAME.service # 确保服务在配置更新后重启

# ========= 获取 IPv6 =========
IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)

# ========= 输出信息 =========
echo -e "\n✅ Hysteria2 + Cloudflare Tunnel 安装完成！"
echo "📌 VPS IPv6: [$IPV6]:$PORT"
echo "🔐 密码: $PASSWORD"
echo "🌐 Cloudflare Tunnel 域名: $CF_TUNNEL_DOMAIN"

echo -e "\n📎 Clash/Sing-box 配置示例："
cat <<EOL
# Clash Meta
- name: 🇩🇪DE-Hy2-CF
  type: hysteria2
  server: $CF_TUNNEL_DOMAIN
  port: 443
  password: $PASSWORD
  sni: $SNI
  skip-cert-verify: true

# Sing-box
{
  "type": "hysteria2",
  "tag": "DE-Hy2-CF",
  "server": "$CF_TUNNEL_DOMAIN",
  "server_port": 443,
  "password": "$PASSWORD",
  "tls": {
    "enabled": true,
    "server_name": "$SNI",
    "insecure": true
  }
}
EOL
