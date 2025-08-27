#!/bin/bash
# Hysteria2 + Cloudflare Tunnel 一键安装脚本 (IPv6 Only VPS)
# GitHub: https://github.com/everett7623/hy2ipv6

set -e

# ========= 基础配置 =========
PORT=443
PASSWORD=$(openssl rand -base64 16)
SNI=www.bing.com   # 可改成任意域名伪装
TUNNEL_NAME=hy2-tunnel

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
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
dpkg -i cloudflared-linux-amd64.deb || true

# ========= 登录 Cloudflare (手动扫码) =========
echo ">>> [4/5] 请用浏览器打开下面的链接完成 Cloudflare 登录授权："
cloudflared tunnel login

# ========= 创建 & 启动隧道 =========
echo ">>> [5/5] 创建并启动 Cloudflare Tunnel"
cloudflared tunnel create $TUNNEL_NAME
UUID=$(cat ~/.cloudflared/*.json | grep -oE '[0-9a-f-]{36}' | head -n1)

cat > ~/.cloudflared/config.yml <<EOF
tunnel: $UUID
credentials-file: /root/.cloudflared/$UUID.json

ingress:
  - hostname: hy2.$(whoami).cfargotunnel.com
    service: https://localhost:$PORT
  - service: http_status:404
EOF

cloudflared tunnel run $TUNNEL_NAME --url localhost:$PORT --detach

# ========= 获取 IPv6 =========
IPV6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1)

# ========= 输出信息 =========
echo -e "\n✅ Hysteria2 + Cloudflare Tunnel 安装完成！"
echo "📌 VPS IPv6: [$IPV6]:$PORT"
echo "🔐 密码: $PASSWORD"
echo "🌐 Cloudflare Tunnel 域名: hy2.$(whoami).cfargotunnel.com"

echo -e "\n📎 Clash/Sing-box 配置示例："
cat <<EOL
- name: 🇩🇪DE-Hy2-CF
  type: hysteria2
  server: hy2.$(whoami).cfargotunnel.com
  port: 443
  password: $PASSWORD
  sni: $SNI
  skip-cert-verify: true
EOL
