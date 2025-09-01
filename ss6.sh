#!/bin/bash

# ========= 配置部分 =========
PORT=$(shuf -i 20000-40000 -n 1)
PASSWORD=$(openssl rand -base64 16)
METHOD="chacha20-ietf-poly1305"
TAG="SS-IPv6"

# ========= 安装 Shadowsocks-libev 和工具 =========
apt update
apt install -y shadowsocks-libev qrencode curl jq

# ========= 获取公网IPv6地址 =========
IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary" | awk '{print $2}' | cut -d/ -f1 | head -n1)
[ -z "$IPV6_ADDR" ] && echo "❌ 未检测到IPv6地址，脚本退出" && exit 1

# ========= 写入配置 =========
cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server":"::",
    "server_port":$PORT,
    "password":"$PASSWORD",
    "timeout":300,
    "method":"$METHOD",
    "mode":"tcp_and_udp",
    "no_delay": true
}
EOF

# ========= 启动服务 =========
systemctl enable shadowsocks-libev
systemctl restart shadowsocks-libev

# ========= 节点生成 =========
ENCODED=$(echo -n "$METHOD:$PASSWORD@$IPV6_ADDR:$PORT" | base64 -w 0)
SS_LINK="ss://$ENCODED#$TAG"

# ========= Clash 节点 =========
CLASH_NODE="- { name: '$TAG', type: ss, server: '$IPV6_ADDR', port: $PORT, cipher: '$METHOD', password: '$PASSWORD', udp: true }"

# ========= 输出结果 =========
echo -e "\n✅ Shadowsocks IPv6 安装完成！\n"
echo "========= 基本信息 ========="
echo "服务器地址: [$IPV6_ADDR]"
echo "端口: $PORT"
echo "密码: $PASSWORD"
echo "加密方式: $METHOD"

echo -e "\n========= 📱 SS 节点 ========="
echo "$SS_LINK"
qrencode -t ANSIUTF8 "$SS_LINK"

echo -e "\n========= 🧩 Clash 节点========="
echo "$CLASH_NODE"

echo -e "\n🎉 完成！请保存以上节点用于各平台导入。"
