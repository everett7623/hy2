#!/bin/bash
set -eu
trap 'echo "Realm validation failed at line $LINENO" >&2' ERR

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

REALM_LIB_ONLY=1 . ./realm.sh

# --- 输入校验 ---
validate_port 443
validate_port 52022
! validate_port 0
! validate_port 65536
! validate_port abc
validate_exit_host 192.0.2.8
validate_exit_host home.example.com
! validate_exit_host '192.0.2.8:22'
! validate_exit_host '-oProxyCommand=sh'
validate_ssh_user root
validate_ssh_user deploy_user
! validate_ssh_user 'root;id'

# --- 生成 toml / 节点 JSON ---
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
REALM_DIR="$tmp/realm"
REALM_CONFIG="$REALM_DIR/config.toml"
REALM_META="$REALM_DIR/meta"
mkdir -p "$REALM_DIR" "$REALM_META"
LANDING_HOST=198.51.100.8
RELAY_LISTEN_PORT=41000
NODE_PORT=42000
LISTEN_HOST=0.0.0.0
write_realm_config
grep -q 'use_udp = false' "$REALM_CONFIG"
grep -q 'no_tcp = false' "$REALM_CONFIG"
grep -q 'listen = "0.0.0.0:41000"' "$REALM_CONFIG"
grep -q 'remote = "198.51.100.8:42000"' "$REALM_CONFIG"

NODE_PROTO=anytls
ANYTLS_PASSWORD=Ab12Cd34Ef56Gh78Ij90Kl12
SERVER_NAME=www.amd.com
SING_BOX_DIR="$tmp/sing-box"
NODE_CONFIG="$SING_BOX_DIR/realm-node.json"
NODE_CERT_DIR="$tmp/cert"
NODE_CERT="$NODE_CERT_DIR/cert.pem"
NODE_KEY="$NODE_CERT_DIR/private.key"
mkdir -p "$SING_BOX_DIR" "$NODE_CERT_DIR"
# Git Bash 下 openssl -subj 路径改写
export MSYS2_ARG_CONV_EXCL='/CN='
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj "/CN=${SERVER_NAME}" \
    -keyout "$NODE_KEY" -out "$NODE_CERT" >/dev/null 2>&1
write_exit_node_config
grep -q '"type": "anytls"' "$NODE_CONFIG"
grep -q "\"password\": \"${ANYTLS_PASSWORD}\"" "$NODE_CONFIG"
grep -q '"listen_port": 42000' "$NODE_CONFIG"

NODE_PROTO=vless
UUID=bf000d23-0752-40b4-affe-68f7707a9661
REALITY_PRIVATE_KEY=UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc
REALITY_PUBLIC_KEY=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
SHORT_ID=0123456789abcdef
HANDSHAKE_PORT=443
write_exit_node_config
grep -q '"type": "vless"' "$NODE_CONFIG"
grep -q '"flow": "xtls-rprx-vision"' "$NODE_CONFIG"
grep -q '"reality": {' "$NODE_CONFIG"

# --- URI：AnyTLS 不带 fp，VLESS 带 fp=chrome ---
NODE_PROTO=anytls
ANYTLS_PASSWORD=Ab12Cd34Ef56Gh78Ij90Kl12
SERVER_NAME=www.amd.com
NODE_NAME='test node'
_uri=$(render_anytls_uri 192.0.2.10 41000 "$ANYTLS_PASSWORD" "$NODE_NAME" "$SERVER_NAME")
printf '%s\n' "$_uri" | grep -q '^anytls://'
printf '%s\n' "$_uri" | grep -q 'insecure=1'
( ! printf '%s\n' "$_uri" | grep -q 'fp=' )
NODE_PROTO=vless
UUID=bf000d23-0752-40b4-affe-68f7707a9661
REALITY_PUBLIC_KEY=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
SHORT_ID=0123456789abcdef
_uri=$(render_vless_uri 192.0.2.10 41000 "$UUID" "$NODE_NAME" "$SERVER_NAME" "$REALITY_PUBLIC_KEY" "$SHORT_ID")
printf '%s\n' "$_uri" | grep -q '^vless://'
printf '%s\n' "$_uri" | grep -q 'fp=chrome'
printf '%s\n' "$_uri" | grep -q 'security=reality'

# --- 远程结果解析 ---
printf 'noise\nREALM_EXIT_RESULT=ok|42000|198.51.100.8|0\n' | parse_remote_result | grep -qx 'ok|42000|198.51.100.8|0'

# --- 静态约束 / 一键体验锁 ---
grep -q '^\[ "\$_REALM_LIB_ONLY" = "1" \] && return 0' realm.sh
( ! grep -qE 'StrictHostKeyChecking=(no|off)|UserKnownHostsFile=/dev/null' realm.sh )
( ! grep -qE 'sshpass|grep -oP|head -c' realm.sh )
( ! grep -qE 'net.ipv4.ip_forward|MASQUERADE|wg-quick' realm.sh )
grep -q 'zhboner/realm' realm.sh
grep -q 'use_udp = false' realm.sh
grep -q '^deploy_realm()' realm.sh
grep -q 'Realm TCP 中转一键部署' realm.sh
grep -q '1. 一键部署 / 重新对接' realm.sh
grep -q '^remote_exit_install()' realm.sh
grep -q '^remote_exit_uninstall()' realm.sh
grep -q 'StrictHostKeyChecking=accept-new' realm.sh
grep -q '^ssh_check_host_key()' realm.sh
grep -qF -- '-o PreferredAuthentications=none' realm.sh
grep -q '确认落地机重装过、信任新的主机密钥？\[y/N\]' realm.sh
grep -q 'ControlMaster=yes -o ControlPersist=900' realm.sh
grep -q 'REALM_EXIT_RESULT=ok|' realm.sh
grep -q 'install|deploy) deploy_realm' realm.sh

echo "Realm validation passed."
