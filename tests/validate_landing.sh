#!/bin/bash
set -eu
trap 'echo "Landing validation failed at line $LINENO" >&2' ERR

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

LANDING_LIB_ONLY=1 . ./landing.sh

# 测试专用的固定样例值，不对应任何真实节点。
TEST_WG_PRIV_A=eDbcGmRqRmUAXr1dKsq4TzD9IK6P1BgLgrFfAMWIUlE=
TEST_WG_PUB_A=5bIhfI0vLyiInZp5xlJCbr4ekQdOSU/+VKtlNfOn6Cg=
TEST_WG_PRIV_B=QLRo8qDZOlRf1SYDBVdmkOEYDsSf1Lqg2X7xuOpDHlg=
TEST_WG_PUB_B=KWYwSnn9qJJbUyNRV8qp+ZnTJ6bqCJUqtYPOcgYPKkE=
TEST_WG_PSK=jK3vB0J1m3x7Rz+o3lYc0n4q9q6l9Q3c8Tf2tWw8Ab0=
TEST_UUID=bf000d23-0752-40b4-affe-68f7707a9661
TEST_REALITY_PRIV=UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc
TEST_REALITY_PUB=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
TEST_SHORT_ID=0123456789abcdef
TEST_PROBE_USER=0123456789abcdef0123456789abcdef
TEST_PROBE_PASS=fedcba9876543210fedcba9876543210

check_root() { :; }

# --- 输入校验 ---
validate_wg_key "$TEST_WG_PRIV_A"
validate_wg_key "$TEST_WG_PUB_B"
validate_wg_key "$TEST_WG_PSK"
! validate_wg_key "${TEST_WG_PUB_B%=}"
! validate_wg_key "${TEST_WG_PUB_B}x"
! validate_wg_key 'KWYwSnn9qJJbUyNRV8qp-ZnTJ6bqCJUqtYPOcgYPKkE='
validate_exit_host 192.0.2.8
validate_exit_host 2001:db8::8
validate_exit_host home.example.com
! validate_exit_host '-oProxyCommand=sh'
! validate_exit_host 'a b.example.com'
! validate_exit_host 'home.example.com;id'
! validate_exit_host '192.0.2.8:22'
! validate_exit_host ''
validate_ssh_user root
validate_ssh_user deploy_user
! validate_ssh_user 'root;id'
! validate_ssh_user '-l'
validate_probe_secret "$TEST_PROBE_USER"
! validate_probe_secret 'short'
! validate_probe_secret 'ABCDEF0123456789'
is_valid_remote_stage_dir /tmp/landing-remote.Ab12Cd
! is_valid_remote_stage_dir /tmp/landing-remote.
! is_valid_remote_stage_dir '/tmp/landing-remote.x; rm -rf /'
! is_valid_remote_stage_dir /root/landing-remote.abc

# --- 密钥生成（模拟 sing-box 输出） ---
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
SING_BOX_BIN="$tmp/sing-box"
cat > "$SING_BOX_BIN" <<EOF
#!/bin/sh
case "\$1 \$2" in
    'generate wg-keypair') printf 'PrivateKey: %s\nPublicKey: %s\n' '$TEST_WG_PRIV_A' '$TEST_WG_PUB_A' ;;
    'generate rand') printf '%s\n' '$TEST_WG_PSK' ;;
    'check -c') exit 0 ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$SING_BOX_BIN"
WG_PRIVATE_KEY=""; WG_PUBLIC_KEY=""
generate_wg_keypair
[ "$WG_PRIVATE_KEY" = "$TEST_WG_PRIV_A" ]
[ "$WG_PUBLIC_KEY" = "$TEST_WG_PUB_A" ]
[ "$(generate_wg_psk)" = "$TEST_WG_PSK" ]
_secret=$(generate_probe_secret)
validate_probe_secret "$_secret"

# --- 落地机回传结果解析 ---
_output=$(printf '%s\n' 'noise' "LANDING_EXIT_RESULT=bad" "LANDING_EXIT_RESULT=${TEST_WG_PUB_B}|47821|198.51.100.7|1")
[ "$(printf '%s\n' "$_output" | parse_remote_result)" = "${TEST_WG_PUB_B}|47821|198.51.100.7|1" ]
apply_remote_result "${TEST_WG_PUB_B}|47821|198.51.100.7|1"
[ "$WG_PEER_PUBLIC_KEY" = "$TEST_WG_PUB_B" ]
[ "$WG_PORT" = 47821 ]
[ "$EXIT_IPV4" = 198.51.100.7 ]
[ "$EXIT_HAS_IPV6" = 1 ]
! apply_remote_result ""
! apply_remote_result "${TEST_WG_PUB_B}|0|198.51.100.7|1"
! apply_remote_result "${TEST_WG_PUB_B}|47821|999.1.1.1|0"
! apply_remote_result "${TEST_WG_PUB_B}|47821|198.51.100.7|2"
! apply_remote_result "not-a-key|47821|198.51.100.7|0"

# --- 对接参数文件：只接受合法密钥，读后立即删除 ---
stage="$tmp/stage"
mkdir -p "$stage"
printf 'RELAY_PUBLIC_KEY=%s\nWG_PSK=%s\nAUTO_UPDATE=0\n' "$TEST_WG_PUB_A" "$TEST_WG_PSK" > "$stage/params"
read_remote_params "$stage"
[ "$REMOTE_PARAM_PUBLIC_KEY" = "$TEST_WG_PUB_A" ]
[ "$REMOTE_PARAM_PSK" = "$TEST_WG_PSK" ]
[ "$REMOTE_PARAM_AUTO_UPDATE" = 0 ]
[ -z "$REMOTE_PARAM_WG_PORT" ]
[ ! -e "$stage/params" ]
printf 'RELAY_PUBLIC_KEY=%s\nWG_PSK=%s\nWG_PORT=51888\n' "$TEST_WG_PUB_A" "$TEST_WG_PSK" > "$stage/params"
read_remote_params "$stage"
[ "$REMOTE_PARAM_WG_PORT" = 51888 ]
printf 'RELAY_PUBLIC_KEY=%s\nWG_PSK=%s\nWG_PORT=70000\n' "$TEST_WG_PUB_A" "$TEST_WG_PSK" > "$stage/params"
! read_remote_params "$stage"
printf 'RELAY_PUBLIC_KEY=bad\nWG_PSK=%s\n' "$TEST_WG_PSK" > "$stage/params"
! read_remote_params "$stage"
! read_remote_params "$stage"

_params=$(WG_PUBLIC_KEY="$TEST_WG_PUB_A" WG_PSK="$TEST_WG_PSK" AUTO_UPDATE=1 REQUESTED_WG_PORT=51888 write_remote_params)
grep -qx "RELAY_PUBLIC_KEY=${TEST_WG_PUB_A}" "$_params"
grep -qx "WG_PSK=${TEST_WG_PSK}" "$_params"
grep -qx "WG_PORT=51888" "$_params"
! grep -q 'PRIVATE' "$_params"
rm -f "$_params"

# --- 配置生成：落地机（exit） ---
LANDING_DIR="$tmp/etc-sing-box"
LANDING_CONFIG="$LANDING_DIR/landing.json"
LANDING_META="$LANDING_DIR/landing-meta"
LANDING_PENDING_DIR="$LANDING_DIR/landing-pending"
SING_BOX_MANAGED_MARKER="$LANDING_DIR/.singbox-tools-managed"
LANDING_BIN="$tmp/landing-server"
SYSTEMD_SERVICE="$tmp/landing-server.service"
OPENRC_SERVICE="$tmp/landing-server.openrc"
AUTO_UPDATE_SCRIPT="$tmp/landing-autoupdate.sh"
AUTO_UPDATE_LOG="$tmp/landing-autoupdate.log"
INIT_SYS=none

reset_config_vars
ROLE=exit
WG_PRIVATE_KEY="$TEST_WG_PRIV_B"; WG_PUBLIC_KEY="$TEST_WG_PUB_B"
WG_PEER_PUBLIC_KEY="$TEST_WG_PUB_A"; WG_PSK="$TEST_WG_PSK"; WG_PORT=47821
EXIT_IPV4=198.51.100.7; EXIT_HAS_IPV6=0
PUBLIC_IP=198.51.100.7; PUBLIC_IPV6=""
write_config
write_meta
grep -q '"type": "wireguard"' "$LANDING_CONFIG"
grep -q '"listen_port": 47821' "$LANDING_CONFIG"
grep -q "\"private_key\": \"${TEST_WG_PRIV_B}\"" "$LANDING_CONFIG"
grep -q "\"public_key\": \"${TEST_WG_PUB_A}\"" "$LANDING_CONFIG"
grep -q "\"pre_shared_key\": \"${TEST_WG_PSK}\"" "$LANDING_CONFIG"
grep -q '"allowed_ips": \["10.233.0.2/32", "fdcc:233::2/128"\]' "$LANDING_CONFIG"
grep -q '"system": false' "$LANDING_CONFIG"
grep -q '"action": "hijack-dns"' "$LANDING_CONFIG"
grep -q '"ip_is_private": true, "action": "reject"' "$LANDING_CONFIG"
grep -q '"default_domain_resolver": "local"' "$LANDING_CONFIG"
! grep -q '"inbounds"' "$LANDING_CONFIG"
[ "$(stat -c %a "$LANDING_CONFIG" 2>/dev/null || echo 600)" = 600 ]
[ "$(stat -c %a "$LANDING_META/config.env" 2>/dev/null || echo 600)" = 600 ]

# 元数据回读必须保留 WireGuard 密钥末尾的 =。
WG_PRIVATE_KEY=""; WG_PSK=""; ROLE=""
read_config
[ "$ROLE" = exit ]
[ "$WG_PRIVATE_KEY" = "$TEST_WG_PRIV_B" ]
[ "$WG_PSK" = "$TEST_WG_PSK" ]
[ "$WG_PEER_PUBLIC_KEY" = "$TEST_WG_PUB_A" ]
[ "$(installed_role)" = exit ]
[ "$(role_port)" = 47821 ]
[ "$(role_proto)" = udp ]

if [ -n "${REAL_SING_BOX_BIN:-}" ]; then
    "$REAL_SING_BOX_BIN" check -c "$LANDING_CONFIG"
fi

# --- 两阶段提交：abort 恢复旧配置，无旧配置则清理 ---
service_stop() { :; }
service_start() { :; }
service_disable() { :; }
service_is_active() { return 1; }
close_ports() { :; }
wait_for_health() { return 0; }
stage_pending_rollback
[ -f "$LANDING_PENDING_DIR/config" ]
cp "$LANDING_CONFIG" "$tmp/exit-original.json"
sed -i 's/47821/40000/' "$LANDING_CONFIG"
sed -i 's/^WG_PORT=47821$/WG_PORT=40000/' "$LANDING_META/config.env"
remote_exit_abort >/dev/null
cmp -s "$LANDING_CONFIG" "$tmp/exit-original.json"
grep -qx 'WG_PORT=47821' "$LANDING_META/config.env"
[ ! -d "$LANDING_PENDING_DIR" ]
stage_pending_rollback
remote_exit_commit >/dev/null
[ ! -d "$LANDING_PENDING_DIR" ]

# 落地机拒绝被当作线路机卸载，反之亦然。
remote_exit_status() { :; }
sed -i 's/^ROLE=exit$/ROLE=relay/' "$LANDING_META/config.env"
! remote_exit_uninstall >/dev/null 2>&1
[ -f "$LANDING_CONFIG" ]
sed -i 's/^ROLE=relay$/ROLE=exit/' "$LANDING_META/config.env"

# 没有 pending 时 abort 等于卸载；共享核心还被其他协议使用时必须保留。
: > "$SING_BOX_MANAGED_MARKER"
printf '{}\n' > "$LANDING_DIR/vless.json"
remote_exit_abort >/dev/null
[ ! -f "$LANDING_CONFIG" ]
[ ! -d "$LANDING_META" ]
[ -x "$SING_BOX_BIN" ]
[ -f "$LANDING_DIR/vless.json" ]
[ -f "$SING_BOX_MANAGED_MARKER" ]
rm -f "$LANDING_DIR/vless.json"

# --- 配置生成：线路机（relay） ---
reset_config_vars
ROLE=relay
LISTEN_PORT=34567; EXT_PORT=34567; LISTEN_HOST="::"; BIND_FAMILY=v4; NAT_MODE=0
UUID="$TEST_UUID"; REALITY_PRIVATE_KEY="$TEST_REALITY_PRIV"; REALITY_PUBLIC_KEY="$TEST_REALITY_PUB"
SHORT_ID="$TEST_SHORT_ID"; SERVER_NAME=www.apple.com; HANDSHAKE_PORT=443
WG_PRIVATE_KEY="$TEST_WG_PRIV_A"; WG_PUBLIC_KEY="$TEST_WG_PUB_A"
WG_PEER_PUBLIC_KEY="$TEST_WG_PUB_B"; WG_PSK="$TEST_WG_PSK"; WG_PORT=47821
EXIT_HOST=home.example.com; EXIT_IPV4=198.51.100.7; EXIT_HAS_IPV6=0
SSH_PORT=2222; SSH_USER=root
PROBE_PORT=45678; PROBE_USER="$TEST_PROBE_USER"; PROBE_PASS="$TEST_PROBE_PASS"
PUBLIC_IP=192.0.2.10; PUBLIC_IPV6=""
write_config
write_meta
grep -q '"type": "vless"' "$LANDING_CONFIG"
grep -q '"flow": "xtls-rprx-vision"' "$LANDING_CONFIG"
grep -q '"listen_port": 34567' "$LANDING_CONFIG"
grep -q '"tag": "probe-in"' "$LANDING_CONFIG"
grep -q '"listen": "127.0.0.1"' "$LANDING_CONFIG"
grep -q '"address": "home.example.com"' "$LANDING_CONFIG"
grep -q '"port": 47821' "$LANDING_CONFIG"
grep -q '"allowed_ips": \["0.0.0.0/0", "::/0"\]' "$LANDING_CONFIG"
grep -q '"persistent_keepalive_interval": 25' "$LANDING_CONFIG"
grep -q '"server": "10.233.0.1", "detour": "wg-out"' "$LANDING_CONFIG"
grep -q '"action": "resolve", "server": "exit-dns", "strategy": "ipv4_only"' "$LANDING_CONFIG"
grep -q '"final": "wg-out"' "$LANDING_CONFIG"
grep -q '"default_domain_resolver": { "server": "local", "strategy": "prefer_ipv4" }' "$LANDING_CONFIG"
! grep -q '"listen_port": 47821' "$LANDING_CONFIG"
! grep -q 'bind_interface' "$LANDING_CONFIG"
if [ -n "${REAL_SING_BOX_BIN:-}" ]; then
    "$REAL_SING_BOX_BIN" check -c "$LANDING_CONFIG"
fi

# 落地机有 IPv6 时线路机按 prefer_ipv4 解析；纯 IPv6 线路机本地解析优先 IPv6。
EXIT_HAS_IPV6=1; BIND_FAMILY=v6
write_config
grep -q '"action": "resolve", "server": "exit-dns", "strategy": "prefer_ipv4"' "$LANDING_CONFIG"
grep -q '"strategy": "ipv6_only"' "$LANDING_CONFIG"
grep -q '"default_domain_resolver": { "server": "local", "strategy": "prefer_ipv6" }' "$LANDING_CONFIG"
EXIT_HAS_IPV6=0; BIND_FAMILY=v4
write_config
write_meta

reset_config_vars
read_config
[ "$ROLE" = relay ]
[ "$EXIT_HOST" = home.example.com ]
[ "$SSH_PORT" = 2222 ]
[ "$WG_PSK" = "$TEST_WG_PSK" ]
[ "$WG_PEER_PUBLIC_KEY" = "$TEST_WG_PUB_B" ]
[ "$(role_proto)" = tcp ]
[ "$(role_port)" = 34567 ]

# 元数据被篡改为非法地址时必须拒绝加载，不能把注入内容带进 ssh 命令行。
cp "$LANDING_META/config.env" "$tmp/relay-meta.bak"
sed -i 's/^EXIT_HOST=.*/EXIT_HOST=-oProxyCommand=id/' "$LANDING_META/config.env"
! read_config
cp "$tmp/relay-meta.bak" "$LANDING_META/config.env"
read_config

# --- 客户端导出 ---
_uri=$(render_uri 192.0.2.10 34567 "$UUID" 'test node')
printf '%s\n' "$_uri" | grep -q "^vless://${TEST_UUID}@192.0.2.10:34567?"
printf '%s\n' "$_uri" | grep -q 'flow=xtls-rprx-vision&security=reality&sni=www.apple.com'
printf '%s\n' "$_uri" | grep -q "pbk=${TEST_REALITY_PUB}&sid=${TEST_SHORT_ID}"
export_mihomo_vless 192.0.2.10 34567 'node' | grep -q "reality-opts: {public-key: '${TEST_REALITY_PUB}'"
[ "$(generate_node_name US relay VLESS-Landing IPv4)" = '🇺🇸 US | relay | VLESS-Landing | IPv4' ]

# --- 出口验证 ---
PUBLIC_IP=192.0.2.10
probe_via_tunnel() { printf '198.51.100.7'; }
sleep() { :; }
verify_exit_egress 2 >/dev/null
[ "$LAST_EGRESS_IP" = 198.51.100.7 ]
probe_via_tunnel() { printf '192.0.2.10'; }
! verify_exit_egress 2 >/dev/null
probe_via_tunnel() { return 1; }
! verify_exit_egress 2 >/dev/null
probe_via_tunnel() {
    case "$1" in
        *1.1.1.1*) printf '198.51.100.7' ;;
        *) return 1 ;;
    esac
}
! verify_exit_egress 2 >/dev/null
unset -f sleep

# --- 卸载：线路机，共享核心无其他使用者时随最后一个协议移除 ---
: > "$SING_BOX_MANAGED_MARKER"
MANAGED_SING_BOX=1
uninstall_landing_files
[ ! -f "$LANDING_CONFIG" ]
[ ! -f "$SING_BOX_BIN" ]
[ ! -d "$LANDING_DIR" ]

# --- 静态约束 ---
grep -q '^\[ "\$_LANDING_LIB_ONLY" = "1" \] && return 0' landing.sh
grep -q 'case "${1:-}" in' landing.sh
grep -q -- '--remote-\*|--upgrade-noninteractive) LANDING_HEADLESS=1 ;;' landing.sh
grep -q 'StrictHostKeyChecking=accept-new' landing.sh
grep -q 'ControlMaster=yes -o ControlPersist=900' landing.sh
grep -q 'BatchMode=yes' landing.sh
! grep -q 'StrictHostKeyChecking=no' landing.sh
! grep -qE 'sshpass|PasswordAuthentication=yes' landing.sh
! grep -qE 'net.ipv4.ip_forward|MASQUERADE|wg-quick' landing.sh
grep -q '47 4 \* \* 1 \$AUTO_UPDATE_SCRIPT' landing.sh
grep -q 'shared_service_restart vless-server /usr/local/bin/vless-server' landing.sh
grep -q 'shared_service_restart anytls-server /usr/local/bin/anytls-server' landing.sh
grep -q 'shared_service_restart proxy-server /usr/local/bin/proxy-server' landing.sh

echo "Landing validation passed."
