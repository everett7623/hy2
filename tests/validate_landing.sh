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
# remote_exit_* 会重新检测 init；CI runner 有真实 systemd，不得触发 systemctl。
detect_init() { INIT_SYS=none; }
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
grep -q '"mtu": 1280,' "$LANDING_CONFIG"
grep -q '"udp_fragment": true,' "$LANDING_CONFIG"
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
# direct 出站没有拨号选项时，detour 指向它会在拨号时报错（check 不报），WG 握手与 REALITY 握手全部失败。
! grep -q '"detour": "direct"' "$LANDING_CONFIG"
grep -q '"action": "resolve", "server": "exit-dns", "strategy": "ipv4_only"' "$LANDING_CONFIG"
grep -q '"action": "route", "outbound": "wg-out"' "$LANDING_CONFIG"
grep -q '"final": "direct"' "$LANDING_CONFIG"
! grep -q '"final": "wg-out"' "$LANDING_CONFIG"
grep -q '"default_domain_resolver": { "server": "local", "strategy": "prefer_ipv4" }' "$LANDING_CONFIG"
! grep -q '"listen_port": 47821' "$LANDING_CONFIG"
# WireGuard 套接字带 DF：外层包超过路径 MTU 即被静默丢弃，隧道 MTU 必须留足余量。
grep -q '"mtu": 1280,' "$LANDING_CONFIG"
! grep -q '"mtu": 1380' "$LANDING_CONFIG"
# udp_fragment 去掉 DF（与内核 WireGuard 一致），路径 MTU 更小时分片送达而不是丢弃。
grep -q '"udp_fragment": true,' "$LANDING_CONFIG"

# 旧线路机 final=wg-out 时，诊断/升级应改写为 final=direct + 入站显式走 wg-out。
cp "$LANDING_CONFIG" "$LANDING_CONFIG.good"
awk '{gsub(/"final": "direct"/, "\"final\": \"wg-out\"")}1' "$LANDING_CONFIG.good" > "$LANDING_CONFIG"
grep -q '"final": "wg-out"' "$LANDING_CONFIG"
service_is_active() { return 1; }
ensure_reality_handshake_direct >/dev/null
grep -q '"final": "direct"' "$LANDING_CONFIG"
grep -q '"action": "route", "outbound": "wg-out"' "$LANDING_CONFIG"
! grep -q '"detour": "direct"' "$LANDING_CONFIG"

# v2.0.47–v2.0.51 部署的线路机带 "detour": "direct"（握手 + WG 端点），诊断/升级必须去掉。
awk '
    { print }
    /"server_port": / && !h { print "            \"detour\": \"direct\","; h=1 }
' "$LANDING_CONFIG.good" | awk '
    /"persistent_keepalive_interval"/ { kp=1 }
    kp && /^      \]$/ { print "      ],"; print "      \"detour\": \"direct\""; kp=0; next }
    { print }
' > "$LANDING_CONFIG"
[ "$(grep -c '"detour": "direct"' "$LANDING_CONFIG")" = "2" ]
ensure_reality_handshake_direct >/dev/null
! grep -q '"detour": "direct"' "$LANDING_CONFIG"
grep -q '"final": "direct"' "$LANDING_CONFIG"
cmp -s "$LANDING_CONFIG" "$LANDING_CONFIG.good"

# v2.0.44–v2.0.54 部署的线路机隧道 MTU 为 1380：路径 MTU 偏小时只丢满尺寸包，
# Telegram 正常而网页打不开。诊断/升级只需改写线路机（隧道内 TCP 的 MSS 取两端较小值）。
sed 's/"mtu": 1280,/"mtu": 1380,/' "$LANDING_CONFIG.good" > "$LANDING_CONFIG"
grep -q '"mtu": 1380,' "$LANDING_CONFIG"
ensure_reality_handshake_direct >/dev/null
cmp -s "$LANDING_CONFIG" "$LANDING_CONFIG.good"
# v2.0.55 部署的线路机已是 MTU 1280 但没有 udp_fragment：同样补上。
grep -v '"udp_fragment": true,' "$LANDING_CONFIG.good" > "$LANDING_CONFIG"
grep -q '"mtu": 1280,' "$LANDING_CONFIG"
! grep -q '"udp_fragment"' "$LANDING_CONFIG"
ensure_reality_handshake_direct >/dev/null
cmp -s "$LANDING_CONFIG" "$LANDING_CONFIG.good"
# 已是当前模板时不重写、不输出。
[ -z "$(ensure_reality_handshake_direct)" ]
unset -f service_is_active
rm -f "${LANDING_CONFIG}.handshake.bak" "$LANDING_CONFIG.good"
# --- 隧道失败时展示线路机日志里的 WireGuard 报错（去掉颜色码） ---
# 只看本次运行：探测超时被取消的连接（context canceled）是噪音，不能当成原因展示。
service_logs_current() { printf '\033[31mERROR\033[0m endpoint/wireguard[wg-out]: peer(abc) - failed to send handshake initiation: detour to an empty direct outbound makes no sense\nINFO inbound/vless[vless-in]: started\nERROR connection: open connection to 1.1.1.1:443 using outbound/wireguard[wg-out]: context canceled\n'; }
_out=$(show_tunnel_errors)
printf '%s\n' "$_out" | grep -q 'failed to send handshake initiation: detour to an empty direct outbound'
! printf '%s\n' "$_out" | grep -q 'vless-in'
! printf '%s\n' "$_out" | grep -q 'context canceled'
! printf '%s\n' "$_out" | grep -q "$(printf '\033')"
# reverse 模式第一个探测包总比落地机的下一次握手先到：只报一次 no known endpoint 属正常，
# 不能据此提示“落地机一直没有连上”；落地机真连不上时，线路机每 5 秒重试都会再报一次。
_noep='ERROR endpoint/wireguard[wg-out]: peer(x) - failed to send handshake initiation: no known endpoint for peer'
service_logs_current() { echo "$_noep"; }
_out=$(show_tunnel_errors)
! printf '%s\n' "$_out" | grep -q '落地机一直没有连上本机'
printf '%s\n' "$_out" | grep -q '属正常'
service_logs_current() { printf '%s\n%s\n%s\n' "$_noep" "$_noep" "$_noep"; }
show_tunnel_errors | grep -q '落地机一直没有连上本机'
# 握手后落地机连不上探测站（隧道已通）：经 wg-out 的连接被拒绝
service_logs_current() { printf '%s\n%s\n' "$_noep" 'ERROR connection: open connection to 1.1.1.1:443 using outbound/wireguard[wg-out]: connect tcp 1.1.1.1:443: connection was refused'; }
_out=$(show_tunnel_errors)
printf '%s\n' "$_out" | grep -q '隧道已建立，但落地机连不上探测站'
! printf '%s\n' "$_out" | grep -q '落地机一直没有连上本机'
service_logs_current() { echo "暂无日志"; }
show_tunnel_errors | grep -q '握手包被防火墙'
unset -f service_logs_current
# systemd 下按 InvocationID 取本次运行的日志，而不是 journalctl -u 的历史尾部。
grep -q '_SYSTEMD_INVOCATION_ID=' landing.sh
grep -q 'systemctl show -p InvocationID --value landing-server' landing.sh

# --- DDNS 看门狗：sing-box 只在启动时解析一次落地机域名，家宽换 IP 后必须重启才能重连 ---
exit_host_is_domain home.example.com
! exit_host_is_domain 198.51.100.7
! exit_host_is_domain 2001:db8::7
! exit_host_is_domain ""
WATCHDOG_SCRIPT="$tmp/landing-watchdog.sh"
WATCHDOG_LOG="$tmp/landing-watchdog.log"
CRONTAB_FILE="$tmp/crontab"
crontab() { if [ "${1:-}" = "-l" ]; then cat "$CRONTAB_FILE" 2>/dev/null; else cat > "$CRONTAB_FILE"; fi; }
shim="$tmp/shim"; mkdir -p "$shim"
cat > "$shim/getent" <<'EOF'
#!/bin/sh
[ -s "$WD_DNS" ] || exit 2
while read -r a; do printf '%s STREAM %s\n%s DGRAM\n' "$a" "$2" "$a"; done < "$WD_DNS"
EOF
cat > "$shim/systemctl" <<'EOF'
#!/bin/sh
echo "$*" >> "$WD_CALLS"
exit 0
EOF
chmod +x "$shim/getent" "$shim/systemctl"
export WD_DNS="$tmp/wd-dns" WD_CALLS="$tmp/wd-calls"
printf '198.51.100.7\n' > "$WD_DNS"
: > "$WD_CALLS"
_saved_path="$PATH"
INIT_SYS=systemd
PATH="$shim:$PATH" ensure_exit_watchdog quiet
INIT_SYS=none
[ -x "$WATCHDOG_SCRIPT" ]
sh -n "$WATCHDOG_SCRIPT"
grep -qF "*/2 * * * * $WATCHDOG_SCRIPT" "$CRONTAB_FILE"
[ "$(cat "$LANDING_META/exit_resolved")" = "home.example.com 198.51.100.7" ]
[ ! -s "$WD_CALLS" ]
PATH="$shim:$PATH" sh "$WATCHDOG_SCRIPT"
[ ! -s "$WD_CALLS" ]
# 解析失败不重启
: > "$WD_DNS"
PATH="$shim:$PATH" sh "$WATCHDOG_SCRIPT"
[ ! -s "$WD_CALLS" ]
[ "$(cat "$LANDING_META/exit_resolved")" = "home.example.com 198.51.100.7" ]
# 家宽换 IP：重启一次并记录
printf '198.51.100.9\n' > "$WD_DNS"
PATH="$shim:$PATH" sh "$WATCHDOG_SCRIPT"
grep -qx 'restart landing-server' "$WD_CALLS"
[ "$(grep -c '^restart' "$WD_CALLS")" = 1 ]
grep -q '198.51.100.7 -> 198.51.100.9' "$WATCHDOG_LOG"
PATH="$shim:$PATH" sh "$WATCHDOG_SCRIPT"
[ "$(grep -c '^restart' "$WD_CALLS")" = 1 ]
# 落地机地址被修改后的首次解析只记录，不重启
awk '{ sub(/^EXIT_HOST=.*/, "EXIT_HOST=ddns.example.net") } 1' "$LANDING_META/config.env" > "$tmp/env" && cat "$tmp/env" > "$LANDING_META/config.env"
PATH="$shim:$PATH" sh "$WATCHDOG_SCRIPT"
[ "$(grep -c '^restart' "$WD_CALLS")" = 1 ]
[ "$(cat "$LANDING_META/exit_resolved")" = "ddns.example.net 198.51.100.9" ]
write_meta
# 改回 IP 地址：看门狗与定时任务一并移除
EXIT_HOST=198.51.100.7
ensure_exit_watchdog quiet
[ ! -e "$WATCHDOG_SCRIPT" ]
! grep -qF "$WATCHDOG_SCRIPT" "$CRONTAB_FILE"
[ ! -e "$LANDING_META/exit_resolved" ]
EXIT_HOST=home.example.com
PATH="$_saved_path"
unset WD_DNS WD_CALLS

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

# --- reverse 模式：落地机主动拨号线路机，落地机无需入站端口 ---
_saved_fns=$(declare -f tcp_port_is_listening udp_port_is_listening service_is_active close_ports 2>/dev/null || true)
restore_fns() { unset -f tcp_port_is_listening udp_port_is_listening service_is_active close_ports; eval "$_saved_fns"; }
cp "$LANDING_CONFIG" "$tmp/fwd-relay.json"; cp "$LANDING_META/config.env" "$tmp/fwd-relay.env"
WG_MODE=reverse; RELAY_HOST=192.0.2.10; WG_PORT=52011
write_config
grep -q '"listen_port": 52011' "$LANDING_CONFIG"
! grep -q '"address": "home.example.com"' "$LANDING_CONFIG"
! grep -q '"persistent_keepalive_interval"' "$LANDING_CONFIG"
grep -q '"allowed_ips": \["0.0.0.0/0", "::/0"\]' "$LANDING_CONFIG"
! grep -q '"detour": "direct"' "$LANDING_CONFIG"
if [ -n "${REAL_SING_BOX_BIN:-}" ]; then "$REAL_SING_BOX_BIN" check -c "$LANDING_CONFIG"; fi
write_meta
reset_config_vars; read_config
[ "$WG_MODE" = reverse ] && [ "$RELAY_HOST" = 192.0.2.10 ] && [ "$WG_PORT" = 52011 ]
# reverse 线路机健康检查还要求 UDP 端口在监听
tcp_port_is_listening() { return 0; }
udp_port_is_listening() { [ "$1" = 52011 ]; }
service_is_active() { return 0; }
service_is_healthy
udp_port_is_listening() { return 1; }
! service_is_healthy
# 关闭端口时 reverse 线路机要同时关闭 TCP 节点端口与 UDP 隧道端口
_closed=""
close_ports() { _closed="${_closed}${1}/${2} "; }
close_role_ports
[ "$_closed" = "34567/tcp 52011/udp " ]
# 看门狗只服务 forward 模式；reverse 下必须移除
WATCHDOG_SCRIPT="$tmp/landing-watchdog.sh"; CRONTAB_FILE="$tmp/crontab"
crontab() { if [ "${1:-}" = "-l" ]; then cat "$CRONTAB_FILE" 2>/dev/null; else cat > "$CRONTAB_FILE"; fi; }
printf '*/2 * * * * %s >/dev/null 2>&1\n' "$WATCHDOG_SCRIPT" > "$CRONTAB_FILE"; : > "$WATCHDOG_SCRIPT"
EXIT_HOST=home.example.com ensure_exit_watchdog quiet
[ ! -e "$WATCHDOG_SCRIPT" ]
! grep -qF "$WATCHDOG_SCRIPT" "$CRONTAB_FILE"
unset -f crontab
restore_fns

# 落地机 reverse：不监听端口，peer 指向线路机并保持心跳
reset_config_vars
ROLE=exit; WG_MODE=reverse; RELAY_HOST=192.0.2.10; WG_PORT=52011
WG_PRIVATE_KEY="$TEST_WG_PRIV_B"; WG_PUBLIC_KEY="$TEST_WG_PUB_B"
WG_PEER_PUBLIC_KEY="$TEST_WG_PUB_A"; WG_PSK="$TEST_WG_PSK"; EXIT_IPV4=198.51.100.7; EXIT_HAS_IPV6=0
LANDING_CONFIG="$tmp/exit-rev.json"
write_exit_config
! grep -q '"listen_port"' "$LANDING_CONFIG"
grep -q '"address": "192.0.2.10"' "$LANDING_CONFIG"
grep -q '"port": 52011' "$LANDING_CONFIG"
grep -q '"persistent_keepalive_interval": 25' "$LANDING_CONFIG"
grep -q '"allowed_ips": \["10.233.0.2/32", "fdcc:233::2/128"\]' "$LANDING_CONFIG"
if [ -n "${REAL_SING_BOX_BIN:-}" ]; then "$REAL_SING_BOX_BIN" check -c "$LANDING_CONFIG"; fi
service_is_active() { return 0; }
udp_port_is_listening() { return 1; }
service_is_healthy
restore_fns
LANDING_CONFIG="$LANDING_DIR/landing.json"

# 对接参数：reverse 必须带合法端口与线路机 IP
printf 'RELAY_PUBLIC_KEY=%s\nWG_PSK=%s\nWG_PORT=52011\nWG_MODE=reverse\nRELAY_HOST=192.0.2.10\n' "$TEST_WG_PUB_A" "$TEST_WG_PSK" > "$stage/params"
read_remote_params "$stage"
[ "$REMOTE_PARAM_WG_MODE" = reverse ] && [ "$REMOTE_PARAM_RELAY_HOST" = 192.0.2.10 ]
printf 'RELAY_PUBLIC_KEY=%s\nWG_PSK=%s\nWG_PORT=52011\nWG_MODE=reverse\nRELAY_HOST=evil;id\n' "$TEST_WG_PUB_A" "$TEST_WG_PSK" > "$stage/params"
! read_remote_params "$stage"
printf 'RELAY_PUBLIC_KEY=%s\nWG_PSK=%s\nWG_MODE=reverse\nRELAY_HOST=192.0.2.10\n' "$TEST_WG_PUB_A" "$TEST_WG_PSK" > "$stage/params"
! read_remote_params "$stage"
printf 'RELAY_PUBLIC_KEY=%s\nWG_PSK=%s\nWG_MODE=sideways\n' "$TEST_WG_PUB_A" "$TEST_WG_PSK" > "$stage/params"
! read_remote_params "$stage"
_params=$(WG_PUBLIC_KEY="$TEST_WG_PUB_A" WG_PSK="$TEST_WG_PSK" AUTO_UPDATE=1 REQUESTED_WG_PORT=52011 WG_MODE=reverse RELAY_HOST=192.0.2.10 write_remote_params)
grep -qx 'WG_MODE=reverse' "$_params" && grep -qx 'RELAY_HOST=192.0.2.10' "$_params"
rm -f "$_params"

# 旧版本元数据没有 WG_MODE 时按 forward 读取，原部署行为不变
cp "$tmp/fwd-relay.json" "$LANDING_DIR/landing.json"
grep -v '^WG_MODE=\|^RELAY_HOST=' "$tmp/fwd-relay.env" > "$LANDING_META/config.env"
reset_config_vars; read_config
[ "$WG_MODE" = forward ] && [ "$WG_PORT" = 47821 ] && [ "$EXIT_HOST" = home.example.com ]
write_config
grep -q '"address": "home.example.com"' "$LANDING_CONFIG"
grep -q '"port": 47821' "$LANDING_CONFIG"
! grep -q '"listen_port"' "$LANDING_CONFIG"
cmp -s "$LANDING_CONFIG" "$tmp/fwd-relay.json"
write_meta

# --- 客户端导出 ---
_uri=$(render_uri 192.0.2.10 34567 "$UUID" 'test node')
printf '%s\n' "$_uri" | grep -q "^vless://${TEST_UUID}@192.0.2.10:34567?"
printf '%s\n' "$_uri" | grep -q 'flow=xtls-rprx-vision&security=reality&sni=www.apple.com'
printf '%s\n' "$_uri" | grep -q "pbk=${TEST_REALITY_PUB}&sid=${TEST_SHORT_ID}"
export_mihomo_vless 192.0.2.10 34567 'node' | grep -q "reality-opts: {public-key: '${TEST_REALITY_PUB}'"
[ "$(generate_node_name US relay VLESS-Landing IPv4)" = '🇺🇸 US | relay | VLESS-Landing | IPv4' ]

# --- 出口验证 ---
# Cloudflare trace 取 ip= 行；http://1.1.1.1 返回的 301 跳转页取不到地址（v2.0.52–v2.0.53 的根因）。
[ "$(printf 'fl=1f1\nh=1.1.1.1\nip=198.51.100.7\nts=1.0\n' | extract_probe_ip)" = 198.51.100.7 ]
[ "$(printf '198.51.100.7\n' | extract_probe_ip)" = 198.51.100.7 ]
! is_valid_ipv4 "$(printf '<html>\n<head><title>301 Moved Permanently</title></head>\n' | extract_probe_ip)"
for _url in $TUNNEL_IP_PROBE_URLS; do
    case "$_url" in https://*) ;; *) false ;; esac
done
PUBLIC_IP=192.0.2.10
# 真实 probe_via_tunnel：带填充参数时附加等长请求头（dd 生成，不用非 POSIX 的 head -c），不带时不附加。
curl() { printf '%s\n' "$@" > "$tmp/curl-args"; printf 'ip=198.51.100.7\n'; }
[ "$(probe_via_tunnel https://1.1.1.1/cdn-cgi/trace)" = 198.51.100.7 ]
! grep -q '^X-Pad:' "$tmp/curl-args"
[ "$(probe_via_tunnel https://1.1.1.1/cdn-cgi/trace "$TUNNEL_PAD_BYTES")" = 198.51.100.7 ]
grep -qx -- '-H' "$tmp/curl-args"
[ "$(awk '/^X-Pad: a+$/ { print length($0) }' "$tmp/curl-args")" = $((7 + TUNNEL_PAD_BYTES)) ]
grep -qxF 'https://1.1.1.1/cdn-cgi/trace' "$tmp/curl-args"
unset -f curl
probe_via_tunnel() { printf '198.51.100.7'; }
sleep() { :; }
verify_exit_egress 2 >/dev/null
[ "$LAST_EGRESS_IP" = 198.51.100.7 ]
# 落地机所在网络屏蔽字面量探测站与部分域名站时，轮换到可用站点仍判定通过，且已验证 DNS 路径。
# probe_via_tunnel 在 $(...) 子 shell 中执行，调用记录只能写文件。
probe_via_tunnel() {
    printf '%s\n' "$1${2:+ pad=$2}" >> "$tmp/probed"
    case "$1" in
        *amazonaws*) printf '198.51.100.7' ;;
        *) return 1 ;;
    esac
}
: > "$tmp/probed"
verify_exit_egress 4 >/dev/null
[ "$LAST_EGRESS_IP" = 198.51.100.7 ]
grep -qxF 'https://1.1.1.1/cdn-cgi/trace' "$tmp/probed"
grep -qxF 'https://1.0.0.1/cdn-cgi/trace' "$tmp/probed"
[ "$(grep -cxF 'https://checkip.amazonaws.com' "$tmp/probed")" = 1 ]
# 大包复测用刚才成功的同一探测站，只差请求大小。
grep -qxF "https://checkip.amazonaws.com pad=${TUNNEL_PAD_BYTES}" "$tmp/probed"
[ "$(grep -c 'pad=' "$tmp/probed")" = 1 ]
: > "$tmp/probed"
! verify_exit_egress 3 >/dev/null
! grep -q amazonaws "$tmp/probed"
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
# MTU 黑洞：小请求全部成功、带大请求头的全部超时。v2.0.54 及以前会判通过，
# 部署出 Telegram 能用、网页与 YouTube 打不开的节点；现在必须判失败并提示 MTU。
probe_via_tunnel() { [ -z "${2:-}" ] && printf '198.51.100.7'; }
! verify_exit_egress 2 >/dev/null
[ -z "$LAST_EGRESS_IP" ]
verify_exit_egress 2 | grep -q '大包不通'
# 大包偶发丢一次（重试成功）不能误判。
: > "$tmp/big"
probe_via_tunnel() {
    if [ -n "${2:-}" ]; then
        printf 'x\n' >> "$tmp/big"
        [ "$(grep -c . "$tmp/big")" -ge 2 ] || return 1
    fi
    printf '198.51.100.7'
}
verify_exit_egress 2 >/dev/null
[ "$LAST_EGRESS_IP" = 198.51.100.7 ]
[ "$(grep -c . "$tmp/big")" = 2 ]
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
