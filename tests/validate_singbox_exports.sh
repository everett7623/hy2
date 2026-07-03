#!/bin/bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

(
    EXPORT_LIB_ONLY=1
    . ./hy2.sh
    [ "$(generate_node_name JP test Hysteria2 IPv4)" = '🇯🇵 JP | test | Hysteria2 | IPv4' ]
    PASSWORD='hy2-password'; SNI='example.com'; BW_UP=50; BW_DOWN=100
    export_singbox_hy2 '192.0.2.1' 443 '🇯🇵 JP | test | Hysteria2 | IPv4'
) > "$tmp/hy2.json"

(
    EXPORT_LIB_ONLY=1
    . ./ss.sh
    [ "$(generate_node_name JP test Shadowsocks IPv4)" = '🇯🇵 JP | test | Shadowsocks | IPv4' ]
    PASSWORD='ss-password'; METHOD='aes-256-gcm'
    export_singbox_ss '192.0.2.2' 8388 '🇯🇵 JP | test | Shadowsocks | IPv4'
) > "$tmp/ss.json"

(
    ANYTLS_LIB_ONLY=1
    . ./anytls.sh
    [ "$(generate_node_name JP test AnyTLS IPv4)" = '🇯🇵 JP | test | AnyTLS | IPv4' ]
    [ "$(generate_node_name UN test AnyTLS IPv4)" = '🌐 UN | test | AnyTLS | IPv4' ]
    render_singbox_client_config '192.0.2.3' 8443 'anytls-password' \
        '🇯🇵 JP | test | AnyTLS | IPv4' 'addons.mozilla.org' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
) > "$tmp/anytls.json"

(
    EXPORT_LIB_ONLY=1
    . ./euservhy2.sh
    [ "$(generate_node_name JP test EUserv-HY2 IPv6)" = '🇯🇵 JP | test | EUserv-HY2 | IPv6' ]
    HY2_CONFIG_DIR="$tmp/euserv"
    LOG_FILE="$tmp/euserv.log"
    mkdir -p "$HY2_CONFIG_DIR"
    cat > "$HY2_CONFIG_DIR/node.conf" <<'EOF'
NODE_PORT=8443
NODE_PASSWORD=euserv-password
NODE_DOMAIN=example.com
EOF
    _get_real_ipv6() { echo '2001:db8::1'; }
    get_node_name() { echo 'test'; }
    get_country_code() { echo 'JP'; }
    get_country_name() { echo 'Japan'; }
    generate_terminal_qrcode() { return 1; }
    generate_online_qrcode_url() { echo 'unused'; }
    show_node_info
) | awk '
    /^{$/ { capture=1 }
    capture { print }
    capture && /^}$/ { exit }
' > "$tmp/euserv.json"

PYTHON_BIN=""
command -v python3 >/dev/null 2>&1 && python3 -c 'import json' >/dev/null 2>&1 && PYTHON_BIN=python3
[ -n "$PYTHON_BIN" ] || { command -v python >/dev/null 2>&1 && python -c 'import json' >/dev/null 2>&1 && PYTHON_BIN=python; }
[ -n "$PYTHON_BIN" ] || { echo "Python is required for JSON validation" >&2; exit 1; }

"$PYTHON_BIN" - "$tmp" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected_types = {
    "hy2.json": "hysteria2",
    "ss.json": "shadowsocks",
    "anytls.json": "anytls",
    "euserv.json": "hysteria2",
}
expected_tags = {
    "hy2.json": "hysteria2",
    "ss.json": "shadowsocks",
    "anytls.json": "anytls",
    "euserv.json": "hysteria2",
}

for filename, outbound_type in expected_types.items():
    with (root / filename).open(encoding="utf-8") as stream:
        config = json.load(stream)

    assert config["log"] == {"level": "info", "timestamp": True}
    proxy_dns, direct_dns = config["dns"]["servers"]
    proxy = config["outbounds"][0]
    assert proxy["type"] == outbound_type
    assert proxy["tag"] == expected_tags[filename]
    expected_proxy_dns_type = "tcp" if outbound_type == "anytls" else "udp"
    assert proxy_dns == {
        "type": expected_proxy_dns_type, "tag": "dns_proxy", "server": "8.8.8.8",
        "detour": expected_tags[filename],
    }
    assert direct_dns == {
        "type": "udp", "tag": "dns_direct", "server": "223.5.5.5",
    }
    assert "strategy" not in config["dns"]
    assert config["dns"]["cache_capacity"] == 4096
    assert config["dns"]["final"] == "dns_proxy"
    assert config["inbounds"][0] == {
        "type": "tun",
        "tag": "tun-in",
        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        "mtu": 1400,
        "auto_route": True,
    }
    rules = config["route"]["rules"]
    assert {"action": "sniff"} in rules
    assert {"protocol": "dns", "action": "hijack-dns"} in rules
    assert {"ip_version": 6, "action": "reject"} not in rules
    assert {"ip_is_private": True, "action": "route", "outbound": "direct"} in rules
    assert {"port": [443, 853], "network": "udp", "action": "reject"} in rules
    assert config["route"]["default_domain_resolver"] == "dns_direct"
    assert config["route"]["final"] == expected_tags[filename]

anytls = json.loads((root / "anytls.json").read_text(encoding="utf-8"))
assert anytls["outbounds"][0]["min_idle_session"] == 0
tls = anytls["outbounds"][0]["tls"]
assert tls["insecure"] is True
assert "certificate_public_key_sha256" not in tls
assert tls["server_name"] == "addons.mozilla.org"
assert tls["utls"] == {"enabled": True, "fingerprint": "chrome"}

print("Sing-box export validation passed.")
PY

if [ -n "${SING_BOX_CHECK_BIN:-}" ]; then
    for config in "$tmp"/*.json; do
        "$SING_BOX_CHECK_BIN" check -c "$config"
    done
    echo "Sing-box core validation passed."
fi
