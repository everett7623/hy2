#!/bin/bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for protocol in anytls vless proxy hy2 ss; do
(
    export ANYTLS_LIB_ONLY=1 VLESS_LIB_ONLY=1 PROXY_LIB_ONLY=1 EXPORT_LIB_ONLY=1
    . "./${protocol}.sh"
    ANYTLS_META="$tmp/$protocol"
    VLESS_META="$tmp/$protocol"
    PROXY_META="$tmp/$protocol"
    HY_META="$tmp/$protocol"
    SS_META="$tmp/$protocol"
    HAS_IPV6=0

    # 隔离真实防火墙，验证 inactive 不会被误认为 active。
    command() {
        if [ "${1:-}" = -v ]; then
            case "$2" in
                ufw) return 0 ;;
                iptables|ip6tables|firewall-cmd|netfilter-persistent) return 1 ;;
            esac
        fi
        builtin command "$@"
    }
    state=inactive
    allow_calls=0
    fail_allow=0
    ufw() {
        case "$1" in
            status)
                [ "${LC_ALL:-}" = C ] || return 1
                printf 'Status: %s\n' "$state"
                [ "$allow_calls" -eq 0 ] || printf '15904/tcp ALLOW Anywhere\n15904/udp ALLOW Anywhere\n'
                ;;
            allow)
                allow_calls=$((allow_calls + 1))
                [ "$fail_allow" = 0 ]
                ;;
            *) return 1 ;;
        esac
    }
    open_test_port() {
        if [ "$protocol" = hy2 ]; then
            open_firewall_port 15904 tcp
        else
            open_ports 15904
        fi
    }
    open_test_port >/dev/null
    [ "$allow_calls" = 0 ]
    state=active
    open_test_port >/dev/null
    [ "$allow_calls" = 1 ]
    open_test_port >/dev/null
    [ "$allow_calls" = 1 ]
    allow_calls=0
    fail_allow=1
    ! open_test_port >/dev/null 2>&1

    case "$protocol" in hy2|ss) exit 0 ;; esac
    RELEASE=alpine
    for arch in amd64 arm64 armv7 386; do
        [ "$(singbox_asset_name 1.14.0 "$arch")" = "sing-box-1.14.0-linux-${arch}-musl.tar.gz" ]
        case "$(build_release_url v1.14.0 "$arch")" in
            *"/sing-box-1.14.0-linux-${arch}-musl.tar.gz") ;;
            *) exit 1 ;;
        esac
    done
    [ "$(singbox_asset_name 1.12.0 amd64)" = sing-box-1.12.0-linux-amd64.tar.gz ]
    [ "$(singbox_asset_name 1.14.0 s390x)" = sing-box-1.14.0-linux-s390x.tar.gz ]
    RELEASE=debian
    [ "$(singbox_asset_name 1.14.0 amd64)" = sing-box-1.14.0-linux-amd64.tar.gz ]

    # 即使输出正确版本，非零退出码也必须拒绝；错误信息不得被吞掉。
    candidate() { printf 'sing-box version 1.14.0\n'; return 0; }
    validate_singbox_execution candidate 1.14.0
    ! validate_singbox_execution candidate 1.13.0 2>/dev/null
    candidate() { printf 'sing-box version 1.14.0\n'; return 137; }
    ! validate_singbox_execution candidate 1.14.0 2>"$tmp/error"
    grep -q SIGKILL "$tmp/error"
    candidate() { printf 'loader missing\n' >&2; return 127; }
    ! validate_singbox_execution candidate 1.14.0 2>"$tmp/error"
    grep -q 'loader missing' "$tmp/error"
)
done
echo 'Platform and firewall validation passed.'
