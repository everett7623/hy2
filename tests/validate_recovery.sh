#!/bin/bash
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

test_bind_case() (
    protocol=$1 scenario=$2
    case "$protocol" in
        anytls) ANYTLS_LIB_ONLY=1 . ./anytls.sh; prefix=ANYTLS ;;
        vless) VLESS_LIB_ONLY=1 . ./vless.sh; prefix=VLESS ;;
        proxy) PROXY_LIB_ONLY=1 . ./proxy.sh; prefix=PROXY ;;
    esac
    sandbox=$(mktemp -d)
    trap 'rm -rf "$sandbox"' EXIT
    config="$sandbox/config.json"; meta="$sandbox/meta"
    mkdir -p "$meta"
    printf -v "${prefix}_CONFIG" '%s' "$config"
    printf -v "${prefix}_META" '%s' "$meta"
    printf '%s\n' '{"bind_interface": "old0"}' > "$config"
    printf 'BIND_INTERFACE=old0\n' > "$meta/config.env"
    BIND_INTERFACE=old0
    get_native_egress_interface() { printf new0; }
    ip() { return 0; }
    service_is_active() { [ "$scenario" != stopped ]; }
    service_restart() {
        echo restart >> "$sandbox/restarts"
        [ "$scenario" != restart_failure ] || [ "$(wc -l < "$sandbox/restarts")" -gt 1 ]
    }
    wait_for_health() {
        [ "$scenario" != health_failure ] || [ "$(wc -l < "$sandbox/restarts")" -gt 1 ]
    }
    write_config() {
        printf '%s\n' '{"bind_interface": "new0"}' > "$config"
        printf 'BIND_INTERFACE=new0\n' > "$meta/config.env"
        if [ "$scenario" = signal ]; then kill -TERM "$BASHPID"; fi
        [ "$scenario" != write_failure ]
    }
    check_config() { [ "$scenario" != check_failure ] && [ "$scenario" != rollback_failure ]; }
    cp() {
        if [ "$scenario" = backup_failure ] && [ "$2" = "$config" ]; then return 1; fi
        if [ "$scenario" = rollback_failure ]; then
            case "$2" in *.bind.*) return 1 ;; esac
        fi
        command cp "$@"
    }
    case "$scenario" in
        latest|upgrade_failure)
            SING_BOX_BIN="$sandbox/core"; printf '#!/bin/sh\nexit 0\n' > "$SING_BOX_BIN"; chmod +x "$SING_BOX_BIN"
            read_config() { return 0; }
            migrate_vless_config() { return 0; }
            get_latest_version() { touch "$sandbox/version-queried"; LAST_VERSION_TAG=v1.2.3; }
            get_installed_version() { printf 1.2.3; }
            if [ "$scenario" = upgrade_failure ]; then
                check_config() { return 1; }
                ! _upgrade_core_locked >/dev/null 2>&1
                [ ! -e "$sandbox/version-queried" ]
                grep -q old0 "$config"
                exit 0
            fi
            _upgrade_core_locked >/dev/null
            ;;
        memory_first)
            ensure_outbound_bind memory
            [ "$BIND_INTERFACE" = new0 ]
            grep -q old0 "$config"
            ensure_outbound_bind rewrite >/dev/null
            ;;
        success|stopped) ensure_outbound_bind rewrite >/dev/null ;;
        *)
            ! ensure_outbound_bind rewrite >/dev/null 2>&1
            [ "$BIND_INTERFACE" = old0 ]
            if [ "$scenario" = rollback_failure ]; then
                [ "$(find "$sandbox" -name '*.bind.*' | wc -l)" -eq 2 ]
                grep -q old0 "$config".bind.*
                exit 0
            fi
            grep -q old0 "$config"
            grep -q old0 "$meta/config.env"
            case "$scenario" in
                restart_failure|health_failure) [ "$(wc -l < "$sandbox/restarts")" -eq 2 ] ;;
                *) [ ! -e "$sandbox/restarts" ] ;;
            esac
            [ -z "$(find "$sandbox" -name '*.bind.*' -print)" ]
            exit 0
            ;;
    esac
    grep -q new0 "$config"
    grep -q new0 "$meta/config.env"
    if [ "$scenario" = stopped ]; then
        [ ! -e "$sandbox/restarts" ]
    else
        [ "$(wc -l < "$sandbox/restarts")" -eq 1 ]
    fi
    # Repeating an unchanged refresh must not restart the service again.
    ensure_outbound_bind rewrite >/dev/null
    if [ "$scenario" != stopped ]; then [ "$(wc -l < "$sandbox/restarts")" -eq 1 ]; fi
    [ -z "$(find "$sandbox" -name '*.bind.*' -print)" ]
)

test_dns() (
    sandbox=$(mktemp -d)
    # Extract only the functions under test; never execute the EUserv entry point.
    for function_name in enable_nat64_dns restore_dns; do
        awk -v name="$function_name" '
            $0 == name "() {" { capture=1 }
            capture { print }
            capture && /^}$/ { exit }
        ' euservhy2.sh | sed "s|/etc/resolv.conf|$sandbox/resolv.conf|g" >> "$sandbox/functions.sh"
    done
    . "$sandbox/functions.sh"
    warn() { printf '%s\n' "$*"; }
    step() { :; }; success() { printf '%s\n' "$*"; }; sleep() { :; }
    DNS_PATCHED=0; NAT64_DNS1=2001:db8::1; NAT64_DNS2=2001:db8::2; NAT64_DNS_BACKUP=2001:db8::3
    printf original > "$sandbox/resolv.conf"
    enable_nat64_dns >/dev/null
    cp() { return 1; }
    ! restore_dns > "$sandbox/output"
    [ "$DNS_PATCHED" = 1 ]
    [ "$(cat "$sandbox/resolv.conf.hy2bak")" = original ]
    ! grep -q 'DNS 已恢复原始配置' "$sandbox/output"
    unset -f cp
    restore_dns >/dev/null
    [ "$DNS_PATCHED" = 0 ]
    [ "$(cat "$sandbox/resolv.conf")" = original ]
    [ ! -e "$sandbox/resolv.conf.hy2bak" ]
    restore_dns
    # A leftover backup from an earlier process must never be discarded.
    printf saved > "$sandbox/resolv.conf.hy2bak"
    ! enable_nat64_dns >/dev/null
    [ "$(cat "$sandbox/resolv.conf.hy2bak")" = saved ]
    [ "$(cat "$sandbox/resolv.conf")" = original ]
    rm "$sandbox/resolv.conf.hy2bak"
    cp() { return 1; }
    ! enable_nat64_dns >/dev/null
    [ "$(cat "$sandbox/resolv.conf")" = original ]
    unset -f cp
    rm "$sandbox/resolv.conf"
    enable_nat64_dns >/dev/null
    [ -f "$sandbox/resolv.conf.hy2absent" ]
    restore_dns >/dev/null
    [ ! -e "$sandbox/resolv.conf" ]
    [ ! -e "$sandbox/resolv.conf.hy2absent" ]
    DNS_PATCHED=1
    ! restore_dns >/dev/null
    [ "$DNS_PATCHED" = 1 ]
    DNS_PATCHED=0
    trap - EXIT INT TERM
    rm -rf "$sandbox"
)

case "${1:-all}" in
    anytls|vless|proxy) protocols=$1 ;;
    dns) protocols='' ;;
    all) protocols='anytls vless proxy' ;;
    *) exit 2 ;;
esac
for protocol in $protocols; do
    for scenario in success stopped check_failure write_failure backup_failure restart_failure health_failure rollback_failure latest upgrade_failure memory_first signal; do
        test_bind_case "$protocol" "$scenario"
    done
done
case "${1:-all}" in dns|all) test_dns ;; esac
echo "Recovery validation passed: ${1:-all}"
