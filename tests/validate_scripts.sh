#!/bin/bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

SCRIPTS="install.sh hy2.sh ss.sh anytls.sh euservhy2.sh"
EXPECTED_VERSION="v2.0.7"
REQUIRED_DOCS="
README.md
AGENTS.md
CLAUDE.md
CONTRIBUTING.md
CHANGELOG.md
docs/ARCHITECTURE.md
docs/TESTING.md
docs/RELEASE.md
docs/MAINTENANCE.md
"

for doc in $REQUIRED_DOCS; do
    if [ ! -s "$doc" ]; then
        echo "Required documentation missing or empty: $doc" >&2
        exit 1
    fi
done

for script in $SCRIPTS; do
    bash -n "$script"

    if grep -q "$(printf '\r')" "$script"; then
        echo "CRLF detected: $script" >&2
        exit 1
    fi

    case "$script" in
        install.sh)
            grep -q "# 版本：${EXPECTED_VERSION}" "$script"
            grep -q "Sing-box Multi-Protocol Tools.*${EXPECTED_VERSION}" "$script"
            ;;
        hy2.sh)
            grep -q "# 版本：${EXPECTED_VERSION}" "$script"
            grep -q "Hysteria2 Management Script ${EXPECTED_VERSION}" "$script"
            ;;
        ss.sh)
            grep -q "# 版本：${EXPECTED_VERSION}" "$script"
            grep -q "Shadowsocks-Rust Management Script ${EXPECTED_VERSION}" "$script"
            ;;
        anytls.sh)
            grep -q "# 版本：${EXPECTED_VERSION}" "$script"
            grep -q "AnyTLS Management Script.*${EXPECTED_VERSION}" "$script"
            grep -q 'github.com/SagerNet/sing-box/releases/download' "$script"
            grep -q '"type": "anytls"' "$script"
            grep -q 'ANYTLS_LIB_ONLY' "$script"
            ;;
        euservhy2.sh)
            grep -q "#  版本: ${EXPECTED_VERSION}" "$script"
            ;;
    esac

    if grep -qE 'grep -oP|head -c|\$\{[^}]+,,\}|\$\{[^}]+\^\^\}' "$script"; then
        echo "Unsupported compatibility construct found: $script" >&2
        exit 1
    fi
done

for script in hy2.sh ss.sh anytls.sh; do
    tmp=$(mktemp)
    awk '
        /cat > "\$AUTO_UPDATE_SCRIPT" <<'\''AUTOUPDATE_EOF'\''/ {
            capture=1
            next
        }
        capture && /^AUTOUPDATE_EOF$/ { exit }
        capture { print }
    ' "$script" > "$tmp"

    if [ ! -s "$tmp" ]; then
        echo "Unable to extract auto-update script: $script" >&2
        rm -f "$tmp"
        exit 1
    fi

    bash -n "$tmp"
    rm -f "$tmp"
done

grep -q 'SCRIPT_VERSION="2.0.7"' euservhy2.sh
grep -q "^## ${EXPECTED_VERSION} " CHANGELOG.md
! grep -R -q 'Keep "tag": "proxy"' hy2.sh ss.sh anytls.sh euservhy2.sh
! grep -R -qE '"(tag|detour|final)": "\$\{(_tag|_safe_tag|safe_node)\}"' hy2.sh ss.sh anytls.sh euservhy2.sh
! grep -R -qE '"strategy": "ipv4_only"|"strict_route": true|"ip_version": 6|tls_certificate_public_key_sha256' hy2.sh ss.sh anytls.sh euservhy2.sh
! grep -R -q 'Path to each client configuration file' hy2.sh ss.sh anytls.sh euservhy2.sh README.md CHANGELOG.md
! grep -R -q 'sing-box-examples/tree/main/Tun' hy2.sh ss.sh anytls.sh euservhy2.sh README.md CHANGELOG.md
! grep -R -qE 'Throne URI|export_throne|render_throne|export_singbox|render_singbox|print_singbox_template_note' hy2.sh ss.sh anytls.sh euservhy2.sh install.sh
! grep -R -qE 'Sing-box JSON 配置|完整 Sing-box/SFA TUN|Sing-box 输出说明|SFA / SFM / SFI' install.sh
! grep -R -qE 'systemctl (start|restart|is-active --quiet) (hysteria|shadowsocks|anytls)-serve$|--no-page$|write_wrappe$' hy2.sh ss.sh anytls.sh euservhy2.sh
! grep -R -qE '(^|[[:space:]])clea$|show_banne$|_numbe$|_manual_add$|_new_ve$|_url_mirro$|_uptime_st$|_tmp_di$|tcp_congestion_control = bb$' hy2.sh ss.sh anytls.sh euservhy2.sh
for script in hy2.sh ss.sh anytls.sh euservhy2.sh; do
    grep -q "printf '%s %s | %s | %s | %s'" "$script"
    grep -q '^get_country_flag()' "$script"
done

for script in install.sh hy2.sh ss.sh anytls.sh euservhy2.sh; do
    _shadow_line=$(grep -n 'Shadowrocket 配置' "$script" | head -1 | cut -d: -f1)
    _loon_line=$(grep -n 'Loon 配置' "$script" | head -1 | cut -d: -f1)
    if [ -z "$_shadow_line" ] || [ -z "$_loon_line" ] || [ "$_shadow_line" -ge "$_loon_line" ]; then
        echo "Loon must appear after Shadowrocket in $script" >&2
        exit 1
    fi
done

grep -q 'bash "$_tmp" "$_action"' install.sh
grep -q 'select_protocol_and_run "安装 / 重装协议" "install"' install.sh
grep -q 'select_protocol_and_run "查看节点信息" "info"' install.sh
grep -q 'select_protocol_and_run "生成二维码" "info"' install.sh
grep -q 'run_script "AnyTLS" "$ANYTLS_URL" "upgrade"' install.sh
grep -q 'run_script "AnyTLS" "$ANYTLS_URL" "uninstall"' install.sh
grep -q 'install) install_hy2' hy2.sh
grep -q 'info|node|export|qrcode) show_config' hy2.sh
grep -q 'install) install_ss' ss.sh
grep -q 'info|node|export|qrcode) show_config' ss.sh
grep -q 'install) install_anytls' anytls.sh
grep -q 'info|node|export|qrcode) show_config' anytls.sh
grep -q 'install) do_install' euservhy2.sh
grep -q 'info|node|export|qrcode) show_banner; show_node_info' euservhy2.sh

bash tests/validate_anytls.sh

echo "Static script validation passed."
