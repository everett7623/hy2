#!/bin/bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

SCRIPTS="install.sh hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh"
HELPER_SCRIPTS="tests/helpers/validators.bash tests/helpers/generators.bash tests/validate_recovery.sh"
EXPECTED_VERSION="v2.0.37"
EXPECTED_VERSION_NUMBER="${EXPECTED_VERSION#v}"
REQUIRED_DOCS="
README.md
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

for script in $SCRIPTS $HELPER_SCRIPTS; do
    bash -n "$script"

    if grep -q "$(printf '\r')" "$script"; then
        echo "CRLF detected: $script" >&2
        exit 1
    fi
done

for script in $SCRIPTS; do
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
        vless.sh)
            grep -q "# 版本：${EXPECTED_VERSION}" "$script"
            grep -q "VLESS Management Script.*${EXPECTED_VERSION}" "$script"
            grep -q 'github.com/SagerNet/sing-box/releases/download' "$script"
            grep -q '"type": "vless"' "$script"
            grep -q '"flow": "xtls-rprx-vision"' "$script"
            grep -q '"reality": {' "$script"
            grep -q 'VLESS_LIB_ONLY' "$script"
            grep -q 'packet-encoding: xudp' "$script"
            ;;
        proxy.sh)
            grep -q "# 版本：${EXPECTED_VERSION}" "$script"
            grep -q "HTTP/SOCKS Proxy Management Script.*${EXPECTED_VERSION}" "$script"
            grep -q 'github.com/SagerNet/sing-box/releases/download' "$script"
            grep -q '"type": "mixed"' "$script"
            grep -q 'PROXY_LIB_ONLY' "$script"
            grep -q 'export_uri_http()' "$script"
            grep -q 'export_uri_socks5()' "$script"
            ! grep -q 'export_mihomo_http\|export_mihomo_socks\|Mihomo HTTP 单行' "$script"
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

for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh; do
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

grep -q "SCRIPT_VERSION=\"${EXPECTED_VERSION_NUMBER}\"" euservhy2.sh
grep -q '版本: v${SCRIPT_VERSION}' euservhy2.sh
grep -q "script_version=${EXPECTED_VERSION}" install.sh
grep -q "^> 当前版本：${EXPECTED_VERSION}" README.md
grep -q "^## ${EXPECTED_VERSION} " CHANGELOG.md
grep -q 'UPGRADE_LOCK_FILE="${UPGRADE_LOCK_FILE:-/var/lock/sing-box-tools-upgrade.lock}"' anytls.sh
grep -q 'UPGRADE_LOCK_FILE="${UPGRADE_LOCK_FILE:-/var/lock/sing-box-tools-upgrade.lock}"' vless.sh
grep -q 'UPGRADE_LOCK_FILE="${UPGRADE_LOCK_FILE:-/var/lock/sing-box-tools-upgrade.lock}"' proxy.sh
! grep -q 'upgrade_core || true' anytls.sh vless.sh
grep -q '^shared_vless_service_restart()' anytls.sh
grep -q '^shared_anytls_service_restart()' vless.sh
grep -q '^shared_proxy_service_restart()' anytls.sh
grep -q '^shared_proxy_service_restart()' vless.sh
grep -q '^ensure_outbound_bind()' anytls.sh
grep -q '^ensure_outbound_bind()' vless.sh
grep -q '^ensure_outbound_bind()' proxy.sh
! grep -R -q 'Keep "tag": "proxy"' hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh
! grep -R -qE '"(tag|detour|final)": "\$\{(_tag|_safe_tag|safe_node)\}"' hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh
! grep -R -qE '"strategy": "ipv4_only"|"strict_route": true|"ip_version": 6|tls_certificate_public_key_sha256' hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh
! grep -R -q 'Path to each client configuration file' hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh README.md CHANGELOG.md
! grep -R -q 'sing-box-examples/tree/main/Tun' hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh README.md CHANGELOG.md
! grep -R -qE 'Throne URI|export_throne|render_throne|export_singbox|render_singbox|print_singbox_template_note' hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh install.sh
! grep -R -qE 'Sing-box JSON 配置|完整 Sing-box/SFA TUN|Sing-box 输出说明|SFA / SFM / SFI' install.sh
! grep -qE 'sing-box core|进程替换运行|无法原地更新|更新 install\.sh 主入口' install.sh
grep -q '刷新 install.sh 主入口缓存' install.sh
grep -q '升级 AnyTLS 核心' install.sh
grep -q '更新 / 升级中心' install.sh
grep -q '卸载 / 清理中心' install.sh
grep -q '系统检测 / BBR 优化' install.sh
grep -q '^show_bbr_detail()' install.sh
grep -q '^enable_standard_bbr()' install.sh
grep -q '^system_tools_menu()' install.sh
grep -q '开启标准 BBR + fq' install.sh
grep -q 'seedloc.com.*vpsknow.com.*nodeloc.com' install.sh
grep -q '^confirm_action()' install.sh
grep -q '^list_backup_archives()' install.sh
grep -q '^run_upgrade_action()' install.sh
grep -q '^run_uninstall_action()' install.sh
grep -q '^upgrade_all_cores()' install.sh
grep -q '^uninstall_all_protocols()' install.sh
! grep -q '^prepare_change_backup()' install.sh
! grep -q '^run_protocol_action()' install.sh
! grep -q 'rollback-.*\.tar\.gz' install.sh
! grep -q 'manifest-.*\.txt' install.sh
! grep -q '改动前创建回滚包' install.sh
grep -q 'VPS 配置备份完成' install.sh
grep -q '如需 VPS 配置备份，请先' install.sh
grep -q 'run_script "AnyTLS" "$ANYTLS_URL" "$_action"' install.sh
grep -q 'run_script "VLESS" "$VLESS_URL" "$_action"' install.sh
grep -q 'select_protocol_and_run "选择协议以导出 URI 分享链接" "uri"' install.sh
grep -q 'select_protocol_and_run "选择协议以导出 Mihomo / Clash 配置" "mihomo"' install.sh
grep -q 'select_protocol_and_run "选择协议以导出 Shadowrocket 配置" "shadowrocket"' install.sh
grep -q 'select_protocol_and_run "生成二维码" "qrcode"' install.sh
! grep -q '协议脚本会输出当前支持的全部格式' install.sh
grep -q '\[4\] 生成二维码' install.sh
grep -q '\[5\] 服务管理' install.sh
! grep -q '\[5\] 生成二维码' install.sh
grep -q 'etc/sysctl.d/99-singbox-tools-bbr.conf' install.sh
! grep -R -qE 'bbr3|tcp_bbr3' install.sh hy2.sh ss.sh README.md CHANGELOG.md
grep -q 'net.ipv4.tcp_congestion_control = bbr' install.sh
grep -q 'net.ipv4.tcp_congestion_control = ${_cc}' hy2.sh
grep -q 'net.ipv4.tcp_congestion_control = ${_cc}' ss.sh
! grep -q 'net.ipv4.tcp_fastopen = 3' hy2.sh
! grep -q 'net.ipv4.tcp_fastopen = 3' ss.sh
grep -q '\[ -s "\$_dest.tmp" \]' install.sh
grep -q '全部脚本缓存刷新完成' install.sh
grep -q '^SHORTCUT_BIN="/usr/local/bin/sb"' install.sh
grep -q '^make_temp_file()' install.sh
grep -q '^install_shortcut_command()' install.sh
grep -q '_tmp=$(make_temp_file)' install.sh
grep -q 'install_shortcut_command || true' install.sh
grep -q '快捷命令: .*sb' install.sh
! grep -R -qE 'systemctl (start|restart|is-active --quiet) (hysteria|shadowsocks|anytls|vless|proxy)-serve$|--no-page$|write_wrappe$' hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh
! grep -R -qE '(^|[[:space:]])clea$|show_banne$|_numbe$|_manual_add$|_new_ve$|_url_mirro$|_uptime_st$|_tmp_di$|tcp_congestion_control = bb$' hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh euservhy2.sh; do
    grep -q "printf '%s %s | %s | %s | %s'" "$script"
    grep -q '^get_country_flag()' "$script"
    grep -q '^yaml_single_quote_escape()' "$script"
    grep -q '^should_show_output()' "$script"
done

grep -q "name: '\${_safe_node}'" hy2.sh
grep -q "password: '\${_pass}'" hy2.sh
grep -q "Hysteria2, %s, %s, '%s'" hy2.sh
grep -q "name: '\${_safe_node}'" ss.sh
grep -q "password: '\${_pass}'" ss.sh
grep -q "Shadowsocks, %s, %s, %s, '%s'" ss.sh
grep -q "name: '\${_safe_node}'" anytls.sh
grep -q "fingerprint: '\${_fingerprint}'" anytls.sh
grep -q "AnyTLS, %s, %s, '%s'" anytls.sh
grep -q "name: '\${safe_node}'" euservhy2.sh
grep -q "password: '\${safe_password}'" euservhy2.sh
grep -q "Hysteria2, \${ipv6_raw}, \${port}, '\${password}'" euservhy2.sh

for script in install.sh hy2.sh ss.sh anytls.sh vless.sh euservhy2.sh; do
    _shadow_line=$(grep -n 'Shadowrocket 配置' "$script" | head -1 | cut -d: -f1)
    _loon_line=$(grep -n 'Loon 配置' "$script" | head -1 | cut -d: -f1)
    if [ -z "$_shadow_line" ] || [ -z "$_loon_line" ] || [ "$_shadow_line" -ge "$_loon_line" ]; then
        echo "Loon must appear after Shadowrocket in $script" >&2
        exit 1
    fi
done

grep -q '^run_local_script()' install.sh
grep -q 'run_local_script "$_tmp" "$_action"' install.sh
grep -q '_status=\$?' install.sh
grep -q 'return "\$_status"' install.sh
grep -q '使用本地缓存脚本' install.sh
grep -q 'select_protocol_and_run "安装 / 重装协议" "install"' install.sh
grep -q 'select_protocol_and_run "查看节点信息" "info"' install.sh
grep -q 'select_protocol_and_run "生成二维码" "qrcode"' install.sh
grep -q 'run_script "AnyTLS" "$ANYTLS_URL" "upgrade"' install.sh
grep -q 'run_script "AnyTLS" "$ANYTLS_URL" "uninstall"' install.sh
grep -q 'run_script "VLESS" "$VLESS_URL" "upgrade"' install.sh
grep -q 'run_script "VLESS" "$VLESS_URL" "uninstall"' install.sh
grep -q 'echo -e "  \[1\] VLESS + REALITY + Vision"' install.sh
grep -q '1) run_script "VLESS" "$VLESS_URL" "\$_action"' install.sh
grep -q 'echo -e "  \[1\] VLESS 服务管理"' install.sh
grep -q '1) protocol_service_menu "VLESS"' install.sh
grep -q 'echo -e "  \[2\] 升级 VLESS 核心"' install.sh
grep -q '2) run_upgrade_action "VLESS" "$VLESS_URL"' install.sh
grep -q 'echo -e "  \[1\] 卸载 VLESS"' install.sh
grep -q '1) run_uninstall_action "VLESS" "$VLESS_URL"' install.sh
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh; do
    grep -q '^generate_random_port()' "$script"
done
! grep -qE '默认 (18888|28888|38888|48888)' hy2.sh ss.sh anytls.sh vless.sh proxy.sh
grep -q '17 4 \* \* 1 \$AUTO_UPDATE_SCRIPT' anytls.sh
grep -q '27 4 \* \* 1 \$AUTO_UPDATE_SCRIPT' vless.sh
grep -q '37 4 \* \* 1 \$AUTO_UPDATE_SCRIPT' proxy.sh
! grep -q '27 4 \* \* 1 \$AUTO_UPDATE_SCRIPT' proxy.sh
grep -q '每周一 04:37' proxy.sh
grep -q '是否重选 REALITY 目标并写回配置' vless.sh
grep -q 'choose_reality_target "$HANDSHAKE_PORT"' vless.sh
! grep -q 'select_reality_target "$HANDSHAKE_PORT"' vless.sh
awk '
    /REALITY 目标端口/ { port_seen=1 }
    /REALITY 目标域名\/SNI/ {
        if (!port_seen) {
            print "VLESS SNI prompt appears before handshake port" > "/dev/stderr"
            exit 1
        }
        port_seen=0
    }
' vless.sh
# service_is_healthy 硬依赖 ss：缺 ss 时健康检查恒失败，会把正常安装/升级误判为失败并回滚。
# 因此五个脚本的两处依赖列表都必须把 ss 列为致命缺失项。
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh; do
    grep -q 'command -v ss >/dev/null 2>&1 || return 1' "$script"
    [ "$(grep -c 'for _cmd in .* ss; do' "$script")" -eq 2 ]
done
# 版本 tag 必须经过格式校验后才能进入下载 URL。重定向兜底失败时 curl 会输出
# 原始请求 URL，裸 sed 抽不出 tag 就把整条 URL 当版本号，非空检查拦不住；
# hy2 还会用它比对二进制实际版本，导致官方永久镜像这条可用路径被误判中止。
grep -q '^normalize_hy2_tag()' hy2.sh
grep -q '^set_hy2_version_tag()' hy2.sh
grep -q '^normalize_ss_tag()' ss.sh
grep -q '^set_ss_version_tag()' ss.sh
! grep -q 'sed .s|\.\*/tag/||.' hy2.sh
! grep -q 'sed .s|\.\*/tag/||.' ss.sh
# github.com 不可达是本项目目标用户的常见场景，五个脚本都必须有镜像回退。
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh; do
    grep -q 'kkgithub.com' "$script"
    grep -q 'gh-proxy.com' "$script"
done

# 公网 IP 探测站不能全部依赖 DNS，也不能全部落在同一个 CDN 之后：
# 旧表的 ipify / ip.gs / icanhazip 同在 Cloudflare 且都要解析域名，
# 一次 DNS 故障或单点阻断就会让全部探测一起失败。
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh install.sh; do
    grep -q '^extract_probe_ip()' "$script"
    grep -q 'https://1.1.1.1/cdn-cgi/trace' "$script"
    grep -q 'https://\[2606:4700:4700::1111\]/cdn-cgi/trace' "$script"
    grep -q 'checkip.amazonaws.com' "$script"
    ! grep -q 'for _url in "https://api.ipify.org" "https://ip.gs"' "$script"
done
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh; do
    grep -q '^get_default_public_ipv6()' "$script"
    grep -q 'for _url in \$IPV4_PROBE_URLS; do' "$script"
    grep -q 'for _url in \$IPV6_PROBE_URLS; do' "$script"
    # 单端点无回退的探测会重新引入同一类故障。
    ! grep -q 'curl -s6 --max-time 6 https://api6.ipify.org' "$script"
done
grep -q '^probe_public_ip()' install.sh
! grep -q 'curl -4 -s --max-time 3 ip.sb' install.sh

# 公网 IP 探测站不可达时，不得直接判定“本机没有 IPv4”。五个协议脚本都必须保留
# “本机原生全局 IPv4 + 默认 IPv4 路由”兜底，否则双栈机被误判为纯 IPv6，
# 节点只下发 IPv6 地址，IPv4 客户端全部连不上。
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh; do
    grep -q '^is_private_ipv4()' "$script"
    grep -q '^has_default_ipv4_route()' "$script"
    grep -q '^get_native_local_ipv4()' "$script"
    grep -q 'if is_valid_ipv4 "\$_local_ipv4" && has_default_ipv4_route; then' "$script"
    grep -q 'IPV4_UNVERIFIED=1' "$script"
    # 私网地址只能证明有 IPv4 出网，落进 PUBLIC_IP 会直接写入分享链接。
    grep -q 'if is_private_ipv4 "\$_local_ipv4"; then' "$script"
    # PUBLIC_IP 为空时不得再做 NAT 比对，否则空串会误判 NAT 状态。
    grep -q 'if \[ "\$HAS_IPV4" = "1" \] && \[ -n "\$PUBLIC_IP" \] && command -v ip >/dev/null 2>&1; then' "$script"
    grep -q 'NAT 机器\${PLAIN}（公网 IPv4 未确认，请手动指定节点地址）' "$script"
done

# 死 IPv6（接口有全局地址但无默认路由且外网不可达）必须按纯 IPv4 处理，
# 否则出站/握手拨号解析到 AAAA 后拨向死路由，连接全部超时。
for script in anytls.sh vless.sh proxy.sh; do
    grep -q '^has_default_ipv6_route()' "$script"
    grep -q 'if \[ -n "\$_real_ipv6" \] && { \[ "\$_ipv6_reachable" = "1" \] || has_default_ipv6_route; }; then' "$script"
    ! grep -q 'if is_valid_ipv6 "\$_ip"; then PUBLIC_IPV6="\$_ip"; HAS_IPV6=1; break; fi' "$script"
done
# mkdir 兜底锁（无 flock 的系统）：持有者若在写 pid 前被杀，锁目录会没有 pid 文件。
# 旧逻辑对这种目录永远拒绝回收，升级会被静默跳过；必须按目录 mtime 判定陈旧后回收。
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh; do
    grep -q 'maxdepth 0 -mmin -5' "$script"
    ! grep -q '\[ -n "$_owner" \] && ! kill -0 "$_owner" 2>/dev/null || return 1' "$script"
done
[ "$(grep -c 'maxdepth 0 -mmin -5' hy2.sh)" -eq 2 ]
[ "$(grep -c 'maxdepth 0 -mmin -5' ss.sh)" -eq 2 ]
# NAT64 DNS 切换必须可回滚：备份失败却照样覆盖 resolv.conf 会导致 DNS 永久停留在 NAT64。
! grep -q 'cp /etc/resolv.conf /etc/resolv.conf.hy2bak 2>/dev/null || true' euservhy2.sh
grep -q 'resolv.conf.hy2absent' euservhy2.sh
grep -q '已跳过 NAT64 DNS 切换' euservhy2.sh
# euservhy2.sh 升级/改配置：备份失败必须中止，回滚失败不得谎报“已回滚”。
grep -q '无法备份现有二进制，已取消升级' euservhy2.sh
grep -q '无法备份当前配置，已取消修改' euservhy2.sh
[ "$(grep -c '回滚失败：备份' euservhy2.sh)" -eq 2 ]
! grep -qE '^    cp "\$HY2_BIN" "\$\{HY2_BIN\}\.bak" 2>/dev/null$' euservhy2.sh
! grep -qE '^ +mv "\$\{HY2_BIN\}\.bak" "\$HY2_BIN"$' euservhy2.sh
# 五个协议脚本的 is_valid_ipv6 必须是完整语法校验，不能退回“含冒号即通过”的宽松写法。
for script in hy2.sh ss.sh anytls.sh vless.sh proxy.sh; do
    grep -q '^is_valid_ipv6()' "$script"
    ! grep -qF "*:*) echo \"\$1\" | grep -qE '^[0-9A-Fa-f:]+\$' ;;" "$script"
    grep -q 'if (s ~ /:::/) exit 1' "$script"
    grep -q 'if (gsub(/::/, "::") > 1) exit 1' "$script"
    grep -q 'if (groups == 0) exit 1' "$script"
done
grep -q 'vless-server:start) nohup /usr/local/bin/vless-server' install.sh
grep -q 'vless-server:stop)' install.sh
grep -q 'etc/systemd/system/vless-server.service' install.sh
grep -q 'etc/init.d/vless-server' install.sh
grep -q 'service_action vless-server restart /var/run/vless-server.pid' install.sh
grep -q 'VLESS    : .*VLESS_STATUS' install.sh
grep -q 'install) install_hy2' hy2.sh
grep -q 'info|node|export|all) show_config' hy2.sh
grep -q 'qrcode|qr) show_config qrcode' hy2.sh
grep -q 'install) install_ss' ss.sh
grep -q 'info|node|export|all) show_config' ss.sh
grep -q 'qrcode|qr) show_config qrcode' ss.sh
grep -q '_downloaded_version.*LAST_VERSION' hy2.sh
grep -q '_downloaded_version.*LAST_VERSION' ss.sh
grep -q '\[ "\$_was_active" = "0" \] || service_restart' hy2.sh
grep -q '\[ "\$_was_active" = "0" \] || service_restart' ss.sh
grep -q 'install) install_anytls' anytls.sh
grep -q 'info|node|export|all) show_config' anytls.sh
grep -q 'qrcode|qr) show_config qrcode' anytls.sh
grep -q 'install) install_vless' vless.sh
grep -q 'info|node|export|all) show_config' vless.sh
grep -q 'qrcode|qr) show_config qrcode' vless.sh
grep -q 'install) install_proxy' proxy.sh
grep -q 'info|node|export|all) show_config' proxy.sh
grep -q 'qrcode|qr) show_config qrcode' proxy.sh
grep -q 'PROXY_URL="${BASE_URL}/proxy.sh"' install.sh
grep -q 'HTTP/SOCKS' install.sh
grep -q 'proxy-server' install.sh
grep -q 'diagnose|check|health) diagnose_vless' vless.sh
grep -q '6. 运行状态与速度诊断' vless.sh
grep -q 'install) do_install' euservhy2.sh
grep -q 'info|node|export|all) show_banner; show_node_info' euservhy2.sh
grep -q 'qrcode|qr) show_banner; show_node_info qrcode' euservhy2.sh

for img in \
    docs/assets/screenshots/01-main-menu.png \
    docs/assets/screenshots/02-anytls-install-export.png \
    docs/assets/screenshots/03-system-detect.png \
    docs/assets/screenshots/04-upgrade-center.png \
    docs/assets/screenshots/05-uninstall-center.png
do
    [ -s "$img" ] || { echo "Required screenshot missing or empty: $img" >&2; exit 1; }
    grep -q "$img" README.md
done

bash tests/validate_recovery.sh dns
bash tests/validate_anytls.sh
bash tests/validate_vless.sh
bash tests/validate_proxy.sh
bash tests/validate_hy2_network.sh
bash tests/validate_ss_network.sh

tmp=$(mktemp)
awk '
    /cat > "\$SHORTCUT_BIN" <<'\''SB_EOF'\''/ {
        capture=1
        next
    }
    capture && /^SB_EOF$/ { exit }
    capture { print }
' install.sh > "$tmp"

if [ ! -s "$tmp" ]; then
    echo "Unable to extract sb shortcut wrapper" >&2
    rm -f "$tmp"
    exit 1
fi

bash -n "$tmp"
grep -q 'CACHE_FILE="${CACHE_DIR}/install.sh"' "$tmp"
# exec 会替换掉当前进程，EXIT trap 不再触发，$_tmp 会每次运行都残留在 /tmp；
# 必须以子进程运行并透传退出码，让 cleanup 正常清理临时文件。
! grep -q 'exec bash "$_tmp" "$@"' "$tmp"
! grep -q 'exec bash "$CACHE_FILE" "$@"' "$tmp"
grep -q 'bash "$_tmp" "$@"' "$tmp"
grep -q 'bash "$CACHE_FILE" "$@"' "$tmp"
grep -q 'trap cleanup EXIT INT TERM' "$tmp"
[ "$(grep -c '^    exit \$?$' "$tmp")" -eq 2 ]
rm -f "$tmp"

echo "Static script validation passed."
