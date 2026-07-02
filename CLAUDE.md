# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Start here

Read `docs/ARCHITECTURE.md`, `CONTRIBUTING.md`, and the relevant sections of `docs/TESTING.md` before editing. Follow `docs/RELEASE.md` for versioned releases and `docs/MAINTENANCE.md` for security, external dependency, and handoff boundaries.

## Project overview

A collection of bash scripts for one-click deployment and management of Hysteria 2 and Shadowsocks proxies on Linux VPS. There is no build system; lightweight static validation runs locally and in GitHub Actions. Scripts are deployed via `curl | bash` from `https://raw.githubusercontent.com/everett7623/hy2/main/`.

## Script relationships

- **`install.sh`** — Remote launcher/menu. Downloads sub-scripts from the GitHub `main` branch and pipes to bash. Does NOT use local files. Bug fixes in local scripts won't take effect until pushed.
- **`hy2.sh`** — Hysteria 2 management script. Full-featured: install/upgrade/uninstall, service management, BBR tuning, auto-update cron, firewall auto-ports, modify bandwidth/config, terminal QR codes, server tools.
- **`ss.sh`** — Shadowsocks-Rust management script. Full-featured: install/upgrade/uninstall, service management, BBR tuning, auto-update cron, modify config, terminal QR codes, connection test, server tools. IPv6-first detection with WARP filtering.
- **`anytls.sh`** — Standalone shell management around sing-box >= 1.12.0 native AnyTLS inbound. Generates JSON, TLS certificates, wrapper and service files without Python.
- **`euservhy2.sh`** — Standalone EUserv IPv6-only script. Does NOT share code with hy2.sh.

## `install.sh` references

`install.sh` points to `hy2.sh`, `ss.sh`, `anytls.sh`, and `euservhy2.sh` on the GitHub `main` branch.

`install.sh` downloads sub-scripts to a temp file (`mktemp /tmp/hy2_sub_XXXXXX.sh`) then runs `bash "$_tmp"` — it never sources local files. To test local edits, run the sub-script directly (e.g., `bash hy2.sh`) rather than going through `install.sh`.

## No shared library

Common helpers (color vars, system detection, service wrappers) are copy-pasted across every script. There is no `source` or `include`. When adding a utility, replicate it — do not refactor into a shared file.

## Every script has these quirks (don't remove them)

1. **Bash bootstrap**: re-execs via `exec bash "$0" "$@"` to ensure bash (Alpine ships `sh` by default).
2. **CRLF guard**: `grep -q $'\r' "$0"` → `sed -i 's/\r$//'` → re-exec. Any edit introducing CRLF will auto-fix at runtime on Linux.
3. **TTY fix**: `[ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty` — required when piped via `curl | bash`.
4. **No `grep -oP` anywhere** — all extraction uses `awk`/`cut` for busybox grep compatibility.
5. **No `${var,,}` bash4+ syntax** — use `tr '[:upper:]' '[:lower:]'` or dual-condition checks for bash 3.x compatibility.
6. **`check_root()`** — every script exits if not running as root.
7. **`change_password()` / config mutation** — never use bare `sed -i 's|password:.*|...|'` for config edits. Always scope with `awk` using block-detection (`/^auth:/` → `in_auth=1`, `/^[^[:space:]]/` → `in_auth=0`) to avoid corrupting other sections that may add password fields in future Hysteria versions.
8. **`service_restart()` must dispatch on `$INIT_SYS`** — use `systemctl restart` / `rc-service restart` when available instead of stop+sleep+start. The sleep-based approach is racy on slow VPS.
9. **NAT detection requires `command -v ip` guard** — without it, missing `iproute2` causes false NAT positives.
10. **`head -c` is non-POSIX** — use `dd bs=N count=1 2>/dev/null` for portable byte-limited reads.
11. **`euservhy2.sh` must keep its bash bootstrap** — it was missing until v2.0.2. Don't let it regress.

## Feature matrix

| Feature | hy2.sh | ss.sh |
|---------|--------|-------|
| Install / upgrade / uninstall | ✅ | ✅ |
| Service management (start/stop/restart) | ✅ | ✅ |
| View logs | ✅ | ✅ |
| Node info / share links | ✅ | ✅ |
| BBR tuning | ✅ | ✅ |
| Auto-update (cron @ 03:00) | ✅ | ✅ |
| Firewall auto-ports | ✅ | ✅ |
| Modify bandwidth/config | ✅ | ✅ |
| Terminal QR code (qrencode) | ✅ | ✅ |
| Server tools sub-menu | ✅ | ✅ |
| IPv4/IPv6 switch | — | ✅ |
| Connection test | — | ✅ |

## Default ports

| Protocol | Default port | NAT support |
|----------|-------------|-------------|
| Hysteria 2 | `18888` | Custom external port supported |
| Shadowsocks | `28888` | Custom external port supported |
| AnyTLS | `8443` | Uses the configured public port |

## Version management

There is no shared version file: each script stores its version in its header (and `euservhy2.sh` also exposes `SCRIPT_VERSION`). The current release policy keeps all four script versions unified, so a project release requires manually updating every script header, visible menu version, date, and `CHANGELOG.md`.

Do not confuse the project script version with the installed proxy version. `get_latest_version()` fetches Hysteria 2 or Shadowsocks-Rust releases from their upstream GitHub APIs at runtime; there are no dependency pins or lockfiles.

## Local development and verification

- Run edited sub-scripts directly, for example `bash hy2.sh`. Do not use `install.sh` to test unpushed local changes.
- Run `bash tests/validate_scripts.sh` on Linux or in a Linux-compatible shell. It includes syntax, version, line-ending, compatibility, and generated auto-update script checks.
- Because the repository has no automated integration tests, installation, upgrade, rollback, service management, firewall changes, and uninstall flows require manual VPS verification.
- Preserve LF line endings. The runtime CRLF guard is a recovery measure, not a formatting convention.
- Never test destructive install or uninstall paths on the developer workstation; use a disposable VPS.

## SS-2022 clock caveat

`2022-blake3-aes-256-gcm` requires accurate system time. If users report timeout issues, the likely cause is clock drift, not a bug. The script attempts `ntpdate` but does not enforce it.

## EUserv script unique patterns

- Temporary NAT64 DNS swap (`2001:67c:2b0::4`) to pull IPv4 resources from IPv6-only VPS.
- Multi-tier download fallback: GitHub CDN → official → IPv6 direct → NAT64+GitHub → ghproxy mirror.
- Post-download ELF binary validation to prevent segfault from corrupted downloads.
- `trap restore_dns EXIT INT TERM` set inside `enable_nat64_dns()` — DNS always recovers on interrupt.
- Uses `NC` (No Color) for reset instead of `PLAIN` — don't mix color var naming when copy-pasting from this script.

## Installation artifacts (Linux VPS paths)

| Component | Path |
|-----------|------|
| Hysteria 2 binary | `/usr/local/bin/hysteria` |
| Hysteria 2 config | `/etc/hysteria/config.yaml` |
| Hysteria 2 metadata | `/etc/hysteria/meta/` |
| SS binary | `/usr/local/bin/ssserver` |
| SS config | `/etc/shadowsocks.json` or `/etc/shadowsocks-rust/config.json` |
| SS auto-update script | `/usr/local/bin/ss-autoupdate.sh` |
| SS auto-update log | `/var/log/ss-autoupdate.log` |
| AnyTLS binary | `/usr/local/bin/anytls-server` |
| AnyTLS config | `/etc/sing-box/anytls.json` |
| Systemd service | `/etc/systemd/system/hysteria-server.service` |
| OpenRC service | `/etc/init.d/hysteria-server` |

## Supported distros

Debian 10/11/12+, Ubuntu 20.04/22.04/24.04+, CentOS 7/8/9, Rocky/AlmaLinux 8/9, Fedora 38+, Arch/Manjaro, Alpine 3.x. Works on standard VPS, NAT machines, IPv6-only, low-memory (≥128MB).
