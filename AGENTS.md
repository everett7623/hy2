# Sing-box Multi-Protocol Tools — VPS 代理工具集

## Start here

Before editing, read `docs/ARCHITECTURE.md`, `CONTRIBUTING.md`, and the relevant sections of `docs/TESTING.md`. Release work must also follow `docs/RELEASE.md`; security and external dependency boundaries are documented in `docs/MAINTENANCE.md`.

## Script relationships

- `install.sh` is a **remote launcher** — it downloads scripts from `https://raw.githubusercontent.com/everett7623/hy2/main/` and pipes to bash. It does **not** use local files. Bug fixes in local scripts won't take effect until pushed to GitHub.
- `hy2.sh` — Hysteria 2 management (install/upgrade/uninstall, BBR, auto-update, firewall, QR, server tools).
- `ss.sh` — Shadowsocks-Rust management (install/upgrade/uninstall, BBR, auto-update, QR, connection test, IPv4/IPv6 switch).
- `anytls.sh` — AnyTLS management via **sing-box >= 1.12.0** native anytls inbound. Downloads and manages sing-box; does NOT use a standalone `anytls-go` binary.
- `vless.sh` — VLESS management via **sing-box >= 1.12.0** native VLESS inbound, using TCP + REALITY + `xtls-rprx-vision`; generates UUID, REALITY keys and short ID.
- `euservhy2.sh` — Standalone EUserv IPv6-only script. Does not share code with hy2.sh.

## Version management

- Each script carries its own version in the header comment block; there is no shared version file. The current release policy keeps all script versions unified, so update every header, visible menu version, date, and `CHANGELOG.md` manually for a project release.
- `install.sh` always points to `main` branch on GitHub. There's no staging/test branch mechanism.
- `get_latest_version()` fetches `apernet/hysteria`, `shadowsocks`, or `SagerNet/sing-box` releases from GitHub API — no dependency file for version pins.

## Validation and CI

- There is no build system, formatter, or typechecker.
- `tests/validate_scripts.sh` runs Bash syntax checks, version consistency checks, line-ending checks, compatibility-rule checks, and validates the generated auto-update scripts.
- GitHub Actions runs the static validation script on pushes and pull requests.
- Runtime behavior still requires manual VPS testing.
- No lockfiles, no package.json, no manifest beyond the MIT `LICENSE`.

## Local verification

- Test local edits by running the edited script directly; never use `install.sh` for unpushed changes.
- Run `bash tests/validate_scripts.sh` before release.
- Preserve LF line endings and UTF-8 encoding.
- Use a disposable Linux VPS for install, upgrade, firewall, service, and uninstall checks.

## Script quirks

1. **Bootstrap**: every script re-execs itself via `exec bash "$0" "$@"` to ensure bash (Alpine ships `sh` by default).
2. **CRLF guard**: `grep -q $'\r' "$0"` → `sed -i 's/\r$//'` → re-exec. Any edit that introduces CRLF will auto-fix at runtime on Linux.
3. **TTY fix**: `[ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty` — required when piped via `curl | bash`.
4. **No shared library**: common helpers (color vars, system detection, service wrappers) are copy-pasted across every script. No `source` or `include`.

## Installation artifacts (Linux VPS)

| Component | Path |
|-----------|------|
| Hysteria 2 binary | `/usr/local/bin/hysteria` |
| Hysteria 2 config | `/etc/hysteria/config.yaml` |
| Hysteria 2 metadata | `/etc/hysteria/meta/` |
| SS binary | `/usr/local/bin/ssserver` |
| SS config | `/etc/shadowsocks.json` or `/etc/shadowsocks-rust/config.json` |
| AnyTLS wrapper | `/usr/local/bin/anytls-server` (shell wrapper invoking sing-box) |
| AnyTLS config | `/etc/sing-box/anytls.json` |
| AnyTLS meta | `/etc/sing-box/anytls-meta/` |
| AnyTLS cert | `/etc/sing-box/anytls-cert/` |
| VLESS wrapper | `/usr/local/bin/vless-server` (shell wrapper invoking sing-box) |
| VLESS config | `/etc/sing-box/vless.json` |
| VLESS meta | `/etc/sing-box/vless-meta/` |
| Shared sing-box ownership marker | `/etc/sing-box/.singbox-tools-managed` |
| Hysteria 2 systemd service | `/etc/systemd/system/hysteria-server.service` |
| AnyTLS systemd service | `/etc/systemd/system/anytls-server.service` |
| VLESS systemd service | `/etc/systemd/system/vless-server.service` |
| Hysteria 2 OpenRC service | `/etc/init.d/hysteria-server` |
| AnyTLS OpenRC service | `/etc/init.d/anytls-server` |
| VLESS OpenRC service | `/etc/init.d/vless-server` |

## Feature matrix

| Feature | hy2.sh | ss.sh | anytls.sh | vless.sh | euservhy2.sh |
|---------|--------|-------|-----------|----------|-------------|
| BBR/tcp tuning | ✅ | ✅ | ✅ | ✅ | ✅ |
| Auto-update (cron) | ✅ | ✅ | ✅ | ✅ | — |
| Firewall auto-ports | ✅ | ✅ | ✅ | ✅ | ✅ |
| Modify bandwidth/config | ✅ | ✅ | ✅ | ✅ | ✅ |
| Terminal QR code | ✅ | ✅ | ✅ | ✅ | ✅ |
| Client export | ✅ | ✅ | ✅ | ✅ | ✅ |
| Upgrade sub-command | ✅ | ✅ | ✅ | ✅ | ✅ |
| IPv4/IPv6 switch | — | ✅ | — | — | — |
| Connection test | — | ✅ | — | — | — |

## SS-2022 caveat

`2022-blake3-aes-256-gcm` requires accurate system time. If a user reports timeout issues, the likely cause is clock drift — not a bug. Script attempts `ntpdate` but does not enforce it.

## EUserv script unique patterns

- Temporary NAT64 DNS swap (`2001:67c:2b0::4`) to pull IPv4 resources from IPv6-only VPS.
- Multi-tier download fallback: GitHub CDN → official → IPv6 direct → NAT64+GitHub → ghproxy mirror.
- Post-download ELF binary validation to prevent segfault from corrupted downloads.
- `trap restore_dns EXIT INT TERM` set inside `enable_nat64_dns()` so DNS always recovers on interrupt.
- No `grep -oP` anywhere — all IPv6 extraction uses `awk '/inet6/ {print $2}' | cut -d/ -f1` for busybox grep compat.
- No `${var,,}` bash4+ syntax — uses `tr '[:upper:]' '[:lower:]'` or dual-condition checks for bash 3.x compat.
