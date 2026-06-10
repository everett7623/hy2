# hy2 — VPS 代理工具集

## Script relationships

- `install.sh` is a **remote launcher** — it downloads scripts from `https://raw.githubusercontent.com/everett7623/hy2/main/` and pipes to bash. It does **not** use local files. Bug fixes in local scripts won't take effect until pushed to GitHub.
- Stable/dev pairs **share most code**. When fixing a bug in `hy2.sh`, also fix `hy2dev.sh` (and vice versa). Same for `ss.sh` / `ssdev.sh`.
- Dev versions (`hy2dev.sh`, `ssdev.sh`) add features on top of stable: BBR, auto-update (cron), firewall rules, modify bandwidth/config, qrencode terminal QR. New features always go into dev first.
- `euservhy2.sh` is standalone — does not share code with the hy2 scripts despite overlapping functionality.

## Version management

- Each script carries its own version in the header comment block. No shared version file. Update manually.
- `install.sh` always points to `main` branch on GitHub. There's no staging/test branch mechanism.
- `get_latest_version()` fetches `apernet/hysteria` or `shadowsocks` releases from GitHub API — no dependency file for version pins.

## No build system, no tests, no CI

- Zero tests. Zero CI. No linter, formatter, or typechecker.
- The only "verification" is manual: run the script on a VPS and observe output.
- No lockfiles, no package.json, no manifest beyond the MIT `LICENSE`.

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
| Systemd service | `/etc/systemd/system/hysteria-server.service` |
| OpenRC service | `/etc/init.d/hysteria-server` |

## Key differences between stable and dev

| Feature | hy2.sh | hy2dev.sh | ss.sh | ssdev.sh |
|---------|--------|-----------|-------|----------|
| BBR/tcp tuning | ❌ | ✅ | ❌ | ✅ |
| Auto-update (cron) | ❌ | ✅ | ❌ | ✅ |
| Firewall auto-ports | ❌ | ✅ | ❌ | ✅ |
| Modify bandwidth/config | ❌ | ✅ | ❌ | ✅ |
| Terminal QR code | ❌ | ✅ | ❌ | ✅ |
| Upgrade sub-command | ✅ | ✅ | ✅ | ✅ |

## SS-2022 caveat

`2022-blake3-aes-256-gcm` requires accurate system time. If a user reports timeout issues, the likely cause is clock drift — not a bug. Script attempts `ntpdate` but does not enforce it.

## EUserv script unique patterns

- Temporary NAT64 DNS swap (`2001:67c:2b0::4`) to pull IPv4 resources from IPv6-only VPS.
- Multi-tier download fallback: GitHub CDN → official → IPv6 direct → NAT64+GitHub → ghproxy mirror.
- Post-download ELF binary validation to prevent segfault from corrupted downloads.
- `trap restore_dns EXIT INT TERM` set inside `enable_nat64_dns()` so DNS always recovers on interrupt.
- No `grep -oP` anywhere — all IPv6 extraction uses `awk '/inet6/ {print $2}' | cut -d/ -f1` for busybox grep compat.
- No `${var,,}` bash4+ syntax — uses `tr '[:upper:]' '[:lower:]'` or dual-condition checks for bash 3.x compat.
