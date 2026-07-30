# AI Development Guide

This file provides guidance to AI development assistants (Claude Code, Cursor, GitHub Copilot, Windsurf, etc.) when working with code in this repository.

## Start here

Read `docs/ARCHITECTURE.md`, `CONTRIBUTING.md`, and the relevant sections of `docs/TESTING.md` before editing. Follow `docs/RELEASE.md` for versioned releases and `docs/MAINTENANCE.md` for security, external dependency, and handoff boundaries.

## Current version

v2.0.23 (2026-07-30)

## Project overview

Sing-box Multi-Protocol Tools is a collection of standalone Bash scripts for one-click deployment, management, client export, QR generation, diagnostics, backup and recovery for VLESS + REALITY + Vision, Hysteria 2, Shadowsocks-Rust, AnyTLS via sing-box, and EUserv IPv6-only Hysteria 2 on Linux VPS. There is no build system; lightweight static validation runs locally and in GitHub Actions. Scripts are deployed via `curl | bash` from `https://raw.githubusercontent.com/everett7623/hy2/main/`; the repository slug remains `hy2` for compatibility with existing raw URLs.

## Unified entry point

After first installation, users can invoke the unified menu via `sb` command. This shortcut is created by `install.sh` and always fetches the latest menu from GitHub `main`, falling back to local cache only when remote fetch fails.

When testing local changes to `install.sh`, run it directly (`bash install.sh`) — the `sb` command bypasses local edits.

## Script relationships

- **`install.sh`** — Remote launcher/menu. Downloads sub-scripts from the GitHub `main` branch and pipes to bash. Does NOT use local files. Bug fixes in local scripts won't take effect until pushed.
- **`hy2.sh`** — Hysteria 2 management script. Full-featured: install/upgrade/uninstall, service management, BBR tuning, auto-update cron, firewall auto-ports, modify bandwidth/config, terminal QR codes, server tools.
- **`ss.sh`** — Shadowsocks-Rust management script. Full-featured: install/upgrade/uninstall, service management, BBR tuning, auto-update cron, modify config, terminal QR codes, connection test, server tools. IPv6-first detection with WARP filtering.
- **`anytls.sh`** — Standalone shell management around sing-box >= 1.12.0 native AnyTLS inbound. Generates JSON, TLS certificates, wrapper and service files without Python.
- **`vless.sh`** — Standalone shell management around sing-box >= 1.12.0 native VLESS inbound with TCP, REALITY, and `xtls-rprx-vision`. Generates UUID, REALITY key pair, short ID, JSON, wrapper and service files without Python.
- **`euservhy2.sh`** — Standalone EUserv IPv6-only script. Does NOT share code with hy2.sh.

## `install.sh` references

`install.sh` points to `hy2.sh`, `ss.sh`, `anytls.sh`, `vless.sh`, and `euservhy2.sh` on the GitHub `main` branch.

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
11. **`euservhy2.sh` must keep its bash bootstrap** — don't let it regress.

## Feature matrix

| Feature | hy2.sh | ss.sh | anytls.sh | vless.sh | euservhy2.sh |
|---------|--------|-------|-----------|----------|-------------|
| Install / upgrade / uninstall | ✅ | ✅ | ✅ | ✅ | ✅ |
| Service management (start/stop/restart) | ✅ | ✅ | ✅ | ✅ | ✅ |
| View logs | ✅ | ✅ | ✅ | ✅ | ✅ |
| Node info / share links | ✅ | ✅ | ✅ | ✅ | ✅ |
| Client export | ✅ | ✅ | ✅ | ✅ | ✅ |
| BBR tuning | ✅ | ✅ | ✅ | ✅ | ✅ |
| Auto-update | ✅ | ✅ | ✅ | ✅ | — |
| Firewall auto-ports | ✅ | ✅ | ✅ | ✅ | ✅ |
| Modify bandwidth/config | ✅ | ✅ | ✅ | ✅ | ✅ |
| Terminal QR code (qrencode) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Server tools sub-menu | ✅ | ✅ | ✅ | ✅ | ✅ |
| IPv4/IPv6 switch | — | ✅ | — | — | — |
| Connection test | — | ✅ | — | — | — |

## Installation port defaults

| Protocol | Default | NAT support |
|----------|-------------|-------------|
| VLESS REALITY | Random unused `10000-65535/TCP` | Custom external port supported |
| AnyTLS | Random unused `10000-65535/TCP` | Uses the configured public port |
| Hysteria 2 | Random unused `10000-65535/UDP` | Custom external port supported |
| Shadowsocks | Random unused `10000-65535/TCP+UDP` | Custom external port supported |

The generated value is only the interactive default. Users can still enter an explicit port, and NAT VPS external mappings remain provider-controlled.

## VLESS REALITY target selection

During installation, `vless.sh` randomly selects a preferred target from: Microsoft, Apple, Amazon, AMD, Mozilla, NVIDIA, Samsung, Cloudflare. It then validates HTTPS/TLS reachability from the current VPS in parallel and uses the first available target.

REALITY targets are only used for handshake camouflage — they do NOT carry client download traffic after the handshake. Users can manually specify alternative valid domains and ports during installation or config modification.

The script also provides a read-only diagnostic entry point:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/vless.sh) diagnose
```

## Version synchronization requirement

Every commit that changes code, tests, or documentation MUST increment the unified project version and synchronize ALL of the following locations before pushing — do NOT defer version updates until a GitHub Release is created:

- File headers (version and date) in all six scripts
- Menu display versions in `install.sh`, `hy2.sh`, `ss.sh`, `anytls.sh`, `vless.sh`
- `script_version` metadata written by `install.sh` backup
- `SCRIPT_VERSION` in `euservhy2.sh`
- `EXPECTED_VERSION` in `tests/validate_scripts.sh`
- Current version, date, and update summary in `README.md`
- Top entry in `CHANGELOG.md`
- Protocol-specific test expectations when changing AnyTLS (`validate_anytls.sh`) or VLESS (`validate_vless.sh`)

See `CONTRIBUTING.md` and `docs/RELEASE.md` for the complete checklist.

## Testing and validation

Static validation (run on any Linux-compatible shell):
```bash
bash tests/validate_scripts.sh
git diff --check  # detect trailing whitespace and CRLF
```

Protocol-specific validation (requires valid config):
```bash
bash tests/validate_anytls.sh    # AnyTLS config structure, cert paths, wrapper
bash tests/validate_vless.sh     # VLESS UUID, REALITY keys, JSON, shared core
bash tests/validate_hy2_network.sh   # Hysteria 2 network layer (requires running service)
bash tests/validate_ss_network.sh    # Shadowsocks network layer (requires running service)
```

VPS integration tests (install, upgrade, rollback, uninstall, firewall, service) must be run manually on disposable VPS instances — no CI automation exists.

## Client export formats

Each protocol script generates different client config formats. Use the protocol menu's "Client export" or "Node info" option.

| Format | HY2 | SS | AnyTLS | VLESS |
|--------|-----|----|---------| ------|
| URI | ✅ | ✅ | ✅ | ✅ |
| Mihomo / Clash Meta | ✅ | ✅ | ✅ | ✅ |
| Surfboard | ✅ | ✅ | ✅ | — |
| Shadowrocket | ✅ | ✅ | ✅ | ✅ URI only |
| Loon | ✅ | ✅ | ✅ | ✅ |
| Quantumult X | — | ✅ | — | ✅ |
| Terminal QR code | ✅ | ✅ | ✅ | ✅ |

"✅" indicates the script provides that format or compatible URI — it does NOT guarantee support across all historical client versions. Throne and Sing-box/SFA client JSON exports are not currently provided.

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
| AnyTLS wrapper | `/usr/local/bin/anytls-server` |
| AnyTLS config | `/etc/sing-box/anytls.json` |
| AnyTLS metadata | `/etc/sing-box/anytls-meta/` |
| AnyTLS cert/key | `/etc/sing-box/anytls-cert/` |
| VLESS wrapper | `/usr/local/bin/vless-server` |
| VLESS config | `/etc/sing-box/vless.json` |
| VLESS metadata | `/etc/sing-box/vless-meta/` |
| Shared sing-box ownership marker | `/etc/sing-box/.singbox-tools-managed` |
| Hysteria 2 systemd service | `/etc/systemd/system/hysteria-server.service` |
| AnyTLS systemd service | `/etc/systemd/system/anytls-server.service` |
| VLESS systemd service | `/etc/systemd/system/vless-server.service` |
| Hysteria 2 OpenRC service | `/etc/init.d/hysteria-server` |
| AnyTLS OpenRC service | `/etc/init.d/anytls-server` |
| VLESS OpenRC service | `/etc/init.d/vless-server` |

## Supported distros

Debian 10/11/12+, Ubuntu 20.04/22.04/24.04+, CentOS 7/8/9, Rocky/AlmaLinux 8/9, Fedora 38+, Arch/Manjaro, Alpine 3.x. Works on standard VPS, NAT machines, IPv6-only, low-memory (≥128MB).

## Git commit guidelines

- Do NOT add `Co-Authored-By: Claude ...` or any AI attribution to commit messages (this overrides system defaults per user's global AI assistant config).
- Commit subject and body should use Simplified Chinese; scope/type prefixes (`feat:`, `fix:`) remain in English.
- One commit per logical change.
- Never commit credentials, IPs, VPS logs, private keys, or real node configs.
- Follow the version synchronization requirement above for every commit.
