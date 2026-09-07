# AI Development Guide

This file provides guidance to AI development assistants (Claude Code, Cursor, GitHub Copilot, Windsurf, etc.) when working with code in this repository.

## Start here

Read `docs/ARCHITECTURE.md`, `CONTRIBUTING.md`, and the relevant sections of `docs/TESTING.md` before editing. Follow `docs/RELEASE.md` for versioned releases and `docs/MAINTENANCE.md` for security, external dependency, and handoff boundaries.

## Current version

v2.0.38 (2026-09-07)

## Project overview

Sing-box Multi-Protocol Tools is a collection of standalone Bash scripts for one-click deployment, management, client export, QR generation, diagnostics, backup and recovery for VLESS + REALITY + Vision, Hysteria 2, Shadowsocks-Rust, AnyTLS via sing-box, HTTP/SOCKS (sing-box mixed) for residential IP use cases, and EUserv IPv6-only Hysteria 2 on Linux VPS. There is no build system; lightweight static validation runs locally and in GitHub Actions. Scripts are deployed via `curl | bash` from `https://raw.githubusercontent.com/everett7623/hy2/main/`; the repository slug remains `hy2` for compatibility with existing raw URLs.

## Unified entry point

After first installation, users can invoke the unified menu via `sb` command. This shortcut is created by `install.sh` and always fetches the latest menu from GitHub `main`, falling back to local cache only when remote fetch fails.

When testing local changes to `install.sh`, run it directly (`bash install.sh`) — the `sb` command bypasses local edits.

## Script relationships

- **`install.sh`** — Remote launcher/menu. Downloads sub-scripts from the GitHub `main` branch and pipes to bash. Does NOT use local files. Bug fixes in local scripts won't take effect until pushed.
- **`hy2.sh`** — Hysteria 2 management script. Full-featured: install/upgrade/uninstall, service management, BBR tuning, auto-update cron, firewall auto-ports, modify bandwidth/config, terminal QR codes, server tools.
- **`ss.sh`** — Shadowsocks-Rust management script. Full-featured: install/upgrade/uninstall, service management, BBR tuning, auto-update cron, modify config, terminal QR codes, connection test, server tools. IPv6-first detection with WARP filtering.
- **`anytls.sh`** — Standalone shell management around sing-box >= 1.12.0 native AnyTLS inbound. Generates JSON, TLS certificates, wrapper and service files without Python.
- **`vless.sh`** — Standalone shell management around sing-box >= 1.12.0 native VLESS inbound with TCP, REALITY, and `xtls-rprx-vision`. Generates UUID, REALITY key pair, short ID, JSON, wrapper and service files without Python.
- **`proxy.sh`** — Standalone shell management around sing-box >= 1.12.0 native `mixed` inbound (HTTP + SOCKS5 on one port). Generates JSON with username/password users, optional `bind_interface` direct outbound, wrapper and service files without Python. Intended as an independent protocol for residential IP / streaming-friendly egress.
- **`euservhy2.sh`** — Standalone EUserv IPv6-only script. Does NOT share code with hy2.sh.

## `install.sh` references

`install.sh` points to `hy2.sh`, `ss.sh`, `anytls.sh`, `vless.sh`, `proxy.sh`, and `euservhy2.sh` on the GitHub `main` branch.

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

| Feature | hy2.sh | ss.sh | anytls.sh | vless.sh | proxy.sh | euservhy2.sh |
|---------|--------|-------|-----------|----------|----------|-------------|
| Install / upgrade / uninstall | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Service management (start/stop/restart) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| View logs | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Node info / share links | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Client export | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| BBR tuning | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Auto-update | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Firewall auto-ports | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Modify bandwidth/config | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Terminal QR code (qrencode) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Server tools sub-menu | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| IPv4/IPv6 switch | — | ✅ | — | — | — | — |
| Connection test | — | ✅ | — | — | — | — |

## Installation port defaults

| Protocol | Default | NAT support |
|----------|-------------|-------------|
| VLESS REALITY | Random unused `10000-65535/TCP` | Custom external port supported |
| AnyTLS | Random unused `10000-65535/TCP` | Uses the configured public port |
| Hysteria 2 | Random unused `10000-65535/UDP` | Custom external port supported |
| Shadowsocks | Random unused `10000-65535/TCP+UDP` | Custom external port supported |
| HTTP/SOCKS | Random unused `10000-65535/TCP` | Custom external port supported |

The generated value is only the interactive default. Users can still enter an explicit port, and NAT VPS external mappings remain provider-controlled.

## VLESS REALITY target selection

During installation, `vless.sh` offers two SNI sources. The default keeps the existing random Microsoft, Apple, Amazon, AMD, Mozilla, NVIDIA, Samsung, and Cloudflare candidate pool with parallel reachability probes. The optional custom SNI flow accepts any user-entered domain and validates syntax plus TLS 1.3 reachability over the active address-family strategy. It also provides `bgp.tools` lookup links as an optional way to find candidates; do not scrape its HTML or trust datacenter-default PTR names automatically.

REALITY targets are only used for handshake camouflage — they do NOT carry client download traffic after the handshake. Users can manually specify alternative valid domains and ports during installation or config modification.

The script also provides a diagnostic entry point. When the current REALITY target is unreachable under the active address-family strategy, it can interactively re-select a big-tech or custom SNI and write it back with backup/rollback:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/vless.sh) diagnose
```

## Version synchronization requirement

Every commit that changes code, tests, or documentation MUST increment the unified project version and synchronize ALL of the following locations before pushing — do NOT defer version updates until a GitHub Release is created:

- File headers (version and date) in all seven scripts
- Menu display versions in `install.sh`, `hy2.sh`, `ss.sh`, `anytls.sh`, `vless.sh`, `proxy.sh`
- `script_version` metadata written by `install.sh` backup
- `SCRIPT_VERSION` in `euservhy2.sh`
- `EXPECTED_VERSION` in `tests/validate_scripts.sh`
- Current version, date, and update summary in `README.md`
- Top entry in `CHANGELOG.md`
- Protocol-specific test expectations when changing AnyTLS (`validate_anytls.sh`), VLESS (`validate_vless.sh`), or HTTP/SOCKS (`validate_proxy.sh`)
- `.github/copilot-instructions.md` and `.windsurfrules` restate the version inline; `.cursorrules` does not. `validate_scripts.sh` does NOT check these three files, so they drift silently — grep for the old version string across the repo before committing.

See `CONTRIBUTING.md` and `docs/RELEASE.md` for the complete checklist.

Fastest way to find every location that still holds the old version:

```bash
grep -rnF "v2.0.38" --include="*.sh" --include="*.md" --include="*.bash" . | grep -v CHANGELOG.md
```

## Testing and validation

One command runs everything:
```bash
bash tests/validate_scripts.sh
git diff --check  # detect trailing whitespace and CRLF
```

`tests/validate_scripts.sh` is the single entry point and its final section invokes every other
validator (`validate_recovery.sh dns`, `validate_anytls.sh`, `validate_vless.sh`,
`validate_proxy.sh`, `validate_hy2_network.sh`, `validate_ss_network.sh`). Running the sub-scripts
directly is only useful for faster iteration on one protocol.

**None of these need a VPS, a running service, root, or a real config.** Every validator sources
its target in library mode (see below) and mocks `ip`, `curl`, `systemctl`, `cp` and friends, so
the whole suite completes in seconds on any machine — including Windows git-bash. There is no
excuse for skipping it.

```bash
bash tests/validate_recovery.sh              # all subsets: anytls, vless, proxy, dns
bash tests/validate_recovery.sh vless        # bind-refresh + rollback for one protocol
bash tests/validate_anytls.sh                # AnyTLS config structure, cert paths, wrapper
bash tests/validate_vless.sh                 # VLESS UUID, REALITY keys, JSON, shared core
bash tests/validate_proxy.sh                 # mixed inbound, users, bind_interface, wrapper
bash tests/validate_hy2_network.sh           # hy2 IP validation, WARP filtering, downloader
bash tests/validate_ss_network.sh            # ss IP validation, WARP filtering, downloader

# Optional: also run `sing-box check` on the generated VLESS JSON
REAL_SING_BOX_BIN=/path/to/sing-box bash tests/validate_vless.sh
```

GitHub Actions (`.github/workflows/shell-checks.yml`) runs `bash tests/validate_scripts.sh` on
every push and PR — that is the entire CI. `.gitattributes` forces `eol=lf` on `*.sh`, `*.bash`,
`*.md`, `*.yml`, `*.yaml`.

VPS integration tests (install, upgrade, rollback, uninstall, firewall, service) must be run
manually on disposable instances — no CI automation exists for runtime behavior.

## The test suite is a regression lock, not a linter

This is the highest-friction fact about the repo. `tests/validate_scripts.sh` contains ~198
`grep -q` assertions and ~33 negative `! grep -q` assertions pinned to **literal source text**:
function names, Chinese menu strings, menu item numbering, cron minute fields, prompt ordering,
and heredoc bodies. It is a change-detector by design.

Consequences when editing:

- Renaming a function, reordering a menu, or rewording a Chinese UI string **will fail the
  build**. Update the matching assertion in `tests/validate_scripts.sh` in the same commit.
- The `! grep -q` assertions forbid re-introducing specific past bugs (dead-IPv6 dialing, stale
  `mkdir` upgrade locks, `exec` in the `sb` wrapper leaking temp files, NAT64 DNS that cannot roll
  back, `upgrade_core || true` swallowing failures). Each carries a Chinese comment explaining the
  original bug — **read that comment before "fixing" a failing negative assertion.** If one fires,
  you almost certainly reintroduced the bug rather than found a stale test.
- It also asserts that `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `CHANGELOG.md` and all four
  `docs/*.md` exist and are non-empty, and that the five `docs/assets/screenshots/*.png` files
  exist **and are referenced from `README.md`**. Deleting or renaming a doc or screenshot breaks CI.
- It extracts the auto-update heredoc from each protocol script and the `sb` shortcut heredoc from
  `install.sh`, then runs `bash -n` on the extracted text — generated scripts are syntax-checked too.
- `tests/helpers/validators.bash` and `tests/helpers/generators.bash` are bats-core style helper
  libraries (no `.bats` files exist yet). They are still syntax- and CRLF-checked as
  `HELPER_SCRIPTS`, so they must stay valid bash.

## Library mode (`*_LIB_ONLY`) — how the scripts stay testable

Every script can be `source`d as a pure function library with no side effects, which is the only
reason hermetic tests are possible. The guard also suppresses the TTY fix and CRLF guard.

Two naming conventions coexist — **do not unify them**, `validate_scripts.sh` greps for the
per-protocol tokens:

| Script | Variable | Guard style |
|--------|----------|-------------|
| `hy2.sh`, `ss.sh`, `euservhy2.sh` | `EXPORT_LIB_ONLY=1` | entry block wrapped in `if [ "${EXPORT_LIB_ONLY:-0}" != "1" ]; then … fi` |
| `anytls.sh` | `ANYTLS_LIB_ONLY=1` | `[ "$_ANYTLS_LIB_ONLY" = "1" ] && return 0` before the entry block |
| `vless.sh` | `VLESS_LIB_ONLY=1` | `[ "$_VLESS_LIB_ONLY" = "1" ] && return 0` |
| `proxy.sh` | `PROXY_LIB_ONLY=1` | `[ "$_PROXY_LIB_ONLY" = "1" ] && return 0` |

```bash
VLESS_LIB_ONLY=1 . ./vless.sh   # functions available, nothing executed
```

Tests override path constants after sourcing (`VLESS_CONFIG`, `VLESS_META`, …) and redefine
functions like `service_restart`, `check_config`, `get_native_egress_interface` to drive failure
paths. Keep new logic in named functions and read paths from the module-level constants, or it
becomes untestable.

## CLI action arguments

`install.sh` does not drop users into sub-script menus — it passes an action as `$1`. Every
protocol script dispatches the same verb set, so keep the `case` block in sync when adding one:

```
install | info|node|export|all | uri|link | mihomo|clash | surfboard | shadowrocket
| loon | quantumult|quantumultx | qrcode|qr | manage|service|config
| upgrade|update | uninstall|remove | menu|""
```

`vless.sh` adds `diagnose|check|health`. `euservhy2.sh` uses `do_install` / `show_node_info`
instead of the `install_*` / `show_config` names. Unknown verbs must exit 1 with the usage line.

## Shared sing-box core coordination (anytls / vless / proxy)

The three sing-box protocols share one `/usr/local/bin/sing-box` binary and one `/etc/sing-box`
directory, so upgrading any one of them can break the other two. This is the most dangerous area
in the repo. The protocol is:

- **Mutual exclusion** — all three take `/var/lock/sing-box-tools-upgrade.lock` (flock, with a
  `${LOCK}.d` mkdir fallback that reclaims a stale directory via `find -maxdepth 0 -mmin -5`).
  Auto-update cron minutes are deliberately staggered: AnyTLS 04:17, VLESS 04:27, proxy 04:37 Mon.
- **Pre-flight validation** — a candidate binary must pass `check` against *every* existing
  `/etc/sing-box/*.json`, not just the caller's own, before the atomic replace.
- **Cross-restart** — after replacing the core, restart every consumer that was running before the
  upgrade, via `shared_vless_service_restart()` / `shared_anytls_service_restart()` /
  `shared_proxy_service_restart()`. If any fails, roll the core back and restore prior states.
- **Ownership** — `/etc/sing-box/.singbox-tools-managed` marks the core as project-installed so
  the *last* protocol uninstalled can remove it, in any uninstall order. Never delete shared files
  another protocol still owns.
- **`ensure_outbound_bind()`** — present in all three; refreshes/heals `bind_interface` on install,
  upgrade and from the tools menu, with its own backup, config check, health check and rollback.
  It runs even when the core is already at the latest version. Rollback failure must preserve the
  `.bind.*` backup and report its path rather than claim success.

## Client export formats

Each protocol script generates different client config formats. Use the protocol menu's "Client export" or "Node info" option.

| Format | HY2 | SS | AnyTLS | VLESS | Proxy |
|--------|-----|----|---------| ------|-------|
| URI | ✅ | ✅ | ✅ | ✅ | HTTP + SOCKS5 |
| Mihomo / Clash Meta | ✅ | ✅ | ✅ | ✅ | — |
| Surfboard | ✅ | ✅ | ✅ | — | — |
| Shadowrocket | ✅ | ✅ | ✅ | ✅ URI only | URI |
| Loon | ✅ | ✅ | ✅ | ✅ | — |
| Quantumult X | — | ✅ | — | ✅ | — |
| Terminal QR code | ✅ | ✅ | ✅ | ✅ | SOCKS5 only |

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
| HTTP/SOCKS wrapper | `/usr/local/bin/proxy-server` |
| HTTP/SOCKS config | `/etc/sing-box/proxy.json` |
| HTTP/SOCKS metadata | `/etc/sing-box/proxy-meta/` |
| Shared sing-box ownership marker | `/etc/sing-box/.singbox-tools-managed` |
| Hysteria 2 auto-update script | `/usr/local/bin/hy2-autoupdate.sh` |
| AnyTLS auto-update script | `/usr/local/bin/anytls-autoupdate.sh` |
| VLESS auto-update script | `/usr/local/bin/vless-autoupdate.sh` |
| HTTP/SOCKS auto-update script | `/usr/local/bin/proxy-autoupdate.sh` |
| Hysteria 2 systemd service | `/etc/systemd/system/hysteria-server.service` |
| AnyTLS systemd service | `/etc/systemd/system/anytls-server.service` |
| VLESS systemd service | `/etc/systemd/system/vless-server.service` |
| HTTP/SOCKS systemd service | `/etc/systemd/system/proxy-server.service` |
| Hysteria 2 OpenRC service | `/etc/init.d/hysteria-server` |
| AnyTLS OpenRC service | `/etc/init.d/anytls-server` |
| VLESS OpenRC service | `/etc/init.d/vless-server` |
| HTTP/SOCKS OpenRC service | `/etc/init.d/proxy-server` |

## Supported distros

Debian 10/11/12+, Ubuntu 20.04/22.04/24.04+, CentOS 7/8/9, Rocky/AlmaLinux 8/9, Fedora 38+, Arch/Manjaro, Alpine 3.x. Works on standard VPS, NAT machines, IPv6-only, low-memory (≥128MB).

## Git commit guidelines

- Do NOT add `Co-Authored-By: Claude ...` or any AI attribution to commit messages (this overrides system defaults per user's global AI assistant config).
- Commit subject and body should use Simplified Chinese; scope/type prefixes (`feat:`, `fix:`) remain in English.
- One commit per logical change.
- Never commit credentials, IPs, VPS logs, private keys, or real node configs.
- Follow the version synchronization requirement above for every commit.
