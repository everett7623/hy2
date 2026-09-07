# CHANGELOG

所有脚本统一版本号，同步更新。

---

## v2.0.40 (2026-09-08)

- `install.sh` 的 `run_script` 在下载并通过非空与 `bash -n` 校验后，把脚本原子落盘为本地缓存。此前只有菜单里的「刷新缓存」会写入缓存，而远程不可达时的兜底恰恰依赖它 —— 从未手动刷新过的用户等于没有兜底。缓存写入失败不影响本次运行。
- 文档同步：`docs/ARCHITECTURE.md` 的文件树补齐 `validate_recovery.sh`、`validate_restore.sh`、`validate_hy2_network.sh`、`validate_ss_network.sh` 与 `tests/helpers/`，此前只列了四个测试文件。
- `docs/MAINTENANCE.md` 的外部依赖表补入 GitHub 镜像、公网 IP 探测站、免 DNS 端点与跨 ASN 端点，并明确「探测与版本获取必须保持多来源」的维护约束。
- `docs/TESTING.md` 增加 `validate_restore.sh` 的覆盖说明，并标注解包失败后的回滚与服务重启仍需实机验证 —— 静态测试只覆盖归档预检，不覆盖真实写 `/` 的行为。
- `CLAUDE.md` 测试章节补入 `validate_restore.sh`，断言计数由 ~198/~33 更新为 ~244/~40。
- `README.md` 能力表补充受限网络与恢复校验说明，并新增「机器类型被识别成纯 IPv6 但明明有公网 IPv4」的常见问题条目与排查命令。
- 验证：对 v2.0.35–v2.0.39 做了交叉场景验证（探测表扩容后路由兜底仍生效、脏 tag 被拒后不残留脏值、GitHub 全线不可达时版本未知→镜像下载→版本回填端到端、免 DNS 端点可用时不退化到网卡地址），并确认健康路径行为与 v2.0.34 基线逐字节一致。

---

## v2.0.39 (2026-09-07)

- 加固 `install.sh` 的配置恢复。`restore_config` 以 root 身份把归档解包到 `/`，是全项目风险最高的写入路径，此前缺少解包前校验、备份失败拦截和失败回滚。
- 新增 `validate_backup_archive()`：解包前先用 `tar -tzf` 走完整个归档。gzip 与 tar 的完整性要读到末尾才能确认，截断归档若直接解包会先写入一部分再失败 —— 实测 200 个文件的归档截断后仍会落盘 120 个，留下无人回滚的半还原状态。
- 归档成员限制在 `etc/` 前缀内，拒绝绝对路径、`..` 组件和其他顶层目录。恢复路径接受用户手输的任意路径，放行越界成员等于以 root 身份任意写文件。空归档与非 tar.gz 文件同样拒绝。
- 恢复前的安全备份失败时中止，不再 `backup_config || true` 带着无法回退的状态继续 —— 与项目其余五个脚本八处「备份失败必须中止」的既有约定对齐。
- 解包失败时自动从安全备份回滚并重启服务；回滚同样失败时保留备份并给出手动恢复路径，不谎报成功。
- 新增 `restart_restored_services()`：只重启确实已安装的服务（按 systemd unit 或 OpenRC 脚本存在判定），并如实报告启动失败。此前无条件重启全部五个服务且一律 `|| true`，未安装的会被算作失败，真正起不来的又会被宣告「恢复完成」。
- 测试：新增 `tests/validate_restore.sh`，覆盖正常归档、截断归档、非归档文件、空归档、越界成员、绝对路径与 `..` 成员七类用例，并接入 `tests/validate_scripts.sh` 主入口。
- 因重启逻辑由五条显式调用改为循环表，同步更新 `tests/validate_scripts.sh` 中对应的服务与 pidfile 配对断言（覆盖全部五个服务，强度不低于原断言）。

---

## v2.0.38 (2026-09-07)

- GitHub 全线不可达时，`hy2.sh` 的全新安装不再被版本获取失败阻断。官方永久镜像 `download.hysteria.network/app/latest/` 本身不依赖版本号，此前 `install_hy2` 在 `get_latest_version` 失败时直接返回，这条本来可用的安装路径被白白浪费 —— 而 GitHub 受限正是本项目目标用户的常见网络环境。
- 版本未知时跳过无法构造的 GitHub 下载 URL，直接走官方镜像，并在下载后从二进制自报版本回填 `LAST_VERSION` 与 `LAST_VERSION_TAG`，供元数据写入和后续升级比对使用。
- 下载物读不出合法版本号时一律判失败，不会被当成「未知版本」放行；版本已知时仍严格比对，镜像给出不同版本照样判失败。
- 升级路径行为不变：`_upgrade_hy2_locked` 在版本未知时仍然中止。版本不明时盲目替换正在工作的二进制会带来不可控的回退风险，这与全新安装的取舍不同。
- 测试：新增镜像安装回填版本、版本已知时比对不符判失败、下载物非二进制判失败三类用例，并加入「安装可降级、升级不可降级」的回归锁断言。

---

## v2.0.37 (2026-09-07)

- 修复 `hy2.sh` 与 `ss.sh` 在 GitHub API 限频时可能把整条 URL 当成版本号的缺陷。原重定向兜底用裸 `sed 's|.*/tag/||'` 提取 tag，而 `curl -w %{url_effective}` 在跳转失败时仍会输出原始请求 URL，抽不出 tag 就原样返回，非空检查无法拦截。
- 该脏 tag 会被拼进下载 URL；`hy2.sh` 还会用它比对下载到的二进制实际版本，导致官方永久镜像 `download.hysteria.network` 这条本来可用的路径被误判为版本不符，安装直接中止。
- 新增 `normalize_hy2_tag()` / `set_hy2_version_tag()` 与 `normalize_ss_tag()` / `set_ss_version_tag()`，tag 必须匹配 `vX.Y.Z`（Hysteria 另加 `app/` 前缀）才被接受，与 AnyTLS/VLESS/HTTP\/SOCKS 侧的 `normalize_version_tag()` 对齐。
- `hy2.sh`、`ss.sh` 的版本获取补齐镜像回退：GitHub API → `github.com` / `kkgithub.com` / `gh-proxy.com` 重定向 → HTML 抓取。此前只有 `github.com` 一条路径，被阻断即彻底失败，而这正是本项目目标用户的常见网络环境。
- `install.sh` 系统检测的 IPv4/IPv6 连通性判断改用多站点探测并显示实际公网地址，单一探测站被阻断不再误报「FAILED」。
- 测试：新增 tag 规范化边界、API 可用、镜像重定向回退、HTML 抓取回退、全来源失败返回非零且不残留脏值等用例，并加入格式校验与镜像回退的回归锁断言。

---

## v2.0.36 (2026-09-07)

- 强化公网 IP 探测，从源头减少 v2.0.35 兜底逻辑被触发的概率。原探测表 `api.ipify.org`、`ip.gs`、`ipv4.icanhazip.com` 三站同在 Cloudflare 之后且全部依赖 DNS 解析，并非独立信源：一次 DNS 故障或单点阻断即导致全部探测失败，机器 IP 检测随之失准。
- 探测清单改为跨 ASN 组合，并各加入一个免 DNS 的字面量地址端点（IPv4 `https://1.1.1.1/cdn-cgi/trace`、IPv6 `https://[2606:4700:4700::1111]/cdn-cgi/trace`）与 AWS `checkip.amazonaws.com`。DNS 完全不可用时仍能取到公网地址。
- 新增 `extract_probe_ip()`，同时支持纯地址响应与 Cloudflare trace 的 `key=value` 多行响应；HTML 错误页不会被当作地址，仍由 `is_valid_ipv4` / `is_valid_ipv6` 拦截。
- 新增 `get_default_public_ipv6()`，节点元数据刷新路径由单端点无回退改为多站点回退，与 IPv4 侧对齐。
- `install.sh` 主菜单顶部的 IP 状态改用同一套多站点探测，不再因单站不可达而整片显示「无」。
- `proxy.sh` 的本机 HTTP 代理自检改为遍历探测清单，避免单站故障被误报成代理不通。
- 单次请求超时从 `--max-time 6` 收紧到 5 秒，抵消站点数量增加带来的最坏耗时。
- 测试：新增 `extract_probe_ip` 响应解析、多站点回退计数、全失败返回非零、探测清单必须含免 DNS 端点与跨 ASN 站点等用例，并加入对应回归锁断言。

---

## v2.0.35 (2026-09-07)

- 修复公网 IP 探测站不可达时，双栈 VPS 被误判为「纯 IPv6」的缺陷。此前 `hy2.sh`、`ss.sh`、`anytls.sh`、`vless.sh`、`proxy.sh` 的 IPv4 判定完全依赖 `api.ipify.org` 等外部探测站，探测失败即认定本机没有 IPv4；而 IPv6 判定已经支持「本机地址 + 默认路由」兜底，两侧不对称导致有公网 IPv4 的机器只下发 IPv6 节点，IPv4 客户端全部连不上。
- 五个协议脚本新增 `has_default_ipv4_route()`、`get_native_local_ipv4()` 与 `is_private_ipv4()`：探测站全部不可达时，改用「原生网卡全局 IPv4 + 默认 IPv4 路由」确认 IPv4 可用，与 IPv6 分支对称。
- 兜底命中私网/CGNAT 地址（10/8、172.16/12、192.168/16、100.64/10）时按 NAT 处理，不写入 `PUBLIC_IP`，避免私网地址进入分享链接；机器类型提示改为「公网 IPv4 未确认，请手动指定节点地址」。
- WARP、隧道网卡持有的 IPv4 不参与兜底；无 IPv4 地址且无默认 IPv4 路由的真实纯 IPv6 机判定不变。
- 探测站不可达但按路由确认 IPv4 时输出提示，便于区分「真的没有 IPv4」与「探测站被墙」。
- `PUBLIC_IP` 为空时不再执行 NAT 比对，避免空串参与匹配造成误判。
- 测试：五个协议验证脚本新增双栈探测失败、私网 NAT、WARP 独占、纯 IPv6 四类场景与 `is_private_ipv4` 边界用例；`tests/validate_scripts.sh` 增加对应回归锁断言。
- 文档：`CLAUDE.md` 补充测试入口的实际覆盖范围、验证套件的回归锁性质、`*_LIB_ONLY` 库模式、命令行动作参数与共享 sing-box 核心协调机制；修正 `.windsurfrules` 的陈旧版本与脚本数量。

---

## v2.0.34 (2026-09-06)

- 整合远程 v2.0.32/v2.0.33 的升级锁、IPv6 校验、依赖检查、EUserv 备份保护和快捷入口清理修复，保留已有 VLESS 双 SNI 诊断及错峰自动更新。
- EUserv DNS 恢复失败保留原配置与恢复标记，不再误报成功；拒绝覆盖上次遗留备份，并在退出时重试恢复。DNS 写入失败立即尝试恢复。
- AnyTLS、VLESS、HTTP/SOCKS 网卡绑定刷新同时备份配置与元数据；写入、校验、重启、健康检查失败或中断时回滚，恢复不完整时保留备份路径。
- 核心已是最新版时，网卡绑定变更仍会重启原本运行中的服务并检查健康；停止中的服务保持停止，无变化时不重复重启。刷新失败中止升级。
- 新增 DNS 和三协议配置恢复故障注入，覆盖校验失败、备份失败、重启失败、回滚失败、中断及同版本升级。

---

## v2.0.33 (2026-09-01)

- 收紧 `is_valid_ipv6`：旧实现只检查"含冒号且全为十六进制字符"，会把 `::`、`:`、`::::`、
  `2001:db8:::1`、`1:2:3:4:5:6:7:8:9`、`12345::1` 等结构非法的值判为合法。该函数是外网
  IPv6 探测结果（`api6.ipify.org` 等）进入 `PUBLIC_IPV6` 的唯一关卡，放行后会直接写入
  分享链接与二维码。现按 `::` 只能出现一次、分组数与分组长度的完整规则校验（5 个脚本）。

---

## v2.0.32 (2026-08-28)

- HTTP/SOCKS 自动更新改为每周一 04:37，与 VLESS 的 04:27、AnyTLS 的 04:17 错开，避免共享 sing-box 升级锁互斥导致其中一方跳过整周更新。
- VLESS 诊断在握手目标不可达时改为走双 SNI 来源（大厂候选或自定义），写回前备份，校验或重启失败则回滚；未验证成功的目标不会落盘。
- 修改 VLESS 配置时先收集 REALITY 目标端口，再进行 SNI 重选/验证，避免 `auto` 探测旧端口。
- AnyTLS 与 HTTP/SOCKS 补齐死 IPv6 判定：接口有全局 IPv6 但外网不可达且无默认 IPv6 路由时按纯 IPv4 处理，避免出站拨号解析到 AAAA 后拨向死路由导致连接超时（此前仅 VLESS 有该判定）。
- VLESS 依赖校验补上 `ss`：`service_is_healthy` 硬依赖 `ss`，缺失时健康检查恒失败，会把正常的安装与升级误判为失败并触发回滚。
- 修复 mkdir 兜底升级锁的永久死锁：无 `flock` 的系统上，持有者若在写 pid 文件前被杀，锁目录会没有 pid，旧逻辑对这种目录永远拒绝回收，此后所有升级都被静默跳过；现按目录 mtime 超过 5 分钟判定陈旧后回收（5 个主脚本 + hy2/ss 自动更新脚本共 7 处）。
- 修复 EUserv 脚本 NAT64 DNS 无法恢复：`/etc/resolv.conf` 备份失败被 `|| true` 吞掉却仍覆盖 DNS，而 `restore_dns` 要求备份存在才恢复，机器会永久停留在 NAT64 DNS；现备份失败即跳过切换，原本无 resolv.conf 的情况在恢复时删除脚本创建的文件。
- 修复 EUserv 升级备份失败仍继续覆盖二进制、且回滚失败仍提示“已回滚”的问题；修改配置时同样校验备份非空，避免回滚用空文件覆盖正常配置。
- 修复 `sb` 快捷命令的临时文件泄漏：`exec` 替换进程后 EXIT trap 不再触发，改为子进程运行并透传退出码。

---

## v2.0.31 (2026-08-21)

- 将 VLESS REALITY 第二种 SNI 来源明确命名为“自定义 SNI”；`bgp.tools` 保留为可选的候选筛选辅助。
- 自定义域名仍须通过格式、TLS 1.3 和当前地址族可达性验证。

---

## v2.0.30 (2026-08-21)

- 修正 `bgp.tools` 邻居 SNI 查询链接：通过 WHOIS 解析 BGP Prefix，优先直达 Prefix 的 DNS 页面，WHOIS 不可用时回退搜索页。
- 明确 DNS 页面主要提供 PTR/反向解析，正向 FDNS 邻居域名需站点权限；用户粘贴域名仍须通过格式、TLS 1.3 和地址族可达性验证。

---

## v2.0.29 (2026-08-21)

- VLESS REALITY 安装与 `auto` 重选新增两种 SNI 来源：保留随机大厂候选，并增加 `bgp.tools` 邻居域名辅助流程。
- 邻居方案通过 WHOIS 解析 BGP Prefix 并直达 DNS 页面，失败时回退搜索页；不抓取网页，用户粘贴的域名必须通过格式、TLS 1.3 和当前地址族可达性验证。

---

## v2.0.28 (2026-08-11)

- VLESS diagnose now treats REALITY handshake targets unreachable under the active address-family strategy as critical, and can auto re-select a reachable target.
- VLESS config edit accepts `auto` to re-pick REALITY SNI; Mihomo export adds `packet-encoding: xudp` for Vision UDP.
- Strengthen VLESS dual-stack / DNS client tips; hide HTTP/SOCKS from non-URI export formats in `install.sh`.
- HTTP/SOCKS diagnose adds local HTTP proxy egress smoke check; remove obsolete `AGENTS.md` from architecture tree.

---

## v2.0.27 (2026-08-11)

- HTTP/SOCKS client export keeps only HTTP URI, SOCKS5 URI, and SOCKS5 terminal QR code; remove Mihomo single-line exports for this protocol.

---

## v2.0.26 (2026-08-11)

- Shared sing-box upgrades from AnyTLS/VLESS now also restart an active `proxy-server` peer so HTTP/SOCKS reloads the new core.
- Add `ensure_outbound_bind` refresh/heal for AnyTLS, VLESS, and HTTP/SOCKS when the native egress interface changes or `bind_interface` is missing from JSON.
- Reorder `install.sh` protocol menus so HTTP/SOCKS is `[5]` and EUserv is `[6]`.
- HTTP/SOCKS CLI accepts unsupported client export formats gracefully with a fallback message instead of failing hard.

---

## v2.0.25 (2026-08-10)

- Remove Mihomo streaming DNS snippet exports from protocol client output; keep single-line Mihomo proxy entries and server-side native egress binding.
- Leave Netflix/streaming DNS customization to the user's own client YAML configuration.

---

## v2.0.24 (2026-08-10)

- Add standalone `proxy.sh` for HTTP/SOCKS via sing-box native `mixed` inbound (HTTP + SOCKS5 on one port), with username/password auth, wrapper/service files, firewall ownership, auto-update, and shared sing-box core management alongside AnyTLS/VLESS.
- Bind direct outbound traffic to the native egress interface when detected, reducing WARP/tunnel IP leakage for residential or streaming use cases.
- Export Mihomo streaming DNS snippets (SOCKS5 / socks5h + nameserver detour) across proxy and other protocol scripts to keep client DNS on-proxy.
- Integrate HTTP/SOCKS into the unified `install.sh` menus for install, status, service, upgrade, cache refresh, and uninstall.
- Add `tests/validate_proxy.sh` and synchronize version, documentation, and static validation for seven scripts at v2.0.24.
- Fix `detect_network` returning non-zero under `set -e` when no egress interface is bound, so AnyTLS/VLESS/Proxy validation and install flows no longer abort after a successful detection.

---

## v2.0.23 (2026-07-30)

- Unify AI development tool documentation: refactor `CLAUDE.md` to support Claude Code, Cursor, GitHub Copilot, Windsurf, and other AI assistants.
- Add configuration files for Cursor (`.cursorrules`), GitHub Copilot (`.github/copilot-instructions.md`), and Windsurf (`.windsurfrules`) that reference the unified `CLAUDE.md`.
- Expand `CLAUDE.md` with current version, `sb` shortcut behavior, VLESS REALITY target selection mechanism, complete testing command list, version synchronization checklist, client export format matrix, and Git commit guidelines.
- Remove deprecated `AGENTS.md` (content merged into `CLAUDE.md`) and update all documentation references in `CONTRIBUTING.md`, `ARCHITECTURE.md`, and `MAINTENANCE.md`.
- Remove `AGENTS.md` validation check from `tests/validate_scripts.sh`.

---

## v2.0.22 (2026-07-21)

- Restore the complete last-known-good VLESS fixes that were accidentally omitted from the v2.0.21 rollback, including dead-IPv6 detection, address-family-aware REALITY resolution, bounded health polling, diagnostics, and quoted Mihomo credentials.
- Migrate installed VLESS configurations to the current schema without rotating UUIDs, REALITY keys, ports, or node addresses, and restore the previous config if validation or service recovery fails.
- Make firewall failures visible across VLESS, AnyTLS, Hysteria 2, Shadowsocks, and EUserv; require verified listeners for service health and clean up project-owned Hysteria 2 rules on rollback or uninstall.
- Verify AnyTLS/VLESS mirror downloads against SHA-256 digests from the official GitHub Release API; when no trusted digest is available, allow only the official GitHub asset URL.
- Expand regression coverage for configuration migration, delayed service startup, firewall failure propagation, rule ownership, and optional real `sing-box check` validation.

---

## v2.0.21 (2026-07-21)

- Restore `vless.sh` and its behavior tests to the proven v2.0.19 baseline after v2.0.20 connectivity regressions.
- Reorganize README around installation safety, protocol selection, client exports, operational boundaries, and task-oriented troubleshooting while preserving current commands and capabilities.

---

## v2.0.20 (2026-07-21)

- Quote VLESS UUID, REALITY public key, and short ID as YAML strings in Mihomo exports to preserve credential types and leading zeroes.
- Prioritize Microsoft, Apple, and Samsung for VLESS REALITY targets, then randomize the first fallback among Amazon, Bing, Intel, AMD, and Adobe while preserving VPS-side address-family reachability checks.
- Constrain VLESS REALITY handshake DNS resolution to the detected IPv4 or IPv6 family through sing-box 1.12+ `domain_resolver` fields, preventing dead alternate-family routes from stalling handshakes.
- Correct the VLESS external download probe direction and add local TCP retransmit/timeout, IP discard, interface error/drop, active qdisc and established-session diagnostics without adding a throughput-test dependency.
- Add opt-in standard `bbr + fq` status and enablement to the standalone VLESS toolbox, with atomic sysctl configuration and rollback when either setting fails to apply.

---

## v2.0.19 (2026-07-17)

- Generate random unused high-port defaults for VLESS, AnyTLS, Hysteria 2, and Shadowsocks while preserving explicit user and NAT mapping choices.
- Put VLESS first in protocol selection, service management, core upgrade, and uninstall menus.
- Select VLESS REALITY targets from globally reachable non-China candidates after probing HTTPS/TLS from the VPS, and remove GitHub/Bing from random SNI defaults.
- Extend VLESS diagnostics with direct CLI/service-menu access, REALITY target reachability, a bounded VPS direct-download probe, and TCP congestion-control context for slow or blocked Speedtest reports.
- Add AnyTLS certificate modes for self-signed certificates, validated existing domain certificate files, and the sing-box 1.14+ ACME Certificate Provider; trusted domain certificates now export strict client verification settings.
- Add standalone VLESS management through sing-box native VLESS inbound with TCP, REALITY, and `xtls-rprx-vision`.
- Generate and validate VLESS UUIDs, REALITY X25519 key pairs, short IDs, JSON metadata, wrappers, systemd/OpenRC services, firewall ownership, and automatic core updates.
- Export VLESS REALITY nodes for URI/Shadowrocket, Mihomo, Loon, and Quantumult X, with an explicit Surfboard compatibility notice.
- Integrate VLESS into the unified install, status, export, QR, service, upgrade, cache, and uninstall menus.
- Validate every existing `/etc/sing-box/*.json` before replacing the shared sing-box core, and preserve project ownership across AnyTLS/VLESS uninstall order with a managed marker.
- Serialize AnyTLS/VLESS core replacement with one shared lock and restart every active managed consumer, rolling back the core if either service fails to recover.
- Add `tests/validate_vless.sh` and extend static validation, architecture, testing, maintenance, contribution, and user documentation.

---

## v2.0.18 (2026-07-14)

- Make HY2, Shadowsocks, and AnyTLS configuration changes atomic and roll back configs, metadata, ports, and service state when validation or restart fails.
- Track firewall rules created by the scripts so port changes and uninstall never remove pre-existing administrator rules.
- Serialize manual and automatic core upgrades with shared locks, including stale-lock recovery on systems without `flock`.
- Check temporary and target filesystem capacity before large downloads, extraction, backup, and binary replacement operations.
- Require the configured TCP or UDP port to be listening before treating an active service as healthy, while degrading safely when `ss` is unavailable.
- Retry package-manager and binary-download failures with bounded exponential backoff and curl/wget fallback.
- Expand regression tests for atomic-write failures, rollback, firewall ownership, lock contention, low-disk conditions, missing listeners, and transient network failures.

---

## v2.0.17 (2026-07-13)

- Restore Hysteria 2, Shadowsocks, and AnyTLS files plus service active/enabled state when reinstall is interrupted by `Ctrl+C` or `TERM`.
- Skip package-manager refreshes when core dependencies already exist, reducing install time and failures caused by slow mirrors or package locks.
- Allow Hysteria 2, Shadowsocks, and generated auto-updaters to fall back between curl and wget instead of requiring one downloader.
- Prefer disk-backed `/var/tmp` for large downloads, extraction, and transactional backups to reduce tmpfs memory pressure on small VPS instances.
- Reject malformed IPv6 discovery responses and cancel only the current Shadowsocks install when the IPv4-only warning is declined.
- Make menu clearing safe in non-TTY, container, serial-console, and missing-TERM environments.
- Add regression coverage for interrupted rollback, service enablement restoration, downloader fallback, IPv6 validation, and IPv4-only cancellation.

---

## v2.0.16 (2026-07-13)

- Prevent AnyTLS, Hysteria 2, and Shadowsocks exports from using a WARP egress IPv4 as the inbound node address.
- Repair legacy metadata containing a confirmed WARP address when a native public IPv4 can be detected.
- Preserve stopped service state during HY2 and Shadowsocks core upgrades, with target-version validation before replacement.
- Add transactional reinstall rollback for HY2 and Shadowsocks binaries, configs, metadata, certificates, and service files.
- Write HY2 YAML and Shadowsocks JSON configs through same-directory temporary files before atomic replacement.

---

## v2.0.15 (2026-07-04)

- Add five README screenshot slots backed by `docs/assets/screenshots/` images.
- Make the unified export menu pass the selected output format to protocol scripts.
- Make the QR menu output QR content only instead of all client formats.
- Add per-format output modes for Hysteria2, Shadowsocks, AnyTLS, and EUserv HY2.
- Replace the broken third-party Project Views badge with stable shields.io GitHub stars and last-commit badges.

---

## v2.0.14 (2026-07-04)

- Remove automatic VPS-side rollback archive creation from install, upgrade, uninstall, config-delete, and BBR flows.
- Keep VPS configuration backup as an explicit manual action in the “备份 / 恢复” menu.
- Clarify upgrade and uninstall prompts so users create VPS config backups manually when needed.
- Keep local source rollback archives outside the repository for development/testing recovery.
- Document the optional GitHub raw `nocache` command for post-release cache troubleshooting.
- Refresh and simplify the README structure, removing outdated screenshot embeds and repeated menu details.

---

## v2.0.13 (2026-07-04)

- Add a unified launcher “系统检测 / BBR 优化” menu with manual standard `bbr + fq` enablement.
- Keep BBR opt-in only; protocol installation does not automatically modify global TCP settings.
- Remove HY2 and Shadowsocks standalone experimental BBR auto-detection and keep the mainstream stable `bbr + fq` profile.
- Include sysctl / BBR config files in the pre-change rollback archive scope.

---

## v2.0.12 (2026-07-04)

- Optimize the unified launcher homepage layout while preserving the author, GitHub, blog, review-site, and forum promotion links.
- Clarify the update/upgrade center so script-cache refresh and core-binary upgrade are shown as separate actions.
- Generate a single rollback archive with metadata before install/reinstall, config-change entry, restore, upgrade, uninstall, and full config deletion flows.
- Add confirmation, best-effort backup, and result summaries around single and batch core upgrades.
- Add confirmation, best-effort backup, and result summaries around single and batch uninstall flows.
- Keep service start/stop results visible with an explicit return prompt.

---

## v2.0.11 (2026-07-03)

- Fix unified launcher child-script exit status propagation so failures are not hidden by temporary-file cleanup.
- Remove obsolete `anytls.py`, which was not part of the shell-script project and could not be imported standalone.
- Include `tests/helpers/*.bash` in Bash syntax and CRLF validation, and normalize helper working-tree line endings to LF.
- Add static regression checks for launcher status preservation to prevent future regressions.

---

## v2.0.10 (2026-07-03)

- 新增快捷命令 `sb`，首次运行统一入口后自动写入 `/usr/local/bin/sb`，后续可直接打开主菜单。
- `sb` 默认优先拉取 GitHub `main` 最新主入口，远程失败时回退到本地缓存脚本。
- 修复部分系统 `mktemp` 不兼容带后缀模板导致加载协议脚本时报“无法创建临时文件”的问题。
- 静态验证新增快捷命令 wrapper 与临时文件创建逻辑检查。

---

## v2.0.9 (2026-07-03)

- Mihomo / Clash 单行配置中的节点名、密码、SNI 和证书指纹等字符串字段统一改为单引号输出。
- Loon 配置中的密码字段统一改为单引号输出。
- 新增 YAML 单引号转义，避免节点名、密码或 SNI 中包含 `'` 时破坏配置。
- 静态与 AnyTLS 行为验证同步新增单引号格式检查。

---

## v2.0.8 (2026-07-03)

- 优化统一入口更新菜单：`更新 install.sh 主入口` 改为 `刷新 install.sh 主入口缓存`，远程运行时不再提示无法原地更新。
- `更新 AnyTLS / sing-box core` 改为 `更新 AnyTLS 核心`，避免和已移除的 Sing-box 客户端导出混淆。
- 子脚本远程下载失败或内容无效时，会尝试使用已验证的本地缓存脚本继续执行。
- 脚本缓存刷新增加空文件和残留临时文件保护，并在批量刷新时提示失败项。
- 静态验证新增更新菜单文案防回归检查。

---

## v2.0.7 (2026-07-03)

- 修复 AnyTLS 安装时获取 sing-box 最新稳定版失败会直接中断的问题。
- AnyTLS 版本获取新增稳定版标签规范化、多源跳转解析、releases 页面解析，以及内置稳定版 `v1.13.14` 兜底。
- 自动测试新增 GitHub 版本接口不可达时的 fallback 覆盖。

---

## v2.0.6 (2026-07-03)

- 统一入口改为向子脚本传入动作参数，安装、节点信息、二维码、升级和卸载不再先落到子脚本主菜单。
- Hysteria2、Shadowsocks、AnyTLS 与 EUserv HY2 新增 `install`、`info`、`manage`、`upgrade`、`uninstall` 命令入口；不带参数时仍保留原独立菜单。
- README 与架构文档同步新的统一入口调度模型。
- 静态验证新增子脚本动作入口和统一入口动作传参检查。

---

## v2.0.5 (2026-07-03)

- 调整统一入口与四个协议脚本的客户端输出顺序：`Loon 配置` 移到 `Shadowrocket 配置` 后面。
- README 和测试说明同步新的输出顺序。
- 静态验证新增输出顺序检查，确保 Shadowrocket 始终排在 Loon 前。

---

## v2.0.4 (2026-07-03)

- 移除 Hysteria2、Shadowsocks、AnyTLS 与 EUserv HY2 的 Throne 客户端导出，避免继续输出不可用或不稳定的导入格式。
- 移除四协议 Sing-box/SFA 客户端 JSON 导出；AnyTLS 服务端仍继续使用 sing-box 原生 AnyTLS inbound，不影响安装、升级和运行。
- README 同步 v2.0.4 说明，新增项目浏览计数徽章，并更新客户端格式兼容说明。
- 静态验证新增不稳定客户端导出防回归检查。

---

## v2.0.3 (2026-07-03)

- 精简四协议 Sing-box / SFA TUN JSON：移除 `ipv4_only`、IPv6 拒绝和 `strict_route`，保留 DNS 缓存、DNS 劫持、私网直连和 UDP 443/853 拒绝规则。
- AnyTLS 的 Throne / Shadowrocket / Sing-box 输出改为兼容模式，不再自动写入 `certificate_public_key_sha256`，避免 Throne 导入时报 base64 解析错误。
- AnyTLS 客户端输出显式使用 `min_idle_session=0`，减少 GUI 客户端预热空闲连接导致的网络切换感和加载卡顿。

---

## v2.0.2 (2026-07-03)

- 修复 Sing-box JSON 内部出站 `tag`、DNS `detour`、`route.final` 使用节点展示名导致 emoji 或隐藏字符破坏 JSON 的问题，统一改为固定 ASCII tag。

---

## v2.0.1 (2026-07-03)

- 优化四协议 Sing-box JSON 客户端导出：日志级别从 debug 调整为 info，并增加 DNS 缓存，降低日志写入和重复远端解析带来的速度损耗。

---

## v2.0.0 (2026-07-02)

**升级为 Sing-box Multi-Protocol Tools**

- 统一入口升级为 `Sing-box Multi-Protocol Tools v2.0`，主菜单重构为安装、节点信息、导出、服务管理、系统检测、备份恢复、更新和卸载
- 保留顶部作者、项目、博客、测评、论坛广告区的原有文案、链接和排序
- AnyTLS、Hysteria2、Shadowsocks、EUserv HY2 节点名统一为 `国家 | 主机名 | 协议 | IP 类型`
- URI、Throne、Mihomo、Loon、Surfboard、Shadowrocket、Quantumult X、Sing-box 输出去除可复制内容前导空格
- AnyTLS 保留现有安装和运行链路，仅优化节点输出、Throne 严格/兼容模式、证书安全提示和二维码隐私提示
- Hysteria2、Shadowsocks、EUserv HY2 补充 Sing-box JSON、Loon、Surfboard 与客户端支持提示
- 按最新要求移除 Surge 输出格式
- 统一入口新增配置备份/恢复、服务状态、监听端口、最近日志和系统检测页面
- 优化统一入口和 AnyTLS 菜单头部排版，BBR 状态显示实际拥塞控制与队列算法
- 国家/地区状态改为 `DE / Germany` 这类文本格式，避免终端不支持旗帜 emoji 时显示异常
- 节点名和 Sing-box tag 增加国旗并保留国家代码，统一使用 `🇩🇪 DE | hostname | 协议 | IP 类型`
- 客户端输出顺序调整为主流格式优先，Sing-box JSON 放到最后并恢复为完整 TUN 客户端配置
- Sing-box JSON 出站 `tag` 和 `route.final` 使用节点名，内置 DNS、TUN、私网直连和 UDP 443/853 拒绝规则
- 修复 AnyTLS 的 Shadowrocket 输出，改为生成可导入的 AnyTLS URI
- 优化 AnyTLS 证书校验提示，按客户端实际输出区分严格模式和兼容模式
- AnyTLS 依赖安装改为静默检查，减少安装页面滚动和闪屏感
- 仅重整四个协议的 Sing-box JSON：恢复 UDP DNS、IPv4 DNS 策略、IPv6 拒绝规则及一致的出站 tag，其他客户端输出保持不变
- 新增四协议 Sing-box JSON 结构化测试，校验 DNS detour、TUN、路由与 AnyTLS TLS 公钥锁定字段
- 修复脚本换行清理误删行尾 `r` 导致的 `clear`、服务名、变量名、wrapper、日志与 BBR 配置截断
- AnyTLS 的代理 DNS 改用 TCP，避免 UDP DNS 经 TCP/TLS 隧道时在丢包或网络切换后长时间卡住
- 五个脚本、测试版本断言和文档同步到 v2.0.0

---

## v1.0.3 (2026-07-01)

**全新实现 AnyTLS**

- 参考已验证的 sing-box AnyTLS 入站链路，将实现迁移为纯 Shell 生成 JSON、证书与服务 wrapper
- 修复自动更新脚本递归调用自身的问题，并为 sing-box 升级增加配置校验与失败回滚
- AnyTLS 安装时随机提供常用 SNI 默认值，并补充证书、配置校验和启动阶段的故障诊断
- 修复配置函数在正常主机名下错误返回失败、导致输入 SNI 后直接退出安装的问题
- AnyTLS 节点信息统一为 HY2/SS 风格，补充 Mihomo/Clash 与 sing-box 客户端配置块
- 完整审计 AnyTLS 安装生命周期：增加重装事务回滚、下载包/可执行校验和同版本升级跳过
- 卸载仅清理 AnyTLS 专属文件并保留共享 sing-box，补充防火墙、cron 与日志清理
- 修复纯 IPv4 监听地址，修改端口后清理旧规则；工具箱新增运行诊断和自动更新移除
- 修复 sing-box 输出仅包含 outbound 片段及 mixed 端口冲突，改为 Android/SFA 可直接运行的完整 TUN 配置
- 新增 Throne AnyTLS 导入链接，并为 Throne、sing-box 与 Mihomo 输出证书公钥/指纹锁定
- 在完整删除旧实现后，从空文件重新开发 `anytls.sh`，不继承旧 AnyTLS 代码
- 使用 sing-box >= 1.12.0 原生 AnyTLS 入站，不依赖 Python 运行环境
- 支持 systemd、OpenRC 和无 init 环境，覆盖 IPv4、IPv6 与双栈监听
- 增加配置读写、节点 URI、升级回滚、自动更新、防火墙和完整卸载流程
- 新增可直接 source 的测试模式及 `tests/validate_anytls.sh` 行为测试
- 统一入口、项目文档和五个脚本版本同步至 v1.0.3

---

## v1.0.2 (2026-06-30)

**移除旧 AnyTLS 实现**

- 删除旧 `anytls.sh` 及统一入口引用
- 删除旧 AnyTLS 文档、维护说明与静态测试断言
- 为全新实现建立无遗留代码的基线

---

## v1.0.1 (2026-06-11)

**兼容性与可靠性修复**

- 修复 `install.sh` 在 Debian/RHEL 系统缺少 Bash 时使用错误包管理器参数的问题
- 启动器兼容 systemd、OpenRC 和无 init 环境的服务状态检测
- 下载二进制改为临时文件校验后原子替换，失败时保留当前可用版本
- 自动更新增加架构补全、二进制校验、服务验证和失败回滚
- 修复运行中但未启用开机启动的服务不会被自动更新器重启的问题
- 增加 Hysteria 2 / Shadowsocks 端口、带宽和密码输入校验
- Shadowsocks 与 EUserv 配置修改增加服务验证和失败回滚
- 防火墙规则改为幂等写入，并补充 IPv6 与 EUserv firewalld 支持
- 修复纯 Bash URI 编码对非 ASCII 内容的错误处理
- Python URI 编码不可用时自动回退到纯 Bash 实现
- 补充多发行版所需的 CA、iproute2 和进程工具依赖
- 调整极简系统的依赖安装顺序，将可选二维码组件与核心依赖拆分
- Bash 自举在 Debian 系列先刷新 apt 索引，提升最小化镜像成功率
- 安装自动更新时主动启用 cron/crond，并验证 `crontab` 可用
- EUserv 下载使用唯一临时文件，移除会直接改写目标二进制的远程安装脚本路径
- EUserv 增加伪装域名与 SNI 校验，并支持在修改配置时更新 SNI
- EUserv 明确校验 systemd 环境，并避免重复插入 iptables 规则
- 修正 Hysteria 2 官方 ARMv7 二进制文件名映射（`arm`）
- 新增 `tests/validate_scripts.sh` 与 GitHub Actions 静态验证
- 新增贡献指南、VPS 测试矩阵、发布流程及维护/AI 接手文档
- 修复 EUserv 卸载遗漏 BBR 配置文件的问题

---

## v1.0.0 (2026-06-11)

**首次统一发布**

### hy2.sh
- 端口跳跃 (Port Hopping) 支持，防火墙范围放行
- BBR 调优、自动更新 cron、防火墙自动放行
- QR 二维码 (qrencode)、修改带宽、服务工具子菜单
- awk 块检测修改密码/带宽，备份回滚机制
- download_hy2() 双源 fallback (GitHub + 官方镜像)

### ss.sh
- IPv6 优先检测 + WARP 虚拟网卡过滤
- 双栈 VPS 支持 IPv4/IPv6 切换
- 架构支持: amd64 / arm64 / armv7 / s390x / loongarch64
- 升级功能 (备份回滚)、BBR、自动更新、QR 二维码
- 修改配置 (端口/密码/加密)、连接测试
- Shadowsocks 2022 协议支持 (blake3-aes-256-gcm)
- Clash/Surge/Loon/Quantumult X 全客户端配置输出

### euservhy2.sh
- EUserv IPv6-only VPS 一键部署 Hysteria2
- NAT64 DNS 临时切换、多级下载 fallback
- WARP/tunnel 虚拟网卡 IPv6 过滤
- bash 自举 / CRLF guard / TTY fix
- busybox 兼容 (无 grep -oP, 无 ${var,,})

### install.sh
- 统一启动器，支持 hy2 / ss / euserv 三种脚本
- 实时状态检测 (运行中/已停止/未安装 + 版本号)

### 项目结构
- dev 版本合并，hy2dev.sh / ssdev.sh 删除
- CLAUDE.md / AGENTS.md / docs/ARCHITECTURE.md
- 脚本模板骨架 (docs/ARCHITECTURE.md)
- 完善 README 快速入口、日常管理、选型、故障排查与安全说明
- 统一开发文档中的版本策略、远程启动器行为和本地验证流程
