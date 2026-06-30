# Requirements Document

## Introduction

本特性包含两大部分：(1) 对现有四个 Shell 脚本（hy2.sh、ss.sh、euservhy2.sh、install.sh）进行全面的 Bug 修复与性能/健壮性优化；(2) 新增 AnyTLS 协议支持，提供独立的 `anytls.sh` 管理脚本并集成到 `install.sh` 统一启动器中。AnyTLS 是一种通过模拟真实 TLS 行为来规避"TLS in TLS"指纹检测的代理协议，使用 TCP 传输，适合 UDP 受限网络。

## Glossary

- **脚本管理器 (Script_Manager)**：指 `hy2.sh`、`ss.sh`、`euservhy2.sh`、`anytls.sh` 中任一管理脚本
- **启动器 (Launcher)**：指 `install.sh`，统一远程入口
- **AnyTLS_Server**：AnyTLS 服务端二进制（`anytls-go`），从 `github.com/anytls/anytls-go` 发布页获取
- **AnyTLS_脚本 (AnyTLS_Script)**：新增的 `anytls.sh` 管理脚本
- **自动更新器 (Auto_Updater)**：由 cron 定时执行的自动升级脚本
- **服务管理层 (Service_Layer)**：systemd 或 OpenRC 服务管理
- **防火墙层 (Firewall_Layer)**：ufw / firewalld / iptables / ip6tables 的统一操作
- **下载器 (Downloader)**：负责从 GitHub Releases 下载二进制的函数逻辑
- **配置生成器 (Config_Generator)**：生成 AnyTLS 服务端 YAML/JSON 配置的逻辑
- **分享链接生成器 (Share_Link_Generator)**：生成客户端导入链接和二维码的逻辑
- **YAML_Editor**：使用 awk 块检测修改 YAML 配置的逻辑
- **备份回滚器 (Backup_Rollback)**：升级或配置修改前的备份与失败回滚机制
- **网络检测器 (Network_Detector)**：检测 IPv4/IPv6/NAT/WARP 状态的逻辑

## Requirements

### Requirement 1: 脚本健壮性与错误处理优化

**User Story:** 作为 VPS 管理员，我希望脚本在各种异常情况下能够优雅处理并给出清晰反馈，以避免系统处于不一致状态。

#### Acceptance Criteria

1. IF 下载器在获取二进制时连接超时（connect-timeout 15 秒）或传输超时（max-time 60 秒）或返回非 200 状态，THEN THE 下载器 SHALL 切换到备用下载源重试一次，若仍失败则返回非零退出码、输出包含失败原因的错误提示，并保留当前已安装的二进制文件不变
2. IF 服务管理层启动服务后通过 `systemctl is-active --quiet` 或 `rc-service status` 检测到服务未处于 active/started 状态（等待最多 3 秒），THEN THE 脚本管理器 SHALL 从 `.bak` 备份文件恢复上一个可用版本、重启服务，并向用户输出包含"回滚"字样的提示信息
3. WHEN 用户输入端口号，THE 脚本管理器 SHALL 验证输入为 1-65535 范围内的纯数字整数，且通过 `ss -tlnp` 或 `netstat -tlnp` 确认该端口当前未被其他进程监听，验证失败时输出具体原因并要求重新输入
4. WHEN 用户输入密码，THE 脚本管理器 SHALL 验证输入长度为 1-128 个字符，且不包含双引号、反斜杠、美元符、反引号或控制字符（正则 `["\\$\x60]|[[:cntrl:]]`），验证失败时输出被禁止的字符类别并拒绝该输入
5. IF 配置修改过程中写入新配置后服务重启失败或写入操作本身返回非零状态，THEN THE YAML_Editor SHALL 从 mktemp 创建的备份文件恢复原始配置、重启服务，并返回非零退出码
6. WHILE 自动更新器执行升级流程，THE 自动更新器 SHALL 以 `[时间戳] 操作描述` 格式将版本检查、下载、备份、替换、服务重启各步骤结果追加写入日志文件，并在任一步骤失败时从 `.bak` 备份二进制恢复、重启服务，且将失败原因写入同一日志文件
7. IF 下载器或自动更新器在创建备份文件时失败（cp 返回非零状态），THEN THE 脚本管理器 SHALL 取消当前升级操作、输出错误提示，并保留现有版本不变

### Requirement 2: 跨发行版兼容性保证

**User Story:** 作为使用不同 Linux 发行版的 VPS 用户，我希望脚本能在所有支持的系统上正确运行，无需手动适配。

#### Acceptance Criteria

1. THE 脚本管理器 SHALL 在 Debian、Ubuntu、CentOS、Rocky、AlmaLinux、Fedora、Arch、Alpine 上通过 `bash -n` 语法检查且退出码为 0
2. THE 脚本管理器 SHALL 避免使用以下 busybox 不兼容的语法：`grep -oP`、`grep -P`、`${var,,}`、`${var^^}`、`head -c`、`readarray`、`mapfile`、`declare -A`（关联数组）、`[[ =~ ]]` 中的非 POSIX 扩展正则
3. WHEN 脚本在无 bash 的环境中首次运行，THE 脚本管理器 SHALL 通过系统包管理器（apk/apt/yum/dnf/pacman）安装 bash 并通过 `exec bash "$0" "$@"` 重新执行自身
4. IF bash 自动安装失败（包管理器返回非零退出码），THEN THE 脚本管理器 SHALL 输出错误信息指明安装失败的原因并以退出码 1 终止执行
5. THE 脚本管理器 SHALL 同时支持 systemd 和 OpenRC 两种 init 系统的服务操作，包括：注册（创建服务文件）、启动、停止、重启、开机自启、查看状态
6. WHEN 防火墙层需要放行端口，THE 防火墙层 SHALL 按优先级顺序检测 ufw、firewalld、iptables，使用首个检测到的工具添加规则；重复执行同一规则时不产生错误输出且不创建重复条目
7. IF 系统中未检测到 ufw、firewalld、iptables 中的任何一个，THEN THE 防火墙层 SHALL 跳过防火墙配置并输出提示信息告知用户未找到防火墙工具
8. THE 脚本管理器 SHALL 在所有字符串比较和文本处理中使用 POSIX 兼容的 `tr`、`awk`、`sed` 替代 bash 4.x+ 特有语法

### Requirement 3: 网络检测与 NAT 支持优化

**User Story:** 作为 NAT VPS 或纯 IPv6 环境的用户，我希望脚本能准确检测网络状态并正确配置代理服务。

#### Acceptance Criteria

1. WHEN 网络检测器检测 IPv6 地址时，THE 网络检测器 SHALL 排除名称匹配 wgcf、warp、tun*、wg*、tailscale、zt* 的网卡所持有的地址，且排除 fe80 开头的链路本地地址
2. WHEN 网络检测器检测 IPv4 时，THE 网络检测器 SHALL 依次请求至少 3 个外部 API（连接超时 3 秒，总超时 6 秒），任一返回合法 IPv4 即停止；IF 全部超时，THEN THE 网络检测器 SHALL 判定为无 IPv4
3. WHILE 处于 NAT 模式，THE 脚本管理器 SHALL 分别记录内网监听端口（LISTEN_PORT）与外网映射端口（EXT_PORT），并在分享链接与客户端配置中统一使用 EXT_PORT 作为连接端口
4. IF 所有 IP 检测 API 均不可达，THEN THE 网络检测器 SHALL 回退到本机非 loopback、非 link-local 的物理网卡 global scope 地址，并向用户输出警告提示需手动确认公网 IP
5. WHEN 生成节点分享链接时，IF 检测到 PUBLIC_IP 非空，THEN THE 分享链接生成器 SHALL 生成 IPv4 节点链接；IF 检测到 PUBLIC_IPV6 非空，THEN THE 分享链接生成器 SHALL 生成 IPv6 节点链接（双栈环境下两者均生成）
6. WHEN 网络检测器检测 IPv6 时，THE 网络检测器 SHALL 依次请求至少 2 个外部 IPv6 API（总超时 6 秒），任一返回含冒号的合法地址即停止；IF 全部超时，THEN THE 网络检测器 SHALL 判定为无公网 IPv6

### Requirement 4: 升级与自动更新机制

**User Story:** 作为长期运行代理节点的用户，我希望能安全地升级二进制版本，且自动更新在升级失败时不会破坏服务。

#### Acceptance Criteria

1. WHEN 执行升级操作时，THE 备份回滚器 SHALL 在删除旧二进制前通过 `cp "$BIN" "${BIN}.bak"` 将其复制到 `.bak` 文件，若 cp 返回非零状态则取消升级并输出错误提示
2. WHEN 下载新版本二进制后，THE 下载器 SHALL 通过执行 `"$tmp_bin" version` 或读取 ELF magic bytes（`\x7fELF`）验证文件为有效的可执行格式，验证失败则删除临时文件并返回非零退出码
3. IF 升级后服务启动失败（等待最多 3 秒后 service_is_active 返回 false），THEN THE 备份回滚器 SHALL 用 `.bak` 文件恢复旧版本、重启服务，并输出包含旧版本号的回滚确认信息
4. WHEN 设置自动更新 cron 时，THE 脚本管理器 SHALL 验证 crontab 命令可用（`command -v crontab`），若不可用则尝试安装对应发行版的 cron 软件包，安装后仍不可用则输出错误并跳过自动更新配置
5. THE 自动更新器 SHALL 在升级日志文件中以 `[YYYY-MM-DD HH:MM:SS] 操作: 结果` 格式记录旧版本号、新版本号、下载结果、替换结果和服务重启结果
6. WHEN 用户选择移除自动更新时，THE 脚本管理器 SHALL 从 crontab 中删除对应条目、删除自动更新脚本文件和日志文件，并输出移除成功的确认信息

### Requirement 5: 防火墙规则管理优化

**User Story:** 作为 VPS 管理员，我希望防火墙规则能被正确且幂等地管理，避免重复插入或遗漏 IPv6 规则。

#### Acceptance Criteria

1. WHEN 防火墙层通过 iptables/ip6tables 添加规则时，THE 防火墙层 SHALL 先使用 `-C`（check）命令检测规则是否已存在，已存在则跳过插入；对于 ufw 和 firewalld，THE 防火墙层 SHALL 直接调用其原生幂等的 allow/add-port 命令
2. WHEN 系统同时具备 IPv4 和 IPv6 网络栈时，THE 防火墙层 SHALL 同时为 iptables 和 ip6tables 添加对应的放行规则；IF 系统仅具备 IPv4 或仅具备 IPv6，THEN THE 防火墙层 SHALL 仅为可用的协议栈添加规则并跳过不可用的协议栈
3. WHEN Hysteria 2 启用端口跳跃时，THE 防火墙层 SHALL 使用单条端口范围规则（ufw 格式 `start:end/proto`、firewalld 格式 `start-end/proto`、iptables 格式 `--dport start:end`）而非逐个端口添加
4. WHEN 卸载服务时，THE 防火墙层 SHALL 移除该服务安装时添加的所有防火墙规则，包括单端口规则和端口范围规则，覆盖所有已放行的协议（TCP 和/或 UDP）
5. IF 未检测到任何已知防火墙工具（ufw、firewalld、iptables）或防火墙命令返回非零退出码，THEN THE 防火墙层 SHALL 输出包含端口号和协议的警告信息并提示用户手动配置，且不阻断安装流程（函数返回成功状态）
6. WHEN 防火墙层通过 iptables/ip6tables 成功添加或删除规则后，THE 防火墙层 SHALL 尝试持久化规则（通过 iptables-save、netfilter-persistent 或 service iptables save），使规则在系统重启后仍然生效

### Requirement 6: AnyTLS 协议安装与管理

**User Story:** 作为需要规避 TLS 指纹检测的用户，我希望能像管理 Hysteria 2 和 Shadowsocks 一样一键安装和管理 AnyTLS 服务。

#### Acceptance Criteria

1. WHEN 用户选择安装 AnyTLS，THE AnyTLS_脚本 SHALL 通过 GitHub API 从 `github.com/anytls/anytls-go` 获取最新 release 版本号，并下载对应架构（amd64 或 arm64）的二进制文件到 mktemp 创建的临时文件
2. THE AnyTLS_脚本 SHALL 通过 `uname -m` 检测系统架构并映射：x86_64→amd64、aarch64/arm64→arm64，其他架构输出不支持错误并返回
3. WHEN 下载完成后，THE AnyTLS_脚本 SHALL 验证二进制有效性（执行 version 子命令或检查 ELF magic bytes），验证通过后移动到 `/usr/local/bin/anytls` 并设置可执行权限
4. WHEN 安装完成后，THE AnyTLS_脚本 SHALL 根据 INIT_SYS 变量注册 systemd service 文件或 OpenRC init 脚本，启用开机自启并启动服务
5. WHEN 用户执行升级操作，THE AnyTLS_脚本 SHALL 按顺序执行：备份当前二进制→获取最新版本→下载→验证→替换→重启服务→检查状态→失败则回滚
6. WHEN 用户执行卸载操作，THE AnyTLS_脚本 SHALL 按顺序执行：停止服务→禁用开机自启→删除服务文件→删除二进制和 .bak→删除配置目录→删除证书文件→删除自动更新脚本和日志→清除 crontab 条目→移除防火墙规则
7. THE AnyTLS_脚本 SHALL 提供交互式主菜单，包含以下选项：安装、升级、卸载、修改配置、查看节点信息、服务器工具、退出

### Requirement 7: AnyTLS 配置管理

**User Story:** 作为用户，我希望能通过交互式菜单设置和修改 AnyTLS 的端口、密码、SNI 和 TLS 证书配置。

#### Acceptance Criteria

1. WHEN 首次安装时，THE 配置生成器 SHALL 引导用户设置监听端口（默认 443）、密码（留空则自动生成 20 位字母数字随机密码）和 SNI 域名（默认 bing.com）
2. THE 配置生成器 SHALL 使用自签证书模式，通过 openssl 自动生成有效期 3650 天的 TLS 证书和私钥文件，证书 CN 字段设置为用户指定的 SNI 域名
3. WHEN 用户选择修改配置，THE YAML_Editor SHALL 支持单独修改端口、密码或 SNI，并在修改前将原配置备份到同目录下带时间戳的备份文件
4. IF 用户提供的 SNI 域名未通过域名格式校验（仅允许字母、数字、点号和连字符组成的合法域名，不含端口号和协议前缀），THEN THE 配置生成器 SHALL 拒绝该输入并提示用户输入纯域名格式
5. WHEN 配置修改完成后，THE AnyTLS_脚本 SHALL 重启服务并在 3 秒后检查进程是否存活来验证服务正常运行
6. IF 配置修改后服务重启失败（进程未存活），THEN THE AnyTLS_脚本 SHALL 从备份文件恢复原始配置、重新启动服务并提示用户修改未生效
7. IF NAT_MODE=1，THEN THE 配置生成器 SHALL 分别提示用户输入本机监听端口和对外映射端口，并将两者分别存储到元数据目录

### Requirement 8: AnyTLS 客户端配置输出

**User Story:** 作为用户，我希望安装完成后能获得可直接导入各种客户端的配置信息和分享链接。

#### Acceptance Criteria

1. WHEN 用户查看节点信息时，THE 分享链接生成器 SHALL 输出适用于 Clash Meta（mihomo）的 AnyTLS 代理配置片段，包含 name、type（anytls）、server、port、password、sni、skip-cert-verify 字段
2. WHEN 用户查看节点信息时，THE 分享链接生成器 SHALL 输出适用于 Shadowrocket 的 URI 格式导入链接（使用 AnyTLS 协议对应的 URI scheme）
3. WHEN 用户查看节点信息时，THE 分享链接生成器 SHALL 输出包含服务器地址、端口、密码、SNI 四项连接参数的文本摘要
4. WHERE 系统已安装 qrencode，WHEN 用户查看节点信息时，THE 分享链接生成器 SHALL 对 Shadowrocket 导入链接调用 `qrencode -t ANSIUTF8` 生成可扫描的终端二维码
5. WHEN 处于 NAT 模式时，THE 分享链接生成器 SHALL 在所有输出（配置片段、导入链接、文本摘要）中使用外网映射端口替代本机监听端口，并使用公网 IP 作为服务器地址
6. IF 配置文件不存在或无法读取，THEN THE 分享链接生成器 SHALL 输出错误提示并返回，不输出任何配置片段
7. WHEN 服务器同时具有 IPv4 和 IPv6 地址时，THE 分享链接生成器 SHALL 分别输出两组完整的客户端配置（每组包含对应 IP 版本的配置片段、导入链接和二维码）

### Requirement 9: 启动器集成 AnyTLS

**User Story:** 作为用户，我希望从统一入口 `install.sh` 中能选择安装和管理 AnyTLS，与现有协议并列。

#### Acceptance Criteria

1. THE 启动器 SHALL 在主菜单"主要代理协议"分区中新增编号为 4 的 AnyTLS 选项，显示格式与 Hysteria 2、Shadowsocks 选项一致，输入有效范围更新为 0-4
2. WHEN 用户选择 AnyTLS 选项，THE 启动器 SHALL 调用现有 `run_script` 函数从 `${BASE_URL}/anytls.sh` 下载脚本（连接超时 15 秒，总超时 60 秒），写入临时文件，执行语法检查通过后运行，运行完毕或失败后删除临时文件
3. THE 启动器 SHALL 在 AnyTLS 菜单项下方的状态行显示 AnyTLS 服务的当前状态：若 AnyTLS 二进制文件存在且服务处于运行状态则显示"运行中"及版本号，若二进制文件存在但服务未运行则显示"已停止"及版本号
4. IF AnyTLS 二进制文件不存在，THEN THE 启动器 SHALL 在 AnyTLS 状态行显示"未安装"标记
5. IF 下载 `anytls.sh` 失败或下载内容语法检查未通过，THEN THE 启动器 SHALL 显示错误提示信息，在 3 秒内返回主菜单，且不执行任何已下载的内容

### Requirement 10: 静态验证与 CI 集成

**User Story:** 作为开发者，我希望新增的 AnyTLS 脚本和修改后的现有脚本都能通过自动化静态验证。

#### Acceptance Criteria

1. THE `tests/validate_scripts.sh` SHALL 在 SCRIPTS 变量中包含 `anytls.sh`，使其接受 `bash -n` 语法检查、CRLF 检查和兼容性规则检查（grep -oP、${var,,} 等）
2. THE `tests/validate_scripts.sh` SHALL 使用 awk 提取 `anytls.sh` 中 heredoc 生成的自动更新脚本内容，并对提取内容执行 `bash -n` 语法检查
3. WHEN 任何脚本包含 CRLF 换行符（`\r`），THE `tests/validate_scripts.sh` SHALL 输出包含文件名的错误信息到 stderr 并以非零状态退出
4. THE `tests/validate_scripts.sh` SHALL 验证 `anytls.sh` 的文件头版本号和菜单版本文本均与 EXPECTED_VERSION 变量一致
5. THE GitHub Actions 工作流 SHALL 在推送和 PR 事件触发时自动运行 `bash tests/validate_scripts.sh`，失败时阻断合并

### Requirement 11: AnyTLS 服务器工具集成

**User Story:** 作为用户，我希望 AnyTLS 脚本也提供 BBR 加速、自动更新和系统信息等服务器工具功能。

#### Acceptance Criteria

1. WHEN 用户选择启用 BBR，THE AnyTLS_脚本 SHALL 检查内核版本（主版本号和次版本号），IF 内核版本 >= 4.9 THEN 将拥塞控制算法设置为 bbr（内核 >= 5.15 时尝试 bbr3，不可用则回落至 bbr）并将队列调度设置为 fq，将配置写入 sysctl 配置文件使其重启后持续生效，并显示启用成功的确认信息
2. IF 用户选择启用 BBR 时内核版本低于 4.9，THEN THE AnyTLS_脚本 SHALL 显示错误信息指示内核版本过低不支持 BBR，且不修改任何系统网络配置
3. WHEN 用户选择启用自动更新，THE AnyTLS_脚本 SHALL 创建自动更新脚本文件并注册每日 03:00 执行的 cron 任务，IF crontab 命令不可用 THEN 先尝试根据发行版自动安装 cron 软件包（Alpine 安装 dcron、Arch 安装 cronie、CentOS/Rocky/Fedora 安装 cronie、其他使用 apt 安装 cron）
4. IF 安装 cron 软件包后 crontab 命令仍不可用，THEN THE AnyTLS_脚本 SHALL 显示错误信息指示 cron 安装失败且无法配置自动更新，不创建 cron 条目
5. WHEN 用户选择查看系统信息，THE AnyTLS_脚本 SHALL 展示以下信息项：操作系统名称、内核版本、CPU 架构、CPU 型号及核心数、已用内存/总内存（MB）、磁盘使用量、系统负载、运行时间、当前 BBR 状态和自动更新状态
6. THE AnyTLS_脚本 SHALL 在服务器工具子菜单中提供以下选项：一键开启 BBR、查看 BBR 状态、开启自动更新、关闭自动更新、查看自动更新日志、系统信息总览，以及返回上级菜单的选项
7. WHEN 用户选择移除自动更新，THE AnyTLS_脚本 SHALL 从 crontab 中删除对应的自动更新条目、删除自动更新脚本文件和日志文件，并显示移除成功的确认信息

### Requirement 12: 脚本模板一致性

**User Story:** 作为维护者，我希望所有脚本遵循统一的代码模板和约定，降低维护成本。

#### Acceptance Criteria

1. THE AnyTLS_脚本 SHALL 以 `docs/ARCHITECTURE.md` 脚本模板为权威参考，包含完全相同的三段前置代码：bash 自举（`[ -z "$BASH_VERSION" ] && exec bash "$0" "$@"`）、TTY 修复（`[ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty`）、CRLF guard（`grep -q $'\r' "$0" && sed -i 's/\r$//' "$0" && exec bash "$0" "$@"`）
2. THE AnyTLS_脚本 SHALL 定义以下颜色变量且赋值与现有脚本完全一致：RED='\033[0;31m'、GREEN='\033[0;32m'、YELLOW='\033[1;33m'、BLUE='\033[0;34m'、CYAN='\033[0;36m'、PLAIN='\033[0m'
3. THE AnyTLS_脚本 SHALL 遵循 `docs/ARCHITECTURE.md` 中定义的函数命名约定（下划线分隔小写：check_root、detect_init、download_anytls、install_anytls、upgrade_anytls、uninstall_anytls、service_start、service_stop、service_restart、show_config、main_menu）和全局变量命名约定（全大写下划线分隔：BIN、CONFIG、META、SERVICE、INIT_SYS、NAT_MODE、PUBLIC_IP）
4. THE AnyTLS_脚本 SHALL 在文件头注释块中包含以下元信息字段：项目名称、版本号（格式 vX.Y.Z）、更新日期（格式 YYYY-MM-DD）
5. WHEN 下载函数（download_anytls）或任何执行网络 I/O 的函数失败时，THE AnyTLS_脚本 SHALL 使用 `return 1` 而非 `exit 1`，由调用方（install_anytls、upgrade_anytls）决定是否终止或回滚
6. THE `tests/validate_scripts.sh` SHALL 能够通过现有兼容性规则检查验证 AnyTLS_脚本不含 `grep -oP`、`${var,,}`、`${var^^}`、`head -c` 等禁止语法
