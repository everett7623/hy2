# Design Document: script-optimization-anytls (v1.1.0)

## Overview

本次升级将 hy2 项目从 v1.0.2 推进至 v1.1.0，涵盖四个方向：

1. **hy2.sh / ss.sh 脚本优化**：代码质量、健壮性和 UX 全面改进
2. **Bug 修复**：边界条件、异常处理、兼容性问题
3. **版本号统一递增**：所有脚本、菜单字符串、验证器、CHANGELOG 同步至 v1.1.0
4. **新增 AnyTLS 协议支持**：独立管理脚本 anytls.sh + install.sh 启动器集成

### 范围说明

- **anytls.sh** 已存在于仓库（v1.0.2），但包含若干 bug（见下文），需要修复后才能通过 `tests/validate_scripts.sh`
- **euservhy2.sh** 不在本次优化范围内（SCRIPT_VERSION 单独维护）
- 所有改动必须保持"零依赖独立脚本"架构：无 `source`/`include`，公共代码复制到每个脚本
- 所有脚本必须通过 `bash tests/validate_scripts.sh`，且保持 LF 换行 + UTF-8 编码

---

## Architecture

### 脚本执行模型

```
用户运行 install.sh (bash <(curl -fsSL URL))
        │
        ├─ 选项 1 ──→ run_script "Hysteria2" $HY2_URL   → 下载 hy2.sh 到 tmpfile → bash "$tmpfile"
        ├─ 选项 2 ──→ run_script "Shadowsocks" $SS_URL  → 下载 ss.sh 到 tmpfile  → bash "$tmpfile"
        ├─ 选项 3 ──→ run_script "EUserv" $EUSERV_URL   → 下载 euservhy2.sh      → bash "$tmpfile"
        └─ 选项 4 ──→ run_script "AnyTLS" $ANYTLS_URL  → 下载 anytls.sh         → bash "$tmpfile"
```

每个子脚本也可独立运行（`bash anytls.sh`）。

### 每个脚本的启动顺序（三段式保护）

```
1. Bash 自举      ─ [ -z "$BASH_VERSION" ] → exec bash "$0" "$@"（含 apk/apt-get/dnf/yum 安装）
2. TTY fix        ─ [ ! -t 0 ] && [ -c /dev/tty ] && exec < /dev/tty
3. CRLF guard     ─ grep -q $'\r' "$0" → sed -i 's/\r$//' → exec bash "$0" "$@"
```

### 文件系统布局

```
/usr/local/bin/anytls-go           ← AnyTLS 主二进制（Go 单文件，原名 anytls-go）
/etc/anytls/config.yaml            ← 服务端配置
/etc/anytls/cert/cert.pem          ← 自签 TLS 证书
/etc/anytls/cert/key.pem           ← TLS 私钥
/etc/anytls/meta/                  ← 元数据目录
  LISTEN_PORT, EXT_PORT, PASSWORD, SNI, NAT_MODE, PUBLIC_IP, PUBLIC_IPV6
/etc/systemd/system/anytls-server.service
/etc/init.d/anytls-server          ← OpenRC 服务脚本
/var/run/anytls.pid                ← nohup 模式 PID 文件
/var/log/anytls.log                ← nohup 模式日志
/usr/local/bin/anytls-autoupdate.sh
/var/log/anytls-autoupdate.log
/etc/sysctl.d/99-anytls-bbr.conf
```

> **注意**：需求文档 Glossary 中提及 `anytls-server` 作为二进制名，但现有 `anytls.sh` 实际使用 `anytls-go`（下载自 `anytls/anytls-go` releases，文件名为 `anytls-linux-{arch}`）。设计以现有实现为准，保持 `/usr/local/bin/anytls-go`，避免破坏性重命名。`service_is_active` 检测使用 systemd 服务名 `anytls-server`。


---

## Components and Interfaces

### 1. anytls.sh — AnyTLS 管理脚本

#### 1.1 现有问题（需修复）

| 问题 | 位置 | 修复方案 |
|------|------|----------|
| `head -c` 违反 busybox 兼容性约束 | `validate_binary()`（3处）, `install_anytls()` 密码生成 | 替换为 `od -An -tx1 \| awk` 读取前4字节；密码改用 `openssl rand -base64 16 \| tr -d '/+='` |
| `ip` 命令被当作独立语句执行 | `detect_network()` 第149、160行（`ip` 孤立行）| 删除孤立的 `ip` 语句 |
| `LOCAL_IP` 和 `LOCAL_IPV6` 变量在赋值前被当作命令执行 | `detect_network()` 第170、180行 | 删除 `LOCAL_IP` 和 `LOCAL_IPV6` 孤立行 |
| IPv6 检测未过滤 `-s6` curl 选项（可能混用 IPv4 API 和 IPv6 强制选项） | `detect_network()` IPv6循环 | 为 IPv6 API 添加 `--max-time 6`，为 IPv4 API 添加 `--connect-timeout 3`（需求6.2） |
| `detect_network()` 缺少 WARP/tunnel 接口过滤 | IPv4 public IP 检测 | 添加 `ip` 命令接口过滤（与 ss.sh 保持一致） |
| `gen_config()` 将 `VERSION=$(get_latest_version)` 写入 meta | `gen_config()` | 保留版本信息但避免嵌套调用产生副作用 |
| `change_port()` 中 `close_firewall_port` 读取 `${ANYTLS_META}.bak` 但备份不存在 | `change_port()` | 在修改前保存旧端口到局部变量，而非从备份文件读取 |
| `install_anytls()` 不调用 `detect_init()` 也不调用 `check_sys()` 在 deps 安装前 | `install_anytls()` | 确保 `check_sys()` 和 `detect_init()` 在 `install_dependencies()` 前调用（已调用） |
| 默认端口为 14444，需求要求默认 443 | `install_anytls()` 端口提示 | 修改默认端口为 443 |
| `show_config()` 使用 `. "$ANYTLS_META/config"` source 元数据但缺少 NAT_MODE 读取 | `show_config()` | 完善 show_config：读取 NAT_MODE，支持双栈节点分别输出，生成完整客户端配置（Clash Meta/Surfboard/URI） |
| `service_start()` 在 systemd 分支中 enable，但不应在 start 时 enable | `service_start()` | 分离 start 和 enable 职责 |
| `uninstall_anytls()` 在删除 meta 目录后才读取其内容 | `uninstall_anytls()` | 先读取端口再删除 |
| 缺少 `show_config` 配置读取失败时的优雅降级 | `show_config()` | 检测 meta 文件缺失并显示错误消息（需求3.8） |
| `detect_network()` 使用 `awk` 的 `getline` 内循环解析 inet6，逻辑有误 | IPv6本地回退检测 | 简化为标准 awk 单次扫描，与 hy2.sh/ss.sh 保持一致 |

#### 1.2 函数清单（完整实现）

```
check_root()           — EUID 检查
check_sys()            — 发行版检测 → RELEASE 变量
detect_init()          — systemd/openrc/none → INIT_SYS 变量
detect_network()       — IPv4/IPv6/NAT/IPv6-only 检测（含 WARP 过滤）
install_dependencies() — 按 RELEASE 分支安装 curl/wget/openssl/ca-certs
validate_port()        — 整数 [1,65535] 检查（无前导零）
validate_password()    — 长度/禁用字符检查
validate_domain()      — 域名格式检查
validate_binary_elf()  — ELF magic 检查（busybox-safe：od + awk，不用 head -c）
get_latest_version()   — GitHub API 获取最新版本号
download_anytls()      — 下载二进制，mktemp → validate → mv，return 1 不 exit
backup_binary()        — cp $BIN ${BIN}.bak
rollback_binary()      — mv ${BIN}.bak $BIN
open_firewall_port()   — ufw/firewalld/iptables TCP 单端口，含 ip6tables
close_firewall_port()  — 反向规则（卸载/端口修改时使用）
gen_cert()             — openssl 自签证书（SNI 作 CN）
gen_config()           — 写入 config.yaml
save_meta()            — 写入 /etc/anytls/meta/ 各文件
read_meta()            — 从 meta 文件读取配置变量
show_config()          — 输出节点信息：双栈分别输出，含 URI/Clash/Surfboard/QR
service_start()        — systemd start / openrc start / nohup
service_stop()         — systemd stop / openrc stop / kill PID
service_restart()      — 重启
service_enable()       — systemd enable + daemon-reload / openrc add
service_disable()      — systemd disable / openrc del
service_is_active()    — systemd is-active / openrc status / kill -0 PID
service_logs()         — journalctl / tail log file
setup_systemd_service()— 写入 systemd unit 文件
setup_openrc_service() — 写入 OpenRC init 脚本
setup_none_service()   — nohup + PID 文件模式（INIT_SYS=none）
install_anytls()       — 完整安装流程
upgrade_anytls()       — 升级（备份 → 下载 → 重启 → 验证 → 回滚）
uninstall_anytls()     — 停服 → 删服务文件 → 删二进制 → 删配置 → 删 cron
change_port()          — 端口修改（备份 → 修改 → 重启 → 验证 → 回滚）
change_password()      — 密码修改
change_sni()           — SNI 修改 + 重新生成证书
enable_bbr()           — 内核版本检测 + BBR3/BBR 选择
setup_autoupdate()     — 创建 /usr/local/bin/anytls-autoupdate.sh + cron
remove_autoupdate()    — 删除 cron + 脚本文件
show_sys_info()        — 系统信息（OS/内核/CPU/内存/BBR/自动更新状态）
server_tools_menu()    — 服务器工具子菜单
main_menu()            — 主菜单循环
```


### 2. install.sh — 启动器集成

**新增改动**：
- 添加 `ANYTLS_URL="${BASE_URL}/anytls.sh"` 常量
- `get_status()` 中增加 AnyTLS 状态检测（`/usr/local/bin/anytls-go` 文件检测 + `anytls-server` 服务状态）
- 主菜单增加选项 4（AnyTLS），更新选项范围提示为 `[0-4]`
- `case "$choice"` 分支增加 `4) run_script "AnyTLS" "$ANYTLS_URL" ;;`
- 版本号 `v1.0.2` → `v1.1.0`

**AnyTLS 状态检测逻辑**（与 HY2/SS 保持一致格式）：
```bash
if [ -f "/usr/local/bin/anytls-go" ]; then
    _ver=$(/usr/local/bin/anytls-go version 2>/dev/null | head -1)
    if service_active anytls-server /var/run/anytls.pid; then
        ANYTLS_STATUS="${GREEN}● 运行中${PLAIN}${DIM} ${_ver}${PLAIN}"
    else
        ANYTLS_STATUS="${YELLOW}● 已停止${PLAIN}${DIM} ${_ver}${PLAIN}"
    fi
else
    ANYTLS_STATUS="${RED}● 未安装${PLAIN}"
fi
```

### 3. hy2.sh 优化点

| 需求 | 当前状态 | 修复内容 |
|------|----------|----------|
| 6.1 密码生成 | `gen_password()` 已实现循环重试，20位 | 已符合要求；确认 tr 过滤为 `A-Za-z0-9` |
| 6.2 IPv4 connect-timeout 3s | 已有 `--connect-timeout 3` | 确认存在 |
| 6.3 auto-update 回滚逻辑 | auto-update 脚本中有备份，但验证逻辑需检查 | 确保 service 验证后再 rm bak，失败时 rollback |
| 6.4 端口跳跃 colon→dash | 已有 `tr ':' '-'` | 确认存在 |
| 6.5 show_config meta 缺失回退 | 当前仅 parse config.yaml 作为兜底 | 明确在无 meta 且无 config.yaml 时显示错误并 return |
| 6.6 mktemp 失败 return 1 | `download_hy2()` 已有 `return 1` | 确认存在 |
| 8.x 通用优化 | trap/sleep/空值检查 | 见§通用优化 |

**版本号**：文件头 `v1.0.2` → `v1.1.0`，菜单中 `Hysteria2 Management Script v1.0.2` → `v1.1.0`

### 4. ss.sh 优化点

| 需求 | 当前状态 | 修复内容 |
|------|----------|----------|
| 7.1 timedatectl 不可用警告 | 当前静默失败 | 检测 timedatectl 可用性，失败时打印黄色警告 |
| 7.2 配置回滚恢复 config+meta | 当前 `modify_config()` 已有 meta 备份/恢复 | 确认恢复后 `service_restart` + `sleep 2` + `service_is_active` 验证 |
| 7.3 auto-update 二进制验证 | auto-update 脚本需在替换前验证 `ssserver --version` | 在 mv 前加 `ssserver --version > /dev/null 2>&1` 验证步骤 |
| 7.4 WARP IPv4 过滤 | 当前有 WARP 过滤但只检测是否有真实 IPv4 接口 | 明确排除 `warp*`, `wg*`, `tun*` 接口名 |
| 7.5 tar 失败清理 | `download_ss()` 已有清理 | 确认 `tar` 失败时同时清理 `_tmp_archive` 和 `_tmp_dir` |
| 7.6 连接测试超时 ≤10s | 需检查 | 确保 `nc`/`/dev/tcp` 探测 timeout ≤10s |

**版本号**：`v1.0.2` → `v1.1.0`，菜单中 `Shadowsocks-Rust Management Script v1.0.2` → `v1.1.0`

### 5. tests/validate_scripts.sh 更新

- `EXPECTED_VERSION="v1.0.2"` → `"v1.1.0"`
- `SCRIPTS` 列表已含 `anytls.sh`（现有文件已包含）
- euservhy2.sh 版本检查：`SCRIPT_VERSION="1.0.1"` → `SCRIPT_VERSION="1.1.0"`（当前为 `"1.0.1"` 见第84行）
- `CHANGELOG.md` 检查：已有 `## v1.0.2`，需改为 `## v1.1.0`

### 6. euservhy2.sh

仅更新版本相关字段：
- 文件头版本注释：`v1.0.2` → `v1.1.0`
- `SCRIPT_VERSION` 变量：`"1.0.1"` → `"1.1.0"`（注意：validate_scripts.sh 检查的是 `SCRIPT_VERSION`，格式无 `v` 前缀）
- 日期字段同步更新


---

## Data Models

### anytls.sh 配置文件格式

**config.yaml**（生成于 `/etc/anytls/config.yaml`）：
```yaml
listen: 0.0.0.0:{PORT}
cert: /etc/anytls/cert/cert.pem
key: /etc/anytls/cert/key.pem
sni: {SNI}
password: {PASSWORD}
```

**元数据目录** `/etc/anytls/meta/`：
```
LISTEN_PORT    # 本机监听端口
EXT_PORT       # 对外端口（NAT 模式下可能不同）
PASSWORD       # 连接密码（明文，权限 600）
SNI            # TLS SNI 域名
NAT_MODE       # 0 或 1
PUBLIC_IP      # 公网 IPv4（可能为空）
PUBLIC_IPV6    # 公网 IPv6（可能为空）
```

> 设计说明：沿用现有 `gen_config()` 中 `cat > "$ANYTLS_META/config"` 的单文件 source-able 格式，改为每个字段单独一个文件（与 hy2.sh 和 ss.sh 保持一致），便于 `read_meta()` 单独读取各字段。

### 客户端配置生成

**AnyTLS URI 格式**：
```
anytls://{PASSWORD}@{HOST}:{PORT}/?sni={SNI}&insecure=1#{NODE_NAME}
```
- IPv6 地址：`HOST` = `[{IPv6}]`
- 节点名：`AnyTLS-v4-{MMdd}` 或 `AnyTLS-v6-{MMdd}`

**Clash Meta YAML**：
```yaml
- name: 'AnyTLS-v4-{MMdd}'
  type: anytls
  server: {IP}
  port: {PORT}
  password: {PASSWORD}
  sni: {SNI}
  skip-cert-verify: true
```

**Surfboard 格式**：
```
AnyTLS-v4-{MMdd} = anytls, {IP}, {PORT}, {PASSWORD}, skip-cert-verify=true, sni={SNI}
```

**命令行示例**（`anytls-client` 参数格式，仅供参考）：
```
anytls-client -s {HOST}:{PORT} -p {PASSWORD} --sni {SNI} --insecure
```

### 自动更新脚本结构

`/usr/local/bin/anytls-autoupdate.sh` 嵌入于 `anytls.sh` 的 heredoc 中（marker: `AUTOUPDATE_EOF`），需通过 `bash -n` 语法检查（由 `validate_scripts.sh` 提取并验证）：

```bash
#!/bin/bash
# 关键逻辑：
# 1. 获取最新版本
# 2. 比较当前版本（anytls-go version 输出第一行）
# 3. 如版本相同则跳过
# 4. 下载 → ELF 验证（od + awk，不用 head -c）→ 备份 → 替换
# 5. service restart → sleep 5 → 验证 active
# 6. 失败时 rollback → service restart
# 7. 所有事件写入 /var/log/anytls-autoupdate.log，格式：[YYYY-MM-DD HH:MM:SS] 消息
```

> **validate_scripts.sh 约束**：自动更新脚本的 heredoc 起始标记必须是单引号引用的 `AUTOUPDATE_EOF`（如 `<<'AUTOUPDATE_EOF'`），确保 heredoc 内容不展开变量，同时让 validate_scripts.sh 的 awk 能正确提取内容。

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: 端口验证完备性

*For any* 字符串输入，`validate_port()` 当且仅当输入为整数且在 [1, 65535] 范围内且无前导零时返回 0，对所有其他输入（空字符串、非数字字符、超出范围的数字、前导零、浮点数）返回非零。

**Validates: Requirements 1.4, 2.2**

### Property 2: 密码验证完备性

*For any* 字符串输入，`validate_password()` 当且仅当输入非空、长度不超过 128 字符且不含双引号、反斜杠、反引号、美元符号或 ASCII 控制字符（0x00-0x1F, 0x7F）时返回 0。

**Validates: Requirements 1.5**

### Property 3: 配置输出完整性

*For any* 有效的配置参数组合（server_ip, port, password, sni），`show_config()` 的输出必须包含 server_ip、port、password、sni 的值，且 Clash Meta YAML 输出中包含所有必填字段（name, type, server, port, password, sni, skip-cert-verify）。

**Validates: Requirements 1.7, 3.1, 3.2, 3.3**

### Property 4: IPv6 地址括号封装

*For any* 包含冒号的 IP 地址字符串（即任意 IPv6 地址），生成的 URI、命令行示例和 Clash Meta server 字段中，该地址必须被方括号包围（`[{addr}]`）；对于不含冒号的 IPv4 地址，不添加方括号。

**Validates: Requirements 3.1**

### Property 5: 双/单栈节点输出完整性

*For any* 网络状态组合（仅 IPv4、仅 IPv6、双栈），`show_config()` 必须精确输出与可用地址数量相同的节点配置组：仅 IPv4 时输出 1 组，仅 IPv6 时输出 1 组，双栈时输出 2 组，无地址时输出错误消息。

**Validates: Requirements 3.6**

### Property 6: 密码自动生成字符集不变式

*For any* 调用 `gen_password()`（hy2.sh）的执行，返回值必须恰好为 20 个字符，且每个字符均属于集合 `[A-Za-z0-9]`。对 100+ 次调用均成立。

**Validates: Requirements 6.1**

### Property 7: 端口跳跃配置转换

*For any* 格式为 `START:END` 的端口跳跃范围字符串（其中 START 和 END 均为有效端口号），写入 `config.yaml` 的 `listen` 字段必须使用 `-` 作为分隔符（即 `:START-END`），而非原始的冒号格式（`:START:END`）。

**Validates: Requirements 6.4**

### Property 8: 防火墙接口过滤（WARP/tunnel 排除）

*For any* 包含 `wgcf`、`warp`、`tun`、`wg`、`tailscale` 或 `zt` 接口的本地网络配置，`detect_network()` 对 IPv4 和 IPv6 的公网地址检测结果不得包含这些接口上的地址；同时，`NAT_MODE` 判断仅基于非隧道接口的地址。

**Validates: Requirements 7.4**

### Property 9: 配置修改回滚原子性

*For any* 配置修改操作（端口/密码/加密方式），若服务重启后 `service_is_active` 返回失败，则配置文件和元数据目录必须被完整恢复至修改前的状态（即备份内容与当前文件内容一致）。

**Validates: Requirements 7.2, 1.9**

### Property 10: 禁用语法不存在不变式

*For any* 属于 `SCRIPTS` 列表的脚本文件，执行 `grep -qE 'grep -oP|head -c|\$\{[^}]+,,\}|\$\{[^}]+\^\^\}'` 必须返回非零（即没有禁用语法）。此性质对列表中每个文件均成立。

**Validates: Requirements 8.5, 10.4**

### Property 11: Bash 自举包管理器正确分发

*For any* Linux 发行版类型（Alpine/Debian-Ubuntu/Fedora/CentOS-RHEL），当 bash 不可用时，自举段必须使用与该发行版对应的包管理器：Alpine 使用 `apk`，Debian/Ubuntu 使用 `apt-get`，Fedora 使用 `dnf`，CentOS/RHEL/Rocky 使用 `yum` 或 `dnf`。

**Validates: Requirements 8.4, 10.5**

### Property 12: URI 编码纯 Bash 多字节处理

*For any* 包含多字节 UTF-8 字符的字符串，`uri_encode()` 的纯 Bash 降级路径必须为该字符的每个字节输出一个 `%XX` 序列（即 N 字节字符产生 N 个 `%XX`）。

**Validates: Requirements 8.6**

### Property 13: init 系统检测与服务文件创建对应性

*For any* init 系统类型，`detect_init()` 的检测结果与服务文件创建行为必须对应：INIT_SYS=systemd 时创建 `.service` 文件；INIT_SYS=openrc 时创建 `/etc/init.d/` 脚本；INIT_SYS=none 时不创建服务文件，使用 nohup+PID 模式。

**Validates: Requirements 10.3**

### Property 14: BBR 算法选择正确性

*For any* 内核版本字符串，BBR 优化的算法选择必须满足：版本 < 4.9 时显示错误并返回（不写入 sysctl）；4.9 ≤ 版本 < 5.15 时选择 BBR；版本 ≥ 5.15 时优先尝试 BBR3，BBR3 不可用时回退到 BBR。

**Validates: Requirements 9.5, 9.6**

### Property 15: 自动更新版本比较幂等性

*For any* 当前安装版本与最新版本相同的情况，自动更新脚本的执行不得触发任何下载、备份或服务重启操作，日志中应记录"已是最新版本"并退出。

**Validates: Requirements 9.2**


---

## Error Handling

### 下载失败处理

所有下载函数（`download_anytls`、`download_hy2`、`download_ss`）遵循相同模式：

```
mktemp → 失败 → return 1（不 exit，不继续下载）
wget   → 失败 → rm tmpfile → return 1
验证   → 失败 → rm tmpfile → return 1
mv     → 成功 → 返回 0
```

**关键约束**：下载函数使用 `return 1`，绝不使用 `exit 1`。调用方（`install_xxx`、`upgrade_xxx`）决定是否展示日志并 return。

### 服务启动验证

所有安装和升级流程在服务启动后必须：
1. `sleep 2`（或由命名变量控制的等待时间，如 `SVCWAIT=2`）
2. 调用 `service_is_active`
3. 成功 → 显示成功消息，删除备份
4. 失败 → 显示失败消息，如有备份则回滚，调用 `service_logs` 展示日志

### 配置修改回滚

```bash
# 修改前
cp "$CONFIG" "${CONFIG}.bak"
cp -a "$META"/. "$META_BAK"/

# 修改后重启失败时
cp "${CONFIG}.bak" "$CONFIG"
rm -rf "$META"
mkdir -p "$META"
cp -a "$META_BAK"/. "$META"/
service_restart
```

### mktemp 失败

```bash
_tmp=$(mktemp /tmp/prefix-XXXXXX 2>/dev/null) || {
    echo -e "${RED}无法创建临时文件${PLAIN}"
    return 1
}
```

### 元数据缺失时的 show_config 降级

1. 尝试从 `/etc/anytls/meta/` 读取各字段
2. 若 meta 目录不存在或关键字段为空，尝试解析 `config.yaml`（如 ss.sh 的回退逻辑）
3. 若 config.yaml 也不存在，显示错误消息并 return（不 exit）

### timedatectl 不可用（ss.sh）

```bash
if command -v timedatectl >/dev/null 2>&1; then
    timedatectl set-ntp true >/dev/null 2>&1
else
    echo -e "${YELLOW}[警告] timedatectl 不可用，SS-2022 要求系统时间精确，请手动确认时间同步${PLAIN}"
fi
```

### ip6tables 创建失败（防火墙）

```bash
if [ "$HAS_IPV6" = "1" ] && command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
        ip6tables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
        echo -e "  ${YELLOW}⚠ ip6tables 规则创建失败，继续安装${PLAIN}"
fi
```

### 无防火墙工具

```bash
echo -e "  ${YELLOW}⚠ 未检测到防火墙工具，请手动放行 TCP/${port}${PLAIN}"
```

### 依赖安装失败

每个核心依赖（curl、wget、openssl）在安装后验证可用性。若任意一个缺失，输出明确错误并以非零状态退出：
```bash
for _cmd in curl wget openssl; do
    command -v "$_cmd" >/dev/null 2>&1 || {
        echo -e "${RED}依赖安装失败: 缺少 ${_cmd}${PLAIN}"
        return 1
    }
done
```

---

## Testing Strategy

### 1. 静态验证（每次提交必须通过）

```bash
bash tests/validate_scripts.sh
```

验证内容：
- 所有脚本通过 `bash -n` 语法检查
- 无 CRLF 换行
- 版本号与 `EXPECTED_VERSION="v1.1.0"` 一致
- 无禁用语法（`grep -oP`、`${var,,}`、`${var^^}`、`head -c`）
- 自动更新脚本 heredoc 可提取且通过 `bash -n`
- euservhy2.sh 的 `SCRIPT_VERSION="1.1.0"`
- CHANGELOG.md 包含 `## v1.1.0` 段落

### 2. 属性测试

本项目使用 Bash 原生编写的属性测试（位于 `tests/` 目录），针对纯函数进行验证。使用 `tests/helpers/generators.bash` 和 `tests/helpers/validators.bash` 提供随机数据生成和断言。

每个属性测试运行 100 次迭代以覆盖边界条件。

**需实现的属性测试**（对应上文 Properties）：

| 属性 | 测试文件 | 核心生成器 |
|------|----------|------------|
| Property 1：端口验证 | `tests/test_validate_port.sh` | 随机整数、负数、字符串、边界值 1 和 65535 |
| Property 2：密码验证 | `tests/test_validate_password.sh` | 含/不含禁用字符的随机字符串，长度 0-200 |
| Property 3：配置输出完整性 | `tests/test_show_config_output.sh` | 随机 IP/端口/密码/SNI 组合 |
| Property 4：IPv6 括号封装 | `tests/test_ipv6_bracket.sh` | 随机 IPv6 地址字符串 |
| Property 5：双/单栈输出 | `tests/test_dual_stack_output.sh` | 4 种 (HAS_IPV4, HAS_IPV6) 组合 |
| Property 6：密码生成字符集 | `tests/test_gen_password.sh` | 调用 gen_password 100 次 |
| Property 7：端口跳跃转换 | `tests/test_port_hop_config.sh` | 随机有效端口范围 START:END |
| Property 8：WARP 接口过滤 | `tests/test_warp_filter.sh` | 模拟含/不含隧道接口的 ip 输出 |
| Property 10：禁用语法检查 | 已由 `validate_scripts.sh` 覆盖 | — |
| Property 11：Bash 自举包管理器 | `tests/test_bootstrap.sh` | 静态 grep 验证各发行版分支 |
| Property 12：URI 编码多字节 | `tests/test_uri_encode.sh` | 多字节 UTF-8 字符串（中文、emoji） |
| Property 14：BBR 算法选择 | `tests/test_bbr_selection.sh` | 不同内核版本号字符串 |
| Property 15：自动更新幂等 | `tests/test_autoupdate_skip.sh` | 当前版本=最新版本时验证无操作 |

**测试标签格式**（注释形式）：
```bash
# Feature: script-optimization-anytls, Property {N}: {property_text}
```

### 3. 集成测试（VPS 上执行）

按 `docs/TESTING.md` 矩阵，以下路径需在一次性 VPS 上验证：

**anytls.sh 最小验收**：
- 全新安装（Debian 12 systemd、Alpine OpenRC、无 init 系统）
- 服务启动、停止、重启、开机启动
- 升级成功（模拟新版本）、下载失败回滚、服务失败回滚
- 配置修改（端口/密码/SNI）成功与失败回滚
- 自动更新创建、手动执行、日志验证、移除
- BBR 启用（内核 ≥4.9 的系统）
- 卸载后服务、配置、cron 完全清理
- NAT 模式（内外端口不同）
- IPv6-only 环境

**hy2.sh / ss.sh 回归**：
- 确认现有功能未被版本号更新破坏
- 验证 timedatectl 警告路径（ss.sh）
- 验证端口跳跃配置文件写入（hy2.sh）

### 4. 单元测试示例

针对特定场景的确定性测试（非属性测试）：

- `show_config` 在 meta 目录不存在时显示错误消息并返回（Property 3 的边界）
- `validate_domain` 拒绝 `http://foo.com`、接受 `microsoft.com`（Property 2 相关）
- 自动更新脚本在版本相同时跳过下载（Property 15 的单点验证）
- install.sh 选项 4 调用 `run_script "AnyTLS" "$ANYTLS_URL"`

### 5. 约束

- **不修改 euservhy2.sh 逻辑**：仅更新版本号和日期
- **不引入 `source` 依赖**：公共代码以复制粘贴方式维护
- **validate_scripts.sh 必须以 exit 0 通过**：这是所有代码修改的硬性验收条件
- **禁用语法检查范围**：`grep -oP`、`${var,,}`、`${var^^}`、`head -c` 均不得出现在任何 `SCRIPTS` 文件中

