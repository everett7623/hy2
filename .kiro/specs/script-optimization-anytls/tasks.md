# Implementation Plan: script-optimization-anytls (v1.1.0)

## Overview

将 hy2 项目从 v1.0.2 升级至 v1.1.0。主要工作分为六个方向：
1. 修复 anytls.sh 中的 14 个已知 bug
2. 补全 anytls.sh 缺失功能（show_config 全格式输出、meta 读写、auto-update heredoc、BBR、服务器工具菜单）
3. 集成 install.sh（AnyTLS 选项 4 状态检测、URL 常量、输入范围 [0-4]）
4. hy2.sh 优化（密码生成、IPv4 超时、auto-update 回滚、端口跳跃分隔符、meta 降级）
5. ss.sh 优化（timedatectl 警告、回滚原子性、二进制验证、WARP 过滤、tar 清理、连接测试超时）
6. 版本号统一递增至 v1.1.0 + 验证器更新 + CHANGELOG + 属性测试

## Tasks

- [ ] 1. 修复 anytls.sh 中的 busybox 兼容性与语法 Bug
  - [-] 1.1 修复 `validate_binary()` 中的 `head -c` 违规
    - 将 `validate_binary()` 中三处 `head -c 4 "$bin" | od ...` 替换为 `od -A d -t x1 -N 4 "$bin" 2>/dev/null | awk 'NR==1 { print $2, $3, $4, $5 }'`，并与 `"7f 45 4c 46"` 比较
    - 同步更新 auto-update heredoc 内部的相同 ELF 检测逻辑（`head -c 4` → `od -A d -t x1 -N 4 ... | awk`）
    - _Requirements: 8.5, 10.4_

  - [-] 1.2 删除 `detect_network()` 中的孤立命令行
    - 删除 IPv4 检测循环内第 1 行孤立的 `ip` 命令（约第 149 行）
    - 删除 IPv6 检测循环内第 1 行孤立的 `ip` 命令（约第 160 行）
    - 删除 IPv4 回退段中孤立的 `LOCAL_IP` 命令行（约第 170 行）
    - 删除 IPv6 回退段中孤立的 `LOCAL_IPV6` 命令行（约第 180 行）
    - _Requirements: 10.4_

  - [-] 1.3 修复 `detect_network()` IPv6 本地回退的 awk 解析逻辑
    - 将当前使用 `getline` 内循环的 IPv6 地址提取 awk 脚本替换为标准单次扫描写法（与 hy2.sh/ss.sh 保持一致：`/^[0-9]+:/ {iface=$2; sub(/:.*/,"",iface)}` + `/inet6/` 过滤）
    - _Requirements: 2.1_

  - [-] 1.4 为 `detect_network()` 添加 WARP/tunnel 接口过滤
    - 在 IPv4 公网地址检测阶段，使用 `ip -4 addr show scope global` 过滤掉 `wgcf|warp|^tun|^wg|tailscale|zt` 前缀接口，若不存在真实 IPv4 接口则置 `HAS_IPV4=0; PUBLIC_IP=""`
    - _Requirements: 2.1, 7.4_

  - [-] 1.5 修复 `service_start()` 的 enable/start 职责混用
    - 将 systemd 分支的 `service_start()` 中的 `systemctl enable anytls-server` 移出，保留单独的 `service_enable()` 函数（已存在但未被调用）；在 `install_anytls()` 中先调用 `service_enable()` 再调用 `service_start()`
    - 同理修复 OpenRC 分支：从 `service_start()` 移除 `rc-update add`，改为在安装流程中单独调用 `service_enable()`
    - _Requirements: 1.3_

  - [-] 1.6 修复 `uninstall_anytls()` 的顺序错误
    - 在删除 `/etc/anytls` 目录前，先读取 `$ANYTLS_META/config` 中的 `LISTEN_PORT` 到局部变量
    - 将 `close_firewall_port "$LISTEN_PORT"` 调用移至 `rm -rf /etc/anytls` 之前执行
    - _Requirements: 1.1_

  - [-] 1.7 修复 `change_port()` 中的备份文件路径错误
    - 在 `change_port()` 开头保存当前 `LISTEN_PORT` 到局部变量 `_old_port`
    - 将 `close_firewall_port "$(grep '^LISTEN_PORT=' "${ANYTLS_META}.bak" | cut -d= -f2)"` 替换为 `close_firewall_port "$_old_port"`
    - _Requirements: 1.10_

  - [-] 1.8 修复 `install_anytls()` 的默认端口
    - 将 `read -rp "请输入监听端口 [默认 14444]: " input_port` 改为 `[默认 443]`
    - 将 `LISTEN_PORT="${input_port:-14444}"` 改为 `LISTEN_PORT="${input_port:-443}"`
    - _Requirements: 1.4_

  - [ ] 1.9 修复 `install_anytls()` 密码自动生成方式
    - 将 `PASSWORD=$(head -c 16 /dev/urandom | base64 | tr -d '/+=')` 替换为 `PASSWORD=$(openssl rand -base64 16 | tr -d '/+=')`（与需求 1.5 一致，避免 head -c）
    - _Requirements: 1.5, 8.5_

- [ ] 2. 补全 anytls.sh 元数据读写与 show_config 完整输出
  - [~] 2.1 将 `gen_config()` 的单文件 meta 格式重构为每字段独立文件
    - 新增 `save_meta()` 函数，将 `LISTEN_PORT`、`EXT_PORT`、`PASSWORD`、`SNI`、`NAT_MODE`、`PUBLIC_IP`、`PUBLIC_IPV6` 分别写入 `$ANYTLS_META/` 目录下同名文件（与 hy2.sh 的 meta 格式保持一致）
    - 新增 `read_meta()` 函数，从 `$ANYTLS_META/` 各文件读取配置变量；若关键字段缺失则回退解析 `config.yaml`
    - 更新 `gen_config()` 调用 `save_meta()` 替代原内嵌的 `cat > "$ANYTLS_META/config"` 单文件写入
    - 更新所有读取 `. "$ANYTLS_META/config"` 的地方改为调用 `read_meta()`
    - _Requirements: 1.6, 3.8_

  - [~] 2.2 重写 `show_config()` 为完整双栈客户端配置输出
    - 调用 `read_meta()`；若关键字段缺失则显示错误消息并 `return`（不 `exit`）
    - 确定 `display_port`（NAT 模式用 `EXT_PORT`，否则用 `LISTEN_PORT`）
    - 实现 `show_node()` 辅助函数，参数为 `IP PORT TAG`，按以下顺序输出：
      1. AnyTLS URI：`anytls://{PASSWORD}@{HOST}:{PORT}/?sni={SNI}&insecure=1#{NODE_NAME}`（IPv6 加方括号）
      2. 终端 QR 码（若 `qrencode` 可用）；否则输出 QR 图片 API URL
      3. Clash Meta YAML（含 name/type/server/port/password/sni/skip-cert-verify 字段）
      4. Surfboard 格式行：`{NODE_NAME} = anytls, {IP}, {PORT}, {PASSWORD}, skip-cert-verify=true, sni={SNI}`
    - 在 `show_config()` 中根据 `HAS_IPV4`/`HAS_IPV6` 分别调用 `show_node()`：双栈输出两组，单栈输出一组，无地址输出错误消息
    - 节点名格式：`AnyTLS-v4-{MMdd}` / `AnyTLS-v6-{MMdd}`
    - _Requirements: 1.7, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8_

  - [ ]* 2.3 写属性测试：配置输出完整性（Property 3）
    - **Property 3: 配置输出完整性**
    - 创建 `tests/test_show_config_output.sh`；source anytls.sh 的辅助函数，模拟 `read_meta()` 返回随机有效参数（IP/端口/密码/SNI），调用 `show_node()` 检查输出包含所有参数值、Clash YAML 含必填字段
    - 运行 100 次迭代
    - **Validates: Requirements 1.7, 3.1, 3.2, 3.3**

  - [ ]* 2.4 写属性测试：IPv6 括号封装（Property 4）
    - **Property 4: IPv6 括号封装**
    - 创建 `tests/test_ipv6_bracket.sh`；对随机 IPv6 地址字符串调用 `show_node()`，断言 URI 中的 HOST 字段被方括号包围；对 IPv4 地址断言无方括号
    - 运行 100 次迭代
    - **Validates: Requirements 3.1**

  - [ ]* 2.5 写属性测试：双/单栈输出完整性（Property 5）
    - **Property 5: 双/单栈节点输出完整性**
    - 创建 `tests/test_dual_stack_output.sh`；测试 `(HAS_IPV4,HAS_IPV6)` 的四种组合，断言 `show_config()` 输出节点组数与可用地址数吻合
    - **Validates: Requirements 3.6**

- [ ] 3. 补全 anytls.sh auto-update heredoc 与 BBR/服务器工具
  - [~] 3.1 重写 `setup_autoupdate()` heredoc 使用 `AUTOUPDATE_EOF` 标记并修复内容
    - 将 heredoc 起始行改为 `cat > "$AUTO_UPDATE_SCRIPT" <<'AUTOUPDATE_EOF'`（单引号，变量不展开）
    - 修复 heredoc 内部的 ELF 验证：将 `head -c 4 "$tmp_bin" | od -A n -t x1 | tr -d ' \n' | grep -q "7f454c46"` 替换为 `od -A d -t x1 -N 4 "$tmp_bin" 2>/dev/null | awk 'NR==1 { print $2, $3, $4, $5 }' | grep -q "7f 45 4c 46"`
    - 确保 heredoc 内：下载后验证 `anytls-go version` 成功才替换二进制；替换后 `sleep 5` 再检查服务是否 active；失败时还原备份并重启服务
    - 确保日志格式：`echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$LOG"`
    - 确保 heredoc 内容通过 `bash -n` 语法检查（validate_scripts.sh 会提取并验证）
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.7, 9.8_

  - [~] 3.2 修复 `enable_bbr()` 内核版本比较逻辑
    - 将当前内核版本字符串解析为 `MAJOR` 和 `MINOR` 两个整数变量
    - 版本 < 4.9：输出错误消息并 `return 1`（不写入 sysctl）
    - 4.9 ≤ 版本 < 5.15：使用 BBR
    - 版本 ≥ 5.15：优先尝试 BBR3，BBR3 `sysctl set` 失败则回退 BBR
    - 写入 `$BBR_CONFIG` 后调用 `sysctl -p "$BBR_CONFIG"`，验证 `net.ipv4.tcp_congestion_control` 值符合预期
    - _Requirements: 9.5, 9.6_

  - [ ]* 3.3 写属性测试：BBR 算法选择正确性（Property 14）
    - **Property 14: BBR 算法选择正确性**
    - 创建 `tests/test_bbr_selection.sh`；mock `uname -r` 输出各种内核版本字符串，验证 BBR 选择逻辑：<4.9 报错返回，4.9-5.14 选 BBR，≥5.15 优先 BBR3
    - **Validates: Requirements 9.5, 9.6**

  - [~] 3.4 完善 `server_tools_menu()` 和日志查看
    - 补全 `service_logs()` 函数：systemd 使用 `journalctl -u anytls-server -n 50 --no-pager`；无 systemd 时 `tail -n 50 /var/log/anytls.log 2>/dev/null`
    - 确保 `server_tools_menu()` 调用 `service_logs()` 而非内联 journalctl
    - 添加 `setup_none_service()` 函数，实现 nohup + `/var/run/anytls.pid` 模式（start/stop 参考 hy2.sh 的 none 分支）
    - _Requirements: 10.6_

  - [ ]* 3.5 写属性测试：自动更新幂等性（Property 15）
    - **Property 15: 自动更新版本比较幂等性**
    - 创建 `tests/test_autoupdate_skip.sh`；解析 heredoc 自动更新脚本，mock `anytls-go version` 返回与"最新版本"相同的值，验证不触发下载/备份/重启
    - **Validates: Requirements 9.2**

- [~] 4. Checkpoint — anytls.sh 修复完成验证
  - 运行 `bash -n anytls.sh` 确保无语法错误
  - 运行 `bash tests/validate_scripts.sh` 检查 anytls.sh 相关规则（禁用语法检查需等版本号更新后执行）
  - 确认 `grep -qE 'grep -oP|head -c|\$\{[^}]+,,\}|\$\{[^}]+\^\^\}' anytls.sh` 返回非零（无违规语法）
  - 确保所有测试通过，向用户说明如有问题

- [ ] 5. install.sh 集成 AnyTLS 选项 4
  - [~] 5.1 确认 install.sh 已包含完整的 AnyTLS 集成内容
    - 确认 `ANYTLS_URL="${BASE_URL}/anytls.sh"` 常量存在（当前文件已有此行，验证即可）
    - 确认 `get_status()` 中包含 AnyTLS 状态检测块（检测 `/usr/local/bin/anytls-go` + `anytls-server` 服务状态）
    - 确认主菜单显示选项 4（AnyTLS）并展示 `$ANYTLS_STATUS`
    - 确认 `case "$choice"` 中有 `4) run_script "AnyTLS" "$ANYTLS_URL" ;;`
    - 确认输入提示为 `[0-4]`，`*` 分支错误消息为"请输入 0-4"
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [ ]* 5.2 写单元测试：install.sh 选项 4 路由验证
    - 创建 `tests/test_install_anytls_option.sh`；grep 验证 install.sh 包含 `ANYTLS_URL`、选项 4 菜单行、`run_script "AnyTLS"` 调用、`[0-4]` 提示字符串
    - _Requirements: 4.2, 4.4_

- [ ] 6. hy2.sh 优化
  - [~] 6.1 验证并确认密码生成函数符合规范
    - 检查 `gen_password()` 中 `tr -dc 'A-Za-z0-9'` 过滤字符集是否正确（确认为纯字母数字）
    - 确认循环重试逻辑：`while [ ${#_pass} -lt 20 ]` 最多重试保证够 20 位
    - 确认最终输出 `printf '%s' "${_pass:0:20}"` 恰好截取 20 字符
    - _Requirements: 6.1_

  - [ ]* 6.2 写属性测试：密码生成字符集不变式（Property 6）
    - **Property 6: 密码自动生成字符集不变式**
    - 创建 `tests/test_gen_password.sh`；source hy2.sh 并调用 `gen_password()` 100 次，断言每次返回恰好 20 字符且全为 `[A-Za-z0-9]`
    - **Validates: Requirements 6.1**

  - [~] 6.3 确认 hy2.sh auto-update 脚本的回滚逻辑
    - 在 hy2.sh 的 auto-update heredoc 中，找到服务重启后的验证块
    - 确认逻辑顺序：`systemctl restart` → `sleep 2` → `systemctl is-active` → 成功则 `rm .bak`；失败则 `mv .bak $HY_BIN` + `systemctl restart`
    - 若缺失 `sleep 2` 验证步骤则补充
    - _Requirements: 6.3_

  - [~] 6.4 确认端口跳跃 colon→dash 转换
    - 确认 `install_hy2()` 中写入 `config.yaml` 前有 `echo "$PORT_HOP" | tr ':' '-'` 转换
    - 确认结果写入 `listen: :${_hop_cfg}` 或 `[::]:${_hop_cfg}`
    - _Requirements: 6.4_

  - [ ]* 6.5 写属性测试：端口跳跃配置转换（Property 7）
    - **Property 7: 端口跳跃配置转换**
    - 创建 `tests/test_port_hop_config.sh`；对随机生成的 `START:END` 格式字符串（START/END 均为合法端口）执行 `tr ':' '-'` 转换，断言结果格式为 `START-END`（使用破折号，不含冒号）
    - **Validates: Requirements 6.4**

  - [~] 6.6 确认 `show_config()` meta 缺失时的降级行为
    - 确认 `read_config_vars()` 在 meta 为空时回退解析 `config.yaml`
    - 确认若 `config.yaml` 也不存在则 `show_config()` 输出错误消息并 `return`（不 `exit`）
    - _Requirements: 6.5_

  - [~] 6.7 确认 `download_hy2()` mktemp 失败返回 1
    - 确认 `mktemp` 失败时输出错误消息并 `return 1`，不继续执行下载
    - _Requirements: 6.6_

- [ ] 7. ss.sh 优化
  - [~] 7.1 添加 `timedatectl` 不可用时的黄色警告
    - 找到 `_select_cipher()` 中 `command -v timedatectl >/dev/null 2>&1 && timedatectl set-ntp true` 调用处
    - 将其修改为：先 `if command -v timedatectl ...` 判断；不可用时输出黄色警告 `"[警告] timedatectl 不可用，SS-2022 要求系统时间精确，请手动确认时间同步"`
    - _Requirements: 7.1_

  - [~] 7.2 确认配置修改回滚的原子性与服务验证
    - 检查 `modify_config()` 回滚路径中，`service_restart` 后是否有 `sleep 2` 和 `service_is_active` 验证步骤
    - 若缺失则补充；确认回滚顺序：`cp bak → config`、`rm -rf SS_META`、`mkdir -p SS_META`、`cp -a bak_dir/. SS_META/`、`service_restart`
    - _Requirements: 7.2_

  - [~] 7.3 在 ss.sh auto-update heredoc 中添加二进制版本验证
    - 找到 `setup_autoupdate()` 的 heredoc（`ss-autoupdate.sh`）
    - 在 `mv "$tmp_bin" "$SS_BIN"` 之前添加 `"$tmp_bin" --version >/dev/null 2>&1 || { log "二进制版本验证失败，跳过更新"; rm -f "$tmp_bin"; exit 0; }`
    - _Requirements: 7.3_

  - [~] 7.4 确认 `detect_network()` 中 WARP/tunnel IPv4 接口过滤
    - 确认过滤正则包含 `warp*`、`wg*`、`tun*` 接口名（当前使用 `wgcf|warp|^tun|^wg|tailscale|zt`）
    - 若过滤模式不完整则修正，确保 `warp0`、`wg0`、`tun0` 等均被排除
    - _Requirements: 7.4_

  - [ ]* 7.5 写属性测试：WARP 接口过滤（Property 8）
    - **Property 8: 防火墙接口过滤（WARP/tunnel 排除）**
    - 创建 `tests/test_warp_filter.sh`；source `tests/helpers/validators.bash` 中的 `filter_ipv6_addrs()`，使用 `tests/helpers/generators.bash` 中的 `gen_ip_addr_*` 生成器，验证 wgcf/warp/tun/wg/tailscale/zt 接口的地址被过滤，真实全局地址保留
    - 运行 100 次迭代，使用 `gen_ip_addr_mixed()`、`gen_ip_addr_only_filtered()`、`gen_ip_addr_multiple_real()`
    - **Validates: Requirements 7.4**

  - [~] 7.6 确认 `download_ss()` tar 失败时同时清理 archive 和临时目录
    - 确认 tar 解压失败分支同时执行 `rm -f "$_tmp_archive"` 和 `rm -rf "$_tmp_dir"`
    - 确认 `_tmp_dir` 是通过 `mktemp -d` 创建的（已存在），不需要手动 mkdir
    - _Requirements: 7.5_

  - [~] 7.7 确认连接测试超时 ≤ 10 秒
    - grep 搜索 ss.sh 中的连接测试函数（`test_connection` 或类似名称）
    - 确认所有 `nc`、`/dev/tcp`、`curl` 探测命令的 timeout 参数不超过 10 秒
    - 若超过则修改至 ≤ 10 秒
    - _Requirements: 7.6_

- [~] 8. Checkpoint — hy2.sh 和 ss.sh 优化验证
  - 运行 `bash -n hy2.sh` 和 `bash -n ss.sh` 确认无语法错误
  - 确认 `grep -qE 'grep -oP|head -c|\$\{[^}]+,,\}|\$\{[^}]+\^\^\}' hy2.sh ss.sh` 返回非零
  - 确保所有测试通过，向用户说明如有问题

- [ ] 9. 属性测试：通用验证函数
  - [~] 9.1 写属性测试：端口验证完备性（Property 1）
    - **Property 1: 端口验证完备性**
    - 创建 `tests/test_validate_port.sh`；source `tests/helpers/generators.bash`，使用 `gen_valid_port`/`gen_invalid_port_*` 生成器，对 100 次随机输入验证 `validate_port()` 返回值与预期一致（合法→0，非法→非0）
    - 同时测试边界值 1 和 65535（`gen_valid_port_boundary`）
    - **Validates: Requirements 1.4, 2.2**

  - [~] 9.2 写属性测试：密码验证完备性（Property 2）
    - **Property 2: 密码验证完备性**
    - 创建 `tests/test_validate_password.sh`；source `tests/helpers/generators.bash`，使用 `gen_valid_password`/`gen_invalid_password_*` 生成器，对 100 次随机输入验证 `validate_password()` 返回值与预期一致
    - 同时测试边界值（长度 1、128）和超长（129+）
    - **Validates: Requirements 1.5**

  - [~] 9.3 写属性测试：Bash 自举包管理器正确分发（Property 11）
    - **Property 11: Bash 自举包管理器正确分发**
    - 创建 `tests/test_bootstrap.sh`；对每个 SCRIPTS 文件 grep 验证 bootstrap 段包含四个发行版分支（apk/apt-get/dnf/yum）
    - **Validates: Requirements 8.4, 10.5**

  - [~] 9.4 写属性测试：URI 编码多字节处理（Property 12）
    - **Property 12: URI 编码纯 Bash 多字节处理**
    - 创建 `tests/test_uri_encode.sh`；source `uri_encode()` 函数，对含多字节 UTF-8 字符的字符串（如中文、emoji）验证纯 bash 降级路径：N 字节字符产生 N 个 `%XX` 序列
    - **Validates: Requirements 8.6**

  - [~] 9.5 写属性测试：禁用语法不存在不变式（Property 10）
    - **Property 10: 禁用语法不存在不变式**
    - 创建 `tests/test_forbidden_syntax.sh`；对 SCRIPTS 列表每个文件执行 `grep -qE 'grep -oP|head -c|\$\{[^}]+,,\}|\$\{[^}]+\^\^\}'` 并断言返回非零
    - **Validates: Requirements 8.5, 10.4**

  - [~] 9.6 写属性测试：init 系统检测与服务文件创建对应性（Property 13）
    - **Property 13: init 系统检测与服务文件创建对应性**
    - 创建 `tests/test_init_detection.sh`；grep 验证 anytls.sh 包含三个 INIT_SYS 分支（systemd/openrc/none）的服务文件创建逻辑，且 none 分支无服务文件创建（使用 nohup）
    - **Validates: Requirements 10.3**

- [ ] 10. 版本号统一递增至 v1.1.0
  - [~] 10.1 更新 anytls.sh 版本号
    - 文件头注释：`v1.0.2` → `v1.1.0`，更新日期为 `2026-07-01`（或当前日期）
    - 菜单字符串：`AnyTLS Management Script v1.0.2` → `AnyTLS Management Script v1.1.0`
    - _Requirements: 5.1, 5.2_

  - [~] 10.2 更新 hy2.sh 版本号
    - 文件头注释：`v1.0.2` → `v1.1.0`
    - 菜单字符串（`main_menu` 中）：`Hysteria2 Management Script v1.0.2` → `v1.1.0`
    - _Requirements: 5.1, 5.2_

  - [~] 10.3 更新 ss.sh 版本号
    - 文件头注释：`v1.0.2` → `v1.1.0`
    - 菜单字符串：`Shadowsocks-Rust Management Script v1.0.2` → `v1.1.0`
    - _Requirements: 5.1, 5.2_

  - [~] 10.4 更新 install.sh 版本号
    - 文件头注释：`v1.0.2` → `v1.1.0`
    - 状态栏版本显示：`${DIM}v1.0.2${PLAIN}` → `${DIM}v1.1.0${PLAIN}`
    - _Requirements: 5.1, 5.3_

  - [~] 10.5 更新 euservhy2.sh 版本号
    - 文件头注释：`v1.0.2` → `v1.1.0`
    - `SCRIPT_VERSION="1.0.1"` → `SCRIPT_VERSION="1.1.0"`（注意：无 `v` 前缀，validate_scripts.sh 检查此格式）
    - _Requirements: 5.1, 5.6_

  - [~] 10.6 更新 `tests/validate_scripts.sh`
    - `EXPECTED_VERSION="v1.0.2"` → `EXPECTED_VERSION="v1.1.0"`
    - euservhy2.sh 版本检查行：`grep -q 'SCRIPT_VERSION="1.0.1"'` → `grep -q 'SCRIPT_VERSION="1.1.0"'`
    - 确认 `SCRIPTS` 列表已包含 `anytls.sh`（当前已包含，验证即可）
    - _Requirements: 5.4, 5.6, 5.7_

  - [~] 10.7 添加 CHANGELOG.md v1.1.0 段落
    - 在 `## v1.0.2` 之前插入新段落 `## v1.1.0 (2026-07-01)` 及完整变更说明，涵盖本次修复的所有方向（bug 修复、hy2.sh/ss.sh 优化、版本递增）
    - _Requirements: 5.5_

- [ ] 11. 最终静态验证门
  - [~] 11.1 运行 `bash tests/validate_scripts.sh` 并确保以 exit 0 通过
    - 运行命令：`bash tests/validate_scripts.sh`
    - 预期输出：`Static script validation passed.`
    - 若失败则根据错误信息定位并修复对应文件
    - _Requirements: 5.7, 8.5_

  - [ ]* 11.2 运行所有属性测试并确认通过
    - 依次运行 `tests/` 目录下所有 `test_*.sh` 文件
    - 确认每个测试文件均以 exit 0 通过（或 BATS 报告无失败）
    - _Requirements: 全部属性_

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; `validate_scripts.sh` (task 11.1) is the hard acceptance gate
- Task 1 (bug fixes) must be completed before Task 2 (show_config rebuild) to avoid compounding errors
- Task 10 (version bump) can be done in parallel with Tasks 6-9 but must be completed before Task 11
- All code must maintain LF line endings and UTF-8 encoding (CRLF will break `validate_scripts.sh`)
- Never use `head -c`, `grep -oP`, `${var,,}`, or `${var^^}` in any SCRIPTS file
- The auto-update heredoc delimiter must be `<<'AUTOUPDATE_EOF'` (with single quotes) for both `validate_scripts.sh` extraction and variable non-expansion
- Meta directory format for anytls.sh must match hy2.sh pattern (one value per file) after Task 2.1
- The `service_start()` / `service_enable()` separation (Task 1.5) is critical for correct boot behavior


## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9"] },
    { "id": 1, "tasks": ["2.1", "6.1", "6.3", "6.4", "6.6", "6.7", "7.1", "7.2", "7.3", "7.4", "7.6", "7.7", "3.2", "3.4"] },
    { "id": 2, "tasks": ["2.2", "3.1", "5.1", "6.5", "7.5", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "10.1", "10.2", "10.3", "10.4", "10.5"] },
    { "id": 3, "tasks": ["2.3", "2.4", "2.5", "3.3", "3.5", "5.2", "6.2", "10.6", "10.7"] },
    { "id": 4, "tasks": ["11.1"] },
    { "id": 5, "tasks": ["11.2"] }
  ]
}
```
