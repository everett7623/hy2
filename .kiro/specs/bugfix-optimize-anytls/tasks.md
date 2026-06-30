# Implementation Plan: Bug 修复、优化与 AnyTLS 支持

## Overview

本实现计划将设计文档拆分为可增量执行的编码任务。先完成现有脚本的 Bug 修复与优化（防火墙、网络检测、输入验证），再创建完整的 `anytls.sh` 管理脚本，最后集成到 `install.sh` 启动器并更新验证脚本。所有代码使用 bash，遵循 busybox 兼容性约束。

## Tasks

- [ ] 1. 创建测试基础设施与辅助工具
  - [-] 1.1 创建 bats-core 测试辅助模块 `tests/helpers/generators.bash`
    - 实现随机端口号生成器（合法范围 + 边界值 + 非法值）
    - 实现随机密码生成器（合法字符 + 禁止字符 + 边界长度）
    - 实现随机域名生成器（合法域名 + 含协议前缀 + 含端口号 + 特殊字符）
    - 实现模拟 `ip addr` 输出生成器（含 WARP/tunnel 网卡、fe80 地址、正常全局地址）
    - 实现随机 ELF/非 ELF 文件内容生成器
    - _Requirements: 1.3, 1.4, 7.4, 3.1, 4.2_

  - [ ] 1.2 创建可独立 source 的验证函数库 `tests/helpers/validators.bash`
    - 从 anytls.sh 设计中提取 `validate_port`、`validate_password`、`validate_domain` 为可独立测试的函数
    - 提取 IPv6 过滤 awk 逻辑为可测试的函数
    - 提取二进制验证逻辑为可测试的函数
    - _Requirements: 1.3, 1.4, 7.4, 3.1, 4.2_

- [ ] 2. 实现核心验证函数与属性测试
  - [~] 2.1 实现 `validate_port` 函数
    - 纯数字检测（不含前导零，"0" 除外）
    - 数值范围 [1, 65535] 检查
    - 拒绝空串、负数、浮点数、带字母、超范围输入
    - _Requirements: 1.3_

  - [ ]* 2.2 编写端口验证属性测试 `tests/test_validate_port.bats`
    - **Property 1: 端口验证正确性**
    - **Validates: Requirements 1.3**
    - 最少 100 次随机迭代

  - [~] 2.3 实现 `validate_password` 函数
    - 长度 [1, 128] 检查
    - 禁止字符检测：`"` `\` `$` `` ` `` 和控制字符 (0x00-0x1F, 0x7F)
    - _Requirements: 1.4_

  - [ ]* 2.4 编写密码验证属性测试 `tests/test_validate_pw.bats`
    - **Property 2: 密码验证正确性**
    - **Validates: Requirements 1.4**
    - 最少 100 次随机迭代

  - [~] 2.5 实现 `validate_domain` 函数
    - 仅允许字母、数字、点号、连字符
    - 不以点号或连字符开头/结尾
    - 禁止协议前缀和端口号
    - _Requirements: 7.4_

  - [ ]* 2.6 编写域名验证属性测试 `tests/test_validate_domain.bats`
    - **Property 3: 域名格式验证正确性**
    - **Validates: Requirements 7.4**
    - 最少 100 次随机迭代

- [ ] 3. 实现网络检测与二进制验证逻辑
  - [~] 3.1 实现 IPv6 地址过滤逻辑
    - 排除 wgcf|warp|tun*|wg*|tailscale|zt* 网卡地址
    - 排除 fe80 链路本地地址
    - 排除 2606:4700: Cloudflare WARP 地址段
    - 使用 awk 实现，不使用 grep -oP
    - _Requirements: 3.1, 3.6_

  - [ ]* 3.2 编写 IPv6 过滤属性测试 `tests/test_ipv6_filter.bats`
    - **Property 4: IPv6 地址过滤正确性**
    - **Validates: Requirements 3.1**
    - 生成模拟 ip addr 输出，验证过滤结果

  - [~] 3.3 实现二进制有效性验证函数 `validate_binary`
    - 检查文件前 4 字节为 ELF magic bytes (`\x7fELF`)
    - 或执行 version 子命令返回退出码 0
    - 拒绝空文件、HTML 错误页、截断下载
    - _Requirements: 4.2, 6.3_

  - [ ]* 3.4 编写二进制验证属性测试 `tests/test_binary_check.bats`
    - **Property 5: 二进制有效性验证**
    - **Validates: Requirements 4.2, 6.3**
    - 生成随机文件内容测试

- [~] 4. Checkpoint - 确认验证函数与属性测试
  - 确保所有属性测试通过，ask the user if questions arise.

- [ ] 5. 实现防火墙管理层
  - [~] 5.1 实现幂等防火墙函数 `open_firewall_port`
    - 按优先级检测 ufw → firewalld → iptables
    - iptables 使用 -C 先检查再 -A，避免重复规则
    - 双栈支持：同时操作 iptables + ip6tables
    - 无防火墙工具时输出警告并跳过
    - _Requirements: 5.1, 5.2, 5.5_

  - [~] 5.2 实现端口范围防火墙函数 `open_firewall_range`
    - ufw 格式 `start:end/proto`
    - firewalld 格式 `start-end/proto`
    - iptables 格式 `--dport start:end`
    - _Requirements: 5.3_

  - [~] 5.3 实现防火墙规则移除函数 `close_firewall_port`
    - 移除单端口和端口范围规则
    - 覆盖 TCP/UDP 双协议
    - _Requirements: 5.4_

  - [~] 5.4 实现防火墙规则持久化
    - 通过 iptables-save / netfilter-persistent / service iptables save 持久化
    - 失败不阻断流程
    - _Requirements: 5.6_

- [ ] 6. 实现备份回滚机制
  - [~] 6.1 实现 `backup_binary` 和 `rollback_binary` 函数
    - backup: `cp "$BIN" "${BIN}.bak"`, 失败则 return 1 取消升级
    - rollback: 从 .bak 恢复 + chmod +x + 重启服务
    - _Requirements: 1.2, 1.7, 4.1, 4.3_

  - [~] 6.2 实现配置备份与回滚逻辑
    - 修改前 mktemp 备份配置文件
    - 服务重启失败时从备份恢复
    - _Requirements: 1.5, 7.3, 7.6_

- [ ] 7. 创建 `anytls.sh` 脚本框架与核心安装逻辑
  - [~] 7.1 创建 `anytls.sh` 文件框架
    - 三段前置代码：bash 自举、TTY 修复、CRLF guard
    - 文件头注释块：项目名、版本号、更新日期
    - 颜色变量定义（与现有脚本一致）
    - 全局常量定义：BIN、CONFIG、META、SERVICE、CERT 路径
    - _Requirements: 12.1, 12.2, 12.3, 12.4_

  - [~] 7.2 实现系统检测函数
    - `check_root()`: root 权限检测
    - `detect_init()`: systemd/OpenRC 检测
    - `install_dependencies()`: 按发行版安装依赖
    - _Requirements: 12.1, 2.5, 2.3_

  - [~] 7.3 实现网络检测函数 `detect_network`
    - IPv4: 3 个 API 依次尝试（connect-timeout 3, max-time 6）
    - IPv6: 2 个 API 依次尝试（max-time 6）
    - WARP/tunnel 网卡过滤
    - NAT 判断逻辑
    - 回退到本机 global scope 地址 + 用户警告
    - _Requirements: 3.1, 3.2, 3.4, 3.6_

  - [~] 7.4 实现下载与版本获取函数
    - `get_latest_version()`: GitHub API 获取最新 release
    - `download_anytls()`: 架构映射 + 双源 fallback + return 1
    - `validate_binary()`: ELF magic / version 验证
    - _Requirements: 6.1, 6.2, 6.3, 12.5_

  - [~] 7.5 实现完整安装流程 `install_anytls`
    - 调用 get_latest_version → download → validate → 移动二进制
    - 引导用户设置端口/密码/SNI
    - 生成自签证书
    - 生成配置文件
    - 注册并启动服务
    - 放行防火墙端口
    - 输出节点信息
    - _Requirements: 6.1, 6.3, 6.4, 7.1, 7.2_

- [ ] 8. 实现 AnyTLS 配置管理与分享链接
  - [~] 8.1 实现配置生成器 `gen_config`
    - 生成 `/etc/anytls/config.yaml`
    - 写入元数据文件（listen_port, ext_port, password, sni, version）
    - NAT 模式分别记录 LISTEN_PORT 和 EXT_PORT
    - _Requirements: 7.1, 7.7_

  - [~] 8.2 实现自签证书生成 `gen_cert`
    - openssl 生成 3650 天有效期证书
    - CN 字段设置为 SNI 域名
    - 输出到 /etc/anytls/cert/
    - _Requirements: 7.2_

  - [~] 8.3 实现 YAML 配置修改函数
    - `change_port()`: awk 块检测修改端口 + 备份回滚
    - `change_password()`: 修改密码 + 备份回滚
    - `change_sni()`: 修改 SNI + 重新生成证书 + 备份回滚
    - 修改后重启服务，3 秒后验证存活
    - _Requirements: 7.3, 7.5, 7.6_

  - [ ]* 8.4 编写 YAML 修改隔离性属性测试 `tests/test_yaml_edit.bats`
    - **Property 6: YAML 配置修改隔离性**
    - **Validates: Requirements 7.3**
    - 随机配置值组合，修改单字段验证其他字段不变

  - [~] 8.5 实现分享链接生成器 `show_config`
    - 输出 Clash Meta (mihomo) 配置片段
    - 输出 Shadowrocket URI 格式链接
    - 输出文本摘要（server、port、password、sni）
    - qrencode 二维码（如已安装）
    - NAT 模式使用 EXT_PORT
    - 双栈环境输出两组配置
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.7_

  - [ ]* 8.6 编写分享链接属性测试 `tests/test_share_links.bats`
    - **Property 7: 分享链接包含全部必要参数**
    - **Validates: Requirements 8.1, 8.2, 8.3**
    - 随机 IP/端口/密码/SNI 组合验证

  - [ ]* 8.7 编写 NAT 端口替换属性测试（在 `tests/test_share_links.bats` 中追加）
    - **Property 8: NAT 模式端口替换一致性**
    - **Validates: Requirements 3.3, 8.5**
    - 随机 LISTEN_PORT ≠ EXT_PORT 对验证

- [~] 9. Checkpoint - 确认 AnyTLS 核心功能
  - 确保所有属性测试通过，ask the user if questions arise.

- [ ] 10. 实现 AnyTLS 升级、卸载与服务管理
  - [~] 10.1 实现升级流程 `upgrade_anytls`
    - 备份 → 获取最新版本 → 下载 → 验证 → 替换 → 重启 → 检查状态 → 失败回滚
    - _Requirements: 6.5, 4.1, 4.2, 4.3_

  - [~] 10.2 实现卸载流程 `uninstall_anytls`
    - 停止服务 → 禁用开机自启 → 删除服务文件 → 删除二进制和 .bak
    - 删除配置目录 → 删除证书 → 删除自动更新脚本/日志 → 清除 crontab → 移除防火墙规则
    - _Requirements: 6.6_

  - [~] 10.3 实现服务管理函数
    - `service_start`、`service_stop`、`service_restart`: 按 INIT_SYS 分发
    - `service_is_active()`: 检测运行状态
    - systemd: systemctl 操作
    - OpenRC: rc-service / rc-update 操作
    - _Requirements: 2.5, 6.4_

  - [~] 10.4 实现 systemd 和 OpenRC 服务文件注册
    - systemd: 写入 `/etc/systemd/system/anytls-server.service`
    - OpenRC: 写入 `/etc/init.d/anytls-server`
    - 启用开机自启
    - _Requirements: 2.5, 6.4_

- [ ] 11. 实现服务器工具与自动更新
  - [~] 11.1 实现 BBR 加速功能 `enable_bbr`
    - 内核版本检查（>= 4.9）
    - 内核 >= 5.15 尝试 bbr3，不可用回落 bbr
    - 设置 fq 队列调度
    - 写入 sysctl 配置持久化
    - 低版本内核输出错误提示
    - _Requirements: 11.1, 11.2_

  - [~] 11.2 实现自动更新功能 `setup_autoupdate` / `remove_autoupdate`
    - 创建 `/usr/local/bin/anytls-autoupdate.sh`（heredoc 生成）
    - 注册每日 03:00 cron 任务
    - crontab 不可用时尝试安装 cron 包
    - 移除时删除 crontab 条目 + 脚本文件 + 日志文件
    - _Requirements: 11.3, 11.4, 11.7, 4.4, 4.5, 4.6_

  - [~] 11.3 实现系统信息展示和服务器工具子菜单
    - 展示 OS、内核、CPU、内存、磁盘、负载、BBR 状态、自动更新状态
    - 子菜单：BBR、BBR 状态、开启/关闭自动更新、查看日志、系统信息、返回
    - _Requirements: 11.5, 11.6_

- [ ] 12. 实现主菜单与交互逻辑
  - [~] 12.1 实现 `anytls.sh` 主菜单 `main_menu`
    - 选项：安装、升级、卸载、修改配置、查看节点信息、服务器工具、退出
    - 已安装/未安装状态下的菜单差异处理
    - _Requirements: 6.7_

  - [~] 12.2 串联所有组件完成 `anytls.sh` 完整脚本
    - 确保所有函数按正确顺序定义
    - main 入口调用 check_root → detect_init → detect_network → main_menu
    - 确保不含 bash 4.x+ 语法
    - _Requirements: 12.1, 12.3, 12.5, 2.1, 2.2, 2.8_

- [~] 13. Checkpoint - 确认 anytls.sh 完整性
  - 确保 `bash -n anytls.sh` 通过语法检查，ask the user if questions arise.

- [ ] 14. 集成到启动器与更新验证脚本
  - [~] 14.1 修改 `install.sh` 集成 AnyTLS
    - 新增 ANYTLS_URL 常量
    - get_status() 中新增 AnyTLS 状态检测
    - 主菜单新增选项 4（AnyTLS）
    - 调用 run_script 下载执行
    - 输入范围更新为 0-4
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

  - [~] 14.2 修改 `tests/validate_scripts.sh` 新增 anytls.sh 验证
    - SCRIPTS 变量加入 anytls.sh
    - 新增 anytls.sh heredoc 提取并语法检查
    - 新增 anytls.sh 版本号一致性检查
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

- [ ] 15. 现有脚本 Bug 修复与优化
  - [~] 15.1 修复 `hy2.sh` 防火墙与网络检测问题
    - 防火墙函数改为幂等（iptables -C 先检查）
    - 新增 ip6tables 双栈支持
    - 网络检测加入 WARP/tunnel 网卡过滤
    - 端口跳跃使用端口范围规则
    - 下载函数使用 return 1 替代 exit 1
    - _Requirements: 1.1, 5.1, 5.2, 5.3, 3.1, 12.5_

  - [~] 15.2 修复 `ss.sh` 防火墙与输入验证问题
    - 防火墙函数改为幂等
    - 新增 ip6tables 双栈支持
    - 添加端口/密码输入验证
    - 下载函数使用 return 1
    - _Requirements: 1.1, 1.3, 1.4, 5.1, 5.2, 12.5_

  - [~] 15.3 修复 `euservhy2.sh` 兼容性与健壮性问题
    - 确保无 bash 4.x+ 语法
    - 下载函数使用 return 1
    - 二进制验证逻辑统一
    - _Requirements: 1.1, 2.2, 4.2, 12.5_

- [~] 16. Final checkpoint - 全面验证
  - 运行 `bash tests/validate_scripts.sh` 确保所有脚本通过静态验证
  - 运行全部 bats 属性测试确保通过
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All bash code must avoid bash 4.x+ syntax for busybox compatibility
- Validation functions are extracted to `tests/helpers/validators.bash` for testability while being inlined in the final scripts (no `source` in production scripts)
- The test framework is bats-core; property tests use custom random generators in `tests/helpers/generators.bash`

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1", "2.3", "2.5", "7.1"] },
    { "id": 2, "tasks": ["2.2", "2.4", "2.6", "3.1", "3.3", "7.2"] },
    { "id": 3, "tasks": ["3.2", "3.4", "5.1", "7.3", "7.4"] },
    { "id": 4, "tasks": ["5.2", "5.3", "5.4", "6.1", "6.2", "7.5"] },
    { "id": 5, "tasks": ["8.1", "8.2", "10.3", "10.4"] },
    { "id": 6, "tasks": ["8.3", "8.5", "10.1", "10.2"] },
    { "id": 7, "tasks": ["8.4", "8.6", "8.7", "11.1", "11.2"] },
    { "id": 8, "tasks": ["11.3", "12.1"] },
    { "id": 9, "tasks": ["12.2"] },
    { "id": 10, "tasks": ["14.1", "14.2", "15.1", "15.2", "15.3"] }
  ]
}
```
