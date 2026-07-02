# CHANGELOG

所有脚本统一版本号，同步更新。

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
