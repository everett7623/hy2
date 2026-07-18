# VLESS 纯 IPv4 连通性异常调查

- 日期：2026-07-17
- 状态：H1（健康检查竞态）已修复并测试；H2（死 IPv6）已加诊断，等待 VPS 数据确认后再动网络代码
- 影响版本：`v2.0.19`（`7da4d86`），功能提交 `a544090`
- 目标：定位相同 VLESS 脚本在双栈 VPS 可用、纯 IPv4 VPS 不可用的环境差异。

## 已确认事实

- 日本 ByteVirt 双栈 VPS：安装后客户端可连接。
- VMIESS 纯 IPv4 VPS：安装后客户端不可连接。
- 用户提供的一次 `vless.sh diagnose` 截图显示：`配置或元数据缺失`。
- `read_config()` 在配置文件缺失、元数据缺失或关键字段校验失败时都会返回失败；旧提示不能区分具体原因（已修复，见下）。
- 本地模拟标准公网 IPv4：`HAS_IPV4=1`、`HAS_IPV6=0`、`NAT_MODE=0`、`BIND_FAMILY=v4`、`LISTEN_HOST=0.0.0.0`。
- 本地模拟 NAT IPv4：同上，`NAT_MODE=1`。
- `tests/validate_vless.sh` 与 GitHub Actions 静态验证通过，但没有覆盖纯 IPv4 VPS 的真实安装和端到端连接。

## 已修复（本轮）

### H1 — 健康检查竞态导致误回滚（高可信）

**根因**：`install_vless()` 原先用 `sleep 2; service_is_healthy` 做一次性检查（vless.sh quirk #8 已预警此类问题）。慢 VPS 冷启动超过 2 秒时 `service_is_healthy` 在端口实际绑定之前就返回失败，触发 `restore_current_install`；全新安装时备份为空，于是 `rm -f "$VLESS_CONFIG"` + `rm -rf "$VLESS_META"` 将刚写入的文件全部删除，导致随后 `diagnose` 看到"配置或元数据缺失"。这完全吻合用户截图的症状，且与 ByteVirt（快）成功、VMIESS（慢/高负载）失败的环境差异一致。

**修复**：引入 `wait_for_health(attempts=12)`，首次立即检查，失败则间隔 1 秒重试，最多 ~12 秒；真正故障的服务仍会超时回滚。已补失败测试（success-after-N 与 never-healthy 两组）。

### 诊断增强

- `diagnose_vless()` 现在区分三种失败原因：**config 缺失**、**meta 缺失**、**字段校验失败（显示字段名，密钥值隐藏）**。
- 新增监听地址状态行（`LISTEN_HOST:LISTEN_PORT | BIND_FAMILY | NAT`）。
- 新增 REALITY 握手目标分 IPv4/IPv6 可达性探测（`curl -4`/`-6`），用于在下次 VPS 运行时直接区分 H2。

### H2 — 死 IPv6 导致 REALITY 握手失败（已定位并修复，commit 见下）

**根因**：`detect_network()` 原逻辑只要接口上扫到全局 IPv6 地址就把 `HAS_IPV6=1`（vless.sh 原 629-635），直接覆盖了前面 curl 外网探测的结果——**完全不校验该 IPv6 是否可达**。廉价商家常给一个 IPv6 地址但路由已死（VMIESS 一类），于是纯 IPv4 机被误判双栈。后果：
1. 客户端链接里塞了个连不上的 IPv6 节点；
2. 更致命：sing-box 每次 REALITY 握手都要连目标域名（如 `www.microsoft.com:443`），解析到 AAAA 后往死 IPv6 拨，握手超时——**连 IPv4 节点也一起废**。sing-box issue [#3231](https://github.com/SagerNet/sing-box/issues/3231)、[#4211](https://github.com/SagerNet/sing-box/issues/4211) 证实其域名拨号会选中 IPv6 且不保证回退 IPv4。双栈 ByteVirt IPv6 路由正常，故不受影响——完全吻合"双栈通、纯 IPv4 不通"。

**修复**：新增 `has_default_ipv6_route()`；`detect_network()` 现在只在「外网 IPv6 探测走通」或「存在默认 IPv6 路由」时才认定 `HAS_IPV6=1`。接口有地址但两者皆无 → 判死 IPv6，按纯 IPv4 处理（`LISTEN_HOST=0.0.0.0`、不下发 IPv6 节点）。正常双栈机有默认路由，行为不变（已加测试确保不误伤）。

**残留边界**：若 VPS 有默认 IPv6 路由但上游被黑洞（有路由、连不通、TCP 超时而非立即 ENETUNREACH），本修复仍会认定双栈。这种情况少见；真遇到需在 sing-box 配置层给握手拨号加 `domain_strategy` 强制 IPv4，但该改动涉及 1.12 DNS schema，需真实 binary 校验后再上，暂不盲改。

## 完成条件

- [x] H1 修复（wait_for_health）已落地，测试通过
- [x] diagnose 区分 config/meta/字段 三种失败原因
- [x] diagnose 输出 IPv4/IPv6 per-family REALITY 可达性
- [x] H2 根因定位：detect_network 未校验 IPv6 可达性，误判双栈
- [x] H2 修复：HAS_IPV6 以「可达或有默认路由」为门控，含双栈不误伤测试
- [ ] 一次性 VPS 验收（VMIESS 纯 IPv4 重装后客户端可连）
- [ ] 验收通过后沉淀为已解决案例；如遇黑洞路由边界再处理 domain_strategy
