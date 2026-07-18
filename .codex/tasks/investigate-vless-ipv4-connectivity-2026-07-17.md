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

## 待验证假设 H2 — 死 IPv6 导致 REALITY 握手失败（仍存疑）

`detect_network()` 优先使用本地接口扫描来判断 `HAS_IPV6`，而非外部可达性测试。若 VPS 有全局 IPv6 地址但路由失效（VMIESS 常见），则脚本误报双栈，`LISTEN_HOST` 仍为 `::`；更关键的是 sing-box 运行时解析握手目标域名时可能尝试 AAAA 并通过死路由，导致所有 REALITY 握手超时，客户端无法连接。双栈 ByteVirt IPv6 路由正常故不受影响。

**下次 VPS 采集时需输出（两台各一份）：**

```bash
echo "=== DIAGNOSE ==="
bash <(curl -fsSL https://raw.githubusercontent.com/everett7623/hy2/main/vless.sh) diagnose

echo "=== IPV6 ROUTE ==="
ip -6 route show 2>/dev/null | head -5 || echo "no ip command"

echo "=== LOCAL IPV6 ADDR ==="
ip -6 addr show scope global 2>/dev/null | grep -v 'wgcf\|warp\|tun\|tailscale' || echo "none"
```

**根因确认标准**：
- VMIESS 诊断输出 `IPv4: ✓ 可达  IPv6: ! 不可达` + `ip -6 route` 只有 unreachable/link-local → H2 确认。
- VMIESS 诊断输出 `IPv4: ✗ 不可达` → H2 之外还有更基础的网络问题。
- VMIESS 诊断输出配置/元数据仍缺失 → H1 修复未生效（检查本次 push 是否已拉取）。

## 完成条件

- [x] H1 修复（wait_for_health）已落地，测试通过
- [x] diagnose 区分 config/meta/字段 三种失败原因
- [x] diagnose 输出 IPv4/IPv6 per-family REALITY 可达性
- [ ] 收到 ByteVirt 双栈与 VMIESS 纯 IPv4 的对比诊断输出
- [ ] H2 根因确认或排除（基于新诊断输出）
- [ ] 若 H2 确认，修复 detect_network 的 HAS_IPV6 可达性门控（需防止误伤正常双栈机）
- [ ] 所有修复运行完整静态验证并记录一次性 VPS 验收结果
- [ ] 根因全部确认后再沉淀为已解决案例
