# VLESS 易用性与网络诊断

- 日期：2026-07-17
- 状态：代码完成，待 VPS 实机验证
- 目标：随机化安装默认端口、优先展示 VLESS、改进 REALITY 目标选择，并补充慢速与 Speedtest 故障诊断。

## 范围

- [x] HY2、Shadowsocks、AnyTLS、VLESS 安装时生成随机高位默认端口，并避开本机已监听端口。
- [x] VLESS REALITY 候选目标不使用中国大陆站点，并优先选择 VPS 实际可完成 TLS 1.3 握手的域名。
- [x] 统一入口的协议选择、服务、升级和卸载菜单将 VLESS 排在第一位。
- [x] VLESS 诊断显示目标 TCP/TLS 可达性和基础公网下载结果，区分服务可用与出口性能问题。
- [x] VLESS 服务管理菜单与 `diagnose` CLI 动作可直接运行诊断。
- [x] 同步自动化测试、README、架构与测试文档。

## 边界与风险

- 随机端口只作为交互默认值，用户仍可手动指定；NAT VPS 的对外映射端口仍由宿主商决定。
- REALITY 目标必须由 VPS 访问，开发机测试不能代替目标 VPS 的网络结果。
- Speedtest 不通可能来自 VPS 出口、客户端分流、MTU、目标站限制或路由质量；在拿到 VPS 诊断数据前不宣称已定位根因。
- 不运行本地安装、服务、防火墙或卸载流程；这些行为只在一次性 VPS 验证。

## 验收

- [x] 端口生成范围、冲突规避与回退有自动化覆盖。
- [x] REALITY 候选列表与 TLS 筛选有自动化覆盖。
- [x] VLESS 在所有统一协议菜单中位于首项。
- [x] `bash tests/validate_scripts.sh` 通过。
- [x] `git diff --check` 通过。
- [x] 明确记录未完成的 VPS 实机验证。

## 验证结果

- `bash tests/validate_scripts.sh`：通过。
- AnyTLS、VLESS、Hysteria 2 网络与 Shadowsocks 网络行为验证：通过。
- `vless.sh diagnose` 分发、服务管理入口与诊断输出行为验证：通过。
- 开发机对候选域名执行 TLS 1.3 基线探测：Microsoft、Apple、Cloudflare、Amazon、AMD、Mozilla、NVIDIA、Samsung 均成功；运行时仍由目标 VPS 重新探测。
- Markdown 重复标题扫描：未发现重复章节。
- `git diff --check`：通过。
- 当前环境未安装 `shellcheck`。
- 未完成：一次性 VPS 上的安装、随机端口防火墙、REALITY 握手、客户端端到端速度与 Speedtest 交叉验证。
