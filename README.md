# Pure Hysteria2 IPv6

🚀 **纯净版** Hysteria2 一键安装脚本，专为 **IPv6 Only VPS** 优化，提供更稳定的直连体验。

## ✨ 功能特性

- ✅ **纯净安装**: 纯净版Hysteria2安装
- ✅ **IPv6 优化**: 完美支持 IPv6 Only VPS
- ✅ **双证书模式**: 支持自签名证书和 Let's Encrypt 证书
- ✅ **智能配置**: 自动检测网络环境并优化配置
- ✅ **菜单式管理**: 友好的交互界面，支持服务管理
- ✅ **性能优化**: 预配置 QUIC 参数，提升连接性能
- ✅ **多客户端支持**: 自动生成 Clash Meta、Sing-box 等配置

## 🚀 快速开始

### 一键安装
```bash
wget -O hy2.sh https://raw.githubusercontent.com/everett7623/hy2ipv6/main/hy2.sh && chmod +x hy2.sh && ./hy2.sh
```

```bash
wget -O- https://raw.githubusercontent.com/everett7623/hy2ipv6/main/hy2.sh | sudo bash
```

### 安装选项

1. **自签名证书模式** (推荐，简单快速)
   - 无需域名 DNS 解析
   - 客户端需开启 `skip-cert-verify: true`
   - 适合个人使用

2. **Let's Encrypt 证书模式**
   - 需要有效域名和 Cloudflare API Token
   - 证书受信任，无需跳过验证
   - 适合分享给他人使用

## 📋 系统要求

- **操作系统**: Ubuntu 18+, Debian 10+, CentOS 7+, RHEL 7+
- **架构**: x86_64 (amd64), ARM64, ARMv7
- **网络**: IPv6 Only VPS 或 双栈 VPS
- **端口**: UDP 443 (自动配置防火墙)
- **权限**: Root 权限

## 🔧 配置说明

### 服务端配置位置
```
/etc/hysteria2/config.yaml      # 主配置文件
/etc/hysteria2/certs/           # 证书目录
/root/hysteria2_client_info.txt # 客户端配置信息
```

### 性能优化参数
脚本已预配置以下 QUIC 优化参数:
```yaml
quic:
  initStreamReceiveWindow: 8388608      # 8MB
  maxStreamReceiveWindow: 8388608       # 8MB  
  initConnReceiveWindow: 20971520       # 20MB
  maxConnReceiveWindow: 20971520        # 20MB
  maxIdleTimeout: 60s
  keepAlivePeriod: 10s
```

## 📱 客户端配置

### Clash Meta (标准格式)
```yaml
- name: 'Pure-HY2'
  type: hysteria2
  server: 'your.domain.com'  # 或服务器IP
  port: 443
  password: 'your_password'
  sni: 'your.domain.com'
  skip-cert-verify: true     # 自签名证书时需要
```

### Clash Meta (紧凑格式)
```yaml
- { name: 'Pure-HY2', type: hysteria2, server: 'your.domain.com', port: 443, password: 'your_password', sni: 'your.domain.com', skip-cert-verify: true }
```

### Sing-box
```json
{
  "type": "hysteria2",
  "tag": "Pure-HY2",
  "server": "your.domain.com",
  "server_port": 443,
  "password": "your_password",
  "tls": {
    "enabled": true,
    "server_name": "your.domain.com",
    "insecure": true
  }
}
```

### V2rayN / NekoBox
```
hysteria2://password@server:443?sni=domain&insecure=true#Pure-HY2
```

## 🛠️ 服务管理

### 常用命令
```bash
# 查看服务状态
systemctl status hysteria-server

# 启动/停止/重启服务
systemctl start hysteria-server
systemctl stop hysteria-server
systemctl restart hysteria-server

# 查看日志
journalctl -u hysteria-server -f

# 查看配置信息
cat /root/hysteria2_client_info.txt
```

### 脚本菜单功能
- 🔧 服务管理 (启动/停止/重启)
- 📊 实时日志监控
- 🔍 连通性测试
- 📄 配置信息查看
- 🗑️ 完全卸载
- ⬆️ 版本更新

## 🌐 网络环境说明

### IPv6 Only VPS
- ✅ **推荐**: 使用服务器 IPv6 地址直连
- ✅ 成本低，性能好
- ✅ 避免 CDN 限制

### 客户端网络要求
- **IPv6 网络**: 直接使用服务器 IPv6 地址
- **IPv4 网络**: 需要 IPv6 隧道或双栈网络
- **移动网络**: 大多数现代移动网络支持 IPv6

## 🔍 故障排除

### 常见问题

1. **端口 443 被占用**
   ```bash
   # 查看占用进程
   ss -ulnp | grep :443
   
   # 停止占用进程
   systemctl stop nginx  # 示例
   ```

2. **服务启动失败**
   ```bash
   # 查看详细日志
   journalctl -u hysteria-server -n 50
   
   # 检查配置文件
   /usr/local/bin/hysteria server --config /etc/hysteria2/config.yaml --check
   ```

3. **客户端连接失败**
   - 检查防火墙是否开放 UDP 443
   - 确认密码和域名配置正确
   - 自签名证书需开启 `skip-cert-verify`

4. **IPv6 连接问题**
   ```bash
   # 测试 IPv6 连通性
   ping6 google.com
   
   # 检查 IPv6 配置
   ip -6 addr show
   ```

### 性能优化建议

1. **BBR 加速** (推荐)
   ```bash
   # 启用 BBR
   echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
   echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
   sysctl -p
   ```

2. **内核参数优化**
   ```bash
   # 增加网络缓冲区
   echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
   echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
   sysctl -p
   ```

## 📊 优势对比

| 特性 | 原复合版本 | 纯净版本 |
|------|------------|----------|
| 安装复杂度 | 高 (需要 CF Token) | 低 (一键安装) |
| 故障点 | 多 (HY2 + CF Tunnel) | 少 (仅 HY2) |
| 网络延迟 | 中等 (经过 CDN) | 低 (直连) |
| 连接稳定性 | 中等 | 高 |
| 配置维护 | 复杂 | 简单 |
| 性能 | 中等 | 高 |
| 隐私性 | 中等 (经过第三方) | 高 (直连) |

## 🎯 使用场景

### 适合使用纯净版的情况:
- ✅ IPv6 VPS 直连使用
- ✅ 追求最佳性能和稳定性
- ✅ 不想依赖第三方 CDN 服务
- ✅ 网络环境支持 IPv6
- ✅ 个人或小团队使用

### 仍需要其他方案的情况:
- ❌ 本地网络完全不支持 IPv6 且无法配置隧道
- ❌ 需要隐藏真实服务器 IP
- ❌ 服务器 IP 被限制访问

## 🔒 安全建议

1. **定期更新**
   - 使用脚本内置更新功能
   - 关注 Hysteria2 官方更新

2. **密码安全**
   - 使用强密码或自动生成
   - 定期更换密码

3. **证书管理**
   - Let's Encrypt 证书自动续期
   - 自签名证书注意有效期

4. **防火墙配置**
   - 仅开放必要端口 (443/udp)
   - 定期检查防火墙规则

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目！

### 开发计划
- [ ] 支持自定义端口
- [ ] 添加流量统计功能
- [ ] 支持多用户认证
- [ ] Web 管理界面

## 📄 License

MIT License

## 🙏 致谢

- [apernet/hysteria](https://github.com/apernet/hysteria) - 优秀的网络代理工具
- [everett7623/hy2ipv6](https://github.com/everett7623/hy2ipv6) - 原始项目灵感来源
- 所有测试和反馈的用户

---

**简化配置，专注性能，Pure Hysteria2 为你提供更稳定的科学上网体验！** 🚀
