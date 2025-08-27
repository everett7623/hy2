````markdown
# hy2ipv6

🚀 一键脚本，在 **IPv6 Only VPS** 上部署 [Hysteria2](https://github.com/apernet/hysteria) 并自动配置 **Cloudflare Tunnel**，实现无论本地是否支持 IPv6，都能轻松使用科学上网。

## 功能特性
- ✅ 自动安装 [Hysteria2](https://github.com/apernet/hysteria)  
- ✅ 自动生成服务端配置文件  
- ✅ 支持 **IPv6 Only VPS**  
- ✅ 自动安装并配置 **Cloudflare Tunnel**  
- ✅ 自动生成 Clash / Sing-box 客户端配置  
- ✅ 即使本地只有 IPv4 也能使用  

---

## 使用方法

1. **运行**
   ```bash
   wget -O install_hy2.sh https://raw.githubusercontent.com/everett7623/hy2ipv6/main/install_hy2.sh && chmod +x install_hy2.sh && ./install_hy2.sh
````

2. **Cloudflare Tunnel 授权**

   * 脚本运行过程中会提示登录：

     ```bash
     cloudflared tunnel login
     ```
   * 浏览器打开输出的链接，选择你的域名或直接使用 Cloudflare 分配的免费隧道域名。

3. **查看配置信息**

   * 脚本执行完后会输出：

     * VPS IPv6 地址
     * Hysteria2 端口
     * 密码
     * Cloudflare Tunnel 分配的域名
     * Clash/Sing-box 配置示例

---

## 客户端配置示例

### Clash Meta

```yaml
- name: 🇩🇪DE-Hy2-CF
  type: hysteria2
  server: hy2.xxx.cfargotunnel.com
  port: 443
  password: <自动生成的密码>
  sni: www.bing.com
  skip-cert-verify: true
```

### Sing-box

```json
{
  "type": "hysteria2",
  "tag": "DE-Hy2-CF",
  "server": "hy2.xxx.cfargotunnel.com",
  "server_port": 443,
  "password": "<自动生成的密码>",
  "tls": {
    "enabled": true,
    "server_name": "www.bing.com",
    "insecure": true
  }
}
```

---

## 注意事项

* VPS 必须为 **纯 IPv6 或 IPv6 Only 环境**。
* 本地如支持 IPv6，可直接用 VPS 的 IPv6 地址连接，不必走 Cloudflare Tunnel。
* 如果本地仅有 IPv4，必须使用 **Cloudflare Tunnel 域名**。
* 默认使用 `www.bing.com` 作为 SNI，可自行修改。

---

## 致谢

* [apernet/hysteria](https://github.com/apernet/hysteria)
* [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared)

---

## License

MIT

```
