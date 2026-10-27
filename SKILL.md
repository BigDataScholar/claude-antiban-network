---
name: claude-antiban-network
description: >-
  用于引导用户或自动化将新购买的海外原生住宅/双ISP VPS（如 LisaHost、搬瓦工等）搭建为防 Claude/ChatGPT 封号的高防专属网络环境。
  覆盖 VPS 服务端 Xray VLESS Reality 搭建、Cloudflare WARP 双轨分流（解锁 Gemini/Google 同时保持 Claude 纯净直连）、Linux 内核 TCP Keepalive 调优（有效缓解长文本推理断流 Broken Pipe）、一键生成本地 Clash Verge/Mihomo 配置文件及 iOS 导入链接、以及端到端连通性与代理路径防泄漏门禁自检。
---

# Claude 防封网络全自动化搭建与加固技能 (claude-antiban-network)

## 技能概述

本技能为 AI Agent 提供了端到端的**「Claude 专属防封网络自动化搭建与验证」**能力。
针对国内用户使用海外 AI 服务时高频遇到的**账号封禁、Gemini 地区限制（"ZZ"代码）、长文本思考掉线（Broken Pipe）、DNS 泄露**等痛点，提供工业级的标准落地流程。

### 核心架构：双轨隔离防封体系 (Dual-Track Isolation)

```mermaid
flowchart TD
    Client["本地设备 (Mac / PC / iOS)"] -->|Clash Verge / Mihomo (Fake-IP)| Proxy["LisaHost 独享双ISP VPS (VLESS Reality)"]
    
    Proxy -->|域名识别分流| Router{"Xray 内部路由引擎"}
    
    Router -->|"Claude / OpenAI (直连原生住宅IP)"| Direct["Native US Residential IP\n(极致防封 / 无污染)"]
    Router -->|"Google / Gemini (分流走 WARP)"| WARP["Cloudflare WARP 40000\n(突破 ZZ 区域封锁)"]
    Router -->|"UDP 443 (QUIC)"| Block["Blackhole 阻断\n(杜绝 UDP IP/DNS 泄露)"]
    
    Direct --> Claude["Claude.ai / OpenAI"]
    WARP --> Gemini["Gemini / Google AI Studio"]
```

1. **Claude / OpenAI 独享原生通道**：强制直连 VPS 绑定的纯净原生 IP，不与任何公用代理混跑，建立极高的发卡地信誉；
2. **Google / Gemini WARP 自动补全**：针对 Google GeoIP 误将新机房识别为国家代码 "ZZ" 的问题，底层无缝路由至 Cloudflare WARP 美区清洁出口，两全其美；
3. **内核级长连接保活 (TCP Keepalive)**：内核 `tcp_keepalive_time` 缩短为 30s，Xray 闲置断开延长至 1800s，通过链路双向保活协同调优，有效防范 Codex、o1/o3 及 Claude 长时间思考无数据包导致的 `Broken pipe (os error 32)`；
4. **阻断常规泄露向量**：VPS 禁用 IPv6、阻断 UDP 443（QUIC），本地配合 Fake-IP 模式防范国内运营商 DNS 污染与代理通道解析泄漏（注: 浏览器端 WebRTC 仍需配合插件禁用以防本地直连泄露）。

---

## 目录结构说明

本技能目录位于 `<skill-path>`（安装于 `~/.gemini/config/skills/claude-antiban-network/`）：
* `scripts/vps_setup.sh`：VPS 服务端一键安装脚本（自动安装 Xray、WARP、配置内核参数与防火墙，输出 JSON 元数据）。
* `scripts/generate_clash_config.py`：本地客户端配置生成器（将 VPS 参数转化为开箱即用的 Clash Verge/Mihomo YAML 配置及移动端 VLESS 链接）。
* `scripts/verify_environment.py`：端到端连通性与防泄露自动化检测门禁（检测美区 IP、Claude/Gemini 状态、DNS 解析环境）。

---

## Agent 标准执行工作流

当用户提出“帮我把新买的 VPS 配置成 Claude 节点”、“怎么搭建防止 Claude 封号的网络”、“检查我的代理有没有 DNS 泄露”等需求时，Agent 应遵循以下五步走流程：

### 第一步：交互式信息采集

向用户询问并确认目标 VPS 的连接凭证：
1. **VPS IP 地址**
2. **SSH 端口号**（LisaHost 等主机商通常为自定义高位端口，如 `22903`）
3. **SSH 账号**（通常为 `root`）
4. **SSH 密码或本地私钥路径**

---

### 第二步：自动化远程 VPS 部署

通过 SSH 远程执行服务端初始化脚本。

```bash
# 1. 将 vps_setup.sh 传送到远程 VPS
scp -P <SSH_PORT> ~/.gemini/config/skills/claude-antiban-network/scripts/vps_setup.sh root@<VPS_IP>:/tmp/vps_setup.sh

# 2. 远程以 root 权限执行并捕获输出
ssh -p <SSH_PORT> root@<VPS_IP> "bash /tmp/vps_setup.sh"
```

> **注意**：脚本执行结束时会打印类似如下的 JSON 块：
> ```json
> ###JSON_OUTPUT_START###
> {
>   "server_ip": "216.167.23.xxx",
>   "port": 24433,
>   "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
>   "flow": "xtls-rprx-vision",
>   "security": "reality",
>   "sni": "gateway.icloud.com",
>   "public_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
>   "short_id": "xxxxxxxxxxxxxxxx",
>   "fingerprint": "chrome",
>   "warp_port": 40000
> }
> ###JSON_OUTPUT_END###
> ```
> Agent 需解析提取该 JSON 块用于下一步。

---

### 第三步：生成本地客户端配置文件与移动端链接

在本地环境调用生成脚本，生成 Clash Verge / Mihomo 配置文件及手机端链接：

```bash
python3 ~/.gemini/config/skills/claude-antiban-network/scripts/generate_clash_config.py \
  --json-input '<提取到的JSON字符串>' \
  --name "🇺🇸 独享-Claude-原生住宅9929" \
  --output "~/Desktop/Claude-独享纯美区配置.yaml"
```

执行后将输出：
1. 本地 YAML 完整路径（保存在用户桌面上，方便拖拽）。
2. `vless://...` 格式的直连分享链接（可直接导入 iPhone 小火箭 / Shadowrocket / Sing-box / Loon）。

---

### 第四步：引导用户客户端导入

向用户清晰展示如下 3 步操作引导：
1. **电脑端（Mac / Windows）**：
   * 打开 **Clash Verge Rev**；
   * 点击左侧 **订阅 (Profiles)**，将桌面上的 `Claude-独享纯美区配置.yaml` 直接拖入窗口；
   * 右键该配置，选择 **使用 (Use)**；
   * 确保软件左下角的 **系统代理 (System Proxy)** 和 **TUN 模式 (Tun Mode)** 已开启；
   * 在代理组中，将 `🚀 独享-AI与代码` 和 `🌐 谷歌与Gemini` 选中为你的独享节点。
2. **手机端（iOS / Android）**：
   * 复制生成的 `vless://...` 链接；
   * 打开 Shadowrocket / Sing-box，点击从剪贴板添加节点即可。

---

### 第五步：自动化门禁检测与验收（覆盖代理路径）

在本地通过代理端口执行自动化验证测试：

```bash
python3 ~/.gemini/config/skills/claude-antiban-network/scripts/verify_environment.py --proxy http://127.0.0.1:7897
```

* **检测项覆盖**：
  * **Egress IP & 地理位置**：确认是原生美国（US）IP，无漂移；
  * **Claude / Anthropic 连通性**：确认可无阻碍到达 Cloudflare 美区边缘节点；
  * **Gemini 地区限制与网关可达**：确认无 `["ZZ"]` 阻断标识；
  * **代理路径防泄漏审计**：确认代理上游 DNS 为海外解析器、无国内运营商泄露，且本机无公网 IPv6 直连绕行（注: 浏览器 WebRTC 仍需插件配合阻断）。

---

## 终极防封行为守则（交付给用户）

除了网络环境达标外，引导用户注意以下 4 个关键防封要点：
1. **支付订阅安全（重中之重）**：严禁在网页端强刷国内普通双币卡（极易触发 Stripe 欺诈拒付并封号）。建议在安卓手机端通过 **Google Play 绑定国内 Visa / Mastercard** 订阅 Claude Pro，原价 $20/月且零风控；
2. **会话期间保持 IP 静态稳定**：在 Claude 网页端打字或运行代码时，切忌频繁切换代理节点，防止触发多地会话劫持拦截；
3. **排查浏览器 WebRTC 泄露**：Chrome/Edge 建议安装 `WebRTC Control` 插件，将其开关置于禁用（Block）状态，防范物理局域网地址泄漏；
4. **内容安全合规**：中文或国内商务内容本身 100% 安全（不会因中文封号），但切勿要求模型生成黑客攻击、违规爬虫等违反 AUP 协议的内容。
