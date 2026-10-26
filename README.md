# Claude Anti-Ban Network (Claude 专属防封网络搭建技能套件)

> 🛡️ **专为海外 AI（Claude / ChatGPT / Gemini）打造的工业级防封专属代理网络自动化构建套件。**
> 支持自动化在全新海外 VPS（如 LisaHost 美区 9929 双 ISP 原生住宅 VPS、搬瓦工等）上一键部署与本地客户端加固。

---

## 📌 为什么需要这套专属网络架构？

使用国内公用机场或普通数据中心 VPS 访问 Claude / ChatGPT 时，通常会遇到以下 4 个致命痛点：

1. **公用 IP 污染导致的批量封号**：公用机场节点成百上千人共用同一个出口，早被 Anthropic / OpenAI 风控系统标记为恶意爬虫或高危机房，开局即封号；
2. **Google & Gemini 区域报错（"ZZ" 阻断）**：许多新购买的美区原生住宅 VPS，其 IP 未被 Google GeoIP 数据库收录，被识别为国家代码 `ZZ`，导致 Gemini / Google AI Studio 提示*“当前地区不支持”*；
3. **深度思考长连接中途掉线（Broken Pipe）**：在跑 o1/o3、Codex 或 Claude 深度长文本生成时，模型思考等待时间往往长达 30s ~ 120s+，普通代理因中途没有保活心跳被防火墙掐断，报 `stream disconnected: Broken pipe (os error 32)`；
4. **DNS 与 WebRTC 泄露真实物理位置**：本地电脑若走传统代理，系统 DNS 往往仍会向国内运营商发起解析，或通过 WebRTC 暴露内网真实 IP。

本套件通过**「双轨隔离分流 + 内核保活调优 + 终端防漏加固」**，大幅降低网络层风控风险，解决长连接掉线与地区误判问题。

---

## 🏛️ 双轨隔离核心架构 (Dual-Track Architecture)

```
                            ┌──────────────────────────────────────────────┐
                            │ 本地客户端 (Mac / PC / iOS / Android)         │
                            │  - Clash Verge Rev / Sing-box / Shadowrocket │
                            │  - 开启 Fake-IP (198.18.0.0/16)              │
                            │  - 启用 Keepalive 心跳保活 (15s)              │
                            └──────────────────────┬───────────────────────┘
                                                   │
                                                   │ VLESS Reality (XTLS-rprx-vision)
                                                   │ 模拟 Chrome 纯净握手 (SNI: iCloud)
                                                   ▼
                            ┌──────────────────────────────────────────────┐
                            │ 海外专属 VPS (如 LisaHost 洛杉矶 9929 双ISP)  │
                            │  - 内核参数调优: TCP Keepalive (30s)         │
                            │  - 禁用 IPv6 (杜绝位置漂移与泄漏)             │
                            │  - 阻断 UDP 443 (QUIC) 消除绕过漏洞           │
                            │                                              │
                            │           Xray 内部精细化路由引擎            │
                            └──────────────┬───────────────────────────────┘
                                           │
                 ┌─────────────────────────┴─────────────────────────┐
                 │                                                   │
                 ▼ 域名识别: 包含 claude.ai / openai.com              ▼ 域名识别: 包含 google / gemini
    ┌───────────────────────────┐                       ┌───────────────────────────┐
    │ 原生独享出口 (Direct Out)  │                       │ WARP 清洁分流 (Socks 40000)│
    │  - 纯净美区住宅/双ISP IP   │                       │  - 走 Cloudflare WARP 出口│
    │  - 独享信誉，Claude 极度友好 │                       │  - 完美解锁 Gemini & 谷歌 │
    └────────────┬──────────────┘                       └────────────┬──────────────┘
                 ▼                                                   ▼
       Anthropic / OpenAI                                     Google / Gemini
```

---

## 📂 项目结构说明

```tree
claude-antiban-network/
├── SKILL.md                          # Agent 技能定义文件（供 AI Agent 自动读取执行）
├── README.md                         # 本文档（详细使用教程、原理与排错手册）
├── .gitignore
├── scripts/
│   ├── vps_setup.sh                  # [VPS 端] 一键初始化安装脚本（Xray + WARP + 内核参数）
│   ├── generate_clash_config.py      # [本地端] 一键生成防漏 Clash Verge 配置文件与移动端链接
│   └── verify_environment.py         # [本地端] 全自动网络环境与防封门禁检测脚本
└── templates/
    ├── xray_server.json.template     # Xray 双轨分流服务端模板
    └── clash_profile.yaml.template   # Clash Verge 客户端抗封锁分流模板
```

---

## 🚀 使用方法

你可以选择 **【方式一：让 AI Agent 全自动部署】**（推荐，小白无门槛），或 **【方式二：手动执行命令部署】**。

### 方式一：作为 AI Agent 技能全自动运行（推荐）

如果你在使用 **Google Antigravity / Cursor / Claude Code / Codex** 等支持 Skill 扩展的智能编程助手：

#### 1. 将本仓库克隆至技能目录
* **全局技能目录**：`~/.gemini/config/skills/claude-antiban-network`
* **当前项目技能目录**：`<你的项目根目录>/.agent/skills/claude-antiban-network`

```bash
git clone https://github.com/BigDataScholar/claude-antiban-network.git ~/.gemini/config/skills/claude-antiban-network
```

#### 2. 对你的 Agent 发出指令
直接在对话窗口对 Agent 说：
> **“我刚买了一台海外 VPS，请使用 `claude-antiban-network` 技能帮我把它搭建成防 Claude 封号的专属网络，并帮我检查是否有 DNS 泄露。”**

#### 3. 自动化闭环流程
Agent 会自动完成：
1. **交互索取**：向你询问 VPS 的 IP 地址、SSH 端口、root 密码；
2. **远程安装**：自动连接 VPS 执行 `vps_setup.sh`，完成 Xray、WARP 与内核参数调优；
3. **生成配置**：自动在你的桌面上生成 `Claude-独享纯美区配置.yaml` 并输出手机小火箭订阅链接；
4. **自动化门禁测试**：运行 `verify_environment.py` 对 IP 纯净度、Claude 连通性、Gemini 解锁情况出具全绿验收报告。

---

### 方式二：手动执行部署（运维与极客方案）

#### 第一步：登录 VPS 执行服务端一键安装
以 `root` 用户登录你刚购买的 Linux VPS（推荐 Ubuntu 22.04+ 或 Debian 11+）：

```bash
curl -fsSL https://raw.githubusercontent.com/BigDataScholar/claude-antiban-network/main/scripts/vps_setup.sh -o /tmp/vps_setup.sh
bash /tmp/vps_setup.sh
```

脚本运行完毕后，会在终端末尾输出一段 JSON 元数据，类似：
```json
###JSON_OUTPUT_START###
{
  "server_ip": "216.167.23.xxx",
  "port": 24433,
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "flow": "xtls-rprx-vision",
  "security": "reality",
  "sni": "gateway.icloud.com",
  "public_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "short_id": "xxxxxxxxxxxxxxxx",
  "fingerprint": "chrome",
  "warp_port": 40000
}
###JSON_OUTPUT_END###
```

#### 第二步：在本地生成客户端配置文件与手机端链接
在本地电脑（Mac 或 PC）上运行配置生成脚本：

```bash
python3 scripts/generate_clash_config.py \
  --json-input '<将上方输出的完整JSON粘贴在此处>' \
  --output "~/Desktop/Claude-独享纯美区配置.yaml"
```

你将在桌面上得到：
1. `Claude-独享纯美区配置.yaml`（用于电脑端 Clash Verge Rev）；
2. 终端打印出的 `vless://...` 链接（用于手机端小火箭 / Sing-box）。

#### 第三步：电脑端导入并启动
1. 打开 **Clash Verge Rev** 客户端；
2. 点击左侧 **订阅 (Profiles)**，将桌面上的 `.yaml` 文件直接拖入窗口；
3. 右键导入的配置，点击 **使用 (Use)**；
4. 打开软件左侧的 **系统代理 (System Proxy)**，并开启 **TUN 模式 (Tun Mode)**；
5. 在 **代理 (Proxies)** 页面中，确认 `🚀 独享-AI与代码` 和 `🌐 谷歌与Gemini` 选中了你的独享节点。

#### 第四步：运行自动化环境门禁自检
在本地终端中运行验证脚本，检查全链路安全性：

```bash
python3 scripts/verify_environment.py --proxy http://127.0.0.1:7897
```

如果环境检测合格，输出示例如下：
```text
=====================================================
 Claude & AI Anti-Ban Network Environment Gate Check 
=====================================================
正在通过代理检测: http://127.0.0.1:7897
[PASS (US)] 出口 IP: 216.167.23.xxx
       物理位置 : United States (US), Los Angeles
       ISP / 归属: NTT America, Inc. / AS2914
[PASS] DNS 解析出口位于海外: 1.1.1.1 (Cloudflare)
[PASS] Anthropic API 网关: 直连成功 (Origin 404, cf-ray: ...-LAX)
[PASS] Claude Web 网页端: 直达无阻 (HTTP 200)
[PASS] Google Gemini 区域检测: 成功 (未出现 ZZ 区域封锁)
[PASS] 本机 IPv6 泄露检查: 未发现直连绕行

=====================================================
 验收检测结论总结 
=====================================================
  - 出口 IP 归属: ✓ 通过 (US)
  - DNS 解析状态: ✓ 正常 (无国内泄露)
  - Anthropic API 网关: ✓ 可直达
  - Claude Web 状态: PASS
  - Gemini 区域解锁: ✓ 未见 ZZ 封锁
  - 本机 IPv6 绕行检查: ✓ 安全
```

---

## ⚠️ 常见排错与日常防封守则 (FAQ)

### 1. 聊天打中文、或者让 Claude 看国内文件会不会导致封号？
* **结论：绝对不会！**
* Anthropic 的风控机制针对的是**“网络连接物理来源（Geo-IP）”**、**“盗刷卡支付”**以及**“恶意黑客/违法违规行为（AUP）”**。
* 全球有数百万海外华人、留学生以及跨国企业分析师每天都在用 Claude 处理中文财报、中国商业合同。只要网络出口 IP 稳定在美区原生环境，语言本身 100% 安全。

### 2. 为什么严禁让主机商“更换解锁 Gemini 的 IP”？
* 很多用户发现新 VPS 上不了 Gemini，就急匆匆去找主机商提工单“换 IP”。
* **高危隐患**：主机商库存中所谓的“解锁 IP”，往往是从备用 IP 池中捞出来的。这些 IP 极有可能之前被其他人频繁用于滥用操作，甚至早已被 Anthropic 列入黑名单！
* **正确做法**：保留当前具有极佳信誉的原生 IP，通过本套件内置的 **Cloudflare WARP 双轨分流** 即可零风险秒级解锁 Gemini，切勿因小失大。

### 3. 如何彻底封堵浏览器的 WebRTC 泄露？
即使开了代理，某些浏览器（尤其是 Chrome、Edge）仍可能通过 WebRTC 协议直接探测到本地的物理局域网网卡。
* **防护建议**：在 Chrome / Edge 应用商店安装免费插件 **`WebRTC Control`**，将状态球切换为**蓝色（Disable WebRTC completely）**即可。

### 4. 深度思考或 Codex 偶尔报错 `Broken Pipe` 怎么办？
* 确认客户端配置已开启 `keep-alive-interval: 15`；
* 确认 VPS 端已生效 `/etc/sysctl.d/99-claude-antiban.conf` 中的 TCP Keepalive 规则：
  ```bash
  sysctl net.ipv4.tcp_keepalive_time
  # 应返回 30
  ```

---

## 📄 License & 免责声明

* 本项目基于 [MIT License](LICENSE) 开源。
* 本项目仅用于个人网络环境加固、远程学术科研协作及合法技术交流，请遵守所在国家和地区的法律法规，请勿用于非法用途。
