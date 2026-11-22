---
name: claude-antiban-network
description: >-
  纯 AI Agent 全自动化防封网络搭建技能套件。用于将全新海外原生住宅/双ISP VPS（如 LisaHost、搬瓦工等）
  全自动部署为防 Claude / ChatGPT 封号的高纯净独享网络环境，涵盖 VPS 端 Xray VLESS Reality、
  Cloudflare WARP 双轨分流（解锁 Gemini 同时锁定 Claude 原生直连）、Linux 内核 TCP Keepalive 防断流、
  本地零泄露防卡顿 Clash Verge 配置生成、本机 IPv6 / WebRTC / Fake-IP 系统级加固与 6 项门禁自动化验收。
---

# Claude 防封网络全自动化搭建技能 (claude-antiban-network)

## 技能定位与核心架构

本技能面向 AI Agent（Google Antigravity / Cursor / Claude Code / Codex 等），提供**端到端、零手工折腾**的 Claude / ChatGPT / Gemini 防封专属网络自动化落地流程。

```mermaid
flowchart TD
    Client["本地设备 (Mac / Windows / iOS / Android)\nClash Verge Rev (系统代理 + TUN 双开 / Fake-IP)\n禁用公网 IPv6 + Chrome WebRTC Control"] -->|VLESS Reality (XTLS-rprx-vision)\nChrome 指纹 + Keepalive 15s| VPS["海外独享原生/双ISP VPS\nUbuntu 22.04+ / Debian 11+\nBBR + TCP Keepalive 30s + 禁用 IPv6"]

    VPS -->|Xray 精细路由| Router{"双轨隔离引擎"}
    Router -->|"Claude / ChatGPT / Persona / Turnstile"| Direct["原生独享美区 IP\n(Fraud Score 0 / 极致防封)"]
    Router -->|"Google / Gemini / AI Studio"| WARP["Cloudflare WARP (127.0.0.1:40000)\n(突破 ZZ 区域封锁)"]
    Router -->|"UDP 443 (QUIC)"| Block["Blackhole 阻断\n(防 UDP 穿透泄露)"]
```

### 实战沉淀的 5 大关键防坑设计（Agent 务必遵循）

1. **零泄露且绝不卡顿的本地 DNS 策略**：
   * 本套件生成的 Clash 配置采用 **`Fake-IP` + `GEOSITE,geolocation-!cn` + `GEOIP,CN,DIRECT,no-resolve`** 组合。
   * **原理**：所有海外与未命中直连的域名直接通过 Fake-IP 以域名形式送往美西 VPS 远程解析（实测上游为美国 Cloudflare DNS，零国内泄露）；同时避免在本地直连海外 DoH（如 `dns.cloudflare.com`）被防火墙限速卡死导致 X / YouTube 无法打开。
   * **避坑**：导入 Clash Verge Rev 后，**不要**开启 Clash Verge 全局 DNS 覆写去覆盖本配置（若用户开启了全局覆写，需对该配置关闭 DNS 覆写）。
2. **「系统代理 + TUN 模式」双开防投毒**：
   * 仅开 TUN 时，用户在中途切换 Wi-Fi（公司 ⇄ 热点 ⇄ 家里）容易被新路由器覆盖系统 DNS 导致 GFW DNS 投毒。
   * 必须引导用户**同时开启「系统代理 (System Proxy)」与「TUN 模式 (Tun Mode)」**（互不重叠、不卡电脑，浏览器直走代理端口免疫换网投毒，终端/CLI 由 TUN 全局兜底）。
3. **本机公网 IPv6 隔离**：
   * 国内家庭宽带常分配联通 `2408:` / 电信 `240e:` / 移动 `2409:` 公网 IPv6。必须通过门禁脚本检查，若检出活跃公网 IPv6，必须引导用户将其改为「仅本地链接」（macOS）或取消勾选 IPv6（Windows）。
4. **严格业务隔离（保护 0 分独享 IP）**：
   * 一人一机独享，严禁多人多账号拼车共用同一 VPS（连带封号高危）；
   * 若用户有高频自动化爬虫/采集需求（如每天数千次抓取 Facebook 等），提醒将其拆分至独立策略组走中转节点，切勿污染 Claude 独享 IP。
5. **安全红线**：
   * 严禁将用户的真实 VPS IP、SSH 密码、UUID、私钥写入仓库或任何可公开文件；
   * `scripts/vps_setup.sh` 已内置无损保留既有配置（多客户端、多 shortId、附加 inbound）、预检校验与失败自动回滚保护。

---

## 目录结构

* `scripts/vps_setup.sh`：VPS 端全自动部署脚本（Xray Reality + WARP 双轨分流 + 内核 BBR/Keepalive + 禁用 IPv6 + 防火墙 + 原子替换回滚 + JSON 输出）。
* `scripts/generate_clash_config.py`：本地配置生成器（输出 `0600` 权限 Clash Verge 防漏配置 + 移动端 `vless://` 链接，纯 Python 3 标准库零依赖）。
* `scripts/verify_environment.py`：端到端 6 项门禁验收脚本（US 出口、上游 DNS 防漏、Anthropic API/Web、Gemini ZZ 检测、本机公网 IPv6 检测、本机 Fake-IP 接管诊断）。
* `templates/`：与脚本保持同步的服务端/客户端参考模板。

---

## Agent 6 步全自动执行 SOP

当用户请求搭建或检查防 Claude 封号网络时，Agent 应严格按以下 6 步闭环推进：

### 第 1 步：交互式采集 VPS 凭证与环境确认

向用户收集：
1. **VPS 公网 IPv4 地址**
2. **SSH 端口号**（如 LisaHost 等主机商通常为自定义高位端口）
3. **SSH 登录账号**（通常为 `root`）
4. **SSH 密码或本地私钥路径**

> **新手科普提示**：VPS 系统需为 **Ubuntu 22.04+ 或 Debian 11+**。若用户疑惑为何是“乌班图（Ubuntu）”，说明 Ubuntu 是行业最标准的轻量服务器系统，不要重装成 Windows。

---

### 第 2 步：远程全自动部署 VPS 服务端

将 `<skill-path>/scripts/vps_setup.sh` 传送至目标 VPS 并以 `root` 权限执行：

```bash
scp -P <SSH_PORT> <skill-path>/scripts/vps_setup.sh root@<VPS_IP>:/tmp/vps_setup.sh
ssh -p <SSH_PORT> root@<VPS_IP> "bash /tmp/vps_setup.sh"
```

* 若本地无 `sshpass` 且需密码登录，macOS 可用系统自带 `/usr/bin/expect` 安全执行（勿将密码落盘持久化）。
* 脚本末尾会打印标准 JSON 元数据块：
  ```text
  ###JSON_OUTPUT_START###
  { ... }
  ###JSON_OUTPUT_END###
  ```
* 提取完整 JSON 块用于第 3 步；同时确认 `warp_ready` 是否为 `true`（若为 `false`，说明已自动降级为 `direct` 保活，可按需协助排查 WARP）。

---

### 第 3 步：生成本地防漏配置与移动端订阅链接

使用第 2 步提取的 JSON 调用生成脚本：

```bash
python3 <skill-path>/scripts/generate_clash_config.py \
  --json-input '<提取到的完整JSON>' \
  --name "🇺🇸 独享-Claude-原生住宅9929" \
  --output "~/Desktop/Claude-独享纯美区配置.yaml"
```

向用户交付：
1. 桌面生成的 `Claude-独享纯美区配置.yaml`（已自动设置 `0600` 权限）；
2. 终端输出的 `vless://...` 链接（用于手机端 Shadowrocket / Sing-box / Loon）。

---

### 第 4 步：引导客户端导入与「双开」加固

清晰引导用户完成客户端配置（每一步都很关键）：
1. **电脑端（Clash Verge Rev）**：
   * 左侧 **订阅 (Profiles)** ➔ 将桌面 `Claude-独享纯美区配置.yaml` 拖入窗口 ➔ 右键点击 **使用 (Use)**；
   * 左侧 **设置 / 主页** ➔ **同时开启「系统代理 (System Proxy)」与「TUN 模式 (Tun Mode)」**；
   * 左侧 **代理 (Proxies)** ➔ 确认 `🚀 独享-AI与代码`、`🌐 谷歌与Gemini`、`🐟 漏网之鱼` 均已选中你的独享节点；
   * 若用户之前开启了 Clash Verge 全局 DNS 覆写，提醒对该配置**关闭 DNS 覆写**（避免覆写引入直连海外 DoH 导致卡顿）。
2. **手机端（iOS / Android）**：
   * 复制 `vless://...` 链接导入 Shadowrocket / Sing-box / Loon。
3. **浏览器防 WebRTC 泄露**：
   * 在 Chrome / Edge 商店安装免费插件 **`WebRTC Control`**，并点击右上角插件图标使其亮起**蓝色状态**（禁用 WebRTC）。

---

### 第 5 步：全自动 6 项门禁验收与本机系统排雷

待用户启动 Clash Verge 后，在本地运行门禁检测脚本：

```bash
python3 <skill-path>/scripts/verify_environment.py --proxy http://127.0.0.1:7897
```

**根据脚本输出结果执行闭环修复**：
* **若检出本机公网 IPv6 泄露**（`[LEAK RISK]`）：
  * **macOS**：引导用户打开 `系统设置 ➔ 网络 ➔ Wi-Fi ➔ 详细信息 ➔ TCP/IP ➔ 配置 IPv6` 改为 **「仅本地链接」** ➔ 点「好」；
  * **Windows**：引导用户打开网络适配器属性，取消勾选 `Internet 协议版本 6 (TCP/IPv6)`；
  * 改完后重新运行 `verify_environment.py`，确认输出 **`[GATE: PASS]`**！
* **若提示 Fake-IP 未接管**（`[WARN]`）：引导用户在 Clash Verge 中关开一次「TUN 模式」开关并确认「系统代理」已开启。
* **最终双站复核**：引导用户在 Chrome 打开 `https://ip.net.coffee/claude`（确认 Trust Score 满分、DNS 未泄露、WebRTC 已禁用）及 `https://scamalytics.com`（确认 Fraud Score < 25）。

---

### 第 6 步：交付防封行为守则与常见故障速查

完成验收后，务必向用户简明交付以下 4 条实战经验：
1. **支付避坑（重中之重）**：严禁在网页端强刷国内双币卡（Stripe 极易拒付封号）；推荐在安卓端通过 **Google Play 绑定国内 Visa / Mastercard** 原价订阅 Claude Pro（\$20/月，零加价且零 Stripe 风控）。
2. **一人一机独享原则**：本人自己的手机/电脑/iPad 同连这台独享 VPS 登录同一个 Claude 账号非常安全；严禁多人多账号拼车共用同一 IP，严禁把高频爬虫混跑在 Claude 独享 IP 上。
3. **换 Wi-Fi 偶发异常秒解**：若切换 Wi-Fi 后遇到外网打不开或 Claude 提示「在您所在的地区不可用」（**注意：这不是封号，只是短暂漏走国内 IP 的实时地域拦截**），在 Clash Verge 里**关开一次 TUN 开关**即可 3 秒恢复。
4. **切勿找主机商“换解锁 Gemini IP”**：新 IP 若遇 Gemini 地区报错，本套件的 WARP 双轨分流已自动无损解锁，切勿向主机商申请换“解锁 IP”（大概率换到被别人滥用过的二手高危 IP）。
