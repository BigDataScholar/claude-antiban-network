---
name: claude-antiban-network
description: >-
  纯 AI Agent 全自动化防封网络搭建技能套件（兼容 Codex / Antigravity / Cursor / Claude Code）。
  用于将【全新】海外原生住宅/双ISP VPS（Debian 11+ / Ubuntu 22.04+）全自动部署为防 Claude / ChatGPT 封号的高纯净独享网络环境，
  采用 SSH 密钥免密 + 0600 文件凭证交接（密码与 UUID 绝不进入聊天/命令历史）、SHA256 校验固定版本 Xray VLESS Reality、
  Cloudflare WARP 双轨分流、严格防火墙与客户端入站实测、精确出口 IP 比对与本地防泄露门禁验收。
---

# Claude 防封网络全自动化搭建技能 (claude-antiban-network)

## 技能定位与安全红线

本技能面向所有主流 AI Agent（**Codex / Google Antigravity / Cursor / Claude Code** 等），提供安全、可验证、跨 Agent 通用的防封网络自动化交付流程。

### ⚠️ 4 条强制安全与稳定性红线（Agent 必须严格遵守）

1. **默认仅支持全新 VPS（防误伤存量服务）**：
   * `scripts/vps_setup.sh` 会在执行任何 `apt` / `sysctl` / Xray / WARP 改动**之前**检查是否已存在 Xray 或 WARP。若检出已有环境，立即退出（exit 2）且零修改；
   * 仅当用户在维护窗口明确确认覆盖时，才允许传入 `ALLOW_EXISTING=true`（如需同时轮换凭证，传 `ALLOW_EXISTING=true REGENERATE=true`）。
2. **零凭证泄露（绝不向用户索要明文密码进聊天！）**：
   * **禁止**让用户在聊天窗口粘贴 VPS `root` 密码；
   * **优先使用本机已有 SSH 密钥 / `ssh-agent`**；若 VPS 仅开通了密码登录，请给用户一行 `ssh-copy-id` 命令，让用户在**自己本机终端亲自输入密码**推上公钥后再交由 Agent 免密接管；
   * **禁止**将含 UUID / PrivateKey 的 JSON 拼进命令行参数，也**禁止**把原始 `vless://` 链接打印到聊天记录；节点凭证全程通过 `0600` 权限文件交接（VPS `/root/claude-antiban-node.json` ➔ `scp` ➔ 本机 `~/.claude-antiban/node.json`）。
3. **固定版本与校验和**：
   * `vps_setup.sh` 已固定经验证的官方 `XTLS/Xray-install` commit SHA、脚本 SHA256 校验和及 Xray-core 版本（`v26.11.9`），不再盲跑上游漂移 `main` 分支。
4. **必须从客户端实测入站端口与精确出口 IP**：
   * 服务端脚本放行 UFW / firewalld / iptables 失败时会直接报错中止（不吞错），但**云厂商控制台安全组独立于 VPS 防火墙**；
   * 验收时必须传入 `--node-json ~/.claude-antiban/node.json`，从本机直连验证 `<VPS_IP>:<PORT>` 入站可达，并精确比对代理出口 IP 等于本次部署的 `<VPS_IP>`。

```mermaid
flowchart TD
    Client["本地设备 (Mac / Windows / iOS / Android)<br/>Clash Verge Rev · 系统代理 + TUN 双开 / Fake-IP<br/>禁用公网 IPv6 + Chrome WebRTC Control"] -->|"VLESS Reality · XTLS-rprx-vision / Keepalive 15s"| VPS["全新海外独享原生 / 双ISP VPS<br/>Ubuntu 22.04+ / Debian 11+<br/>BBR + TCP Keepalive 30s + 禁用 IPv6"]

    VPS -->|"Xray 精细路由"| Router{"双轨隔离引擎"}
    Router -->|"Claude / ChatGPT / Persona / Turnstile"| Direct["原生独享美区 IP<br/>极致防封 / 零污染"]
    Router -->|"Google / Gemini / AI Studio"| WARP["Cloudflare WARP · 127.0.0.1:40000<br/>突破 ZZ 区域封锁"]
    Router -->|"UDP 443 · QUIC"| Block["Blackhole 阻断<br/>防 UDP 穿透泄露"]
```

---

## 目录结构

* `scripts/vps_setup.sh`：VPS 端部署脚本（全新 VPS 预检、SHA256 校验固定 Xray 版本、WARP 优雅降级、0600 服务端配置与备份、严格防火墙校验、从最终活跃 `config.json` 生成 `0600` 元数据文件）。
* `scripts/generate_clash_config.py`：本地配置生成器（从 `0600` 文件读取节点元数据，生成 `0600` 防漏 Clash YAML 与 `0600` 移动端 VLESS 链接文件，支持合法空 `short_id`）。
* `scripts/verify_environment.py`：客户端端到端门禁脚本（免疫 `NO_PROXY`、直测 VPS 入站端口、精确比对目标 VPS 出口 IP、单次代理 DNS 探针、Anthropic API/Web 分离报告、Gemini ZZ、本机 IPv6 与 Fake-IP 门禁）。
* `tests/test_suite.py`：内置零依赖 Python 回归测试套件（覆盖预检、防火墙失败传播、0600 权限、空 shortId 复用、凭证轮换、NO_PROXY 免疫与出口 IP 精确比对）。

---

## Agent 6 步全自动执行 SOP

### 第 1 步：采集目标信息并建立免密 SSH（零密码进聊天）

向用户确认以下**非敏感连接信息**：
1. **VPS 公网 IPv4 地址**（确认是全新 Debian 11+ / Ubuntu 22.04+ VPS）
2. **SSH 端口号**（如主机商提供的自定义高位端口）
3. **SSH 用户名**（通常为 `root`）

**建立安全 SSH 连接（严禁要求用户在聊天框发密码）**：
1. Agent 先测试本机已有 SSH 密钥 / `ssh-agent` 能否直接连通：
   ```bash
   ssh -o BatchMode=yes -o ConnectTimeout=5 -p <SSH_PORT> root@<VPS_IP> "echo SSH_KEY_OK"
   ```
2. 若尚未配置免密密钥，请引导用户在**自己本机终端**运行一次授权命令（密码仅由用户本人在本地终端输入，不经过 Agent）：
   ```bash
   # 若本机尚无公钥先执行：ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
   ssh-copy-id -p <SSH_PORT> root@<VPS_IP>
   ```
3. 待用户完成后，复测 `BatchMode=yes` 确认免密通道就绪。

---

### 第 2 步：远程部署 VPS 并通过 `0600` 文件回收节点元数据

```bash
# 1. 上传并执行服务端部署脚本（默认仅允许全新 VPS；不向终端吐出敏感凭证）
scp -P <SSH_PORT> <skill-path>/scripts/vps_setup.sh root@<VPS_IP>:/tmp/vps_setup.sh
ssh -p <SSH_PORT> root@<VPS_IP> "bash /tmp/vps_setup.sh && rm -f /tmp/vps_setup.sh"

# 2. 创建本机受限目录 (0700)，通过 scp 拉取 0600 节点元数据文件
mkdir -p -m 700 ~/.claude-antiban
scp -P <SSH_PORT> root@<VPS_IP>:/root/claude-antiban-node.json ~/.claude-antiban/node.json
chmod 600 ~/.claude-antiban/node.json
```

* 若 `vps_setup.sh` 退出码为 `2`：说明目标 VPS 已有旧 Xray/WARP，向用户汇报并确认是否要显式启用 `ALLOW_EXISTING=true`（或换一台全新 VPS）。
* 若防火墙步骤报错退出：直接告知用户具体失败项，切勿假装部署成功。

---

### 第 3 步：生成本地防漏配置与移动端 `0600` 链接文件

使用 `--json-file` 读取受限文件（绝不将 UUID 暴露在命令参数或聊天中）：

```bash
python3 <skill-path>/scripts/generate_clash_config.py \
  --json-file ~/.claude-antiban/node.json \
  --name "🇺🇸 独享-Claude-原生住宅9929" \
  --output "~/Desktop/Claude-独享纯美区配置.yaml"
```

产出两个 `0600` 受限文件：
1. `~/Desktop/Claude-独享纯美区配置.yaml`（桌面端 Clash Verge Rev 配置）；
2. `~/Desktop/Claude-独享纯美区配置-mobile-vless.txt`（移动端 Shadowrocket / Sing-box / Loon 导入链接，请用户自行本地打开复制，勿打印到聊天）。

---

### 第 4 步：引导客户端导入与「双开」加固

1. **桌面端（Clash Verge Rev）**：
   * 左侧 **订阅 (Profiles)** ➔ 拖入桌面 `Claude-独享纯美区配置.yaml` ➔ 右键点击 **使用 (Use)**；
   * 左侧 **设置 / 主页** ➔ **同时开启「系统代理 (System Proxy)」与「TUN 模式 (Tun Mode)」**；
   * 左侧 **代理 (Proxies)** ➔ 确认 `🚀 独享-AI与代码`、`🌐 谷歌与Gemini`、`🐟 漏网之鱼` 均选中你的独享节点；
   * **避坑提醒**：若用户开启过 Clash Verge 全局 DNS 覆写，务必对该配置**关闭 DNS 覆写**（以免覆写注入直连海外 DoH 导致 X / YouTube 卡死）。
2. **浏览器 WebRTC 防护**：
   * Chrome / Edge 安装 **`WebRTC Control`** 插件，点击右上角图标点亮**蓝色禁用状态**。

---

### 第 5 步：客户端端到端门禁验收（精确比对目标 VPS）

待用户启动 Clash Verge 后，**必须传入 `--node-json ~/.claude-antiban/node.json`** 运行门禁验收：

```bash
python3 <skill-path>/scripts/verify_environment.py \
  --proxy http://127.0.0.1:7897 \
  --node-json ~/.claude-antiban/node.json
```

**按故障定位结果闭环处理**：
* **入站 TCP 端口不可达**：定位为**云厂商控制台安全组 / VPS 防火墙**未放行该端口 ➔ 引导用户在云控制台放行 TCP 端口后重测；
* **端口可达但出口 IP 不匹配**：定位为 Clash 未选中新节点或代理端口不对 ➔ 检查 Clash 策略组；
* **检出本机公网 IPv6 绕行**：
  * **macOS**：`系统设置 ➔ 网络 ➔ Wi-Fi ➔ 详细信息 ➔ TCP/IP ➔ 配置 IPv6` 改为 **「仅本地链接」**；
  * **Windows**：网络适配器属性取消勾选 `Internet 协议版本 6 (TCP/IPv6)`；
* **Fake-IP 未接管**：确认 Clash 已开启「TUN 模式」（若切换过 Wi-Fi，关开一次 TUN 开关）；
* **人工确认项**：提醒用户在真实浏览器中打开 `https://claude.ai`（完成 Turnstile 人机校验并确认账号登录可用），并在 `https://ip.net.coffee/claude` 与 `https://scamalytics.com` 人工复核。

---

### 第 6 步：交付《防封行为守则与常见排障》

验收通过后，向用户简明交付：
1. **支付避坑**：安卓端通过 Google Play 绑定国内 Visa/Mastercard 原价订阅 Claude Pro，避免网页端强刷国内双币卡触发 Stripe 风控；
2. **严格独享与业务隔离**：一人一机独享（本人多设备登同一账号安全），严禁多人多账号拼车，严禁把高频爬虫混跑在 Claude 独享 IP 上；
3. **换 Wi-Fi 偶发异常秒解**：若换 Wi-Fi 后外网打不开或 Claude 提示「地区不可用」（非封号），在 Clash Verge 关开一次 TUN 开关即可；
4. **勿向主机商申请“换解锁 Gemini IP”**：本套件已通过 WARP 自动解锁，避免换到被滥用的高危二手 IP。
