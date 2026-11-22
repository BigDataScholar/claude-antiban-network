#!/usr/bin/env python3
"""
Generate a hardened, anti-leak Clash Verge / Mihomo YAML profile and VLESS Share Link
from VPS setup output.

Battle-tested design:
- Fake-IP + GEOSITE,geolocation-!cn + GEOIP,CN,DIRECT,no-resolve:
  Zero domestic DNS leak for overseas domains AND zero GFW DoH hang.
- Blocks UDP 443 (QUIC) to prevent browser UDP bypass/leak.
- Dedicated AI group locked to the user's native residential US VPS.
- Complete rules for Claude/Anthropic (incl. Persona/Turnstile), OpenAI/ChatGPT,
  Google/Gemini/YouTube, Twitter/X (incl. twimg/t.co), and dev ecosystem.
"""

import argparse
import json
import os
import sys
import urllib.parse

TEMPLATE_YAML = """port: 7890
socks-port: 7891
mixed-port: 7897
mode: rule
unified-delay: true
keep-alive-interval: 15
log-level: info
allow-lan: false
external-controller: 127.0.0.1:9097

dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  respect-rules: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver-policy:
    "geosite:cn,private":
      - 223.5.5.5
      - 119.29.29.29

tun:
  enable: true
  stack: mixed
  dns-hijack:
    - "any:53"
    - "tcp://any:53"
  auto-route: true
  auto-detect-interface: true

proxies:
  - name: {node_name_yaml}
    type: vless
    server: {server_ip_yaml}
    port: {port}
    uuid: {uuid_yaml}
    network: tcp
    udp: true
    tls: true
    flow: {flow_yaml}
    servername: {sni_yaml}
    reality-opts:
      public-key: {public_key_yaml}
      short-id: {short_id_yaml}
    client-fingerprint: {fingerprint_yaml}

proxy-groups:
  - name: "🚀 独享-AI与代码"
    type: select
    proxies:
      - {node_name_yaml}
      - DIRECT

  - name: "🌐 谷歌与Gemini"
    type: select
    proxies:
      - {node_name_yaml}
      - DIRECT

  - name: "🐟 漏网之鱼"
    type: select
    proxies:
      - {node_name_yaml}
      - DIRECT

rules:
  # ==========================================
  # 1. 阻断 QUIC (UDP 443)，强制走 TCP 代理防止绕行与泄露
  # ==========================================
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT

  # ==========================================
  # 2. 核心 AI 专属规则（直连原生独享美区纯净 IP）
  # ==========================================
  - DOMAIN-SUFFIX,anthropic.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,claude.ai,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,claudeusercontent.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,withpersona.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,challenges.cloudflare.com,🚀 独享-AI与代码
  - DOMAIN-KEYWORD,anthropic,🚀 独享-AI与代码
  - DOMAIN-KEYWORD,claude,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,openai.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,chatgpt.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,oaistatic.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,oaiusercontent.com,🚀 独享-AI与代码
  - DOMAIN-KEYWORD,openai,🚀 独享-AI与代码
  - DOMAIN-KEYWORD,chatgpt,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,sentry.io,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,statsigapi.net,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,intercom.io,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,stripe.com,🚀 独享-AI与代码

  # ==========================================
  # 3. 谷歌、Gemini 与 YouTube（VPS 内部自动走 WARP 解锁）
  # ==========================================
  - GEOSITE,youtube,🌐 谷歌与Gemini
  - GEOSITE,google,🌐 谷歌与Gemini
  - DOMAIN-SUFFIX,youtube.com,🌐 谷歌与Gemini
  - DOMAIN-SUFFIX,googlevideo.com,🌐 谷歌与Gemini
  - DOMAIN-SUFFIX,ytimg.com,🌐 谷歌与Gemini
  - DOMAIN-SUFFIX,ggpht.com,🌐 谷歌与Gemini
  - DOMAIN-SUFFIX,gemini.google.com,🌐 谷歌与Gemini
  - DOMAIN-SUFFIX,aistudio.google.com,🌐 谷歌与Gemini
  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,🌐 谷歌与Gemini
  - DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,🌐 谷歌与Gemini
  - DOMAIN-KEYWORD,gemini,🌐 谷歌与Gemini
  - DOMAIN-KEYWORD,antigravity,🌐 谷歌与Gemini

  # ==========================================
  # 4. Twitter / X 与开发者常用生态
  # ==========================================
  - GEOSITE,twitter,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,twitter.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,x.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,twimg.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,t.co,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,github.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,githubusercontent.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,cursor.com,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,cursor.sh,🚀 独享-AI与代码
  - DOMAIN-SUFFIX,v2ex.com,🚀 独享-AI与代码

  # ==========================================
  # 5. 全局非国内域名防漏拦截（Fake-IP 直送 VPS 远程解析）
  # ==========================================
  - GEOSITE,geolocation-!cn,🚀 独享-AI与代码

  # ==========================================
  # 6. 国内直连与内网拦截（no-resolve 彻底杜绝未知域名触发国内 DNS）
  # ==========================================
  - GEOIP,lan,DIRECT,no-resolve
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT,no-resolve

  # ==========================================
  # 7. 最终兜底（未匹配域名一律远程解析并走独享节点）
  # ==========================================
  - MATCH,🐟 漏网之鱼
"""


def generate_vless_url(node):
    params = {
        "security": "reality",
        "encryption": "none",
        "pbk": node["public_key"],
        "headerType": "none",
        "fp": node.get("fingerprint", "chrome"),
        "type": "tcp",
        "flow": node.get("flow", "xtls-rprx-vision"),
        "sni": node["sni"],
        "sid": node["short_id"]
    }
    query_str = urllib.parse.urlencode(params)
    name_encoded = urllib.parse.quote(node.get("node_name", "🇺🇸 独享-Claude-原生住宅9929"))
    return f"vless://{node['uuid']}@{node['server_ip']}:{node['port']}?{query_str}#{name_encoded}"


def main():
    parser = argparse.ArgumentParser(description="Generate Clash Verge / Mihomo profile and VLESS URL")
    parser.add_argument("--json-input", help="Path to JSON file or raw JSON string from vps_setup.sh")
    parser.add_argument("--ip", help="VPS Server IPv4")
    parser.add_argument("--port", type=int, default=24433, help="Port (default: 24433)")
    parser.add_argument("--uuid", help="Client UUID")
    parser.add_argument("--public-key", help="Reality Public Key")
    parser.add_argument("--short-id", help="Reality Short ID")
    parser.add_argument("--sni", default="gateway.icloud.com", help="Server SNI (default: gateway.icloud.com)")
    parser.add_argument("--name", default="🇺🇸 独享-Claude-原生住宅9929", help="Node display name")
    parser.add_argument("--output", default="Claude-AntiBan-Profile.yaml", help="Output YAML path")

    args = parser.parse_args()

    data = {}
    if args.json_input:
        if os.path.exists(args.json_input):
            with open(args.json_input, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.loads(args.json_input)

    server_ip = data.get("server_ip") or args.ip
    port = data.get("port") or args.port
    uuid = data.get("uuid") or args.uuid
    public_key = data.get("public_key") or args.public_key
    short_id = data.get("short_id") or args.short_id
    sni = data.get("sni") or args.sni
    flow = data.get("flow") or "xtls-rprx-vision"
    fingerprint = data.get("fingerprint") or "chrome"
    node_name = args.name

    if not all([server_ip, port, uuid, public_key, short_id, sni]):
        print("Error: Missing required connection parameters (server_ip, port, uuid, public_key, short_id, sni)!", file=sys.stderr)
        sys.exit(1)

    output_path = os.path.expanduser(args.output)
    output_dir = os.path.dirname(os.path.abspath(output_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Use standard JSON string dumps for YAML flow scalars.
    # Standard JSON string literals are fully valid YAML 1.2 double-quoted strings,
    # correctly handling all backslashes, quotes, octals/integers (like short-id), and control chars.
    node_dict = {
        "server_ip_yaml": json.dumps(str(server_ip), ensure_ascii=False),
        "port": int(port),
        "uuid_yaml": json.dumps(str(uuid), ensure_ascii=False),
        "flow_yaml": json.dumps(str(flow), ensure_ascii=False),
        "sni_yaml": json.dumps(str(sni), ensure_ascii=False),
        "public_key_yaml": json.dumps(str(public_key), ensure_ascii=False),
        "short_id_yaml": json.dumps(str(short_id), ensure_ascii=False),
        "fingerprint_yaml": json.dumps(str(fingerprint), ensure_ascii=False),
        "node_name_yaml": json.dumps(str(node_name), ensure_ascii=False)
    }

    yaml_content = TEMPLATE_YAML.format(**node_dict)

    # Restrict file permissions to 0600 on creation/write (owner read/write only)
    try:
        if os.path.exists(output_path):
            os.chmod(output_path, 0o600)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(output_path, flags, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(yaml_content)
        os.chmod(output_path, 0o600)
        print(f"\n[SUCCESS] Generated Clash YAML Profile: {os.path.abspath(output_path)}")
        print(f"[SECURITY] Set file permissions to 0600: {os.path.abspath(output_path)}")
    except Exception as e:
        print(f"\n[ERROR] Failed to write profile to {output_path} with 0600 permissions: {e}", file=sys.stderr)
        sys.exit(1)

    vless_node_info = {
        "server_ip": server_ip,
        "port": port,
        "uuid": uuid,
        "flow": flow,
        "sni": sni,
        "public_key": public_key,
        "short_id": short_id,
        "fingerprint": fingerprint,
        "node_name": node_name
    }
    vless_url = generate_vless_url(vless_node_info)

    print(f"\n[VLESS Share Link (for iOS Shadowrocket / Sing-box / Loon)]:\n{vless_url}\n")


if __name__ == "__main__":
    main()
