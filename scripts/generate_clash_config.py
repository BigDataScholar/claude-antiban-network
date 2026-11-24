#!/usr/bin/env python3
"""
Generate a hardened, anti-leak Clash Verge / Mihomo YAML profile and mobile VLESS link
from a restricted (0600) VPS node metadata JSON file.

Security & correctness features:
- Prefers --json-file <path> so credentials never appear in CLI argv / shell history.
- Writes both the Clash YAML profile and mobile VLESS link to 0600 files (no raw
  secrets printed to stdout unless --print-vless is explicitly passed).
- Supports valid empty Reality short_id ("") without breaking YAML or VLESS URLs.
- Fake-IP + GEOSITE,geolocation-!cn + GEOIP,CN,DIRECT,no-resolve + UDP 443 REJECT.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.parse

HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
PLACEHOLDER_HOSTS = {"YOUR_VPS_IP", "VPS_IP", "<VPS_IP>", "EXAMPLE_IP"}


def is_valid_server_host(host):
    if not isinstance(host, str):
        return False
    h = host.strip()
    if not h or h != host or h.upper() in PLACEHOLDER_HOSTS or "<" in h or ">" in h:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(h))

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


def write_file_0600(path, content):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(path):
        os.chmod(path, 0o600)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with open(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, 0o600)


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
        "sid": node["short_id"],
    }
    query_str = urllib.parse.urlencode(params)
    name_encoded = urllib.parse.quote(node.get("node_name", "🇺🇸 独享-Claude-原生住宅9929"))
    return f"vless://{node['uuid']}@{node['server_ip']}:{node['port']}?{query_str}#{name_encoded}"


def main():
    parser = argparse.ArgumentParser(
        description="Generate Clash Verge / Mihomo profile and mobile VLESS link (0600 file handoff)"
    )
    parser.add_argument(
        "--json-file",
        help="Path to restricted (0600) node metadata JSON file fetched from VPS (recommended)",
    )
    parser.add_argument(
        "--json-input",
        help="Legacy alias: path to JSON file (passing raw JSON strings on CLI is discouraged)",
    )
    parser.add_argument("--ip", help="Client-facing VPS host/IP (overrides JSON metadata)")
    parser.add_argument("--inbound-host", help="Alias for --ip: external client-facing host/IP (for NAT VPS)")
    parser.add_argument("--port", type=int, default=None, help="Client-facing TCP port (overrides JSON metadata; fallback: 24433)")
    parser.add_argument("--inbound-port", type=int, default=None, help="Alias for --port: external client-facing TCP port (for NAT VPS)")
    parser.add_argument("--uuid", help="Client UUID (overrides JSON metadata)")
    parser.add_argument("--public-key", help="Reality Public Key (overrides JSON metadata)")
    parser.add_argument("--short-id", default=None, help="Reality Short ID (overrides JSON metadata; empty string '' is valid)")
    parser.add_argument("--sni", default=None, help="Server SNI (overrides JSON metadata; fallback: gateway.icloud.com)")
    parser.add_argument("--name", default="🇺🇸 独享-Claude-原生住宅9929", help="Node display name")
    parser.add_argument("--output", default="Claude-AntiBan-Profile.yaml", help="Output Clash YAML path")
    parser.add_argument(
        "--vless-output",
        default=None,
        help="Output path for 0600 mobile VLESS share link file (default: <output-stem>-mobile-vless.txt)",
    )
    parser.add_argument(
        "--print-vless",
        action="store_true",
        help="Also print raw VLESS URL to stdout (off by default to keep secrets out of logs/chat)",
    )

    args = parser.parse_args()

    data = {}
    json_source = args.json_file or args.json_input
    if json_source:
        expanded = os.path.expanduser(json_source)
        if os.path.exists(expanded):
            with open(expanded, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            if args.json_file:
                print(f"[ERROR] JSON metadata file not found: {expanded}", file=sys.stderr)
                sys.exit(1)
            print(
                "[SECURITY WARN] Passing raw credentials JSON via CLI argument exposes UUID to process lists and shell history. Prefer --json-file <0600-path>.",
                file=sys.stderr,
            )
            data = json.loads(json_source)

    # Explicit CLI overrides ALWAYS take precedence over JSON metadata;
    # prefer client-facing inbound_host / inbound_port for NAT VPS deployments.
    server_ip = args.inbound_host or args.ip or data.get("inbound_host") or data.get("server_ip")

    if args.inbound_port is not None:
        port = args.inbound_port
    elif args.port is not None:
        port = args.port
    elif data.get("inbound_port") is not None:
        port = data["inbound_port"]
    elif data.get("port") is not None:
        port = data["port"]
    elif data.get("listen_port") is not None:
        port = data["listen_port"]
    else:
        port = 24433

    uuid = args.uuid or data.get("uuid")
    public_key = args.public_key or data.get("public_key")
    sni = args.sni or data.get("sni") or "gateway.icloud.com"
    flow = data.get("flow") or "xtls-rprx-vision"
    fingerprint = data.get("fingerprint") or "chrome"
    node_name = args.name

    # Explicitly preserve valid empty string short_id == "" (CLI overrides JSON)
    if args.short_id is not None:
        short_id = str(args.short_id)
    elif "short_id" in data and data["short_id"] is not None:
        short_id = str(data["short_id"])
    else:
        short_id = None

    if not all([server_ip, port, uuid, public_key, sni]) or short_id is None:
        print(
            "[ERROR] Missing required connection parameters (server_ip, port, uuid, public_key, short_id, sni)!",
            file=sys.stderr,
        )
        sys.exit(1)

    if not is_valid_server_host(str(server_ip)):
        print(
            f"[ERROR] Invalid or placeholder server address: {server_ip!r}. Provide a valid IP address or hostname.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            raise ValueError("out of range")
    except (TypeError, ValueError):
        print(f"[ERROR] Invalid TCP port: {port!r} (must be 1..65535).", file=sys.stderr)
        sys.exit(1)
    port = port_int

    output_path = os.path.expanduser(args.output)
    if args.vless_output:
        vless_output_path = os.path.expanduser(args.vless_output)
    else:
        stem, _ = os.path.splitext(output_path)
        vless_output_path = f"{stem}-mobile-vless.txt"

    node_dict = {
        "server_ip_yaml": json.dumps(str(server_ip), ensure_ascii=False),
        "port": int(port),
        "uuid_yaml": json.dumps(str(uuid), ensure_ascii=False),
        "flow_yaml": json.dumps(str(flow), ensure_ascii=False),
        "sni_yaml": json.dumps(str(sni), ensure_ascii=False),
        "public_key_yaml": json.dumps(str(public_key), ensure_ascii=False),
        "short_id_yaml": json.dumps(str(short_id), ensure_ascii=False),
        "fingerprint_yaml": json.dumps(str(fingerprint), ensure_ascii=False),
        "node_name_yaml": json.dumps(str(node_name), ensure_ascii=False),
    }

    yaml_content = TEMPLATE_YAML.format(**node_dict)

    try:
        write_file_0600(output_path, yaml_content)
        print(f"[SUCCESS] Generated Clash YAML Profile (0600): {os.path.abspath(output_path)}")
    except Exception as e:
        print(f"[ERROR] Failed to write Clash profile to {output_path}: {e}", file=sys.stderr)
        sys.exit(1)

    vless_url = generate_vless_url(
        {
            "server_ip": server_ip,
            "port": int(port),
            "uuid": uuid,
            "flow": flow,
            "sni": sni,
            "public_key": public_key,
            "short_id": short_id,
            "fingerprint": fingerprint,
            "node_name": node_name,
        }
    )

    try:
        write_file_0600(vless_output_path, vless_url + "\n")
        print(f"[SUCCESS] Saved mobile VLESS share link (0600): {os.path.abspath(vless_output_path)}")
        print("[SECURITY] Raw VLESS link was NOT printed to stdout to prevent leaking credentials into chat/logs.")
    except Exception as e:
        print(f"[ERROR] Failed to write VLESS share link to {vless_output_path}: {e}", file=sys.stderr)
        sys.exit(1)

    if args.print_vless:
        print(f"\n[VLESS Share Link]:\n{vless_url}\n")


if __name__ == "__main__":
    main()
