#!/usr/bin/env python3
"""
Automated Anti-Ban Environment Gate Check

Hardened verification design:
1. Immune to NO_PROXY / no_proxy environment variables via ForcedProxyHandler.
2. Verifies direct client-to-VPS TCP port reachability first, localizing failures
   between cloud security group / VPS firewall vs. local Clash client config.
3. Queries egress IP & geolocation strictly over HTTPS (no plaintext HTTP fallback)
   and matches observed egress IP against the deployed VPS egress IP, with separate
   --inbound-host and --expected-egress-ip flags for NAT VPS deployments.
4. Separately reports:
   - Automated Proxy Chain Hard Gates (VPS port, exact HTTPS egress IP match + US,
     Anthropic API, Gemini ZZ check, single-request proxy DNS probe, local IPv6,
     local Fake-IP)
   - Observed Browser Challenge Status (claude.ai HTTP 200 vs CF Turnstile Challenge vs 403 Block)
   - Manual Verification Items (account login usability, WebRTC, Scamalytics score)
"""

import argparse
import base64
import errno
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"

HTTPS_GEO_ENDPOINTS = (
    ("ipinfo.io", "https://ipinfo.io/json"),
    ("api.ip.sb", "https://api.ip.sb/geoip"),
)


class ForcedProxyHandler(urllib.request.ProxyHandler):
    """Enforces the explicit --proxy URL and completely ignores NO_PROXY / no_proxy."""

    def proxy_open(self, req, proxy, type):
        parsed = urllib.parse.urlparse(proxy)
        proxy_type = parsed.scheme or req.type
        hostport = parsed.netloc
        if not hostport:
            # Handle bare host:port without scheme
            hostport = parsed.path
            proxy_type = req.type
        if "@" in hostport:
            auth_part, hostport = hostport.rsplit("@", 1)
            user_pass = urllib.parse.unquote(auth_part)
            creds = base64.b64encode(user_pass.encode("utf-8")).decode("ascii")
            req.add_header("Proxy-authorization", f"Basic {creds}")
        hostport = urllib.parse.unquote(hostport)
        req.set_proxy(hostport, proxy_type)
        if req.type == proxy_type or req.type == "https":
            return None
        return self.parent.open(req, timeout=req.timeout)


def print_header(title):
    print(f"\n{BOLD}{BLUE}====================================================={RESET}")
    print(f"{BOLD}{BLUE} {title} {RESET}")
    print(f"{BOLD}{BLUE}====================================================={RESET}")


def build_opener(proxy_url):
    handler = ForcedProxyHandler({"http": proxy_url, "https": proxy_url})
    return urllib.request.build_opener(handler)


def check_vps_port_reachable(inbound_host, port, timeout=5):
    try:
        with socket.create_connection((inbound_host, int(port)), timeout=timeout):
            print(f"[{GREEN}PASS{RESET}] 客户端直连目标 VPS 入站端口可达: {inbound_host}:{port}/tcp")
            return True
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] 客户端直连目标 VPS 入站端口不可达: {inbound_host}:{port}/tcp ({e})")
        print(f"       {YELLOW}故障定位 -> 请检查：(1) 云厂商控制台安全组/防火墙是否放行 TCP {port}；(2) VPS 本机 ufw/iptables 与 xray 服务监听状态。{RESET}")
        return False


def _normalize_geo_payload(provider, data):
    """Normalize HTTPS GeoIP JSON from ipinfo.io or api.ip.sb."""
    if not isinstance(data, dict):
        return None
    ip = (data.get("ip") or data.get("query") or "").strip()
    if not ip:
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    if provider == "ipinfo.io":
        country_code = (data.get("country") or "").strip().upper()
        country = data.get("country_name") or country_code
        city = data.get("city") or ""
        region = data.get("region") or ""
        org = data.get("org") or ""
        isp = org
        as_name = org
    else:
        country_code = (data.get("country_code") or data.get("countryCode") or "").strip().upper()
        country = data.get("country") or country_code
        city = data.get("city") or ""
        region = data.get("region") or ""
        isp = data.get("isp") or data.get("organization") or ""
        asn = data.get("asn")
        as_org = data.get("asn_organization") or data.get("organization") or ""
        as_name = f"AS{asn} {as_org}".strip() if asn else as_org

    location = ", ".join(part for part in (city, region) if part)
    return {
        "provider": provider,
        "ip": ip,
        "country": country,
        "country_code": country_code,
        "location": location,
        "isp": isp,
        "as_name": as_name,
    }


def fetch_egress_geo_https(opener):
    """Query egress IP and GeoIP strictly over HTTPS with HTTPS fallback."""
    errors = []
    for provider, url in HTTPS_GEO_ENDPOINTS:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "curl/7.88.1", "Accept": "application/json"},
        )
        try:
            with opener.open(req, timeout=10) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                normalized = _normalize_geo_payload(provider, payload)
                if normalized and normalized["country_code"]:
                    return normalized
                errors.append(f"{provider}: incomplete JSON payload")
        except Exception as e:
            errors.append(f"{provider}: {e}")
    raise RuntimeError("; ".join(errors))


def test_ip_and_geo(opener, expected_egress_ip=None, allow_any_us=False):
    try:
        info = fetch_egress_geo_https(opener)
        ip = info["ip"]
        country = info["country"]
        country_code = info["country_code"]
        location = info["location"]
        isp = info["isp"]
        as_name = info["as_name"]
        provider = info["provider"]

        is_us = country_code == "US"
        ip_matches = True if allow_any_us else (bool(expected_egress_ip) and ip == expected_egress_ip)

        if is_us and ip_matches:
            tag = f"{GREEN}PASS (US{' · 目标VPS精确匹配' if expected_egress_ip else ''}){RESET}"
        elif is_us and not expected_egress_ip and not allow_any_us:
            tag = f"{RED}FAIL (未指定目标VPS出口IP){RESET}"
        elif is_us and expected_egress_ip and ip != expected_egress_ip:
            tag = f"{RED}FAIL (出口IP不匹配){RESET}"
        else:
            tag = f"{RED}FAIL ({country_code}){RESET}"

        print(f"[{tag}] 实际出口 IP (HTTPS · {provider}): {ip}")
        print(f"       物理位置 : {country} ({country_code}){f', {location}' if location else ''}")
        print(f"       ISP / 归属: {isp or 'N/A'}{f' / {as_name}' if as_name and as_name != isp else ''}")

        if expected_egress_ip and ip != expected_egress_ip:
            print(f"       {RED}故障定位 -> 预期出口为本次部署的 VPS ({expected_egress_ip})，但实际走了无关出口 ({ip})！请检查 Clash 当前选中的节点与策略组（若是 NAT VPS 入口与出口 IP 不同，请分别传入 --inbound-host 与 --expected-egress-ip）。{RESET}")
        elif not expected_egress_ip and not allow_any_us:
            print(f"       {YELLOW}提示 -> 请传入 --node-json <0600文件> 或 --expected-egress-ip <VPS出口IP> 以确认流量经过本次部署的 VPS（仅显式指定 --allow-any-us 时才跳过比对）。{RESET}")

        return is_us, ip_matches, ip
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] 经本地代理通过 HTTPS 获取出口 IP 失败: {e}")
        print(f"       {YELLOW}故障定位 -> 若上方 VPS 端口可达但此处失败，说明问题在本地 Clash 节点凭证（UUID/PublicKey/ShortId/SNI）、代理端口或规则配置。{RESET}")
        return False, False, None


def test_dns_leak(opener):
    try:
        req = urllib.request.Request("https://edns.ip-api.com/json", headers={"User-Agent": "curl/7.88.1"})
        with opener.open(req, timeout=10) as resp:
            raw_body = resp.read().decode()
            try:
                data = json.loads(raw_body)
            except Exception:
                print(f"[{YELLOW}UNVERIFIED{RESET}] 单次代理 DNS 探针响应非标准 JSON 格式。")
                return None

            if not isinstance(data, dict) or not isinstance(data.get("dns"), dict):
                print(f"[{YELLOW}UNVERIFIED{RESET}] 单次代理 DNS 探针缺少有效的 dns 字段。")
                return None

            raw_ip = data["dns"].get("ip")
            raw_geo = data["dns"].get("geo")
            if not isinstance(raw_ip, str) or not isinstance(raw_geo, str):
                print(f"[{YELLOW}UNVERIFIED{RESET}] 单次代理 DNS 探针数据类型异常。")
                return None

            dns_ip = raw_ip.strip()
            dns_geo = raw_geo.strip()
            if not dns_ip or not dns_geo or dns_geo.lower() in ("unknown", "undefined", "none"):
                print(f"[{YELLOW}UNVERIFIED{RESET}] 单次代理 DNS 探针地理归属无效 ({dns_geo})。")
                return None

            try:
                ipaddress.ip_address(dns_ip)
            except ValueError:
                print(f"[{YELLOW}UNVERIFIED{RESET}] 单次代理 DNS 探针 IP 格式无效 ({dns_ip})。")
                return None

            if "China" in dns_geo or dns_geo.startswith("CN"):
                print(f"[{RED}LEAK DETECTED{RESET}] 单次代理 DNS 探针检出国内解析服务器: {dns_ip} ({dns_geo})")
                print(f"       {YELLOW}风险提示: 未分流域名正被国内运营商 DNS 解析。请使用本工具生成的配置（含 GEOSITE,geolocation-!cn 与 GEOIP,CN,DIRECT,no-resolve），并关闭 Clash Verge 对该配置的冲突 DNS 覆写。{RESET}")
                return False
            else:
                print(f"[{GREEN}PASS{RESET}] 单次代理 DNS 探针上游解析器位于海外: {dns_ip} ({dns_geo})")
                print("       范围说明: 本探针仅验证本次代理请求的解析路径，不代表系统全局或浏览器 WebRTC 完全无泄露。")
                return True
    except Exception as e:
        print(f"[{YELLOW}UNVERIFIED{RESET}] 单次代理 DNS 探针请求失败 ({e})，请在 https://ip.net.coffee/claude 复核。")
        return None


def test_anthropic_and_claude(opener):
    # 1. Test Anthropic API Edge
    api_reachable = False
    req_api = urllib.request.Request("https://api.anthropic.com", headers={"User-Agent": "curl/7.88.1"})
    try:
        with opener.open(req_api, timeout=10) as resp:
            api_reachable = True
            print(f"[{GREEN}PASS{RESET}] Anthropic API 网关: 连接成功 (HTTP {resp.getcode()})")
    except urllib.error.HTTPError as e:
        cf_ray = e.headers.get("cf-ray", "")
        if e.code == 404:
            api_reachable = True
            print(f"[{GREEN}PASS{RESET}] Anthropic API 网关: 直连成功 (Origin 404, cf-ray: {cf_ray or 'US'})")
        elif e.code == 403:
            print(f"[{RED}BLOCKED{RESET}] Anthropic API 网关返回 HTTP 403 (IP 可能被 Cloudflare 或 Anthropic 封禁)")
        else:
            print(f"[{YELLOW}WARN{RESET}] Anthropic API 网关返回异常 HTTP {e.code} (cf-ray: {cf_ray})")
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Anthropic API 网关连接异常: {e}")

    # 2. Observe Claude Web Front (strictly distinguish 200 vs CF Turnstile Challenge vs 403 Block)
    web_status = "UNKNOWN"
    req_web = urllib.request.Request(
        "https://claude.ai",
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with opener.open(req_web, timeout=10) as resp:
            code = resp.getcode()
            if code in (200, 301, 302, 307):
                web_status = "DIRECT_200"
                print(f"[{GREEN}PASS{RESET}] Claude Web 网页端: 直达响应 (HTTP {code})")
    except urllib.error.HTTPError as e:
        cf_mitigated = e.headers.get("cf-mitigated", "")
        cf_ray = e.headers.get("cf-ray", "")
        if "challenge" in cf_mitigated:
            web_status = "CF_CHALLENGE"
            print(f"[{YELLOW}CHALLENGE{RESET}] Claude Web 网页端: 返回 Cloudflare 浏览器人机盾 (HTTP 403, cf-mitigated: challenge, cf-ray: {cf_ray})")
            print("       说明: 非 IP 封锁，但脚本无法代替浏览器完成 Turnstile 校验；需在真实浏览器打开 claude.ai 确认。")
        elif e.code == 403:
            web_status = "BLOCKED_403"
            print(f"[{RED}BLOCKED{RESET}] Claude Web 网页端: 被硬拦截 (HTTP 403 无 challenge，IP 可能受限)")
        else:
            web_status = f"HTTP_{e.code}"
            print(f"[{YELLOW}WARN{RESET}] Claude Web 网页端返回异常状态: HTTP {e.code}")
    except Exception as e:
        web_status = "ERROR"
        print(f"[{RED}FAIL{RESET}] Claude Web 网页端连接异常: {e}")

    return api_reachable, web_status


def test_gemini(opener):
    req = urllib.request.Request(
        "https://gemini.google.com",
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        },
    )
    try:
        with opener.open(req, timeout=12) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            if '["ZZ"]' in content or "not supported in your country" in content.lower():
                print(f"[{RED}BLOCKED{RESET}] Google Gemini 区域检测: 失败 (检测到 ZZ 地区封锁标识)")
                return False
            print(f"[{GREEN}PASS{RESET}] Google Gemini 网关可达 (未见 ZZ 封锁；登录与交互权限需在真实浏览器确认)")
            return True
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Google Gemini 连接异常: {e}")
        return False


def check_local_ipv6_leak():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("2001:4860:4860::8888", 80))
        local_ipv6 = s.getsockname()[0]
        s.close()
        if not local_ipv6.startswith("fe80:") and not local_ipv6.startswith("::1"):
            print(f"[{RED}LEAK RISK{RESET}] 本机检测到活跃的公网 IPv6 地址/路由: {local_ipv6}")
            print(f"       {YELLOW}修复 (macOS): 系统设置 -> 网络 -> Wi-Fi -> 详细信息 -> TCP/IP -> 配置 IPv6 改为「仅本地链接」{RESET}")
            print(f"       {YELLOW}修复 (Windows): 网络适配器属性 -> 取消勾选 Internet 协议版本 6 (TCP/IPv6){RESET}")
            return False
        print(f"[{GREEN}PASS{RESET}] 本机仅有链路本地 IPv6（无公网 IPv6 绕行风险）")
        return True
    except OSError as e:
        if e.errno in (errno.ENETUNREACH, errno.EADDRNOTAVAIL, errno.EHOSTUNREACH):
            print(f"[{GREEN}PASS{RESET}] 本机无公网 IPv6 路由（无 IPv6 绕行风险）")
            return True
        print(f"[{YELLOW}UNVERIFIED{RESET}] 本机 IPv6 检查异常 (errno={e.errno}: {e})")
        return None
    except Exception as e:
        print(f"[{YELLOW}UNVERIFIED{RESET}] 本机 IPv6 检查异常 ({e})")
        return None


def check_local_fake_ip():
    try:
        resolved = socket.gethostbyname("claude.ai")
        addr = ipaddress.ip_address(resolved)
        fake_net = ipaddress.ip_network("198.18.0.0/15")
        if addr in fake_net:
            print(f"[{GREEN}PASS{RESET}] 本机系统 DNS 已由 Clash Fake-IP 接管 (claude.ai -> {resolved})")
            return True
        print(f"[{RED}FAIL{RESET}] 本机系统 DNS 未命中 Clash Fake-IP (claude.ai -> {resolved})")
        print(f"       {YELLOW}故障定位 -> TUN 模式可能未生效，或切换 Wi-Fi 后被路由器 DNS 覆盖。请在 Clash Verge 同时开启「系统代理 + TUN 模式」或关开一次 TUN 开关（若刻意仅用系统代理而不开 TUN，请传 --proxy-only）。{RESET}")
        return False
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] 本机 Fake-IP 检测异常 ({e})")
        return False


def main():
    parser = argparse.ArgumentParser(description="Verify Claude Anti-Ban Network Environment")
    parser.add_argument("--proxy", default="http://127.0.0.1:7897", help="Local proxy URL (default: http://127.0.0.1:7897)")
    parser.add_argument("--node-json", help="Path to restricted (0600) node metadata JSON from vps_setup.sh (recommended)")
    parser.add_argument("--expected-ip", help="Shorthand for both inbound host and expected egress IP (dedicated VPS)")
    parser.add_argument("--inbound-host", help="Inbound VPS host/IP for direct TCP port check (useful for NAT VPS)")
    parser.add_argument("--inbound-port", type=int, default=None, help="External client-facing TCP port (useful for NAT VPS)")
    parser.add_argument("--expected-egress-ip", help="Expected outbound egress IPv4 address (useful for NAT VPS)")
    parser.add_argument("--expected-port", type=int, default=None, help="Expected VPS TCP inbound port for direct reachability check")
    parser.add_argument("--allow-any-us", action="store_true", help="Allow any US egress IP without verifying exact VPS match")
    parser.add_argument("--proxy-only", action="store_true", help="Skip hard requirement for TUN Fake-IP takeover (system-proxy-only mode)")
    parser.add_argument("--strict-web", action="store_true", help="Fail gate if claude.ai returns Cloudflare Turnstile Challenge (CF_CHALLENGE)")
    args = parser.parse_args()

    node_meta = {}
    if args.node_json:
        node_path = os.path.expanduser(args.node_json)
        if not os.path.exists(node_path):
            print(f"[{RED}ERROR{RESET}] --node-json file not found: {node_path}", file=sys.stderr)
            sys.exit(1)
        with open(node_path, "r", encoding="utf-8") as f:
            node_meta = json.load(f)

    inbound_host = args.inbound_host or args.expected_ip or node_meta.get("inbound_host") or node_meta.get("server_ip")
    expected_egress_ip = args.expected_egress_ip or args.expected_ip or node_meta.get("egress_ip") or node_meta.get("server_ip")
    if args.inbound_port is not None:
        expected_port = args.inbound_port
    elif args.expected_port is not None:
        expected_port = args.expected_port
    elif node_meta.get("inbound_port") is not None:
        expected_port = node_meta["inbound_port"]
    elif node_meta.get("port") is not None:
        expected_port = node_meta["port"]
    else:
        expected_port = node_meta.get("listen_port")

    print_header("Claude & AI Anti-Ban Network Environment Gate Check")
    print(f"代理入口 : {args.proxy} (强制走代理，已免疫 NO_PROXY/no_proxy)")
    if inbound_host:
        print(f"入站目标 : {inbound_host}{f':{expected_port}' if expected_port else ''}")
    if expected_egress_ip:
        print(f"预期出口 : {expected_egress_ip}{' (NAT 独立出口)' if inbound_host and expected_egress_ip != inbound_host else ''}")

    # 0. Direct client-to-VPS TCP port check (localizes firewall/SG issues before proxy)
    port_ok = None
    if inbound_host and expected_port:
        port_ok = check_vps_port_reachable(inbound_host, expected_port)

    opener = build_opener(args.proxy)

    # 1. Exact HTTPS Egress IP & Geo
    is_us, ip_matches, observed_ip = test_ip_and_geo(
        opener, expected_egress_ip=expected_egress_ip, allow_any_us=args.allow_any_us
    )

    # 2. Single-Request Proxy DNS Probe
    dns_clean = test_dns_leak(opener)

    # 3. Anthropic API & Claude Web
    api_reachable, web_status = test_anthropic_and_claude(opener)

    # 4. Gemini
    gemini_ok = test_gemini(opener)

    # 5. Local IPv6
    ipv6_safe = check_local_ipv6_leak()

    # 6. Local Fake-IP (Hard gate by default; advisory only if --proxy-only)
    fake_ip_ok = check_local_fake_ip()

    print_header("验收结果分类报告")
    print(f"{BOLD}[A] 自动化网络链路门禁 (Hard Gates):{RESET}")
    gate_checks = []
    if inbound_host and expected_port:
        gate_checks.append(("目标 VPS 入站 TCP 端口可达", port_ok is True, f"{inbound_host}:{expected_port} 不可达（请检查云安全组/VPS防火墙）"))
    if args.allow_any_us:
        gate_checks.append(("HTTPS 出口 IP 归属美国 (US)", is_us is True, "出口 IP 非美国或未能识别"))
    else:
        gate_checks.append((
            "HTTPS 出口 IP 精确匹配目标 VPS 且为 US",
            is_us is True and ip_matches is True,
            f"未匹配目标出口 ({expected_egress_ip or '未指定'})，实际出口: {observed_ip or '无'}",
        ))
    gate_checks.append(("Anthropic API 网关直达", api_reachable is True, "api.anthropic.com 连接失败或被 403 拦截"))
    if args.strict_web:
        gate_checks.append(("Claude Web 网页端无盾直达 (--strict-web)", web_status == "DIRECT_200", f"当前状态: {web_status}"))
    else:
        gate_checks.append(("Claude Web 未被硬封禁 (非纯 403/断连)", web_status in ("DIRECT_200", "CF_CHALLENGE"), f"当前状态: {web_status}"))
    gate_checks.append(("Google Gemini 网关可达 (无 ZZ 封锁)", gemini_ok is True, "检测到 ZZ 区域封锁或连接失败"))
    gate_checks.append(("单次代理 DNS 探针位于海外", dns_clean is True, "检出国内解析器或未完成验证"))
    gate_checks.append(("本机无活跃公网 IPv6 绕行", ipv6_safe is True, "检测到活跃公网 IPv6 路由，请改为「仅本地链接」"))
    if not args.proxy_only:
        gate_checks.append(("本机系统 DNS 已由 Clash Fake-IP 接管", fake_ip_ok is True, "claude.ai 未解析至 198.18.0.0/15（请检查 TUN 开关）"))

    all_passed = True
    for name, passed, fail_reason in gate_checks:
        if passed:
            print(f"  [{GREEN}PASS{RESET}] {name}")
        else:
            all_passed = False
            print(f"  [{RED}FAIL{RESET}] {name} -> {fail_reason}")

    print(f"\n{BOLD}[B] 浏览器人机挑战与账号可用性（脚本无法替代，需人工确认）:{RESET}")
    if web_status == "DIRECT_200":
        print(f"  - Claude Web 观测状态: {GREEN}DIRECT_200（无盾直达）{RESET}")
    elif web_status == "CF_CHALLENGE":
        print(f"  - Claude Web 观测状态: {YELLOW}CF_CHALLENGE（存在 Cloudflare Turnstile 浏览器挑战，请在 Chrome 打开 claude.ai 验证通过）{RESET}")
    else:
        print(f"  - Claude Web 观测状态: {RED}{web_status}{RESET}")
    print("  - Claude / Gemini 账号登录与对话可用性: 需在真实浏览器中登录账号实测。")
    print("  - 浏览器 WebRTC 防护: Chrome/Edge 安装 'WebRTC Control' 插件并点亮蓝色图标。")
    print("  - IP 欺诈分与全局漏泄复核: 在 https://ip.net.coffee/claude 与 https://scamalytics.com 人工复核。")
    print("=====================================================\n")

    if not all_passed:
        print(f"{BOLD}{RED}[GATE: FAIL] 自动化门禁未全部通过，请按上方故障定位逐项修复后重测！{RESET}\n")
        sys.exit(1)

    if web_status == "CF_CHALLENGE":
        print(f"{BOLD}{YELLOW}[GATE: PASS_PROXY_CHAIN] 代理链路与目标 VPS 门禁全部通过；请再于真实浏览器完成 claude.ai 人机验证与账号实测。{RESET}\n")
        sys.exit(0)

    print(f"{BOLD}{GREEN}[GATE: PASS] 全部自动化网络门禁均已通过！{RESET}\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
