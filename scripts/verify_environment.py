#!/usr/bin/env python3
"""
Automated Anti-Ban Environment Gate Check
Tests:
1. Proxy reachability and Egress IP / GeoIP
2. Real DNS resolver leak test (probes upstream DNS resolver country)
3. Anthropic & Claude Gateway accessibility & challenge detection
4. Gemini (Google) accessibility & regional policy test
5. Local IPv6 bypass detection and WebRTC manual audit prompts
"""

import argparse
import errno
import ipaddress
import json
import socket
import sys
import urllib.request
import urllib.error

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_header(title):
    print(f"\n{BOLD}{BLUE}====================================================={RESET}")
    print(f"{BOLD}{BLUE} {title} {RESET}")
    print(f"{BOLD}{BLUE}====================================================={RESET}")

def test_ip_and_geo(proxy_handler):
    opener = urllib.request.build_opener(proxy_handler)
    req = urllib.request.Request("http://ip-api.com/json", headers={"User-Agent": "curl/7.88.1"})
    try:
        with opener.open(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            ip = data.get("query")
            country = data.get("country")
            country_code = data.get("countryCode")
            isp = data.get("isp")
            as_name = data.get("as")
            
            is_us = country_code == "US"
            status_color = GREEN if is_us else RED
            status_text = "PASS (US)" if is_us else f"FAIL ({country_code})"
            
            print(f"[{status_color}{status_text}{RESET}] 出口 IP: {ip}")
            print(f"       物理位置 : {country} ({country_code}), {data.get('city', '')}")
            print(f"       ISP / 归属: {isp} / {as_name}")
            return is_us, ip
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] 无法获取出口 IP 归属信息: {e}")
        return False, None

def test_dns_leak(proxy_handler):
    opener = urllib.request.build_opener(proxy_handler)
    # Query edns.ip-api.com which reflects the DNS resolver IP seen by authoritative servers
    try:
        req = urllib.request.Request("https://edns.ip-api.com/json", headers={"User-Agent": "curl/7.88.1"})
        with opener.open(req, timeout=10) as resp:
            raw_body = resp.read().decode()
            try:
                data = json.loads(raw_body)
            except Exception:
                print(f"[{YELLOW}UNVERIFIED{RESET}] DNS 探针响应非标准 JSON 格式，未能验证解析服务器。")
                return None

            if not isinstance(data, dict):
                print(f"[{YELLOW}UNVERIFIED{RESET}] DNS 探针响应结构异常，未能验证解析服务器。")
                return None

            dns_info = data.get("dns")
            if not isinstance(dns_info, dict):
                print(f"[{YELLOW}UNVERIFIED{RESET}] DNS 探针未包含有效的 dns 字段对象，标记为未验证。")
                print(f"       注意: 本探针仅测试经由代理通道的解析服务器，不代表操作系统全局或浏览器 WebRTC 完全无泄露。")
                return None

            raw_ip = dns_info.get("ip")
            raw_geo = dns_info.get("geo")
            if not isinstance(raw_ip, str) or not isinstance(raw_geo, str):
                print(f"[{YELLOW}UNVERIFIED{RESET}] DNS 探针返回的数据类型异常，无法判定。")
                return None

            dns_ip = raw_ip.strip()
            dns_geo = raw_geo.strip()

            if not dns_ip or not dns_geo:
                print(f"[{YELLOW}UNVERIFIED{RESET}] DNS 探针返回的 IP 或地理字段为空，无法判定。")
                return None

            try:
                ipaddress.ip_address(dns_ip)
            except ValueError:
                print(f"[{YELLOW}UNVERIFIED{RESET}] DNS 探针返回的 IP 格式无效 ({dns_ip})，无法判定。")
                return None

            if dns_geo.lower() in ["unknown", "undefined", "none"]:
                print(f"[{YELLOW}UNVERIFIED{RESET}] DNS 探针返回未知的地理归属 ({dns_geo})，无法判定。")
                return None

            if "China" in dns_geo or dns_geo.startswith("CN"):
                print(f"[{RED}LEAK DETECTED{RESET}] DNS 解析发生泄露!")
                print(f"       解析服务器 : {dns_ip} ({dns_geo})")
                print(f"       {YELLOW}风险提示: 您的常规未分流域名正被国内运营商 DNS 解析。请确保已在 Clash 启用 Fake-IP 模式并检查 nameserver 规则。{RESET}")
                return False
            else:
                print(f"[{GREEN}PASS{RESET}] 经代理路径解析的 DNS 出口位于海外: {dns_ip} ({dns_geo})")
                print(f"       说明: 本项仅验证代理通道上游解析器为海外服务器，不替代系统级 WebRTC/Fake-IP 配置审计。")
                return True
    except Exception as e:
        print(f"[{YELLOW}UNVERIFIED{RESET}] 自动 DNS 泄露探针未能完成 ({e})，标记为未验证。建议人工在 https://ip.net.coffee/claude 中复核。")
        return None

def test_anthropic_and_claude(proxy_handler):
    opener = urllib.request.build_opener(proxy_handler)
    
    # 1. Test Anthropic API Edge
    api_reachable = False
    req_api = urllib.request.Request(
        "https://api.anthropic.com",
        headers={"User-Agent": "curl/7.88.1"}
    )
    try:
        with opener.open(req_api, timeout=10) as resp:
            api_reachable = True
            print(f"[{GREEN}PASS{RESET}] Anthropic API 网关: 连接成功 (HTTP {resp.getcode()})")
    except urllib.error.HTTPError as e:
        cf_ray = e.headers.get("cf-ray", "")
        if e.code == 404:
            # 404 is the expected response from Anthropic API origin root
            api_reachable = True
            print(f"[{GREEN}PASS{RESET}] Anthropic API 网关: 直连成功 (Origin 404, cf-ray: {cf_ray or 'US'})")
        elif e.code == 403:
            print(f"[{RED}BLOCKED{RESET}] Anthropic API 网关返回 HTTP 403 (IP 可能被 Cloudflare 或 Anthropic 封禁)")
        else:
            print(f"[{YELLOW}WARN{RESET}] Anthropic API 网关返回 HTTP {e.code} (cf-ray: {cf_ray})")
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Anthropic API 网关连接异常: {e}")

    # 2. Test Claude Web Front
    web_status = "UNKNOWN"
    req_web = urllib.request.Request(
        "https://claude.ai",
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
    )
    try:
        with opener.open(req_web, timeout=10) as resp:
            code = resp.getcode()
            if code in [200, 301, 302, 307]:
                web_status = "PASS"
                print(f"[{GREEN}PASS{RESET}] Claude Web 网页端: 直达无阻 (HTTP {code})")
    except urllib.error.HTTPError as e:
        cf_mitigated = e.headers.get("cf-mitigated", "")
        cf_ray = e.headers.get("cf-ray", "")
        if "challenge" in cf_mitigated:
            web_status = "CHALLENGE"
            print(f"[{YELLOW}CHALLENGE{RESET}] Claude Web 网页端: 触发 Cloudflare 盾 (HTTP 403, cf-mitigated: challenge, cf-ray: {cf_ray})")
            print(f"       说明: 这是针对脚本/非浏览器的正常人机验证。真实浏览器访问时由 Turnstile 验证通过。")
        elif e.code == 403:
            web_status = "BLOCKED"
            print(f"[{RED}BLOCKED{RESET}] Claude Web 网页端: 被拦截 (HTTP 403, 可能是 IP 封锁或受限)")
        else:
            print(f"[{YELLOW}WARN{RESET}] Claude Web 网页端返回异常状态: HTTP {e.code}")
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Claude Web 网页端连接异常: {e}")

    return api_reachable, web_status

def test_gemini(proxy_handler):
    opener = urllib.request.build_opener(proxy_handler)
    req = urllib.request.Request(
        "https://gemini.google.com",
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
    )
    try:
        with opener.open(req, timeout=12) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            if '["ZZ"]' in content or "not supported in your country" in content.lower():
                print(f"[{RED}BLOCKED{RESET}] Gemini 区域检测: 失败 (检测到区域封锁标识或 ZZ 代码)")
                return False
            else:
                print(f"[{GREEN}PASS{RESET}] Google Gemini 网关可达 (未出现 ZZ 封锁标识；注: 实际模型交互与登录权限需在浏览器中验证)")
                return True
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Gemini 连接异常: {e}")
        return False

def check_local_ipv6_leak():
    # Test if local machine has a functional public IPv6 route that might bypass IPv4 proxies
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(2)
        # Google Public DNS IPv6
        s.connect(("2001:4860:4860::8888", 80))
        local_ipv6 = s.getsockname()[0]
        s.close()
        if not local_ipv6.startswith("fe80:") and not local_ipv6.startswith("::1"):
            print(f"[{RED}LEAK RISK{RESET}] 本机检测到活跃的公网 IPv6 地址/路由: {local_ipv6}")
            print(f"       风险提示: 若客户端代理未开启 IPv6 代理或系统未禁用 IPv6，双栈应用可能绕过代理直连国内 IPv6 发生泄露。")
            return False
        print(f"[{GREEN}PASS{RESET}] 本机仅有链路本地 IPv6（未发现公网直连绕行风险）")
        return True
    except OSError as e:
        if e.errno in (errno.ENETUNREACH, errno.EADDRNOTAVAIL, errno.EHOSTUNREACH):
            print(f"[{GREEN}PASS{RESET}] 本机无公网 IPv6 路由（未发现 IPv6 绕过代理风险）")
            return True
        print(f"[{YELLOW}UNVERIFIED{RESET}] 本机 IPv6 检查异常 (errno={e.errno}: {e})，无法确认 IPv6 路由状态。")
        return None
    except Exception as e:
        print(f"[{YELLOW}UNVERIFIED{RESET}] 本机 IPv6 检查异常 ({e})，无法确认 IPv6 路由状态。")
        return None

def main():
    parser = argparse.ArgumentParser(description="Verify Claude Anti-Ban Network Environment")
    parser.add_argument("--proxy", default="http://127.0.0.1:7897", help="Local proxy URL (default: http://127.0.0.1:7897 or http://127.0.0.1:7890)")
    args = parser.parse_args()

    print_header("Claude & AI Anti-Ban Network Environment Gate Check")
    print(f"正在通过代理检测: {args.proxy}")

    proxy_handler = urllib.request.ProxyHandler({
        "http": args.proxy,
        "https": args.proxy
    })

    # 1. IP & Geo
    is_us, ip = test_ip_and_geo(proxy_handler)

    # 2. DNS Leak
    dns_clean = test_dns_leak(proxy_handler)

    # 3. Claude & Anthropic
    api_reachable, web_status = test_anthropic_and_claude(proxy_handler)

    # 4. Gemini
    gemini_ok = test_gemini(proxy_handler)

    # 5. Local IPv6
    ipv6_safe = check_local_ipv6_leak()

    print_header("验收门禁综合判定")
    gate_checks = [
        ("出口 IP 归属 (US 纯净独享)", is_us is True, "出口 IP 非美国或未能识别"),
        ("Anthropic API 网关直达", api_reachable is True, "Anthropic API 边缘网关连接失败"),
        ("Claude Web 网页端直达", web_status == "PASS", f"Claude Web 网页端未达直达状态 (当前状态: {web_status})"),
        ("Google Gemini 区域可达", gemini_ok is True, "Google Gemini 提示区域限制或 ZZ 代码"),
        ("代理上游 DNS 解析无泄露", dns_clean is True, "DNS 解析未完成验证或检测到国内运营商泄露"),
        ("本机 IPv6 隔离安全", ipv6_safe is True, "检测到活跃公网 IPv6 路由或未能确认 IPv6 隔离")
    ]

    all_passed = True
    for name, passed, fail_reason in gate_checks:
        if passed:
            print(f"  [{GREEN}PASS{RESET}] {name}")
        else:
            all_passed = False
            print(f"  [{RED}FAIL{RESET}] {name} -> {fail_reason}")

    print("\n[人工审计与日常防封指引 (Manual Audit Tips)]:")
    print("1. WebRTC 防护: 本探针仅测试代理路径。请在 Chrome/Edge 中安装 'WebRTC Control' 插件并开启禁用，防止浏览器 WebRTC 暴露本地 IP。")
    print("2. 欺诈分复核: 建议在权威数据库 https://scamalytics.com 中输入你的出口 IP 进行人工复核（低于 25 分为安全）。")
    print("3. 稳定使用原则: 会话期间请勿频繁变动网络或切换节点。")
    print("=====================================================\n")

    if all_passed:
        print(f"{BOLD}{GREEN}[GATE: PASS] 全部 6 项网络隔离与连通性门禁检测均已通过！{RESET}\n")
        sys.exit(0)
    else:
        print(f"{BOLD}{RED}[GATE: FAIL] 门禁检测未全部达标，拒绝盲目验收通过！{RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
