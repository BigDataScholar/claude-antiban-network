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
            data = json.loads(resp.read().decode())
            dns_info = data.get("dns", {})
            dns_ip = dns_info.get("ip", "")
            dns_geo = dns_info.get("geo", "")

            if "China" in dns_geo or dns_geo.startswith("CN"):
                print(f"[{RED}LEAK DETECTED{RESET}] DNS 解析发生泄露!")
                print(f"       解析服务器 : {dns_ip} ({dns_geo})")
                print(f"       {YELLOW}风险提示: 您的常规未分流域名正被国内运营商 DNS 解析。请确保已在 Clash 启用 Fake-IP 模式并检查 nameserver 规则。{RESET}")
                return False
            else:
                print(f"[{GREEN}PASS{RESET}] DNS 解析出口位于海外: {dns_ip} ({dns_geo})")
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
                print(f"[{RED}BLOCKED{RESET}] Gemini 区域检测: 失败 (Google GeoIP 标记为国家代码 'ZZ'，未解锁)")
                return False
            else:
                print(f"[{GREEN}PASS{RESET}] Google Gemini 区域检测: 成功 (未出现 ZZ 区域封锁)")
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
            print(f"[{YELLOW}WARN{RESET}] 本机检测到活跃的公网 IPv6 地址: {local_ipv6}")
            print(f"       建议: 如果客户端代理未开启 IPv6 代理或未禁用 IPv6，可能会导致流量绕过代理发生泄露。")
            return False
    except Exception:
        # IPv6 socket connect failed, meaning IPv6 is not actively leaking or not routed
        pass
    print(f"[{GREEN}PASS{RESET}] 本机 IPv6 泄露检查: 未发现直连绕行")
    return True

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

    print_header("验收检测结论总结")
    print(f"  - 出口 IP 归属: {'✓ 通过 (US)' if is_us else '✗ 失败'}")
    print(f"  - DNS 解析状态: {'✓ 正常 (无国内泄露)' if dns_clean is True else ('✗ 存在泄露' if dns_clean is False else '? 未能自动化复核')}")
    print(f"  - Anthropic API 网关: {'✓ 可直达' if api_reachable else '✗ 无法连接'}")
    print(f"  - Claude Web 状态: {web_status}")
    print(f"  - Gemini 区域解锁: {'✓ 未见 ZZ 封锁' if gemini_ok else '✗ 存在区域限制'}")
    print(f"  - 本机 IPv6 绕行检查: {'✓ 安全' if ipv6_safe else '⚠ 需注意 IPv6 泄露风险'}")

    print("\n[人工审计与日常防封指引 (Manual Audit Tips)]:")
    print("1. WebRTC 防护: 代理无法彻底关闭浏览器内部 WebRTC。请在 Chrome/Edge 中安装 'WebRTC Control' 插件并开启禁用。")
    print("2. 欺诈分复核: 建议在权威数据库 https://scamalytics.com 中输入你的出口 IP 进行人工复核（低于 25 分为安全）。")
    print("3. 稳定使用原则: 会话期间请勿频繁变动网络或切换节点。")
    print("=====================================================\n")

    overall_pass = is_us and api_reachable and gemini_ok and (dns_clean is not False)
    sys.exit(0 if overall_pass else 1)

if __name__ == "__main__":
    main()
