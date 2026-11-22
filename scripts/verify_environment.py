#!/usr/bin/env python3
"""
Automated Anti-Ban Environment Gate Check
Tests:
1. Proxy reachability and Egress IP / GeoIP (US check)
2. Real DNS resolver leak test (probes upstream DNS resolver country)
3. Anthropic API & Claude Web gateway accessibility & challenge/block detection
4. Gemini (Google) accessibility & regional ZZ block test
5. Local public IPv6 bypass detection (with macOS/Windows remediation hint)
6. Local Fake-IP DNS takeover diagnostic (detects Wi-Fi switch DNS poisoning)
"""

import argparse
import errno
import ipaddress
import json
import socket
import sys
import urllib.error
import urllib.request

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
                print(f"       {YELLOW}风险提示: 未分流域名正被国内运营商 DNS 解析。请确保使用本工具生成的配置（含 GEOSITE,geolocation-!cn 与 GEOIP,CN,DIRECT,no-resolve），并关闭 Clash Verge 对该配置的冲突 DNS 覆写。{RESET}")
                return False
            else:
                print(f"[{GREEN}PASS{RESET}] 经代理路径解析的 DNS 出口位于海外: {dns_ip} ({dns_geo})")
                return True
    except Exception as e:
        print(f"[{YELLOW}UNVERIFIED{RESET}] 自动 DNS 泄露探针未能完成 ({e})，建议在 https://ip.net.coffee/claude 中复核。")
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
            print(f"[{GREEN}PASS (CF Challenge){RESET}] Claude Web 网页端: 未封禁 IP，仅对脚本返回常规 Cloudflare Turnstile 盾 (cf-ray: {cf_ray})")
            print(f"       说明: 真实浏览器访问时可正常通过人机验证。")
        elif e.code == 403:
            web_status = "BLOCKED"
            print(f"[{RED}BLOCKED{RESET}] Claude Web 网页端: 被直接拦截 (HTTP 403 无 challenge，IP 可能已被封锁)")
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
                print(f"[{GREEN}PASS{RESET}] Google Gemini 网关可达 (未出现 ZZ 封锁标识)")
                return True
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Gemini 连接异常: {e}")
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
            print(f"       {YELLOW}修复方法 (macOS): 系统设置 -> 网络 -> Wi-Fi -> 详细信息 -> TCP/IP -> 配置 IPv6 改为「仅本地链接」{RESET}")
            print(f"       {YELLOW}修复方法 (Windows): 网络适配器属性 -> 取消勾选 Internet 协议版本 6 (TCP/IPv6){RESET}")
            return False
        print(f"[{GREEN}PASS{RESET}] 本机仅有链路本地 IPv6（无公网 IPv6 绕行风险）")
        return True
    except OSError as e:
        if e.errno in (errno.ENETUNREACH, errno.EADDRNOTAVAIL, errno.EHOSTUNREACH):
            print(f"[{GREEN}PASS{RESET}] 本机无公网 IPv6 路由（无 IPv6 绕过代理风险）")
            return True
        print(f"[{YELLOW}UNVERIFIED{RESET}] 本机 IPv6 检查异常 (errno={e.errno}: {e})，无法确认 IPv6 路由状态。")
        return None
    except Exception as e:
        print(f"[{YELLOW}UNVERIFIED{RESET}] 本机 IPv6 检查异常 ({e})，无法确认 IPv6 路由状态。")
        return None


def check_local_fake_ip():
    try:
        resolved = socket.gethostbyname("claude.ai")
        addr = ipaddress.ip_address(resolved)
        fake_net = ipaddress.ip_network("198.18.0.0/15")
        if addr in fake_net:
            print(f"[{GREEN}PASS{RESET}] 本机系统 DNS 已由 Clash Fake-IP 接管 (claude.ai -> {resolved})")
            return True
        else:
            print(f"[{YELLOW}WARN{RESET}] 本机系统 DNS 未返回 Fake-IP (claude.ai -> {resolved})")
            print(f"       提示: 若刚切换过 Wi-Fi，请在 Clash Verge 中「关开一次 TUN 模式」并同时开启「系统代理」以防路由器 DNS 投毒。")
            return False
    except Exception as e:
        print(f"[{YELLOW}WARN{RESET}] 本机 Fake-IP 检测异常 ({e})")
        return False


def main():
    parser = argparse.ArgumentParser(description="Verify Claude Anti-Ban Network Environment")
    parser.add_argument("--proxy", default="http://127.0.0.1:7897", help="Local proxy URL (default: http://127.0.0.1:7897)")
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

    # 6. Local Fake-IP (Advisory diagnostic)
    fake_ip_ok = check_local_fake_ip()

    print_header("验收门禁综合判定")
    web_ok = web_status in ("PASS", "CHALLENGE")
    gate_checks = [
        ("出口 IP 归属 (US 纯净独享)", is_us is True, "出口 IP 非美国或未能识别"),
        ("Anthropic API 网关直达", api_reachable is True, "Anthropic API 边缘网关连接失败"),
        ("Claude Web 网页端未被封禁", web_ok, f"Claude Web 网页端异常或被拦截 (当前状态: {web_status})"),
        ("Google Gemini 区域可达", gemini_ok is True, "Google Gemini 提示区域限制或 ZZ 代码"),
        ("代理上游 DNS 解析无泄露", dns_clean is True, "DNS 解析未完成验证或检测到国内运营商泄露"),
        ("本机 IPv6 隔离安全", ipv6_safe is True, "检测到活跃公网 IPv6 路由，请改为「仅本地链接」")
    ]

    all_passed = True
    for name, passed, fail_reason in gate_checks:
        if passed:
            print(f"  [{GREEN}PASS{RESET}] {name}")
        else:
            all_passed = False
            print(f"  [{RED}FAIL{RESET}] {name} -> {fail_reason}")

    if not fake_ip_ok:
        print(f"  [{YELLOW}INFO{RESET}] 本机系统 Fake-IP 接管提醒 -> 若使用 TUN 模式，建议同时开启「系统代理」或重拨一次 TUN 开关")

    print("\n[上线前最后 3 项人工复核清单]:")
    print("1. 浏览器 WebRTC 防护: Chrome/Edge 安装 'WebRTC Control' 插件并点亮蓝色图标（彻底禁用 WebRTC）。")
    print("2. 客户端双开加固: Clash Verge Rev 同时开启「系统代理 (System Proxy)」与「TUN 模式 (Tun Mode)」。")
    print("3. IP 纯净度复核: 在 https://ip.net.coffee/claude 与 https://scamalytics.com 确认无泄露且欺诈分 < 25。")
    print("=====================================================\n")

    if all_passed:
        print(f"{BOLD}{GREEN}[GATE: PASS] 全部 6 项核心防封与连通性门禁检测均已通过！{RESET}\n")
        sys.exit(0)
    else:
        print(f"{BOLD}{RED}[GATE: FAIL] 门禁检测未全部达标，请按上方提示修复后重新验收！{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
