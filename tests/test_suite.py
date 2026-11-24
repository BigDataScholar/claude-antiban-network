#!/usr/bin/env python3
"""
Regression test suite for claude-antiban-network (stdlib-only unittest).
Covers:
- P0 upstream XTLS/Xray-install behavior: no removed `-u` flag, empty `{}` stub
  created on fresh VPS, non-root service group 0640 readability + 0600 backups/metadata.
- Firewall failure BEFORE mutating active config.json, full rollback, and recoverable retry.
- Zero secret exposure in child-process CLI argv (jq / xray) and redacted error stderr.
- Empty Reality shortId ("") reuse, extra inbound preservation, and REGENERATE rotation.
- HTTPS-only egress verification (ipinfo.io + api.ip.sb fallback), NAT VPS split
  --inbound-host / --expected-egress-ip, NO_PROXY immunity, and 0600 file handoff.
"""

import grp
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import generate_clash_config as gen_cfg  # noqa: E402
import verify_environment as verify_env  # noqa: E402

# Real RFC 7748 Section 6.1 X25519 keypairs (base64url without '=' padding)
# Alice keypair:
ALICE_PRIV = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo"
ALICE_PUB = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
# Bob keypair (5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb ->
#              de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f):
BOB_PRIV = "XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os"
BOB_PUB = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"


class FakeResponse:
    def __init__(self, body, status=200, headers=None):
        self._body = body.encode("utf-8") if isinstance(body, str) else body
        self._status = status
        self.headers = headers or {}

    def read(self):
        return self._body

    def getcode(self):
        return self._status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestGenerateClashConfig(unittest.TestCase):
    def test_json_file_handoff_0600_no_stdout_secret_and_empty_short_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            node_file = Path(tmp) / "node.json"
            yaml_file = Path(tmp) / "profile.yaml"
            vless_file = Path(tmp) / "profile-mobile-vless.txt"

            secret_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            node_data = {
                "server_ip": "198.51.100.42",
                "port": 24433,
                "uuid": secret_uuid,
                "flow": "xtls-rprx-vision",
                "security": "reality",
                "sni": "gateway.icloud.com",
                "public_key": ALICE_PUB,
                "short_id": "",  # Valid empty Reality shortId
                "fingerprint": "chrome",
            }
            node_file.write_text(json.dumps(node_data), encoding="utf-8")
            os.chmod(node_file, 0o600)

            res = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS_DIR / "generate_clash_config.py"),
                    "--json-file",
                    str(node_file),
                    "--output",
                    str(yaml_file),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            # Raw secret must NOT appear in stdout by default
            self.assertNotIn(secret_uuid, res.stdout)
            self.assertNotIn("vless://", res.stdout)

            # Both generated artifacts must be 0600
            self.assertEqual(stat.S_IMODE(yaml_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(vless_file.stat().st_mode), 0o600)

            yaml_text = yaml_file.read_text(encoding="utf-8")
            self.assertIn('short-id: ""', yaml_text)
            self.assertIn("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT", yaml_text)
            self.assertIn("GEOSITE,geolocation-!cn,🚀 独享-AI与代码", yaml_text)
            self.assertIn("GEOIP,CN,DIRECT,no-resolve", yaml_text)

            vless_text = vless_file.read_text(encoding="utf-8").strip()
            self.assertTrue(vless_text.startswith(f"vless://{secret_uuid}@198.51.100.42:24433?"))
            self.assertIn("sid=", vless_text)


class TestVerifyEnvironment(unittest.TestCase):
    def test_forced_proxy_handler_ignores_no_proxy_env(self):
        with mock.patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*"}):
            handler = verify_env.ForcedProxyHandler(
                {"http": "http://127.0.0.1:7897", "https": "http://127.0.0.1:7897"}
            )
            req = urllib.request.Request("https://ipinfo.io/json")
            handler.proxy_open(req, "http://127.0.0.1:7897", "https")
            self.assertEqual(req.host, "127.0.0.1:7897")
            self.assertEqual(req.type, "https")

    def _run_verify_with_mocks(
        self,
        cli_args,
        ipinfo_resp=None,
        ipsb_resp=None,
        web_behavior="challenge",
        fake_ip="198.18.0.30",
        port_ok=True,
    ):
        opened_urls = []
        port_calls = []

        def fake_open(req, timeout=10):
            url = req.full_url
            opened_urls.append(url)
            if "ipinfo.io/json" in url:
                if ipinfo_resp is None:
                    raise urllib.error.URLError("ipinfo simulated failure")
                return FakeResponse(json.dumps(ipinfo_resp))
            if "api.ip.sb/geoip" in url:
                if ipsb_resp is None:
                    raise urllib.error.URLError("ipsb simulated failure")
                return FakeResponse(json.dumps(ipsb_resp))
            if "edns.ip-api.com" in url:
                return FakeResponse(json.dumps({"dns": {"ip": "1.1.1.1", "geo": "United States - Cloudflare"}}))
            if "api.anthropic.com" in url:
                raise urllib.error.HTTPError(url, 404, "Not Found", {"cf-ray": "abc-LAX"}, None)
            if "claude.ai" in url:
                if web_behavior == "direct":
                    return FakeResponse("<html>ok</html>", 200)
                if web_behavior == "challenge":
                    raise urllib.error.HTTPError(
                        url, 403, "Forbidden", {"cf-mitigated": "challenge", "cf-ray": "xyz-LAX"}, None
                    )
                if web_behavior == "blocked":
                    raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
            if "gemini.google.com" in url:
                return FakeResponse("<html>Gemini US</html>", 200)
            raise AssertionError(f"Unexpected URL: {url}")

        def fake_port_check(host, port, timeout=5):
            port_calls.append((host, int(port)))
            return port_ok

        fake_opener = mock.MagicMock()
        fake_opener.open.side_effect = fake_open

        buf = io.StringIO()
        exit_code = None
        with mock.patch.object(sys, "argv", ["verify_environment.py"] + cli_args), \
             mock.patch.object(verify_env, "build_opener", return_value=fake_opener), \
             mock.patch.object(verify_env, "check_local_ipv6_leak", return_value=True), \
             mock.patch.object(verify_env, "check_vps_port_reachable", side_effect=fake_port_check), \
             mock.patch("socket.gethostbyname", return_value=fake_ip), \
             redirect_stdout(buf):
            try:
                verify_env.main()
            except SystemExit as e:
                exit_code = e.code
        return exit_code, buf.getvalue(), opened_urls, port_calls

    def test_https_only_egress_with_fallback_never_uses_plaintext_http(self):
        ipsb_ok = {
            "ip": "203.0.113.10",
            "country": "United States",
            "country_code": "US",
            "city": "Los Angeles",
            "isp": "NTT",
            "asn": 2914,
            "asn_organization": "NTT America",
        }
        code, out, urls, _ = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"],
            ipinfo_resp=None,  # Force HTTPS fallback to api.ip.sb
            ipsb_resp=ipsb_ok,
            web_behavior="direct",
        )
        self.assertEqual(code, 0)
        self.assertIn("api.ip.sb", out)
        self.assertTrue(all(u.startswith("https://") for u in urls), f"Non-HTTPS URL used: {urls}")

    def test_nat_vps_separate_inbound_host_and_expected_egress_ip(self):
        ipinfo_ok = {
            "ip": "203.0.113.88",
            "country": "US",
            "city": "San Jose",
            "region": "California",
            "org": "AS2914 NTT",
        }
        code, out, _, port_calls = self._run_verify_with_mocks(
            [
                "--inbound-host",
                "198.51.100.10",
                "--expected-port",
                "24433",
                "--expected-egress-ip",
                "203.0.113.88",
            ],
            ipinfo_resp=ipinfo_ok,
            web_behavior="direct",
            port_ok=True,
        )
        self.assertEqual(code, 0)
        self.assertEqual(port_calls, [("198.51.100.10", 24433)])
        self.assertIn("NAT 独立出口", out)
        self.assertIn("[GATE: PASS]", out)

    def test_rejects_unrelated_us_exit_ip(self):
        code, out, _, _ = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"],
            ipinfo_resp={"ip": "198.51.100.99", "country": "US", "city": "LA", "org": "AS1 Other"},
            web_behavior="direct",
        )
        self.assertEqual(code, 1)
        self.assertIn("[GATE: FAIL]", out)
        self.assertIn("出口IP不匹配", out)

    def test_fails_when_expected_ip_not_provided_without_allow_any_us(self):
        code, out, _, _ = self._run_verify_with_mocks(
            [],
            ipinfo_resp={"ip": "198.51.100.99", "country": "US", "city": "LA", "org": "AS1 Other"},
            web_behavior="direct",
        )
        self.assertEqual(code, 1)
        self.assertIn("[GATE: FAIL]", out)

    def test_fails_when_fake_ip_not_active_by_default(self):
        code, out, _, _ = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"],
            ipinfo_resp={"ip": "203.0.113.10", "country": "US", "city": "LA", "org": "AS2914 NTT"},
            web_behavior="direct",
            fake_ip="185.45.5.35",
        )
        self.assertEqual(code, 1)
        self.assertIn("未命中 Clash Fake-IP", out)

    def test_strict_web_fails_on_cf_challenge_and_default_reports_separately(self):
        ip_ok = {"ip": "203.0.113.10", "country": "US", "city": "LA", "org": "AS2914 NTT"}
        code_strict, out_strict, _, _ = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10", "--strict-web"], ipinfo_resp=ip_ok, web_behavior="challenge"
        )
        self.assertEqual(code_strict, 1)
        self.assertIn("[GATE: FAIL]", out_strict)

        code_default, out_default, _, _ = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"], ipinfo_resp=ip_ok, web_behavior="challenge"
        )
        self.assertEqual(code_default, 0)
        self.assertIn("PASS_PROXY_CHAIN", out_default)
        self.assertIn("CF_CHALLENGE", out_default)

        code_blocked, out_blocked, _, _ = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"], ipinfo_resp=ip_ok, web_behavior="blocked"
        )
        self.assertEqual(code_blocked, 1)
        self.assertIn("BLOCKED_403", out_blocked)

    def test_fails_when_vps_inbound_port_unreachable(self):
        ip_ok = {"ip": "203.0.113.10", "country": "US", "city": "LA", "org": "AS2914 NTT"}
        code, out, _, _ = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10", "--expected-port", "24433"],
            ipinfo_resp=ip_ok,
            web_behavior="direct",
            port_ok=False,
        )
        self.assertEqual(code, 1)
        self.assertIn("目标 VPS 入站 TCP 端口可达", out)


class TestVpsSetupScript(unittest.TestCase):
    """Isolated sandbox tests for scripts/vps_setup.sh using mock binaries & mock upstream installer."""

    def _mock_xray_script(self, priv=ALICE_PRIV, pub=ALICE_PUB, broken_x25519=False, argv_log=None):
        log_line = f'printf "%s\\n" "$*" >> "{argv_log}"\n' if argv_log else ""
        if broken_x25519:
            x25519_block = 'echo "PrivateKey: SECRET_LEAK_TOKEN_999"\n    echo "MalformedLineWithoutPub"'
        else:
            x25519_block = f'echo "PrivateKey: {priv}"\n    echo "Password (PublicKey): {pub}"'
        return f"""#!/usr/bin/env bash
{log_line}if [ "$1" = "uuid" ]; then
    echo "99999999-8888-7777-6666-555555555555"
elif [ "$1" = "x25519" ]; then
    {x25519_block}
elif [ "$1" = "run" ] && [ "$2" = "-test" ]; then
    jq empty "$4"
else
    exit 0
fi
"""

    def _create_sandbox(
        self,
        tmp,
        ufw_fail=False,
        use_upstream_installer=False,
        xray_group="none",
        broken_x25519=False,
        spy_argv=False,
    ):
        tmp_path = Path(tmp)
        bin_dir = tmp_path / "bin"
        cfg_dir = tmp_path / "xray_etc"
        bin_dir.mkdir()
        cfg_dir.mkdir()

        argv_log = tmp_path / "child_argv.log" if spy_argv else None
        mock_xray = bin_dir / "xray"
        xray_content = self._mock_xray_script(broken_x25519=broken_x25519, argv_log=argv_log)

        if not use_upstream_installer:
            mock_xray.write_text(xray_content, encoding="utf-8")
            mock_xray.chmod(0o755)
        else:
            # Build a realistic mock upstream XTLS/Xray-install script:
            # 1. Fails with exit 1 if removed `-u` flag is passed (P0-1 regression check)
            # 2. Installs the mock xray binary at $XRAY_BIN
            # 3. Creates empty `{}` at $CONFIG_DIR/config.json (P0-2 regression check)
            xray_template = tmp_path / "xray_payload.sh"
            xray_template.write_text(xray_content, encoding="utf-8")
            installer_file = tmp_path / "mock-install-release.sh"
            installer_file.write_text(
                f"""#!/usr/bin/env bash
set -euo pipefail
for a in "$@"; do
    if [ "$a" = "-u" ]; then
        echo "error: -u option was removed in pinned XTLS/Xray-install!" >&2
        exit 1
    fi
done
if [ "${{1:-}}" != "install" ]; then
    echo "error: expected install subcommand" >&2
    exit 1
fi
cp "{xray_template}" "${{XRAY_BIN}}"
chmod 755 "${{XRAY_BIN}}"
mkdir -p "${{CONFIG_DIR}}"
echo '{{}}' > "${{CONFIG_DIR}}/config.json"
chmod 640 "${{CONFIG_DIR}}/config.json"
""",
                encoding="utf-8",
            )
            installer_sha256 = hashlib.sha256(installer_file.read_bytes()).hexdigest()

        # Optional spy wrapper for real jq
        if spy_argv:
            real_jq = subprocess.check_output(["which", "jq"], text=True).strip()
            spy_jq = bin_dir / "jq"
            spy_jq.write_text(
                f"""#!/usr/bin/env bash
printf "jq %s\\n" "$*" >> "{argv_log}"
exec "{real_jq}" "$@"
""",
                encoding="utf-8",
            )
            spy_jq.chmod(0o755)

        # Mock systemctl
        mock_systemctl = bin_dir / "systemctl"
        mock_systemctl.write_text(
            """#!/usr/bin/env bash
if [ "$1" = "is-active" ] || [ "$1" = "is-enabled" ]; then
    if [ -f "${MOCK_XRAY_RUNNING:-/nonexistent}" ] && [ "$3" = "xray" ]; then
        exit 0
    fi
    if [ "$1" = "is-active" ] && [ "$3" = "xray" ] && [ -f "${CONFIG_DIR}/config.json" ]; then
        exit 0
    fi
    exit 1
fi
exit 0
""",
            encoding="utf-8",
        )
        mock_systemctl.chmod(0o755)

        # Mock ufw (reads UFW_FAIL_FLAG dynamically so retry tests can toggle it)
        ufw_fail_flag = tmp_path / "ufw_fail.flag"
        if ufw_fail:
            ufw_fail_flag.write_text("1", encoding="utf-8")
        mock_ufw = bin_dir / "ufw"
        mock_ufw.write_text(
            f"""#!/usr/bin/env bash
if [ "$1" = "status" ]; then
    echo "Status: active"
    exit 0
fi
if [ "$1" = "allow" ]; then
    if [ -f "{ufw_fail_flag}" ]; then
        exit 1
    fi
    exit 0
fi
exit 0
""",
            encoding="utf-8",
        )
        mock_ufw.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["SKIP_ROOT_CHECK"] = "true"
        env["SKIP_APT"] = "true"
        env["SKIP_XRAY_INSTALL"] = "false" if use_upstream_installer else "true"
        env["SKIP_SYSCTL"] = "true"
        env["SKIP_WARP"] = "true"
        env["SKIP_LISTEN_CHECK"] = "true"
        env["XRAY_BIN"] = str(mock_xray)
        env["CONFIG_DIR"] = str(cfg_dir)
        env["SYSCTL_FILE"] = str(tmp_path / "99-antiban.conf")
        env["OUTPUT_FILE"] = str(tmp_path / "node.json")
        env["SERVER_IP_OVERRIDE"] = "203.0.113.55"
        env["XRAY_GROUP"] = xray_group
        if use_upstream_installer:
            env["XRAY_INSTALL_URL"] = f"file://{installer_file}"
            env["XRAY_INSTALL_SHA256"] = installer_sha256
        return tmp_path, cfg_dir, env, ufw_fail_flag, argv_log

    def test_aborts_on_existing_config_without_allow_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env, _, _ = self._create_sandbox(tmp)
            cfg_file = cfg_dir / "config.json"
            original = '{"marker": "untouched"}\n'
            cfg_file.write_text(original, encoding="utf-8")

            res = subprocess.run(
                ["bash", str(SCRIPTS_DIR / "vps_setup.sh")],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 2)
            self.assertEqual(cfg_file.read_text(encoding="utf-8"), original)
            self.assertFalse((tmp_path / "node.json").exists())

    def test_fresh_install_with_upstream_installer_empty_stub_and_0640_service_group(self):
        # Covers all 3 P0 blockers in one realistic end-to-end fresh-install flow:
        # P0-1: no `-u` passed to installer
        # P0-2: installer creates empty `{}` config.json stub, treated as fresh install
        # P0-3: config dir 0750 & config.json 0640 readable by service group, backups/node.json 0600
        current_group = grp.getgrgid(os.getgid()).gr_name
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env, _, _ = self._create_sandbox(
                tmp, use_upstream_installer=True, xray_group=current_group
            )
            res = subprocess.run(
                ["bash", "-c", f"umask 022 && bash '{SCRIPTS_DIR / 'vps_setup.sh'}'"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            cfg_file = cfg_dir / "config.json"
            node_file = tmp_path / "node.json"

            self.assertEqual(stat.S_IMODE(cfg_dir.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(cfg_file.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(node_file.stat().st_mode), 0o600)
            self.assertEqual(len(list(cfg_dir.glob("config.json.bak.*"))), 0)

            meta = json.loads(node_file.read_text(encoding="utf-8"))
            self.assertNotIn(meta["uuid"], res.stdout)
            self.assertNotIn(ALICE_PRIV, res.stdout)
            self.assertEqual(meta["public_key"], ALICE_PUB)
            self.assertEqual(meta["firewall_status"], "ufw_allowed")

    def test_fresh_install_without_service_group_uses_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env, _, _ = self._create_sandbox(tmp, xray_group="none")
            subprocess.run(
                ["bash", "-c", f"umask 022 && bash '{SCRIPTS_DIR / 'vps_setup.sh'}'"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(stat.S_IMODE((cfg_dir / "config.json").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((tmp_path / "node.json").stat().st_mode), 0o600)

    def test_ufw_failure_rolls_back_before_mutating_config_and_retry_recovers(self):
        # Part 1: Fresh install fails at UFW -> stub removed, no config written, retry with ALLOW_EXISTING recovers
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env, ufw_fail_flag, _ = self._create_sandbox(
                tmp, ufw_fail=True, use_upstream_installer=True
            )
            res = subprocess.run(
                ["bash", str(SCRIPTS_DIR / "vps_setup.sh")],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn("UFW allowed", res.stdout)
            self.assertNotIn("VPS SETUP COMPLETE", res.stdout)
            self.assertFalse((cfg_dir / "config.json").exists())
            self.assertFalse((tmp_path / "node.json").exists())

            # Fix UFW and retry with ALLOW_EXISTING=true -> must recover cleanly!
            ufw_fail_flag.unlink()
            env["ALLOW_EXISTING"] = "true"
            res_retry = subprocess.run(
                ["bash", str(SCRIPTS_DIR / "vps_setup.sh")],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("VPS SETUP COMPLETE", res_retry.stdout)
            meta = json.loads((tmp_path / "node.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["public_key"], ALICE_PUB)

        # Part 2: Existing config with ALLOW_EXISTING=true + UFW failure -> active config untouched!
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env, _, _ = self._create_sandbox(tmp, ufw_fail=True)
            cfg_file = cfg_dir / "config.json"
            old_cfg = {
                "inbounds": [
                    {
                        "port": 24433,
                        "protocol": "vless",
                        "settings": {"clients": [{"id": "keep-untouched-uuid", "flow": "xtls-rprx-vision"}]},
                        "streamSettings": {
                            "realitySettings": {
                                "serverNames": ["gateway.icloud.com"],
                                "privateKey": BOB_PRIV,
                                "shortIds": [""],
                            }
                        },
                    }
                ]
            }
            original_text = json.dumps(old_cfg)
            cfg_file.write_text(original_text, encoding="utf-8")
            env["ALLOW_EXISTING"] = "true"

            res = subprocess.run(
                ["bash", str(SCRIPTS_DIR / "vps_setup.sh")],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertEqual(cfg_file.read_text(encoding="utf-8"), original_text)

    def test_zero_secrets_in_child_argv_and_redacted_keygen_error(self):
        # 1. Verify no secret ever appears in child process CLI argv (jq / xray)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, _, env, _, argv_log = self._create_sandbox(tmp, spy_argv=True)
            subprocess.run(
                ["bash", str(SCRIPTS_DIR / "vps_setup.sh")],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            meta = json.loads((tmp_path / "node.json").read_text(encoding="utf-8"))
            logged = argv_log.read_text(encoding="utf-8")
            self.assertNotIn(meta["uuid"], logged)
            self.assertNotIn(ALICE_PRIV, logged)
            self.assertNotIn(ALICE_PUB, logged)
            self.assertNotIn(meta["short_id"], logged)

        # 2. Verify broken xray x25519 output never leaks raw PrivateKey to stderr/stdout
        with tempfile.TemporaryDirectory() as tmp:
            _, _, env, _, _ = self._create_sandbox(tmp, broken_x25519=True)
            res = subprocess.run(
                ["bash", str(SCRIPTS_DIR / "vps_setup.sh")],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn("SECRET_LEAK_TOKEN_999", res.stdout)
            self.assertNotIn("SECRET_LEAK_TOKEN_999", res.stderr)
            self.assertIn("redacted", res.stderr)

    def test_empty_short_id_reuse_and_extra_inbound_consistency(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env, _, _ = self._create_sandbox(tmp)
            cfg_file = cfg_dir / "config.json"
            old_cfg = {
                "inbounds": [
                    {
                        "port": 31337,
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {"id": "old-uuid-primary", "flow": "xtls-rprx-vision"},
                                {"id": "old-uuid-second", "flow": "xtls-rprx-vision"},
                            ],
                            "decryption": "none",
                        },
                        "streamSettings": {
                            "network": "tcp",
                            "security": "reality",
                            "realitySettings": {
                                "serverNames": ["example.com"],
                                "privateKey": BOB_PRIV,
                                "shortIds": [""],  # Valid empty Reality shortId
                            },
                        },
                    },
                    {"port": 8443, "protocol": "dokodemo-door", "settings": {}},
                ]
            }
            cfg_file.write_text(json.dumps(old_cfg), encoding="utf-8")
            env["ALLOW_EXISTING"] = "true"

            subprocess.run(
                ["bash", "-c", f"umask 022 && bash '{SCRIPTS_DIR / 'vps_setup.sh'}'"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )

            new_cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
            meta = json.loads((tmp_path / "node.json").read_text(encoding="utf-8"))

            self.assertEqual(len(new_cfg["inbounds"]), 2)
            self.assertEqual(len(new_cfg["inbounds"][0]["settings"]["clients"]), 2)
            self.assertEqual(new_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"], [""])
            self.assertEqual(new_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"], BOB_PRIV)

            # Backup file must have strict 0600 permissions
            backups = list(cfg_dir.glob("config.json.bak.*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)

            # Emitted metadata MUST match final config.json with RFC 7748 derived pubkey
            self.assertEqual(meta["port"], 31337)
            self.assertEqual(meta["uuid"], "old-uuid-primary")
            self.assertEqual(meta["short_id"], "")
            self.assertEqual(meta["sni"], "example.com")
            self.assertEqual(meta["public_key"], BOB_PUB)

    def test_regenerate_rotates_all_credentials_consistently(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env, _, _ = self._create_sandbox(tmp)
            cfg_file = cfg_dir / "config.json"
            old_cfg = {
                "inbounds": [
                    {
                        "port": 24433,
                        "protocol": "vless",
                        "settings": {"clients": [{"id": "old-uuid-1", "flow": "xtls-rprx-vision"}]},
                        "streamSettings": {
                            "realitySettings": {
                                "serverNames": ["gateway.icloud.com"],
                                "privateKey": BOB_PRIV,
                                "shortIds": [""],
                            }
                        },
                    }
                ]
            }
            cfg_file.write_text(json.dumps(old_cfg), encoding="utf-8")
            env["ALLOW_EXISTING"] = "true"
            env["REGENERATE"] = "true"

            subprocess.run(
                ["bash", str(SCRIPTS_DIR / "vps_setup.sh")],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )

            new_cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
            meta = json.loads((tmp_path / "node.json").read_text(encoding="utf-8"))

            self.assertEqual(new_cfg["inbounds"][0]["settings"]["clients"][0]["id"], meta["uuid"])
            self.assertNotEqual(meta["uuid"], "old-uuid-1")
            self.assertEqual(new_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"], ALICE_PRIV)
            self.assertEqual(meta["public_key"], ALICE_PUB)
            self.assertEqual(new_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"], [meta["short_id"]])
            self.assertTrue(len(meta["short_id"]) > 0)


if __name__ == "__main__":
    unittest.main()
