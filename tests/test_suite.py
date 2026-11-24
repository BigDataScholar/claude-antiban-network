#!/usr/bin/env python3
"""
Regression test suite for claude-antiban-network (stdlib-only unittest).
Covers all P1 security, firewall, fresh-VPS preflight, credential consistency,
empty shortId, 0600 file permissions, NO_PROXY immunity, and exact egress matching.
"""

import io
import json
import os
import socket
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
                "public_key": "pubKeyTestValue123456",
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
            req = urllib.request.Request("http://ip-api.com/json")
            handler.proxy_open(req, "http://127.0.0.1:7897", "http")
            self.assertEqual(req.host, "127.0.0.1:7897")
            self.assertEqual(req.type, "http")

    def _run_verify_with_mocks(self, cli_args, ip_resp, web_behavior="challenge", fake_ip="198.18.0.30", port_ok=True):
        def fake_open(req, timeout=10):
            url = req.full_url
            if "ip-api.com/json" in url and "edns" not in url:
                return FakeResponse(json.dumps(ip_resp))
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

        fake_opener = mock.MagicMock()
        fake_opener.open.side_effect = fake_open

        buf = io.StringIO()
        exit_code = None
        with mock.patch.object(sys, "argv", ["verify_environment.py"] + cli_args), \
             mock.patch.object(verify_env, "build_opener", return_value=fake_opener), \
             mock.patch.object(verify_env, "check_local_ipv6_leak", return_value=True), \
             mock.patch.object(verify_env, "check_vps_port_reachable", return_value=port_ok), \
             mock.patch("socket.gethostbyname", return_value=fake_ip), \
             redirect_stdout(buf):
            try:
                verify_env.main()
            except SystemExit as e:
                exit_code = e.code
        return exit_code, buf.getvalue()

    def test_rejects_unrelated_us_exit_ip(self):
        code, out = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"],
            {"query": "198.51.100.99", "country": "United States", "countryCode": "US", "city": "LA", "isp": "Other", "as": "AS1"},
            web_behavior="direct",
        )
        self.assertEqual(code, 1)
        self.assertIn("[GATE: FAIL]", out)
        self.assertIn("出口IP不匹配", out)

    def test_fails_when_expected_ip_not_provided_without_allow_any_us(self):
        code, out = self._run_verify_with_mocks(
            [],
            {"query": "198.51.100.99", "country": "United States", "countryCode": "US", "city": "LA", "isp": "Other", "as": "AS1"},
            web_behavior="direct",
        )
        self.assertEqual(code, 1)
        self.assertIn("[GATE: FAIL]", out)

    def test_fails_when_fake_ip_not_active_by_default(self):
        code, out = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"],
            {"query": "203.0.113.10", "country": "United States", "countryCode": "US", "city": "LA", "isp": "NTT", "as": "AS2914"},
            web_behavior="direct",
            fake_ip="185.45.5.35",
        )
        self.assertEqual(code, 1)
        self.assertIn("未命中 Clash Fake-IP", out)

    def test_strict_web_fails_on_cf_challenge_and_default_reports_separately(self):
        ip_ok = {"query": "203.0.113.10", "country": "United States", "countryCode": "US", "city": "LA", "isp": "NTT", "as": "AS2914"}
        code_strict, out_strict = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10", "--strict-web"], ip_ok, web_behavior="challenge"
        )
        self.assertEqual(code_strict, 1)
        self.assertIn("[GATE: FAIL]", out_strict)

        code_default, out_default = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"], ip_ok, web_behavior="challenge"
        )
        self.assertEqual(code_default, 0)
        self.assertIn("PASS_PROXY_CHAIN", out_default)
        self.assertIn("CF_CHALLENGE", out_default)

        code_blocked, out_blocked = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10"], ip_ok, web_behavior="blocked"
        )
        self.assertEqual(code_blocked, 1)
        self.assertIn("BLOCKED_403", out_blocked)

    def test_fails_when_vps_inbound_port_unreachable(self):
        ip_ok = {"query": "203.0.113.10", "country": "United States", "countryCode": "US", "city": "LA", "isp": "NTT", "as": "AS2914"}
        code, out = self._run_verify_with_mocks(
            ["--expected-ip", "203.0.113.10", "--expected-port", "24433"],
            ip_ok,
            web_behavior="direct",
            port_ok=False,
        )
        self.assertEqual(code, 1)
        self.assertIn("目标 VPS 入站 TCP 端口可达", out)


class TestVpsSetupScript(unittest.TestCase):
    """Isolated sandbox tests for scripts/vps_setup.sh using mock binaries."""

    def _create_sandbox(self, tmp, ufw_fail=False):
        tmp_path = Path(tmp)
        bin_dir = tmp_path / "bin"
        cfg_dir = tmp_path / "xray_etc"
        bin_dir.mkdir()
        cfg_dir.mkdir()

        # Mock xray binary (supports uuid, x25519, x25519 -i <priv>, run -test -config)
        mock_xray = bin_dir / "xray"
        mock_xray.write_text(
            """#!/usr/bin/env bash
if [ "$1" = "uuid" ]; then
    echo "99999999-8888-7777-6666-555555555555"
elif [ "$1" = "x25519" ] && [ "$2" = "-i" ]; then
    echo "PrivateKey: $3"
    echo "Password (PublicKey): pub_of_$3"
elif [ "$1" = "x25519" ]; then
    echo "PrivateKey: new_priv_key_xyz"
    echo "Password (PublicKey): pub_of_new_priv_key_xyz"
elif [ "$1" = "run" ] && [ "$2" = "-test" ]; then
    jq empty "$4"
else
    exit 0
fi
""",
            encoding="utf-8",
        )
        mock_xray.chmod(0o755)

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

        # Mock ufw
        mock_ufw = bin_dir / "ufw"
        mock_ufw.write_text(
            f"""#!/usr/bin/env bash
if [ "$1" = "status" ]; then
    echo "Status: active"
    exit 0
fi
if [ "$1" = "allow" ]; then
    exit {1 if ufw_fail else 0}
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
        env["SKIP_XRAY_INSTALL"] = "true"
        env["SKIP_SYSCTL"] = "true"
        env["SKIP_WARP"] = "true"
        env["SKIP_LISTEN_CHECK"] = "true"
        env["XRAY_BIN"] = str(mock_xray)
        env["CONFIG_DIR"] = str(cfg_dir)
        env["SYSCTL_FILE"] = str(tmp_path / "99-antiban.conf")
        env["OUTPUT_FILE"] = str(tmp_path / "node.json")
        env["SERVER_IP_OVERRIDE"] = "203.0.113.55"
        return tmp_path, cfg_dir, env

    def test_aborts_on_existing_config_without_allow_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env = self._create_sandbox(tmp)
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

    def test_ufw_failure_aborts_and_never_prints_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, env = self._create_sandbox(tmp, ufw_fail=True)
            res = subprocess.run(
                ["bash", str(SCRIPTS_DIR / "vps_setup.sh")],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertNotIn("UFW allowed", res.stdout)
            self.assertNotIn("VPS SETUP COMPLETE", res.stdout)

    def test_fresh_install_0600_perms_and_no_stdout_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env = self._create_sandbox(tmp)
            res = subprocess.run(
                ["bash", "-c", f"umask 022 && bash '{SCRIPTS_DIR / 'vps_setup.sh'}'"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            cfg_file = cfg_dir / "config.json"
            node_file = tmp_path / "node.json"
            self.assertEqual(stat.S_IMODE(cfg_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(node_file.stat().st_mode), 0o600)

            meta = json.loads(node_file.read_text(encoding="utf-8"))
            self.assertNotIn(meta["uuid"], res.stdout)
            self.assertNotIn("new_priv_key_xyz", res.stdout)
            self.assertEqual(meta["public_key"], "pub_of_new_priv_key_xyz")
            self.assertEqual(meta["firewall_status"], "ufw_allowed")

    def test_empty_short_id_reuse_and_extra_inbound_consistency(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env = self._create_sandbox(tmp)
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
                                "privateKey": "old_priv_key_123",
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

            # Must preserve 2 inbounds, 2 clients, [""] shortIds, and old privateKey
            self.assertEqual(len(new_cfg["inbounds"]), 2)
            self.assertEqual(len(new_cfg["inbounds"][0]["settings"]["clients"]), 2)
            self.assertEqual(new_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"], [""])
            self.assertEqual(new_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"], "old_priv_key_123")

            # Backup file must also have strict 0600 permissions
            backups = list(cfg_dir.glob("config.json.bak.*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)

            # Emitted metadata MUST exactly match final config.json
            self.assertEqual(meta["port"], 31337)
            self.assertEqual(meta["uuid"], "old-uuid-primary")
            self.assertEqual(meta["short_id"], "")
            self.assertEqual(meta["sni"], "example.com")
            self.assertEqual(meta["public_key"], "pub_of_old_priv_key_123")

    def test_regenerate_rotates_all_credentials_consistently(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path, cfg_dir, env = self._create_sandbox(tmp)
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
                                "privateKey": "old_priv_key",
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
            self.assertEqual(new_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"], "new_priv_key_xyz")
            self.assertEqual(meta["public_key"], "pub_of_new_priv_key_xyz")
            self.assertEqual(new_cfg["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"], [meta["short_id"]])
            self.assertTrue(len(meta["short_id"]) > 0)


if __name__ == "__main__":
    unittest.main()
