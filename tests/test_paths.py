import copy
import json
import subprocess
import unittest
from unittest.mock import patch

import agy_network as net
from agy_debug import parse_debug


class PathTest(unittest.TestCase):
    def test_static_proxy_settings_are_ephemeral_and_explicit(self):
        settings = """<dictionary> {
  HTTPSEnable : 1
  HTTPSPort : 7892
  HTTPSProxy : 2001:db8::12
  ProxyAutoConfigEnable : 0
}"""
        with patch.object(net.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=settings)):
            state, proxy = net.system_proxy()
        self.assertEqual((state, proxy), ("https", "http://[2001:db8::12]:7892"))

    def test_pac_settings_and_disabled_proxy_do_not_fall_back_to_direct(self):
        with patch.object(net.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout="  ProxyAutoConfigEnable : 1")
            self.assertEqual(net.system_proxy(), ("automatic", None))
            run.return_value = subprocess.CompletedProcess([], 0, stdout="<dictionary> {\n}")
            self.assertEqual(net.system_proxy(), ("disabled", None))

    def test_proxy_curl_does_not_use_direct_dns_or_fall_back(self):
        process = subprocess.CompletedProcess([], 56, stdout="000 0.000 0 0.010 407 0.020\n")
        with patch.object(net, "dns_result") as dns, patch.object(net.subprocess, "run", return_value=process) as run:
            result = net.probe("daily-cloudcode-pa.googleapis.com", "http://proxy.example:8080")
        dns.assert_not_called()
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--proxy") + 1], "http://proxy.example:8080")
        self.assertEqual(command[command.index("--noproxy") + 1], "")
        self.assertEqual(result, {
            "dns": "delegated", "tcp": "connected", "tls": "proxy_rejected",
            "http": None, "connect_http": 407, "elapsed_ms": 20,
        })

    def test_proxy_dns_and_negotiation_failures_are_distinguished(self):
        for code, expected in ((5, "proxy_dns_error"), (97, "proxy_handshake_error")):
            with self.subTest(code=code):
                process = subprocess.CompletedProcess([], code, stdout="000 0.000 0 0.000 000 0.001\n")
                with patch.object(net.subprocess, "run", return_value=process):
                    result = net.probe("daily-cloudcode-pa.googleapis.com", "socks5h://proxy.example:8080")
                self.assertEqual(result["tls"], expected)

    def test_latency_median_uses_only_attempts_with_http_response(self):
        rows = [
            net.sample("a", "verified", tcp="connected", http=404, elapsed_ms=110),
            net.sample("a", "timeout", elapsed_ms=7000),
            net.sample("a", "verified", tcp="connected", http=404, elapsed_ms=150),
        ]
        report = net.path_details(rows, "disabled")
        self.assertIn("130 ms（2/3）", report)

    def test_capture_uses_three_samples_per_path_and_sanitizes_output(self):
        proxy = "http://private-proxy.example:7892"
        def fake_probe(host, proxy_url=None):
            return {
                "dns": "delegated" if proxy_url else "a", "tcp": "connected", "tls": "verified",
                "http": 404, "connect_http": 200 if proxy_url else None, "elapsed_ms": 35,
            }
        with patch.object(net, "system_proxy", return_value=("https", proxy)), patch.object(net, "probe", side_effect=fake_probe) as probe:
            before = net.capture(parse_debug("Error: HTTP 429 Too Many Requests"))
            after = net.capture(net.app_observation("confirmed_success"))
        self.assertEqual(probe.call_count, 2 * 2 * 2 * 3)
        for host in net.HOSTS:
            self.assertEqual(len(before["probes"][host]["direct"]), 3)
            self.assertEqual(len(before["probes"][host]["proxy"]), 3)
        report = net.compare(before, after)
        for text in ("## Antigravity 应用实测", "## 网络双路径探测", "系统代理", "HTTP 429", "3/3", "35 ms"):
            self.assertIn(text, report)
        self.assertNotIn("private-proxy", report + json.dumps(before))

    def test_proxy_disabled_is_listed_as_not_sampled(self):
        with patch.object(net, "system_proxy", return_value=("disabled", None)), patch.object(
            net, "probe", return_value={
                "dns": "a", "tcp": "connected", "tls": "verified", "http": 404,
                "connect_http": None, "elapsed_ms": 10,
            },
        ) as probe:
            sample = net.capture(net.app_observation("not_tested"))
        self.assertEqual(probe.call_count, 6)
        self.assertTrue(all(not routes["proxy"] for routes in sample["probes"].values()))
        self.assertIn("未启用静态代理", net.compare(sample, sample))

    def test_legacy_snapshot_is_compared_without_inventing_samples(self):
        legacy = {
            "version": 1, "app": net.app_observation("not_tested"),
            "probes": {host: {"dns": "a", "tls": "verified", "http": 404} for host in net.HOSTS},
        }
        report = net.compare(legacy, copy.deepcopy(legacy))
        self.assertIn("1/1", report)
        self.assertIn("旧版快照未采集", report)
        self.assertNotIn("3/3", report)


if __name__ == "__main__":
    unittest.main()
