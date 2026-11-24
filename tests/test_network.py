from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import agy_doctor
import agy_network


class NetworkTest(unittest.TestCase):
    def setUp(self):
        proxy = patch.object(agy_network, "system_proxy", return_value=("disabled", None))
        proxy.start()
        self.addCleanup(proxy.stop)

    def test_probe_uses_verified_tls_and_does_not_keep_addresses(self):
        responses = [
            subprocess.CompletedProcess([], 0, stdout="ip_address: 192.0.2.1\nipv6_address: 2001:db8::1\n"),
            subprocess.CompletedProcess([], 0, stdout="404 0.048 0 0.010 000 0.052\n"),
        ]
        with patch.object(agy_network.subprocess, "run", side_effect=responses) as run:
            result = agy_network.probe("daily-cloudcode-pa.googleapis.com")
        self.assertEqual(result, agy_network.sample("a_and_aaaa", "verified", tcp="connected", http=404, elapsed_ms=52))
        curl = run.call_args.args[0]
        self.assertEqual(curl[:2], ["/usr/bin/curl", "--disable"])
        self.assertIn("--noproxy", curl)
        self.assertNotIn("--insecure", curl)

    def test_tls_failure_and_dns_timeout_are_independent(self):
        responses = [
            subprocess.TimeoutExpired("dscacheutil", 4),
            subprocess.CompletedProcess([], 60, stdout="000 0.000 1\n"),
        ]
        with patch.object(agy_network.subprocess, "run", side_effect=responses):
            result = agy_network.probe("daily-cloudcode-pa.googleapis.com")
        self.assertEqual(result, agy_network.sample("timeout", "certificate_error"))

    def test_timeout_after_successful_tls_preserves_handshake(self):
        result = subprocess.CompletedProcess([], 28, stdout="000 0.050 0\n")
        self.assertEqual(agy_network.tls_result(result), ("verified", None))

    def test_comparison_distinguishes_app_recovery_from_network_probes(self):
        debug = 'Error: HTTP 400 Bad Request\n{"error":{"code":400,"status":"FAILED_PRECONDITION","message":"User location is not supported for the API use.","details":"private-fixture"}}'
        same_probe = agy_network.sample("a", "verified", tcp="connected", http=404)
        with patch.object(agy_network, "probe", return_value=same_probe):
            before = agy_network.capture(agy_doctor.parse_debug(debug))
            after = agy_network.capture(agy_network.app_observation("confirmed_success"))
        report = agy_network.compare(before, after)
        for text in ("HTTP 400", "FAILED_PRECONDITION", "用户确认 Agent 成功回复", "应用测试恢复", "HTTP 404"):
            self.assertIn(text, report)
        self.assertNotIn("private-fixture", json.dumps(before))
        self.assertNotIn("private-fixture", report)

    def test_missing_app_evidence_does_not_claim_recovery(self):
        same_probe = agy_network.sample("a", "verified", tcp="connected", http=404)
        with patch.object(agy_network, "probe", return_value=same_probe):
            before = agy_network.capture(agy_doctor.parse_debug("Error: HTTP 429"))
            after = agy_network.capture(agy_network.app_observation("not_tested"))
        self.assertIn("缺少切换后的应用测试", agy_network.compare(before, after))
        self.assertNotIn("应用测试恢复", agy_network.compare(before, after))

    def test_wizard_rejects_stale_clipboard_and_saves_clean_markdown(self):
        raw = "Error: HTTP 429 Too Many Requests"
        same_probe = agy_network.sample("a", "verified", tcp="connected", http=404)
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            original = Path.cwd()
            os.chdir(directory)
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch("builtins.input", side_effect=["", "", "", "s"]))
                    clipboard = stack.enter_context(patch.object(agy_doctor, "read_input", return_value=raw))
                    stack.enter_context(patch.object(agy_network, "probe", return_value=same_probe))
                    stack.enter_context(redirect_stdout(out))
                    stack.enter_context(redirect_stderr(err))
                    agy_doctor.wizard()
                report, = Path(directory).glob("antigravity-report-*.md")
                self.assertEqual(out.getvalue(), report.read_text())
            finally:
                os.chdir(original)
        self.assertEqual(clipboard.call_count, 2)
        self.assertIn("剪贴板与切换前相同", err.getvalue())
        self.assertTrue(out.getvalue().startswith("# Antigravity 网络对比脱敏报告"))
        self.assertIn("应用测试恢复", out.getvalue())

    def test_imported_snapshot_cannot_echo_injected_text(self):
        same_probe = agy_network.sample("a", "verified", tcp="connected", http=404)
        with patch.object(agy_network, "probe", return_value=same_probe):
            sample = agy_network.capture(agy_network.app_observation("not_tested"))
        sample["app"]["status"] = "private-fixture"
        with self.assertRaisesRegex(ValueError, "快照格式无效"):
            agy_network.compare(sample, sample)

    def test_extra_probe_fields_are_rejected(self):
        same_probe = agy_network.sample("a", "verified", tcp="connected", http=404)
        with patch.object(agy_network, "probe", return_value=same_probe):
            sample = agy_network.capture(agy_network.app_observation("not_tested"))
        sample["probes"][agy_network.HOSTS[0]]["direct"][0]["other"] = "private-fixture"
        with self.assertRaisesRegex(ValueError, "快照格式无效"):
            agy_network.compare(sample, sample)

    def test_compare_cli_works_from_two_snapshot_files(self):
        same_probe = agy_network.sample("a", "verified", tcp="connected", http=404)
        with patch.object(agy_network, "probe", return_value=same_probe):
            snapshot = agy_network.capture(agy_network.app_observation("not_tested"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(snapshot))
            result = subprocess.run(
                [sys.executable, str(Path(agy_doctor.__file__)), "compare", str(path), str(path)],
                capture_output=True, text=True, timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Antigravity 网络对比脱敏报告", result.stdout)


if __name__ == "__main__":
    unittest.main()
