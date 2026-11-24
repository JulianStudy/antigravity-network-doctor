import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "agy_doctor.py"


def run(raw=None, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=raw, text=True, capture_output=True, timeout=10,
    )


class DoctorCLI(unittest.TestCase):
    def assert_report(self, result, diagnosis):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn(diagnosis, result.stdout)
        self.assertIn("# Antigravity 脱敏诊断报告", result.stdout)

    def test_location_export_with_html_and_trailing_backslashes(self):
        lines = [
            "Trajectory ID: synthetic-trajectory-id",
            "Error: HTTP 400 Bad Request",
            "Sherlog: ",
            "TraceID: 0xsynthetictrace",
            'Headers: {"Server":["ESF"],"Authorization":["Bearer synthetic-token"]}',
            "",
            "{",
            '&#x20; "error": {',
            '&#x20;   "code": 400,',
            '&#x20;   "message": "User location is not supported for the API use.",',
            '&#x20;   "status": "FAILED_PRECONDITION"',
            "  }",
            "}",
        ]
        result = run("\\\n".join(lines))
        self.assert_report(result, "服务端拒绝当前请求的地区条件")
        for evidence in ("HTTP 400", "FAILED_PRECONDITION", "网络出口或账号地区"):
            self.assertIn(evidence, result.stdout)
        for secret in ("synthetic-", "0xsynthetic", "ESF", "Authorization"):
            self.assertNotIn(secret, result.stdout)

    def test_redaction_does_not_echo_arbitrary_fields(self):
        raw = '''Error: HTTP 403 https://alice:pw@private.test/?key=url-secret
Headers: {"Cookie":"session=cookie-secret","TraceID":"header-secret"}
''' + json.dumps({
            "error": {
                "code": 403,
                "status": "INTERNAL_ACCOUNT_LABEL",
                "message": "user@private.test /Users/private/project 192.0.2.123",
                "details": ["nested-secret"],
            }
        })
        result = run(raw)
        self.assert_report(result, "权限或访问受限")
        for secret in ("private", "192.0.2.123", "INTERNAL_ACCOUNT_LABEL", "secret", "Cookie"):
            self.assertNotIn(secret, result.stdout)

    def test_known_errors(self):
        cases = [
            ("Error: HTTP 429 Too Many Requests", "请求频率或配额受限"),
            ('{"error":{"status":"RESOURCE_EXHAUSTED"}}', "请求频率或配额受限"),
            ("Error: HTTP 401 Unauthorized", "登录或身份验证失败"),
            ("Error: HTTP 503 Service Unavailable", "服务端暂时异常"),
            ("Error: dial tcp: lookup private.local: no such host", "DNS 解析失败"),
            ("Error: x509: certificate signed by unknown authority", "TLS 证书验证失败"),
            ("Error: context deadline exceeded", "连接或请求超时"),
            ("Error: HTTP 400 Bad Request", "请求失败，具体原因待确认"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assert_report(run(raw), expected)

    def test_header_and_unknown_text_are_never_evidence(self):
        result = run('Headers: {"X":"HTTP 429", "X-Two":"User location is not supported for the API use."}\nprivate prompt')
        self.assert_report(result, "未识别到可分类的错误")
        self.assertNotIn("429", result.stdout)
        self.assertNotIn("private prompt", result.stdout)

    def test_empty_error_line_does_not_read_following_headers(self):
        raw = 'Error:\nHeaders: {"X":"User location is not supported for the API use."}'
        self.assert_report(run(raw), "未识别到可分类的错误")

    def test_clipboard_mode_reads_macos_clipboard_and_handles_failure(self):
        spec = importlib.util.spec_from_file_location("agy_doctor", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        raw = b"Error: HTTP 429 Too Many Requests"
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=raw)) as read:
            self.assertEqual(module.read_input(clipboard=True), raw.decode())
            read.assert_called_once_with(["/usr/bin/pbpaste"], capture_output=True, check=True, timeout=5)
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("pbpaste", 5)):
            with self.assertRaisesRegex(ValueError, "无法读取剪贴板"):
                module.read_input(clipboard=True)

    def test_empty_and_oversized_input_are_rejected(self):
        for raw, expected in [(" \n", "输入为空"), ("x" * (1024 * 1024 + 1), "输入过大")]:
            with self.subTest(expected=expected):
                result = run(raw)
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
