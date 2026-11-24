import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import agy_doctor
import agy_logs
import agy_network


PREFIX = "ERROR: logging before google.Init: E1124 22:10:05.327193    1234 errorreport.go:51] "
LOCATION = PREFIX + (
    "agent executor error: generating and executing: FAILED_PRECONDITION (code 400): "
    "User location is not supported for the API use. private-test@example.invalid"
)
QUOTA = PREFIX + "agent executor error: generating and executing: RESOURCE_EXHAUSTED (code 429): rejected"
DUPLICATE_CHANNEL = PREFIX + "generating and executing: FAILED_PRECONDITION (code 400): details"


class LogTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "language_server.log"

    def append(self, text):
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(text)

    def test_only_new_terminal_error_is_read_and_redacted(self):
        self.append(QUOTA + "\n")
        cursor = agy_logs.mark(self.path)
        self.append(LOCATION + "\n" + DUPLICATE_CHANNEL + "\n")
        result = agy_logs.read_new_error(cursor)
        self.assertEqual(result, {
            "source": "local_log", "category": "location", "http": None,
            "api_code": 400, "status": "FAILED_PRECONDITION",
        })
        self.assertNotIn("private-test", json.dumps(result))

    def test_no_match_for_old_messages_background_errors_or_partial_lines(self):
        self.append(LOCATION + "\n")
        cursor = agy_logs.mark(self.path)
        self.append(QUOTA.replace("errorreport.go", "background.go") + "\n" + QUOTA)
        self.assertIsNone(agy_logs.read_new_error(cursor))
        self.append("\n")
        self.assertEqual(agy_logs.read_new_error(cursor)["category"], "quota")

    def test_multiple_terminal_errors_require_manual_confirmation(self):
        self.append("")
        cursor = agy_logs.mark(self.path)
        self.append(QUOTA + "\n" + LOCATION + "\n")
        self.assertIsNone(agy_logs.read_new_error(cursor))

    def test_partial_second_terminal_record_prevents_automatic_attribution(self):
        self.append("")
        cursor = agy_logs.mark(self.path)
        self.append(QUOTA + "\n" + LOCATION)
        self.assertIsNone(agy_logs.read_new_error(cursor))

    def test_file_replacement_and_in_place_truncation_do_not_backfill(self):
        self.path.write_text(QUOTA + "\n")
        cursor = agy_logs.mark(self.path)
        self.path.write_text(LOCATION + "\n")
        self.assertIsNone(agy_logs.read_new_error(cursor))
        cursor = agy_logs.mark(self.path)
        self.path.rename(self.path.with_suffix(".old"))
        self.path.write_text(QUOTA + "\n")
        self.assertIsNone(agy_logs.read_new_error(cursor))

    def test_missing_log_and_bounded_window_fall_back(self):
        self.assertIsNone(agy_logs.read_new_error(agy_logs.mark(self.path)))
        self.append("")
        cursor = agy_logs.mark(self.path)
        self.append("x" * (agy_logs.MAX_DELTA_BYTES + 1) + "\n" + LOCATION + "\n")
        self.assertIsNone(agy_logs.read_new_error(cursor))

    def test_wizard_automatically_uses_new_error_before_clipboard(self):
        self.append(QUOTA + "\n")

        def fail_test_in_app():
            self.append(LOCATION + "\n")
            return ""

        with patch.object(agy_doctor, "mark", side_effect=lambda: agy_logs.mark(self.path)), patch(
            "builtins.input", side_effect=lambda: fail_test_in_app()
        ), patch.object(agy_doctor, "read_input") as clipboard, redirect_stderr(io.StringIO()):
            result, _ = agy_doctor.prompt_app("本轮实测")
        self.assertEqual(result["source"], "local_log")
        clipboard.assert_not_called()
        with patch.object(agy_network, "system_proxy", return_value=("disabled", None)), patch.object(
            agy_network, "probe", return_value=agy_network.sample("a", "verified", tcp="connected", http=404)
        ):
            snapshot = agy_network.capture(result)
        report = agy_network.compare(snapshot, snapshot)
        self.assertIn("本地日志", report)
        self.assertIn("服务端错误码 400", report)
        self.assertNotIn("private-test", report)

    def test_wizard_requests_copy_if_no_new_local_error(self):
        self.append(LOCATION + "\n")
        with patch.object(agy_doctor, "mark", side_effect=lambda: agy_logs.mark(self.path)), patch(
            "builtins.input", side_effect=["", "", "c"]
        ), patch.object(agy_doctor, "read_input", return_value="Error: HTTP 429") as clipboard, redirect_stderr(io.StringIO()) as notice:
            result, _ = agy_doctor.prompt_app("本轮实测")
        self.assertIn("Copy debug info", notice.getvalue())
        self.assertEqual(result["source"], "debug_info")
        clipboard.assert_called_once_with(clipboard=True)
        self.assertIn("输入 c", notice.getvalue())

    def test_explicit_success_does_not_override_with_background_error(self):
        self.append("")
        with patch.object(agy_doctor, "mark", side_effect=lambda: agy_logs.mark(self.path)), patch(
            "builtins.input", return_value="s"
        ), patch.object(agy_doctor, "read_new_error") as reader, redirect_stderr(io.StringIO()):
            result, _ = agy_doctor.prompt_app("本轮实测")
        self.assertEqual(result["source"], "confirmed_success")
        reader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
