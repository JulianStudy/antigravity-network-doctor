#!/usr/bin/env python3
"""采集 macOS DNS、TLS 和 Antigravity 应用结果，生成脱敏报告。"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from agy_debug import MAX_INPUT_BYTES, make_report, parse_debug, read_input
from agy_network import app_observation, capture, compare


def read_snapshot(path):
    try:
        with path.open("rb") as file:
            data = file.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ValueError
        return json.loads(data)
    except (OSError, ValueError, RecursionError):
        raise ValueError("无法读取快照。请确认文件存在，并由 capture 命令生成。") from None


def terminal_prompt(prompt):
    print(prompt, file=sys.stderr, flush=True)
    return input().strip().lower()


def prompt_app(stage, previous_digest=None):
    while True:
        print(
            f"在 Antigravity 发一条最小测试消息（{stage}）。若失败，重新点 Copy debug info。",
            file=sys.stderr,
        )
        choice = terminal_prompt("按回车读取本轮报错，输入 s 记录成功，输入 n 跳过应用测试 > ")
        if choice in ("s", "n"):
            return app_observation("confirmed_success" if choice == "s" else "not_tested"), None
        if not choice:
            try:
                raw = read_input(clipboard=True)
            except ValueError:
                print("无法读取剪贴板报错。请重新复制，或输入 n 跳过。", file=sys.stderr)
                continue
            digest = hashlib.sha256(raw.strip().encode("utf-8")).digest()
            if digest == previous_digest:
                print("剪贴板与切换前相同。请复制本轮调试信息，或输入 n 跳过。", file=sys.stderr)
                continue
            result = parse_debug(raw)
            if result["category"] == "unrecognized":
                print("剪贴板里未识别到报错，请重新复制或跳过。", file=sys.stderr)
                continue
            return result, digest
        else:
            print("请输入 s、n 或直接按回车。", file=sys.stderr)


def wizard():
    before_app, before_digest = prompt_app("切换前")
    print("正在采集切换前的系统路由和系统代理，每条可用路径三次…", file=sys.stderr)
    before = capture(before_app)
    terminal_prompt("请切换节点，等待网络连接稳定，然后按回车继续 > ")
    after, _ = prompt_app("切换后，保持相同账号、模型和提示词", before_digest)
    print("正在采集切换后的系统路由和系统代理，每条可用路径三次…", file=sys.stderr)
    report = compare(before, capture(after))
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="antigravity-report-", suffix=".md",
        dir=Path.cwd(), delete=False,
    ) as file:
        file.write(report)
    print(f"脱敏报告已保存到 {Path(file.name).name}", file=sys.stderr)
    print(report, end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clipboard", action="store_true", help="旧版用法，只解析剪贴板中的 debug info。")
    commands = parser.add_subparsers(dest="command")
    debug = commands.add_parser("debug", help="只解析调试信息，不发起网络探测。")
    debug.add_argument("--clipboard", action="store_true", help="从 macOS 剪贴板读取。")
    scan = commands.add_parser("capture", help="一次采集并输出脱敏 JSON 快照。")
    source = scan.add_mutually_exclusive_group()
    source.add_argument("--clipboard", action="store_true", help="读取刚复制的 Copy debug info。")
    source.add_argument("--debug-stdin", action="store_true", help="从标准输入读取 debug info。")
    source.add_argument("--success", action="store_true", help="记录用户已经确认 Agent 成功回复。")
    diff = commands.add_parser("compare", help="用两份 JSON 快照生成 Markdown 对比报告。")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    commands.add_parser("wizard", help="交互式完成两次采集，并将 Markdown 报告存到当前目录。")
    args = parser.parse_args()
    try:
        if args.command == "wizard":
            wizard()
        elif args.command == "capture":
            if args.clipboard or args.debug_stdin:
                app = parse_debug(read_input(args.clipboard))
            else:
                app = app_observation("confirmed_success" if args.success else "not_tested")
            print(json.dumps(capture(app), ensure_ascii=False, indent=2))
        elif args.command == "compare":
            print(compare(read_snapshot(args.before), read_snapshot(args.after)), end="")
        else:
            print(make_report(read_input(args.clipboard)), end="")
    except (EOFError, KeyboardInterrupt):
        print("\n采集已取消。", file=sys.stderr)
        return 130
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    except OSError:
        print("无法保存报告，请检查当前目录的写入权限。", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
