"""只从 Antigravity 当前日志文件的新增区间提取可脱敏的错误。"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

from agy_debug import KNOWN_STATUSES, classify


MAX_DELTA_BYTES = 256 * 1024
ANCHOR_BYTES = 128
EXECUTOR_PREFIX = re.compile(
    r"^(?:ERROR: logging before google\.Init:[ \t]+)?"
    r"E[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?[ \t]+[0-9]+[ \t]+"
    r"(?:[A-Za-z0-9_./-]+/)?errorreport\.go:[0-9]+\][ \t]+"
    r"agent executor error:[ \t]*"
)
STATUS_CODE = re.compile(r"(?:^|: )([A-Z_]+) \(code ([45][0-9]{2})\):[ \t]*(.*)$")


@dataclass(frozen=True)
class LogCursor:
    path: Path
    device: int
    inode: int
    offset: int
    anchor: bytes


def open_log(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    return os.fdopen(descriptor, "rb")


def mark(path=None):
    """在发请求前记下同一文件的末尾位置，保留少量内存字节检查截断。"""
    if path is None:
        path = Path.home() / "Library" / "Logs" / "Antigravity" / "language_server.log"
    try:
        with open_log(path) as log:
            info = os.fstat(log.fileno())
            if not stat.S_ISREG(info.st_mode):
                return None
            count = min(info.st_size, ANCHOR_BYTES)
            log.seek(info.st_size - count)
            anchor = log.read(count)
            if len(anchor) != count:
                return None
            return LogCursor(path, info.st_dev, info.st_ino, info.st_size, anchor)
    except OSError:
        return None


def appended_lines(cursor):
    if cursor is None:
        return ()
    try:
        with open_log(cursor.path) as log:
            info = os.fstat(log.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or (info.st_dev, info.st_ino) != (cursor.device, cursor.inode)
                or not cursor.offset <= info.st_size <= cursor.offset + MAX_DELTA_BYTES
            ):
                return ()
            log.seek(cursor.offset - len(cursor.anchor))
            if log.read(len(cursor.anchor)) != cursor.anchor:
                return ()
            new_bytes = log.read(info.st_size - cursor.offset)
            if len(new_bytes) != info.st_size - cursor.offset:
                return ()
    except OSError:
        return ()

    # 去掉尚未写完整的最后一行和测试前已经开始写的第一行。
    lines = new_bytes.split(b"\n")
    if cursor.anchor and not cursor.anchor.endswith(b"\n"):
        lines = lines[1:]
    if not lines or EXECUTOR_PREFIX.match(lines[-1].decode("utf-8", errors="replace")):
        return ()
    return lines[:-1]


def read_new_error(cursor):
    """只有单条可信的终止记录才自动归入这一轮应用结果。"""
    details = []
    for line in appended_lines(cursor):
        text = line.decode("utf-8", errors="replace").rstrip("\r")
        match = EXECUTOR_PREFIX.match(text)
        if match:
            details.append(text[match.end():])
            if len(details) > 1:
                return None
    if not details:
        return None

    detail = details[0]
    signal = STATUS_CODE.search(detail)
    code = int(signal[2]) if signal else None
    status = signal[1] if signal and signal[1] in KNOWN_STATUSES else None
    message = signal[3] if signal else detail
    category = classify(code, status, message.lower())
    if code is None and category in ("unknown", "unrecognized"):
        return None

    # 调用者只会收到已知分类、状态和范围校验过的数字。
    return {"source": "local_log", "category": category, "http": None, "api_code": code, "status": status}
