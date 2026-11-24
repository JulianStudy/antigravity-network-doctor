"""离线读取 Antigravity 调试信息，输出中文 Markdown 脱敏诊断。"""

import html
import json
import re
import subprocess
import sys


MAX_INPUT_BYTES = 1024 * 1024
KNOWN_STATUSES = frozenset({
    "DEADLINE_EXCEEDED", "FAILED_PRECONDITION", "INTERNAL",
    "INVALID_ARGUMENT", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED",
    "UNAUTHENTICATED", "UNAVAILABLE",
})
ERROR_LINE = re.compile(r"^[ \t]*Error[ \t]*:[ \t]*(.*)$", re.IGNORECASE | re.MULTILINE)
HTTP_CODE = re.compile(r"^HTTP\s+([45][0-9]{2})\b", re.IGNORECASE)
JSON_START = re.compile(r"^[ \t]*\{", re.MULTILINE)
LOCATION_MESSAGE = "user location is not supported for the api use"


def server_error(text):
    """读取调试输出中独立 JSON 对象里的 error 字段。"""
    decoder = json.JSONDecoder()
    for match in JSON_START.finditer(text):
        try:
            payload, _ = decoder.raw_decode(text, match.end() - 1)
        except (ValueError, RecursionError):
            continue
        error = payload.get("error")
        if isinstance(error, dict):
            return error
    return {}


DIAGNOSES = {
    "location": (
        "服务端拒绝当前请求的地区条件",
        "请求已到达服务端。Google 返回了地区限制错误。此日志无法区分判定依据来自网络出口或账号地区。",
        "核对 Antigravity 支持地区及 Google 账号关联地区。若都符合且可复现，向官方支持提供报错时间和追踪编号。",
    ),
    "quota": (
        "请求频率或配额受限",
        "服务端返回了频率限制或资源耗尽信号。",
        "在 Antigravity 里查看当前模型用量与重置时间，再按提示重试。",
    ),
    "authentication": (
        "登录或身份验证失败",
        "服务端返回了认证失败信号。",
        "确认 Antigravity 登录的是预期账号，并在应用内查看是否需要重新登录。",
    ),
    "permission": (
        "权限或访问受限",
        "服务端拒绝了该请求，现有信息不足以确定具体限制。",
        "检查账号权限、组织策略和当前模型可用性。",
    ),
    "timeout": (
        "连接或请求超时",
        "请求未能在规定时间内完成。",
        "重试一个最小请求。若反复发生，检查连接质量与代理路径。",
    ),
    "server": (
        "服务端暂时异常",
        "返回的状态指向服务端错误或服务不可用。",
        "稍后重试。若持续出现，可用其他可用模型做对照。",
    ),
    "dns": (
        "DNS 解析失败",
        "错误信息表明请求路径上的域名解析失败。",
        "检查当前网络和代理使用的 DNS，再重试同一请求。",
    ),
    "certificate": (
        "TLS 证书验证失败",
        "错误信息表明 TLS 证书验证未通过。",
        "检查系统时间、证书信任设置和网络是否经过 HTTPS 检查。",
    ),
    "unknown": (
        "请求失败，具体原因待确认",
        "提取到错误信息，但缺少可确认具体原因的信号。",
        "重新使用 Antigravity 的 Copy debug info 获取完整信息，或记录可复现的步骤。",
    ),
    "unrecognized": (
        "未识别到可分类的错误",
        "输入中没有可识别的 Antigravity 错误字段。",
        "请粘贴 Copy debug info 复制的完整内容。",
    ),
}


def classify(code, status, message):
    if LOCATION_MESSAGE in message:
        return "location"
    if code == 429 or status == "RESOURCE_EXHAUSTED":
        return "quota"
    if code == 401 or status == "UNAUTHENTICATED":
        return "authentication"
    if code == 403 or status == "PERMISSION_DENIED":
        return "permission"
    if code in (408, 504) or status == "DEADLINE_EXCEEDED" or any(
        marker in message for marker in (
            "deadline exceeded", "timed out", "i/o timeout", "timeout awaiting",
        )
    ):
        return "timeout"
    if (code is not None and code >= 500) or status in ("UNAVAILABLE", "INTERNAL"):
        return "server"
    if "no such host" in message or "could not resolve host" in message:
        return "dns"
    if any(marker in message for marker in ("x509:", "certificate verify failed", "certificate verification failed")):
        return "certificate"
    if code is not None or status or message:
        return "unknown"
    return "unrecognized"


def parse_debug(raw):
    text = html.unescape(raw.replace("\r\n", "\n"))
    text = re.sub(r"\\[ \t]*$", "", text, flags=re.MULTILINE)
    line = ERROR_LINE.search(text)
    line_message = line.group(1).strip() if line else ""
    error = server_error(text)
    body_code = error.get("code")
    http_match = HTTP_CODE.match(line_message)
    http_code = int(http_match.group(1)) if http_match else None
    body_code = body_code if type(body_code) is int and 400 <= body_code <= 599 else None
    status = error.get("status")
    status = status if isinstance(status, str) and status in KNOWN_STATUSES else None
    body_message = error.get("message")
    message = body_message if isinstance(body_message, str) and body_message.strip() else line_message
    return {
        "source": "debug_info",
        "category": classify(body_code or http_code, status, message.lower()),
        "http": http_code,
        "api_code": body_code,
        "status": status,
    }


def error_codes(error):
    http_code, body_code, status = (error[key] for key in ("http", "api_code", "status"))

    # 只输出固定文案、经范围校验的数字和预先列出的状态值。
    codes = []
    if http_code is not None:
        codes.append(f"HTTP {http_code}")
    if body_code is not None and body_code != http_code:
        codes.append(f"服务端错误码 {body_code}")
    if status:
        codes.append(status)
    return " / ".join(codes)


def make_report(raw):
    error = parse_debug(raw)
    title, evidence, next_step = DIAGNOSES[error["category"]]
    return "\n".join([
        "# Antigravity 脱敏诊断报告",
        "",
        f"- **诊断**　{title}",
        f"- **错误信号**　{error_codes(error) or '无可保留的结构化状态码'}",
        f"- **依据**　{evidence}",
        f"- **下一步**　{next_step}",
        "",
    ])


def read_input(clipboard):
    if clipboard:
        try:
            result = subprocess.run(
                ["/usr/bin/pbpaste"], capture_output=True, check=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            raise ValueError("无法读取剪贴板。请直接粘贴到终端，然后按 Control+D。") from None
        data = result.stdout
    else:
        if sys.stdin.isatty():
            print("请粘贴 Antigravity 的 debug info，然后按回车，再按 Control+D。", file=sys.stderr)
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)

    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("输入过大。请提供 1 MiB 以内的调试信息。")
    text = data.decode("utf-8-sig", errors="replace")
    if not text.strip():
        raise ValueError("输入为空。请复制或粘贴 Antigravity 的 debug info。")
    return text
