"""有界的 macOS 网络探测和脱敏快照。"""

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import re
import subprocess

from agy_debug import DIAGNOSES, KNOWN_STATUSES, error_codes


HOSTS = ("daily-cloudcode-pa.googleapis.com", "cloudcode-pa.googleapis.com")
SNAPSHOT_VERSION = 1
DNS_LABELS = {
    "a": "返回 IPv4",
    "aaaa": "返回 IPv6",
    "a_and_aaaa": "返回 IPv4 和 IPv6",
    "no_answer": "无 IP 结果",
    "timeout": "解析超时",
    "unavailable": "无法探测",
}
TLS_LABELS = {
    "verified": "握手及证书验证通过",
    "certificate_error": "证书验证失败",
    "handshake_error": "TLS 握手失败",
    "timeout": "未在时限内确认握手",
    "dns_error": "无法解析域名",
    "connection_error": "TCP 连接失败",
    "unverified": "未确认 TLS 连接",
    "unavailable": "无法探测",
}
APP_LABELS = {
    "confirmed_success": "用户确认 Agent 成功回复",
    "not_tested": "未采集应用测试结果",
}


def dns_result(host):
    try:
        process = subprocess.run(
            ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", host],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=4,
        )
    except subprocess.TimeoutExpired:
        return "timeout"
    except OSError:
        return "unavailable"
    if process.returncode:
        return "unavailable"

    families = set()
    for value in re.findall(r"^ip(?:v6)?_address:[ \t]*(\S+)", process.stdout, re.MULTILINE):
        try:
            families.add(ipaddress.ip_address(value).version)
        except ValueError:
            continue
    return {(): "no_answer", (4,): "a", (6,): "aaaa", (4, 6): "a_and_aaaa"}[tuple(sorted(families))]


def tls_result(process):
    fields = re.fullmatch(r"([0-9]{3}) (\d+(?:\.\d+)?) (\d+)\s*", process.stdout)
    if process.returncode == 60:
        return "certificate_error", None
    if fields and fields[3] == "0":
        code = int(fields[1])
        valid_http = 100 <= code <= 599
        if valid_http or float(fields[2]) > 0:
            return "verified", code if valid_http else None
    return {
        6: "dns_error",
        7: "connection_error",
        28: "timeout",
        35: "handshake_error",
        51: "certificate_error",
    }.get(process.returncode, "unverified"), None


def probe(host):
    dns = dns_result(host)
    try:
        process = subprocess.run(
            [
                "/usr/bin/curl", "--disable", "--noproxy", "*", "--proto", "=https",
                "--head", "--silent", "--output", "/dev/null",
                "--connect-timeout", "4", "--max-time", "7",
                "--write-out", "%{http_code} %{time_appconnect} %{ssl_verify_result}\n",
                f"https://{host}/",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8,
        )
        tls, http = tls_result(process)
    except subprocess.TimeoutExpired:
        tls, http = "timeout", None
    except OSError:
        tls, http = "unavailable", None
    return {"dns": dns, "tls": tls, "http": http}


def app_observation(source):
    return {"source": source, "category": None, "http": None, "api_code": None, "status": None}


def capture(app):
    with ThreadPoolExecutor(max_workers=len(HOSTS)) as pool:
        probes = dict(zip(HOSTS, pool.map(probe, HOSTS)))
    return {"version": SNAPSHOT_VERSION, "app": app, "probes": probes}


def valid_code(value, min_code):
    return value is None or (type(value) is int and min_code <= value <= 599)


def validate_snapshot(snapshot):
    """导入的快照只接受固定字段、枚举和状态码。"""
    try:
        app = snapshot["app"]
        probes = snapshot["probes"]
        if (
            set(snapshot) != {"version", "app", "probes"}
            or type(snapshot["version"]) is not int
            or snapshot["version"] != SNAPSHOT_VERSION
            or set(probes) != set(HOSTS)
            or set(app) != {"source", "category", "http", "api_code", "status"}
        ):
            raise ValueError
        source = app["source"]
        if source == "debug_info":
            if (
                app["category"] not in DIAGNOSES
                or not valid_code(app["http"], 400)
                or not valid_code(app["api_code"], 400)
                or (app["status"] is not None and app["status"] not in KNOWN_STATUSES)
            ):
                raise ValueError
        elif source not in APP_LABELS or app != app_observation(source):
            raise ValueError
        for row in probes.values():
            if (
                set(row) != {"dns", "tls", "http"}
                or row["dns"] not in DNS_LABELS
                or row["tls"] not in TLS_LABELS
                or not valid_code(row["http"], 100)
            ):
                raise ValueError
            if row["http"] is not None and row["tls"] != "verified":
                raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError("快照格式无效。请使用当前版本的 capture 重新采集。") from None


def format_app(app):
    if app["source"] != "debug_info":
        return APP_LABELS[app["source"]]
    title = DIAGNOSES[app["category"]][0]
    codes = error_codes(app)
    return f"{title}（{codes}）" if codes else title


def app_comparison(before, after):
    if after["source"] == "not_tested" or after["category"] == "unrecognized":
        return "缺少切换后的应用测试证据。请用同一账号、模型和最小提示词重试。"
    before_error = before["source"] == "debug_info" and before["category"] != "unrecognized"
    if after["source"] == "confirmed_success":
        if before_error:
            return "应用测试恢复。切换前有应用报错，切换后由用户确认成功回复。"
        return "切换后用户确认应用可用。切换前缺少可分类的应用报错。"
    if before_error and before["category"] == after["category"]:
        return "切换后仍有应用报错，诊断类别相同。"
    if before_error:
        return "切换后仍有应用报错，但诊断类别发生变化。"
    return "切换后记录到应用报错。"


def compare(before, after):
    validate_snapshot(before)
    validate_snapshot(after)
    before_app, after_app = before["app"], after["app"]
    lines = [
        "# Antigravity 网络对比脱敏报告",
        "",
        f"**应用结论**　{app_comparison(before_app, after_app)}",
        "",
        "| 检查 | 切换前 | 切换后 |",
        "| --- | --- | --- |",
        f"| Antigravity 应用测试 | {format_app(before_app)} | {format_app(after_app)} |",
    ]
    network_changed = before["probes"] != after["probes"]
    for host in HOSTS:
        old, new = before["probes"][host], after["probes"][host]
        lines.extend([
            f"| `{host}` DNS | {DNS_LABELS[old['dns']]} | {DNS_LABELS[new['dns']]} |",
            f"| `{host}` TLS | {TLS_LABELS[old['tls']]} | {TLS_LABELS[new['tls']]} |",
            f"| `{host}` HTTP | {format_http(old['http'])} | {format_http(new['http'])} |",
        ])
    lines.extend([
        "",
        "**网络探测**　" + ("至少一项结果发生变化。" if network_changed else "本次采集的结果一致。"),
        "",
        "DNS 使用 macOS 系统解析；TLS 使用系统 curl 经当前路由访问公开 Google API 根路径，不携带账号凭据。"
        "系统级 VPN/TUN 可能参与路由，探测会忽略 HTTP 代理设置。"
        "HTTP 401、403、404 等状态可证明探测收到响应，应用是否可用以应用测试为准。",
        "",
        "节点由用户在外部切换。探测结果不能确认应用看到的出口 IP、账号地区或节点变更是否造成恢复。",
        "",
    ])
    return "\n".join(lines)


def format_http(code):
    return f"HTTP {code}" if code is not None else "未收到可验证的 HTTP 响应"
