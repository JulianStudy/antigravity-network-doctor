"""有界的 macOS 网络探测和脱敏快照。"""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import re
from statistics import median
import subprocess

from agy_debug import DIAGNOSES, KNOWN_STATUSES, error_codes


HOSTS = ("daily-cloudcode-pa.googleapis.com", "cloudcode-pa.googleapis.com")
SNAPSHOT_VERSION = 3
SAMPLE_COUNT = 3
ROUTES = {"direct": "系统路由", "proxy": "系统代理"}
PROXY_LABELS = {
    "https": "已采集静态 HTTPS 代理",
    "socks": "已采集静态 SOCKS 代理",
    "automatic": "已启用 PAC 或自动发现，本工具未采集该代理",
    "disabled": "未启用静态代理",
    "invalid": "静态代理地址或端口无效",
    "unavailable": "无法读取系统代理配置",
    "legacy": "旧版快照未采集代理",
}
DNS_LABELS = {
    "delegated": "目标域名由代理处理，本机未验证",
    "a": "返回 IPv4",
    "aaaa": "返回 IPv6",
    "a_and_aaaa": "返回 IPv4 和 IPv6",
    "no_answer": "无 IP 结果",
    "timeout": "解析超时",
    "unavailable": "无法探测",
}
TCP_LABELS = {
    "connected": "已连接",
    "unconfirmed": "未确认连接",
    "unavailable": "无数据",
}
TLS_LABELS = {
    "proxy_rejected": "代理拒绝 CONNECT",
    "proxy_dns_error": "无法解析代理地址",
    "proxy_handshake_error": "代理协商失败",
    "verified": "握手及证书验证通过",
    "certificate_error": "证书验证失败",
    "handshake_error": "TLS 握手失败",
    "timeout": "未在时限内确认握手",
    "dns_error": "无法解析域名",
    "connection_error": "TCP 连接失败",
    "unverified": "未确认 TLS 连接",
    "unavailable": "无法探测",
}
PROXY_FAILURES = {5: "proxy_dns_error", 97: "proxy_handshake_error"}
PROXY_TLS_STATES = {"proxy_rejected", *PROXY_FAILURES.values()}
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


def system_proxy():
    """读取 macOS 当前代理设置，端点只用于本轮 curl。"""
    try:
        result = subprocess.run(
            ["/usr/sbin/scutil", "--proxy"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable", None
    if result.returncode:
        return "unavailable", None

    settings = dict(re.findall(r"^  ([A-Za-z]+) : ([^\r\n]+)$", result.stdout, re.MULTILINE))
    if any(settings.get(key) == "1" for key in ("ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable")):
        return "automatic", None
    for prefix, scheme in (("HTTPS", "http"), ("SOCKS", "socks5h")):
        if settings.get(f"{prefix}Enable") == "1":
            host = settings.get(f"{prefix}Proxy", "").strip().strip("[]")
            port = settings.get(f"{prefix}Port", "")
            if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
                return "invalid", None
            if ":" in host:
                try:
                    host = f"[{ipaddress.IPv6Address(host)}]"
                except ValueError:
                    return "invalid", None
            elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
                return "invalid", None
            return prefix.lower(), f"{scheme}://{host}:{int(port)}"
    return "disabled", None


def tls_result(process):
    fields = process.stdout.split()
    if process.returncode in (51, 60):
        return "certificate_error", None
    if len(fields) >= 3 and fields[2] == "0":
        code = curl_http_code(fields[0])
        if code is not None or positive_duration(fields[1]):
            return "verified", code
    return {
        5: "dns_error",
        6: "dns_error",
        7: "connection_error",
        28: "timeout",
        35: "handshake_error",
    }.get(process.returncode, "unverified"), None


def curl_http_code(value):
    return int(value) if re.fullmatch(r"[1-5][0-9]{2}", value) else None


def positive_duration(value):
    return bool(re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,9})?", value) and float(value) > 0)


def probe(host, proxy_url=None):
    dns = "delegated" if proxy_url else dns_result(host)
    route_options = ["--proxy", proxy_url, "--noproxy", ""] if proxy_url else ["--noproxy", "*"]
    try:
        process = subprocess.run(
            [
                "/usr/bin/curl", "--disable", *route_options, "--proto", "=https",
                "--head", "--silent", "--output", "/dev/null",
                "--connect-timeout", "4", "--max-time", "7", "--write-out",
                "%{http_code} %{time_appconnect} %{ssl_verify_result} "
                "%{time_connect} %{http_connect} %{time_total}\n",
                f"https://{host}/",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8,
        )
    except subprocess.TimeoutExpired:
        return sample(dns, "timeout")
    except OSError:
        return sample(dns, "unavailable", tcp="unavailable")

    if proxy_url and process.returncode in PROXY_FAILURES:
        tls, http = PROXY_FAILURES[process.returncode], None
    else:
        tls, http = tls_result(process)
    fields = process.stdout.split()
    if len(fields) != 6:
        return sample(dns, tls, http=http)
    _, _, _, connect_time, connect_code, elapsed = fields
    connect_http = curl_http_code(connect_code) if proxy_url else None
    tcp = "connected" if positive_duration(connect_time) or tls == "verified" or connect_http else "unconfirmed"
    if connect_http is not None and not 200 <= connect_http <= 299:
        tls, http = "proxy_rejected", None
    elapsed_ms = round(float(elapsed) * 1000) if positive_duration(elapsed) and float(elapsed) <= 8 else None
    return sample(dns, tls, tcp=tcp, http=http, connect_http=connect_http, elapsed_ms=elapsed_ms)


def sample(dns, tls, *, tcp="unconfirmed", http=None, connect_http=None, elapsed_ms=None):
    return dict(dns=dns, tcp=tcp, tls=tls, http=http, connect_http=connect_http, elapsed_ms=elapsed_ms)


def app_observation(source):
    return {"source": source, "category": None, "http": None, "api_code": None, "status": None}


def capture(app):
    proxy_state, proxy_url = system_proxy()
    routes = {"direct": None}
    if proxy_url:
        routes["proxy"] = proxy_url
    probes = {host: {route: [] for route in ROUTES} for host in HOSTS}

    # 三轮顺序执行。每轮并行探测不同域名和路径，各请求都重新建立连接。
    with ThreadPoolExecutor(max_workers=len(HOSTS) * len(routes)) as pool:
        for _ in range(SAMPLE_COUNT):
            tasks = {
                (host, route): pool.submit(probe, host, endpoint)
                for host in HOSTS for route, endpoint in routes.items()
            }
            for (host, route), task in tasks.items():
                probes[host][route].append(task.result())

    return {"version": SNAPSHOT_VERSION, "app": app, "proxy_state": proxy_state, "probes": probes}


def valid_code(value, min_code, max_code=599):
    return value is None or (type(value) is int and min_code <= value <= max_code)


def validate_app(app, version):
    if set(app) != {"source", "category", "http", "api_code", "status"}:
        raise ValueError
    source = app["source"]
    if source == "debug_info" or (source == "local_log" and version >= 3):
        if (
            app["category"] not in DIAGNOSES
            or (source == "local_log" and (app["http"] is not None or app["category"] == "unrecognized"))
            or not valid_code(app["http"], 400)
            or not valid_code(app["api_code"], 400)
            or (app["status"] is not None and app["status"] not in KNOWN_STATUSES)
        ):
            raise ValueError
    elif source not in APP_LABELS or app != app_observation(source):
        raise ValueError


def adapt_legacy(snapshot):
    if set(snapshot) != {"version", "app", "probes"} or set(snapshot["probes"]) != set(HOSTS):
        raise ValueError
    probes = {}
    for host, row in snapshot["probes"].items():
        if (
            set(row) != {"dns", "tls", "http"}
            or row["dns"] == "delegated" or row["tls"] in PROXY_TLS_STATES
        ):
            raise ValueError
        probes[host] = {"direct": [sample(row["dns"], row["tls"], tcp="unavailable", http=row["http"])], "proxy": []}
    return {"version": SNAPSHOT_VERSION, "app": snapshot["app"], "proxy_state": "legacy", "probes": probes}


def validate_sample(row, route):
    if (
        set(row) != {"dns", "tcp", "tls", "http", "connect_http", "elapsed_ms"}
        or row["dns"] not in DNS_LABELS
        or row["tcp"] not in TCP_LABELS
        or row["tls"] not in TLS_LABELS
        or not valid_code(row["http"], 100)
        or not valid_code(row["connect_http"], 100)
        or not valid_code(row["elapsed_ms"], 0, 8000)
        or (row["http"] is not None and row["tls"] != "verified")
        or (row["dns"] == "delegated") != (route == "proxy")
        or (route == "direct" and (row["connect_http"] is not None or row["tls"] in PROXY_TLS_STATES))
    ):
        raise ValueError


def validated_snapshot(snapshot):
    """读取 v1 至 v3 快照，渲染时仅使用受限的枚举和数字。"""
    try:
        version = snapshot["version"]
        if type(version) is not int or version not in (1, 2, SNAPSHOT_VERSION):
            raise ValueError
        if version == 1:
            snapshot = adapt_legacy(snapshot)
        if set(snapshot) != {"version", "app", "proxy_state", "probes"}:
            raise ValueError
        validate_app(snapshot["app"], version)
        state = snapshot["proxy_state"]
        probes = snapshot["probes"]
        if state not in PROXY_LABELS or (state == "legacy" and version != 1) or set(probes) != set(HOSTS):
            raise ValueError
        expected = {"direct": 1 if version == 1 else SAMPLE_COUNT, "proxy": SAMPLE_COUNT if state in ("https", "socks") else 0}
        for routes in probes.values():
            if set(routes) != set(ROUTES):
                raise ValueError
            for route, rows in routes.items():
                if not isinstance(rows, list) or len(rows) != expected[route]:
                    raise ValueError
                for row in rows:
                    validate_sample(row, route)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError("快照格式无效。请使用 capture 重新采集。") from None
    return snapshot


def format_app(app):
    if app["source"] in APP_LABELS:
        return APP_LABELS[app["source"]]
    title = DIAGNOSES[app["category"]][0]
    codes = error_codes(app)
    fields = [codes] if codes else []
    if app["source"] == "local_log":
        fields.append("来源为本地日志")
    return f"{title}（{' · '.join(fields)}）" if fields else title


def app_comparison(before, after):
    if after["source"] == "not_tested" or after["category"] == "unrecognized":
        return "缺少切换后的应用测试证据。请用同一账号、模型和最小提示词重试。"
    before_error = before["category"] not in (None, "unrecognized")
    if after["source"] == "confirmed_success":
        if before["source"] == "confirmed_success":
            return "两轮应用测试均收到 Agent 回复。"
        if before_error:
            return "应用测试恢复。切换前有应用报错，切换后由用户确认成功回复。"
        return "切换后用户确认应用可用。切换前缺少可分类的应用报错。"
    if before_error and before["category"] == after["category"]:
        return "切换后仍有应用报错，诊断类别相同。"
    if before_error:
        return "切换后仍有应用报错，但诊断类别发生变化。"
    return "切换后记录到应用报错。"


def format_counts(values, labels):
    return "、".join(f"{labels[value]} {count}/{len(values)}" for value, count in Counter(values).items())


def format_codes(values):
    codes = sorted({code for code in values if code is not None})
    labels = {code: f"HTTP {code}" for code in codes}
    labels[None] = "无响应"
    return format_counts(values, labels)


def path_details(rows, proxy_state):
    if not rows:
        return PROXY_LABELS[proxy_state]
    dns = format_counts([row["dns"] for row in rows], DNS_LABELS)
    tcp = format_counts([row["tcp"] for row in rows], TCP_LABELS)
    tls = format_counts([row["tls"] for row in rows], TLS_LABELS)
    http = format_codes([row["http"] for row in rows])
    details = [f"DNS {dns}", f"TCP {tcp}", f"TLS {tls}", http]
    connect_codes = [row["connect_http"] for row in rows]
    if any(code is not None for code in connect_codes):
        details.append(f"代理 CONNECT {format_codes(connect_codes)}")
    timings = [row["elapsed_ms"] for row in rows if row["http"] is not None and row["elapsed_ms"] is not None]
    if timings:
        details.append(f"HTTP 响应耗时中位数 {round(median(timings))} ms（{len(timings)}/{len(rows)}）")
    return "<br>".join(details)


def compare(before, after):
    before, after = validated_snapshot(before), validated_snapshot(after)
    before_app, after_app = before["app"], after["app"]
    lines = [
        "# Antigravity 网络对比脱敏报告",
        "",
        "## Antigravity 应用实测",
        "",
        f"- **切换前**　{format_app(before_app)}",
        f"- **切换后**　{format_app(after_app)}",
        f"- **应用结论**　{app_comparison(before_app, after_app)}",
    ]
    if after_app["category"] in DIAGNOSES:
        _, evidence, next_step = DIAGNOSES[after_app["category"]]
        lines.extend([f"- **依据**　{evidence}", f"- **下一步**　{next_step}"])
    lines.extend([
        "",
        "## 网络双路径探测",
        "",
        f"- **代理状态（前 / 后）**　{PROXY_LABELS[before['proxy_state']]} / {PROXY_LABELS[after['proxy_state']]}",
        "",
        "| 域名与路径 | 切换前 | 切换后 |",
        "| --- | --- | --- |",
    ])
    for host in HOSTS:
        for route, label in ROUTES.items():
            old = path_details(before["probes"][host][route], before["proxy_state"])
            new = path_details(after["probes"][host][route], after["proxy_state"])
            lines.append(f"| `{host}` {label} | {old} | {new} |")
    lines.extend([
        "",
        "- **系统路由**　忽略应用层代理设置，仍可能经过 VPN/TUN。DNS 反映 macOS 系统解析结果。",
        "- **系统代理**　强制经检测到的静态代理访问。目标 DNS 交由代理，无法从本机独立验证。"
        "TCP 只代表与代理端点的连接，CONNECT 若有响应会单列。",
        "- **TLS 和 HTTP**　使用证书验证向公开 API 根路径发无认证 HEAD 请求。HTTP 404 也能表明收到了 HTTPS 响应。"
        "耗时统计仅包含收到 HTTP 响应的样本，包含连接过程与请求。Agent 是否可用以应用实测为准。",
        "- **判断范围**　这些探测无法确认 Antigravity 应用实际使用的代理、出口 IP 或账号地区，也无法单独证明节点切换造成了应用异常。",
        "",
    ])
    return "\n".join(lines)
