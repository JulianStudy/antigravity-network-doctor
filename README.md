# Antigravity Network Doctor

A macOS tool for comparing DNS, TLS, and Google Antigravity Agent behavior before and after a network change. It produces a redacted Markdown report in Chinese.

## 在 Mac 上使用

需要 Python 3.9 或以上版本。下载或克隆仓库后，在 Finder 中双击 **Compare Antigravity Network.command**，或在仓库目录运行：

```bash
python3 agy_doctor.py wizard
```

1. 在 Antigravity 里用当前模型发一条最小测试消息，例如「只回复 OK」。如果失败，点 **Copy debug info**，回到终端按回车。如果收到回复，输入 `s`。如果跳过应用测试，输入 `n`。
2. 等提示切换节点后，在 VPN 客户端切换，等连接稳定，再回到终端按回车。
3. 用同一账号、模型和提示词再试一次，记录这次的错误或成功。每次失败都要重新点 **Copy debug info**，以免使用剪贴板里的旧报错。
4. 工具在终端显示结果，并在当前目录保存一份 `antigravity-report-*.md`。

## 命令行分步采集

可以保存两份快照，稍后再对比：

```bash
# 切换前。先复制本轮的 Antigravity debug info。
python3 agy_doctor.py capture --clipboard > before.json

# 切换节点后，用同一账号和模型重试。收到回复时使用 --success。
python3 agy_doctor.py capture --success > after.json

python3 agy_doctor.py compare before.json after.json > antigravity-report-comparison.md
```

切换后仍报错时，重新复制调试信息并用 `capture --clipboard`。已有日志文件可以用 `capture --debug-stdin < debug.txt`。单独运行 `capture` 只测网络，并把应用结果标为未采集。

只想读调试信息时，用 `python3 agy_doctor.py debug --clipboard` 或 `python3 agy_doctor.py debug < debug.txt`。旧版的裸命令和顶部 `--clipboard` 仍可用。这些用法都在本地解析，不发网络探测请求。

## 怎样看报告

- **DNS** 记录 macOS 系统解析返回了哪个地址族。TUN 的 Fake IP 也可能形成有效的系统解析结果。
- **TLS** 使用系统 curl 验证证书，并对两个固定 Google API 域名的根路径发无认证的 HTTPS HEAD 请求。系统级 VPN/TUN 可能参与路由，curl 探测会忽略 HTTP 代理设置。根路径响应 HTTP 404 仍可证明探测收到 HTTPS 响应。
- **应用** 使用用户复制的 Antigravity debug info，或用户实测确认的回复。仅凭 DNS、TLS 和 HTTP 探测无法确认 Agent 可用、网络出口身份或账号地区。
- **脱敏** 使用固定中文文案、状态枚举和有限范围的数字重新生成快照与 Markdown。输出省略原始日志、追踪标识、账号信息、请求头、IP 地址和精确时间。工具把探测请求发给固定的 Google 域名，诊断数据留在本机。工具不会切换节点或修改网络设置。

## 测试

```bash
python3 -m unittest discover -s tests
```
