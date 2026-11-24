# Antigravity Network Doctor

A macOS tool for comparing three samples per network path before and after a network change. It checks the system route and the configured static proxy, records Google Antigravity Agent results separately, and produces a redacted Markdown report in Chinese.

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

- **采样**　每轮对两个固定 Google API 域名分别测三次。每个路径显示各结果出现次数。耗时中位数只计算收到 HTTP 响应且有计时的样本，包含连接和请求。旧版快照仍可对比，会显示原来的一次采样与缺失字段。
- **系统路由**　使用 macOS 系统解析，再用 curl 发无认证 HTTPS HEAD 请求。该路径忽略应用层代理设置，仍可能经过 VPN/TUN。DNS 返回的地址可能是 TUN 提供的 Fake IP。
- **系统代理**　读取 macOS 当前静态 HTTPS 代理。没有配置时使用启用的静态 SOCKS 代理。探测强制经过该端点，不应用目标域名的代理例外。目标 DNS 交给代理，TCP 表示连接到代理；HTTPS CONNECT 响应单独显示。启用 PAC 或自动发现时，报告标记为未采集该路径。
- **TLS 与 HTTP**　默认验证目标证书。根路径返回 HTTP 404 仍可证明探测收到了 HTTPS 响应。
- **应用** 使用用户复制的 Antigravity debug info，或用户实测确认的回复。仅凭 DNS、TLS 和 HTTP 探测无法确认 Agent 可用、网络出口身份或账号地区。
- **脱敏** 使用固定中文文案、状态枚举和有限范围的数字重新生成快照与 Markdown。输出省略原始日志、追踪标识、账号信息、请求头、IP 地址和精确时间。工具把探测请求发给固定的 Google 域名，诊断数据留在本机。工具不会切换节点或修改网络设置。

## 测试

```bash
python3 -m unittest discover -s tests
```
