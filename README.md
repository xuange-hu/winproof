# WinProof · Windows 驻留取证与基线比对

> 不是又一个"清理工具"。它回答的是清理工具回答不了的那三个问题：
> **什么东西变了 · 什么时候变的 · 你刚才那个处置方式会不会被还原。**

零依赖：只要 Windows 自带的 PowerShell 5.1。不装 .NET SDK、不装 Node、不联网、不上传任何东西。
双击 `scan.bat` 就出一份自包含的 HTML 取证报告。

---

## 为什么需要它：一个真实的对照实验

我的 Edge 启动页被 `2345.pbgia.com` 劫持过两次。两次都用同一种"删掉 `startup_urls`"的手法处理，
结果一个复发、一个至今干净。差别不是运气，是两个可观测的结构差异：

| | Edge / Profile 1 | Chrome / Default |
|---|---|---|
| 修复备份 | `bak_20261010-221049` · 71,212 B · 含恶意 URL | `bak_20261010-152128` · 30,814 B · 含恶意 URL |
| 当前文件 | 145,715 B · 2026-10-14 21:58 | 30,745 B · 2026-10-14 13:09 |
| 当前 `startup_urls` | **`http://2345.pbgia.com/win23` 回来了** | 空 |
| 密封副本 | `startup_urls_edge_enclave` + `_verify`（4 个键） | 无 |
| `sync.preferences` | 开 | 关 |
| **结论** | **复发**（BR-05 高危） | **修复保持**（BR-07 正常） |

同一个处置动作，在两个结构不同的对象上一个失效一个有效——**而"失效"在文件层面看起来和"成功"完全一样**：
明文键确实被删掉了。是 Edge 从 `_edge_enclave` 密封副本里把它还原的。

市面上的工具不报告这件事，因为它们都只做一次快照式的"扫描—删除"。
WinProof 把**基线**做成一等公民：`baseline.bat` 固化此刻的状态，之后每次 `scan.bat`
把每条结论分类成 `新发现 / 已变化 / 持续存在 / 已消失`。

> 基线**永不自动更新**。否则往你机器里写东西的那位，只要等你重新采集一次基线就把自己洗白了。

---

## 30 秒上手

```
scan.bat                       # 只读采集 + 求值 + 生成 out\report.html 并打开
baseline.bat                   # 把当前状态固化为参照点（第一次用完它再决定要不要留）
ack.bat "BR-06|Edge / Profile 1"   # 「这是我自己的配置，别再报」——不删规则，只降级这一条
```

报告长这样（真机截图，已脱敏）：

![report](docs/report.png)

---

## 这台机器上它实际报了什么

```
engine: subjects=62 rules=14 findings=20 high=4 resolved=0
```

| 严重度 | 规则 | 命中 | 对象 |
|---|---|---|---|
| 高危 | BR-01 启动页被劫持 | 1 | Edge / Profile 1 |
| 高危 | BR-02 存在密封副本，只删明文会被还原 | 2 | Edge / Default、Edge / Profile 1 |
| 高危 | BR-05 清理后又回来了 | 1 | Edge / Profile 1 |
| 中危 | BR-04 签名孤儿（此处曾被篡改并清理过） | 3 | Edge ×2、Chrome ×1 |
| 中危 | PS-01 自启动项指向已不存在的文件 | 1 | service / AndrowsSvr |
| 中危 | PS-02 开机自启程序无有效签名 | 3 | Lively、Authenticator、OpenClaw Gateway |
| 低危 | BR-06 浏览器上次不是正常退出 | 2 | Edge / Profile 1、Chrome / Default |
| 低危 | PS-07 常驻程序位于用户可写目录 | 5 | Rd_Service、3 条 WPS 任务、OpenClaw |
| 观察 | BR-03 启动模式被设为"打开特定页面" | 1 | Edge / Profile 1 |
| 正常 | BR-07 上次修复经受住了复查 | 1 | Chrome / Default |

**PS-03 / PS-04 / PS-05 / PS-06 命中 0 条，这是正确状态而不是漏报。**
Early-Launch 成员只有 `WdBoot`、hosts 只有 `127.0.0.1 localhost`、IFEO 下没有 `Debugger`、
5 个 Winsock LSP 全是微软签名的系统 DLL。每条规则的 `verified_evidence` 都写明了本机实测分布，
所以"命中 0"是可以被复核的，不是"这条规则大概没写好吧"。

---

## 架构：四层，各层职责不重叠

```
probes/    只读采集事实，不做任何判断
rules/     纯 JSON 数据，没有代码、没有 eval
engine.ps1 声明式谓词解释器 + 基线 diff
report.ps1 生成自包含静态 HTML，没有服务器
```

**规则不是代码，这是本项目的核心决策。**

一条规则长这样：

```json
{
  "id": "PS-07",
  "title": "常驻程序放在用户可写目录",
  "severity": "low",
  "when": { "all": [
    { "fact": "exe_exists",  "op": "eq",     "value": true },
    { "fact": "in_writable", "op": "eq",     "value": true },
    { "fact": "signer",      "op": "notIn",  "value": ["Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation"] }
  ]},
  "show": ["kind", "exe", "signer", "sig_status", "exe_mtime", "exe_bytes"]
}
```

条件是一个受限 AST，算子集合固定为 `eq / ne / nonEmpty / isEmpty / hasAny / countGte / in / notIn`，
未知算子直接 `throw`。这意味着：

- 从 PR 里合进来的一条规则、或者大模型帮你生成的一条规则，**永远不会变成可执行输入**——注入面为 0；
- 规则可以被静态检查、被 diff、被机器校验，而不是"读代码才知道它会不会 `Invoke-Expression`"；
- 加一条判据不用碰引擎。

`when` 决定命中，`show` 决定哪些字段进入**证据指纹**。指纹只由 `show` 列出的字段算出，
所以一个文件被改写、但相关证据没动时，这条结论仍然是 `PERSIST` 而不是 `CHANGED`——
否则一次浏览器启动会把该 Profile 上所有规则全部点亮，"什么变了"就又被噪声淹没了。

---

## 踩过的坑，以及它们如何变成判据

这些不是感想，每一条都对应一段现在还活在代码里的逻辑。

**1. `Secure Preferences` 和 `Preferences` 得合起来看。**
被劫持的值在 `Secure Preferences` 的 `session.startup_urls`，
而决定"手改文件会不会被云端回灌"的 `sync.preferences` 在另一个文件的 `sync` 段里。
单看任何一个文件都会给出错误的处置建议。引擎按 Profile 合并两份文档，
派生出 `sync_preferences_enabled` 再喂给规则。

**2. 明文键名在两个文件里不一样。**
`Secure Preferences` 用 `restore_on_startup`，纯 `Preferences` 用 `startup_setting`。
只查一个就会漏。

**3. 密封副本必须整族删除。**
Edge 在 `session` 下另存 `startup_urls_edge_enclave` / `_verify`（另一台机器上是 `_edge_lightweight`）。
只删明文，Edge 下次写文件时从密封副本还原——这正是上面那格"复发"的成因。
所以规则匹配的是 `_(edge_enclave|edge_lightweight)(_verify)?$` 整个键族。

**4. `protection.macs` 是两层的：段名 → 键名 → 签名。**
而且这些签名是**确定性**的：`Default` 和 `Profile 2` 对同一个不存在的值有一模一样的签名字节。
也就是说篡改者不需要伪造任何东西——删掉值、留下签名，就是本机 `BR-04` 报的"签名孤儿"。
它不是当前威胁，是历史证据：说明这个位置被改过并清理过。

**5. 用签名者归属，不用厂商关键词黑名单。**
关键词列表只能抓到别人已经写进列表的那几家。
"这个每次开机都跑的二进制没有有效签名"抓的是**你机器上实际存在的东西**。

**6. `Microsoft Windows Hardware Compatibility Publisher` 不是微软的软件。**
它是 WHQL 第三方签名通道。一开始我把它当成微软签名，导致一批第三方驱动被放过。
`PS-07` 的排除列表因此是精确的三个名字，不是一个 `startswith("Microsoft")`。

**7. `PS-07` 必须排除微软签名，否则 Defender 自己会被报成可疑。**
`WinDefend` 和 `MDCoreSvc` 的真实二进制就在 `C:\ProgramData\Microsoft\Windows Defender\` 下。
自检里这条被**正向断言**：先确认本机确实存在"微软签名 + 可写目录常驻"的对象（2 个），
再断言它们一个都没漏进 `PS-07`。少了前半句，这个断言可以永远空转通过。

**8. 裸命令名不是丢失的文件。**
`scheduled_task\自动拨号` 的命令行是 `rasdial <连接名> <账号> <密码>`。
第一版把它报成"目标文件已不存在"——假阳性。`CreateProcess` 是按 `PATH` 解析裸名的，
它指向 `C:\Windows\System32\rasdial.exe`，活得好好的。
补上 `Resolve-BareCommand` 之后 `PS-01` 从 2 条降到真实的 1 条。
（顺带：那行命令行里存着明文拨号密码。修掉解析缺陷之后它不再进报告，
`verify.js` 现在会从事实文件里取出这些 token 并断言它们没出现在 HTML 里。）

**9. `\SystemRoot\...` 相对 ImagePath 要展开。**
不展开的话 `WdBoot` 看起来是"丢失的文件"，残留规则会打在 Defender 身上。

**10. 带空格的未加引号路径不能按第一个空格切。**
注册表里 `"C:\Program Files\...\x.exe"` 这种值，要把 token 逐个拼回去试 `Test-Path`，
拼不上再按扩展名兜底——第二个判据保证一个真丢了的文件仍归属到完整路径，而不是 `C:\Program`。

**11. `countGte` 对标量取的是数值，不是"数组长度"。**
`host_effective = 0` 被当成 1 个元素，于是**每台机器都会报 hosts 被劫持**。
这是自检里 [7] 那节钉住的行为，正反两个方向都断言。

**12. PowerShell 5.1 的序列化坑。**
空数组变 `{}`、单元素数组变对象 → 渲染层统一 `norm()`；
`PSCustomObject.ToString()` 是空串 → 证据必须 `ConvertTo-Json -Compress` 再进指纹，
否则对象型证据（备份列表、密封键族）对指纹毫无贡献，基线 diff 会永久失明。

**13. `-Value [string]$x` 在参数模式下不是表达式。**
`[string]` 被当成字面量 token，值变成字符串 `"[string]@{...}.group"`，
后续哈希查表全部落空 → 报告里每张卡片的分组名静默为空。必须写 `-Value ([string]$x)`。
这个 bug 是靠截图发现的，现在 `selftest [9b]` 直接断言 `group_title` 非空且不含 `@{`。

---

## 已知答案测试：46 PASS / 0 FAIL

判据先于扫描逻辑定义。跑 `powershell -File tools\selftest.ps1`：

```
[1]  从真机采集建立基线                          [6]  驻留规则 vs 从原始事实独立重算的谓词
[2]  同一份事实复扫：不得有任何 CHANGED          [7]  countGte 的标量语义（曾导致全员误报）
[3]  夹具 B：把 URL 注回 Chrome → NEW + 旧结论 RESOLVED
[4]  夹具 C：被劫持文件再次被写 → CHANGED 而非 NEW   [8]  植入一条假残留 → 必须 NEW，且不得吞掉邻居
[5]  acknowledge 只降级不删规则                  [9]  未知探针名必须抛错，不许静默丢事实
                                                [9b] 分组名/标题/指纹必须完整
                                                [10] 每条"残留"都要独立复核为确实不存在
```

[6] 和 [10] 是关键：**期望集合不是抄下来的快照，而是用独立逻辑从原始事实重算的。**
所以这台机器明天多一条或少一条启动项，测试不会红；
但哪条规则的实现和它声称的判据漂移了，测试会红。

[10] 专门用来防止第 8 条那个假阳性复发——任何被 `PS-01` 称为残留的行，
都会在测试里重新 `Test-Path` 一次，且裸命令名直接判为缺陷。

另有 `tools/layout-probe.html`：把报告塞进 360–1280px 的 iframe 里量 `scrollWidth`，用无头 Edge 跑完——

```
msedge --headless=new --allow-file-access-from-files --virtual-time-budget=20000 \
       --dump-dom file:///.../tools/layout-probe.html
```

当前 **7 个宽度全部 0 像素横向溢出**（驻留类结论动辄一条 120 字符的 Windows 路径）。
之所以要这么测：这类报告最容易在"我屏幕上看着没问题"中被毁掉。

---

## 探针覆盖

**`browser_prefs.ps1`** — Edge / Chrome 全部 Profile 的 `Preferences` + `Secure Preferences`：
启动页 URL、启动模式、密封键族、`protection.macs` 与孤立签名、`sync.preferences`、
`profile.exit_type`、以及**历史修复备份的内容**（备份里当时有没有恶意值，是复发判定的时间轴证据）。

**`persistence.ps1`** — 8 类开机驻留面：
Run / RunOnce（5 个视图，含 WOW6432Node）、启动文件夹、非 `\Microsoft\` 路径的计划任务、
Auto 启动且不在 Windows 目录的服务、`Group=Early-Launch` 的 ELAM 驱动、hosts、IFEO Debugger、Winsock LSP。
每条都带目标二进制的 Authenticode 签名者、状态、修改时间、体积，以及 `in_windows` / `in_writable` 归属。

只读。不写注册表、不停服务、不改文件、不联网。报告里的每条建议都需要你手动执行——
因为"正确的处置方式"取决于密封副本与同步开关是否存在，而这个判定未必适用于你的机器。

---

## 局限（说在前面）

- **Windows only**，且依赖 PowerShell 5.1 自带的 `Get-AuthenticodeSignature` / `Get-ScheduledTask`。
- 浏览器规则目前只覆盖启动页/搜索引擎这一族劫持，没覆盖扩展策略、计划任务式重启器。
- `PS-05`（IFEO）与 `PS-06`（LSP）的判据按实测结构实现，但本机没有可命中的样本，
  属于"写对了但没被打过"的规则。首版不为它们编造成功案例。
- 基线是**按机器**的：换一台机器、或你主动装了一批软件，`CHANGED` 会很多，那是正常的。
- `domain_blocklist` 是子串匹配，你主动把 `so.com` 设成首页也会被报。
  正确处置是 `ack.bat` 标记为已知，而不是把规则调瞎。

---

## English

A read-only forensic differ for Windows persistence. Not another cleaner.

The premise: a cleanup that silently gets reverted is indistinguishable from a successful one at the
file level, because the plaintext key really is gone — Edge restores it from a sealed
`startup_urls_edge_enclave` copy. WinProof captures a baseline, then classifies every finding as
new / changed / persisting / resolved, and reports the structural reason a given remediation will or
won't stick (sealed copy present? `sync.preferences` on?).

- **Rules are data, not code.** Conditions are a bounded AST over a fixed operator set, so a rule
  arriving from a pull request or an LLM can never become executable input. Zero injection surface.
- **Fingerprints cover only the evidence a rule cites**, so unrelated file writes don't light up every
  rule on that object.
- **14 rules, 46 known-answer assertions.** Expected hit sets are recomputed from raw facts by
  independent logic rather than snapshotted, so the suite survives a machine that changes.
- Ships as a self-contained static HTML report. No server, no dependencies beyond PowerShell 5.1.

---

## 贡献规则

在 `rules/*.json` 里加一条，不用碰引擎。请一并填 `verified_on` 和 `verified_evidence`：
**在你自己机器上跑出来的命中数和对象名**。没有实测证据的判据不会进主干——
这个项目所有的可信度都来自"每条规则都能被复述成一次具体的观察"。

```bash
powershell -File tools\selftest.ps1     # 46 PASS 才算过
node tools\verify.js                    # 结构 + 脱敏
powershell -File tools\hygiene.ps1      # .bat 必须 CRLF；.ps1 必须纯 ASCII 或带 BOM
```

`hygiene.ps1` 拦的是两类在 Windows 上不会报错的坑：LF-only 的 `.bat` 会被 cmd 执行一半；
无 BOM 的 `.ps1` 会被 PowerShell 5.1 按活动代码页解码，注释里的中文变成乱码字节，
万一其中某个字节解析成引号或反引号，就变成一个只在别人机器上出现的语法错误。

## License

MIT
