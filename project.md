# ReuseGuard 项目设计

> 复用开源项目前的安全准入编排层。
>
> 注意：密码学领域存在同名术语 `ReuseGuard`（防 nonce 重用）。本项目与密码学无关，
> 领域是开源仓库的安全评估。

## 1. 定位

ReuseGuard 不发明新的召回算法，也不发明新的检测技术。它做的是**编排**：

> 输入一个种子仓库或一段需求描述，召回相似项目，用已有信号做信誉过滤和
> 只读静态检查，最后输出一份分级、可解释、标注了局限的安全准入报告。

它解决的不是“如何发现漏洞”，而是“在决定复用某个轮子之前，如何低成本地做一次
有依据的检查”。

## 2. 不做什么

- 不做通用代码扫描平台（VibeGuard / secureCodeBox 的领域）
- 不自己实现沙箱（v0.1 不做动态执行）
- 不保证“绝对安全”，只聚合信号并写明置信边界
- 不把仓库内容上传给 LLM
- 不替用户做最终决定；`AVOID` 也是分诊，不是恶意软件判决

## 3. 用户故事

1. 我有一个种子仓库 URL，想找同类替代品，并比较它们的安全性。
2. 我准备复用某个项目，想知道有没有安装钩子、混淆、危险执行或明显 CI 风险。
3. 我想把“复用前检查”接进 CI，出现 `AVOID` 时让流水线失败。

## 4. 当前状态（v0.1.0）

已实现：

- 输入解析：GitHub URL / `owner/repo` / SSH URL
- 召回：GitHub Search，最多 3 条查询，四维相似度排序
- 信誉过滤：OpenSSF Scorecard 公共服务
- 快照：`codeload.github.com` tarball，安全解包，无 `git clone`
- 静态扫描：内置规则集，带误报抑制和覆盖上限
- 结论：USE / INSPECT FIRST / AVOID + 置信度 + 理由 + 局限
- 输出：Markdown / JSON
- CLI：`check`、`--idea`、`demo`、`--fail-on`、`--keep-workdir`
- 测试：fake adapter，全离线

未实现：

- 动态沙箱验证
- 外部扫描器（Semgrep / OSV / gitleaks）
- YAML 策略配置
- 私有仓库的完整支持（取决于 token 权限与 Scorecard 覆盖）

## 5. 架构

```text
src/reuseguard/
├── cli.py              # argparse、日志、退出码、输出
├── config.py           # Settings、token 解析
├── models.py           # 纯数据契约，无 I/O
├── pipeline.py         # 阶段编排、临时目录、错误降级
├── report.py           # Markdown / JSON 渲染
├── demo.py             # 离线 demo 数据
├── adapters/
│   ├── github.py       # GitHub REST：元数据 + search
│   ├── scorecard.py    # OpenSSF Scorecard API
│   ├── snapshot.py     # codeload 下载 + 安全解包
│   └── scanner.py      # 内置静态规则
└── stages/
    ├── recall.py       # 查询构造、相似度、召回
    ├── reputation.py   # Scorecard → FilterResult
    └── verdict.py      # Filter + Scan → Verdict
```

原则：

- `models.py` 不依赖任何外部工具，便于测试和替换。
- 外部调用都放在 `adapters/`，失败时转换成带类型的异常，由 pipeline 降级为
  `unknown` / `error`，而不是让整次运行崩掉。
- 阶段判定规则集中在 `stages/`，它们是本项目的核心差异点，优先自己维护。
- 报告渲染不参与判定，只消费 `Report`。

## 6. 数据契约

| 类型 | 作用 | 关键字段 |
| --- | --- | --- |
| `RepoRef` | 校验后的 owner/name | `owner`, `name` |
| `RepoMeta` | GitHub 元数据 | stars, topics, language, pushed_at, archived, size_kb |
| `Similarity` | 可解释的相似度 | total, topics, keywords, language, recency, popularity |
| `Candidate` | seed / alternative / candidate | repo, role, similarity |
| `FilterResult` | 信誉过滤结果 | status, score, checks, reasons, warnings |
| `Finding` | 单条静态发现 | rule_id, severity, path, line, evidence, suppressed |
| `ScanReport` | 扫描结果 | status, risk, findings, files_scanned, truncated |
| `Verdict` | 最终结论 | decision, confidence, reasons, limitations |
| `Assessment` | 一个仓库的全部证据 | candidate, filter, scan, verdict |
| `Report` | 一次运行的完整结果 | seed, query, assessments, queries, warnings, settings |

`Report.to_dict()` 会递归把 dataclass / Enum / datetime / Path 转成 JSON 类型，并附加
`counts`。token 永远不会进入 `Report`。

## 7. 阶段规则

### 7.1 召回

输入种子后，从三类信号构造查询：

1. `topic:<primary> language:X`：`primary` 是清洗后最能描述种子的 topic
2. 如果还有一个带连字符的 topic（通常更具体），单独作为第二条 `topic:` 查询
3. 描述 + 仓库名提取的关键词（最多 4 个） + 语言

不做 `topic:a topic:b` 这样的多 topic AND：GitHub 会把 qualifier 当作合取条件，
`topic:client topic:cookies` 几乎搜不到东西。`primary` 的选择顺序是“出现在描述里的
topic → 出现在仓库名里的 topic → 带连字符的 topic → 较短的 topic”。`client`、`api`、
`rest`、`python`、`library` 等泛化 topic 会被剔除。

所有查询都带 `stars:>=N fork:false`，去重后最多 3 条。关键词会剔除停用词、语言名和
泛化 topic。

相似度 0–100：

- topic Jaccard × 40
- 语言相同 20；一方未知 10；不同 0
- 最近 push：`20 × max(0, 1 - days/1095)`
- 热度：`20 × min(1, log10(stars+1)/5)`

召回结果只用于排序，不进入安全结论。GitHub Search 失败或限流会变成 `warnings`，
不会中断种子仓库的评估。

#### `--idea` 模式

没有种子仓库时，从需求描述提取最多 5 个 ASCII 关键词，生成两条查询：

1. 前 4 个关键词 + `--language` + stars / fork
2. 前 2 个关键词 + `--language` + stars / fork（更宽）

若没有 ASCII 关键词（例如纯中文需求），把清洗后的原文作为查询词。候选按以下 0–100
分排序：

- 关键词覆盖率 × 40：仓库名、描述、topics 的 token 中命中了多少需求关键词
- 语言：指定语言时相同 20，不同 0；未指定时中性 10
- 最近 push：20
- 热度：20

`--idea` 模式不评估种子仓库，所有候选的 role 为 `candidate`；报告头使用 `Idea:` 而不是
`Seed:`。`--idea` 与 URL 互斥，且不能与 `--no-recall` 同用。

### 7.2 信誉过滤

数据源：`https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}`。

- 404 / 410 → `UNKNOWN`（未收录）
- 网络或解析错误 → `UNKNOWN`
- score < 0 → `UNKNOWN`
- score < `--scorecard-min`（默认 2.0）→ `SKIPPED`
- `Maintained == 0` 且 `Vulnerabilities == 0` → `SKIPPED`
- 其余 → `PASSED`

`archived`、`fork`、`Dangerous-Workflow == 0`、`Token-Permissions == 0`、
`Binary-Artifacts == 0` 会进入 warnings，但不单独触发 skip。

跳过信誉过滤的项目不会下载快照，直接进入结论阶段。

### 7.3 静态扫描

快照来源：`codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}`。

安全解包规则：

- 只接受普通文件和目录
- 拒绝绝对路径、`..`、盘符 / 冒号、Windows 保留名、结尾空格或点
- 拒绝符号链接、硬链接、设备节点
- 单文件 > 5 MB 跳过；解压总量默认 ≤ 200 MB；文件数 ≤ 20000
- 扫描阶段再限制：2000 文件 / 单文件 1 MB / 总量 20 MB

扫描规则（内置，v1）：

| 类别 | 代表规则 |
| --- | --- |
| 安装钩子 | `npm-lifecycle`、`pth-startup-code`、`setup-cmdclass`、`vscode-folder-open` |
| 执行 | `py-eval-exec`、`py-shell-true`、`py-os-command`、`py-unsafe-deserialize`、`js-child-process` |
| 编码执行 | `py-encoded-exec`、`js-encoded-eval`、`powershell-encoded` |
| 网络加载 | `download-pipe-shell`、`powershell-download-exec` |
| CI | `ci-pwn-request`、`ci-write-all` |
| 混淆 | `unicode-bidi` |
| 凭据 | `private-key`、`aws-access-key`、`github-token`、`slack-token`、`generic-secret` |
| 其他 | `rm-rf-root`、`chmod-777`、`docker-add-url` |

风险等级取**未被抑制**发现中的最高 severity：

- critical：编码执行、CI pwn-request
- high：下载后执行、`.pth` 启动代码、folderOpen、GitHub / AWS / Slack token
- medium：eval/exec、shell=True、pickle、child_process、npm lifecycle、远程 ADD、
  私钥块（通常是测试证书，需人工确认）
- low：generic secret、chmod 777

### 7.4 误报抑制

以下路径的发现标记为 `suppressed=True`，不计入风险，但保留在报告中：

- 目录：`docs/`、`examples/`、`tests/`、`test_*`、`*_test/`、`fixtures/`、`benchmarks/` 等
- 文件：`README*`、`*.md`、`*.rst`、`*.txt`、`test_*.py`、`conftest.py` 等

理由：README 里的 `curl | bash` 是安装说明，不是恶意代码；测试夹具里的
`package.json` 不会在用户安装时执行。

代价：恶意代码可以藏在 tests 里。报告会明确显示 suppressed 数量，JSON 保留全部
finding；这是可接受的取舍，后续可通过策略配置调整。

### 7.5 结论

```text
filter SKIPPED                                  → AVOID
scan disabled / skipped / error                 → INSPECT
scan risk critical                              → AVOID (high confidence)
scan risk high                                  → AVOID (medium confidence)
scan risk medium                                → INSPECT
scan.files_scanned == 0                         → INSPECT
scan risk low/none:
  archived                                      → INSPECT
  scan truncated                                → INSPECT
  filter disabled                               → INSPECT
  filter unknown                                → INSPECT
  filter score < 5.0                            → INSPECT
  otherwise                                     → USE (high confidence)
```

这里的 5.0 是 **USE 门槛**，与 `--scorecard-min` 的 2.0 **skip 门槛**不同：

- < 2.0：连扫描都不做，直接 AVOID
- 2.0–5.0：扫描，但结论最多 INSPECT
- ≥ 5.0 且扫描干净：USE

## 8. 安全模型

被检查的仓库是不可信输入。安全边界：

1. **不执行**：不跑安装脚本、测试、构建，不 import 模块。
2. **不 clone**：避免 hooks、submodule、仓库本地 config；tarball 由 GitHub 生成。
3. **解包防护**：见 7.3；解包路径必须位于目标目录内。
4. **只读扫描**：不修改快照；不跟随 symlink；二进制跳过。
5. **网络边界**：只访问 `api.github.com`、`codeload.github.com`、
   `api.securityscorecards.dev`。不调用 LLM，不上传内容。
6. **凭据**：token 只从 `GITHUB_TOKEN` / `GH_TOKEN` / `gh auth token` 读取；
   不写入报告、不打印、不落盘。
7. **报告注入**：仓库描述、finding 证据等用户可控文本会做 HTML 转义；表格中的
   `|` 会转义。

剩余风险：

- tarball 下载和解压仍消耗磁盘 / 带宽；已有大小上限，但不是硬隔离。
- 静态扫描存在漏报；动态行为未验证。
- 私有仓库的 tarball 访问需要 token；当前实现不向 codeload 发送 token，
  因此私有仓库可能下载失败（会降级为 scan error → INSPECT）。
- Scorecard 只覆盖公开、被索引的仓库。

## 9. 测试策略

- 所有测试默认离线，使用 `tests/fakes.py` 的 fake GitHub / Scorecard / snapshot。
- 扫描器测试用 `tmp_path` 构造真实文件，覆盖：
  - 干净仓库
  - README 抑制
  - 根 `package.json` 的恶意 postinstall
  - fixture 中的 `package.json` 抑制
  - `test_*` 目录抑制
  - pickle、编码执行、bidi、`.pth`、VS Code、CI pwn-request
  - 锁文件 / `node_modules` / 二进制跳过
  - 文件数截断 / 大文件跳过
- 快照测试构造恶意 tar：`../`、绝对路径、symlink、hardlink、Windows 保留名。
- 结论测试覆盖 7.5 的每条分支。
- CLI 测试覆盖 `demo`、非法 URL、`--fail-on` 退出码。
- 真实网络只用于手动验收，不进入默认 CI。

手动验收命令：

```powershell
reuseguard check psf/requests --limit 2
reuseguard check elastic/elasticsearch-py --limit 0
reuseguard check tconbeer/harlequin --limit 0
```

## 10. 里程碑

- **M1（已完成）**：种子 → 召回 → Scorecard → 静态扫描 → Markdown
- **M2（已完成）**：JSON、`--fail-on`、demo、抑制、CI、打包
- **M3（已完成）**：自然语言输入
  - `check --idea TEXT [--language LANG]`
  - 关键词提取、宽/窄两条查询、关键词覆盖率排序
  - `Report.seed` 可为空，报告头使用 `Idea:`
- **M4**：隔离动态验证
  - 只对 high/critical 或用户显式要求触发
  - 容器内运行，观察网络 / 文件 / 进程；结果只代表单次运行
- **M5**：外部扫描器
  - 统一 `Finding` schema
  - Semgrep / OSV / gitleaks 适配器，失败可降级
- **M6**：YAML 策略
  - 自定义 skip 阈值、抑制路径、规则启停
  - 团队级“什么算阻断”

## 11. 决策记录

| 决策 | 选择 | 理由 |
| --- | --- | --- |
| 快照方式 | codeload tarball | 避免 git hooks / submodule；实现更可控；httpx 已可用 |
| 静态扫描 | 内置规则 + 适配器边界 | 避免强制安装重型工具；先保证链路和报告质量 |
| Scorecard | 只读公开 API | 不执行第三方构建步骤；速度快；失败可降级 |
| 种子是否评估 | 是 | 用户通常也想知道手上的仓库本身是否安全 |
| 候选数量 | 默认 5 个替代 + 种子 | 控制下载和扫描时间 |
| 误报策略 | 文档/测试降权而非删除 | 保留证据，同时避免 README 安装说明导致 AVOID |
| pickle 等级 | medium | 本地缓存等合法用法常见；单独出现不应直接 AVOID |
| `--no-scorecard` | 结论最多 INSPECT | 没有信誉证据时不应给 USE |
| 动态验证 | v0.1 不做 | 成本高、边界复杂；先验证静态链路 |

## 12. 开放问题

1. **召回质量**：topic 稀疏的仓库召回效果有限；是否需要 LLM 扩展查询？
2. **私有仓库**：codeload 需要认证；是否支持带 token 下载？
3. **正则误报**：是否需要基于 AST 的规则来区分 `pickle.load` 的来源？
4. **Scorecard 覆盖**：未收录仓库只能 INSPECT，是否提供本地 `scorecard` CLI 回退？
5. **沙箱**：Docker / gVisor 的可用性检测、超时、网络隔离怎么做？
6. **策略配置**：抑制路径和阈值是否应该按团队可配置？
7. **报告规模**：候选很多时 Markdown 会很长；是否需要摘要模式？

## 13. 如何扩展

### 增加一条静态规则

在 `adapters/scanner.py` 的 `_PATTERN_RULES` 中加 `PatternRule`：

```python
PatternRule(
    "my-rule",
    "Short title",
    RiskLevel.MEDIUM,
    "category",
    re.compile(r"...", re.MULTILINE),
    frozenset({".py"}),
    "Why this matters.",
)
```

需要新文件类型时同步更新 `_TEXT_EXTENSIONS`；需要结构化检查时在 `_scan_text` 中加
专用 handler。

### 替换扫描器

`Pipeline` 接受 `scan_fn(root, *, limits) -> ScanReport`。实现一个适配器把 Semgrep
输出转成 `Finding` / `ScanReport` 即可，不需要改 verdict 或 report。

### 增加召回来源

`stages/recall.py` 的 `recall_similar` 返回 `RecallResult`。可以并联多个来源，
统一去重后交给 `Candidate`。

### 增加新阶段

在 `Pipeline.run` 中插入阶段，并在 `models.py` 增加结果类型；结论阶段只消费结构化
证据，不直接调用外部工具。
