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
- 不自己实现容器运行时；隔离检查复用 Docker，只做编排与证据收集
- 不在沙箱里执行仓库代码（M4 当前范围；行为探测是后续工作）
- 不保证“绝对安全”，只聚合信号并写明置信边界
- 不把仓库内容上传给 LLM
- 不替用户做最终决定；`AVOID` 也是分诊，不是恶意软件判决

## 3. 用户故事

1. 我有一个种子仓库 URL，想找同类替代品，并比较它们的安全性。
2. 我准备复用某个项目，想知道有没有安装钩子、混淆、危险执行或明显 CI 风险。
3. 我想把“复用前检查”接进 CI，出现 `AVOID` 时让流水线失败。

## 4. 当前状态（v0.7.1）

已实现：

- 输入解析：GitHub URL / `owner/repo` / SSH URL，或 `--idea` 需求描述
- 召回：GitHub Search，最多 3 条查询，四维相似度排序
- 信誉过滤：OpenSSF Scorecard 公共服务
- 快照：`codeload.github.com` tarball，安全解包，无 `git clone`
- 静态扫描：内置规则集，带误报抑制和覆盖上限
- 外部扫描器：Semgrep 适配器（本地规则、JSON → 统一 `Finding`、降级 / 错误边界）
- 外部扫描器：gitleaks 适配器（`--gitleaks`，内置规则、固定本地配置、凭据脱敏、追加合并）
- 外部扫描器：osv-scanner 适配器（`--osv`，lockfile 依赖漏洞、别名合并、追加合并）
- 结论：USE / INSPECT FIRST / AVOID + 置信度 + 理由 + 局限
- 输出：Markdown / JSON
- CLI：`check`、`--idea`、`--discover-only`（配合 `--no-scan`）、`--config`、
  `--semgrep-config`、`--gitleaks`、`--osv`、`--sandbox`、`demo`、`--fail-on`、
  `--keep-workdir`
- 策略：YAML 阈值、限制、规则启停、severity 覆盖、抑制路径
- 沙箱隔离检查（默认关闭）：Docker 检测、加固 `docker run`、容器内隔离探测、
  报告区块；`--sandbox auto` 只跑 high/critical，`--sandbox` / `all` 跑全部
- 测试：fake adapter / fake runner，全离线
- 打包：v0.7.1 wheel 构建成功（用 `.venv` 的 Python），安装到 `.venv` 后 console script
  验证通过（`reuseguard --version` → 0.7.1 / `demo` / `--discover-only`）；
  pytest 用 `pythonpath=src` 测试工作区源码
- 已验证（Windows）：gitleaks 8.30.1 与 osv-scanner 2.7.0 的真实二进制；装在项目内
  `.tools/scanners/`，不写入系统 PATH，删目录即卸载

未实现：

- 在沙箱内执行仓库行为（安装、导入、运行测试）；设计草案见
  [docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)（待确认，尚未实现）
- OSV 离线数据库模式（当前 `--osv` 需要网络）
- gitleaks 自定义规则集（当前固定使用二进制内置规则）
- 私有仓库的完整支持（取决于 token 权限与 Scorecard 覆盖）

## 5. 架构

```text
src/reuseguard/
├── cli.py              # argparse、日志、退出码、输出
├── config.py           # Settings、YAML Policy、token 解析
├── models.py           # 纯数据契约，无 I/O
├── pipeline.py         # 阶段编排、临时目录、错误降级
├── report.py           # Markdown / JSON 渲染
├── demo.py             # 离线 demo 数据
├── adapters/
│   ├── github.py       # GitHub REST：元数据 + search
│   ├── scorecard.py    # OpenSSF Scorecard API
│   ├── snapshot.py     # codeload 下载 + 安全解包
│   ├── scanner.py      # 内置静态规则 + 公共抑制策略
│   ├── process.py      # 通用 argv 子进程边界（shell=False + 超时）
│   ├── semgrep.py      # Semgrep JSON → 统一 ScanReport
│   ├── gitleaks.py     # gitleaks JSON → 统一 ScanReport（凭据脱敏）
│   ├── osv.py          # osv-scanner JSON → 统一 ScanReport（依赖漏洞）
│   └── sandbox.py      # Docker 检测 + 加固命令 + 隔离探测
└── stages/
    ├── recall.py       # 查询构造、相似度、召回
    ├── reputation.py   # Scorecard → FilterResult
    └── verdict.py      # Filter + Scan → Verdict（含沙箱 caveat）
```

原则：

- `models.py` 不依赖任何外部工具，便于测试和替换。
- 外部调用都放在 `adapters/`，失败时转换成带类型的异常，由 pipeline 降级为
  `unknown` / `error`，而不是让整次运行崩掉。
- 阶段判定规则集中在 `stages/`，它们是本项目的核心差异点，优先自己维护。
- 报告渲染不参与判定，只消费 `Report`。
- 追加式扫描器（gitleaks）返回自己的 `ScanReport`，由 `models.merge_scan_reports()`
  合并：取最高风险、按 `(rule_id, path, line)` 去重、文件数取最宽而不是相加。

## 6. 数据契约

| 类型 | 作用 | 关键字段 |
| --- | --- | --- |
| `RepoRef` | 校验后的 owner/name | `owner`, `name` |
| `RepoMeta` | GitHub 元数据 | stars, topics, language, pushed_at, archived, size_kb |
| `Similarity` | 可解释的相似度 | total, topics, keywords, language, recency, popularity |
| `Candidate` | seed / alternative / candidate | repo, role, similarity |
| `FilterResult` | 信誉过滤结果 | status, score, checks, reasons, warnings |
| `Finding` | 单条静态发现 | rule_id, severity, path, line, evidence, suppressed |
| `ScanReport` | 扫描结果 | status, risk, findings, files_scanned, truncated, scanner（合并后可为 `semgrep+gitleaks`） |
| `SandboxReport` | 一次容器隔离探测的证据 | status, image, exit_code, timed_out, containment_ok, probe, error |
| `Verdict` | 最终结论 | decision, confidence, reasons, limitations, withheld（仅展示层） |
| `Assessment` | 一个仓库的全部证据 | candidate, filter, scan, verdict, sandbox |
| `Report` | 一次运行的完整结果 | seed, query, assessments, queries, warnings, settings, discover_only |

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
不会中断种子仓库的评估。搜索偶尔会返回 `owner/.github` 这类无法通过 `RepoRef.parse`
的仓库名；`recall_idea` / `recall_similar` 会在进入 Scorecard 之前跳过它们，并写
`Skipped N search result(s) with an invalid repository name.`。跳过意味着候选覆盖不完整，
不是“没有问题”。

#### `--idea` 模式

没有种子仓库时，从需求描述提取最多 5 个 ASCII 关键词，生成两条查询。关键词提取带一个**显式短词 allowlist**（`ai`、`2d`、`3d`、`c#`、`c++`、`f#`、`go`、`r`、`js`、`ts`、`ml`、`ui`、`ux`、`vr`、`ar`、`c`）：这些词即使只有 1–3 个字符也会保留，其他短词和孤立标点仍然忽略。之前的正则要求至少 3 个字符且以字母开头，导致 `AI`、`2D`、`3D`、`C#`、`C++` 被静默丢弃。查询构造如下：

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
  filter score < use_scorecard_min           → INSPECT
  otherwise                                     → USE (high confidence)
```

`use_scorecard_min` 默认 5.0，可用 `--config` 的 `thresholds.use_scorecard_min` 覆盖；
`--scorecard-min`（默认 2.0）是 **skip 门槛**，两者不同：

- < scorecard_min：连扫描都不做，直接 AVOID
- scorecard_min–use_scorecard_min：扫描，但结论最多 INSPECT
- ≥ use_scorecard_min 且扫描干净：USE

#### `--discover-only`（展示层，不改变判定）

`--discover-only` 必须与 `--no-scan`（或 YAML `features.scan: false`）一起使用，否则 CLI
报参数错误。它只影响 Markdown 展示：

- summary 的 Verdict 列显示 `—`，并去掉 Static risk / Sandbox 列，只保留仓库、Role、
  Stars、Match、Scorecard；
- 每个仓库的 Verdict 区块显示 `withheld`，报告写明
  “No static scan was performed, so no verdict is given.”；
- `decide()` 完全不变，仍会算出 `INSPECT`；JSON 保留该 `decision`，同时写
  `Verdict.withheld = true`、`Report.discover_only = true`、`scan.status = "disabled"`，
  让机器读者能区分“结论被隐藏”与“没有扫描”；
- `--fail-on` 仍按计算出的结论判断。隐藏结论不是“没有结论”，更不是“安全”。

### 7.6 策略配置

`--config PATH` 加载 YAML，支持：

- `thresholds`：`scorecard_min`、`use_scorecard_min`
- `limits`：候选数、星标门槛、下载 / 扫描上限、超时
- `features`：`recall` / `scorecard` / `scan` 开关
- `rules.disable`：按 rule ID 关闭规则
- `rules.severity`：把规则覆盖为 low / medium / high / critical
- `suppress.paths`：额外抑制 glob

优先级：显式 CLI > YAML > 内置默认。未知 key、未知 rule ID、非法 severity 或类型错误
都会直接报 `ConfigError`，不会静默忽略。`Settings.public_dict()` 会把最终生效的
规则策略写入报告，便于审计。

### 7.7 沙箱隔离检查（M4，默认关闭）

触发模式（`--sandbox`）：

- `off`（默认）：不调用 Docker，`Assessment.sandbox = None`
- `auto`：仅当静态扫描 `risk in {high, critical}` 时运行
- `all`：对所有已扫描候选运行；裸 `--sandbox` 等价于 `all`

执行前先 `docker info --format '{{.ServerVersion}}'`。不可用时写 warning 并记录
`SandboxStatus.UNAVAILABLE`，**不改变结论**。

容器参数固定为：

- `--network none`、`--read-only`、`/tmp` 为 `noexec,nosuid` tmpfs
- 快照目录只读 bind mount 到 `/src`（`--mount type=bind,...,readonly`）
- `--cap-drop ALL`、`--security-opt no-new-privileges`、`--user 65534:65534`
- `--memory` / `--memory-swap`、`--cpus`、`--pids-limit`、`--ulimit nofile`
- `--pull=never`，不自动拉镜像
- 不挂 Docker socket，不用 `--privileged`，不用宿主网络 / PID

容器内运行 ReuseGuard 自己的固定探测脚本，只做四件事：`stat` 文件、验证 `/src`
不可写、验证 `/tmp` 可写、验证网络不可达。**不 import / 安装 / 执行仓库代码。**

超时（默认 20s）后执行 `docker rm -f <name>`；退出码 137 记为 `oom_suspected`
启发式标记。`containment_ok` 需要同时满足“`/src` 不可写 + 网络不可达 + 挂载可读”。

结论层只追加 caveat，不会因为探测通过而升级为 USE，也不会因为探测失败而把仓库
判为恶意。报告明确写“一次运行、不代表后续版本、不是安全证明”。

行为探测（M4 的下一阶段）不在本节范围内：它会在一次性容器里执行仓库代码，必须显式
开启、用 `@sha256:` 锁定镜像，并按固定协议记录证据。设计草案见
[docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)；设计确认前不实现，也不在沙箱里
执行仓库代码。

### 7.8 外部扫描器：Semgrep（M5 第一步）

`--semgrep-config PATH` 开启。`PATH` 必须是本地文件或目录，否则 CLI 直接报错。

调用方式（`shell=False`，argv 列表）：

```text
semgrep scan --json --quiet --metrics=off --disable-version-check
  --no-git-ignore --config <PATH> --timeout 30
  --max-target-bytes <max_file_bytes> --max-memory 1024 --jobs 1 <root>
```

- **禁止 `--config auto`**：不隐式联网、不拉远程规则。
- `--metrics=off` / `--disable-version-check`：关闭遥测和版本检查。
- `--no-git-ignore`：仓库自己的 `.gitignore` 不能把文件藏起来；Semgrep 仍可能读取
  仓库内 `.semgrepignore`，这是已知覆盖缺口。
- `--jobs 1`：单进程，资源可预测。
- 整体进程超时默认 300s，可用 `--semgrep-timeout` 调整（10–3600）。

映射：

| Semgrep | ReuseGuard |
| --- | --- |
| `ERROR` | high |
| `WARNING` | medium |
| `INFO` | low |
| `metadata.severity = critical` | critical |
| 其他 | low |

`check_id` → `rule_id`，`path` 规范化到快照内相对路径（越界路径丢弃），
`start.line` → `line`，`extra.message` / `extra.lines` → `message` / `evidence`。
复用 `scanner.suppression_reason()`，docs/tests/examples 的命中仍标记 suppressed。

覆盖完整性：

- Semgrep `errors` 非空或 `paths.skipped` 非空 → `truncated=True`。
- 命中数超过 `ScanLimits.max_findings` → 截断并标记。

失败语义：

- 找不到可执行文件 → `SemgrepUnavailable`，pipeline 降级到内置扫描器 + warning。
- 配置缺失、非零退出、超时、JSON 非法 → `ScanReport(status=ERROR, scanner="semgrep")`，
  **不静默降级**；结论为 INSPECT。

### 7.9 外部扫描器：gitleaks（M5 第二步，追加式）

`--gitleaks` 开启，默认关闭。它在**内置扫描或 Semgrep 之后**运行，结果合并进同一个
`ScanReport`（`scanner` 形如 `builtin-patterns+gitleaks`）。之所以是追加而不是替换：
凭据扫描和安装钩子/执行模式是不同证据，替换会缩小覆盖范围。

调用方式（`shell=False`，argv 列表）：

```text
gitleaks dir <root>
  --report-format json --report-path <tmp>/report.json
  --config <tmp>/reuseguard-gitleaks.toml
  --gitleaks-ignore-path <tmp>
  --ignore-gitleaks-allow --exit-code 0 --redact
  --no-banner --no-color --max-target-megabytes N
```

- 需要 gitleaks 提供 `dir` 命令（v8.19+）。已弃用的 `detect --no-git` 不使用；命令不被
  接受时（退出码 126）报 scan error，而不是静默降级。
- **被检查的仓库不能决定规则。** gitleaks 默认会读快照内的 `.gitleaks.toml`（可整体替换
  或 allowlist 规则）、`.gitleaksignore`（按 fingerprint 忽略发现）和 `# gitleaks:allow`
  行内注释。适配器固定 `--config` 为 ReuseGuard 生成的最小配置
  （`[extend] useDefault = true`，即二进制内置规则），`--gitleaks-ignore-path` 指向空目录，
  并加 `--ignore-gitleaks-allow`。
- JSON 报告写到私有临时目录（不写快照），读取上限 16 MB；`--max-target-megabytes`
  跟随 `--max-file-kb`（向上取整）。
- 凭据脱敏：工具先 `--redact`，适配器再从 `Secret` 字段替换一次。`Finding.evidence`
  只保留单行、脱敏后的匹配片段；`Secret` 原文不进入任何字段。secret 缺失或长度 < 4 时
  直接丢弃匹配行，避免部分泄露。
- severity：私钥和知名厂商 token（AWS / GCP / GitHub / Slack / Stripe 等）→ high；
  `generic-*` 等熵规则与未知规则 → medium。gitleaks 没有 severity 字段，这是适配器
  映射，不是工具结论。
- 复用 `suppression_reason()`：docs/tests/examples 的命中仍记为 suppressed。
- 找不到可执行文件 → 跳过并写 warning；超时、非零退出、报告缺失/过大/非法 → scan error。

诚实边界：gitleaks 不报告扫描文件数，合并报告沿用基础扫描器的 `files_scanned`；它只扫
默认分支快照、不扫 git 历史，因此“没发现凭据”不等于“从未泄露过”。

### 7.10 外部扫描器：osv-scanner（M5 第三步，追加式）

`--osv` 开启，默认关闭。和 gitleaks 一样追加在内置扫描 / Semgrep 之后，结果合并进同一个
`ScanReport`（形如 `builtin-patterns+gitleaks+osv`）。

调用方式（`shell=False`，argv 列表，需要 osv-scanner **v2**）：

```text
osv-scanner scan source --recursive <root> --format json --output-file <tmp>/osv.json
```

- v1 的 `osv-scanner -r <root> --format json` 不兼容；v1 会以 scan error 失败，不静默跳过。
- 实测边界：递归扫描**跳过 `.` 开头的隐藏目录**（仓库里 `.config/` 这类目录下的 lockfile
  不会被扫到）；lockfile 带 **UTF-8 BOM** 时解析失败，以非 0 退出（适配器记为 scan error，
  不会当成干净）。
- **退出码不是“0 成功 / 非 0 失败”**：0 = 有包但无漏洞，1 = 有漏洞（正常结果），
  128 = 没找到任何 lockfile，127 = 一般错误，其余记为 scan error。
- 解析 `results[].packages[].groups`：一个 advisory 可能有多个编号（GHSA / CVE / GO /
  RUSTSEC），`groups` 已按别名归并，**一个 group 只产生一条 finding**，避免同一条漏洞在
  报告里出现三次。
- 同一 advisory 命中同一 lockfile 的多个包时合并成一条，列出受影响的包（最多 5 个）；
  不同 lockfile 各自一条（`path` 不同，合并时不会被去重掉）。
- severity 取 `database_specific.severity` / `ecosystem_specific.severity` 标签。
  **只有 CVSS 向量时按 medium 记录**，不在本地重算分数（算错成 critical 比保守的
  medium 更糟）。
- `rule_id = osv:<首选编号>`，`category="dependency"`，`path=lockfile`，`line=None`；
  `evidence` 只放 `包名@版本` 和 `https://osv.dev/vulnerability/<id>`。
- 复用 `suppression_reason()`：tests/fixtures 下的 lockfile 命中记为 suppressed。
- **没有 lockfile（退出码 128）→ `SCANNED` + `truncated=True`**，结论至少 INSPECT，并写
  warning。绝不能把“没找到 lockfile”当成“没有漏洞依赖”。

诚实边界：只覆盖 osv-scanner 认识的 lockfile；`--osv` 会访问 `api.osv.dev`（解析不完整的
锁文件时可能还会访问包管理器 registry），只发包名和版本；离线数据库模式未实现。

## 8. 安全模型

被检查的仓库是不可信输入。安全边界：

1. **不执行**：不跑安装脚本、测试、构建，不 import 模块。沙箱探测只读文件元数据。
2. **不 clone**：避免 hooks、submodule、仓库本地 config；tarball 由 GitHub 生成。
3. **解包防护**：见 7.3；解包路径必须位于目标目录内。
4. **只读扫描**：不修改快照；不跟随 symlink；二进制跳过。
5. **沙箱加固**：默认关闭；仅在显式模式下调用 Docker。argv 列表、`shell=False`，
   固定 `--network none` / 只读挂载 / cap-drop / 非 root / 资源与超时上限，不挂
   Docker socket，不用 `--privileged`，不自动 pull。挂载源拒绝文件系统根、home
   及其祖先、含逗号 / 换行的路径。行为探测尚未实现；其设计把执行限制为显式开关 +
   digest 镜像 + 每阶段一容器（见 [docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)）。
6. **外部扫描器**：Semgrep 只接受本地规则路径，禁止 `--config auto`，关闭
   metrics / 版本检查；argv 列表、`shell=False`、显式超时；输出按不可信 JSON 解析，
   越界路径丢弃。
7. **gitleaks 边界**：只调用本机二进制；固定 `--config` 忽略仓库 `.gitleaks.toml`，
   `--gitleaks-ignore-path` 指向空目录，`--ignore-gitleaks-allow` 关闭行内白名单；
   报告写在私有临时目录并限制大小；finding 只保留脱敏证据。
8. **osv-scanner 边界**：只读 lockfile，不安装依赖、不执行构建；JSON 写私有临时目录并
   限制大小；没有 lockfile 记为覆盖不完整；依赖漏洞按 advisory 标签定级，缺标签时保守为
   medium，不本地重算 CVSS。
9. **网络边界**：默认只访问 `api.github.com`、`codeload.github.com`、
   `api.securityscorecards.dev`；开启 `--osv` 时额外访问 `api.osv.dev`（只发包名和版本，
   解析不完整的锁文件时可能访问包管理器 registry）。不调用 LLM，不上传仓库内容。
   Semgrep 不会因扫描而联网（本地规则 + `--metrics=off` + `--disable-version-check`）；
   gitleaks 只用本地规则，不访问网络。
10. **凭据**：token 只从 `GITHUB_TOKEN` / `GH_TOKEN` / `gh auth token` 读取；
    不写入报告、不打印、不落盘。被检查仓库里的凭据同样不写进报告，只保留 `[REDACTED]`。
11. **报告注入**：仓库描述、finding 证据等用户可控文本会做 HTML 转义；表格中的
    `|` 会转义。容器探测输出和外部扫描器输出同样按不可信数据处理。

剩余风险：

- tarball 下载和解压仍消耗磁盘 / 带宽；已有大小上限，但不是硬隔离。
- 静态扫描存在漏报；沙箱当前只验证隔离，不观察仓库行为。
- Semgrep 的覆盖范围取决于用户提供的规则集；`.semgrepignore` 仍可能缩小扫描范围。
- gitleaks 的规则集来自本机安装的二进制；仓库提供的配置/白名单被刻意忽略，但团队
  自定义规则仍需后续支持。它只扫默认分支快照，不覆盖 git 历史。
- osv-scanner 只覆盖它认识的 lockfile；`--osv` 需要网络，且没有 lockfile 时无法给出
  依赖层面的结论。
- 沙箱依赖本机 Docker daemon、容器运行时和本地镜像；这些仍是信任边界。
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
- 沙箱测试全部使用 `FakeCommandRunner` / fake detector：不启动 Docker、不执行
  不可信代码。覆盖检测失败、超时清理、非零退出、坏 JSON、`containment_ok` 失败、
  触发策略（off / auto / all）、不可用降级和 CLI 参数校验。
- Semgrep 测试全部使用 `FakeCommandRunner`，CI 不安装 Semgrep。覆盖严重度映射、
  抑制、越界路径、坏 JSON、超时、非零退出、缺可执行文件降级、缺配置、截断、
  去重、参数加固和 CLI 校验。
- gitleaks 测试全部使用 fake runner + 临时报告文件，CI 不安装 gitleaks。覆盖命令加固
  （`dir`、`--config`、`--gitleaks-ignore-path`、`--ignore-gitleaks-allow`、
  `--exit-code 0`）、severity 映射、凭据脱敏（多行、已脱敏、短/缺失 secret）、
  越界路径、坏 JSON / 缺报告 / 超限、去重、截断、缺失二进制降级、合并语义和 CLI 校验。
- osv-scanner 测试全部使用 fake runner + 临时报告文件，CI 不安装 osv-scanner、不联网。
  覆盖：退出码语义（0/1 成功、128 覆盖不完整、其余错误）、别名分组、同 advisory 多包
  合并、跨 lockfile 不合并、severity 标签映射与缺失回退、CVSS-only 不猜分、越界路径、
  抑制、规则禁用/覆盖、截断、坏 JSON / 缺报告 / 超限、缺失二进制降级和 CLI 校验。
- 结论测试覆盖 7.5 的每条分支。
- CLI 测试覆盖 `demo`、非法 URL、`--fail-on` 退出码、`--sandbox` 参数组合。
- `pyproject.toml` 配置 `pythonpath = ["src"]`：`python -m pytest` 始终测试工作区源码，
  不会被 `.venv` 里安装的 wheel 遮住。
- 真实网络和真实 Docker 只用于手动验收，不进入默认 CI。

### 真实二进制验收（2026-10-31，Windows）

- **gitleaks 8.30.1**：夹具里放恶意 `.gitleaks.toml`（allowlist 全部路径）和
  `# gitleaks:allow` 注释，2 条命中仍然被报出；有命中时退出码为 0（`--exit-code 0`）；
  `--redact` 后证据只剩 `[REDACTED]`。
- **osv-scanner 2.7.0**：真实 `package-lock.json` / `requirements.txt` 解析成功，`groups`
  别名合并正确，有漏洞时退出码 1 被当成正常结果；发现隐藏目录跳过与 BOM 解析失败两个边界。
- **端到端**：`lodash/lodash` 真实快照 + `--gitleaks --osv` → `builtin-patterns+gitleaks+osv`，
  119 条发现，结论 AVOID，两条 scanner caveat 均在。
- **未验收**：Semgrep（缺本地规则）、Docker（缺镜像与 daemon）。

手动验收命令：

```powershell
reuseguard check psf/requests --limit 2
reuseguard check elastic/elasticsearch-py --limit 0
reuseguard check tconbeer/harlequin --limit 0
reuseguard check --idea "fast HTTP client with retries" --language Python --limit 3
reuseguard check psf/requests --config examples/reuseguard.yaml
reuseguard check psf/requests --no-recall --sandbox all
reuseguard check psf/requests --no-recall --semgrep-config rules/
reuseguard check psf/requests --no-recall --gitleaks
reuseguard check psf/requests --no-recall --osv
```

## 10. 里程碑

- **M1（已完成）**：种子 → 召回 → Scorecard → 静态扫描 → Markdown
- **M2（已完成）**：JSON、`--fail-on`、demo、抑制、CI、打包
- **M3（已完成）**：自然语言输入
  - `check --idea TEXT [--language LANG]`
  - 关键词提取、宽/窄两条查询、关键词覆盖率排序
  - `Report.seed` 可为空，报告头使用 `Idea:`
- **M4**：隔离动态验证
  - 已完成：安全骨架 + CLI / pipeline 接入
    - `adapters/sandbox.py`：Docker 可用性检测、加固命令计划、容器内隔离探测
    - `SandboxReport` / `SandboxStatus` 数据契约，`Assessment.sandbox`
    - 只读 bind mount、`--network none`、cap-drop、no-new-privileges、非 root、
      内存 / CPU / PID / 超时限制、超时杀容器
    - 探测脚本只 `stat` 文件并验证隔离，不执行仓库代码
    - `--sandbox off|auto|all`、`--sandbox-image`、`--sandbox-timeout`；默认 off
    - 报告“Sandbox”区块与 summary 列；结论只加 caveat，不升级也不判恶意
  - 待办：真实 Docker 手动冒烟验收；在沙箱内执行仓库行为（安装 / 导入 / 测试）
    - 已完成设计草案：[docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)（待用户确认，
      确认前不写实现、不执行仓库代码）
  - 边界：单次运行只代表当次容器配置，不是“无害证明”
- **M5（已完成）**：外部扫描器
  - Semgrep 适配器
    - `adapters/process.py`：共享的 argv / `shell=False` / 超时 runner
    - `adapters/semgrep.py`：本地规则、JSON 解析、severity 映射、抑制、截断
    - `--semgrep-config` / `--semgrep-timeout`；缺可执行文件才降级到内置
    - 非零退出 / 坏 JSON / 超时 / 缺配置 → scan error，不静默降级
  - gitleaks 适配器（追加式）
    - `adapters/gitleaks.py`：`dir` 扫描、固定本地配置、ignore 路径隔离、凭据脱敏
    - `--gitleaks` / `--gitleaks-timeout`；缺可执行文件才跳过
    - `models.merge_scan_reports()`：多扫描器合并（最高风险、去重、最宽文件数）
  - osv-scanner 适配器（追加式）
    - `adapters/osv.py`：`scan source --recursive`、别名分组、退出码语义、缺 lockfile 标记
    - `--osv` / `--osv-timeout`；依赖漏洞按 advisory 标签定级
  - 待办：外部规则 ID 进入 `rules.disable` / `rules.severity`；OSV 离线数据库；真实二进制验收
- **M6（已完成）**：YAML 策略
  - `--config PATH`
  - 阈值、限制、features 开关、规则启停、severity 覆盖、抑制 glob
  - 未知 key / 规则 / 类型直接报错
- **发现体验 P0（2026-11-01，已完成）**：
  - 短词 allowlist：`AI` / `2D` / `3D` / `C#` / `C++` 等不再被关键词正则丢掉
  - `--discover-only`：扫描关闭时 Markdown 隐藏结论，JSON 用 `withheld` 标记；
    不改变 `decide()`
  - 召回边界过滤非法仓库名（`owner/.github`），写 warning，不再中断整次运行

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
| 策略文件 | 严格 YAML + 未知 key 报错 | 拼写错误不应静默放宽安全策略 |
| 动态验证 | v0.3 只做容器隔离探测，默认关闭 | 先证明隔离配置可用，不在沙箱里执行不可信代码 |
| 沙箱触发 | `off` / `auto` / `all` 三态 | 默认零副作用；high/critical 与显式请求都能覆盖 |
| 沙箱失败 | 只写 warning，不改变结论 | 隔离失败是环境证据，不是仓库恶意证据 |
| 沙箱镜像 | 不自动 pull，`--pull=never` | 避免隐式联网和镜像供应链副作用 |
| 行为探测（设计） | 默认关闭、显式 `--behavior`、必须 `@sha256:`、每阶段一容器、结论最多 INSPECT | 设计草案待确认；执行不可信代码不能自动化，也不能用一次运行证明安全 |
| 短词提取 | 显式 allowlist（AI / 2D / C# / C++ 等） | 不放开任意短词或标点，避免把 `ok`、`my` 带进查询 |
| 非法仓库名 | 召回边界过滤 + warning | 一个 `owner/.github` 不应让整次运行崩溃；跳过必须记录，不能静默 |
| `--discover-only` | 只改 Markdown 展示，JSON 保留 decision + `withheld` | 判定规则不因展示需求改变；隐藏结论不等于“安全”，也不能让机器读者误以为扫描过 |
| Semgrep 规则 | 只接受本地路径 | 避免 `--config auto` 隐式联网和规则供应链风险 |
| Semgrep 缺可选依赖 | 降级内置 + warning | 外部工具不可用不应中断整次评估 |
| Semgrep 运行失败 | scan error，不静默降级 | 用户显式要求 Semgrep 时，静默换扫描器会掩盖覆盖缺口 |
| gitleaks 模式 | 追加而不替换基础扫描 | 凭据与安装钩子/执行模式是不同证据，替换会缩小覆盖 |
| gitleaks 配置 | 固定 `[extend] useDefault`，忽略仓库配置 | 否则被检查仓库可用 `.gitleaks.toml` / `.gitleaksignore` / `gitleaks:allow` 隐藏全部发现 |
| gitleaks 证据 | 只保留脱敏片段 | 报告会被复制、贴进工单和 CI 日志 |
| 多扫描器合并 | 最高风险 + 去重 + 最宽文件数 | 文件数相加会重复计数并夸大覆盖 |
| OSV 实现路径 | `osv-scanner` 二进制，不自己调 HTTP API | `querybatch` 要包名+版本，走 HTTP 等于自研六种 lockfile 解析器 |
| OSV 退出码 | 0 和 1 都算成功 | 退出码 1 表示“发现漏洞”，当成失败会把每个有漏洞的仓库变成 scan error |
| OSV 别名 | 按 `groups` 合并为一条 | 同一 advisory 的 GHSA/CVE/GO 编号不应在报告里出现三次 |
| OSV 缺 severity | 保守为 medium，不本地算 CVSS | 算错成 critical 比保守的 medium 更糟 |
| OSV 无 lockfile | `truncated=True` → 至少 INSPECT | “没找到 lockfile”不能写成“没有漏洞依赖” |

## 12. 开放问题

1. **召回质量**：topic 稀疏的仓库召回效果有限；是否需要 LLM 扩展查询？
2. **私有仓库**：codeload 需要认证；是否支持带 token 下载？
3. **正则误报**：是否需要基于 AST 的规则来区分 `pickle.load` 的来源？
4. **Scorecard 覆盖**：未收录仓库只能 INSPECT，是否提供本地 `scorecard` CLI 回退？
5. **沙箱**：Docker / gVisor 的可用性检测、超时、网络隔离怎么做？
   已定方向（M4 骨架 + CLI）：只支持本机 Docker daemon；`--network none`、只读
   bind mount、`--cap-drop ALL`、`--security-opt no-new-privileges`、非 root、
   资源上限、超时杀容器；不挂 docker socket。gVisor / runsc 仍待评估。
6. **沙箱行为探测**：设计草案见
   [docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)。是否/如何执行安装脚本、
   导入模块或运行测试，同时保证“单次运行”不被误读为安全证明？需要固定的探针协议
   和输出上限。
7. **外部扫描器覆盖**：Semgrep 的 `.semgrepignore` 仍可能让仓库缩小扫描范围；
   是否需要在隔离副本中删除该文件，或直接传入显式文件列表？
8. **策略演进**：YAML schema 后续如何做版本迁移和团队继承？
9. **报告规模**：候选很多时 Markdown 会很长；是否需要摘要模式？
10. **gitleaks 自定义规则**：当前固定使用二进制内置规则并刻意忽略仓库配置；是否需要
    `--gitleaks-config PATH`（同样必须是本地路径）让团队注入自己的 TOML？
11. **OSV 离线模式**：`--osv` 目前必须联网（`api.osv.dev`）。是否增加
    `--osv-offline` + 本地数据库路径，让不能联网的环境也能查依赖漏洞？
12. **OSV registry 访问**：解析不完整的锁文件时 osv-scanner 可能访问包管理器 registry。
    是否默认加 `--no-resolve`（只信 lockfile、不解析传递依赖）来收紧网络边界？
13. **开发依赖噪音**：`--osv` 会把 devDependencies 一起报出来（lodash 实测 119 条）。
    是否加“只看生产依赖”的开关，或在报告里把 dev/prod 分层显示？
14. **依赖漏洞的等级口径**：当前用 advisory 标签；实测 osv-scanner 按 CVSS 会多报一条
    High（GitHub 标 MODERATE、CVSS ≥ 7）。是否本地实现 CVSS v3 计算，或同时显示两种口径？
15. **短词召回噪音**：`ai` / `2d` 进入查询后，GitHub 会匹配 README，可能召回
    `china-dictatorship` 这类同时包含这些词的大仓库。是否给 `--idea` 查询加
    `in:name,description,topics`，或提供 `--strict-idea`？

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

`Pipeline` 接受 `scan_fn(root, *, limits) -> ScanReport`。Semgrep 适配器就是例子：
`SemgrepScanner.scan(...)` 复用 `ScanLimits` 和 `scanner.suppression_reason()`，
把结果转成统一 `Finding` / `ScanReport`，不需要改 verdict 或 report。

新增外部扫描器时：

1. 用 `adapters/process.py` 的 runner（argv 列表、`shell=False`、显式超时）。
2. 把工具输出当作不可信数据，限制条数、路径必须落在快照内。
3. 区分“工具不存在”（可降级）和“工具运行失败”（scan error，不静默降级）。
4. 复用 `suppression_reason()`，并让截断 / 错误进入 `ScanReport.truncated`。
5. 如果扫描器是**追加式**的（例如凭据、依赖漏洞），不要替换基础结果：返回自己的
   `ScanReport`，由 pipeline 用 `merge_scan_reports()` 合并（参考 gitleaks）。

### 增加召回来源

`stages/recall.py` 的 `recall_similar` 返回 `RecallResult`。可以并联多个来源，
统一去重后交给 `Candidate`。

### 增加新阶段

在 `Pipeline.run` 中插入阶段，并在 `models.py` 增加结果类型；结论阶段只消费结构化
证据，不直接调用外部工具。
