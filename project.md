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

## 4. 当前状态（v0.4.0）

已实现：

- 输入解析：GitHub URL / `owner/repo` / SSH URL，或 `--idea` 需求描述
- 召回：GitHub Search，最多 3 条查询，四维相似度排序
- 信誉过滤：OpenSSF Scorecard 公共服务
- 快照：`codeload.github.com` tarball，安全解包，无 `git clone`
- 静态扫描：内置规则集，带误报抑制和覆盖上限
- 外部扫描器：Semgrep 适配器（本地规则、JSON → 统一 `Finding`、降级 / 错误边界）
- 结论：USE / INSPECT FIRST / AVOID + 置信度 + 理由 + 局限
- 输出：Markdown / JSON
- CLI：`check`、`--idea`、`--config`、`--semgrep-config`、`--sandbox`、`demo`、
  `--fail-on`、`--keep-workdir`
- 策略：YAML 阈值、限制、规则启停、severity 覆盖、抑制路径
- 沙箱隔离检查（默认关闭）：Docker 检测、加固 `docker run`、容器内隔离探测、
  报告区块；`--sandbox auto` 只跑 high/critical，`--sandbox` / `all` 跑全部
- 测试：fake adapter / fake runner，全离线

未实现：

- 在沙箱内执行仓库行为（安装、导入、运行测试）
- OSV（lockfile）与 gitleaks（secret）适配器
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
| `SandboxReport` | 一次容器隔离探测的证据 | status, image, exit_code, timed_out, containment_ok, probe, error |
| `Verdict` | 最终结论 | decision, confidence, reasons, limitations |
| `Assessment` | 一个仓库的全部证据 | candidate, filter, scan, verdict, sandbox |
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
  filter score < use_scorecard_min           → INSPECT
  otherwise                                     → USE (high confidence)
```

`use_scorecard_min` 默认 5.0，可用 `--config` 的 `thresholds.use_scorecard_min` 覆盖；
`--scorecard-min`（默认 2.0）是 **skip 门槛**，两者不同：

- < scorecard_min：连扫描都不做，直接 AVOID
- scorecard_min–use_scorecard_min：扫描，但结论最多 INSPECT
- ≥ use_scorecard_min 且扫描干净：USE

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

## 8. 安全模型

被检查的仓库是不可信输入。安全边界：

1. **不执行**：不跑安装脚本、测试、构建，不 import 模块。沙箱探测只读文件元数据。
2. **不 clone**：避免 hooks、submodule、仓库本地 config；tarball 由 GitHub 生成。
3. **解包防护**：见 7.3；解包路径必须位于目标目录内。
4. **只读扫描**：不修改快照；不跟随 symlink；二进制跳过。
5. **沙箱加固**：默认关闭；仅在显式模式下调用 Docker。argv 列表、`shell=False`，
   固定 `--network none` / 只读挂载 / cap-drop / 非 root / 资源与超时上限，不挂
   Docker socket，不用 `--privileged`，不自动 pull。挂载源拒绝文件系统根、home
   及其祖先、含逗号 / 换行的路径。
6. **外部扫描器**：Semgrep 只接受本地规则路径，禁止 `--config auto`，关闭
   metrics / 版本检查；argv 列表、`shell=False`、显式超时；输出按不可信 JSON 解析，
   越界路径丢弃。
7. **网络边界**：只访问 `api.github.com`、`codeload.github.com`、
   `api.securityscorecards.dev`。不调用 LLM，不上传内容。Semgrep 不会因扫描而联网
   （本地规则 + `--metrics=off` + `--disable-version-check`）。
8. **凭据**：token 只从 `GITHUB_TOKEN` / `GH_TOKEN` / `gh auth token` 读取；
   不写入报告、不打印、不落盘。
9. **报告注入**：仓库描述、finding 证据等用户可控文本会做 HTML 转义；表格中的
   `|` 会转义。容器探测输出和外部扫描器输出同样按不可信数据处理。

剩余风险：

- tarball 下载和解压仍消耗磁盘 / 带宽；已有大小上限，但不是硬隔离。
- 静态扫描存在漏报；沙箱当前只验证隔离，不观察仓库行为。
- Semgrep 的覆盖范围取决于用户提供的规则集；`.semgrepignore` 仍可能缩小扫描范围。
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
- 结论测试覆盖 7.5 的每条分支。
- CLI 测试覆盖 `demo`、非法 URL、`--fail-on` 退出码、`--sandbox` 参数组合。
- 真实网络和真实 Docker 只用于手动验收，不进入默认 CI。

手动验收命令：

```powershell
reuseguard check psf/requests --limit 2
reuseguard check elastic/elasticsearch-py --limit 0
reuseguard check tconbeer/harlequin --limit 0
reuseguard check --idea "fast HTTP client with retries" --language Python --limit 3
reuseguard check psf/requests --config examples/reuseguard.yaml
reuseguard check psf/requests --no-recall --sandbox all
reuseguard check psf/requests --no-recall --semgrep-config rules/
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
  - 边界：单次运行只代表当次容器配置，不是“无害证明”
- **M5（进行中）**：外部扫描器
  - 已完成：Semgrep 适配器
    - `adapters/process.py`：共享的 argv / `shell=False` / 超时 runner
    - `adapters/semgrep.py`：本地规则、JSON 解析、severity 映射、抑制、截断
    - `--semgrep-config` / `--semgrep-timeout`；缺可执行文件才降级到内置
    - 非零退出 / 坏 JSON / 超时 / 缺配置 → scan error，不静默降级
  - 待办：OSV（lockfile）与 gitleaks（secret）适配器；统一 finding schema 扩展
- **M6（已完成）**：YAML 策略
  - `--config PATH`
  - 阈值、限制、features 开关、规则启停、severity 覆盖、抑制 glob
  - 未知 key / 规则 / 类型直接报错

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
| Semgrep 规则 | 只接受本地路径 | 避免 `--config auto` 隐式联网和规则供应链风险 |
| Semgrep 缺可选依赖 | 降级内置 + warning | 外部工具不可用不应中断整次评估 |
| Semgrep 运行失败 | scan error，不静默降级 | 用户显式要求 Semgrep 时，静默换扫描器会掩盖覆盖缺口 |

## 12. 开放问题

1. **召回质量**：topic 稀疏的仓库召回效果有限；是否需要 LLM 扩展查询？
2. **私有仓库**：codeload 需要认证；是否支持带 token 下载？
3. **正则误报**：是否需要基于 AST 的规则来区分 `pickle.load` 的来源？
4. **Scorecard 覆盖**：未收录仓库只能 INSPECT，是否提供本地 `scorecard` CLI 回退？
5. **沙箱**：Docker / gVisor 的可用性检测、超时、网络隔离怎么做？
   已定方向（M4 骨架 + CLI）：只支持本机 Docker daemon；`--network none`、只读
   bind mount、`--cap-drop ALL`、`--security-opt no-new-privileges`、非 root、
   资源上限、超时杀容器；不挂 docker socket。gVisor / runsc 仍待评估。
6. **沙箱行为探测**：是否/如何执行安装脚本、导入模块或运行测试，同时保证
   “单次运行”不被误读为安全证明？需要固定的探针协议和输出上限。
7. **外部扫描器覆盖**：Semgrep 的 `.semgrepignore` 仍可能让仓库缩小扫描范围；
   是否需要在隔离副本中删除该文件，或直接传入显式文件列表？
8. **策略演进**：YAML schema 后续如何做版本迁移和团队继承？
9. **报告规模**：候选很多时 Markdown 会很长；是否需要摘要模式？

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

### 增加召回来源

`stages/recall.py` 的 `recall_similar` 返回 `RecallResult`。可以并联多个来源，
统一去重后交给 `Candidate`。

### 增加新阶段

在 `Pipeline.run` 中插入阶段，并在 `models.py` 增加结果类型；结论阶段只消费结构化
证据，不直接调用外部工具。
