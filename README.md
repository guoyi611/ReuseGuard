# ReuseGuard

> Vet open-source projects before you reuse them.
>
> 复用开源项目前的安全准入编排层。

[![CI](https://github.com/guoyi611/ReuseGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/guoyi611/ReuseGuard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

ReuseGuard 不发明新的扫描器。它把 **召回相似项目 → OpenSSF Scorecard 信誉过滤 → 只读静态扫描 → 分级结论** 串成一次命令，输出一份带证据、置信度和局限说明的报告。

它想回答的问题很具体：

1. 我手上有一个仓库，有没有功能相近、维护更好的替代品？
2. 这些候选里，哪个可以直接复用，哪个需要先看一眼，哪个应该放弃？
3. 结论是基于什么证据得出的，哪些东西工具其实没有检查？

## 它是什么，不是什么

| 是 | 不是 |
| --- | --- |
| 一个把已有信号串起来的编排层 | 一个新的漏洞扫描引擎 |
| 一次命令得到分级结论和证据 | “一键保证安全”的平台 |
| 对仓库做**只读**静态检查 | 完整的行为分析或恶意软件判定 |
| 可选的容器隔离检查（不执行仓库代码） | 把“没有发现”当成“安全” |
| 明确写出每个结论的边界 | 用高分暗示“绝对安全” |
| 可替换适配器的 CLI 工具 | 锁定某个 SaaS 的托管服务 |

> ReuseGuard 的 `USE` 只表示“在当前证据下没有发现阻断性问题”，**不是安全保证**。

## 状态

v0.6.0 已经可用：

- 输入 `owner/repo`、GitHub URL、SSH clone URL，或用 `--idea` 描述需求
- 用 GitHub Search 召回相似项目，并按可解释的四维分数排序
- 用 OpenSSF Scorecard 的公开数据做信誉过滤
- 下载默认分支的只读快照，做静态风险扫描
- 可选使用**本地** Semgrep 规则集做外部静态扫描（`--semgrep-config`）
- 可选用本地 gitleaks 追加**凭据**扫描（`--gitleaks`），结果并入静态扫描
- 可选检查 lockfile 里的**已知漏洞依赖**（`--osv`，会联网查询公开 OSV 数据库）
- 可选地在容器里验证隔离配置（`--sandbox auto` / `--sandbox all`），默认关闭
- 输出 Markdown 或 JSON 报告
- 用 `--fail-on` 接入 CI

尚未实现：在沙箱内执行仓库行为（安装、导入、运行测试）；OSV 离线数据库模式。
沙箱当前只验证“容器隔离是否按配置生效”，不是行为分析。行为探测的设计草案见
[docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)（待确认，未实现）。

## 工作流

```text
                 ┌──────────────────────────────┐
owner/repo  ───► │ 1. Recall                    │
GitHub URL       │    GitHub Search API         │──► candidates
--idea TEXT  ───►│    topic / keyword / language│    + similarity score
                 └──────────────┬───────────────┘
                                │
                 ┌──────────────▼───────────────┐
                 │ 2. Reputation filter         │
                 │    OpenSSF Scorecard API     │──► passed / skipped / unknown
                 └──────────────┬───────────────┘
                                │
                 ┌──────────────▼───────────────┐
                 │ 3. Static scan (read-only)   │
                 │    tarball → safe extract    │──► findings + risk level
                 │    built-in pattern rules    │
                 └──────────────┬───────────────┘
                                │
                 ┌──────────────▼───────────────┐
                 │ 3b. Sandbox (opt-in)         │
                 │    docker run, network none, │──► containment evidence
                 │    read-only mount, limits   │    (not repository behavior)
                 └──────────────┬───────────────┘
                                │
                 ┌──────────────▼───────────────┐
                 │ 4. Verdict                   │
                 │    USE / INSPECT FIRST /     │──► Markdown / JSON
                 │    AVOID + reasons           │
                 └──────────────────────────────┘
```

## 快速开始

要求 Python 3.10+ 和 Git（仅用于克隆本项目；ReuseGuard 本身不调用 `git clone`）。

```powershell
git clone https://github.com/guoyi611/ReuseGuard.git
cd ReuseGuard

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

先离线看一份报告，不联网、不需要 token：

```powershell
reuseguard demo
```

评估一个真实仓库：

```powershell
# 推荐：有 token 时 REST 限额从 60/小时 提升到 5000/小时
$env:GITHUB_TOKEN = gh auth token

reuseguard check https://github.com/psf/requests --limit 3
```

报告默认输出到 stdout。写入文件：

```powershell
reuseguard check psf/requests --limit 3 -o reports/requests.md
reuseguard check psf/requests --no-recall --format json -o reports/requests.json
```

如果本机已登录 `gh`，ReuseGuard 会在没有 `GITHUB_TOKEN` / `GH_TOKEN` 时尝试读取 `gh auth token`。用 `--no-gh-token` 可以关闭这个行为。

没有种子仓库、只有需求描述时：

```powershell
reuseguard check --idea "a fast HTTP client with retries and connection pooling" `
  --language Python --limit 3
```

`--idea` 模式不会评估种子仓库，只返回匹配的候选；排序按关键词覆盖率、语言、活跃度和热度计算。中文需求如果没有可提取的英文关键词，会把原文作为查询词。

关键词提取使用**显式短词 allowlist**：`AI`、`2D`、`3D`、`C#`、`C++`、`Go`、`R`、`JS`、`TS` 等短但有意义的词会保留，不会因为“少于 3 个字符”被丢掉；allowlist 之外的短词和孤立标点仍然忽略，避免把 `ok`、`my` 这类噪音带进查询。

想要容器隔离证据时（需要本机 Docker，镜像必须先拉到本地）：

```powershell
# 只对静态扫描为 high / critical 的候选运行
reuseguard check psf/requests --sandbox auto

# 对所有已扫描候选运行
reuseguard check psf/requests --sandbox

reuseguard check psf/requests --sandbox auto `
  --sandbox-image python:3.11-slim --sandbox-timeout 30
```

沙箱默认关闭；没有显式开启时 ReuseGuard 不会调用 Docker。

### 示例输出

```markdown
| # | Repository | Role | Stars | Match | Scorecard | Static risk | Sandbox | Verdict |
|---:|---|---|---:|---:|---:|---|---|---|
| 1 | [acme/http-kit](https://github.com/acme/http-kit) | seed | 4,200 | — | 7.8/10 | none | — | **USE** |
| 2 | [acme/web-client](https://github.com/acme/web-client) | alternative | 2,800 | 73.6 | 8.1/10 | none | — | **USE** |
| 3 | [acme/legacy-http](https://github.com/acme/legacy-http) | alternative | 950 | 58.0 | n/a | none | — | **INSPECT FIRST** |
| 4 | [acme/suspicious-helper](https://github.com/acme/suspicious-helper) | alternative | 700 | 44.2 | 6.0/10 | high | containment ok | **AVOID** |
```

完整示例见 [examples/demo-report.md](examples/demo-report.md)（虚构数据，由 `reuseguard demo` 生成）。

## 结论怎么读

| 结论 | 触发条件（v0.3） | 建议动作 |
| --- | --- | --- |
| **USE** | Scorecard ≥ 5.0，扫描完整，无 medium 及以上有效发现，未归档 | 可以进入下一步评估，但仍需读报告 |
| **INSPECT FIRST** | 有 medium 发现；或 Scorecard 未知 / 被关闭 / < 5；或仓库已归档；或扫描被截断 / 未完成 | 人工看具体文件和原因 |
| **AVOID** | Scorecard < 2.0，或 Maintained 与 Vulnerabilities 同时为 0；或静态扫描出现 high / critical | 默认不引入；如要使用，先看证据 |

`AVOID` 是分诊结果，不是“恶意软件”的判决。静态规则会误报，报告会给出具体文件、行号和证据，方便你推翻它。

## 召回与相似度

召回不依赖 AI 对话。默认从种子仓库的 topic、主语言和描述关键词生成最多 3 条 GitHub Search 查询，去重后按下面的 0–100 分排序：

查询不会把多个 topic 用 AND 串起来（那几乎搜不到结果），而是先选一个最能描述种子的 topic，再补充关键词查询。

| 维度 | 权重 | 说明 |
| --- | ---: | --- |
| Topic 重叠 | 40 | 种子与候选 topic 集合的 Jaccard 相似度 |
| 语言匹配 | 20 | 相同语言 20；一方未知 10；不同 0 |
| 近期活跃度 | 20 | 最近 push 越新越高，三年以上衰减到 0 |
| 热度 | 20 | 星标数的对数缩放 |

分数只用于排序，不参与安全结论。召回结果受 GitHub Search 限制；**没召回不等于不存在**。

`--idea` 模式没有 topic，因此把 40 分换成关键词覆盖率：候选的仓库名、描述和 topics 中出现了多少比例的需求关键词。语言匹配 20、活跃度 20、热度 20 保持不变。

## 静态扫描覆盖什么

内置规则集刻意保持小而透明，重点覆盖复用前最值得看的模式：

| 类别 | 例子 |
| --- | --- |
| 安装期钩子 | `package.json` 的 `preinstall` / `install` / `postinstall` / `prepare`、`.pth` 启动代码、`setup.py` 的 `cmdclass`、VS Code `folderOpen` 任务 |
| 代码执行 | `eval` / `exec`、`subprocess(..., shell=True)`、`os.system`、`pickle.load(s)`、Node `child_process`、编码后执行 |
| 网络加载 | `curl ... \| bash`、PowerShell 下载并执行、`-EncodedCommand` |
| CI 风险 | `pull_request_target` 配合 checkout PR head、`permissions: write-all` |
| 混淆与伪装 | Unicode 双向控制字符（Trojan Source）、编码命令 |
| 凭据 | 私钥块、AWS / GitHub / Slack token 形态、硬编码密码赋值 |
| 其他 | `rm -rf /`、`chmod 777`、Dockerfile 远程 `ADD` |

### 误报控制

- `README`、`docs/`、`examples/`、`tests/`、`test_*`、`fixtures/` 等路径中的发现会被标记为 **suppressed**，不计入风险等级；它们仍保留在 JSON 和报告附录里。
- 锁文件、`node_modules`、`vendor/`、构建产物、压缩文件不扫描。
- 单文件默认上限 1 MB，单仓库默认上限 2000 个文件 / 20 MB；触发上限会在报告中标记“覆盖不完整”。
- 规则命中会附带文件、行号、消息和证据，方便人工判断。

### 外部扫描器：Semgrep

内置规则保持轻量，但团队通常已有自己的 Semgrep 规则。用 `--semgrep-config PATH` 开启：

```powershell
reuseguard check psf/requests --semgrep-config rules/semgrep.yaml
reuseguard check psf/requests --semgrep-config rules/ --semgrep-timeout 120
```

- 规则来源必须是**本地文件或目录**；ReuseGuard 从不使用 `--config auto`，也不隐式联网拉规则。
- 调用参数固定包含 `--json`、`--metrics=off`、`--disable-version-check`、`--no-git-ignore`、`--jobs 1`，并通过 argv 列表 + `shell=False` 执行。
- `--no-git-ignore` 防止仓库自己的 `.gitignore` 把文件藏起来。注意 Semgrep 可能仍读取仓库内的 `.semgrepignore`，这是当前已知覆盖缺口。
- 结果映射到统一的 `Finding`（`check_id`、路径、行号、severity、证据），并复用 docs/tests/examples 的抑制策略。
- Semgrep 的 `ERROR` → high、`WARNING` → medium、`INFO` → low；`metadata.severity: critical` → critical。
- Semgrep 报告解析错误或跳过文件时，扫描标记为“覆盖不完整”，结论不会当成干净。
- 找不到 `semgrep` 可执行文件时降级到内置扫描器并写 warning；Semgrep 运行失败或输出非法时记为 scan error，**不会静默降级**。

| 参数 | 默认值 | 说明 |
| --- | ---: | --- |
| `--semgrep-config PATH` | — | 本地规则文件或目录；开启 Semgrep 扫描 |
| `--semgrep-timeout SECONDS` | 300 | 整体进程上限（10–3600） |

### 外部扫描器：gitleaks（凭据）

硬编码凭据用 `--gitleaks` 开启。它是**追加**在内置扫描（或 Semgrep）之上的，不会替代已有的模式扫描：

```powershell
reuseguard check psf/requests --gitleaks
reuseguard check psf/requests --semgrep-config rules/ --gitleaks --gitleaks-timeout 600
```

- 只调用本机 `gitleaks` 二进制，不联网；需要提供 `dir` 命令的版本（v8.19+）。
- **不让被检查的仓库决定规则。** gitleaks 默认会读取快照里的 `.gitleaks.toml`（改写规则）、
  `.gitleaksignore`（忽略发现）和 `# gitleaks:allow`（行内白名单），三者都能隐藏命中。
  ReuseGuard 固定传入自己的最小配置（`[extend] useDefault = true`，即二进制内置规则），
  把 ignore 路径指向一个空的私有目录，并加 `--ignore-gitleaks-allow`。
- `--redact` 让工具先脱敏，ReuseGuard 再按 JSON 的 `Secret` 字段替换一次。报告里只有
  `[REDACTED]`、规则、文件、行号和脱敏后的匹配行，**不写入凭据原文**。
- severity：私钥和知名厂商 token（AWS / GCP / GitHub / Slack / Stripe 等）→ high；
  `generic-*` 等熵规则 → medium。gitleaks 本身没有 severity 字段。
- JSON 报告写在 ReuseGuard 的临时目录里，不写进快照，且读取有大小上限。
- 找不到 gitleaks → 跳过凭据扫描并写 warning；运行失败或输出非法 → scan error，
  **不会静默降级**。多个扫描器的结果会合并，`scanner` 显示为 `builtin-patterns+gitleaks`
  这样的组合名。
- gitleaks 不报告扫描文件数，合并报告沿用基础扫描器的计数；结论里会追加“只扫默认分支
  快照、不扫 git 历史”的 caveat。

| 参数 | 默认值 | 说明 |
| --- | ---: | --- |
| `--gitleaks` | off | 追加 gitleaks 凭据扫描（内置规则） |
| `--gitleaks-timeout SECONDS` | 300 | 整体进程上限（10–3600） |

> 已在 Windows 上用 gitleaks 8.30.1 实测：仓库自带的 `.gitleaks.toml` 和 `# gitleaks:allow`
> 无法隐藏命中；`--redact` 后证据只剩 `[REDACTED]`。

### 外部扫描器：osv-scanner（依赖漏洞）

`--osv` 让 osv-scanner 检查快照里的 lockfile，并把已知漏洞并入静态扫描：

```powershell
reuseguard check psf/requests --osv
reuseguard check psf/requests --osv --osv-timeout 600
```

- 需要 osv-scanner **v2**（`scan source --recursive`）。v1 的命令行不兼容，会以 scan error
  失败，不会静默跳过。
- **会联网**：查询公开的 OSV 数据库（`api.osv.dev`）；解析不完整的锁文件时还可能访问
  包管理器 registry。**只发送包名和版本**，不发送仓库代码。介意的话目前只能不开 `--osv`
  （离线数据库模式尚未实现）。
- 只覆盖它认识的 lockfile（`package-lock.json`、`poetry.lock`、`Cargo.lock`、`go.mod`、
  `Gemfile.lock` 等）。**没有 lockfile 时记为“覆盖不完整”，结论至少 INSPECT**，不会写成
  “没有漏洞依赖”。
- 同一漏洞的多个编号（GHSA / CVE / GO / RUSTSEC）合并为一条发现；同一 advisory 影响多个包
  时也合并成一条，列出受影响的包（最多 5 个）。
- severity 取 advisory 自带的标签（`database_specific.severity`）：critical/high → 高危，
  moderate/medium → 中危，low → 低危。**只有 CVSS 向量、没有标签的按 medium 记录**，
  不在本地重新计算分数。
- 统一 `Finding`：`rule_id = osv:<GHSA/CVE>`、`category=dependency`、`path=lockfile`；
  docs/tests 下的 lockfile 仍按误报抑制处理。
- 退出码 **1 表示“发现漏洞”，不是运行失败**；0/1 都算扫描成功，128 表示没找到任何 lockfile，
  其他退出码记为 scan error。

| 参数 | 默认值 | 说明 |
| --- | ---: | --- |
| `--osv` | off | 追加依赖漏洞扫描（联网查询 OSV） |
| `--osv-timeout SECONDS` | 300 | 整体进程上限（10–3600） |

> 已在 Windows 上用 osv-scanner 2.7.0 实测：真实 lockfile 解析、别名合并、退出码 1 都正常。
> 两个边界：递归扫描会跳过 `.` 开头的隐藏目录；lockfile 带 UTF-8 BOM 时会解析失败（记为
> scan error，不会静默放过）。

## 沙箱隔离检查（可选）

v0.3 增加了一个**默认关闭**的容器隔离检查。它验证 ReuseGuard 的隔离配置是否按预期生效，**不在沙箱里执行仓库代码**：

```text
--sandbox off    默认：不接触 Docker
--sandbox auto   只对静态扫描为 high / critical 的候选运行
--sandbox        裸参数等价于 all：对所有已扫描候选运行
--sandbox all    显式 all
```

运行条件与限制：

| 项 | 行为 |
| --- | --- |
| Docker | 先执行 `docker info` 检测守护进程；不可用只记 warning，不改变结论 |
| 镜像 | 默认 `python:3.11-slim`，可用 `--sandbox-image` 覆盖；**不会自动 pull**，镜像必须已在本地 |
| 网络 | `--network none` |
| 文件系统 | 容器根只读；快照以只读 bind mount 挂到 `/src`；`/tmp` 是 `noexec,nosuid` 的 tmpfs |
| 权限 | `--cap-drop ALL`、`--security-opt no-new-privileges`、非 root（uid 65534） |
| 资源 | 256 MB 内存（含 swap）、0.5 CPU、64 PIDs、`nofile=256` |
| 超时 | 默认 20 秒，可用 `--sandbox-timeout` 调整（1–600）；超时后 `docker rm -f` 清理 |
| 禁止项 | 不挂载 Docker socket，不使用 `--privileged`，不使用宿主网络 / PID 命名空间 |

容器里运行的是 ReuseGuard 自己的固定探测脚本：只 `stat` 文件、验证 `/src` 不可写、验证 `/tmp` 可写、验证网络不可达。报告会显示结果和失败项。

> **一次运行、一种配置，不等于安全。** 探测通过只说明这次容器隔离按配置生效；它没有执行仓库代码，不能证明仓库无害，也不代表后续版本。

## 行为探测（设计阶段，尚未实现）

M4 的下一步是在一次性容器里按固定协议执行仓库的 `import` / `test`，记录进程、文件写入、
网络能力、退出码和资源使用。**当前版本没有实现，也不会执行仓库代码。**

设计草案（探针协议、证据 schema、输出上限、镜像 digest 锁定、超时/OOM/逃逸记录，
以及“单次运行 ≠ 安全”的措辞）见
[docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)。设计确认前不会开始实现。

> 行为探测即使实现，也只提供“一次运行”的行为证据，不是安全证明；默认关闭，必须显式
> 开启并提供 `@sha256:` 锁定的镜像。

## 安全模型

ReuseGuard 自身也按“被检查的代码不可信”来设计：

- **默认不执行任何被检查的代码。** 不跑安装脚本、不跑测试、不导入模块。沙箱探测只读取文件元数据。行为探测是设计阶段（见上），即使实现也必须显式开启。
- **不使用 `git clone`。** 从 `codeload.github.com` 下载默认分支的 tar.gz，避免 hooks、submodule 和仓库本地配置。
- **安全解包。** 拒绝绝对路径、`..`、Windows 盘符 / 保留名、符号链接、硬链接和设备节点；限制文件数、单文件大小和总解压大小。
- **不跟随符号链接。** 扫描器只读普通文件，二进制文件跳过。
- **沙箱是加固后的旁路。** 只有在显式开启时才调用 Docker；命令用 argv 列表拼装（`shell=False`），固定 `--network none` / 只读挂载 / cap-drop / 非 root / 资源与超时上限，不挂 Docker socket，不用 `--privileged`，不自动拉镜像。
- **外部扫描器只读本地规则。** Semgrep 用 `--semgrep-config PATH` 的本地规则，禁止 `--config auto`；关闭 metrics、版本检查和 gitignore 绕过，不执行仓库代码。
- **gitleaks 不听仓库的配置。** 固定 `--config`（`[extend] useDefault = true`）防止快照内的 `.gitleaks.toml` 改写规则，`--gitleaks-ignore-path` 指向空目录，`--ignore-gitleaks-allow` 关闭行内白名单；报告只保留脱敏证据。
- **osv-scanner 只读 lockfile。** 不安装依赖、不运行构建；报告写在私有临时目录；没有 lockfile 时明确记为覆盖不完整，不当作“无漏洞”。
- **网络边界明确。** 默认只访问 `api.github.com`、`codeload.github.com`、`api.securityscorecards.dev`；开启 `--osv` 时额外访问 `api.osv.dev`（只发包名和版本，不发代码）。不把仓库内容上传给 LLM。
- **只访问 GitHub 和 OpenSSF Scorecard。** 不把仓库内容上传给 LLM 或其他第三方。
- **token 不落盘。** 只从环境变量或 `gh auth token` 读取，不写入报告，不打印。
- **不在报告里渲染原始 HTML。** 仓库描述等用户可控文本会做 HTML 转义。

已知边界：GitHub 生成的 tarball 本身是可信来源，但仓库内容不可信；静态扫描只覆盖文本文件，不覆盖二进制、vendored 依赖和生成代码。沙箱依赖本机 Docker daemon 与本地镜像，容器运行时本身仍是信任边界。

## 策略配置

团队可以用 YAML 覆盖阈值、限制、功能开关、规则启停和抑制路径，示例见 [examples/reuseguard.yaml](examples/reuseguard.yaml)。

```powershell
reuseguard check psf/requests --config examples/reuseguard.yaml
```

```yaml
version: 1
thresholds:
  scorecard_min: 2.0
  use_scorecard_min: 5.0
limits:
  max_candidates: 5
  min_stars: 50
features:
  recall: true
  scorecard: true
  scan: true
rules:
  disable: [generic-secret]
  severity:
    py-eval-exec: high
suppress:
  paths:
    - "src/generated/**"
```

优先级：**显式 CLI 参数 > YAML > 内置默认值**。配置文件里的未知 key、未知规则 ID、非法 severity 会直接报错，避免拼写错误悄悄放宽策略。`suppress.paths` 命中的发现仍保留在 JSON 中，但标记为 suppressed，不计入风险等级。

## CLI

```text
reuseguard check <url> [options]
reuseguard check --idea TEXT [--language LANG] [options]
reuseguard demo [--format md|json] [-o PATH]
reuseguard --version
```

`check` 常用参数：

| 参数 | 默认值 | 说明 |
| --- | ---: | --- |
| `url`（位置参数） | — | GitHub URL / `owner/repo` / SSH URL；与 `--idea` 二选一 |
| `--idea TEXT` | — | 用自然语言需求发现候选；与 `url` 二选一 |
| `--language LANG` | — | `--idea` 模式下的语言过滤 |
| `--config PATH` | — | 加载 YAML 策略（阈值、限制、规则、抑制路径） |
| `--limit N` | 5 | 最多评估多少个候选 |
| `--min-stars N` | 50 | 召回候选的最低星标数 |
| `--no-recall` | off | 只评估种子仓库（仅 URL 模式） |
| `--no-scorecard` | off | 关闭信誉过滤（结论会变成 INSPECT） |
| `--no-scan` | off | 关闭快照下载和静态扫描 |
| `--semgrep-config PATH` | — | 用本地 Semgrep 规则文件/目录扫描；绝不使用 `--config auto` |
| `--semgrep-timeout SECONDS` | 300 | Semgrep 整体进程上限（10–3600） |
| `--gitleaks` | off | 追加 gitleaks 凭据扫描；不用快照内的 `.gitleaks.toml` / `.gitleaksignore` |
| `--gitleaks-timeout SECONDS` | 300 | gitleaks 整体进程上限（10–3600） |
| `--osv` | off | 追加依赖漏洞扫描；会联网查询 OSV，只发包名和版本 |
| `--osv-timeout SECONDS` | 300 | osv-scanner 整体进程上限（10–3600） |
| `--sandbox [MODE]` | off | 容器隔离检查：`auto` 只跑 high/critical，`all` 或裸参数跑全部，`off` 关闭 |
| `--sandbox-image IMAGE` | python:3.11-slim | 沙箱镜像；必须已在本地，不会自动 pull |
| `--sandbox-timeout SECONDS` | 20 | 单次沙箱运行上限（1–600），超时杀容器 |
| `--scorecard-min SCORE` | 2.0 | 低于该分数直接跳过 |
| `--timeout SECONDS` | 20 | 单次网络请求超时 |
| `--max-repo-mb MB` | 150 | 单仓库下载上限 |
| `--max-files N` | 2000 | 单仓库扫描文件数上限 |
| `--max-file-kb KB` | 1024 | 单文件扫描上限 |
| `--max-scan-mb MB` | 20 | 单仓库扫描总字节上限 |
| `--keep-workdir` | off | 保留下载的快照，便于排查 |
| `--format md\|json` | md | 报告格式 |
| `-o, --output PATH` | stdout | 输出文件 |
| `--fail-on never\|inspect\|avoid` | never | 达到阈值时以状态码 3 退出 |
| `--no-gh-token` | off | 不读取 `gh` CLI 的 token |
| `-v, --verbose` / `-q, --quiet` | off | 日志详细程度 |

退出码：`0` 成功；`1` 运行时 / 网络错误；`2` 参数或 URL 无效；`3` 触发了 `--fail-on` 阈值。

## 局限

- 静态分析无法证明代码无害；它只能发现已知形态的模式。
- Scorecard 衡量的是项目实践和卫生，不是具体代码的安全性。
- 召回依赖 GitHub Search，查询词和限额会影响结果。
- 不扫描 vendored 依赖、二进制文件、生成代码；这些地方也可能有风险。
- 结果是运行时刻的快照；之后的新 commit 可能行为不同。
- v0.3 的沙箱只验证容器隔离配置，不执行仓库代码；行为探测仍是设计草案
  （[docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)），未实现。两者都不能替代
  人工审计。
- 沙箱需要本机 Docker 守护进程和预拉取的镜像；不可用时只记 warning，不改变结论。
- Semgrep 的覆盖范围完全取决于你提供的规则集；ReuseGuard 不内置或联网获取规则。
- gitleaks 只扫描默认分支快照，不覆盖 git 历史；漏报取决于其内置规则，没有命中不等于没有凭据。
- osv-scanner 只检查它认识的 lockfile；没有 lockfile 时不做依赖判断（开启 `--osv` 会把结论压到 INSPECT）。离线数据库模式尚未实现。
- `--osv` 会把开发依赖也算进去（lodash 实测一次 119 条），当前没有 dev/prod 过滤，报告会显得很吵但结果是真实的。

## 开发

```powershell
python -m pip install -e ".[dev]"
python -m pytest
ruff check src tests
ruff format --check src tests
```

测试全部使用 fake adapter，不访问网络。想在本地跑真实链路，直接用 `reuseguard check`，或设置 `GITHUB_TOKEN` 后运行。

## Roadmap

- **M1（已完成）**：种子 URL → 召回 → Scorecard → 静态扫描 → Markdown
- **M2（已完成）**：JSON 输出、`--fail-on`、误报抑制、离线 demo、测试与 CI
- **M3（已完成）**：`--idea` 自然语言需求输入、关键词召回与排序
- **M4（进行中）**：隔离动态验证；已完成安全骨架与 CLI 接入（Docker 检测、
  加固容器命令、隔离探测、`--sandbox` 触发、报告区块、fake runner 测试），
  行为探测设计草案见 [docs/m4-behavior-probe.md](docs/m4-behavior-probe.md)（待确认），
  待做“在沙箱内执行仓库行为”
- **M5（已完成）**：可插拔外部扫描器。Semgrep（本地规则、替换内置扫描）、
  gitleaks（凭据、追加）、osv-scanner（依赖漏洞、追加）；统一 `Finding`、
  多扫描器合并、降级与错误边界
- **M6（已完成）**：YAML 策略配置，支持阈值、限制、规则启停、severity 覆盖和抑制路径

设计取舍和阶段规则见 [project.md](project.md)。

## 名字说明

`ReuseGuard` = Reuse（复用）+ Guard（守卫）。密码学领域也有一个同名术语（防 nonce 重用的 ReuseGuard），与本项目无关。

## License

[MIT](LICENSE)
