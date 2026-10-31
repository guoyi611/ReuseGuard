# ReuseGuard 交接文档

> 最后更新：2026-10-31
> 仓库：https://github.com/guoyi611/ReuseGuard
> 分支：`main`
> 当前版本：`0.6.0`
> 基线提交：`da9ffa4 feat: add OSV dependency-vulnerability adapter`（M5 第三步，
> M5 完成；第二步 `c7d0595`，第一步 `c711b42`，M4 基线 `f39c84b`）
> CI：全部通过（Ubuntu 3.10/3.11/3.12 + Windows 3.11）

这份文档用于把当前会话的上下文交给下一个对话。新对话请先读本文件，再执行
`git status`、`git log --oneline -5` 和 `python -m pytest`，确认起点。

## 1. 项目是什么

ReuseGuard 是“复用开源项目前的安全准入编排层”，不是新的扫描器。它把：

```text
输入（种子仓库 URL / --idea 需求描述）
  → GitHub Search 召回
  → OpenSSF Scorecard 信誉过滤
  → codeload tarball 只读快照 + 安全解包
  → 内置静态规则扫描
  → USE / INSPECT FIRST / AVOID + 置信度 + 理由 + 局限
  → Markdown / JSON
```

串成一条 CLI 流水线。核心原则：**不执行被检查的代码**。

## 2. 当前完成度

| 里程碑 | 状态 | 内容 |
| --- | --- | --- |
| M1 | 完成 | 种子 URL → 召回 → Scorecard → 静态扫描 → Markdown |
| M2 | 完成 | JSON、`--fail-on`、误报抑制、离线 demo、测试、CI、打包 |
| M3 | 完成 | `--idea` 自然语言输入、关键词召回与排序、`Report.seed=None` |
| M4 | **进行中（骨架完成）** | 隔离动态验证：Docker 检测、加固容器、隔离探测、`--sandbox` CLI / pipeline / 报告均已接入；**不在沙箱内执行仓库代码**，真实 Docker 冒烟待做 |
| M5 | **完成** | 三个适配器：Semgrep（替换内置）、gitleaks（追加凭据）、osv-scanner（追加依赖漏洞）；统一 Finding、合并、降级/错误边界 |
| M6 | 完成 | YAML 策略：阈值、限制、features、规则启停、severity、抑制路径 |

当前测试：**359 个，全部离线通过**；`ruff check` / `ruff format --check` 全绿；
wheel / sdist 构建成功，v0.2.0 在干净 venv 中验证过 console script（0.6.0 待重建验证）。

## 3. 代码地图

```text
src/reuseguard/
├── cli.py              # argparse、输入校验、配置合并、日志、退出码
├── config.py           # Settings、YAML Policy、ConfigError、token 解析
├── models.py           # 纯数据契约（无 I/O）
├── pipeline.py         # run(seed) / run_idea(idea) / _execute / _scan
├── report.py           # Markdown / JSON 渲染
├── demo.py             # 固定日期的离线 demo
├── adapters/
│   ├── github.py       # GitHub REST 元数据 + search
│   ├── scorecard.py    # OpenSSF Scorecard API
│   ├── snapshot.py     # codeload 下载 + 安全解包
│   ├── scanner.py      # 内置规则、KNOWN_RULE_IDS、suppression_reason()
│   ├── process.py      # 共享 argv 子进程边界（shell=False + 超时）
│   ├── semgrep.py      # Semgrep JSON → 统一 ScanReport
│   ├── gitleaks.py     # gitleaks JSON → 统一 ScanReport（凭据脱敏）
│   ├── osv.py          # osv-scanner JSON → 统一 ScanReport（依赖漏洞）
│   └── sandbox.py      # Docker 检测 + 加固 docker run + 隔离探测
└── stages/
    ├── recall.py       # seed 召回 + idea 召回 + 相似度
    ├── reputation.py   # Scorecard → FilterResult
    └── verdict.py      # Filter + Scan → Verdict（含 add_sandbox_caveat）
```

测试：

```text
tests/
├── fakes.py            # FakeGitHub / FakeScorecard / snapshot / FakeCommandRunner
├── test_cli.py
├── test_config.py
├── test_models.py
├── test_pipeline.py
├── test_policy.py
├── test_recall.py
├── test_report.py
├── test_reputation.py
├── test_sandbox.py
├── test_scanner.py
├── test_semgrep.py
├── test_gitleaks.py
├── test_osv.py
├── test_snapshot.py
└── test_verdict.py
```

## 4. 上一会话实际改动（M3 / M6）

1. **M3 自然语言输入**
   - `check --idea TEXT [--language LANG]`
   - `--idea` 与 URL 互斥；不能和 `--no-recall` 同用；`--limit` 至少 1
   - 需求关键词提取（忽略停用词；不过滤 `client` 这类领域词）
   - 两条查询：前 4 个关键词、前 2 个关键词；纯中文无 ASCII 关键词时回退原文
   - 排序：关键词覆盖率 40 + 语言 20 + 活跃度 20 + 热度 20
   - `Report.seed` 改为可空，新增 `Report.query`；报告头显示 `Idea:`
   - `Candidate.role="candidate"`；`Similarity.keywords` 新字段

2. **M6 YAML 策略**
   - `--config PATH`
   - `thresholds.scorecard_min` / `use_scorecard_min`
   - `limits.*`、`features.recall/scorecard/scan`
   - `rules.disable`、`rules.severity`
   - `suppress.paths`（glob，命中仍记录但 suppressed）
   - 未知 key / 未知 rule ID / 非法类型或 severity 直接 `ConfigError`
   - 优先级：显式 CLI > YAML > 内置默认
   - 示例：`examples/reuseguard.yaml`
   - `Settings.public_dict()` 把最终策略写进报告，便于审计

3. **精度修正**
   - `AKIAIOSFODNN7EXAMPLE` 这类文档占位密钥不再触发 high
   - demo 使用固定日期，避免每天 diff
   - v0.2.0 版本号

## 4.1 本会话 M4：沙箱安全骨架 + 接入

新增 `src/reuseguard/adapters/sandbox.py`、`SandboxReport` / `SandboxStatus` 数据模型，
并接入 pipeline / CLI / report：

- `detect_docker()`：`docker info --format '{{.ServerVersion}}'`，缺失可执行文件、
  守护进程不可达、超时、空版本都降级为 `available=False` + 原因。
- `build_plan()`：只从允许列表拼 argv（`shell=False`），固定：
  `--network none`、`--read-only`、`--tmpfs /tmp:rw,noexec,nosuid,size=64m`、
  `--cap-drop ALL`、`--security-opt no-new-privileges`、`--user 65534:65534`、
  `--pids-limit`、`--memory` / `--memory-swap`、`--cpus`、`--ulimit nofile`、
  `--pull=never`、只读 bind mount 到 `/src`。**不挂 docker socket、不用
  `--privileged`、不用 `--volume`/`-v`**。
- 挂载源校验：必须存在、是目录、不是文件系统根、不是 home 或其祖先、路径不含逗号
  或换行（避免破坏 `--mount` 语法）。
- `run_probe()`：超时杀容器（`docker rm -f <name>`）；记录退出码、耗时、
  timeout、`oom_suspected`（退出码 137 的启发式标记）。
- 容器内 `_PROBE_SCRIPT` 是 ReuseGuard 自己的固定脚本：只 `stat` 文件、测试
  `/src` 只读、`/tmp` 可写、`--network none` 下网络不可达。**不 import、不安装、
  不执行仓库代码**。
- 触发：`--sandbox off`（默认）/ `auto`（只跑 high/critical）/ `all`（裸
  `--sandbox` 等价 all）；`--sandbox-image`、`--sandbox-timeout`（1–600）。
  Docker 不可用只写 warning，不改变结论；`--sandbox` 与 `--no-scan` 互斥。
- 报告：summary 新增 `Sandbox` 列；每个仓库新增 `### Sandbox — ...` 区块，展示
  镜像、耗时、网络、挂载、内存 / CPU / PID、探测结果；失败时明确
  “containment NOT verified”。结论只追加 caveat，不升级也不判恶意。
- 版本：0.3.0。
- 测试 `tests/test_sandbox.py`（36 个）+ pipeline / CLI / report / config 用例，
  全部用 `FakeCommandRunner` / fake detector，不启动 Docker。唯一真实子进程测试
  只验证缺失可执行文件的降级。

诚实边界：当前探测验证的是**容器隔离配置**，不是仓库行为。`containment_ok=True`
不等于仓库安全；报告与文档必须这么写。

## 4.2 本会话 M5 第一步：Semgrep 适配器

新增：

- `src/reuseguard/adapters/process.py`：从 sandbox 抽出的共享 runner
  （`CommandResult` / `CommandRunner` / `run_command`）。sandbox 现在从这里导入。
- `src/reuseguard/adapters/semgrep.py`：
  - `SemgrepOptions`（本地 config、rule timeout、process timeout、max memory）
  - `SemgrepScanner.scan(root, limits=..., disabled_rules=..., severity_overrides=...,
    suppress_globs=...) -> ScanReport`
  - `SemgrepUnavailable`：只有“可执行文件不存在”才抛，pipeline 降级到内置扫描器
  - 固定 argv：`semgrep scan --json --quiet --metrics=off --disable-version-check
    --no-git-ignore --config <PATH> --timeout 30 --max-target-bytes N --max-memory N
    --jobs 1 <root>`；**禁止 `--config auto`**
  - severity：ERROR→high、WARNING→medium、INFO→low、metadata critical→critical
  - 路径必须落在快照内，越界丢弃；复用 `scanner.suppression_reason()`
  - `errors` / `skipped` 非空或命中数超限 → `truncated=True`
  - 非零退出、超时、坏 JSON、缺 config → `ScanReport(status=ERROR, scanner="semgrep")`，
    **不静默降级**
- CLI：`--semgrep-config PATH`、`--semgrep-timeout SECONDS`（10–3600）
  - config 必须存在；不能与 `--no-scan` 同用
  - `--semgrep-timeout` 不能单独使用
  - semgrep 不在 PATH → warning，实际由 pipeline 降级
- Pipeline：`Settings.semgrep_config` 有值时优先 Semgrep；只有 `SemgrepUnavailable`
  回退内置并写 warning；其他错误直接 scan error。
- Report：run details 显示 `Scanner: semgrep`、config、timeout；limitations 增加
  “外部规则集决定覆盖范围”。
- 版本：0.4.0。
- 测试：`tests/test_semgrep.py` 31 个 + pipeline / CLI 用例，全部 `FakeCommandRunner`；
  CI 不安装 Semgrep。

诚实边界：

- 扫描的是本地规则集；没写的规则不会产生 finding，不能把“0 findings”当安全。
- Semgrep 仍可能读取仓库内 `.semgrepignore`，可能缩小覆盖范围（已记入开放问题）。
- 没有在 CI 里跑真实 Semgrep；只在 fake runner 层验证命令与解析。

## 4.3 本会话 M5 第二步：gitleaks 适配器

新增 `src/reuseguard/adapters/gitleaks.py`、`models.merge_scan_reports()`，并接入
config / CLI / pipeline / report / verdict：

- `gitleaks dir <root>`（**需要 v8.19+**；`detect --no-git` 已弃用，不使用）。固定
  `--report-format json --report-path <tmp>/report.json --exit-code 0 --redact
  --no-banner --no-color --ignore-gitleaks-allow --max-target-megabytes N
  --gitleaks-ignore-path <tmp> --config <tmp>/reuseguard-gitleaks.toml`。
- **仓库不能决定规则**：gitleaks 默认会读快照里的 `.gitleaks.toml`（可整体 allowlist）、
  `.gitleaksignore` 和 `# gitleaks:allow`。适配器写一个最小配置
  `[extend] useDefault = true` 并用 `--config` 固定；ignore 路径指向空的私有目录；
  `--ignore-gitleaks-allow` 关掉行内白名单。
- 报告写私有临时目录（不写快照），读取上限 16 MB（`MAX_REPORT_BYTES`），JSON 允许
  顶层数组、`null`、以及 `{"leaks": [...]}` 三种形状。
- **凭据脱敏**：工具先 `--redact`，适配器再从 `Secret` 字段替换一次；`Finding.evidence`
  只保留单行脱敏片段。secret 缺失或 < 4 字符时直接不给 evidence（避免部分泄露）。
  `Secret` 原文不进入任何 `Finding` 字段，测试用 `to_jsonable(report)` 断言原文不出现。
- severity 映射（gitleaks 没有 severity）：私钥 + 知名厂商（aws/gcp/github/gitlab/
  slack/stripe/twilio/npm/pypi/jwt…）→ high；`generic-*` 与未知规则 → medium。
- `rule_id` 加 `gitleaks:` 前缀（如 `gitleaks:aws-access-token`），避免与内置规则
  同名；`disabled_rules` / `severity_overrides` 同时接受带前缀和不带前缀的 ID。
- 复用 `suppression_reason()` 与 `ScanLimits`；命中超限 → `truncated=True`。
- **追加而非替换**：pipeline 先跑内置（或 Semgrep），再跑 gitleaks，最后
  `merge_scan_reports()`：取最高 risk、按 `(rule_id, path, line)` 去重、`files_scanned`
  取最宽而不是相加（gitleaks 不报告文件数）。
- 失败语义：可执行文件缺失 → `GitleaksUnavailable` → 跳过 + warning；超时/非零退出/
  126/坏 JSON/报告缺失或过大 → `ScanReport(status=ERROR, scanner="gitleaks")`，
  合并后整份 scan 为 ERROR，结论 INSPECT，**不静默降级**。
- CLI：`--gitleaks`、`--gitleaks-timeout`（10–3600，默认 300）；不能与 `--no-scan` 同用；
  timeout 不能单独使用；gitleaks 不在 PATH → warning。
- 版本：0.5.0。测试：`tests/test_gitleaks.py` 36 个 + models 合并 8 个 + pipeline 5 个
  + CLI 5 个，全部 fake runner / 临时目录，CI 不安装 gitleaks。

诚实边界：

- 只扫默认分支快照，不扫 git 历史；`containment` 那套 caveat 不适用于它，但结论里会写
  “没发现凭据 ≠ 从未提交过凭据”。
- 没有真实 gitleaks 二进制验收（本机未安装、也没联网下载）；命令与解析只在 fake
  runner 层验证。首次真实运行时重点确认 `dir` 命令、`[extend] useDefault`、
  `--gitleaks-ignore-path` 指向空目录不报错。
- gitleaks 不报告扫描文件数，合并报告沿用基础扫描器的 `files_scanned`；如果将来让
  gitleaks 单独出报告，`files_scanned == 0` 会触发 INSPECT。
- 外部规则 ID 还不能写进 YAML 的 `rules.disable` / `rules.severity`（配置校验只认
  `KNOWN_RULE_IDS`）；目前只有程序内调用能覆盖 gitleaks 规则。

## 4.4 本会话 M5 第三步：OSV lockfile 适配器

新增 `src/reuseguard/adapters/osv.py`，接入 config / CLI / pipeline / report / verdict。

- 决定用 **osv-scanner v2 二进制**，不自己调 `api.osv.dev/v1/querybatch`：那个接口收的是
  “包名 + 版本”，不是 lockfile，走 HTTP 等于自研 npm / pip / poetry / go / cargo / gem
  的解析器。
- 固定 argv：`osv-scanner scan source --recursive <root> --format json
  --output-file <tmp>/osv.json`。v1 的 `-r` 命令行不兼容，会以 scan error 失败。
- **退出码语义（容易踩）**：0 = 有包无漏洞，1 = 有漏洞（正常结果，不是失败），
  128 = 没找到 lockfile，127 = 一般错误，其余也记为 scan error。
- 解析 `results[].packages[].groups`：同一 advisory 的多个编号（GHSA / CVE / GO / RUSTSEC）
  已被工具按别名归并，**一个 group 只出一条 finding**，不会同一漏洞报三次。
- 同一 advisory 命中同一 lockfile 的多个包 → 合并成一条并列出受影响包（最多 5 个）；
  不同 lockfile 各自一条，`path` 不同所以不会被 `merge_scan_reports()` 去重掉。
- severity 取 `database_specific.severity` / `ecosystem_specific.severity` 标签；
  **只有 CVSS 向量时按 medium**，不在本地重算（算错成 critical 比保守 medium 更糟）。
- `rule_id = osv:<首选编号>`、`category="dependency"`、`path=lockfile`、`line=None`；
  `evidence` 只放 `包名@版本` + osv.dev 链接。
- **没有 lockfile（退出码 128）→ SCANNED + truncated=True**，pipeline 写 warning，结论至少
  INSPECT。这是本步最重要的一条诚实性约束：不能把“没找到 lockfile”写成“没有漏洞依赖”。
- 失败语义：可执行文件缺失 → `OsvUnavailable` → 跳过 + warning；超时 / 非 0-1-128 退出 /
  坏 JSON / 缺报告 / 超限 → `ScanReport(status=ERROR, scanner="osv")`，合并后整份 ERROR。
- 版本 0.6.0。CLI：`--osv` / `--osv-timeout`（10–3600，默认 300），默认关闭，不能与
  `--no-scan` 同用。
- 测试：`tests/test_osv.py` 48 个（含参数化）+ pipeline 6 个 + CLI 5 个（含参数化）
  + report 2 个，全部 fake runner + 临时报告文件，CI 不安装 osv-scanner、不联网。

诚实边界：

- 没有真实 osv-scanner 验收（本机未安装）。命令、JSON 结构、退出码都按官方 v2 文档写，
  首次真跑要确认 `--output-file` 行为、`groups` 是否总出现、退出码 128 的实际触发条件。
- `--osv` **会联网**；解析不完整锁文件时 osv-scanner 可能访问包管理器 registry。已写进
  README / project.md 的网络边界。离线数据库模式未做。
- 只覆盖工具认识的 lockfile；Monorepo 里多个 lockfile 会各出一条，报告会变长。
- 严格档下，critical/high 的依赖漏洞会让结论变成 AVOID；这是产品选择，不是“项目恶意”。
  报告 caveat 写了“通常可以通过升级修复”。

## 5. 如何运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

reuseguard demo
reuseguard check psf/requests --limit 3
reuseguard check --idea "a fast HTTP client with retries" --language Python --limit 3
reuseguard check psf/requests --config examples/reuseguard.yaml
reuseguard check psf/requests --no-recall --sandbox all
reuseguard check psf/requests --no-recall --sandbox auto --sandbox-timeout 30
reuseguard check psf/requests --no-recall --semgrep-config rules/semgrep.yaml
reuseguard check psf/requests --no-recall --semgrep-config rules/ --semgrep-timeout 120
reuseguard check psf/requests --no-recall --gitleaks
reuseguard check psf/requests --no-recall --semgrep-config rules/ --gitleaks --gitleaks-timeout 600
reuseguard check psf/requests --no-recall --osv
reuseguard check psf/requests --no-recall --gitleaks --osv --osv-timeout 600
```

需要 token 时：

```powershell
$env:GITHUB_TOKEN = gh auth token
```

没有 token 也能跑，但 GitHub REST 限额是 60/小时、搜索 10/分钟。

测试与构建：

```powershell
python -m pytest
ruff check src tests
ruff format --check src tests
python -m build
```

## 6. 关键设计取舍

- **不用 `git clone`**：codeload tarball，避免 hooks / submodule / 本地 config。
- **静态扫描默认内置规则**：保证零重依赖；Semgrep 作为可选适配器，需要显式
  `--semgrep-config` 才启用。
- **Scorecard 只读公开 API**：不执行第三方构建；未收录时 `UNKNOWN → INSPECT`。
- **不使用 LLM**：召回是 GitHub Search + 关键词，不是语义搜索。
- **误报抑制**：docs/tests/examples/fixtures 降权；vendor/generated/minified 跳过。
- **风险分级**：critical/high → AVOID；medium → INSPECT；低风险 + Scorecard ≥ 5
  且扫描完整 → USE。
- **沙箱默认关闭且不执行仓库代码**：只验证容器隔离配置；Docker 不可用只降级为
  warning + `UNAVAILABLE`，不改变结论。`containment_ok=True` 不是“无害证明”。
- **外部扫描器分级接入**：Semgrep 替换内置扫描（用户显式给规则集）；gitleaks 追加到
  基础扫描之后（凭据与模式是不同证据）。gitleaks 固定本地配置，仓库内的
  `.gitleaks.toml` / `.gitleaksignore` / `gitleaks:allow` 一律不生效；报告只留脱敏证据。
- **OSV 只信 lockfile 里的证据**：退出码 1 是“有漏洞”不是失败；按 `groups` 合并别名；
  severity 缺失时保守为 medium；**没有 lockfile 记为覆盖不完整**，绝不写成“无漏洞依赖”。
  代价是开启 `--osv` 时会联网查询 `api.osv.dev`（只发包名和版本）。

## 7. 已知问题 / 雷区

1. **远程是 SSH 地址**：`git@github.com:guoyi611/ReuseGuard.git`。本沙箱里 Git 的
   HTTPS credential helper 会因命名管道限制失败，SSH 也需要显式 `GIT_SSH`：
   ```powershell
   $env:GIT_SSH = (Get-Command ssh).Source
   $env:GIT_SSH_VARIANT = "ssh"
   git push github main
   ```
   不要为了“修推送”把 token 写进 URL、`.git/config` 或提交里。

2. **`gh` 的 OAuth token 没有 `workflow` scope**。HTTPS 推送包含
   `.github/workflows/ci.yml` 的提交会被 GitHub 拒绝；当前已通过 SSH 推送成功。
   如果以后改回 HTTPS，需要 `gh auth refresh -s workflow`。

3. **私有仓库不完整**：元数据可带 token 读，但 `fetch_snapshot` 不向 codeload 发送
   token，私有仓库会 scan error → INSPECT。

4. **扫描器是启发式**：仍可能误报/漏报；不要把它当作恶意软件判决。修改规则后
   一定要跑真实仓库回归。

5. **PyYAML 是运行时依赖**：`pyproject.toml` 已加 `PyYAML>=6.0,<7`；CI 会安装。

6. **`.tools/`、`.venv/`、`dist/`、`reports/` 都是本地生成物**，已 gitignore。
   不要提交。

7. **沙箱没有做真实 Docker 验收**：当前测试全部用 fake runner。真实运行时注意：
   - 镜像必须已在本地（`--pull=never`，不会自动 pull）；缺失会记为 sandbox error。
   - 容器以 uid 65534 运行，pipeline 会把 workdir chmod 到 755；如果手工调用
     `run_probe()`，快照目录必须对该用户可读，否则 `containment_ok=False`。
   - Windows / Docker Desktop 的 bind mount 权限语义与 Linux 不同，需要在目标平台
     单独冒烟。
   - 超时只保证杀掉容器；宿主机 Docker daemon 卡死时 `docker rm -f` 也可能超时。

8. **gitleaks 需要 `dir` 命令（v8.19+）**：更老的版本以退出码 126 失败，适配器记为
   scan error，不会静默降级。**还没有真实 gitleaks 验收**（本机未安装、也未联网下载）；
   首次真跑时确认 `dir`、`[extend] useDefault`、`--gitleaks-ignore-path` 指向空目录
   这三处。若空目录会报错，改成传一个显式的空 `.gitleaksignore` 文件路径。

9. **Python 包没有装进 `.venv`**：本会话用 `$env:PYTHONPATH="src"` 跑 pytest，ruff 用
   `.tools\bin\ruff.exe`。直接 `python -m pytest` 会 `ModuleNotFoundError`。

10. **osv-scanner 需要 v2**：v1 的 `-r` 命令行不兼容，会以 scan error 失败。**同样没有真实
    二进制验收**；首次真跑重点确认 `--output-file`、`groups`、退出码 1/128。`--osv` 会联网
    （`api.osv.dev`，可能还有包管理器 registry），只发包名和版本。

## 8. 下一步建议：M4 收尾 / 行为探测

现状：安全骨架 + CLI / pipeline / 报告已完成。目标仍是“对 high/critical 或用户
显式要求的高风险候选，在容器里观察行为”，**默认关闭**，绝不在宿主机执行被检查代码。

已完成：

1. ~~新增 `adapters/sandbox.py`~~ **（已完成）**：
   - `detect_docker()`，检测 `docker info` 是否可用
   - `build_plan()`：`--network none`、只读挂载快照、`--memory`、`--cpus`、
     `--pids-limit`、`--read-only`、`--tmpfs /tmp`、超时杀容器
   - 不挂载 docker socket，不使用 `--privileged`
   - 记录 stdout/stderr、退出码、超时、OOM 标记
   - **不要**把执行结果当成“无害证明”，只作为行为证据
2. ~~新增 `SandboxReport` 数据模型~~ **（已完成）**；verdict caveat、`--sandbox` /
   `--sandbox-image` / `--sandbox-timeout` CLI 参数**已完成**，默认关闭
3. ~~只有 `scan.risk in {high, critical}` 或显式 `--sandbox` 才触发~~ **（已完成）**：
   `off` / `auto` / `all` 三态
4. ~~测试全部用 fake runner~~ **（已完成）**：`tests/test_sandbox.py` 36 个 +
   pipeline / CLI / report / config 用例，全部不调用 Docker
5. ~~报告新增沙箱区块~~ **（已完成）**：含“单次运行、不代表后续版本、不执行仓库代码”
6. ~~README、project.md 同步~~ **（已完成）**

待办（真正的“动态行为”，需要单独设计）：

- 在容器内执行安装 / 导入 / 测试的固定探针协议，输出上限与证据 schema
- 真实 Docker 手动冒烟验收（本机已有 Docker 时跑一次 `--sandbox all`）
- 镜像供应链：校验镜像 digest，或要求 `@sha256:` 引用
- gVisor / runsc 运行时评估

风险：Docker 逃逸、容器镜像本身、挂载路径、网络代理、资源耗尽。当前实现已经做到
“默认不接触 Docker + 不执行仓库代码”；下一步若要做行为探测，必须先设计固定探针
协议、输出上限和“单次运行不等于安全”的措辞，再写代码。

## 9. 下一步建议：验收 / M4 设计 / 收尾

M5 的三个扫描器（Semgrep、gitleaks、OSV）都已完成。现在最值钱的不再是新功能，而是**验证**
和**收尾**。

### 9.1 已完成（记录，避免重复做）

- Semgrep（4.2）：替换内置扫描，本地规则；禁止 `--config auto`。
- gitleaks（4.3）：追加式凭据扫描；固定本地配置；凭据只留脱敏片段。
- OSV（4.4）：追加式依赖漏洞扫描；osv-scanner v2；缺 lockfile 记为覆盖不完整。
- 统一合并 `merge_scan_reports()`：最高风险 + 去重 + 最宽文件数 + 任一 scanner 出错整份
  ERROR。

### 9.2 真实工具验收（建议先做，但要先问用户）

当前机器上 docker / gitleaks / semgrep / osv-scanner **一个都没装**，所有外部路径只有
fake runner 验证。按成本从低到高：

1. **gitleaks + osv-scanner**（单个二进制，不需要 Docker）：
   `reuseguard check <repo> --no-recall --gitleaks --osv`。
   重点确认：`gitleaks dir`、`[extend] useDefault`、`--gitleaks-ignore-path` 指向空目录
   不报错；`osv-scanner scan source --output-file`、退出码 1/128 的真实行为。
2. **Semgrep**：需要用户提供本地规则目录；验证 `--no-git-ignore` 与 `.semgrepignore` 的
   实际影响（这是已知覆盖缺口）。
3. **Docker**：`--sandbox all`，需要本地镜像，且 Windows / Docker Desktop 的 bind mount
   权限语义与 Linux 不同。

装工具属于改动机器，**动手前必须问用户**。验收时记录：命令、输出摘要、与假设不符的地方，
写回本文件 4.x。

### 9.3 M4 行为探测（先设计，不写代码）

用户明确要求：在完成独立的探针协议与证据边界设计之前，不要在沙箱里执行仓库代码。设计
文档至少覆盖：

- 探针协议：安装 / 导入 / 运行测试分别做什么、以什么身份、允许哪些网络与文件系统操作。
- 输出上限：stdout/stderr 截断、总时长、文件数、报告大小。
- 证据 schema：什么算“观察到行为”（进程、网络连接、文件写入、退出码），如何存。
- 措辞：“单次运行 ≠ 安全”“行为证据 ≠ 恶意判决”。
- 镜像供应链：digest 锁定 / 要求 `@sha256:` 引用。
- 失败与逃逸：超时、OOM、容器逃逸的检测与记录。

### 9.4 小项（穿插做）

- 0.6.0 wheel / console script 重建验证（上次只验到 v0.2.0）。
- 外部规则 ID 进入 `rules.disable` / `rules.severity`：给 policy 加“外部规则前缀”白名单，
  不要直接放开任意字符串。
- `.semgrepignore` 覆盖缺口：是否在隔离副本里删掉它，或改成显式文件列表。
- OSV 离线数据库模式；`--no-resolve` 是否默认开启（收紧 registry 访问）。
- 私有仓库 tarball 支持 token。

### 9.5 通用约束

- 不要把“扫描器没报”写成安全；报告 / verdict limitations 必须写覆盖范围。
- 每个扫描器单独 commit，补测试 + 跑 pytest/ruff + 更新三份文档。
- 外部工具都可能被仓库内容影响（配置、忽略文件、白名单）：接入前先问“被检查的仓库能不能
  用它自己的配置让扫描器闭嘴”。gitleaks 和 Semgrep 都已经踩过。

## 10. 新对话提示词

把下面这段直接发给下一个对话：

```text
继续开发 ReuseGuard（https://github.com/guoyi611/ReuseGuard）。

先读仓库根目录的 HANDOFF.md、README.md、project.md，然后执行：
- git status
- git log --oneline -5
- python -m pytest
- ruff check src tests
确认基线（main，v0.6.0，359 个测试通过）后再动手。注意：当前 .venv 里没有安装本包，
需要用 $env:PYTHONPATH="src" 跑 pytest，ruff 用 .tools\bin\ruff.exe。

已完成的里程碑：M1、M2、M3（--idea）、M4 安全骨架（默认关闭的容器隔离探测）、
M5 全部三个外部扫描器（Semgrep / gitleaks / osv-scanner）、M6（YAML 策略）。
未完成：M4 行为探测（在沙箱内执行安装/导入/测试）、真实工具冒烟验收、OSV 离线模式、
打包后的 console script 重建验证。

请按 HANDOFF.md 第 9 节的顺序继续：
1. 先问用户要不要在本机安装 gitleaks / osv-scanner 做真实冒烟（装工具属于改动机器）。
   如果同意，按 9.2 跑真实链路并记录命令、输出、与假设不符的地方。
2. 写 M4 行为探测的设计文档（9.3），不要直接写代码；探针协议和证据边界先定。
3. 穿插做 9.4 的小项；每个可验证的小步单独 commit + push。

不要把被检查代码在宿主机上执行，也不要在沙箱里执行仓库代码，除非先完成独立的
探针协议与证据边界设计。不要用 `--config auto` 或任何会隐式联网拉规则的路径。
接入任何新扫描器前先问：“被检查的仓库能不能用它自己的配置让扫描器闭嘴？”
（gitleaks 的 .gitleaks.toml / .gitleaksignore / gitleaks:allow 就是例子。）

每完成一个可验证的小步：
- 补测试
- 跑 pytest + ruff
- 更新 README/project.md/HANDOFF.md
- commit 并 push（远程是 SSH；必要时设置 GIT_SSH 指向 ssh.exe）

注意：
- 不提交 token、.env、.tools、.venv、dist、reports
- 不把“没有发现”写成“安全”
- 不改动 .github/workflows/ci.yml 的 workflow scope 限制，除非先处理 gh scope
- 用户不是安全工程师：汇报时先说人话、再说细节，术语要解释
- 每步完成后告诉我改了什么、验证结果和下一步
```
