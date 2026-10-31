# ReuseGuard 交接文档

> 最后更新：2026-10-31
> 仓库：https://github.com/guoyi611/ReuseGuard
> 分支：`main`
> 当前版本：`0.4.0`
> 基线提交：`git log --oneline -1`（M5 第一步 Semgrep；M4 基线为 `f39c84b`）
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
| M5 | **进行中** | Semgrep 适配器完成（本地规则、JSON 解析、统一 Finding、降级/错误边界）；OSV、gitleaks 待做 |
| M6 | 完成 | YAML 策略：阈值、限制、features、规则启停、severity、抑制路径 |

当前测试：**237 个，全部离线通过**；`ruff check` / `ruff format --check` 全绿；
wheel / sdist 构建成功，v0.2.0 在干净 venv 中验证过 console script（0.4.0 待重建验证）。

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
- **静态扫描是内置规则，不是 Semgrep**：保证零重依赖；适配器边界留给 M5。
- **Scorecard 只读公开 API**：不执行第三方构建；未收录时 `UNKNOWN → INSPECT`。
- **不使用 LLM**：召回是 GitHub Search + 关键词，不是语义搜索。
- **误报抑制**：docs/tests/examples/fixtures 降权；vendor/generated/minified 跳过。
- **风险分级**：critical/high → AVOID；medium → INSPECT；低风险 + Scorecard ≥ 5
  且扫描完整 → USE。
- **沙箱默认关闭且不执行仓库代码**：只验证容器隔离配置；Docker 不可用只降级为
  warning + `UNAVAILABLE`，不改变结论。`containment_ok=True` 不是“无害证明”。

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

## 9. 下一步建议：M5 剩余扫描器

Semgrep 已完成（见 4.2）。接下来按难度：

### 9.1 gitleaks（建议先做）

- 本地可执行文件，JSON 输出稳定；`gitleaks detect --no-git --source <root>
  --report-format json --report-path -`。
- 重点：`--no-git`（快照没有 `.git`）、关闭远端配置、明确超时。
- 解析 `leaks` 数组：`RuleID`、`File`、`StartLine`、`Description`、`Match`、
  `Secret`。**不要把 `Secret` 原文写进报告**，只保留脱敏后的证据。
- severity：gitleaks 没有 severity，按规则 ID 映射（私钥/token → high，其他 → medium）。
- 可执行文件缺失 → 降级内置 + warning；运行失败/坏 JSON → scan error。
- 全部用 fake runner 测试，CI 不安装 gitleaks。

### 9.2 OSV（lockfile）

- 两种实现路径，需先定：
  1. `osv-scanner --lockfile <path> --format json`（外部二进制，和 Semgrep/gitleaks 一致）
  2. 直接调 `https://api.osv.dev/v1/querybatch`（需要网络、httpx、可注入 client）
- 不管哪条路，都需要先识别 lockfile：`requirements.txt`、`poetry.lock`、
  `package-lock.json`、`go.mod`、`Cargo.lock`、`Gemfile.lock` 等。
- 网络路径必须考虑离线测试：用 fake HTTP client，不访问真实 OSV。
- 漏洞 finding 的 severity 来自 OSV `database_specific.severity` 或 CVSS；
  缺失时保守为 medium，不要默认 high。
- 统一 `Finding`：`rule_id` 用 OSV ID（如 `GHSA-...` / `CVE-...`），
  `category="dependency"`，`path=lockfile`，`line` 可空。

### 9.3 通用约束（沿用 Semgrep）

- 场景：`--gitleaks` / `--osv` CLI 开关，默认关闭；`--no-scan` 时禁用。
- 组合多个扫描器时，`ScanReport` 需要合并 findings、取最高 risk、保留 scanner 列表；
  这可能要扩展 `ScanReport.scanner` 为可读字符串（如 `semgrep+gitleaks`）。
- 不要把“扫描器没报”写成安全；报告 limitations 必须写覆盖范围。
- 每个扫描器单独 commit，补测试 + 跑 pytest/ruff + 更新三份文档。

## 10. 新对话提示词

把下面这段直接发给下一个对话：

```text
继续开发 ReuseGuard（https://github.com/guoyi611/ReuseGuard）。

先读仓库根目录的 HANDOFF.md、README.md、project.md，然后执行：
- git status
- git log --oneline -5
- python -m pytest
- ruff check src tests
确认基线（main，v0.4.0，237 个测试通过）后再动手。

已完成的里程碑：M1、M2、M3（--idea）、M4 安全骨架（默认关闭的容器隔离探测）、
M5 第一步（Semgrep 适配器：本地规则、统一 Finding、降级/错误边界）、M6（YAML 策略）。
未完成：M5 剩余（gitleaks、OSV）、M4 行为探测（在沙箱内执行安装/导入/测试）、
真实 Docker 冒烟验收。

请按 HANDOFF.md 第 9 节的顺序继续：
1. 先做 gitleaks 适配器（--no-git、JSON 解析、Secret 脱敏、fake runner 测试）。
2. 再做 OSV lockfile 适配器（先决定 osv-scanner 二进制还是 HTTP API）。
3. 每个扫描器单独 commit，补测试 + pytest + ruff + 更新三份文档 + push。

不要把被检查代码在宿主机上执行，也不要在沙箱里执行仓库代码，除非先完成独立的
探针协议与证据边界设计。不要用 `--config auto` 或任何会隐式联网拉规则的路径。

每完成一个可验证的小步：
- 补测试
- 跑 pytest + ruff
- 更新 README/project.md/HANDOFF.md
- commit 并 push（远程是 SSH；必要时设置 GIT_SSH 指向 ssh.exe）

注意：
- 不提交 token、.env、.tools、.venv、dist、reports
- 不把“没有发现”写成“安全”
- 不改动 .github/workflows/ci.yml 的 workflow scope 限制，除非先处理 gh scope
- 每步完成后告诉我改了什么、验证结果和下一步
```
