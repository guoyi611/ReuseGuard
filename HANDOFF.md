# ReuseGuard 交接文档

> 最后更新：2026-10-31
> 仓库：https://github.com/guoyi611/ReuseGuard
> 分支：`main`
> 当前版本：`0.2.0`
> 基线提交：`292c422 feat: add YAML policy configuration`（本文件单独提交在其后）
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
| M4 | **未开始** | Docker/gVisor 隔离动态验证 |
| M5 | **未开始** | Semgrep / OSV / gitleaks 外部扫描器适配 |
| M6 | 完成 | YAML 策略：阈值、限制、features、规则启停、severity、抑制路径 |

当前测试：**136 个，全部离线通过**；`ruff check` / `ruff format --check` 全绿；
wheel / sdist 构建成功，v0.2.0 在干净 venv 中验证过 console script。

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
│   └── scanner.py      # 内置规则、KNOWN_RULE_IDS、策略参数
└── stages/
    ├── recall.py       # seed 召回 + idea 召回 + 相似度
    ├── reputation.py   # Scorecard → FilterResult
    └── verdict.py      # Filter + Scan → Verdict
```

测试：

```text
tests/
├── fakes.py            # FakeGitHub / FakeScorecard / snapshot 工厂
├── test_cli.py
├── test_config.py
├── test_models.py
├── test_pipeline.py
├── test_policy.py
├── test_recall.py
├── test_report.py
├── test_reputation.py
├── test_scanner.py
├── test_snapshot.py
└── test_verdict.py
```

## 4. 本次会话实际改动

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

## 5. 如何运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

reuseguard demo
reuseguard check psf/requests --limit 3
reuseguard check --idea "a fast HTTP client with retries" --language Python --limit 3
reuseguard check psf/requests --config examples/reuseguard.yaml
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
- **动态验证尚未实现**：v0.2 明确不做，不能在文档里暗示已有沙箱。

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

## 8. 下一步建议：M4 隔离动态验证

目标：对 high/critical 或用户显式要求的高风险候选，在容器里观察行为。**默认关闭**，
绝不在宿主机执行被检查代码。

建议实现顺序：

1. 新增 `adapters/sandbox.py`：
   - `DockerSandbox`，检测 `docker info` 是否可用
   - 运行参数：`--network none`、只读挂载快照、`--memory`、`--cpus`、`--pids-limit`、
     `--read-only`、`--tmpfs /tmp`、超时杀容器
   - 不挂载 docker socket，不使用 `--privileged`
   - 记录 stdout/stderr、退出码、超时、OOM 标记
   - **不要**把执行结果当成“无害证明”，只作为行为证据
2. 新增 `SandboxReport` 数据模型与 verdict 输入；`--sandbox` / `--sandbox-image` /
   `--sandbox-timeout` CLI 参数，默认关闭
3. 只有 `scan.risk in {high, critical}` 或显式 `--sandbox` 才触发
4. 测试全部用 fake runner，不实际运行 Docker；CI 里 Docker 不可用时跳过
5. 报告中新增“动态行为”区块，并写明“单次运行、不代表后续版本”
6. 文档同步：README、project.md、本文件

风险：Docker 逃逸、容器镜像本身、挂载路径、网络代理、资源耗尽。宁可先只做
“检测 Docker 是否可用 + 生成待执行计划”，也不要为了演示执行不可信代码。

## 9. 下一步建议：M5 外部扫描器

优先做 **Semgrep 适配器**，因为它的 JSON 输出稳定、只解析不执行：

- `scan_fn` 已经是可注入的；实现 `SemgrepScanner` 返回统一 `ScanReport`
- 通过 `subprocess.run([...], shell=False)` 调用，显式超时
- 规则来源必须是用户提供的 `--semgrep-config PATH` 或仓库内固定配置，**不要**
  默认 `--config auto`（会联网拉规则）
- 找不到 semgrep 时降级为内置扫描器并写 warning
- 用 fake executable / fake subprocess 写测试，CI 不安装 semgrep
- 后续再加 OSV（lockfile）和 gitleaks（secret），统一 `Finding` schema

## 10. 新对话提示词

把下面这段直接发给下一个对话：

```text
继续开发 ReuseGuard（https://github.com/guoyi611/ReuseGuard）。

先读仓库根目录的 HANDOFF.md、README.md、project.md，然后执行：
- git status
- git log --oneline -5
- python -m pytest
- ruff check src tests
确认基线（main，v0.2.0，136 个测试通过）后再动手。

已完成的里程碑：M1、M2、M3（--idea 自然语言输入）、M6（YAML 策略）。
未完成：M4（隔离动态验证）、M5（Semgrep/OSV/gitleaks 适配）。

请按 HANDOFF.md 第 8、9 节的顺序继续，优先做 M4 的安全骨架（默认关闭、
Docker 检测、network none、只读挂载、资源/超时限制、fake runner 测试），
不要把被检查代码在宿主机上执行。每完成一个可验证的小步：
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
