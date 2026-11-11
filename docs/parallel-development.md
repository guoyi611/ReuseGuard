# 并行开发与分支隔离

> 状态：2026-11-11 建立
> 适用：`main` 保持可发布，`develop` 做集成，`feat/*` 并行开发后合并
> 关联：[HANDOFF](../HANDOFF.md) · [project.md](../project.md)

## 0. 一句话

并行开发不要在同一个工作区切分支：用 `git worktree` 给每个功能分支一个独立目录，
所有功能分支从 `develop` 拉出，完成后按顺序合并回 `develop`，`develop` 稳定后再合 `main`。

## 1. 分支模型

```text
main        可发布、已验证；只接受来自 develop 的合并
  └─ develop   集成分支；feature 的合并目标，CI 也会跑
       ├─ feat/discovery-quality
       ├─ feat/scanner-hardening
       ├─ feat/policy-external-rules
       ├─ feat/private-repo-token
       └─ feat/m4-behavior-probe   ← 改动面最大，最后合
```

规则：

- `main` 不直接开发；发布或文档修正除外。
- `develop` 是并行开发的汇合点；不要长期偏离。
- `feat/*` 生命周期尽量短；完成一个功能就合并，不要攒成大分支。
- 每个 feature 分支只做**一个功能分区**的事；跨分区改动拆分到不同分支。

## 2. 当前功能分区

| 分支 | 范围 | 主要文件 | 状态 / 阻塞 |
| --- | --- | --- | --- |
| `feat/discovery-quality` | P0：`--idea` 查询相关性、候选来源、`--strict-idea`、`license unknown` 警告 | `stages/recall.py`、`report.py`、`stages/verdict.py`、`cli.py`、`test_recall.py`、`test_report.py` | 可立即开发 |
| `feat/scanner-hardening` | OSV 离线 / `--no-resolve` / dev 依赖 / CVSS 口径；gitleaks 自定义规则；Semgrep 真实验收 | `adapters/osv.py`、`adapters/gitleaks.py`、`adapters/semgrep.py`、`config.py`、`cli.py`、`pipeline.py` | 可开发；Semgrep 需本地二进制和规则集 |
| `feat/policy-external-rules` | 外部规则 ID 进入 YAML `rules.disable` / `rules.severity` | `config.py`、`adapters/scanner.py`、`test_policy.py` | 可开发 |
| `feat/private-repo-token` | 私有仓库 codeload tarball 支持 token | `adapters/snapshot.py`、`config.py`、`pipeline.py`、`test_snapshot.py` | 可开发；需要 token 传递的安全审查 |
| `feat/m4-behavior-probe` | M4 行为探测实现 + 真实 Docker 验收 | 新增 `adapters/behavior.py`；`models.py`、`cli.py`、`pipeline.py`、`report.py` | **等用户确认设计 + Docker 环境**；最后合并 |

后续如果需要，可以再加：

- `feat/report-zh`：中文报告输出（P2）。
- `feat/recall-sources`：多召回源 / 候选来源统计。

## 3. Worktree 布局

每个分支在 `.worktrees/` 下有独立工作目录（已 gitignore，不提交）：

```text
.worktrees/
├── discovery-quality/
├── scanner-hardening/
├── policy-external-rules/
├── private-repo-token/
└── m4-behavior-probe/
```

查看：

```powershell
git worktree list
```

新建一个功能分支和 worktree：

```powershell
git fetch github
git worktree add .worktrees/<name> -b feat/<name> github/develop
```

删除已合并的 worktree：

```powershell
git worktree remove .worktrees/<name>
git branch -d feat/<name>
```

注意：

- `.worktrees/` 是本地目录，**不要** `git add`。
- 每个 worktree 有自己的 checkout；互不影响，但共享同一个 `.git` 仓库。
- 不要在 `.worktrees/` 里再创建 venv 或复制 `.tools/`；工具从主工作区用绝对路径调用。

## 4. 在每个 worktree 里怎么跑

测试（pytest 配置了 `pythonpath=src`，跑的是当前 worktree 的源码）：

```powershell
python -m pytest
```

ruff（从主工作区调用）：

```powershell
C:\Users\z\Desktop\projects\ReuseGuard\.tools\bin\ruff.exe check src tests
C:\Users\z\Desktop\projects\ReuseGuard\.tools\bin\ruff.exe format --check src tests
```

CLI（不要用主工作区 `.venv` 里安装的旧 wheel；强制当前 worktree 的 `src`）：

```powershell
$env:PYTHONPATH = "src"
python -m reuseguard --version
```

外部扫描器（gitleaks / osv-scanner 在**主工作区**的 `.tools/scanners`）：

```powershell
$env:PATH = "C:\Users\z\Desktop\projects\ReuseGuard\.tools\scanners;$env:PATH"
```

## 5. 合并顺序与流程

建议顺序：

1. `feat/discovery-quality`
2. `feat/scanner-hardening`
3. `feat/policy-external-rules`
4. `feat/private-repo-token`
5. `feat/m4-behavior-probe`（最后）

理由：M4 会同时改 `models.py`、`cli.py`、`pipeline.py`、`report.py`，是冲突面最大的分支；
放在最后合并，前面的小改动先进入 `develop`，M4 只需要 rebase 一次。

每个功能分支完成时：

```powershell
git fetch github
git rebase github/develop
python -m pytest
C:\Users\z\Desktop\projects\ReuseGuard\.tools\bin\ruff.exe check src tests
C:\Users\z\Desktop\projects\ReuseGuard\.tools\bin\ruff.exe format --check src tests
git push --force-with-lease github feat/<name>
```

然后开 PR：`feat/<name>` → `develop`。CI 会对 PR 跑 Ubuntu 3.10/3.11/3.12 + Windows 3.11。

`develop` 稳定后：

- 开 PR：`develop` → `main`；
- CI 全绿、测试全绿后再合并；
- 合并后在 `main` 打 tag / 更新版本号。

## 6. 冲突热点

| 文件 | 可能同时改的分支 |
| --- | --- |
| `report.py` | discovery-quality、m4-behavior-probe |
| `cli.py` | discovery-quality、scanner-hardening、m4-behavior-probe |
| `pipeline.py` | scanner-hardening、private-repo-token、m4-behavior-probe |
| `models.py` | m4-behavior-probe |
| `config.py` | scanner-hardening、policy-external-rules、private-repo-token |
| `tests/test_pipeline.py` | 几乎所有分支 |

减少冲突的做法：

- 只改自己分区需要的行，不顺手格式化/重排无关代码；
- 新字段尽量追加在 dataclass 末尾；
- 新 CLI 参数追加在同类参数附近，不改已有参数顺序；
- 合并前先 rebase `develop`，不要反过来把 `develop` merge 进 feature；
- 冲突解决后必须重跑 pytest + ruff。

## 7. 不要做

- 不要在 `main` 或 `develop` 上直接开发功能。
- 不要提交 `.worktrees/`、`.venv/`、`.tools/`、`dist/`、`reports/`。
- 不要合并测试没过的分支。
- 不要 `force-push` `main` / `develop`；feature 分支 rebase 后可以用 `--force-with-lease`。
- 不要把“没发现”写成“安全”；分支隔离不改变这条产品约束。
