# Semgrep 真实验收手册

> 状态：待执行（需要用户提供本地规则集）
> 关联：[HANDOFF §4.2 / §9.2](../HANDOFF.md) · [project.md §7.8](../project.md)

## 0. 为什么这份文档存在

Semgrep 适配器已经完成并用 `FakeCommandRunner` 覆盖了命令构造、JSON 解析、severity
映射、抑制、越界路径、超时、非零退出、缺配置、截断等场景。**还没有用真实 Semgrep
二进制跑过**。主要缺口是 `.semgrepignore` 的实际影响：仓库可以用它缩小扫描范围，
而 ReuseGuard 传的 `--no-git-ignore` 只关掉 `.gitignore`，不关 `.semgrepignore`。

这份文档列出验收步骤和预期结果；**真实执行必须等用户提供本地规则目录**。不要
为了"跑通"而用 `--config auto` 或拉远程规则。

## 1. 前置条件

- Semgrep 已安装并在 PATH 上（`semgrep --version` ≥ 1.x）
- 本地规则目录或文件已准备好（例如 `.tools/scanners/semgrep-rules/`），**不含
  `--config auto` 引用**
- 测试夹具仓库快照（含 `.semgrepignore`、`.gitignore`、隐藏文件、符号链接）

推荐夹具结构：

```text
semgrep-fixture/
├── .gitignore           # 忽略 ignored-by-git.txt
├── .semgrepignore       # 忽略 ignored-by-semgrep.py
├── app.py               # 应被扫描
├── ignored-by-git.txt   # --no-git-ignore 下应被扫描
├── ignored-by-semgrep.py# .semgrepignore 命中，预期被跳过
└── .hidden/
    └── secret.py        # 隐藏目录下的文件；验证是否被扫到
```

## 2. 验收命令

```powershell
$env:PATH = "C:\Users\z\Desktop\projects\ReuseGuard\.tools\scanners;$env:PATH"
$env:PYTHONPATH = "src"

# 基线：内置规则 + gitleaks + osv（已知工作）
python -m reuseguard check acme/fixture-repo --no-recall --gitleaks --osv

# Semgrep 替换内置扫描
python -m reuseguard check acme/fixture-repo --no-recall `
  --semgrep-config .tools/scanners/semgrep-rules/ `
  --semgrep-timeout 120

# Semgrep + gitleaks + osv 全开
python -m reuseguard check acme/fixture-repo --no-recall `
  --semgrep-config .tools/scanners/semgrep-rules/ `
  --gitleaks --osv
```

## 3. 预期结果与核对清单

| 检查项 | 预期 | 失败含义 |
| --- | --- | --- |
| `semgrep --version` 成功 | ≥ 1.x | 版本太旧可能缺 `--max-memory` / `--jobs` |
| `--semgrep-config <dir>` 接受目录 | 不报错 | 适配器把目录透传给 `--config` |
| `--semgrep-config <file>` 接受单文件 | 不报错 | 同上 |
| `--config auto` **不被使用** | argv 里没有 `auto` | 安全边界破坏 |
| `--metrics=off --disable-version-check` 在 argv 里 | 是 | 遥测未关闭 |
| `--no-git-ignore` 在 argv 里 | 是 | `.gitignore` 不能藏文件 |
| `.semgrepignore` 命中的文件不出现在 findings | 是 | 这是已知覆盖缺口；记录在 limitations |
| `.gitignore` 命中的文件**出现**在 findings | 是 | `--no-git-ignore` 生效 |
| 隐藏目录下的文件被扫描 | 取决于 Semgrep 默认行为 | 记录实际行为 |
| 非零退出 → scan error | 报告 `Scan status: error` | 不静默降级 |
| 超时 → scan error | 同上 | 同上 |
| 缺可执行文件 → 降级内置 + warning | warning 出现在 Run details | 唯一允许降级的情况 |
| severity 映射正确 | ERROR→high, WARNING→medium, INFO→low, metadata.critical→critical | 检查 JSON |
| 越界路径被丢弃 | findings.path 全部落在快照内 | 安全检查 |
| docs/tests/examples 命中被 suppressed | suppressed_findings > 0 | 误报抑制生效 |
| 合并后 scanner 字段形如 `semgrep+gitleaks+osv` | 是 | merge_scan_reports 工作 |

## 4. `.semgrepignore` 影响验证（重点）

这是 HANDOFF 9.2 / project.md §12 #7 的开放问题。验收时必须回答：

1. **夹具里放一个 `.semgrepignore` 忽略 `ignored-by-semgrep.py`**，该文件含一条
   规则必中的模式（例如 `eval(`）。
2. 跑 `--semgrep-config <rules>`，检查 findings 里是否有 `ignored-by-semgrep.py`。
3. **预期**：该文件**不会**出现在 findings 里（Semgrep 默认读 `.semgrepignore`）。
4. **记录**：在报告的 Limitations 区块确认措辞已包含 ".semgrepignore may reduce
   coverage"。如果实际行为与文档不符，更新 HANDOFF 4.2 的诚实边界。

缓解选项（不在本轮实现，仅记录）：

- 在隔离副本里删除 `.semgrepignore` 后再扫
- 改用显式文件列表（`--include`）代替目录扫描
- 在报告里列出被 `.semgrepignore` 跳过的文件数（需要 Semgrep 输出支持）

## 5. 失败处理

- **Semgrep 不在 PATH**：CLI 应 warning，pipeline 降级到内置扫描器 + warning。
  这不是验收失败，是预期行为。
- **规则目录含语法错误**：Semgrep 非零退出 → scan error → INSPECT。检查 stderr
  是否被截断到 `_MAX_ERROR_TAIL`（1500 字符）。
- **规则引用了远程资源**：如果规则 YAML 里有 `r/...` 或 `p/...` URL，Semgrep
  会联网。这违反"禁止 `--config auto`"的精神。**拒绝此类规则集**，要求用户提供
  纯本地规则。

## 6. 验收完成后要更新的文件

- `HANDOFF.md` §4.2 / §9.2：把"仍待做"改成"已验收"，附版本号、SHA256、实测边界
- `project.md` §7.8 / §9：同步实测结论
- `README.md`：如果 `.semgrepignore` 影响比预期大，加一段用户提示
- 本文件：把"待执行"改成"已完成于 YYYY-MM-DD"，附命令输出摘要

## 7. 不要做

- 不要用 `--config auto` 或任何远程规则源
- 不要在 CI 里装 Semgrep（继续用 fake runner）
- 不要把"0 findings"写成"安全"
- 不要因为 Semgrep 漏扫了就降低 verdict；保持 INSPECT + limitation
