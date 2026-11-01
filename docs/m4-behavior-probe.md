# M4 行为探测：探针协议与证据边界（设计草案）

> 状态：**设计草案，等待确认。本文不含实现，ReuseGuard 目前仍然不会在沙箱里执行仓库代码。**
>
> 适用版本：v0.6.0 之后（M4 行为探测）
> 最后更新：2026-11-01
> 关联：[README](../README.md) · [project.md](../project.md) · [HANDOFF.md](../HANDOFF.md)

---

## 0. 先看这一页（给非安全工程师）

现在的 `--sandbox` 只做一件事：证明“容器隔离配置确实按预期生效”，容器里跑的是
ReuseGuard 自己的固定脚本，**不运行仓库代码**。

这份文档设计下一步：在一次性容器里，按固定协议运行仓库的“导入”和“测试”，观察它
碰了哪些文件、起了哪些进程、有没有网络能力。可以用一个比喻：

> 把仓库放进一个可丢弃的玻璃房，让它自己动一次；我们在玻璃房外面记录。
> 玻璃房能挡住大部分东西，但“这次没出事”不等于“它以后不会出事”。

**三个必须先说清楚的结论：**

1. **单次运行 ≠ 安全。** 仓库可以检测沙箱、延迟行为、在别的环境里表现不同。一次干净
   的运行不能证明仓库无害，也不能证明后续版本无害。
2. **行为证据 ≠ 恶意判决。** 测试失败可能只是镜像缺依赖；导入成功也不代表代码可信。
   观察结果只交给人工判断，不由工具自动判“恶意”。
3. **探测本身不是没有代价。** 它会真正执行不可信代码。所以默认关闭、必须显式开启、
   必须用 digest 锁定镜像，并且所有证据都有采集上限。

### 0.1 需要用户拍板的决定

| # | 决定 | 本设计的建议 |
| ---: | --- | --- |
| 1 | 第一版跑哪些阶段 | 只跑 `import` + `test`；`install` 推迟到离线缓存阶段（Tier 2），避免隐式联网 |
| 2 | 是否对 high/critical 自动跑 | **不自动**。即使 `--sandbox auto`，行为探测也必须显式 `--behavior` |
| 3 | 行为证据能否改变结论 | 只能把结论“压到最多 INSPECT”，**不能自动 AVOID、不能升级为 USE、不能提高置信度** |
| 4 | 镜像来源 | 必须 `IMAGE@sha256:...`，本地已有，`--pull=never`；不内置默认镜像 digest |
| 5 | 工作副本放哪 | 宿主侧一次性目录 bind 到 `/work`，宿主自己算文件差异；不用容器内 tmpfs |
| 6 | 原始 stdout/stderr 放哪 | JSON 里放有上限的尾部；Markdown 默认只放结构化证据，避免把仓库内容/密钥抄进报告 |

如果这些建议里有任何一条你不同意，先改设计，再写代码。

---

## 1. 目标与非目标

### 1.1 目标

- 对**一个快照**、在**一次性容器**里，按**固定协议**执行仓库代码一次。
- 观察并记录四类证据：进程、文件写入、网络能力/连接、退出码与资源使用。
- 所有证据有类型、有上限、有“采集可信度”标注，能进 JSON 审计。
- 默认关闭；没有显式开关和 digest 镜像时，连 Docker 都不碰。
- 结论层只增加 caveat（限制说明），不把“没观察到”写成“安全”。

### 1.2 非目标（本设计明确不做）

- 不做恶意软件判定、不做“无罪证明”。
- 不做完整 syscall 追踪（不用 eBPF / ptrace / strace）；进程证据是**采样**的。
- 不在第一版做联网安装、不访问包管理器 registry、不配置代理白名单。
- 不检测内核或容器运行时逃逸；那是宿主内核 / Docker / runc 的信任边界。
- 不做多次运行、差分运行、对抗沙箱检测的“隐身”分析。
- 不做任意命令执行器：只运行固定命令表里的命令，不接受仓库提供的参数。
- 不在 Windows 宿主机上直接运行仓库代码；仍然跑 Linux 容器。

---

## 2. 威胁模型

### 2.1 要保护的东西

- 宿主机的文件、凭据、SSH key、浏览器数据、其他项目。
- Docker daemon 和本机其他容器/镜像。
- 宿主机网络和局域网。
- ReuseGuard 自己的报告、日志和临时目录。

### 2.2 被检查仓库能做什么

仓库作者控制仓库里的**所有文件**：源码、`package.json` 的 scripts、`conftest.py`、
`tox.ini`、`Makefile`、测试数据、文档。执行导入或测试时，这些代码会以容器内非 root
用户身份运行，因此它可以：

- 在 `/work` 里读写、删除文件，创建大量文件或占满磁盘。
- 起大量进程（fork bomb）、申请大量内存、跑满 CPU。
- 尝试联网、DNS、访问云元数据地址（`169.254.169.254`）。
- 尝试读容器里可见的文件：镜像自带的 `/etc/passwd`、`/work`、`/proc`。
- 尝试通过内核/运行时漏洞逃逸；尝试找 Docker socket；尝试挂载。
- 检测自己在容器里（hostname、`/proc/1/cgroup`、缺少某些文件），然后表现正常。
- 向 stdout/stderr 输出伪造的“探测结果”、ANSI 转义、超长内容。
- 在 `/work` 里创建符号链接、FIFO、socket，诱导宿主侧扫描器跟随或阻塞。

### 2.3 信任边界（Trusted Computing Base）

以下组件被视为**可信**，不在本探测的检测范围内：

- 宿主操作系统内核。
- Docker daemon、容器运行时（runc 或用户配置的 runsc）。
- 通过 digest 锁定的镜像内容（只信任到你拉取它的 registry 和本地 daemon）。
- ReuseGuard 宿主侧代码。

如果其中任何一个被攻破，行为探测不能提供保护。报告必须写明这一点。

### 2.4 关键假设

- 容器以非 root、无 capabilities、无 new privileges 运行。
- 容器没有网络（`--network none`），没有宿主路径（除了 `/work`），没有 Docker socket。
- 镜像已经按 digest 拉取到本地，ReuseGuard 不会自动 pull。
- 宿主环境变量、token、代理设置不会传进容器。
- 一次只跑一个探测容器；失败后清理。

---

## 3. 总体架构

### 3.1 为什么不是“容器内再放一个 supervisor”

第一版采用**宿主侧编排、每个阶段一个容器**，而不是在容器里跑一个 ReuseGuard 脚本去
启动子进程。原因：

- **退出码由宿主观察**：`docker run` / `docker inspect` 的退出码比容器内脚本自报的
  结果更难伪造。
- **没有“被观测代码杀掉 supervisor”的问题**：容器里只有阶段进程本身；它退出，容器
  就结束，宿主仍然拿得到状态。
- **每个阶段 rootfs 全新**：`/tmp`、`/run`、`/dev/shm` 都是新的；只有 `/work` 在阶段
  之间保留，用来承载安装/构建产物。
- **实现更小**：不需要在镜像里放 Python 脚本，也不依赖镜像自带 Python。

### 3.2 数据流

```text
快照目录（只读）
   │  宿主安全复制（拒绝符号链接/设备/FIFO，限制文件数与字节数）
   ▼
<workdir>/repo  ──bind rw──►  容器 /work/repo
   │                              │
   │ 宿主侧基线清单                │ 固定 argv 运行 import / test
   │                              ▼
   │                         阶段进程（uid 65534）
   │                              │
   ├── 宿主轮询进程 / 资源 ◄──────┤
   ├── 宿主读取容器 netns ◄───────┤
   ├── 宿主捕获 stdout/stderr ◄───┤
   ▼                              ▼
阶段结束后：docker inspect（OOM/退出码）、文件差异、canary 校验、清理
   │
   ▼
BehaviorReport（JSON）+ Markdown 区块 + verdict caveat
```

### 3.3 与现有 containment 探测的关系

| | containment probe（已有） | behavior probe（本设计） |
| --- | --- | --- |
| 是否执行仓库代码 | 否 | 是（显式开启） |
| 目的 | 验证隔离配置生效 | 观察一次运行的行为 |
| 数据模型 | `SandboxReport` | 新增 `BehaviorReport` |
| 触发 | `--sandbox off/auto/all` | 新增 `--behavior`，默认 off |
| 结论影响 | 只加 caveat | 只加 caveat；异常时最多压到 INSPECT |

两者互相独立：可以只跑 containment，也可以只跑 behavior；报告分别展示，不互相替代。
`containment_ok=True` 不能当作行为探测的准入条件，行为探测也不证明 containment 有效。

---

## 4. 探针协议

### 4.1 通用执行契约

每个阶段都是一次独立的 `docker run`：

- **固定 argv**：命令来自本设计的固定表；不接受用户或仓库提供的额外参数。
- **`shell=False`**：直接 exec，不经过 shell；不做字符串拼接。
- **固定 entrypoint**：`--entrypoint` 指向阶段工具（`python` / `npm` / `go` / `cargo`），
  绕过镜像自带的 entrypoint 脚本，减少镜像差异。
- **固定 cwd**：仓库副本根目录 `/work/repo`（import 的 src-layout 例外，见 4.4）。
- **固定身份**：uid/gid `65534:65534`，无 supplementary groups（见 4.2）。
- **固定环境变量**：只传 allowlist（见 4.3）。
- **固定超时**：单阶段默认 120 秒，总预算默认 300 秒（见第 8 节）。
- **固定网络**：`--network none`（见第 6 节）。
- **退出码由宿主记录**：容器内程序退出码 + Docker CLI 退出码 + `docker inspect` 的
  `State.ExitCode` 三者都记，冲突时以 inspect 为准并写 warning。

### 4.2 以什么身份执行

| 项 | 值 | 说明 |
| --- | --- | --- |
| uid / gid | `65534:65534` | 镜像里通常叫 `nobody`；没有就用数字 uid，不要求 passwd 条目 |
| supplementary groups | 无 | 不通过 `--group-add` 添加 |
| capabilities | `--cap-drop ALL` | 包括 `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_MKNOD` |
| no-new-privileges | `true` | setuid 二进制不能提权 |
| seccomp | Docker 默认 profile | 不禁用；不传 `seccomp=unconfined` |
| AppArmor / SELinux | 宿主默认 | 不显式禁用 |
| rootfs | 只读 | 写操作只能落在 `/work`、`/tmp`、`/run`、`/dev/shm` |
| HOME | `/work/home` | 可写；避免包管理器去写 `/root` 或 `/nonexistent` |
| umask | `0077` | 由阶段命令的 shell 环境无法直接设置；由 `/work` 目录权限和文件默认权限兜底，报告中记录实际文件 mode |
| core dump | `ulimit core=0` | 不把内存内容落盘 |
| PID 1 | `--init` 的 tini | 负责回收僵尸；阶段进程是它的子进程 |

**重要限制**：宿主侧无法给阶段进程换一个“更不可信”的 uid——容器里只有 65534 一个
身份。被观测代码和（如果有）辅助进程同 uid，因此它理论上可以干扰同 uid 的进程。
第一版不依赖容器内 supervisor，正是为了减少这种干扰面；但证据仍然不是防篡改的
（见第 9.2 和 11.3）。

### 4.3 环境变量 allowlist

只传下面这些；**不传宿主环境**，特别是不传 `GITHUB_TOKEN`、`GH_TOKEN`、`HTTP_PROXY`、
`HTTPS_PROXY`、`SSH_AUTH_SOCK`、`AWS_*`、`DOCKER_*`。

```text
PATH=/usr/local/bin:/usr/bin:/bin
HOME=/work/home
TMPDIR=/tmp
LANG=C.UTF-8
LC_ALL=C.UTF-8
TZ=UTC
CI=1
TERM=dumb
NO_COLOR=1
PYTHONDONTWRITEBYTECODE=1
PYTHONUNBUFFERED=1
PYTHONNOUSERSITE=1
PIP_DISABLE_PIP_VERSION_CHECK=1
PIP_NO_INPUT=1
npm_config_cache=/work/.npm
npm_config_update_notifier=false
GOCACHE=/work/.gocache
GOPATH=/work/.go
GOTOOLCHAIN=local
GOPROXY=off
GOSUMDB=off
CARGO_HOME=/work/.cargo
CARGO_NET_OFFLINE=true
BUNDLE_PATH=/work/.bundle
```

注意：

- `PYTHONNOUSERSITE` / `-s` 防止加载用户 site-packages；`-E` 在 Python 导入命令里使用，
  所以 `PYTHONPATH` 即使被设置也会被忽略（我们也不设置它）。
- `GOPROXY=off`、`CARGO_NET_OFFLINE=true` 让包管理器在 `--network none` 下快速失败，
  而不是卡在超时上。
- 这些变量是**环境约束**，不是安全边界；真正的边界是网络/文件系统/权限。

### 4.4 三个阶段分别做什么

| 阶段 | v1 是否执行 | 目的 | 固定命令（argv 形式，示例） | 身份 | 网络 | 文件系统 | 失败怎么记 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `install` | **否**（Tier 2） | 跑仓库声明的安装步骤，观察安装钩子/生命周期脚本 | 按生态固定，例如 `python -m pip install --no-index --find-links /opt/reuseguard/cache/wheels --no-build-isolation .`、`npm ci --offline --cache /opt/reuseguard/cache/npm` | 65534 | `none` + 只读缓存 | `/work` 可写；缓存只读 | `skipped_not_enabled` / `skipped_cache_missing`；**不得写成“没有安装钩子”** |
| `import` | 是 | 触发包初始化/顶层代码，这是 import-time 恶意行为最常出现的位置 | Python：`python -E -s -c "import <pkg>"`；Node：`node -e "require(process.cwd())"`；Go：`go build ./...`；Rust：`cargo check --offline` | 65534 | `none` | `/work` 可写 | `failed` / `inconclusive`，不是安全发现 |
| `test` | 是 | 运行仓库自己的测试套件，观察测试期的文件/进程/资源行为 | Python：`python -m pytest -q -p no:cacheprovider --maxfail=20`；Node：`npm test`；Go：`go test ./...`；Rust：`cargo test --offline` | 65534 | `none` | `/work` 可写 | `failed` / `inconclusive`，不是安全发现 |

**为什么第一版不做 `install`：** 安装默认需要网络（PyPI / npm / Go proxy / crates.io），
而 `--network none` 下必须依赖本地缓存。缓存格式、完整性、生命周期都比 import/test
复杂；在没有设计好“只读缓存 + 不隐式联网”之前，宁可不做，也不要在用户不知情时放开
网络。Tier 2 的离线缓存设计见 5.5。

#### 4.4.1 `import` 的检测与命令

| 生态 | 检测信号 | 命令 | cwd | 说明 |
| --- | --- | --- | --- | --- |
| Python（flat layout） | 根目录有 `<pkg>/__init__.py` | `python -E -s -c "import <pkg>"` | `/work/repo` | `-E` 忽略 `PYTHON*`，`-s` 忽略 user site；`-c` 的 sys.path[0] 是 cwd |
| Python（src layout） | `src/<pkg>/__init__.py` | 同上 | `/work/repo/src` | 让 cwd 直接成为包父目录 |
| Node / npm | `package.json` 有 `main` / `exports` / `index.js` | `node -e "require(process.cwd())"` | `/work/repo` | ESM-only 包会失败，记为 `inconclusive` |
| Go | `go.mod` | `go build ./...` | `/work/repo` | 编译也会执行 `init`/代码生成；不是纯“导入” |
| Rust | `Cargo.toml` | `cargo check --offline` | `/work/repo` | 离线；缺依赖会失败，记为 `inconclusive` |
| 其他 | — | — | — | `skipped_unsupported`，不猜命令 |

`<pkg>` 只从仓库自身的目录名/`pyproject.toml` 的包名候选里选一个，必须是合法 Python
标识符；不从仓库输出、不让仓库提供命令行参数。多个候选时只取一个并在报告里说明。

#### 4.4.2 `test` 的检测与命令

| 生态 | 检测信号 | 命令 | 说明 |
| --- | --- | --- | --- |
| Python | `pytest.ini` / `pyproject.toml` 有 pytest 配置 / `tests/` 或 `test_*.py` | `python -m pytest -q -p no:cacheprovider --maxfail=20` | 会加载仓库的 `conftest.py` 和插件——这正是要观察的代码；`--maxfail` 防止无限失败输出 |
| Node | `package.json` 有 `scripts.test` | `npm test` | `npm test` 会执行仓库定义的 `pretest`/`test`/`posttest`；这是仓库代码，不是 ReuseGuard 的代码 |
| Go | `go.mod` 且存在 `*_test.go` | `go test ./...` | 编译并运行测试；`GOTOOLCHAIN=local` 防止下载工具链 |
| Rust | `Cargo.toml` 且有 `tests/` 或 `#[test]` | `cargo test --offline` | 离线；缺依赖失败记为 inconclusive |
| 其他 | — | — | `skipped_unsupported` |

**关键诚实点**：测试命令是固定的，但**测试内容完全由仓库控制**。仓库可以让测试什么都不做、
全部 skip、或者输出伪造的“PASS”。所以“测试通过”只能说明“这个固定命令退出码是 0”，
不能说明代码安全。报告必须写这一点。

#### 4.4.3 工具预检（避免把“工具缺失”误判成“测试失败”）

每个阶段执行前，用**同一个镜像、同样的限制、`--network none`** 跑一次短预检，cwd 为
`/work`（不是仓库目录），确认工具存在：

| 阶段 | 预检命令 | 缺失时 |
| --- | --- | --- |
| `import`（Python） | `python -c "import sys; print(sys.version_info[:2])"` | `skipped_tool_missing` |
| `import`（Node） | `node --version` | `skipped_tool_missing` |
| `test`（Python/pytest） | `python -m pytest --version` | `skipped_tool_missing` |
| `test`（npm） | `npm --version` | `skipped_tool_missing` |
| `test`（Go） | `go version` | `skipped_tool_missing` |
| `test`（Rust） | `cargo --version` | `skipped_tool_missing` |

预检也使用 digest 镜像、非 root、无网络、只读 rootfs；它不接触仓库文件。预检失败只记录
“镜像不含该工具”，不记录为仓库行为。

### 4.5 阶段顺序与状态机

```text
prepare（镜像 digest 校验 + 预检 container 配置）
  → copy（快照 → /work/repo，宿主侧安全复制）
  → baseline（宿主侧文件清单）
  → [install]（v1 跳过）
  → import
  → test
  → finalize（最终文件差异、资源汇总、canary 校验、清理）
```

规则：

- 阶段顺序固定，不并发；一次只允许一个探测容器。
- 前一阶段失败不阻止后一阶段：安装失败可能只是因为缺缓存，测试仍然可能给出行为证据；
  报告记录 `dependency_state`。
- 每个阶段新建容器；`/work` 跨阶段保留（安装/构建产物可见），`/tmp`、`/run`、
  `/dev/shm`、rootfs 每阶段重置。
- 总预算耗尽后不再启动新阶段，剩余阶段记为 `not_run`。
- 任何阶段出现 `integrity_failure`（预检配置不符、canary 被动过）→ 立即停止后续阶段，
  保留证据，报告醒目标记。

阶段状态枚举：

```text
completed | failed | timeout | oom | resource_exhausted | killed
skipped_unsupported | skipped_tool_missing | skipped_cache_missing | not_run | docker_error
```

---

## 5. 容器配置与镜像供应链

### 5.1 镜像必须按 digest 锁定

行为探测执行不可信代码，镜像本身就是供应链的一部分。规则：

1. `--behavior-image` 必须匹配 `@sha256:[0-9a-f]{64}`；**拒绝 tag**（包括 `:latest`）。
2. 镜像必须已在本地；`--pull=never`。ReuseGuard 不自动 pull，也不隐式访问 registry。
3. 启动前用 `docker image inspect` 校验：
   - `RepoDigests` 里包含请求的引用（大小写归一）；
   - 记录 `Id`、`Os`、`Architecture`、`RepoDigests`；
   - 校验失败 → `REFUSED`，**一个容器都不启动**。
4. 报告记录完整 digest、image id、平台；JSON 里保留，Markdown 里显示短 digest。
5. 第一版不做镜像签名 / SBOM / cosign 验证；报告明确写“只信任 registry + 本地 daemon”。

用户获取 digest 的方式（文档示例，不由工具执行）：

```powershell
docker pull python:3.12-slim
docker image inspect python:3.12-slim --format '{{index .RepoDigests 0}}'
# 输出形如 python@sha256:<64 hex>，把它作为 --behavior-image
```

**为什么不用内置默认 digest**：默认 digest 会过期，用户也无法判断它对应哪个镜像；
强制用户显式提供，能让“我信任这个镜像”成为一个有意识的动作。代价是首次使用更麻烦。

### 5.2 `docker run` 固定参数

以下参数由 ReuseGuard 从 allowlist 拼装，`shell=False`，顺序固定；不允许仓库或用户
追加参数：

```text
docker run
  --name reuseguard-behavior-<run>-<phase>
  --label reuseguard.run=<run>
  --label reuseguard.phase=<phase>
  --pull=never
  --network none
  --read-only
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m
  --tmpfs /dev/shm:rw,noexec,nosuid,nodev,size=64m
  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m
  --cap-drop ALL
  --security-opt no-new-privileges:true
  --user 65534:65534
  --pids-limit 128
  --memory 512m
  --memory-swap 512m
  --cpus 1.0
  --ulimit nofile=512:512
  --ulimit core=0:0
  --init
  --hostname reuseguard-probe
  --workdir /work/repo
  --mount type=bind,source=<workdir>,target=/work
  --env <allowlist>
  --entrypoint <phase tool>
  <image>@sha256:<digest>
  <fixed argv>
```

明确禁止：

- `--privileged`、`--cap-add`、`--device`、`--security-opt seccomp=unconfined`、
  `--security-opt apparmor=unconfined`。
- `--network host`、`--pid host`、`--ipc host`、`--uts host`。
- 改变 Docker 默认的 user namespace 配置（不要求 rootless Docker，但推荐 rootless 宿主）。
- 挂载 `/var/run/docker.sock`、`/run/containerd/containerd.sock`、宿主 home、宿主 `/`。
- `-v` / `--volume` 简写；统一用 `--mount`，避免逗号/冒号歧义。
- `--entrypoint` 指向 shell 或仓库里的脚本。
- `--env-file`、从宿主继承环境。

> `/dev/shm` 的 tmpfs 覆盖在部分 Docker 版本上可能与默认 shm 挂载冲突。preflight 会暴露
> 差异：冲突时拒绝执行，或退回 `--shm-size 64m` 并在报告里写 `shm_noexec=false`，不能
> 假装它仍然是 noexec。

### 5.3 启动前 preflight：验证“实际生效的配置”

Docker 可能因为平台差异、daemon 配置、旧版本而忽略/改写参数。每个 run 在真正执行阶段
之前，先用**同样的参数**启动一个 `--entrypoint /bin/true` 的预检容器（不接触仓库代码），
然后 `docker inspect` 校验：

| 检查项 | 期望 |
| --- | --- |
| `HostConfig.NetworkMode` | `none` |
| `HostConfig.ReadonlyRootfs` | `true` |
| `HostConfig.Privileged` | `false` |
| `HostConfig.CapDrop` | 包含 `ALL`（且 `CapAdd` 为空） |
| `HostConfig.SecurityOpt` | 包含 `no-new-privileges:true` |
| `Config.User` | `65534:65534` |
| `HostConfig.PidsLimit` | 等于计划值 |
| `HostConfig.Memory` / `MemorySwap` | 等于计划值 |
| `HostConfig.NanoCpus` | 等于计划值 |
| `Mounts` | 只有 `/work`，且 `RW=true`、source 是预期目录 |
| `HostConfig.Binds` | 为空（只用 `--mount`） |

任何一项不符 → `INTEGRITY_FAILURE`，**不启动阶段容器**，报告写“环境未按计划加固，
本次不执行仓库代码”。这比“先跑了再说”更安全，也避免把平台差异误读成仓库行为。

`/bin/true` 不存在时预检失败（有些极简镜像可能没有）——第一版接受这个限制，报告
`preflight_tool_missing` 并拒绝执行；不退回“猜测配置”。

### 5.4 每个阶段容器的生命周期

1. 宿主计算剩余总预算；不足则 `not_run`。
2. `docker create` + `docker start -a` 或 `docker run`（需要拿到容器名做 inspect）。
3. 宿主开始捕获 stdout/stderr、轮询进程/资源。
4. 阶段进程退出 → 容器退出（`--init` 负责回收）。
5. 宿主 `docker inspect` 读取 `State`（退出码、OOMKilled、起止时间、Error）。
6. `docker rm -f` 删除容器；记录清理结果。
7. 宿主扫描 `/work`，生成该阶段的文件差异增量。
8. 若超时：`docker kill --signal KILL` → inspect → `docker rm -f`；记录 `timed_out`。

容器名带随机 run id，并打 label；清理时按名字和 label 双保险，绝不 `docker system prune`。

### 5.5 Tier 2：离线安装（本设计定义，v1 不实现）

当用户提供本地只读缓存时，才允许 `install`：

- `--behavior-install-cache DIR`：必须是本地目录，不能位于仓库快照内，不能是 home 或
  文件系统根；以只读方式挂到 `/opt/reuseguard/cache`。
- 固定命令按生态选择，仍然 `shell=False`、非 root、`--network none`：
  - Python：`python -m pip install --no-index --find-links /opt/reuseguard/cache/wheels --no-build-isolation .`
  - Node：`npm ci --offline --cache /opt/reuseguard/cache/npm`
  - Go：`go mod download`（模块缓存只读挂载，`GOMODCACHE` 指向可写副本）
  - Rust：`cargo fetch --offline`（`CARGO_HOME` 指向缓存的可写副本）
- 缓存缺失 → `skipped_cache_missing`，不是错误。
- 缓存本身是用户提供的信任输入；报告记录路径和文件数，不记录内容。
- **不做**：自动下载依赖、自动 `pip install` 联网、自动 `npm install` 联网。

Tier 3（更远）：允许安装时联网，但只能经过一个**用户提供的、digest 锁定的代理容器**，
代理按域名 allowlist 转发并记录请求；Docker 网络用 internal network，只有代理能出网。
这需要单独设计代理镜像、allowlist、日志和证书，不在本设计的 v1 范围。

---

## 6. 网络边界

### 6.1 第一版：`--network none`

- 容器只有 loopback，没有默认路由、没有 DNS、没有外部接口。
- 任何 `connect()` 到外部地址都会失败；ReuseGuard **不枚举失败的连接尝试**（没有
  syscall 追踪），只记录“容器没有出网能力”这个事实。
- `169.254.169.254`、Docker 内嵌 DNS、宿主局域网都不可达。
- 测试套件如果依赖网络，会失败；报告记为 `inconclusive`，不是安全发现。

报告措辞必须区分：

- ✅ “本次运行的容器没有网络能力。”
- ❌ “仓库没有尝试联网。”（无法从 `--network none` 推出这句话）

### 6.2 可观察的网络证据

| 证据 | 采集方式 | 可信度 |
| --- | --- | --- |
| 网络模式 | `docker inspect` | 宿主观察，高 |
| 出网能力 | `--network none` 配置 | 宿主观察，高 |
| 容器内监听端口 | Linux：读 `/proc/<container-pid>/net/tcp{,6}`；Windows：不可用 | 采样，可能漏 |
| 已建立连接 | 同上 | 采样；`none` 下只可能是 loopback |
| 连接尝试 | **不采集** | 没有 syscall 追踪；不要声称“没有尝试” |

### 6.3 Tier 3：代理白名单（未来）

如果以后要支持联网安装，必须满足：

- Docker 网络是 `internal`，容器没有直接出网路由。
- 唯一出口是用户提供的代理容器（digest 锁定），代理按域名 allowlist 转发。
- 代理日志记录目标 host、时间、字节数；**不记录请求体**（避免把仓库内容写进日志）。
- 报告把“代理记录到的请求”标为 `proxy_observed`，仍然不是“仓库只访问了这些域名”的证明。

---

## 7. 文件系统边界

### 7.1 挂载表

| 容器路径 | 类型 | 权限 | 内容 | 说明 |
| --- | --- | --- | --- | --- |
| `/` | 镜像 rootfs | 只读 | 镜像内容 | `--read-only`；不能写 `/usr`、`/etc` |
| `/work` | 宿主 bind | rw | 一次性工作目录 | 仓库副本、HOME、缓存、构建产物 |
| `/work/repo` | 同上 | rw | 仓库副本 | 阶段 cwd |
| `/tmp` | tmpfs | rw, noexec, nosuid, nodev, 64m | 临时文件 | 不能执行，不能 setuid |
| `/run` | tmpfs | rw, noexec, nosuid, nodev, 16m | 运行时目录 | 某些工具需要 |
| `/dev/shm` | tmpfs | rw, noexec, nosuid, nodev, 64m | 共享内存 | 防止用宿主 `/dev/shm` |
| `/proc` | 默认 | 只读/掩码 | — | 保留 Docker 默认 masked/read-only paths |
| `/sys` | 默认 | 只读 | — | 不额外挂载 |
| Docker socket | 不挂载 | — | — | 容器内不存在 |
| 宿主 home / `/` | 不挂载 | — | — | 明确拒绝 |

### 7.2 工作副本怎么来

- 宿主在 ReuseGuard 的临时目录下创建 `<workdir>`，父目录权限 `0700`。
- 从快照复制到 `<workdir>/repo`：
  - 只复制普通文件和目录；**拒绝符号链接、硬链接、设备、FIFO、socket**（快照解包阶段
    本来就已经拒绝，这里是第二道）。
  - 清除 setuid/setgid 位；文件 mode 收敛到 `0644` / `0755`。
  - 限制：最多 20,000 个文件、200 MiB；超过则拒绝执行（`COPY_LIMIT`），不截断后继续。
  - 保留可执行位（测试/构建需要），但不保留危险权限。
- `<workdir>` 对容器 uid 65534 可写：在 Linux 上 `chmod 0777` 这个一次性目录；父目录
  仍是 `0700`。Windows / Docker Desktop 的 bind mount 权限语义不同，需单独冒烟（见 14.3）。
- `/work/home`、`/work/.cache`、`/work/.npm`、`/work/.cargo` 等由宿主预创建，避免
  包管理器因为 HOME 不可写而失败。

### 7.3 哪些文件行为能被观察到

宿主在以下时间点扫描 `<workdir>`：

- 复制完成后（基线）。
- 每个阶段结束后（阶段增量）。
- 全部阶段结束后（最终差异）。

记录：

- `created` / `modified` / `deleted`；
- `type`（file / dir / symlink / fifo / socket / other）；
- `size`、`mode`、`mtime`；
- 对普通文件，若 `size <= 1 MiB` 且总哈希预算未用完，记录 `sha256` 和
  `content_verified=true`；否则只记大小/mtime，`content_verified=false`。

**看不到什么**（必须写进报告）：

- 同一阶段内“创建后又删除”的文件：最终状态看不到。
- 覆盖写后恢复原大小/mtime 的内容：没有哈希的文件看不出来。
- `/work` 之外的写入：rootfs 只读，写不进去；但“尝试写”本身也观察不到。
- 容器内 `/tmp` 的写入：阶段结束就消失，不进入证据。
- 进程内存里的数据、临时 socket、管道内容。

### 7.4 扫描器的自我防护

- 只用 `lstat`，**从不跟随符号链接**；不打开 FIFO/socket/设备文件；只对普通文件算哈希。
- 文件名可能包含控制字符/超长字节：渲染前做转义、截断；JSON 里保留 UTF-8 可表示形式。
- 单个目录项数、总路径数、哈希字节数都有上限（见第 8 节），防止仓库用海量文件拖死宿主。
- 文件差异列表按路径排序，最多每类 500 条；超出标记 `truncated`。

---

## 8. 超时、输出与资源上限

所有上限都是**硬上限**；超限要记录 `truncated` / `resource_exhausted`，不能静默截断。

### 8.1 时间

| 项 | 默认 | 允许范围 | 超限行为 |
| --- | ---: | ---: | --- |
| 总预算（整个 behavior probe） | 300 s | 30–1800 s | 停止启动新阶段；当前阶段 kill；状态 `timeout` |
| 单阶段 | 120 s | 10–900 s | `docker kill --signal KILL`；inspect；`timed_out=true` |
| 工具预检 | 15 s | 固定 | `skipped_tool_missing` / `preflight_error` |
| `docker info` | 5 s | 固定 | Docker 不可用，降级 |
| 容器清理 | 30 s | 固定 | 记录 `cleanup_failed`，保留容器名 |
| 总预算的计时起点 | 第一个预检容器启动前 | — | 包含复制/预检/阶段/清理前的所有宿主操作 |

### 8.2 输出

| 项 | 上限 | 处理 |
| --- | ---: | --- |
| 单阶段 stdout | 64 KiB | 保留前 32 KiB + 后 32 KiB，中间插入 `... [truncated N bytes] ...` |
| 单阶段 stderr | 64 KiB | 同上 |
| 整个 probe 捕获的原始输出 | 512 KiB | 超出后继续 drain（防止管道阻塞），但不再保存；标记 `truncated` |
| 宿主从 Docker 读取的原始流 | 1 MiB | 超出后丢弃中段；仍保留尾部；标记 `output_flood` |
| 阶段输出里的单行长度 | 4 KiB | 截断并标记 |
| 报告 JSON 总大小 | 2 MiB | 按优先级裁剪：输出尾部 → 进程样本 → 文件列表；保留阶段/退出码/完整性 |
| Markdown 的 behavior 区块 | 120 行 / 每类 20 条事件 | 只展示结构化摘要，不展示原始输出 |

输出处理：

- 去掉 ANSI 转义序列；NUL 和其他控制字符替换为 `?`（保留 `\n`、`\t`）。
- UTF-8 解码失败用 `errors="replace"`。
- 不执行输出里的任何内容；不把输出当 JSON 解析（除非是 ReuseGuard 自己的、宿主生成的
  结构化字段）。
- Markdown 里对输出做 HTML/Markdown 转义；默认不渲染原始 stdout/stderr。

### 8.3 资源

| 项 | 默认 | 允许范围 | 超限行为 |
| --- | ---: | ---: | --- |
| 内存（含 swap） | 512 MiB | 128–4096 MiB | cgroup OOM；inspect `OOMKilled` |
| CPU | 1.0 | 0.1–4.0 | 限流；不 kill |
| PIDs | 128 | 16–512 | fork 失败；记录 `pids_limit_hit` |
| nofile | 512 | 固定 | 打开文件失败 |
| core dump | 0 | 固定 | 不落盘 |
| `/work` 总字节 | 512 MiB | 64–4096 MiB | 宿主每 1 s 监控，超限 kill；`resource_exhausted` |
| `/work` 文件数 | 50,000 | 1,000–200,000 | 同上 |
| 进程采样 | 2,000 条样本 / 200 个唯一进程 | 固定 | 停止采样，标 `truncated` |
| 文件清单 | 50,000 个路径 | 固定 | 停止扫描，标 `truncated`；不继续哈希 |
| 哈希预算 | 5,000 个文件 / 64 MiB | 固定 | 剩余文件 `content_verified=false` |
| 容器数 | 1 个并发 | 固定 | 顺序执行 |

内存的说明：`--memory` 限制的是容器 cgroup；tmpfs（`/tmp`、`/run`、`/dev/shm`）的页也
计入 cgroup，所以不要把 tmpfs 设得比内存上限还大。`/work` 是宿主磁盘，不占容器内存，
但占宿主磁盘，因此单独监控。

### 8.4 报告大小与隐私

- JSON 报告可能包含仓库自己打印的内容（包括它自己的密钥）。默认只保留有上限的尾部，
  并在文档里提醒“JSON 报告按敏感文件处理”。
- Markdown 默认不展示原始输出；需要排查时用 `--format json` 或 `-v`。
- 不把宿主环境变量、token、代理配置写进报告。

---

## 9. 证据 schema

### 9.1 可信度分级

每条证据都带 `trust` 字段，避免读者把“采样”当成“完整”：

| trust | 含义 | 例子 |
| --- | --- | --- |
| `host_observed` | 宿主直接观察，不依赖容器内程序配合 | Docker inspect 的退出码/OOM、镜像 digest、挂载配置、文件差异、canary |
| `host_sampled` | 宿主轮询，可能漏掉短命事件 | 进程列表、内存/CPU/PID 峰值 |
| `proxy_observed` | 未来代理记录 | 出网请求（Tier 3） |
| `untrusted_repo_output` | 仓库自己打印的内容，只作线索 | stdout/stderr 尾部、测试输出 |
| `unavailable` | 平台/权限不支持 | Windows 上的容器内 socket 列表 |

### 9.2 JSON 示例

```json
{
  "schema": "reuseguard.behavior/1",
  "status": "completed",
  "run_id": "01J9Z8YQ3K7V5M2C4R6T8W0XAB",
  "tool_version": "0.7.0",
  "protocol_version": 1,
  "platform": {"os": "linux", "architecture": "amd64", "docker": "27.3.1"},
  "image": {
    "reference": "python@sha256:0123...abcd",
    "repo_digest": "python@sha256:0123...abcd",
    "image_id": "sha256:89ab...ef01",
    "os": "linux",
    "architecture": "amd64",
    "digest_verified": true
  },
  "container": {
    "runtime": "runc",
    "user": "65534:65534",
    "network_mode": "none",
    "readonly_rootfs": true,
    "cap_drop": ["ALL"],
    "no_new_privileges": true,
    "pids_limit": 128,
    "memory_mb": 512,
    "cpus": 1.0,
    "preflight_ok": true
  },
  "limits": {
    "total_timeout_seconds": 300,
    "phase_timeout_seconds": 120,
    "max_output_bytes": 65536,
    "max_work_bytes": 536870912,
    "max_work_files": 50000
  },
  "started_at": "2026-11-01T07:00:00Z",
  "finished_at": "2026-11-01T07:00:42Z",
  "duration_seconds": 42.1,
  "phases": [
    {
      "name": "import",
      "argv": ["python", "-E", "-s", "-c", "import demo"],
      "cwd": "/work/repo",
      "exit_code": 0,
      "docker_exit_code": 0,
      "signal": null,
      "status": "completed",
      "timed_out": false,
      "oom_killed": false,
      "duration_seconds": 1.2,
      "stdout": {
        "tail": "hello from import\n",
        "bytes": 17,
        "truncated": false,
        "trust": "untrusted_repo_output"
      },
      "stderr": {
        "tail": "",
        "bytes": 0,
        "truncated": false,
        "trust": "untrusted_repo_output"
      },
      "tool_preflight": {"argv": ["python", "-c", "import sys"], "exit_code": 0},
      "error": null
    },
    {
      "name": "test",
      "argv": ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--maxfail=20"],
      "cwd": "/work/repo",
      "exit_code": 137,
      "docker_exit_code": 137,
      "signal": 9,
      "status": "oom",
      "timed_out": false,
      "oom_killed": true,
      "duration_seconds": 8.4,
      "stdout": {"tail": "...", "bytes": 4096, "truncated": false, "trust": "untrusted_repo_output"},
      "stderr": {"tail": "Killed", "bytes": 7, "truncated": false, "trust": "untrusted_repo_output"},
      "tool_preflight": {"argv": ["python", "-m", "pytest", "--version"], "exit_code": 0},
      "error": null
    }
  ],
  "processes": {
    "trust": "host_sampled",
    "sampled": true,
    "interval_ms": 250,
    "unique": 2,
    "samples": [
      {
        "pid": 7,
        "ppid": 1,
        "uid": 65534,
        "comm": "python3",
        "cmdline": "python -E -s -c import demo",
        "first_seen": "2026-11-01T07:00:05Z",
        "last_seen": "2026-11-01T07:00:06Z",
        "samples": 3
      }
    ],
    "truncated": false,
    "note": "Sampled from the host; short-lived processes may be missed."
  },
  "files": {
    "trust": "host_observed",
    "created": [
      {
        "path": "repo/demo.pyc",
        "type": "file",
        "size": 120,
        "mode": "0644",
        "sha256": "f00d...",
        "content_verified": true,
        "phase": "import"
      }
    ],
    "modified": [],
    "deleted": [],
    "truncated": false,
    "note": "Only final-state differences are observable; create-then-delete inside a phase is invisible."
  },
  "network": {
    "trust": "host_observed",
    "mode": "none",
    "egress_possible": false,
    "connections": [],
    "listening_sockets": [],
    "note": "With --network none, failed connection attempts cannot be enumerated."
  },
  "resources": {
    "trust": "host_sampled",
    "peak_memory_bytes": 48234496,
    "peak_pids": 2,
    "cpu_seconds": 0.42,
    "oom_killed": true,
    "oom_suspected": true
  },
  "integrity": {
    "preflight_ok": true,
    "canary_ok": true,
    "unexpected_docker_objects": [],
    "tamper_possible": true,
    "notes": [
      "Evidence is collected by the host; observed code runs as an unprivileged container user.",
      "A kernel or container-runtime escape is outside this probe's detection scope."
    ]
  },
  "truncations": [],
  "warnings": []
}
```

### 9.3 字段语义

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `schema` | string | 固定 `reuseguard.behavior/1`；破坏性变更升 `2` |
| `status` | enum | `completed` / `timeout` / `error` / `partial` / `refused` / `unavailable` / `integrity_failure` |
| `run_id` | string | 本次运行随机 id；用于容器 label 和清理 |
| `image.reference` | string | 用户输入的 digest 引用；启动前校验 |
| `image.digest_verified` | bool | `RepoDigests` 校验结果；false 时绝不执行 |
| `container.preflight_ok` | bool | 实际生效配置是否与计划一致 |
| `started_at` / `finished_at` | ISO 8601 UTC | 宿主时钟 |
| `duration_seconds` | float | 宿主单调时钟测得 |
| `phases[].argv` | string[] | 实际执行的固定 argv；不含宿主路径 |
| `phases[].exit_code` | int/null | 以 `docker inspect .State.ExitCode` 为准 |
| `phases[].docker_exit_code` | int/null | `docker run` CLI 的退出码；与前者不同时写 warning |
| `phases[].signal` | int/null | `exit_code > 128` 时按 `exit_code - 128` 推断，仅作线索 |
| `phases[].timed_out` | bool | 宿主超时标记，**不靠 137 猜** |
| `phases[].oom_killed` | bool | `docker inspect .State.OOMKilled` |
| `phases[].stdout/stderr` | object | 有上限的尾部；`trust=untrusted_repo_output` |
| `processes` | object | 采样进程；`trust=host_sampled`；可能漏 |
| `files` | object | 宿主侧最终状态差异；不跟随符号链接 |
| `network` | object | 网络模式 + 能力；`none` 下不声称“没有尝试” |
| `resources` | object | 峰值内存/PID/CPU；采样 |
| `integrity` | object | 预检、canary、Docker 对象差异；`tamper_possible` 恒为 true |
| `truncations` | string[] | 每个被截断的字段/原因 |
| `warnings` | string[] | 平台限制、清理失败、无法观察项 |

### 9.4 与数据模型的映射（实现时）

新增（不改变现有 `SandboxReport`）：

```text
BehaviorStatus        disabled | unavailable | refused | completed | timeout | error | partial | integrity_failure
BehaviorReport        status, schema, run_id, tool_version, image, container, limits,
                      started_at, finished_at, duration_seconds, phases, processes,
                      files, network, resources, integrity, truncations, warnings
BehaviorPhase         name, argv, cwd, exit_code, docker_exit_code, signal, status,
                      timed_out, oom_killed, duration_seconds, stdout, stderr,
                      tool_preflight, error
CapturedStream        tail, bytes, truncated, trust
ProcessSample         pid, ppid, uid, comm, cmdline, first_seen, last_seen, samples
FileChange            path, type, size, mode, sha256, content_verified, phase
NetworkEvidence       mode, egress_possible, connections, listening_sockets, note
ResourceUsage         peak_memory_bytes, peak_pids, cpu_seconds, oom_killed, oom_suspected
IntegrityEvidence     preflight_ok, canary_ok, unexpected_docker_objects, tamper_possible, notes
```

`Assessment` 增加 `behavior: BehaviorReport | None`；`Report.to_dict()` 自动序列化。
报告 `schema_version` 从 1 升到 2 时，在 README 写迁移说明（新增字段，旧字段不变）。

---

## 10. 失败、超时、OOM 的检测与记录

### 10.1 退出码语义

| 情况 | `phases[].status` | 记录 | 结论影响 |
| --- | --- | --- | --- |
| 命令退出 0 | `completed` | exit_code=0 | 无（不代表安全） |
| 命令退出 1–124 | `failed` | exit_code | 无（可能是测试失败/缺依赖） |
| Docker CLI 125（daemon/run 错误） | `docker_error` | docker_exit_code, stderr 尾部 | warning；不执行后续阶段 |
| 126（无法执行） | `failed` | exit_code=126 | warning |
| 127（找不到命令） | `failed` / `skipped_tool_missing` | 预检结果 | 视为镜像缺工具 |
| 128+n（信号） | `killed` | signal=n | warning |
| 137 且 inspect OOMKilled=true | `oom` | `oom_killed=true` | 压到 INSPECT（覆盖不完整） |
| 137 但非 OOM | `killed` | `kill_suspected=true` | 记录；不自动判恶意 |
| 宿主超时后 kill | `timeout` | `timed_out=true` | 压到 INSPECT |
| 文件/字节超限 | `resource_exhausted` | 超限字段 | 压到 INSPECT |
| 预检配置不符 / canary 被动 | `integrity_failure`（整体） | 具体项 | 压到 INSPECT + 醒目警告 |
| 平台无法观察 | `partial` | `trust=unavailable` | warning；不声称完整 |

**不要做的事**：

- 不把测试失败写成“发现漏洞”。
- 不把退出码 137 一律写成 OOM。
- 不把“没有进程样本”写成“没有起进程”。
- 不把“网络不可达”写成“没有联网尝试”。

### 10.2 超时的检测与记录

- 宿主用单调时钟计算 deadline；到点后 `docker kill --signal KILL`。
- kill 后等待最多 10 s，再 `docker rm -f`；inspect 必须在 rm 之前。
- 记录：`timed_out=true`、阶段已运行时长、最后 64 KiB 输出、当时的进程样本。
- 如果 `docker kill` 本身失败/daemon 无响应：记录 `docker_unresponsive`，停止后续阶段，
  报告写“容器可能仍在运行”，给出容器名，建议人工 `docker rm -f`；不无限重试。
- 总预算耗尽时，剩余阶段 `not_run`，整体 status=`timeout`。

### 10.3 OOM 的检测与记录

- 唯一可靠的 OOM 证据是 `docker inspect .State.OOMKilled`。
- `exit_code == 137` 只是线索：可能是 OOM，也可能是宿主超时 kill、用户手动 kill。
- `docker stats --no-stream` 的峰值内存是采样，可能低于真实峰值；报告标 `host_sampled`。
- OOM 的含义是“本次运行没跑完”，不是“仓库恶意”；结论压到 INSPECT 是因为证据不完整。
- 如果 OOM 发生在 import 阶段，测试阶段仍然可以跑（如果预算允许），但要记录
  `dependency_state=oom`。

### 10.4 容器逃逸：能做什么、不能做什么

**先说不能做的**：ReuseGuard 是用户态工具，**无法检测内核漏洞或容器运行时逃逸**。
如果攻击者利用了 runc/内核漏洞，它已经在信任边界之外；本探测不会给出可靠告警。
报告必须写：“容器运行时和宿主内核是信任边界；本探测不检测内核/运行时逃逸。”

**能做的 best-effort 检查**：

1. **预检配置校验**（5.3）：确认 `--network none`、只读 rootfs、cap-drop、
   no-new-privileges、非 root、挂载范围实际生效。配置不符直接拒绝执行。
2. **宿主 canary**：在 `<workdir>` 的兄弟目录创建随机内容、`0700` 的 canary 文件，
   运行前后比对 SHA256。被改动 → `integrity_failure`，停止后续阶段，保留现场。
   （canary 不在挂载范围内，正常容器看不到。）
3. **Docker 对象快照**：运行前后记录 `docker ps -a` 和 `docker images` 的 id/name，
   对比是否出现新容器/新镜像。新对象可能是用户并发操作，因此只记 `warning`，不单独
   判恶意；结合 label 和时间窗口解释。
4. **清理校验**：按 label 查残留容器；有残留 → `cleanup_failed`，报告容器名。
5. **不挂载** Docker socket、宿主 home、宿主根、设备；`--privileged=false`。
6. **阶段进程与宿主隔离**：容器 PID namespace 独立；宿主只通过 Docker API 和 `/proc`
   读取，不 `docker exec` 进容器执行命令。

如果 canary 或预检出现 `integrity_failure`：

- 立即停止后续阶段，不删除 `<workdir>`（保留证据）。
- 报告最前面写“本次隔离完整性校验失败，不要依赖本次结果”。
- 建议用户检查宿主：`docker ps -a --filter label=reuseguard.run=<run>`、宿主安全日志。
- **不自动把仓库判为恶意**：也可能是 Docker Desktop 配置、权限、并发操作导致的误报；
  需要人工判断。

---

## 11. 结论与措辞

### 11.1 结论影响规则

| 行为探测结果 | 对 decision 的影响 | confidence | 必须追加的 limitation |
| --- | --- | --- | --- |
| 未请求 / `off` | 无 | 不变 | 无 |
| Docker 不可用 / 镜像缺失 / digest 不符 | 无 | 不变 | “行为探测未运行；这不影响静态结论，但也没有行为证据。” |
| `completed`，无异常观察 | **不升级、不降级** | 不变 | “一次运行、一个快照；没有观察到异常不等于安全。” |
| `completed`，有可疑观察（未来 Tier 3） | 最多压到 INSPECT | ≤ medium | “观察到的行为需要人工判断；不是恶意判决。” |
| `timeout` / `oom` / `resource_exhausted` | 最多压到 INSPECT | ≤ medium | “行为探测未完成，覆盖不完整。” |
| `failed` / `inconclusive` | 无 | 不变 | “阶段失败可能是环境/依赖问题，不是安全发现。” |
| `integrity_failure` | 最多压到 INSPECT | ≤ low | “隔离完整性校验失败，本次结果不可依赖。” |
| 静态结论已是 AVOID | **不改变** | 不变 | 行为探测不能把 AVOID 洗成 USE/INSPECT |

**硬规则**：

- 行为探测**永远不能**把结论升级为 USE，也不能提高 confidence。
- 行为探测**永远不能**自动产生 AVOID；AVOID 仍只来自静态 high/critical 或信誉门槛。
- 行为探测**不能**覆盖或削弱已有 caveat；只能追加。
- 如果行为探测没跑/跑了但没结论，报告不能暗示“已做动态验证”。

### 11.2 固定措辞（报告英文，文档中文）

报告里每个 behavior 区块固定包含：

```text
Behavior probe executed repository code in a disposable container.
This was one run, of one snapshot, on one machine.

A run with no observations is not evidence of safety. Code can detect the
sandbox, delay activity, or behave differently outside it.

Observed behavior is evidence, not a verdict. Only a human can judge intent.

Process and resource observations are sampled; short-lived processes can be missed.
File evidence reflects final state only; create-then-delete is invisible.

The container runtime and host kernel are trusted. This probe does not detect
kernel or container-runtime escapes.

Image pinned by digest: <reference>. Image contents are trusted only as far as
the registry and the local Docker daemon.
```

中文版（README / 文档）：

> 行为探测在一次性容器里执行了仓库代码。这是一次运行、一个快照、一台机器。
> 没有观察到异常不等于安全；代码可以检测沙箱、延迟行为，或在别的环境里表现不同。
> 行为证据不等于恶意判决；进程和资源是采样的，文件证据只反映最终状态。
> 容器运行时和宿主内核是信任边界；本探测不检测内核/运行时逃逸。

### 11.3 为什么强调“证据可被干扰”

- 被观测代码和证据采集器不在同一个信任级别：代码只能写 `/work`，但宿主采集器读的是
  文件系统的**最终状态**，代码可以删除/覆盖自己的痕迹。
- 进程是采样的，短命进程可能完全没被看到。
- 网络在 `--network none` 下只能证明“没有出网能力”，不能证明“没有尝试”。
- stdout/stderr 完全由仓库控制，不能当作事实，只能当作线索。

因此报告写“observed / not observed”，不写“did / did not”。

---

## 12. CLI、配置与报告

### 12.1 CLI（设计）

```text
--behavior [import|test|all]      默认 off；显式开启；all = import + test
--behavior-image IMAGE@sha256:... 必填（当 --behavior 不是 off）
--behavior-timeout SECONDS        总预算，默认 300（30–1800）
--behavior-phase-timeout SECONDS  单阶段，默认 120（10–900）
--behavior-memory-mb MB           默认 512（128–4096）
--behavior-cpus N                 默认 1.0（0.1–4.0）
--behavior-pids N                 默认 128（16–512）
--behavior-max-work-mb MB         默认 512（64–4096）
--behavior-max-work-files N       默认 50000（1000–200000）
--behavior-keep-workdir           保留 /work 现场，便于排查；仍不保留宿主其他路径
```

校验规则：

- `--behavior` 非 off 时，`--behavior-image` 必填，且必须带 `@sha256:`。
- `--behavior-image` 单独出现（没有 `--behavior`）→ 参数错误，避免以为已经开启。
- `--behavior` 与 `--no-scan` 互斥：没有快照就没有东西可跑。
- `--behavior` 与 `--sandbox off` 可以共存（两者独立）。
- `--behavior` 不会因为 `--sandbox auto` 自动开启。
- 只对“扫描完成、有快照”的候选运行；被信誉过滤跳过的候选记 `not_run`。

### 12.2 配置（YAML）

第一版**不允许 YAML 开启行为探测**（执行不可信代码必须是显式 CLI 动作）。YAML 只允许
调整上限/镜像引用（仍然必须是 digest）：

```yaml
behavior:
  image: "python@sha256:..."
  timeout_seconds: 300
  phase_timeout_seconds: 120
  memory_mb: 512
  cpus: 1.0
  pids: 128
  max_work_mb: 512
  max_work_files: 50000
```

如果 YAML 里出现 `enabled: true` 这样的 key，直接 `ConfigError`，防止团队策略“悄悄打开”
执行不可信代码。

### 12.3 报告展示

Summary 表新增一列 `Behavior`（没跑显示 `—`，跑了显示 `1 phase` / `timeout` / `oom`）。

每个仓库的详情区块：

```markdown
### Behavior — one container run (not a safety proof)

- Image: `python@sha256:0123…abcd` (digest verified)
- Container: uid 65534, network none, read-only rootfs, 512 MB / 1 CPU / 128 PIDs
- Status: completed in 42.1 s

| Phase | Exit | Duration | Result |
| --- | ---: | ---: | --- |
| import | 0 | 1.2 s | completed |
| test | 137 | 28.4 s | oom (container killed) |

Observed: 2 processes (sampled), 3 files created, 0 files modified, 0 deleted.
Network: none (no egress capability; failed attempts are not enumerated).

> One run, one snapshot, one machine. No observation is not a safety proof.
> Behavior evidence is not a malware verdict.
> The container runtime and host kernel are trusted; escapes are out of scope.
```

规则：

- 不展示原始 stdout/stderr（Markdown）；JSON 里有有上限的尾部。
- 文件事件最多展示 20 条，其余“见 JSON”。
- OOM/timeout/integrity_failure 用醒目文案，不淹没在表格里。
- 不在 Markdown 里渲染仓库提供的 HTML/ANSI。

---

## 13. 测试与验收

### 13.1 单元测试（全部离线，CI 不装 Docker）

用 `FakeCommandRunner` / 临时目录覆盖：

- 镜像引用校验：tag、缺 digest、digest 格式错、`RepoDigests` 不含请求、大小写。
- 预检配置校验：NetworkMode、ReadonlyRootfs、CapDrop、User、Mounts、Binds 不符。
- 阶段选择：`import` / `test` / `all`、语言检测、src-layout、unsupported。
- 命令构造：固定 argv、无 shell、无仓库参数、entrypoint 正确。
- 环境 allowlist：宿主 token/代理变量不出现；禁止项不出现。
- 输出截断：前 32 KiB + 后 32 KiB、单行 4 KiB、总 512 KiB、ANSI/控制字符。
- 进程解析：`/proc` 采样、去重、上限、平台不可用。
- 文件差异：created/modified/deleted、symlink 不跟随、FIFO 不打开、哈希预算、截断。
- 退出码：0/1/125/126/127/137、inspect 与 CLI 不一致时的 warning。
- 超时：kill 调用序列、inspect 在 rm 前、清理失败。
- OOM：`OOMKilled=true` vs 仅 137。
- 资源：`/work` 字节/文件数超限、pids 上限。
- 完整性：canary 改动、预检不符、新 Docker 对象、清理残留。
- 报告：JSON schema、Markdown 区块、固定 caveat、无原始输出。
- 结论：不升级、不自动 AVOID、timeout/OOM/integrity 的 INSPECT floor、AVOID 不被洗白。
- 清理：异常路径也调用 `docker rm -f`；不调用 `docker system prune`。

### 13.2 集成测试（fake Docker）

按顺序断言：

1. `docker info` → image inspect → digest 校验 → preflight create/start/inspect/rm。
2. baseline copy → 阶段容器 → inspect → 文件扫描 → 下一阶段。
3. 异常注入：预检失败时不启动阶段；超时后不启动下一阶段；总预算耗尽。
4. 所有路径都清理容器；`--behavior-keep-workdir` 时保留 `/work`、仍删容器。

### 13.3 手动 Docker 冒烟（设计确认后，问用户是否安装/使用 Docker）

不跑真实恶意软件。夹具：

| 夹具 | 目的 | 预期 |
| --- | --- | --- |
| benign Python 包（`import` 只打印） | 正常路径 | completed；退出码 0；文件差异可解释 |
| 写文件的包（启动时写 `/work/repo/created.txt`） | 文件证据 | created 列表包含它；Markdown 不展示原文 |
| 读 `/etc/passwd`、尝试连 `1.1.1.1:443` 的包 | 网络/文件观察 | 网络 egress=false；连接失败；不声称“没有尝试” |
| `sleep 3600` 的测试 | 超时 | `timeout`；容器被 kill；后续阶段 `not_run` |
| 分配 2 GB 的测试 | OOM | `oom_killed=true`；结论 INSPECT |
| 输出 10 MB 的测试 | 输出上限 | 截断标记；宿主内存不爆 |
| 创建 100k 文件的测试 | 文件数上限 | `resource_exhausted`；kill |
| tag 镜像 / 错 digest | 供应链 | `refused`；一个容器都不启动 |
| 预检配置不符（人为改 Docker 参数） | 完整性 | `integrity_failure`；不执行阶段 |

Windows / Docker Desktop 额外检查：

- bind mount 的 uid/permission 是否允许 65534 写入；不允许则预检失败，明确报错。
- `docker top` / `/proc` 不可用时，进程证据标 `partial`，不假装完整。
- 容器内 socket 列表不可用时标 `unavailable`。

### 13.4 验收标准（实现完成的定义）

1. 没有 `--behavior` + digest 镜像时，代码路径**绝不**调用 `docker run` 执行仓库代码。
2. 镜像 digest 校验失败时，一个容器都不启动。
3. 预检配置不符时，不启动阶段容器。
4. 所有上限都有测试；超限有 `truncated` / `resource_exhausted` 标记。
5. 报告每个 behavior 区块都包含 11.2 的固定措辞。
6. 行为探测不能升级结论、不能自动 AVOID；timeout/OOM/integrity 的 INSPECT floor 有测试。
7. 清理路径在异常时也执行；不残留带 label 的容器。
8. CI 仍然全离线、不装 Docker；359+ 测试全部通过。
9. README / project.md / HANDOFF 同步；JSON schema 有文档。
10. 至少一次手动 Docker 冒烟（在用户同意后），结果写回 HANDOFF。

---

## 14. 分阶段实施建议

| 步骤 | 内容 | 验证 |
| ---: | --- | --- |
| 0 | 用户确认第 0.1 节的 6 个决定 | 本文档更新为“已确认” |
| 1 | 数据模型 + CLI 校验 + 配置错误边界（不执行） | 单元测试；pytest/ruff |
| 2 | 镜像 digest 校验 + preflight + Docker 对象/清理骨架 | fake runner 测试 |
| 3 | 宿主侧复制、文件清单、差异、哈希上限 | 临时目录测试 |
| 4 | `import` / `test` 固定命令表 + 工具预检 | fake runner + 夹具 |
| 5 | 输出捕获/截断、进程/资源采样、超时/OOM | fake runner + 边界测试 |
| 6 | `BehaviorReport` + Markdown + verdict caveat | 报告/结论测试 |
| 7 | 手动 Docker 冒烟（先问用户） | 13.3 表格 |
| 8 | Tier 2 离线安装缓存 | 单独设计 + 测试 |
| 9 | Tier 3 代理出网 | 单独设计，不在 M4 v1 |
| 10 | gVisor / runsc 评估 | 单独文档 |

每个步骤单独 commit，补测试、跑 pytest + ruff、更新三份文档。**第 0 步没确认之前，
不写第 1 步代码。**

---

## 15. 待确认问题（请逐条回答）

1. **阶段范围**：第一版只做 `import` + `test`，`install` 放到 Tier 2 离线缓存，可以吗？
   （建议：可以。理由：安装几乎必然需要网络或缓存，先不放开。）
2. **触发方式**：行为探测只在显式 `--behavior` 时运行，`--sandbox auto` 不自动触发，
   可以吗？（建议：可以。自动执行不可信代码的风险太高。）
3. **结论影响**：行为证据最多把结论压到 INSPECT，不自动 AVOID、不升级 USE、不提高
   置信度，可以吗？（建议：可以。符合“行为证据 ≠ 恶意判决”。）
4. **镜像策略**：必须用户提供 `@sha256:` 镜像，ReuseGuard 不内置默认 digest、不自动
   pull，可以吗？（建议：可以。代价是首次使用要手动 pull + inspect。）
5. **工作副本**：用宿主侧一次性目录 bind 到 `/work`，宿主自己算文件差异（而不是容器内
   tmpfs + 容器自报），可以吗？（建议：可以。证据更可信，代价是要管宿主临时目录权限。）
6. **原始输出**：JSON 保留有上限的 stdout/stderr 尾部，Markdown 默认只展示结构化证据，
   可以吗？（建议：可以。避免把仓库内容/密钥抄进报告。）

另外两个可选项，不阻塞 v1：

- 是否在 README 明确写“Windows 上进程/socket 证据可能不完整”？
- 是否现在就把 containment 的默认镜像也改成 digest（会破坏现有 `--sandbox` 用法）？

---

## 附录 A：与现有代码的接入点（实现时参考，不是代码）

- `src/reuseguard/adapters/sandbox.py`：保留 containment；新增
  `src/reuseguard/adapters/behavior.py` 或 `sandbox_behavior.py`，不要塞进现有模块。
- `src/reuseguard/adapters/process.py`：复用 `run_command` 的 argv/`shell=False`/超时
  约定；行为探测需要**有界流式捕获**，不能把 10 MB 输出一次性读进内存。
- `src/reuseguard/models.py`：新增 `BehaviorReport` 等，`Assessment.behavior`；不动
  `SandboxReport` 的语义。
- `src/reuseguard/pipeline.py`：在沙箱阶段之后、verdict 之前插入 behavior 阶段；
  失败只写 warning，不改变已有 scan 结果。
- `src/reuseguard/stages/verdict.py`：新增 `add_behavior_caveat(verdict, behavior)`；
  实现第 11.1 的 floor 规则。
- `src/reuseguard/report.py`：新增 behavior 区块；Markdown 不输出原始 stdout/stderr。
- `src/reuseguard/config.py` / `cli.py`：新增参数与交叉校验；YAML 不允许 `enabled`。
- 测试：新增 `tests/test_behavior.py`；`tests/fakes.py` 增加 fake Docker inspect /
  top / stats 数据。

## 附录 B：术语

| 术语 | 人话 |
| --- | --- |
| 行为探测 | 在一次性容器里真的运行一次仓库代码，记录它做了什么 |
| 快照 | 从 GitHub 默认分支下载的 tar.gz 解包后的只读目录 |
| 镜像 digest | 镜像内容的密码学指纹；`@sha256:...` 保证你跑的是同一份镜像 |
| bind mount | 把宿主的一个目录挂进容器；这里只挂一次性 `/work` |
| cap-drop | 去掉 Linux capabilities，容器不能 mount、ptrace、改网络等 |
| no-new-privileges | 禁止通过 setuid 等机制提权 |
| seccomp | 限制容器能调用的系统调用 |
| OOM | 内存超限被内核杀掉；`docker inspect` 的 `OOMKilled` 是可靠证据 |
| canary | 放在挂载范围外的诱饵文件；被动过说明隔离可能有问题 |
| 信任边界 | 我们假设不会被攻破的组件；这里包括宿主内核和容器运行时 |

## 附录 C：参考

- Docker seccomp 默认配置：<https://docs.docker.com/engine/security/seccomp/>
- Docker 资源限制：<https://docs.docker.com/engine/containers/resource_constraints/>
- OCI Runtime Spec：<https://github.com/opencontainers/runtime-spec>
- gVisor：<https://gvisor.dev/>
- OpenSSF Scorecard（现有信誉阶段）：<https://github.com/ossf/scorecard>

---

> 再次强调：本文档只是设计。ReuseGuard 当前仍然**不会**在沙箱里执行仓库代码；在用户
> 确认第 15 节之前，不会开始实现。
