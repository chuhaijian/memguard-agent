# MemGuard 技术设计与实现方案

> 基于 eunomia-bpf/agentsight master（v1.0.31，commit `bb99b66f8f98`）源码研读
> 目标：在 AgentSight 的工程底座上，实现 LLM Agent 长期记忆投毒检测（FARMA/MINJA）

## 一、为什么基于 AgentSight 扩展而非全自研

| 能力 | AgentSight 现状 | 我们要补的 |
|---|---|---|
| TLS 明文捕获 | ✅ sslsniff.bpf.c（SSL_write/read + rustls ABI） | 无（直接复用） |
| 进程/文件事件 | ✅ exec/openat/write 计数/bash readline | 无（复用） |
| 事件流水线 | ✅ Event → Analyzer → sinks → SQLite | 无（复用） |
| CLI/常驻服务 | ✅ top/record/report/monitor + systemd | 无（复用） |
| **写入内容捕获** | ❌ 只统计字节数，不抓 payload | **新增 vfs_write 探针抓内容** |
| **投毒特征匹配** | ❌ 不认识投毒 | **新增 PoisonAnalyzer** |
| **告警出口** | ❌ 只有 Web UI/OTel | **新增 wecom/serverchan sink** |

## 二、落点清单（改动文件）

### 1. 新探针：记忆库写入内容捕获
- **文件**：`bpf/` 新增 `memwrite.bpf.c` + `memwrite.h`（照搬 ebpf_memguard.py 的 BPF 内核逻辑）
- **思路**：kprobe `vfs_write`，文件名前缀过滤记忆库（如 `ehragent_memory.db`），抓取载荷"头尾双窗口各 128B"（sqlite cell 从页尾生长，只抓头部会漏）
- **事件类型**：新增 `EVENT_TYPE_MEM_WRITE` / `EVENT_TYPE_MEM_READ`，写入 ringbuf
- **用户态**：`agentsight-capture/src/runners/` 新增 runner 解析该事件，产出 `Event { source: "memwrite", data: { path, offset, payload } }`

### 2. 投毒检测分析器（核心新增）
- **文件**：`agentsight-capture/src/analyzers/poison.rs` + `mod.rs` 注册
- **实现**：实现官方 `Analyzer` trait（`async fn process(stream) -> Result<stream>`）
  - 对 123 事件里的 `payload` 做 `POISON_SIGNATURES`（15 条中/英）匹配
  - 命中则重写 `Event.data`：注入 `poison: { matched: [...], severity: HIGH/CRITICAL }`
  - 保持无命中事件原样透传（Analyzer 是 stream 变换，天然可链接）

### 3. 告警 sink（出口）
- **文件**：`collector/src/output/`（或新增 `notify/` 模块）+ CLI 参数
- **实现**：移植 ebpf_memguard.py 的 `Notifier` 类（企业微信 markdown + Server酱），批量时间窗推送（默认 10s），`--notify-wecom/--notify-serverchan`
- **接入**：在 cmd_trace/cmd_monitor 的事件消费循环里，命中 poison 的事件经过 Notifier 聚合推送

### 4. 特征热加载（M2 可延后）
- 计划留口：`poison.rs` 支持从 `--poison-rules` 读外部特征文件（现在先硬编码 15 条）

## 三、里程碑（调整后）

- **M0 编译跑通**（✅ 09-02 达成）：服务器 2GB + swap 编译出 agentsight 二进制，`record` 能抓到沙箱记忆库写入
- **M1 检测闭环**（✅ 09-03 达成）：memwrite 探针 → PoisonAnalyzer → 告警，端到端 7 次投毒命中
  - 探针双 attach 成功：kprobe vfs_write + vfs_writev；verifier 修复见下方"M1 关键坑"
  - PoisonAnalyzer 集成路径：`BinaryRunner::memwrite()`（独立二进制+JSONL 流，与 sslsniff/stdiocap 同构）
  - 实测：`agentsight record --memwrite --memwrite-path bpf/memwrite -c python3` → demo 投毒 → 7 次 `[MemGuard] poison write detected`，9 特征命中
- **M2 规则热加载 + 多记忆库**（延后）：外部特征文件、多 path 前缀监控、事件查询 CLI
- **M3 产品化收口**（✅ 09-03 达成）：webhook/wecom 告警 sink 实链验证 + systemd 常驻服务 + 安装脚本 + 文档
  - 实链验证详情见下方「M3 实测记录」

## 三（补充）、M1 关键坑（已实测解决）

| 坑 | 现象 | 解法 |
|---|---|---|
| BPF verifier `R2 min value is negative` | bpf_probe_read_user 变长长度无法证明非负 | ① 常量长度读取（推荐）：`if (iov_len >= HALF) read(HALF)`；② 或 `len &= 0xff` 掩码——**注意 clang -O2 会把恒等掩码优化掉**（ternary 结果 ≤128 时 `& 0xff` 被消除） |
| clang 二次加载丢 range | ternary `cond ? mem : const` 编译成"比较→跳转→**重新从栈加载**"，verifier 分支约束不跟随 | 避免含栈内存读的变长路径；用常量长度读取代 |
| SQLite 写整页 | 投毒 cell 在页中部（实测距页尾 643–1114B），head/tail 128B 窗口 0 命中 | **fs 补偿**：loader 输出绝对 `path`（readlink /proc/pid/cwd），PoisonAnalyzer 读 `[offset, offset+count]` 整页全文匹配 → 100% 覆盖 |
| 探针二进制分发 | BinaryExtractor 用 include_bytes! 内嵌（每改必重编 collector） | 走 `--memwrite-path <外部路径>`（同 sslsniff `--binary-path` 模式），探针迭代只 re-make bpf/ |

## 四、构建环境（已实测）

- 服务器：Ubuntu 22.04 云主机（2 vCPU / 2GB + swap），内核 5.15.0-181-generic
- 内存：2GB + 5GB swap（新增 /swapfile2 4G），`CARGO_BUILD_JOBS=1`
- 已装：rustup（rustc 1.98.0）、clang-14（软链为 clang）、libelf-dev、node v22
- BTF：`/sys/kernel/btf/vmlinux` 存在 → CO-RE 直接可用，无需 vmlinux.h
- BPF 编译 ✅：process/sslsniff/stdiocap 三个探针 .o 均生成
- 依赖：`apt install clang-14 llvm-14 libelf-dev zlib1g-dev libssl-dev pkg-config`

## 五、风险与对策

| 风险 | 对策 |
|---|---|
| Rust 编译 OOM | 已扩 5GB swap + 单 job，若仍失败再扩或只编 collector |
| kprobe vfs_write 与 libbpf CO-RE 冲突 | 探针独立成 .bpf.c，log_level 调试；必要时改 tracepoint sys_enter_write |
| 探针需要 root + CAP_BPF | service 文件已默认 root 运行，与官方一致 |
| 事件负载过大（抓 256B/写） | 只对命中前缀的记忆库文件抓取，全系统开销 <3% 目标 |

## 六、M3 实测记录（09-03，已全链路验证）

### 6.1 告警推送实链（echo server 联调端验证）

用 `127.0.0.1:18099` 的 BaseHTTPRequestHandler 回显服务充当 webhook 出口，`--alert-base` 覆盖 API host（走 `override_url: base + api_no_scheme + suffix`）：

**WeCom（企业微信 markdown POST）** ✅
```
>>> POST /qyapi.weixin.qq.com/cgi-bin/webhook/send?key=fakekey123 HTTP/1.1
CT=application/json
BODY={"markdown":{"content":"**MemGuard 告警 1条 「记忆库写入×1」**\n[17:07:39] CRITICAL pid=356001 comm=python3 file=/tmp/memguard-demo/ehragent_memory.db sig=trusted source,pre-approved,bypass validation"},"msgtype":"markdown"}
```

**ServerChan（form GET .send）** ✅ — URL 编码正确（中文标题 `%20`/`%E5`…正常），query 解析出 title/desp 完整。

**检测→推送间的批处理窗口** ✅：`--alert-interval 3` 下一条命中也按窗口批量发出，severity 正确映射（子串命中 HIGH、组合命中 CRITICAL）。

### 6.2 验证踩坑：探针前缀匹配的是「文件名」不是「目录」

两次跑通验证里失败（零 MEM_WRITE、零告警）的共通根因：
`memwrite.bpf.c` 的 `watch_prefix` 用 **`d_name`（文件名）前缀匹配**，`resolve_path()` 只是把 `/proc/<pid>/cwd` 与 filename 拼成绝对路径供 fs 补偿用。
- ❌ demo 写成 `/tmp/.../ehragent_memory/ehr.db`（目录名含前缀、文件名 `ehr.db`）→ **不捕获**
- ✅ demo 写成 `<cwd>/ehragent_memory.db` 或任何以 `ehragent_memory` **开头**的文件名 → 捕获

调试判定技巧：看日志有没有 `[MemGuard] poison write detected`——没有就是探针没触发（前缀/权限问题），有但无推送才是 sink 问题。

### 6.3 systemd 常驻服务（memguard.service）

| 文件 | 落点 | 说明 |
|---|---|---|
| `run-memguard.sh` | `/opt/agentsight/run-memguard.sh` | 读 `/etc/memguard.env`，按 `WECOM_KEY/SERVERCHAN_KEY/ALERT_BASE/ALERT_DRY_RUN/MEMWRITE_PREFIX/ALERT_INTERVAL/ATTACH_COMM` 构造命令 |
| `memguard.env.example` | `/etc/memguard.env` | 模板；初装 `ALERT_DRY_RUN=1` 安全模式 |
| `memguard.service` | `/etc/systemd/system/memguard.service` | root + `KillSignal=SIGINT`（record 优雅落盘）+ 日志 append `/var/log/memguard.log` + `MemoryMax=2G` |

**部署命令**（初次）：
```bash
install -m 0644 memguard.env.example /etc/memguard.env   # 默认 dry_run=1
install -m 0755 run-memguard.sh /opt/agentsight/run-memguard.sh
install -m 0644 memguard.service /etc/systemd/system/memguard.service
systemctl daemon-reload && systemctl enable --now memguard
```

**服务态端到端验证**（不手动起 record，直接投毒）✅：
```
systemctl is-active memguard → active
日志: [MemGuard] poison write detected: pid=358450 comm=python3 file=/tmp/memguard-demo/ehragent_memory.db signatures=免验证,trusted source
日志: [MemGuard][dry-run] MemGuard 告警 1条 「记忆库写入×1」 [17:12:28] HIGH pid=358450 ...
```

**关键坑：`record` 强校验 attach 目标** — `agentsight record` 无 `-c/-p/--command` 直接报
`Error: record requires either a command or an attach target`。
memwrite 探针本身是独立二进制（按前缀 watch 所有进程），attach 目标仅满足 record 入口校验；
服务脚本默认 `-c python3`（记忆库写入侧常见 comm），`ATTACH_COMM` 可覆盖。sslsniff/process 等
其余 runner 即使 OpenSSL 缺失也只是 WARN，不影响 memwrite 链路。

### 6.4 上生产（切真实 webhook）

```bash
vim /etc/memguard.env   # 填 WECOM_KEY 或 SERVERCHAN_KEY; ALERT_DRY_RUN=0; ALERT_INTERVAL=10
systemctl restart memguard
```
验证：投一次 demo poison（见 6.2 命名规则），手机/群里收告警。

### 6.5 M2 完成：多前缀监控 + 投毒规则热加载（2026-09-03）

**多前缀监控（BPF 侧）**：`memwrite.bpf.c` 的 `watch_prefix` 从单字符串改为 `[MAX_WATCH_PREFIXES][WATCH_PREFIX_LEN] = 8×64` 二维数组 + `watch_prefix_count`；`match_prefix()` 双层 `#pragma unroll` 遍历所有前缀。`memwrite.c` loader 支持 `--prefix "a,b,c"` 逗号分隔填充 rodata（空则回退 `ehragent_memory`）。
- 选型理由：比 collector 侧起多个 runner 干净——多个 runner 会各挂一份 Analyzer/Sink，告警被拆批。一个探针实例 watch 多前缀，告警聚合在同一链路上。

**规则热加载（Rust 侧）**：`PoisonAnalyzer::new(prefix).with_rules(rules: Vec<String>)`；`--poison-rules <FILE>` 逐行读（支持 `#` 注释/空行），非空则**替换**内建 15 条，空则回退默认。`cmd_trace.rs` 在 build 时读文件、`prefix` 改为逗号分隔 `path.contains(any)` 匹配。

**实测（服务器）** ✅：
```
用例1 多前缀: ehragent_memory.db + codex_memory.db 都检出 signatures=trusted source,pre-approved
用例2a 自定义规则 poison_marker_xyz: 命中 (signatures=poison_marker_xyz)
用例2b 自定义规则下默认特征: 0 命中 (规则仅 poison_marker_xyz，验证替换生效)
```

**M2 验收踩坑（重要）**：
1. 验收脚本相对路径 bug：脚本先 `cd /tmp/memguard-demo` 后调用 `./target/release/agentsight`（相对路径）→ cwd 已变 → `No such file or directory` → record 没启动 → 零事件。修复：统一绝对路径 `AGENT=/opt/agentsight/collector/target/release/agentsight`，且验收前 `systemctl stop memguard` 避免抢同一 kprobe。
2. clap 参数名语义 bug：`main.rs` 字段名 `memwrite_rules` 自动生成长选项 `--memwrite-rules`，但调用用 `--poison-rules` → 运行时 `error: unexpected argument '--poison-rules' found`。修复：`#[arg(long = "poison-rules")]` 显式指定。**这类语义 bug 本地 `cargo check` 抓不到（编译通过），必须端到端验收。**

### 6.6 开发与验证工作流

推荐的改动验证流程（两级，避免"编译通过但语义错误"的返工）：

1. **本地静态检查**：Rust 改动先在本地 `cargo check -p agentsight-analysis` + `-p agentsight`
   （agentsight-capture-core 的 build.rs 条件编译会跳过 BPF 部分，非 Linux 环境亦可运行），
   零成本抓编译级错误（类型/借用/未定义符号/clap 同名冲突）。
2. **端到端验收**：改动同步到 Linux 构建机后编译探针与 collector，按 6.5 的三个用例
   （多前缀 / 自定义规则命中 / 默认特征不命中）实测验收。**注意：clap 参数名语义错误等
   运行时问题本地 check 抓不到，必须端到端验收覆盖。**
3. 验收前先 `systemctl stop memguard`，避免常驻服务与验收实例争抢同一 kprobe。
