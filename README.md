# MemGuard

**LLM Agent 记忆库投毒的 eBPF 实时检测与告警系统**

*eBPF-based real-time poisoning detection for LLM agent memory stores.*

MemGuard 是一套**叠加在 [AgentSight](https://github.com/eunomia-bpf/agentsight) 之上的扩展改动层（overlay）**，在 Agent 写入长期记忆（向量库 / SQLite 记忆库 / 会话摘要文件）的瞬间，于内核态完成投毒特征检测并触发告警，对 Agent 本身零侵入。

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![CI](https://github.com/chuhaijian/memguard-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/chuhaijian/memguard-agent/actions/workflows/ci.yml)

---

## 1. 背景与定位

LLM Agent 的长期记忆存在一类隐蔽攻击面：**记忆投毒（Memory Poisoning / Indirect Prompt Injection）**。攻击者在 Agent 可读取的内容中植入带有"信任背书"语义的片段——例如 `trusted source`、`免验证`、`可直接导入`——一旦被写入记忆库，后续会话会无条件继承这些指令，形成跨会话的持久化后门（学术上称为 FARMA / MINJA 类攻击）。

问题的关键在于，**写入发生后的审计往往已经太晚**。MemGuard 的定位是在**写入发生的瞬间**完成检测与告警：

| 维度 | 传统方案 | MemGuard |
|---|---|---|
| 检测时机 | 事后扫描数据库 / 日志 | **写入瞬间**（内核态 kprobe 捕获） |
| 侵入性 | 需改造 Agent 代码或 Hook 框架 | **零改造**，对 Agent 完全透明 |
| 覆盖范围 | 需枚举所有记忆库访问点 | 按文件名前缀统一 watch 全进程 |
| 响应手段 | 人工排查 | 秒级企业微信 / ServerChan 告警 |
| 默认安全 | — | **dry-run 模式上线**，不误发告警 |

## 2. 工作原理

```
                    ┌─────────────────────── 内核态 (eBPF) ───────────────────────┐
  Agent 进程写记忆库  │  kprobe: vfs_write / vfs_writev                            │
  (SQLite/文件) ─────┼─▶ 1. 按文件名前缀过滤（最多 8 个前缀，非目标文件零开销）      │
                    │  2. 捕获载荷 head/tail 各 128B 窗口                          │
                    │  3. 记录绝对路径 + offset + count（供用户态补偿读取）          │
                    └─────────────────────────┬─────────────────────────────────┘
                                              │ ringbuf
                    ┌───────────────────── 用户态 (Rust) ────────────────────────┐
                    │  memwrite loader (libbpf) ──▶ JSONL ──▶ BinaryRunner        │
                    │                                            │                │
                    │  PoisonAnalyzer                            ▼                │
                    │   ├─ ① 窗口匹配：15 条内建中英文签名（大小写不敏感）          │
                    │   └─ ② FS 补偿：窗口未命中则按 [offset, offset+count] 重读   │
                    │      （解决 SQLite 整页写入时毒 cell 落在页中部的盲区）        │
                    │                                            │                │
                    │  AlertSink（时间窗聚合，抑制告警风暴）       ▼                │
                    │   ├─▶ 企业微信机器人 webhook（markdown）                    │
                    │   ├─▶ ServerChan（Server 酱）                              │
                    │   └─▶ dry-run：仅落本地日志，不对外发送                      │
                    └───────────────────────────────────────────────────────────┘
```

**为什么需要 FS 补偿**：SQLite 以 4096 字节整页提交，毒 cell 常落在距页尾 643–1114 字节处，head/tail 各 128B 的窗口**永远抓不到**。因此 loader 额外输出写入文件的绝对路径与区间，analyzer 在窗口未命中时重读该区间，实现 100% 覆盖。

## 3. 核心能力

| 能力 | 说明 |
|---|---|
| 多记忆库监控 | `--memwrite-prefix "ehragent_memory,codex_memory"`，单探针实例 watch 最多 8 个前缀；告警聚合在一条链路，不被拆分 |
| 规则热加载 | `--poison-rules <FILE>` 外部签名文件（每行一条，`#` 注释），非空时**替换**内建 15 条签名，可按业务调优误报 |
| FS 补偿扫描 | 见上，覆盖整页写入盲区；读取上限 4 MiB，避免大文件拖慢链路 |
| 告警去重 | 时间窗（`--alert-interval`，默认 10s）内聚合为一条推送；命中签名越多，severity 越高（HIGH → CRITICAL） |
| 常驻部署 | systemd 服务模板 + env 配置，默认 `ALERT_DRY_RUN=1` 安全上线 |
| 上游兼容 | 作为 AgentSight 的叠加层（overlay）提供，不改动上游既有探针与流水线 |

## 4. 构建与部署

### 4.1 环境要求

| 项目 | 要求 |
|---|---|
| 操作系统 | Linux，内核 ≥ 5.8（需 BTF：`/sys/kernel/btf/vmlinux`，支持 CO-RE） |
| 权限 | root 或 `CAP_BPF` + `CAP_PERFMON` |
| 工具链 | clang/LLVM ≥ 12、libbpf、rustup（stable，实测 1.98） |
| 上游依赖 | [eunomia-bpf/agentsight](https://github.com/eunomia-bpf/agentsight) v1.0.31（CI 锁定 commit `bb99b66f8f98`） |

```bash
apt install clang-14 llvm-14 libelf-dev zlib1g-dev libssl-dev pkg-config
```

### 4.2 构建（叠加到 AgentSight）

本仓库 `overlay/` 目录下的文件**已按上游仓库的相对路径组织**，可直接整体覆盖到克隆的 AgentSight 源码树：

```bash
# 1. 获取上游源码并切到 CI 锁定的版本（含 BPF 子模块）
git clone --recurse-submodules https://github.com/eunomia-bpf/agentsight.git
cd agentsight && git checkout bb99b66f8f98

# 2. 叠加本仓库改动（保持相对路径一致，可直接 cp）
cp -R /path/to/memguard-agent/overlay/* ./

# 或使用提供的脚本（含落点校验，推荐）
/path/to/memguard-agent/scripts/apply-overlay.sh /path/to/agentsight

# 3. 编译上游探针与采集器
cd bpf && make          # 编译 sslsniff/process/stdiocap 等内置探针
cd ../collector && cargo build --release
```

> `memwrite.bpf.c` 是 MemGuard 新增的探针（不在上游 `bpf/Makefile` 的默认 `APPS` 内），
> 由 agent 通过 `--memwrite-path` 在运行时加载；如需随上游一并编译，将其加入 `bpf/Makefile` 的 `APPS` 后 `make memwrite`。
> `overlay/` 的目录结构严格对应 AgentSight 源码树（`bpf/`、`collector/src/`、`agentsight-capture/src/`、`ext/analysis/src/`、`deploy/systemd/`），因此 `cp -R overlay/* ./` 不会错位。如需逐项校验落点，见 `scripts/apply-overlay.sh`。

### 4.3 运行

```bash
./target/release/agentsight record \
  --memwrite \
  --memwrite-path /path/to/agentsight/bpf/memwrite \
  --memwrite-prefix "ehragent_memory,codex_memory" \
  --poison-rules /path/to/memguard-agent/examples/poison-rules.txt \
  -c python3 \
  --alert-wecom <WEBHOOK_KEY> \
  --alert-interval 10
```

> `record` 入口要求指定 attach 目标（`-c <comm>` / `-p <pid>`）。memwrite 探针本身按前缀 watch 全部进程，此处 attach 目标仅用于满足入口校验，服务脚本默认 `-c python3`。

**关键参数**

| 参数 | 说明 | 默认 |
|---|---|---|
| `--memwrite` | 启用记忆库写入探针 | - |
| `--memwrite-path` | 探针二进制路径（外部分发，避免每改必重编 collector） | - |
| `--memwrite-prefix` | 监控的文件名前缀，逗号分隔，最多 8 个 | `ehragent_memory` |
| `--poison-rules` | 外部签名文件路径 | 内建 15 条 |
| `--alert-wecom` / `--alert-serverchan` | 告警通道密钥 | - |
| `--alert-interval` | 告警聚合窗口（秒） | 10 |
| `--alert-dry-run` | 仅落本地日志，不实际推送 | - |

> **注意：前缀匹配的是文件名（`d_name`）而非目录。** 例如目录名为 `ehragent_memory/` 而文件名为 `ehr.db` **不会**被捕获；文件名以 `ehragent_memory` 开头（如 `ehragent_memory.db`）才会命中。

### 4.4 常驻服务

```bash
install -m 0644 overlay/deploy/systemd/memguard.env.example /etc/memguard.env   # 默认 dry_run=1
install -m 0755 overlay/deploy/systemd/run-memguard.sh      /opt/agentsight/run-memguard.sh
install -m 0644 overlay/deploy/systemd/memguard.service     /etc/systemd/system/memguard.service
systemctl daemon-reload && systemctl enable --now memguard
```

上线即 `dry-run`（只落 `/var/log/memguard.log`），确认链路无误后再切换生产：

```bash
vim /etc/memguard.env     # 填 WECOM_KEY 或 SERVERCHAN_KEY；ALERT_DRY_RUN=0
systemctl restart memguard
```

## 5. 验证记录

| 里程碑 | 内容 | 结果 |
|---|---|---|
| M1 | 探针加载与端到端检测闭环 | 单次运行捕获 109–150 条 `MEM_WRITE`，demo 投毒 7/7 命中 |
| M1 | 告警出口实链 | 企业微信 markdown POST、ServerChan GET 双通道经回显服务验证报文正确 |
| M2 | 多前缀监控 | `ehragent_memory.db` + `codex_memory.db` 同时监测，两者均检出 |
| M2 | 规则热加载 | 自定义规则命中；自定义规则下默认签名 0 命中（替换语义生效） |
| M3 | systemd 常驻 | 服务 `active`，投毒后日志检出 + dry-run 告警正常落盘 |

完整设计说明、实现细节与踩坑记录见 [`docs/design.md`](./docs/design.md)。

## 6. 目录结构

```
memguard-agent/
├── overlay/                    # 叠加到 AgentSight v1.0.31 的改动层（路径与上游一一对应）
│   ├── bpf/                    #   memwrite.bpf.c / .c / .h —— eBPF 探针内核态逻辑 + libbpf loader
│   ├── collector/src/          #   CLI 接线（main.rs / cmd_trace.rs）
│   ├── agentsight-capture/src/runners/  # BinaryRunner 构造器（common.rs）
│   ├── ext/analysis/src/analyzers/      # analyzer 注册（mod.rs）+ poison.rs（PoisonAnalyzer）+ alert_sink.rs（AlertSink）
│   └── deploy/systemd/         #   常驻服务三件套（memguard.service / .env.example / run-memguard.sh）
├── scripts/apply-overlay.sh   # 将 overlay/ 叠加到 AgentSight 的权威脚本（含落点校验）
├── docs/design.md              # 技术设计与实测记录
├── examples/poison-rules.txt   # 签名规则示例
├── LICENSE                     # Apache-2.0
├── CONTRIBUTING.md             # 贡献指南
├── SECURITY.md                 # 安全漏洞报告渠道
└── .gitignore
```

## 7. 路线图

- [x] M1 探针与检测闭环
- [x] M2 多前缀监控 + 规则热加载
- [x] M3 告警推送 + systemd 常驻
- [ ] 目录级记忆库监控（突破文件名前缀限制）
- [ ] 事件查询 CLI 与报表
- [ ] 告警规则分级与白名单机制
- [ ] 上游 PR 提交

## 8. 安全说明

- 本工具以 root 运行采集，请仅在**自有或已授权**的主机上启用。
- 容器内使用时需 `CAP_BPF` / `CAP_PERFMON` 能力及 BTF 挂载。
- 告警内容包含进程名、PID 与文件路径，请按需限制 webhook 可见范围。
- 漏洞报告请通过 [SECURITY.md](./SECURITY.md) 中的渠道提交，勿在公开 issue 中披露。

## 9. 许可证

[Apache License 2.0](./LICENSE)

本项目基于 [AgentSight](https://github.com/eunomia-bpf/agentsight) 的工程底座实现，特此致谢。
