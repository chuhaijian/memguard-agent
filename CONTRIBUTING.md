# 贡献指南 / Contributing

感谢你关注 MemGuard。以下内容帮助你的改动更快被合并。

## 开发流程

1. **Fork 本仓库**并创建特性分支（`feat/xxx`、`fix/xxx`）。
2. **本地检查**：Rust 改动请先通过 `cargo check -p agentsight-analysis` 与 `cargo check -p agentsight`
   （`agentsight-capture-core` 的 build.rs 条件编译会跳过 BPF 部分，非 Linux 环境亦可运行）。
3. **端到端验收**：eBPF 与 CLI 改动必须在 Linux 构建机上完成实测，至少覆盖以下三个用例：
   - 多前缀监控：两个不同前缀的文件均被检出
   - 自定义规则：外部签名文件命中
   - 替换语义：自定义规则生效时，默认签名不命中
4. **提交 PR**：说明改动动机、影响面与验证结果。

## 代码约定

| 层面 | 约定 |
|---|---|
| eBPF C | 保持 BPF verifier 友好：**优先常量长度读取**，避免在变长路径上做掩码或 ternary；新增循环需 `#pragma unroll` |
| Rust | 遵循 `cargo fmt` 与 `cargo clippy` 默认告警；Analyzer 为 stream 变换，无命中事件须原样透传 |
| 注释与文档 | 代码注释用英文，设计与运维文档用中文；新增特性请同步更新 `README.md` 与 `docs/design.md` |
| 提交信息 | 中文或英文均可，需一句话说明"改了什么 / 为什么" |

## 已知约束（改动前请务必阅读）

- **前缀匹配的是文件名（`d_name`）而非目录路径**，这是探针在内核态做过滤的既有语义，改动需评估兼容性。
- `agentsight record` 强制要求 attach 目标（`-c` / `-p`），纯探针模式也需传入。
- 探针为独立二进制，通过 `--memwrite-path` 外部分发；请勿改为 `include_bytes!` 内嵌，否则每次探针迭代都要重编 collector。
- clap 参数名由字段名自动生成，新增参数请显式 `#[arg(long = "...")]` 并检查与调用方一致——**这类运行时语义问题 `cargo check` 无法发现**。

## 行为准则

请保持技术讨论聚焦、互相尊重。恶意或无关内容将被关闭。
