#!/usr/bin/env bash
# MemGuard 常驻服务启动脚本: 按 /etc/memguard.env 构造 agentsight record 命令。
# 供 systemd memguard.service 调用(以 root 运行, 需要 BPF 权限)。
set -u

ENV_FILE="${MEMGUARD_ENV_FILE:-/etc/memguard.env}"
BIN=/opt/agentsight/collector/target/release/agentsight
PROBE=/opt/agentsight/bpf/memwrite
PREFIX_DEFAULT=ehragent_memory
INTERVAL_DEFAULT=10

[ -f "$ENV_FILE" ] && . "$ENV_FILE" || true

PREFIX="${MEMWRITE_PREFIX:-$PREFIX_DEFAULT}"
INTERVAL="${ALERT_INTERVAL:-$INTERVAL_DEFAULT}"
# record 入口要求一个 attach 目标; memwrite 探针自身按前缀独立 watch 全部进程,
# 这里 attach 记忆库侧常见 comm(默认 python3), env 可覆盖。
ATTACH_COMM="${ATTACH_COMM:-python3}"

ARGS=(record
  --no-server
  --memwrite
  --memwrite-path "$PROBE"
  --memwrite-prefix "$PREFIX"
  -c "$ATTACH_COMM"
  --alert-interval "$INTERVAL"
)

# 告警通道: 至少一个有效配置才附加 AlertSink?
# 注意: AlertSink 在 collector 里按配置条件创建, 全空时 chain 不挂 sink。
if [ -n "${WECOM_KEY:-}" ]; then
  ARGS+=(--alert-wecom "$WECOM_KEY")
fi
if [ -n "${SERVERCHAN_KEY:-}" ]; then
  ARGS+=(--alert-serverchan "$SERVERCHAN_KEY")
fi
if [ -n "${ALERT_BASE:-}" ]; then
  ARGS+=(--alert-base "$ALERT_BASE")
fi
if [ "${ALERT_DRY_RUN:-0}" = "1" ]; then
  ARGS+=(--alert-dry-run)
fi

export PATH=/usr/local/bin:/usr/bin:/bin
exec "$BIN" "${ARGS[@]}"