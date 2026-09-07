#!/usr/bin/env bash
#
# apply-overlay.sh — 将 MemGuard 的 overlay/ 改动层叠加到已克隆的 AgentSight 源码树。
#
# 用法:
#   scripts/apply-overlay.sh <AGENTSIGHT_SRC_DIR>
#
# 约定:
#   - 目标目录须为 eunomia-bpf/agentsight 的源码根（建议与 CI 中 AGENTSIGHT_REF 锁定的版本一致）。
#   - overlay/ 内的相对路径与上游一一对应，本脚本逐文件复制并打印落点，便于人工复核。
#   - 默认 dry-run（仅打印），加 --apply 才真正写入。
#
set -euo pipefail

OVERLAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/overlay"

if [[ $# -lt 1 ]]; then
  echo "用法: $0 <AGENTSIGHT_SRC_DIR> [--apply]" >&2
  exit 1
fi

TARGET="$1"
APPLY=0
[[ "${2:-}" == "--apply" ]] && APPLY=1

if [[ ! -d "$TARGET" ]]; then
  echo "错误: 目标目录不存在: $TARGET" >&2
  exit 2
fi

# src(相对 overlay/) -> dst(相对 AGENTSIGHT 源码根)
MAP=(
  "bpf/memwrite.bpf.c:bpf/memwrite.bpf.c"
  "bpf/memwrite.c:bpf/memwrite.c"
  "bpf/memwrite.h:bpf/memwrite.h"
  "collector/src/cmd_trace.rs:collector/src/cmd_trace.rs"
  "collector/src/main.rs:collector/src/main.rs"
  "agentsight-capture/src/runners/common.rs:agentsight-capture/src/runners/common.rs"
  "ext/analysis/src/analyzers/mod.rs:ext/analysis/src/analyzers/mod.rs"
  "ext/analysis/src/analyzers/poison.rs:ext/analysis/src/analyzers/poison.rs"
  "ext/analysis/src/analyzers/alert_sink.rs:ext/analysis/src/analyzers/alert_sink.rs"
  "deploy/systemd/memguard.service:deploy/systemd/memguard.service"
  "deploy/systemd/memguard.env.example:deploy/systemd/memguard.env.example"
  "deploy/systemd/run-memguard.sh:deploy/systemd/run-memguard.sh"
)

echo "== MemGuard overlay -> $TARGET =="
if [[ $APPLY -eq 0 ]]; then
  echo "   [dry-run] 以下文件将被复制（加 --apply 执行）:"
fi

rc=0
for entry in "${MAP[@]}"; do
  src="${entry%%:*}"; dst="${entry##*:}"
  srcp="$OVERLAY_DIR/$src"
  dstp="$TARGET/$dst"
  if [[ ! -f "$srcp" ]]; then
    echo "   [缺失] $src (overlay 中找不到)" >&2
    rc=3
    continue
  fi
  if [[ $APPLY -eq 1 ]]; then
    mkdir -p "$(dirname "$dstp")"
    cp -f "$srcp" "$dstp"
    echo "   [ok]   $src -> $dst"
  else
    echo "   [copy] $src -> $dst"
  fi
done

if [[ $APPLY -eq 0 ]]; then
  echo
  echo "确认无误后执行: $0 $TARGET --apply"
fi
exit $rc
