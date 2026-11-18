#!/usr/bin/env bash
# ============================================================
#  run-purity.sh —— Linux / 服务器版：只做纯净度，不探测节点
#
#  与 run-purity.cmd 等价，供没有 cmd.exe 的环境使用（VPS、容器、CI）：
#    curl 订阅 → parse_sub → stage1（解析+归属）→ batch（逐个 IP 打分，可断点续跑）
#    → collect → purity_report（出前 50 榜单）
#
#  用法：
#    SUB_URL=https://example.com/sub.txt ./audit/run-purity.sh
#    SUB_URL=... TOP=30 ./audit/run-purity.sh
#
#  如果 audit/ 里已经有 v2.txt，会直接复用、不再下载。
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${IPQ_PYTHON:-$(command -v python3 || command -v python)}"
[ -n "$PY" ] || { echo "[error] 找不到 python3，可用 IPQ_PYTHON 指定" >&2; exit 1; }
export PYTHONIOENCODING=utf-8 PYTHONUTF8=1

step() { printf '\n=== %s ===\n' "$*"; }

step "1/5 取订阅"
if [ -n "${SUB_URL:-}" ]; then
  curl -fsSL --retry 3 -o v2.txt "$SUB_URL" || echo "[warn] 下载失败，回退用已有 v2.txt"
elif [ -f v2.txt ]; then
  echo "[skip] 已存在 v2.txt"
else
  echo "[error] 没有 SUB_URL，也没有 v2.txt" >&2
  exit 1
fi

step "2/5 解析节点"
"$PY" parse_sub.py v2.txt

step "3/5 解析域名 + 归属"
"$PY" stage1.py

step "4/5 逐个 IP 打分（中断可续跑）"
"$PY" batch.py

step "5/5 汇总 + 纯净度排名"
"$PY" collect.py
"$PY" purity_report.py

echo
echo "完成：out/report-purity-top${TOP:-50}.md"
