#!/usr/bin/env bash
# IPQuality 一键运行（Windows / Git Bash 环境）
# 用法:
#   ./run.sh            # 双栈检测
#   ./run.sh -4         # 仅 IPv4
#   ./run.sh -6         # 仅 IPv6
#   ./run.sh -4 -o out.ansi   # 输出报告到文件（文件必须不存在）
#
# 说明:
#   1) 必须清除 HTTP 代理变量：沙箱代理只有 IPv4 出口，会导致 curl -6 失败
#   2) compat/ 目录提供 dig / nc / bc / ss / jq 的兼容实现
#   3) -n 跳过依赖检测与安装（依赖已由 compat 提供）

# 纯 bash 取脚本目录，不依赖外部 dirname（部分 bash 发行版 PATH 里没有 coreutils）
here=${0%/*}
[ "$here" = "$0" ] && here=.
cd "$here" || exit 1

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
export PATH="$PWD/compat:$PATH"
export TERM=xterm-256color

# 挑一个装了 dnspython 的 python（本机有多个 python，默认那个可能没有依赖）
pick_python(){
  local c
  if [ -n "${IPQ_PYTHON:-}" ]; then echo "$IPQ_PYTHON"; return; fi
  for c in python python3 py; do
    if command -v "$c" >/dev/null 2>&1; then
      if "$c" -c "import dns.resolver" >/dev/null 2>&1; then echo "$c"; return; fi
    fi
  done
  echo python
}

# 传 IP 时自动转去查该 IP：ip.sh 只能测本机出口，没有"指定 IP"的能力
if [[ "${1:-}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "${1:-}" == *:* ]]; then
  exec "$(pick_python)" compat/ip_lookup "$@"
fi

bash ip.sh -n "$@"
