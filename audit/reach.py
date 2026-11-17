#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""节点级 TCP 可达性 + 延迟（从本机出发），用于筛掉死节点。"""
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 4.0


def probe(node):
    host, port = node["server"], node["port"]
    ips = node.get("_ips") or [host]
    best = None
    for ip in ips:
        t0 = time.time()
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT):
                ms = (time.time() - t0) * 1000
                if best is None or ms < best:
                    best = ms
        except Exception:
            continue
    return {**{k: node[k] for k in ("name", "type", "server", "port")},
            "ip": ips[0] if ips else host, "tcp_ms": round(best, 1) if best else None}


def main():
    nodes = json.load(open("nodes.json", encoding="utf-8"))
    resolved = json.load(open("resolved.json", encoding="utf-8"))
    for n in nodes:
        n["_ips"] = (resolved.get(n["server"]) or {}).get("ips") or [n["server"]]
    t0 = time.time()
    out = []
    with ThreadPoolExecutor(max_workers=96) as pool:
        for i, r in enumerate(pool.map(probe, nodes), 1):
            out.append(r)
            if i % 200 == 0:
                print(f"  {i}/{len(nodes)} {time.time()-t0:.0f}s", flush=True)
    json.dump(out, open("reach.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    ok = sum(1 for r in out if r["tcp_ms"])
    print(f"reachable {ok}/{len(out)}")


if __name__ == "__main__":
    main()

