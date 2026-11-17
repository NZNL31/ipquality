#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐个 IP 调用 compat/ip_lookup，结果落 JSONL（可断点续跑）。"""
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

PY = sys.executable
LOOKUP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "compat", "ip_lookup")
OUT = "deep.jsonl"
LOG = "deep.log"
WORKERS = 20
TIMEOUT = 90

lock = threading.Lock()


def done_set():
    s = set()
    if os.path.exists(OUT):
        for line in open(OUT, encoding="utf-8"):
            try:
                s.add(json.loads(line)["ip"])
            except Exception:
                pass
    return s


def run_one(ip):
    t0 = time.time()
    try:
        p = subprocess.run([PY, LOOKUP, ip, "--json"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace",
                           timeout=TIMEOUT)
        raw = p.stdout.strip()
        data = json.loads(raw) if raw else {"ip": ip, "error": "empty"}
    except subprocess.TimeoutExpired:
        data = {"ip": ip, "error": "timeout"}
    except Exception as exc:
        data = {"ip": ip, "error": str(exc)[:200]}
    data["_elapsed"] = round(time.time() - t0, 1)
    with lock:
        with open(OUT, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(data, ensure_ascii=False) + "\n")
        with open(LOG, "a", encoding="utf-8") as fh:
            sc = (data.get("score") or {}).get("score")
            fh.write("%s\t%s\t%s\t%.1fs\n" % (ip, sc, data.get("error", ""), data["_elapsed"]))
    return ip


def main():
    ips = json.load(open("targets.json", encoding="utf-8"))
    seen = done_set()
    todo = [ip for ip in ips if ip not in seen]
    print(f"total={len(ips)} done={len(seen)} todo={len(todo)}", flush=True)
    t0 = time.time()
    n = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for ip in pool.map(run_one, todo):
            n += 1
            if n % 20 == 0:
                el = time.time() - t0
                print(f"  {n}/{len(todo)}  {el:.0f}s  eta {el/n*(len(todo)-n):.0f}s",
                      flush=True)


if __name__ == "__main__":
    main()


