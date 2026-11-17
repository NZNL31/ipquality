#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把优选出的节点从 repo-node/clash.yaml 里抽出来，生成可直接导入的 Clash 配置。"""
import json
import os
import sys

import yaml

if len(sys.argv) > 1:
    SRC = sys.argv[1]
elif os.path.exists("clash-source.yaml"):
    SRC = "clash-source.yaml"
else:
    SRC = r"..\repo-node\clash.yaml"
OUT = "out/top50.yaml"


def main():
    picked = json.load(open("out/summary.json", encoding="utf-8"))["picked"]
    doc = yaml.safe_load(open(SRC, encoding="utf-8"))
    index = {}
    by_host = {}
    for p in doc.get("proxies") or []:
        index.setdefault(p.get("name"), p)
        by_host.setdefault((p.get("server"), p.get("port")), p)

    proxies, miss = [], []
    for r in picked:
        p = index.get(r["name"]) if r["name"] else None
        if p is None:
            p = by_host.get((r["server"], r["port"]))
        if p:
            proxies.append(p)
        else:
            miss.append(r["name"])

    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["223.5.5.5", "119.29.29.29"],
            "fallback": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
        },
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 优选", "type": "url-test", "proxies": [p["name"] for p in proxies],
             "url": "http://www.gstatic.com/generate_204", "interval": 300,
             "tolerance": 50, "lazy": True},
            {"name": "🌐 手动", "type": "select", "proxies": ["🚀 优选"] + [p["name"] for p in proxies]},
        ],
        "rules": [
            "GEOIP,LAN,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 优选",
        ],
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, allow_unicode=True, sort_keys=False, width=4096)
    print(f"exported {len(proxies)} proxies -> {OUT}; missing {len(miss)}")
    if miss:
        print("missing:", miss[:5])


if __name__ == "__main__":
    sys.exit(main())

