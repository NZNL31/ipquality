#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""汇总节点、可达性、IP 深度检测结果，产出全量报告与优选 50 报告。"""
import ipaddress
import json
import os
import statistics
from collections import Counter, defaultdict

PROTO_W = {"vless": 1.0, "trojan": 0.95, "vmess": 0.9, "hysteria2": 0.85,
           "tuic": 0.85, "ss": 0.6, "ssr": 0.5}
UDP = {"hysteria2", "tuic", "wireguard", "hysteria"}


def load_jsonl(path):
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        try:
            r = json.loads(line)
        except Exception:
            continue
        out[r["ip"]] = r
    return out


def lat_score(ms):
    if ms is None:
        return 0.0
    return max(0.0, min(100.0, 100.0 - ms / 5.0))


def main():
    nodes = json.load(open("nodes.json", encoding="utf-8"))
    resolved = json.load(open("resolved.json", encoding="utf-8"))
    meta = json.load(open("ipmeta.json", encoding="utf-8"))
    reach = {f'{r["name"]}|{r["server"]}|{r["port"]}': r
             for r in json.load(open("reach.json", encoding="utf-8"))}
    deep = load_jsonl("deep.jsonl")

    rows = []
    for n in nodes:
        ips = (resolved.get(n["server"]) or {}).get("ips") or []
        ip = ips[0] if ips else None
        key = f'{n["name"]}|{n["server"]}|{n["port"]}'
        rr = reach.get(key) or {}
        d = deep.get(ip) or {}
        sc = d.get("score") or {}
        m = meta.get(ip) or {}
        dnsbl = d.get("dnsbl") or {}
        hits = dnsbl.get("hits") or []
        blocks_hit = [b["name"] for b in (d.get("blocks") or [])
                      if b.get("state") == "hit"]
        vt = next((i for i in (d.get("intel") or []) if i.get("name") == "VirusTotal"), {})
        ab = next((s for s in (d.get("sources") or []) if s.get("name") == "AbuseIPDB"), {})
        pf = (d.get("platforms") or {}).get("platforms") or []
        passed = sum(1 for p in pf if p.get("verdict") in ("通过", "观察"))
        rows.append({
            "name": n["name"], "type": n["type"], "server": n["server"],
            "port": n["port"], "ip": ip, "country": m.get("countryCode"),
            "city": m.get("city"), "asn": m.get("as"), "org": m.get("org") or m.get("isp"),
            "hosting": m.get("hosting"), "proxy_flag": m.get("proxy"),
            "mobile": m.get("mobile"), "tcp_ms": rr.get("tcp_ms"),
            "ip_score": sc.get("score"), "grade": sc.get("grade"),
            "grade_cn": sc.get("grade_cn"),
            # 工具内部把 sev(匿名代理)>=0.95 标成「Tor 出口」，实际含义是「几乎所有库都判代理」
            "nature": {"Tor 出口": "强代理特征"}.get(sc.get("nature"), sc.get("nature")),
            "verdict": sc.get("verdict"), "confidence": sc.get("confidence"),
            "dnsbl_black": dnsbl.get("blacklisted"), "dnsbl_total": dnsbl.get("total"),
            "dnsbl_hits": [h.get("zone") for h in hits
                           if h.get("verdict") == "blacklisted"][:4],
            "blocks_hit": blocks_hit, "vt": vt.get("note"),
            "abuse": ab.get("score"), "platforms_pass": f"{passed}/{len(pf)}" if pf else "",
            "report_path": d.get("ip") and "—",
        })
    json.dump(rows, open("rows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    have = [r for r in rows if r["ip_score"] is not None]
    print(f"nodes={len(rows)} with_deep={len(have)} reachable={sum(1 for r in rows if r['tcp_ms'])}")
    print("grade dist", Counter(r["grade"] for r in have).most_common())


if __name__ == "__main__":
    main()


