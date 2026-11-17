#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阶段一：解析域名为 IP，并用 ip-api 批量接口取基础归属/类型元数据。"""
import ipaddress
import json
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

FIELDS = ("status,message,country,countryCode,regionName,city,isp,org,as,asname,"
          "reverse,mobile,proxy,hosting,query")


def resolve(host):
    try:
        ipaddress.ip_address(host)
        return host, [host], None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = []
        for fam, _, _, _, sock in infos:
            ip = sock[0]
            if ip not in ips:
                ips.append(ip)
        return host, ips, None
    except Exception as exc:
        return host, [], str(exc)


def main():
    nodes = json.load(open("nodes.json", encoding="utf-8"))
    hosts = sorted({n["server"] for n in nodes})
    print(f"servers={len(hosts)}")
    t0 = time.time()
    resolved = {}
    with ThreadPoolExecutor(max_workers=64) as pool:
        for host, ips, err in pool.map(resolve, hosts):
            resolved[host] = {"ips": ips, "error": err}
    ok = sum(1 for v in resolved.values() if v["ips"])
    print(f"resolved {ok}/{len(hosts)} in {time.time()-t0:.1f}s")

    ips = []
    for v in resolved.values():
        for ip in v["ips"]:
            try:
                a = ipaddress.ip_address(ip)
                if a.is_global and ip not in ips:
                    ips.append(ip)
            except ValueError:
                pass
    print(f"unique global IPs={len(ips)}")
    json.dump(resolved, open("resolved.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    meta = {}
    batches = [ips[i:i + 100] for i in range(0, len(ips), 100)]
    for i, batch in enumerate(batches, 1):
        body = json.dumps(batch).encode()
        req = urllib.request.Request(
            f"http://ip-api.com/batch?fields={FIELDS}", data=body,
            headers={"Content-Type": "application/json"})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = json.loads(r.read().decode())
                break
            except Exception as exc:
                print(f"  batch {i} attempt {attempt+1} failed: {exc}")
                time.sleep(3)
                data = []
        for item in data:
            q = item.get("query")
            if q:
                meta[q] = item
        print(f"  batch {i}/{len(batches)} -> {len(meta)} total")
        if i < len(batches):
            time.sleep(4.5)  # 15 请求/分钟
    json.dump(meta, open("ipmeta.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    targets = [ip for ip, v in meta.items() if v.get("status") == "success"]
    json.dump(targets, open("targets.json", "w", encoding="utf-8"))
    print("done", len(meta), "targets", len(targets))


if __name__ == "__main__":
    main()

