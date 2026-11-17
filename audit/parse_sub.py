#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 v2.txt（base64 分享链接）为节点清单。"""
import base64
import json
import re
import sys
import urllib.parse as up


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def parse_uri(uri):
    uri = uri.strip()
    if not uri:
        return None
    if uri.startswith("vmess://"):
        try:
            j = json.loads(b64d(uri[8:]).decode("utf-8", "replace"))
        except Exception:
            return None
        return {
            "type": "vmess",
            "name": j.get("ps") or "",
            "server": str(j.get("add") or "").strip("[]"),
            "port": int(str(j.get("port") or 0) or 0),
        }
    m = re.match(r"^([a-z0-9+.-]+)://(.*)$", uri, re.I)
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = m.group(2)
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    name = up.unquote(frag)
    if scheme == "ssr":
        try:
            raw = b64d(rest).decode("utf-8", "replace")
            parts = raw.split(":")
            host, port = parts[0], int(parts[1])
        except Exception:
            return None
        return {"type": "ssr", "name": name, "server": host.strip("[]"), "port": port}
    if scheme == "ss":
        # ss://base64(method:pass)@host:port 或 全 base64
        if "@" not in rest:
            try:
                rest = b64d(rest).decode("utf-8", "replace")
            except Exception:
                return None
        hostport = rest.rsplit("@", 1)[-1]
        hostport = hostport.split("?")[0].split("/")[0]
        host, _, port = hostport.rpartition(":")
        try:
            port = int(port)
        except Exception:
            return None
        return {"type": "ss", "name": name, "server": host.strip("[]"), "port": port}
    # vless / trojan / hysteria2 / tuic / anytls
    hp = rest.split("?")[0].split("/")[0]
    if "@" in hp:
        hp = hp.rsplit("@", 1)[-1]
    host, _, port = hp.rpartition(":")
    try:
        port = int(port)
    except Exception:
        return None
    return {"type": scheme, "name": name, "server": host.strip("[]"), "port": port}


def main(path):
    raw = open(path, "rb").read()
    try:
        text = b64d(raw.decode("utf-8", "ignore")).decode("utf-8", "replace")
        if "://" not in text:
            raise ValueError
    except Exception:
        text = raw.decode("utf-8", "replace")
    lines = [l for l in text.splitlines() if "://" in l]
    nodes, bad = [], 0
    for l in lines:
        n = parse_uri(l)
        if n and n["server"] and n["port"]:
            nodes.append(n)
        else:
            bad += 1
    print(f"URIs={len(lines)} parsed={len(nodes)} unparsed={bad}")
    from collections import Counter
    print("types:", dict(Counter(n["type"] for n in nodes)))
    hosts = {}
    for n in nodes:
        hosts.setdefault(n["server"], []).append(n)
    print(f"unique servers={len(hosts)}")
    json.dump(nodes, open("nodes.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump({h: len(v) for h, v in hosts.items()},
              open("hosts.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "v2.txt")

