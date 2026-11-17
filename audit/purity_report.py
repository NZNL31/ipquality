#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""纯纯净度排名（不依赖本机网络）：只按 ipquality 的 IP 评分排序，不做 TCP 探测。"""
import ipaddress
import json
from collections import Counter

CAP_IP, CAP_NET, CAP_ASN = 1, 3, 4
CDN_ASN = ("AS13335", "AS209242", "AS20940", "AS54113", "AS19551",
           "AS60068", "AS199524", "AS200325")


def net24(ip):
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return ip


def main():
    rows = json.load(open("rows.json", encoding="utf-8"))
    for r in rows:
        r["cdn"] = any((r["asn"] or "").startswith(a) for a in CDN_ASN)
    pool = [r for r in rows if r["ip_score"] is not None]
    pool.sort(key=lambda r: (-r["ip_score"], -(r["confidence"] or 0), r["dnsbl_black"] or 0))

    picked, per_ip, per_net, per_asn = [], Counter(), Counter(), Counter()
    for r in pool:
        if per_ip[r["ip"]] >= CAP_IP or per_net[net24(r["ip"])] >= CAP_NET:
            continue
        asn = (r["asn"] or "")[:12]
        if per_asn[asn] >= CAP_ASN:
            continue
        picked.append(r)
        per_ip[r["ip"]] += 1
        per_net[net24(r["ip"])] += 1
        per_asn[asn] += 1
        if len(picked) == 50:
            break
    for i, r in enumerate(picked, 1):
        r["rank"] = i

    L = []
    A = L.append
    A("# 优选 50 节点 —— 纯纯净度版（不依赖本机网络）\n")
    A("## 排序口径\n")
    A("只按 `ipquality` 的 IP 质量评分排序：恶意与滥用 25 + 匿名代理 25 + 基础设施 18 + "
      "主动行为 14 + 黑名单 12 + 邮件信誉 6。**没有做任何本机 TCP 探测、不看延迟**，"
      "所以结果在任何一台机器上跑都一样（第三方库的判定不随你的出口 IP 改变）。")
    A("")
    A("同分时依次比：置信度（数据源覆盖度）→ DNSBL 命中数（越少越前）。"
      f"去重：同一 IP 取 1 个、同一 /24 最多 {CAP_NET} 个、同一 ASN 最多 {CAP_ASN} 个。")
    A("")
    A(f"参评 {len(pool)} 个节点（有评分的全部节点，含本机连不上的）→ 选出 {len(picked)} 个。\n")
    A("## 清单\n")
    A("| # | 节点 | 协议 | 服务器:端口 | IP | 入口 | 国家 | 评分 | 等级 | 性质 | DNSBL | 置信度 |")
    A("|---:|---|---|---|---|---|---|---|---:|---|---|---:|---:|")
    for r in picked:
        name = (r["name"] or "").strip()[:26].replace("|", "/") or "（无名）"
        A(f"| {r['rank']} | {name} | {r['type']} | {r['server']}:{r['port']} | {r['ip']} | "
          f"{'CDN' if r['cdn'] else '直连'} | {r['country']} | {r['ip_score']} | {r['grade']} | "
          f"{r['nature'] or '—'} | {r['dnsbl_black'] or 0} | {r['confidence'] or '—'}% |")
    A("")
    A("## 读这份表要注意\n")
    A("1. **纯净度 ≠ 能连**。这里没有可用性门槛，排名靠前的节点完全可能在你这边连不上"
      "（比如只对特定地区开放、或已经死掉）。要「能连 + 干净」请看《report-top50.md》。")
    A("2. 评分里「基础设施属性」对机房段固定扣 18 分，所以住宅/移动出口的 IP 天生占优；"
      "这类节点往往是别人家的落地机，长期稳定性不如正规机场。")
    A("3. CDN 前置节点（入口列标 CDN）测的是 Cloudflare/Akamai 边缘 IP，"
      "分数反映的是 CDN 而不是落地服务器，参考价值有限。")
    A("4. VirusTotal（4 次/分）和 IPQS（35 次/天）免费额度很小，检测到后段时这两个源会缺失，"
      "只降低置信度、不臆造结论——置信度列就是给这个用的。")
    open("out/report-purity-top50.md", "w", encoding="utf-8").write("\n".join(L))
    print("picked", len(picked), Counter(r["grade"] for r in picked))


if __name__ == "__main__":
    main()



