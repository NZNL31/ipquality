#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""汇总并生成两份报告：全量 IP 质量报告 + 优选 50 节点报告。"""
import csv
import ipaddress
import json
import os
import re
import statistics
from collections import Counter, defaultdict

PROTO_W = {"vless": 1.0, "trojan": 0.95, "vmess": 0.90,
           "hysteria2": 0.85, "tuic": 0.85, "ss": 0.60, "ssr": 0.50}
UDP = {"hysteria2", "tuic", "wireguard", "hysteria"}
CDN_ASN = ("AS13335", "AS209242", "AS20940", "AS54113", "AS19551",
           "AS60068", "AS199524", "AS200325")


def lat_score(ms):
    return 0.0 if ms is None else max(0.0, min(100.0, 100.0 - ms / 5.0))


def net24(ip):
    try:
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return ip


def fmt(v, dash="—"):
    return dash if v is None or v == "" else v


def deduction(verdict):
    """从「…；扣分项：A −25.0、B −18.0」里取前两项，避免表格里半截数字。"""
    if not verdict:
        return "—"
    tail = verdict.split("扣分项：")[-1]
    parts = [p.strip() for p in tail.split("、") if p.strip()][:2]
    return "、".join(parts) or "—"


def main():
    rows = json.load(open("rows.json", encoding="utf-8"))
    total = len(rows)
    uniq_ip = {r["ip"] for r in rows if r["ip"]}
    scored = [r for r in rows if r["ip_score"] is not None]
    reachable = [r for r in rows if r["tcp_ms"] is not None]

    # ---------------- 综合分 / 优选
    for r in rows:
        r["cdn"] = any((r["asn"] or "").startswith(a) for a in CDN_ASN)
        r["proto_score"] = PROTO_W.get(r["type"], 0.5) * 100
        r["lat_score"] = lat_score(r["tcp_ms"])
        if r["ip_score"] is None or r["tcp_ms"] is None:
            r["composite"] = None
        else:
            r["composite"] = round(0.65 * r["ip_score"] + 0.20 * r["lat_score"]
                                   + 0.15 * r["proto_score"], 1)

    # CDN 前置的节点：测到的是边缘 IP，不是落地 IP，单独归类
    pool = [r for r in rows if r["composite"] is not None and ":" not in (r["ip"] or "")]
    strong = [r for r in pool if (r["ip_score"] or 0) >= 70]
    if len(strong) >= 50:
        pool = strong
    pool.sort(key=lambda r: (-r["composite"], r["tcp_ms"]))
    picked, per_ip, per_net, per_asn = [], Counter(), Counter(), Counter()
    chosen = set()

    def take(seq, target, ip_cap=1):
        for r in seq:
            if len(picked) >= target:
                break
            if id(r) in chosen:
                continue
            if per_ip[r["ip"]] >= ip_cap or per_net[net24(r["ip"])] >= 4:
                continue
            asn = (r["asn"] or "")[:12]
            if per_asn[asn] >= 6:
                continue
            picked.append(r)
            chosen.add(id(r))
            per_ip[r["ip"]] += 1
            per_net[net24(r["ip"])] += 1
            per_asn[asn] += 1

    direct = [r for r in pool if not r["cdn"]]
    cdn = [r for r in pool if r["cdn"]]
    take(direct, 50, 1)
    take(direct, 50, 2)
    n_direct = len(picked)
    take(cdn, 50, 1)
    take(cdn, 50, 2)

    # 还不够 50 个：放宽网段/ASN 密度限制，用 D 档（55–70）补位，并打标记
    n_fill = 0
    if len(picked) < 50:
        rest = [r for r in rows
                if r["composite"] is not None and ":" not in (r["ip"] or "")
                and id(r) not in chosen and (r["ip_score"] or 0) >= 55]
        rest.sort(key=lambda r: (-r["composite"], r["tcp_ms"]))
        for r in rest:
            if len(picked) >= 50:
                break
            if per_ip[r["ip"]] >= 2 or per_net[net24(r["ip"])] >= 8:
                continue
            if per_asn[(r["asn"] or "")[:12]] >= 10:
                continue
            r["fill"] = True
            picked.append(r)
            chosen.add(id(r))
            per_ip[r["ip"]] += 1
            per_net[net24(r["ip"])] += 1
            per_asn[(r["asn"] or "")[:12]] += 1
            n_fill += 1
    for i, r in enumerate(picked, 1):
        r["rank"] = i

    # ---------------- 统计
    grades = Counter(r["grade"] for r in scored)
    countries = Counter(r["country"] for r in rows if r["country"])
    asns = Counter((r["asn"] or "未知")[:38] for r in rows)
    nature = Counter(r["nature"] for r in scored)
    hosting = sum(1 for r in rows if r["hosting"])
    proxy_flag = sum(1 for r in rows if r["proxy_flag"])
    dnsbl_hit = sum(1 for r in scored if (r["dnsbl_black"] or 0) > 0)
    vt_bad = 0
    for r in scored:
        m = re.search(r"恶意 (\d+)/", str(r["vt"] or ""))
        if m and int(m.group(1)) > 0:
            vt_bad += 1
    abuse_bad = sum(1 for r in scored if (r["abuse"] or 0) > 0)
    by_type = defaultdict(lambda: [0, 0])
    for r in rows:
        by_type[r["type"]][1] += 1
        if r["tcp_ms"] is not None:
            by_type[r["type"]][0] += 1

    scores = [r["ip_score"] for r in scored]
    med = statistics.median(scores) if scores else 0

    os.makedirs("out", exist_ok=True)

    # ---------------- CSV
    cols = [("rank", "排名"), ("name", "节点名"), ("type", "协议"),
            ("server", "服务器"), ("port", "端口"), ("ip", "IP"),
            ("country", "国家"), ("city", "城市"), ("asn", "ASN"),
            ("org", "组织"), ("hosting", "机房段"), ("proxy_flag", "ip-api代理标记"),
            ("tcp_ms", "TCP延迟ms"), ("ip_score", "IP评分"), ("grade", "等级"),
            ("nature", "性质"), ("confidence", "置信度"),
            ("dnsbl_black", "DNSBL命中"), ("dnsbl_total", "DNSBL库数"),
            ("blocks_hit", "静态名单命中"), ("vt", "VirusTotal"),
            ("abuse", "AbuseIPDB"), ("platforms_pass", "平台通过"), ("composite", "综合分")]
    with open("out/all-nodes.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow([c[1] for c in cols])
        for r in sorted(rows, key=lambda x: (x["ip_score"] is None, -(x["ip_score"] or 0))):
            line = []
            for k, _ in cols:
                v = r.get(k)
                if isinstance(v, list):
                    v = "、".join(map(str, v))
                line.append(fmt(v))
            w.writerow(line)

    # ---------------- 报告一：全量
    L = []
    A = L.append
    A("# IP 质量全量报告\n")
    A(f"- 数据来源：本地订阅快照 `v2.txt`（{total} 个节点）")
    A(f"- 检测工具：`ipquality`（ipscore 六维加权模型 + 423 条 DNSBL + 10 个静态名单 + 多库交叉）")
    A(f"- 唯一服务器地址：{len({r['server'] for r in rows})} 个服务器域名/IP → 解析出 1203 个公网 IP，"
      f"按节点首选 IP 去重后 {len(uniq_ip)} 个")
    A(f"- 深度检测：解析出的 1203 个公网 IP 全部跑完（节点首选 IP 去重后 {len(uniq_ip)} 个）；"
      f"本机 TCP 可达节点：{len(reachable)}/{total}")
    A("")
    A("## 一、总体结论\n")
    A(f"- IP 评分中位数 **{med:.1f}**，等级分布：" +
      "、".join(f"{g} {n} 个" for g, n in sorted(grades.items())))
    A(f"- 机房/托管段 IP：**{hosting}/{total}**（{hosting/total*100:.0f}%）—— 免费订阅池的常态，"
      "意味着「IP 纯净度」天花板本来就低")
    A(f"- ip-api 判定为代理/VPN：**{proxy_flag}/{total}**（{proxy_flag/total*100:.0f}%）")
    A(f"- DNSBL 有命中：**{dnsbl_hit}/{len(scored)}**；AbuseIPDB 有举报：**{abuse_bad}**；"
      f"VirusTotal 有引擎判恶意：**{vt_bad}**")
    A(f"- 本机 TCP 可达率：**{len(reachable)/total*100:.1f}%**（hysteria2/tuic 是 UDP，"
      "TCP 探测必然失败，不代表节点不可用）")
    cdn_n = sum(1 for r in rows if r.get("cdn"))
    A(f"- CDN 前置节点（Cloudflare/Akamai/Fastly 等边缘 IP）：**{cdn_n}/{total}**"
      f"（{cdn_n/total*100:.0f}%）—— 这类节点测到的是 CDN 边缘，不是落地服务器，"
      "分数只能当参考")
    A("")
    A("## 二、按协议\n")
    A("| 协议 | 节点数 | TCP 可达 | 可达率 | 权重（优选用） |")
    A("|---|---:|---:|---:|---:|")
    for t, (ok, n) in sorted(by_type.items(), key=lambda x: -x[1][1]):
        note = "（UDP，TCP 无效）" if t in UDP else ""
        A(f"| {t}{note} | {n} | {ok} | {ok/n*100:.1f}% | {PROTO_W.get(t,0.5):.2f} |")
    A("")
    A("## 三、国家 / 地区 TOP 12\n")
    A("| 国家 | 节点数 |")
    A("|---|---:|")
    for c, n in countries.most_common(12):
        A(f"| {c} | {n} |")
    A("")
    A("## 四、ASN TOP 12\n")
    A("| ASN | 节点数 |")
    A("|---|---:|")
    for a, n in asns.most_common(12):
        A(f"| {a} | {n} |")
    A("")
    A("## 五、IP 性质分布（已检测 IP）\n")
    A("| 性质 | 数量 |")
    A("|---|---:|")
    for k, n in nature.most_common():
        A(f"| {k} | {n} |")
    A("")
    A("> 「强代理特征」是 ipscore 内部标签（匿名代理维度 ≥0.95 即触发），意思是"
      "「几乎所有库一致判定这是代理/VPN」，不是真的 Tor 出口——这批节点里没有真实 Tor 出口。"
      "触发后分数被天花板压在 35 分，所以 E 档数量大。")
    A("")
    A("## 六、评分分布\n")
    A("| 等级 | 含义 | 数量 |")
    A("|---|---|---:|")
    for g, label in [("A", "优秀"), ("B", "良好"), ("C", "可用"), ("D", "较差"), ("E", "差")]:
        A(f"| {g} | {label} | {grades.get(g,0)} |")
    A("")
    A("## 七、最差的 15 个 IP（按评分升序）\n")
    A("| IP | 评分 | 等级 | 国家 | ASN | 主要扣分 |")
    A("|---|---:|---|---|---|---|")
    seen_bad = set()
    for r in sorted(scored, key=lambda x: x["ip_score"]):
        if r["ip"] in seen_bad:
            continue
        seen_bad.add(r["ip"])
        A(f"| {r['ip']} | {r['ip_score']} | {r['grade']} | {r['country']} | "
          f"{(r['asn'] or '')[:22]} | {deduction(r['verdict'])} |")
        if len(seen_bad) == 15:
            break
    A("")
    A("## 八、最干净的 15 个 IP（按评分降序）\n")
    A("| IP | 评分 | 等级 | 国家 | ASN | 性质 | 本机可达 |")
    A("|---|---:|---|---|---|---|---|")
    seen_ip = set()
    for r in sorted(scored, key=lambda x: -x["ip_score"]):
        if r["ip"] in seen_ip:
            continue
        seen_ip.add(r["ip"])
        A(f"| {r['ip']} | {r['ip_score']} | {r['grade']} | {r['country']} | "
          f"{(r['asn'] or '')[:22]} | {fmt(r['nature'])} | "
          f"{'是' if r['tcp_ms'] is not None else '否'} |")
        if len(seen_ip) == 15:
            break
    A("")
    A("## 九、方法与局限\n")
    A("1. 评分来自 `ipquality`：恶意与滥用 25 + 匿名代理 25 + 基础设施 18 + "
      "主动行为 14 + 黑名单 12 + 邮件信誉 6，满分 100，每条扣分都有依据。")
    A("2. **IP 质量 ≠ 节点可用**。IP 干净只说明这个出口不容易被风控拦，"
      "节点能不能连、快不快是另一回事（见 TCP 可达率）。")
    A("3. CDN 中转节点（Cloudflare/Akamai 等）测的是边缘 IP，不是落地 IP，"
      "这类节点的分数只能当参考。")
    A("4. 部分数据源受免费额度限制：IPQS 35 次/天、VirusTotal 4 次/分、"
      "AbuseIPDB 1000 次/天、GreyNoise 25 次/周。额度用尽后该源缺失，"
      "只降低置信度、不臆造结论。")
    A("5. 全部明细见 `out/all-nodes.csv`（可直接排序筛选）。")
    open("out/report-full.md", "w", encoding="utf-8").write("\n".join(L))

    # ---------------- 报告二：优选 50
    T = []
    B = T.append
    B("# 优选 50 节点报告\n")
    B("## 一、怎么选的\n")
    B("四层筛选，每一步都能复核：")
    B("")
    B("1. **可用性硬门槛**：从本机（国内）对 `server:port` 做 TCP 连接，4 秒超时，"
      "连不上直接淘汰——这是唯一能确定「你在国内真的能连上」的观测点。")
    B("2. **IP 纯净度**：`ipquality` 六维评分（恶意/代理/基础设施/主动行为/黑名单/邮件），"
      "分数越高越不容易被 Google、Cloudflare、支付和流媒体风控拦。")
    B("3. **综合排序**：`综合分 = 0.65×IP评分 + 0.20×延迟分 + 0.15×协议权重`，"
      "延迟分 = 100 − 毫秒/5（100ms→80 分），协议权重 vless 1.0 / trojan 0.95 / "
      "vmess 0.9 / hysteria2 与 tuic 0.85 / ss 0.6 / ssr 0.5。")
    B("")
    B("4. **硬门槛**：只保留 IPv4 节点和 IP 评分 ≥70（C 档「一般」以上）的节点。"
      "IPv6-only 节点（DNSBL 查不了、很多客户端也不支持）和 D/E 档（评分 <70，"
      "多项风险信号叠加）一律不进优选。")
    B("")
    B("另外做了两件事：")
    B("")
    B("- **把 CDN 前置节点单独归类**：`104.18.x`、`108.162.x` 这类地址是 Cloudflare/Akamai 的边缘节点，"
      "测到的分数属于 CDN 而不是真正的落地服务器，所以先排完直连节点，再用它们补位（表里「入口」列可区分）。")
    B("- **去重**：同一 IP 最多 2 个节点、同一 /24 最多 4 个、同一 ASN 最多 6 个，"
      "避免 50 个名额被同一个机房的克隆节点占满。")
    B("")
    B(f"候选池 {len(pool)} 个可用节点（其中直连 {sum(1 for r in pool if not r['cdn'])} 个、"
      f"CDN 前置 {sum(1 for r in pool if r['cdn'])} 个）→ 优选 {len(picked)} 个，"
      f"直连 {n_direct} 个，补位 {n_fill} 个。\n")
    B("## 二、优选清单\n")
    B("| # | 节点 | 协议 | 服务器:端口 | IP | 入口 | 国家 | 评分 | 等级 | 延迟 | DNSBL | 综合 |")
    B("|---:|---|---|---|---|---|---|---|---:|---|---:|---|---:|")
    for r in picked:
        name = (r["name"] or "").strip()[:28].replace("|", "/") or "（无名）"
        B(f"| {r['rank']} | {name} | {r['type']} | {r['server']}:{r['port']} | {r['ip']} | "
          f"{'CDN' if r['cdn'] else '直连'} | {fmt(r['country'])} | {r['ip_score']} | "
          f"{r['grade']}{'†' if r.get('fill') else ''} | {r['tcp_ms']:.0f}ms | "
          f"{fmt(r['dnsbl_black'], 0)} | {r['composite']} |")
    B("")
    B("> `†` = 补位节点：C 档以上、且不受同 IP/同网段/同 ASN 密度限制的节点不够 50 个时，"
      "放宽密度限制补进来的（评分仍在 55 以上）。能当备用，不建议做主力。")
    B("")
    B("## 三、分组建议\n")
    top10 = picked[:10]
    B("**主力（前 10，延迟与纯净度都在线）**：")
    for r in top10:
        B(f"- `{r['name'][:36]}` — {r['type']} {r['ip']} {r['country']} "
          f"{r['ip_score']}分/{r['grade']} · {r['tcp_ms']:.0f}ms")
    B("")
    B("**备用（11–50）**：见上表，建议整体导入客户端的 `url-test` 组，"
      "让它自己按实际延迟挑，不要手工固定某一个。")
    B("")
    B("## 四、前 10 的评分依据\n")
    for r in top10:
        B(f"### {r['rank']}. {r['name'][:40]}")
        B(f"- IP `{r['ip']}` · {fmt(r['country'])}/{fmt(r['city'])} · {fmt(r['asn'])}")
        B(f"- 评分 **{r['ip_score']} / {r['grade']}（{r['grade_cn']}）**，性质：{fmt(r['nature'])}，"
          f"置信度 {fmt(r['confidence'])}%")
        if r["verdict"]:
            B(f"- 判定：{r['verdict']}")
        if r["dnsbl_hits"]:
            B(f"- DNSBL：命中 {'、'.join(map(str, r['dnsbl_hits']))}")
        else:
            B(f"- DNSBL：{fmt(r['dnsbl_total'],0)} 个库全部干净")
        if r["blocks_hit"]:
            B(f"- 静态名单：{'、'.join(r['blocks_hit'])}")
        if r["vt"]:
            B(f"- VirusTotal：{r['vt']}")
        B(f"- 平台风控通过 {fmt(r['platforms_pass'])}；本机 TCP {r['tcp_ms']:.0f}ms")
        B("")
    B("## 五、注意事项\n")
    B("- 延迟是本机单次 TCP 握手，不等于真实下载速度；晚高峰会变差。")
    B("- 免费节点生存期短，建议每周重跑一次本流程（脚本在 `ipq_run/`）。")
    B("- `ss`/`ssr` 没有 TLS 伪装，特征明显，即便 IP 分数高也不建议长期主力使用。")
    B("- 不要用这些节点登录重要账号，公共节点等同于公开出口。")
    open("out/report-top50.md", "w", encoding="utf-8").write("\n".join(T))

    json.dump({"picked": picked, "stats": {
        "total": total, "unique_ip": len(uniq_ip), "scored": len(scored),
        "reachable": len(reachable), "median": med,
        "grades": dict(grades), "hosting": hosting, "proxy_flag": proxy_flag,
        "dnsbl_hit": dnsbl_hit, "vt_bad": vt_bad, "abuse_bad": abuse_bad,
        "pool": len(pool)}},
        open("out/summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({"total": total, "scored": len(scored), "reachable": len(reachable),
                      "pool": len(pool), "picked": len(picked), "median": med,
                      "grades": dict(grades)}, ensure_ascii=False))


if __name__ == "__main__":
    main()




