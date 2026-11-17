#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把结果导出为 Excel：概览 / 优选50 / 全量明细。"""
import json

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

HEAD = ["排名", "节点名", "协议", "服务器", "端口", "IP", "国家", "城市", "ASN", "组织",
        "机房段", "代理标记", "TCP延迟ms", "IP评分", "等级", "性质", "置信度",
        "DNSBL命中", "DNSBL库数", "静态名单命中", "VirusTotal", "AbuseIPDB",
        "平台通过", "综合分"]


def row_of(r):
    return [r.get("rank") or "", r.get("name") or "", r.get("type") or "",
            r.get("server") or "", r.get("port") or "", r.get("ip") or "",
            r.get("country") or "", r.get("city") or "", r.get("asn") or "",
            (r.get("org") or "")[:38], "是" if r.get("hosting") else "否",
            "是" if r.get("proxy_flag") else "否", r.get("tcp_ms"),
            r.get("ip_score"), r.get("grade") or "", r.get("nature") or "",
            r.get("confidence"), r.get("dnsbl_black"), r.get("dnsbl_total"),
            "、".join(r.get("blocks_hit") or []), (r.get("vt") or "")[:60],
            r.get("abuse"), r.get("platforms_pass") or "", r.get("composite")]


def sheet(wb, title, rows, widths, first=False):
    ws = wb.active if first else wb.create_sheet(title)
    ws.title = title
    ws.append(HEAD)
    fill = PatternFill("solid", fgColor="1F4E78")
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = fill
        c.alignment = Alignment(horizontal="center")
    for r in rows:
        ws.append(row_of(r))
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    return ws


def main():
    summ = json.load(open("out/summary.json", encoding="utf-8"))
    rows = json.load(open("rows.json", encoding="utf-8"))
    picked = summ["picked"]
    s = summ["stats"]

    wb = Workbook()
    ws = wb.active
    ws.title = "概览"
    ws.append(["指标", "数值"])
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F4E78")
    items = [
        ("节点总数", s["total"]), ("唯一公网 IP", s["unique_ip"]),
        ("完成深度检测 IP", s["scored"]), ("本机 TCP 可达节点", s["reachable"]),
        ("IP 评分中位数", round(s["median"], 1)),
        ("机房/托管段节点", s["hosting"]), ("ip-api 判代理", s["proxy_flag"]),
        ("DNSBL 有命中", s["dnsbl_hit"]), ("VirusTotal 判恶意", s["vt_bad"]),
        ("AbuseIPDB 有举报", s["abuse_bad"]), ("可参与优选", s["pool"]),
        ("等级 A", s["grades"].get("A", 0)), ("等级 B", s["grades"].get("B", 0)),
        ("等级 C", s["grades"].get("C", 0)), ("等级 D", s["grades"].get("D", 0)),
        ("等级 E", s["grades"].get("E", 0)),
    ]
    for k, v in items:
        ws.append([k, v])
    ws.column_dimensions["A"].width = 24
    ws.column_dimensions["B"].width = 16

    widths = [6, 34, 10, 28, 7, 16, 7, 12, 26, 30, 7, 8, 10, 8, 6, 14, 8, 9, 9, 22, 34, 10, 9, 8]
    sheet(wb, "优选50", picked, widths)
    sheet(wb, "全量明细", sorted(rows, key=lambda x: (x["ip_score"] is None, -(x["ip_score"] or 0))), widths)
    wb.save("out/ip-quality-report.xlsx")
    print("saved out/ip-quality-report.xlsx", len(rows))


if __name__ == "__main__":
    main()


