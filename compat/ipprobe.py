#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实测验证：让请求真的从目标 IP 发出去，看平台到底拦不拦。

为什么必须走代理
----------------
风控是看「请求从哪个 IP 来」的，所以只有把出站流量绑到目标 IP 上，
测到的才是这个 IP 的待遇。因此本模块要求显式给一个 socks5 代理
（就是你客户端本地那个监听端口），并且**先校验出口 IP 是否等于目标 IP**，
不等就直接拒测——否则测的是你自己的宽带，毫无意义。

能测到什么、测不到什么
----------------------
能测到：这一次请求有没有被拦（HTTP 码、跳转、挑战页特征串）。
测不到：平台的内部评分。风控是概率性的，同一条干净请求可能只是碰巧没触发。
        所以结论写「本次实测」，并且建议连测几次再下判断。
"""
import os
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# 每个探针：block 命中即「拦截」，challenge 命中即「挑战」，
# ok_codes 内且未命中前两者即「通过」。特征串都取自有辨识度的页面文案，
# 不用 captcha/cloudflare 这种到处都是的泛词，避免误判。
PROBES = [
    {
        "name": "Google 搜索", "key": "google",
        "url": "https://www.google.com/search?q=network+test&hl=en&gl=us",
        "block": ["unusual traffic", "sorry/index", "our systems have detected"],
        "block_codes": [429],
        "ok_codes": [200],
        "why": "IP 级反爬拦截，命中即说明该 IP 已被 Google 标记",
    },
    {
        "name": "Google 账号页", "key": "google",
        "url": "https://accounts.google.com/signin/v2/identifier?hl=en",
        "block": ["unusual traffic", "sorry/index"],
        "block_codes": [429],
        "ok_codes": [200],
        "why": "账号注册/登录入口，比搜索页宽松，能过说明不是硬封",
    },
    {
        "name": "Cloudflare 防护站", "key": "cloudflare",
        "url": "https://discord.com/",
        "head_challenge": ["cf-mitigated: challenge"],
        "challenge": ["just a moment", "cf_chl_opt",
                      "enable javascript and cookies to continue"],
        "why": "Bot Management 的挑战页特征，命中说明 bot score 被打低",
    },
    {
        "name": "Amazon", "key": "ecommerce",
        "url": "https://www.amazon.com/",
        "block": ["validatecaptcha", "enter the characters you see below",
                  "api-services-support@amazon.com"],
        "head_challenge": ["x-amzn-waf-action: challenge"],
        "challenge": ["automated access", "enter the characters you see below"],
        "challenge_codes": [202],
        "ok_codes": [200],
        "why": "机器人检测页，机房与代理段常直接跳验证码",
    },
    {
        "name": "ChatGPT / OpenAI", "key": "ai",
        "url": "https://chatgpt.com/",
        "block": ["not available in your country", "unable to load site",
                  "access denied"],
        "head_challenge": ["cf-mitigated: challenge"],
        "challenge": ["just a moment", "cf_chl_opt",
                      "enable javascript and cookies to continue"],
        "ok_codes": [200, 302],
        "why": "同时体现地区限制与 Cloudflare 挑战两层",
    },
    {
        "name": "Netflix", "key": "streaming",
        "url": "https://www.netflix.com/title/81280792",
        "block": ["unblocker", "you seem to be using", "not available in your region",
                  "nsez-403"],
        "block_codes": [403],
        "ok_codes": [200, 301, 302],
        "why": "代理检测页，住宅段通常能过，机房段基本必挂",
    },
    {
        "name": "Steam 商店", "key": "gaming",
        "url": "https://store.steampowered.com/",
        "block": ["access is denied", "blocked"],
        "ok_codes": [200, 301, 302],
        "why": "按地区与代理封禁，宽松一档，用作对照基线",
    },
]


def _curl(url, proxy, timeout=20, retry=1):
    """带重试的取页：schannel 偶发抖动不该被当成「IP 不可达」。"""
    resp = _curl_once(url, proxy, timeout)
    for _ in range(retry):
        if not resp.get("error"):
            return resp
        resp = _curl_once(url, proxy, timeout)
    return resp


def _curl_once(url, proxy, timeout=20):
    """用 curl 走 socks5 取一次响应，返回状态码/跳转/耗时/正文/响应头。"""
    with tempfile.TemporaryDirectory() as td:
        body_path = os.path.join(td, "body")
        head_path = os.path.join(td, "head")
        cmd = ["curl", "-sS", "--max-time", str(timeout)]
        if proxy:
            cmd += ["--proxy", proxy]
        cmd += ["-A", UA,
               "-H", "Accept-Language: en-US,en;q=0.9",
               "-H", "Accept: text/html,application/xhtml+xml",
                "-D", head_path, "-o", body_path,
                "-w", "%{http_code}\t%{redirect_url}\t%{time_total}",
                url]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  errors="replace", timeout=timeout + 8)
        except Exception as exc:
            return {"error": str(exc)[:80]}
        if proc.returncode != 0:
            msg = (proc.stderr or "").strip().splitlines()
            text = msg[-1] if msg else "curl 失败 %d" % proc.returncode
            text = text.replace("curl: ", "")
            if len(text) > 110:
                text = text[:107] + "…"
            return {"error": text}
        parts = (proc.stdout or "").strip().split("\t")
        code = parts[0] if parts else "000"
        redirect = parts[1] if len(parts) > 1 else ""
        elapsed = parts[2] if len(parts) > 2 else "?"
        try:
            with open(body_path, "r", encoding="utf-8", errors="replace") as fh:
                body = fh.read(400000)
        except Exception:
            body = ""
        try:
            with open(head_path, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(20000)
        except Exception:
            head = ""
        return {"code": code, "redirect": redirect,
                "elapsed": elapsed, "body": body, "head": head}


def _head_has(head, pair):
    """在响应头里做「头名: 值」精确匹配。
    形如 x-amzn-waf-action: challenge，必须落在行首的头名位置，
    避免正文或 cookie 里出现同名子串造成误判。"""
    name, _, val = pair.partition(":")
    pat = r"(?im)^%s:[^\n]*%s" % (re.escape(name.strip()), re.escape(val.strip()))
    return re.search(pat, head) is not None


def _judge(probe, resp):
    if resp.get("error"):
        return "不可达", resp["error"]
    code = resp["code"]
    body = resp["body"].lower()
    head = resp["head"]
    head_low = head.lower()
    redirect = (resp["redirect"] or "").lower()

    try:
        numeric = int(code)
    except Exception:
        numeric = 0

    # 响应头里的显式标记最可信：WAF 主动声明「我在挑战你」，
    # 比正文里搜关键词可靠得多（正文关键词常常只是引用的脚本）
    for pair in probe.get("head_block", []):
        if _head_has(head, pair):
            return "拦截", "响应头 %s" % pair
    for pair in probe.get("head_challenge", []):
        if _head_has(head, pair):
            return "挑战", "响应头 %s" % pair

    if numeric in probe.get("block_codes", []):
        return "拦截", "HTTP %d" % numeric
    for sig in probe.get("block", []):
        if sig in body or sig in redirect:
            return "拦截", "命中「%s」" % sig
    if numeric in probe.get("challenge_codes", []):
        return "挑战", "HTTP %d（人机校验响应）" % numeric
    for sig in probe.get("challenge", []):
        if sig in body or sig in head_low:
            return "挑战", "命中「%s」" % sig
    if numeric in probe.get("ok_codes", [200]):
        return "通过", "HTTP %d" % numeric
    # 3xx 只是跳转，不等于被拦；跳到拦截页的情况已在 block 里用 redirect 捕获
    if 300 <= numeric < 400:
        return "通过", "HTTP %d 重定向" % numeric
    return "异常", "HTTP %d" % numeric


def exit_ip(proxy, timeout=15):
    """确认这个 socks 端口的出口 IP。校验不过就不测，避免测错对象。"""
    resp = _curl("https://api.ipify.org?format=json", proxy, timeout)
    if resp.get("error"):
        return None, resp["error"]
    m = re.search(r'"ip"\s*:\s*"([^"]+)"', resp.get("body") or "")
    if m:
        return m.group(1), None
    body = (resp.get("body") or "").strip()
    if re.match(r"^[0-9a-fA-F:.]+$", body):
        return body, None
    return None, "出口 IP 解析失败"


def run(ip, proxy, workers=4):
    """跑全套探针，返回实测结果 + 出口校验结论。"""
    ip_out, err = exit_ip(proxy)
    report = {"proxy": proxy, "exit_ip": ip_out, "error": err,
              "match": bool(ip_out and ip_out.strip() == ip.strip()),
              "results": []}
    if err or not ip_out:
        return report
    if not report["match"]:
        # 出口不是目标 IP 就没有意义，直接返回让调用方提示用户
        return report

    with ThreadPoolExecutor(max_workers=workers) as pool:
        responses = list(pool.map(lambda p: _curl(p["url"], proxy), PROBES))
    for probe, resp in zip(PROBES, responses):
        verdict, evidence = _judge(probe, resp)
        report["results"].append({
            "name": probe["name"],
            "key": probe.get("key"),
            "verdict": verdict,
            "evidence": evidence,
            "elapsed": resp.get("elapsed", "?"),
            "why": probe["why"],
        })
    return report
