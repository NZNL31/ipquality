#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主流平台风控视角：把同一份 IP 证据投射到各平台的风控规则上。

必须先说清楚边界
----------------
这里**没有任何平台的官方接口**（Google、Cloudflare、PayPal 都不对外开放
"这个 IP 多少分"）。所以本模块做的是「按公开可验证的规则推断」，不是
「读取平台内部评分」：

  1. 平台风控的原料，本质就是数据商的字段——IPQS 的 fraud_score、
     AbuseIPDB 的 abuseConfidenceScore、Spamhaus 的收录、VT 的标签、
     ASN 的类型（住宅/机房/移动）。这些我们已经在查了。
  2. 平台之间的差异**不在数据源，而在敏感度**：流媒体只关心「是不是机房」，
     支付关心「是不是代理 + 有没有滥用史」，邮件投递只关心「发信信誉」。
     同一个 IP 在 Netflix 畅通、在 PayPal 却要验证码，原因就在这里。
  3. 所以本表输出的是「会不会被拦、拦得多狠」的档位 + 信任分，
     不是「平台内部给我打了 73 分」这种假精确。

敏感度取值是经验值，写在 PROFILES 里，可逐条改。
高档位判定都会附带触发依据，便于复核。
"""

# 五个证据维度 → 中文短名（表头用）
DIM_CN = {
    "infra": "机房",
    "anonymity": "代理",
    "malicious": "滥用",
    "behavior": "扫描",
    "mail": "邮件",
}

# 平台画像：sens 是该平台对五类证据的敏感度（0-1），
# strict 是额外的严格度偏移（支付/广告这类天然更严），
# veto 是硬规则——命中即拒，不参与加权。
PROFILES = [
    {
        "key": "google",
        "name": "Google 搜索 / 账号注册",
        "sens": {"infra": 0.85, "anonymity": 0.90, "malicious": 0.70,
                 "behavior": 0.60, "mail": 0.10},
        "strict": 4,
        "note": "机房与代理会直接压低 reCAPTCHA 分；注册账号后补手机验证",
    },
    {
        "key": "cloudflare",
        "name": "Cloudflare Bot Management",
        "sens": {"infra": 0.90, "anonymity": 0.85, "malicious": 0.80,
                 "behavior": 0.75, "mail": 0.0},
        "strict": 3,
        "note": "机房段 bot score 天生低，扫描行为直接扣到挑战",
    },
    {
        "key": "ecommerce",
        "name": "电商下单（Amazon / Shopify）",
        "sens": {"infra": 0.80, "anonymity": 0.95, "malicious": 0.85,
                 "behavior": 0.40, "mail": 0.30},
        "strict": 5,
        "note": "代理标记是最强信号，下单阶段会二次验证支付方式",
    },
    {
        "key": "payment",
        "name": "支付 / 银行（PayPal / Stripe）",
        "sens": {"infra": 0.85, "anonymity": 0.95, "malicious": 0.95,
                 "behavior": 0.50, "mail": 0.15},
        "strict": 8,
        "veto": [("anonymity", 0.95, "明确代理/VPN 出口")],
        "note": "最严的一档：代理 + 滥用史任一坐实即触发人工审核",
    },
    {
        "key": "streaming",
        "name": "流媒体（Netflix / Disney+）",
        "sens": {"infra": 0.95, "anonymity": 0.80, "malicious": 0.30,
                 "behavior": 0.15, "mail": 0.0},
        "strict": 0,
        "veto": [("infra", 0.85, "机房段，识别为代理")],
        "note": "只看机房与代理：住宅段畅通，机房段直接锁区",
    },
    {
        "key": "social",
        "name": "社交注册（X / Discord / Reddit）",
        "sens": {"infra": 0.65, "anonymity": 0.85, "malicious": 0.75,
                 "behavior": 0.45, "mail": 0.10},
        "strict": 3,
        "note": "注册阶段看代理，日常浏览宽松；新号风控更严",
    },
    {
        "key": "mail",
        "name": "邮件投递（Gmail / Outlook）",
        "sens": {"infra": 0.50, "anonymity": 0.40, "malicious": 0.60,
                 "behavior": 0.55, "mail": 0.90},
        "strict": 2,
        "note": "不看住宅/机房，只看发信信誉与是否在垃圾邮件名单",
    },
    {
        "key": "gaming",
        "name": "游戏（Steam / Epic）",
        "sens": {"infra": 0.60, "anonymity": 0.80, "malicious": 0.55,
                 "behavior": 0.30, "mail": 0.0},
        "strict": 2,
        "note": "封禁按地区与代理，机房段仍可正常登录",
    },
    {
        "key": "ads",
        "name": "广告平台（Google / Meta Ads）",
        "sens": {"infra": 0.85, "anonymity": 0.95, "malicious": 0.85,
                 "behavior": 0.40, "mail": 0.10},
        "strict": 7,
        "veto": [("anonymity", 0.95, "明确代理/VPN 出口")],
        "note": "代理 + 多账号是所有广告平台的头号封禁理由",
    },
    {
        "key": "ai",
        "name": "AI 服务（OpenAI / Claude）",
        "sens": {"infra": 0.55, "anonymity": 0.85, "malicious": 0.45,
                 "behavior": 0.30, "mail": 0.0},
        "strict": 2,
        "note": "对机房与代理敏感（地区限制），不关心住宅属性",
    },
]

# 档位阈值（对「信任分 - strict」后的有效分）
TIERS = [(85, "通过"), (72, "观察"), (55, "挑战"), (-1, "拒绝")]

# 证据强度措辞：直接把 0.90 这种数字翻成人话
STRENGTH = [(0.85, "极强"), (0.60, "强"), (0.35, "中等"), (0.15, "偏弱")]


def _strength(value):
    for threshold, word in STRENGTH:
        if value >= threshold:
            return word
    return ""


def _tier(effective):
    for threshold, label in TIERS:
        if effective >= threshold:
            return label
    return "拒绝"


def assess(severity, dims=None):
    """按各平台敏感度投射证据，返回每个平台的信任分与预判档位。

    severity: {infra/anonymity/malicious/behavior/mail/blocklist: 0-1}
    dims:     ipscore 的 dimensions 列表，仅用于取依据文案（可选）
    """
    sev = {k: float(severity.get(k) or 0) for k in DIM_CN}
    evidence = {}
    for d in (dims or []):
        evidence[d["key"]] = d.get("evidence", "")

    rows = []
    for p in PROFILES:
        sens = p["sens"]
        denom = sum(sens.values()) or 1.0
        weighted = sum(sens[k] * sev[k] for k in sens)
        trust = int(round(100 * (1 - weighted / denom)))

        hard = None
        for key, threshold, why in p.get("veto", []):
            if sev.get(key, 0) >= threshold:
                hard = why
                break

        effective = trust - p["strict"]
        verdict = _tier(effective)
        if hard:
            verdict = "拒绝"

        # 排序看「实际扣了多少」（敏感度×证据强度）：只展示真的扣了分的维度，
        # 一个都没扣就写「—」，不拿平台偏好来冒充扣分
        ordered = sorted(sens.items(),
                         key=lambda kv: (-(kv[1] * sev[kv[0]]), -kv[1]))
        hit = [kv for kv in ordered
               if kv[1] * sev[kv[0]] > 0.01 and sev[kv[0]] >= 0.10][:2]
        sensitive = "·".join(DIM_CN[k] for k, _ in hit) if hit else "—"

        # 依据：只列真正扣了分的维度，避免每行都堆满无关信息
        reasons = []
        for k, w in hit:
            if sev[k] >= 0.15 and w >= 0.4:
                reasons.append("%s特征%s" % (DIM_CN[k], _strength(sev[k])))
        if hard:
            basis = hard
        elif reasons:
            basis = "、".join(reasons)
        else:
            basis = "未见扣分项"

        rows.append({
            "key": p["key"],
            "name": p["name"],
            "trust": trust,
            "effective": effective,
            "verdict": verdict,
            "sensitive": sensitive,
            "basis": basis,
            "vetoed": bool(hard),
            "note": p["note"],
        })

    ranked = sorted(rows, key=lambda r: r["effective"])
    return {
        "platforms": rows,
        "strictest": ranked[0]["name"] if ranked else None,
        "loosest": ranked[-1]["name"] if ranked else None,
        "disclaimer": "平台无公开查询接口，此表按各平台已知敏感项加权推断，"
                      "非平台内部评分",
    }
