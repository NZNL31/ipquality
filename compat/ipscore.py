#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IP 质量评分模型（可解释加权扣分制）。

设计原则
--------
1. 满分 100，六个维度各占固定权重，维度内取「最强信号」而不是累加，
   避免同一个事实被多个库重复扣分（例如 VT 恶意 5 个引擎 + AbuseIPDB 90 分，
   两者说的是同一件事，取 max 就够了）。
2. 所有扣分都带一句人话依据，并注明数字来源，可逐条复核。
3. 权重固定不调参，保证同一 IP 任何时候算出来的分数可比。
4. 数据缺口不猜测，只降低「置信度」，不给分也不扣分。

维度与权重
----------
恶意与滥用记录  25   有没有真凭实据的作恶记录（VT / AbuseIPDB / OTX / blocklist.de）
匿名代理特征    25   Tor / VPN / SOCKS / 公开代理，直接影响能否通过风控
基础设施属性    15   机房段天生低信任；住宅、移动网络是加分项
主动攻击行为    15   是否被观测到主动扫描、爆破、漏洞利用
黑名单收录广度  12   多少名单把它列进去了，收录越广越可信
邮件与论坛信誉   8   发信与注册场景专用（灰名单、SFS）
"""
import re

DIMENSIONS = [
    ("malicious", "恶意与滥用记录", 25),
    ("anonymity", "匿名代理特征", 25),
    ("infra", "基础设施属性", 18),
    ("behavior", "主动攻击行为", 14),
    ("blocklist", "黑名单收录广度", 12),
    ("mail", "邮件与论坛信誉", 6),
]

# 否决上限：某些属性一旦成立，无论其它维度多干净都不该得高分。
# 线性扣分表达不了「Tor 出口天生不可信」，所以需要一个天花板。
CAP_RULES = [
    ("anonymity", 0.95, 35, "Tor 出口"),
    ("malicious", 0.70, 45, "多个引擎判定恶意"),
    ("blocklist", 0.70, 55, "被广泛列入黑名单"),
    ("anonymity", 0.85, 65, "明确的代理/VPN 特征"),
]

# 机房/云厂商特征词（出现在 AS 名或 org 里即视为托管段）
DC_WORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh",
    "hetzner", "vultr", "linode", "akamai", "cloudflare", "alibaba", "aliyun",
    "tencent", "huawei cloud", "oracle", "contabo", "leaseweb", "choopa",
    "m247", "hostinger", "rackspace", "equinix", "colocation", "colocrossing",
    "serverhunter", "datacenter", "data center", "idc", "vps", "hosting",
    "cloud", "server", "dedipath", "psychz", "frantech", "buyvm", "ionos",
    "scaleway", "upcloud", "kamatera", "hosthatch", "greencloud", "racknerd",
)

# 住宅/移动网络的典型特征（反向解析里出现即可）
RES_PTR = (
    "bbtec.net", "ocn.ne.jp", "mesh.ad.jp", "plala.or.jp", "so-net.ne.jp",
    "hinet.net", "dynamic", ".ppp", "ppp.", "dsl", "adsl", "pool", "broadband",
    "fiber", "fibre", "ftth", "dial", "cable", "cust-", "static-", "static.",
    "dyn.", "dsl-", "client.", "user.", "home.", "res.", "pon.",
)

# 运营商特征词（用于判定「住宅/家宽」属性）
ISP_WORDS = (
    "softbank", "ntt", "kddi", "biglobe", "ocn", "plala", "hinet", "chunghwa",
    "comcast", "verizon", "at&t", "spectrum", "cox", "centurylink", "frontier",
    "telekom", "orange", "vodafone", "talktalk", "sky broadband", "telstra",
    "optus", "rogers", "bell canada", "telecom", "telefonica", "vivo", "claro",
    "china telecom", "china unicom", "china mobile", "chinanet", "unicom",
    "bharti", "airtel", "jio", "reliance", "turk telekom", "swisscom",
    "proximus", "telia", "elisa", "isp", "broadband", "cable",
)

PROXY_TYPES = ("vpn", "socks", "socks4", "socks5", "tor", "public proxy",
               "web proxy", "proxy", "compromised server", "openvpn", "wireguard")


def _ramp(x, lo, hi):
    """x<=lo 记 0，x>=hi 记 1，中间线性。缺值视为 0。"""
    if x is None:
        return 0.0
    try:
        x = float(x)
    except Exception:
        return 0.0
    if x <= lo:
        return 0.0
    if x >= hi:
        return 1.0
    return (x - lo) / float(hi - lo)


def _has(text, words):
    """特征词匹配。短词要求词边界，避免 idc 命中 midcontinent 这类误判。"""
    if not text:
        return None
    low = str(text).lower()
    for w in words:
        if len(w) <= 4 and w.isalnum():
            if re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(w), low):
                return w
        elif w in low:
            return w
    return None


def _dim(sev, evidence):
    return {"sev": max(0.0, min(1.0, sev)), "evidence": evidence}


# ----------------------------------------------------------------- 各维度
def _malicious(itl, src):
    """有实据的滥用记录：同指一件事的信号取最强，不叠加。"""
    sig, seen = [], []
    vt = itl.get("VirusTotal")
    if vt:
        mal, sus = vt.get("_mal") or 0, vt.get("_sus") or 0
        total = vt.get("_total") or 92
        rep = vt.get("_rep")
        if mal:
            # 看比例不看绝对数：2/92 是噪声，10/92 才是定论
            sev = min(1.0, (mal / float(total or 92)) / 0.12)
            if isinstance(rep, int) and rep >= 100:
                sev *= 0.6      # 社区信誉强正向，说明多数人认为它干净
            sig.append((sev, "VirusTotal %d/%d 引擎判恶意（%.1f%%）"
                        % (mal, total, 100.0 * mal / float(total or 92))))
        if sus:
            sig.append((min(0.35, (sus / float(total or 92)) / 0.25),
                        "VirusTotal %d 个引擎判可疑" % sus))
        if rep is not None and rep < 0:
            sig.append((min(0.60, abs(rep) / 100.0),
                        "VirusTotal 社区信誉 %d" % rep))
        seen.append("VT 恶意 %d/%d" % (mal, total))
    ab = src.get("AbuseIPDB")
    if ab and ab.get("score") is not None:
        conf = int(ab["score"])
        reps = ab.get("_reports") or 0
        if conf:
            sig.append((conf / 100.0,
                        "AbuseIPDB 滥用置信度 %d%%（近 90 天 %s 条举报）"
                        % (conf, reps)))
        seen.append("AbuseIPDB %d%%" % conf)
    iq = src.get("IPQualityScore")
    if iq:
        if iq.get("score") is not None:
            fs = int(iq["score"])
            if fs:
                sig.append((fs / 100.0, "IPQS 欺诈分 %d" % fs))
            seen.append("IPQS 欺诈分 %d" % fs)
        if iq.get("_abuse"):
            sig.append((0.55, "IPQS 标记近期滥用"))
    bd = itl.get("blocklist.de")
    if bd:
        att = bd.get("_attacks") or 0
        if att:
            sig.append((_ramp(att, 0, 40), "blocklist.de 记录 %d 次攻击" % att))
        seen.append("blocklist.de %d 次" % att)
    sn = itl.get("SANS ISC")
    if sn:
        att = sn.get("_attacks") or 0
        if att:
            sig.append((_ramp(att, 0, 200), "SANS ISC 记录 %d 次攻击" % att))
        seen.append("SANS 攻击 %d" % att)
    ot = itl.get("AlienVault OTX")
    if ot:
        p = ot.get("_pulses") or 0
        if p:
            sig.append((_ramp(p, 0, 4), "AlienVault OTX 收录于 %d 个情报包" % p))
        seen.append("OTX %d 条" % p)
    sf = itl.get("StopForumSpam")
    if sf:
        ap = sf.get("_appears") or 0
        if ap:
            sig.append((_ramp(ap, 0, 10), "StopForumSpam 出现 %d 次" % ap))

    if not sig:
        return _dim(0.0, "未记录任何滥用行为（%s）"
                    % ("、".join(seen) if seen else "无可用情报源"))
    sig.sort(key=lambda x: -x[0])
    top = sig[0]
    extra = ""
    if len(sig) > 1:
        extra = "；另有 " + "、".join(s[1] for s in sig[1:3])
    return _dim(top[0], top[1] + extra)


def _anonymity(src, itl, blocks):
    """Tor / VPN / 代理判定。Tor 一票否决，其余按投票比例。"""
    sig = []
    tor_src = [n for n, s in src.items() if s.get("tor") is True]
    tor_static = [b["name"] for b in blocks
                  if b.get("cat") == "tor" and b.get("state") == "hit"]
    if tor_src or tor_static:
        return _dim(1.0, "Tor 出口（%s）"
                    % "、".join(tor_src + tor_static))

    voters = [s for s in src.values() if s.get("proxy") is not None]
    votes = [s["name"] for s in voters if s.get("proxy") is True]
    if votes:
        # 1/4 票只算弱证据：ip-api 的 proxy 字段粒度很粗，
        # 单独一家说不算数，四家一致才接近定论。
        ratio = len(votes) / float(len(voters))
        sev = min(1.0, 0.15 + 0.80 * ratio)
        if len(votes) == 1 and len(voters) >= 3:
            sev *= 0.6          # 3 家否 1 家是，少数派只作参考
        sig.append((sev, "%d/%d 个库判代理（%s）"
                    % (len(votes), len(voters), "、".join(votes))))
    ptype_votes = [(s["name"], s.get("_ptype"))
                   for s in src.values()
                   if s.get("_ptype")
                   and any(t in str(s["_ptype"]).lower() for t in PROXY_TYPES)]
    if ptype_votes:
        sig.append((0.90, "%s 类型判为 %s"
                    % (ptype_votes[0][0], ptype_votes[0][1])))

    vpn_flags = [n for n, s in src.items() if s.get("vpn") is True]
    if vpn_flags:
        sig.append((0.80, "%s 的 vpn 字段为真" % "、".join(vpn_flags)))

    vt = itl.get("VirusTotal")
    if vt:
        tags = set(vt.get("_tags") or [])
        hit = tags & {"vpn", "proxy", "tor", "anonymous", "exit-node",
                      "open-proxy", "socks"}
        if "tor" in hit:
            sig.append((1.0, "VirusTotal 语料库标签 tor"))
        elif hit:
            sig.append((min(0.75, 0.40 + 0.15 * (len(hit) - 1)),
                        "VirusTotal 语料库标签 %s" % "、".join(sorted(hit))))

    sd = itl.get("Shodan")
    ports = set(sd.get("_ports") or []) if sd else set()
    dports = sorted(ports & {1080, 1081, 3128, 8080, 8118, 8888, 8388, 9050,
                             9150, 7890, 7891})
    if dports:
        sig.append((0.55, "Shodan 探测到代理常见端口 %s"
                    % ",".join(map(str, dports))))
    static_proxy = [b["name"] for b in blocks
                    if b.get("cat") == "proxy" and b.get("state") == "hit"]
    if static_proxy:
        sig.append((0.90, "命中代理段名单 %s" % "、".join(static_proxy)))

    if not sig:
        if not voters:
            return _dim(0.0, "无可用代理判定源")
        return _dim(0.0, "%d 个库一致判定非代理（%s）"
                    % (len(voters), "、".join(s["name"] for s in voters)))
    sig.sort(key=lambda x: -x[0])
    extra = [s[1] for s in sig[1:3] if s[0] > 0]
    return _dim(sig[0][0], sig[0][1] + ("；另有 " + "、".join(extra)
                                        if extra else ""))


def _infra(src, org, ptr, blocks, itl=None):
    """机房 vs 住宅。机房段本身不是罪，但在注册/风控场景是硬扣分。"""
    sig = []
    hosting_src = [s["name"] for s in src.values() if s.get("hosting") is True]
    if hosting_src:
        sig.append((min(1.0, 0.85 + 0.075 * (len(hosting_src) - 1)),
                    "%s 判定为数据中心/托管段" % "、".join(hosting_src)))
    static_dc = [b["name"] for b in blocks
                 if b.get("cat") == "cloud" and b.get("state") == "hit"]
    if static_dc:
        sig.append((1.0, "命中机房段名单 %s" % "、".join(static_dc)))
    word = _has(org, DC_WORDS)
    if word:
        sig.append((1.0, "归属方为托管服务商（%s）" % org))
    if ptr:
        w = _has(ptr, ("vps", "cloud", "server", "dedicated", "datacenter",
                       "hosting", "amazonaws", "colocation"))
        if w:
            sig.append((0.55, "反向解析疑似服务器主机名（%s）" % ptr))

    mobile = any(s.get("mobile") is True for s in src.values())
    res_ptr = _has(ptr, RES_PTR)
    res_isp = _has(org, ISP_WORDS)

    # 出口复用度（被动 DNS）：独享出口的信誉自控，共享出口一损俱损。
    # 机房/CDN 挂大量域名是正常现象，只对「非机房段却高密度共享」计权；
    # 共用域名里有被判恶意的，无论本 IP 是否机房段都算邻居连坐。
    pd = (itl or {}).get("PassiveDNS") or {}
    pd_recent = pd.get("_recent") or 0
    pd_mal = pd.get("_mal_hosts") or []
    is_hosting = bool(hosting_src or static_dc or word)
    if pd_mal:
        sig.append((min(0.7, 0.30 + 0.10 * len(pd_mal)),
                    "共用出口的域名中 %d 个被引擎判恶意（邻居连坐）" % len(pd_mal)))
    elif pd_recent >= 20 and not is_hosting:
        sig.append((min(0.5, 0.20 + pd_recent / 200.0),
                    "近 90 天有 %d 个域名共用此出口（非机房段却高密度共享）" % pd_recent))

    if sig:
        sig.sort(key=lambda x: -x[0])
        sev, note = sig[0]
        # 公共 DNS / CDN 这类经 GreyNoise RIOT 认定的良性服务，
        # 机房属性是预期的而非可疑的，减半计权但仍保留「非常住」的判定。
        if any(s.get("_riot") is True for s in src.values()):
            sev *= 0.5
            note += "（GreyNoise RIOT 良性公共服务，机房属性减半计权）"
        return _dim(sev, note)
    if mobile:
        return _dim(0.0, "移动网络（运营商级 NAT 段，境外风控通常视为真人）")
    if res_ptr or res_isp:
        bits = []
        if res_ptr:
            bits.append("反向解析符合家宽命名（%s）" % ptr)
        if res_isp:
            bits.append("归属为运营商（%s）" % org)
        return _dim(0.0, "；".join(bits) or "住宅网络特征")
    return _dim(0.0, "未见机房特征，但也没有明确住宅证据")


def _behavior(itl, src):
    """主动行为：被观测到扫描/爆破，是「正在作恶」的证据。"""
    sig = []
    # GreyNoise 同时在 sources（风险库表）与 intel 里，两边都查
    gn = itl.get("GreyNoise") or src.get("GreyNoise")
    if gn and gn.get("_err"):
        return _dim(0.0, "GreyNoise %s，主动行为未计入" % gn["_err"])
    if gn:
        if gn.get("_riot") is True:
            return _dim(0.0, "GreyNoise RIOT 良性服务（公共 DNS/CDN 类）")
        if gn.get("_noise") is True:
            cls = (gn.get("_class") or "unknown").lower()
            base = {"malicious": 1.0, "suspicious": 0.8, "benign": 0.25}.get(cls, 0.45)
            sig.append((base, "GreyNoise 观测到主动扫描（分类 %s，最近 %s）"
                        % (cls, gn.get("_last") or "未知")))
        elif gn.get("_noise") is False:
            sig.append((0.0, "GreyNoise 未观测到扫描行为"))
    sd = itl.get("Shodan")
    if sd:
        vulns = sd.get("_vulns") or []
        if vulns:
            sig.append((min(0.8, 0.25 * len(vulns)),
                        "Shodan 索引到 %d 个已知漏洞" % len(vulns)))
    if not sig:
        return _dim(0.0, "无主动行为观测数据")
    sig.sort(key=lambda x: -x[0])
    return _dim(sig[0][0], sig[0][1])


def _blocklist(dnsbl, blocks):
    """被多少名单收录。收录越广，说明越多独立维护者认为它有问题。"""
    sig = []
    if isinstance(dnsbl, dict) and dnsbl.get("total"):
        black = dnsbl.get("blacklisted") or 0
        if black:
            sig.append((min(1.0, 0.55 + 0.10 * (black - 1)),
                        "DNSBL %d/%d 库列为黑名单" % (black, dnsbl["total"])))
    hits = [b for b in blocks if b.get("cat") == "blacklist"
            and b.get("state") == "hit"]
    if hits:
        points, detail = 0.0, []
        for b in hits:
            if b["name"] == "IPsum" and b.get("detail"):
                points += min(0.5, float(b["detail"]) / 20.0)
                detail.append("IPsum 被 %s 个名单收录" % b["detail"])
            else:
                points += 0.35
                detail.append(b["name"])
        sig.append((min(1.0, points), "命中静态恶意名单：%s" % "、".join(detail)))
    if not sig:
        total = (dnsbl or {}).get("total") or 0
        other = (dnsbl or {}).get("other") or 0
        if total:
            msg = "%d 个 DNSBL 全部未列黑名单" % total
            if other:
                msg += "（另有 %d 个灰名单标记）" % other
            return _dim(0.0, msg)
        return _dim(0.0, "无可用的名单比对结果")
    sig.sort(key=lambda x: -x[0])
    return _dim(sig[0][0], sig[0][1])


def _mail(dnsbl, itl):
    """发信与注册场景：灰名单、垃圾邮件库、论坛注册黑名单。"""
    sig = []
    sf = itl.get("StopForumSpam")
    if sf:
        ap, fq = sf.get("_appears") or 0, sf.get("_freq") or 0
        if ap or fq:
            sig.append((max(_ramp(ap, 0, 10), _ramp(fq, 0, 50)),
                        "StopForumSpam 出现 %d 次（频率 %d）" % (ap, fq)))
    if isinstance(dnsbl, dict):
        other = dnsbl.get("hits") and [h for h in dnsbl["hits"]
                                       if h["verdict"] == "other"
                                       and not h.get("suspect")]
        if other:
            sig.append((min(0.60, 0.25 * len(other)),
                        "邮件/灰名单标记 %s" % "、".join(
                            h["zone"] for h in other[:4])))
    vt = itl.get("VirusTotal")
    if vt and (set(vt.get("_tags") or []) & {"spam", "phishing", "malware"}):
        sig.append((0.5, "VirusTotal 标签 %s"
                    % "、".join(sorted(set(vt.get("_tags") or [])
                                      & {"spam", "phishing", "malware"}))))
    if not sig:
        return _dim(0.0, "未进邮件黑名单，SFS 无记录")
    sig.sort(key=lambda x: -x[0])
    return _dim(sig[0][0], sig[0][1])


# ----------------------------------------------------------------- 评级
def _grade(total):
    if total >= 90:
        return "A", "优秀", "未见风险信号，可放心用于敏感场景"
    if total >= 80:
        return "B", "良好", "基本干净，存在少量非致命瑕疵"
    if total >= 70:
        return "C", "一般", "有明确瑕疵，敏感场景需谨慎"
    if total >= 55:
        return "D", "较差", "多项风险信号叠加，不建议用于登录态业务"
    return "E", "危险", "已被广泛判定为恶意或匿名出口，避免使用"


def _usecases(total, sev, flags, evidence):
    """场景适用性：同一 IP 在不同用途下的容忍度完全不同。"""
    rows = []

    def add(name, state, note=""):
        rows.append({"name": name, "state": state, "note": note})

    if flags["tor"]:
        add("日常浏览 / 流媒体", "no", "Tor 出口，主流站点默认拦截")
    elif total >= 70:
        add("日常浏览 / 流媒体", "yes", "")
    else:
        add("日常浏览 / 流媒体", "warn", "可用但可能遇到验证码")

    if flags["tor"]:
        add("流媒体地区解锁", "no", "Tor 段基本被流媒体封禁")
    elif flags["residential"] and sev["infra"] < 0.5:
        add("流媒体地区解锁", "yes", "住宅出口，地区解锁成功率高")
    elif sev["infra"] >= 0.5:
        add("流媒体地区解锁", "warn", "机房段，多数平台识别为代理")

    if flags["tor"]:
        add("注册账号 / 电商风控", "no", "Tor 必然触发二次验证")
    elif (total >= 85 and sev["anonymity"] < 0.35 and sev["infra"] < 0.35
          and sev["malicious"] < 0.2):
        add("注册账号 / 电商风控", "yes", "住宅属性 + 无代理标记")
    else:
        why = []
        if sev["anonymity"] >= 0.35:
            why.append("存在代理标记")
        if sev["infra"] >= 0.35:
            why.append("机房属性")
        if sev["malicious"] >= 0.2:
            why.append("有滥用记录")
        add("注册账号 / 电商风控", "warn" if total >= 70 else "no",
            "、".join(why) or "风险分偏低")

    if (sev["mail"] < 0.30 and sev["blocklist"] < 0.30
            and sev["malicious"] < 0.30):
        add("邮件发送 / SMTP", "yes", "")
    elif sev["mail"] >= 0.30:
        add("邮件发送 / SMTP", "warn" if sev["mail"] < 0.6 else "no",
            "邮件信誉有污点，进垃圾箱概率高")
    else:
        add("邮件发送 / SMTP", "warn", "未进邮件黑名单，但整体信誉偏低")

    if flags["tor"]:
        add("自动化采集 / 爬虫", "warn", "Tor 出口易被指纹识别")
    elif flags["datacenter"]:
        add("自动化采集 / 爬虫", "yes", "机房段，本就适合跑服务")
    else:
        add("自动化采集 / 爬虫", "yes", "住宅/移动段，被封锁概率更低")

    if total >= 90 and sev["anonymity"] < 0.2 and sev["malicious"] < 0.2:
        add("支付 / 金融风控", "yes", "")
    else:
        add("支付 / 金融风控", "warn" if total >= 80 else "no",
            "风控模型通常要求无代理标记且无滥用史")

    return rows


def _confidence(sources, dnsbl, blocks, intel):
    """置信度：数据源覆盖越全，分数越可信。缺源只降置信度，不改分数。

    分母取「全配状态」：8 个风险库（5 免 key + 3 个 key 源）、7 个情报源、
    10 个静态名单、一次完整的 DNSBL 扫描。少一项就少一份底气。
    """
    usable = [s for s in (sources or []) if not s.get("_err") and "error" not in s]
    risk = min(1.0, len(usable) / 8.0) * 40
    dnsbl_ok = 25 if isinstance(dnsbl, dict) and (dnsbl.get("total") or 0) > 0 else 0
    intel_ok = min(1.0, len(intel or []) / 7.0) * 20
    bl_ok = min(1.0, len(blocks or []) / 10.0) * 15
    return int(round(risk + dnsbl_ok + intel_ok + bl_ok))


# ----------------------------------------------------------------- 入口
def evaluate(ip, org, ptr, sources, intel, dnsbl, blocks):
    src = {s["name"]: s for s in (sources or [])}
    itl = {i["name"]: i for i in (intel or [])}
    blocks = blocks or []

    raw = {
        "malicious": _malicious(itl, src),
        "anonymity": _anonymity(src, itl, blocks),
        "infra": _infra(src, org, ptr, blocks, itl),
        "behavior": _behavior(itl, src),
        "blocklist": _blocklist(dnsbl, blocks),
        "mail": _mail(dnsbl, itl),
    }

    dims, total, deductions, sev = [], 0.0, [], {}
    for key, name, weight in DIMENSIONS:
        sev[key] = raw[key]["sev"]
        penalty = weight * raw[key]["sev"]
        got = weight - penalty
        total += got
        dims.append({
            "key": key, "name": name, "weight": weight,
            "sev": round(raw[key]["sev"], 3),
            "score": round(got, 1),
            "penalty": round(penalty, 1),
            "evidence": raw[key]["evidence"],
        })
        if penalty >= 0.5:
            deductions.append({"name": name, "points": round(penalty, 1),
                               "reason": raw[key]["evidence"]})

    total = round(total, 1)
    raw_total = total
    cap, cap_reason = 100, None
    for key, threshold, limit, reason in CAP_RULES:
        if sev[key] >= threshold and limit < cap:
            cap, cap_reason = limit, reason
    capped = total > cap
    if capped:
        total = float(cap)

    grade, grade_cn, tail = _grade(int(total))
    deductions.sort(key=lambda d: -d["points"])

    flags = {
        "tor": sev["anonymity"] >= 0.95,
        "proxy": sev["anonymity"] >= 0.35,
        "datacenter": sev["infra"] >= 0.5,
        # 住宅属性只看基础设施，不能被某一家库的代理标记抹掉——
        # 住宅 IP 跑代理依然住在住宅段，这是两件事。
        "residential": sev["infra"] < 0.35,
        "malicious": sev["malicious"] >= 0.3,
    }

    # 一句话结论：先定性，再说瑕疵
    nature = ("Tor 出口" if flags["tor"] else
              "机房/托管段" if flags["datacenter"] else
              "住宅/移动出口" if flags["residential"] else "属性不明出口")
    if capped:
        verdict = "%s · 触发上限 %d 分（%s）" % (nature, cap, cap_reason)
        if deductions:
            verdict += "；%s" % "、".join(
                "%s −%s" % (d["name"], d["points"]) for d in deductions[:2])
    elif deductions:
        verdict = "%s · %s；扣分项：%s" % (
            nature, tail,
            "、".join("%s −%s" % (d["name"], d["points"]) for d in deductions[:3]))
    else:
        verdict = "%s · %s" % (nature, tail)

    return {
        "score": total,
        "raw_score": round(raw_total, 1),
        "cap": cap if capped else None,
        "cap_reason": cap_reason,
        "grade": grade,
        "grade_cn": grade_cn,
        "verdict": verdict,
        "nature": nature,
        "confidence": _confidence(sources, dnsbl, blocks, intel),
        "dimensions": dims,
        "deductions": deductions,
        "flags": flags,
        "severity": {k: round(v, 3) for k, v in sev.items()},
        "usecases": _usecases(total, sev, flags, raw),
    }
