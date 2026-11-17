# 工作流：给一个订阅做 IP 纯净度体检

把订阅文件里的每个节点拆出服务器地址，解析成公网 IP，逐个交给 `compat/ip_lookup`
的评分引擎，最后输出：全量报告、纯净度榜、综合优选榜、Clash 配置。

适用场景：判断一个节点池"干不干净"——这些出口有没有被风控库标成代理/滥用、
有没有进黑名单、机房段还是住宅段。

---

## 一、两种模式

| 模式 | 是否探测节点 | 结果是否受运行位置影响 | 用途 |
|---|---|---|---|
| **纯纯净度**（`run-purity.cmd`） | 不探测 | 不受影响，换机器结果一样 | 只看 IP 干不干净 |
| **完整版**（`run-full.cmd`） | 对本机做 TCP 探测 `server:port` | 受影响，测的是"你这里能不能连" | 要"能连 + 干净"的可用清单 |

纯净度评分全部来自第三方数据库（ip-api / IPQS / VirusTotal / AbuseIPDB / DNSBL），
查询时只把**目标 IP** 发给对方，请求从哪台机器发出不影响判定。

> 只测纯净度，不需要你的机器去连这些节点。

延迟是另一回事：`reach.py` 从本机对 `server:port` 做 4 秒 TCP 握手，测的是**你到节点**。
它只做两件事：淘汰连不上的节点、给综合分贡献 20% 权重。纯纯净度模式完全不跑它。

---

## 二、目录

```
ipquality/
├─ ipq.cmd / ipq.ps1        单 IP 查询入口（调 compat/ip_lookup）
├─ ipq-run.cmd              跑上游 shell 脚本，测本机出口 IP
├─ install.cmd              把本目录加进用户 PATH
├─ ip.sh / run.sh           上游 xykt/IPQuality 脚本（AGPL-3.0）
├─ dnsbl.list               423 条 DNSBL 列表
├─ compat/                  Windows 侧重写：ip_lookup + 评分 + 平台视角
└─ audit/
   ├─ run-purity.cmd        纯纯净度，一键
   ├─ run-full.cmd          完整版，一键
   ├─ parse_sub.py          订阅（base64/URI/Clash）→ nodes.json
   ├─ stage1.py             域名解析 + ip-api 批量归属
   ├─ batch.py              逐个 IP 评分，写 deep.jsonl（可续跑）
   ├─ reach.py              本机 TCP 可达性（完整版才用）
   ├─ collect.py            合并成 rows.json
   ├─ purity_report.py      纯净度前 50
   ├─ build_report.py       全量报告 + 综合优选 50 + CSV
   ├─ build_yaml.py         优选节点 → Clash 配置
   └─ export_xlsx.py        导出 Excel（需 openpyxl）
```

`audit/` 里的脚本默认读同目录的 `v2.txt`，输出到 `audit/out/`。

---

## 三、命令

```bat
cd audit
set SUB_URL=https://example.com/your-subscription.txt
run-purity.cmd
```

或者手动一步步来：

```bat
set PY=python

%PY% parse_sub.py v2.txt     :: -> nodes.json
%PY% stage1.py               :: -> resolved.json / ipmeta.json / targets.json
%PY% batch.py                :: -> deep.jsonl（1200 个 IP 约 25-40 分钟）
%PY% collect.py              :: -> rows.json
%PY% purity_report.py        :: -> out\report-purity-top50.md
```

完整版再加：

```bat
%PY% reach.py                :: -> reach.json（本机 TCP，约 1 分钟）
%PY% build_report.py         :: -> out\report-full.md / report-top50.md / all-nodes.csv
%PY% build_yaml.py           :: -> out\top50.yaml
%PY% export_xlsx.py          :: -> out\ip-quality-report.xlsx
```

依赖：Python 3.10+、`dnspython`；导出 Excel 另需 `openpyxl`；抓订阅用系统自带 `curl`。

---

## 四、耗时与额度

| 步骤 | 输出 | 耗时 | 依赖额度 |
|---|---|---|---|
| `parse_sub.py` | nodes.json | <1s | 无 |
| `stage1.py` | resolved/ipmeta.json | ~40s | ip-api 批量 15 次/分 |
| `batch.py` | deep.jsonl | 25~40min | 见下 |
| `reach.py` | reach.json | ~1min | 无 |
| `collect.py` | rows.json | 3s | 无 |
| 报告类 | md/csv/xlsx/yaml | 数秒 | 无 |

`batch.py` 的 `WORKERS = 20` 是实测的甜点：约 45 个 IP/分钟。
再高会撞 ip-api 的 45 次/分，部分 IP 拿不到归属，置信度下降。

| 数据源 | 免费额度 | 用尽后 |
|---|---|---|
| ip-api.com | 45 次/分 | 归属字段缺失 |
| IPQualityScore | 1000 次/月，每日 35 | 欺诈分缺失，匿名代理维度可能虚高 |
| VirusTotal | 500 次/天，4 次/分 | 恶意维度只剩 AbuseIPDB |
| AbuseIPDB | 1000 次/天 | 举报数据缺失 |
| GreyNoise | 25 次/周 | 主动行为维度记 0 分 |

没有 key 也能跑：`compat/.keys.env` 里的 key 是可选的，缺了就少几个数据源，
只影响置信度，不会编造结论。

---

## 五、几个必须知道的判定细节

1. **`list.dnswl.org` 是白名单**，命中说明信誉好，`verdict` 是 `other` 不是 `blacklisted`。
   统计黑名单只算 `blacklisted`。
2. **`nature` 里的「Tor 出口」不是真 Tor**：ipscore 把"匿名代理维度 ≥0.95"标成 Tor，
   实际含义是"几乎所有库都判它是代理"，触发后分数被天花板压到 35。
3. **IPv6 查不了 DNSBL**（423 个库只支持 IPv4 反查），IPv6-only 节点置信度天然偏低。
4. **CDN 前置节点**（Cloudflare / Fastly / Akamai 段）测到的是边缘 IP，不是落地服务器，
   分数只能当参考。脚本按 ASN 把它们标成 `CDN`。
5. 同一域名常对应几十个节点（只靠 Host 区分），所以"节点数"远多于"IP 数"。

---

## 六、评分口径

满分 100，六维加权扣分，维度内取最强信号、不叠加：

| 维度 | 权重 | 依据 |
|---|---:|---|
| 恶意与滥用记录 | 25 | VirusTotal、AbuseIPDB、OTX、blocklist.de |
| 匿名代理特征 | 25 | Tor/VPN/SOCKS/公开代理的多库投票 |
| 基础设施属性 | 18 | 机房/托管段、云厂商 ASN、住宅/移动特征 |
| 主动攻击行为 | 14 | GreyNoise、Shodan、SANS ISC |
| 黑名单收录广度 | 12 | 423 条 DNSBL + 10 个静态 CIDR 名单 |
| 邮件与论坛信誉 | 6 | 邮件黑名单、StopForumSpam |

评级：A ≥90｜B ≥80｜C ≥70｜D ≥55｜E <55。
天花板：Tor/强代理 ≤35、多引擎判恶意 ≤45、广泛列黑 ≤55。

---

## 七、两份榜单的口径

- **纯净度榜**（`purity_report.py`）：只按 IP 评分排，同分比置信度、再比 DNSBL 命中数。
  去重：同 IP 1 个、同 /24 最多 3 个、同 ASN 最多 4 个。**不看能不能连。**
- **综合榜**（`build_report.py`）：
  `综合分 = 0.65×IP评分 + 0.20×延迟分 + 0.15×协议权重`，延迟分 = 100 − 毫秒/5；
  协议权重 vless 1.0 / trojan 0.95 / vmess 0.9 / hysteria2·tuic 0.85 / ss 0.6 / ssr 0.5。
  门槛：IPv4、IP 评分 ≥70、本机 TCP 可达；直连优先，CDN 后备；D 档只在名额不够时补位（标 `†`）。

---

## 八、结果怎么用

1. `out/top50.yaml` 直接导入 Clash/mihomo，`🚀 优选` 是 url-test 组。
2. 只看纯净度就用 `report-purity-top50.md`，但里面可能有你连不上的节点。
3. 公共节点生存期很短，建议每周重跑；`deep.jsonl` 是原始证据，留着能改口径重排，不用重跑 40 分钟。
