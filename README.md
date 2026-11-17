# ipquality (Windows edition)

IP 质量 / 纯净度检测工具，**[xykt/IPQuality](https://github.com/xykt/IPQuality) 的 Windows 移植 + 批量体检流程**。

原版是一份跑在 Linux 上的 bash 脚本，依赖 `jq`、`bc`、`dig`、`nc`、`ss` 等工具。
这个项目把那套判定逻辑重写成纯 Python（`compat/`），在 Windows 上双击就能跑，
并额外提供了一条"把一个订阅里上千个节点逐个查一遍"的批处理流水线（`audit/`）。

---

## 能查什么

单个 IP：

- 归属与类型：ASN、组织、国家/城市、反向解析、机房段 / 住宅段
- 风险评分：六维加权扣分（满分 100），每笔扣分都带一句依据
- 匿名代理：Tor / VPN / SOCKS / 公开代理，多个库投票
- 威胁情报：Shodan、blocklist.de、StopForumSpam、SANS ISC、AlienVault OTX、VirusTotal
- 黑名单：423 条 DNSBL 反查 + 10 个静态 CIDR 名单（Spamhaus DROP、IPsum 等）
- 平台视角：Google / Cloudflare / 电商 / 支付 / 流媒体 / 社交 / 邮件 / 游戏 / 广告 / AI
  十个场景的"通过·观察·挑战·拒绝"推断

批量：

- 订阅 → 节点列表 → 公网 IP → 逐个评分 → 报告 / 榜单 / Clash 配置

## 快速开始

```bat
:: 单个 IP
ipq.cmd 1.2.3.4
ipq.cmd 1.2.3.4 --json
ipq.cmd 1.2.3.4 --no-dnsbl

:: 测本机出口 IP（需要 bash + coreutils，即 Git for Windows）
ipq-run.cmd -4

:: 交互式，循环输入
查询IP.cmd
```

批量体检：

```bat
cd audit
set SUB_URL=https://example.com/your-subscription.txt
run-purity.cmd          :: 只测纯净度，不探测节点
run-full.cmd            :: 纯净度 + 从本机测可达性
```

## 依赖

- Python 3.10+，`pip install -r requirements.txt`（主体只需要 `dnspython`）
- 可选：`openpyxl`（导出 Excel）、Git for Windows（`ipq-run.cmd` 跑上游 shell 脚本）
- 可选 API key：IPQS / AbuseIPDB / VirusTotal，写进 `compat/.keys.env`（见 `.keys.env.example`）。
  **没有 key 也能用**，只是少几个数据源、置信度低一些。

## 评分模型

满分 100，六维加权扣分，维度内取最强信号、不叠加：

| 维度 | 权重 |
|---|---:|
| 恶意与滥用记录 | 25 |
| 匿名代理特征 | 25 |
| 基础设施属性 | 18 |
| 主动攻击行为 | 14 |
| 黑名单收录广度 | 12 |
| 邮件与论坛信誉 | 6 |

评级 A ≥90 / B ≥80 / C ≥70 / D ≥55 / E <55。
天花板：Tor 或强代理特征 ≤35、多引擎判恶意 ≤45、广泛列黑 ≤55。

## 目录

```
ipq.cmd / ipq.ps1 / ipq-run.cmd / install.cmd   入口
ip.sh / run.sh / dnsbl.list                     上游 AGPL 脚本与列表
compat/                                         Windows 侧 Python 实现
  ip_lookup      单 IP 查询主程序（--json / --brief / --no-dnsbl / --keys）
  ipscore.py     六维评分模型
  iprisk.py      十个平台的风控视角
  ipprobe.py     代理链路实测
  ipqtools.py    共享工具
  dnsbl_check    DNSBL 反查
  bc / dig / nc / ss   给上游脚本用的 shim
audit/                                          批量体检流水线（见 audit/WORKFLOW.md）
```

## 说明与局限

- 免费数据源有额度：ip-api 45 次/分、IPQS 35 次/天、VirusTotal 4 次/分、AbuseIPDB 1000 次/天。
  额度用尽后该源缺失，只降低"置信度"，不会给出假分数。
- `nature` 里的"Tor 出口"是内部标签，含义是"几乎所有库都判它是代理"，不一定是真的 Tor 出口。
- 平台视角是按各平台公开敏感项做的**推断**，不是平台内部评分。
- IP 纯净度 ≠ 节点可用性。IP 干净只说明不容易被风控拦，能不能连、快不快是另一件事。

## 许可

本项目基于 [xykt/IPQuality](https://github.com/xykt/IPQuality)（AGPL-3.0）改写，
因此同样以 **AGPL-3.0** 发布，详见 `LICENSE` 与 `NOTICE.md`。
