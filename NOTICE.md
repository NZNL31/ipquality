# NOTICE

## 上游

`ip.sh`、`run.sh`、`dnsbl.list` 以及评分模型（`compat/ipscore.py`）、平台视角
（`compat/iprisk.py`）、查询流程（`compat/ip_lookup`）均改写自：

- **xykt/IPQuality** — https://github.com/xykt/IPQuality
- 许可：GNU Affero General Public License v3.0

上游版权归其作者所有。本项目对其逻辑做了 Python 重写以支持 Windows，
并按 AGPL-3.0 第 5 条以同一许可发布。

## 本仓库附带说明

- `compat/bc`、`compat/dig`、`compat/nc`、`compat/ss` 是供上游 shell 脚本调用的
  轻量 shim，不是对应工具的完整实现。
- `compat/jq.exe` 为 jq 官方 Windows 构建（MIT），随仓库分发以省去安装步骤。
- 仓库不包含任何订阅内容、节点清单、检测结果或 API 密钥。
  `compat/.keys.env` 已在 `.gitignore` 中，示例见 `compat/.keys.env.example`。
