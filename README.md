# PixelLance

> Port-triggered pentest orchestration — inspired by [leebaird/discover](https://github.com/leebaird/discover), rebuilt in Python on top of the [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) tool server.

**发现什么端口 → 自动跑对应工具 → 结果驱动下一步 → CVE 关联排序。**

## 工作流

```
targets.txt
    │
    ▼  nmap 全面扫描（经 HexStrike 在 Kali 上执行）
    │
    ▼  gnmap 解析 → 按端口拆触发文件 (22.txt / 445.txt / 3306.txt / http.txt ...)
    │
    ▼  端口触发器匹配执行（声明式注册，指纹感知）
    │    445.txt  → smb-vuln-ms17_010 + enum4linux
    │    161.txt  → snmp-info + onesixtyone
    │    http.txt → whatweb + httpx + nuclei
    │    ...
    │
    ▼  结果写入 script-*.txt，SQLite 会话入库
    │
    ▼  CVE 关联：CPE/banner/whatweb 指纹 → NVD → CISA KEV → EPSS → PoC
    │
    ▼  暗色 Web 报告 (127.0.0.1:17322)
```

## 安装

```bash
git clone https://github.com/wdfdsyhb/pixellance.git
cd pixellance
pip install -e .
```

依赖：Python 3.8+，`requests`。工具执行通过 [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) 服务端（建议跑在 Kali VM 里，自带 nmap/metasploit/nuclei 等百余工具的 REST 封装）。

## 快速开始

```bash
# 标准扫描 + 触发器
pixellance scan targets.txt -n corp-lan

# 完整流程：全 profile + Shodan 富化 + CVE 关联 + Web 面板
pixellance scan targets.txt -p full --shodan --cve --serve

# 指定 HexStrike 服务器
pixellance scan targets.txt --server http://<kali-vm>:8888

# 只看会跑什么（不实际执行）
pixellance scan targets.txt --dry-run

# 历史会话
pixellance history
pixellance session 3

# 对已有工作区重跑触发器
pixellance rerun reports/scan-2026-01-01-120000

# 补跑 CVE 关联，输出 Top 优先级目标
pixellance cve reports/scan-2026-01-01-120000
```

## 六个子命令

| 子命令 | 作用 |
|--------|------|
| `scan` | nmap 扫描 → 端口拆分 → 触发器 → 可选 MSF/CVE/Shodan/报告 |
| `history` | 列出历史扫描会话（SQLite 持久化） |
| `session` | 查看某次会话的主机/端口/触发器/发现 |
| `rerun` | 对已有工作区重跑触发器 |
| `report` | 生成报告 + 启动本地面板 |
| `cve` | 对已有工作区做 CVE 关联 |

## 智能模块

### CVE 关联引擎（cve.py）

流水线：`指纹(CPE/banner/whatweb) → NVD → CISA KEV → EPSS → PoC`

- **CPE 精确查询优先**：Shodan 提供的 CPE 直接走 NVD `cpeName` 检索，精确命中产品漏洞（实测 "Apache httpd 2.4.49" 关键词搜索命中 0，CPE 查询直接命中 CVE-2021-41773 等全部已知洞）
- keyword 搜索带**自动降级**：精确查询 0 命中时剥掉版本号重试
- 输出按 KEV 在网 > CVSS > EPSS 排序
- cve-mcp-server 可用时走其异步管道（KEV/EPSS/PoC 全阶段），否则直连 NVD 兜底

### Nuclei 模板自动选择（nuclei.py）

whatweb/httpx 指纹 → 40+ 技术映射表 → 按技术栈选模板标签。检测到 WordPress 加载 `wp-plugin/wp-theme/cms`，检测到 Jenkins 追加 `CVE-2024-23897` 模板。不再全模板盲扫。

### Shodan 富化（shodan.py）

每主机查 Org/端口/banner/CPE/已知 CVE。SSRF 防护：公网 IP 校验 + 固定域解析校验 + 禁重定向。无 key 时优雅降级。

### Metasploit 资源文件生成（msfgen.py）

按开放端口动态拼装 `.rc` 文件（80+ 端口→auxiliary 模块映射），`msfconsole -r` 一键批量执行。

## 与 discover 的对比

| | discover | PixelLance |
|---|---|---|
| 语言 | Bash | Python |
| 执行后端 | 本地 subprocess | HexStrike HTTP API（工具跑在 Kali VM） |
| 触发逻辑 | `if [ -f PORT.txt ]` 硬编码 | 声明式 PortTrigger 注册 |
| CVE 关联 | 无 | NVD → KEV → EPSS → PoC 全链路 |
| 状态持久化 | 文件目录 | SQLite（会话/主机/端口/触发器/发现五表） |
| 重入 | f_rerun | `rerun` 子命令 |

## 环境变量

| 变量 | 用途 | 默认 |
|------|------|------|
| `HEXSTRIKE_SERVER` | HexStrike 服务端地址 | `http://127.0.0.1:8888` |
| `SHODAN_KEY` | Shodan API key | 无（降级跳过） |
| `NVD_API_KEY` | NVD 速率 5→50 req/30s | 无 |
| `PIXELLANCE_HOME` | 缓存目录 | `~/.pixellance` |

## 扩展：自定义触发器

```python
from pixellance.triggers import PortTrigger, TriggerEngine

engine = TriggerEngine(workspace)
engine.register(PortTrigger(
    port_file="8443.txt",
    name="Custom check",
    tool="nmap",                # HexStrike 工具名
    tool_args={...},
    output_file="script-8443.txt",
))
```

## 定位声明

仅供授权渗透测试与安全教育用途。请勿对未授权目标使用。
