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

## 八个子命令

| 子命令 | 作用 |
|--------|------|
| `scan` | nmap 扫描 → 端口拆分 → 触发器 → 可选 MSF/CVE/Shodan/报告 |
| `history` | 列出历史扫描会话（SQLite 持久化） |
| `session` | 查看某次会话的主机/端口/触发器/发现 |
| `rerun` | 对已有工作区重跑触发器 |
| `report` | 报告 + 启动本地面板 |
| `cve` | 对已有工作区做 CVE 关联 |
| `handoff` | 工作区 → [PentAGI](docs/PENTAGI.md) 任务简报（侦察前端→自主深挖后端） |
| `deepdive` | 限定范围 agent 深挖单个发现（Path B，工具白名单+花费上界+目标锁死） |

## MCP Server（让 Agent 直接驱动扫描）

8 个子命令已全部包装为 MCP 工具，任何支持 MCP 的 agent（ZCode / Claude Code / Codex 等）可以直接调用：

```bash
# 启动（stdio 模式）
pixellance-mcp
```

MCP 客户端配置示例（ZCode / Claude Code 通用）：

```json
{
  "mcpServers": {
    "pixellance": {
      "command": "pixellance-mcp"
    }
  }
}
```

暴露的工具：`pixellance_scan` / `pixellance_history` / `pixellance_session` / `pixellance_rerun` / `pixellance_report` / `pixellance_cve` / `pixellance_handoff` / `pixellance_deepdive`。

设计要点：每个工具都是 CLI 子进程包装，health check、范围守卫、状态管理走同一套代码路径；`scan` 与 `deepdive` 标注为长任务（30 分钟上限），输出超 50KB 自动截断。

## 深挖模式（Path B：限定范围 agent）

当扫描发现高价值目标（KEV CVE、ms17_010 阳性），`deepdive` 启动一个
**有严格边界的 agent 循环**，只深挖这一个发现：

```bash
# 本地 7B 验证架构（慢，每轮 3-8 分钟）
pixellance deepdive reports/lab --cve CVE-2021-41773 --target 192.168.98.1

# GLM API 生产跑（秒级完成）
DEEPDIVE_API_KEY=your-key pixellance deepdive reports/lab \
  --cve CVE-2021-41773 --target 192.168.98.1 \
  --llm https://open.bigmodel.cn/api/paas/v4 --model glm-4.5
```

**三条硬边界：**

| 边界 | 实现 |
|------|------|
| 目标锁死 | 每个工具调用的 URL/主机必须等于 `--target`，否则拒绝 |
| 工具白名单 | 仅 `http_request` + `nmap_script` + `finish`，无 shell 逃逸 |
| 花费上界 | token 预算（默认 50k）AND 轮数上限（默认 8），任一触发即停 |

产出 `deepdive-<CVE>.json`：verdict（confirmed/not_vulnerable/inconclusive）
+ 证据 + 复现步骤。

实测发现：**7B 本地模型在多轮 ReAct 循环中会漂移到文本模式**（70 分钟
7 轮却 0 次工具调用），因此加了快速失败防护——连续 2 轮无工具调用
即终止并诚实报告"推荐更强模型"。**生产环境请使用 GLM API 或
14B+ 模型**，deepdive 在强模型上单轮秒级完成。

## PentAGI 联动（handoff）

PixelLance 做确定性侦察 + CVE 关联，[PentAGI](https://github.com/vxcontrol/pentagi) 做 LLM 自主深挖。
`handoff` 把扫描结果变成事实驱动型任务简报，让 PentAGI 的 generator 跳过盲探阶段：

```bash
pixellance scan targets.txt --cve --shodan
pixellance handoff reports/corp --print   # 生成简报 + 上下文 JSON
```

简报含严格 scope 清单、技术指纹、KEV/CVSS/EPSS 排序的 CVE 表、非破坏性验证指令。
部署与 GLM provider 配置见 [docs/PENTAGI.md](docs/PENTAGI.md)。

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
