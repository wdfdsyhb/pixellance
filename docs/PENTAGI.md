# PixelLance → PentAGI 联动指南

**架构分工**：PixelLance 做确定性侦察+CVE 关联（快、免费、无幻觉），PentAGI 做自主深挖（LLM 决策、迭代利用）。`pixellance handoff` 把侦察结果变成 PentAGI 的任务简报，跳过它最烧钱的盲探阶段。

```
pixellance scan targets.txt --cve --shodan     ← 快、免费、确定性
        │
        ▼  pixellance handoff reports/<name>
        │
        ├── pentagi-task.md        ← 粘贴为 flow 输入
        └── pentagi-context.json   ← 上传为 flow 资源附件
        │
        ▼  PentAGI flow (provider=glm)
        │     generator 拿着事实做计划 → pentester agent 验证 KEV CVE
        ▼
    验证报告（confirmed / not vulnerable / inconclusive）
```

## 1. 部署 PentAGI

### 方式 A：Windows 宿主机（Docker Desktop）

需要 Docker Desktop + 16GB 内存（建议跑之前停掉 Kali VM 和 ComfyUI）。

### 方式 B：Kali VM 内（轻量，省宿主资源）

```bash
# VM 里装 docker（Kali 2026 自带源）
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER && newgrp docker
```

注意：VM 内跑时 agent 沙箱是 Docker-in-Docker，4GB 内存的 VM 偏紧，给 VM 6GB+ 更稳。

### 拉起服务栈

```bash
git clone https://github.com/vxcontrol/pentagi.git
cd pentagi

cp .env.example .env
# 编辑 .env（见下节 GLM 配置）
docker compose up -d
```

Web UI: `http://localhost:8080`（默认账号密码在 .env 的 `PENTAGI_ADMIN_*`）

### GLM 配置（.env 关键行）

PentAGI 原生支持 GLM，不需要 OpenAI 兼容层：

```ini
# 国内端点（open.bigmodel.cn，推荐国内网络用）
GLM_API_KEY=你的智谱key
GLM_SERVER_URL=https://open.bigmodel.cn/api/paas/v4
GLM_PROVIDER=glm

# 或 z.ai 国际端点（默认值）
# GLM_SERVER_URL=https://api.z.ai/api/paas/v4
```

搜索工具（searcher agent 用）至少配一个：`GOOGLE_API_KEY`+`GOOGLE_CX`、
`TAVILY_API_KEY`、`PERPLEXITY_API_KEY` 或自建 `SEARXNG`（免 key）。

最小可跑 = GLM 三行 + 一个搜索 key，其余全部留空。

## 2. 生成任务简报

```bash
# 在 pixellance 项目里（完整链路：扫描→触发器→CVE 关联→简报）
pixellance scan targets.txt -n corp --cve --shodan
pixellance handoff reports/corp

# 或对已有工作区补生成
pixellance handoff reports/corp --print   # --print 直接看简报内容
```

产出两个文件：

| 文件 | 用途 |
|------|------|
| `pentagi-task.md` | 任务简报（粘贴为 flow 输入） |
| `pentagi-context.json` | 机器可读上下文（hosts/tech/CVE 全量） |

简报内容：严格 scope 清单、技术指纹、按 KEV→CVSS→EPSS 排序的 CVE 表、
任务指令（先验证 KEV、非破坏性优先、出界即停）。

## 3. 喂给 PentAGI

### 方式 A：UI 粘贴（最快）

1. 打开 `http://localhost:8080` → New Flow
2. Provider 选 `glm`
3. 把 `pentagi-task.md` 全文粘进输入框 → 创建
4. （可选）Files 页上传 `pentagi-context.json` 作为附件

### 方式 B：REST API（可脚本化）

```bash
BASE=http://localhost:8080/api/v1
TOKEN=你的APItoken   # UI → Settings → API tokens 生成

# 上传上下文资源
RES_ID=$(curl -s -X POST "$BASE/files/resources" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@pentagi-context.json" | jq -r '.id')

# 创建 flow
curl -s -X POST "$BASE/flows" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"provider\": \"glm\", \"input\": $(jq -Rs . < pentagi-task.md), \
       \"resource_ids\": [$RES_ID]}"
```

## 4. 成本与安全

| 项 | 说明 |
|----|------|
| token 消耗 | 有简报比盲探省 60-80%（一次 flow 约 0.1-1 元 GLM 费用，复杂目标更高） |
| scope 控制 | 简报里有 STRICT scope 清单，agent 被明确禁止出界扫描 |
| 破坏性动作 | 简报要求 KEV 验证走非破坏性 PoC，破坏性验证需停下来报告 |
| 沙箱隔离 | agent 全部在 PentAGI 的 Docker 沙箱里执行，不直接碰你的宿主机 |

## 5. 排错

- **GLM 连接失败**：确认 `GLM_SERVER_URL` 与 key 的签发方匹配（bigmodel 的 key 配 bigmodel URL）
- **agent 说工具不存在**：flow 创建时 provider 必须填 `glm`，不是 `custom`
- **搜索无结果**：检查至少一个搜索 provider 的 key
- **内存不足**：`docker compose down` 后先停 Kali VM / ComfyUI 再起
