# PixelLance · Port-Triggered Pentest Orchestration

> Feed it a targets.txt: it triggers the right tools per open port, correlates CVEs ranked by KEV/EPSS, and lands everything in a local web report.
>
> English: Port-triggered pentest orchestration — inspired by [leebaird/discover](https://github.com/leebaird/discover), rebuilt in Python on top of the [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) tool server.

**Find an open port → run the matching tool automatically → let results drive the next step → rank by CVE correlation.**

## Workflow

```
targets.txt
    │
    ▼  full nmap scan (executed on Kali via HexStrike)
    │
    ▼  gnmap parsing → split trigger files per port (22.txt / 445.txt / 3306.txt / http.txt ...)
    │
    ▼  port trigger matching and execution (declarative registration, fingerprint-aware)
    │    445.txt  → smb-vuln-ms17_010 + enum4linux
    │    161.txt  → snmp-info + onesixtyone
    │    http.txt → whatweb + httpx + nuclei
    │    ...
    │
    ▼  results written to script-*.txt, sessions persisted to SQLite
    │
    ▼  CVE correlation: CPE/banner/whatweb fingerprints → NVD → CISA KEV → EPSS → PoC
    │
    ▼  dark-themed web report (127.0.0.1:17322)
```

## Installation

```bash
git clone https://github.com/wdfdsyhb/pixellance.git
cd pixellance
pip install -e .
```

Requirements: Python 3.8+, `requests`. Tool execution goes through the [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) server (best run in a Kali VM — it ships REST wrappers for a hundred-plus tools such as nmap/metasploit/nuclei).

## Quick Start

```bash
# Standard scan + triggers
pixellance scan targets.txt -n corp-lan

# Full pipeline: all profiles + Shodan enrichment + CVE correlation + web panel
pixellance scan targets.txt -p full --shodan --cve --serve

# Point at a specific HexStrike server
pixellance scan targets.txt --server http://<kali-vm>:8888

# Show what would run (no execution)
pixellance scan targets.txt --dry-run

# Session history
pixellance history
pixellance session 3

# Re-run triggers against an existing workspace
pixellance rerun reports/scan-2026-01-01-120000

# Run CVE correlation on an existing workspace, output top-priority targets
pixellance cve reports/scan-2026-01-01-120000
```

## Eight Subcommands

| Subcommand | What it does |
|--------|------|
| `scan` | nmap scan → port splitting → triggers → optional MSF/CVE/Shodan/report |
| `history` | List past scan sessions (SQLite persistence) |
| `session` | Inspect hosts/ports/triggers/findings of one session |
| `rerun` | Re-run triggers against an existing workspace |
| `report` | Generate report + start the local panel |
| `cve` | Run CVE correlation on an existing workspace |
| `handoff` | Workspace → [PentAGI](docs/PENTAGI.md) task brief (recon front end → autonomous deep-dive back end) |
| `deepdive` | Scope-limited agent deep-dive on a single finding (Path B: tool whitelist + spend cap + locked target) |

## MCP Server (let agents drive scans directly)

All 8 subcommands are wrapped as MCP tools. Any MCP-capable agent (ZCode / Claude Code / Codex, etc.) can call them directly:

```bash
# Start (stdio mode)
pixellance-mcp
```

MCP client configuration example (works for ZCode / Claude Code alike):

```json
{
  "mcpServers": {
    "pixellance": {
      "command": "pixellance-mcp"
    }
  }
}
```

Exposed tools: `pixellance_scan` / `pixellance_history` / `pixellance_session` / `pixellance_rerun` / `pixellance_report` / `pixellance_cve` / `pixellance_handoff` / `pixellance_deepdive`.

Design notes: every tool is a CLI subprocess wrapper; health checks, scope guards and state management share one code path. `scan` and `deepdive` are flagged as long-running tasks (30-minute cap); output over 50KB is truncated automatically.

## Deep-Dive Mode (Path B: scope-limited agent)

When a scan surfaces a high-value finding (a KEV CVE, a positive ms17_010 check), `deepdive` starts an
**agent loop with hard boundaries** that digs into that one finding only:

```bash
# Local 7B validation architecture (slow, 3-8 min per round)
pixellance deepdive reports/lab --cve CVE-2021-41773 --target 192.168.98.1

# Production run via GLM API (completes in seconds)
DEEPDIVE_API_KEY=your-key pixellance deepdive reports/lab \
  --cve CVE-2021-41773 --target 192.168.98.1 \
  --llm https://open.bigmodel.cn/api/paas/v4 --model glm-4.5
```

**Three hard boundaries:**

| Boundary | Implementation |
|------|------|
| Locked target | Every tool call's URL/host must equal `--target`, otherwise refused |
| Tool whitelist | Only `http_request` + `nmap_script` + `finish`, no shell escape |
| Spend cap | Token budget (default 50k) AND round limit (default 8); either one stops the run |

Output is `deepdive-<CVE>.json`: verdict (confirmed/not_vulnerable/inconclusive)
+ evidence + reproduction steps.

Field finding: **local 7B models drift into text mode in multi-round ReAct loops**
(70 minutes, 7 rounds, 0 tool calls). A fast-fail guard was added: two consecutive
rounds without a tool call terminate the run and honestly report "use a stronger
model". **For production use the GLM API or a 14B+ model** — deepdive completes
in seconds per round on strong models.

## PentAGI Integration (handoff)

PixelLance does deterministic recon + CVE correlation; [PentAGI](https://github.com/vxcontrol/pentagi) does LLM-driven autonomous deep-dive.
`handoff` turns scan results into a fact-driven task brief so PentAGI's generator can skip the blind-probing phase:

```bash
pixellance scan targets.txt --cve --shodan
pixellance handoff reports/corp --print   # generate brief + context JSON
```

The brief contains a strict scope list, technical fingerprints, a CVE table ranked by KEV/CVSS/EPSS, and non-destructive verification instructions.
Deployment and GLM provider configuration: [docs/PENTAGI.md](docs/PENTAGI.md).

## Smart Modules

### CVE Correlation Engine (cve.py)

Pipeline: `fingerprints (CPE/banner/whatweb) → NVD → CISA KEV → EPSS → PoC`

- **CPE exact query first**: CPEs provided by Shodan go straight into NVD `cpeName` lookup, hitting product vulnerabilities precisely (in practice, keyword search for "Apache httpd 2.4.49" returned 0 hits while a CPE query hit all known CVEs such as CVE-2021-41773)
- Keyword search has **automatic fallback**: when the exact query returns 0 hits, the version number is stripped and the search retried
- Output ranked by in-KEV > CVSS > EPSS
- Uses the cve-mcp-server async pipeline (KEV/EPSS/PoC at every stage) when available, otherwise falls back to direct NVD queries

### Automatic Nuclei Template Selection (nuclei.py)

whatweb/httpx fingerprints → a 40+ technology mapping table → template tags chosen per tech stack. WordPress detected loads `wp-plugin/wp-theme/cms`; Jenkins detected appends the `CVE-2024-23897` template. No more blind full-template scans.

### Shodan Enrichment (shodan.py)

Per host: org/ports/banners/CPE/known CVEs. SSRF protection: public-IP validation + pinned domain resolution checks + redirects disabled. Degrades gracefully without an API key.

### Metasploit Resource File Generation (msfgen.py)

Dynamically assembles `.rc` files per open port (80+ port→auxiliary module mappings); one `msfconsole -r` runs the whole batch.

## Comparison with discover

| | discover | PixelLance |
|---|---|---|
| Language | Bash | Python |
| Execution backend | Local subprocess | HexStrike HTTP API (tools run in a Kali VM) |
| Trigger logic | Hardcoded `if [ -f PORT.txt ]` | Declarative PortTrigger registration |
| CVE correlation | None | Full NVD → KEV → EPSS → PoC chain |
| State persistence | File directory | SQLite (five tables: sessions/hosts/ports/triggers/findings) |
| Re-entry | f_rerun | `rerun` subcommand |

## Environment Variables

| Variable | Purpose | Default |
|------|------|------|
| `HEXSTRIKE_SERVER` | HexStrike server address | `http://127.0.0.1:8888` |
| `SHODAN_KEY` | Shodan API key | none (skipped gracefully) |
| `NVD_API_KEY` | NVD rate 5→50 req/30s | none |
| `PIXELLANCE_HOME` | Cache directory | `~/.pixellance` |

## Extending: Custom Triggers

```python
from pixellance.triggers import PortTrigger, TriggerEngine

engine = TriggerEngine(workspace)
engine.register(PortTrigger(
    port_file="8443.txt",
    name="Custom check",
    tool="nmap",                # HexStrike tool name
    tool_args={...},
    output_file="script-8443.txt",
))
```

## Positioning Statement

For authorized penetration testing and security education only. Do not use against unauthorized targets.

> 🇨🇳 中文文档: [README.md](README.md)
