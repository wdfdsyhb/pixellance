"""Path B: bounded deep-dive agent for high-value findings.

When PixelLance surfaces a KEV CVE or confirmed vuln, this module spawns
a scoped agent loop that investigates JUST that one finding:

- target locked to the finding's host (every tool call re-validated)
- tool whitelist: http_request + nmap_script (+ finish), nothing else
- cost ceiling: token budget AND max turns, whichever hits first
- non-destructive: verification only, no exploit payloads

LLM: any OpenAI-compatible /v1/chat/completions endpoint with tool
calling — local Ollama (default) or GLM API.
"""
import json
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

from .client import HexStrikeClient, HexStrikeError

DEFAULT_LLM_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "qwen2.5:7b-instruct-q4_K_M"
DEFAULT_BUDGET = 50000     # total LLM tokens (in+out)
DEFAULT_TURNS = 8
TOOL_OUTPUT_LIMIT = 2500   # chars of tool output fed back to the LLM
LLM_TIMEOUT = 900          # seconds per LLM call (slow local models)

# NOTE: local 7B models ( Ollama ) verify the ARCHITECTURE but are too
# slow for full PoC loops (each turn ~3-8 min). For production runs,
# point --llm at GLM/OpenAI and set DEEPDIVE_API_KEY -- a full
# deep-dive then finishes in seconds.

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Send ONE HTTP request to the target and get status + "
                "headers + body. Use for PoC verification (path traversal, "
                "info disclosure, default pages). URL host MUST be the "
                "scoped target."),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string",
                            "description": "Full URL incl. path and port"},
                    "method": {"type": "string",
                               "enum": ["GET", "HEAD", "POST"],
                               "description": "HTTP method"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_script",
            "description": (
                "Run nmap with NSE scripts against the scoped target for "
                "service-level verification. Safe scripts only "
                "(discovery/vuln categories, no exploit)."),
            "parameters": {
                "type": "object",
                "properties": {
                    "ports": {"type": "string",
                              "description": "Port(s), e.g. '8081' or '80,443'"},
                    "scripts": {"type": "string",
                                "description": "NSE script names, comma "
                                "separated, e.g. 'http-enum,http-vuln*'"},
                },
                "required": ["ports"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": (
                "End the investigation with a verdict. Call this as soon as "
                "you have enough evidence."),
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string",
                                "enum": ["confirmed", "not_vulnerable",
                                         "inconclusive"]},
                    "evidence": {"type": "string",
                                 "description": "What you observed that "
                                 "supports the verdict (quote actual output)"},
                    "repro_steps": {"type": "string",
                                    "description": "Minimal reproduction "
                                    "steps, one per line"},
                },
                "required": ["verdict", "evidence"],
            },
        },
    },
]

SYSTEM_TEMPLATE = """# VULNERABILITY VERIFICATION SPECIALIST

You verify ONE specific vulnerability finding. This is an AUTHORIZED
engagement; the target is in scope.

## Finding
- CVE: {cve_id} (CVSS {cvss})
- Description: {description}
- Target host: {target} (the ONLY host you may touch)
- Known context: {context}

## Rules
1. NON-DESTRUCTIVE ONLY: verification requests, never exploits that
   modify data, crash services, or persist access.
2. Scope lock: every URL/target in tool calls must be exactly {target}.
   Anything else will be rejected.
3. Use the finding's known PoC technique first; adapt if it fails.
4. Quote ACTUAL tool output as evidence, not assumptions.
5. Call `finish` as soon as the verdict is clear. Do not over-investigate.

## Verdict criteria
- confirmed: the vulnerable response is observable (e.g. file contents
  returned, vulnerable banner + working probe)
- not_vulnerable: patched behavior observed (404/403 on PoC paths,
  fixed version banner)
- inconclusive: could not determine either way
"""


class DeepDiveAgent:
    """Bounded ReAct loop for one finding."""

    def __init__(self, client: HexStrikeClient, llm_url: str = DEFAULT_LLM_URL,
                 model: str = DEFAULT_MODEL, api_key: str = "",
                 budget: int = DEFAULT_BUDGET, max_turns: int = DEFAULT_TURNS):
        self.client = client
        self.llm_url = llm_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.budget = budget
        self.max_turns = max_turns
        self.tokens_used = 0

    # ---------- scope guard ----------

    def _assert_scope(self, value: str, target: str):
        """Every tool target/URL must point at the scoped host."""
        if value.startswith(("http://", "https://")):
            host = urlparse(value).hostname or ""
        else:
            host = value.split("/")[0].split(":")[0]
        if host != target:
            raise ValueError(
                "scope violation: '" + host + "' != target '" + target + "'")

    # ---------- tool executors ----------

    def _exec_http_request(self, args: dict, target: str) -> str:
        url = args["url"]
        self._assert_scope(url, target)
        method = args.get("method", "GET")
        result = self.client.call("http-framework", {
            "action": "request",
            "url": url,
            "method": method,
        })
        # http-framework returns a rich dict, not stdout — compact it
        if isinstance(result, dict):
            keep = {k: result.get(k) for k in
                    ("success", "status_code", "status", "headers",
                     "body", "response", "error", "content") if k in result}
            return json.dumps(keep, ensure_ascii=False)[:TOOL_OUTPUT_LIMIT]
        return str(result)[:TOOL_OUTPUT_LIMIT]

    def _exec_nmap_script(self, args: dict, target: str) -> str:
        self._assert_scope(target, target)
        ports = args["ports"]
        scripts = args.get("scripts", "")
        extra = ("--script=" + scripts) if scripts else ""
        out = self.client.nmap(target, ports=ports, scan_type="-sT",
                               extra=extra)
        return out[:TOOL_OUTPUT_LIMIT]

    def _execute(self, name: str, args: dict, target: str) -> str:
        try:
            if name == "http_request":
                return self._exec_http_request(args, target)
            if name == "nmap_script":
                return self._exec_nmap_script(args, target)
            if name == "finish":
                return "__FINISH__"
            return "error: unknown tool '" + name + "'"
        except HexStrikeError as e:
            return ("tool error: " + str(e))[:TOOL_OUTPUT_LIMIT]
        except ValueError as e:
            return "error: " + str(e)

    # ---------- LLM ----------

    def _chat(self, messages: list) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        resp = requests.post(
            self.llm_url + "/chat/completions",
            json={"model": self.model, "messages": messages,
                  "tools": TOOL_SPECS, "stream": False},
            headers=headers, timeout=LLM_TIMEOUT,
            proxies={"http": None, "https": None})
        resp.raise_for_status()
        data = resp.json()
        usage = data.get("usage", {}) or {}
        self.tokens_used += int(usage.get("prompt_tokens", 0) or 0)
        self.tokens_used += int(usage.get("completion_tokens", 0) or 0)
        return data

    # ---------- context guard ----------

    def _estimate_tokens(self, messages: list) -> int:
        """Rough token estimate: ~4 chars/token for mixed en/zh/tool content."""
        chars = 0
        for m in messages:
            chars += len(str(m.get("content", "")))
            tc = m.get("tool_calls")
            if tc:
                chars += len(json.dumps(tc, ensure_ascii=False))
        return chars // 3 + len(messages) * 4

    def _context_full(self, messages: list, headroom: int = 2048) -> bool:
        return self._estimate_tokens(messages) > (16384 - headroom)

    # ---------- main loop ----------

    def run(self, cve: dict, target: str) -> dict:
        system = SYSTEM_TEMPLATE.format(
            cve_id=cve.get("id", "?"),
            cvss=cve.get("cvss", "?"),
            description=(cve.get("description") or "")[:300],
            target=target,
            context=json.dumps(
                {k: cve.get(k) for k in ("kev", "poc", "epss", "query")},
                ensure_ascii=False))
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content":
                "Verify whether " + target + " is vulnerable to " +
                cve.get("id", "the finding") + ". Start now."},
        ]

        verdict = {"verdict": "inconclusive",
                   "evidence": "budget or turn limit reached",
                   "repro_steps": "", "tokens_used": 0, "turns": 0}
        started = time.time()

        for turn in range(1, self.max_turns + 1):
            if self._context_full(messages):
                verdict["evidence"] = ("context window full after " +
                                       str(turn - 1) + " turns")[:300]
                break
            if self.tokens_used > self.budget:
                verdict["evidence"] = (
                    "token budget exhausted (" + str(self.tokens_used) +
                    " > " + str(self.budget) + ") before verdict")
                break
            try:
                data = self._chat(messages)
            except Exception as e:
                verdict["evidence"] = ("LLM error: " + str(e))[:300]
                break

            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message", {})
            tool_calls = msg.get("tool_calls") or []

            if not tool_calls:
                # plain answer without tool call — if context still has
                # room, nudge once; otherwise force finish to avoid overflow
                if not self._context_full(messages):
                    content = msg.get("content", "")
                    if content:
                        messages.append({"role": "assistant",
                                         "content": content})
                        messages.append({"role": "user", "content":
                                         "Use a tool call (http_request, "
                                         "nmap_script, or finish)."})
                        continue
                # context full or empty reply → stop
                verdict["evidence"] = ("context limit reached or model "
                                       "declined to use tools after nudge")[:300]
                break

            messages.append(msg)
            finished = False
            for tc in tool_calls:
                fn = (tc.get("function") or {})
                name = fn.get("name", "")
                try:
                    fargs = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    fargs = {}
                if name == "finish":
                    verdict = {
                        "verdict": fargs.get("verdict", "inconclusive"),
                        "evidence": fargs.get("evidence", ""),
                        "repro_steps": fargs.get("repro_steps", ""),
                        "tokens_used": self.tokens_used,
                        "turns": turn,
                    }
                    finished = True
                    break
                result = self._execute(name, fargs, target)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": result,
                })
            if finished:
                break
            verdict["turns"] = turn
            verdict["tokens_used"] = self.tokens_used

        verdict["target"] = target
        verdict["cve"] = cve.get("id", "?")
        verdict["duration_s"] = round(time.time() - started, 1)
        verdict["model"] = self.model
        return verdict


def run_deepdive(workspace: Path, cve_id: str, target: str,
                 client: HexStrikeClient, llm_url: str = DEFAULT_LLM_URL,
                 model: str = DEFAULT_MODEL, api_key: str = "",
                 budget: int = DEFAULT_BUDGET,
                 max_turns: int = DEFAULT_TURNS) -> dict:
    """Verify one CVE against one host; writes deepdive-<cve>.json."""
    findings = {}
    f = workspace / "cve-findings.json"
    if f.exists():
        data = json.loads(f.read_text(encoding="utf-8"))
        findings = {x.get("id"): x for x in data.get("findings", [])}
    cve = findings.get(cve_id, {"id": cve_id, "cvss": "?"})

    agent = DeepDiveAgent(client, llm_url=llm_url, model=model,
                          api_key=api_key, budget=budget, max_turns=max_turns)
    verdict = agent.run(cve, target)

    out = workspace / ("deepdive-" + cve_id + ".json")
    out.write_text(json.dumps(verdict, indent=2, ensure_ascii=False),
                   encoding="utf-8")

    print("\n[*] Deep-dive verdict for " + cve_id + " @ " + target)
    print("    verdict:     " + verdict.get("verdict", "?"))
    print("    evidence:    " + (verdict.get("evidence") or "")[:200])
    print("    tokens: " + str(verdict.get("tokens_used", 0)) +
          " | turns: " + str(verdict.get("turns", 0)) +
          " | " + str(verdict.get("duration_s", 0)) + "s")
    print("    saved: " + str(out))
    return verdict
