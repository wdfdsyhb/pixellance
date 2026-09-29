"""MCP server for pixellance.

Exposes the 8 CLI subcommands as MCP tools so any MCP-capable agent
(ZCode, Claude Code, Codex, ...) can drive scans, reports and handoffs.

Design: each tool shells out to `python -m pixellance <subcommand>` and
returns the CLI output verbatim. This keeps one code path — the CLI's
health checks, scope guards and state handling all apply unchanged.

Run:  pixellance-mcp            (console script)
  or: python -m pixellance.mcp_server
"""
import os
import subprocess
import sys

from fastmcp import FastMCP

SHORT_TIMEOUT = 120        # history/session/report/cve/handoff/rerun
LONG_TIMEOUT = 1800        # scan / deepdive (real scans take a while)
MAX_OUTPUT = 50_000        # truncate huge CLI dumps

mcp = FastMCP(
    "pixellance",
    instructions=(
        "Port-triggered pentest orchestration on top of a HexStrike backend. "
        "Workflow: pixellance_scan (dry-run first!) -> pixellance_cve / "
        "pixellance_session -> pixellance_handoff for PentAGI briefing. "
        "Only scan targets you are explicitly authorized to test."
    ),
)


def _run(args: list[str], timeout: int) -> str:
    """Run pixellance CLI as a subprocess, return combined output."""
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONSAFEPATH"] = "0"
    cmd = [sys.executable, "-m", "pixellance"] + args
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        return f"[pixellance-mcp] timed out after {timeout}s: {' '.join(args)}"
    out = (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr.strip() else "")
    if proc.returncode != 0:
        out = f"[exit {proc.returncode}]\n{out}"
    if len(out) > MAX_OUTPUT:
        out = out[:MAX_OUTPUT] + f"\n...[truncated, {len(out)} chars total]"
    return out.strip() or "(no output)"


def _flags(**kw) -> list[str]:
    """Turn {flag: True} kwargs into CLI flags."""
    out = []
    for k, v in kw.items():
        if v is True:
            out.append(f"--{k.replace('_','-')}")
    return out


# ---------------- scan ----------------

@mcp.tool
def pixellance_scan(
    targets: str,
    name: str | None = None,
    profile: str = "standard",
    fast: bool = False,
    version: bool = False,
    delay: int = 0,
    msf: bool = False,
    run_msf: bool = False,
    shodan: bool = False,
    cve: bool = False,
    nuclei_auto: bool = False,
    dry_run: bool = False,
    server: str | None = None,
) -> str:
    """Run nmap scan + triggered exploits via HexStrike. LONG-RUNNING (up to 30 min).
    Always do a dry_run=True pass first. Only authorized targets.

    Args:
        targets: path to target file (IPs/CIDRs, one per line)
        name: scan name (default: scan-<timestamp>)
        profile: trigger profile - standard | web | full
        fast: top-1000 ports only
        version: enable service version detection
        delay: inter-packet delay 0-5s (stealth)
        msf: generate Metasploit resource script
        run_msf: also EXECUTE msf modules (destructive, think twice)
        shodan: enrich hosts via Shodan
        cve: correlate fingerprints with NVD/KEV/EPSS/PoC
        nuclei_auto: tech-aware nuclei template selection
        dry_run: show what would run, execute nothing
        server: HexStrike base URL override
    """
    args = ["scan", str(targets)]
    if name:
        args += ["-n", name]
    args += ["-p", profile]
    args += _flags(fast=fast, version=version, msf=msf, run_msf=run_msf,
                   shodan=shodan, cve=cve, nuclei_auto=nuclei_auto, dry_run=dry_run)
    if delay:
        args += ["-d", str(delay)]
    if server:
        args += ["--server", server]
    return _run(args, LONG_TIMEOUT)


# ---------------- history / session ----------------

@mcp.tool
def pixellance_history(limit: int = 20) -> str:
    """List past scan sessions (id, name, date, findings count)."""
    return _run(["history", "-l", str(limit)], SHORT_TIMEOUT)


@mcp.tool
def pixellance_session(session_id: int) -> str:
    """Show full details of one scan session by ID."""
    return _run(["session", str(session_id)], SHORT_TIMEOUT)


# ---------------- rerun / report / cve ----------------

@mcp.tool
def pixellance_rerun(workspace: str, profile: str = "standard") -> str:
    """Re-run trigger engines on an existing scan workspace.

    Args:
        workspace: path to the scan workspace directory
        profile: standard | web | full
    """
    return _run(["rerun", str(workspace), "-p", profile], SHORT_TIMEOUT)


@mcp.tool
def pixellance_report(workspace: str, port: int = 17322) -> str:
    """Generate HTML/markdown report for a workspace and start the web dashboard."""
    return _run(["report", str(workspace), "--port", str(port)], SHORT_TIMEOUT)


@mcp.tool
def pixellance_cve(workspace: str) -> str:
    """Correlate a workspace's service fingerprints with NVD/KEV/EPSS/PoC data."""
    return _run(["cve", str(workspace)], SHORT_TIMEOUT)


# ---------------- handoff / deepdive ----------------

@mcp.tool
def pixellance_handoff(workspace: str, outdir: str | None = None,
                       print_md: bool = False) -> str:
    """Convert a workspace into a facts-based PentAGI flow briefing (markdown)."""
    args = ["handoff", str(workspace)]
    if outdir:
        args += ["-o", str(outdir)]
    if print_md:
        args.append("--print")
    return _run(args, SHORT_TIMEOUT)


@mcp.tool
def pixellance_deepdive(
    workspace: str,
    cve: str | None = None,
    target: str | None = None,
    llm: str | None = None,
    model: str | None = None,
    budget: int = 50000,
    turns: int = 8,
    server: str | None = None,
) -> str:
    """Bounded LLM-agent deep-dive on ONE high-value finding (Path B).
    LONG-RUNNING. Scope-locked to the given target.

    Args:
        workspace: scan workspace path
        cve: CVE id to verify, e.g. CVE-2021-41773
        target: host owning the finding (scope-locked)
        llm: OpenAI-compatible base URL (default local Ollama :11434/v1)
        model: model name (default qwen2.5:7b)
        budget: max total LLM tokens
        turns: max agent turns
        server: HexStrike base URL override
    """
    args = ["deepdive", str(workspace), "--budget", str(budget),
            "--turns", str(turns)]
    if cve:
        args += ["--cve", cve]
    if target:
        args += ["--target", target]
    if llm:
        args += ["--llm", llm]
    if model:
        args += ["--model", model]
    if server:
        args += ["--server", server]
    return _run(args, LONG_TIMEOUT)


if __name__ == "__main__":
    mcp.run()


def run():
    """Console-script entry point (pixellance-mcp)."""
    mcp.run()
