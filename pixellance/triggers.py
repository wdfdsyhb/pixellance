"""
Port-triggered orchestration engine.

Each trigger defines: which port file → what action to run via HexStrike API.
Output is intelligently summarized to keep context manageable.
"""
import re
from pathlib import Path
from typing import Callable, Optional
from dataclasses import dataclass, field

from .client import HexStrikeClient, HexStrikeError


# --- output summarization ---

def _summarize_nmap(text: str, max_lines: int = 40) -> str:
    """Keep host summary lines, drop verbose per-probe noise."""
    if not text:
        return ""
    lines = text.splitlines()
    kept = []
    for line in lines:
        # Keep: host headers, port table rows, OS, scan summary
        if re.match(r"^Nmap scan report", line):
            kept.append(line)
        elif re.match(r"^\d+/tcp", line) or re.match(r"^\d+/udp", line):
            kept.append("  " + line.strip())
        elif re.match(r"^OS details:", line) or re.match(r"^Aggressive OS", line):
            kept.append(line)
        elif re.match(r"^Nmap done:", line):
            kept.append(line)
        elif "Host is" in line:
            kept.append(line)
        if len(kept) >= max_lines:
            kept.append(f"  ... ({len(lines)} total lines, truncated)")
            break
    return "\n".join(kept) if kept else text[:1000]


def _summarize_nuclei(text: str, max_findings: int = 20) -> str:
    """Keep only nuclei JSON finding lines, count totals."""
    if not text:
        return ""
    lines = text.splitlines()
    findings = []
    for line in lines:
        line = line.strip()
        if line.startswith('{"template') or line.startswith('{"template-ID"'):
            findings.append(line)
    if not findings:
        return text[:500]
    summary = findings[:max_findings]
    truncated = len(findings) - max_findings
    result = "\n".join(summary)
    if truncated > 0:
        result += f"\n... ({truncated} more findings, total {len(findings)})"
    return result


def _summarize_ffuf(text: str, max_lines: int = 30) -> str:
    """Keep ffuf result JSON lines."""
    if not text:
        return ""
    lines = [l for l in text.splitlines() if l.strip().startswith("{")]
    if not lines:
        return text[:500]
    shown = lines[:max_lines]
    result = "\n".join(shown)
    if len(lines) > max_lines:
        result += f"\n... ({len(lines) - max_lines} more results)"
    return result


def _summarize_generic(text: str, max_chars: int = 3000) -> str:
    """Generic fallback: truncate with indicator."""
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [{len(text)} chars total, truncated]"


# Tool name → summarizer
_SUMMARIZERS = {
    "nmap": _summarize_nmap,
    "nuclei": _summarize_nuclei,
    "ffuf": _summarize_ffuf,
    "gobuster": _summarize_ffuf,
}


def summarize_output(tool_name: str, raw_output: str) -> str:
    """Summarize tool output to keep it context-friendly."""
    summarizer = _SUMMARIZERS.get(tool_name)
    if summarizer:
        return summarizer(raw_output)
    return _summarize_generic(raw_output)


# --- data classes ---

@dataclass
class PortTrigger:
    """Defines what to run when a specific port is found open."""
    port_file: str              # e.g. "445.txt"
    name: str                   # human-readable name
    cmd: list[str] = field(default_factory=list)  # legacy, unused with API
    tool: str = ""              # HexStrike tool name (e.g. "nmap", "nuclei")
    tool_args: dict = field(default_factory=dict)  # tool-specific args
    condition: Optional[Callable[[Path], bool]] = None
    output_file: Optional[str] = None
    enabled: bool = True


@dataclass
class TriggerResult:
    port_file: str
    name: str
    success: bool
    returncode: int
    output: str = ""
    skipped: bool = False


class TriggerEngine:
    """Runs port-triggered actions via HexStrike API."""

    def __init__(self, workspace: Path, client: HexStrikeClient,
                 dry_run: bool = False):
        self.workspace = workspace
        self.client = client
        self.dry_run = dry_run
        self.triggers: list[PortTrigger] = []
        self.results: list[TriggerResult] = []

    def register(self, trigger: PortTrigger):
        """Register a new port trigger."""
        self.triggers.append(trigger)

    def register_tool(self, port_file: str, name: str, tool: str,
                     tool_args: dict, output_file: Optional[str] = None):
        """Convenience: register a HexStrike tool trigger."""
        self.triggers.append(PortTrigger(
            port_file=port_file,
            name=name,
            tool=tool,
            tool_args=tool_args,
            output_file=output_file,
        ))

    def run_all(self) -> list[TriggerResult]:
        """Execute all matching triggers via HexStrike API."""
        self.results = []

        for trigger in self.triggers:
            target = self.workspace / trigger.port_file

            # Port must be open (file must exist)
            if not target.exists():
                continue

            # Extra condition check
            if trigger.condition and not trigger.condition(target):
                continue

            if not trigger.enabled:
                self.results.append(TriggerResult(
                    port_file=trigger.port_file,
                    name=trigger.name,
                    success=False,
                    returncode=-1,
                    skipped=True,
                ))
                continue

            # Build args: resolve placeholders in tool_args
            args = {}
            for k, v in trigger.tool_args.items():
                if isinstance(v, str):
                    v = v.replace("{port_file}", str(target))
                    v = v.replace("{workspace}", str(self.workspace))
                args[k] = v

            # If target_file specified, read hosts and set as comma-separated target
            target_file = args.pop("target_file", None)
            if target_file:
                tf = Path(target_file)
                if tf.exists():
                    hosts = [l.strip() for l in tf.read_text(errors="replace").splitlines()
                             if l.strip() and not l.startswith("#")]
                    args["target"] = ",".join(hosts) if hosts else ""
                else:
                    # Target file not found — skip this trigger
                    continue

            print(f"    [{trigger.name}]")

            if self.dry_run:
                print(f"    $ {trigger.tool} {args}")
                self.results.append(TriggerResult(
                    port_file=trigger.port_file,
                    name=trigger.name,
                    success=True,
                    returncode=0,
                    output="[dry-run]",
                ))
                continue

            # Execute via HexStrike
            try:
                raw_output = self.client.extract_output(
                    self.client.call(trigger.tool, args)
                )
                output = summarize_output(trigger.tool, raw_output)

                # Save output
                if trigger.output_file:
                    out_path = self.workspace / trigger.output_file
                    out_path.write_text(raw_output, encoding="utf-8",
                                        errors="replace")
                    # Cleanup empty files
                    if out_path.stat().st_size == 0:
                        out_path.unlink()

                self.results.append(TriggerResult(
                    port_file=trigger.port_file,
                    name=trigger.name,
                    success=True,
                    returncode=0,
                    output=output[:500],
                ))

            except HexStrikeError as e:
                print(f"    [!] {e}")
                self.results.append(TriggerResult(
                    port_file=trigger.port_file,
                    name=trigger.name,
                    success=False,
                    returncode=-1,
                    output=str(e)[:200],
                ))

        return self.results

    def summary(self) -> str:
        """Print execution summary."""
        lines = ["", "=" * 60, "Trigger Execution Summary", "=" * 60]
        for r in self.results:
            status = "SKIP" if r.skipped else ("OK" if r.success else "FAIL")
            lines.append(f"  [{status:4}] {r.port_file:12} {r.name}")
        lines.append(f"\nTotal: {len(self.results)} triggers executed")
        return "\n".join(lines)
