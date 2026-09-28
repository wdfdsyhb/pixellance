"""PixelLance -> PentAGI handoff.

Converts a PixelLance workspace (recon facts + CVE findings) into a
PentAGI flow input: a facts-based task briefing that lets the generator
agent skip its blind-exploration phase and plan directly from evidence.

Path A of the complementarity design: PixelLance = deterministic recon
front-end, PentAGI = autonomous deep-dive back-end.
"""
import json
import re
from pathlib import Path

# CVE priority tiers for the directive section
KEV_TIER = 0
HIGH_TIER = 1


def _read_lines(ws: Path, name: str) -> list[str]:
    f = ws / name
    if not f.exists():
        return []
    return [l.strip() for l in f.read_text(encoding="utf-8", errors="replace")
            .splitlines() if l.strip()]


def _collect_hosts(ws: Path) -> list[dict]:
    """host -> {ports: [(port/proto/service)], services: [strings]}"""
    hosts: dict[str, dict] = {}
    for f in sorted(ws.glob("*.txt")):
        name = f.stem
        # per-port files: "22.txt" / "523-tcp.txt" / aliases like "smtp.txt"
        m = re.match(r"^(\d+)(?:-(tcp|udp))?$", name)
        if m:
            port, proto = m.group(1), m.group(2) or "tcp"
            for line in _read_lines(ws, f.name):
                entry = hosts.setdefault(line, {"ports": [], "services": []})
                p = (int(port), proto)
                if p not in entry["ports"]:
                    entry["ports"].append(p)
        elif name == "hosts":
            for line in _read_lines(ws, "hosts.txt"):
                hosts.setdefault(line, {"ports": [], "services": []})

    # service names from gnmap (port/proto -> service)
    gnmap = ws / "nmap.gnmap"
    if gnmap.exists():
        svc_map: dict[tuple[int, str], str] = {}
        for line in gnmap.read_text(errors="replace").splitlines():
            pm = re.search(r"Ports:\s+(.+?)(?:\t|$)", line)
            if not pm:
                continue
            for info in pm.group(1).split(", "):
                im = re.match(r"(\d+)/open/(tcp|udp)//([^/]*)/", info.strip())
                if im and im.group(3):
                    svc_map[(int(im.group(1)), im.group(2))] = im.group(3)
        for host in hosts.values():
            for port, proto in host["ports"]:
                svc = svc_map.get((port, proto))
                if svc:
                    host["services"].append(f"{port}/{proto} {svc}")
    return [ {"ip": ip, **data} for ip, data in sorted(hosts.items()) ]


def _collect_tech(ws: Path) -> list[str]:
    """Tech fingerprints from whatweb output."""
    techs: set[str] = set()
    for line in _read_lines(ws, "script-http-whatweb.txt"):
        for m in re.finditer(r"([A-Za-z][A-Za-z0-9._-]+)\[", line):
            t = m.group(1)
            if t.lower() not in ("http", "https"):
                techs.add(t)
    return sorted(techs)


def _load_cves(ws: Path) -> list[dict]:
    f = ws / "cve-findings.json"
    if not f.exists():
        return []
    data = json.loads(f.read_text(encoding="utf-8"))
    return data.get("findings", [])


def _tier(cve: dict) -> int:
    return KEV_TIER if cve.get("kev") else HIGH_TIER


def build_context(ws: Path) -> dict:
    """Machine-readable engagement context (for upload as flow resource)."""
    return {
        "generated_by": "pixellance handoff",
        "hosts": _collect_hosts(ws),
        "technologies": _collect_tech(ws),
        "cves": _load_cves(ws),
    }


def build_markdown(ws: Path, lang: str = "en") -> str:
    """Human-readable task briefing to paste as PentAGI flow input."""
    ctx = build_context(ws)
    hosts = ctx["hosts"]
    techs = ctx["technologies"]
    cves = ctx["cves"]
    kev = [c for c in cves if c.get("kev")]
    hot = [c for c in cves if c.get("poc") and not c.get("kev")]

    lines: list[str] = []
    lines.append("# Authorized penetration testing engagement")
    lines.append("")
    lines.append("A recon scan has ALREADY been completed against the scoped targets.")
    lines.append("All facts below are verified scan output — treat them as ground truth")
    lines.append("and do NOT spend subtasks rediscovering them.")
    lines.append("")
    lines.append("## Scope (STRICT — touch nothing outside this list)")
    lines.append("")
    for h in hosts:
        ports = ", ".join(f"{p}/{pr}" for p, pr in h["ports"]) or "none"
        lines.append(f"- {h['ip']} — open: {ports}")
    lines.append("")
    if techs:
        lines.append("## Verified technology fingerprints")
        lines.append("")
        lines.append(", ".join(techs))
        lines.append("")
    if cves:
        lines.append("## Prioritized CVEs (deterministic NVD/KEV/EPSS/PoC correlation)")
        lines.append("")
        lines.append("| CVE | CVSS | EPSS | Flags | Description |")
        lines.append("|-----|------|------|-------|-------------|")
        for c in sorted(cves, key=lambda c: (_tier(c), -c.get("cvss", 0.0))):
            flags = []
            if c.get("kev"):
                flags.append("KEV")
            if c.get("poc"):
                flags.append("PoC")
            epss = c.get("epss")
            lines.append("| {id} | {cvss} | {epss} | {flags} | {desc} |".format(
                id=c.get("id", ""),
                cvss=c.get("cvss", 0) or "-",
                epss="{:.2f}".format(epss) if epss else "-",
                flags=",".join(flags) or "-",
                desc=(c.get("description") or "")[:80],
            ))
        lines.append("")
    lines.append("## Mission")
    lines.append("")
    mission: list[str] = []
    if kev:
        mission.append("**Verify the KEV-listed CVEs above** against the matching "
                       "hosts (safe proof-of-concept first, non-destructive checks only).")
    if hot:
        mission.append("For CVEs with known public PoC, validate exploitability manually.")
    mission.append("For each verified vulnerability, produce: evidence, impact, "
                   "and a minimal reproduction step list.")
    mission.append("Do NOT scan or attack hosts outside the scope list.")
    mission.append("Stop and report if a verification would be destructive "
                   "(DoS, data destruction, ransomware-style behavior).")
    for i, item in enumerate(mission, 1):
        lines.append(f"{i}. {item}")
    lines.append("")
    lines.append("## Expected deliverable")
    lines.append("")
    lines.append("A per-CVE verification result table: confirmed / not vulnerable /")
    lines.append("inconclusive, with evidence for each verdict and a final prioritized")
    lines.append("remediation list.")
    lines.append("")
    return "\n".join(lines)


def make_handoff(ws: Path, outdir: Path | None = None) -> tuple[Path, Path]:
    """Write pentagi-task.md + pentagi-context.json. Returns their paths."""
    outdir = outdir or ws
    outdir.mkdir(parents=True, exist_ok=True)

    md_path = outdir / "pentagi-task.md"
    md_path.write_text(build_markdown(ws), encoding="utf-8")

    ctx_path = outdir / "pentagi-context.json"
    ctx_path.write_text(
        json.dumps(build_context(ws), indent=2, ensure_ascii=False),
        encoding="utf-8")
    return md_path, ctx_path
