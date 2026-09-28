"""Technology-aware nuclei template selection.

Parses whatweb/httpx output for technology fingerprints, then maps
them to the right nuclei template tags — instead of blindly running
all templates against every target.

Now uses HexStrike API for execution; this module returns tool_specs
(dict) that TriggerEngine can register directly.
"""
import json
import re
from pathlib import Path

# tech fingerprint (lowercase) -> nuclei template tags
TECH_TEMPLATE_MAP = {
    "wordpress": ["wordpress", "wp-plugin", "wp-theme", "cms"],
    "joomla": ["joomla", "cms"],
    "drupal": ["drupal", "cms"],
    "magento": ["magento", "ecommerce"],
    "shopify": ["shopify", "ecommerce"],
    "tomcat": ["tomcat", "apache"],
    "jenkins": ["jenkins", "ci"],
    "gitlab": ["gitlab", "vcs"],
    "gitea": ["gitea", "vcs"],
    "kibana": ["kibana", "elastic"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "grafana": ["grafana", "dashboard"],
    "kubernetes": ["kubernetes", "k8s"],
    "docker": ["docker", "container"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis", "microsoft"],
    "sharepoint": ["sharepoint", "microsoft"],
    "exchange": ["exchange", "microsoft", "owa"],
    "owa": ["owa", "microsoft"],
    "weblogic": ["weblogic", "oracle"],
    "jboss": ["jboss"],
    "struts": ["struts", "apache"],
    "spring": ["spring", "springboot"],
    "springboot": ["springboot", "actuator"],
    "thinkphp": ["thinkphp"],
    "phpunit": ["phpunit"],
    "phpmyadmin": ["phpmyadmin", "db-admin"],
    "adminer": ["adminer", "db-admin"],
    "mongodb": ["mongodb"],
    "mysql": ["mysql"],
    "postgresql": ["postgres"],
    "redis": ["redis"],
    "vmware": ["vmware", "vsphere"],
    "v_center": ["vmware", "vcenter"],
    "vsphere": ["vmware", "vsphere"],
    "citrix": ["citrix"],
    "cisco": ["cisco"],
    "fortinet": ["fortinet", "fortigate"],
    "sonicwall": ["sonicwall"],
    "palo-alto": ["paloalto"],
    "zabbix": ["zabbix"],
    "nagios": ["nagios"],
    "sonarqube": ["sonarqube"],
    "jira": ["jira", "atlassian"],
    "confluence": ["confluence", "atlassian"],
    "bitbucket": ["bitbucket", "atlassian"],
    "minio": ["minio"],
    "harbor": ["harbor"],
    "nexus": ["sonatype"],
    "artifactory": ["jfrog"],
    "next.js": ["nextjs"],
}

# default tags when no tech detected
DEFAULT_TAGS = ["critical", "high"]


def _parse_whatweb(ws: Path) -> list[str]:
    """Extract technologies from whatweb output (script-http-whatweb.txt)."""
    techs: set[str] = set()
    f = ws / "script-http-whatweb.txt"
    if not f.exists():
        return []
    for line in f.read_text(errors="replace").splitlines():
        for m in re.finditer(r"([A-Za-z][A-Za-z0-9._-]+)\[", line):
            tech = m.group(1).lower()
            if tech not in ("http", "https"):
                techs.add(tech)
    return sorted(techs)


def _parse_httpx(ws: Path) -> list[str]:
    """Extract technologies from httpx JSON output (script-httpx.txt)."""
    techs: set[str] = set()
    f = ws / "script-httpx.txt"
    if not f.exists():
        return []
    for line in f.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        for t in data.get("tech", []) or data.get("technologies", []) or []:
            techs.add(t.lower())
        server = data.get("webserver", "") or ""
        if server:
            techs.add(server.split("/")[0].lower())
    return sorted(techs)


def _parse_nmap_banners(ws: Path) -> list[str]:
    """Extract product names from nmap banners.txt."""
    techs: set[str] = set()
    f = ws / "banners.txt"
    if not f.exists():
        return []
    for line in f.read_text(errors="replace").splitlines():
        for known in TECH_TEMPLATE_MAP:
            if known in line.lower():
                techs.add(known)
    return sorted(techs)


def select_templates(ws: Path) -> dict:
    """Detect technologies and return nuclei template selection plan."""
    techs: set[str] = set()
    techs.update(_parse_whatweb(ws))
    techs.update(_parse_httpx(ws))
    techs.update(_parse_nmap_banners(ws))

    tags: set[str] = set()
    template_ids: set[str] = set()

    for tech in techs:
        mapping = TECH_TEMPLATE_MAP.get(tech)
        if mapping:
            tags.update(t for t in mapping if t)

    tags.update(DEFAULT_TAGS)

    # Tech-specific known-vuln template IDs
    tech_to_template_ids = {
        "wordpress": ["wp-plugin-detect"],
        "jenkins": ["CVE-2024-23897"],
        "confluence": ["CVE-2023-22518"],
        "exchange": ["proxyshell", "proxylogon"],
        "vmware": ["CVE-2022-22954"],
    }
    for tech in techs:
        for tid in tech_to_template_ids.get(tech, []):
            template_ids.add(tid)

    return {
        "techs": sorted(techs),
        "tags": sorted(tags),
        "template_ids": sorted(template_ids),
        "targets": {
            "http": str(ws / "http.txt") if (ws / "http.txt").exists() else None,
            "https": str(ws / "https.txt") if (ws / "https.txt").exists() else None,
        },
    }


def build_nuclei_commands(ws: Path) -> list[dict]:
    """Build nuclei tool specs for HexStrike API.

    Returns list of dicts, each containing target_file + nuclei args.
    The profile loader extracts target_file as the port_file trigger key.
    """
    plan = select_templates(ws)
    commands = []

    for proto, target_path in plan["targets"].items():
        if not target_path:
            continue
        target_name = Path(target_path).name  # "http.txt" or "https.txt"
        args: dict = {
            "target_file": target_name,
            "severity": "critical,high,medium",
            "output_format": "json",
        }
        if plan["tags"]:
            args["tags"] = ",".join(plan["tags"])
        if plan["template_ids"]:
            args["template"] = ",".join(plan["template_ids"])
        commands.append(args)

    return commands


def run_nuclei_direct(ws: Path, client, severity: str = "critical,high,medium",
                      tags: str = "") -> str:
    """Run nuclei via HexStrike API directly (without trigger system)."""
    for fname in ("http.txt", "https.txt"):
        target = ws / fname
        if not target.exists():
            continue
        args = {
            "target_file": fname,
            "severity": severity,
            "output_format": "json",
        }
        if tags:
            args["tags"] = tags
        # Engine resolves target_file → target
        try:
            raw = client.extract_output(client.call("nuclei", args))
            out_path = ws / f"script-nuclei-{fname.replace('.txt', '')}.json"
            out_path.write_text(raw, encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"[!] nuclei on {fname}: {e}")


def summary(ws: Path) -> str:
    """Human-readable template selection summary."""
    plan = select_templates(ws)
    lines = [
        "",
        "=" * 60,
        "Nuclei Template Selection",
        "=" * 60,
        "  Detected tech: " + (", ".join(plan["techs"]) or "none"),
        "  Template tags: " + (", ".join(plan["tags"]) or "default"),
        "  Template IDs:  " + (", ".join(plan["template_ids"]) or "none"),
        "  Targets:       " + str([v for v in plan["targets"].values() if v]),
    ]
    return "\n".join(lines)
