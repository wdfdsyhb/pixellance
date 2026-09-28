"""Nmap scanning and result parsing.

Uses HexStrike HTTP API for nmap execution (runs on Kali VM).
Parsing works on text output returned from API.
"""
import re
from pathlib import Path
from typing import Optional

from .client import HexStrikeClient, HexStrikeError
from .config import (
    HIGH_VALUE_TCP_PORTS, HIGH_VALUE_UDP_PORTS,
    SERVICE_ALIASES, HTTP_PORTS, HTTPS_PORTS,
)


class NmapScanner:
    """Run nmap via HexStrike and parse results into port-triggered files."""

    def __init__(self, workspace: Path, client: HexStrikeClient,
                 excludes: Optional[Path] = None):
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.client = client
        self.excludes = excludes
        self.raw_output = ""

    def full_scan(self, targets, fast=False, version=False, delay=0) -> bool:
        """Run comprehensive scan via HexStrike. Returns True if hosts alive."""
        targets = str(targets)
        # Read target file and pass IPs as comma-separated to HexStrike
        target_path = Path(targets)
        if target_path.is_file():
            hosts = [l.strip() for l in target_path.read_text(errors="replace").splitlines()
                     if l.strip() and not l.startswith("#")]
            if not hosts:
                print("[!] Target file is empty.")
                return False
            target_str = ",".join(hosts)
        else:
            target_str = targets
        print(f"[*] Running nmap scan via HexStrike ({target_str[:80]})...")

        try:
            if fast:
                output = self.client.nmap(
                    target_str,
                    extra="--top-ports 1000 -sT -sU --open -O --osscan-guess "
                         "--max-os-tries 1 --max-retries 2 "
                         "--max-rtt-timeout 1000ms --stats-every 20s",
                )
            else:
                tcp = ",".join(str(p) for p in HIGH_VALUE_TCP_PORTS)
                udp = ",".join(str(p) for p in HIGH_VALUE_UDP_PORTS)
                scan_t = "-sTV" if version else "-sT"
                scan_u = "-sUV" if version else "-sU"
                ports_arg = f"-p T:{tcp},U:{udp}"
                extra_parts = [
                    "--privileged", "-n", "-PE",
                    "-PS21,22,23,25,53,80,110,111,135,139,143,443,445,"
                    "993,995,1723,3306,3389,5900,8080",
                    "-PU53,67,68,69,123,135,137,138,139,161,162,445,500,"
                    "514,520,631,1434,1900,4500,49152",
                    scan_t, scan_u, ports_arg,
                    "-O", "--osscan-guess", "--max-os-tries", "1",
                    "--max-retries", "2", "--max-rtt-timeout", "1000ms",
                    "--min-rate", "450", "--max-rate", "5000",
                    "--open", "--stats-every", "20s",
                ]
                if self.excludes:
                    extra_parts += ["--excludefile", str(self.excludes)]
                if delay > 0:
                    extra_parts += ["--scan-delay", str(delay)]
                output = self.client.nmap(target_str, extra=" ".join(extra_parts))
        except HexStrikeError as e:
            print(f"[!] nmap scan failed: {e}")
            return False

        self.raw_output = output
        (self.workspace / "nmap.raw.txt").write_text(output, encoding="utf-8",
                                                      errors="replace")
        return "(0 hosts up)" not in output if output else False

    def parse_results(self) -> dict:
        """Parse nmap text output, split into per-port host files + banners."""
        content = self.raw_output
        if not content:
            raw_file = self.workspace / "nmap.raw.txt"
            if raw_file.exists():
                content = raw_file.read_text(errors="replace")
            else:
                return {}

        port_map: dict[str, list[str]] = {}
        hosts: list[str] = []
        http_urls: list[str] = []
        https_urls: list[str] = []
        banners: set[str] = set()
        current_host = ""

        for line in content.splitlines():
            # Match "Nmap scan report for <IP>"
            m = re.search(r"Nmap scan report for (.+)", line)
            if m:
                ip = m.group(1).strip()
                # Handle "hostname (IP)" format
                paren = re.search(r"\(([\d.]+)\)", ip)
                if paren:
                    ip = paren.group(1)
                current_host = ip
                if current_host not in hosts:
                    hosts.append(current_host)
                continue

            # Match port lines: "22/tcp  open  ssh  OpenSSH 10.3p1"
            pm = re.match(r"^(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)(.*)", line)
            if pm and current_host:
                port_num = pm.group(1)
                proto = pm.group(2)
                service = pm.group(4).strip()
                version = pm.group(5).strip() if pm.group(5) else ""

                port_map.setdefault(port_num, [])
                if current_host not in port_map[port_num]:
                    port_map[port_num].append(current_host)

                # Banner extraction
                if service and service != "unknown":
                    ver_str = f"{service} {version}".strip() if version else service
                    banners.add(f"{ver_str} @{current_host}:{port_num}")

                if proto == "tcp":
                    pn = int(port_num)
                    if pn in HTTP_PORTS:
                        http_urls.append(f"http://{current_host}:{port_num}")
                    elif pn in HTTPS_PORTS:
                        https_urls.append(f"https://{current_host}:{port_num}")

        if banners:
            (self.workspace / "banners.txt").write_text(
                "\n".join(sorted(banners)) + "\n", encoding="utf-8")
        if hosts:
            (self.workspace / "hosts.txt").write_text(
                "\n".join(hosts) + "\n", encoding="utf-8")
        if http_urls:
            (self.workspace / "http.txt").write_text(
                "\n".join(sorted(set(http_urls))) + "\n", encoding="utf-8")
        if https_urls:
            (self.workspace / "https.txt").write_text(
                "\n".join(sorted(set(https_urls))) + "\n", encoding="utf-8")

        for port, ip_list in port_map.items():
            (self.workspace / f"{port}.txt").write_text(
                "\n".join(sorted(set(ip_list))) + "\n", encoding="utf-8")

        for alias, ports in SERVICE_ALIASES.items():
            combined: list[str] = []
            for p in ports:
                combined.extend(port_map.get(str(p), []))
            if combined:
                (self.workspace / f"{alias}.txt").write_text(
                    "\n".join(sorted(set(combined))) + "\n", encoding="utf-8")

        print(f"[*] Found {len(hosts)} hosts, {len(port_map)} ports")
        return port_map
