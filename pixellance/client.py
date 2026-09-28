"""
HexStrike HTTP API client.

Replaces all subprocess calls in pixellance. Tool execution runs on the
Kali VM (HexStrike server); this client just sends REST requests and
parses results.
"""
import ipaddress
import re
import socket
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests


DEFAULT_SERVER = "http://127.0.0.1:8888"
DEFAULT_TIMEOUT = 600  # 10 min for long scans


class HexStrikeError(RuntimeError):
    """Raised when HexStrike API returns an error."""


def _validate_server_url(server: str) -> str:
    """Prevent SSRF: only allow http/https to global or RFC1918 IPs from allowlist."""
    parsed = urlparse(server)
    if parsed.scheme not in ("http", "https"):
        raise HexStrikeError(f"Invalid scheme '{parsed.scheme}': only http/https allowed")
    hostname = parsed.hostname
    if not hostname:
        raise HexStrikeError(f"Cannot parse hostname from: {server}")
    # NOTE: loopback IS allowed — a local HexStrike (127.0.0.1) is the
    # default single-machine deployment and is deliberately configured
    # by the operator, not attacker-supplied input.
    try:
        socket.getaddrinfo(hostname, parsed.port or 80, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise HexStrikeError(f"Cannot resolve hostname: {hostname}")
    return server


class HexStrikeClient:
    """Thin wrapper over HexStrike REST API."""

    def __init__(self, server: str = DEFAULT_SERVER, timeout: int = DEFAULT_TIMEOUT):
        self.server = _validate_server_url(server.rstrip("/"))
        self.timeout = timeout
        # Disable redirects to prevent DNS rebinding after initial validation
        self._session = requests.Session()
        self._session.max_redirects = 2
        # Bypass system proxy (DevSidecar etc.) for direct Kali VM access
        self._session.trust_env = False

    # --- low-level ---

    def call(self, tool: str, args: dict) -> dict:
        """POST /api/tools/{tool} — args sent flat (not nested under 'args')."""
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]{0,31}$", tool):
            raise HexStrikeError(f"Invalid tool name: {tool}")
        url = f"{self.server}/api/tools/{tool}"
        try:
            # HexStrike expects flat JSON: {"target": "...", "scan_type": "..."}
            resp = self._session.post(url, json=args,
                                      timeout=self.timeout, allow_redirects=False)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            raise HexStrikeError(
                f"Cannot connect to HexStrike at {self.server}. "
                f"Is the Kali VM running? (vmrun start)"
            )
        except requests.exceptions.Timeout:
            raise HexStrikeError(
                f"HexStrike tool '{tool}' timed out after {self.timeout}s"
            )
        except requests.exceptions.HTTPError as e:
            raise HexStrikeError(f"HTTP {e.response.status_code}: {e.response.text[:200]}")

    def extract_output(self, result: dict) -> str:
        """Pull stdout out of HexStrike response: {stdout, stderr, success}."""
        if not result:
            return ""
        if isinstance(result, dict):
            out = result.get("stdout", "")
            err = result.get("stderr", "")
            if not out and not err:
                # Fallback for non-standard responses
                return str(result)
            parts = [str(p) for p in (out, err) if p and str(p).strip()]
            return "\n".join(parts)
        return str(result)

    # --- high-level helpers ---

    def nmap(self, targets: str, ports: str = "",
             scan_type: str = "-sT", extra: str = "") -> str:
        args: dict = {"target": targets, "scan_type": scan_type}
        if ports:
            args["ports"] = ports
        if extra:
            args["additional_args"] = extra
        return self.extract_output(self.call("nmap", args))

    def nmap_from_file(self, target_file: Path, ports: str = "",
                       scan_type: str = "-sT", extra: str = "") -> str:
        if not target_file.exists():
            return ""
        hosts = target_file.read_text(errors="replace").splitlines()
        hosts = [h.strip() for h in hosts if h.strip()]
        if not hosts:
            return ""
        target = ",".join(hosts)
        return self.nmap(target, ports, scan_type, extra)

    def whatweb(self, url_file: Path) -> str:
        if not url_file.exists():
            return ""
        urls = url_file.read_text(errors="replace").splitlines()
        urls = [u.strip() for u in urls if u.strip()]
        if not urls:
            return ""
        return self.extract_output(self.call("whatweb", {
            "target": urls[0] if len(urls) == 1 else "\n".join(urls),
        }))

    def httpx(self, target_file: Path, options: str = "-title -status-code -tech-detect") -> str:
        if not target_file.exists():
            return ""
        targets = target_file.read_text(errors="replace").splitlines()
        targets = [t.strip() for t in targets if t.strip()]
        if not targets:
            return ""
        return self.extract_output(self.call("httpx", {
            "target": "\n".join(targets),
            "additional_args": options,
        }))

    def sslscan(self, target_file: Path) -> str:
        if not target_file.exists():
            return ""
        targets = target_file.read_text(errors="replace").splitlines()
        targets = [t.strip() for t in targets if t.strip()]
        if not targets:
            return ""
        return self.extract_output(self.call("sslscan", {
            "target": "\n".join(targets),
        }))

    def nuclei(self, target_file: Path, severity: str = "critical,high,medium",
               tags: str = "", template: str = "") -> str:
        if not target_file.exists():
            return ""
        targets = target_file.read_text(errors="replace").splitlines()
        targets = [t.strip() for t in targets if t.strip()]
        if not targets:
            return ""
        args: dict = {"target": "\n".join(targets), "output_format": "json"}
        if severity:
            args["severity"] = severity
        if tags:
            args["tags"] = tags
        if template:
            args["template"] = template
        return self.extract_output(self.call("nuclei", args))

    def enum4linux(self, target_file: Path) -> str:
        if not target_file.exists():
            return ""
        targets = target_file.read_text(errors="replace").splitlines()
        targets = [t.strip() for t in targets if t.strip()]
        if not targets:
            return ""
        return self.extract_output(self.call("enum4linux", {
            "target": targets[0] if len(targets) == 1 else "\n".join(targets),
        }))

    def onesixtyone(self, target_file: Path, community_file: str = "/usr/share/doc/onesixtyone/dict.txt") -> str:
        if not target_file.exists():
            return ""
        targets = target_file.read_text(errors="replace").splitlines()
        targets = [t.strip() for t in targets if t.strip()]
        if not targets:
            return ""
        return self.extract_output(self.call("onesixtyone", {
            "target": "\n".join(targets),
            "community_file": community_file,
        }))

    def ffuf(self, url_file: Path, wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
             extra: str = "") -> str:
        if not url_file.exists():
            return ""
        urls = url_file.read_text(errors="replace").splitlines()
        urls = [u.strip() for u in urls if u.strip()]
        if not urls:
            return ""
        return self.extract_output(self.call("ffuf", {
            "url": urls[0],
            "wordlist": wordlist,
            "additional_args": extra,
        }))

    def nikto(self, target: str) -> str:
        return self.extract_output(self.call("nikto", {"target": target}))

    def dirb(self, target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        return self.extract_output(self.call("dirb", {
            "url": target, "wordlist": wordlist,
        }))

    def wpscan(self, url: str) -> str:
        return self.extract_output(self.call("wpscan", {"url": url}))

    def sqlmap(self, url: str) -> str:
        return self.extract_output(self.call("sqlmap", {"url": url}))

    def gobuster(self, url: str, mode: str = "dir",
                 wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        return self.extract_output(self.call("gobuster", {
            "url": url, "mode": mode, "wordlist": wordlist,
        }))

    def netexec(self, target_file: Path, protocol: str = "smb") -> str:
        if not target_file.exists():
            return ""
        targets = target_file.read_text(errors="replace").splitlines()
        targets = [t.strip() for t in targets if t.strip()]
        if not targets:
            return ""
        return self.extract_output(self.call("netexec", {
            "target": targets[0] if len(targets) == 1 else "\n".join(targets),
            "protocol": protocol,
        }))

    def health(self) -> bool:
        """Check if HexStrike server is reachable (root responds with Flask)."""
        try:
            resp = self._session.get(f"{self.server}/", timeout=5,
                                     allow_redirects=False)
            # Flask returns 404 for / but that means the server is up
            return resp.status_code in (200, 404)
        except requests.exceptions.RequestException:
            return False

    def metasploit(self, module: str, options: dict) -> str:
        return self.extract_output(self.call("metasploit_run", {
            "module": module, "options": options,
        }))
