"""Shodan enrichment — look up each discovered host for services, banners, CVEs.

Uses cve_mcp's shodan_client (SHODAN_KEY env var), falls back to a direct
API call if the package isn't importable.
"""
import ipaddress
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

SHODAN_API_BASE = "https://api.shodan.io"


def _is_public_ip(value: str) -> bool:
    """Only allow global (public) IP addresses into lookup URLs."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global


def _validate_api_host() -> bool:
    """Resolve the fixed API host and require all addresses to be global.
    Guards against DNS rebinding to private/loopback ranges."""
    import socket
    try:
        infos = socket.getaddrinfo("api.shodan.io", 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_global:
                return False
        except ValueError:
            return False
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _load_hosts(ws: Path, limit: int) -> list[str]:
    hosts_file = ws / "hosts.txt"
    if not hosts_file.exists():
        return []
    lines = [l.strip() for l in hosts_file.read_text().splitlines() if l.strip()]
    return [h for h in lines if _is_public_ip(h)][:limit]


def _direct_shodan_lookup(ip: str, api_key: str) -> dict | None:
    """Direct Shodan REST call. Host fixed; ip format-validated; no redirects."""
    if not _is_public_ip(ip) or not _validate_api_host():
        return None
    query = urllib.parse.urlencode({"key": api_key})
    url = SHODAN_API_BASE + "/shodan/host/" + ip + "?" + query
    try:
        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, method="GET")
        with opener.open(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def ws_cache_path() -> Path:
    """Shared cache db for enrichment data."""
    p = Path(os.environ.get("PIXELLANCE_HOME", str(Path.home() / ".pixellance")))
    p.mkdir(exist_ok=True)
    return p / "cache.db"


def _cve_mcp_lookup(ip: str, cache_path: Path) -> dict | None:
    """Lookup via cve_mcp.shodan_client (async wrapper)."""
    try:
        import asyncio
        import httpx
        from cve_mcp.api.shodan_client import shodan_host_lookup
        from cve_mcp.cache.sqlite_cache import VulnCache

        async def _run():
            cache = VulnCache(str(cache_path))
            await cache.initialize()
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    return await shodan_host_lookup(ip, client, cache)
            finally:
                if hasattr(cache, "close"):
                    await cache.close()

        return asyncio.run(_run())
    except Exception:
        return None


def enrich_hosts(ws: Path, limit: int = 100) -> dict:
    """Look up every host on Shodan. Returns {ip: shodan_data}."""
    api_key = os.environ.get("SHODAN_KEY") or os.environ.get("SHODAN_API_KEY", "")
    hosts = _load_hosts(ws, limit)
    results: dict = {}
    out_file = ws / "shodan-enrichment.json"
    cache_path = ws_cache_path()

    print("[*] Shodan enrichment for " + str(len(hosts)) + " hosts...")

    for ip in hosts:
        data = None
        if api_key:
            data = _direct_shodan_lookup(ip, api_key)
        else:
            data = _cve_mcp_lookup(ip, cache_path)

        if data and "error" not in data:
            vulns = data.get("vulns") or []
            if isinstance(vulns, dict):
                vulns = list(vulns.keys())
            results[ip] = {
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "country": data.get("country_name", ""),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "vulns": vulns,
                "cpes": list(data.get("cpes") or [])[:20],
                "banners_sample": [
                    {"port": b.get("port"), "product": b.get("product"),
                     "version": b.get("version"), "cpe": b.get("cpe", [])}
                    for b in (data.get("data") or [])[:10]
                ],
            }
            print("    " + ip + " — " + str(len(vulns)) + " CVEs, "
                  + str(len(results[ip]["ports"])) + " ports")
        else:
            print("    " + ip + " — no data / lookup failed")

    if results:
        out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print("[*] Saved: " + str(out_file))
    else:
        print("[!] No Shodan data collected (check SHODAN_KEY env var).")

    return results


def extract_cpes(ws: Path) -> list[str]:
    """Collect unique CPEs from Shodan enrichment for CVE matching."""
    f = ws / "shodan-enrichment.json"
    if not f.exists():
        return []
    data = json.loads(f.read_text())
    cpes: set[str] = set()
    for host in data.values():
        for c in host.get("cpes", []):
            if c:
                cpes.add(c)
        for b in host.get("banners_sample", []):
            for c in b.get("cpe", []) or []:
                if c:
                    cpes.add(c)
    return sorted(cpes)


def extract_products(ws: Path) -> list[str]:
    """Collect product:version pairs for NVD keyword search."""
    f = ws / "shodan-enrichment.json"
    if not f.exists():
        return []
    data = json.loads(f.read_text())
    products: set[str] = set()
    for host in data.values():
        for b in host.get("banners_sample", []):
            product = b.get("product") or ""
            version = b.get("version") or ""
            if product:
                products.add(product + (" " + version if version else ""))
    return sorted(products)
