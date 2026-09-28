"""CVE correlation engine.

Pipeline: detected products/CPEs → NVD keyword search → KEV check →
EPSS score → PoC availability. Produces a prioritized attack-surface list.

Uses cve_mcp's async API directly (nvd_client, kev_client, epss_client,
poc_checker) with its shared sqlite cache and rate limiter.
"""
import asyncio
import ipaddress
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

# Fixed NVD endpoint — protocol and host are constants, never user input.
NVD_BASE = "https://services.nvd.nist.gov"

MAX_QUERIES = 25
MAX_CVES_PER_QUERY = 5
MIN_CVSS_TO_REPORT = 7.0


def _validate_nvd_host() -> bool:
    """Resolve the fixed NVD host; require all addresses to be global."""
    import socket
    try:
        infos = socket.getaddrinfo("services.nvd.nist.gov", 443,
                                   proto=socket.IPPROTO_TCP)
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


def _nvd_cpe_search(cpe: str, api_key: str) -> list[dict]:
    """CPE-exact NVD search. Pull 50, keep CVSS>=MIN client-side.
    CPE queries hit the right products (unlike noisy keyword search)."""
    if not _validate_nvd_host():
        return []
    params = urllib.parse.urlencode({"cpeName": cpe, "resultsPerPage": 50})
    url = NVD_BASE + "/rest/json/cves/2.0?" + params
    headers = {"apiKey": api_key} if api_key else {}
    try:
        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, headers=headers, method="GET")
        with opener.open(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return []

    out = []
    for item in (data.get("vulnerabilities") or []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        cvss = 0.0
        try:
            cvss = float(cve["metrics"]["cvssMetricV31"][0]
                         ["cvssData"]["baseScore"])
        except (KeyError, IndexError, TypeError, ValueError):
            pass
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:200]
                break
        if cvss < MIN_CVSS_TO_REPORT:
            continue
        out.append({"id": cve_id, "query": "cpe:" + cpe.rsplit(":", 4)[0],
                    "cvss": cvss, "description": desc})
    out.sort(key=lambda f: -f["cvss"])
    return out[:MAX_CVES_PER_QUERY]


def _relax_query(query: str) -> str | None:
    """Drop trailing version-like tokens ('Apache 2.4.49' -> 'Apache').
    NVD keyword search rarely matches full version strings."""
    words = query.split()
    while len(words) > 1 and re.match(r"^[0-9]", words[-1]):
        words.pop()
    relaxed = " ".join(words)
    return relaxed if relaxed != query else None


def _nvd_keyword_search(query: str, api_key: str) -> dict | None:
    """One NVD keyword query. Query value is URL-encoded; host is fixed.
    Auto-retries with relaxed query when the precise one hits nothing."""
    if not _validate_nvd_host():
        return None
    headers = {"apiKey": api_key} if api_key else {}
    opener = urllib.request.build_opener(_NoRedirect)

    q = query
    for attempt in range(2):
        # NOTE: no cvssV31Severity here — NVD errors (empty body) when it is
        # combined with keywordSearch; filter client-side instead
        params = urllib.parse.urlencode({
            "keywordSearch": q,
            "resultsPerPage": MAX_CVES_PER_QUERY,
        })
        url = NVD_BASE + "/rest/json/cves/2.0?" + params
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with opener.open(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            return None
        if (data.get("totalResults") or 0) > 0 or attempt == 1:
            return data
        q = _relax_query(q) or q


def _cve_mcp_available() -> bool:
    try:
        import cve_mcp  # noqa: F401
        import httpx  # noqa: F401
        import aiosqlite  # noqa: F401
        return True
    except ImportError:
        return False


def _gather_queries(ws: Path) -> list[str]:
    """Build NVD keyword queries from all fingerprint sources."""
    queries: list[str] = []

    # 1. Shodan CPEs (highest precision)
    try:
        from .shodan import extract_cpes
        for cpe in extract_cpes(ws):
            parts = cpe.split(":")
            if len(parts) >= 5 and parts[0] == "cpe":
                product = parts[4].replace("_", " ")
                version = parts[5] if len(parts) > 5 else ""
                q = product + (" " + version if version else "")
                if q not in queries:
                    queries.append(q)
    except Exception:
        pass

    # 2. Shodan product banners
    try:
        from .shodan import extract_products
        for p in extract_products(ws):
            if p not in queries:
                queries.append(p)
    except Exception:
        pass

    # 3. Nmap banners.txt — format "Product version @ip:port"
    banners = ws / "banners.txt"
    if banners.exists():
        for line in banners.read_text(errors="replace").splitlines():
            fingerprint = line.split("@")[0].strip()
            words = fingerprint.split()[:3]
            if words:
                q = " ".join(words)
                if q not in queries:
                    queries.append(q)

    # 4. whatweb tech name + version
    whatweb_out = ws / "script-http-whatweb.txt"
    if whatweb_out.exists():
        for line in whatweb_out.read_text(errors="replace").splitlines():
            for m in re.finditer(r"([A-Za-z][A-Za-z0-9._-]+)\[([0-9][^]]*)\]", line):
                q = m.group(1) + " " + m.group(2).split()[0]
                if q not in queries:
                    queries.append(q)

    return queries[:MAX_QUERIES]


async def _correlate_async(queries: list[str], cache_path: Path,
                           seed_findings: list[dict] | None = None) -> list[dict]:
    """Run the full NVD→KEV→EPSS→PoC pipeline. CPE seeds get enriched too."""
    import httpx
    from cve_mcp.api.nvd_client import search_nvd
    from cve_mcp.api.kev_client import fetch_kev_catalog, lookup_kev
    from cve_mcp.api.epss_client import get_epss
    from cve_mcp.api.poc_checker import search_poc_existence
    from cve_mcp.api.rate_limiter import TokenBucketRateLimiter
    from cve_mcp.cache.sqlite_cache import VulnCache
    from cve_mcp.config import NVD_RATE, NVD_BURST

    cache = VulnCache(str(cache_path))
    await cache.initialize()
    limiter = TokenBucketRateLimiter(NVD_RATE, NVD_BURST)

    # CPE-exact findings come in as seeds; keyword phase adds more
    findings: dict[str, dict] = {f["id"]: dict(f) for f in (seed_findings or [])}
    try:
        async with httpx.AsyncClient(timeout=40) as client:
            # Phase 1: NVD keyword search (with relax-retry on zero hits)
            for q in queries:
                tried = [q]
                relaxed = _relax_query(q)
                if relaxed:
                    tried.append(relaxed)
                results = []
                for attempt_q in tried:
                    try:
                        results = await search_nvd(
                            query=attempt_q, severity="HIGH",
                            limit=MAX_CVES_PER_QUERY,
                            client=client, limiter=limiter, cache=cache,
                        ) or []
                    except Exception:
                        results = []
                    if results:
                        break
                for cve in results or []:
                    cve_id = cve.get("id") or ""
                    if not cve_id or cve_id in findings:
                        continue
                    cvss = 0.0
                    try:
                        v31 = (cve.get("metrics") or {}).get("cvssMetricV31", [])
                        if v31:
                            cvss = float(v31[0]["cvssData"]["baseScore"])
                    except (KeyError, IndexError, TypeError, ValueError):
                        pass
                    desc = ""
                    if cve.get("descriptions"):
                        desc = cve["descriptions"][0].get("value", "")[:200]
                    findings[cve_id] = {"id": cve_id, "query": q,
                                        "cvss": cvss, "description": desc}

            # Phase 2: KEV check
            try:
                kev_catalog = await fetch_kev_catalog(client, cache)
                for f in findings.values():
                    entry = lookup_kev(kev_catalog, f["id"])
                    if entry:
                        f["kev"] = True
                        f["kev_due"] = entry.dueDate
                        f["ransomware_use"] = entry.knownRansomwareCampaignUse
            except Exception:
                pass

            # Phase 3: EPSS
            try:
                for e in await get_epss(list(findings.keys()), client, cache):
                    f = findings.get(getattr(e, "cve_id", ""))
                    if f:
                        f["epss"] = float(getattr(e, "epss", 0.0))
            except Exception:
                pass

            # Phase 4: PoC availability for hot findings only
            hot = [f for f in findings.values()
                   if f.get("kev") or f.get("cvss", 0) >= MIN_CVSS_TO_REPORT]
            for f in hot[:20]:
                try:
                    poc = await search_poc_existence(f["id"], client, cache)
                    f["poc"] = bool(poc.get("github") or poc.get("exploitdb"))
                except Exception:
                    f["poc"] = None
    finally:
        if hasattr(cache, "close"):
            await cache.close()

    return list(findings.values())


def _fallback_nvd_sync(queries: list[str]) -> list[dict]:
    """Direct NVD search without cve_mcp (no KEV/EPSS/PoC phases)."""
    findings: dict[str, dict] = {}
    api_key = os.environ.get("NVD_API_KEY", "")

    for q in queries[:10]:
        data = _nvd_keyword_search(q, api_key)
        if not data:
            continue
        for item in (data.get("vulnerabilities") or []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id or cve_id in findings:
                continue
            cvss = 0.0
            try:
                cvss = float(cve["metrics"]["cvssMetricV31"][0]
                             ["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                pass
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break
            if cvss < MIN_CVSS_TO_REPORT:
                continue
            findings[cve_id] = {"id": cve_id, "query": q, "cvss": cvss,
                                "description": desc}
    return list(findings.values())


def correlate(ws: Path) -> dict:
    """Run the full correlation pipeline. Writes cve-findings.json."""
    queries = _gather_queries(ws)
    out_file = ws / "cve-findings.json"

    # CPE-exact search takes priority when Shodan provided CPEs
    api_key = os.environ.get("NVD_API_KEY", "")
    findings: dict[str, dict] = {}
    try:
        from .shodan import extract_cpes
        cpes = extract_cpes(ws)[:10]
    except Exception:
        cpes = []
    if cpes:
        print("[*] CPE-exact search: " + str(len(cpes)) + " CPEs")
        for cpe in cpes:
            for f in _nvd_cpe_search(cpe, api_key):
                if f["id"] not in findings:
                    findings[f["id"]] = f
    seeds = list(findings.values())

    if not queries and not cpes:
        print("[!] No product fingerprints found to correlate.")
        out_file.write_text(json.dumps({"queries": [], "findings": []}, indent=2))
        return {"queries": [], "findings": []}

    if queries:
        print("[*] CVE correlation: " + str(len(queries)) + " queries")
        for q in queries:
            print("    - " + q)

    cache_path = ws.parent.parent / ".pixellance-cache" / "cache.db"
    cache_path.parent.mkdir(exist_ok=True)

    if _cve_mcp_available():
        print("[*] Using cve_mcp pipeline (NVD → KEV → EPSS → PoC)")
        findings = asyncio.run(
            _correlate_async(queries, cache_path, seed_findings=seeds))
    else:
        print("[!] cve_mcp not importable — fallback to direct NVD only")
        kw_findings = _fallback_nvd_sync(queries)
        for f in kw_findings:
            findings.setdefault(f["id"], f)
        findings = list(findings.values())

    # Prioritize: KEV first, then CVSS, then EPSS
    findings.sort(key=lambda f: (
        not f.get("kev", False),
        -f.get("cvss", 0.0),
        -f.get("epss", 0.0),
    ))

    result = {
        "generated": True,
        "queries": queries,
        "count": len(findings),
        "kev_count": sum(1 for f in findings if f.get("kev")),
        "poc_count": sum(1 for f in findings if f.get("poc")),
        "findings": findings,
    }
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("[*] " + str(len(findings)) + " CVEs (" + str(result["kev_count"]) +
          " KEV, " + str(result["poc_count"]) + " with PoC) → " + str(out_file))
    return result


def top_targets(ws: Path, n: int = 10) -> list[dict]:
    """Return the n highest-priority findings for quick triage."""
    f = ws / "cve-findings.json"
    if not f.exists():
        return []
    data = json.loads(f.read_text())
    return data.get("findings", [])[:n]
