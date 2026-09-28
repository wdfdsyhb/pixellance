"""Local web report server."""
import http.server
import json
import socketserver
from pathlib import Path
from datetime import datetime


REPORT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Pixellance Report</title>
<style>
:root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950; --red: #f85149; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
.stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 15px; text-align: center; }}
.stat .value {{ font-size: 2em; font-weight: bold; color: var(--accent); }}
.stat .label {{ font-size: 0.85em; color: #8b949e; margin-top: 5px; }}
.ports {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 15px; margin: 20px 0; }}
.port-grid {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
.port {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 5px 10px; }}
.results {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 15px; margin: 20px 0; }}
.file-list {{ list-style: none; padding: 0; }}
.file-list li {{ padding: 5px 0; border-bottom: 1px solid var(--border); }}
.file-list a {{ color: var(--accent); text-decoration: none; }}
</style>
</head>
<body>
<div class="container">
<h1>Pixellance Report</h1>
<p>Generated: {timestamp}</p>
<div class="stats">
  <div class="stat"><div class="value">{host_count}</div><div class="label">Hosts</div></div>
  <div class="stat"><div class="value">{port_count}</div><div class="label">Ports</div></div>
  <div class="stat"><div class="value">{trigger_count}</div><div class="label">Triggers</div></div>
  <div class="stat"><div class="value">{result_count}</div><div class="label">Results</div></div>
</div>
<div class="ports"><h2>Open Ports</h2><div class="port-grid">{port_badges}</div></div>
{cve_section}
{shodan_section}
<div class="results"><h2>Result Files</h2><ul class="file-list">{file_list}</ul></div>
</div>
</body>
</html>"""

CVE_SECTION = """
<div class="ports" style="border-color: var(--red);">
<h2 style="color: var(--red);">CVE Findings ({kev_count} KEV / {total} total)</h2>
<table style="width:100%; border-collapse:collapse; font-size:0.9em; margin-top:10px;">
<tr style="border-bottom:1px solid var(--border); color:#8b949e; text-align:left;">
  <th style="padding:6px;">CVE</th><th>CVSS</th><th>EPSS</th><th>Flags</th><th>Matched By</th><th>Description</th>
</tr>
{rows}
</table>
</div>"""

CVE_ROW = """<tr style="border-bottom:1px solid var(--border);">
<td style="padding:6px; color:var(--accent);">{cve_id}</td>
<td style="color:{cvss_color}; font-weight:bold;">{cvss}</td>
<td>{epss}</td>
<td>{flags}</td>
<td style="color:#8b949e;">{query}</td>
<td style="color:#8b949e; font-size:0.85em;">{desc}</td>
</tr>"""

SHODAN_SECTION = """
<div class="ports" style="border-color: var(--accent);">
<h2>Shodan Enrichment ({host_count} hosts)</h2>
<table style="width:100%; border-collapse:collapse; font-size:0.9em; margin-top:10px;">
<tr style="border-bottom:1px solid var(--border); color:#8b949e; text-align:left;">
  <th style="padding:6px;">IP</th><th>Org</th><th>Country</th><th>Ports</th><th>Shodan CVEs</th><th>Hostnames</th>
</tr>
{rows}
</table>
</div>"""

SHODAN_ROW = """<tr style="border-bottom:1px solid var(--border);">
<td style="padding:6px; color:var(--accent);">{ip}</td>
<td>{org}</td>
<td>{country}</td>
<td style="color:#8b949e;">{ports}</td>
<td style="color:{vuln_color}; font-weight:bold;">{vulns}</td>
<td style="color:#8b949e; font-size:0.85em;">{hostnames}</td>
</tr>"""


class ReportGenerator:
    """Generate and serve an HTML report from workspace results."""

    def __init__(self, workspace: Path):
        self.workspace = workspace

    def generate(self) -> Path:
        """Generate the HTML report file."""
        hosts_file = self.workspace / "hosts.txt"
        host_count = 0
        if hosts_file.exists():
            host_count = len(hosts_file.read_text().strip().splitlines())

        port_files = sorted(self.workspace.glob("[0-9]*.txt"))
        port_count = len(port_files)

        script_files = sorted(self.workspace.glob("script-*"))
        result_count = len(script_files)

        port_badges = "".join(
            '<span class="port">' + f.stem + "</span>" for f in port_files
        )

        file_items = ""
        for f in script_files:
            sz = f.stat().st_size
            sz_str = str(sz) + " B" if sz < 1024 else "{:.1f} KB".format(sz / 1024)
            file_items += '<li><a href="script-' + f.name + '">' + f.name + "</a> (" + sz_str + ")</li>"

        for name in ("nmap.nmap", "hosts.txt"):
            fp = self.workspace / name
            if fp.exists():
                sz = fp.stat().st_size
                sz_str = "{:.1f} KB".format(sz / 1024)
                file_items += "<li><a href=\"" + name + "\">" + name + "</a> (" + sz_str + ")</li>"

        html = REPORT_HTML.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            host_count=host_count,
            port_count=port_count,
            trigger_count=port_count,
            result_count=result_count,
            port_badges=port_badges,
            file_list=file_items,
            cve_section=self._cve_section(),
            shodan_section=self._shodan_section(),
        )

        report_path = self.workspace / "report.html"
        report_path.write_text(html, encoding="utf-8")
        return report_path

    def _cve_section(self) -> str:
        """Build CVE findings table if cve-findings.json exists."""
        f = self.workspace / "cve-findings.json"
        if not f.exists():
            return ""
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return ""
        findings = data.get("findings", [])
        if not findings:
            return ""

        rows = ""
        for cve in findings[:30]:
            cvss = cve.get("cvss", 0)
            cvss_color = "var(--red)" if cvss >= 9 else \
                         ("var(--accent)" if cvss >= 7 else "#8b949e")
            flags = []
            if cve.get("kev"):
                flags.append('<span style="color:var(--red);">KEV</span>')
            if cve.get("poc"):
                flags.append('<span style="color:var(--green);">PoC</span>')
            if cve.get("ransomware_use") and "Known" in str(cve.get("ransomware_use")):
                flags.append('<span style="color:var(--red);">Ransomware</span>')
            epss = cve.get("epss")
            epss_str = "{:.3f}".format(epss) if epss else "-"
            rows += CVE_ROW.format(
                cve_id=cve.get("id", ""),
                cvss=cvss if cvss else "-",
                cvss_color=cvss_color,
                epss=epss_str,
                flags=" ".join(flags) or "-",
                query=cve.get("query", ""),
                desc=cve.get("description", "")[:100],
            )

        return CVE_SECTION.format(
            kev_count=data.get("kev_count", 0),
            total=data.get("count", len(findings)),
            rows=rows,
        )

    def _shodan_section(self) -> str:
        """Build Shodan enrichment table if shodan-enrichment.json exists."""
        f = self.workspace / "shodan-enrichment.json"
        if not f.exists():
            return ""
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return ""
        if not data:
            return ""

        rows = ""
        for ip, info in list(data.items())[:30]:
            vuln_n = len(info.get("vulns", []))
            rows += SHODAN_ROW.format(
                ip=ip,
                org=info.get("org", "-"),
                country=info.get("country", "-"),
                ports=", ".join(str(p) for p in info.get("ports", [])[:15]),
                vulns=vuln_n if vuln_n else "0",
                vuln_color="var(--red)" if vuln_n else "#8b949e",
                hostnames=", ".join(info.get("hostnames", [])[:3]) or "-",
            )

        return SHODAN_SECTION.format(host_count=len(data), rows=rows)

    def serve(self, port: int = 17322):
        """Start a local HTTP server."""
        report_path = self.generate()
        print("\n[*] Report: " + str(report_path))

        workspace = self.workspace

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(workspace), **kwargs)

            def do_GET(self):
                if self.path == "/" or self.path == "/index.html":
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(report_path.read_bytes())
                else:
                    super().do_GET()

            def log_message(self, fmt, *args):
                pass

        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.TCPServer(("127.0.0.1", port), Handler)
        print("[*] Dashboard: http://127.0.0.1:" + str(port) + "/")
        print("[*] Press Ctrl+C to stop")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
            server.shutdown()
