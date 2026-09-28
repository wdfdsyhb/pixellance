"""CLI entry point for pixellance.

Now uses HexStrike HTTP API as tool execution backend.
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path

from .client import HexStrikeClient, HexStrikeError
from .scanner import NmapScanner
from .triggers import TriggerEngine
from .profiles import load_standard_profile, load_web_profile
from .msfgen import MsfResourceGenerator
from .report import ReportGenerator
from .state import ScanState
from .config import HEXSTRIKE_SERVER, HEXSTRIKE_TIMEOUT, REPORT_DIR


def make_client(server: str = HEXSTRIKE_SERVER,
                timeout: int = HEXSTRIKE_TIMEOUT) -> HexStrikeClient:
    return HexStrikeClient(server=server, timeout=timeout)


def cmd_scan(args, client: HexStrikeClient, state: ScanState):
    """Execute full scan pipeline."""
    name = args.name or datetime.now().strftime("scan-%Y%m%d-%H%M%S")
    workspace = REPORT_DIR / name
    targets = Path(args.targets).resolve()

    if not targets.exists():
        print(f"[!] Target file not found: {targets}")
        sys.exit(1)

    # Create session record
    session_id = state.create_session(
        name=name, workspace=str(workspace),
        target_file=str(targets), profile=args.profile,
        server=client.server,
    )

    print(f"\n{'='*60}")
    print(f"  PixelLance v0.2.0 — {name}")
    print(f"  Targets: {targets}")
    print(f"  Server:  {client.server}")
    print(f"  Workspace: {workspace}")
    print(f"{'='*60}\n")

    # Health check
    if not client.health():
        print(f"[!] WARNING: HexStrike server at {client.server} is not responding.")
        print(f"    Start the Kali VM and try again.")
        if not args.force:
            sys.exit(1)

    try:
        # Phase 1: nmap
        scanner = NmapScanner(workspace, client)
        alive = scanner.full_scan(
            targets,
            fast=args.fast,
            version=args.version,
            delay=args.delay,
        )

        if not alive:
            print("[!] No live hosts. Exiting.")
            state.complete_session(session_id, status="no_hosts")
            sys.exit(0)

        # Phase 2: parse and split
        port_map = scanner.parse_results()

        # Save to state DB
        hosts_file = workspace / "hosts.txt"
        if hosts_file.exists():
            for line in hosts_file.read_text(errors="replace").splitlines():
                ip = line.strip()
                if ip:
                    state.add_host(session_id, ip)
        for port_num, ip_list in port_map.items():
            for ip in ip_list:
                state.add_port(session_id, ip, int(port_num))
        state.commit()

        # Phase 3: run triggers
        engine = TriggerEngine(workspace, client, dry_run=args.dry_run)

        if args.profile in ("standard", "full"):
            load_standard_profile(engine, workspace)
        if args.profile in ("web", "full"):
            load_web_profile(engine, workspace)

        # Tech-aware nuclei after web fingerprinting
        if args.nuclei_auto and args.profile in ("web", "full"):
            from .profiles import load_nuclei_auto
            load_nuclei_auto(engine, workspace)

        results = engine.run_all()
        print(engine.summary())

        # Save trigger results to DB
        for r in results:
            out_file = workspace / (r.port_file.replace(".txt", "") if r.port_file else "")
            size = out_file.stat().st_size if out_file.exists() else 0
            state.add_trigger_run(
                session_id, name=r.name,
                port_file=r.port_file,
                success=r.success,
                output_size=size,
            )
        state.commit()

        # Phase 4: Metasploit
        if args.msf or args.run_msf:
            msf = MsfResourceGenerator(workspace, client)
            master = msf.build_master_script(name)
            if master and args.run_msf:
                msf.run(master)

        # Phase 5: Shodan enrichment
        if args.shodan:
            from .shodan import enrich_hosts
            enrich_hosts(workspace)

        # Phase 6: CVE correlation
        if args.cve:
            from .cve import correlate
            correlate(workspace)

        # Load findings into state DB
        state.load_workspace(session_id, workspace)

        # Phase 7: report
        report = ReportGenerator(workspace)
        report_path = report.generate()
        print(f"\n[*] Report: {report_path}")

        # Mark session complete
        state.complete_session(
            session_id,
            host_count=len(port_map),
            port_count=len(port_map),
            trigger_count=len(results),
        )

        if args.serve:
            report.serve()

    except HexStrikeError as e:
        print(f"\n[!] HexStrike error: {e}")
        state.complete_session(session_id, status="failed")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        state.complete_session(session_id, status="interrupted")
        sys.exit(130)


def cmd_history(args, client: HexStrikeClient, state: ScanState):
    """List recent scan sessions."""
    sessions = state.list_sessions(limit=args.limit)
    if not sessions:
        print("No scan sessions found.")
        return

    print(f"\n{'='*80}")
    print(f"  {'ID':>4}  {'Status':<12}  {'Hosts':>5}  {'Ports':>5}  {'Name'}")
    print(f"{'='*80}")
    for s in sessions:
        print(f"  {s['id']:>4}  {s['status']:<12}  {s['host_count']:>5}  "
              f"{s['port_count']:>5}  {s['name']}")
        print(f"       {s.get('started_at', '')}  {s.get('workspace', '')}")
    print(f"{'='*80}")


def cmd_session(args, client: HexStrikeClient, state: ScanState):
    """Show details of one scan session."""
    s = state.get_session(args.session_id)
    if not s:
        print(f"Session {args.session_id} not found.")
        return

    print(f"\n{'='*60}")
    print(f"  Session #{s['id']}: {s['name']}")
    print(f"  Status: {s['status']}")
    print(f"  Started: {s['started_at']}")
    print(f"  Workspace: {s['workspace']}")
    print(f"  Hosts: {s['host_count']}, Ports: {s['port_count']}, "
          f"Triggers: {s['trigger_count']}")
    print(f"{'='*60}")

    findings = state.get_findings(args.session_id)
    if findings:
        print(f"\n  Findings ({len(findings)}):")
        for f in findings[:20]:
            print(f"    [{f['severity']:>8}] {f['ftype']}: {f['title']}")


def cmd_rerun(args, client: HexStrikeClient, state: ScanState):
    """Re-run triggers on existing workspace."""
    workspace = Path(args.workspace).resolve()
    if not (workspace / "hosts.txt").exists():
        print(f"[!] Not a valid workspace: {workspace}")
        sys.exit(1)

    print(f"[*] Re-running triggers on {workspace}")
    engine = TriggerEngine(workspace, client)
    if args.profile == "standard":
        load_standard_profile(engine, workspace)
    elif args.profile == "web":
        load_web_profile(engine, workspace)

    results = engine.run_all()
    print(engine.summary())


def cmd_report(args, client: HexStrikeClient, state: ScanState):
    """Just generate report and serve."""
    workspace = Path(args.workspace).resolve()
    if not workspace.exists():
        print(f"[!] Workspace not found: {workspace}")
        sys.exit(1)
    report = ReportGenerator(workspace)
    report.serve(port=args.port)


def cmd_cve(args, client: HexStrikeClient, state: ScanState):
    """Standalone CVE correlation on an existing workspace."""
    from .cve import correlate, top_targets
    workspace = Path(args.workspace).resolve()
    if not workspace.exists():
        print(f"[!] Workspace not found: {workspace}")
        sys.exit(1)
    correlate(workspace)

    top = top_targets(workspace)
    if top:
        print("\n[*] Top priority targets:")
        for f in top:
            flags = []
            if f.get("kev"):
                flags.append("KEV")
            if f.get("poc"):
                flags.append("PoC")
            if f.get("epss"):
                flags.append("EPSS " + f"{f['epss']:.2f}")
            flag_str = " [" + ",".join(flags) + "]" if flags else ""
            print("    " + f["id"] + " (CVSS " + str(f.get("cvss", 0)) + ")"
                  + flag_str + " ← " + f.get("query", ""))


def main():
    parser = argparse.ArgumentParser(
        prog="pixellance",
        description="Port-triggered pentest orchestration (HexStrike backend)",
    )
    parser.add_argument("-s", "--server", default=HEXSTRIKE_SERVER,
                        help=f"HexStrike server URL (default: {HEXSTRIKE_SERVER})")
    parser.add_argument("--force", action="store_true",
                        help="Skip health check and proceed even if server is down")
    parser.add_argument("--timeout", type=int, default=HEXSTRIKE_TIMEOUT,
                        help="Per-tool timeout in seconds")

    sub = parser.add_subparsers(dest="command")

    # --- scan ---
    p_scan = sub.add_parser("scan", help="Run scan + triggers")
    p_scan.add_argument("targets", help="Target file (IPs/CIDRs)")
    p_scan.add_argument("-n", "--name", default=None, help="Scan name")
    p_scan.add_argument("-p", "--profile", default="standard",
                        choices=["standard", "web", "full"],
                        help="Trigger profile")
    p_scan.add_argument("-f", "--fast", action="store_true",
                        help="Fast scan (top 1000 ports)")
    p_scan.add_argument("-V", "--version", action="store_true",
                        help="Enable version detection")
    p_scan.add_argument("-d", "--delay", type=int, default=0,
                        help="Inter-packet delay (0-5s)")
    p_scan.add_argument("--msf", action="store_true",
                        help="Generate Metasploit resource script")
    p_scan.add_argument("--run-msf", action="store_true",
                        help="Also execute Metasploit modules")
    p_scan.add_argument("--shodan", action="store_true",
                        help="Enrich hosts via Shodan")
    p_scan.add_argument("--cve", action="store_true",
                        help="Correlate fingerprints with NVD/KEV/EPSS/PoC")
    p_scan.add_argument("--nuclei-auto", action="store_true",
                        help="Tech-aware nuclei template selection")
    p_scan.add_argument("--dry-run", action="store_true",
                        help="Show what would be run without executing")
    p_scan.add_argument("--serve", action="store_true",
                        help="Start web dashboard after scan")

    # --- history ---
    p_hist = sub.add_parser("history", help="List past scan sessions")
    p_hist.add_argument("-l", "--limit", type=int, default=20,
                        help="Max sessions to show")

    # --- session ---
    p_sess = sub.add_parser("session", help="Show session details")
    p_sess.add_argument("session_id", type=int, help="Session ID")

    # --- rerun ---
    p_rerun = sub.add_parser("rerun", help="Re-run triggers on existing workspace")
    p_rerun.add_argument("workspace", help="Path to existing scan workspace")
    p_rerun.add_argument("-p", "--profile", default="standard",
                         choices=["standard", "web", "full"])

    # --- report ---
    p_report = sub.add_parser("report", help="Generate report + start dashboard")
    p_report.add_argument("workspace", help="Path to scan workspace")
    p_report.add_argument("--port", type=int, default=17322)

    # --- cve ---
    p_cve = sub.add_parser("cve", help="Correlate existing workspace with NVD/KEV")
    p_cve.add_argument("workspace", help="Path to scan workspace")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Initialize client and state
    client = make_client(server=args.server,
                         timeout=getattr(args, 'timeout', HEXSTRIKE_TIMEOUT))
    state = ScanState()

    try:
        if args.command == "scan":
            cmd_scan(args, client, state)
        elif args.command == "history":
            cmd_history(args, client, state)
        elif args.command == "session":
            cmd_session(args, client, state)
        elif args.command == "rerun":
            cmd_rerun(args, client, state)
        elif args.command == "report":
            cmd_report(args, client, state)
        elif args.command == "cve":
            cmd_cve(args, client, state)
    finally:
        state.close()


if __name__ == "__main__":
    main()
