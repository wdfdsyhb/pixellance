"""Pre-built trigger profiles — the actual pentest playbooks.

Uses HexStrike API tool names + args instead of subprocess cmd lists.
Target files are referenced relative to workspace; the engine resolves
them to host lists before calling the API.
"""
from pathlib import Path
from .triggers import TriggerEngine, PortTrigger


# --- helpers ---

def _nmap_trigger(engine, port_file, name, ports, scripts, scan_type="-sT",
                  output_suffix=None):
    """Register an nmap NSE trigger."""
    args = {
        "target_file": "{port_file}",
        "ports": ports,
        "scan_type": scan_type,
        "additional_args": f"--script={scripts} --script-timeout 20s",
    }
    engine.register(PortTrigger(
        port_file=port_file,
        name=name,
        tool="nmap",
        tool_args=args,
        output_file=f"script-{output_suffix or port_file.replace('.txt','')}.txt",
    ))


def _file_tool_trigger(engine, port_file, name, tool, extra_args=None,
                       output_suffix=None):
    """Register a file-based tool trigger (whatweb, enum4linux, etc.)."""
    args = {"target_file": "{port_file}"}
    if extra_args:
        args.update(extra_args)
    engine.register(PortTrigger(
        port_file=port_file,
        name=name,
        tool=tool,
        tool_args=args,
        output_file=f"script-{output_suffix or tool}.txt",
    ))


# --- profiles ---

def load_standard_profile(engine: TriggerEngine, workspace: Path):
    """
    Standard recon profile: NSE scripts per port + auxiliary tools.
    Covers the most useful enumeration targets.
    """

    # --- SMB ---
    _nmap_trigger(engine, "445.txt", "SMB Vulns", "445",
                  "smb-vuln-cve-2017-7494,smb-vuln-ms17-010,smb-vuln-ms10-061",
                  output_suffix="smbvulns")
    _nmap_trigger(engine, "445.txt", "SMB Enum", "445",
                  "smb-enum-domains,smb-enum-groups,smb-enum-shares,smb-enum-users,smb-os-discovery",
                  output_suffix="smbenum")
    _file_tool_trigger(engine, "445.txt", "enum4linux", "enum4linux",
                       output_suffix="enum4linux")

    # --- SSH ---
    _nmap_trigger(engine, "22.txt", "SSH Enum", "22",
                  "rsa-vuln-roca,sshv1,ssh2-enum-algos")

    # --- HTTP ---
    _file_tool_trigger(engine, "http.txt", "HTTP whatweb", "whatweb")
    _file_tool_trigger(engine, "http.txt", "httpx", "httpx",
                       extra_args={"additional_args": "-title -status-code -tech-detect"},
                       output_suffix="httpx")

    # --- HTTPS ---
    _file_tool_trigger(engine, "https.txt", "SSL Scan", "sslscan")

    # --- SMTP ---
    _nmap_trigger(engine, "smtp.txt", "SMTP Enum", "25,465,587",
                  "smtp-commands,smtp-enum-users,smtp-open-relay")

    # --- DNS ---
    _nmap_trigger(engine, "53.txt", "DNS Enum", "53",
                  "dns-zone-transfer,dns-recursion,dns-service-discovery",
                  scan_type="-sU")

    # --- SNMP ---
    _nmap_trigger(engine, "161.txt", "SNMP Enum", "161",
                  "snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-users",
                  scan_type="-sU")
    _file_tool_trigger(engine, "161.txt", "onesixtyone", "onesixtyone")

    # --- MySQL ---
    _nmap_trigger(engine, "3306.txt", "MySQL Enum", "3306",
                  "mysql-databases,mysql-empty-password,mysql-info,mysql-users")

    # --- RDP ---
    _nmap_trigger(engine, "3389.txt", "RDP Vuln", "3389",
                  "rdp-vuln-ms12-020,rdp-enum-encryption")

    # --- PostgreSQL ---
    _nmap_trigger(engine, "5432.txt", "PostgreSQL Enum", "5432",
                  "pgsql-brute")

    # --- Redis ---
    _nmap_trigger(engine, "6379.txt", "Redis Info", "6379",
                  "redis-info")

    # --- MongoDB ---
    _nmap_trigger(engine, "27017.txt", "MongoDB Enum", "27017",
                  "mongodb-databases,mongodb-info")

    # --- FTP ---
    _nmap_trigger(engine, "21.txt", "FTP Enum", "21",
                  "ftp-anon,ftp-bounce,ftp-proftpd-backdoor")

    # --- ICS/SCADA ---
    _nmap_trigger(engine, "502.txt", "Modbus Enum", "502",
                  "modbus-discover")

    # --- IPMI ---
    _nmap_trigger(engine, "623.txt", "IPMI Cipher", "623",
                  "ipmi-version,ipmi-cipher-zero", scan_type="-sU")

    # --- VNC ---
    _nmap_trigger(engine, "5900.txt", "VNC Info", "5900",
                  "realvnc-auth-bypass,vnc-info")

    # --- Docker ---
    _nmap_trigger(engine, "2375.txt", "Docker Enum", "2375",
                  "docker-version")


def load_web_profile(engine: TriggerEngine, workspace: Path):
    """
    Web-focused profile: nuclei (tech-aware) + ffuf + additional fuzzing.
    """

    engine.register(PortTrigger(
        port_file="http.txt",
        name="nuclei scan",
        tool="nuclei",
        tool_args={
            "target_file": "http.txt",
            "severity": "critical,high,medium",
            "output_format": "json",
        },
        output_file="script-nuclei.txt",
    ))
    engine.register(PortTrigger(
        port_file="https.txt",
        name="nuclei scan (https)",
        tool="nuclei",
        tool_args={
            "target_file": "https.txt",
            "severity": "critical,high,medium",
            "output_format": "json",
        },
        output_file="script-nuclei-https.txt",
    ))
    engine.register(PortTrigger(
        port_file="http.txt",
        name="ffuf fuzz",
        tool="ffuf",
        tool_args={
            "target_file": "http.txt",
            "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        },
        output_file="script-ffuf.txt",
    ))


def load_nuclei_auto(engine: TriggerEngine, workspace: Path):
    """
    Tech-aware nuclei profile: run after whatweb/httpx have fingerprinted
    targets. Uses nuclei.py to pick templates per detected technology.
    """
    from .nuclei import build_nuclei_commands, select_templates

    plan = select_templates(workspace)
    if plan["techs"]:
        print("[nuclei-auto] Detected: " + ", ".join(plan["techs"]))
        print("[nuclei-auto] Tags: " + ", ".join(plan["tags"]))
    else:
        print("[nuclei-auto] No tech detected yet — run standard/web profile first")

    for i, cmd_spec in enumerate(build_nuclei_commands(workspace)):
        # cmd_spec is now a dict: {"target_file": "...", "tags": "...", "severity": "..."}
        port_file = cmd_spec.pop("target_file", "http.txt")
        engine.register(PortTrigger(
            port_file=Path(port_file).name,
            name=f"nuclei-auto #{i + 1}",
            tool="nuclei",
            tool_args=cmd_spec,
            output_file=f"script-nuclei-auto-{i + 1}.txt",
        ))
