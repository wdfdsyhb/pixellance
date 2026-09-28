"""Metasploit resource file generator + executor.

Keeps the .rc generation logic, but execution goes through HexStrike API
instead of spawning msfconsole locally.
"""
from pathlib import Path
from typing import Optional

from .client import HexStrikeClient, HexStrikeError


# Per-port Metasploit auxiliary modules
# Each entry: port_file -> list of (module_name, options_dict)
MSF_AUXILIARIES = {
    "21.txt": [
        ("auxiliary/scanner/ftp/ftp_version", {}),
        ("auxiliary/scanner/ftp/anonymous", {}),
    ],
    "22.txt": [
        ("auxiliary/scanner/ssh/ssh_version", {}),
        ("auxiliary/scanner/ssh/ssh_login", {"USERPASS_FILE": "/usr/share/wordlists/metasploit/root_userpass.txt"}),
    ],
    "25.txt": [
        ("auxiliary/scanner/smtp/smtp_version", {}),
        ("auxiliary/scanner/smtp/smtp_enum", {}),
    ],
    "80.txt": [
        ("auxiliary/scanner/http/http_version", {}),
        ("auxiliary/scanner/http/robots_txt", {}),
    ],
    "161.txt": [
        ("auxiliary/scanner/snmp/snmp_enum", {}),
        ("auxiliary/scanner/snmp/snmp_enumusers", {}),
    ],
    "445.txt": [
        ("auxiliary/scanner/smb/smb_ms17_010", {}),
        ("auxiliary/scanner/smb/smb_enumshares", {}),
        ("auxiliary/scanner/smb/smb_enumusers", {}),
        ("auxiliary/scanner/smb/pipe_auditor", {}),
        ("auxiliary/scanner/smb/smb_login", {}),
        ("auxiliary/scanner/dcerpc/petitpotam", {}),
    ],
    "1433.txt": [
        ("auxiliary/scanner/mssql/mssql_ping", {}),
        ("auxiliary/scanner/mssql/mssql_login", {}),
    ],
    "3306.txt": [
        ("auxiliary/scanner/mysql/mysql_version", {}),
        ("auxiliary/scanner/mysql/mysql_login", {}),
    ],
    "3389.txt": [
        ("auxiliary/scanner/rdp/ms12_020_check", {}),
    ],
    "5432.txt": [
        ("auxiliary/scanner/postgres/postgres_version", {}),
    ],
    "5900.txt": [
        ("auxiliary/vnc/vnc_none_auth", {}),
    ],
    "6379.txt": [
        ("auxiliary/scanner/redis/redis_server", {}),
    ],
    "27017.txt": [
        ("auxiliary/scanner/mongodb/mongodb_login", {}),
    ],
}


class MsfResourceGenerator:
    """Generate and execute Metasploit resource scripts via HexStrike API."""

    def __init__(self, workspace: Path, client: HexStrikeClient,
                 db_url: Optional[str] = None):
        self.workspace = workspace
        self.client = client
        self.db_url = db_url
        self.resource_dir = workspace / "msf_resources"
        self.resource_dir.mkdir(exist_ok=True)

    def build_master_script(self, scan_name: str) -> Optional[Path]:
        """Assemble a master .rc file from per-port fragments."""
        master = self.resource_dir / "master.rc"
        fragments = []

        header = [
            "workspace -a " + scan_name,
            "spool " + str(self.workspace / "msf_output.txt"),
        ]
        if self.db_url:
            header.insert(0, "db_connect " + self.db_url)

        module_count = 0
        for port_file, modules in MSF_AUXILIARIES.items():
            target = self.workspace / port_file
            if not target.exists():
                continue

            rhosts_line = "setg RHOSTS file:" + str(target)
            for module, options in modules:
                fragment = [rhosts_line]
                for key, val in options.items():
                    fragment.append("setg " + key + " " + val)
                fragment.append("use " + module)
                fragment.append("run")
                fragment.append("")
                fragments.extend(fragment)
                module_count += 1

        if not fragments:
            print("[*] No matching MSF modules for open ports.")
            return None

        master.write_text("\n".join(header + fragments), encoding="utf-8")
        print(f"[*] Master MSF script: {master} ({module_count} modules)")
        return master

    def run(self, master_script: Path) -> bool:
        """Execute MSF modules via HexStrike metasploit_run API."""
        print("[*] Running Metasploit modules via HexStrike...")

        total = 0
        success = 0
        failed = 0

        for port_file, modules in MSF_AUXILIARIES.items():
            target = self.workspace / port_file
            if not target.exists():
                continue

            hosts = target.read_text(errors="replace").splitlines()
            hosts = [h.strip() for h in hosts if h.strip()]
            if not hosts:
                continue

            rhosts = ",".join(hosts)

            for module, options in modules:
                total += 1
                opts = dict(options)
                opts["RHOSTS"] = rhosts
                try:
                    output = self.client.extract_output(
                        self.client.call("metasploit_run", {
                            "module": module,
                            "options": opts,
                        })
                    )
                    if output:
                        success += 1
                        # Save per-module output
                        safe_name = module.replace("/", "_")
                        out_path = self.workspace / "msf_resources" / f"{safe_name}.txt"
                        out_path.write_text(output, encoding="utf-8",
                                            errors="replace")
                except HexStrikeError as e:
                    failed += 1
                    print(f"    [!] {module}: {e}")

        print(f"[*] MSF complete: {success}/{total} succeeded, {failed} failed")
        return failed == 0
