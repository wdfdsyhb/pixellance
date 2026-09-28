"""SQLite state persistence for scan sessions.

Tracks every scan run so context survives across CLI invocations and
sessions can be resumed or reviewed later.
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    workspace TEXT NOT NULL,
    target_file TEXT,
    profile TEXT,
    server TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT DEFAULT 'running',  -- running, completed, failed, interrupted
    host_count INTEGER DEFAULT 0,
    port_count INTEGER DEFAULT 0,
    trigger_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    hostname TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    host_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT,
    service TEXT,
    banner TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS trigger_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    port_file TEXT,
    tool TEXT,
    success INTEGER,
    output_size INTEGER,
    output_file TEXT,
    ran_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    ftype TEXT NOT NULL,       -- 'cve', 'shodan', 'nuclei', etc.
    severity TEXT,
    title TEXT,
    detail TEXT,
    source_file TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_hosts_session ON hosts(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_session ON ports(session_id);
CREATE INDEX IF NOT EXISTS idx_triggers_session ON trigger_runs(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
"""


class ScanState:
    """SQLite-backed scan session state."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            p = Path.home() / ".pixellance"
            p.mkdir(exist_ok=True)
            db_path = p / "state.db"
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # --- sessions ---

    def create_session(self, name: str, workspace: str, target_file: str = "",
                      profile: str = "standard", server: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO sessions (name, workspace, target_file, profile, server, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, workspace, target_file, profile, server,
             datetime.now().isoformat()),
        )
        self.conn.commit()
        return cur.lastrowid

    def complete_session(self, session_id: int, host_count: int = 0,
                         port_count: int = 0, trigger_count: int = 0,
                         status: str = "completed"):
        self.conn.execute(
            "UPDATE sessions SET completed_at=?, status=?, host_count=?, "
            "port_count=?, trigger_count=? WHERE id=?",
            (datetime.now().isoformat(), status, host_count, port_count,
             trigger_count, session_id),
        )
        self.conn.commit()

    def get_session(self, session_id: int) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_sessions(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- hosts & ports ---

    def add_host(self, session_id: int, ip: str, hostname: str = ""):
        self.conn.execute(
            "INSERT INTO hosts (session_id, ip, hostname) VALUES (?, ?, ?)",
            (session_id, ip, hostname),
        )

    def add_port(self, session_id: int, host_ip: str, port: int,
                 proto: str = "", service: str = "", banner: str = ""):
        self.conn.execute(
            "INSERT INTO ports (session_id, host_ip, port, proto, service, banner) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, host_ip, port, proto, service, banner),
        )

    def commit(self):
        self.conn.commit()

    # --- trigger runs ---

    def add_trigger_run(self, session_id: int, name: str, port_file: str = "",
                       tool: str = "", success: bool = True,
                       output_size: int = 0, output_file: str = ""):
        self.conn.execute(
            "INSERT INTO trigger_runs (session_id, name, port_file, tool, success, "
            "output_size, output_file, ran_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, name, port_file, tool, int(success), output_size,
             output_file, datetime.now().isoformat()),
        )

    # --- findings ---

    def add_finding(self, session_id: int, ftype: str, title: str,
                    severity: str = "", detail: str = "",
                    source_file: str = ""):
        self.conn.execute(
            "INSERT INTO findings (session_id, ftype, severity, title, detail, source_file) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, ftype, severity, title, detail, source_file),
        )

    def get_findings(self, session_id: int, ftype: str = "") -> list[dict]:
        if ftype:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE session_id=? AND ftype=? ORDER BY severity DESC",
                (session_id, ftype),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY severity DESC",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # --- bulk load from workspace ---

    def load_workspace(self, session_id: int, workspace: Path):
        """Parse workspace files to populate hosts/ports."""
        # Hosts
        hosts_file = workspace / "hosts.txt"
        if hosts_file.exists():
            for line in hosts_file.read_text(errors="replace").splitlines():
                ip = line.strip()
                if ip:
                    self.add_host(session_id, ip)

        # Ports from numbered files
        for port_file in workspace.glob("[0-9]*.txt"):
            if port_file.name in ("hosts.txt", "http.txt", "https.txt"):
                continue
            try:
                port_num = int(port_file.stem)
            except ValueError:
                continue
            for line in port_file.read_text(errors="replace").splitlines():
                ip = line.strip()
                if ip:
                    self.add_port(session_id, ip, port_num)

        # Trigger outputs from script-* files
        for script_file in workspace.glob("script-*"):
            size = script_file.stat().st_size
            self.add_trigger_run(
                session_id, name=script_file.name,
                port_file="", tool="",
                success=size > 0, output_size=size,
                output_file=str(script_file.name),
            )

        # CVE findings
        cve_file = workspace / "cve-findings.json"
        if cve_file.exists():
            try:
                data = json.loads(cve_file.read_text())
                for f in data.get("findings", []):
                    severity = "critical" if f.get("cvss", 0) >= 9 else \
                               "high" if f.get("cvss", 0) >= 7 else "medium"
                    if f.get("kev"):
                        severity = "critical"
                    self.add_finding(
                        session_id, "cve", f.get("id", ""),
                        severity=severity,
                        detail=f.get("description", "")[:200],
                        source_file="cve-findings.json",
                    )
            except (json.JSONDecodeError, KeyError):
                pass

        self.conn.commit()
