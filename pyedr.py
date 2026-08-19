#!/usr/bin/env python3
"""
PyEDR - Lightweight Host-Based EDR Agent
==========================================
A transparent, rule-based endpoint detection tool. Runs as a continuous
monitoring agent (baselines the system, then alerts on new persistence
and live behavioral indicators) or as a one-shot deep scan.

Detections are MITRE ATT&CK-mapped and use explicit, readable logic --
no black-box scoring. Every rule that fires tells you exactly why.

Author:  Techienerd
Scope:   Windows-focused (registry/services/scheduled tasks are Windows
         concepts). Process/network monitoring works cross-platform.
Deps:    psutil (pip install psutil)

DISCLAIMER: For use only on systems you own or are authorized to monitor.
This is a portfolio/educational EDR-lite tool, not a replacement for
commercial EDR (no kernel-level visibility, no cloud threat intel, and
it can be evaded by a sufficiently motivated attacker with local access
to tamper with or kill this process).
"""

import argparse
import csv
import json
import os
import platform
import re
import sys
import time
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:
    print("This tool requires psutil. Install with: pip install psutil")
    sys.exit(1)

IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    try:
        import winreg
    except ImportError:
        winreg = None
else:
    winreg = None


# ---------------------------------------------------------------------------
# Console colors
# ---------------------------------------------------------------------------

class C:
    RESET = "\033[0m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    MAGENTA = "\033[95m"

    @staticmethod
    def enable_on_windows():
        if IS_WINDOWS:
            os.system("")  # enables ANSI escape processing on modern cmd/powershell


SEVERITY_COLOR = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH": C.RED,
    "MEDIUM": C.YELLOW,
    "LOW": C.CYAN,
    "INFO": C.GRAY,
}
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


# ---------------------------------------------------------------------------
# Alert structure
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    timestamp: str
    severity: str
    technique_id: str
    technique_name: str
    title: str
    details: str
    source: str  # which monitor raised it: process | persistence | network

    def to_dict(self):
        return asdict(self)

    def print_console(self):
        color = SEVERITY_COLOR.get(self.severity, C.RESET)
        print(f"{color}[{self.severity}] {self.technique_id} {self.technique_name}{C.RESET}")
        print(f"  {C.BOLD}{self.title}{C.RESET}")
        print(f"  {C.GRAY}{self.details}{C.RESET}")
        print(f"  {C.GRAY}@ {self.timestamp}{C.RESET}\n")


# ---------------------------------------------------------------------------
# MITRE ATT&CK-mapped detection rules
# ---------------------------------------------------------------------------
# Each rule is documented with: technique ID, technique name, severity,
# and the exact condition that triggers it. This is intentionally
# transparent -- you should be able to read this and know precisely why
# something fired.

SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\\AppData\\Local\\Temp\\", re.I),
    re.compile(r"\\Users\\Public\\", re.I),
    re.compile(r"\\Windows\\Temp\\", re.I),
    re.compile(r"\\ProgramData\\(?!Microsoft)", re.I),
    re.compile(r"\\\$Recycle\.Bin\\", re.I),
]

SYSTEM_PROCESS_EXPECTED_DIR = {
    "svchost.exe": r"\windows\system32",
    "csrss.exe": r"\windows\system32",
    "lsass.exe": r"\windows\system32",
    "winlogon.exe": r"\windows\system32",
    "services.exe": r"\windows\system32",
    "explorer.exe": r"\windows",
    "smss.exe": r"\windows\system32",
    "spoolsv.exe": r"\windows\system32",
}

RAT_PROCESS_NAMES = [
    "teamviewer", "anydesk", "vncserver", "winvnc", "tvnserver", "ammyy",
    "supremo", "quickassist", "ultraviewer", "remoteutilities", "dwservice",
    "ngrok", "radmin", "logmein", "splashtop", "gotomypc", "showmypc",
    "netsupport",
]

CREDENTIAL_ACCESS_TOOL_NAMES = [
    "mimikatz", "procdump", "pwdump", "gsecdump", "wce", "lazagne",
]

LOLBIN_DOWNLOAD_INDICATORS = ["certutil", "bitsadmin", "curl", "wget"]

# Parent process -> child process combos that are classic living-off-the-land
# / macro-malware droppers (Office app spawning a shell/scripting engine).
SUSPICIOUS_PARENT_CHILD = {
    "winword.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "excel.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "outlook.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "powerpnt.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "acrord32.exe": {"cmd.exe", "powershell.exe"},
}

POWERSHELL_OBFUSCATION_FLAGS = re.compile(
    r"(-enc\b|-encodedcommand|-nop\b|-noprofile|-w(indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass)",
    re.I,
)

BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def is_suspicious_path(path: str) -> bool:
    if not path:
        return False
    return any(p.search(path) for p in SUSPICIOUS_PATH_PATTERNS)


def is_masquerading(name: str, path: str) -> bool:
    """T1036.005 - process name matches a core Windows system process,
    but its on-disk path is not where that process is supposed to live."""
    if not path:
        return False
    expected = SYSTEM_PROCESS_EXPECTED_DIR.get(name.lower())
    if not expected:
        return False
    return expected not in path.lower()


def cmdline_str(proc_info) -> str:
    try:
        cl = proc_info.get("cmdline") or []
        return " ".join(cl)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Evaluates live process, persistence, and network state against the
    MITRE-mapped rule set above. Stateless per-call -- callers pass in
    the current snapshot (and, where relevant, the prior baseline) and
    get back a list of Alert objects.
    """

    def __init__(self):
        self.seen_pids_flagged = set()  # avoid re-alerting same PID/rule combo

    def _mk(self, severity, tid, tname, title, details, source):
        return Alert(
            timestamp=datetime.now().isoformat(timespec="seconds"),
            severity=severity, technique_id=tid, technique_name=tname,
            title=title, details=details, source=source,
        )

    # ---- Process-based behavioral rules ----------------------------------

    def evaluate_process(self, proc_info) -> list:
        alerts = []
        name = (proc_info.get("name") or "").lower()
        path = proc_info.get("exe") or ""
        pid = proc_info.get("pid")
        ppid = proc_info.get("ppid")
        cmd = cmdline_str(proc_info)
        key = f"{pid}:{name}"

        # T1036.005 Masquerading
        if is_masquerading(name, path):
            alerts.append(self._mk(
                "CRITICAL", "T1036.005", "Masquerading: Match Legitimate Name",
                f"Process '{name}' running from unexpected location",
                f"PID {pid} named '{name}' expects to run from "
                f"{SYSTEM_PROCESS_EXPECTED_DIR.get(name)}, actually at: {path}",
                "process",
            ))

        # Unsigned / suspicious-path autostart-style binary
        if is_suspicious_path(path):
            alerts.append(self._mk(
                "HIGH", "T1036", "Masquerading (suspicious execution path)",
                f"Process '{name}' executing from a non-standard path",
                f"PID {pid}, path: {path}",
                "process",
            ))

        # T1219 / RAT tooling present
        if any(r in name for r in RAT_PROCESS_NAMES):
            alerts.append(self._mk(
                "MEDIUM", "T1219", "Remote Access Software",
                f"Remote access tool running: '{name}'",
                f"PID {pid}, path: {path}. Confirm this was installed intentionally.",
                "process",
            ))

        # T1003 Credential dumping tool names
        if any(r in name for r in CREDENTIAL_ACCESS_TOOL_NAMES):
            alerts.append(self._mk(
                "CRITICAL", "T1003", "OS Credential Dumping",
                f"Known credential-access tool detected: '{name}'",
                f"PID {pid}, path: {path}, cmdline: {cmd}",
                "process",
            ))

        # T1059.001 PowerShell obfuscation/bypass flags
        if name == "powershell.exe" and POWERSHELL_OBFUSCATION_FLAGS.search(cmd):
            alerts.append(self._mk(
                "HIGH", "T1059.001", "Command and Scripting Interpreter: PowerShell",
                "PowerShell launched with obfuscation/bypass flags",
                f"PID {pid}, cmdline: {cmd}",
                "process",
            ))

        # T1027 Base64 blob in command line (possible obfuscated payload)
        if BASE64_BLOB.search(cmd):
            alerts.append(self._mk(
                "MEDIUM", "T1027", "Obfuscated Files or Information",
                f"Long base64-like string in command line of '{name}'",
                f"PID {pid}, cmdline (truncated): {cmd[:150]}...",
                "process",
            ))

        # T1105 LOLBin download indicators (certutil/bitsadmin fetching a URL)
        if name.replace(".exe", "") in LOLBIN_DOWNLOAD_INDICATORS and re.search(r"https?://", cmd, re.I):
            alerts.append(self._mk(
                "HIGH", "T1105", "Ingress Tool Transfer",
                f"'{name}' invoked with a URL argument (living-off-the-land download)",
                f"PID {pid}, cmdline: {cmd}",
                "process",
            ))

        # T1055-adjacent: suspicious parent/child (office app spawning shell)
        if ppid:
            try:
                parent = psutil.Process(ppid)
                pname = parent.name().lower()
                if pname in SUSPICIOUS_PARENT_CHILD and name in SUSPICIOUS_PARENT_CHILD[pname]:
                    alerts.append(self._mk(
                        "CRITICAL", "T1566/T1059", "Suspicious Parent-Child Process",
                        f"'{pname}' spawned '{name}' -- classic macro/dropper pattern",
                        f"Parent PID {ppid} ({pname}) -> Child PID {pid} ({name}), cmdline: {cmd}",
                        "process",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return alerts

    # ---- Persistence delta rules -------------------------------------------

    def evaluate_persistence_delta(self, baseline: dict, current: dict) -> list:
        """Compares a previous persistence snapshot to the current one and
        raises alerts for anything NEW. Covers registry run keys, startup
        folder items, scheduled tasks, and services."""
        alerts = []

        new_run_keys = current["run_keys"] - baseline["run_keys"]
        for entry in new_run_keys:
            alerts.append(self._mk(
                "HIGH", "T1547.001", "Registry Run Keys / Startup Folder",
                "New autostart registry entry detected",
                entry, "persistence",
            ))

        new_startup = current["startup_files"] - baseline["startup_files"]
        for entry in new_startup:
            alerts.append(self._mk(
                "HIGH", "T1547.001", "Registry Run Keys / Startup Folder",
                "New file dropped in a Startup folder",
                entry, "persistence",
            ))

        new_tasks = current["scheduled_tasks"] - baseline["scheduled_tasks"]
        for entry in new_tasks:
            alerts.append(self._mk(
                "HIGH", "T1053.005", "Scheduled Task/Job: Scheduled Task",
                "New scheduled task created",
                entry, "persistence",
            ))

        new_services = current["services"] - baseline["services"]
        for entry in new_services:
            alerts.append(self._mk(
                "HIGH", "T1543.003", "Create or Modify System Process: Windows Service",
                "New auto-start service detected",
                entry, "persistence",
            ))

        return alerts

    # ---- Network rules -----------------------------------------------------

    def evaluate_network(self, conn_info) -> list:
        alerts = []
        proc_name = (conn_info.get("process_name") or "").lower()
        remote_port = conn_info.get("remote_port")

        # Processes that have no legitimate reason to make outbound network
        # calls, doing so anyway.
        quiet_processes = {"notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe"}
        if proc_name in quiet_processes:
            alerts.append(self._mk(
                "MEDIUM", "T1071", "Application Layer Protocol",
                f"Unexpected outbound connection from '{proc_name}'",
                f"{conn_info.get('laddr')} -> {conn_info.get('raddr')} "
                f"(PID {conn_info.get('pid')})",
                "network",
            ))

        # Common C2 / reverse shell ports
        if remote_port in (4444, 1337, 31337, 6666, 8888):
            alerts.append(self._mk(
                "HIGH", "T1071", "Application Layer Protocol",
                f"Connection to commonly-abused port {remote_port}",
                f"{conn_info.get('laddr')} -> {conn_info.get('raddr')} "
                f"(PID {conn_info.get('pid')}, process: {proc_name})",
                "network",
            ))

        return alerts


# ---------------------------------------------------------------------------
# Collectors -- gather raw state from the OS
# ---------------------------------------------------------------------------

def collect_persistence_snapshot() -> dict:
    """Returns a dict of sets describing current persistence state.
    Windows-only collectors degrade gracefully on other platforms."""
    snap = {
        "run_keys": set(),
        "startup_files": set(),
        "scheduled_tasks": set(),
        "services": set(),
    }

    if not IS_WINDOWS:
        return snap

    run_key_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    if winreg:
        for hive, subkey in run_key_paths:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            snap["run_keys"].add(f"{subkey}\\{name} = {value}")
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                pass

    startup_dirs = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
    ]
    for d in startup_dirs:
        if os.path.isdir(d):
            for f in os.listdir(d):
                snap["startup_files"].add(os.path.join(d, f))

    try:
        out = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=20,
        )
        if out.returncode == 0:
            reader = csv.DictReader(out.stdout.splitlines())
            for row in reader:
                name = row.get("TaskName", "")
                if name and "\\Microsoft\\" not in name and row.get("Scheduled Task State") == "Enabled":
                    snap["scheduled_tasks"].add(name)
    except Exception:
        pass

    try:
        for svc in psutil.win_service_iter():
            info = svc.as_dict()
            if info.get("start_type") == "automatic" and info.get("status") == "running":
                snap["services"].add(f"{info.get('name')} | {info.get('binpath')}")
    except Exception:
        pass

    return snap


def collect_processes() -> list:
    procs = []
    for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"]):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def collect_connections() -> list:
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue
            pname = None
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pname = None
            conns.append({
                "pid": c.pid, "process_name": pname,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "remote_port": c.raddr.port if c.raddr else None,
            })
    except (psutil.AccessDenied, PermissionError):
        pass
    return conns


# ---------------------------------------------------------------------------
# Alert Logger -- console + JSON lines + CSV
# ---------------------------------------------------------------------------

class AlertLogger:
    def __init__(self, out_dir: str, min_severity: str = "LOW"):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.json_path = self.out_dir / f"pyedr_alerts_{stamp}.jsonl"
        self.csv_path = self.out_dir / f"pyedr_alerts_{stamp}.csv"
        self.min_severity = SEVERITY_ORDER.get(min_severity, 1)
        self._csv_header_written = False
        self.count = 0
        self.count_by_severity = {k: 0 for k in SEVERITY_ORDER}

    def log(self, alert: Alert):
        if SEVERITY_ORDER.get(alert.severity, 0) < self.min_severity:
            return
        alert.print_console()
        self.count += 1
        self.count_by_severity[alert.severity] = self.count_by_severity.get(alert.severity, 0) + 1

        with open(self.json_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

        write_header = not self._csv_header_written
        with open(self.csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(alert.to_dict().keys()))
            if write_header:
                writer.writeheader()
                self._csv_header_written = True
            writer.writerow(alert.to_dict())

    def summary(self):
        print(f"\n{C.BOLD}{'=' * 70}{C.RESET}")
        print(f"{C.BOLD}Session summary: {self.count} alert(s){C.RESET}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            n = self.count_by_severity.get(sev, 0)
            if n:
                print(f"  {SEVERITY_COLOR[sev]}{sev}: {n}{C.RESET}")
        print(f"  JSON log: {self.json_path}")
        print(f"  CSV log:  {self.csv_path}")
        print(f"{C.BOLD}{'=' * 70}{C.RESET}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_scan(logger: AlertLogger, engine: DetectionEngine):
    """One-shot deep scan: evaluates current process list, current
    persistence state (informational -- no baseline to diff against yet
    on a fresh scan), and current network connections."""
    print(f"{C.CYAN}{C.BOLD}PyEDR -- One-shot scan starting...{C.RESET}\n")

    print(f"{C.GRAY}Scanning {len(collect_processes())} running processes...{C.RESET}")
    for p in collect_processes():
        for alert in engine.evaluate_process(p):
            logger.log(alert)

    print(f"{C.GRAY}Scanning persistence locations...{C.RESET}")
    persistence = collect_persistence_snapshot()
    print(f"{C.GRAY}  {len(persistence['run_keys'])} run-key entries, "
          f"{len(persistence['startup_files'])} startup files, "
          f"{len(persistence['scheduled_tasks'])} non-Microsoft scheduled tasks, "
          f"{len(persistence['services'])} auto-start services{C.RESET}")
    # On a cold scan there's no prior baseline -- compare against an empty
    # one so every current entry is surfaced as informational context.
    empty = {k: set() for k in persistence}
    for alert in engine.evaluate_persistence_delta(empty, persistence):
        alert.severity = "INFO"  # downgrade: this is inventory, not a detected change
        alert.title = alert.title.replace("New ", "Existing: ")
        logger.log(alert)

    print(f"{C.GRAY}Scanning active network connections...{C.RESET}")
    for c in collect_connections():
        for alert in engine.evaluate_network(c):
            logger.log(alert)

    logger.summary()
    print(f"\n{C.GRAY}Tip: run in --mode agent to catch NEW persistence and live "
          f"behavioral events as they happen, rather than a single snapshot.{C.RESET}")


def run_agent(logger: AlertLogger, engine: DetectionEngine, interval: int):
    """Continuous monitoring agent. Baselines persistence state on startup,
    then polls on the given interval, alerting on:
      - new persistence entries (diffed against the running baseline)
      - live process behavioral indicators (evaluated on every newly-seen PID)
      - live network behavioral indicators (evaluated on every connection seen)
    """
    print(f"{C.CYAN}{C.BOLD}PyEDR Agent starting -- baselining system state...{C.RESET}")
    baseline_persistence = collect_persistence_snapshot()
    print(f"{C.GRAY}Baseline: {len(baseline_persistence['run_keys'])} run keys, "
          f"{len(baseline_persistence['startup_files'])} startup files, "
          f"{len(baseline_persistence['scheduled_tasks'])} tasks, "
          f"{len(baseline_persistence['services'])} services{C.RESET}")

    known_pids = {p["pid"] for p in collect_processes()}
    print(f"{C.GRAY}Baseline: {len(known_pids)} running processes{C.RESET}")
    print(f"{C.GREEN}Agent live. Polling every {interval}s. Ctrl+C to stop.{C.RESET}\n")

    try:
        while True:
            time.sleep(interval)

            # --- persistence delta ---
            current_persistence = collect_persistence_snapshot()
            for alert in engine.evaluate_persistence_delta(baseline_persistence, current_persistence):
                logger.log(alert)
            baseline_persistence = current_persistence  # roll baseline forward

            # --- new processes: behavioral evaluation ---
            current_procs = collect_processes()
            current_pids = {p["pid"] for p in current_procs}
            new_pids = current_pids - known_pids
            for p in current_procs:
                if p["pid"] in new_pids:
                    for alert in engine.evaluate_process(p):
                        logger.log(alert)
            known_pids = current_pids

            # --- network behavioral evaluation ---
            for c in collect_connections():
                for alert in engine.evaluate_network(c):
                    logger.log(alert)

    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Agent stopped by user.{C.RESET}")
        logger.summary()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    C.enable_on_windows()

    parser = argparse.ArgumentParser(
        description="PyEDR -- lightweight, transparent, MITRE-mapped host EDR agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pyedr.py --mode scan
  python pyedr.py --mode agent --interval 15
  python pyedr.py --mode agent --interval 30 --min-severity MEDIUM --out ./logs
""",
    )
    parser.add_argument("--mode", choices=["scan", "agent"], default="scan",
                         help="scan = one-shot deep report; agent = continuous monitoring (default: scan)")
    parser.add_argument("--interval", type=int, default=10,
                         help="agent poll interval in seconds (default: 10)")
    parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER.keys()), default="LOW",
                         help="minimum severity to log/print (default: LOW)")
    parser.add_argument("--out", default="./pyedr_reports",
                         help="output directory for JSON/CSV alert logs (default: ./pyedr_reports)")
    args = parser.parse_args()

    if not IS_WINDOWS:
        print(f"{C.YELLOW}Note: not running on Windows -- registry/service/scheduled-task "
              f"persistence checks will be skipped. Process and network monitoring still work.{C.RESET}\n")

    logger = AlertLogger(args.out, min_severity=args.min_severity)
    engine = DetectionEngine()

    if args.mode == "scan":
        run_scan(logger, engine)
    else:
        run_agent(logger, engine, args.interval)


if __name__ == "__main__":
    main()
