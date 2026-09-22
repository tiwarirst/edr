# PyEDR: Enterprise Endpoint Detection and Response Agent

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![Platform: Windows | Linux | macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

**PyEDR** is a lightweight, rule-based endpoint detection system designed for transparent, continuous monitoring of host activities. Built to provide high-fidelity security telemetry, it empowers security teams, researchers, and system administrators to detect advanced threats without the overhead of heavy kernel-level drivers.

Our detection logic is highly auditable, deterministic, and rigorously mapped to the **MITRE ATT&CK®** framework.

## 🚀 Key Capabilities

- **Real-Time Behavioral Analysis**: Monitors process spawning and network connections to identify indicators of compromise (IoCs) and anomalous behaviors as they occur.
- **Persistence Mechanism Detection**: Continuously baselines and monitors system configurations (Registry keys, Scheduled Tasks, Windows Services, and Startup folders) to detect unauthorized persistence mechanisms.
- **Deterministic Detection Engine**: Eliminates "black-box" scoring models. Every alert provides explicit, context-rich details explaining the exact condition and MITRE technique that triggered it.
- **Flexible Deployment**: Supports both continuous background monitoring (Agent mode) and comprehensive point-in-time assessments (Scan mode).

## 🛠️ Architecture and Modes of Operation

PyEDR is designed for minimal system impact while maximizing visibility into user-space operations.

### Agent Mode (Continuous Monitoring)
The primary deployment mode for PyEDR. On initialization, the agent establishes a comprehensive baseline of the system's persistence mechanisms. It then continuously polls the system to detect:
- **State Anomalies**: Differential analysis of persistence configurations against the baseline.
- **Process Telemetry**: Real-time evaluation of newly spawned processes against behavioral signatures.
- **Network Telemetry**: Auditing of active network connections for unauthorized communications.

```bash
python pyedr.py --mode agent --interval 10
```

### Scan Mode (Point-in-Time Assessment)
Ideal for rapid forensic triage or incident response, Scan Mode conducts a deep, one-off evaluation of the system's current state, including active processes, persistence configurations, and network connections.

```bash
python pyedr.py --mode scan
```

## 🛡️ MITRE ATT&CK® Coverage

PyEDR provides out-of-the-box detection capabilities for the following adversary techniques:

| ID | Technique | Detection Logic |
|:---|:---|:---|
| **T1036.005** | Masquerading: Match Legitimate Name | Identifies processes imitating core Windows binaries (e.g., `svchost.exe`, `lsass.exe`) executing from unauthorized paths. |
| **T1036** | Masquerading (Space/Path) | Detects execution from inherently suspicious directories (e.g., `%Temp%`, `%Public%`, `%WinDir%\Temp`). |
| **T1219** | Remote Access Software | Flags execution of known Remote Monitoring and Management (RMM) and remote access tools. |
| **T1003** | OS Credential Dumping | Identifies known credential extraction tool signatures (e.g., `mimikatz`, `procdump`). |
| **T1059.001** | Command and Scripting: PowerShell | Detects execution of PowerShell with known evasion or obfuscation flags (`-EncodedCommand`, `-ep bypass`, etc.). |
| **T1027** | Obfuscated Files or Information | Identifies high-entropy or Base64-encoded payloads passed via command-line arguments. |
| **T1105** | Ingress Tool Transfer | Flags anomalous usage of Living-off-the-Land Binaries (LoLBins) like `certutil` or `bitsadmin` for network transfers. |
| **T1566/T1059** | Suspicious Parent-Child Process | Detects macro-based malware patterns where Office applications spawn scripting interpreters or command shells. |
| **T1547.001** | Registry Run Keys / Startup Folder | Identifies unauthorized additions to system autostart configurations. |
| **T1053.005** | Scheduled Task/Job | Detects the creation of non-standard scheduled tasks. |
| **T1543.003** | Windows Service | Flags the registration of new auto-start system services. |
| **T1071** | Application Layer Protocol | Identifies anomalous outbound connections from benign processes (e.g., `notepad.exe`) or connections to known C2 ports. |

## 📊 Reporting and Telemetry

PyEDR supports robust integration with existing SIEM/SOAR infrastructure through standardized output formats:

- **Standard Output (Console)**: Color-coded execution logs for immediate visual feedback.
- **JSON Lines (`.jsonl`)**: Structured, machine-readable telemetry ideal for log aggregation and SIEM ingestion.
- **Comma-Separated Values (`.csv`)**: Tabular data format for offline analysis and reporting.

By default, telemetry is stored in the `pyedr_reports/` directory.

## ⚙️ Installation and Usage

### Prerequisites
- Python 3.8 or higher.
- `psutil` library.

### Deployment Instructions

1. Clone the repository and install dependencies:
   ```bash
   git clone https://github.com/tiwarirst/edr.git
   cd edr
   pip install -r requirements.txt
   ```

2. Execute PyEDR (Administrative privileges recommended for full visibility):
   ```bash
   # Comprehensive point-in-time scan
   python pyedr.py --mode scan

   # Continuous monitoring agent (Logs MEDIUM and higher severity alerts)
   python pyedr.py --mode agent --interval 15 --min-severity MEDIUM

   # Continuous monitoring with custom telemetry routing
   python pyedr.py --mode agent --out D:\SecurityLogs
   ```

*Note: For complete visibility into Registry Run Keys, Windows Services, and Scheduled Tasks, PyEDR must be executed with Administrative (SYSTEM) privileges.*

## 💻 Platform Support

- **Windows**: Full feature support (Process, Network, and Persistence Monitoring).
- **macOS & Linux**: Process and Network behavioral monitoring supported. Persistence collectors fail gracefully.


## ⚠️ Disclaimer

PyEDR is an open-source, user-space detection tool. It does not employ kernel-level telemetry callbacks (e.g., ETWti) or advanced ML-based behavioral prevention mechanisms. It is designed to complement—not replace—commercial Endpoint Detection and Response (EDR) solutions. Use exclusively on systems where you possess explicit authorization.
