# PyEDR — Lightweight, Transparent Host EDR Agent

A rule-based, MITRE ATT&CK-mapped endpoint detection tool. It's built to be
**honest** about what it is: a real, working EDR-lite you can run and learn
from — not a re-implementation of CrowdStrike Falcon. There's no kernel
driver, no ML model, no cloud threat intel feed. What it does have is
readable, auditable detection logic you can point to and explain in an
interview.

## What "EDR-lite" means here

Commercial EDR (CrowdStrike, SentinelOne, Defender for Endpoint) gets its
power from kernel-mode telemetry hooks, behavioral ML trained across
millions of endpoints, and cloud-correlated threat intelligence. None of
that is replicable in a userspace script. What **is** replicable — and is
still genuinely useful — is the core detection loop every EDR runs on top
of that infrastructure: watch processes, watch persistence, watch network
connections, compare against known-bad patterns, alert with context.

## Two modes

### Scan mode (one-shot)
```bash
python pyedr.py --mode scan
```
Full inventory pass: evaluates every running process against behavioral
rules, snapshots all persistence locations, checks live network
connections. Good for "is anything obviously wrong right now."

### Agent mode (continuous)
```bash
python pyedr.py --mode agent --interval 10
```
Baselines the system on startup, then polls on the given interval
(default 10s):
- **Persistence delta detection** — diffs the current registry Run keys /
  startup folder / scheduled tasks / services against the last known
  state. Only *new* entries trigger an alert — this is what real EDR
  persistence monitoring looks like, and it's far more signal-rich than a
  static snapshot.
- **New-process behavioral evaluation** — every newly-spawned process is
  checked against all process rules at the moment it appears.
- **Network behavioral evaluation** — every established connection is
  checked on each poll.

Stop with Ctrl+C; you'll get a session summary.

## Detection rules (MITRE ATT&CK-mapped)

| Technique | Name | Trigger |
|---|---|---|
| T1036.005 | Masquerading: Match Legitimate Name | Process name matches a core Windows binary (svchost.exe, lsass.exe, etc.) but runs from the wrong directory |
| T1036 | Masquerading (path) | Any process executing from `%Temp%`, `C:\Users\Public`, `%WinDir%\Temp`, or non-Microsoft `ProgramData` |
| T1219 | Remote Access Software | Process name matches a known remote-access tool (TeamViewer, AnyDesk, ngrok, etc.) |
| T1003 | OS Credential Dumping | Process name matches a known credential-dumping tool (mimikatz, procdump, etc.) |
| T1059.001 | PowerShell w/ obfuscation flags | `-enc`, `-EncodedCommand`, `-nop`, `-w hidden`, `-ep bypass` on the command line |
| T1027 | Obfuscated Files or Information | Long base64-looking blob (80+ chars) in a command line |
| T1105 | Ingress Tool Transfer | `certutil`/`bitsadmin`/`curl`/`wget` invoked with a URL argument |
| T1566/T1059 | Suspicious Parent-Child Process | Office app (Word/Excel/Outlook/PowerPoint) spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, etc. |
| T1547.001 | Registry Run Keys / Startup Folder | New autostart registry entry or new Startup-folder file (agent mode only — needs a baseline to diff against) |
| T1053.005 | Scheduled Task/Job | New non-Microsoft scheduled task appears (agent mode only) |
| T1543.003 | Windows Service | New auto-start service appears (agent mode only) |
| T1071 | Application Layer Protocol | Outbound connection from a process with no legitimate reason to talk to the network (notepad.exe, calc.exe, etc.), or a connection to a commonly-abused C2 port (4444, 1337, 31337, 6666, 8888) |

Every alert prints the exact rule and the exact data that triggered it —
by design, there's no hidden scoring model. If you disagree with a finding,
you can read the code and see precisely why it fired.

## Output

- **Console**: color-coded by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **JSON Lines**: `pyedr_reports/pyedr_alerts_<timestamp>.jsonl` — one alert
  per line, easy to `tail -f` or feed into a SIEM
- **CSV**: same alerts, spreadsheet-friendly

## Usage

```bash
pip install -r requirements.txt

# Quick one-time check
python pyedr.py --mode scan

# Run as a monitoring agent, only log MEDIUM+ to reduce noise
python pyedr.py --mode agent --interval 15 --min-severity MEDIUM

# Custom output location
python pyedr.py --mode agent --out D:\SecurityLogs
```

Run **as Administrator on Windows** for full registry/service/scheduled-task
visibility — without elevation, some persistence locations are invisible to
the script (this mirrors real-world EDR agent deployment, which also runs
with elevated/system privileges).

## Platform notes

- **Process and network monitoring**: cross-platform (via `psutil`)
- **Persistence monitoring** (registry keys, scheduled tasks, services,
  startup folders): Windows-only. On Linux/Mac these collectors return
  empty sets and the agent will note this at startup rather than fail.

## Design choices worth explaining if asked

- **Delta-based persistence detection over static snapshots**: A one-time
  scan of "everything currently in your Run keys" is mostly noise — most
  of it is legitimate software you installed. What actually matters is
  *new* persistence appearing after the agent started watching. This
  mirrors how real EDR baselines an endpoint and alerts on deviation.
- **Rule transparency over ML scoring**: Every rule is a documented,
  auditable `if` condition mapped to a specific ATT&CK technique. This
  makes false positives explainable and the detection logic defensible —
  a property real SOC analysts value when tuning detection content.
- **Severity is fixed per rule, not computed**: Kept deliberately simple
  and honest rather than simulating a risk-scoring engine that doesn't
  have the telemetry breadth to back it up.

## Known limitations (be upfront about these)

- No kernel-level visibility — a sufficiently privileged attacker can see
  and kill this process like any other userspace program
- No file integrity monitoring / hashing of binaries yet (v1 of the
  earlier `SysTriage.ps1` script covers signature + hash checks — a good
  v2 addition here would be merging that in)
- No tamper protection — nothing stops an attacker from terminating the
  agent or clearing its logs
- Static rule set — no ML/anomaly baselining of "normal" behavior beyond
  the persistence delta mechanism
- Polling-based, not event-driven — a process that spawns and exits
  between polls in agent mode could be missed; a production EDR uses
  kernel callbacks (e.g., ETW on Windows) for this, which is a natural
  "what I'd build next" talking point

## Suggested v2 ideas (good for a follow-up portfolio iteration)

- Merge in the file-hash/signature checking from the earlier triage script
- Add ETW (Event Tracing for Windows) consumption via `pywin32` for
  real-time process creation events instead of polling
- Add a simple YARA rule integration for on-disk file scanning
- Add a `--baseline-file` option to persist baseline state across agent
  restarts (currently baselines fresh each run)
