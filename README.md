# AP Disjoin RCA

Automated root-cause-analysis platform for Cisco Catalyst 9800 wireless LAN
controllers. It watches a WLC for access points that keep disjoining, and — with
zero manual SSH — automatically captures the debug traces, embedded packet capture,
and evidence needed to explain why, then hands you a finished report.

## Features

- Real-time AP disjoin detection straight from the WLC, via a pushed EEM applet
  (no polling)
- Three trigger modes: EEM-confirmed batch (default), plain per-disjoin telemetry,
  and SNMP traps
- Fully automated RCA workflow per disjoining AP: targeted debug traces, a scoped
  Embedded Packet Capture (EPC), WLC-side evidence collection, and a second,
  independent SSH session straight to the AP itself
- Rule-based correlation engine — confidence level, probable cause, and
  recommended action, computed separately for WLC-side and AP-side evidence
- Automatic pcap + always-on RA-trace log export off the WLC via TFTP or SFTP
- Live PySide6 desktop GUI: colourised live log, workflow/transfer progress bars,
  and running stat tiles (lines, events, APs traced)
- One timestamped report folder per run — nothing overwrites a prior session
- Ships for Windows (single `.exe`) and macOS Apple Silicon (`.app` bundle)

## Technologies Used

- Python 3.12+
- PySide6 (GUI)
- Netmiko / Paramiko (SSH automation to WLC and AP)
- grpcio + Protocol Buffers (MDT telemetry dial-out listener)
- PyYAML (device inventory)
- PyInstaller (Windows/macOS packaging)

## Prerequisites

- Python 3.11+ (3.12 recommended — this is what the project has been built and
  tested against)
- Network reachability to the target WLC on SSH (TCP/22)
- For telemetry/EEM-batch trigger modes: the WLC must be able to reach **this
  machine** on the configured gRPC port (default `57500`) — see
  [Configuration](#configuration) below
- A Cisco IOS-XE WLC (developed and tested on C9800-CL) with SSH access and EEM
  applet support
- `netconf-yang` enabled on the WLC — required for the MDT telemetry subscription
  the app pushes. If it's missing, the app's EEM/telemetry config push still
  succeeds, but no disjoin will ever be seen (see
  [Troubleshooting](#troubleshooting))

## Installation

```bash
git clone https://github.com/SamarthMasti/ap-disjoin-rca-git.git
cd ap-disjoin-rca-git

python3 -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt
```

## How to Run

```bash
python gui_main.py
```

This launches the desktop GUI, a three-step flow:

1. **Workflow Selection** — pick the workflow (currently: AP Disjoin RCA).
2. **Configure** — pick a device from the inventory (or fill in one manually),
   choose the trigger mode, transfer protocol, and any advanced options.
3. **Run** — start the monitor. You'll see a live, colourised log, a workflow
   progress bar (tracks the current RCA phase), a transfer progress bar (tracks
   an in-progress TFTP/SFTP upload), and running stat tiles for lines/events/APs
   traced.

The app keeps running and watching for disjoins until you click **Stop**, or a
configured duration limit is reached.

## Configuration

### Device inventory — `CONF/iosxe_devices.yaml`

Each entry describes one WLC and its companion settings:

```yaml
iosxe_devices:
  - name: WLC_1
    host: 192.168.0.100
    username: admin
    password: Cisco123
    enable_secret: ''
    port: 22
    platform: C9800-CL
    os_version: 17.9.4
    ap_username: admin
    ap_password: Aigle123
    ap_secret: Aigle123
    jumphost_ip: 192.168.0.16      # see note below — not an SSH jump host
    tftp_ip: 192.168.0.16
    transfer_proto: TFTP           # or SFTP
    sftp_username: sftpuser
    sftp_password: Cisco123!
```

> **`jumphost_ip` is misleadingly named** — it is not an SSH jump host. It's the
> address the WLC is told to dial its telemetry stream *back to*, i.e. **this
> machine's own IP as reachable from the WLC's network**. If it's wrong or
> unreachable, the EEM/telemetry config still pushes without error — the WLC
> just never calls back, and no disjoin is ever detected.

### Evidence command catalogs

Two plain-text files drive what gets collected during an RCA:

- `CONF/wlc_commands.conf` — commands run over the **WLC's own CLI**, asking it
  about the AP (crash files, image version, CPU, CAPWAP counters, etc.)
- `CONF/ap_commands.conf` — commands run over a **second, direct SSH session to
  the AP itself** (CAPWAP/DTLS debug toggles, live traffic capture debugs, etc.)

Each line is either a plain `show`/config command, or a command suffixed with
`|debug` to mark it as a debug toggle rather than a show command:

```
show ap crash-file
show wireless stats ap mac {mac} discovery detailed
debug capwap client event|debug
```

### Trigger modes

Selected on the Configure page:

| GUI label | Internal mode | Behaviour |
|---|---|---|
| TELEMETRY EEM (default) | `eem_batch` | WLC counts 3 disjoins in any 10-minute window itself, then confirms the batch and launches a full RCA on the most recently disjoined AP |
| — (no GUI control currently) | `telemetry` | Reacts to each individual disjoin directly |
| SNMP Traps | `snmp` | Same batch-counting logic as EEM_BATCH, delivered as an SNMP trap instead of an MDT telemetry export — currently disabled in the GUI pending backend completion |

## Output / Reports

Every run gets its own timestamped folder:

```
reports/2026/09/10/run_13/
├── session_log_192.168.0.100_20260910T070527Z.txt   full raw session log
├── wlc_telemetry_192_168_0_212_20260910070630.txt   WLC-side evidence + correlation
├── ap_telemetry_192_168_0_212_20260910070630.txt    direct-AP-SSH evidence
└── detected_aps_20260910070630.txt                  APs seen in the confirmed batch
```

The packet capture (`.pcap`) and the WLC's always-on RA-trace log are **not**
stored locally — they're exported to the WLC's own flash, then shipped straight
off to whichever TFTP/SFTP server is configured for that device.

## Building the executable

Two separate `.spec` files, kept deliberately independent so neither platform's
build settings can affect the other. PyInstaller does not cross-compile — each
must be built on a machine actually running that OS.

### Windows

```bash
pip install pyinstaller
pyinstaller APDIsjoinRCA.spec
```

Output: `dist/APDisjoinRCA.exe` (single-file, no console window).

### macOS (Apple Silicon)

```bash
pip install pyinstaller
pyinstaller APDisjoinRCA-macos-arm64.spec
```

Output: `dist/APDisjoinRCA.app` — a proper double-clickable app bundle
(Finder/Dock/Applications integration), pinned to `arm64`. Must be run on a Mac.

## Project structure

```
ap-disjoin-rca-git/
├── gui_main.py                    GUI entry point (PySide6)
├── ap_disjoin_monitor_tool.py     Core engine — EEM/trigger handling, RCA
│                                  workflow, gRPC listener, finalization
├── backend/
│   ├── config.py                 Runtime config (CLI args + GUI config → one shape)
│   ├── engine/
│   │   ├── monitor_engine.py     GUI ⇄ core engine bridge
│   │   ├── finalizer.py          Second-disjoin cleanup, pcap export, TFTP/SFTP
│   │   └── event_engine.py       Batch window / dedup logic
│   ├── rca/
│   │   └── correlation.py        Rule-based correlation engine
│   └── state/                    Small JSON state files (dedup, counters, history)
├── gui/controllers/
│   └── monitor_controller.py     Engine event → Qt signal bridge
├── CONF/
│   ├── iosxe_devices.yaml        Device inventory
│   ├── wlc_commands.conf         WLC-side evidence catalog
│   └── ap_commands.conf          AP-side evidence catalog
├── reports/                      Per-run output (created at runtime)
├── requirements.txt
├── APDIsjoinRCA.spec              PyInstaller spec — Windows
└── APDisjoinRCA-macos-arm64.spec  PyInstaller spec — macOS (Apple Silicon)
```

## Troubleshooting

- **`show telemetry ietf subscription ... detail` returns "process not
  responding"** — `netconf-yang` isn't enabled on the WLC. Enable it
  (`configure terminal` → `netconf-yang`), wait a minute or two for the process
  to come up, and retry.
- **Everything connects fine, but no disjoin is ever detected** — almost always
  `jumphost_ip` (see [Configuration](#configuration)) pointing at an address the
  WLC can't actually reach. Confirm it's this machine's real IP as seen from the
  WLC's side of the network.
- **`[MDT] gRPC session closed` with no `Stop requested` line before it, followed
  by a `TypeError` traceback** — this is the WLC's own MDT dial-out client
  cycling its session after a period of idle time. It's expected Cisco-side
  behaviour, not a crash — the app is a passive gRPC server and automatically
  accepts the WLC's next connection when it reconnects.
- **A WLC ACL locks you out over SSH** — Cisco extended ACLs carry an implicit
  `deny ip any any` at the end. Any ACL applied to a management interface/VTY
  line with no explicit `permit` will block everything, including your own
  management session. Recovery requires console access (not SSH) to remove the
  offending `ip access-group`/`access-class` line.
