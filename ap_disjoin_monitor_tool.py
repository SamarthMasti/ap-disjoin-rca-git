#!/usr/bin/env python3
"""
ap_disjoin_monitor_tool.py —  Network Automation Toolkit
==============================================================
Live-stream AP disjoin detection for Cisco Catalyst 9800 IOS-XE WLC.

Architecture:
    terminal monitor  →  WLC pushes logs live to SSH terminal
    Parse stream      →  detect disjoin event, extract MAC
    debug wireless mac <MAC>  →  trigger RA conditional trace
    show commands     →  collect evidence for that specific AP

No polling. No repeated full log reads. Event-driven and real-time.
"""
# gRPC MDT — generated from telemetry.proto + mdt_grpc_dialout.proto
# Run: python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. telemetry.proto mdt_grpc_dialout.proto

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import socket
import traceback

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections import deque

try:
    from netmiko import ConnectHandler
except ImportError:
    print(json.dumps({"ok": False, "error": "pip install netmiko"}))
    sys.exit(1)

try:
    import yaml
except ImportError:
    print(json.dumps({"ok": False, "error": "pip install pyyaml"}))
    sys.exit(1)
import queue
from concurrent.futures import ThreadPoolExecutor

from backend.config import config_from_args
from backend.engine import event_engine
from backend.engine import MonitorEngine
from backend.state import counters as state_counters
from backend.state import disjoin_occurrences as state_disjoin_occurrences
from backend.state import event_history as state_event_history
from backend.state import finalized_history as state_finalized_history
from backend.state import workflow_state as state_workflow_state
from backend.rca import (
    correlate, correlate_ap_side, CorrelationEngine,
    collect_ap_side_evidence, resolve_ap_name_from_mac,
    collect_advanced_capwap_on_ap,
)
MAX_CONCURRENT_RCA = int(os.getenv("MAX_CONCURRENT_RCA", "5"))
_rca_queue: queue.Queue = queue.Queue()
_rca_executor: ThreadPoolExecutor | None = None



import logging
from logging.handlers import RotatingFileHandler

def setup_logging(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("")
    logger.setLevel(logging.WARNING)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
   
    if not logger.handlers:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        #logger.addHandler(fh)
        logger.addHandler(ch)
    return logger

log: logging.Logger | None = None   # initialized in run_monitor()

# Config
# ---------------------------------------------------------------------------

DEFAULT_INVENTORY   = "inventory/iosxe_devices.yaml"
REPORTS_DIR         = Path("reports")

GRPC_PORT            = 57500
MAC_LOOKBACK_LINES   = 50
TRACE_SETTLE_DELAY  = 5     # seconds after debug command before collecting
LIVE_BUFFER_MAXLEN  = 200    # rolling buffer size (lines)
DISJOIN_COUNTER_FILE = REPORTS_DIR / "ap_disjoin_counters.json"
SUMMARY_STATS_FILE   = REPORTS_DIR / "summary_stats.json"
AP_STATS_FILE        = REPORTS_DIR / "ap_disjoin_stats.json"
AP_STATS_LOCK        = threading.Lock()
AP_STATS_MAX_TIMESTAMPS = 100
DEDUP_CACHE_TTL = int(os.getenv("DEDUP_TTL_SECONDS", "30"))  # configurable
MIN_RCA_SESSION_AGE = int(
    os.getenv("MIN_RCA_SESSION_AGE_SECONDS", "30")
)
_dedup_cache: dict[str, float] = {}   # key → last_seen epoch
_dedup_lock  = threading.Lock()
# ── AP Traced Count file ──────────────────────────────────────────────────
AP_TRACED_COUNT_FILE = REPORTS_DIR / "ap_traced_count.json"
AP_TRACED_COUNT_LOCK = threading.Lock()

def set_ap_traced_count(value: int) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with AP_TRACED_COUNT_LOCK:
        tmp = AP_TRACED_COUNT_FILE.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps({"count": value}), encoding="utf-8")
            tmp.replace(AP_TRACED_COUNT_FILE)
        except Exception:
            try: tmp.unlink(missing_ok=True)
            except Exception: pass

def increment_ap_traced_count() -> int:
    with AP_TRACED_COUNT_LOCK:
        try:
            data = json.loads(AP_TRACED_COUNT_FILE.read_text(encoding="utf-8"))
            current = data.get("count", 0)
        except Exception:
            current = 0
        new_val = current + 1
        tmp = AP_TRACED_COUNT_FILE.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps({"count": new_val}), encoding="utf-8")
            tmp.replace(AP_TRACED_COUNT_FILE)
        except Exception:
            try: tmp.unlink(missing_ok=True)
            except Exception: pass
        return new_val
def _is_duplicate(key: str) -> bool:
    """Returns True if this key was seen within DEDUP_CACHE_TTL seconds."""
    now = time.monotonic()
    with _dedup_lock:
        # expire stale entries
        expired = [k for k, t in _dedup_cache.items() if now - t > DEDUP_CACHE_TTL]
        for k in expired:
            del _dedup_cache[k]
        if key in _dedup_cache:
            return True
        _dedup_cache[key] = now
        return False
DISJOIN_THRESHOLD    = 3    # full RCA triggered at this count
MDT_DEBUG = os.getenv("MDT_DEBUG", "false").lower() == "true"
MDT_DEBUG_DIR = REPORTS_DIR / "raw_mdt_payloads"
# ── Transport mode: set at runtime via CLI prompt ─────────────────────────
SNMP_COMMUNITY  = "public"
TRIGGER_MODE    = "telemetry"   # overwritten in run_monitor() based on user input
MYCAP_NAME           = "MYCAP"
# ACTIVE_RCA holds the currently running RCA session.
# Structure: { "mac": str, "ap_name": str|None, "ip": str|None,
#              "conn": ConnectHandler, "finalize_event": threading.Event }
# None = no active session.
ACTIVE_RCA_SESSIONS: dict[str, dict] = {}   # keyed by MAC
ACTIVE_RCA_LOCK = threading.Lock()
# ── GDC: Global Disjoin Counter — never resets, persisted to JSON ─────────
GDC_FILE  = REPORTS_DIR / "gdc.json"
GDC_LOCK  = threading.Lock()

# ── CGDC: Cumulative Global Disjoin Counter — resets after every batch of 3
CGDC_FILE                  = REPORTS_DIR / "cgdc.json"
CGDC_LOCK                  = threading.Lock()
CGDC_BATCH_SIZE            = 3
CGDC_WINDOW_SECONDS        = 600

# ── EEM-BATCH MODE: single global RCA session state machine ──────────────
# States: IDLE → RCA_ACTIVE → WAITING_RECURRENCE → IDLE
GLOBAL_RCA_SESSION_FILE             = REPORTS_DIR / "global_rca_session.json"
GLOBAL_RCA_SESSION_LOCK             = threading.Lock()
EEM_BATCH_DETECTION_WINDOW_SECONDS  = 600    # 3 disjoins (any AP) within 10 min
EEM_BATCH_RECURRENCE_WINDOW_SECONDS = 1800   # same locked AP recurs within 30 min
FOURTH_DISJOIN_RECURRENCE_WINDOW = int(os.getenv("FOURTH_DISJOIN_RECURRENCE_WINDOW", "1800"))

DISJOIN_OCCURRENCES_FILE   = REPORTS_DIR / "disjoin_occurrences.json"
DISJOIN_OCCURRENCES_LOCK   = threading.Lock()

# ── Disjoin Event History — every completed CGDC batch stored here ────────
DISJOIN_EVENT_HISTORY_FILE = REPORTS_DIR / "disjoin_event_history.json"
DISJOIN_EVENT_HISTORY_LOCK = threading.Lock()

# ── AP Workflow State — per-AP active workflow tracking ───────────────────
AP_WORKFLOW_STATE_FILE = REPORTS_DIR / "ap_workflow_state.json"
FINALIZED_APS_FILE = REPORTS_DIR / "finalized_aps_history.json"
FINALIZED_APS_LOCK = threading.Lock()
AP_WORKFLOW_STATE_LOCK = threading.Lock()

# ── Per-workflow disjoin threshold before finalization ────────────────────
WORKFLOW_DISJOIN_THRESHOLD = 3    # finalize when per-AP count reaches this
RCA_SESSION_TIMEOUT        = 30 * 60   # 30-minute per-workflow timer
SUCCESS_RE = re.compile(
    r"\d+\s+bytes\s+copied\s+in\s+\d+(\.\d+)?\s+secs",
    re.I
)
# ── Custom Debug Commands — Start/Stop block parser ────────────────────────
DEBUG_START_RE = re.compile(r"^\s*start\s*$", re.IGNORECASE)
DEBUG_STOP_RE  = re.compile(r"^\s*stop\s*$",  re.IGNORECASE)

def parse_debug_command_file(path: str) -> tuple[list[str], list[str]]:
    """
    Parse an attached debug-command .txt file into (start_cmds, stop_cmds).

    - A line that is exactly "Start" marks the beginning of the start block.
    - A line that is exactly "Stop" (if present, after Start) ends the start
      block and begins the stop block — everything after it to EOF.
    - If no "Stop" line exists, every line after "Start" becomes start_cmds
      and stop_cmds is empty.
    - If no "Start" line exists at all, every non-blank line in the file is
      treated as start_cmds (flat list still works).
    Blank lines and lines starting with '!' or '#' are ignored.
    """
    try:
        raw_lines = Path(path).read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        print(f"[{ts()}] [DEBUG_CMDS] Could not read {path}: {exc}", file=sys.stderr)
        return [], []

    start_idx = None
    stop_idx  = None
    for i, line in enumerate(raw_lines):
        if start_idx is None and DEBUG_START_RE.match(line):
            start_idx = i
            continue
        if start_idx is not None and stop_idx is None and DEBUG_STOP_RE.match(line):
            stop_idx = i
            break

    def _clean(block: list[str]) -> list[str]:
        return [
            l.strip() for l in block
            if l.strip() and not l.strip().startswith("!") and not l.strip().startswith("#")
        ]

    if start_idx is None:
        return _clean(raw_lines), []

    if stop_idx is not None:
        return _clean(raw_lines[start_idx + 1:stop_idx]), _clean(raw_lines[stop_idx + 1:])

    return _clean(raw_lines[start_idx + 1:]), []

def load_command_catalog(path: str) -> list[dict]:
    """
    Load a flat command list from a .conf file.
    Each line is either:
        a plain command            → {"cmd": line, "is_debug": False}
        a command|debug             → {"cmd": cmd_part, "is_debug": True}
    Blank lines and lines starting with '#' or '!' are ignored.
    Returns [] if the file doesn't exist or fails to parse — caller should
    fall back to an empty list (no commands run) rather than crash.
    """
    p = Path(path)
    if not p.exists():
        print(f"[{ts()}] [CMD_CATALOG] File not found: {path} — no commands loaded.", file=sys.stderr)
        return []
    try:
        raw_lines = p.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        print(f"[{ts()}] [CMD_CATALOG] Could not read {path}: {exc}", file=sys.stderr)
        return []

    catalog: list[dict] = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if line.endswith("|debug"):
            catalog.append({"cmd": line[:-len("|debug")].strip(), "is_debug": True})
        else:
            catalog.append({"cmd": line, "is_debug": False})
    return catalog
# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
_AP_NAME_BLOCKLIST = {
    "event", "name", "mac", "address", "ip", "has", "disjoined",
    "from", "the", "wlc", "join", "disjoin", "capwap", "dtls",
    "connected", "registered", "unregistered", "reset", "reboot",
    "chassis", "active", "standby", "controller", "wireless",
}
DISJOIN_RE = re.compile(
    r"AP_JOIN_DISJOIN.*Disjoined",
    re.IGNORECASE,
)
EEM_TRIGGER_RE = re.compile(
    r"(AP_JOIN_DISJOIN.*Disjoined|EEM_BATCH_TRIGGER)",
    re.IGNORECASE
)
APNAME_RE = re.compile(
    r"AP Name: ([^ ]+)",
    re.IGNORECASE
)

APMAC_RE = re.compile(
    r"Mac: ([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})",
    re.IGNORECASE
)

APIP_RE = re.compile(
    r"Session-IP: (\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE
)

REASON_RE = re.compile(
    r"Disjoined (.*)",
    re.IGNORECASE
)
AP_NAME_RE = re.compile(r"AP\s*(?:Name)?[:\s]+([A-Za-z0-9_\-\.]+)", re.IGNORECASE)

# Matches  cc7f.755a.e740  OR  cc:7f:75:5a:e7:40  OR  cc-7f-75-5a-e7-40
MAC_RE = re.compile(
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})|"
    r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
    r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})"
)

IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

# Correlation
CRASH_RE    = re.compile(r"reboot.*crash|crash.*reboot",   re.IGNORECASE)
WATCHDOG_RE = re.compile(r"watchdog|kernel\s+panic",       re.IGNORECASE)
DTLS_RE     = re.compile(r"DTLS.*(?:alert|closed)",        re.IGNORECASE)
HB_RE       = re.compile(r"heart\s*beat|keepalive",        re.IGNORECASE)
# ── AP-SIDE correlation patterns (WLC-reported AP telemetry) ──────────────
AP_SHORT_UPTIME_RE  = re.compile(
    r"(\d+)\s*day[s]?,\s*(\d+)\s*hour[s]?,\s*(\d+)\s*minute",
    re.IGNORECASE,
)
AP_CRASH_FILE_RE    = re.compile(r"crash|watchdog|kernel.?panic|exception|core", re.IGNORECASE)
AP_CAPWAP_RESET_RE  = re.compile(r"retransmit|timeout|reset|tunnel.*down|dtls.*fail|handshake", re.IGNORECASE)
AP_UPLINK_RE        = re.compile(r"ethernet.*down|link.*down|port.*down|uplink.*fail|carrier.*lost", re.IGNORECASE)
AP_POE_RE           = re.compile(r"poe|power.?over.?ethernet|insufficient.*power|power.*denied|brownout", re.IGNORECASE)
AP_REBOOT_REASON_RE = re.compile(r"reboot.*reason|reload.*reason|last.*reset|power.?cycle|cold.?reset", re.IGNORECASE)
# ── AP-SIDE command catalog — desired telemetry vs what WLC actually supports ──
# key          : identifier used for capability matching
# cmd_template : format string — {ap_name} substituted at runtime
# description  : what this command collects
# ── AP-SIDE validated command catalog — production-confirmed IOS-XE syntax ──
# Global commands (no ap_name substitution) use needs_ap_name=False.
# Per-AP commands use needs_ap_name=True — skipped if AP name is unavailable.
AP_SIDE_COMMAND_CATALOG: list[dict] = [
    {
        "key":           "uptime",
        "cmd_template":  "show ap uptime",
        "needs_ap_name": False,
        "description":   "All AP uptimes — detect recent reboots across the controller",
    },
    {
        "key":           "summary",
        "cmd_template":  "show ap summary",
        "needs_ap_name": False,
        "description":   "AP join state and operational baseline",
    },
    {
        "key":           "crash-file",
        "cmd_template":  "show ap crash-file",
        "needs_ap_name": False,
        "description":   "AP crash files — watchdog, kernel panic, software exception evidence",
    },
    {
        "key":           "config",
        "cmd_template":  "show ap name {ap_name} config general",
        "needs_ap_name": True,
        "description":   "AP config — regulatory domain, mode, join parameters",
    },
    {
        "key":           "capwap",
        "cmd_template":  "show ap name {ap_name} capwap retransmit",
        "needs_ap_name": True,
        "description":   "CAPWAP retransmit counters — tunnel instability evidence",
    },
    {
        "key":           "ethernet",
        "cmd_template":  "show ap name {ap_name} ethernet statistics",
        "needs_ap_name": True,
        "description":   "AP Ethernet port statistics — uplink errors and drops",
    },
    {
        "key":           "environment",
        "cmd_template":  "show ap name {ap_name} environment",
        "needs_ap_name": True,
        "needs_mac":     False,
        "description":   "AP environment — PoE, power draw, temperature",
    },
    # ── New WLC commands validated list ───────────────────
    {
        "key":           "platform-resources",
        "cmd_template":  "show platform resources",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "Controller CPU/memory utilization",
    },
    {
        "key":           "cpu-wncd",
        "cmd_template":  "show processes cpu platform | include wncd",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "wncd process CPU — high CPU delays CAPWAP keepalive handling",
    },
    {
        "key":           "ap-image",
        "cmd_template":  "show ap image summary",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "AP image versions — mismatch causes repeated disjoin/rejoin",
    },
    {
        "key":           "disjoin-log",
        "cmd_template":  "show logging | include AP_JOIN_DISJOIN",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "Historical AP_JOIN_DISJOIN syslog entries",
    },
    {
        "key":           "wireless-stats-history",
        "cmd_template":  "show wireless stats ap history",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "AP join/disjoin history counters across the controller",
    },
    {
        "key":           "crash-dir",
        "cmd_template":  "dir all | include crash",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "Filesystem-level crash file listing",
    },
    {
        "key":           "cpu-sorted",
        "cmd_template":  "show processes cpu platform sorted | exclude      0%      0%      0%",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "Top CPU consumers on controller platform",
    },
    {
        "key":           "obj-mgr-delete",
        "cmd_template":  "show platform software object-manager chassis active F0 childless-delete-object",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "Object manager delete queue — stale CAPWAP object buildup",
    },
    {
        "key":           "obj-mgr-pending",
        "cmd_template":  "show platform software object-manager chassis active F0 pending-issue-update",
        "needs_ap_name": False,
        "needs_mac":     False,
        "description":   "Object manager pending updates — forwarding plane sync issues",
    },
    {
        "key":           "stats-discovery",
        "cmd_template":  "show wireless stats ap mac {mac} discovery detailed",
        "needs_ap_name": False,
        "needs_mac":     True,
        "description":   "Per-AP CAPWAP discovery phase statistics",
    },
    {
        "key":           "stats-join",
        "cmd_template":  "show wireless stats ap mac {mac} join detailed",
        "needs_ap_name": False,
        "needs_mac":     True,
        "description":   "Per-AP CAPWAP join phase failure counters",
    },
    {
        "key":           "always-on-log",
        "cmd_template":  "show logging profile wireless start last 15 min filter mac {mac} to-file flash:ALWAYS_ON_{mac}.log",
        "needs_ap_name": False,
        "needs_mac":     True,
        "description":   "Always-on RA trace for this AP — last 15 minutes",
    },
]
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def _warn(message: str) -> None:
    print(f"[{ts()}] {message}", file=sys.stderr)

def normalise_mac(raw: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(digits) != 12:
        return raw.lower()
    return ":".join(digits[i:i+2] for i in range(0, 12, 2)).lower()

def extract_mac(text: str) -> str | None:
    m = MAC_RE.search(text)
    return normalise_mac(m.group(0)) if m else None
def reset_disjoin_counter(mac: str) -> None:
    counters = load_disjoin_counters()
    if mac in counters:
        del counters[mac]
    #REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    #tmp_path = DISJOIN_COUNTER_FILE.with_suffix(".json.tmp")
    #try:
     #   tmp_path.write_text(
      #      json.dumps(counters, indent=2, sort_keys=True),
       #     encoding="utf-8",
        #)
        #tmp_path.replace(DISJOIN_COUNTER_FILE)
    #except Exception as exc:
     #   print(
      #      f"[{ts()}] WARNING: Could not save counter file during reset: {exc}",
       #     file=sys.stderr,
        #)
        #ry:
         #   tmp_path.unlink(missing_ok=True)
        #except Exception:
         #   pass
def extract_ap_name(text: str) -> str | None:
    for m in AP_NAME_RE.finditer(text):
        candidate = m.group(1).strip()
        # skip known false-positive words
        if candidate.lower() in _AP_NAME_BLOCKLIST:
            continue
        # skip if it looks like a MAC address fragment
        if re.fullmatch(r"[0-9a-fA-F]{2,4}[\.\:\-][0-9a-fA-F]+.*", candidate):
            continue
        return candidate
    return None
def resolve_ap_name_from_mac(conn: Any, mac: str) -> str | None:
    """
    Look up the real AP name from 'show ap summary' using the MAC address.
    Handles both colon (cc:7f:75:5a:e7:40) and dot (cc7f.755a.e740) notation.
    """
    digits  = re.sub(r"[^0-9a-fA-F]", "", mac)
    dot_mac = f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}".lower()
    colon_mac = mac.lower()

    try:
        output = conn.send_command("show ap summary", read_timeout=30)
        for line in output.splitlines():
            line_lower = line.lower()
            if dot_mac in line_lower or colon_mac in line_lower:
                parts = line.split()
                if parts:
                    return parts[0]   # AP name is always the first column
    except Exception:
        pass
    return None

def load_finalized_aps_history() -> list:
    return state_finalized_history.load_finalized_aps_history(REPORTS_DIR, FINALIZED_APS_FILE)


def save_finalized_aps_history(data: list) -> None:
    state_finalized_history.save_finalized_aps_history(
        data, REPORTS_DIR, FINALIZED_APS_FILE, _warn
    )


def append_finalized_ap(
    mac: str,
    ap_name: str | None,
    ip: str | None,
    
) -> None:
    state_finalized_history.append_finalized_ap(
        mac, ap_name, ip, REPORTS_DIR, FINALIZED_APS_FILE,
        FINALIZED_APS_LOCK, ts, _warn
    )
def collect_ap_side_evidence(conn: Any, ap_name: str | None, mac: str) -> dict[str, str]:
    """
    Collect AP-side operational telemetry via WLC SSH.
    All commands are WLC EXEC-level — no direct AP console access.

    Uses a validated production-confirmed command list.
    Global commands run unconditionally.
    Per-AP commands are skipped if ap_name is unavailable.
    Defensive error handling skips any command that returns an error response.
    """
    ap_evidence: dict[str, str] = {}

    digits  = re.sub(r"[^0-9a-fA-F]", "", mac)
    dot_mac = f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}".lower()

    for entry in AP_SIDE_COMMAND_CATALOG:
        needs_ap  = entry["needs_ap_name"]
        needs_mac = entry.get("needs_mac", False)

        # skip per-AP commands if we don't have the AP name
        if needs_ap and not ap_name:
            print(
                f"[{ts()}]   [WLC AP TELEMETRY] SKIP (no AP name): {entry['cmd_template']}",
                file=sys.stderr,
            )
            continue

        if needs_ap and needs_mac:
            cmd = entry["cmd_template"].format(ap_name=ap_name, mac=dot_mac)
        elif needs_ap:
            cmd = entry["cmd_template"].format(ap_name=ap_name)
        elif needs_mac:
            cmd = entry["cmd_template"].format(mac=dot_mac)
        else:
            cmd = entry["cmd_template"]

        print(f"[{ts()}]   [WLC AP TELEMETRY] {cmd}", file=sys.stderr)
        try:
            output = conn.send_command(cmd, read_timeout=60)

            # guard: discard IOS-XE error responses — don't pollute evidence
            if not output or output.strip().startswith("%") or "Invalid input" in output:
                print(
                    f"[{ts()}]   [WLC AP TELEMETRY] Skipped (unsupported/error): {cmd}",
                    file=sys.stderr,
                )
                continue

            ap_evidence[cmd] = output

        except Exception as exc:
            print(
                f"[{ts()}]   [WLC AP TELEMETRY] Error executing '{cmd}': {exc}",
                file=sys.stderr,
            )

    return ap_evidence
# ── Advanced CAPWAP/DTLS command catalog ──────────────────────────────────
# show commands → send_command (returns output)
# debug commands → send_command_timing (toggle only; output is the ack line)
AP_ADVANCED_CAPWAP_CATALOG: list[dict] = [
    #{"key": "terminal-len",        "cmd": "terminal length 0",      "is_debug": True},    
    #{"key": "show-logging",        "cmd": "show logging",  "is_debug": False},    
    # ── CAPWAP client state ───────────────────────────────────────────────
    {"key": "capwap-client-conf",  "cmd": "show capwap client conf",  "is_debug": False},
    {"key": "capwap-client-rcb",   "cmd": "show capwap client rcb",   "is_debug": False},
    # ── PnP / provisioning ───────────────────────────────────────────────
    {"key": "pnpinfo",             "cmd": "show pnpinfo",             "is_debug": False},
    {"key": "pnp-log",             "cmd": "show pnp log",             "is_debug": False},
    # ── IPv6 DHCP ────────────────────────────────────────────────────────
    {"key": "ipv6-dhcp",           "cmd": "show ipv6 dhcp",           "is_debug": False},
    # ── DTLS state ───────────────────────────────────────────────────────
    {"key": "dtls-connections",    "cmd": "show dtls connections",    "is_debug": False},
    {"key": "dtls-statistics",     "cmd": "show dtls statistics",     "is_debug": False},
    # ── CAPWAP debug toggles (ack-only output) ────────────────────────────
    {"key": "dbg-capwap-event",    "cmd": "debug capwap client event",   "is_debug": True},
    {"key": "dbg-capwap-info",     "cmd": "debug capwap client info",    "is_debug": True},
    {"key": "dbg-capwap-payload",  "cmd": "debug capwap client payload", "is_debug": True},
    {"key": "dbg-capwap-detail",   "cmd": "debug capwap client detail",  "is_debug": True},
    {"key": "dbg-capwap-pmtu",     "cmd": "debug capwap client pmtu",    "is_debug": True},
    {"key": "dbg-capwap-events",   "cmd": "debug capwap client events",  "is_debug": True},
    # ── DTLS debug toggles ────────────────────────────────────────────────
    {"key": "dbg-dtls-events",     "cmd": "debug dtls client events",        "is_debug": True},
    {"key": "dbg-dtls-events-det", "cmd": "debug dtls client events detail", "is_debug": True},
    # ── UDP 5246 traffic capture (non-blocking, one-shot) ─────────────────
    {"key": "dbg-traffic-host",    "cmd": "debug traffic host filter UDP dst_port 5246 capture",  "is_debug": True},
    {"key": "dbg-traffic-wired",   "cmd": "debug traffic wired filter UDP dst_port 5246 capture", "is_debug": True},
    # ── Additional AP-side commands list ─────────────────
    {"key": "show-ip-int-br",      "cmd": "show ip int br",               "is_debug": False},
    {"key": "dbg-capwap-error",    "cmd": "debug capwap client error",    "is_debug": True},
    {"key": "dbg-dtls-error",      "cmd": "debug dtls client error",      "is_debug": True},
    {"key": "dbg-dtls-event",      "cmd": "debug dtls client event",      "is_debug": True},
    # ── Enable Terminal Monitor on AP ─────────────────
    
]


def collect_advanced_capwap_evidence(conn: Any, ap_name: str | None) -> dict[str, str]:
    """Stub — advanced CAPWAP/DTLS commands are now sent directly to the AP via SSH."""
    return {}


def collect_advanced_capwap_on_ap(ap_ip: str, ap_auth: dict, ap_name: str | None) -> dict[str, str]:
    """
    SSH directly to the AP and collect advanced CAPWAP/DTLS diagnostics.
    Uses AP credentials from inventory (ap_username / ap_password / ap_secret).
    All failures are swallowed — never interrupts the main RCA pipeline.
    """
    advanced: dict[str, str] = {}
    
    print(f"[{ts()}]   [AP] Connecting directly to AP at {ap_ip} ...",
          file=sys.stdout)
    catalog = load_command_catalog("CONF/ap_commands.conf")
    if not catalog:
        catalog = AP_ADVANCED_CAPWAP_CATALOG   # fallback to built-in defaults
        print(f"[{ts()}]   [AP] Using built-in command catalog (CONF/ap_commands.conf not found/empty).", file=sys.stderr)
    time.sleep(TRACE_SETTLE_DELAY)
    try:
        ap_conn = ConnectHandler(
            device_type="cisco_ios",
            host=ap_ip,
            port=22,
            username=ap_auth["username"],
            password=ap_auth["password"],
            secret=ap_auth.get("secret", "password"),
            fast_cli=False,
            global_delay_factor=2,
        )
    except Exception as exc:
        print(f"[{ts()}]   [AP] AP SSH failed: {exc} — skipping AP-direct collection",
              file=sys.stderr)
        return advanced

    # Detect actual prompt — AP may be user-mode only
    # Detect actual prompt — AP may be user-mode only
    try:
        ap_conn.enable()
        _prompt = ap_conn.find_prompt()
        if not _prompt.endswith("#"):
            ap_conn.base_prompt = _prompt.rstrip(">").rstrip("#")
            ap_conn.RETURN = "\n"
            print(f"[{ts()}]   [AP] Prompt after enable(): '{_prompt}' — staying in USER MODE", file=sys.stderr)
        else:
            print(f"[{ts()}]   [AP] Prompt after enable(): '{_prompt}' — ENABLE MODE confirmed", file=sys.stderr)
    except Exception as _enable_exc:
        print(f"[{ts()}]   [AP] enable() raised: {_enable_exc} — attempting prompt recovery", file=sys.stderr)
        try:
            _prompt = ap_conn.find_prompt()
            ap_conn.base_prompt = _prompt.rstrip("#>")
            print(f"[{ts()}]   [AP] Recovered prompt: '{_prompt}' — base_prompt='{ap_conn.base_prompt}'", file=sys.stderr)
        except Exception as _fp_exc:
            print(f"[{ts()}]   [AP] find_prompt() also failed: {_fp_exc} — AP SSH may be unusable", file=sys.stderr)

    # Lock the prompt BEFORE any commands run — prevents syslog contamination
    # from ever being mistaken for a prompt by Netmiko's auto-detection.
    try:
        _discovered = ap_conn.find_prompt()
        ap_conn.base_prompt = _discovered.rstrip("#>")
        # Pre-compute the expect pattern once — reused by show debug above
        ap_conn._locked_expect = rf"{re.escape(ap_conn.base_prompt)}#"
    except Exception:
        ap_conn._locked_expect = r"\S+#"
    try:
        ap_conn.send_command_timing("terminal length 0", delay_factor=3, read_timeout=10)
        time.sleep(2)  # let AP settle
    except Exception:
        pass

    try:
        ap_conn.send_command_timing("terminal length 0", delay_factor=1, read_timeout=5)
    except Exception:
        pass

    try:
        for entry in catalog:
            cmd      = entry["cmd"]
            is_debug = entry["is_debug"]

            print(f"[{ts()}]   [AP] {'(debug) ' if is_debug else ''}{cmd}",
                  file=sys.stderr)
            try:
                if is_debug:
                    output = ap_conn.send_command_timing(cmd, delay_factor=2, read_timeout=15)
                else:
                     output = ap_conn.send_command(
                            cmd,
                            expect_string=getattr(ap_conn, "_locked_expect", None),
                            read_timeout=30,
                        )

                if output is None or (output.strip().startswith("%")) or "Invalid input" in output or "Incomplete command" in output:
                    print(f"[{ts()}]   [AP] Skipped (unsupported/error): {cmd}",
                          file=sys.stderr)
                    continue

                if not output or not output.strip():
                    print(f"[{ts()}]   [AP] Executed (no output returned): {cmd}",
                          file=sys.stderr)
                    advanced[cmd] = "(executed — no output)"
                else:
                    advanced[cmd] = output

            except Exception as exc:
                print(f"[{ts()}]   [AP] Error on '{cmd}': {exc}",
                      file=sys.stderr)

        # ── show debug — snapshot active AP debugs BEFORE terminal monitor ──
        # CRITICAL: send_command with explicit expect_string to prevent Netmiko
        # from misidentifying a syslog line as the prompt.
        _ap_sd = "show debug"
        print(f"[{ts()}]   [AP] {_ap_sd}", file=sys.stderr)
        try:
            _base = ap_conn.base_prompt or ap_conn.find_prompt().rstrip("#>")
            sd_out = ap_conn.send_command(
                _ap_sd,
                expect_string=rf"{re.escape(_base)}#",
                read_timeout=15,
            )
            if sd_out and not sd_out.strip().startswith("%") and "Invalid input" not in sd_out:
                advanced[_ap_sd] = sd_out
        except Exception as exc:
            print(f"[{ts()}]   [AP] Error on '{_ap_sd}': {exc}", file=sys.stderr)

        # ── terminal monitor — enable LAST, after all show commands ──────────
        # Enabling earlier causes syslog lines to inject into the SSH stream
        # and corrupt Netmiko's prompt detection for subsequent send_command calls.
        print(f"[{ts()}]   [AP] (debug) terminal monitor", file=sys.stderr)
        try:
            ap_conn.send_command_timing("terminal monitor", delay_factor=2, read_timeout=10)
            time.sleep(1)  # brief settle before final log snapshot
        except Exception as exc:
            print(f"[{ts()}]   [AP] Error on 'terminal monitor': {exc}", file=sys.stderr)

        # ── Final logging snapshot — uses send_command_timing to avoid prompt ──
        # Must use send_command_timing (not send_command) here because terminal
        # monitor is now active and syslog output can appear at any point,
        # making a stable prompt match impossible.
        _log_final = "show logging"
        print(f"[{ts()}]   [AP] {_log_final}", file=sys.stderr)
        try:
            log_out = ap_conn.send_command_timing(
                _log_final, delay_factor=3, read_timeout=20
            )
            if log_out and not log_out.strip().startswith("%") and "Invalid input" not in log_out:
                advanced[_log_final] = log_out
        except Exception as exc:
            print(f"[{ts()}]   [AP] Error on '{_log_final}': {exc}", file=sys.stderr)

        

        

        

        

        

        

        
        print(f"[{ts()}]   [AP] done — {len(advanced)} commands returned output.",
              file=sys.stderr)
        

    finally:
        ap_conn.disconnect()
        print(f"[{ts()}]   [AP] AP SSH session closed.", file=sys.stderr)

    return advanced
    """
    Collect advanced CAPWAP/DTLS diagnostics via WLC SSH.

    Show commands: full output captured.
    Debug commands: toggle-only — output is the WLC acknowledgment line.
    All failures are swallowed so the main RCA pipeline is never interrupted.
    Results are merged into the caller's ap_side_evidence dict.
    """
    advanced: dict[str, str] = {}

    print(f"[{ts()}]   [AP] starting collection ...",
          file=sys.stderr)

    for entry in AP_ADVANCED_CAPWAP_CATALOG:
        cmd       = entry["cmd"]
        is_debug  = entry["is_debug"]

        print(f"[{ts()}]   [AP] {'(debug) ' if is_debug else ''}{cmd}",
              file=sys.stderr)
        try:
            if is_debug:
                # Debug commands toggle a flag and return a short ack line —
                # use send_command_timing so we don't block waiting for a prompt
                # that may never match.
                output = conn.send_command_timing(cmd, delay_factor=1, read_timeout=10)
            else:
                output = conn.send_command(cmd, read_timeout=10)

            # Discard IOS-XE error responses — keeps evidence dict clean
            if not output or output.strip().startswith("%") or "Invalid input" in output:
                print(
                    f"[{ts()}]   [AP] Skipped (unsupported/error): {cmd}",
                    file=sys.stderr,
                )
                continue

            advanced[cmd] = output

        except Exception as exc:
            print(
                f"[{ts()}]   [AP] Error on '{cmd}': {exc}",
                file=sys.stderr,
            )

    print(
        f"[{ts()}]   [ADVANCED CAPWAP/DTLS TELEMETRY] done — "
        f"{len(advanced)} commands returned output.",
        file=sys.stderr,
    )
    return advanced
def send_custom_commands_to_wlc(conn: Any, commands: list[str]) -> dict[str, str]:
    """
    Send exact custom commands to an already-open WLC SSH session.
    'debug ...' commands use send_command_timing (ack-only, non-blocking);
    everything else uses send_command. Never raises.
    """
    results: dict[str, str] = {}
    for cmd in commands:
        is_debug = cmd.strip().lower().startswith("debug")
        print(f"[{ts()}]   [CUSTOM-WLC]{' (debug)' if is_debug else ''} {cmd}", file=sys.stderr)
        try:
            out = (conn.send_command_timing(cmd, delay_factor=1, read_timeout=15) if is_debug
                   else conn.send_command(cmd, read_timeout=30))
            results[cmd] = out if out else "(no output)"
        except Exception as exc:
            print(f"[{ts()}]   [CUSTOM-WLC] Error on '{cmd}': {exc}", file=sys.stderr)
            results[cmd] = f"ERROR: {exc}"
    return results


def send_custom_commands_to_ap(ap_ip: str, ap_auth: dict, commands: list[str]) -> dict[str, str]:
    """
    Open a dedicated SSH session to the AP and send exact custom commands.
    Mirrors collect_advanced_capwap_on_ap()'s connection handling. Never raises.
    """
    results: dict[str, str] = {}
    if not ap_ip or not commands:
        return results
    try:
        ap_conn = ConnectHandler(
            device_type="cisco_ios", host=ap_ip, port=22,
            username=ap_auth["username"], password=ap_auth["password"],
            secret=ap_auth.get("secret", "password"), fast_cli=False,
        )
        if ap_auth.get("secret"):
            ap_conn.enable()
    except Exception as exc:
        print(f"[{ts()}]   [CUSTOM-AP] AP SSH failed: {exc} — skipping custom commands", file=sys.stderr)
        return results
    try:
        for cmd in commands:
            is_debug = cmd.strip().lower().startswith("debug")
            print(f"[{ts()}]   [CUSTOM-AP]{' (debug)' if is_debug else ''} {cmd}", file=sys.stderr)
            try:
                out = (ap_conn.send_command_timing(cmd, delay_factor=1, read_timeout=10) if is_debug
                       else ap_conn.send_command(cmd, read_timeout=15))
                results[cmd] = out if out else "(no output)"
            except Exception as exc:
                print(f"[{ts()}]   [CUSTOM-AP] Error on '{cmd}': {exc}", file=sys.stderr)
                results[cmd] = f"ERROR: {exc}"
    finally:
        ap_conn.disconnect()
        print(f"[{ts()}]   [CUSTOM-AP] AP SSH session closed.", file=sys.stderr)
    return results
def correlate_ap_side(ap_evidence: dict[str, str], ap_name: str | None) -> dict[str, Any]:
    """
    Infer probable AP-side root cause from WLC-reported AP telemetry.
    Returns a structured finding dict — same style as correlate().
    """
    combined = "\n".join(ap_evidence.values())
    observations: list[str] = []
    confidence   = "inconclusive"
    probable_cause = "No AP-side indicators found in collected telemetry"
    action         = "Manually review AP eventlog and crash-file on WLC"

    # ── 1. Crash file evidence ────────────────────────────────────────────
    crash_output = ap_evidence.get(
        next((k for k in ap_evidence if "crash-file" in k), ""), ""
    )
    has_crash_file = bool(AP_CRASH_FILE_RE.search(crash_output)) and \
                     "no crash" not in crash_output.lower() and \
                     len(crash_output.strip()) > 10

    # ── 2. Short uptime — AP rebooted recently ───────────────────────────
    uptime_output = ap_evidence.get(
        next((k for k in ap_evidence if "uptime" in k), ""), ""
    )
    recently_rebooted = False
    uptime_match = AP_SHORT_UPTIME_RE.search(uptime_output)
    if uptime_match:
        days    = int(uptime_match.group(1))
        hours   = int(uptime_match.group(2))
        minutes = int(uptime_match.group(3))
        total_minutes = days * 1440 + hours * 60 + minutes
        recently_rebooted = total_minutes < 30   # rebooted within last 30 min
        if recently_rebooted:
            observations.append(
                f"AP uptime is only {days}d {hours}h {minutes}m — "
                "consistent with a recent reboot at time of disjoin"
            )

    # ── 3. CAPWAP tunnel instability ─────────────────────────────────────
    capwap_output = ap_evidence.get(
        next((k for k in ap_evidence if "capwap" in k), ""), ""
    )
    has_capwap_instability = bool(AP_CAPWAP_RESET_RE.search(capwap_output))
    if has_capwap_instability:
        observations.append("CAPWAP tunnel shows retransmission/reset/timeout indicators")

    # ── 4. Eventlog — uplink, PoE, reboot reason ─────────────────────────
    eventlog_output = ap_evidence.get(
        next((k for k in ap_evidence if "eventlog" in k), ""), ""
    )
    has_uplink_down = bool(AP_UPLINK_RE.search(eventlog_output))
    has_poe_issue   = bool(AP_POE_RE.search(eventlog_output))
    has_reboot_reason = bool(AP_REBOOT_REASON_RE.search(eventlog_output))

    if has_uplink_down:
        observations.append("Ethernet/uplink down event detected in AP eventlog")
    if has_poe_issue:
        observations.append("PoE / power instability event detected in AP eventlog")
    if has_reboot_reason:
        observations.append("Explicit reboot reason entry found in AP eventlog")

    # ── Decision tree ─────────────────────────────────────────────────────
    if has_crash_file and recently_rebooted:
        probable_cause = (
            "AP crash file present AND short uptime detected — "
            "watchdog crash or software exception likely caused AP reboot → disjoin"
        )
        confidence = "high"
        action     = (
            f"Run: show ap name {ap_name} crash-file detail on WLC. "
            "Collect crashinfo and open TAC case."
        )

    elif has_crash_file and not recently_rebooted:
        probable_cause = (
            "Crash file exists but AP uptime suggests it predates this disjoin event. "
            "May be a prior unrelated crash."
        )
        confidence = "medium"
        action     = (
            "Check crash-file timestamp vs disjoin timestamp. "
            "If timestamps align, open TAC case."
        )

    elif recently_rebooted and has_reboot_reason:
        probable_cause = (
            "AP rebooted shortly before disjoin. "
            "Reboot reason entry found in eventlog — not a software crash."
        )
        confidence = "high"
        action     = "Review eventlog reboot reason. Check for planned reload or PoE reset."

    elif has_poe_issue and recently_rebooted:
        probable_cause = (
            "AP rebooted AND PoE/power instability detected in eventlog. "
            "Power interruption likely caused AP to reboot → stop CAPWAP heartbeats → disjoin."
        )
        confidence = "high"
        action     = "Check PoE budget on switch port. Verify switch PoE logs."

    elif has_uplink_down:
        probable_cause = (
            "Ethernet/uplink down event detected. "
            "AP lost network connectivity, preventing CAPWAP heartbeats from reaching WLC."
        )
        confidence = "medium"
        action     = "Check switch port connected to AP. Review STP and uplink events."

    elif has_capwap_instability and not recently_rebooted:
        probable_cause = (
            "CAPWAP tunnel instability detected without AP reboot. "
            "Possible network path degradation or DTLS negotiation issue."
        )
        confidence = "medium"
        action     = "Check MTU on AP network path. Review DTLS cert validity."

    elif recently_rebooted:
        probable_cause = (
            "AP rebooted recently (short uptime) but no crash file or specific "
            "event found. Cause undetermined from available telemetry."
        )
        confidence = "low"
        action     = "Manually review AP eventlog for reload trigger."

    return {
        "observations"  : observations,
        "probable_cause": probable_cause,
        "confidence"    : confidence,
        "action"        : action,
        "raw_indicators": {
            "crash_file_present"   : has_crash_file,
            "recently_rebooted"    : recently_rebooted,
            "capwap_instability"   : has_capwap_instability,
            "uplink_down"          : has_uplink_down,
            "poe_issue"            : has_poe_issue,
            "explicit_reboot_reason": has_reboot_reason,
        },
    }
def _parse_gpbkv(fields, result=None):
        """Recursively decode GPBKV field hierarchy into a flat dict."""
        if result is None:
            result = {}
        for f in fields:
            val = None
            if f.string_value:
                val = f.string_value
            elif f.uint64_value:
                val = f.uint64_value
            elif f.sint64_value:
                val = f.sint64_value
            elif f.bool_value:
                val = f.bool_value
            elif f.bytes_value:
                val = f.bytes_value.hex()
            if f.fields:
                _parse_gpbkv(f.fields, result)
            if val is not None:
                result[f.name] = val
        return result
def extract_disjoin_event(envelope) -> dict:
    """
    Extract disjoin fields from a Telemetry() protobuf envelope.
    Field-order agnostic. Tolerates missing fields.
    """
    FIELD_MAP = {
        "ap_name":    ("ap_name", "apName", "AP Name", "name"),
        "mac":        ("mac", "ap_mac", "apMac", "Mac", "macAddress"),
        "ip":         ("ip", "session_ip", "sessionIp", "Session-IP", "ipAddress"),
        "reason":     ("reason", "disjoin_reason", "Reason", "msg"),
        "event_type": ("event_type", "eventType", "type", "Event"),
        "timestamp":  ("timestamp", "event_time", "time", "Timestamp"),
    }
    flat: dict = {}
    for row in envelope.data_gpbkv:
        flat.update(_parse_gpbkv(row.fields))

    result = {}
    for key, candidates in FIELD_MAP.items():
        for c in candidates:
            if c in flat:
                result[key] = str(flat[c])
                break
        else:
            result[key] = None

    if result.get("mac"):
        result["mac"] = normalise_mac(result["mac"])
    if not result.get("timestamp"):
        result["timestamp"] = ts()

    return result
def extract_ip(text: str) -> str | None:
    m = IP_RE.search(text)
    return m.group(1) if m else None

def load_inventory(path: str) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return {d["name"]: d for d in data.get("iosxe_devices", []) if "name" in d}

def correlate(evidence: str) -> dict[str, str]:
    if CRASH_RE.search(evidence) and HB_RE.search(evidence):
        return {
            "probable_cause": "AP crashed → stopped sending CAPWAP heartbeats → WLC disjoined it",
            "confidence": "high",
            "action": "Collect AP crashinfo; open TAC if recurring",
        }
    if WATCHDOG_RE.search(evidence):
        return {
            "probable_cause": "AP watchdog / kernel panic triggered reboot → disjoin",
            "confidence": "high",
            "action": "Check AP hardware health and firmware version",
        }
    if DTLS_RE.search(evidence):
        return {
            "probable_cause": "CAPWAP DTLS tunnel failed — possible MTU, cert, or path issue",
            "confidence": "medium",
            "action": "Check MTU >= 1485 on AP path; verify AP certificate",
        }
    if HB_RE.search(evidence):
        return {
            "probable_cause": "Heartbeat expiry without crash — likely network path interruption",
            "confidence": "medium",
            "action": "Check uplink/STP events around disjoin timestamp",
        }
    return {
        "probable_cause": "Insufficient evidence — manual trace bundle recommended",
        "confidence": "inconclusive",
        "action": "Run: request wireless trace bundle on WLC",
    }
class CorrelationEngine:
    """
    Pluggable correlation framework.
    Current implementation: rule-based only.
    Future slots: anomaly_detector, ml_scorer, root_cause_ranker.
    """

    def __init__(self):
        self._rules   = [self._rule_based]
        self._scorers = []          # ML scorers — plug in here later
        self._rankers = []          # root cause rankers — plug in here later

    def register_scorer(self, fn):
        """Register a future ML scoring function."""
        self._scorers.append(fn)

    def register_ranker(self, fn):
        """Register a future root cause ranking function."""
        self._rankers.append(fn)

    def _rule_based(self, evidence: str) -> dict:
        return correlate(evidence)   # delegates to existing function

    def run(self, evidence: str) -> dict:
        results = [r(evidence) for r in self._rules]
        # future: merge scorer outputs here
        # future: pass to ranker here
        # For now: return first rule result (only one rule exists)
        return results[0] if results else {
            "probable_cause": "No correlation rule matched",
            "confidence": "inconclusive",
            "action": "Manual review required",
        }

# Singleton — used by _react() instead of calling correlate() directly
_correlation_engine = CorrelationEngine()

# ---------------------------------------------------------------------------
# Core session
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# AP Statistics — persistent per-AP disjoin history
# ---------------------------------------------------------------------------

def load_ap_stats() -> dict[str, dict]:
    """
    Load the persistent AP statistics JSON from disk.
    Returns an empty dict on missing file or corruption.
    Thread-safe: caller must hold AP_STATS_LOCK or use record_disjoin_event().
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not AP_STATS_FILE.exists():
        return {}
    try:
        raw = AP_STATS_FILE.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("AP stats file root is not a JSON object")
        return data
    except json.JSONDecodeError as exc:
        print(
            f"[{ts()}] WARNING: AP stats file is corrupted (JSONDecodeError: {exc}) "
            f"— backing up and starting fresh.",
            file=sys.stderr,
        )
        _backup = AP_STATS_FILE.with_suffix(".json.bak")
        try:
            AP_STATS_FILE.rename(_backup)
        except Exception:
            pass
        return {}
    except Exception as exc:
        print(
            f"[{ts()}] WARNING: Could not load AP stats ({AP_STATS_FILE}): {exc} "
            f"— starting fresh.",
            file=sys.stderr,
        )
        return {}


def save_ap_stats(stats: dict[str, dict]) -> None:
    """
    Atomically write AP statistics to disk using a temp-file + rename pattern.
    Thread-safe: caller must hold AP_STATS_LOCK.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = AP_STATS_FILE.with_suffix(".json.tmp")
    try:
        tmp_path.write_text(
            json.dumps(stats, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        tmp_path.replace(AP_STATS_FILE)   # atomic on POSIX; best-effort on Windows
    except Exception as exc:
        print(
            f"[{ts()}] WARNING: Could not save AP stats: {exc}",
            file=sys.stderr,
        )
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


def record_disjoin_event(
    mac: str,
    ap_name: str | None = None,
    ip: str | None = None,
) -> dict:
    """
    Record a single disjoin event for *mac* and persist to disk.

    - Increments disjoin_count.
    - Appends the current UTC timestamp (capped at AP_STATS_MAX_TIMESTAMPS).
    - Updates first_disjoin (only on the very first event) and last_disjoin.
    - Preserves the best-known ap_name and ip (non-None values win).

    Returns the updated AP stats dict for this MAC so the caller can log it.
    Thread-safe via AP_STATS_LOCK.
    """
    now = ts()
    with AP_STATS_LOCK:
        stats = load_ap_stats()

        entry = stats.get(mac)
        if entry is None:
            entry = {
                "ap_name":      ap_name,
                "ip":           ip,
                "disjoin_count": 0,
                "first_disjoin": now,
                "last_disjoin":  now,
                "timestamps":    [],
            }
            stats[mac] = entry

        # Always prefer a concrete value over None
        if ap_name:
            entry["ap_name"] = ap_name
        if ip:
            entry["ip"] = ip

        entry["disjoin_count"] += 1
        entry["last_disjoin"]   = now

        # Cap timestamp history
        entry["timestamps"].append(now)
        if len(entry["timestamps"]) > AP_STATS_MAX_TIMESTAMPS:
            entry["timestamps"] = entry["timestamps"][-AP_STATS_MAX_TIMESTAMPS:]

        save_ap_stats(stats)

    print(
        f"[{now}] [AP_STATS] {mac} | count={entry['disjoin_count']} "
        f"ap={entry['ap_name'] or '?'} ip={entry['ip'] or '?'}",
        file=sys.stderr,
    )
    update_summary_stats(mac)
    return dict(entry)   # return a shallow copy — caller must not mutate


def get_ap_stats(mac: str | None = None) -> dict:
    """
    Return stats for a single MAC (or all MACs if mac is None).
    Thread-safe read — acquires AP_STATS_LOCK.
    """
    with AP_STATS_LOCK:
        stats = load_ap_stats()
    return stats.get(mac, {}) if mac else stats


def reset_ap_stats(mac: str | None = None) -> None:
    """
    Clear stats for a single MAC, or wipe the entire file if mac is None.
    Thread-safe via AP_STATS_LOCK.
    """
    with AP_STATS_LOCK:
        if mac is None:
            save_ap_stats({})
            print(f"[{ts()}] [AP_STATS] All AP stats reset.", file=sys.stderr)
        else:
            stats = load_ap_stats()
            if mac in stats:
                del stats[mac]
                save_ap_stats(stats)
                print(f"[{ts()}] [AP_STATS] Stats reset for {mac}.", file=sys.stderr)
def load_disjoin_counters() -> dict[str, int]:
    """Load persistent AP disjoin counters from JSON file."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not DISJOIN_COUNTER_FILE.exists():
        return {}
    try:
        data = json.loads(DISJOIN_COUNTER_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Counter file is not a JSON object")
        return {k: int(v) for k, v in data.items()}
    except Exception as exc:
        print(
            f"[{ts()}] WARNING: Could not load counter file "
            f"({DISJOIN_COUNTER_FILE}): {exc} — starting fresh",
            file=sys.stderr,
        )
        return {}


def increment_disjoin_counter(mac: str) -> int:
    """
    Increment the persistent disjoin counter for *mac*.
    Saves immediately after increment.
    Returns the new counter value.
    """
    counters = load_disjoin_counters()
    counters[mac] = counters.get(mac, 0) + 1
    new_count = counters[mac]
    return new_count
def update_summary_stats(mac: str) -> None:
    """
    Persist a rolling summary of total disjoin counts and total event counts.
    Reads current values from ap_disjoin_stats.json and disjoin_event_history.json,
    then writes a clean snapshot to summary_stats.json.
    Called after every confirmed disjoin.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Total disjoins across all APs ────────────────────────────────────
    all_stats   = load_ap_stats()
    total_disjoins = sum(v.get("disjoin_count", 0) for v in all_stats.values())
    per_ap = {
        mac: {
            "ap_name":      v.get("ap_name") or "unknown",
            "disjoin_count": v.get("disjoin_count", 0),
            "last_disjoin":  v.get("last_disjoin") or "N/A",
        }
        for mac, v in all_stats.items()
    }

    # ── Total completed events (CGDC batches) ────────────────────────────
    event_history   = load_disjoin_event_history()
    total_events    = event_history.get("completed_count", 0)

    summary = {
        "last_updated":    ts(),
        "total_disjoins":  total_disjoins,
        "total_events":    total_events,
        "per_ap":          per_ap,
    }

    tmp = SUMMARY_STATS_FILE.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(SUMMARY_STATS_FILE)
        print(
            f"[{ts()}] [SUMMARY] total_disjoins={total_disjoins} "
            f"total_events={total_events} → {SUMMARY_STATS_FILE}",
            file=sys.stderr,
        )
    except Exception as exc:
        print(f"[{ts()}] WARNING: Could not save summary stats: {exc}", file=sys.stderr)
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# GDC persistence
# ---------------------------------------------------------------------------

def load_gdc() -> int:
    return state_counters.load_gdc(REPORTS_DIR, GDC_FILE)

def save_gdc(value: int) -> None:
    state_counters.save_gdc(value)

def increment_gdc() -> int:
    return state_counters.increment_gdc(REPORTS_DIR, GDC_FILE, GDC_LOCK)

# ---------------------------------------------------------------------------
# CGDC persistence
# ---------------------------------------------------------------------------

def load_cgdc() -> dict:
    """Returns {"cgdc": int, "batch": [...]} where batch is current partial batch."""
    return state_counters.load_cgdc(REPORTS_DIR, CGDC_FILE)

def save_cgdc(data: dict) -> None:
    state_counters.save_cgdc(data, REPORTS_DIR, CGDC_FILE, _warn)

def reset_cgdc() -> None:
    save_cgdc({"cgdc": 0, "batch": []})

# ---------------------------------------------------------------------------
# Disjoin Event History persistence
# ---------------------------------------------------------------------------

def load_disjoin_event_history() -> dict:
    return state_event_history.load_disjoin_event_history(
        REPORTS_DIR, DISJOIN_EVENT_HISTORY_FILE
    )

def save_disjoin_event_history(data: dict) -> None:
    state_event_history.save_disjoin_event_history(
        data, REPORTS_DIR, DISJOIN_EVENT_HISTORY_FILE, _warn
    )

def append_disjoin_event_history(event: dict) -> int:
    """Append a completed batch event. Returns the new completed_count."""
    return state_event_history.append_disjoin_event_history(
        event, REPORTS_DIR, DISJOIN_EVENT_HISTORY_FILE,
        DISJOIN_EVENT_HISTORY_LOCK, _warn
    )

# ---------------------------------------------------------------------------
# AP Workflow State persistence
# ---------------------------------------------------------------------------

def load_ap_workflow_state() -> dict:
    return state_workflow_state.load_ap_workflow_state(
        REPORTS_DIR, AP_WORKFLOW_STATE_FILE
    )

def save_ap_workflow_state(data: dict) -> None:
    state_workflow_state.save_ap_workflow_state(
        data, REPORTS_DIR, AP_WORKFLOW_STATE_FILE, _warn
    )

def set_ap_workflow_active(mac: str, ap_name: str | None, ip: str | None) -> None:
    state_workflow_state.set_ap_workflow_active(
        mac, ap_name, ip, REPORTS_DIR, AP_WORKFLOW_STATE_FILE,
        AP_WORKFLOW_STATE_LOCK, ts, RCA_SESSION_TIMEOUT, _warn
    )

def increment_ap_workflow_disjoin(mac: str) -> int:
    """
    Increment the per-AP workflow disjoin counter.
    Returns the new count. If no active workflow exists, returns 0.
    """
    return state_workflow_state.increment_ap_workflow_disjoin(
        mac, REPORTS_DIR, AP_WORKFLOW_STATE_FILE,
        AP_WORKFLOW_STATE_LOCK, ts, _warn
    )

def clear_ap_workflow(mac: str) -> None:
    state_workflow_state.clear_ap_workflow(
        mac, REPORTS_DIR, AP_WORKFLOW_STATE_FILE,
        AP_WORKFLOW_STATE_LOCK, _warn
    )

def is_ap_workflow_active(mac: str) -> bool:
    return state_workflow_state.is_ap_workflow_active(
        mac, REPORTS_DIR, AP_WORKFLOW_STATE_FILE, AP_WORKFLOW_STATE_LOCK
    )
# ── Per-AP "used" cooldown — prevents immediate re-entry into new windows ──
_AP_USED_COOLDOWN: dict[str, float] = {}   # mac → monotonic time of finalization
_AP_USED_LOCK = threading.Lock()
AP_USED_COOLDOWN_SECONDS = 600   # 10 minutes

def mark_ap_used(mac: str) -> None:
    """Mark AP as used (cooldown) for 10 minutes after finalization."""
    with _AP_USED_LOCK:
        _AP_USED_COOLDOWN[mac] = time.monotonic()
    print(f"[{ts()}] [COOLDOWN] AP {mac} marked used — will be available again in {AP_USED_COOLDOWN_SECONDS}s.", file=sys.stderr)

def is_ap_used(mac: str) -> bool:
    """Returns True if AP is within 10-minute post-finalization cooldown."""
    now = time.monotonic()
    with _AP_USED_LOCK:
        t = _AP_USED_COOLDOWN.get(mac)
        if t is None:
            return False
        if now - t >= AP_USED_COOLDOWN_SECONDS:
            del _AP_USED_COOLDOWN[mac]
            print(f"[{ts()}] [COOLDOWN] AP {mac} cooldown expired — now unused.", file=sys.stderr)
            return False
        return True
# ---------------------------------------------------------------------------
# CGDC batch processor — called on every confirmed disjoin event
# ---------------------------------------------------------------------------
def load_disjoin_occurrences() -> list:
    return state_disjoin_occurrences.load_disjoin_occurrences(
        REPORTS_DIR, DISJOIN_OCCURRENCES_FILE
    )

def save_disjoin_occurrences(occurrences: list) -> None:
    state_disjoin_occurrences.save_disjoin_occurrences(
        occurrences, REPORTS_DIR, DISJOIN_OCCURRENCES_FILE, _warn
    )

def append_disjoin_occurrence(mac: str, ap_name: str | None, ip: str | None) -> list:
    """
    Append a new unused disjoin occurrence and return the full list.
    Thread-safe via DISJOIN_OCCURRENCES_LOCK.
    """
    return state_disjoin_occurrences.append_disjoin_occurrence(
        mac, ap_name, ip, REPORTS_DIR, DISJOIN_OCCURRENCES_FILE,
        DISJOIN_OCCURRENCES_LOCK, _warn
    )

def evaluate_disjoin_event(monitor: "LiveMonitor") -> None:
    """
    Sliding-window event detection.

    1. Append the new occurrence (already done by caller).
    2. Find the 3 newest consecutive unused occurrences.
    3. If C.timestamp - A.timestamp <= 600s → VALID EVENT.
       Mark A,B,C used; launch workflows.
    4. If > 600s → leave all unused; log INVALID.
    """
    with DISJOIN_OCCURRENCES_LOCK:
        occurrences = load_disjoin_occurrences()
        unused = event_engine.unused_occurrences(occurrences)

        if len(unused) < CGDC_BATCH_SIZE:
            print(
                f"[{ts()}] [EVENT] Only {len(unused)} unused occurrence(s) — "
                f"need {CGDC_BATCH_SIZE} to evaluate.",
                file=sys.stderr,
            )
            return

        # Newest 3 consecutive unused
        window = event_engine.newest_candidate_window(unused, CGDC_BATCH_SIZE)
        A, B, C = window.first, window.second, window.third
        duration = window.duration_seconds
        labels = window.labels

        print(f"[{ts()}] [EVENT] Evaluating unused window: {labels}", file=sys.stderr)
        print(f"[{ts()}] [EVENT] Duration={duration:.1f} seconds", file=sys.stderr)

        if not event_engine.is_valid_window(window, CGDC_WINDOW_SECONDS):
            print(f"[{ts()}] [EVENT] INVALID EVENT — leaving disjoins available for future evaluation", file=sys.stderr)
            return

        # ── Valid event ───────────────────────────────────────────────
        print(f"[{ts()}] [EVENT] VALID EVENT DETECTED", file=sys.stderr)
        set_ap_traced_count(3)
        # Mark A, B, C used — match by identity (index in unused list)
        marked = event_engine.mark_window_used(occurrences, window)
        save_disjoin_occurrences(occurrences)
        print(f"[{ts()}] [EVENT] Marked {marked} disjoins as consumed", file=sys.stderr)

    # ── GDC increment ─────────────────────────────────────────────────
    gdc_val = increment_gdc()
    print(f"[{ts()}] [GDC] Incremented → GDC={gdc_val}", file=sys.stderr)

    # ── Build participant list (deduplicated by MAC) ──────────────────
    batch    = [A, B, C]
    seen_macs: set[str] = set()
    unique_aps: list[dict] = []
    for entry in batch:
        if entry["mac"] not in seen_macs:
            seen_macs.add(entry["mac"])
            unique_aps.append(entry)

    print(f"[{ts()}] [EVENT] Launching workflows for {len(unique_aps)} unique APs", file=sys.stderr)

    # ── Persist to event history ──────────────────────────────────────
    t1 = A["timestamp"]
    t3 = C["timestamp"]
    history_event = {
        "event_time":              datetime.fromtimestamp(t3, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_duration_seconds": round(duration, 2),
        "event_valid":             True,
        "aps": [
            {"ap_name": e["ap_name"], "mac": e["mac"], "ip": e["ip"]}
            for e in batch
        ],
    }
    completed_count = append_disjoin_event_history(history_event)
    print(f"[{ts()}] [EVENT] Stored → Completed_Disjoin_Events_Count={completed_count}", file=sys.stderr)

    # ── Launch RCA workflows ──────────────────────────────────────────
    for entry in unique_aps:
        ap_mac = entry["mac"]
        ap_n   = entry["ap_name"]
        ap_ip  = entry["ip"]
        ap_ets = datetime.fromtimestamp(entry["timestamp"], tz=timezone.utc).isoformat()

        if is_ap_workflow_active(ap_mac):
            print(
                f"[{ts()}] [EVENT] AP {ap_mac}({ap_ip or '?'}) already has active workflow — "
                f"skipping duplicate launch.",
                file=sys.stderr,
            )
            continue

        if is_ap_used(ap_mac):
            print(
                f"[{ts()}] [EVENT] AP {ap_mac}({ap_ip or '?'}) is in post-finalization cooldown "
                f"— skipping RCA launch for this window.",
                file=sys.stderr,
            )
            continue

        set_ap_workflow_active(ap_mac, ap_n, ap_ip)
        print(
            f"[{ts()}] [EVENT] Submitting RCA for mac={ap_mac}({ap_ip or '?'}) ap={ap_n or '?'}",
            file=sys.stderr,
        )

        if _rca_executor:
            _rca_executor.submit(
                monitor._react,
                ap_mac, ap_n, ap_ip, ap_ets,
                [],
                True,
            )
        else:
            threading.Thread(
                target=monitor._react,
                args=(ap_mac, ap_n, ap_ip, ap_ets, [], True),
                daemon=True,
            ).start()
def process_cgdc_event(
    mac: str,
    ap_name: str | None,
    ip: str | None,
    monitor: "LiveMonitor",
) -> None:
    append_disjoin_occurrence(mac, ap_name, ip)
    increment_ap_traced_count()
    print(
        f"[{ts()}] [EVENT] New occurrence appended — mac={mac} ap={ap_name or '?'}",
        file=sys.stderr,
    )
    evaluate_disjoin_event(monitor)

# ---------------------------------------------------------------------------
# EEM-BATCH global session state machine
# ---------------------------------------------------------------------------

def _load_global_rca_session() -> dict:
    """
    Load the single global RCA session state from disk.
    Returns IDLE state dict on missing file or corruption.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    _idle = {
        "state":        "IDLE",
        "locked_mac":   None,
        "locked_ap_name": None,
        "locked_ip":    None,
        "trigger_ts":   None,
        "detection_window": [],   # list of {mac, ap_name, ip, timestamp} for current window
    }
    if not GLOBAL_RCA_SESSION_FILE.exists():
        return _idle
    try:
        data = json.loads(GLOBAL_RCA_SESSION_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "state" not in data:
            raise ValueError("bad schema")
        return data
    except Exception as exc:
        print(f"[{ts()}] [GLOBAL_RCA] WARNING: Could not load session file: {exc} — starting IDLE.", file=sys.stderr)
        return _idle


def _save_global_rca_session(data: dict) -> None:
    """Atomically persist global RCA session state to disk."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = GLOBAL_RCA_SESSION_FILE.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(GLOBAL_RCA_SESSION_FILE)
    except Exception as exc:
        print(f"[{ts()}] [GLOBAL_RCA] WARNING: Could not save session file: {exc}", file=sys.stderr)
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def _reset_global_rca_session() -> None:
    """Reset state to IDLE and persist."""
    _save_global_rca_session({
        "state":          "IDLE",
        "locked_mac":     None,
        "locked_ap_name": None,
        "locked_ip":      None,
        "trigger_ts":     None,
        "detection_window": [],
    })
    print(f"[{ts()}] [GLOBAL_RCA] State → IDLE", file=sys.stderr)


def _eem_batch_on_disjoin(
    mac: str,
    ap_name: str | None,
    ip: str | None,
    monitor: "LiveMonitor",
) -> None:
    """
    EEM-BATCH MODE state machine entry point.
    Called for EVERY individual disjoin that arrives while in eem_batch mode
    (i.e. BEFORE the WLC has batched 3 — we receive individual MDT events
    because the WLC syslog EEM also fires per-event; the batch trigger is
    the 3rd one carrying "EEM_BATCH_TRIGGER").

    State transitions:
      IDLE              → accumulate detection window; on 3rd within 10 min → RCA_ACTIVE
      RCA_ACTIVE        → ignore all APs (still record to occurrences.json)
      WAITING_RECURRENCE→ if same locked AP reappears within 30 min → finalize
                          else ignore (still record to occurrences.json)

    Ignored disjoins (during RCA_ACTIVE / WAITING_RECURRENCE) are always
    appended to disjoin_occurrences.json so they are not lost.
    """
    now_epoch = time.time()
    now_iso   = ts()

    with GLOBAL_RCA_SESSION_LOCK:
        session = _load_global_rca_session()
        state   = session.get("state", "IDLE")

        # ── Always record every disjoin to occurrences.json ──────────
        append_disjoin_occurrence(mac, ap_name, ip)
        record_disjoin_event(mac, ap_name=ap_name, ip=ip)

        # ── STATE: RCA_ACTIVE — ignore, RCA workflow is running ───────
        if state == "RCA_ACTIVE":
            print(
                f"[{now_iso}] [GLOBAL_RCA] State=RCA_ACTIVE — "
                f"disjoin from {mac} ignored (RCA in progress for {session.get('locked_mac')})",
                file=sys.stderr,
            )
            return

        # ── STATE: WAITING_RECURRENCE — watch for locked AP only ──────
        if state == "WAITING_RECURRENCE":
            locked_mac  = session.get("locked_mac")
            trigger_ts_epoch = session.get("trigger_ts_epoch", 0)
            elapsed     = now_epoch - trigger_ts_epoch

            if mac != locked_mac:
                print(
                    f"[{now_iso}] [GLOBAL_RCA] State=WAITING_RECURRENCE — "
                    f"disjoin from {mac} ignored (watching for {locked_mac})",
                    file=sys.stderr,
                )
                return

            # Same AP reappeared
            if elapsed <= EEM_BATCH_RECURRENCE_WINDOW_SECONDS:
                print(
                    f"[{now_iso}] [GLOBAL_RCA] RECURRENCE CONFIRMED — "
                    f"locked AP {locked_mac} disjoined again after {elapsed:.0f}s "
                    f"(within {EEM_BATCH_RECURRENCE_WINDOW_SECONDS}s window) → FINALIZE",
                    file=sys.stderr,
                )
                # Transition to IDLE before launching finalization
                # (finalization is async; we don't want a second disjoin to re-enter)
                _reset_global_rca_session()
                _ip   = session.get("locked_ip") or ip
                _name = session.get("locked_ap_name") or ap_name
                threading.Thread(
                    target=monitor._finalize_rca_session,
                    args=(None, locked_mac, _ip),
                    daemon=True,
                ).start()
            else:
                print(
                    f"[{now_iso}] [GLOBAL_RCA] RECURRENCE TIMEOUT — "
                    f"locked AP {locked_mac} reappeared after {elapsed:.0f}s "
                    f"(> {EEM_BATCH_RECURRENCE_WINDOW_SECONDS}s) → resetting to IDLE",
                    file=sys.stderr,
                )
                _reset_global_rca_session()
            return

        # ── STATE: IDLE — accumulate detection window ──────────────────
        window: list[dict] = session.get("detection_window", [])

        # Prune entries older than EEM_BATCH_DETECTION_WINDOW_SECONDS
        window = [
            e for e in window
            if now_epoch - e.get("timestamp_epoch", 0) <= EEM_BATCH_DETECTION_WINDOW_SECONDS
        ]

        # Append current disjoin
        window.append({
            "mac":             mac,
            "ap_name":         ap_name,
            "ip":              ip,
            "timestamp_iso":   now_iso,
            "timestamp_epoch": now_epoch,
        })

        print(
            f"[{now_iso}] [GLOBAL_RCA] State=IDLE — detection window now "
            f"{len(window)}/{CGDC_BATCH_SIZE} disjoins",
            file=sys.stderr,
        )

        if len(window) < CGDC_BATCH_SIZE:
            # Not enough disjoins yet — save updated window and wait
            session["detection_window"] = window
            _save_global_rca_session(session)
            return

        # ── 3 disjoins within 10 min — VALID BURST ────────────────────
        locked = window[-1]   # 3rd (most recent) disjoin becomes the locked AP
        locked_mac     = locked["mac"]
        locked_ap_name = locked["ap_name"]
        locked_ip      = locked["ip"]

        print(
            f"[{now_iso}] [GLOBAL_RCA] VALID BURST DETECTED — "
            f"3 disjoins in {now_epoch - window[0]['timestamp_epoch']:.0f}s. "
            f"Locked AP: {locked_mac} ({locked_ap_name or '?'}) → RCA_ACTIVE",
            file=sys.stderr,
        )

        # Persist ACTIVE state before spawning RCA thread
        _save_global_rca_session({
            "state":            "RCA_ACTIVE",
            "locked_mac":       locked_mac,
            "locked_ap_name":   locked_ap_name,
            "locked_ip":        locked_ip,
            "trigger_ts":       now_iso,
            "trigger_ts_epoch": now_epoch,
            "detection_window": [],   # clear for next cycle
            "burst_participants": [
                {"mac": e["mac"], "ap_name": e["ap_name"], "ip": e["ip"]}
                for e in window
            ],
        })

    # ── Launch RCA (_react) outside the lock ──────────────────────────
    event_ts_iso = now_iso
    set_ap_workflow_active(locked_mac, locked_ap_name, locked_ip)

    def _rca_then_wait(_mac=locked_mac, _name=locked_ap_name, _ip=locked_ip):
        # Run the full RCA evidence collection (_react handles SSH/MYCAP/show cmds)
        monitor._react(_mac, _name, _ip, event_ts_iso, [], True)

        # _react returns after telemetry collection + MYCAP started.
        # Now transition to WAITING_RECURRENCE.
        with GLOBAL_RCA_SESSION_LOCK:
            _s = _load_global_rca_session()
            if _s.get("state") == "RCA_ACTIVE" and _s.get("locked_mac") == _mac:
                _s["state"] = "WAITING_RECURRENCE"
                _save_global_rca_session(_s)
                print(
                    f"[{ts()}] [GLOBAL_RCA] State → WAITING_RECURRENCE "
                    f"(watching for {_mac} to disjoin again within "
                    f"{EEM_BATCH_RECURRENCE_WINDOW_SECONDS}s)",
                    file=sys.stderr,
                )

        # ── 30-min timeout: if locked AP never reappears, reset ───────
        time.sleep(EEM_BATCH_RECURRENCE_WINDOW_SECONDS)
        with GLOBAL_RCA_SESSION_LOCK:
            _s = _load_global_rca_session()
            if _s.get("state") == "WAITING_RECURRENCE" and _s.get("locked_mac") == _mac:
                print(
                    f"[{ts()}] [GLOBAL_RCA] 30-min recurrence window expired for "
                    f"{_mac} — no recurrence detected → resetting to IDLE",
                    file=sys.stderr,
                )
                _reset_global_rca_session()
                clear_ap_workflow(_mac)

    threading.Thread(target=_rca_then_wait, daemon=True).start()


class LiveMonitor:

    def __init__(self, auth: dict[str, Any], wlc_host: str, device_name: str | None, grpc_port: int = GRPC_PORT) -> None:
        self.auth    = auth
        self.ap_auth = {
            "username": auth.get("ap_username", "Cisco"),
            "password": auth.get("ap_password", "Cisco"),
            "secret":   auth.get("ap_secret", ""),
        }

        self.wlc_host      = wlc_host
        self.grpc_port     = grpc_port
         
        self.device_name   = device_name
        self.start_ts    = ts()
        self.traced_macs : set[str]         = set()   # dedup — one trace per MAC
        self.events      : list[dict]        = []
        self.ap_reports  : dict[str, dict]  = {}      # keyed by MAC
        self.raw_stream  : list[str]         = []
        self.live_buffer : deque             = deque(maxlen=LIVE_BUFFER_MAXLEN)  # rolling live context
        self.stop_event = threading.Event()
        self._eem_window_seconds = 600   # overwritten by MonitorEngine if eem_batch mode
        # Allow GUI to override the 30-min finalization timeout
        _rca_timeout_override = auth.get("rca_session_timeout_seconds")
        if _rca_timeout_override:
            global RCA_SESSION_TIMEOUT
            RCA_SESSION_TIMEOUT = int(_rca_timeout_override)
            print(f"[{ts()}] [CONFIG] RCA_SESSION_TIMEOUT set to {RCA_SESSION_TIMEOUT}s from config.", file=sys.stderr)
        _4th_window_override = auth.get("fourth_disjoin_recurrence_window_seconds")
        if _4th_window_override:
            global FOURTH_DISJOIN_RECURRENCE_WINDOW
            FOURTH_DISJOIN_RECURRENCE_WINDOW = int(_4th_window_override)
            print(
                f"[{ts()}] [CONFIG] FOURTH_DISJOIN_RECURRENCE_WINDOW set to "
                f"{FOURTH_DISJOIN_RECURRENCE_WINDOW}s from config.",
                file=sys.stderr,
            )
        # ── Custom debug commands (optional) ────────────────────────
        self.debug_commands_enabled = bool(auth.get("debug_commands_enabled", False))
        self.wlc_debug_start_cmds: list[str] = []
        self.wlc_debug_stop_cmds:  list[str] = []
        self.ap_debug_start_cmds:  list[str] = []
        self.ap_debug_stop_cmds:   list[str] = []
        if self.debug_commands_enabled:
            _wlc_file = auth.get("wlc_debug_cmd_file")
            _ap_file  = auth.get("ap_debug_cmd_file")
            if _wlc_file:
                self.wlc_debug_start_cmds, self.wlc_debug_stop_cmds = parse_debug_command_file(_wlc_file)
            if _ap_file:
                self.ap_debug_start_cmds, self.ap_debug_stop_cmds = parse_debug_command_file(_ap_file)
            print(
                f"[{ts()}] [DEBUG_CMDS] Loaded WLC(start={len(self.wlc_debug_start_cmds)}, "
                f"stop={len(self.wlc_debug_stop_cmds)})  "
                f"AP(start={len(self.ap_debug_start_cmds)}, stop={len(self.ap_debug_stop_cmds)})",
                file=sys.stderr,
            )
        # Per-MAC finalization guard — prevents double-finalization if two
        # disjoin events arrive for the same MAC while finalization is in flight.
        self._finalizing_macs: set[str] = set()
        self._finalizing_lock = threading.Lock()
    # ------------------------------------------------------------------ #
    # Phase 1 — session setup                                             #
    # ------------------------------------------------------------------ #

    
    # ------------------------------------------------------------------ #
    # Phase 1 — EEM applet provisioning                                   #
    # ------------------------------------------------------------------ #

    def _push_eem_applet(self) -> None:
        """
        SSH to the WLC once at startup and (re)install the EEM AP_DISJOIN applet.
        Idempotent — 'no event manager applet' first ensures a clean slate.
        Falls back gracefully if SSH fails (listener still starts).
        JumpHost IP is read from device YAML (JumpHost_ip field).
        """
        print(f"[{ts()}] Pushing EEM applet AP_DISJOIN to {self.wlc_host} ...", file=sys.stderr)
        try:
            conn = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                conn.enable()
            # add these two lines right after:  if self.auth.get("secret"): conn.enable()
            jumphost_ip = self.auth.get("jumphost_ip", "")
            source_ip   = self.wlc_host   # WLC's own IP — already known
        except Exception as exc:
            print(
                f"[{ts()}] WARNING: SSH failed during EEM setup: {exc}\n"
                f"[{ts()}] Proceeding — ensure AP_DISJOIN applet is already present on WLC.",
                file=sys.stderr,
            )
            return
        # ── If a custom EEM script was attached via GUI, send it and return ──
        eem_script_path = self.auth.get("eem_script_path")
        if eem_script_path and Path(eem_script_path).exists():
            print(f"[{ts()}] [EEM] Sending attached EEM script: {eem_script_path}", file=sys.stderr)
            try:
                lines = Path(eem_script_path).read_text(encoding="utf-8").splitlines()
                # Strip blank lines and comments, send as config block
                config_lines = [l for l in lines if l.strip() and not l.strip().startswith("!")]
                conn.send_config_set(config_lines, read_timeout=60, exit_config_mode=True)
                print(f"[{ts()}] [EEM] Custom EEM script sent — {len(config_lines)} lines.", file=sys.stderr)
            except Exception as exc:
                print(f"[{ts()}] [EEM] WARNING: Failed to send custom script: {exc}", file=sys.stderr)
            finally:
                conn.disconnect()
                print(f"[{ts()}] EEM setup SSH session closed.", file=sys.stderr)
            return   # ← skip the built-in EEM config below
        if TRIGGER_MODE == "snmp":
            # Mirrors the eem_batch applet exactly (event/action numbering and all) —
            # only the export action differs: snmp-trap instead of export-to-telemetry.
            EEM_APPLET_CONFIG = [
                f"snmp-server community {SNMP_COMMUNITY} RO",
                f"snmp-server host {jumphost_ip} version 2c public",
                "snmp-server enable traps",
                "snmp-server enable traps event-manager",
                "no event manager applet AP_DISJOIN_BATCH_SNMP",
                "event manager applet AP_DISJOIN_BATCH_SNMP",
                ' event syslog occurs 3 pattern "AP_JOIN_DISJOIN.*Disjoined" period 600',
                ' action 010 set trigger_msg "EEM_BATCH_TRIGGER"',
                ' action 020 syslog msg "$trigger_msg"',
                ' action 030 snmp-trap strdata1 "$trigger_msg"',
            ]
            print(
                f"[{ts()}] [DEBUG] TRIGGER_MODE={TRIGGER_MODE}",
                file=sys.stderr
            )
            EEM_TELEMETRY_CONFIG = []   # SNMP mode has no MDT subscription
        elif TRIGGER_MODE == "eem_batch":
            EEM_APPLET_CONFIG = [
            "no event manager applet AP_DISJOIN_BATCH",
            "event manager applet AP_DISJOIN_BATCH",
            ' event syslog occurs 3 pattern "AP_JOIN_DISJOIN.*Disjoined" period 600',
            ' action 010 set trigger_msg "EEM_BATCH_TRIGGER"',
            ' action 020 syslog msg "$trigger_msg"',
            ' action 030 export-to-telemetry "$trigger_msg"',
            "no event manager applet AP_DISJOIN_INDIVIDUAL",
            "event manager applet AP_DISJOIN_INDIVIDUAL",
            ' event syslog pattern "AP_JOIN_DISJOIN.*Disjoined"',
            ' action 010 export-to-telemetry "$_syslog_msg"',
              ]
            EEM_TELEMETRY_CONFIG = [
                "no telemetry ietf subscription 12123",
                "telemetry ietf subscription 12123",
                " encoding encode-kvgpb",
                " filter xpath /ios-events-ios-xe-oper:eem-event-publish",
                f" source-address {source_ip}",
                " stream yang-notif-native",
                " update-policy on-change",
                f" receiver ip address {jumphost_ip} 57500 protocol grpc-tcp",
            ]
        else:
            EEM_APPLET_CONFIG = [
                "no event manager applet AP_DISJOIN",
                "event manager applet AP_DISJOIN",
                ' event syslog pattern "AP_JOIN_DISJOIN.*Disjoined"',
                ' action 010 counter name AP_DISJOIN_CNT op inc value 1',
                ' action 020 if $_counter_val_AP_DISJOIN_CNT ge 3',
                ' action 030  counter name AP_DISJOIN_CNT op set value 0',
                ' action 040  syslog msg "$_syslog_msg"',
                ' action 050  cli command "show ap summary"',
                ' action 060  export-to-telemetry $_syslog_msg',
                ' action 070 end',
            ]
            EEM_TELEMETRY_CONFIG = [
                "no telemetry ietf subscription 12123",
                "telemetry ietf subscription 12123",
                " encoding encode-kvgpb",
                " filter xpath /ios-events-ios-xe-oper:eem-event-publish",
                f" source-address {source_ip}",
                " stream yang-notif-native",
                " update-policy on-change",
                f" receiver ip address {jumphost_ip} 57500 protocol grpc-tcp",
            ]

        try:
            # Step 1: push EEM applet (exits applet submode cleanly first)
            conn.send_config_set(EEM_APPLET_CONFIG, read_timeout=30, exit_config_mode=True)
            # Step 2: push telemetry subscription at global config level (SNMP has none)
            if EEM_TELEMETRY_CONFIG:
                conn.send_config_set(EEM_TELEMETRY_CONFIG, read_timeout=30, exit_config_mode=True)
            print(f"[{ts()}] EEM applet config sent.", file=sys.stderr)

            # verify registration
            verify = conn.send_command(
                "show event manager policy registered name AP_DISJOIN",
                read_timeout=15,
            )
            if "AP_DISJOIN" in verify:
                print(f"[{ts()}] Verified: EEM applet AP_DISJOIN is registered on WLC.", file=sys.stderr)
            else:
                pass #print(f"[{ts()}] WARNING: EEM applet not found after push — verify manually.", file=sys.stderr)

        except Exception as exc:
            print(f"[{ts()}] WARNING: EEM applet push failed mid-flight: {exc}", file=sys.stderr)
        finally:
            conn.disconnect()
            print(f"[{ts()}] EEM setup SSH session closed.", file=sys.stderr)
    # ------------------------------------------------------------------ #
    # Phase 2 — live stream loop                                          #
    # ------------------------------------------------------------------ #
    def _start_epc(self) -> None:
        """
        Open a short SSH session to the WLC, inject the EPC start sequence,
        then close. Called ONCE at startup, before listen() begins.
        EPC runs silently in background for the entire monitoring session.
        """
        print(f"[{ts()}] [EPC] Connecting to WLC to start EPC capture ...", file=sys.stderr)
        try:
            conn = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                conn.enable()
        except Exception as exc:
            print(
                f"[{ts()}] [EPC] WARNING: SSH failed during EPC setup: {exc} — "
                f"monitoring continues without EPC.",
                file=sys.stderr,
            )
            self.epc_meta = {
                "epc_enabled": False,
                "epc_start_time": ts(),
                "epc_error": str(exc),
                "epc_export_file": None,
                "epc_export_time": None,
            }
            return

        try:
            # epc_start: not yet implemented — mark as disabled and close
            self.epc_meta = {
                "epc_enabled": False,
                "epc_start_time": ts(),
                "epc_error": "epc_start not implemented",
                "epc_export_file": None,
                "epc_export_time": None,
            }
        finally:
            conn.disconnect()
            print(f"[{ts()}] [EPC] EPC setup SSH session closed.", file=sys.stderr)
    def _run_custom_debug_start(self, mac: str, ip: str | None) -> None:
        """Send the attached 'Start' commands to WLC + AP. No-op if disabled."""
        if not self.debug_commands_enabled:
            return
        if self.wlc_debug_start_cmds:
            print(f"[{ts()}] [CUSTOM_DEBUG] Sending {len(self.wlc_debug_start_cmds)} "
                  f"start command(s) to WLC for {mac} ...", file=sys.stderr)
            try:
                conn = ConnectHandler(
                    device_type="cisco_ios", host=self.wlc_host, port=self.auth["port"],
                    username=self.auth["username"], password=self.auth["password"],
                    secret=self.auth.get("secret"), fast_cli=False,
                )
                if self.auth.get("secret"):
                    conn.enable()
                digits = re.sub(r"[^0-9a-fA-F]", "", mac)
                mycap_name = f"MYCAP_{digits}"

                _auto_start = [
                    f"monitor capture {mycap_name} clear",
                    f"monitor capture {mycap_name} buffer size 100 circular bidirectional interface Tw0/0/0 both",
                    f"monitor capture {mycap_name} control-plane both",
                ]

                if ip:
                    _auto_start.append(
                        f"monitor capture {mycap_name} match ipv4 host {ip} any bidirectional"
                    )

                _auto_start.append(f"monitor capture {mycap_name} start")

                send_custom_commands_to_wlc(conn, _auto_start)
                send_custom_commands_to_wlc(conn, self.wlc_debug_start_cmds)
                conn.disconnect()
            except Exception as exc:
                print(f"[{ts()}] [CUSTOM_DEBUG] WLC SSH failed: {exc}", file=sys.stderr)
        if self.ap_debug_start_cmds and ip:
            print(f"[{ts()}] [CUSTOM_DEBUG] Sending {len(self.ap_debug_start_cmds)} "
                  f"start command(s) to AP {ip} for {mac} ...", file=sys.stderr)
            send_custom_commands_to_ap(ip, self.ap_auth, self.ap_debug_start_cmds)

    def _run_custom_debug_stop(self, mac: str, ip: str | None) -> None:
        """Send the attached 'Stop' commands to WLC + AP. No-op if disabled."""
        if not self.debug_commands_enabled:
            return
        if self.wlc_debug_stop_cmds:
            print(f"[{ts()}] [CUSTOM_DEBUG] Sending {len(self.wlc_debug_stop_cmds)} "
                  f"stop command(s) to WLC for {mac} ...", file=sys.stderr)
            try:
                conn = ConnectHandler(
                    device_type="cisco_ios", host=self.wlc_host, port=self.auth["port"],
                    username=self.auth["username"], password=self.auth["password"],
                    secret=self.auth.get("secret"), fast_cli=False,
                )
                if self.auth.get("secret"):
                    conn.enable()
                send_custom_commands_to_wlc(conn, self.wlc_debug_stop_cmds)
                digits = re.sub(r"[^0-9a-fA-F]", "", mac)
                mycap_name = f"MYCAP_{digits}"

                _auto_stop = [
                    f"monitor capture {mycap_name} stop",
                    f"monitor capture {mycap_name} export bootflash:ApDisjoinEpc_{mycap_name}.pcap",
                ]

                send_custom_commands_to_wlc(conn, _auto_stop)
                conn.disconnect()
            except Exception as exc:
                print(f"[{ts()}] [CUSTOM_DEBUG] WLC SSH failed during stop: {exc}", file=sys.stderr)
        if self.ap_debug_stop_cmds and ip:
            print(f"[{ts()}] [CUSTOM_DEBUG] Sending {len(self.ap_debug_stop_cmds)} "
                  f"stop command(s) to AP {ip} for {mac} ...", file=sys.stderr)
            send_custom_commands_to_ap(ip, self.ap_auth, self.ap_debug_stop_cmds)
    # DELETE stream(), ADD:
    def _finalize_rca_session(self, conn: Any, mac: str, ip: str | None) -> None:
        from backend.engine.finalizer import run_finalization
        with ACTIVE_RCA_LOCK:
            _session = ACTIVE_RCA_SESSIONS.get(mac, {})
        mycap_name = _session.get("mycap_name") or f"MYCAP_{re.sub(r'[^0-9a-fA-F]', '', mac)}"
        if self.debug_commands_enabled:
            self._run_custom_debug_stop(mac, ip)
        run_finalization(
            wlc_host=self.wlc_host,
            auth=self.auth,
            ap_auth=self.ap_auth,
            mac=mac,
            ip=ip,
            mycap_name=mycap_name,
            active_rca_sessions=ACTIVE_RCA_SESSIONS,
            active_rca_lock=ACTIVE_RCA_LOCK,
            ts=ts,
            clear_ap_workflow=clear_ap_workflow,
            mark_ap_used=mark_ap_used,
            reset_disjoin_counter=reset_disjoin_counter,
            append_finalized_ap=append_finalized_ap,
            save_report=self.save_report,
            skip_hardcoded=self.debug_commands_enabled,
        )
    def _cleanup_telemetry_subscription(self) -> None:
        """Remove the MDT telemetry subscription from WLC on exit."""
        print(f"[{ts()}] [CLEANUP] Removing telemetry subscription 12123 from {self.wlc_host} ...", file=sys.stderr)
        try:
            conn = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                conn.enable()
            cleanup_cmds = [
                "no telemetry ietf subscription 12123",
                "no event manager applet AP_DISJOIN",
                "no event manager applet AP_DISJOIN_BATCH",
                "no event manager applet AP_DISJOIN_BATCH_SNMP",
                "no event manager applet AP_DISJOIN_INDIVIDUAL",
                "no event manager applet FOURTH_DISJOIN_WATCHER",
            ]
            conn.send_config_set(cleanup_cmds, read_timeout=15, exit_config_mode=True)
            conn.disconnect()
            print(f"[{ts()}] [CLEANUP] Telemetry subscription 12123 removed.", file=sys.stderr)
        except Exception as exc:
            print(f"[{ts()}] [CLEANUP] WARNING: Could not remove subscription: {exc}", file=sys.stderr)
    def listen(self, duration_minutes: int | None) -> None:
        import grpc
        from concurrent import futures
        import telemetry_pb2
        import mdt_grpc_dialout_pb2
        import mdt_grpc_dialout_pb2_grpc
        # ── SNMP trap listener — active only when TRIGGER_MODE == "snmp" ──
        if TRIGGER_MODE == "snmp":
            import socketserver

            _monitor_self = self   # capture for closure

            class _SnmpTrapHandler(socketserver.BaseRequestHandler):
                def handle(self):
                    data   = self.request[0]
                    sender = self.client_address[0]
                    now    = ts()

                    print(f"[{now}] [SNMP_TRAP] RECEIVED — {len(data)} bytes from {sender}", file=sys.stderr)

                    # ── Extract printable OCTET STRING varbinds from raw UDP payload ──
                    strings = []
                    i, raw = 0, data
                    while i < len(raw):
                        if raw[i] == 0x04 and i + 1 < len(raw):
                            len_byte = raw[i + 1]
                            if len_byte & 0x80:
                                num_len_bytes = len_byte & 0x7f
                                if i + 2 + num_len_bytes > len(raw):
                                    break
                                length = int.from_bytes(raw[i + 2:i + 2 + num_len_bytes], "big")
                                val_start = i + 2 + num_len_bytes
                            else:
                                length = len_byte
                                val_start = i + 2
                            val = raw[val_start: val_start + length]
                            try:
                                strings.append(val.decode("utf-8", errors="ignore"))
                            except Exception:
                                pass
                            i = val_start + length
                            continue
                        i += 1
                    combined_text = " ".join(strings)
                    print(f"[{now}] [SNMP_TRAP] PARSED STRINGS: {strings}", file=sys.stderr)

                    if (
                        "EEM_BATCH_TRIGGER" not in combined_text
                        and ("Disjoined" not in combined_text or "AP_JOIN_DISJOIN" not in combined_text)
                    ):
                        return

                    print(f"[{now}] [SNMP_TRAP] Disjoin trap from {sender}: {combined_text[:120]}", file=sys.stderr)

                    if "EEM_BATCH_TRIGGER" in combined_text:
                        print(
                            f"[{now}] [SNMP_TRAP] EEM batch trigger received via SNMP trap",
                            file=sys.stderr,
                        )
                        threading.Thread(
                            target=_monitor_self._on_eem_trigger,
                            args=(combined_text, now),
                            daemon=True,
                        ).start()
                        return

                    m_name   = APNAME_RE.search(combined_text)
                    m_mac    = APMAC_RE.search(combined_text)
                    m_ip     = APIP_RE.search(combined_text)

                    ap_name  = m_name.group(1)                if m_name else None
                    mac      = normalise_mac(m_mac.group(1))  if m_mac  else None
                    ip       = m_ip.group(1)                  if m_ip   else None

                    if not mac:
                        print(f"[{now}] [SNMP_TRAP] Could not extract MAC — ignoring trap.", file=sys.stderr)
                        return

                    print(f"[{now}] [SNMP_TRAP] AP={ap_name or '?'} MAC={mac} IP={ip or '?'}", file=sys.stderr)

                    threading.Thread(
                        target=process_cgdc_event,
                        args=(mac, ap_name, ip, _monitor_self),
                        daemon=True,
                    ).start()
            snmp_server = socketserver.UDPServer(("0.0.0.0", 162), _SnmpTrapHandler)
            snmp_thread = threading.Thread(target=snmp_server.serve_forever, daemon=True)
            snmp_thread.start()
            print(f"[{ts()}] SNMP trap listener started on UDP 162 (mode=snmp)",
                  file=sys.stderr)

            deadline = (time.monotonic() + duration_minutes * 60) if duration_minutes else None
            try:
                while True:
                    if deadline and time.monotonic() > deadline:
                        print(f"[{ts()}] Duration limit reached.", file=sys.stderr)
                        break
                    time.sleep(1)
                    if self.stop_event.is_set():
                        print(f"[{ts()}] Stop requested — shutting down gRPC listener.", file=sys.stderr)
                        break

            except KeyboardInterrupt:
                print(f"\n[{ts()}] Interrupted. Flushing report...", file=sys.stderr)
            finally:
                snmp_server.shutdown()
            return   # ← exits listen() entirely; gRPC block below is skipped
        def _decode_and_dispatch(raw: bytes) -> None:
            try:
                envelope = telemetry_pb2.Telemetry()
                envelope.ParseFromString(raw)
            except Exception as exc:
                print(f"[{ts()}] [MDT] Protobuf decode failed: {exc}", file=sys.stderr)
                return
            node_id = envelope.node_id_str
            path    = envelope.encoding_path
            for row in envelope.data_gpbkv:
                fields = _parse_gpbkv(row.fields)
                event_text = (
                    fields.get("msg")
                    or fields.get("message")
                    or fields.get("syslog_msg")
                    or str(fields)
                )
                if MDT_DEBUG:
                    MDT_DEBUG_DIR.mkdir(parents=True, exist_ok=True)
                    payload_record = {
                        "timestamp": ts(),
                        "node_id": node_id,
                        "encoding_path": path,
                        "decoded_fields": {k: str(v) for k, v in fields.items()},
                    }
                    debug_file = MDT_DEBUG_DIR / f"mdt_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.json"
                    debug_file.write_text(json.dumps(payload_record, indent=2), encoding="utf-8")
                    print(f"[{ts()}] [MDT_DEBUG] Saved raw payload → {debug_file}", file=sys.stderr)
                self.live_buffer.append(f"{ts()} [MDT] {node_id} {path} {event_text}")
                if "AP_JOIN_DISJOIN" in event_text and "Disjoined" in event_text:
                    self._last_disjoin_line = event_text
                    if TRIGGER_MODE == "eem_batch":
                        _m = APMAC_RE.search(event_text)
                        _dedup_key = normalise_mac(_m.group(1)) if _m else event_text
                        if not _is_duplicate(_dedup_key):
                            self._on_eem_trigger(event_text, ts())
                        else:
                            print(f"[{ts()}] [DEDUP] Duplicate individual disjoin suppressed: {_dedup_key}", file=sys.stderr)
                if "EEM_BATCH_TRIGGER" in event_text:
                    print(f"[{ts()}] [EEM] EEM Batch Trigger fired — 3 disjoins detected", file=sys.stdout)
                    self._on_eem_trigger(event_text, ts())
                
                

        class MdtDialoutCollector(mdt_grpc_dialout_pb2_grpc.gRPCMdtDialoutServicer):
            def __init__(inner_self):
                inner_self.stop_event = threading.Event()

            def MdtDialout(inner_self, request_iterator, context):
                peer = context.peer()
                _err = sys.stderr
                print(f"[{ts()}] [MDT] gRPC session opened from {peer}", file=_err)
                print("Waiting for DISJOIN.......")
                try:
                    for dialout_args in request_iterator:
                        raw = dialout_args.data
                        self.raw_stream.append(repr(raw[:200]))
                        _decode_and_dispatch(raw)
                except Exception:
                        print(
                            f"[{ts()}] [MDT] Stream exception from {peer}\n"
                            f"{traceback.format_exc()}",
                            file=sys.stderr,
                        )
                print(f"[{ts()}] [MDT] gRPC session closed from {peer}", file=sys.stderr)
                return mdt_grpc_dialout_pb2.MdtDialoutArgs()

    # server setup inside listen()

        self._grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        server = self._grpc_server
        servicer = MdtDialoutCollector()
        mdt_grpc_dialout_pb2_grpc.add_gRPCMdtDialoutServicer_to_server(servicer, server)
        tls_cert = os.getenv("GRPC_TLS_CERT")
        tls_key  = os.getenv("GRPC_TLS_KEY")
        tls_ca   = os.getenv("GRPC_TLS_CA")    # optional — enables mTLS if set

        if tls_cert and tls_key:
            with open(tls_cert, "rb") as f: cert_chain = f.read()
            with open(tls_key,  "rb") as f: private_key = f.read()
            root_certs = None
            if tls_ca:
                with open(tls_ca, "rb") as f: root_certs = f.read()
            credentials = grpc.ssl_server_credentials(
                [(private_key, cert_chain)],
                root_certificates=root_certs,
                require_client_auth=bool(tls_ca),
            )
            server.add_secure_port(f"0.0.0.0:{self.grpc_port}", credentials)
            print(f"[{ts()}] gRPC TLS {'mTLS' if tls_ca else 'TLS'} enabled on port {self.grpc_port}", file=sys.stderr)
        else:
            server.add_insecure_port(f"0.0.0.0:{self.grpc_port}")
            #print(f"[{ts()}] WARNING: gRPC running insecure — set GRPC_TLS_CERT/KEY for production", file=sys.stderr)
        server.start()
        print(f"[{ts()}] MDT gRPC dial-out collector listening on port {self.grpc_port}. Ctrl+C to stop.",
              file=sys.stderr)

        deadline = (time.monotonic() + duration_minutes * 60) if duration_minutes else None
        try:
            while True:
                if deadline and time.monotonic() > deadline:
                    print(f"[{ts()}] Duration limit reached.", file=sys.stderr)
                    break
                if self.stop_event.is_set():
                    print(f"[{ts()}] Stop requested — shutting down gRPC listener.", file=sys.stderr)
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n[{ts()}] Interrupted. Flushing report...", file=sys.stderr)
        finally:
            server.stop(grace=2)
            self._cleanup_telemetry_subscription()
            

    # ------------------------------------------------------------------ #
    # Phase 3/4/5 — react to a disjoin line                              #
    # ------------------------------------------------------------------ #

    # DELETE _check_line(), ADD:
    def _on_eem_trigger(self, trigger_line: str, trigger_ts: str) -> None:
        # ── SNMP mode has no _decode_and_dispatch() step — the 4th-disjoin
        # recurrence trap lands here directly. Route it exactly like the
        # gRPC/telemetry path does, before any of the batch-trigger logic below.
        

        print(f"[{trigger_ts}] *** EEM TRIGGER received — parsing structured payload ***", file=sys.stderr)
        # Direct extraction from structured SNMP payload
        m_name   = APNAME_RE.search(trigger_line)
        m_mac    = APMAC_RE.search(trigger_line)
        m_ip     = APIP_RE.search(trigger_line)
        m_reason = REASON_RE.search(trigger_line)

        ap_name = m_name.group(1)   if m_name   else None
        mac     = normalise_mac(m_mac.group(1)) if m_mac else None
        ip      = m_ip.group(1)     if m_ip     else None
        reason  = m_reason.group(1) if m_reason else "unknown"

        # Dedup check — skip entirely for eem_batch and snmp, both rely on their own
        # state machine (_handle_eem_batch_trigger / workflow-active checks) for dedup.
        # For telemetry: suppress within 30s unless workflow already active for this AP.
        if TRIGGER_MODE not in ("eem_batch", "snmp"):
            dedup_key = f"{mac}:{reason}"
            if _is_duplicate(dedup_key):
                if not is_ap_workflow_active(mac):
                    print(f"[{trigger_ts}] [DEDUP] Duplicate trigger suppressed for {mac}", file=sys.stderr)
                    return
                print(f"[{trigger_ts}] [DEDUP] Duplicate but workflow active for {mac} — passing through for finalization.", file=sys.stderr)
        

        #print(f"[{trigger_ts}] DISJOIN payload | ap={ap_name or '?'} ip={ip or '?'} mac={mac or '?'} reason={reason}", file=sys.stderr)

        # ── Guard: skip JOIN events — AP_JOIN_DISJOIN syslog covers both ──
        payload_lower = trigger_line.lower()
        # AFTER:
        is_batch_trigger = "eem_batch_trigger" in payload_lower
        is_disjoin_event = "ap_join_disjoin" in payload_lower and "disjoined" in payload_lower
        if not is_batch_trigger and not is_disjoin_event:
            print(f"[{trigger_ts}] [FILTER] Non-disjoin MDT event ignored: {trigger_line[:80]}", file=sys.stderr)
            return

        # ── EEM_BATCH: only react to the WLC-confirmed 3rd disjoin trigger ──
        

        self.events.append({"timestamp": trigger_ts, "trigger_line": trigger_line,
                            "ap_name": ap_name, "ap_mac": mac, "ip": ip, "reason": reason})

        if not mac:
            if TRIGGER_MODE in ("eem_batch", "snmp"):
                print(f"[{trigger_ts}] [EEM_BATCH] Batch trigger received — launching log fetch", file=sys.stderr)
                threading.Thread(
                    target=self._handle_eem_batch_trigger,
                    daemon=True,
                ).start()
                return
            print(f"[{ts()}] No APMAC in payload — skipping RCA", file=sys.stderr)
            return

        # ── EEM_BATCH / SNMP: WLC already confirmed 3 disjoins — fetch APs then fire RCA ──
        if TRIGGER_MODE in ("eem_batch", "snmp"):
            if is_batch_trigger:
                threading.Thread(
                    target=self._handle_eem_batch_trigger,
                    daemon=True,
                ).start()
            else:
                # Individual disjoin — record only, WLC hasn't confirmed burst yet
                # Note: dedup already applied in _decode_and_dispatch using MAC key,
                # so _on_eem_trigger is only reached once per MAC per DEDUP_CACHE_TTL.
                if mac:
                    append_disjoin_occurrence(mac, ap_name, ip)
                    record_disjoin_event(mac, ap_name=ap_name, ip=ip)
                    _occ = load_disjoin_occurrences()
                    _seen = {e.get("mac") for e in _occ if e.get("mac")}
                    if "reset config cmd sent" not in (reason or "").lower():
                        print(
                            f"[{trigger_ts}] [DISJOIN_DETECTED] AP={ap_name or '?'} "
                            f"MAC={mac} IP={ip or '?'} | Total unique APs seen: {len(_seen)}",
                            file=sys.stderr,
                        )
                    
        

        # ── telemetry: existing per-AP CGDC sliding window ─────
        global ACTIVE_RCA_SESSIONS

        if mac and TRIGGER_MODE not in ("eem_batch", "snmp"):
            threading.Thread(
                target=process_cgdc_event,
                args=(mac, ap_name, ip, self),
                daemon=True,
            ).start()

        # ── Per-AP workflow disjoin counter (only if workflow already active) ──
        if is_ap_workflow_active(mac):
            print(
                f"[{ts()}] [WORKFLOW] AP {mac} disjoin detected while workflow active "
                f"— triggering finalization immediately.",
                file=sys.stderr,
            )
            # Guard: only one finalization thread per MAC at a time.
            with self._finalizing_lock:
                if mac in self._finalizing_macs:
                    print(
                        f"[{ts()}] [WORKFLOW] Finalization already in flight for {mac} "
                        f"— suppressing duplicate.",
                        file=sys.stderr,
                    )
                    return
                self._finalizing_macs.add(mac)

            with ACTIVE_RCA_LOCK:
                session = ACTIVE_RCA_SESSIONS.get(mac)

            def _finalize_and_clear(_mac=mac, _ip=session.get("ip") if session else ip):
                try:
                    self._finalize_rca_session(None, _mac, _ip)
                finally:
                    with self._finalizing_lock:
                        self._finalizing_macs.discard(_mac)

            threading.Thread(target=_finalize_and_clear, daemon=True).start()
            return
    def _react(self, mac: str, ap_name: str | None, ip: str | None, event_ts: str, live_snapshot: list[str], force_rca: bool = False) -> None:
        global ACTIVE_RCA_SESSIONS
        with ACTIVE_RCA_LOCK:
            ACTIVE_RCA_SESSIONS[mac] = {"mac": mac, "ap_name": ap_name, "ip": ip, "start_time": time.time()}
        # Ensure workflow state is active for ALL RCA paths (CGDC or legacy counter).
        # process_cgdc_event() calls set_ap_workflow_active() before submitting, so
        # this is a safe no-op for CGDC-triggered calls (it overwrites with same data).
        # For legacy counter-triggered calls it is the only place this gets set.
        if not is_ap_workflow_active(mac):
            set_ap_workflow_active(mac, ap_name, ip)

        # ── Persistent disjoin counter ────────────────────────────────────
        disjoin_count = increment_disjoin_counter(mac)
        record_disjoin_event(mac, ap_name=ap_name, ip=ip)
        print(
            f"[{ts()}] Disjoin counter for {ip or mac}: {disjoin_count} "
            f"(threshold={DISJOIN_THRESHOLD})",
            file=sys.stderr,
        )
        if disjoin_count < DISJOIN_THRESHOLD and not force_rca:
            print(
                f"[{ts()}] Counter {disjoin_count} < {DISJOIN_THRESHOLD} — "
                f"skipping full RCA for {mac}",
                file=sys.stderr,
            )
            
            self.ap_reports[mac] = {
                "ap_name":         ap_name,
                "ap_mac":          mac,
                "session_ip":      ip,
                "event_timestamp": event_ts,

                "disjoin_count":   disjoin_count,
                "rca_skipped":     True,
                "rca_skip_reason": f"Counter {disjoin_count} below threshold {DISJOIN_THRESHOLD}",
            }
            
            with ACTIVE_RCA_LOCK:
                ACTIVE_RCA_SESSIONS.pop(mac, None)
            return
        if force_rca and disjoin_count < DISJOIN_THRESHOLD:
            print(
                f"[{ts()}] [CGDC] force_rca=True — bypassing legacy counter threshold "
                f"(count={disjoin_count}) for {mac}",
                file=sys.stderr,
            )
        print(
            f"[{ts()}] *** THRESHOLD REACHED ({disjoin_count}) — "
            f"triggering full troubleshooting workflow for {ip or mac} ***",
            file=sys.stderr,
        )
        print(f"[{ts()}] Opening SSH session to {self.wlc_host} ...", file=sys.stderr)
        try:
            conn = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                conn.enable()
        except Exception as exc:
            print(f"[{ts()}] SSH connection failed: {exc} — RCA aborted for {mac}", file=sys.stderr)
            with ACTIVE_RCA_LOCK:
                ACTIVE_RCA_SESSIONS.pop(mac, None)
            return

        # ── Snapshot rolling live buffer at moment of disjoin ────────────
          # pre + event context captured here
        # ── NEW: resolve AP name from WLC if log extraction failed ──────
        try:
            # ── Resolve AP name from WLC if log extraction failed ─────
            if not ap_name:
                ap_name = resolve_ap_name_from_mac(conn, mac)
                if ap_name:
                    print(f"[{ts()}] Resolved AP name via show ap summary: {ap_name}",
                        file=sys.stderr)
                else:
                    print(f"[{ts()}] AP name unknown for {mac} — evidence will be MAC-only",
                        file=sys.stderr)

            # ── PHASE 4: trigger trace ────────────────────────────────
            print(f"[{ts()}] debug wireless mac {mac}", file=sys.stderr)
            conn.send_command_timing(
                f"debug wireless mac {mac}",
                delay_factor=1,
            )
            time.sleep(TRACE_SETTLE_DELAY)   # let WLC finish printing RA banner
            conn.clear_buffer()              # drain residual output before next send_command

            # ── MAC format helpers ────────────────────────────────────
            digits       = re.sub(r"[^0-9a-fA-F]", "", mac)
            dot_mac      = f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}".lower()
            event_ts_safe = re.sub(r"[^0-9]", "", event_ts)[:14]   # safe filename suffix

            evidence: dict[str, str] = {}

            evidence: dict[str, str] = {}
            wlc_ap_evidence:    dict[str, str] = {}
            direct_ap_evidence: dict[str, str] = {}

            if not self.debug_commands_enabled:
                # ── PHASE 4b: terminal session setup ─────────────────────
                for cmd in ["terminal exec prompt timestamp", "terminal length 0"]:
                    print(f"[{ts()}]   [WLC-SETUP] {cmd}", file=sys.stderr)
                    try:
                        out = conn.send_command_timing(cmd, delay_factor=1, read_timeout=15)
                        evidence[cmd] = out if out else "(no output)"
                    except Exception as exc:
                        print(f"[{ts()}]   [WLC-SETUP] Error on '{cmd}': {exc}", file=sys.stderr)
                        evidence[cmd] = f"ERROR: {exc}"

                # ── PHASE 4c: debug platform condition ───────────────────
                for cmd in [
                    f"debug platform condition feature wireless mac {dot_mac}",
                    "debug platform condition start",
                ]:
                    print(f"[{ts()}]   [WLC-DEBUG] {cmd}", file=sys.stderr)
                    try:
                        out = conn.send_command_timing(cmd, delay_factor=1, read_timeout=15)
                        evidence[cmd] = out if out else "(no output)"
                    except Exception as exc:
                        print(f"[{ts()}]   [WLC-DEBUG] Error on '{cmd}': {exc}", file=sys.stderr)
                        evidence[cmd] = f"ERROR: {exc}"
                # ── show debug — snapshot active WLC debugs ──────────────
                _wlc_sd = "show debug"
                print(f"[{ts()}]   [WLC-DEBUG] {_wlc_sd}", file=sys.stderr)
                try:
                    out = conn.send_command(_wlc_sd, read_timeout=15)
                    evidence[f"{_wlc_sd} (post-WLC-debugs)"] = out if out else "(no output)"
                except Exception as exc:
                    print(f"[{ts()}]   [WLC-DEBUG] Error on '{_wlc_sd}': {exc}", file=sys.stderr)
                    evidence[f"{_wlc_sd} (post-WLC-debugs)"] = f"ERROR: {exc}"

                # ── PHASE 4d: MYCAP packet capture ───────────────────────
                mycap_name = f"MYCAP_{digits}"   # unique per AP — avoids cross-session clobbering
                with ACTIVE_RCA_LOCK:
                    if mac in ACTIVE_RCA_SESSIONS:
                        ACTIVE_RCA_SESSIONS[mac]["mycap_name"] = mycap_name
                _mycap_cmds = [
                    f"monitor capture {mycap_name} clear",
                    f"monitor capture {mycap_name} buffer size 100 circular bidirectional interface Tw0/0/0 both",
                    f"monitor capture {mycap_name} control-plane both",
                    f"monitor capture {mycap_name} match ipv4 host {ip} any bidirectional" if ip else None,
                    f"monitor capture {mycap_name} start",
                   
                    
                ]
                _mycap_cmds = [c for c in _mycap_cmds if c is not None]
                for cmd in _mycap_cmds:
                    print(f"[{ts()}]   [MYCAP] {cmd}", file=sys.stderr)
                    try:
                        out = conn.send_command_timing(cmd, delay_factor=1, read_timeout=15)
                        evidence[cmd] = out if out else "(no output)"
                    except Exception as exc:
                        print(f"[{ts()}]   [MYCAP] Error on '{cmd}': {exc}", file=sys.stderr)
                        evidence[cmd] = f"ERROR: {exc}"

                # ── MYCAP verification — give the capture 15s to collect packets ──
                print(f"[{ts()}]   [MYCAP] Waiting 15s for capture {mycap_name} to collect packets...", file=sys.stderr)
                time.sleep(15)
                _verify_cmd = f"show monitor capture {mycap_name} buffer brief"
                print(f"[{ts()}]   [MYCAP] {_verify_cmd}", file=sys.stderr)
                try:
                    verify_out = conn.send_command(_verify_cmd, read_timeout=30)
                    evidence[_verify_cmd] = verify_out if verify_out else "(no output)"
                    if not verify_out or not verify_out.strip():
                        print(f"[{ts()}]   [MYCAP] WARNING: No packets captured for {mycap_name} after 15s.", file=sys.stderr)
                except Exception as exc:
                    print(f"[{ts()}]   [MYCAP] Error on '{_verify_cmd}': {exc}", file=sys.stderr)
                    evidence[_verify_cmd] = f"ERROR: {exc}"

                # ── PHASE 4e: ping AP to verify reachability ─────────────
                if ip:
                    cmd = f"ping {ip}"
                    print(f"[{ts()}]   [WLC-PING] {cmd}", file=sys.stderr)
                    try:
                        out = conn.send_command(cmd, read_timeout=30)
                        evidence[cmd] = out if out else "(no output)"
                    except Exception as exc:
                        print(f"[{ts()}]   [WLC-PING] Error on '{cmd}': {exc}", file=sys.stderr)
                        evidence[cmd] = f"ERROR: {exc}"

                # ── PHASE 5: WLC evidence collection (externalized) ──────
                _wlc_catalog = load_command_catalog(
                    self.auth.get("wlc_evidence_cmd_file", "CONF/wlc_commands.conf")
                )
                _show_cmds: list[str] = []
                for entry in _wlc_catalog:
                    raw_cmd = entry["cmd"]
                    if "{ap_name}" in raw_cmd and not ap_name:
                        continue   # skip ap_name-dependent lines if AP name unknown
                    cmd = raw_cmd.format(
                        mac=dot_mac,
                        event_ts=event_ts_safe,
                        ap_name=ap_name or "",
                    )
                    _show_cmds.append(cmd)
                if not _show_cmds:
                    print(f"[{ts()}] [CMD_CATALOG] WLC command catalog empty — no evidence commands to run.", file=sys.stderr)
                for cmd in _show_cmds:
                    print(f"[{ts()}]   {cmd}", file=sys.stderr)
                    try:
                        output = conn.send_command(cmd, read_timeout=120)
                        if not output or output.strip().startswith("%") or "Invalid input" in output:
                            print(f"[{ts()}]   Skipped (unsupported/error): {cmd}", file=sys.stderr)
                            evidence[cmd] = "(skipped — unsupported or error response)"
                        else:
                            evidence[cmd] = output
                    except Exception as exc:
                        print(f"[{ts()}]   Error on '{cmd}': {exc}", file=sys.stderr)
                        evidence[cmd] = f"ERROR: {exc}"

                # ── PHASE 6: parallel WLC AP telemetry + direct AP SSH ────
                def _wlc_ap_worker() -> None:
                    print(f"[{ts()}] [WLC AP TELEMETRY] Starting collection ...", file=sys.stderr)
                    wlc_ap_evidence.update(collect_ap_side_evidence(conn, ap_name, mac))
                    print(f"[{ts()}] [WLC AP TELEMETRY] Done — {len(wlc_ap_evidence)} commands.",
                          file=sys.stderr)

                def _ap_ssh_worker() -> None:
                    if not ip:
                        print(f"[{ts()}] [DIRECT AP SSH TELEMETRY] No AP IP — skipping.",
                              file=sys.stderr)
                        return
                    direct_ap_evidence.update(
                        collect_advanced_capwap_on_ap(ip, self.ap_auth, ap_name))

                t_wlc = threading.Thread(target=_wlc_ap_worker, daemon=True)
                t_ap  = threading.Thread(target=_ap_ssh_worker, daemon=True)
                t_wlc.start()
                t_ap.start()
                t_wlc.join()
                t_ap.join()

            else:
                # ── CUSTOM-ONLY MODE: skip ALL hardcoded evidence collection ──
                # Only the attached wlc_cmds.txt / ap_cmds.txt start-commands run.
                mycap_name = f"MYCAP_{digits}"
                with ACTIVE_RCA_LOCK:
                    if mac in ACTIVE_RCA_SESSIONS:
                        ACTIVE_RCA_SESSIONS[mac]["mycap_name"] = mycap_name

                if self.wlc_debug_start_cmds:
                    print(f"[{ts()}] [CUSTOM-ONLY] Sending {len(self.wlc_debug_start_cmds)} "
                          f"WLC start command(s) for {mac} ...", file=sys.stderr)
                    evidence.update(send_custom_commands_to_wlc(conn, self.wlc_debug_start_cmds))
                else:
                    print(f"[{ts()}] [CUSTOM-ONLY] No WLC custom commands loaded — nothing sent.",
                          file=sys.stderr)

                if self.ap_debug_start_cmds and ip:
                    print(f"[{ts()}] [CUSTOM-ONLY] Sending {len(self.ap_debug_start_cmds)} "
                          f"AP start command(s) to {ip} for {mac} ...", file=sys.stderr)
                    direct_ap_evidence.update(
                        send_custom_commands_to_ap(ip, self.ap_auth, self.ap_debug_start_cmds))
                elif self.ap_debug_start_cmds and not ip:
                    print(f"[{ts()}] [CUSTOM-ONLY] No AP IP available — skipping AP custom commands.",
                          file=sys.stderr)

            # ── correlation (WLC controller evidence) ─────────────────
            live_context  = "\n".join(live_snapshot)
            supplementary = "\n".join(
                v for v in evidence.values()
                if v and not v.startswith("ERROR") and v != "(no output)"
                and v != "(skipped — unsupported or error response)"
            )
            combined = live_context + "\n" + supplementary
            finding  = _correlation_engine.run(combined)
            print(
                f"[{ts()}] Correlation → [{finding['confidence'].upper()}] "
                f"{finding['probable_cause']}",
                file=sys.stderr,
            )

            # ── WLC AP correlation ────────────────────────────────────
            if wlc_ap_evidence:
                ap_side_finding = correlate_ap_side(wlc_ap_evidence, ap_name)
                print(
                    f"[{ts()}] [WLC AP TELEMETRY] Correlation → "
                    f"[{ap_side_finding['confidence'].upper()}] "
                    f"{ap_side_finding['probable_cause']}",
                    file=sys.stderr,
                )
            else:
                ap_side_finding = {}
                print(f"[{ts()}] [WLC AP TELEMETRY] Collection returned no evidence",
                      file=sys.stderr)

            # ── Save wlc_telemetry file (controller + WLC AP cmds) ────
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            safe_mac     = mac.replace(":", "")
            safe_ip = (ip or safe_mac).replace(".", "_")
            wlc_tel_path = REPORTS_DIR / f"wlc_telemetry_{safe_ip}_{event_ts_safe}.txt"
            wlc_tel_lines = [
                f"WLC Telemetry — {self.wlc_host}",
                f"AP MAC  : {mac}",
                f"AP Name : {ap_name or 'unknown'}",
                f"AP IP   : {ip or 'unknown'}",
                f"Event   : {event_ts}",
                "=" * 60, "",
                "── WLC CONTROLLER DIAGNOSTICS ──", "",
            ]
            for cmd, out in evidence.items():
                wlc_tel_lines += [f"=== {cmd} ===", out, ""]
            wlc_tel_lines += ["", "── WLC AP TELEMETRY ──", ""]
            for cmd, out in wlc_ap_evidence.items():
                wlc_tel_lines += [f"=== {cmd} ===", out, ""]
            wlc_tel_path.write_text("\n".join(wlc_tel_lines), encoding="utf-8")
            print(f"[{ts()}] WLC telemetry saved → {wlc_tel_path}", file=sys.stderr)

            # ── Save ap_telemetry file (direct AP SSH only) ───────────
            ap_tel_path  = REPORTS_DIR / f"ap_telemetry_{safe_ip}_{event_ts_safe}.txt"
            ap_tel_lines = [
                f"Direct AP SSH Telemetry — {ip or 'unknown'}",
                f"AP MAC  : {mac}",
                f"AP Name : {ap_name or 'unknown'}",
                f"AP IP   : {ip or 'unknown'}",
                f"Event   : {event_ts}",
                "=" * 60, "",
                "── DIRECT AP SSH TELEMETRY ──", "",
            ]
            if direct_ap_evidence:
                for cmd, out in direct_ap_evidence.items():
                    ap_tel_lines += [f"=== {cmd} ===", out, ""]
            else:
                ap_tel_lines.append("No direct AP SSH output collected.")
            ap_tel_path.write_text("\n".join(ap_tel_lines), encoding="utf-8")
            print(f"[{ts()}] AP telemetry saved → {ap_tel_path}", file=sys.stderr)

            self.ap_reports[mac] = {
                "ap_name":                     ap_name,
                "ap_mac":                      mac,
                "session_ip":                  ip,
                "event_timestamp":             event_ts,
                "disjoin_count":               disjoin_count,
                "trace_triggered_at":          ts(),
                "pre_event_live_context":      live_snapshot[:-20] if len(live_snapshot) > 20 else live_snapshot,
                "event_live_context_snapshot": live_snapshot[-20:],
                "evidence":                    evidence,
                "wlc_telemetry_file":          str(wlc_tel_path),
                "ap_telemetry_file":           str(ap_tel_path),
                "correlation":                 finding,
                "wlc_ap_evidence":             wlc_ap_evidence,
                "direct_ap_evidence":          direct_ap_evidence,
                "ap_side_evidence":            {**wlc_ap_evidence, **direct_ap_evidence},
                "ap_side_correlation":         ap_side_finding,
            }
            
        finally:
            conn.disconnect()
            print(
                f"[{ts()}] SSH session closed after telemetry collection for {mac}. "
                f"Session now WAITING_FOR_NEXT_DISJOIN.",
                file=sys.stderr,
            )
            # ACTIVE_RCA intentionally NOT cleared here.
            # Finalization happens on the next disjoin OR after the 30-min timeout below.

            # ── 30-minute auto-finalization window ───────────────────
            def _timeout_finalize_worker(_mac=mac, _ip=ip):
                _wait = RCA_SESSION_TIMEOUT
                print(
                    f"[{ts()}] [TIMEOUT] 30-min timer started for {_mac}.",
                    file=sys.stderr,
                )
                time.sleep(_wait)
                # Check both ACTIVE_RCA_SESSIONS and AP workflow state
                with ACTIVE_RCA_LOCK:
                    still_active = _mac in ACTIVE_RCA_SESSIONS
                if still_active or is_ap_workflow_active(_mac):
                    print(
                        f"[{ts()}] [TIMEOUT] 30-min timer expired for {_mac} — "
                        f"triggering finalization.",
                        file=sys.stderr,
                    )
                    # Honour the same finalization guard used by _on_eem_trigger.
                    with self._finalizing_lock:
                        if _mac in self._finalizing_macs:
                            print(
                                f"[{ts()}] [TIMEOUT] Finalization already in flight for {_mac} "
                                f"— timeout worker exiting.",
                                file=sys.stderr,
                            )
                            return
                        self._finalizing_macs.add(_mac)
                    try:
                        self._finalize_rca_session(None, _mac, _ip)
                    finally:
                        with self._finalizing_lock:
                            self._finalizing_macs.discard(_mac)
                else:
                    print(
                        f"[{ts()}] [TIMEOUT] Session for {_mac} already finalized — "
                        f"timeout worker exiting cleanly.",
                        file=sys.stderr,
                    )
            threading.Thread(target=_timeout_finalize_worker, daemon=True).start()
    def _finalize_all_active_on_4th(self, trigger_line: str = "") -> None:
        """
        Called when FOURTH_DISJOIN_DETECTED fires.
        Parses the AP that actually disjoined out of the embedded syslog text
        and compares it against the locked AP from the original 3-disjoin batch.
          - MATCH    → same AP recurred → finalize active RCA session(s) (logic below unchanged).
          - NO MATCH → a different AP disjoined → record it only, no finalization.
        """
        now = ts()

        m_name = APNAME_RE.search(trigger_line)
        m_mac  = APMAC_RE.search(trigger_line)
        m_ip   = APIP_RE.search(trigger_line)
        ap_name = m_name.group(1) if m_name else None
        mac     = normalise_mac(m_mac.group(1)) if m_mac else None
        ip      = m_ip.group(1) if m_ip else None

        if not mac:
            print(f"[{now}] [4TH_DISJOIN] Could not parse AP MAC from trigger payload — ignoring.", file=sys.stderr)
            return

        # ── Always record this disjoin to the disjoins file ──────────
        # ── Always record this disjoin to the disjoins file ──────────
        append_disjoin_occurrence(mac, ap_name, ip)
        record_disjoin_event(mac, ap_name=ap_name, ip=ip)
        set_ap_traced_count(len({o.get("mac") for o in load_disjoin_occurrences() if o.get("mac")}))   # ← ADD THIS LINE

        locked_mac = getattr(self, "_locked_mac_for_4th", None)

        if mac != locked_mac:
            print(
                f"[{now}] [DISJOIN_DETECTED] AP={ap_name or '?'} MAC={mac} IP={ip or '?'} "
                f"(non-matching disjoin received — recorded)",
                file=sys.stdout,
            )
            print(
                f"[{now}] [4TH_DISJOIN] Disjoin from {mac} ({ap_name or '?'}) does NOT match "
                f"locked AP {locked_mac} — recording only, no finalization.",
                file=sys.stderr,
            )
            return   # ← self._increment_detected_aps_counter(mac, ap_name, ip) line is DELETED

        print(f"[{now}] [4TH_DISJOIN] Disjoin from {mac} matches locked AP — finalizing active RCA session(s) ...", file=sys.stderr)

        with ACTIVE_RCA_LOCK:
            active_macs = list(ACTIVE_RCA_SESSIONS.keys())

        # If _react hasn't populated ACTIVE_RCA_SESSIONS yet but workflow IS active,
        # fall back to the locked MAC itself so finalization is never missed.
        if not active_macs and is_ap_workflow_active(mac):
            active_macs = [mac]

        finalize_threads: list[threading.Thread] = []

        for mac in active_macs:
            with ACTIVE_RCA_LOCK:
                session = ACTIVE_RCA_SESSIONS.get(mac)
            ip = session.get("ip") if session else None

            should_skip = False
            with self._finalizing_lock:
                if mac in self._finalizing_macs:
                    should_skip = True
                else:
                    self._finalizing_macs.add(mac)

            if should_skip:
                print(f"[{now}] [4TH_DISJOIN] Finalization already in flight for {mac} — waiting for it to complete.", file=sys.stderr)
                while True:
                    with self._finalizing_lock:
                        if mac not in self._finalizing_macs:
                            break
                    time.sleep(1)
                print(f"[{now}] [4TH_DISJOIN] In-flight finalization for {mac} completed.", file=sys.stderr)
                continue

            print(f"[{now}] [4TH_DISJOIN] Finalizing {mac} ({ip or '?'}) ...", file=sys.stderr)

            def _do_finalize(_mac=mac, _ip=ip):
                try:
                    self._finalize_rca_session(None, _mac, _ip)
                finally:
                    with self._finalizing_lock:
                        self._finalizing_macs.discard(_mac)

            t = threading.Thread(target=_do_finalize, daemon=True)
            finalize_threads.append(t)
            t.start()
        if not finalize_threads:
            return
        # Wait for ALL finalization threads to complete before shutting down
        for t in finalize_threads:
            t.join()

        # ── Remove the 4th-disjoin watcher applet from WLC ───────────
        try:
            _c = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                _c.enable()
            _c.send_config_set(
                ["no event manager applet FOURTH_DISJOIN_WATCHER"],
                read_timeout=15, exit_config_mode=True,
            )
            _c.disconnect()
            print(f"[{now}] [4TH_DISJOIN] FOURTH_DISJOIN_WATCHER applet removed from WLC.", file=sys.stderr)
            self._watcher_running_for = None
        except Exception as exc:
            print(f"[{now}] [4TH_DISJOIN] WARNING: Could not remove watcher applet: {exc}", file=sys.stderr)
        
        

        print(
        f"\n[{now}] ╔══════════════════════════════════════════════════╗",
        file=sys.stderr,
            )
        print(
                f"[{now}] ║        ✅  EVIDENCE COLLECTION COMPLETE          ║",
                file=sys.stderr,
            )
        print(
                f"[{now}] ║  disjoin confirmed — RCA finalized           ║",
                file=sys.stderr,
            )
        print(
                f"[{now}] ║  AP: {', '.join(active_macs) or 'unknown':<44}║",
                file=sys.stderr,
            )
        print(
                f"[{now}] ║  Reports saved to: {str(REPORTS_DIR):<31}║",
                file=sys.stderr,
            )
        print(
                f"[{now}] ╚══════════════════════════════════════════════════╝\n",
                file=sys.stderr,
            )
        # ── Graceful shutdown — 4th disjoin confirmed, evidence collected ──────
        now2 = ts()
        report = self.ap_reports.get(active_macs[0] if active_macs else "", {})
        wlc_tel = report.get("wlc_telemetry_file", str(REPORTS_DIR))
        ap_tel  = report.get("ap_telemetry_file",  str(REPORTS_DIR))

        print(f"\n[{now2}] ┌─────────────────────────────────────────────────────┐", file=sys.stderr)
        print(f"[{now2}] │  ✅  RCA COMPLETE — EVIDENCE SUMMARY                 │", file=sys.stderr)
        print(f"[{now2}] ├─────────────────────────────────────────────────────┤", file=sys.stderr)
        print(f"[{now2}] │  WLC Telemetry  → {str(wlc_tel)[-50:]:<50}│", file=sys.stderr)
        print(f"[{now2}] │  AP  Telemetry  → {str(ap_tel)[-50:]:<50}│", file=sys.stderr)
        print(f"[{now2}] │  Reports dir    → {str(REPORTS_DIR):<50}│", file=sys.stderr)
        print(f"[{now2}] ├─────────────────────────────────────────────────────┤", file=sys.stderr)
        print(f"[{now2}] │  Shutting down monitor and cleaning up WLC applets.  │", file=sys.stderr)
        print(f"[{now2}] └─────────────────────────────────────────────────────┘\n", file=sys.stderr)

        # Signal the listen() loop to stop — triggers _cleanup_telemetry_subscription()
        self.stop_event.set()
    def _increment_detected_aps_counter(self, mac: str, ap_name: str | None, ip: str | None) -> None:
        """
        Append a newly-seen AP to the most recent detected_aps_*.txt file and
        bump its 'Total unique APs seen' count — this is the same file the GUI
        polls (_poll_ap_occurrences) to populate the 'APs TRACED' stat card.
        """
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        detected_files = sorted(REPORTS_DIR.glob("detected_aps_*.txt"), reverse=True)
        if not detected_files:
            print(f"[{ts()}] [4TH_DISJOIN] No detected_aps file found — skipping AP counter update.", file=sys.stderr)
            return

        path = detected_files[0]
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            print(f"[{ts()}] [4TH_DISJOIN] Could not read {path}: {exc}", file=sys.stderr)
            return

        if any(mac in line for line in lines):
            print(f"[{ts()}] [4TH_DISJOIN] AP {mac} already present in {path.name} — not re-counting.", file=sys.stderr)
            return

        new_total = None
        for i, line in enumerate(lines):
            m = re.search(r"Total unique APs seen in disjoin log:\s*(\d+)", line)
            if m:
                new_total = int(m.group(1)) + 1
                lines[i] = f"Total unique APs seen in disjoin log: {new_total}"
                break

        if new_total is None:
            print(f"[{ts()}] [4TH_DISJOIN] Could not find AP counter line in {path.name} — skipping.", file=sys.stderr)
            return

        lines.append(f"  {new_total}. AP={ap_name or '?'}  MAC={mac}  IP={ip or '?'}")

        try:
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"[{ts()}] [4TH_DISJOIN] AP counter incremented → {new_total} (added {mac}) in {path.name}", file=sys.stderr)
        except Exception as exc:
            print(f"[{ts()}] [4TH_DISJOIN] Could not write {path}: {exc}", file=sys.stderr)
    def _handle_eem_batch_trigger(self) -> None:
        """
        Called when WLC EEM fires EEM_BATCH_TRIGGER (3 disjoins confirmed by WLC).
        SSH to WLC, fetch latest AP_JOIN_DISJOIN log lines, extract the 3 most
        recent unique APs, then launch RCA for each.
        """
        trigger_ts = ts()
        print(f"[{trigger_ts}] [EEM_BATCH] Trigger received — SSHing to WLC to fetch latest disjoins ...", file=sys.stderr)

        try:
            conn = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                conn.enable()
        except Exception as exc:
            print(f"[{trigger_ts}] [EEM_BATCH] SSH failed: {exc} — cannot fetch AP details", file=sys.stderr)
            return

        try:
            output = conn.send_command(
                "show logging | include AP_JOIN_DISJOIN",
                read_timeout=30,
            )
        except Exception as exc:
            print(f"[{trigger_ts}] [EEM_BATCH] 'show logging' failed: {exc}", file=sys.stderr)
            conn.disconnect()
            return
        finally:
            conn.disconnect()
            print(f"[{trigger_ts}] [EEM_BATCH] SSH session closed after log fetch.", file=sys.stderr)

        # ── Parse ALL disjoin lines — collect every AP seen ──────────
        all_detected: list[dict] = []
        seen_macs_detected: set[str] = set()
        for line in reversed(output.splitlines()):
            if "Disjoined" not in line:
                continue

            m_name = APNAME_RE.search(line)
            m_mac  = APMAC_RE.search(line)
            m_ip   = APIP_RE.search(line)

            mac_val  = normalise_mac(m_mac.group(1)) if m_mac else None
            name_val = m_name.group(1) if m_name else None
            ip_val   = m_ip.group(1)   if m_ip   else None

            if not mac_val or mac_val in seen_macs_detected:
                continue

            seen_macs_detected.add(mac_val)
            all_detected.append({
                "mac": mac_val, "ap_name": name_val, "ip": ip_val,
                "detected_at": trigger_ts,
            })

        if not all_detected:
            print(f"[{trigger_ts}] [EEM_BATCH] No AP_JOIN_DISJOIN lines found in logging — RCA aborted.", file=sys.stderr)
            return

        # ── Write ALL detected APs to a file ─────────────────────────
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        detected_path = REPORTS_DIR / f"detected_aps_{re.sub(r'[^0-9]', '', trigger_ts)[:14]}.txt"
        detected_lines = [
            f"Detected APs at EEM Batch Trigger — {trigger_ts}",
            f"Total unique APs seen in disjoin log: {len(all_detected)}",
            "=" * 50, "",
        ]
        for i, ap in enumerate(all_detected, start=1):
            detected_lines.append(
                f"  {i}. AP={ap['ap_name'] or '?'}  MAC={ap['mac']}  IP={ap['ip'] or '?'}"
            )
        detected_lines.append("")
        detected_path.write_text("\n".join(detected_lines), encoding="utf-8")
        print(
            f"[{trigger_ts}] [EEM_BATCH] {len(all_detected)} AP(s) detected — "
            f"written to {detected_path}",
            file=sys.stderr,
        )
        history_event = {
            "event_time": trigger_ts,
            "event_valid": True,
            "aps": [
                {"ap_name": ap["ap_name"], "mac": ap["mac"], "ip": ap["ip"]}
                for ap in all_detected
            ],
        }
        completed_count = append_disjoin_event_history(history_event)
        print(f"[{trigger_ts}] [EEM_BATCH] Event recorded → Completed_Disjoin_Events_Count={completed_count}", file=sys.stderr)

        # ── The locked AP for the 4th watcher = the most recent (first in reversed list) ──
        # parsed keeps the single entry used for RCA launch (unchanged behaviour)
        parsed: list[dict] = [all_detected[0]]
        entry = parsed[0]
        locked_mac_for_4th = entry["mac"]
        self._locked_mac_for_4th = locked_mac_for_4th   # remember for match-check in _finalize_all_active_on_4th
        self._eem_batch_ap_count = getattr(self, "_eem_batch_ap_count", 0) + len(all_detected)
        print(
            f"[{trigger_ts}] [EEM_BATCH] Last disjoin: mac={entry['mac']} "
            f"ap={entry['ap_name'] or '?'} ip={entry['ip'] or '?'}",
            file=sys.stderr,
        )

        # ── Push 4th-disjoin watcher EEM applet to WLC ───────────────
        try:
            _4th_conn = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                _4th_conn.enable()

            _digits = re.sub(r"[^0-9a-fA-F]", "", locked_mac_for_4th)
            _dot_mac = f"{_digits[0:4]}.{_digits[4:8]}.{_digits[8:12]}".lower()

            _4th_export_action = (
                ' action 020 snmp-trap strdata "$trigger_msg"' if TRIGGER_MODE == "snmp"
                else ' action 020 export-to-telemetry "$trigger_msg"'
            )
            
            _suspend_batch = [
                "no event manager applet AP_DISJOIN_BATCH",
            ]
            _4th_conn.send_config_set(_suspend_batch, read_timeout=30, exit_config_mode=True)
            _4th_conn.disconnect()
            print(
                f"[{trigger_ts}] [EEM_BATCH] disjoin watcher pushed for MAC {_dot_mac}. "
                f"AP_DISJOIN_BATCH suspended until 4th disjoin or timeout.",
                f"Waiting up to {FOURTH_DISJOIN_RECURRENCE_WINDOW}s for same AP to disjoin again.",
                file=sys.stderr,
            )
        except Exception as exc:
            print(f"[{trigger_ts}] [EEM_BATCH] WARNING: Could not push 4th-disjoin applet: {exc}", file=sys.stderr)

        # ── Launch RCA for the last disjoined AP only ─────────────────
        for entry in parsed:
            ap_mac  = entry["mac"]
            ap_name = entry["ap_name"]
            ap_ip   = entry["ip"]

            if is_ap_workflow_active(ap_mac):
                ...
                continue

            append_disjoin_occurrence(ap_mac, ap_name, ap_ip)
            record_disjoin_event(ap_mac, ap_name=ap_name, ip=ap_ip)
            set_ap_workflow_active(ap_mac, ap_name, ap_ip)
            set_ap_workflow_active(ap_mac, ap_name, ap_ip)

            # Pre-register in ACTIVE_RCA_SESSIONS so _finalize_all_active_on_4th
            # can find this MAC immediately, even before _react acquires SSH.
            with ACTIVE_RCA_LOCK:
                ACTIVE_RCA_SESSIONS[ap_mac] = {
                    "mac":        ap_mac,
                    "ap_name":    ap_name,
                    "ip":         ap_ip,
                    "start_time": time.time(),
                }

            # ── Start recurrence timeout watcher only once per locked MAC ──
            if not getattr(self, "_watcher_running_for", None) == locked_mac_for_4th:
                self._watcher_running_for = locked_mac_for_4th
                threading.Thread(
                    target=self._fourth_disjoin_timeout_watcher,
                    args=(locked_mac_for_4th, FOURTH_DISJOIN_RECURRENCE_WINDOW),
                    daemon=True,
                ).start()
            else:
                print(
                    f"[{trigger_ts}] [4TH_WATCHER] Watcher already running for "
                    f"{locked_mac_for_4th} — not restarting timer.",
                    file=sys.stderr,
                )

            

            print(f"[{trigger_ts}] [EEM_BATCH] Launching RCA for mac={ap_mac} ap={ap_name or '?'} ip={ap_ip or '?'}", file=sys.stderr)

            if _rca_executor:
                _rca_executor.submit(
                    self._react,
                    ap_mac, ap_name, ap_ip, trigger_ts, [], True,
                )
            else:
                threading.Thread(
                    target=self._react,
                    args=(ap_mac, ap_name, ap_ip, trigger_ts, [], True),
                    daemon=True,
                ).start()  

    # ------------------------------------------------------------------ #
    # Report                                                              #
    # ------------------------------------------------------------------ #
    def _fourth_disjoin_timeout_watcher(self, locked_mac: str, window_seconds: int) -> None:
        start = time.monotonic()
        poll_interval = 5
        now_iso = ts()
        WATCHER_GRACE_SECONDS = 60

        #print(
          #  f"[{now_iso}] [4TH_WATCHER] Waiting up to {window_seconds}s for "
           # f"AP {locked_mac} to disjoin again (disjoin = finalization trigger).",
            #file=sys.stderr,
        #)

        while time.monotonic() - start < window_seconds:
            elapsed = time.monotonic() - start
            with ACTIVE_RCA_LOCK:
                still_active = locked_mac in ACTIVE_RCA_SESSIONS
            if elapsed > WATCHER_GRACE_SECONDS and not still_active and not is_ap_workflow_active(locked_mac):
                print(
                    f"[{ts()}] [4TH_WATCHER] AP {locked_mac} session already finalized "
                    f"— watcher exiting cleanly.",
                    file=sys.stderr,
                )
                return
            time.sleep(poll_interval)

        # ── Timeout: 4th disjoin did NOT arrive within the window ────── (dedented — was inside the while loop before)
        print(
            f"\n[{ts()}] [4TH_WATCHER] ⏰ Recurrence window ({window_seconds}s) expired "
            f"for AP {locked_mac} — no 4th disjoin detected.",
            file=sys.stderr,
        )
        print(
            f"[{ts()}] [4TH_WATCHER] Resetting monitoring loop → re-pushing EEM batch applet.",
            file=sys.stderr,
        )

        # Step 1: Remove the stale 4th-disjoin watcher applet from WLC
        try:
            _c = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                _c.enable()
            _c.send_config_set(
                ["no event manager applet FOURTH_DISJOIN_WATCHER"],
                read_timeout=15, exit_config_mode=True,
            )
            _c.disconnect()
            print(f"[{ts()}] [4TH_WATCHER] Stale FOURTH_DISJOIN_WATCHER removed from WLC.", file=sys.stderr)
        except Exception as exc:
            print(f"[{ts()}] [4TH_WATCHER] WARNING: Could not remove watcher applet: {exc}", file=sys.stderr)

        with ACTIVE_RCA_LOCK:
            still_active = locked_mac in ACTIVE_RCA_SESSIONS
            session = ACTIVE_RCA_SESSIONS.get(locked_mac, {})
        if still_active:
            print(f"[{ts()}] [4TH_WATCHER] Finalizing RCA session for {locked_mac} after timeout.", file=sys.stderr)
            with self._finalizing_lock:
                if locked_mac not in self._finalizing_macs:
                    self._finalizing_macs.add(locked_mac)
                    try:
                        self._finalize_rca_session(None, locked_mac, session.get("ip"))
                    finally:
                        with self._finalizing_lock:
                            self._finalizing_macs.discard(locked_mac)

        clear_ap_workflow(locked_mac)
        mark_ap_used(locked_mac)

        self._watcher_running_for = None
    def save_report(self) -> tuple[Path, Path]:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp     = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", self.wlc_host)
        base      = REPORTS_DIR / f"ap_disjoin_{safe_host}_{stamp}"
        json_path = base.with_suffix(".json")
        txt_path  = Path(str(base) + "_summary.txt")

        report = {
            "ok":               True,
            "schema_version":   "2.0",
            "session_metadata": {
                "wlc_host":      self.wlc_host,
                "device_name":   self.device_name,
                "session_start": self.start_ts,
                "session_end":   ts(),
                "total_events":  len(self.events),
                "unique_aps":    len(self.ap_reports),
            },
            "disjoin_events":  self.events,
            "ap_reports":      self.ap_reports,
            "raw_stream_lines": self.raw_stream,
        }
        #json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

        # plain-text summary
        lines = [f"AP Disjoin Session — {self.wlc_host}", "=" * 50, ""]
        if not self.ap_reports:
            lines.append("No disjoin events with traceable MAC detected.")
        for mac, r in self.ap_reports.items():
            c = r["correlation"]
            lines += [
                f"AP  : {r['ap_name'] or 'unknown'}  [{mac}]",
                f"Time: {r['event_timestamp']}",
                "",
                f"  [WLC CONTROLLER DIAGNOSTICS]",
                f"  Confidence : {c['confidence'].upper()}",
                f"  Cause      : {c['probable_cause']}",
                f"  Action     : {c['action']}",
                f"  Commands   : {len(r.get('evidence', {}))} collected",
                f"  File       : {r.get('wlc_telemetry_file', 'N/A')}",
                "",
            ]

            # ── WLC AP Telemetry section ──────────────────────────────
            ap_s        = r.get("ap_side_correlation", {})
            wlc_ap_cmds = r.get("wlc_ap_evidence", {})
            direct_cmds = r.get("direct_ap_evidence", {})

            if ap_s:
                lines += [
                    f"  [WLC AP TELEMETRY]",
                    f"  Confidence : {ap_s.get('confidence', 'N/A').upper()}",
                    f"  Cause      : {ap_s.get('probable_cause', 'N/A')}",
                    f"  Action     : {ap_s.get('action', 'N/A')}",
                    f"  Commands   : {len(wlc_ap_cmds)} collected via WLC CLI",
                    f"  File       : {r.get('wlc_telemetry_file', 'N/A')}",
                ]
                for obs in ap_s.get("observations", []):
                    lines.append(f"    · {obs}")
                lines.append("")

            # ── Direct AP SSH Telemetry section ───────────────────────
            if direct_cmds:
                lines += [
                    f"  [DIRECT AP SSH TELEMETRY]",
                    f"  Commands   : {len(direct_cmds)} collected directly from AP ({r.get('session_ip', 'unknown IP')})",
                    f"  File       : {r.get('ap_telemetry_file', 'N/A')}",
                    "",
                ]
            else:
                lines += [
                    f"  [DIRECT AP SSH TELEMETRY]",
                    f"  No output collected (AP SSH unreachable or no IP available)",
                    f"  File       : {r.get('ap_telemetry_file', 'N/A')}",
                    "",
                ]
        # ── AP Disjoin History section ────────────────────────────────────
        all_stats = get_ap_stats()
        if all_stats:
            lines += ["", "=" * 26, "AP DISJOIN HISTORY", "=" * 26]
            for stat_mac, stat in sorted(all_stats.items()):
                lines += [
                    "",
                    f"AP Name : {stat.get('ap_name') or 'unknown'}",
                    f"MAC     : {stat_mac}",
                    f"IP      : {stat.get('ip') or 'unknown'}",
                    "",
                    f"Total Disjoins : {stat.get('disjoin_count', 0)}",
                    "",
                    "Disjoin Timeline:",
                ]
                for idx, stamp in enumerate(stat.get("timestamps", []), start=1):
                    # Reformat ISO timestamp to a readable UTC string
                    try:
                        dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                        readable = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        readable = stamp
                    lines.append(f"  {idx}. {readable}")
                lines.append("")

        txt_path.write_text("\n".join(lines), encoding="utf-8")
        return json_path, txt_path

# ---------------------------------------------------------------------------
# Session log tee
# ---------------------------------------------------------------------------

class _TeeStream:
    """Writes to both the original stderr and a log file simultaneously."""
    def __init__(self, original, logfile):
        self._orig = original
        self._log  = logfile

    def write(self, msg):
        self._orig.write(msg)
        self._log.write(msg)

    def flush(self):
        self._orig.flush()
        self._log.flush()

    def fileno(self):          # needed by some internals
        return self._orig.fileno()
# ---------------------------------------------------------------------------
# Auth / inventory
# ---------------------------------------------------------------------------

def resolve_auth(args: argparse.Namespace) -> dict[str, Any]:
    device_data: dict | None = None
    if getattr(args, "device", None):
        inv = load_inventory(args.inventory_file)
        device_data = inv.get(args.device)
        if not device_data:
            print(json.dumps({"ok": False, "error": f"Device '{args.device}' not in inventory"}))
            sys.exit(1)

    host     = args.host     or (device_data or {}).get("host")
    username = args.username or (device_data or {}).get("username")
    port     = args.port     or int((device_data or {}).get("port", 22))
    password = (
        args.password
        or os.getenv("IOSXE_PASSWORD")
        or (device_data or {}).get("password")
    )
    secret = (
        args.secret
        or os.getenv("IOSXE_SECRET")
        or (device_data or {}).get("enable_secret")
    )
    if not host or not username:
        print(json.dumps({"ok": False, "error": "host and username required"}))
        sys.exit(1)
    if not password:
        import getpass
        password = getpass.getpass("Password: ")

    return {"host": host, "username": username, "password": password,
        "port": port, "secret": secret,
        "ap_username": (device_data or {}).get("ap_username", "Cisco"),
        "ap_password": (device_data or {}).get("ap_password", "Cisco"),
        "ap_secret":   (device_data or {}).get("ap_secret", ""),
        "jumphost_ip": (device_data or {}).get("jumphost_ip", ""),
        "tftp_ip":     (device_data or {}).get("tftp_ip", ""),
        "eem_script_path": getattr(args, "eem_script_path", None),
        "fourth_disjoin_recurrence_window_seconds": (device_data or {}).get("fourth_disjoin_recurrence_window_seconds", None),
        "wlc_evidence_cmd_file": (device_data or {}).get("wlc_evidence_cmd_file", "CONF/wlc_commands.conf"),}


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def _run_monitor_legacy_inline(args: argparse.Namespace) -> None:
    auth        = resolve_auth(args)
    host        = auth["host"]
    grpc_port = getattr(args, "grpc_port", GRPC_PORT)

    # ── Session log file ─────────────────────────────────────────────────
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    global log
    log = setup_logging(REPORTS_DIR)
    stamp        = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_host    = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", host)
    log_path     = REPORTS_DIR / f"session_log_{safe_host}_{stamp}.txt"
    _log_file    = log_path.open("w", encoding="utf-8", buffering=1)
    _orig_stderr = sys.stderr
    _orig_stdout = sys.stdout
    sys.stderr   = _TeeStream(_orig_stderr, _log_file)
    sys.stdout   = _TeeStream(_orig_stdout, _log_file)
    # ─────────────────────────────────────────────────────────────────────

    print(f"[{ts()}]  AP Disjoin Monitor starting — WLC={host}", file=sys.stderr)

    # ── Trigger mode selection ────────────────────────────────────────────
    global TRIGGER_MODE
    TRIGGER_MODE = (
        "snmp"      if getattr(args, "snmp", False)      else
        "eem_batch" if getattr(args, "eem_batch", False)  else
        "telemetry"
    )
    print(f"[{ts()}] Trigger mode: {TRIGGER_MODE.upper()}", file=sys.stderr)
    # ─────────────────────────────────────────────────────────────────────

    # ── Clear stale workflow state from previous session ──────────────────
    if AP_WORKFLOW_STATE_FILE.exists():
        try:
            stale = json.loads(AP_WORKFLOW_STATE_FILE.read_text(encoding="utf-8"))
            for mac_key in stale:
                stale[mac_key]["workflow_active"] = False
            AP_WORKFLOW_STATE_FILE.write_text(
                json.dumps(stale, indent=2, sort_keys=True), encoding="utf-8"
            )
            print(f"[{ts()}] Cleared stale workflow state from previous session.", file=sys.stderr)
        except Exception as exc:
            print(f"[{ts()}] WARNING: Could not clear stale workflow state: {exc}", file=sys.stderr)

    monitor = LiveMonitor(auth=auth, wlc_host=host,
                      device_name=getattr(args, "device", None),
                      grpc_port=grpc_port)
    _emergency_cleanup._monitor = monitor
    global _rca_executor
    _rca_executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_RCA)
    monitor._push_eem_applet()
    monitor.listen(getattr(args, "duration_minutes", None))
    _rca_executor.shutdown(wait=True)

    json_path, txt_path = monitor.save_report()

    # ── Restore stderr and close log ─────────────────────────────────────
    sys.stderr = _orig_stderr
    sys.stdout = _orig_stdout
    _log_file.close()
    print(f"[{ts()}] Session log saved → {log_path}", file=sys.stderr)
    high = sum(
        1 for r in monitor.ap_reports.values()
        if (r.get("correlation") or {}).get("confidence") == "high"
        or (r.get("ap_side_correlation") or {}).get("confidence") == "high"
    )
    print(json.dumps({
        "ok": True, "wlc_host": host,
        "trigger_mode": f"EEM_{'SNMP_trap' if TRIGGER_MODE == 'snmp' else 'MDT_gRPC_dialout'}",
        "grpc_port": grpc_port if TRIGGER_MODE != "snmp" else None,
        "total_disjoin_events": len(monitor.events),
        "unique_aps_traced": max(len(monitor.ap_reports), getattr(monitor, "_eem_batch_ap_count", 0)),
        "high_confidence_findings": high,
        "report_json": str(json_path), "report_summary": str(txt_path),
    }, indent=2))


def run_analyze(args: argparse.Namespace) -> None:
    path = Path(args.report)
    if not path.exists():
        print(json.dumps({"ok": False, "error": f"Not found: {path}"}))
        sys.exit(1)
    data = json.loads(path.read_text())
    findings = []
    for mac, r in data.get("ap_reports", {}).items():
        live_context  = "\n".join(
            r.get("pre_event_live_context", []) +
            r.get("event_live_context_snapshot", [])
        )
        supplementary = "\n".join(r.get("evidence", {}).values())
        combined      = live_context + "\n" + supplementary
        wlc_finding   = correlate(combined)

        # ── re-correlate AP-side too ──────────────────────────────────
        ap_side_evidence = r.get("ap_side_evidence", {})
        ap_side_finding  = correlate_ap_side(ap_side_evidence, r.get("ap_name")) \
                           if ap_side_evidence else {}

        findings.append({
            "ap_mac":            mac,
            "ap_name":           r.get("ap_name"),
            "wlc_correlation":   wlc_finding,
            "ap_side_correlation": ap_side_finding,
        })
    print(json.dumps({"ok": True, "source": str(path),
                      "findings": findings}, indent=2))


def run_monitor(args: argparse.Namespace) -> None:
    config = config_from_args(args)
    engine = MonitorEngine()
    _emergency_cleanup._engine = engine
    engine.start(config)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=" — Live AP Disjoin Monitor for Cisco 9800 WLC"
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    mon = sub.add_parser("monitor", help="Live stream monitoring session")
    mon.add_argument("--device")
    mon.add_argument("--inventory-file", default=DEFAULT_INVENTORY)
    mon.add_argument("--host")
    mon.add_argument("--port", type=int, default=22)
    mon.add_argument("--username")
    mon.add_argument("--password")
    mon.add_argument("--secret")
    mon.add_argument("--duration-minutes", type=int, default=None)
    mon.add_argument("--report-dir", default="reports")
   
    mon.set_defaults(func=run_monitor)
    mon.add_argument("--grpc-port", type=int, default=GRPC_PORT, dest="grpc_port",
                 help=f"TCP port for MDT gRPC dial-out receiver (default {GRPC_PORT})")
    mon.add_argument("--snmp", action="store_true", default=False,
                 help="Use SNMP trap mode instead of MDT gRPC dial-out")
    ana = sub.add_parser("analyze", help="Re-analyze a saved report JSON")
    ana.add_argument("--report", required=True)
    ana.set_defaults(func=run_analyze)

    return p
import atexit
import signal

def _emergency_cleanup():
    """Best-effort cleanup of WLC applets on unexpected exit."""
    try:
        # Try engine path (GUI/MonitorEngine flow)
        if hasattr(_emergency_cleanup, "_engine") and _emergency_cleanup._engine:
            monitor = getattr(_emergency_cleanup._engine, "_monitor", None)
            if monitor:
                monitor._cleanup_telemetry_subscription()
                return
        # Try direct monitor path (legacy inline flow)
        if hasattr(_emergency_cleanup, "_monitor") and _emergency_cleanup._monitor:
            _emergency_cleanup._monitor._cleanup_telemetry_subscription()
    except Exception:
        pass

atexit.register(_emergency_cleanup)

def main() -> None:
    args = build_parser().parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc),
                          "type": type(exc).__name__}), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()