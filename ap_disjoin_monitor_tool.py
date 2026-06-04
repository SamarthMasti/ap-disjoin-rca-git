#!/usr/bin/env python3
"""
ap_disjoin_monitor_tool.py — Minion Network Automation Toolkit
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

MAX_CONCURRENT_RCA = int(os.getenv("MAX_CONCURRENT_RCA", "5"))
_rca_queue: queue.Queue = queue.Queue()
_rca_executor: ThreadPoolExecutor | None = None



import logging
from logging.handlers import RotatingFileHandler

def setup_logging(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("minion")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
    # Rotating file handler — 5 MB × 5 files
    fh = RotatingFileHandler(
        log_dir / "minion.log", maxBytes=5*1024*1024, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
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
    r"AP_JOIN_DISJOIN.*Disjoined",
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
    {"key": "terminal-len",        "cmd": "terminal length 0",      "is_debug": True},    
    {"key": "show-logging",        "cmd": "show logging",  "is_debug": False},    
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
    {"key": "terminal-monitor",      "cmd": "terminal monitor",      "is_debug": True},
    # ── Final logging snapshot ────────────────────────
    {"key": "show-logging-final",    "cmd": "show logging",          "is_debug": False},
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
        )
        if ap_auth.get("secret"):
            ap_conn.enable()
    except Exception as exc:
        print(f"[{ts()}]   [AP] AP SSH failed: {exc} — skipping AP-direct collection",
              file=sys.stderr)
        return advanced

    try:
        for entry in AP_ADVANCED_CAPWAP_CATALOG:
            cmd      = entry["cmd"]
            is_debug = entry["is_debug"]

            print(f"[{ts()}]   [AP] {'(debug) ' if is_debug else ''}{cmd}",
                  file=sys.stderr)
            try:
                if is_debug:
                    output = ap_conn.send_command_timing(cmd, delay_factor=1, read_timeout=10)
                else:
                    output = ap_conn.send_command(cmd, read_timeout=10)

                if not output or output.strip().startswith("%") or "Invalid input" in output:
                    print(f"[{ts()}]   [AP] Skipped (unsupported/error): {cmd}",
                          file=sys.stderr)
                    continue

                advanced[cmd] = output

            except Exception as exc:
                print(f"[{ts()}]   [AP] Error on '{cmd}': {exc}",
                      file=sys.stderr)

        # ── show debug — snapshot active AP debugs ───────────────────
        _ap_sd = "show debug"
        print(f"[{ts()}]   [AP] {_ap_sd}", file=sys.stderr)
        try:
            sd_out = ap_conn.send_command(_ap_sd, read_timeout=15)
            if sd_out and not sd_out.strip().startswith("%") and "Invalid input" not in sd_out:
                advanced[_ap_sd] = sd_out
        except Exception as exc:
            print(f"[{ts()}]   [AP] Error on '{_ap_sd}': {exc}", file=sys.stderr)

        

        

        

        

        

        

        
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
    """
    Called once per confirmed disjoin event.
    Appends occurrence then evaluates the sliding window.
    """
    append_disjoin_occurrence(mac, ap_name, ip)
    print(
        f"[{ts()}] [EVENT] New occurrence appended — mac={mac} ap={ap_name or '?'}",
        file=sys.stderr,
    )
    evaluate_disjoin_event(monitor)
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

        if TRIGGER_MODE == "snmp":
            EEM_CONFIG = [
                f"snmp-server community {SNMP_COMMUNITY} RO",
                f"snmp-server host {jumphost_ip} version 2c {SNMP_COMMUNITY}",
                "snmp-server enable traps",
                "no event manager applet AP_DISJOIN",
                "event manager applet AP_DISJOIN",
                ' event syslog pattern "Disjoined"',
                ' action 1.0 snmp-trap strdata "$_syslog_msg"',
            ]
        else:
            EEM_CONFIG = [
                "no event manager applet AP_DISJOIN",
                "event manager applet AP_DISJOIN",
                ' event syslog pattern "AP_JOIN_DISJOIN.*Disjoined"',
                ' action 1.0 syslog msg "$_syslog_msg"',
                ' action 2.0 cli command "show ap summary"',
                ' action 3.0 export-to-telemetry $_syslog_msg',
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
            conn.send_config_set(EEM_CONFIG, read_timeout=30, exit_config_mode=False)
            conn.exit_config_mode()
            print(f"[{ts()}] EEM applet config sent.", file=sys.stderr)

            # verify registration
            verify = conn.send_command(
                "show event manager policy registered name AP_DISJOIN",
                read_timeout=15,
            )
            if "AP_DISJOIN" in verify:
                print(f"[{ts()}] Verified: EEM applet AP_DISJOIN is registered on WLC.", file=sys.stderr)
            else:
                print(f"[{ts()}] WARNING: EEM applet not found after push — verify manually.", file=sys.stderr)

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
            self.epc_meta = epc_start(conn)
        finally:
            conn.disconnect()
            print(f"[{ts()}] [EPC] EPC setup SSH session closed.", file=sys.stderr)

    # DELETE stream(), ADD:
    def _finalize_rca_session(self, conn: Any, mac: str, ip: str | None) -> None:
        """
        Execute the clean finalization sequence for the active RCA session.
        Called ONLY when a second disjoin of the SAME AP/MAC is received.
        Opens a fresh SSH connection — the RCA collection conn may already be closed.

        Sequence:
          1. undebug all on WLC
          2. monitor capture MYCAP stop
          3. monitor capture MYCAP export bootflash:mycap.pcap
          4. show flash: | inc .pcap   (verify)
          5. undebug all on AP (direct SSH)
          6. generate + save JSON and summary reports
          7. clear ACTIVE_RCA state
        """
        global ACTIVE_RCA_SESSIONS

        print(f"[{ts()}] [FINALIZE] Second disjoin of same AP ({mac}) — starting finalization sequence.",
              file=sys.stderr)

        # ── 1+2+3+4: WLC cleanup via fresh SSH ───────────────────────────
        wlc_conn = None
        try:
            print(f"[{ts()}] [FINALIZE] Opening WLC SSH for cleanup ...", file=sys.stderr)
            wlc_conn = ConnectHandler(
                device_type="cisco_ios",
                host=self.wlc_host,
                port=self.auth["port"],
                username=self.auth["username"],
                password=self.auth["password"],
                secret=self.auth.get("secret"),
                fast_cli=False,
            )
            if self.auth.get("secret"):
                wlc_conn.enable()

            # undebug all
            print(f"[{ts()}] [FINALIZE] [WLC] undebug all", file=sys.stderr)
            try:
                wlc_conn.send_command_timing("undebug all", delay_factor=1, read_timeout=15)
            except Exception as exc:
                print(f"[{ts()}] [FINALIZE] WARNING: undebug all failed: {exc}", file=sys.stderr)

            # ── Stop MYCAP ────────────────────────────────────────────────
            stop_cmd = f"monitor capture {MYCAP_NAME} stop"
            print(f"[{ts()}] [FINALIZE] [MYCAP] {stop_cmd}", file=sys.stderr)
            try:
                stop_out = wlc_conn.send_command_timing(
                    stop_cmd, delay_factor=1, read_timeout=30
                )
                if stop_out:
                    print(f"[{ts()}] [FINALIZE] [MYCAP] {stop_out.strip()}", file=sys.stderr)
                # "Capture MYCAP is not active" is informational — not a failure.
                if "not active" in (stop_out or "").lower():
                    print(
                        f"[{ts()}] [FINALIZE] [MYCAP] Capture was already stopped — continuing.",
                        file=sys.stderr,
                    )
            except Exception as exc:
                print(f"[{ts()}] [FINALIZE] WARNING: '{stop_cmd}' failed: {exc}", file=sys.stderr)

            # ── Export MYCAP — handle interactive overwrite prompt ────────
            export_cmd = f"monitor capture {MYCAP_NAME} export bootflash:ApDisjoinEpc.pcap"
            print(f"[{ts()}] [FINALIZE] [MYCAP] {export_cmd}", file=sys.stderr)
            try:
                # Send the export command and collect the immediate response.
                # IOS-XE may pause and emit an interactive overwrite prompt before
                # completing the export.  We must answer it before sending anything
                # else, otherwise the next command string gets partially consumed
                # by the pending prompt (producing e.g. "how flash: | inc .pcap").
                export_out = wlc_conn.send_command_timing(
                    export_cmd,
                    delay_factor=1,       # give IOS-XE time to emit the prompt
                    read_timeout=30,
                )
                print(f"[{ts()}] [FINALIZE] [MYCAP] initial response: {export_out.strip()!r}",
                      file=sys.stderr)

                OVERWRITE_PATTERNS = (
                    "overwrite?[confirm]",
                    "overwrite existing",
                    "[confirm]",
                    "confirm",
                )
                if any(p in export_out.lower() for p in OVERWRITE_PATTERNS):
                    print(
                        f"[{ts()}] [FINALIZE] [MYCAP] Overwrite prompt detected — "
                        f"sending ENTER to confirm.",
                        file=sys.stderr,
                    )
                    # Send ENTER and wait for the export to finish writing the file.
                    confirm_out = wlc_conn.send_command_timing(
                        "\n",
                        delay_factor=1,   # file export can take several seconds
                        read_timeout=60,
                    )
                    if confirm_out:
                        print(
                            f"[{ts()}] [FINALIZE] [MYCAP] post-confirm output: "
                            f"{confirm_out.strip()!r}",
                            file=sys.stderr,
                        )
                    # Extra settle — ensure IOS-XE has returned to the exec prompt
                    # and the output buffer is fully drained before the next command.
                    time.sleep(2)
                    wlc_conn.clear_buffer()
                else:
                    # No prompt — export completed (or failed) without interaction.
                    # Still allow a short settle before verification.
                    time.sleep(2)
                    wlc_conn.clear_buffer()

            except Exception as exc:
                print(
                    f"[{ts()}] [FINALIZE] WARNING: export command failed: {exc}",
                    file=sys.stderr,
                )

            # ── Verify .pcap exists on flash — only after export is complete ─
            verify_cmd = "show flash: | inc .pcap"
            print(f"[{ts()}] [FINALIZE] [MYCAP] {verify_cmd}", file=sys.stderr)
            try:
                verify_out = wlc_conn.send_command(
                    verify_cmd,
                    read_timeout=30,
                )
                if verify_out:
                    print(
                        f"[{ts()}] [FINALIZE] [MYCAP] {verify_out.strip()}",
                        file=sys.stderr,
                    )
                    if "mycap.pcap" in verify_out.lower():
                        print(
                            f"[{ts()}] [FINALIZE] [MYCAP] ✓ mycap.pcap confirmed on flash.",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            f"[{ts()}] [FINALIZE] [MYCAP] WARNING: mycap.pcap not found in "
                            f"flash listing — export may have failed.",
                            file=sys.stderr,
                        )
            except Exception as exc:
                print(
                    f"[{ts()}] [FINALIZE] WARNING: '{verify_cmd}' failed: {exc}",
                    file=sys.stderr,
                )

            # ── Upload MYCAP to tftp server for analysis ────────
            #copy flash:/mycap.pcap tftp://192.168.0.6/mycap.pcap
            tftp_ip = self.auth.get("tftp_ip", "")
            export_cmd = f"copy flash:/ApDisjoinEpc.pcap tftp://{tftp_ip}/ApDisjoinEpc.pcap"
            print(f"[{ts()}] [EPC_TFTP_Upload] {export_cmd}", file=sys.stderr)
            try:
                export_out = wlc_conn.send_command_timing(
                    export_cmd,
                    delay_factor=1,       # give IOS-XE time to emit the prompt
                    read_timeout=100,
                )
                print(f"[{ts()}] [EPC_TFTP_Upload] First Enter response: {export_out.strip()!r}",file=sys.stderr)
                # Send ENTER and wait for the export to finish writing the file.
                confirm_out = wlc_conn.send_command_timing(
                    "\n",
                    delay_factor=1,   # file export can take several seconds
                    read_timeout=10,
                )
                print(f"[{ts()}] [EPC_TFTP_Upload] Second Enter response: {export_out.strip()!r}",file=sys.stderr)
                # Send ENTER and wait for the export to finish writing the file.
                confirm_out = wlc_conn.send_command_timing(
                    "\n",
                    delay_factor=1,
                    read_timeout=10,
                )
                if SUCCESS_RE.search(confirm_out or ""):
                    print(f"[{ts()}] [EPC_TFTP_Upload] ✓ ApDisjoinEpc.pcap transferred successfully.", file=sys.stderr)
                else:
                    print(f"[{ts()}] [EPC_TFTP_Upload] WARNING: ApDisjoinEpc.pcap transfer may have failed. Response: {confirm_out!r}", file=sys.stderr)
            except Exception as exc:
                print(
                    f"[{ts()}] [EPC_TFTP_Upload] WARNING: export command failed: {exc}",
                    file=sys.stderr,
                )
            # ── Upload RA Always ON Traces to tftp server for analysis ────────
            #copy flash:/ALWAYS_ON_3c41.0e3a.ca00.log tftp://192.168.0.6/ALWAYS_ON_3c41.0e3a.ca00.log
            digits  = re.sub(r"[^0-9a-fA-F]", "", mac)
            dot_mac = f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}".lower()
            export_cmd = f"copy flash:/ALWAYS_ON_{dot_mac}.log tftp://{tftp_ip}/ALWAYS_ON_{dot_mac}.log"
            print(f"[{ts()}] [EPC_TFTP_Upload] {export_cmd}", file=sys.stderr)
            try:
                export_out = wlc_conn.send_command_timing(
                    export_cmd,
                    delay_factor=1,       # give IOS-XE time to emit the prompt
                    read_timeout=100,
                )
                print(f"[{ts()}] [EPC_TFTP_Upload] First Enter response: {export_out.strip()!r}",file=sys.stderr)
                # Send ENTER and wait for the export to finish writing the file.
                confirm_out = wlc_conn.send_command_timing(
                    "\n",
                    delay_factor=1,   # file export can take several seconds
                    read_timeout=10,
                )
                print(f"[{ts()}] [EPC_TFTP_Upload] Second Enter response: {export_out.strip()!r}",file=sys.stderr)
                # Send ENTER and wait for the export to finish writing the file.
                confirm_out = wlc_conn.send_command_timing(
                    "\n",
                    delay_factor=1,
                    read_timeout=10,
                )
                if SUCCESS_RE.search(confirm_out or ""):
                    print(f"[{ts()}] [EPC_TFTP_Upload] ✓ ALWAYS_ON log transferred successfully.", file=sys.stderr)
                else:
                    print(f"[{ts()}] [EPC_TFTP_Upload] WARNING: ALWAYS_ON log transfer may have failed. Response: {confirm_out!r}", file=sys.stderr)
            except Exception as exc:
                print(
                    f"[{ts()}] [EPC_TFTP_Upload] WARNING: export command failed: {exc}",
                    file=sys.stderr,
                )
        except Exception as exc:
            print(f"[{ts()}] [FINALIZE] WARNING: WLC SSH for cleanup failed: {exc}", file=sys.stderr)
        finally:
            if wlc_conn:
                try:
                    wlc_conn.disconnect()
                    print(f"[{ts()}] [FINALIZE] WLC cleanup SSH session closed.", file=sys.stderr)
                except Exception:
                    pass

        # ── 5: undebug all on AP (direct SSH) ────────────────────────────
        if ip:
            try:
                print(f"[{ts()}] [FINALIZE] [AP] Connecting to AP {ip} for undebug all ...",
                      file=sys.stderr)
                ap_conn = ConnectHandler(
                    device_type="cisco_ios",
                    host=ip,
                    port=22,
                    username=self.ap_auth["username"],
                    password=self.ap_auth["password"],
                    secret=self.ap_auth.get("secret", ""),
                    fast_cli=False,
                )
                if self.ap_auth.get("secret"):
                    ap_conn.enable()
                ap_conn.send_command_timing("undebug all", delay_factor=1, read_timeout=15)
                print(f"[{ts()}] [FINALIZE] [AP] undebug all sent to AP {ip}", file=sys.stderr)
                ap_conn.disconnect()
            except Exception as exc:
                print(f"[{ts()}] [FINALIZE] WARNING: AP undebug all failed: {exc}", file=sys.stderr)

        # ── 6: generate reports ───────────────────────────────────────────
        print(f"[{ts()}] [FINALIZE] Generating reports ...", file=sys.stderr)
        try:
            json_path, txt_path = self.save_report()
            print(f"[{ts()}] [FINALIZE] JSON report  → {json_path}", file=sys.stderr)
            print(f"[{ts()}] [FINALIZE] Summary report → {txt_path}", file=sys.stderr)
        except Exception as exc:
            print(f"[{ts()}] [FINALIZE] WARNING: report generation failed: {exc}", file=sys.stderr)

        # ── 7: clear ACTIVE_RCA state ─────────────────────────────────────
        with ACTIVE_RCA_LOCK:
            ACTIVE_RCA_SESSIONS.pop(mac, None)
        clear_ap_workflow(mac)
        mark_ap_used(mac)
        print(f"[{ts()}] [FINALIZE] Session complete for {mac}.", file=sys.stderr)
        reset_disjoin_counter(mac)
        print(f"[{ts()}] [FINALIZE] Disjoin counter reset for {mac}.", file=sys.stderr)
        print(f"[{ts()}] [FINALIZE] Finalization complete for {mac}.", file=sys.stderr)
        append_finalized_ap(
                mac=mac,
                ap_name=ACTIVE_RCA_SESSIONS.get(mac, {}).get("ap_name"),
                ip=ip,
                
            )
    
    def listen(self, duration_minutes: int | None) -> None:
        import grpc
        from concurrent import futures
        import telemetry_pb2
        import mdt_grpc_dialout_pb2
        import mdt_grpc_dialout_pb2_grpc
        # ── SNMP trap listener — active only when TRIGGER_MODE == "snmp" ──
        if TRIGGER_MODE == "snmp":
            import socketserver, struct

            class _SnmpTrapHandler(socketserver.BaseRequestHandler):
                def handle(inner_self):
                    data = inner_self.request[0]
                    try:
                        text = data.decode("latin-1", errors="replace")
                    except Exception:
                        text = repr(data)
                    print(f"[{ts()}] [SNMP] Raw trap received ({len(data)} bytes)",
                          file=sys.stderr)
                    if "AP_JOIN_DISJOIN" in text and "Disjoined" in text:
                        self._on_eem_trigger(text, ts())

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
                if "AP_JOIN_DISJOIN" in event_text or "Disjoined" in event_text:
                    self._on_eem_trigger(event_text, ts())

        class MdtDialoutCollector(mdt_grpc_dialout_pb2_grpc.gRPCMdtDialoutServicer):
            def __init__(inner_self):
                inner_self.stop_event = threading.Event()

            def MdtDialout(inner_self, request_iterator, context):
                peer = context.peer()
                print(f"[{ts()}] [MDT] gRPC session opened from {peer}", file=sys.stderr)
                try:
                    for dialout_args in request_iterator:
                        raw = dialout_args.data
                        self.raw_stream.append(repr(raw[:200]))
                        _decode_and_dispatch(raw)        # ← plain closure call, no self needed
                except Exception:
                        print(
                            f"[{ts()}] [MDT] Stream exception from {peer}\n"
                            f"{traceback.format_exc()}",
                            file=sys.stderr,
                        )
                print(f"[{ts()}] [MDT] gRPC session closed from {peer}", file=sys.stderr)
                return mdt_grpc_dialout_pb2.MdtDialoutArgs()

    # server setup inside listen()

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
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
            print(f"[{ts()}] WARNING: gRPC running insecure — set GRPC_TLS_CERT/KEY for production", file=sys.stderr)
        server.start()
        print(f"[{ts()}] MDT gRPC dial-out collector listening on port {self.grpc_port}. Ctrl+C to stop.",
              file=sys.stderr)

        deadline = (time.monotonic() + duration_minutes * 60) if duration_minutes else None
        try:
            while True:
                if deadline and time.monotonic() > deadline:
                    print(f"[{ts()}] Duration limit reached.", file=sys.stderr)
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n[{ts()}] Interrupted. Flushing report...", file=sys.stderr)
        finally:
            server.stop(grace=5)

    # ------------------------------------------------------------------ #
    # Phase 3/4/5 — react to a disjoin line                              #
    # ------------------------------------------------------------------ #

    # DELETE _check_line(), ADD:
    def _on_eem_trigger(self, trigger_line: str, trigger_ts: str) -> None:
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

        # Dedup check — mac now available
        dedup_key = f"{mac}:{reason}"
        if _is_duplicate(dedup_key):
            print(f"[{trigger_ts}] [DEDUP] Duplicate trigger suppressed for {mac}", file=sys.stderr)
            return
        

        print(f"[{trigger_ts}] DISJOIN payload | ap={ap_name or '?'} ip={ip or '?'} mac={mac or '?'} reason={reason}", file=sys.stderr)

        # ── Guard: skip JOIN events — AP_JOIN_DISJOIN syslog covers both ──
        payload_lower = trigger_line.lower()
        if "ap_join_disjoin" not in payload_lower or "disjoined" not in payload_lower:
            print(f"[{trigger_ts}] [FILTER] Non-disjoin MDT event ignored (likely AP join): {trigger_line[:80]}", file=sys.stderr)
            return

        self.events.append({"timestamp": trigger_ts, "trigger_line": trigger_line,
                            "ap_name": ap_name, "ap_mac": mac, "ip": ip, "reason": reason})
# ── CGDC batch processor — runs in background, never blocks MDT ──
        if mac:
            threading.Thread(
                target=process_cgdc_event,
                args=(mac, ap_name, ip, self),
                daemon=True,
            ).start()
        

        if not mac:
            print(f"[{ts()}] No APMAC in payload — skipping RCA", file=sys.stderr)
            return

        global ACTIVE_RCA_SESSIONS

        # ── Per-AP workflow disjoin counter (only if workflow already active) ──
        if is_ap_workflow_active(mac):
            print(
                f"[{ts()}] [WORKFLOW] AP {mac} disjoin detected while workflow active "
                f"— triggering finalization immediately.",
                file=sys.stderr,
            )
            with ACTIVE_RCA_LOCK:
                session = ACTIVE_RCA_SESSIONS.get(mac)
            threading.Thread(
                target=self._finalize_rca_session,
                args=(None, mac, session.get("ip") if session else ip),
                daemon=True,
            ).start()
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
            # ── PHASE 4d: MYCAP packet capture ───────────────────────
                #monitor capture MYCAP clear
                #monitor capture MYCAP buffer size 100 circular bidirectional interface Tw0/0/0 both
                #monitor capture MYCAP control-plane both
                #monitor capture MYCAP match ipv4 host <ap_ip> any bidirectional
                #monitor capture start
                #monitor capture MYCAP export flash:ApDisjoinEpc.pcap
                #show flash: | in .pcap
                #show monitor capture MYCAP buffer brief
                #copy flash:ApDisjEpc.pcap tftp://192.168.0.6/ApDisjEpc.pcap

            _mycap_cmds = [
                f"monitor capture {MYCAP_NAME} clear",
                f"monitor capture {MYCAP_NAME} buffer size 100 circular bidirectional interface Tw0/0/0 both",
                f"monitor capture {MYCAP_NAME} control-plane both",
                f"monitor capture {MYCAP_NAME} match ipv4 host {ip} any bidirectional" if ip else None,
                f"monitor capture {MYCAP_NAME} start",
                f"ping 192.168.0.212",
                f"ping 192.168.0.1",
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

            # ── PHASE 5: WLC evidence collection ─────────────────────
            _show_cmds: list[str] = [
                "show logging",
                "show platform resources",
                "show processes cpu platform | include wncd",
                "show ap image summary",
                "show logging | include AP_JOIN_DISJOIN",
                "show ap uptime",
                "show wireless stats ap history",
                "show ap crash-file",
                "dir all | include crash",
                "show processes cpu platform sorted",
                "show logging",
                "show platform software object-manager chassis active F0 childless-delete-object",
                "show platform software object-manager chassis active F0 pending-issue-update",
                f"show wireless stats ap mac {dot_mac} discovery detailed",
                f"show wireless stats ap mac {dot_mac} join detailed",
                f"show logging profile wireless start last 15 min filter mac {dot_mac} "
                f"to-file harddisk:AP_DISCONNECT_ALWAYS_ON_LOG_{event_ts_safe}.log",
                "show logging",
            ]
            if ap_name:
                _show_cmds += [
                    f"show ap name {ap_name} config general",
                    f"show ap name {ap_name} uptime",
                ]
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

            # ── PHASE 6: parallel WLC AP telemetry + direct AP SSH ────
            wlc_ap_evidence:    dict[str, str] = {}
            direct_ap_evidence: dict[str, str] = {}

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
                    self._finalize_rca_session(None, _mac, _ip)
                else:
                    print(
                        f"[{ts()}] [TIMEOUT] Session for {_mac} already finalized — "
                        f"timeout worker exiting cleanly.",
                        file=sys.stderr,
                    )
            threading.Thread(target=_timeout_finalize_worker, daemon=True).start()
        
        

    # ------------------------------------------------------------------ #
    # Report                                                              #
    # ------------------------------------------------------------------ #

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
        "tftp_ip":     (device_data or {}).get("tftp_ip", ""),}


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
    sys.stderr   = _TeeStream(_orig_stderr, _log_file)
    # ─────────────────────────────────────────────────────────────────────

    print(f"[{ts()}] Minion AP Disjoin Monitor starting — WLC={host}", file=sys.stderr)

    # ── Trigger mode selection ────────────────────────────────────────────
    global TRIGGER_MODE
    TRIGGER_MODE = "snmp" if getattr(args, "snmp", False) else "telemetry"
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
    global _rca_executor
    _rca_executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_RCA)
    monitor._push_eem_applet()
    monitor.listen(getattr(args, "duration_minutes", None))
    _rca_executor.shutdown(wait=True)

    json_path, txt_path = monitor.save_report()

    # ── Restore stderr and close log ─────────────────────────────────────
    sys.stderr = _orig_stderr
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
        "unique_aps_traced": len(monitor.ap_reports),
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
    MonitorEngine().start(config)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Minion — Live AP Disjoin Monitor for Cisco 9800 WLC"
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
