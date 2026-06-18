# backend/rca/wlc_ssh.py
"""
WLC SSH evidence collection — extracted verbatim from ap_disjoin_monitor_tool.py.
Zero behavior changes. ts() defined locally to avoid circular import.
"""
from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from typing import Any


# ── Local timestamp helper (mirrors ts() in ap_disjoin_monitor_tool.py) ──
def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── AP-SIDE validated command catalog (verbatim from ap_disjoin_monitor_tool.py) ──
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


def resolve_ap_name_from_mac(conn: Any, mac: str) -> str | None:
    """
    Look up the real AP name from 'show ap summary' using the MAC address.
    Handles both colon (cc:7f:75:5a:e7:40) and dot (cc7f.755a.e740) notation.
    """
    digits    = re.sub(r"[^0-9a-fA-F]", "", mac)
    dot_mac   = f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}".lower()
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
                f"[{_ts()}]   [WLC AP TELEMETRY] SKIP (no AP name): {entry['cmd_template']}",
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

        print(f"[{_ts()}]   [WLC AP TELEMETRY] {cmd}", file=sys.stderr)
        try:
            output = conn.send_command(cmd, read_timeout=60)

            # guard: discard IOS-XE error responses — don't pollute evidence
            if not output or output.strip().startswith("%") or "Invalid input" in output:
                print(
                    f"[{_ts()}]   [WLC AP TELEMETRY] Skipped (unsupported/error): {cmd}",
                    file=sys.stderr,
                )
                continue

            ap_evidence[cmd] = output

        except Exception as exc:
            print(
                f"[{_ts()}]   [WLC AP TELEMETRY] Error executing '{cmd}': {exc}",
                file=sys.stderr,
            )

    return ap_evidence
