# backend/rca/ap_ssh.py
"""
Direct AP SSH evidence collection — extracted verbatim from ap_disjoin_monitor_tool.py.
Zero behavior changes. ts() and TRACE_SETTLE_DELAY defined locally.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from typing import Any

try:
    from netmiko import ConnectHandler
except ImportError:
    ConnectHandler = None  # type: ignore


# ── Local timestamp helper (mirrors ts() in ap_disjoin_monitor_tool.py) ──
def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


TRACE_SETTLE_DELAY = 5   # seconds — matches ap_disjoin_monitor_tool.py

# ── Advanced CAPWAP/DTLS command catalog (verbatim from ap_disjoin_monitor_tool.py) ──
AP_ADVANCED_CAPWAP_CATALOG: list[dict] = [
    {"key": "terminal-len",        "cmd": "terminal length 0",      "is_debug": True},
    {"key": "show-logging",        "cmd": "show logging",           "is_debug": False},
    # ── CAPWAP client state ──────────────────────────────────────────────
    {"key": "capwap-client-conf",  "cmd": "show capwap client conf",  "is_debug": False},
    {"key": "capwap-client-rcb",   "cmd": "show capwap client rcb",   "is_debug": False},
    # ── PnP / provisioning ──────────────────────────────────────────────
    {"key": "pnpinfo",             "cmd": "show pnpinfo",             "is_debug": False},
    {"key": "pnp-log",             "cmd": "show pnp log",             "is_debug": False},
    # ── IPv6 DHCP ───────────────────────────────────────────────────────
    {"key": "ipv6-dhcp",           "cmd": "show ipv6 dhcp",           "is_debug": False},
    # ── DTLS state ──────────────────────────────────────────────────────
    {"key": "dtls-connections",    "cmd": "show dtls connections",    "is_debug": False},
    {"key": "dtls-statistics",     "cmd": "show dtls statistics",     "is_debug": False},
    # ── CAPWAP debug toggles (ack-only output) ───────────────────────────
    {"key": "dbg-capwap-event",    "cmd": "debug capwap client event",   "is_debug": True},
    {"key": "dbg-capwap-info",     "cmd": "debug capwap client info",    "is_debug": True},
    {"key": "dbg-capwap-payload",  "cmd": "debug capwap client payload", "is_debug": True},
    {"key": "dbg-capwap-detail",   "cmd": "debug capwap client detail",  "is_debug": True},
    {"key": "dbg-capwap-pmtu",     "cmd": "debug capwap client pmtu",    "is_debug": True},
    {"key": "dbg-capwap-events",   "cmd": "debug capwap client events",  "is_debug": True},
    # ── DTLS debug toggles ───────────────────────────────────────────────
    {"key": "dbg-dtls-events",     "cmd": "debug dtls client events",        "is_debug": True},
    {"key": "dbg-dtls-events-det", "cmd": "debug dtls client events detail", "is_debug": True},
    # ── UDP 5246 traffic capture (non-blocking, one-shot) ────────────────
    {"key": "dbg-traffic-host",    "cmd": "debug traffic host filter UDP dst_port 5246 capture",  "is_debug": True},
    {"key": "dbg-traffic-wired",   "cmd": "debug traffic wired filter UDP dst_port 5246 capture", "is_debug": True},
    # ── Additional AP-side commands ──────────────────────────────────────
    {"key": "show-ip-int-br",      "cmd": "show ip int br",               "is_debug": False},
    {"key": "dbg-capwap-error",    "cmd": "debug capwap client error",    "is_debug": True},
    {"key": "dbg-dtls-error",      "cmd": "debug dtls client error",      "is_debug": True},
    {"key": "dbg-dtls-event",      "cmd": "debug dtls client event",      "is_debug": True},
    # ── Enable Terminal Monitor on AP ────────────────────────────────────
    {"key": "terminal-monitor",    "cmd": "terminal monitor",             "is_debug": True},
    # ── Final logging snapshot ───────────────────────────────────────────
    {"key": "show-logging-final",  "cmd": "show logging",                "is_debug": False},
]


def collect_advanced_capwap_on_ap(ap_ip: str, ap_auth: dict, ap_name: str | None) -> dict[str, str]:
    """
    SSH directly to the AP and collect advanced CAPWAP/DTLS diagnostics.
    Uses AP credentials from inventory (ap_username / ap_password / ap_secret).
    All failures are swallowed — never interrupts the main RCA pipeline.
    """
    advanced: dict[str, str] = {}

    print(f"[{_ts()}]   [AP] Connecting directly to AP at {ap_ip} ...", file=sys.stdout)
    time.sleep(TRACE_SETTLE_DELAY)

    if ConnectHandler is None:
        print(f"[{_ts()}]   [AP] netmiko not available — skipping AP-direct collection", file=sys.stderr)
        return advanced

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
        print(f"[{_ts()}]   [AP] AP SSH failed: {exc} — skipping AP-direct collection", file=sys.stderr)
        return advanced

    try:
        for entry in AP_ADVANCED_CAPWAP_CATALOG:
            cmd      = entry["cmd"]
            is_debug = entry["is_debug"]

            print(f"[{_ts()}]   [AP] {'(debug) ' if is_debug else ''}{cmd}", file=sys.stderr)
            try:
                if is_debug:
                    output = ap_conn.send_command_timing(cmd, delay_factor=1, read_timeout=10)
                else:
                    output = ap_conn.send_command(cmd, read_timeout=10)

                if not output or output.strip().startswith("%") or "Invalid input" in output:
                    print(f"[{_ts()}]   [AP] Skipped (unsupported/error): {cmd}", file=sys.stderr)
                    continue

                advanced[cmd] = output

            except Exception as exc:
                print(f"[{_ts()}]   [AP] Error on '{cmd}': {exc}", file=sys.stderr)

        # ── show debug — snapshot active AP debugs ────────────────────
        _ap_sd = "show debug"
        print(f"[{_ts()}]   [AP] {_ap_sd}", file=sys.stderr)
        try:
            sd_out = ap_conn.send_command(_ap_sd, read_timeout=15)
            if sd_out and not sd_out.strip().startswith("%") and "Invalid input" not in sd_out:
                advanced[_ap_sd] = sd_out
        except Exception as exc:
            print(f"[{_ts()}]   [AP] Error on '{_ap_sd}': {exc}", file=sys.stderr)

        print(f"[{_ts()}]   [AP] done — {len(advanced)} commands returned output.", file=sys.stderr)

    finally:
        ap_conn.disconnect()
        print(f"[{_ts()}]   [AP] AP SSH session closed.", file=sys.stderr)

    return advanced
