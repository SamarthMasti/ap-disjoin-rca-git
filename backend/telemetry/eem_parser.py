# backend/telemetry/eem_parser.py
from __future__ import annotations

import re
from typing import Any

APNAME_RE = re.compile(r"AP Name: ([^ ]+)", re.IGNORECASE)
APMAC_RE  = re.compile(r"Mac: ([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", re.IGNORECASE)
APIP_RE   = re.compile(r"Session-IP: (\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
REASON_RE = re.compile(r"Disjoined (.*)", re.IGNORECASE)


def parse_eem_trigger_payload(trigger_line: str) -> dict[str, Any]:
    """
    Parse a structured EEM/MDT trigger line and return extracted fields.
    Preserves exact field extraction semantics from LiveMonitor._on_eem_trigger.
    Returns: {ap_name, mac, ip, reason} — any field may be None if absent.
    """
    from ap_disjoin_monitor_tool import normalise_mac  # avoid circular import at module level

    m_name   = APNAME_RE.search(trigger_line)
    m_mac    = APMAC_RE.search(trigger_line)
    m_ip     = APIP_RE.search(trigger_line)
    m_reason = REASON_RE.search(trigger_line)

    mac = normalise_mac(m_mac.group(1)) if m_mac else None

    return {
        "ap_name": m_name.group(1) if m_name else None,
        "mac":     mac,
        "ip":      m_ip.group(1)   if m_ip   else None,
        "reason":  m_reason.group(1) if m_reason else "unknown",
    }