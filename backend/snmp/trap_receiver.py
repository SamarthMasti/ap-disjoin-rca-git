# backend/snmp/trap_receiver.py
"""
SNMP trap receiver — extracted from LiveMonitor.listen() SNMP branch.
Preserves exact trap detection and dispatch semantics.
"""
from __future__ import annotations

import socketserver
import sys
from typing import Callable


def make_snmp_trap_handler(
    ts: Callable[[], str],
    on_eem_trigger: Callable[[str, str], None],
) -> type:
    """
    Returns a socketserver.BaseRequestHandler subclass that handles SNMP traps.
    Preserves exact original detection: AP_JOIN_DISJOIN + Disjoined in payload.
    """

    class _SnmpTrapHandler(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request[0]
            try:
                text = data.decode("latin-1", errors="replace")
            except Exception:
                text = repr(data)
            print(
                f"[{ts()}] [SNMP] Raw trap received ({len(data)} bytes)",
                file=sys.stderr,
            )
            if "AP_JOIN_DISJOIN" in text and "Disjoined" in text:
                on_eem_trigger(text, ts())

    return _SnmpTrapHandler