# backend/snmp/trap_receiver.py
"""
SNMP trap receiver for AP disjoin detection.

The receiver only detects, parses, validates, and forwards disjoin events.
It does not own event counting, RCA launch, recurrence, cooldown, or workflow
state.
"""
from __future__ import annotations

import re
import socketserver
import sys
import threading
from typing import Callable


APNAME_RE = re.compile(r"AP Name: ([^ ]+)", re.IGNORECASE)
APMAC_RE = re.compile(
    r"Mac: ([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})",
    re.IGNORECASE,
)
APIP_RE = re.compile(r"Session-IP: (\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
REASON_RE = re.compile(r"Disjoined (.*)", re.IGNORECASE)


def _extract_octet_strings(data: bytes) -> list[str]:
    strings: list[str] = []
    i = 0
    while i < len(data):
        if data[i] == 0x04 and i + 1 < len(data):
            length = data[i + 1]
            val = data[i + 2: i + 2 + length]
            if len(val) == length:
                text = val.decode("utf-8", errors="ignore").strip()
                if text:
                    strings.append(text)
            i += 2 + length
            continue
        i += 1
    return strings


def _trap_text(data: bytes) -> str:
    strings = _extract_octet_strings(data)
    if strings:
        return " ".join(strings)
    return data.decode("latin-1", errors="replace")


class SNMPTrapReceiver:
    def __init__(
        self,
        *,
        host: str = "0.0.0.0",
        port: int = 162,
        ts: Callable[[], str],
        normalise_mac: Callable[[str], str],
        process_disjoin_event: Callable[[str, str | None, str | None, str, str], None],
        on_eem_trigger: Callable[[str, str], None] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.ts = ts
        self.normalise_mac = normalise_mac
        self.process_disjoin_event = process_disjoin_event
        self.on_eem_trigger = on_eem_trigger
        self._server: socketserver.UDPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        receiver = self

        class _SnmpTrapHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                receiver._handle_packet(self.request[0], self.client_address[0])

        self._server = socketserver.UDPServer((self.host, self.port), _SnmpTrapHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        print(
            f"[{self.ts()}] SNMP trap listener started on UDP {self.port} (mode=snmp)",
            file=sys.stderr,
        )

    def shutdown(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def _handle_packet(self, data: bytes, sender: str) -> None:
        now = self.ts()
        combined_text = _trap_text(data)

        if (
            "EEM_BATCH_TRIGGER" not in combined_text
            and ("Disjoined" not in combined_text or "AP_JOIN_DISJOIN" not in combined_text)
        ):
            return

        print(
            f"[{now}] [SNMP_TRAP] Disjoin trap from {sender}: {combined_text[:120]}",
            file=sys.stderr,
        )

        if "EEM_BATCH_TRIGGER" in combined_text:
            if self.on_eem_trigger:
                print(
                    f"[{now}] [SNMP_TRAP] EEM batch trigger received via SNMP trap",
                    file=sys.stderr,
                )
                threading.Thread(
                    target=self.on_eem_trigger,
                    args=(combined_text, now),
                    daemon=True,
                ).start()
            return

        m_name = APNAME_RE.search(combined_text)
        m_mac = APMAC_RE.search(combined_text)
        m_ip = APIP_RE.search(combined_text)
        m_reason = REASON_RE.search(combined_text)

        ap_name = m_name.group(1) if m_name else None
        mac = self.normalise_mac(m_mac.group(1)) if m_mac else None
        ip = m_ip.group(1) if m_ip else None
        reason = m_reason.group(1).strip() if m_reason else "unknown"

        if not mac:
            print(f"[{now}] [SNMP_TRAP] Could not extract MAC - ignoring trap.", file=sys.stderr)
            return

        print(
            f"[{now}] [SNMP_TRAP] AP={ap_name or '?'} MAC={mac} IP={ip or '?'} reason={reason}",
            file=sys.stderr,
        )
        threading.Thread(
            target=self.process_disjoin_event,
            args=(mac, ap_name, ip, now, "snmp"),
            daemon=True,
        ).start()


def make_snmp_trap_handler(
    ts: Callable[[], str],
    on_eem_trigger: Callable[[str, str], None],
) -> type:
    """
    Compatibility helper for older callers that expect a request handler class.
    """

    class _SnmpTrapHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = self.request[0]
            text = _trap_text(data)
            print(
                f"[{ts()}] [SNMP] Raw trap received ({len(data)} bytes)",
                file=sys.stderr,
            )
            if "AP_JOIN_DISJOIN" in text and "Disjoined" in text:
                on_eem_trigger(text, ts())

    return _SnmpTrapHandler
