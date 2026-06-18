# backend/telemetry/mdt_receiver.py
"""
MDT gRPC dial-out receiver — extracted from LiveMonitor.listen().
Preserves exact decode and dispatch semantics.
No behavior changes.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Callable, Any


def decode_and_dispatch(
    raw: bytes,
    ts: Callable[[], str],
    live_buffer: Any,
    on_eem_trigger: Callable[[str, str], None],
    raw_stream: list,
    mdt_debug: bool,
    mdt_debug_dir: Path,
) -> None:
    """
    Decode a raw MDT protobuf message and dispatch to on_eem_trigger if it
    matches AP_JOIN_DISJOIN/Disjoined. Preserves exact original semantics.
    """
    import json
    try:
        import telemetry_pb2
    except ImportError:
        print(f"[{ts()}] [MDT] telemetry_pb2 not available", file=sys.stderr)
        return

    try:
        envelope = telemetry_pb2.Telemetry()
        envelope.ParseFromString(raw)
    except Exception as exc:
        print(f"[{ts()}] [MDT] Protobuf decode failed: {exc}", file=sys.stderr)
        return

    from ap_disjoin_monitor_tool import _parse_gpbkv  # preserve exact parsing

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

        if mdt_debug:
            mdt_debug_dir.mkdir(parents=True, exist_ok=True)
            payload_record = {
                "timestamp": ts(),
                "node_id": node_id,
                "encoding_path": path,
                "decoded_fields": {k: str(v) for k, v in fields.items()},
            }
            debug_file = mdt_debug_dir / f"mdt_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.json"
            debug_file.write_text(json.dumps(payload_record, indent=2), encoding="utf-8")
            print(f"[{ts()}] [MDT_DEBUG] Saved raw payload → {debug_file}", file=sys.stderr)

        live_buffer.append(f"{ts()} [MDT] {node_id} {path} {event_text}")

        if "AP_JOIN_DISJOIN" in event_text or "Disjoined" in event_text:
            on_eem_trigger(event_text, ts())