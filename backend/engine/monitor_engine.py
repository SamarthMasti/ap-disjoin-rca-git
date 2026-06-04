from __future__ import annotations

import importlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.adapters import BackendEventBridge
from backend.config import MonitorRuntimeConfig, RuntimePaths


@dataclass(slots=True)
class MonitorResult:
    ok: bool
    wlc_host: str
    trigger_mode: str
    grpc_port: int | None
    total_disjoin_events: int
    unique_aps_traced: int
    high_confidence_findings: int
    report_json: str
    report_summary: str
    session_log: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "wlc_host": self.wlc_host,
            "trigger_mode": self.trigger_mode,
            "grpc_port": self.grpc_port,
            "total_disjoin_events": self.total_disjoin_events,
            "unique_aps_traced": self.unique_aps_traced,
            "high_confidence_findings": self.high_confidence_findings,
            "report_json": self.report_json,
            "report_summary": self.report_summary,
        }


class MonitorEngine:
    """Frontend-neutral engine facade that preserves the existing monitor workflow."""

    def start(self, config: MonitorRuntimeConfig) -> MonitorResult:
        legacy = self._load_legacy_backend()
        self._apply_runtime_config(legacy, config)
        event_bridge = BackendEventBridge(config.event_sink)
        event_bridge.emit("engine_started", host=config.host, trigger_mode=config.trigger_mode)

        auth = config.auth_dict()
        host = auth["host"]
        report_dir = Path(config.report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)

        legacy.log = legacy.setup_logging(report_dir)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", host)
        log_path = report_dir / f"session_log_{safe_host}_{stamp}.txt"
        log_file = log_path.open("w", encoding="utf-8", buffering=1)
        orig_stderr = sys.stderr
        sys.stderr = legacy._TeeStream(orig_stderr, log_file)

        monitor = None
        try:
            print(f"[{legacy.ts()}] Minion AP Disjoin Monitor starting — WLC={host}", file=sys.stderr)
            print(f"[{legacy.ts()}] Trigger mode: {legacy.TRIGGER_MODE.upper()}", file=sys.stderr)
            self._clear_stale_workflow_state(legacy)

            monitor = legacy.LiveMonitor(
                auth=auth,
                wlc_host=host,
                device_name=config.device_name,
                grpc_port=config.grpc_port,
            )
            legacy._rca_executor = legacy.ThreadPoolExecutor(max_workers=legacy.MAX_CONCURRENT_RCA)
            monitor._push_eem_applet()
            monitor.listen(config.duration_minutes)
            legacy._rca_executor.shutdown(wait=True)

            json_path, txt_path = monitor.save_report()
            event_bridge.report_generated(report_json=str(json_path), report_summary=str(txt_path))
        finally:
            sys.stderr = orig_stderr
            log_file.close()

        print(f"[{legacy.ts()}] Session log saved → {log_path}", file=sys.stderr)
        high = sum(
            1 for r in monitor.ap_reports.values()
            if (r.get("correlation") or {}).get("confidence") == "high"
            or (r.get("ap_side_correlation") or {}).get("confidence") == "high"
        )
        result = MonitorResult(
            ok=True,
            wlc_host=host,
            trigger_mode=f"EEM_{'SNMP_trap' if legacy.TRIGGER_MODE == 'snmp' else 'MDT_gRPC_dialout'}",
            grpc_port=config.grpc_port if legacy.TRIGGER_MODE != "snmp" else None,
            total_disjoin_events=len(monitor.events),
            unique_aps_traced=len(monitor.ap_reports),
            high_confidence_findings=high,
            report_json=str(json_path),
            report_summary=str(txt_path),
            session_log=str(log_path),
        )
        print(json.dumps(result.as_dict(), indent=2))
        event_bridge.emit("engine_completed", result=result.as_dict())
        return result

    def _apply_runtime_config(self, legacy: Any, config: MonitorRuntimeConfig) -> None:
        paths = RuntimePaths.from_config(
            inventory_file=config.inventory_file,
            report_dir=config.report_dir,
            log_dir=config.log_dir,
            capture_dir=config.capture_dir,
            state_dir=config.state_dir,
        )
        state_files = paths.legacy_report_state_files()
        legacy.REPORTS_DIR = paths.report_dir
        legacy.DISJOIN_COUNTER_FILE = state_files["disjoin_counter"]
        legacy.SUMMARY_STATS_FILE = state_files["summary_stats"]
        legacy.AP_STATS_FILE = state_files["ap_stats"]
        legacy.MDT_DEBUG_DIR = state_files["mdt_debug_dir"]
        legacy.GDC_FILE = state_files["gdc"]
        legacy.CGDC_FILE = state_files["cgdc"]
        legacy.DISJOIN_OCCURRENCES_FILE = state_files["disjoin_occurrences"]
        legacy.DISJOIN_EVENT_HISTORY_FILE = state_files["disjoin_event_history"]
        legacy.AP_WORKFLOW_STATE_FILE = state_files["ap_workflow_state"]
        legacy.FINALIZED_APS_FILE = state_files["finalized_aps"]
        legacy.TRIGGER_MODE = "snmp" if config.snmp_enabled else "telemetry"
        legacy.SNMP_COMMUNITY = config.snmp_community or "public"

    def _load_legacy_backend(self) -> Any:
        main_module = sys.modules.get("__main__")
        if main_module is not None and hasattr(main_module, "LiveMonitor"):
            return main_module
        return importlib.import_module("ap_disjoin_monitor_tool")

    def _clear_stale_workflow_state(self, legacy: Any) -> None:
        if not legacy.AP_WORKFLOW_STATE_FILE.exists():
            return
        try:
            stale = json.loads(legacy.AP_WORKFLOW_STATE_FILE.read_text(encoding="utf-8"))
            for mac_key in stale:
                stale[mac_key]["workflow_active"] = False
            legacy.AP_WORKFLOW_STATE_FILE.write_text(
                json.dumps(stale, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            print(f"[{legacy.ts()}] Cleared stale workflow state from previous session.", file=sys.stderr)
        except Exception as exc:
            print(f"[{legacy.ts()}] WARNING: Could not clear stale workflow state: {exc}", file=sys.stderr)
