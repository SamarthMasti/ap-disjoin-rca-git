from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Callable


def load_ap_workflow_state(report_dir: Path, workflow_state_file: Path) -> dict:
    report_dir.mkdir(parents=True, exist_ok=True)
    if not workflow_state_file.exists():
        return {}
    try:
        data = json.loads(workflow_state_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_ap_workflow_state(
    data: dict,
    report_dir: Path,
    workflow_state_file: Path,
    warn: Callable[[str], None],
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    tmp = workflow_state_file.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(workflow_state_file)
    except Exception as exc:
        warn(f"WARNING: Could not save AP workflow state: {exc}")
        tmp.unlink(missing_ok=True)


def set_ap_workflow_active(
    mac: str,
    ap_name: str | None,
    ip: str | None,
    report_dir: Path,
    workflow_state_file: Path,
    lock: Lock,
    now: Callable[[], str],
    session_timeout: int,
    warn: Callable[[str], None],
) -> None:
    current_time = now()
    expiry = datetime.fromtimestamp(time.time() + session_timeout, tz=timezone.utc).isoformat()
    with lock:
        data = load_ap_workflow_state(report_dir, workflow_state_file)
        data[mac] = {
            "ap_mac": mac,
            "ap_name": ap_name,
            "ip": ip,
            "workflow_active": True,
            "workflow_start_time": current_time,
            "workflow_expiry_time": expiry,
            "disjoin_count": 1,
            "last_disjoin_time": current_time,
        }
        save_ap_workflow_state(data, report_dir, workflow_state_file, warn)


def increment_ap_workflow_disjoin(
    mac: str,
    report_dir: Path,
    workflow_state_file: Path,
    lock: Lock,
    now: Callable[[], str],
    warn: Callable[[str], None],
) -> int:
    with lock:
        data = load_ap_workflow_state(report_dir, workflow_state_file)
        entry = data.get(mac)
        if not entry or not entry.get("workflow_active"):
            return 0
        entry["disjoin_count"] = entry.get("disjoin_count", 0) + 1
        entry["last_disjoin_time"] = now()
        save_ap_workflow_state(data, report_dir, workflow_state_file, warn)
        return entry["disjoin_count"]


def clear_ap_workflow(
    mac: str,
    report_dir: Path,
    workflow_state_file: Path,
    lock: Lock,
    warn: Callable[[str], None],
) -> None:
    with lock:
        data = load_ap_workflow_state(report_dir, workflow_state_file)
        if mac in data:
            data[mac]["workflow_active"] = False
            save_ap_workflow_state(data, report_dir, workflow_state_file, warn)


def is_ap_workflow_active(
    mac: str,
    report_dir: Path,
    workflow_state_file: Path,
    lock: Lock,
) -> bool:
    with lock:
        data = load_ap_workflow_state(report_dir, workflow_state_file)
        entry = data.get(mac)
        return bool(entry and entry.get("workflow_active"))

