from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Callable


def load_gdc(report_dir: Path, gdc_file: Path) -> int:
    report_dir.mkdir(parents=True, exist_ok=True)
    if not gdc_file.exists():
        return 0
    try:
        return int(json.loads(gdc_file.read_text(encoding="utf-8")).get("gdc", 0))
    except Exception:
        return 0


def save_gdc(value: int) -> None:
    # Preserve current behavior: GDC increments are not persisted by the legacy tool.
    pass


def increment_gdc(report_dir: Path, gdc_file: Path, lock: Lock) -> int:
    with lock:
        val = load_gdc(report_dir, gdc_file) + 1
        save_gdc(val)
    return val


def load_cgdc(report_dir: Path, cgdc_file: Path) -> dict:
    report_dir.mkdir(parents=True, exist_ok=True)
    if not cgdc_file.exists():
        return {"cgdc": 0, "batch": []}
    try:
        data = json.loads(cgdc_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"cgdc": 0, "batch": []}
        return data
    except Exception:
        return {"cgdc": 0, "batch": []}


def save_cgdc(
    data: dict,
    report_dir: Path,
    cgdc_file: Path,
    warn: Callable[[str], None],
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    tmp = cgdc_file.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(cgdc_file)
    except Exception as exc:
        warn(f"WARNING: Could not save CGDC: {exc}")
        tmp.unlink(missing_ok=True)

