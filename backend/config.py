from __future__ import annotations

import argparse
import getpass
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = "inventory/iosxe_devices.yaml"
LEGACY_CONF_INVENTORY = "CONF/iosxe_devices.yaml"
LEGACY_CONF_LOWER_INVENTORY = "conf/iosxe_devices.yaml"
INVENTORY_PATH_CANDIDATES = (
    DEFAULT_INVENTORY,
    LEGACY_CONF_INVENTORY,
    LEGACY_CONF_LOWER_INVENTORY,
)
DEFAULT_REPORT_DIR = "reports"
DEFAULT_LOG_DIR = "logs"
DEFAULT_CAPTURE_DIR = "captures"
DEFAULT_STATE_DIR = "state"
DEFAULT_GRPC_PORT = 57500
DEFAULT_SSH_PORT = 22

BackendEventSink = Callable[[dict[str, Any]], None]


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    """Centralized project paths with legacy-compatible state locations."""

    inventory_file: Path
    report_dir: Path
    log_dir: Path
    capture_dir: Path
    state_dir: Path

    @classmethod
    def from_config(
        cls,
        inventory_file: str | None = None,
        report_dir: str | None = None,
        log_dir: str | None = None,
        capture_dir: str | None = None,
        state_dir: str | None = None,
    ) -> "RuntimePaths":
        resolved_report_dir = Path(report_dir or DEFAULT_REPORT_DIR)
        return cls(
            inventory_file=Path(resolve_inventory_path(inventory_file)),
            report_dir=resolved_report_dir,
            log_dir=Path(log_dir or resolved_report_dir),
            capture_dir=Path(capture_dir or DEFAULT_CAPTURE_DIR),
            state_dir=Path(state_dir or resolved_report_dir),
        )

    def legacy_report_state_files(self) -> dict[str, Path]:
        """Existing backend keeps state JSON under reports; preserve that layout."""
        return {
            "disjoin_counter": self.report_dir / "ap_disjoin_counters.json",
            "summary_stats": self.report_dir / "summary_stats.json",
            "ap_stats": self.report_dir / "ap_disjoin_stats.json",
            "mdt_debug_dir": self.report_dir / "raw_mdt_payloads",
            "gdc": self.report_dir / "gdc.json",
            "cgdc": self.report_dir / "cgdc.json",
            "disjoin_occurrences": self.report_dir / "disjoin_occurrences.json",
            "disjoin_event_history": self.report_dir / "disjoin_event_history.json",
            "ap_workflow_state": self.report_dir / "ap_workflow_state.json",
            "finalized_aps": self.report_dir / "finalized_aps_history.json",
        }


@dataclass(slots=True)
class MonitorRuntimeConfig:
    """Frontend-neutral runtime configuration for a monitor session."""

    host: str
    username: str
    password: str
    port: int = DEFAULT_SSH_PORT
    secret: str | None = None
    device_name: str | None = None
    inventory_file: str = DEFAULT_INVENTORY
    grpc_port: int = DEFAULT_GRPC_PORT
    trigger_mode: str = "telemetry"
    snmp_community: str = "public"
    duration_minutes: int | None = None
    report_dir: str = DEFAULT_REPORT_DIR
    log_dir: str | None = None
    capture_dir: str | None = None
    state_dir: str | None = None
    tftp_ip: str = ""
    jumphost_ip: str = ""
    ap_username: str = "Cisco"
    ap_password: str = "Cisco"
    ap_secret: str = ""
    epc_enabled: bool = True
    debug_commands_enabled: bool = False
    wlc_debug_cmd_file: str | None = "CONF/wlc_commands.conf"
    ap_debug_cmd_file: str | None = "CONF/ap_commands.conf"
    event_sink: BackendEventSink | None = field(default=None, repr=False, compare=False)

    @property
    def snmp_enabled(self) -> bool:
        return self.trigger_mode.lower() == "snmp"

    def auth_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "secret": self.secret,
            "ap_username": self.ap_username or "Cisco",
            "ap_password": self.ap_password or "Cisco",
            "ap_secret": self.ap_secret or "",
            "jumphost_ip": self.jumphost_ip or "",
            "tftp_ip": self.tftp_ip or "",
            "debug_commands_enabled": self.debug_commands_enabled,
            "wlc_debug_cmd_file": self.wlc_debug_cmd_file,
            "ap_debug_cmd_file": self.ap_debug_cmd_file,
            "wlc_evidence_cmd_file": getattr(self, "wlc_evidence_cmd_file", "CONF/wlc_commands.conf"),
        }


def resolve_inventory_path(path: str | None) -> str:
    """Resolve inventory dynamically across supported project layouts."""
    candidate = Path(path or DEFAULT_INVENTORY)
    if candidate.exists():
        return str(candidate)

    normalized = str(candidate).replace("\\", "/")
    if normalized in INVENTORY_PATH_CANDIDATES:
        for inventory_candidate in INVENTORY_PATH_CANDIDATES:
            resolved = Path(inventory_candidate)
            if resolved.exists():
                return str(resolved)
    return str(candidate)


def load_inventory(path: str) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return {d["name"]: d for d in data.get("iosxe_devices", []) if isinstance(d, dict) and "name" in d}


def config_from_args(args: argparse.Namespace) -> MonitorRuntimeConfig:
    inventory_file = resolve_inventory_path(getattr(args, "inventory_file", DEFAULT_INVENTORY))
    device_data: dict[str, Any] | None = None
    device_name = getattr(args, "device", None)
    if device_name:
        inv = load_inventory(inventory_file)
        device_data = inv.get(device_name)
        if not device_data:
            raise ValueError(f"Device '{device_name}' not in inventory")

    host = getattr(args, "host", None) or (device_data or {}).get("host")
    username = getattr(args, "username", None) or (device_data or {}).get("username")
    port = getattr(args, "port", None) or int((device_data or {}).get("port", DEFAULT_SSH_PORT))
    password = (
        getattr(args, "password", None)
        or os.getenv("IOSXE_PASSWORD")
        or (device_data or {}).get("password")
    )
    secret = (
        getattr(args, "secret", None)
        or os.getenv("IOSXE_SECRET")
        or (device_data or {}).get("enable_secret")
    )

    if not host or not username:
        raise ValueError("host and username required")
    if not password:
        password = getpass.getpass("Password: ")

    return MonitorRuntimeConfig(
        host=host,
        username=username,
        password=password,
        port=int(port),
        secret=secret,
        device_name=device_name,
        inventory_file=inventory_file,
        grpc_port=int(getattr(args, "grpc_port", DEFAULT_GRPC_PORT)),
        trigger_mode="snmp" if getattr(args, "snmp", False) else "telemetry",
        duration_minutes=getattr(args, "duration_minutes", None),
        report_dir=getattr(args, "report_dir", DEFAULT_REPORT_DIR),
        log_dir=getattr(args, "log_dir", None),
        capture_dir=getattr(args, "capture_dir", None),
        state_dir=getattr(args, "state_dir", None),
        tftp_ip=(device_data or {}).get("tftp_ip", ""),
        jumphost_ip=(device_data or {}).get("jumphost_ip", ""),
        ap_username=(device_data or {}).get("ap_username", "Cisco"),
        ap_password=(device_data or {}).get("ap_password", "Cisco"),
        ap_secret=(device_data or {}).get("ap_secret", ""),
    )


def config_from_gui_dict(config: dict[str, Any], event_sink: BackendEventSink | None = None) -> MonitorRuntimeConfig:
    duration = config.get("duration_minutes")
    return MonitorRuntimeConfig(
        host=str(config.get("host", "")).strip(),
        username=str(config.get("username", "")).strip(),
        password=str(config.get("password", "")),
        port=int(config.get("port") or DEFAULT_SSH_PORT),
        secret=config.get("enable_secret") or config.get("secret") or None,
        device_name=config.get("device_name") or None,
        inventory_file=resolve_inventory_path(config.get("inventory_file")),
        grpc_port=int(config.get("grpc_port") or DEFAULT_GRPC_PORT),
        trigger_mode=str(config.get("trigger_mode") or "telemetry").lower(),
        snmp_community=str(config.get("snmp_community") or "public"),
        duration_minutes=int(duration) if duration else None,
        report_dir=_resolve_run_dir(str(config.get("report_dir") or DEFAULT_REPORT_DIR)),
        log_dir=str(config["log_dir"]) if config.get("log_dir") else None,
        capture_dir=str(config["capture_dir"]) if config.get("capture_dir") else None,
        state_dir=str(config["state_dir"]) if config.get("state_dir") else None,
        tftp_ip=str(config.get("tftp_ip") or ""),
        jumphost_ip=str(config.get("jumphost_ip") or ""),
        ap_username=str(config.get("ap_username") or "Cisco"),
        ap_password=str(config.get("ap_password") or "Cisco"),
        ap_secret=str(config.get("ap_secret") or ""),
        debug_commands_enabled=bool(config.get("debug_commands_enabled", False)),
        wlc_debug_cmd_file=config.get("wlc_debug_cmd_file") or "CONF/wlc_commands.conf",
        ap_debug_cmd_file=config.get("ap_debug_cmd_file") or "CONF/ap_commands.conf",
        event_sink=event_sink,
    )
def _resolve_run_dir(base_report_dir: str) -> str:
    """
    Resolve the per-run subdirectory path:
        <base_report_dir>/YYYY/MM/DD/run_N
    N is auto-incremented — counts existing run_* folders under today's date.
    Creates the directory immediately so all writers find it ready.
    """
    from datetime import date
    today   = date.today()
    day_dir = (
        Path(base_report_dir)
        / str(today.year)
        / f"{today.month:02d}"
        / f"{today.day:02d}"
    )
    day_dir.mkdir(parents=True, exist_ok=True)

    existing = sorted(
        p for p in day_dir.iterdir()
        if p.is_dir() and p.name.startswith("run_")
    )
    next_n  = len(existing) + 1
    run_dir = day_dir / f"run_{next_n}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return str(run_dir)