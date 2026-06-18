# backend/engine/finalizer.py
"""
Finalizer sequence — extracted from LiveMonitor._finalize_rca_session.
All logic verbatim. Dependencies passed as parameters; no global state imported.
Zero behavior changes. Thread safety is the caller's responsibility (unchanged).
"""
from __future__ import annotations

import re
import sys
import time
import threading
from typing import Any, Callable

MYCAP_NAME = "MYCAP"
SUCCESS_RE = re.compile(
    r"\d+\s+bytes\s+copied\s+in\s+\d+(\.\d+)?\s+secs",
    re.I,
)


def run_finalization(
    *,
    wlc_host: str,
    auth: dict,
    ap_auth: dict,
    mac: str,
    ip: str | None,
    mycap_name: str,
    active_rca_sessions: dict,
    active_rca_lock: threading.Lock,
    ts: Callable[[], str],
    clear_ap_workflow: Callable[[str], None],
    mark_ap_used: Callable[[str], None],
    reset_disjoin_counter: Callable[[str], None],
    append_finalized_ap: Callable[..., None],
    save_report: Callable[[], tuple],
    skip_hardcoded: bool = False,
) -> None:
    from netmiko import ConnectHandler

    print(
        f"[{ts()}] [FINALIZE] Second disjoin of same AP ({mac}) — starting finalization sequence.",
        file=sys.stderr,
    )

    if not skip_hardcoded:
        # ── 1+2+3+4+5: WLC cleanup via fresh SSH ─────────────────────────────
        wlc_conn = None
        try:
            print(f"[{ts()}] [FINALIZE] Opening WLC SSH for cleanup ...", file=sys.stderr)
            wlc_conn = ConnectHandler(
                device_type="cisco_ios",
                host=wlc_host,
                port=auth["port"],
                username=auth["username"],
                password=auth["password"],
                secret=auth.get("secret"),
                fast_cli=False,
            )
            if auth.get("secret"):
                wlc_conn.enable()

            print(f"[{ts()}] [FINALIZE] [WLC] undebug all", file=sys.stderr)
            try:
                wlc_conn.send_command_timing("undebug all", delay_factor=1, read_timeout=15)
            except Exception as exc:
                print(f"[{ts()}] [FINALIZE] WARNING: undebug all failed: {exc}", file=sys.stderr)

            stop_cmd = f"monitor capture {mycap_name} stop"
            print(f"[{ts()}] [FINALIZE] [MYCAP] {stop_cmd}", file=sys.stderr)
            try:
                stop_out = wlc_conn.send_command_timing(stop_cmd, delay_factor=1, read_timeout=30)
                if stop_out:
                    print(f"[{ts()}] [FINALIZE] [MYCAP] {stop_out.strip()}", file=sys.stderr)
                if "not active" in (stop_out or "").lower():
                    print(
                        f"[{ts()}] [FINALIZE] [MYCAP] Capture was already stopped — continuing.",
                        file=sys.stderr,
                    )
                time.sleep(3)
            except Exception as exc:
                print(f"[{ts()}] [FINALIZE] WARNING: '{stop_cmd}' failed: {exc}", file=sys.stderr)

            pcap_filename = f"ApDisjoinEpc_{mycap_name}.pcap"
            export_cmd = f"monitor capture {mycap_name} export bootflash:{pcap_filename}"
            print(f"[{ts()}] [FINALIZE] [MYCAP] {export_cmd}", file=sys.stderr)
            try:
                export_out = wlc_conn.send_command_timing(export_cmd, delay_factor=1, read_timeout=30)
                print(
                    f"[{ts()}] [FINALIZE] [MYCAP] initial response: {export_out.strip()!r}",
                    file=sys.stderr,
                )

                OVERWRITE_PATTERNS = (
                    "overwrite?[confirm]",
                    "overwrite existing",
                    "[confirm]",
                    "confirm",
                )
                if any(p in export_out.lower() for p in OVERWRITE_PATTERNS):
                    print(
                        f"[{ts()}] [FINALIZE] [MYCAP] Overwrite prompt detected — sending ENTER to confirm.",
                        file=sys.stderr,
                    )
                    confirm_out = wlc_conn.send_command_timing("\n", delay_factor=1, read_timeout=60)
                    if confirm_out:
                        print(
                            f"[{ts()}] [FINALIZE] [MYCAP] post-confirm output: {confirm_out.strip()!r}",
                            file=sys.stderr,
                        )
                    time.sleep(2)
                    wlc_conn.clear_buffer()
                else:
                    time.sleep(2)
                    wlc_conn.clear_buffer()
            except Exception as exc:
                print(f"[{ts()}] [FINALIZE] WARNING: export command failed: {exc}", file=sys.stderr)

            verify_cmd = "show flash: | inc .pcap"
            print(f"[{ts()}] [FINALIZE] [MYCAP] {verify_cmd}", file=sys.stderr)
            try:
                verify_out = wlc_conn.send_command(verify_cmd, read_timeout=30)
                if verify_out:
                    print(f"[{ts()}] [FINALIZE] [MYCAP] {verify_out.strip()}", file=sys.stderr)
                    if pcap_filename.lower() in verify_out.lower():
                        print(f"[{ts()}] [FINALIZE] [MYCAP] ✓ {pcap_filename} confirmed on flash.", file=sys.stderr)
                    else:
                        print(
                            f"[{ts()}] [FINALIZE] [MYCAP] WARNING: {pcap_filename} not found in flash listing.",
                            file=sys.stderr,
                        )
            except Exception as exc:
                print(f"[{ts()}] [FINALIZE] WARNING: '{verify_cmd}' failed: {exc}", file=sys.stderr)

            tftp_ip = auth.get("tftp_ip", "")
            tftp_export = f"copy flash:/{pcap_filename} tftp://{tftp_ip}/{pcap_filename}"
            print(f"[{ts()}] [EPC_TFTP_Upload] {tftp_export}", file=sys.stderr)
            try:
                export_out = wlc_conn.send_command_timing(tftp_export, delay_factor=1, read_timeout=100)
                print(f"[{ts()}] [EPC_TFTP_Upload] First Enter response: {export_out.strip()!r}", file=sys.stderr)
                wlc_conn.send_command_timing("\n", delay_factor=1, read_timeout=10)
                confirm_out = wlc_conn.send_command_timing("\n", delay_factor=1, read_timeout=10)
                if SUCCESS_RE.search(confirm_out or ""):
                    print(f"[{ts()}] [EPC_TFTP_Upload] ✓ ApDisjoinEpc.pcap transferred successfully.", file=sys.stderr)
                else:
                    print(
                        f"[{ts()}] [EPC_TFTP_Upload] WARNING: transfer may have failed. Response: {confirm_out!r}",
                        file=sys.stderr,
                    )
            except Exception as exc:
                print(f"[{ts()}] [EPC_TFTP_Upload] WARNING: EPC export failed: {exc}", file=sys.stderr)

            digits  = re.sub(r"[^0-9a-fA-F]", "", mac)
            dot_mac = f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}".lower()
            always_on_export = f"copy flash:/ALWAYS_ON_{dot_mac}.log tftp://{tftp_ip}/ALWAYS_ON_{dot_mac}.log"
            print(f"[{ts()}] [EPC_TFTP_Upload] {always_on_export}", file=sys.stderr)
            try:
                export_out = wlc_conn.send_command_timing(always_on_export, delay_factor=1, read_timeout=100)
                print(f"[{ts()}] [EPC_TFTP_Upload] First Enter response: {export_out.strip()!r}", file=sys.stderr)
                wlc_conn.send_command_timing("\n", delay_factor=1, read_timeout=10)
                confirm_out = wlc_conn.send_command_timing("\n", delay_factor=1, read_timeout=10)
                if SUCCESS_RE.search(confirm_out or ""):
                    print(f"[{ts()}] [EPC_TFTP_Upload] ✓ ALWAYS_ON log transferred successfully.", file=sys.stderr)
                else:
                    print(
                        f"[{ts()}] [EPC_TFTP_Upload] WARNING: ALWAYS_ON log transfer may have failed. Response: {confirm_out!r}",
                        file=sys.stderr,
                    )
            except Exception as exc:
                print(f"[{ts()}] [EPC_TFTP_Upload] WARNING: always-on log export failed: {exc}", file=sys.stderr)

        except Exception as exc:
            print(f"[{ts()}] [FINALIZE] WARNING: WLC SSH for cleanup failed: {exc}", file=sys.stderr)
        finally:
            if wlc_conn:
                try:
                    wlc_conn.disconnect()
                    print(f"[{ts()}] [FINALIZE] WLC cleanup SSH session closed.", file=sys.stderr)
                except Exception:
                    pass

        # ── 6: undebug all on AP (direct SSH) ────────────────────────────────
        if ip:
            try:
                print(f"[{ts()}] [FINALIZE] [AP] Connecting to AP {ip} for undebug all ...", file=sys.stderr)
                ap_conn = ConnectHandler(
                    device_type="cisco_ios",
                    host=ip,
                    port=22,
                    username=ap_auth["username"],
                    password=ap_auth["password"],
                    secret=ap_auth.get("secret", ""),
                    fast_cli=False,
                )
                if ap_auth.get("secret"):
                    ap_conn.enable()
                ap_conn.send_command_timing("undebug all", delay_factor=1, read_timeout=15)
                print(f"[{ts()}] [FINALIZE] [AP] undebug all sent to AP {ip}", file=sys.stderr)
                ap_conn.disconnect()
            except Exception as exc:
                print(f"[{ts()}] [FINALIZE] WARNING: AP undebug all failed: {exc}", file=sys.stderr)
    else:
        print(
            f"[{ts()}] [FINALIZE] [CUSTOM-ONLY] Skipping hardcoded WLC/MYCAP/TFTP cleanup "
            f"sequence for {mac} — custom stop commands already sent by caller.",
            file=sys.stderr,
        )

    # ── 7: generate reports (always runs) ─────────────────────────────────
    print(f"[{ts()}] [FINALIZE] Generating reports ...", file=sys.stderr)
    try:
        json_path, txt_path = save_report()
        print(f"[{ts()}] [FINALIZE] JSON report   → {json_path}", file=sys.stderr)
        print(f"[{ts()}] [FINALIZE] Summary report → {txt_path}", file=sys.stderr)
    except Exception as exc:
        print(f"[{ts()}] [FINALIZE] WARNING: report generation failed: {exc}", file=sys.stderr)

    # ── 8: clear ACTIVE_RCA state (always runs) ────────────────────────────
    with active_rca_lock:
        active_rca_sessions.pop(mac, None)
    clear_ap_workflow(mac)
    mark_ap_used(mac)
    print(f"[{ts()}] [FINALIZE] Session complete for {mac}.", file=sys.stderr)
    reset_disjoin_counter(mac)
    print(f"[{ts()}] [FINALIZE] Disjoin counter reset for {mac}.", file=sys.stderr)
    print(f"[{ts()}] [FINALIZE] Finalization complete for {mac}.", file=sys.stderr)
    append_finalized_ap(
        mac=mac,
        ap_name=active_rca_sessions.get(mac, {}).get("ap_name"),
        ip=ip,
    )
