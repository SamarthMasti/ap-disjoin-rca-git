# backend/rca/correlation.py
"""
Correlation helpers — extracted verbatim from ap_disjoin_monitor_tool.py.
Zero behavior changes. All regex patterns copied exactly as-is.
"""
from __future__ import annotations

import re
from typing import Any

# ── Correlation patterns (verbatim from ap_disjoin_monitor_tool.py) ──────
CRASH_RE    = re.compile(r"reboot.*crash|crash.*reboot",   re.IGNORECASE)
WATCHDOG_RE = re.compile(r"watchdog|kernel\s+panic",       re.IGNORECASE)
DTLS_RE     = re.compile(r"DTLS.*(?:alert|closed)",        re.IGNORECASE)
HB_RE       = re.compile(r"heart\s*beat|keepalive",        re.IGNORECASE)

# ── AP-SIDE correlation patterns (verbatim from ap_disjoin_monitor_tool.py)
AP_SHORT_UPTIME_RE  = re.compile(
    r"(\d+)\s*day[s]?,\s*(\d+)\s*hour[s]?,\s*(\d+)\s*minute",
    re.IGNORECASE,
)
AP_CRASH_FILE_RE    = re.compile(r"crash|watchdog|kernel.?panic|exception|core", re.IGNORECASE)
AP_CAPWAP_RESET_RE  = re.compile(r"retransmit|timeout|reset|tunnel.*down|dtls.*fail|handshake", re.IGNORECASE)
AP_UPLINK_RE        = re.compile(r"ethernet.*down|link.*down|port.*down|uplink.*fail|carrier.*lost", re.IGNORECASE)
AP_POE_RE           = re.compile(r"poe|power.?over.?ethernet|insufficient.*power|power.*denied|brownout", re.IGNORECASE)
AP_REBOOT_REASON_RE = re.compile(r"reboot.*reason|reload.*reason|last.*reset|power.?cycle|cold.?reset", re.IGNORECASE)


def correlate(evidence: str) -> dict[str, str]:
    if CRASH_RE.search(evidence) and HB_RE.search(evidence):
        return {
            "probable_cause": "AP crashed → stopped sending CAPWAP heartbeats → WLC disjoined it",
            "confidence": "high",
            "action": "Collect AP crashinfo; open TAC if recurring",
        }
    if WATCHDOG_RE.search(evidence):
        return {
            "probable_cause": "AP watchdog / kernel panic triggered reboot → disjoin",
            "confidence": "high",
            "action": "Check AP hardware health and firmware version",
        }
    if DTLS_RE.search(evidence):
        return {
            "probable_cause": "CAPWAP DTLS tunnel failed — possible MTU, cert, or path issue",
            "confidence": "medium",
            "action": "Check MTU >= 1485 on AP path; verify AP certificate",
        }
    if HB_RE.search(evidence):
        return {
            "probable_cause": "Heartbeat expiry without crash — likely network path interruption",
            "confidence": "medium",
            "action": "Check uplink/STP events around disjoin timestamp",
        }
    return {
        "probable_cause": "Insufficient evidence — manual trace bundle recommended",
        "confidence": "inconclusive",
        "action": "Run: request wireless trace bundle on WLC",
    }


def correlate_ap_side(ap_evidence: dict[str, str], ap_name: str | None) -> dict[str, Any]:
    """
    Infer probable AP-side root cause from WLC-reported AP telemetry.
    Returns a structured finding dict — same style as correlate().
    """
    observations: list[str] = []
    confidence   = "inconclusive"
    probable_cause = "No AP-side indicators found in collected telemetry"
    action         = "Manually review AP eventlog and crash-file on WLC"

    # ── 1. Crash file evidence ────────────────────────────────────────────
    crash_output = ap_evidence.get(
        next((k for k in ap_evidence if "crash-file" in k), ""), ""
    )
    has_crash_file = bool(AP_CRASH_FILE_RE.search(crash_output)) and \
                     "no crash" not in crash_output.lower() and \
                     len(crash_output.strip()) > 10

    # ── 2. Short uptime — AP rebooted recently ───────────────────────────
    uptime_output = ap_evidence.get(
        next((k for k in ap_evidence if "uptime" in k), ""), ""
    )
    recently_rebooted = False
    uptime_match = AP_SHORT_UPTIME_RE.search(uptime_output)
    if uptime_match:
        days    = int(uptime_match.group(1))
        hours   = int(uptime_match.group(2))
        minutes = int(uptime_match.group(3))
        total_minutes = days * 1440 + hours * 60 + minutes
        recently_rebooted = total_minutes < 30   # rebooted within last 30 min
        if recently_rebooted:
            observations.append(
                f"AP uptime is only {days}d {hours}h {minutes}m — "
                "consistent with a recent reboot at time of disjoin"
            )

    # ── 3. CAPWAP tunnel instability ─────────────────────────────────────
    capwap_output = ap_evidence.get(
        next((k for k in ap_evidence if "capwap" in k), ""), ""
    )
    has_capwap_instability = bool(AP_CAPWAP_RESET_RE.search(capwap_output))
    if has_capwap_instability:
        observations.append("CAPWAP tunnel shows retransmission/reset/timeout indicators")

    # ── 4. Eventlog — uplink, PoE, reboot reason ─────────────────────────
    eventlog_output = ap_evidence.get(
        next((k for k in ap_evidence if "eventlog" in k), ""), ""
    )
    has_uplink_down   = bool(AP_UPLINK_RE.search(eventlog_output))
    has_poe_issue     = bool(AP_POE_RE.search(eventlog_output))
    has_reboot_reason = bool(AP_REBOOT_REASON_RE.search(eventlog_output))

    if has_uplink_down:
        observations.append("Ethernet/uplink down event detected in AP eventlog")
    if has_poe_issue:
        observations.append("PoE / power instability event detected in AP eventlog")
    if has_reboot_reason:
        observations.append("Explicit reboot reason entry found in AP eventlog")

    # ── Decision tree ─────────────────────────────────────────────────────
    if has_crash_file and recently_rebooted:
        probable_cause = (
            "AP crash file present AND short uptime detected — "
            "watchdog crash or software exception likely caused AP reboot → disjoin"
        )
        confidence = "high"
        action     = (
            f"Run: show ap name {ap_name} crash-file detail on WLC. "
            "Collect crashinfo and open TAC case."
        )

    elif has_crash_file and not recently_rebooted:
        probable_cause = (
            "Crash file exists but AP uptime suggests it predates this disjoin event. "
            "May be a prior unrelated crash."
        )
        confidence = "medium"
        action     = (
            "Check crash-file timestamp vs disjoin timestamp. "
            "If timestamps align, open TAC case."
        )

    elif recently_rebooted and has_reboot_reason:
        probable_cause = (
            "AP rebooted shortly before disjoin. "
            "Reboot reason entry found in eventlog — not a software crash."
        )
        confidence = "high"
        action     = "Review eventlog reboot reason. Check for planned reload or PoE reset."

    elif has_poe_issue and recently_rebooted:
        probable_cause = (
            "AP rebooted AND PoE/power instability detected in eventlog. "
            "Power interruption likely caused AP to reboot → stop CAPWAP heartbeats → disjoin."
        )
        confidence = "high"
        action     = "Check PoE budget on switch port. Verify switch PoE logs."

    elif has_uplink_down:
        probable_cause = (
            "Ethernet/uplink down event detected. "
            "AP lost network connectivity, preventing CAPWAP heartbeats from reaching WLC."
        )
        confidence = "medium"
        action     = "Check switch port connected to AP. Review STP and uplink events."

    elif has_capwap_instability and not recently_rebooted:
        probable_cause = (
            "CAPWAP tunnel instability detected without AP reboot. "
            "Possible network path degradation or DTLS negotiation issue."
        )
        confidence = "medium"
        action     = "Check MTU on AP network path. Review DTLS cert validity."

    elif recently_rebooted:
        probable_cause = (
            "AP rebooted recently (short uptime) but no crash file or specific "
            "event found. Cause undetermined from available telemetry."
        )
        confidence = "low"
        action     = "Manually review AP eventlog for reload trigger."

    return {
        "observations"  : observations,
        "probable_cause": probable_cause,
        "confidence"    : confidence,
        "action"        : action,
        "raw_indicators": {
            "crash_file_present"    : has_crash_file,
            "recently_rebooted"     : recently_rebooted,
            "capwap_instability"    : has_capwap_instability,
            "uplink_down"           : has_uplink_down,
            "poe_issue"             : has_poe_issue,
            "explicit_reboot_reason": has_reboot_reason,
        },
    }


class CorrelationEngine:
    """
    Pluggable correlation framework.
    Current implementation: rule-based only.
    Future slots: anomaly_detector, ml_scorer, root_cause_ranker.
    """

    def __init__(self):
        self._rules   = [self._rule_based]
        self._scorers = []          # ML scorers — plug in here later
        self._rankers = []          # root cause rankers — plug in here later

    def register_scorer(self, fn):
        """Register a future ML scoring function."""
        self._scorers.append(fn)

    def register_ranker(self, fn):
        """Register a future root cause ranking function."""
        self._rankers.append(fn)

    def _rule_based(self, evidence: str) -> dict:
        return correlate(evidence)   # delegates to existing function

    def run(self, evidence: str) -> dict:
        results = [r(evidence) for r in self._rules]
        # future: merge scorer outputs here
        # future: pass to ranker here
        # For now: return first rule result (only one rule exists)
        return results[0] if results else {
            "probable_cause": "No correlation rule matched",
            "confidence": "inconclusive",
            "action": "Manual review required",
        }
