# setup_cython.py  — Cython compile setup for AP Disjoin RCA Platform
from setuptools import setup
from Cython.Build import cythonize

targets = [
    "gui_main.py",
    "ap_disjoin_monitor_tool.py",
    "backend/config.py",
    "backend/adapters/event_bridge.py",
    "backend/engine/event_engine.py",
    "backend/engine/finalizer.py",
    "backend/engine/monitor_engine.py",
    "backend/rca/ap_ssh.py",
    "backend/rca/correlation.py",
    "backend/rca/wlc_ssh.py",
    "backend/snmp/trap_receiver.py",
    "backend/state/counters.py",
    "backend/state/disjoin_occurrences.py",
    "backend/state/event_history.py",
    "backend/state/finalized_history.py",
    "backend/state/workflow_state.py",
    "backend/telemetry/eem_parser.py",
    "backend/telemetry/mdt_receiver.py",
    "gui/controllers/monitor_controller.py",
]

if __name__ == "__main__":
    setup(
        name="APDisjoinRCA",
        ext_modules=cythonize(
            targets,
            compiler_directives={
                "language_level": "3",
            },
        ),
    )