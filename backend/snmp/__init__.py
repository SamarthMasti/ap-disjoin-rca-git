"""SNMP package placeholder for gradual extraction."""

# backend/snmp/__init__.py
from backend.snmp.trap_receiver import make_snmp_trap_handler

__all__ = ["make_snmp_trap_handler"]