#!/usr/bin/env python3
"""
gui_main.py — AP Disjoin RCA Automation Platform
==================================================
PySide6 desktop GUI — Step 1 (Workflow Selection) + Step 2 (Configuration).

Run:
    python gui_main.py

Directory layout expected:
    AP_DISJOIN/
    ├── gui_main.py                  ← this file
    ├── ap_disjoin_monitor_tool.py   ← backend (never modified)
    └── conf/
        └── iosxe_devices.yaml       ← device inventory
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

from PySide6.QtCore import (
    Qt, QThread, Signal, QPropertyAnimation, QEasingCurve,
    QTimer, QSize,
)
from PySide6.QtGui import (
    QColor, QFont, QIcon, QPalette, QPixmap,
    QLinearGradient, QPainter, QBrush,
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QSpinBox,
    QRadioButton, QButtonGroup, QCheckBox, QGroupBox,
    QScrollArea, QFrame, QSizePolicy, QFileDialog,
    QToolButton, QStatusBar, QSplitter, QSpacerItem,
    QGraphicsOpacityEffect,
)

from backend.config import resolve_inventory_path
from gui.controllers import MonitorController

# ---------------------------------------------------------------------------
# ── CONSTANTS ────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

APP_NAME    = "Network Automation Platform"
APP_VERSION = "1.0.0"

DEFAULT_INVENTORY = resolve_inventory_path(None)
DEFAULT_REPORTS   = str(Path(__file__).parent / "reports")
DEFAULT_GRPC_PORT = 57500
DEFAULT_SSH_PORT  = 22

# ---------------------------------------------------------------------------
# ── STYLESHEET — NOC dark theme, blue/cyan accent ────────────────────────────
# ---------------------------------------------------------------------------

STYLESHEET = """
/* ── Global ── */
QMainWindow, QWidget {
    background-color: #f4f6f8;
    color: #c9d8e8;
    font-family: "Segoe UI", "Inter", "SF Pro Display", sans-serif;
    font-size: 13px;
}

/* ── Sidebar ── */
#Sidebar {
    background-color: #0f172a;
    border-right: 1px solid #0d1f35;
    min-width: 220px;
    max-width: 220px;
}
#SidebarTitle {
    color: #2563eb;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    padding: 6px 20px 2px 20px;
}
#SidebarDivider {
    background-color: #0d1f35;
    max-height: 1px;
    margin: 4px 16px;
}
#NavButton {
    background: transparent;
    color: #6a8aa8;
    border: none;
    border-left: 3px solid transparent;
    padding: 10px 20px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}
#NavButton:hover {
    background-color: #0d1f35;
    color: #a8d4f0;
    border-left: 3px solid #0056a8;
}
#NavButton[active="true"] {
    background-color: #091828;
    color: #14b8a6;
    border-left: 3px solid #14b8a6;
    font-weight: 600;
}
#SidebarLogo {
    color: #14b8a6;

    font-size: 18px;
    font-weight: 700;
    padding: 24px 20px 8px 20px;
    letter-spacing: 1px;
}
#SidebarSubtitle {
    color: #2a4a6a;
    font-size: 10px;
    padding: 0px 20px 20px 20px;
    letter-spacing: 1px;
}

/* ── Status bar ── */
QStatusBar {
    background-color: #040810;
    color: #2a5a7a;
    border-top: 1px solid #0d1f35;
    font-size: 11px;
}
#StatusDot {
    font-size: 9px;
}

/* ── Content area ── */
#ContentArea {
    background-color: #111827;
}
#PageHeader {
    background-color: #111827;
    border-bottom: 1px solid #1f2937;
}
#PageTitle {
     color: #f8fafc;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 0.5px;
}
#PageSubtitle {
    color: #94a3b8;
    font-size: 12px;
    letter-spacing: 1.5px;
    font-weight: 500;
}
#Breadcrumb {
    color: #1a4a6a;
    font-size: 11px;
}
#BreadcrumbActive {
    color: #2563eb;
    font-size: 11px;
}

/* ── Workflow cards ── */
#WorkflowCard {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
}
#WorkflowCard:hover {
    border: 1px solid #64748b;
}
#CardBadge {
    background-color: #003050;
    color: #14b8a6;

    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 8px;
    letter-spacing: 1px;
}
#CardBadgeDisabled {
    background-color: #0d1828;
    color: #1a3a5a;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 8px;
    letter-spacing: 1px;
    border: 1px solid #0d2a40;
}
#CardTitle {
    color: #f8fafc;
    font-size: 15px;
    font-weight: 600;
}
#CardTitleDisabled {
    color: #1e3a5a;
    font-size: 15px;
    font-weight: 600;
}
#CardDescription {
    color: #94a3b8;
    font-size: 12px;
    line-height: 1.5;
}
#CardDescriptionDisabled {
    color: #122030;
    font-size: 12px;
}
#CardIcon {
    color: #14b8a6;
    font-size: 28px;
}
#CardIconDisabled {
    color: #0d2a3a;
    font-size: 28px;
}
#LaunchButton {
    background-color: #14b8a6;
    color: #e0f4ff;
    border: none;
    border-radius: 6px;
    padding: 9px 22px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.5px;
}
#LaunchButton:hover {
    background-color: #0f9b8e;
}
#LaunchButton:pressed {
    background: #003a70;
}
#LaunchButtonDisabled {
    background-color: #0d1828;
    color: #1a3a5a;
    border: 1px solid #0d2a40;
    border-radius: 6px;
    padding: 9px 22px;
    font-size: 12px;
    font-weight: 600;
}

/* ── Section headers ── */
#SectionHeader {
    color: #00a8c8;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    padding-bottom: 2px;
    border-bottom: 1px solid #0d2a40;
}

/* ── Form fields ── */
QLineEdit, QSpinBox, QComboBox {
    background-color: #0a1525;
    color: #c0d8f0;
    border: 1px solid #0d2a40;
    border-radius: 5px;
    padding: 7px 10px;
    font-size: 13px;
    selection-background-color: #2563eb;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1px solid #2563eb;
    background-color: #0a1828;
}
QLineEdit[valid="false"] {
    border: 1px solid #8b1a2a;
    background-color: #120810;
}
QLineEdit[valid="true"] {
    border: 1px solid #1a5a2a;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox::down-arrow {
    width: 10px;
    height: 10px;
}
QComboBox QAbstractItemView {
    background-color: #0a1525;
    color: #c0d8f0;
    border: 1px solid #0d2a40;
    selection-background-color: #00508a;
}
QSpinBox::up-button, QSpinBox::down-button {
    background-color: #0d2040;
    border: none;
    width: 18px;
}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #0d3060;
}

/* ── Radio buttons ── */
QRadioButton {
    color: #8ab4d4;
    spacing: 8px;
    font-size: 13px;
}
QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border-radius: 8px;
    border: 2px solid #0d3a5a;
    background-color: #f4f6f8;
}
QRadioButton::indicator:checked {
    background-color: #00a8c8;
    border: 2px solid #2563eb;
}
QRadioButton::indicator:hover {
    border: 2px solid #005880;
}

/* ── Checkboxes ── */
QCheckBox {
    color: #8ab4d4;
    spacing: 8px;
    font-size: 13px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 3px;
    border: 2px solid #0d3a5a;
    background-color: #f4f6f8;
}
QCheckBox::indicator:checked {
    background-color: #2563eb;
    border: 2px solid #3b82f6;
}
QCheckBox::indicator:hover {
    border: 2px solid #005880;
}

/* ── GroupBox (collapsible sections) ── */
QGroupBox {
    background-color: #0a1220;
    border: 1px solid #0d2a40;
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 10px;
    font-size: 12px;
    font-weight: 600;
    color: #4a8aaa;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    left: 12px;
    color: #4a8aaa;
}

/* ── Summary card ── */
#SummaryCard {
    background-color: #060e1a;
    border: 1px solid #003a60;
    border-radius: 8px;
    padding: 4px;
}
#SummaryLabel {
    color: #2a6a90;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
}
#SummaryValue {
    color: #2563eb;
    font-size: 13px;
    font-weight: 500;
}

/* ── Validation label ── */
#ValidationError {
    color: #e05060;
    font-size: 11px;
}
#ValidationOk {
    color: #3aaa60;
    font-size: 11px;
}

/* ── Primary action button ── */
#PrimaryButton {
    background-color: #14b8a6;
    color: #e0f4ff;
    border: none;
    border-radius: 6px;
    padding: 10px 28px;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.5px;
    min-width: 120px;
}
#PrimaryButton:hover {
    background-color: #0f9b8e;
}
#PrimaryButton:pressed {
    background: #003a70;
}
#PrimaryButton:disabled {
    background-color: #0a1828;
    color: #1a3a5a;
}

/* ── Secondary button ── */
#SecondaryButton {
    background-color: transparent;
    color: #4a8aaa;
    border: 1px solid #0d2a40;
    border-radius: 6px;
    padding: 10px 22px;
    font-size: 13px;
    font-weight: 500;
    min-width: 100px;
}
#SecondaryButton:hover {
    background-color: #0a1828;
    color: #6ab0d0;
    border: 1px solid #005080;
}
#SecondaryButton:pressed {
    background-color: #060e1a;
}

/* ── Collapse toggle button ── */
#CollapseButton {
    background-color: transparent;
    color: #2a6a90;
    border: none;
    font-size: 12px;
    font-weight: 600;
    text-align: left;
    padding: 4px 2px;
}
#CollapseButton:hover {
    color: #4a9ab8;
}

/* ── Scroll area ── */
QScrollArea {
    border: none;
    background-color: transparent;
}
QScrollBar:vertical {
    background: #060a14;
    width: 6px;
    border-radius: 3px;
}
QScrollBar::handle:vertical {
    background: #0d3a5a;
    border-radius: 3px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background: #005080;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* ── Separator line ── */
#HRule {
    background-color: #0d2a40;
    max-height: 1px;
}

/* ── Inventory status badge ── */
#InventoryOk {
    background-color: #0a2a18;
    color: #3aaa60;
    border: 1px solid #1a5a30;
    border-radius: 4px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 600;
}
#InventoryError {
    background-color: #1a0810;
    color: #e05060;
    border: 1px solid #5a1a28;
    border-radius: 4px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 600;
}

/* ── Step indicator ── */
#StepCircleActive {
    background-color: #14b8a6;
    color: #e0f4ff;
    border-radius: 14px;
    font-size: 12px;
    font-weight: 700;
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
}
#StepCircleInactive {
    background-color: #0a1828;
    color: #1a3a5a;
    border: 1px solid #0d2a40;
    border-radius: 14px;
    font-size: 12px;
    font-weight: 700;
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
}
#StepLabel {
     color: #14b8a6;
    font-size: 12px;
    font-weight: 600;
}
#StepLabelInactive {
    color: #1a3a5a;
    font-size: 12px;
}
#StepConnector {
    background-color: #0d2a40;
    max-height: 2px;
    min-width: 40px;
}
#StepConnectorActive {
    background-color: #14b8a6;
    max-height: 2px;
    min-width: 40px;
}
"""

# ---------------------------------------------------------------------------
# ── WORKFLOW REGISTRY — add future workflows here only ───────────────────────
# ---------------------------------------------------------------------------

MODERN_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0f1117;
    color: #d6dae3;
    font-family: "Segoe UI", "Inter", "SF Pro Display", sans-serif;
    font-size: 13px;
}

QLabel {
    background-color: transparent;
}

#Sidebar {
    background-color: #111827;
    border-right: 1px solid #242b38;
    min-width: 240px;
    max-width: 240px;
}
#SidebarLogo {
    color: #f8fafc;
    font-size: 18px;
    font-weight: 700;
    padding: 28px 22px 6px 22px;
}
#SidebarSubtitle {
    color: #8b95a7;
    font-size: 10px;
    padding: 0px 22px 22px 22px;
}
#SidebarTitle {
    color: #8b95a7;
    font-size: 11px;
    font-weight: 700;
    padding: 12px 22px 8px 22px;
}
#SidebarDivider {
    background-color: #242b38;
    max-height: 1px;
    margin: 2px 18px;
}
#NavButton {
    background: transparent;
    color: #aab2c0;
    border: none;
    border-left: 3px solid transparent;
    padding: 12px 22px;
    text-align: left;
    font-size: 13px;
    font-weight: 600;
}
#NavButton:hover {
    background-color: #1b2433;
    color: #f8fafc;
}
#NavButton[active="true"] {
    background-color: #202a3a;
    color: #f8fafc;
    border-left: 3px solid #2dd4bf;
}

QStatusBar {
    background-color: #0b0d12;
    color: #9aa4b5;
    border-top: 1px solid #242b38;
    font-size: 11px;
}
#StatusDot {
    font-size: 10px;
}

#ContentArea {
    background-color: #0f1117;
}
#PageHeader {
    background-color: #151922;
    border-bottom: 1px solid #242b38;
}
#PageTitle {
    color: #f8fafc;
    font-size: 24px;
    font-weight: 700;
}
#PageSubtitle {
    color: #9aa4b5;
    font-size: 12px;
    font-weight: 600;
}

#WorkflowCard {
    background-color: #181d27;
    border: 1px solid #2b3444;
    border-radius: 8px;
}
#WorkflowCard:hover {
    background-color: #1c2330;
    border: 1px solid #3d4a5f;
}
#CardBadge {
    background-color: #123b35;
    color: #6ee7d8;
    border: 1px solid #1f6f64;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    padding: 3px 9px;
}
#CardBadgeDisabled {
    background-color: #20242d;
    color: #687386;
    border: 1px solid #303746;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    padding: 3px 9px;
}
#CardTitle {
    color: #f8fafc;
    font-size: 16px;
    font-weight: 700;
}
#CardTitleDisabled {
    color: #687386;
    font-size: 16px;
    font-weight: 700;
}
#CardDescription {
    color: #aab2c0;
    font-size: 12px;
}
#CardDescriptionDisabled {
    color: #596274;
    font-size: 12px;
}
#CardIcon {
    color: #2dd4bf;
    font-size: 28px;
}
#CardIconDisabled {
    color: #596274;
    font-size: 28px;
}

#LaunchButton, #PrimaryButton {
    background-color: #2dd4bf;
    color: #071311;
    border: none;
    border-radius: 8px;
    padding: 10px 24px;
    font-size: 13px;
    font-weight: 700;
    min-width: 120px;
}
#LaunchButton:hover, #PrimaryButton:hover {
    background-color: #5eead4;
}
#LaunchButton:pressed, #PrimaryButton:pressed {
    background-color: #14b8a6;
}
#LaunchButtonDisabled, #PrimaryButton:disabled {
    background-color: #222833;
    color: #687386;
    border: 1px solid #303746;
    border-radius: 8px;
    padding: 10px 24px;
    font-size: 13px;
    font-weight: 700;
}

#SecondaryButton {
    background-color: #181d27;
    color: #d6dae3;
    border: 1px solid #343d4e;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 13px;
    font-weight: 600;
    min-width: 96px;
}
#SecondaryButton:hover {
    background-color: #222a38;
    border: 1px solid #4b5870;
    color: #f8fafc;
}
#SecondaryButton:pressed {
    background-color: #141922;
}

#SectionHeader {
    color: #cbd5e1;
    font-size: 11px;
    font-weight: 800;
    padding-bottom: 8px;
    border-bottom: 1px solid #2b3444;
}

QLineEdit, QSpinBox, QComboBox {
    background-color: #151922;
    color: #eef2f7;
    border: 1px solid #323b4c;
    border-radius: 8px;
    padding: 8px 11px;
    font-size: 13px;
    selection-background-color: #2dd4bf;
    selection-color: #071311;
}
QLineEdit:hover, QSpinBox:hover, QComboBox:hover {
    border: 1px solid #46536a;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1px solid #2dd4bf;
    background-color: #181f2a;
}
QLineEdit[valid="false"] {
    border: 1px solid #f87171;
    background-color: #241519;
}
QLineEdit[valid="true"] {
    border: 1px solid #34d399;
}
QComboBox::drop-down {
    border: none;
    width: 28px;
}
QComboBox QAbstractItemView {
    background-color: #151922;
    color: #eef2f7;
    border: 1px solid #323b4c;
    selection-background-color: #203a3a;
}
QSpinBox::up-button, QSpinBox::down-button {
    background-color: #222a38;
    border: none;
    width: 18px;
}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #2b3444;
}

QRadioButton, QCheckBox {
    color: #cbd5e1;
    spacing: 9px;
    font-size: 13px;
}
QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border-radius: 8px;
    border: 2px solid #596274;
    background-color: #111827;
}
QRadioButton::indicator:checked {
    background-color: #2dd4bf;
    border: 2px solid #99f6e4;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 2px solid #596274;
    background-color: #111827;
}
QCheckBox::indicator:checked {
    background-color: #2dd4bf;
    border: 2px solid #99f6e4;
}

QGroupBox {
    background-color: #181d27;
    border: 1px solid #2b3444;
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 10px;
    font-size: 12px;
    font-weight: 700;
    color: #cbd5e1;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    left: 12px;
    color: #cbd5e1;
}

#SummaryCard {
    background-color: #181d27;
    border: 1px solid #2b3444;
    border-radius: 8px;
    padding: 4px;
}
#SummaryLabel {
    color: #8b95a7;
    font-size: 11px;
    font-weight: 700;
}
#SummaryValue {
    color: #f8fafc;
    font-size: 13px;
    font-weight: 600;
}

#ValidationError {
    color: #f87171;
    font-size: 11px;
}
#ValidationOk {
    color: #34d399;
    font-size: 11px;
}

#CollapseButton {
    background-color: transparent;
    color: #d6dae3;
    border: none;
    font-size: 12px;
    font-weight: 700;
    text-align: left;
    padding: 6px 2px;
}
#CollapseButton:hover {
    color: #2dd4bf;
}

QScrollArea {
    border: none;
    background-color: transparent;
}
QScrollBar:vertical {
    background: #0f1117;
    width: 8px;
}
QScrollBar::handle:vertical {
    background: #343d4e;
    border-radius: 4px;
    min-height: 34px;
}
QScrollBar::handle:vertical:hover {
    background: #4b5870;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

#HRule {
    background-color: #252d3b;
    max-height: 1px;
}

#InventoryOk {
    background-color: #123b35;
    color: #6ee7d8;
    border: 1px solid #1f6f64;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 700;
}
#InventoryError {
    background-color: #3b171c;
    color: #fda4af;
    border: 1px solid #7f1d1d;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 700;
}

#StepCircleActive {
    background-color: #2dd4bf;
    color: #071311;
    border-radius: 14px;
    font-size: 12px;
    font-weight: 800;
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
}
#StepCircleInactive {
    background-color: #181d27;
    color: #8b95a7;
    border: 1px solid #343d4e;
    border-radius: 14px;
    font-size: 12px;
    font-weight: 700;
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
}
#StepLabel {
    color: #f8fafc;
    font-size: 12px;
    font-weight: 700;
}
#StepLabelInactive {
    color: #8b95a7;
    font-size: 12px;
}
#StepConnector {
    background-color: #343d4e;
    max-height: 2px;
    min-width: 40px;
}
#StepConnectorActive {
    background-color: #2dd4bf;
    max-height: 2px;
    min-width: 40px;
}
"""

WORKFLOWS = [
    {
        "id":          "ap_disjoin_rca",
        "icon":        "⚡",
        "title":       "AP Disjoin RCA",
        "badge":       "ACTIVE",
        "description": (
            "Detect AP disjoin events, launch RCA workflows, collect WLC and AP "
            "telemetry, perform automated correlation, and generate evidence reports."
        ),
        "enabled":     True,
    }
    
]

# ---------------------------------------------------------------------------
# ── INVENTORY LOADER ─────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class InventoryLoader:
    """
    Thin wrapper around the backend's load_inventory() function.
    Falls back to a direct yaml.safe_load if the backend is not importable.
    Never raises — returns (devices_dict, error_string | None).
    """

    @staticmethod
    def load(path: str) -> tuple[dict[str, Any], str | None]:
        p = Path(path)
        if not p.exists():
            return {}, f"File not found: {path}"
        try:
            # Try to reuse backend function directly
            try:
                sys.path.insert(0, str(Path(__file__).parent))
                import ap_disjoin_monitor_tool as backend  # noqa: F401
                devices = backend.load_inventory(path)
                return devices, None
            except ImportError:
                pass

            # Fallback: parse YAML directly (same logic as backend)
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            devices = {
                d["name"]: d
                for d in raw.get("iosxe_devices", [])
                if "name" in d
            }
            return devices, None
        except Exception as exc:
            return {}, str(exc)

# ---------------------------------------------------------------------------
# ── VALIDATORS ───────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

_IP_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_PORT_RE = re.compile(r"^\d+$")

def validate_ip(value: str) -> str | None:
    """Returns None if valid, else an error string."""
    v = value.strip()
    if not v:
        return "Required"
    if not _IP_RE.match(v):
        return "Invalid IP address"
    parts = v.split(".")
    if any(int(p) > 255 for p in parts):
        return "Octet out of range"
    return None

def validate_port(value: str) -> str | None:
    v = value.strip()
    if not v:
        return "Required"
    if not _PORT_RE.match(v):
        return "Must be a number"
    if not (1 <= int(v) <= 65535):
        return "Must be 1–65535"
    return None

def validate_nonempty(value: str) -> str | None:
    return None if value.strip() else "Required"

def validate_optional_ip(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None   # optional — blank is fine
    return validate_ip(v)

# ---------------------------------------------------------------------------
# ── REUSABLE WIDGETS ─────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def h_rule() -> QFrame:
    line = QFrame()
    line.setObjectName("HRule")
    line.setFrameShape(QFrame.Shape.HLine)
    return line

def section_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("SectionHeader")
    return lbl

def make_spacer(w: int = 0, h: int = 0) -> QSpacerItem:
    return QSpacerItem(w, h, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)


class ValidatedLineEdit(QWidget):
    """
    QLineEdit + inline error label underneath.
    Signals: value_changed(str) — emitted on every keystroke after validation.
    """
    value_changed = Signal(str)

    def __init__(
        self,
        placeholder: str = "",
        password: bool = False,
        validator_fn=None,
        parent=None,
    ):
        super().__init__(parent)
        self._validator = validator_fn
        self._is_valid  = True

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        self.field = QLineEdit()
        self.field.setPlaceholderText(placeholder)
        if password:
            self.field.setEchoMode(QLineEdit.EchoMode.Password)

        self._err_lbl = QLabel("")
        self._err_lbl.setObjectName("ValidationError")
        self._err_lbl.hide()

        layout.addWidget(self.field)
        layout.addWidget(self._err_lbl)

        self.field.textChanged.connect(self._on_changed)

    def _on_changed(self, text: str):
        self.validate()
        self.value_changed.emit(text)

    def validate(self) -> bool:
        if self._validator is None:
            self._is_valid = True
            self.field.setProperty("valid", None)
            self.field.style().unpolish(self.field)
            self.field.style().polish(self.field)
            self._err_lbl.hide()
            return True
        err = self._validator(self.field.text())
        if err:
            self._is_valid = False
            self.field.setProperty("valid", "false")
            self._err_lbl.setText(err)
            self._err_lbl.show()
        else:
            self._is_valid = True
            self.field.setProperty("valid", "true")
            self._err_lbl.hide()
        self.field.style().unpolish(self.field)
        self.field.style().polish(self.field)
        return self._is_valid

    def text(self) -> str:
        return self.field.text()

    def setText(self, text: str):
        self.field.setText(text)

    @property
    def is_valid(self) -> bool:
        return self._is_valid


class CollapsibleSection(QWidget):
    """
    A section with a toggle button that shows/hides its content widget.
    """
    def __init__(self, title: str, content: QWidget, collapsed: bool = True, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._toggle = QPushButton(f"▶  {title}")
        self._toggle.setObjectName("CollapseButton")
        self._toggle.setCheckable(True)
        self._toggle.setChecked(not collapsed)
        self._toggle.clicked.connect(self._on_toggle)
        layout.addWidget(self._toggle)

        self._content = content
        self._content.setVisible(not collapsed)
        layout.addWidget(self._content)

        self._title = title
        self._update_arrow()

    def _on_toggle(self, checked: bool):
        self._content.setVisible(checked)
        self._update_arrow()

    def _update_arrow(self):
        arrow = "▼" if self._toggle.isChecked() else "▶"
        self._toggle.setText(f"{arrow}  {self._title}")


class StepIndicator(QWidget):
    """Top step breadcrumb: Step 1 → Step 2 → Step 3"""

    def __init__(self, steps: list[str], current: int = 0, parent=None):
        super().__init__(parent)
        self._steps   = steps
        self._current = current
        self._circles: list[QLabel] = []
        self._labels:  list[QLabel] = []
        self._build()

    def _build(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addStretch()

        for i, name in enumerate(self._steps):
            active = (i <= self._current)

            circle = QLabel(str(i + 1))
            circle.setObjectName("StepCircleActive" if active else "StepCircleInactive")
            circle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._circles.append(circle)

            lbl = QLabel(name)
            lbl.setObjectName("StepLabel" if active else "StepLabelInactive")

            col = QVBoxLayout()
            col.setSpacing(4)
            col.setAlignment(Qt.AlignmentFlag.AlignCenter)
            row = QHBoxLayout()
            row.setAlignment(Qt.AlignmentFlag.AlignCenter)
            row.addWidget(circle)
            col.addLayout(row)
            col.addWidget(lbl)

            layout.addLayout(col)
            self._labels.append(lbl)

            if i < len(self._steps) - 1:
                conn = QFrame()
                conn.setObjectName("StepConnectorActive" if active else "StepConnector")
                conn.setFrameShape(QFrame.Shape.HLine)
                conn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
                conn.setFixedWidth(50)
                vconn = QVBoxLayout()
                vconn.setAlignment(Qt.AlignmentFlag.AlignCenter)
                vconn.addSpacing(10)
                vconn.addWidget(conn)
                layout.addLayout(vconn)

        layout.addStretch()

    def set_step(self, index: int):
        self._current = index
        for i, (circle, lbl) in enumerate(zip(self._circles, self._labels)):
            active = (i <= index)
            circle.setObjectName("StepCircleActive" if active else "StepCircleInactive")
            lbl.setObjectName("StepLabel" if active else "StepLabelInactive")
            circle.style().unpolish(circle)
            circle.style().polish(circle)
            lbl.style().unpolish(lbl)
            lbl.style().polish(lbl)

# ---------------------------------------------------------------------------
# ── STEP 1 — WORKFLOW SELECTION PAGE ─────────────────────────────────────────
# ---------------------------------------------------------------------------

class WorkflowCard(QFrame):
    """
    A single workflow card. Emits launched(workflow_id) when the button is clicked.
    """
    launched = Signal(str)

    def __init__(self, workflow: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("WorkflowCard")
        self._id      = workflow["id"]
        self._enabled = workflow["enabled"]

        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(12)

        # ── Header row ────────────────────────────────────────────────
        header = QHBoxLayout()

        icon_lbl = QLabel(workflow["icon"])
        icon_lbl.setObjectName("CardIcon" if self._enabled else "CardIconDisabled")
        icon_lbl.setFixedWidth(40)
        header.addWidget(icon_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(4)

        title_lbl = QLabel(workflow["title"])
        title_lbl.setObjectName("CardTitle" if self._enabled else "CardTitleDisabled")
        title_col.addWidget(title_lbl)

        badge = QLabel(workflow["badge"])
        badge.setObjectName("CardBadge" if self._enabled else "CardBadgeDisabled")
        badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        title_col.addWidget(badge)

        header.addLayout(title_col)
        header.addStretch()
        outer.addLayout(header)

        # ── Description ───────────────────────────────────────────────
        desc = QLabel(workflow["description"])
        desc.setObjectName("CardDescription" if self._enabled else "CardDescriptionDisabled")
        desc.setWordWrap(True)
        outer.addWidget(desc)

        outer.addStretch()

        # ── Launch button ─────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        if self._enabled:
            btn = QPushButton("Launch Workflow  →")
            btn.setObjectName("LaunchButton")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda: self.launched.emit(self._id))
            btn_row.addWidget(btn)
        else:
            btn = QPushButton("Not Available")
            btn.setObjectName("LaunchButtonDisabled")
            btn.setEnabled(False)
            btn_row.addWidget(btn)

        outer.addLayout(btn_row)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)


class WorkflowSelectionPage(QWidget):
    """Step 1 — grid of workflow cards."""

    workflow_selected = Signal(str)   # emits workflow id

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ContentArea")
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Page header ───────────────────────────────────────────────
        header_wrap = QWidget()
        header_wrap.setObjectName("PageHeader")
        header_layout = QVBoxLayout(header_wrap)
        header_layout.setContentsMargins(36, 24, 36, 24)
        header_layout.setSpacing(6)

        title = QLabel("AP Troubleshooting")
        title.setObjectName("PageTitle")
        header_layout.addWidget(title)

        subtitle = QLabel("SELECT WORKFLOW")
        subtitle.setObjectName("PageSubtitle")
        header_layout.addWidget(subtitle)

        root.addWidget(header_wrap)

        # ── Scrollable card area ──────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        content.setObjectName("ContentArea")
        grid_layout = QVBoxLayout(content)
        grid_layout.setContentsMargins(36, 30, 36, 36)
        grid_layout.setSpacing(0)

        # Intro
        intro = QLabel(
            "Choose an automation workflow to configure and launch. "
            "Each workflow connects directly to your Cisco 9800 WLC infrastructure."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #aab2c0; font-size: 13px; padding-bottom: 24px;")
        grid_layout.addWidget(intro)

        # Cards in 2-column grid
        grid = QGridLayout()
        grid.setSpacing(16)

        for idx, wf in enumerate(WORKFLOWS):
            card = WorkflowCard(wf)
            card.launched.connect(self.workflow_selected.emit)
            row, col = divmod(idx, 2)
            grid.addWidget(card, row, col)

        # If odd number of cards, fill last cell
        if len(WORKFLOWS) % 2 == 1:
            filler = QWidget()
            grid.addWidget(filler, len(WORKFLOWS) // 2, 1)

        grid_layout.addLayout(grid)
        grid_layout.addStretch()

        scroll.setWidget(content)
        root.addWidget(scroll)

# ---------------------------------------------------------------------------
# ── STEP 2 — CONFIGURATION PAGE ──────────────────────────────────────────────
# ---------------------------------------------------------------------------

class SummaryCard(QWidget):
    """Live-updating config summary card shown at bottom of Step 2."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("SummaryCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        header = QLabel("CONFIGURATION SUMMARY")
        header.setObjectName("SectionHeader")
        layout.addWidget(header)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(1, 20)

        self._fields: dict[str, QLabel] = {}
        rows = [
            ("Workflow",      "AP Disjoin RCA"),
            ("Target WLC",    "—"),
            ("Trigger Mode",  "MDT Telemetry"),
            ("gRPC Port",     str(DEFAULT_GRPC_PORT)),
            ("SSH Port",      str(DEFAULT_SSH_PORT)),
            ("TFTP Server",   "—"),
            ("Report Dir",    "—"),
            ("Inventory",     "—"),
        ]
        for i, (key, default) in enumerate(rows):
            lbl = QLabel(key)
            lbl.setObjectName("SummaryLabel")
            val = QLabel(default)
            val.setObjectName("SummaryValue")
            val.setWordWrap(True)
            grid.addWidget(lbl, i, 0)
            grid.addWidget(val, i, 2)
            self._fields[key] = val

        layout.addLayout(grid)

    def update(self, key: str, value: str):
        if key in self._fields:
            self._fields[key].setText(value or "—")


class ConfigurationPage(QWidget):
    """
    Step 2 — full configuration form.

    Populates from iosxe_devices.yaml automatically.
    Emits back_requested() or launch_requested(config_dict).
    """

    back_requested   = Signal()
    launch_requested = Signal(dict)

    # Emitted whenever any field changes so the summary card stays live
    _config_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ContentArea")

        self._inventory: dict[str, Any] = {}
        self._inventory_path = DEFAULT_INVENTORY
        self._inventory_error: str | None = None

        # Field references (set during _build)
        self._device_combo:     QComboBox           | None = None
        self._f_host:           ValidatedLineEdit   | None = None
        self._f_username:       ValidatedLineEdit   | None = None
        self._f_password:       ValidatedLineEdit   | None = None
        self._f_secret:         ValidatedLineEdit   | None = None
        self._f_port:           QSpinBox            | None = None
        self._rb_mdt:           QRadioButton        | None = None
        self._rb_snmp:          QRadioButton        | None = None
        self._snmp_frame:       QWidget             | None = None
        self._f_grpc_port:      QSpinBox            | None = None
        self._f_duration:       QSpinBox            | None = None
        self._f_tftp:           ValidatedLineEdit   | None = None
        self._f_report_dir:     QLineEdit           | None = None
        self._f_jumphost:       ValidatedLineEdit   | None = None
        self._f_ap_user:        QLineEdit           | None = None
        self._f_ap_pass:        QLineEdit           | None = None
        
        self._summary:          SummaryCard         | None = None
        self._launch_btn:       QPushButton         | None = None
        self._inv_status:       QLabel              | None = None
        self._step_indicator:   StepIndicator       | None = None

        self._build()
        self._load_inventory()

    # ------------------------------------------------------------------ #
    # Build UI                                                            #
    # ------------------------------------------------------------------ #

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Page header ───────────────────────────────────────────────
        header_wrap = QWidget()
        header_wrap.setObjectName("PageHeader")
        hv = QVBoxLayout(header_wrap)
        hv.setContentsMargins(36, 20, 36, 20)
        hv.setSpacing(6)

        top_row = QHBoxLayout()
        title = QLabel("AP Disjoin RCA Workflow")
        title.setObjectName("PageTitle")
        top_row.addWidget(title)
        top_row.addStretch()

        self._step_indicator = StepIndicator(
            ["Select Workflow", "Configure", "Run"], current=1
        )
        top_row.addWidget(self._step_indicator)
        hv.addLayout(top_row)

        subtitle = QLabel("WORKFLOW CONFIGURATION")
        subtitle.setObjectName("PageSubtitle")
        hv.addWidget(subtitle)

        root.addWidget(header_wrap)

        # ── Scrollable form + summary ─────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        content.setObjectName("ContentArea")
        clayout = QVBoxLayout(content)
        clayout.setContentsMargins(36, 28, 36, 28)
        clayout.setSpacing(24)

        # ── Inventory status row ──────────────────────────────────────
        inv_row = QHBoxLayout()
        inv_lbl = QLabel("Inventory File:")
        inv_lbl.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        inv_row.addWidget(inv_lbl)

        self._inv_path_lbl = QLabel(self._inventory_path)
        self._inv_path_lbl.setStyleSheet("color: #8b95a7; font-size: 12px;")
        inv_row.addWidget(self._inv_path_lbl, stretch=1)

        browse_btn = QPushButton("Browse…")
        browse_btn.setObjectName("SecondaryButton")
        browse_btn.setFixedWidth(90)
        browse_btn.clicked.connect(self._browse_inventory)
        inv_row.addWidget(browse_btn)

        self._inv_status = QLabel("Loading…")
        self._inv_status.setObjectName("InventoryOk")
        inv_row.addWidget(self._inv_status)

        clayout.addLayout(inv_row)
        clayout.addWidget(h_rule())

        # ── Device Selection ──────────────────────────────────────────
        clayout.addWidget(section_label("Device Selection"))
        form_device = QFormLayout()
        form_device.setSpacing(10)
        form_device.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_device.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self._device_combo = QComboBox()
        self._device_combo.setPlaceholderText("Select device from inventory…")
        self._device_combo.currentTextChanged.connect(self._on_device_selected)
        form_device.addRow("Device Name:", self._device_combo)

        self._f_host = ValidatedLineEdit(
            placeholder="e.g. 192.168.0.100",
            validator_fn=validate_ip,
        )
        self._f_host.value_changed.connect(self._on_any_change)
        form_device.addRow("WLC IP Address:", self._f_host)

        self._f_username = ValidatedLineEdit(
            placeholder="SSH username",
            validator_fn=validate_nonempty,
        )
        self._f_username.value_changed.connect(self._on_any_change)
        form_device.addRow("Username:", self._f_username)

        self._f_password = ValidatedLineEdit(
            placeholder="SSH password",
            password=True,
            validator_fn=validate_nonempty,
        )
        self._f_password.value_changed.connect(self._on_any_change)
        form_device.addRow("Password:", self._f_password)

        self._f_secret = ValidatedLineEdit(
            placeholder="Enable secret (optional)",
            password=True,
        )
        form_device.addRow("Enable Secret:", self._f_secret)

        self._f_port = QSpinBox()
        self._f_port.setRange(1, 65535)
        self._f_port.setValue(DEFAULT_SSH_PORT)
        self._f_port.valueChanged.connect(self._on_any_change)
        form_device.addRow("SSH Port:", self._f_port)

        clayout.addLayout(form_device)
        clayout.addWidget(h_rule())

        # ── Telemetry Section ─────────────────────────────────────────
        clayout.addWidget(section_label("Telemetry"))

        trig_row = QHBoxLayout()
        trig_row.setSpacing(24)
        trig_lbl = QLabel("Trigger Mode:")
        trig_lbl.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        trig_lbl.setFixedWidth(120)
        trig_row.addWidget(trig_lbl)

        self._rb_mdt  = QRadioButton("MDT Telemetry  (gRPC dial-out)")
        self._rb_snmp = QRadioButton("SNMP Traps")
        self._rb_mdt.setChecked(True)

        btn_grp = QButtonGroup(self)
        btn_grp.addButton(self._rb_mdt)
        btn_grp.addButton(self._rb_snmp)

        self._rb_mdt.toggled.connect(self._on_trigger_changed)
        self._rb_snmp.toggled.connect(self._on_any_change)
        trig_row.addWidget(self._rb_mdt)
        trig_row.addWidget(self._rb_snmp)
        trig_row.addStretch()
        clayout.addLayout(trig_row)

        # SNMP-specific fields (hidden by default)
        self._snmp_frame = QWidget()
        snmp_layout = QFormLayout(self._snmp_frame)
        snmp_layout.setSpacing(10)
        snmp_layout.setContentsMargins(124, 8, 0, 0)
        snmp_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        snmp_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self._f_snmp_community = QLineEdit()
        self._f_snmp_community.setText("public")
        self._f_snmp_community.setPlaceholderText("SNMP community string")
        snmp_layout.addRow("SNMP Community:", self._f_snmp_community)

        self._snmp_frame.setVisible(False)
        clayout.addWidget(self._snmp_frame)
        clayout.addWidget(h_rule())

        # ── Monitoring Section ────────────────────────────────────────
        clayout.addWidget(section_label("Monitoring"))
        form_mon = QFormLayout()
        form_mon.setSpacing(10)
        form_mon.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_mon.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self._f_grpc_port = QSpinBox()
        self._f_grpc_port.setRange(1, 65535)
        self._f_grpc_port.setValue(DEFAULT_GRPC_PORT)
        self._f_grpc_port.valueChanged.connect(self._on_any_change)
        form_mon.addRow("gRPC Port:", self._f_grpc_port)

        self._f_duration = QSpinBox()
        self._f_duration.setRange(0, 1440)
        self._f_duration.setValue(0)
        self._f_duration.setSpecialValueText("Unlimited")
        self._f_duration.setSuffix(" min")
        form_mon.addRow("Duration:", self._f_duration)

        self._f_tftp = ValidatedLineEdit(
            placeholder="e.g. 192.168.0.6",
            validator_fn=validate_optional_ip,
        )
        self._f_tftp.value_changed.connect(self._on_any_change)
        form_mon.addRow("TFTP Server IP:", self._f_tftp)

        report_row = QHBoxLayout()
        self._f_report_dir = QLineEdit()
        self._f_report_dir.setText(DEFAULT_REPORTS)
        self._f_report_dir.setPlaceholderText("Path to reports directory")
        report_row.addWidget(self._f_report_dir)
        browse_rep = QPushButton("…")
        browse_rep.setFixedWidth(32)
        browse_rep.setObjectName("SecondaryButton")
        browse_rep.clicked.connect(self._browse_reports)
        report_row.addWidget(browse_rep)
        form_mon.addRow("Report Directory:", report_row)

        clayout.addLayout(form_mon)

        # ── Advanced (collapsible) ────────────────────────────────────
        adv_content = QWidget()
        adv_form = QFormLayout(adv_content)
        adv_form.setSpacing(10)
        adv_form.setContentsMargins(0, 10, 0, 10)
        adv_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        adv_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self._f_jumphost = ValidatedLineEdit(
            placeholder="Jumphost / listener IP (optional)",
            validator_fn=validate_optional_ip,
        )
        adv_form.addRow("Jumphost IP:", self._f_jumphost)

        self._f_ap_user = QLineEdit()
        self._f_ap_user.setText("Cisco")
        self._f_ap_user.setPlaceholderText("AP SSH username")
        adv_form.addRow("AP Username:", self._f_ap_user)

        self._f_ap_pass = QLineEdit()
        self._f_ap_pass.setText("Cisco")
        self._f_ap_pass.setPlaceholderText("AP SSH password")
        self._f_ap_pass.setEchoMode(QLineEdit.EchoMode.Password)
        adv_form.addRow("AP Password:", self._f_ap_pass)

        adv_form.addRow("", QLabel(""))  # spacer

        

        adv_section = CollapsibleSection("Advanced Options", adv_content, collapsed=False)
        clayout.addWidget(h_rule())
        clayout.addWidget(adv_section)
        clayout.addWidget(h_rule())

        # ── Summary card ──────────────────────────────────────────────
        self._summary = SummaryCard()
        clayout.addWidget(self._summary)

        # ── Bottom button row ─────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        back_btn = QPushButton("← Back")
        back_btn.setObjectName("SecondaryButton")
        back_btn.clicked.connect(self.back_requested.emit)
        btn_row.addWidget(back_btn)
        btn_row.addStretch()

        self._launch_btn = QPushButton("Launch Workflow  →")
        self._launch_btn.setObjectName("PrimaryButton")
        self._launch_btn.setEnabled(False)
        self._launch_btn.clicked.connect(self._on_launch)
        btn_row.addWidget(self._launch_btn)

        clayout.addSpacerItem(make_spacer(0, 8))
        clayout.addLayout(btn_row)

        scroll.setWidget(content)
        root.addWidget(scroll)

    # ------------------------------------------------------------------ #
    # Inventory                                                           #
    # ------------------------------------------------------------------ #

    def _load_inventory(self):
        self._inventory, self._inventory_error = InventoryLoader.load(self._inventory_path)
        self._refresh_inventory_ui()

    def _refresh_inventory_ui(self):
        if self._inv_status is None:
            return
        if self._inventory_error:
            self._inv_status.setText(f"✗  {self._inventory_error}")
            self._inv_status.setObjectName("InventoryError")
        else:
            count = len(self._inventory)
            self._inv_status.setText(f"✓  {count} device(s) loaded")
            self._inv_status.setObjectName("InventoryOk")
        self._inv_status.style().unpolish(self._inv_status)
        self._inv_status.style().polish(self._inv_status)

        self._inv_path_lbl.setText(self._inventory_path)
        self._summary.update("Inventory", Path(self._inventory_path).name)

        # Repopulate device dropdown
        self._device_combo.blockSignals(True)
        self._device_combo.clear()
        self._device_combo.addItem("")    # blank sentinel
        for name in sorted(self._inventory.keys()):
            self._device_combo.addItem(name)
        self._device_combo.blockSignals(False)

        # Auto-select first device if only one exists
        if len(self._inventory) == 1:
            first = next(iter(self._inventory))
            self._device_combo.setCurrentText(first)

        self._validate_all()

    def _browse_inventory(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Inventory File", str(Path(self._inventory_path).parent),
            "YAML Files (*.yaml *.yml);;All Files (*)"
        )
        if path:
            self._inventory_path = path
            self._load_inventory()

    def _browse_reports(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Report Directory", self._f_report_dir.text()
        )
        if path:
            self._f_report_dir.setText(path)

    # ------------------------------------------------------------------ #
    # Slot: device dropdown changed                                       #
    # ------------------------------------------------------------------ #

    def _on_device_selected(self, name: str):
        device = self._inventory.get(name)
        if not device:
            return

        def _set(widget, key, default=""):
            val = str(device.get(key, default))
            if isinstance(widget, ValidatedLineEdit):
                widget.setText(val)
            elif isinstance(widget, QLineEdit):
                widget.setText(val)
            elif isinstance(widget, QSpinBox):
                widget.setValue(int(val) if val.isdigit() else widget.value())

        _set(self._f_host,     "host")
        _set(self._f_username, "username")
        _set(self._f_password, "password")
        _set(self._f_secret,   "enable_secret")
        _set(self._f_port,     "port", str(DEFAULT_SSH_PORT))
        _set(self._f_tftp,     "tftp_ip")
        _set(self._f_jumphost, "jumphost_ip")
        _set(self._f_ap_user,  "ap_username", "Cisco")
        _set(self._f_ap_pass,  "ap_password", "Cisco")

        self._on_any_change()

    # ------------------------------------------------------------------ #
    # Slot: trigger mode radio                                            #
    # ------------------------------------------------------------------ #

    def _on_trigger_changed(self, mdt_checked: bool):
        self._snmp_frame.setVisible(not mdt_checked)
        self._f_grpc_port.setEnabled(mdt_checked)
        mode = "MDT Telemetry" if mdt_checked else "SNMP Traps"
        self._summary.update("Trigger Mode", mode)
        self._on_any_change()

    # ------------------------------------------------------------------ #
    # Slot: any field changed → update summary + revalidate              #
    # ------------------------------------------------------------------ #

    def _on_any_change(self, *_):
        self._summary.update("Target WLC",   self._f_host.text())
        self._summary.update("gRPC Port",    str(self._f_grpc_port.value()))
        self._summary.update("SSH Port",     str(self._f_port.value()))
        self._summary.update("TFTP Server",  self._f_tftp.text())
        self._summary.update("Report Dir",   self._f_report_dir.text())
        mode = "MDT Telemetry" if self._rb_mdt.isChecked() else "SNMP Traps"
        self._summary.update("Trigger Mode", mode)
        self._validate_all()

    # ------------------------------------------------------------------ #
    # Validation                                                          #
    # ------------------------------------------------------------------ #

    def _validate_all(self) -> bool:
        results = [
            self._f_host.validate(),
            self._f_username.validate(),
            self._f_password.validate(),
            self._f_tftp.validate(),
            self._f_jumphost.validate(),
        ]
        all_ok = all(results)
        if self._launch_btn:
            self._launch_btn.setEnabled(all_ok)
        return all_ok

    # ------------------------------------------------------------------ #
    # Build runtime config dict → emit launch_requested                  #
    # ------------------------------------------------------------------ #

    def _on_launch(self):
        if not self._validate_all():
            return

        duration_val = self._f_duration.value()

        config = {
            # ── Device ──────────────────────────────────────────────
            "device_name":    self._device_combo.currentText(),
            "host":           self._f_host.text().strip(),
            "username":       self._f_username.text().strip(),
            "password":       self._f_password.text(),
            "enable_secret":  self._f_secret.text(),
            "port":           self._f_port.value(),

            # ── Telemetry ────────────────────────────────────────────
            "trigger_mode":   "snmp" if self._rb_snmp.isChecked() else "telemetry",
            "snmp_community": self._f_snmp_community.text().strip(),
            "grpc_port":      self._f_grpc_port.value(),

            # ── Monitoring ───────────────────────────────────────────
            "duration_minutes": duration_val if duration_val > 0 else None,
            "tftp_ip":          self._f_tftp.text().strip(),
            "report_dir":       self._f_report_dir.text().strip(),

            # ── Advanced ─────────────────────────────────────────────
            "jumphost_ip":      self._f_jumphost.text().strip(),
            "ap_username":      self._f_ap_user.text().strip(),
            "ap_password":      self._f_ap_pass.text(),
            

            # ── Inventory ────────────────────────────────────────────
            "inventory_file":   self._inventory_path,
        }

        self.launch_requested.emit(config)

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #

    def reset(self):
        """Called each time the page becomes visible to re-validate."""
        self._validate_all()
        self._on_any_change()

# ---------------------------------------------------------------------------
# ── SIDEBAR ──────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class Sidebar(QWidget):
    """Left navigation panel."""

    nav_requested = Signal(int)   # page index

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self._buttons: list[QPushButton] = []
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo
        logo = QLabel("AP TROUBLESHOOTING")
        logo.setObjectName("SidebarLogo")
        layout.addWidget(logo)

        sub = QLabel("NETWORK AUTOMATION")
        sub.setObjectName("SidebarSubtitle")
        layout.addWidget(sub)

        # Divider
        div = QFrame()
        div.setObjectName("SidebarDivider")
        div.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(div)

        # Section title
        sec = QLabel("WORKFLOWS")
        sec.setObjectName("SidebarTitle")
        layout.addWidget(sec)

        # Nav buttons
        nav_items = [
            ("⚡  Workflow Selection",  0),
            ("⚙️  Configure",           1),
        ]

        for label, idx in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.setProperty("active", "false")
            btn.clicked.connect(lambda _, i=idx: self.nav_requested.emit(i))
            layout.addWidget(btn)
            self._buttons.append(btn)

        layout.addStretch()

        # Bottom version label
        ver = QLabel(f"v{APP_VERSION}")
        ver.setStyleSheet("color: #687386; font-size: 10px; padding: 12px 22px;")
        layout.addWidget(ver)

    def set_active(self, index: int):
        for i, btn in enumerate(self._buttons):
            btn.setProperty("active", "true" if i == index else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

# ---------------------------------------------------------------------------
# ── MAIN WINDOW ──────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1100, 720)
        self.resize(1280, 800)
        self._monitor_controller = MonitorController(self)
        self._monitor_controller.started.connect(self._on_monitor_started)
        self._monitor_controller.event.connect(self._on_monitor_event)
        self._monitor_controller.failed.connect(self._on_monitor_failed)
        self._monitor_controller.finished.connect(self._on_monitor_finished)

        self._build()
        self._navigate(0)   # start on workflow selection

    def _build(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ───────────────────────────────────────────────────
        self._sidebar = Sidebar()
        self._sidebar.nav_requested.connect(self._navigate)
        root.addWidget(self._sidebar)

        # ── Stacked content pages ─────────────────────────────────────
        self._stack = QStackedWidget()
        self._stack.setObjectName("ContentArea")
        root.addWidget(self._stack, stretch=1)

        # Page 0 — workflow selection
        self._selection_page = WorkflowSelectionPage()
        self._selection_page.workflow_selected.connect(self._on_workflow_selected)
        self._stack.addWidget(self._selection_page)

        # Page 1 — configuration
        self._config_page = ConfigurationPage()
        self._config_page.back_requested.connect(lambda: self._navigate(0))
        self._config_page.launch_requested.connect(self._on_launch_requested)
        self._stack.addWidget(self._config_page)

        # ── Status bar ────────────────────────────────────────────────
        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status_dot = QLabel("●")
        self._status_dot.setObjectName("StatusDot")
        self._status_dot.setStyleSheet("color: #8b95a7; font-size: 10px;")
        self._status_msg = QLabel("Ready  —  Select a workflow to begin")
        sb.addWidget(self._status_dot)
        sb.addWidget(self._status_msg)
        sb.addPermanentWidget(QLabel(f"  {APP_NAME}  v{APP_VERSION}  "))

    # ------------------------------------------------------------------ #
    # Navigation                                                         #
    # ------------------------------------------------------------------ #

    def _navigate(self, index: int):
        self._stack.setCurrentIndex(index)
        self._sidebar.set_active(index)
        if index == 1:
            self._config_page.reset()
        labels = ["Select Workflow", "Configure"]
        self._status_msg.setText(f"Step {index+1}  —  {labels[index]}")

    def _on_workflow_selected(self, workflow_id: str):
        if workflow_id == "ap_disjoin_rca":
            self._navigate(1)

    # ------------------------------------------------------------------ #
    # Launch → placeholder (Step 3 not implemented yet)                  #
    # ------------------------------------------------------------------ #

    def _on_launch_requested_placeholder(self, config: dict):
        """
        Step 3 entry point.

        This is where WorkflowWorker(QThread) will be created and started.
        The worker will:
            1. Import ap_disjoin_monitor_tool as backend
            2. Set backend.TRIGGER_MODE = config["trigger_mode"]
            3. Set backend.REPORTS_DIR  = Path(config["report_dir"])
            4. Build auth dict from config
            5. Instantiate backend.LiveMonitor(auth, host, device_name, grpc_port)
            6. Call monitor._push_eem_applet()
            7. Call monitor.listen(duration_minutes)
            8. Emit signals back to UI for log lines and progress updates

        Not implemented in this milestone (Step 1 + Step 2 only).
        """
        device = config.get("device_name") or config.get("host")
        self._status_msg.setText(
            f"Configuration ready  —  {device}  |  "
            f"{config['trigger_mode'].upper()}  |  "
            f"Port {config['grpc_port']}  ·  Launch not implemented yet (Step 3)"
        )
        self._status_dot.setStyleSheet("color: #34d399; font-size: 10px;")

    def _on_launch_requested(self, config: dict):
        device = config.get("device_name") or config.get("host")
        try:
            self._monitor_controller.start(config)
        except RuntimeError as exc:
            self._status_msg.setText(str(exc))
            return
        self._status_msg.setText(
            f"Workflow starting  -  {device}  |  "
            f"{config['trigger_mode'].upper()}  |  "
            f"Port {config['grpc_port']}"
        )
        self._status_dot.setStyleSheet("color: #34d399; font-size: 10px;")

    def _on_monitor_started(self):
        self._status_dot.setStyleSheet("color: #34d399; font-size: 10px;")

    def _on_monitor_event(self, event: dict):
        if event.get("type") == "engine_started":
            self._status_msg.setText(
                f"Monitoring  -  {event.get('host')}  |  "
                f"{str(event.get('trigger_mode', '')).upper()}"
            )

    def _on_monitor_failed(self, message: str):
        self._status_dot.setStyleSheet("color: #f87171; font-size: 10px;")
        self._status_msg.setText(f"Workflow failed  -  {message}")

    def _on_monitor_finished(self, result: dict):
        self._status_dot.setStyleSheet("color: #34d399; font-size: 10px;")
        self._status_msg.setText(
            f"Workflow complete  -  {result.get('unique_aps_traced', 0)} AP(s) traced"
        )

# ---------------------------------------------------------------------------
# ── ENTRY POINT ──────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyleSheet(MODERN_STYLESHEET)

    # Use Fusion style as base (best dark-theme compatibility)
    app.setStyle("Fusion")

    # Override palette so Qt-native widgets also respect dark background
    palette = QPalette()
    dark = QColor("#0f1117")
    palette.setColor(QPalette.ColorRole.Window,          dark)
    palette.setColor(QPalette.ColorRole.WindowText,      QColor("#d6dae3"))
    palette.setColor(QPalette.ColorRole.Base,            QColor("#151922"))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor("#181d27"))
    palette.setColor(QPalette.ColorRole.ToolTipBase,     dark)
    palette.setColor(QPalette.ColorRole.ToolTipText,     QColor("#d6dae3"))
    palette.setColor(QPalette.ColorRole.Text,            QColor("#eef2f7"))
    palette.setColor(QPalette.ColorRole.Button,          QColor("#181d27"))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor("#d6dae3"))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor("#2dd4bf"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#071311"))
    app.setPalette(palette)

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
