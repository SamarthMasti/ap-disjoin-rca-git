# APDisjoinRCA.spec
import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['gui_main.py'],   # entry point is the compiled .pyd
    pathex=['.'],
    binaries=[],
    datas=[
        ('CONF/iosxe_devices.yaml', 'CONF'),
        ('wfconfig_WLC_1.yaml', '.'),
        ('mdt_grpc_dialout_pb2.py', '.'),
        ('mdt_grpc_dialout_pb2_grpc.py', '.'),
        ('telemetry_pb2.py', '.'),
        ('telemetry_pb2_grpc.py', '.'),
    ],
    hiddenimports=[
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'netmiko',
        'yaml',
        'grpc',
        'google.protobuf',
        'paramiko',
        'cryptography',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='APDisjoinRCA',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,           # no black terminal window — GUI only
    onefile=True,            # single .exe like WlanPollerGUI.exe
)