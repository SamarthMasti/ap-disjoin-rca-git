# APDisjoinRCA.spec
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

block_cipher = None

app_icon = 'assets/ciscologo.icns' if sys.platform == 'darwin' else 'assets/ciscologo.ico'

# grpc's real implementation is mostly a compiled C-extension — listing it in
# hiddenimports alone only traces its plain-Python parts. collect_all() pulls
# in its binaries and data files too, which is what's actually needed for it
# to work once bundled.
grpc_datas, grpc_binaries, grpc_hiddenimports = collect_all('grpc')

a = Analysis(
    ['gui_main.py'],   # entry point is the compiled .pyd
    pathex=['.'],
    binaries=[*grpc_binaries],
    datas=[
        ('assets/ciscologo.ico', 'assets'),
        ('CONF/iosxe_devices.yaml', 'CONF'),
        ('mdt_grpc_dialout_pb2.py', '.'),
        ('mdt_grpc_dialout_pb2_grpc.py', '.'),
        ('telemetry_pb2.py', '.'),
        ('telemetry_pb2_grpc.py', '.'),
        *grpc_datas,
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
        *grpc_hiddenimports,
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
    icon=app_icon,
)