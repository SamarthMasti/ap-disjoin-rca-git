# APDisjoinRCA-macos-arm64.spec
# macOS (Apple Silicon) build — kept separate from APDIsjoinRCA.spec (Windows)
# on purpose, so neither platform's build settings can bleed into the other.
#
# Build ONLY on a Mac (PyInstaller does not cross-compile):
#     pyinstaller APDisjoinRCA-macos-arm64.spec
#
# Output: dist/APDisjoinRCA.app

block_cipher = None

app_icon = 'assets/ciscologo.icns'

a = Analysis(
    ['gui_main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('assets/ciscologo.icns', 'assets'),
        ('CONF/iosxe_devices.yaml', 'CONF'),
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
    upx=False,              # UPX is known to corrupt/unsign macOS binaries, esp. Apple Silicon
    console=False,          # no terminal window — GUI only
    onefile=True,
    target_arch='arm64',    # pin to Apple Silicon; omit/'universal2' for Intel+ARM in one binary
    icon=app_icon,
)

# The step Windows doesn't need: wraps the binary into a real, double-clickable
# .app bundle (Finder/Dock/Applications integration). Without this, EXE() alone
# only produces a raw Unix executable you'd have to run from Terminal.
app = BUNDLE(
    exe,
    name='APDisjoinRCA.app',
    icon=app_icon,
    bundle_identifier='com.aigle.apdisjoinrca',
    info_plist={
        'NSHighResolutionCapable': 'True',
        'CFBundleShortVersionString': '1.0.0',
    },
)
