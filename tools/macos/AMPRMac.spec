from pathlib import Path
MAC = Path(SPECPATH).resolve()
ROOT = MAC.parents[1]

# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    [str(ROOT / 'tools' / 'ampr_mac_gui.py')],
    pathex=[str(ROOT / 'tools')],
    binaries=[],
    datas=[(str(MAC / name), '.') for name in ('recording-debug.sprx', 'runtime-pack.sprx') if (MAC / name).is_file()] + [(str(MAC / 'help-resources'), 'help-resources')],
    hiddenimports=['lz4.block', 'ampr_pack', 'ampr_pack_profile', 'build_ampr_index', 'ampr_project', 'ampr_pack_gui', 'ampr_progress', 'ampr_emulators'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AMPRPackTools',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AMPRPackTools',
)

app = BUNDLE(coll, icon=str(MAC / "assets" / "AMPR.icns"), name="AMPR Pack Tools.app", bundle_identifier="org.ampr.packtools.macos", info_plist={"CFBundleShortVersionString":"0.4.2.2", "CFBundleVersion":"20260907.11", "NSHighResolutionCapable":True})
