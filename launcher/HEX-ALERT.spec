# -*- mode: python ; coding: utf-8 -*-
"""Standalone Windows directory build; no project secrets, Docker images, or GGUF are bundled."""
import os

root = os.path.abspath(os.path.join(SPECPATH, os.pardir))

a = Analysis(
    [os.path.join(root, "launcher", "main.py")],
    pathex=[root],
    binaries=[],
    datas=[],
    hiddenimports=["PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["torch", "transformers", "llama_cpp", "pytest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)
debug_build = os.environ.get("HEX_ALERT_DEBUG_BUILD") == "1"
exe_name = "HEX-ALERT-DEBUG" if debug_build else "HEX-ALERT"
exe = EXE(
    pyz,
    a.scripts,
    [],
    [],
    name=exe_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    exclude_binaries=True,
    console=debug_build,
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
    upx=False,
    upx_exclude=[],
    name=exe_name,
    contents_directory="_internal",
)
