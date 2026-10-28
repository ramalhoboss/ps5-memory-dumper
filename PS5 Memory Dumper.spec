# -*- mode: python ; coding: utf-8 -*-
# PyInstaller build of one self-contained "PS5 Memory Dumper.exe" (no _internal folder, no Python needed).
# Run through build_exe.ps1, which first makes the icon and artwork from "icone 2.png" / Icon.png / Logo.jpg.
#
# Qt parts a widgets app never uses are left out so the .exe is smaller and unpacks faster at start:
# the software OpenGL renderer, Qt's own translations, and networking/TLS (the console connection
# uses Python sockets, not Qt).
#
# Only DLLs from the Python installation are bundled. PyInstaller otherwise also copies DLLs it finds on
# PATH, so the result depended on who built it: copies of ucrtbase.dll / api-ms-win-*.dll / ICU from other
# programs' folders made builds fail with "DLL load failed while importing QtWidgets". The Universal C
# Runtime is never bundled: Windows 10/11 has it.
import os
import sys

UNUSED = ("opengl32sw.dll", "PySide6/translations/", "Qt6Network", "QtNetwork", "plugins/tls/",
          "plugins/networkinformation/", "libssl-3-x64.dll", "libcrypto-3-x64.dll")
SYSTEM_RUNTIME = ("ucrtbase.dll", "api-ms-win-")
PYTHON_DIRS = tuple({os.path.normcase(os.path.abspath(p)) + os.sep for p in (sys.base_prefix, sys.prefix)})


def used(entry):
    destination = entry[0].replace("\\", "/")
    name = destination.rsplit("/", 1)[-1].lower()
    return not any(part in destination for part in UNUSED) and not name.startswith(SYSTEM_RUNTIME)


def from_python(entry):
    return os.path.normcase(os.path.abspath(entry[1])).startswith(PYTHON_DIRS)


a = Analysis(
    ['PS5 Memory Dumper.pyw'],
    pathex=[],
    binaries=[],
    datas=[('ps5dumper/gui/assets', 'ps5dumper/gui/assets')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['PySide6.QtNetwork', 'tkinter'],
    noarchive=False,
    optimize=0,
)
a.binaries = [entry for entry in a.binaries if used(entry) and from_python(entry)]
a.datas = [entry for entry in a.datas if used(entry)]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PS5 Memory Dumper',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['ps5dumper/gui/assets/icon.ico'],
)
