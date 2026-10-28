# Third-party notices

PS5 Memory Dumper is © RamalhoBoss and licensed under the **GNU General Public License v3.0** (see
[LICENSE](LICENSE)). It uses the components below. The Windows `.exe` bundles them; running from source
installs them with `pip install -r requirements.txt`.

| Component | Used for | Licence | Source |
|-----------|----------|---------|--------|
| ps5dbg 0.1.1 | ps5debug-NG client (console protocol) | GPL-3.0-only | https://github.com/Darkatek7/ps5dbg |
| Qt 6.12 (Core, Gui, Widgets, Svg and their plugins) | desktop interface | LGPL-3.0 | https://code.qt.io |
| PySide6 / Shiboken6 6.12 | Python bindings for Qt | LGPL-3.0 | https://code.qt.io/cgit/pyside/pyside-setup.git |
| CPython 3.14 | Python runtime | PSF License 2.0 | https://github.com/python/cpython |
| OpenSSL 3.5 (libssl, libcrypto, shipped with CPython) | Python's `ssl`/`hashlib` modules | Apache-2.0 | https://github.com/openssl/openssl |
| libffi (shipped with CPython) | Python's `ctypes` | MIT | https://github.com/libffi/libffi |
| bzip2, xz/liblzma, zstd, mpdecimal (built into CPython modules) | compression, decimals | bzip2 licence, 0BSD/public domain, BSD-3-Clause, BSD-2-Clause | see CPython's licence file |
| Microsoft Visual C++ runtime (`VCRUNTIME140*.dll`, `MSVCP140*.dll`) | C++ runtime for Python and Qt | Microsoft Visual C++ Redistributable licence | https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist |
| PyInstaller 6 bootloader | starts the single-file `.exe` | GPL-2.0 with bootloader exception | https://github.com/pyinstaller/pyinstaller |

## Notes for the Windows build

- **Qt / PySide6 (LGPL-3.0).** The complete source of this program and the script that builds the `.exe`
  (`build_exe.ps1`, `PS5 Memory Dumper.spec`) are in this repository, so you can rebuild the executable with
  modified versions of Qt or PySide6. The Qt libraries are used unmodified.
- **ps5dbg (GPL-3.0).** Because the `.exe` includes ps5dbg, the whole executable is distributed under the
  GPL-3.0. The corresponding source is this repository at the release tag.
- **PyInstaller bootloader.** Its licence exception allows bundling programs under any licence.

## Credits for methods and data

- [ps5debug-NG](https://github.com/Pharaoh2k/ps5debug-NG): payload and SDK; source of the firmware 13.60 kernel
  offsets used for automatic kernel capture.
- [kdump_ps5](https://github.com/earthonion/kdump_ps5): kernel module-info size discovery and kernel request size.

## Trademarks

PlayStation and PS5 are trademarks of Sony Interactive Entertainment. This project is not affiliated with,
endorsed or sponsored by Sony. The app icon and artwork belong to the author.
