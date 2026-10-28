"""Desktop app entry point."""
import sys

import shiboken6
from PySide6.QtWidgets import QApplication

from .. import APP_NAME
from .main_window import MainWindow
from .theme import apply_theme
from .widgets import app_icon


def main(argv=None):
    if sys.platform == "win32":
        # Own taskbar identity, so Windows shows the app icon instead of python.exe's.
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PS5Dumper.App")
    app = QApplication(sys.argv if argv is None else argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(app_icon())
    apply_theme(app)
    window = MainWindow()
    window.show()
    code = app.exec()
    # Delete the window now, while the QApplication exists: signal lambdas keep it in reference cycles,
    # and if Python frees it after the application it crashes on exit (about one run in three).
    shiboken6.delete(window)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
