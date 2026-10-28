"""Message boxes and human-readable error text."""
import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtWidgets import QMessageBox
from ps5dbg.errors import BadStatus, ConnectionLost

from ..core.dumper import ResumeError, summarize
from ..core.manifest import MANIFEST_NAME
from ..core.reporting import DumpCancelled
from .widgets import human_duration, human_size


def describe_error(error):
    if isinstance(error, BadStatus):
        return (f"The payload answered but refused the operation: {error}.\n\n"
                "Check the address range and that the payload supports this command. "
                "This does not mean the IP address is wrong.")
    if isinstance(error, ConnectionLost):
        return (f"{error}.\n\nCheck that the console is on, the ps5debug payload is running "
                "and the PC is on the same network.")
    if isinstance(error, DumpCancelled):
        return "Cancelled by the user. Data already written is kept; you can resume it from the Dumps page."
    if isinstance(error, ResumeError):
        return f"This dump cannot be resumed: {error}."
    return f"{type(error).__name__}: {error}"


def open_folder(path):
    path = Path(path)
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606 - opens Explorer on a folder we created
    else:
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(path)])


def _with_open_button(box, folder):
    open_button = box.addButton("Open folder", QMessageBox.ActionRole) if folder else None
    box.addButton(QMessageBox.Close)
    box.exec()
    if open_button is not None and box.clickedButton() is open_button:
        open_folder(folder)


def show_dump_result(parent, document, folder):
    summary = summarize(document)
    lines = [f"Saved {human_size(summary['bytes'])} from {summary['regions']} region(s)"
             + (f" in {human_duration(summary['seconds'])}." if summary["seconds"] else ".")]
    if summary["gaps"]:
        lines.append(f"{summary['gaps']} unreadable gap(s), {human_size(summary['gap_bytes'])} in total "
                     f"(listed in {MANIFEST_NAME}).")
    if document.get("type") == "kernel":
        lines.append("This is a kernel range, not automatically the full kernel nor an ELF.")
    complete = summary["bytes"] and not summary["incomplete"]
    box = QMessageBox(QMessageBox.Information if complete else QMessageBox.Warning,
                      "Dump complete" if complete else "Dump finished with gaps", "\n\n".join(lines), parent=parent)
    box.setInformativeText(str(folder))
    _with_open_button(box, folder)


def show_dump_failure(parent, error, folder):
    cancelled = isinstance(error, DumpCancelled)
    box = QMessageBox(QMessageBox.Information if cancelled else QMessageBox.Critical,
                      "Dump cancelled" if cancelled else "Dump failed", describe_error(error), parent=parent)
    if folder:
        box.setInformativeText(f"Partial data and {MANIFEST_NAME} are in:\n{folder}")
    _with_open_button(box, folder)


def confirm(parent, title, text):
    return QMessageBox.question(parent, title, text) == QMessageBox.Yes
