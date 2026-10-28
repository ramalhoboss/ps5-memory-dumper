"""Dumps page: browse saved dumps, resume them, and export regions as a flat image or an ELF."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QFileDialog, QMessageBox, QSplitter, QVBoxLayout, QWidget

from ...core.dumper import prot_string, resume_dump
from ...core.files import MAX_MERGE_SPAN, export_elf, merge_regions
from ...core.manifest import dump_status, list_dumps, process_name, started_at
from ...core.reader import MIB
from ..dialogs import confirm, open_folder, show_dump_failure, show_dump_result
from ..widgets import Card, SortItem, button, human_size, label, row, table, tinted

STATUS_TONES = dict(complete="success", incomplete="warning", cancelled="warning", failed="danger",
                    running="accent", unreadable="danger")
RESUMABLE = ("incomplete", "cancelled", "failed", "running")
ERROR_LABELS = dict(DumpCancelled="cancelled", ConnectionLost="connection lost", ProtocolError="connection lost",
                    BadStatus="refused", NotMapped="not mapped", KeyboardInterrupt="interrupted")
LARGE_IMAGE = 1024 * MIB


def _saved_dialog(parent, title, text, path):
    box = QMessageBox(QMessageBox.Information, title, text, parent=parent)
    open_button = box.addButton("Open folder", QMessageBox.ActionRole)
    box.addButton(QMessageBox.Close)
    box.exec()
    if box.clickedButton() is open_button:
        open_folder(Path(path).parent)


def _ask_new_file(parent, title, default, file_filter):
    path, _ = QFileDialog.getSaveFileName(parent, title, str(default), file_filter,
                                          options=QFileDialog.DontConfirmOverwrite)
    if path and Path(path).exists():
        QMessageBox.warning(parent, "File exists", "Existing files are never overwritten. Choose a new name.")
        return None
    return path or None


class DumpsPage(QWidget):
    def __init__(self, session, settings, parent=None):
        super().__init__(parent)
        self.session = session
        self.settings = settings
        self.entries = []
        self.selected = None  # (folder, document)

        top = Card("Saved dumps", "Cancelled, failed or incomplete dumps can be resumed while the process is "
                                  "still running.")
        self.root_label = label("", name="Value", selectable=True)
        change, open_root, refresh = button("Change folder…"), button("Open folder"), button("Refresh")
        self.resume_button = button("Resume dump", "primary",
                                    "Continue the selected dump: complete regions are kept, interrupted ones "
                                    "continue where they stopped")
        change.clicked.connect(self.change_root)
        open_root.clicked.connect(lambda: self.settings.dumps_dir.is_dir() and open_folder(self.settings.dumps_dir))
        refresh.clicked.connect(self.refresh)
        self.resume_button.clicked.connect(self.resume)
        top.body.addLayout(row(self.root_label, None, change, open_root, refresh, 12, self.resume_button,
                               stretch_at=0))
        self.dumps = table(["Dump", "Type", "Process", "Started", "Data", "Regions", "Status"], stretch_column=0)
        self.dumps.setSortingEnabled(True)
        self.dumps.sortByColumn(3, Qt.DescendingOrder)  # newest first
        self.dumps.itemSelectionChanged.connect(self.dump_selected)
        self.dumps.setMinimumHeight(130)
        top.body.addWidget(self.dumps, 1)

        detail = Card("Regions", "Tick regions to export them by address: a flat image (holes become zeros) or an "
                                 "ELF with one segment per region, for Ghidra/IDA.")
        self.detail_title = label("Select a dump above.", muted=True)
        detail.body.addWidget(self.detail_title)
        self.regions = table(["", "Name", "Start", "End", "Data", "Prot", "Status"], stretch_column=1)
        self.regions.setSortingEnabled(True)
        self.regions.itemChanged.connect(lambda item: item.column() == 0 and self.update_buttons())
        self.regions.setMinimumHeight(130)
        detail.body.addWidget(self.regions, 1)
        self.open_dump = button("Open dump folder")
        self.select_exec = button("Executable", "link", "Tick the executable regions (r-x) and the contiguous "
                                                        "regions after them that share their name")
        select_all, select_none = button("All", "link"), button("None", "link")
        self.elf_button = button("Export ELF…", tooltip="One PT_LOAD segment per ticked region at its address "
                                                        "(ET_EXEC; use the command line for ET_CORE)")
        self.merge_button = button("Merge into flat image…", "primary")
        self.open_dump.clicked.connect(lambda: self.selected and open_folder(self.selected[0]))
        self.select_exec.clicked.connect(self.select_executable)
        select_all.clicked.connect(lambda: self.set_checks(lambda r: True))
        select_none.clicked.connect(lambda: self.set_checks(lambda r: False))
        self.elf_button.clicked.connect(self.export_elf)
        self.merge_button.clicked.connect(self.merge)
        self.merge_info = label("", muted=True)
        detail.body.addLayout(row(self.open_dump, self.select_exec, select_all, select_none, None,
                                  self.merge_info, self.elf_button, self.merge_button))

        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(top)
        splitter.addWidget(detail)
        splitter.setSizes([330, 400])
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)
        for signal in (session.background.busy_changed, session.console.busy_changed, session.connection_changed):
            signal.connect(self.update_buttons)
        self.update_buttons()

    def showEvent(self, event):
        self.refresh()
        super().showEvent(event)

    def change_root(self):
        path = QFileDialog.getExistingDirectory(self, "Dumps folder", str(self.settings.dumps_dir))
        if path:
            self.settings.dumps_dir = Path(path)
            self.refresh()

    def refresh(self):
        root = self.settings.dumps_dir
        self.root_label.setText(str(root))
        keep = self.selected[0] if self.selected else None
        self.entries = list_dumps(root)
        self.dumps.blockSignals(True)
        self.dumps.clearSelection()  # so re-selecting the same row below notifies dump_selected
        self.dumps.setSortingEnabled(False)
        self.dumps.setRowCount(len(self.entries))
        for r, (folder, document) in enumerate(self.entries):
            started = started_at(folder, document)
            status = dump_status(document)
            name = SortItem(folder.name, folder.name.lower())
            name.setData(Qt.UserRole, r)
            self.dumps.setItem(r, 0, name)
            self.dumps.setItem(r, 1, SortItem(document.get("type", "?")))
            process = process_name(folder, document)
            pid = document.get("pid")
            self.dumps.setItem(r, 2, SortItem(f"{process} ({pid})" if pid else process, process.lower()))
            self.dumps.setItem(r, 3, SortItem(f"{started:%Y-%m-%d %H:%M}", started.timestamp()))
            self.dumps.setItem(r, 4, SortItem(human_size(document.get("bytes", 0)), document.get("bytes", 0)))
            self.dumps.setItem(r, 5, SortItem(str(len(document["regions"])), len(document["regions"])))
            self.dumps.setItem(r, 6, tinted(SortItem(status), STATUS_TONES.get(status, "muted")))
        self.dumps.setSortingEnabled(True)
        self.dumps.blockSignals(False)
        self.selected = None
        self.regions.setRowCount(0)
        self.detail_title.setText("Select a dump above." if self.entries else
                                  "No dumps yet. Dumps you make from Processes or Kernel appear here.")
        for r in range(self.dumps.rowCount()):
            if keep is not None and self.entries[self.dumps.item(r, 0).data(Qt.UserRole)][0] == keep:
                self.dumps.selectRow(r)
        self.update_buttons()

    def dump_selected(self):
        rows = self.dumps.selectionModel().selectedRows()
        if not rows:
            return
        self.selected = folder, document = self.entries[self.dumps.item(rows[0].row(), 0).data(Qt.UserRole)]
        regions = document["regions"]
        self.regions.blockSignals(True)
        self.regions.setSortingEnabled(False)
        self.regions.setRowCount(len(regions))
        for r, region in enumerate(regions):
            start, end = int(region["start"], 16), int(region["end"], 16)
            check = SortItem("", 0)
            check.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)
            check.setCheckState(Qt.Unchecked)
            check.setData(Qt.UserRole, r)
            self.regions.setItem(r, 0, check)
            self.regions.setItem(r, 1, SortItem(region.get("name", ""), region.get("name", "").lower()))
            self.regions.setItem(r, 2, SortItem(f"0x{start:x}", start, mono=True))
            self.regions.setItem(r, 3, SortItem(f"0x{end:x}", end, mono=True))
            self.regions.setItem(r, 4, SortItem(human_size(region.get("bytes", 0)), region.get("bytes", 0)))
            self.regions.setItem(r, 5, SortItem(prot_string(region.get("prot")), region.get("prot") or 0, mono=True))
            gaps = region.get("gaps") or []
            if region.get("errors"):
                kind = region["errors"][-1].get("type", "")
                text, tone = ERROR_LABELS.get(kind, kind or "error"), "warning" if kind == "DumpCancelled" else "danger"
            elif not region.get("file"):
                text, tone = "no data", "danger"
            elif gaps:
                text, tone = f"{len(gaps)} gap(s)", "warning"
            else:
                text, tone = "complete", "success"
            self.regions.setItem(r, 6, tinted(SortItem(text), tone))
        self.regions.setSortingEnabled(True)
        self.regions.sortByColumn(2, Qt.AscendingOrder)
        self.regions.blockSignals(False)
        gap_note = "gaps zero-filled" if document.get("gap_fill") == "zeros" else "gaps not padded"
        resumed = f" · resumed {len(document['resumed'])}×" if document.get("resumed") else ""
        self.detail_title.setText(f"{folder.name} · {len(regions)} regions · {gap_note}{resumed}")
        self.update_buttons()

    def checked_regions(self):
        if self.selected is None:
            return []
        regions = self.selected[1]["regions"]
        return [regions[self.regions.item(r, 0).data(Qt.UserRole)] for r in range(self.regions.rowCount())
                if self.regions.item(r, 0).checkState() == Qt.Checked]

    def set_checks(self, predicate):
        if self.selected is None:
            return
        regions = self.selected[1]["regions"]
        self.regions.blockSignals(True)
        for r in range(self.regions.rowCount()):
            item = self.regions.item(r, 0)
            item.setCheckState(Qt.Checked if predicate(regions[item.data(Qt.UserRole)]) else Qt.Unchecked)
        self.regions.blockSignals(False)
        self.regions.viewport().update()
        self.update_buttons()

    def select_executable(self):
        """The main executable usually spans r-x code followed by contiguous r--/rw- regions of the same name."""
        if self.selected is None:
            return
        ordered = sorted(self.selected[1]["regions"], key=lambda r: int(r["start"], 16))
        chosen = set()
        previous = None
        for region in ordered:
            continues = (previous is not None and id(previous) in chosen
                         and region.get("name") == previous.get("name")
                         and int(region["start"], 16) == int(previous["end"], 16))
            if region.get("file") and ((region.get("prot") or 0) & 4 or continues):
                chosen.add(id(region))
            previous = region
        self.set_checks(lambda r: id(r) in chosen)

    def update_buttons(self, *_):
        checked = self.checked_regions()
        if checked:
            start = min(int(r["start"], 16) for r in checked)
            end = max(int(r["end"], 16) for r in checked)
            self.merge_info.setText(f"{len(checked)} region(s) · 0x{start:x}-0x{end:x}")
        else:
            self.merge_info.setText("")
        idle = not self.session.background.busy
        self.merge_button.setEnabled(bool(checked) and idle)
        self.elf_button.setEnabled(bool(checked) and idle)
        self.open_dump.setEnabled(self.selected is not None)
        self.select_exec.setEnabled(self.selected is not None)
        resumable = (self.selected is not None and self.selected[1].get("type") in ("process", "kernel")
                     and dump_status(self.selected[1]) in RESUMABLE)
        self.resume_button.setEnabled(resumable and self.session.connected and not self.session.console.busy)
        self.resume_button.setToolTip("Connect to the console first" if resumable and not self.session.connected
                                      else "Continue the selected dump: complete regions are kept, interrupted "
                                           "ones continue where they stopped")

    # -- actions -----------------------------------------------------------

    def resume(self):
        folder, document = self.selected
        status = dump_status(document)
        box = QMessageBox(QMessageBox.Question, "Resume dump",
                          f"Resume {folder.name}?\n\nComplete regions are kept, interrupted regions continue where "
                          "they stopped, and regions never started are read. The process must still be running "
                          "with the same PID (for the kernel: the console must not have restarted).", parent=self)
        retry = QCheckBox("Also read unreadable gaps again")
        retry.setChecked(status == "incomplete")
        box.setCheckBox(retry)
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        if box.exec() != QMessageBox.Yes:
            return
        retry_gaps, retries = retry.isChecked(), self.settings.retries

        def task(reporter, cancel):
            return resume_dump(self.session.ps5, folder, reporter, cancel, retry_gaps, retries)

        def done(result):
            show_dump_result(self, result, folder)
            self.refresh()

        def failed(error):
            show_dump_failure(self, error, folder)
            self.refresh()

        self.session.console.run(task, done, failed, title=f"Resuming {folder.name}")

    def export_elf(self):
        folder, _ = self.selected
        regions = self.checked_regions()
        start = min(int(r["start"], 16) for r in regions)
        path = _ask_new_file(self, "Export ELF", folder.parent / f"{folder.name}_{start:x}.elf",
                             "ELF files (*.elf);;All files (*)")
        if not path:
            return
        self.session.background.run(
            lambda reporter, cancel: export_elf(folder, regions, path, "exec", reporter, cancel),
            lambda result: _saved_dialog(self, "ELF exported",
                                         f"{result['destination']}\n\n{result['segments']} segment(s) at their real "
                                         f"addresses (first: {result['start']}). Open it in Ghidra or IDA as an "
                                         f"x86-64 ELF.\nSHA-256: {result['sha256']}", result["destination"]),
            title="Exporting ELF")

    def merge(self):
        folder, _ = self.selected
        regions = self.checked_regions()
        start = min(int(r["start"], 16) for r in regions)
        end = max(int(r["end"], 16) for r in regions)
        span = end - start
        if span > LARGE_IMAGE and not confirm(self, "Large image",
                                              f"The flat image spans {human_size(span)} because the regions are "
                                              "far apart. Holes are written as zeros. Continue?"):
            return
        path = _ask_new_file(self, "Save flat image", folder / f"merged_{start:x}-{end:x}.bin",
                             "Binary files (*.bin);;All files (*)")
        if not path:
            return
        self.session.background.run(
            lambda reporter, cancel: merge_regions(folder, regions, path, max(MAX_MERGE_SPAN, span), reporter, cancel),
            lambda result: _saved_dialog(self, "Flat image saved",
                                         f"{result['destination']}\n\nLoad it at base address {result['start']} "
                                         f"in your disassembler.\nSHA-256: {result['sha256']}", result["destination"]),
            title="Merging regions")
