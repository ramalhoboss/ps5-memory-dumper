"""Processes page: pick a process, choose its memory regions and dump them."""
from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QCheckBox, QComboBox, QLineEdit, QSplitter, QVBoxLayout, QWidget
from ps5dbg.errors import BadStatus

from ...core.console import process_details
from ...core.dumper import (create_output_dir, dump_process, filter_regions, prot_string, readable_regions,
                            safe_name)
from ..dialogs import describe_error, show_dump_failure, show_dump_result
from ..widgets import Card, ConnectionGate, SortItem, button, human_size, label, row, table, tinted


class ProcessesPage(QWidget):
    kernel_requested = Signal()

    def __init__(self, session, settings, go_connect, parent=None):
        super().__init__(parent)
        self.session = session
        self.settings = settings
        self.previous = None  # (pid, name) pairs of the previous refresh, for the "New" tag
        self.current = None  # (pid, name) whose regions are listed
        self.maps = []
        self.pending_pid = None

        left = Card("Processes")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name or PID")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.apply_search)
        self.refresh_button = button("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        left.body.addLayout(row(self.search, self.refresh_button, stretch_at=0))
        self.procs = table(["PID", "Process", ""], stretch_column=1)
        self.procs.setSortingEnabled(True)
        self.procs.itemSelectionChanged.connect(self.process_selected)
        left.body.addWidget(self.procs, 1)
        self.proc_status = label("", muted=True)
        left.body.addWidget(self.proc_status)

        right = Card("Memory regions", "Readable regions of the selected process. Tick the ones to dump.")
        self.region_title = label("Select a process on the left.", muted=True)
        right.body.addWidget(self.region_title)
        self.name_filter = QLineEdit()
        self.name_filter.setPlaceholderText("Name contains")
        self.name_filter.setClearButtonEnabled(True)
        self.need_write = QCheckBox("Writable")
        self.need_exec = QCheckBox("Executable")
        self.max_size = QComboBox()
        for text, mib in (("Any size", None), ("Up to 16 MiB", 16), ("Up to 64 MiB", 64),
                          ("Up to 256 MiB", 256), ("Up to 1 GiB", 1024)):
            self.max_size.addItem(text, mib)
        select_matching = button("Select matching", tooltip="Tick only the regions that match these filters")
        select_all, select_none = button("Select all", "link"), button("Clear", "link")
        select_matching.clicked.connect(self.select_matching)
        select_all.clicked.connect(lambda: self.set_checks(lambda m: True))
        select_none.clicked.connect(lambda: self.set_checks(lambda m: False))
        self.name_filter.returnPressed.connect(self.select_matching)
        right.body.addLayout(row(self.name_filter, self.max_size, stretch_at=0))
        right.body.addLayout(row(self.need_write, self.need_exec, None, select_matching))
        self.regions = table(["", "Name", "Start", "End", "Size", "Prot"], stretch_column=1)
        self.regions.setSortingEnabled(True)
        self.regions.itemChanged.connect(lambda item: item.column() == 0 and self.update_selection())
        right.body.addWidget(self.regions, 1)
        self.selection_label = label("", muted=True)
        self.destination = label("", muted=True)
        self.fill_gaps = QCheckBox("Zero-fill unreadable gaps")
        self.fill_gaps.setToolTip("Keeps file offset = address − region start, so files load at the right "
                                  "address in a disassembler. Gaps are still listed in manifest.json.")
        self.fill_gaps.setChecked(settings.fill_gaps)
        self.fill_gaps.toggled.connect(lambda value: setattr(settings, "fill_gaps", value))
        self.dump_button = button("Dump selected", "primary")
        self.dump_button.clicked.connect(self.start_dump)
        right.body.addLayout(row(self.selection_label, select_all, select_none, None, self.dump_button))
        right.body.addWidget(self.fill_gaps)
        right.body.addWidget(self.destination)

        left.setMinimumWidth(370)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([370, 900])
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.addWidget(splitter)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(ConnectionGate(session, content, go_connect))

        session.connection_changed.connect(self.connection_changed)
        session.console.busy_changed.connect(self.update_buttons)
        self.update_selection()

    def showEvent(self, event):
        self.destination.setText(f"Saving to {self.settings.dumps_dir} (change it on the Dumps page)")
        super().showEvent(event)

    def connection_changed(self, connected):
        self.previous = self.current = None
        self.maps = []
        self.procs.setRowCount(0)
        self.regions.setRowCount(0)
        self.region_title.setText("Select a process on the left.")
        self.update_selection()
        if connected:
            self.refresh()

    def update_buttons(self, *_):
        busy = self.session.console.busy
        self.refresh_button.setEnabled(self.session.connected and not busy)
        self.dump_button.setEnabled(self.session.connected and not busy and bool(self.checked_maps()))

    # -- processes ---------------------------------------------------------

    def show_process(self, pid):
        """Refreshes the list and selects `pid` (used by "Dump running app")."""
        self.pending_pid = pid
        self.refresh()

    def refresh(self):
        def task(reporter, cancel):
            ps5 = self.session.ps5
            procs = sorted(ps5.procs(), key=lambda p: p.pid)
            try:
                foreground = ps5.foreground_app()
            except BadStatus:
                foreground = None
            return procs, foreground

        if self.session.console.run(task, self.show_processes):
            self.proc_status.setText("Refreshing...")

    def show_processes(self, result):
        procs, foreground = result
        current = {(p.pid, p.name) for p in procs}
        new = current - self.previous if self.previous is not None else set()
        self.previous = current
        foreground_pid = foreground.pid if foreground and foreground.pid else None
        keep = self.pending_pid or (self.current[0] if self.current else foreground_pid)
        self.pending_pid = None
        self.procs.blockSignals(True)
        self.procs.setSortingEnabled(False)
        self.procs.setRowCount(len(procs))
        for r, p in enumerate(procs):
            self.procs.setItem(r, 0, SortItem(str(p.pid), p.pid, mono=True))
            self.procs.setItem(r, 1, SortItem(p.name, p.name.lower()))
            running = p.pid == foreground_pid
            tag = "Running app" if running else "New" if (p.pid, p.name) in new else ""
            self.procs.setItem(r, 2, tinted(SortItem(tag), "accent" if running else "success"))
        self.procs.setSortingEnabled(True)
        self.procs.blockSignals(False)
        status = f"{len(procs)} processes · updated {datetime.now():%H:%M:%S}"
        if new:
            status += f" · {len(new)} new"
        self.proc_status.setText(status if procs else "No process returned. Try Refresh.")
        self.apply_search()
        if keep is not None:
            self.select_pid(keep)

    def apply_search(self):
        text = self.search.text().strip().lower()
        for r in range(self.procs.rowCount()):
            pid, name = self.procs.item(r, 0).text(), self.procs.item(r, 1).text().lower()
            self.procs.setRowHidden(r, bool(text) and text not in name and text != pid)

    def select_pid(self, pid):
        for r in range(self.procs.rowCount()):
            if self.procs.item(r, 0).text() == str(pid):
                self.procs.selectRow(r)
                self.procs.scrollToItem(self.procs.item(r, 0))
                return

    def process_selected(self):
        rows = self.procs.selectionModel().selectedRows()
        if not rows:
            return
        pid = int(self.procs.item(rows[0].row(), 0).text())
        name = self.procs.item(rows[0].row(), 1).text()
        if self.current != (pid, name):
            self.load_regions(pid, name)

    # -- regions -----------------------------------------------------------

    def load_regions(self, pid, name):
        if pid == 0:
            self.current = None
            self.maps = []
            self.regions.setRowCount(0)
            self.region_title.setText("PID 0 is the kernel. Use the Kernel page to select a range.")
            self.update_selection()
            self.kernel_requested.emit()
            return

        def task(reporter, cancel):
            return readable_regions(self.session.ps5.maps(pid))

        def done(maps):
            self.current = (pid, name)
            self.maps = maps
            self.show_regions()

        def failed(error):
            self.region_title.setText(f"Could not read the maps of {name} (PID {pid}). {describe_error(error)}")

        if self.session.console.run(task, done, failed):
            self.region_title.setText(f"Loading regions of {name} (PID {pid})...")
        else:
            self.region_title.setText("Busy: wait for the current task to finish, then select the process again.")

    def show_regions(self):
        pid, name = self.current
        self.regions.blockSignals(True)
        self.regions.setSortingEnabled(False)
        self.regions.setRowCount(len(self.maps))
        for r, m in enumerate(self.maps):
            check = SortItem("", 0)
            check.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)
            check.setCheckState(Qt.Checked)
            check.setData(Qt.UserRole, r)
            self.regions.setItem(r, 0, check)
            self.regions.setItem(r, 1, SortItem(m.name, m.name.lower()))
            self.regions.setItem(r, 2, SortItem(f"0x{m.start:x}", m.start, mono=True))
            self.regions.setItem(r, 3, SortItem(f"0x{m.end:x}", m.end, mono=True))
            self.regions.setItem(r, 4, SortItem(human_size(m.end - m.start), m.end - m.start))
            self.regions.setItem(r, 5, SortItem(prot_string(m.prot), m.prot, mono=True))
        self.regions.setSortingEnabled(True)
        self.regions.sortByColumn(2, Qt.AscendingOrder)
        self.regions.blockSignals(False)
        self.region_title.setText(f"{name} · PID {pid} · {len(self.maps)} readable regions")
        self.update_selection()

    def checked_maps(self):
        checked = []
        for r in range(self.regions.rowCount()):
            item = self.regions.item(r, 0)
            if item is not None and item.checkState() == Qt.Checked:
                checked.append(self.maps[item.data(Qt.UserRole)])
        return sorted(checked, key=lambda m: m.start)

    def set_checks(self, predicate):
        self.regions.blockSignals(True)
        for r in range(self.regions.rowCount()):
            item = self.regions.item(r, 0)
            item.setCheckState(Qt.Checked if predicate(self.maps[item.data(Qt.UserRole)]) else Qt.Unchecked)
        self.regions.blockSignals(False)
        self.regions.viewport().update()
        self.update_selection()

    def select_matching(self):
        required = 1 | (2 if self.need_write.isChecked() else 0) | (4 if self.need_exec.isChecked() else 0)
        matching = {id(m) for m in filter_regions(self.maps, required, self.name_filter.text().strip() or None,
                                                  self.max_size.currentData())}
        self.set_checks(lambda m: id(m) in matching)

    def update_selection(self):
        checked = self.checked_maps()
        total = sum(m.end - m.start for m in checked)
        self.selection_label.setText(f"{len(checked)} of {len(self.maps)} regions · {human_size(total)}"
                                     if self.maps else "")
        self.update_buttons()

    # -- dump --------------------------------------------------------------

    def start_dump(self):
        selected = self.checked_maps()
        if not selected or self.current is None:
            return
        pid, name = self.current
        total = sum(m.end - m.start for m in selected)
        root, fill_gaps, ip = self.settings.dumps_dir, self.fill_gaps.isChecked(), self.session.ip
        retries = self.settings.retries
        state = {}

        def task(reporter, cancel):
            ps5 = self.session.ps5
            folder = state["folder"] = create_output_dir(f"{safe_name(name)}_{pid}", required=total, root=root)
            reporter.log(f"Destination: {folder}")
            reporter.log(f"Reading {human_size(total)} in {len(selected)} regions of {name} (PID {pid})")
            info = dict(console=ip, process=name, **process_details(ps5, pid))
            return dump_process(ps5, pid, selected, folder, reporter, cancel, fill_gaps, info, retries)

        self.session.console.run(task, lambda document: show_dump_result(self, document, state["folder"]),
                                 lambda error: show_dump_failure(self, error, state.get("folder")),
                                 title=f"Dumping {name} (PID {pid})")
