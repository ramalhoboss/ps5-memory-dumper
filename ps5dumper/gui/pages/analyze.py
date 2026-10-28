"""Analyze page: compare two dumps and scan values across dumps, offline."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QLineEdit, QMessageBox, QSplitter,
                               QTabWidget, QVBoxLayout, QWidget)

from ...core.analysis import (CONDITIONS, VALUE_TYPES, compare_dumps, next_scan, scan_rows, search,
                              write_compare_csv, write_scan_csv)
from ...core.manifest import list_dumps, started_at
from ..widgets import Card, SortItem, button, label, row, table

SHOWN = 5000  # rows put in a table; CSV export has all of them
TYPE_LABELS = dict(int8="Int8 (1 byte)", int16="Int16 (2 bytes)", int32="Int32 (4 bytes)", int64="Int64 (8 bytes)",
                   float="Float", double="Double", string="Text (UTF-8)", utf16="Text (UTF-16)",
                   bytes="Bytes (hex, ?? = any)")
CONDITION_LABELS = dict(equals="Equals value", changed="Changed", unchanged="Unchanged",
                        increased="Increased", decreased="Decreased")


def _fill_dumps(combo, entries):
    keep = combo.currentData()
    combo.blockSignals(True)
    combo.clear()
    for folder, document in entries:
        combo.addItem(f"{folder.name}   ({started_at(folder, document):%Y-%m-%d %H:%M})", str(folder.resolve()))
    index = combo.findData(keep)
    combo.setCurrentIndex(index if index >= 0 else 0)
    combo.blockSignals(False)


def _value_text(value):
    if value is None:
        return "—"
    return f"{value:g}" if isinstance(value, float) else str(value)


class AnalyzePage(QWidget):
    def __init__(self, session, settings, parent=None):
        super().__init__(parent)
        self.session = session
        self.settings = settings
        self.comparison = None
        self.scan = None
        tabs = QTabWidget()
        tabs.setObjectName("Tabs")
        tabs.addTab(self.build_compare(), "Compare dumps")
        tabs.addTab(self.build_search(), "Search values")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(tabs)
        session.background.busy_changed.connect(self.update_buttons)
        self.update_buttons()

    def showEvent(self, event):
        entries = list_dumps(self.settings.dumps_dir)
        for combo in (self.before, self.after, self.scan_dump, self.next_dump):
            _fill_dumps(combo, entries)
        if self.after.currentIndex() == self.before.currentIndex() and self.after.count() > 1:
            self.before.setCurrentIndex(1)  # newest is "after", the one before it is "before"
        super().showEvent(event)

    def update_buttons(self, *_):
        idle = not self.session.background.busy
        self.compare_button.setEnabled(idle and self.before.count() > 0)
        self.compare_csv.setEnabled(idle and self.comparison is not None)
        self.first_button.setEnabled(idle and self.scan_dump.count() > 0)
        self.next_button.setEnabled(idle and self.scan is not None and bool(self.scan["addresses"]))
        self.scan_csv.setEnabled(idle and self.scan is not None)
        self.next_value.setEnabled(self.condition.currentData() == "equals")

    # -- compare -----------------------------------------------------------

    def build_compare(self):
        card = Card(None, "Dump the process, change one thing in the game, dump again, then compare. Regions are "
                          "matched by address; changes closer than 8 bytes form one range.")
        self.before, self.after = QComboBox(), QComboBox()
        self.compare_button = button("Compare", "primary")
        self.compare_button.clicked.connect(self.compare)
        card.body.addLayout(row(label("Before", muted=True), self.before, 12, label("After", muted=True), self.after,
                                12, self.compare_button, stretch_at=(1, 4)))
        self.compare_summary = label("Choose two dumps of the same process.", muted=True, wrap=True)
        card.body.addWidget(self.compare_summary)
        self.changed_regions = table(["Region", "Start", "Changed", "Ranges"], stretch_column=0)
        self.changed_regions.setSortingEnabled(True)
        self.changed_regions.itemSelectionChanged.connect(self.filter_ranges)
        self.ranges = table(["Address", "Size", "Region", "Before", "After"], stretch_column=4)
        self.ranges.setSortingEnabled(True)
        self.ranges.itemDoubleClicked.connect(lambda item: self.copy_address(self.ranges, item))
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(self.changed_regions)
        splitter.addWidget(self.ranges)
        splitter.setSizes([440, 600])
        card.body.addWidget(splitter, 1)
        self.compare_csv = button("Export CSV…")
        self.compare_csv.clicked.connect(self.export_compare)
        card.body.addLayout(row(label("Double-click a row to copy its address. Select a region to filter.",
                                      muted=True), None, self.compare_csv))
        return card

    def compare(self):
        a, b = self.before.currentData(), self.after.currentData()
        if a == b:
            QMessageBox.warning(self, "Compare", "Choose two different dumps.")
            return

        def done(result):
            self.comparison = result
            self.show_comparison()

        self.session.background.run(lambda reporter, cancel: compare_dumps(a, b, reporter=reporter, cancel=cancel),
                                    done, title="Comparing dumps")

    def show_comparison(self):
        result = self.comparison
        changed = [r for r in result["regions"] if r["changed_bytes"]]
        notes = []
        if result["unmatched_a"] or result["unmatched_b"]:
            notes.append(f"{result['unmatched_a']} region(s) only before, {result['unmatched_b']} only after")
        if result["skipped"]:
            notes.append(f"{result['skipped']} region(s) without usable data")
        if result["truncated"]:
            notes.append(f"only the first {len(result['ranges'])} ranges were kept")
        self.compare_summary.setText(
            f"{result['changed_bytes']:,} changed byte(s) in {result['range_count']:,} range(s) across "
            f"{len(changed)} of {len(result['regions'])} region(s)." + (" " + "; ".join(notes) + "." if notes else ""))
        self.changed_regions.setSortingEnabled(False)
        self.changed_regions.setRowCount(len(changed))
        for r, region in enumerate(changed):
            name = SortItem(region["name"], region["name"].lower())
            name.setData(Qt.UserRole, (region["start"], region["end"]))
            self.changed_regions.setItem(r, 0, name)
            self.changed_regions.setItem(r, 1, SortItem(f"0x{region['start']:x}", region["start"], mono=True))
            self.changed_regions.setItem(r, 2, SortItem(f"{region['changed_bytes']:,}", region["changed_bytes"]))
            self.changed_regions.setItem(r, 3, SortItem(f"{region['ranges']:,}", region["ranges"]))
        self.changed_regions.setSortingEnabled(True)
        self.changed_regions.sortByColumn(2, Qt.DescendingOrder)
        self.show_ranges(result["ranges"])
        self.update_buttons()

    def show_ranges(self, ranges):
        self.ranges.setSortingEnabled(False)
        self.ranges.setRowCount(min(len(ranges), SHOWN))
        for r, item in enumerate(ranges[:SHOWN]):
            self.ranges.setItem(r, 0, SortItem(f"0x{item['address']:x}", item["address"], mono=True))
            self.ranges.setItem(r, 1, SortItem(str(item["size"]), item["size"]))
            self.ranges.setItem(r, 2, SortItem(item["region"]))
            self.ranges.setItem(r, 3, SortItem(item["before"], mono=True))
            self.ranges.setItem(r, 4, SortItem(item["after"], mono=True))
        self.ranges.setSortingEnabled(True)

    def filter_ranges(self):
        rows = self.changed_regions.selectionModel().selectedRows()
        if not rows or self.comparison is None:
            return
        start, end = self.changed_regions.item(rows[0].row(), 0).data(Qt.UserRole)
        self.show_ranges([r for r in self.comparison["ranges"] if start <= r["address"] < end])

    def export_compare(self):
        path = self.ask_csv("comparison.csv")
        if path:
            write_compare_csv(self.comparison, path)
            self.session.background.log.emit(f"Comparison saved to {path}", "ok")

    # -- search ------------------------------------------------------------

    def build_search(self):
        card = Card(None, "First scan finds a value in one dump. Next scan keeps the addresses whose value in a later "
                          "dump changed the way you expect (e.g. ammo 30 → 29: first scan 30, next scan 'Decreased' "
                          "or 'Equals 29').")
        self.scan_dump, self.kind, self.value = QComboBox(), QComboBox(), QLineEdit()
        for kind in VALUE_TYPES:
            self.kind.addItem(TYPE_LABELS[kind], kind)
        self.kind.setCurrentIndex(VALUE_TYPES.index("int32"))
        self.value.setPlaceholderText("Value, e.g. 30, 0x1E, 1.5 or 48 8B ?? 05")
        self.value.returnPressed.connect(self.first_scan)
        self.aligned = QCheckBox("Aligned")
        self.aligned.setChecked(True)
        self.aligned.setToolTip("Numbers only at addresses that are a multiple of their size (much fewer false hits)")
        self.writable = QCheckBox("Writable regions only")
        self.writable.setChecked(True)
        self.writable.setToolTip("Game state (ammo, health, money) lives in writable memory")
        self.first_button = button("First scan", "primary")
        self.first_button.clicked.connect(self.first_scan)
        card.body.addLayout(row(label("Dump", muted=True), self.scan_dump, self.kind, self.value, self.first_button,
                                stretch_at=1))
        card.body.addLayout(row(self.aligned, self.writable, None))
        self.next_dump, self.condition, self.next_value = QComboBox(), QComboBox(), QLineEdit()
        for condition in CONDITIONS:
            self.condition.addItem(CONDITION_LABELS[condition], condition)
        self.condition.setCurrentIndex(CONDITIONS.index("changed"))
        self.condition.currentIndexChanged.connect(self.update_buttons)
        self.next_value.setPlaceholderText("New value")
        self.next_value.returnPressed.connect(self.next_scan)
        self.next_button = button("Next scan")
        self.next_button.clicked.connect(self.next_scan)
        reset = button("Reset", "link")
        reset.clicked.connect(self.reset_scan)
        card.body.addLayout(row(label("Then", muted=True), self.next_dump, self.condition, self.next_value,
                                self.next_button, reset, stretch_at=1))
        self.scan_summary = label("No scan yet.", muted=True, wrap=True)
        card.body.addWidget(self.scan_summary)
        self.results = table(["Address", "Region", "Previous", "Current"], stretch_column=1)
        self.results.setSortingEnabled(True)
        self.results.itemDoubleClicked.connect(lambda item: self.copy_address(self.results, item))
        card.body.addWidget(self.results, 1)
        self.scan_csv = button("Export CSV…")
        self.scan_csv.clicked.connect(self.export_scan)
        card.body.addLayout(row(label("Double-click a row to copy its address.", muted=True), None, self.scan_csv))
        return card

    def first_scan(self):
        folder, kind, text = self.scan_dump.currentData(), self.kind.currentData(), self.value.text()
        aligned, writable = self.aligned.isChecked(), self.writable.isChecked()

        def task(reporter, cancel):
            scan = search(folder, kind, text, aligned, writable, reporter=reporter, cancel=cancel)
            return scan, scan_rows(scan, SHOWN)

        self.session.background.run(task, self.show_scan, title="First scan")

    def next_scan(self):
        scan, folder = self.scan, self.next_dump.currentData()
        condition, text = self.condition.currentData(), self.next_value.text()
        if folder == scan["folder"] and condition != "equals":
            QMessageBox.warning(self, "Next scan", "Choose a later dump to compare with; the scan already uses this one.")
            return

        def task(reporter, cancel):
            result = next_scan(scan, folder, condition, text, reporter, cancel)
            return result, scan_rows(result, SHOWN)

        self.session.background.run(task, self.show_scan, title="Next scan")

    def show_scan(self, result):
        self.scan, rows = result
        scan = self.scan
        count = len(scan["addresses"])
        name = Path(scan["folder"]).name
        text = f"{count:,} address(es) in {name} · {TYPE_LABELS[scan['kind']]}"
        if scan["truncated"]:
            text += " · stopped at the result limit: use a more specific value or a next scan"
        if count > SHOWN:
            text += f" · showing the first {SHOWN:,}"
        if scan.get("skipped"):
            text += f" · {scan['skipped']} region(s) without usable data"
        self.scan_summary.setText(text)
        self.results.setSortingEnabled(False)
        self.results.setRowCount(len(rows))
        for r, (address, region, old, new) in enumerate(rows):
            self.results.setItem(r, 0, SortItem(f"0x{address:x}", address, mono=True))
            self.results.setItem(r, 1, SortItem(region))
            self.results.setItem(r, 2, SortItem(_value_text(old), old if isinstance(old, (int, float)) else str(old),
                                                mono=True))
            self.results.setItem(r, 3, SortItem(_value_text(new), new if isinstance(new, (int, float)) else str(new),
                                                mono=True))
        self.results.setSortingEnabled(True)
        index = self.next_dump.findData(scan["folder"])
        if index > 0:
            self.next_dump.setCurrentIndex(index - 1)  # the list is newest first: suggest the next newer dump
        self.update_buttons()

    def reset_scan(self):
        self.scan = None
        self.results.setRowCount(0)
        self.scan_summary.setText("No scan yet.")
        self.update_buttons()

    def export_scan(self):
        path = self.ask_csv("scan.csv")
        if path:
            self.session.background.run(lambda reporter, cancel: write_scan_csv(self.scan, path),
                                        lambda _: self.session.background.log.emit(f"Scan saved to {path}", "ok"),
                                        title="Exporting scan")

    # -- shared ------------------------------------------------------------

    def ask_csv(self, name):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", str(self.settings.dumps_dir / name),
                                              "CSV files (*.csv)", options=QFileDialog.DontConfirmOverwrite)
        if path and Path(path).exists():
            QMessageBox.warning(self, "File exists", "Existing files are never overwritten. Choose a new name.")
            return None
        return path or None

    def copy_address(self, widget, item):
        address = widget.item(item.row(), 0).text()
        QApplication.clipboard().setText(address)
        self.session.background.log.emit(f"Copied {address}", "info")

