"""Tools page: offline work on dumped files (concatenation, zero-run segmentation)."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QLineEdit, QListWidget, QListWidgetItem,
                               QMessageBox, QSpinBox, QVBoxLayout, QWidget)

from ...core.files import concatenate_files, list_bin_files
from ...core.segment import restore, segment
from ..dialogs import open_folder
from ..widgets import Card, button, human_size, row


def _path_field(placeholder):
    field = QLineEdit()
    field.setPlaceholderText(placeholder)
    field.setClearButtonEnabled(True)
    return field


class ToolsPage(QWidget):
    def __init__(self, session, settings, parent=None):
        super().__init__(parent)
        self.session = session
        self.settings = settings
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        concat = Card("Concatenate .bin files",
                      "Joins files byte for byte in the order below (drag to reorder). Addresses and gaps are "
                      "not rebuilt: for an address-correct image use Dumps → Merge into flat image.")
        self.concat_folder = _path_field("Folder with .bin files")
        self.concat_folder.returnPressed.connect(self.load_concat_folder)
        browse_folder = button("Browse…")
        browse_folder.clicked.connect(self.browse_concat_folder)
        concat.body.addLayout(row(self.concat_folder, browse_folder, stretch_at=0))
        self.files = QListWidget()
        self.files.setObjectName("FileList")
        self.files.setDragDropMode(QAbstractItemView.InternalMove)
        self.files.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.files.setMinimumHeight(140)
        concat.body.addWidget(self.files, 1)
        remove = button("Remove selected")
        remove.clicked.connect(lambda: [self.files.takeItem(self.files.row(i)) for i in self.files.selectedItems()])
        self.concat_output = _path_field("Output file (new)")
        browse_output = button("Browse…")
        browse_output.clicked.connect(lambda: self.browse_save(self.concat_output, "Concatenated file"))
        self.concat_button = button("Concatenate", "primary")
        self.concat_button.clicked.connect(self.concatenate)
        concat.body.addLayout(row(remove, 16, self.concat_output, browse_output, self.concat_button, stretch_at=2))
        layout.addWidget(concat, 1)

        segments = Card("Split by zero runs / restore",
                        "Stores a large snapshot as data segments plus segments.json, skipping long runs of zeros. "
                        "Restore rebuilds the exact original and verifies every SHA-256.")
        self.segment_source = _path_field("Snapshot file to split")
        browse_source = button("Browse…")
        browse_source.clicked.connect(self.browse_segment_source)
        self.min_run = QSpinBox()
        self.min_run.setRange(1, 1024 * 1024)
        self.min_run.setValue(64)
        self.min_run.setSuffix(" KiB zero run")
        self.base = _path_field("Base (optional)")
        self.base.setToolTip("Address of the first byte, e.g. 0x400000; recorded in segments.json")
        self.base.setFixedWidth(170)
        self.split_button = button("Split", "primary")
        self.split_button.clicked.connect(self.split)
        segments.body.addLayout(row(self.segment_source, browse_source, self.min_run, self.base,
                                    self.split_button, stretch_at=0))
        self.manifest = _path_field("segments.json to restore")
        browse_manifest = button("Browse…")
        browse_manifest.clicked.connect(self.browse_manifest)
        self.restore_button = button("Restore…", "primary")
        self.restore_button.clicked.connect(self.restore)
        segments.body.addLayout(row(self.manifest, browse_manifest, self.restore_button, stretch_at=0))
        layout.addWidget(segments)

        session.background.busy_changed.connect(self.update_buttons)
        self.update_buttons()

    def update_buttons(self, *_):
        idle = not self.session.background.busy
        for widget in (self.concat_button, self.split_button, self.restore_button):
            widget.setEnabled(idle)

    def run(self, task, title, done_text):
        def done(result):
            QMessageBox.information(self, title, done_text(result))
        self.session.background.run(task, done, title=title)

    # -- concatenation -----------------------------------------------------

    def browse_concat_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Folder with .bin files", str(self.settings.dumps_dir))
        if path:
            self.concat_folder.setText(path)
            self.load_concat_folder()

    def load_concat_folder(self):
        self.files.clear()
        try:
            files = list_bin_files(self.concat_folder.text().strip())
        except ValueError as error:
            QMessageBox.warning(self, "Concatenate", str(error))
            return
        for path in files:
            item = QListWidgetItem(f"{path.name}    ({human_size(path.stat().st_size)})")
            item.setData(Qt.UserRole, str(path))
            self.files.addItem(item)
        folder = Path(self.concat_folder.text().strip()).resolve()
        if not self.concat_output.text().strip():
            self.concat_output.setText(str(folder.parent / f"{folder.name}_concatenated.bin"))

    def browse_save(self, field, title):
        path, _ = QFileDialog.getSaveFileName(self, title, field.text() or str(self.settings.dumps_dir),
                                              "Binary files (*.bin);;All files (*)",
                                              options=QFileDialog.DontConfirmOverwrite)
        if path:
            field.setText(path)

    def concatenate(self):
        files = [self.files.item(i).data(Qt.UserRole) for i in range(self.files.count())]
        output = self.concat_output.text().strip()
        if not files or not output:
            QMessageBox.warning(self, "Concatenate", "Choose a folder with .bin files and an output file.")
            return
        self.run(lambda reporter, cancel: concatenate_files(files, output, reporter, cancel), "Concatenating files",
                 lambda result: f"Wrote {human_size(result['bytes'])} to\n{result['destination']}\n\n"
                                f"SHA-256: {result['sha256']}")

    # -- segmentation ------------------------------------------------------

    def browse_segment_source(self):
        path, _ = QFileDialog.getOpenFileName(self, "Snapshot to split", str(self.settings.dumps_dir))
        if path:
            self.segment_source.setText(path)

    def browse_manifest(self):
        path, _ = QFileDialog.getOpenFileName(self, "segments.json", str(self.settings.dumps_dir),
                                              "Segment manifest (segments.json);;JSON (*.json)")
        if path:
            self.manifest.setText(path)

    def split(self):
        source = Path(self.segment_source.text().strip())
        if not source.is_file():
            QMessageBox.warning(self, "Split", "Choose an existing snapshot file.")
            return
        try:
            base = int(self.base.text().strip(), 0) if self.base.text().strip() else None
        except ValueError:
            QMessageBox.warning(self, "Split", "The base address must be a number such as 0x400000.")
            return
        output = source.with_name(source.name + ".segments")
        minimum = self.min_run.value() * 1024

        def done(document):
            box = QMessageBox(QMessageBox.Information, "Split complete",
                              f"Stored {human_size(document['stored_bytes'])}, skipped "
                              f"{human_size(document['omitted_zero_bytes'])} of zeros in "
                              f"{len(document['segments'])} segments.\n\n{output}", parent=self)
            open_button = box.addButton("Open folder", QMessageBox.ActionRole)
            box.addButton(QMessageBox.Close)
            box.exec()
            if box.clickedButton() is open_button:
                open_folder(output)

        self.session.background.run(lambda reporter, cancel: segment(source, output, minimum, base), done,
                                    title="Splitting snapshot")

    def restore(self):
        manifest = Path(self.manifest.text().strip())
        if not manifest.is_file():
            QMessageBox.warning(self, "Restore", "Choose an existing segments.json.")
            return
        destination, _ = QFileDialog.getSaveFileName(self, "Restored file", str(manifest.parent.parent / "restored.bin"),
                                                     options=QFileDialog.DontConfirmOverwrite)
        if not destination:
            return
        self.run(lambda reporter, cancel: restore(manifest, destination), "Restoring snapshot",
                 lambda size: f"Restored and verified {human_size(size)}:\n{destination}")
