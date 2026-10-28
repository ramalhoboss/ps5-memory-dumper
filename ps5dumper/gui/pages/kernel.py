"""Kernel capture: guided full image or an explicit manual range."""
from PySide6.QtWidgets import (QCheckBox, QComboBox, QGridLayout, QLineEdit,
                               QScrollArea, QSpinBox, QVBoxLayout, QWidget)

from ...core.dumper import (HYPERVISOR_WARNING, KERNEL_ADDRESS_MIN, KERNEL_LIMIT, create_output_dir, dump_kernel,
                            kernel_data_base, validate_kernel_range)
from ...core.reader import MIB
from ..dialogs import confirm, describe_error, show_dump_failure, show_dump_result
from ..theme import COLORS
from ..widgets import Card, ConnectionGate, button, human_size, label, row


class KernelPage(QWidget):
    def __init__(self, session, settings, go_connect, parent=None):
        super().__init__(parent)
        self.session, self.settings = session, settings
        self.data_base = None

        hypervisor = Card("Disable the hypervisor first", tone="warning")
        hypervisor.body.addWidget(label(
            HYPERVISOR_WARNING + " This applies to the full kernel and to manual ranges.", wrap=True))
        guide = Card("Capture the kernel", "Full image capture for firmware 13.60 with ps5debug-NG.")
        guide.body.addWidget(label(
            "1. On the PS5, run the jailbreak, then disable the hypervisor (hypervisor bypass), "
            "then load ps5debug-NG.\n"
            "2. Connect to the console on the Connection page. Keep the console running during capture.\n"
            "3. Choose Full kernel below and start the dump. The app detects the start and exact size.\n"
            "4. Keep the .bin and manifest.json together. Review the result on the Dumps page.",
            muted=True, wrap=True))

        capture = Card("Capture settings")
        self.mode = QComboBox()
        self.mode.addItem("Full kernel — automatic (13.60)")
        self.mode.addItem("Manual range — advanced")
        capture.body.addLayout(row(label("Mode", muted=True), self.mode, stretch_at=1))
        self.mode_hint = label("", muted=True, wrap=True)
        capture.body.addWidget(self.mode_hint)
        self.manual = QWidget()
        grid = QGridLayout(self.manual)
        grid.setContentsMargins(0, 6, 0, 6)
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(10)
        self.base = label("Not read", name="Value", selectable=True)
        self.read_base = button("Read .data base", "link")
        self.read_base.clicked.connect(self.fetch_base)
        self.start = QLineEdit()
        self.start.setPlaceholderText("Leave blank for .data base, or enter 0xffffffff…")
        self.start.textChanged.connect(self.validate)
        self.size = QSpinBox()
        self.size.setRange(1, KERNEL_LIMIT // MIB)
        self.size.setValue(1)
        self.size.valueChanged.connect(self.validate)
        self.units = QComboBox()
        for name, factor in (("MiB", MIB), ("KiB", 1024), ("Bytes", 1)):
            self.units.addItem(name, factor)
        self.units.currentIndexChanged.connect(self.change_units)
        self.recover = QCheckBox("Recover refused pages (experimental)")
        self.recover.setToolTip("Retries refused blocks in smaller pieces and records gaps. "
                                "This does not protect the console from invalid kernel addresses.")
        grid.addWidget(label(".data base", muted=True), 0, 0)
        grid.addLayout(row(self.base, self.read_base, None), 0, 1)
        grid.addWidget(label("Start address", muted=True), 1, 0)
        grid.addWidget(self.start, 1, 1)
        grid.addWidget(label("Size", muted=True), 2, 0)
        grid.addLayout(row(self.size, self.units, None), 2, 1)
        grid.addWidget(label("Recovery", muted=True), 3, 0)
        grid.addWidget(self.recover, 3, 1)
        grid.setColumnStretch(1, 1)
        capture.body.addWidget(self.manual)
        self.summary = label("", name="Value", wrap=True, selectable=True)
        capture.body.addWidget(self.summary)
        self.destination = label("", muted=True, wrap=True, selectable=True)
        capture.body.addWidget(self.destination)
        self.error = label("", wrap=True)
        self.error.setStyleSheet(f"color: {COLORS['danger']};")
        capture.body.addWidget(self.error)
        self.dump_button = button("Dump full kernel", "primary")
        self.dump_button.clicked.connect(self.start_dump)
        capture.body.addLayout(row(None, self.dump_button))

        notes = Card("Understand the result")
        notes.body.addWidget(label(
            "A successful full capture matches the detected module size, with no errors or gaps. "
            "The manifest records the addresses, byte count and SHA-256. Output is raw memory (.bin).\n\n"
            "Other dumpers may include extra bytes to finish a 16 KiB block. A small size difference "
            "alone does not indicate missing data. Live data can differ between captures.\n\n"
            "If the connection drops, capture stops and keeps the bytes received. Reconnect before "
            "resuming from Dumps; start a new dump if the console restarted.", muted=True, wrap=True))
        content = QWidget()
        body = QVBoxLayout(content)
        body.setContentsMargins(0, 0, 8, 0)
        body.setSpacing(16)
        for card in (hypervisor, guide, capture, notes):
            body.addWidget(card)
        body.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setWidget(content)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.gate = ConnectionGate(session, scroll, go_connect)
        self.gate.setCurrentIndex(1 if session.connected else 0)
        layout.addWidget(self.gate)
        self.mode.currentIndexChanged.connect(self.validate)
        session.console.busy_changed.connect(self.validate)
        session.connection_changed.connect(self.reset_base)
        session.info_changed.connect(self.validate)
        self.validate()

    def is_automatic(self):
        return self.mode.currentIndex() == 0

    def amount_bytes(self):
        return self.size.value() * self.units.currentData()

    def change_units(self):
        self.size.setMaximum(KERNEL_LIMIT // self.units.currentData())
        self.validate()

    def reset_base(self, *_):
        self.data_base = None
        self.base.setText("Not read")
        self.validate()

    def showEvent(self, event):
        self.validate()
        super().showEvent(event)

    def parse_start(self):
        if self.is_automatic():
            return None
        text = self.start.text().strip()
        try:
            start = int(text, 16) if text else None
        except ValueError:
            raise ValueError("Enter a hexadecimal kernel address, with or without 0x.") from None
        validate_kernel_range(start if start is not None else self.data_base or KERNEL_ADDRESS_MIN,
                              self.amount_bytes())
        return start

    def validate(self, *_):
        automatic = self.is_automatic()
        busy = self.session.console.busy
        self.manual.setVisible(not automatic)
        self.mode.setEnabled(not busy)
        self.manual.setEnabled(not busy)
        self.mode_hint.setText(
            "Recommended for a full image. Start address and size are detected from kernel metadata; "
            "manual fields are not needed." if automatic else
            "Read only a known address range (maximum 83 MiB). This is a partial capture. "
            "Blank start uses .data, not the start of the full kernel. The hypervisor must be disabled; "
            "invalid addresses may restart the console.")
        valid = True
        try:
            start = self.parse_start()
            firmware = self.session.info.get("firmware")
            if automatic and firmware and firmware != "13.60":
                raise ValueError(f"Automatic detection supports 13.60; connected firmware is {firmware}. "
                                 "Use a known manual range for other firmware.")
            self.error.setText("")
            if automatic:
                self.summary.setText("Start and size: detected automatically • Exact byte count • No gap recovery")
            else:
                start = start if start is not None else self.data_base
                interval = f"0x{start:x} → 0x{start + self.amount_bytes():x} (end excluded)" if start else ".data base → base + size"
                self.summary.setText(f"{interval} • {self.amount_bytes():,} bytes ({human_size(self.amount_bytes())})")
        except ValueError as error:
            self.error.setText(str(error))
            self.summary.setText("")
            valid = False
        self.destination.setText(f"Save to: {self.settings.dumps_dir}  ·  Change folder on the Dumps page")
        self.dump_button.setText("Dump full kernel" if automatic else "Dump manual range")
        self.dump_button.setEnabled(valid and self.session.connected and not busy)
        self.read_base.setEnabled(self.session.connected and not busy)
        return valid

    def fetch_base(self):
        def done(base):
            self.data_base = base
            self.base.setText(f"0x{base:x}")
            self.validate()
        def failed(error):
            self.data_base = None
            self.base.setText("Not read")
            self.error.setText(describe_error(error))
        self.session.console.run(lambda reporter, cancel: kernel_data_base(self.session.ps5), done, failed)

    def start_dump(self):
        if not self.validate():
            return
        automatic = self.is_automatic()
        start, size = self.parse_start(), None if automatic else self.amount_bytes()
        root, ip, retries = self.settings.dumps_dir, self.session.ip, self.settings.retries
        recover = self.recover.isChecked() and not automatic
        if not confirm(self, "Hypervisor disabled?",
                       HYPERVISOR_WARNING + "\n\nIs the hypervisor disabled on the PS5?"):
            return
        if recover and not confirm(self, "Experimental kernel recovery",
                                   "Refused pages will be retried in smaller blocks. Invalid kernel addresses "
                                   "can restart the console. Continue?"):
            return
        state = {}
        def task(reporter, cancel):
            folder = state["folder"] = create_output_dir("kernel_0", required=size or KERNEL_LIMIT, root=root)
            reporter.log(f"Destination: {folder}")
            return dump_kernel(self.session.ps5, folder, size, start, reporter, cancel, info=dict(console=ip),
                               recover=recover, retries=retries)
        self.session.console.run(task, lambda document: show_dump_result(self, document, state["folder"]),
                                 lambda error: show_dump_failure(self, error, state.get("folder")),
                                 title="Dumping full kernel" if automatic else "Dumping manual kernel range")
