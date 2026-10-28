"""Connection page: find the console, connect, and show what is running."""
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QGridLayout, QHBoxLayout, QSpinBox, QVBoxLayout, QWidget

from ...core.console import discover_consoles
from ..dialogs import describe_error
from ..theme import COLORS
from ..widgets import Artwork, Card, button, label, row


class ConnectionPage(QWidget):
    dump_app_requested = Signal(int)

    FIELDS = (("ip", "Address"), ("version", "Payload protocol"), ("brand", "Server"),
              ("firmware", "Firmware"), ("app", "Running app"), ("title_id", "Title ID"),
              ("app_ver", "App version"), ("pid", "App PID"))

    def __init__(self, session, settings, parent=None):
        super().__init__(parent)
        self.session = session
        self.settings = settings
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(20)
        layout = QVBoxLayout()
        layout.setSpacing(16)

        connect_card = Card("Connect to your console",
                            "Start the ps5debug payload on the PS5, then connect over your local network "
                            "(TCP 744). Find on network uses the payload's UDP discovery.")
        self.ip = QComboBox()
        self.ip.setEditable(True)
        self.ip.setInsertPolicy(QComboBox.NoInsert)
        self.ip.lineEdit().setPlaceholderText("PS5 IP address, e.g. 192.168.1.50")
        self.ip.addItems(settings.ip_history)
        self.ip.setMinimumWidth(260)
        self.ip.lineEdit().returnPressed.connect(self.connect_clicked)
        self.find_button = button("Find on network")
        self.connect_button = button("Connect", "primary")
        self.disconnect_button = button("Disconnect", "danger")
        self.find_button.clicked.connect(self.find_consoles)
        self.connect_button.clicked.connect(self.connect_clicked)
        self.disconnect_button.clicked.connect(session.disconnect)
        connect_card.body.addLayout(row(self.ip, self.find_button, self.connect_button,
                                        self.disconnect_button, None, stretch_at=0))
        self.hint = label("", muted=True, wrap=True)
        self.retries = QSpinBox()
        self.retries.setRange(0, 20)
        self.retries.setValue(settings.retries)
        self.retries.setSuffix(" attempts")
        self.retries.setSpecialValueText("Off")
        self.retries.setToolTip("If the connection drops during a dump, reconnect and repeat the request "
                                "this many times (waiting 1, 2, 4… s) before giving up.")
        self.retries.valueChanged.connect(lambda value: setattr(settings, "retries", value))
        connect_card.body.addLayout(row(self.hint, label("Auto-reconnect during dumps", muted=True),
                                        self.retries, stretch_at=0))
        layout.addWidget(connect_card)

        info_card = Card("Console", "Information reported by the payload. Fields stay blank when "
                                    "the payload does not support the command.")
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(8)
        self.values = {}
        for index, (key, title) in enumerate(self.FIELDS):
            grid.addWidget(label(title, muted=True), index // 2, (index % 2) * 2)
            self.values[key] = label("—", name="Value", selectable=True)
            grid.addWidget(self.values[key], index // 2, (index % 2) * 2 + 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        info_card.body.addLayout(grid)
        self.refresh_button = button("Refresh")
        self.dump_app_button = button("Dump running app", "primary",
                                      "Open the running game or app in Processes with its regions loaded")
        self.refresh_button.clicked.connect(session.refresh_info)
        self.dump_app_button.clicked.connect(
            lambda: self.dump_app_requested.emit(self.session.info["foreground"].pid))
        info_card.body.addLayout(row(self.refresh_button, None, self.dump_app_button))
        layout.addWidget(info_card)
        layout.addStretch(1)
        outer.addLayout(layout, 1)
        outer.addWidget(Artwork("logo.jpg"))

        session.connection_changed.connect(self.update_state)
        session.info_changed.connect(self.show_info)
        session.info_changed.connect(self.update_state)
        session.console.busy_changed.connect(self.update_state)
        session.background.busy_changed.connect(self.update_state)
        self.update_state()
        self.show_info({})

    def set_hint(self, text, tone="muted"):
        self.hint.setText(text)
        self.hint.setStyleSheet(f"color: {COLORS[tone]};")

    def update_state(self, *_):
        connected = self.session.connected
        busy = self.session.console.busy
        self.ip.setEnabled(not connected and not busy)
        self.connect_button.setVisible(not connected)
        self.connect_button.setEnabled(not busy)
        self.disconnect_button.setVisible(connected)
        self.disconnect_button.setEnabled(not busy)
        self.find_button.setEnabled(not connected and not self.session.background.busy)
        self.refresh_button.setEnabled(connected and not busy)
        foreground = self.session.info.get("foreground")
        self.dump_app_button.setEnabled(connected and not busy and bool(foreground and foreground.pid))
        if not connected:
            self.show_info({})

    def show_info(self, info):
        foreground = info.get("foreground")
        has_app = bool(foreground and foreground.pid)
        values = dict(ip=self.session.ip if info else None, version=info.get("version"),
                      brand=" · ".join(filter(None, (info.get("brand"), info.get("capability")
                                                     and f"capability {info['capability']}"))),
                      firmware=info.get("firmware"),
                      app=foreground.name if has_app else None, title_id=foreground.titleid if has_app else None,
                      app_ver=foreground.app_ver if has_app else None, pid=str(foreground.pid) if has_app else None)
        for key, widget in self.values.items():
            widget.setText(values.get(key) or "—")

    def connect_clicked(self):
        ip = self.ip.currentText().strip()
        if not ip:
            self.set_hint("Enter the PS5 IP address, or use Find on network.", "warning")
            return
        if self.session.connected or self.session.console.busy:
            return
        self.set_hint(f"Connecting to {ip}...")

        def done():
            self.settings.remember_ip(ip)
            self.ip.clear()
            self.ip.addItems(self.settings.ip_history)
            self.set_hint(f"Connected to {ip}.", "success")

        def failed(error):
            self.set_hint(f"Could not connect to {ip}. {describe_error(error)}", "danger")

        self.session.connect_to(ip, done, failed)

    def find_consoles(self):
        self.set_hint("Looking for consoles on the local network...")

        def done(found):
            if not found:
                self.set_hint("No console answered. Check that the payload is running, the PC is on the same "
                              "network, and the firewall allows UDP 1010.", "warning")
                return
            for ip in reversed(found):
                if self.ip.findText(ip) < 0:
                    self.ip.insertItem(0, ip)
            self.ip.setCurrentText(found[0])
            self.set_hint(f"Found {len(found)} console(s): {', '.join(found)}", "success")

        def failed(error):
            self.set_hint(f"Discovery failed: {describe_error(error)}", "danger")

        self.session.background.run(lambda reporter, cancel: discover_consoles(), done, failed)
