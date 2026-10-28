"""Main window: sidebar navigation, page header, job bars and the activity log."""
import html
import time
from datetime import datetime

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QListWidget, QMainWindow, QMessageBox, QPlainTextEdit,
                               QProgressBar, QSplitter, QStackedWidget, QVBoxLayout, QWidget)
from ps5dbg.errors import ConnectionLost

from .. import APP_NAME, AUTHOR, AUTHOR_URL, __version__
from ..core.reporting import DumpCancelled
from .dialogs import describe_error
from .pages.analyze import AnalyzePage
from .pages.connection import ConnectionPage
from .pages.dumps import DumpsPage
from .pages.kernel import KernelPage
from .pages.processes import ProcessesPage
from .pages.tools import ToolsPage
from .settings import Settings
from .theme import COLORS
from .widgets import BrandMark, StatusPill, app_icon, button, emblem, human_duration, human_size, label, row, rule
from .worker import Session

PAGES = (
    ("Connection", "Find your console, connect and see what is running."),
    ("Processes", "Dump the memory regions of a running process."),
    ("Kernel", "Detect and dump the kernel image, or select an explicit memory range."),
    ("Dumps", "Browse saved dumps, resume them, and export flat images or ELF files."),
    ("Analyze", "Compare dumps and search values, offline."),
    ("Tools", "Work with dumped files offline."),
)
LOG_TONES = dict(info="text", ok="success", warn="warning", error="danger")


class JobBar(QFrame):
    """Progress of the titled task running on one TaskRunner; hidden while idle."""

    def __init__(self, runner, parent=None):
        super().__init__(parent)
        self.setObjectName("JobBar")
        self.runner = runner
        self.title = label("", name="CardTitle")
        self.detail = label("", muted=True)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setTextVisible(False)
        self.cancel = button("Cancel", "danger")
        self.cancel.clicked.connect(self.cancel_clicked)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 12, 24, 12)
        layout.setSpacing(6)
        layout.addLayout(row(self.title, None, self.detail, 12, self.cancel))
        layout.addWidget(self.bar)
        self.hide()
        self.started = 0.0
        self.region_text = ""
        runner.started.connect(self.start)
        runner.finished.connect(lambda *_: self.hide())
        runner.region.connect(self.region)
        runner.progress.connect(self.progress)

    def start(self, title):
        if not title:
            return
        self.title.setText(title)
        self.detail.setText("Starting…")
        self.region_text = ""
        self.bar.setValue(0)
        self.cancel.setEnabled(True)
        self.cancel.setText("Cancel")
        self.started = time.monotonic()
        self.show()

    def cancel_clicked(self):
        self.runner.cancel()
        self.cancel.setEnabled(False)
        self.cancel.setText("Cancelling…")

    def region(self, index, count, item):
        self.region_text = f"Region {index + 1}/{count} · {item['name']} · "

    def progress(self, done, total, rate):
        if not total:
            return
        self.bar.setValue(int(done * 1000 / total))
        elapsed = time.monotonic() - self.started
        text = f"{self.region_text}{human_size(done)} of {human_size(total)}"
        if rate:
            text += f" · {rate / 1024 / 1024:.1f} MiB/s"
        if done and elapsed > 2 and done < total:
            text += f" · {human_duration(elapsed * (total - done) / done)} left"
        self.detail.setText(text)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = Settings()
        self.session = Session(self)
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        screen = QGuiApplication.primaryScreen().availableGeometry()
        self.resize(min(1400, int(screen.width() * 0.92)), min(900, int(screen.height() * 0.92)))
        self.setMinimumSize(980, 640)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(236)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 18, 0, 16)
        side.setSpacing(4)
        ornament = rule("Ornament")
        ornament.setFixedWidth(180)
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav.addItems([title for title, _ in PAGES])
        self.nav.setCursor(Qt.PointingHandCursor)
        version = label(f"v{__version__}", name="Version")
        credit = label(f'Developed by <b style="color:{COLORS["text"]}">{AUTHOR}</b><br>'
                       f'<a href="{AUTHOR_URL}" style="color:{COLORS["gold"]}; text-decoration:none">'
                       f'{AUTHOR_URL.removeprefix("https://")}</a>', name="Credit")
        credit.setOpenExternalLinks(True)
        credit.setToolTip(f"Open {AUTHOR_URL}")
        for widget in (credit, version):
            widget.setAlignment(Qt.AlignCenter)
        side.addWidget(emblem(184), 0, Qt.AlignCenter)
        side.addSpacing(6)
        side.addWidget(BrandMark(APP_NAME))
        side.addSpacing(8)
        side.addWidget(ornament, 0, Qt.AlignCenter)
        side.addSpacing(12)
        side.addWidget(self.nav, 1)
        side.addWidget(rule("Ornament"))
        side.addSpacing(8)
        side.addWidget(credit)
        side.addSpacing(4)
        side.addWidget(version)

        self.page_title = label("", name="PageTitle")
        self.page_subtitle = label("", name="PageSubtitle")
        self.pill = StatusPill()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(self.page_title)
        titles.addWidget(self.page_subtitle)
        header = QHBoxLayout()
        header.addLayout(titles, 1)
        header.addWidget(self.pill, 0, Qt.AlignTop)

        self.connection_page = ConnectionPage(self.session, self.settings)
        self.processes_page = ProcessesPage(self.session, self.settings, lambda: self.go(0))
        self.pages = QStackedWidget()
        self.pages.setObjectName("Pages")
        for page in (self.connection_page, self.processes_page,
                     KernelPage(self.session, self.settings, lambda: self.go(0)),
                     DumpsPage(self.session, self.settings), AnalyzePage(self.session, self.settings),
                     ToolsPage(self.session, self.settings)):
            self.pages.addWidget(page)
        self.connection_page.dump_app_requested.connect(self.dump_running_app)
        self.processes_page.kernel_requested.connect(lambda: self.go(2))

        body = QWidget()
        body.setObjectName("PageBody")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(28, 22, 28, 18)
        body_layout.setSpacing(0)
        body_layout.addLayout(header)
        body_layout.addSpacing(12)
        body_layout.addWidget(rule())
        body_layout.addSpacing(18)
        body_layout.addWidget(self.pages, 1)

        self.log = QPlainTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        log_panel = QFrame()
        log_panel.setObjectName("LogPanel")
        log_layout = QVBoxLayout(log_panel)
        log_layout.setContentsMargins(24, 8, 24, 8)
        log_layout.setSpacing(4)
        clear = button("Clear", "link")
        clear.clicked.connect(self.log.clear)
        log_layout.addLayout(row(label("Activity", muted=True), None, clear))
        log_layout.addWidget(self.log, 1)

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.setChildrenCollapsible(True)
        self.splitter.addWidget(body)
        self.splitter.addWidget(log_panel)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setSizes([640, 150])

        main = QVBoxLayout()
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        main.addWidget(self.splitter, 1)
        for runner in (self.session.console, self.session.background):
            main.addWidget(JobBar(runner))
            runner.log.connect(self.append_log)
            runner.failed.connect(self.task_failed)
            runner.busy_changed.connect(self.update_pill)
        root = QWidget()
        root.setObjectName("Root")
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(sidebar)
        root_layout.addLayout(main, 1)
        self.setCentralWidget(root)

        self.nav.currentRowChanged.connect(self.show_page)
        self.session.connection_changed.connect(self.connection_changed)
        self.session.info_changed.connect(self.update_pill)
        self.nav.setCurrentRow(0)
        geometry = self.settings.value("geometry")
        if isinstance(geometry, QByteArray):
            self.restoreGeometry(geometry)
        splitter_state = self.settings.value("splitter")
        if isinstance(splitter_state, QByteArray):
            self.splitter.restoreState(splitter_state)
        self.append_log(f"{APP_NAME} {__version__} ready. Dumps folder: {self.settings.dumps_dir}")

    # -- navigation --------------------------------------------------------

    def go(self, index):
        self.nav.setCurrentRow(index)

    def show_page(self, index):
        self.pages.setCurrentIndex(index)
        self.page_title.setText(PAGES[index][0])
        self.page_subtitle.setText(PAGES[index][1])

    def dump_running_app(self, pid):
        self.go(1)
        self.processes_page.show_process(pid)

    # -- state -------------------------------------------------------------

    def connection_changed(self, connected):
        if connected:
            self.append_log(f"Connected to {self.session.ip}", "ok")
        else:
            self.append_log("Disconnected", "warn")
        self.update_pill()

    def update_pill(self, *_):
        if self.session.console.busy or self.session.background.busy:
            self.pill.set_state("Working…" if not self.session.connected else f"{self.session.ip} · working…",
                                "warning")
        elif self.session.connected:
            firmware = self.session.info.get("firmware")
            self.pill.set_state(f"Connected · {self.session.ip}" + (f" · FW {firmware}" if firmware else ""),
                                "success")
        else:
            self.pill.set_state("Disconnected", "muted")

    def append_log(self, message, level="info"):
        color = COLORS[LOG_TONES.get(level, "text")]
        self.log.appendHtml(f'<span style="color:{COLORS["muted"]}">{datetime.now():%H:%M:%S}</span>&nbsp; '
                            f'<span style="color:{color}">{html.escape(message)}</span>')

    def task_failed(self, title, error, handled):
        if isinstance(error, DumpCancelled):
            self.append_log(f"{title or 'Task'} cancelled; data already written is kept", "warn")
            return
        self.append_log(f"{title or 'Task'} failed: {type(error).__name__}: {error}", "error")
        if isinstance(error, ConnectionLost) and self.session.connected:
            self.session.connection_lost()
        if not handled:
            QMessageBox.warning(self, title or "Something went wrong", describe_error(error))

    def closeEvent(self, event):
        runners = (self.session.console, self.session.background)
        if any(r.busy for r in runners):
            if QMessageBox.question(self, "Task running",
                                    "A task is still running. Cancel it and quit? Data already written is kept."
                                    ) != QMessageBox.Yes:
                event.ignore()
                return
        self.settings.set_value("geometry", self.saveGeometry())
        self.settings.set_value("splitter", self.splitter.saveState())
        for runner in runners:
            runner.shutdown()
        if self.session.ps5 is not None:
            self.session.ps5.close()
        event.accept()
