"""Background execution for the GUI.

The PS5Debug connection is not thread-safe, so every call on it runs in the single
thread of `Session.console`; discovery and file tools run in `Session.background`. Tasks report through
Qt signals, which are delivered in the GUI thread.
"""
import itertools
import threading
import time

from PySide6.QtCore import QObject, QThread, Signal, Slot

from ..core.console import connect, console_info
from ..core.reporting import Reporter


class _Worker(QObject):
    done = Signal(int, object)
    failed = Signal(int, object)
    log = Signal(str, str)
    region = Signal(int, int, object)
    progress = Signal(object, object, float)  # object: byte counts exceed 32 bits

    @Slot(int, object)
    def execute(self, job, call):
        try:
            result = call()
        except BaseException as error:  # reported to the GUI, never lost in the thread
            self.failed.emit(job, error)
        else:
            self.done.emit(job, result)


class GuiReporter(Reporter):
    PROGRESS_EVERY = 0.1  # seconds; keeps the event queue small on fast links

    def __init__(self, worker):
        self.worker = worker
        self.last = 0.0

    def log(self, message, level="info"):
        self.worker.log.emit(message, level)

    def region_started(self, index, count, item):
        self.worker.region.emit(index, count, dict(item))

    def progress(self, done, total, rate):
        now = time.monotonic()
        if done >= total or now - self.last >= self.PROGRESS_EVERY:
            self.last = now
            self.worker.progress.emit(done, total, rate)


class TaskRunner(QObject):
    """Runs one task at a time in its own thread."""

    busy_changed = Signal(bool)
    started = Signal(str)  # title; empty for quick tasks that need no progress bar
    finished = Signal(str, bool)
    failed = Signal(str, object, bool)  # title, exception, handled by the caller
    log = Signal(str, str)
    region = Signal(int, int, object)
    progress = Signal(object, object, float)
    _submit = Signal(int, object)

    def __init__(self, name, parent=None):
        super().__init__(parent)
        self.thread = QThread(self)
        self.thread.setObjectName(name)
        self.worker = _Worker()
        self.worker.moveToThread(self.thread)
        self._submit.connect(self.worker.execute)
        self.worker.done.connect(self._done)
        self.worker.failed.connect(self._failed)
        self.worker.log.connect(self.log)
        self.worker.region.connect(self.region)
        self.worker.progress.connect(self.progress)
        self.thread.start()
        self.cancel_event = threading.Event()
        self.busy = False
        self._jobs = {}
        self._ids = itertools.count(1)

    def run(self, task, on_done=None, on_error=None, title=""):
        """`task(reporter, cancel)` runs in the worker thread; the callbacks run in the GUI thread.

        Passing `on_error` means the caller shows the failure itself (no default dialog).
        """
        if self.busy:
            return False
        job = next(self._ids)
        cancel = self.cancel_event = threading.Event()
        reporter = GuiReporter(self.worker)
        self._jobs[job] = (on_done, on_error, title)
        self._set_busy(True)
        self.started.emit(title)
        self._submit.emit(job, lambda: task(reporter, cancel))
        return True

    def cancel(self):
        self.cancel_event.set()

    def _set_busy(self, busy):
        self.busy = busy
        self.busy_changed.emit(busy)

    def _done(self, job, result):
        on_done, _, title = self._jobs.pop(job)
        self._set_busy(False)
        self.finished.emit(title, True)
        if on_done is not None:
            on_done(result)

    def _failed(self, job, error):
        _, on_error, title = self._jobs.pop(job)
        self._set_busy(False)
        self.finished.emit(title, False)
        self.failed.emit(title, error, on_error is not None)
        if on_error is not None:
            on_error(error)

    def shutdown(self, wait_ms=3000):
        self.cancel()
        self.thread.quit()
        self.thread.wait(wait_ms)


class Session(QObject):
    """Connection state shared by every page."""

    connection_changed = Signal(bool)
    info_changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.console = TaskRunner("console", self)
        self.background = TaskRunner("background", self)  # discovery and file tools
        self.ps5 = None  # only used inside console tasks
        self.ip = None
        self.info = {}

    @property
    def connected(self):
        return self.ps5 is not None

    def connect_to(self, ip, on_done=None, on_error=None):
        def task(reporter, cancel):
            reporter.log(f"Connecting to {ip}...")
            ps5 = connect(ip)
            try:
                return ps5, console_info(ps5)
            except BaseException:
                ps5.close()
                raise

        def done(result):
            self.ps5, self.info = result
            self.ip = ip.strip()
            self.connection_changed.emit(True)
            self.info_changed.emit(self.info)
            if on_done is not None:
                on_done()

        return self.console.run(task, done, on_error)

    def disconnect(self):
        ps5 = self.ps5

        def task(reporter, cancel):
            ps5.close()

        def done(_):
            self.connection_lost()

        if ps5 is not None:
            self.console.run(task, done)

    def connection_lost(self):
        """Forgets the connection; called after a ConnectionLost or a deliberate disconnect."""
        if self.ps5 is not None:
            self.ps5.close()
        self.ps5 = None
        self.info = {}
        self.connection_changed.emit(False)

    def refresh_info(self):
        def task(reporter, cancel):
            return console_info(self.ps5)

        def done(info):
            self.info = info
            self.info_changed.emit(info)

        if self.ps5 is not None:
            self.console.run(task, done)
