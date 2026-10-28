"""Progress reporting and cancellation shared by the CLI and the GUI.

The engine never prints: it calls a Reporter, and each front-end decides how to
show it. Cancellation is a threading.Event checked between requests.
"""


class DumpCancelled(Exception):
    """Raised between requests when the user cancels; data already written is kept."""


class Reporter:
    """No-op base. Levels: info, ok, warn, error."""

    def log(self, message, level="info"):
        pass

    def region_started(self, index, count, item):
        pass

    def progress(self, done, total, rate):
        """`done`/`total` are address bytes handled (read or skipped); `rate` is bytes/s received."""

    def region_finished(self, index, count, item):
        pass


def check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise DumpCancelled("cancelled by the user")
