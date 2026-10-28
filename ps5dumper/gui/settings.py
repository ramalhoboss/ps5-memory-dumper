"""Persistent preferences (Windows registry / platform equivalent via QSettings)."""
from pathlib import Path

from PySide6.QtCore import QSettings

from ..core.dumper import DEFAULT_RETRIES, default_dumps_dir

MAX_HISTORY = 8


class Settings:
    def __init__(self):
        self.store = QSettings("PS5Dumper", "PS5Dumper")

    @property
    def ip_history(self):
        return [ip for ip in self.store.value("ip_history", [], type=list) if ip]

    def remember_ip(self, ip):
        history = [ip] + [old for old in self.ip_history if old != ip]
        self.store.setValue("ip_history", history[:MAX_HISTORY])

    @property
    def dumps_dir(self):
        return Path(self.store.value("dumps_dir", str(default_dumps_dir())))

    @dumps_dir.setter
    def dumps_dir(self, path):
        self.store.setValue("dumps_dir", str(path))

    @property
    def fill_gaps(self):
        return self.store.value("fill_gaps", True, type=bool)

    @fill_gaps.setter
    def fill_gaps(self, value):
        self.store.setValue("fill_gaps", bool(value))

    @property
    def retries(self):
        return self.store.value("retries", DEFAULT_RETRIES, type=int)

    @retries.setter
    def retries(self, value):
        self.store.setValue("retries", int(value))

    def value(self, key, default=None, kind=None):
        return self.store.value(key, default) if kind is None else self.store.value(key, default, type=kind)

    def set_value(self, key, value):
        self.store.setValue(key, value)
