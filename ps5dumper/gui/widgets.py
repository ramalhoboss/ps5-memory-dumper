"""Small building blocks shared by the pages."""
from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import (QBrush, QColor, QFont, QFontMetricsF, QIcon, QLinearGradient, QPainter, QPainterPath,
                           QPen, QPixmap)
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QPushButton,
                               QSizePolicy, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .theme import ASSETS, COLORS, mono_font

SORT_ROLE = Qt.UserRole + 1


def human_size(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024


def human_duration(seconds):
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    return f"{hours}:{rest // 60:02d}:{rest % 60:02d}" if hours else f"{rest // 60}:{rest % 60:02d}"


def button(text, kind=None, tooltip=None):
    widget = QPushButton(text)
    widget.setCursor(Qt.PointingHandCursor)
    if kind:
        widget.setProperty("kind", kind)
    if tooltip:
        widget.setToolTip(tooltip)
    return widget


def label(text="", muted=False, name=None, wrap=False, selectable=False):
    widget = QLabel(text)
    if muted:
        widget.setProperty("muted", True)
    if name:
        widget.setObjectName(name)
    widget.setWordWrap(wrap)
    if selectable:
        widget.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return widget


def row(*widgets, spacing=8, stretch_at=None):
    """Horizontal layout: None adds a stretch, an int adds spacing; `stretch_at` (index or indexes) grows."""
    stretched = {stretch_at} if isinstance(stretch_at, int) else set(stretch_at or ())
    layout = QHBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(spacing)
    for index, widget in enumerate(widgets):
        if widget is None:
            layout.addStretch(1)
        elif isinstance(widget, int):
            layout.addSpacing(widget)
        elif isinstance(widget, QHBoxLayout):
            layout.addLayout(widget)
        else:
            layout.addWidget(widget, 1 if index in stretched else 0)
    return layout


class Card(QFrame):
    """Rounded surface with an optional title/subtitle; add content to `body`."""

    def __init__(self, title=None, subtitle=None, tone=None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        if tone:
            self.setProperty("tone", tone)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(12)
        self.header = QHBoxLayout()
        self.header.setSpacing(8)
        if title or subtitle:
            titles = QVBoxLayout()
            titles.setSpacing(2)
            if title:
                titles.addWidget(label(title, name="CardTitle"))
            if subtitle:
                titles.addWidget(label(subtitle, muted=True, wrap=True))
            self.header.addLayout(titles, 1)
            outer.addLayout(self.header)
        self.body = QVBoxLayout()
        self.body.setSpacing(10)
        outer.addLayout(self.body, 1)


class StatusPill(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.set_state("Disconnected", "muted")

    def set_state(self, text, tone):
        color = COLORS[tone]
        self.setText(f'<span style="color:{color}">●</span>&nbsp; {text}')
        self.setStyleSheet(f"QLabel {{ background: {COLORS['surface']}; border: 1px solid {COLORS['gold_dim']};"
                           " border-radius: 13px; padding: 4px 12px; }")


class SortItem(QTableWidgetItem):
    """Table cell that shows `text` but sorts by `key` (numbers, addresses)."""

    def __init__(self, text, key=None, mono=False):
        super().__init__(text)
        self.setData(SORT_ROLE, text if key is None else key)
        self.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        if mono:
            self.setFont(mono_font())

    def __lt__(self, other):
        mine, theirs = self.data(SORT_ROLE), other.data(SORT_ROLE)
        try:
            return mine < theirs
        except TypeError:
            return str(mine) < str(theirs)


def table(headers, stretch_column=None):
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.verticalHeader().hide()
    widget.verticalHeader().setDefaultSectionSize(32)
    widget.setSelectionBehavior(QAbstractItemView.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SingleSelection)
    widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    widget.setAlternatingRowColors(True)
    widget.setShowGrid(False)
    widget.setWordWrap(False)
    header = widget.horizontalHeader()
    header.setHighlightSections(False)
    header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    header.setSectionResizeMode(QHeaderView.ResizeToContents)
    if stretch_column is not None:
        header.setSectionResizeMode(stretch_column, QHeaderView.Stretch)
    return widget


def tinted(item, tone):
    item.setForeground(QColor(COLORS[tone]))
    return item


class EmptyState(QWidget):
    def __init__(self, title, text, action_text=None, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addStretch(1)
        layout.addWidget(emblem(88), 0, Qt.AlignCenter)
        layout.addSpacing(6)
        heading = label(title, name="EmptyTitle")
        heading.setAlignment(Qt.AlignCenter)
        body = label(text, muted=True, wrap=True)
        body.setAlignment(Qt.AlignCenter)
        layout.addWidget(heading)
        layout.addWidget(body)
        self.action = None
        if action_text:
            self.action = button(action_text, "primary")
            layout.addLayout(row(None, self.action, None))
        layout.addStretch(2)


class ConnectionGate(QStackedWidget):
    """Shows `content` while connected and an empty state otherwise."""

    def __init__(self, session, content, go_connect, parent=None):
        super().__init__(parent)
        self.empty = EmptyState("Not connected", "Connect to your console to list processes and read memory.",
                                "Go to Connection")
        self.empty.action.clicked.connect(go_connect)
        self.addWidget(self.empty)
        self.addWidget(content)
        session.connection_changed.connect(lambda connected: self.setCurrentIndex(1 if connected else 0))


def rule(name="Rule"):
    """Thin gold line: "Rule" fades out to the right, "Ornament" fades out at both ends."""
    line = QFrame()
    line.setObjectName(name)
    line.setFixedHeight(1)
    return line


def asset_pixmap(name, width, ratio=2.0):
    """Asset scaled to `width` logical pixels, sharp on high-DPI screens."""
    pixmap = QPixmap(str(ASSETS / name))
    if pixmap.isNull():
        return pixmap
    pixmap = pixmap.scaledToWidth(round(width * ratio), Qt.SmoothTransformation)
    pixmap.setDevicePixelRatio(ratio)
    return pixmap


def emblem(size):
    widget = QLabel()
    widget.setPixmap(asset_pixmap("icon.png", size))
    widget.setFixedSize(size, size)
    return widget


class Artwork(QWidget):
    """Picture scaled to fit (aspect kept, top-aligned) inside a thin gold frame."""

    def __init__(self, name, max_width=320, parent=None):
        super().__init__(parent)
        self.pixmap = QPixmap(str(ASSETS / name))
        self.setMinimumWidth(160)
        self.setMaximumWidth(max_width)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)

    def sizeHint(self):
        if self.pixmap.isNull():
            return QSize(0, 0)
        width = self.maximumWidth()
        return QSize(width, round(width * self.pixmap.height() / self.pixmap.width()))

    def paintEvent(self, event):
        if self.pixmap.isNull():
            return
        size = self.pixmap.size().scaled(self.size(), Qt.KeepAspectRatio)
        rect = QRectF((self.width() - size.width()) / 2, 0.5, size.width() - 1, size.height() - 1)
        path = QPainterPath()
        path.addRoundedRect(rect, 10, 10)
        painter = QPainter(self)
        painter.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        painter.setClipPath(path)
        painter.drawPixmap(rect, self.pixmap, QRectF(self.pixmap.rect()))
        painter.setClipping(False)
        painter.setPen(QPen(QColor(COLORS["gold_dim"]), 1))
        painter.drawPath(path)


METAL_GOLD = ((0.0, "#fff4cf"), (0.45, "#f3cc6b"), (0.55, "#d9a443"), (1.0, "#9c6b1d"))
METAL_SILVER = ((0.0, "#ffffff"), (0.5, "#dfe3ea"), (0.56, "#b7bdc8"), (1.0, "#8a909c"))


def _font(family, pixels, weight, italic=False, tracking=0.0):
    font = QFont(family)
    font.setPixelSize(pixels)
    font.setWeight(weight)
    font.setItalic(italic)
    font.setLetterSpacing(QFont.AbsoluteSpacing, tracking)
    return font


class BrandMark(QWidget):
    """App name in metallic lettering like the icon: gold "PS5" over silver/gold "MEMORY DUMPER".

    Drawn as vector paths with gradients (labels cannot fill text with a gradient), so it stays sharp at
    any display scaling.
    """

    def __init__(self, name, parent=None):
        super().__init__(parent)
        self.prefix, _, rest = name.upper().partition(" ")
        self.words = rest.split()
        self.big = _font("Segoe UI Black", 44, QFont.Black, italic=True, tracking=1.0)
        self.small = _font("Segoe UI", 16, QFont.Bold, tracking=2.0)
        self.setFixedHeight(round(QFontMetricsF(self.big).capHeight() + QFontMetricsF(self.small).capHeight() + 30))

    @staticmethod
    def _path(text, font):
        path = QPainterPath()
        path.addText(0, 0, font, text)
        return path

    @staticmethod
    def _fill(painter, path, stops):
        shadow = QPainterPath(path)
        shadow.translate(0, 1.5)
        painter.fillPath(shadow, QColor(0, 0, 0, 200))
        box = path.boundingRect()
        gradient = QLinearGradient(box.topLeft(), box.bottomLeft())
        for stop, color in stops:
            gradient.setColorAt(stop, QColor(color))
        painter.fillPath(path, QBrush(gradient))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        prefix = self._path(self.prefix, self.big)
        box = prefix.boundingRect()
        prefix.translate((self.width() - box.width()) / 2 - box.left(), 4 - box.top())
        self._fill(painter, prefix, METAL_GOLD)
        # Words alternate silver / gold, as "MEMORY DUMPER" does on the icon.
        words = [self._path(word, self.small) for word in self.words]
        gap = 9
        total = sum(path.boundingRect().width() for path in words) + gap * (len(words) - 1)
        x, top = (self.width() - total) / 2, prefix.boundingRect().bottom() + 10
        for index, path in enumerate(words):
            box = path.boundingRect()
            path.translate(x - box.left(), top - box.top())
            self._fill(painter, path, METAL_GOLD if index % 2 else METAL_SILVER)
            x += box.width() + gap


def app_icon():
    return QIcon(str(ASSETS / "icon.ico"))
