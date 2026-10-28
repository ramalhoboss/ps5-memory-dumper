"""Black and gold theme taken from the logo. Widgets opt in through objectName / properties.

Backgrounds are pure black and neutral greys. Gold marks brand and actions (titles, primary buttons,
the selected page and row); electric blue is kept for small data accents (progress, checkboxes, links),
like the data stream in the artwork.
"""
from pathlib import Path

from PySide6.QtGui import QColor, QFont, QPalette

ASSETS = Path(__file__).resolve().parent / "assets"

COLORS = dict(
    bg="#000000", sidebar="#050505", surface="#0c0c0c", field="#080808", raised="#161616",
    border="#242424", border_strong="#333333", text="#ece8de", muted="#8f8f8f",
    gold="#d6a849", gold_light="#f4d68a", title="#efc970", gold_deep="#9a7127", gold_dim="#4a3b1d",
    accent="#2f8cff", accent_hover="#5aa6ff", accent_pressed="#1f6fe0", selection="#2a2312",
    success="#3ccf8e", warning="#ff9a3d", danger="#ff5d64",
)
MONO_FAMILIES = ["Cascadia Mono", "Consolas", "Courier New"]
SERIF = '"Palatino Linotype", "Book Antiqua", "Georgia", serif'

STYLESHEET = """
* {{ font-family: "Segoe UI", "Inter", sans-serif; font-size: 11pt; color: {text}; }}
QMainWindow, QWidget#Root {{ background: {bg}; }}
QWidget#PageBody {{ background: {bg}; }}

QFrame#Sidebar {{ background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0a0a0a, stop:1 {bg});
                  border-right: 1px solid {gold_dim}; }}
QLabel#Version, QLabel#Credit {{ color: {muted}; font-size: 9.5pt; }}
QFrame#Ornament {{ border: none; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 transparent,
                   stop:0.5 {gold}, stop:1 transparent); }}
QFrame#Rule {{ border: none; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {gold_deep},
               stop:0.5 {gold_dim}, stop:1 transparent); }}
QListWidget#Nav {{ background: transparent; border: none; outline: none; }}
QListWidget#Nav::item {{ padding: 10px 14px; margin: 2px 10px; border-radius: 6px; color: {muted};
                         font-weight: 600; }}
QListWidget#Nav::item:hover {{ background: {raised}; color: {text}; }}
QListWidget#Nav::item:selected {{ color: {gold_light}; border-left: 3px solid {gold};
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(214, 168, 73, 0.22),
                                stop:1 rgba(214, 168, 73, 0)); }}

QLabel#PageTitle {{ font-family: {serif}; font-size: 23pt; font-weight: 700; color: {title}; }}
QLabel#PageSubtitle, QLabel[muted="true"] {{ color: {muted}; }}
QLabel#CardTitle {{ font-size: 12.5pt; font-weight: 600; color: {gold_light}; }}
QLabel#Value {{ font-family: "Cascadia Mono", "Consolas", monospace; color: #f2ecdc; }}
QLabel#EmptyTitle {{ font-family: {serif}; font-size: 17pt; font-weight: 700; color: {title}; }}

QFrame#Card {{ background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #101010, stop:1 #0a0a0a);
               border: 1px solid {border}; border-top-color: #2c2a24; border-radius: 10px; }}
QFrame#Card[tone="warning"] {{ border-left: 3px solid {warning}; }}
QFrame#JobBar {{ background: {surface}; border-top: 1px solid {gold_dim}; }}
QFrame#LogPanel {{ background: {sidebar}; border-top: 1px solid {border}; }}

QPushButton {{ background: {raised}; border: 1px solid {border_strong}; border-radius: 6px;
               padding: 6px 14px; }}
QPushButton:hover {{ border-color: {gold_deep}; color: {gold_light}; }}
QPushButton:pressed {{ background: {field}; }}
QPushButton:disabled {{ color: {muted}; background: {surface}; border-color: {border}; }}
QPushButton[kind="primary"] {{ color: #160f03; font-weight: 700; border: 1px solid #f3d27a;
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f6dc93, stop:0.45 #ddb055, stop:1 #a9792b); }}
QPushButton[kind="primary"]:hover {{ color: #160f03; border-color: #fde9ad;
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fde8aa, stop:0.45 #e8be63, stop:1 #ba8a37); }}
QPushButton[kind="primary"]:pressed {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #c99a43, stop:1 #8e6421); }}
QPushButton[kind="primary"]:disabled {{ background: {raised}; border-color: {border}; color: {muted}; }}
QPushButton[kind="danger"] {{ color: {danger}; }}
QPushButton[kind="danger"]:hover {{ border-color: {danger}; color: {danger}; }}
QPushButton[kind="link"] {{ background: transparent; border: none; color: {accent_hover}; padding: 2px 4px; }}
QPushButton[kind="link"]:hover {{ color: #8cc4ff; text-decoration: underline; }}

QLineEdit, QComboBox, QSpinBox {{ background: {field}; border: 1px solid {border_strong}; border-radius: 6px;
                                  padding: 5px 8px; selection-background-color: {accent}; }}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover {{ border-color: #474747; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {accent}; }}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{ color: {muted}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {field}; border: 1px solid {gold_dim};
                               selection-background-color: {selection}; }}
QSpinBox {{ padding-right: 20px; }}
QSpinBox::up-button, QSpinBox::down-button {{ subcontrol-origin: border; width: 18px; border: none;
                                              background: transparent; }}
QSpinBox::up-button {{ subcontrol-position: top right; }}
QSpinBox::down-button {{ subcontrol-position: bottom right; }}
QSpinBox::up-arrow {{ image: url({assets}/chevron-up.svg); width: 10px; height: 10px; }}
QSpinBox::down-arrow {{ image: url({assets}/chevron-down.svg); width: 10px; height: 10px; }}
QComboBox::down-arrow {{ image: url({assets}/chevron-down.svg); width: 12px; height: 12px; margin-right: 8px; }}

QCheckBox {{ spacing: 7px; }}
QCheckBox::indicator {{ width: 15px; height: 15px; border-radius: 4px; border: 1px solid {border_strong};
                        background: {field}; }}
QCheckBox::indicator:hover {{ border-color: {accent}; }}
QCheckBox::indicator:checked {{ background: {accent}; border-color: {accent};
                                image: url({assets}/check.svg); }}

QTableView, QListWidget#FileList {{ background: {field}; alternate-background-color: #0e0e0e;
    border: 1px solid {border}; border-radius: 6px; gridline-color: transparent;
    selection-background-color: {selection}; selection-color: white; }}
QTableView::item {{ padding: 2px 6px; }}
QTableView::indicator {{ width: 14px; height: 14px; border-radius: 3px; border: 1px solid {border_strong};
                        background: {bg}; }}
QTableView::indicator:checked {{ background: {accent}; border-color: {accent}; image: url({assets}/check.svg); }}
QHeaderView::section {{ background: {surface}; color: {gold}; border: none;
    border-bottom: 1px solid {gold_dim}; padding: 6px; font-weight: 600; }}
QTableCornerButton::section {{ background: {surface}; border: none; }}

QProgressBar {{ background: {field}; border: 1px solid {border}; border-radius: 4px; height: 8px;
                text-align: center; color: transparent; }}
QProgressBar::chunk {{ border-radius: 3px; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
    stop:0 #1b5fd6, stop:0.8 #3d9bff, stop:0.96 #8cc6ff, stop:1 {gold_light}); }}

QTabWidget#Tabs::pane {{ border: none; }}
QTabWidget#Tabs > QTabBar::tab {{ background: transparent; color: {muted}; padding: 8px 18px; margin-right: 4px;
                                  border: none; border-bottom: 2px solid transparent; font-weight: 600; }}
QTabWidget#Tabs > QTabBar::tab:hover {{ color: {text}; }}
QTabWidget#Tabs > QTabBar::tab:selected {{ color: {gold_light}; border-bottom-color: {gold}; }}
QPlainTextEdit#Log {{ background: {sidebar}; border: none; font-family: "Cascadia Mono", "Consolas", monospace;
                      font-size: 10pt; }}
QSplitter::handle {{ background: {bg}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {border_strong}; border-radius: 5px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {border_strong}; border-radius: 5px; min-width: 30px; }}
QScrollBar::handle:hover {{ background: {gold_deep}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QToolTip {{ background: {raised}; color: {text}; border: 1px solid {gold_dim}; padding: 4px; }}
QMessageBox, QDialog {{ background: {surface}; }}
""".format(assets=ASSETS.as_posix(), serif=SERIF, **COLORS)


def apply_theme(app):
    app.setStyle("Fusion")
    palette = QPalette()
    for role, key in ((QPalette.Window, "bg"), (QPalette.Base, "field"), (QPalette.AlternateBase, "surface"),
                      (QPalette.Button, "raised"), (QPalette.Text, "text"), (QPalette.WindowText, "text"),
                      (QPalette.ButtonText, "text"), (QPalette.Highlight, "accent"),
                      (QPalette.ToolTipBase, "raised"), (QPalette.ToolTipText, "text"),
                      (QPalette.PlaceholderText, "muted"), (QPalette.Link, "accent_hover")):
        palette.setColor(role, QColor(COLORS[key]))
    palette.setColor(QPalette.HighlightedText, QColor("white"))
    app.setPalette(palette)
    app.setFont(QFont("Segoe UI", 11))
    app.setStyleSheet(STYLESHEET)


def mono_font(size=10.5):
    font = QFont()
    font.setFamilies(MONO_FAMILIES)
    font.setPointSizeF(size)
    return font
