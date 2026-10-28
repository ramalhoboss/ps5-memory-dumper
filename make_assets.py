"""Builds the app's icon and artwork from the images in this folder.

Writes into ps5dumper/gui/assets/:
  icon.ico  - Windows icon (16-256 px) for the .exe, the window and the taskbar, from "icone 2.png";
              the black corners outside its rounded gold frame are made transparent
  icon.png  - 512 px emblem from Icon.png, shown in the sidebar and on empty pages
  logo.jpg  - artwork from Logo.jpg, shown on the Connection page

Run it again after replacing any of these images; build_exe.ps1 runs it before every build.
"""
import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QIODevice, QRectF, Qt
from PySide6.QtGui import QBrush, QGuiApplication, QImage, QPainter, QPainterPath

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "ps5dumper" / "gui" / "assets"
APP_ICON, EMBLEM, LOGO = ROOT / "icone 2.png", ROOT / "Icon.png", ROOT / "Logo.jpg"
ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
LOGO_HEIGHT = 900
# Outline of the app icon's gold frame, as fractions of its side (measured on the 1254 px image).
FRAME_INSET, FRAME_RADIUS = 0.0024, 0.145


def shrink(image, width, height=None):
    """Halve repeatedly before the final step so small sizes stay sharp instead of aliasing."""
    height = height or width
    while image.width() >= width * 2 and image.height() >= height * 2:
        image = image.scaled(image.width() // 2, image.height() // 2, Qt.IgnoreAspectRatio,
                             Qt.SmoothTransformation)
    return image.scaled(width, height, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)


def square(image):
    """Centre-crop to a square so a non-square image is not stretched."""
    side = min(image.width(), image.height())
    return image.copy((image.width() - side) // 2, (image.height() - side) // 2, side, side)


def rounded_corners(image):
    """Keeps only what is inside the rounded frame, so the corners are transparent, not black squares."""
    side = image.width()
    result = QImage(side, side, QImage.Format_ARGB32_Premultiplied)
    result.fill(Qt.transparent)
    inset, radius = side * FRAME_INSET, side * FRAME_RADIUS
    outline = QPainterPath()
    outline.addRoundedRect(QRectF(inset, inset, side - 2 * inset, side - 2 * inset), radius, radius)
    painter = QPainter(result)
    painter.setRenderHint(QPainter.Antialiasing)  # smooth edge (a clip path would be jagged)
    painter.fillPath(outline, QBrush(image))
    painter.end()
    return result


def png_bytes(image):
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(buffer.data())


def write_ico(image, destination):
    """ICO with one PNG-compressed entry per size (supported since Windows Vista)."""
    entries = [png_bytes(shrink(image, size)) for size in ICON_SIZES]
    offset = 6 + 16 * len(entries)
    header = struct.pack("<HHH", 0, 1, len(entries))
    directory = b""
    for size, data in zip(ICON_SIZES, entries):
        directory += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    destination.write_bytes(header + directory + b"".join(entries))


def load(path):
    if not path.is_file():
        raise SystemExit(f"Missing {path.name} in {ROOT}")
    image = QImage(str(path))
    if image.isNull():
        raise SystemExit(f"Could not read {path.name}")
    return image


def main():
    QGuiApplication(sys.argv[:1])  # image-format plugins (JPEG) and painting
    icon, emblem, logo = load(APP_ICON), load(EMBLEM), load(LOGO)
    ASSETS.mkdir(parents=True, exist_ok=True)
    write_ico(rounded_corners(square(icon.convertToFormat(QImage.Format_ARGB32))), ASSETS / "icon.ico")
    shrink(square(emblem.convertToFormat(QImage.Format_ARGB32)), 512).save(str(ASSETS / "icon.png"), "PNG")
    if logo.height() > LOGO_HEIGHT:
        logo = shrink(logo, round(logo.width() * LOGO_HEIGHT / logo.height()), LOGO_HEIGHT)
    logo.save(str(ASSETS / "logo.jpg"), "JPG", 90)
    for name in ("icon.ico", "icon.png", "logo.jpg"):
        print(f"{name}: {(ASSETS / name).stat().st_size / 1024:.0f} KiB")


if __name__ == "__main__":
    main()
