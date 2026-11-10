"""Extract files stored in dumped memory: carves them out of .bin files into a folder.

Every signature hit is checked by a parser that walks the format's own structure (ELF
headers, PNG chunks, JPEG markers, the ZIP directory...) to find where the file ends;
hits that do not parse are ignored. Each .bin is scanned on its own, so a file that
continues past the end of its region is cut there and marked truncated. Files with the
same content are written once. Optionally also writes the text strings of every .bin.
"""
import csv
import hashlib
import math
import mmap
import re
import struct
import zlib
from collections import Counter
from pathlib import Path

from .files import list_bin_files
from .manifest import find_manifest, load_manifest
from .reader import MIB
from .reporting import Reporter, check_cancel

MAX_FILE = 256 * MIB  # larger structures are treated as false positives
MAX_GZIP_OUTPUT = 1024 * MIB
MIN_TRUNCATED = 1024  # truncated hits smaller than this are not worth a file
MIN_STRING = 6
INDEX_NAME = "index.csv"
STRINGS_FOLDER = "strings"


class _Truncated(Exception):
    """The structure is valid so far but continues past the end of the data."""


def _need(position, count, limit):
    if position + count > limit:
        raise _Truncated


def _printable(raw):
    return all(0x20 <= c < 0x7F for c in raw)


def _entropy(raw):
    """Bits per byte: about 8 for encrypted or compressed data, far less for code, tables and text."""
    total = len(raw)
    return -sum(n / total * math.log2(n / total) for n in Counter(raw).values()) if total else 0.0


# -- parsers: (data, start, limit) -> (size, extension, note[, label]) or None
# A label (an app name) starts the file's name and is passed on to the files found inside it.

ELF_KINDS = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core",
             0xFE00: "SCE executable", 0xFE10: "SCE dynamic executable", 0xFE18: "SCE dynamic library"}
MACHINES = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64"}
PACKED = "segment data looks encrypted or compressed"
PACKED_ENTROPY = 7.2


def _elf(data, start, limit):
    """Size from the program headers (file layout), plus the section headers when they are present.

    When the first loadable segment looks encrypted or compressed, the headers do not describe how
    the body is stored, so the note says so (and _carve cuts it at the next ELF header).
    """
    bits, order, version = data[start + 4], data[start + 5], data[start + 6]
    if bits not in (1, 2) or order not in (1, 2) or version != 1:
        return None
    endian = "<" if order == 1 else ">"
    header, phsize, shsize = (64, 56, 64) if bits == 2 else (52, 32, 40)
    _need(start, header, limit)
    (kind, machine, version, _, phoff, shoff, _, ehsize, phentsize, phnum, shentsize, shnum,
     _) = struct.unpack_from(endian + ("HHIQQQIHHHHHH" if bits == 2 else "HHIIIIIHHHHHH"), data, start + 16)
    if (version != 1 or ehsize != header or not phnum or phentsize != phsize or phoff < header
            or (shnum and shentsize != shsize)):
        return None
    end = phoff + phnum * phsize
    if end > MAX_FILE:
        return None
    _need(start, end, limit)
    entry = endian + ("IIQQQQQQ" if bits == 2 else "IIIIIIII")
    first_load = None
    for index in range(phnum):
        fields = struct.unpack_from(entry, data, start + phoff + index * phsize)
        segment_type, offset, size = (fields[0], fields[2], fields[5]) if bits == 2 else fields[:2] + fields[4:5]
        if size:
            end = max(end, offset + size)
            if segment_type == 1 and first_load is None:  # PT_LOAD
                first_load = offset
    if end > MAX_FILE:
        return None
    sections = shoff + shnum * shsize
    if shnum and sections <= MAX_FILE and start + sections <= limit:
        end = max(end, sections)  # section headers are optional (often not loaded); kept when they fit
    name = ELF_KINDS.get(kind, f"type 0x{kind:x}")
    note = f"{32 * bits}-bit {MACHINES.get(machine, f'machine {machine}')} {name}"
    sample = data[start + first_load:min(start + first_load + 4096, limit)] if first_load is not None else b""
    if len(sample) >= 1024 and _entropy(sample) > PACKED_ENTROPY:
        note += f"; {PACKED}"
    _need(start, end, limit)
    return end, "elf", note


def _self(data, start, limit):
    """PS4 (version 0x00) and PS5 (0x10) SELF: the file size is in the header; the ELF header follows the entries."""
    _need(start, 32, limit)
    (version, mode, endian, _, _, header_size, _, file_size, entries,
     _) = struct.unpack_from("<4BIHHQHH", data, start + 4)
    if (version not in (0x00, 0x10) or (mode, endian) != (1, 1) or not 0 < entries <= 1024
            or not 32 <= header_size < file_size <= MAX_FILE):
        return None
    _need(start, file_size, limit)
    return file_size, "self", f"{'PS4' if data[start] == 0x4F else 'PS5'} SELF, {entries} segments"


def _png(data, start, limit):
    position = start + 8
    while True:
        _need(position, 12, limit)
        length, kind = struct.unpack_from(">I4s", data, position)
        if length > MAX_FILE or not kind.isalpha() or (position == start + 8 and (kind != b"IHDR" or length != 13)):
            return None
        position += 12 + length
        if kind == b"IEND":
            _need(position, 0, limit)
            width, height = struct.unpack_from(">II", data, start + 16)
            return position - start, "png", f"{width}x{height}"


JPEG_FIRST = {0xC0, 0xC1, 0xC2, 0xC4, 0xDB, 0xDD, 0xFE} | set(range(0xE0, 0xF0))
JPEG_FRAMES = set(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}


def _jpeg(data, start, limit):
    """Walks the marker segments; after each scan, skips entropy-coded data to the next real marker."""
    if data[start + 3] not in JPEG_FIRST:
        return None
    position, frame, scanned = start + 2, None, False
    while True:
        _need(position, 2, limit)
        if data[position] != 0xFF:
            return None
        marker = data[position + 1]
        if marker == 0xFF:  # fill byte
            position += 1
            continue
        if marker == 0xD9:  # end of image
            if not scanned:
                return None
            return position + 2 - start, "jpg", f"{frame[0]}x{frame[1]}"
        if 0xD0 <= marker <= 0xD7:
            position += 2
            continue
        if marker in (0x00, 0x01, 0xD8):
            return None
        _need(position, 4, limit)
        length = struct.unpack_from(">H", data, position + 2)[0]
        if length < 2:
            return None
        if marker in JPEG_FRAMES:
            _need(position, 9, limit)
            height, width = struct.unpack_from(">HH", data, position + 5)
            frame = (width, height)
        position += 2 + length
        if marker == 0xDA:
            if frame is None:
                return None
            scanned = True
            while True:
                found = data.find(b"\xff", position, limit)
                if found < 0 or found + 1 >= limit:
                    raise _Truncated
                following = data[found + 1]
                if following == 0x00 or 0xD0 <= following <= 0xD7:
                    position = found + 2
                elif following == 0xFF:
                    position = found + 1
                else:
                    position = found
                    break


def _gif_blocks(data, position, limit):
    while True:
        _need(position, 1, limit)
        size = data[position]
        position += 1 + size
        if not size:
            return position


def _gif(data, start, limit):
    _need(start, 13, limit)
    width, height, packed = struct.unpack_from("<HHB", data, start + 6)
    if not width or not height:
        return None
    position = start + 13 + (3 << ((packed & 7) + 1) if packed & 0x80 else 0)
    images = 0
    while True:
        _need(position, 1, limit)
        block = data[position]
        if block == 0x3B:  # trailer
            return (position + 1 - start, "gif", f"{width}x{height}, {images} frame(s)") if images else None
        if block == 0x21:  # extension
            position = _gif_blocks(data, position + 2, limit)
        elif block == 0x2C:  # image
            _need(position, 11, limit)
            local = data[position + 9]
            position += 10 + (3 << ((local & 7) + 1) if local & 0x80 else 0)
            _need(position, 1, limit)
            if not 2 <= data[position] <= 12:
                return None
            position = _gif_blocks(data, position + 1, limit)
            images += 1
        else:
            return None


ZIP_METHODS = {0, 8, 9, 12, 14, 93, 95, 98, 99}


def _zip(data, start, limit):
    """Ends at the end-of-central-directory record whose directory sits right before it."""
    _need(start, 30, limit)
    method, name_length = struct.unpack_from("<H", data, start + 8)[0], struct.unpack_from("<H", data, start + 26)[0]
    if method not in ZIP_METHODS or not 0 < name_length <= 1024:
        return None
    position = start + 30
    while True:
        found = data.find(b"PK\x05\x06", position, limit)
        if found < 0:
            raise _Truncated
        _need(found, 22, limit)
        disk, directory_disk, _, entries, size, offset, comment = struct.unpack_from("<HHHHIIH", data, found + 4)
        zip64 = offset == 0xFFFFFFFF and data[found - 20:found - 16] == b"PK\x06\x07"
        if zip64 or (disk == directory_disk == 0 and entries and offset + size == found - start
                     and data[start + offset:start + offset + 4] == b"PK\x01\x02"):
            _need(found, 22 + comment, limit)
            return found + 22 + comment - start, "zip", "ZIP64" if zip64 else f"{entries} entries"
        position = found + 4


def _gzip(data, start, limit):
    """Inflates the stream (output discarded) to find where it ends; the CRC is checked too."""
    _need(start, 18, limit)
    if data[start + 3] & 0xE0:
        return None
    stream = zlib.decompressobj(31)
    position, output = start, 0
    try:
        while not stream.eof:
            if position >= limit:
                raise _Truncated
            chunk = data[position:min(position + 64 * 1024, limit)]
            position += len(chunk)
            output += len(stream.decompress(chunk, MIB))
            while stream.unconsumed_tail and not stream.eof:
                output += len(stream.decompress(stream.unconsumed_tail, MIB))
                if output > MAX_GZIP_OUTPUT:
                    return None
    except zlib.error:
        return None
    end = position - len(stream.unused_data)
    return (end - start, "gz", f"{output} bytes inflated") if output else None


def _sqlite(data, start, limit):
    _need(start, 100, limit)
    page_size, write, read, _, maximum, minimum, leaf = struct.unpack_from(">HBBBBBB", data, start + 16)
    pages = struct.unpack_from(">I", data, start + 28)[0]
    page_size = 65536 if page_size == 1 else page_size
    if (page_size < 512 or page_size & (page_size - 1) or write not in (1, 2) or read not in (1, 2)
            or (maximum, minimum, leaf) != (64, 32, 32) or not pages or page_size * pages > MAX_FILE):
        return None
    _need(start, page_size * pages, limit)
    return page_size * pages, "sqlite", f"{pages} pages"


RIFF_FORMS = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}
ATRAC9 = bytes.fromhex("d242e147ba368d4d88fc61654f8c836c")  # WAVE_FORMAT_EXTENSIBLE subformat GUID


def _riff(data, start, limit):
    _need(start, 20, limit)
    size, form, chunk = struct.unpack_from("<I4s4s", data, start + 4)
    if size < 12 or size + 8 > MAX_FILE or not _printable(form) or not _printable(chunk):
        return None
    extension = RIFF_FORMS.get(form, "riff")
    if form == b"WAVE" and data.find(ATRAC9, start + 12, min(start + 0x80, limit)) >= 0:
        extension = "at9"
    _need(start, size + 8, limit)
    return size + 8, extension, f"RIFF {form.decode('ascii').strip()}"


def _ogg(data, start, limit):
    """Follows the pages of the first logical stream to its end-of-stream page."""
    position, serial, codec = start, None, ""
    while True:
        _need(position, 27, limit)
        if data[position:position + 4] != b"OggS" or data[position + 4] != 0:
            return (position - start, "ogg", f"{codec} (no end-of-stream page)".strip()) if serial is not None else None
        flags = data[position + 5]
        page = struct.unpack_from("<I", data, position + 14)[0]
        segments = data[position + 26]
        _need(position + 27, segments, limit)
        if serial is None:
            if not flags & 0x02:  # the first page must begin a stream
                return None
            serial = page
            packet = data[position + 27 + segments:position + 35 + segments]
            codec = "Vorbis" if packet.startswith(b"\x01vorbis") else "Opus" if packet.startswith(b"OpusHead") else ""
        position += 27 + segments + sum(data[position + 27:position + 27 + segments])
        if flags & 0x04 and page == serial:
            _need(position, 0, limit)
            return position - start, "ogg", codec


def _sfo(data, start, limit):
    """PS4/PS5 param.sfo (PSF)."""
    _need(start, 20, limit)
    version, keys, values, count = struct.unpack_from("<IIII", data, start + 4)
    if (version not in (0x100, 0x101) or not 0 < count <= 1024 or keys != 20 + 16 * count
            or not keys < values <= 0x10000):
        return None
    _need(start + 20, 16 * count, limit)
    end = values
    for index in range(count):
        _, kind, length, maximum, offset = struct.unpack_from("<HHIII", data, start + 20 + 16 * index)
        if kind not in (0x0004, 0x0204, 0x0404) or length > maximum or values + offset + maximum > MAX_FILE:
            return None
        end = max(end, values + offset + maximum)
    _need(start, end, limit)
    return end, "sfo", f"{count} entries"


PEM_HEADER = re.compile(rb"-----BEGIN ([A-Z0-9 ]{1,40})-----")


def _pem(data, start, limit):
    match = PEM_HEADER.match(data, start, min(limit, start + 64))
    if not match:
        return None
    footer = b"-----END " + match[1] + b"-----"
    found = data.find(footer, match.end(), min(limit, start + MIB))
    if found < 0:
        return None
    end = found + len(footer)
    end += 2 if data[end:end + 2] == b"\r\n" else 1 if data[end:end + 1] == b"\n" else 0
    label = match[1].decode("ascii")
    return end - start, "crt" if "CERTIFICATE" in label else "key" if "KEY" in label else "pem", label


HERMES_MAGIC = bytes.fromhex("c61fbc03c103191f")


def _hermes(data, start, limit):
    """Hermes bytecode: React Native JavaScript compiled by Meta's Hermes engine (the PS5 menus use it).

    The header holds the file length, and the footer the SHA-1 of everything before it.
    """
    _need(start, 128, limit)
    version, = struct.unpack_from("<I", data, start + 8)
    length, _, functions = struct.unpack_from("<III", data, start + 32)
    if not 40 <= version <= 200 or not 128 <= length <= MAX_FILE:
        return None
    _need(start, length, limit)
    body = data[start:start + length]
    verified = hashlib.sha1(body[:-20]).digest() == body[-20:]
    return length, "hbc", (f"Hermes bytecode v{version}, {functions} functions, "
                           + ("SHA-1 verified" if verified else "SHA-1 does not match (changed or incomplete)"))


RNPS_SIGNATURE = 0x180  # RSA-3072 signature after the signed part
COMMON_NAME = re.compile(rb"\x06\x03\x55\x04\x03[\x0c\x13\x16]([\x01-\x7f])")  # X.509 commonName, short form
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # safe as the start of a file name


def _rnps_app(data, start, end):
    """The app's name (rnps-home, rnps-control-center...): the commonName of the last, leaf certificate."""
    names = [data[match.end():match.end() + match[1][0]] for match in COMMON_NAME.finditer(data, start, end)]
    name = names[-1].decode("ascii", "replace") if names else ""
    return name if LABEL.fullmatch(name) else ""


def _rnps(data, start, limit):
    """PS5 React Native app (application.ps.bundle): header, Sony certificates, Hermes payload, signature.

    On the SSD the payload is encrypted; the copy a running app keeps in memory is decrypted.
    """
    _need(start, 0x30, limit)
    version, certificates, _, _, _, offset, padded, length, signed = struct.unpack_from("<9I", data, start + 8)
    if (version != 2 or not 0x30 <= certificates < offset or offset + padded != signed or length > padded
            or signed + RNPS_SIGNATURE > MAX_FILE):
        return None
    payload = data[start + offset:min(start + offset + 8, limit)]
    state = ("decrypted: Hermes bytecode inside" if payload == HERMES_MAGIC
             else "payload not readable here" if len(payload) < 8 else "encrypted payload")
    _need(start, signed + RNPS_SIGNATURE, limit)
    app = _rnps_app(data, start + certificates, start + offset)
    return signed + RNPS_SIGNATURE, "bundle", f"RNPS app bundle{f' {app}' if app else ''}, {state}", app


# Where a PS5 dump says which title ID (NPXS...) an app has: the system's app table, each app's
# manifest and its telemetry "env" block. The bundle itself only carries the app's name.
TITLE_ID_KEY = b'"titleId"'
TITLE_PAIRS = [re.compile(pattern) for pattern in (
    r'"([A-Za-z0-9._-]{2,64})":\{"default":\{"rnps":\{"component":"[A-Za-z0-9_]+","titleId":"(NPXS\d{5})"',
    r'"applicationName":\s*"([A-Za-z0-9._-]{2,64})",[^{}]{0,600}?"titleId":\s*"(NPXS\d{5})"',
    r'"appName":"([A-Za-z0-9._-]{2,64})",[^{}]{0,300}?"titleId":"(NPXS\d{5})"')]


def _app_key(name):
    name = name.lower()
    return name[5:] if name.startswith("rnps-") else name


def _collect_title_ids(data, table):
    """Adds {app name: {title IDs}} found in `data` (ASCII and UTF-16 text) to `table`."""
    wide = TITLE_ID_KEY.decode().encode("utf-16-le")
    for needle, before, after, codec in ((TITLE_ID_KEY, 800, 40, "latin-1"), (wide, 1600, 80, "utf-16-le")):
        position = data.find(needle)
        while position >= 0:
            start = max(0, position - before)
            start += (position - start) % 2 if codec == "utf-16-le" else 0  # stay on character boundaries
            text = data[start:position + after].decode(codec, "replace")
            for pattern in TITLE_PAIRS:
                for match in pattern.finditer(text):
                    table.setdefault(_app_key(match[1]), set()).add(match[2])
            position = data.find(needle, position + len(needle))


def _title_id(app, table):
    """The title ID of a bundle's app: same name (rnps- aside), else the longest app name that starts it.

    rnps-action-cards-host-app is rnps-action-cards in its manifest. No ID when the name has several.
    """
    key = _app_key(app)
    found = table.get(key)
    if not found:
        prefixes = [name for name in table if key.startswith(name + "-")]
        found = table[max(prefixes, key=len)] if prefixes else set()
    return next(iter(found)) if len(found) == 1 else ""


HTML_END = re.compile(rb"</html\s*>", re.IGNORECASE)
HTML_TITLE = re.compile(rb"<title[^>]*>([^<]{1,80})</title>", re.IGNORECASE)


def _html(data, start, limit):
    """A whole HTML document (often with its JavaScript inline), up to </html>."""
    match = HTML_END.search(data, start, min(limit, start + 16 * MIB))
    if not match:
        return None
    text = data[start:match.end()]
    if b"\x00" in text:
        return None  # binary data in between: not one document
    title = HTML_TITLE.search(text)
    return len(text), "html", title[1].decode("utf-8", "replace").strip() if title else ""


# magic -> (type, parser); `type` is what callers filter on (riff covers wav/at9/avi/webp, pem covers crt/key)
SIGNATURES = {
    b"\x7fELF": ("elf", _elf),
    b"\x4f\x15\x3d\x1d": ("self", _self),  # PS4
    b"\x54\x14\xf5\xee": ("self", _self),  # PS5
    b"\x00PSF": ("sfo", _sfo),
    b"RNPSHEDR": ("rnps", _rnps),
    HERMES_MAGIC: ("hbc", _hermes),
    b"<!doctype html": ("html", _html),
    b"<!DOCTYPE html": ("html", _html),
    b"<!DOCTYPE HTML": ("html", _html),
    b"\x89PNG\r\n\x1a\n": ("png", _png),
    b"\xff\xd8\xff": ("jpg", _jpeg),
    b"GIF87a": ("gif", _gif),
    b"GIF89a": ("gif", _gif),
    b"RIFF": ("riff", _riff),
    b"OggS": ("ogg", _ogg),
    b"PK\x03\x04": ("zip", _zip),
    b"\x1f\x8b\x08": ("gz", _gzip),
    b"SQLite format 3\x00": ("sqlite", _sqlite),
    b"-----BEGIN ": ("pem", _pem),
}
TYPES = tuple(dict.fromkeys(kind for kind, _ in SIGNATURES.values()))
CONTAINERS = {"self", "zip", "ogg"}  # hits inside these are parts of them, not files of their own
EXTENSIONS = dict(rnps="bundle")  # for truncated hits, whose parser never named the extension


def _carve(data, kinds, cancel, on_position, titles=None):
    """[offset, size, extension, note, truncated, label] for every hit that parses, in offset order.

    `titles` ({app name: {title IDs}}) adds the title ID to the name of app bundles and their contents.
    """
    hits = []
    magics = [magic for magic, (kind, _) in SIGNATURES.items() if kind in kinds]
    length = len(data)
    candidates = []
    for index, magic in enumerate(magics):  # one fast search per magic beats one regex over all of them
        position = data.find(magic)
        while position >= 0:
            if not len(candidates) % 4096:
                check_cancel(cancel)
            candidates.append((position, magic))
            position = data.find(magic, position + 1)
        on_position(length * (index + 1) // len(magics))
    inside = 0
    for start, magic in sorted(candidates):
        check_cancel(cancel)
        if start < inside:
            continue
        kind, parser = SIGNATURES[magic]
        limit = min(length, start + MAX_FILE)
        try:
            result, truncated = parser(data, start, limit), False
        except _Truncated:
            result, truncated = None, limit == length and length - start >= MIN_TRUNCATED
            if truncated:
                result = (length - start, EXTENSIONS.get(kind, kind), "truncated: continues past the end of the region")
        except (IndexError, struct.error, ValueError, OverflowError):
            result = None
        if result is None:
            continue
        size, extension, note, *label = result
        if kind in CONTAINERS:
            inside = start + size
        hits.append([start, size, extension, note, truncated, label[0] if label else ""])
    # A packed ELF's headers do not describe how its body is stored: it ends where the next ELF starts.
    elves = [hit for hit in hits if hit[2] == "elf"]
    for hit, following in zip(elves, elves[1:]):
        if PACKED in hit[3] and following[0] < hit[0] + hit[1]:
            hit[3] += f"; cut where the next ELF starts (the headers declare 0x{hit[1]:x} bytes)"
            hit[1], hit[4] = following[0] - hit[0], False
    # What sits inside a named app bundle (its Hermes payload, HTML in its strings) belongs to that app.
    for bundle in [hit for hit in hits if hit[2] == "bundle" and hit[5]]:
        app, title = bundle[5], _title_id(bundle[5], titles or {})
        if title:
            bundle[3], bundle[5] = f"{bundle[3]}; title ID {title}", f"{title}_{app}"
        for hit in hits:
            if bundle[0] < hit[0] < bundle[0] + bundle[1] and not hit[5]:
                where = f"inside the {app} bundle" + (f" ({title})" if title else "")
                hit[3], hit[5] = f"{hit[3]}; {where}".lstrip("; "), bundle[5]
    return hits


def _sources(source, regions):
    """(file, address of its first byte or None, region name) for every .bin to scan."""
    if source.is_file():
        # a region file of a dump still gets its addresses
        manifest = find_manifest(source.parent) and load_manifest(source.parent)
        region = next((r for r in (manifest or {}).get("regions", []) if r.get("file") == source.name), None)
        if region is not None and (manifest.get("gap_fill") == "zeros" or not region.get("gaps")):
            return [(source, int(region["start"], 16), region.get("name", ""))]
        return [(source, None, "")]
    if not source.is_dir():
        raise ValueError(f"The source does not exist: {source}")
    if find_manifest(source) is None:
        return [(path, None, "") for path in list_bin_files(source)]
    document = load_manifest(source)
    exact = document.get("gap_fill") == "zeros"  # otherwise offsets drift after an unpadded gap
    items = []
    for region in sorted(regions if regions is not None else document["regions"], key=lambda r: int(r["start"], 16)):
        if not region.get("file"):
            continue
        path = (source / region["file"]).resolve()
        if path.parent != source:
            raise ValueError(f"Invalid file path in the manifest: {region['file']}")
        if path.is_file():
            address = int(region["start"], 16) if exact or not region.get("gaps") else None
            items.append((path, address, region.get("name", "")))
    return items


def default_destination(source):
    """`extracted` inside a folder, `<name>_extracted` next to a file; numbered if it already exists."""
    source = Path(source).expanduser().resolve()
    base = source / "extracted" if source.is_dir() else source.with_name(f"{source.stem}_extracted")
    candidate, number = base, 2
    while candidate.exists():
        candidate, number = base.with_name(f"{base.name}_{number}"), number + 1
    return candidate


def _starts_with(path, content):
    with path.open("rb") as stream:
        return stream.read(len(content)) == content


def _location(address, path, offset):
    return f"{address + offset:016x}" if address is not None else f"{path.stem}_{offset:08x}"


def _write_strings(data, path, address, output, minimum, cancel, on_position):
    """`address<TAB>A|U<TAB>text` per line: A = ASCII, U = UTF-16LE. Returns the number of strings."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}|(?:[\x20-\x7e]\x00){%d,}" % (minimum, minimum))
    count = 0
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(f"# Strings of {path.name} (at least {minimum} characters); A = ASCII, U = UTF-16LE\n")
        for match in pattern.finditer(data):
            if not count % 4096:
                check_cancel(cancel)
                on_position(match.start())
            raw = match.group()
            wide = len(raw) > 1 and raw[1] == 0
            text = raw.decode("utf-16-le" if wide else "ascii")
            where = f"0x{address + match.start():016x}" if address is not None else f"0x{match.start():08x}"
            stream.write(f"{where}\t{'U' if wide else 'A'}\t{text}\n")
            count += 1
    return count


def extract_files(source, destination=None, regions=None, kinds=None, strings=False, min_string=MIN_STRING,
                  reporter=None, cancel=None):
    """Copies every file found inside `source` to `destination`, one folder per file type, plus index.csv.

    `source` is a dump folder (addresses come from its manifest; `regions` limits the scan to some
    of them), a folder of .bin files or a single file. `destination` must not exist yet; by default
    it is `extracted` inside the folder, or `<name>_extracted` next to the file. `kinds` limits the
    types (see TYPES). With `strings`, also writes strings/<bin>.txt with the text of each .bin.
    """
    reporter = reporter or Reporter()
    source = Path(source).expanduser().resolve()
    kinds = set(TYPES if kinds is None else kinds)
    unknown = kinds - set(TYPES)
    if unknown:
        raise ValueError(f"Unknown file type(s): {', '.join(sorted(unknown))}; choose from {', '.join(TYPES)}")
    if not kinds and not strings:
        raise ValueError("Choose at least one file type, or strings")
    items = _sources(source, regions)
    if not items:
        raise ValueError("There are no .bin files to scan")
    destination = Path(destination).expanduser().resolve() if destination else default_destination(source)
    destination.mkdir(parents=True, exist_ok=False)
    sizes = [path.stat().st_size for path, _, _ in items]
    passes = 2 if strings and kinds else 1
    total = max(sum(sizes) * passes, 1)
    reporter.log(f"Scanning {len(items)} file(s), {sum(sizes) / MIB:.2f} MiB, for: "
                 + ", ".join(sorted(kinds) + (["strings"] if strings else [])))
    rows, seen, written = [], {}, Counter()
    starts = {}  # (extension, SHA-256 of the first bytes) -> a complete file, to spot partial copies of it
    string_count, truncated_count, done = 0, 0, 0
    titles = {}  # app name -> title IDs, read from the whole source so ticked regions still get them
    try:
        if "rnps" in kinds:
            for path, _, _ in _sources(source, None):
                check_cancel(cancel)
                if path.stat().st_size:
                    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                        _collect_title_ids(data, titles)
            if titles:
                reporter.log(f"App title IDs found in memory: {len(titles)} app name(s)")
        for (path, address, region), size in zip(items, sizes):
            if not size:
                continue
            with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                found = 0
                for offset, length, extension, note, truncated, label in _carve(
                        data, kinds, cancel, lambda position: reporter.progress(done + position, total, 0), titles):
                    content = data[offset:offset + length]
                    digest = hashlib.sha256(content).hexdigest()
                    start_key = (extension, hashlib.sha256(content[:MIN_TRUNCATED]).digest())
                    if digest in seen:
                        relative, note = seen[digest], f"{note}; same content as {seen[digest]}".lstrip("; ")
                    elif truncated and start_key in starts and _starts_with(destination / starts[start_key], content):
                        relative, note = starts[start_key], f"partial copy of {starts[start_key]}"
                    else:
                        name = ((f"{label}_" if label else "") + _location(address, path, offset)
                                + ("_truncated" if truncated else ""))
                        relative = f"{extension}/{name}.{extension}"
                        (destination / extension).mkdir(exist_ok=True)
                        (destination / relative).write_bytes(content)
                        seen[digest] = relative
                        if not truncated:
                            starts.setdefault(start_key, relative)
                        truncated_count += truncated
                        written[extension] += 1
                        found += 1
                    rows.append(dict(type=extension, file=relative, size=length, source=path.name,
                                     offset=f"0x{offset:x}",
                                     address=f"0x{address + offset:x}" if address is not None else "",
                                     region=region, sha256=digest, note=note))
                if found:
                    reporter.log(f"{path.name}{f' ({region})' if region else ''}: {found} file(s)")
                if kinds:
                    done += size
                if strings:
                    (destination / STRINGS_FOLDER).mkdir(exist_ok=True)
                    string_count += _write_strings(
                        data, path, address, destination / STRINGS_FOLDER / f"{path.stem}.txt", min_string, cancel,
                        lambda position: reporter.progress(done + position, total, 0))
                    done += size
            reporter.progress(done, total, 0)
    finally:
        index = destination / INDEX_NAME
        with index.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, ["type", "file", "size", "source", "offset", "address", "region",
                                             "sha256", "note"])
            writer.writeheader()
            writer.writerows(rows)
    files = sum(written.values())
    reporter.log(f"Extracted {files} file(s)" + (f" ({', '.join(f'{n} {e}' for e, n in written.most_common())})"
                                                 if files else "")
                 + (f", {len(rows) - files} repeated" if len(rows) > files else "")
                 + (f", {string_count} strings" if strings else ""), "ok")
    reporter.log(f"Destination: {destination}", "ok")
    return dict(destination=str(destination), scanned=len(items), bytes=sum(sizes), files=files,
                types=dict(written), repeated=len(rows) - files, truncated=truncated_count, strings=string_count,
                index=str(index))
