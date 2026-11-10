"""Offline checks for file extraction (carving) from dumped .bin files."""
import csv
import gzip
import hashlib
import io
import random
import sqlite3
import struct
import tempfile
import unittest
import wave
import zipfile
import zlib
from pathlib import Path

from ps5dumper.core.extract import ATRAC9, HERMES_MAGIC, TYPES, extract_files
from ps5dumper.core.manifest import save_manifest


def png(width=3, height=2, colour=0, pixels=None):
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    rows = pixels or b"".join(b"\x00" + bytes([colour]) * width * 3 for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def jpeg():
    """Structurally valid baseline JPEG; the scan holds stuffed 0xFF bytes and a restart marker."""
    def segment(marker, body):
        return b"\xff" + bytes([marker]) + struct.pack(">H", len(body) + 2) + body
    return (b"\xff\xd8" + segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
            + segment(0xDB, b"\x00" + bytes(range(1, 65)))
            + segment(0xC0, b"\x08\x00\x10\x00\x20\x01\x01\x11\x00")
            + segment(0xC4, b"\x00" + bytes(16) + b"")
            + segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
            + b"\x12\x34\xff\x00\x56\xff\xd0\x78\x9a\xff\xff\xd9")


def gif():
    return (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
            b"\x21\xf9\x04\x01\x00\x00\x00\x00"
            b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")


def ogg():
    def page(flags, sequence, packet):
        return (b"OggS\x00" + bytes([flags]) + struct.pack("<qIII", 0, 77, sequence, 0)
                + bytes([1, len(packet)]) + packet)
    return page(0x02, 0, b"\x01vorbis" + bytes(22)) + page(0x00, 1, b"x" * 40) + page(0x04, 2, b"y" * 9)


def elf(payload=b"\x90" * 300):
    header = struct.pack("<4s5B7sHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 9, 0, bytes(7), 0xFE10, 62, 1, 0x400000,
                         64, 0, 0, 64, 56, 1, 64, 0, 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 120, 0x400000, 0x400000, len(payload), len(payload), 0x4000)
    return header + program + payload


def self_file():
    """PS5 SELF holding an ELF: the inner ELF header must not be extracted on its own."""
    inner = elf(b"\xcc" * 900)
    header = struct.pack("<4s4BIHHQHHI", b"\x54\x14\xf5\xee", 0x10, 1, 1, 0x32, 0x10000301, 64, 32,
                         64 + len(inner), 1, 0x52, 0)
    return header + struct.pack("<QQQQ", 0x4, 64, len(inner), len(inner)) + inner


def sfo():
    keys = b"TITLE\x00TITLE_ID\x00\x00\x00"
    values = b"My Game\x00".ljust(16, b"\x00") + b"PPSA01234\x00".ljust(12, b"\x00")
    index = struct.pack("<HHIII", 0, 0x0204, 8, 16, 0) + struct.pack("<HHIII", 6, 0x0204, 10, 12, 16)
    key_start = 20 + len(index)
    return (struct.pack("<4sIIII", b"\x00PSF", 0x101, key_start, key_start + len(keys), 2) + index + keys + values)


def wav():
    stream = io.BytesIO()
    with wave.open(stream, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(bytes(range(200)))
    return stream.getvalue()


def at9():
    fmt = struct.pack("<HHIIHHHHI", 0xFFFE, 2, 48000, 0, 0, 0, 22, 0, 0) + ATRAC9 + bytes(12)
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", 64) + bytes(64)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def sqlite_file(folder):
    path = folder / "sample.db"
    connection = sqlite3.connect(path)
    connection.execute("create table t (v text)")
    connection.execute("insert into t values ('ps5')")
    connection.commit()
    connection.close()
    return path.read_bytes()


def zip_file(inner):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("readme.txt", "hello " * 50, compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("inner.png", inner, compress_type=zipfile.ZIP_STORED)
    return stream.getvalue()


def hermes(size=700, functions=3):
    """Hermes bytecode whose footer is the SHA-1 of the rest, as the engine writes it."""
    header = HERMES_MAGIC + struct.pack("<I", 89) + bytes(20) + struct.pack("<III", size, 0, functions)
    body = (header + bytes(range(256)) * (size // 256 + 1))[:size - 20]
    return body + hashlib.sha1(body).digest()


def rnps(payload, app=b"rnps-home"):
    """application.ps.bundle layout: header, certificates, payload padded to 16, 384-byte signature."""
    offset, padded = 0xB20, -(-len(payload) // 16) * 16
    header = b"RNPSHEDR" + struct.pack("<9I", 2, 0x1D0, 0x4AE, 0x67E, 0x49B, offset, padded, len(payload),
                                       offset + padded)
    names = b"".join(b"\x06\x03\x55\x04\x03\x0c" + bytes([len(name)]) + name + b"0"
                     for name in (b"SIE RNPS Root", app))
    certificates = (names + b"CERT" * 1000)[:offset - 0x1D0]  # the last commonName is the app's
    return (header.ljust(0x1D0, b"\x00") + certificates + payload.ljust(padded, b"\x00")
            + bytes(range(256)) + bytes(range(128)))


HTML = b"<!DOCTYPE html>\n<html><head><title>Store</title></head><body><script>const a = 1;</script></body></html>"
PEM = b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ0xQ\n-----END CERTIFICATE-----\n"


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name) / "dump"
        self.folder.mkdir()
        self.random = random.Random(5)

    def tearDown(self):
        self.temporary.cleanup()

    def noise(self, size):
        """Random bytes salted with signatures that must not parse."""
        data = bytearray(self.random.randbytes(size))
        for junk in (b"\xff\xd8\xff\x00\x00", b"PK\x03\x04\xff\xff", b"\x7fELF\x05", b"RIFF\x00\x00\x00\x00",
                     b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dXXXX", b"OggS\x00\x00"):
            position = self.random.randrange(0, size - len(junk))
            data[position:position + len(junk)] = junk
        return bytes(data)

    def write_dump(self, regions):
        """regions: (start, [parts]); returns {address of each bytes part: part}."""
        placed, entries = {}, []
        for start, parts in regions:
            data = bytearray()
            for part in parts:
                if isinstance(part, int):
                    data += self.noise(part)
                else:
                    placed.setdefault(start + len(data), part)
                    data += part
            name = f"{start:016x}-{start + len(data):016x}.bin"
            (self.folder / name).write_bytes(data)
            entries.append(dict(name="executable", start=hex(start), end=hex(start + len(data)), file=name,
                                bytes=len(data), complete=True, gaps=[], prot=5))
        save_manifest(self.folder, dict(format_version=2, type="process", gap_fill="zeros", regions=entries))
        return placed

    def rows(self, result):
        with open(result["index"], encoding="utf-8", newline="") as stream:
            return list(csv.DictReader(stream))

    def test_every_type_is_extracted_exactly_at_its_address(self):
        image = png()
        samples = [elf(), self_file(), sfo(), image, jpeg(), gif(), wav(), at9(), ogg(),
                   zip_file(png(5, 5, 9)), gzip.compress(b"ps5 " * 4000), sqlite_file(Path(self.temporary.name)), PEM]
        parts = []
        for sample in samples:
            parts += [self.random.randrange(64, 4096), sample]
        placed = self.write_dump([(0x400000, parts + [4096]), (0x800000, [2048, image, 512])])
        result = extract_files(self.folder)
        destination = Path(result["destination"])
        self.assertEqual(destination, self.folder / "extracted")
        rows = {int(row["address"], 16): row for row in self.rows(result)}
        self.assertEqual(set(rows), set(placed), "every sample found, nothing else (the PNG inside the ZIP neither)")
        for address, sample in placed.items():
            row = rows[address]
            self.assertEqual((destination / row["file"]).read_bytes(), sample, row)
            self.assertEqual(int(row["size"]), len(sample))
        extensions = sorted(row["type"] for row in rows.values())
        self.assertEqual(extensions, sorted(["elf", "self", "sfo", "png", "png", "jpg", "gif", "wav", "at9", "ogg",
                                             "zip", "gz", "sqlite", "crt"]))
        self.assertEqual(rows[0x800000 + 2048]["file"], rows[min(a for a, s in placed.items() if s == image)]["file"],
                         "the repeated PNG points to the first copy")
        self.assertEqual(result["repeated"], 1)
        self.assertEqual(result["files"], len(placed) - 1)
        self.assertIn("SCE dynamic executable", rows[min(placed)]["note"])

    def test_truncated_file_at_the_end_of_a_region(self):
        image = png(64, 64, pixels=self.random.randbytes(64 * (64 * 3 + 1)))
        cut = image[:len(image) - 20]
        self.write_dump([(0x10000, [100, cut])])
        result = extract_files(self.folder)
        (row,) = self.rows(result)
        self.assertTrue(row["file"].endswith("_truncated.png"))
        self.assertEqual((Path(result["destination"]) / row["file"]).read_bytes(), cut)
        self.assertEqual(result["truncated"], 1)

    def test_types_filter_strings_and_selected_regions(self):
        self.write_dump([(0x1000, [bytes(64), b"hello_ps5_world", bytes(64), png()]),
                         (0x9000, [bytes(64), "wide_text_here".encode("utf-16-le"), bytes(64), jpeg()])])
        result = extract_files(self.folder, Path(self.temporary.name) / "out", kinds=["jpg"], strings=True)
        self.assertEqual([row["type"] for row in self.rows(result)], ["jpg"])
        strings = Path(result["destination"]) / "strings"
        lines = next(strings.glob("0000000000001000-*.txt")).read_text(encoding="utf-8").splitlines()
        self.assertIn("0x0000000000001040\tA\thello_ps5_world", lines)
        lines = next(strings.glob("0000000000009000-*.txt")).read_text(encoding="utf-8").splitlines()
        self.assertIn("0x0000000000009040\tU\twide_text_here", lines)
        from ps5dumper.core.manifest import load_manifest
        second = load_manifest(self.folder)["regions"][1:]
        result = extract_files(self.folder, regions=second)
        self.assertEqual([row["type"] for row in self.rows(result)], ["jpg"])
        self.assertTrue(result["destination"].endswith("extracted"))
        again = extract_files(self.folder, regions=second)
        self.assertTrue(again["destination"].endswith("extracted_2"), "never writes into an existing folder")

    def test_single_file_and_loose_folder(self):
        loose = Path(self.temporary.name) / "loose"
        loose.mkdir()
        (loose / "a.bin").write_bytes(self.noise(300) + gif() + self.noise(50))
        result = extract_files(loose / "a.bin")
        (row,) = self.rows(result)
        self.assertEqual(row["file"], "gif/a_0000012c.gif")
        self.assertEqual(row["address"], "")
        self.assertEqual(Path(result["destination"]), loose / "a_extracted")
        result = extract_files(loose)
        self.assertEqual(len(self.rows(result)), 1)
        with self.assertRaises(ValueError):
            extract_files(loose, kinds=["exe"])
        self.assertIn("png", TYPES)

    def test_packed_elf_is_cut_where_the_next_elf_starts(self):
        body = self.random.randbytes(6000)  # encrypted-looking segment data
        first, second = elf(body)[:120 + 5000], elf(body)  # the first stores less than its headers declare
        self.write_dump([(0x30000, [bytes(64), first, second, bytes(64)])])
        rows = self.rows(extract_files(self.folder))
        self.assertEqual([int(row["size"]) for row in rows], [len(first), len(second)])
        self.assertIn("cut where the next ELF starts", rows[0]["note"])
        self.assertIn("encrypted or compressed", rows[1]["note"])

    def test_react_native_bundles_hermes_and_html(self):
        app = hermes(5000, functions=42)
        bundle = rnps(app)
        self.write_dump([(0x201800000, [bytes(256), bundle, bytes(256), hermes(), bytes(64), HTML, 300]),
                         (0x207504000, [bytes(128), bundle[:6000]])])  # cut-off copy of the bundle
        rows = {int(row["address"], 16): row for row in self.rows(extract_files(self.folder))}
        start = 0x201800000 + 256
        self.assertEqual(rows[start]["type"], "bundle")
        self.assertEqual(rows[start]["note"], "RNPS app bundle rnps-home, decrypted: Hermes bytecode inside")
        self.assertEqual(rows[start]["file"], f"bundle/rnps-home_{start:016x}.bundle")
        self.assertEqual(int(rows[start]["size"]), len(bundle))
        inner = rows[start + 0xB20]
        self.assertEqual((inner["type"], int(inner["size"])), ("hbc", len(app)))
        self.assertEqual(inner["note"],
                         "Hermes bytecode v89, 42 functions, SHA-1 verified; inside the rnps-home bundle")
        self.assertEqual(inner["file"], f"hbc/rnps-home_{start + 0xB20:016x}.hbc")
        self.assertEqual((self.folder / "extracted" / inner["file"]).read_bytes(), app)
        html = next(row for row in rows.values() if row["type"] == "html")
        self.assertEqual((int(html["size"]), html["note"]), (len(HTML), "Store"))
        self.assertNotIn("rnps-home", html["file"])  # outside the bundle
        copy = rows[0x207504000 + 128]
        self.assertEqual(copy["note"], f"partial copy of {rows[start]['file']}")
        self.assertFalse(list((self.folder / "extracted" / "bundle").glob("*_truncated*")))
        encrypted = bytearray(rnps(app, b"../evil"))  # a name that is not safe in a path is left out
        encrypted[0xB20:0xB28] = b"\x13" * 8
        broken = bytearray(app)
        broken[300] ^= 1
        self.write_dump([(0x1000, [bytes(64), bytes(encrypted), bytes(64), bytes(broken), bytes(64)])])
        rows = self.rows(extract_files(self.folder))
        self.assertEqual([row["note"] for row in rows],
                         ["RNPS app bundle, encrypted payload",
                          "Hermes bytecode v89, 42 functions, SHA-1 does not match (changed or incomplete)"])

    def test_app_bundles_are_named_with_their_title_id_from_memory(self):
        table = (b'{"rnps-homeui":{"default":{"rnps":{"component":"Main","titleId":"NPXS40001"}}},'
                 b'"rnps-action-cards-host":{"default":{"rnps":{"component":"Main","titleId":"NPXS40036"}}}}')
        manifest = ('{\n    "applicationName": "rnps-home",\n    "applicationVersion": "13.6.0+96197",\n'
                    '    "titleId": "NPXS40002"\n}').encode("utf-16-le")  # the shell keeps these as UTF-16
        env = b'"env":{"appName":"universal-checkout","buildVersion":"13.6.0+96197","titleId":"NPXS40062"}'
        apps = [b"rnps-home", b"rnps-action-cards-host-app", b"rnps-universal-checkout", b"js-launcher"]
        bundles = [rnps(hermes(900 + 16 * index), app) for index, app in enumerate(apps)]
        parts = []
        for bundle in bundles:
            parts += [64, bundle]
        self.write_dump([(0x201800000, parts + [64]), (0x880000000, [64, table, 65, manifest, 64, env, 64])])
        from ps5dumper.core.manifest import load_manifest
        first = load_manifest(self.folder)["regions"][:1]  # the tables are in a region that is not ticked
        rows = [row for row in self.rows(extract_files(self.folder, regions=first, kinds=["rnps", "hbc"]))]
        names = [row["file"].split("/")[1].rsplit("_", 1)[0] for row in rows]
        self.assertEqual(names, ["NPXS40002_rnps-home", "NPXS40002_rnps-home",  # same name, rnps- aside
                                 "NPXS40036_rnps-action-cards-host-app", "NPXS40036_rnps-action-cards-host-app",
                                 "NPXS40062_rnps-universal-checkout", "NPXS40062_rnps-universal-checkout",
                                 "js-launcher", "js-launcher"])  # prefix of the table's name / env name / none
        self.assertTrue(rows[0]["note"].endswith("; title ID NPXS40002"))
        self.assertTrue(rows[1]["note"].endswith("; inside the rnps-home bundle (NPXS40002)"))
        self.assertTrue(rows[7]["note"].endswith("; inside the js-launcher bundle"))

    def test_title_id_is_left_out_when_memory_disagrees(self):
        from ps5dumper.core.extract import _title_id
        self.assertEqual(_title_id("rnps-home", {"home": {"NPXS40002", "NPXS40099"}}), "")
        self.assertEqual(_title_id("rnps-action-cards-host-app", {"action": {"NPXS1"}, "action-cards": {"NPXS2"}}),
                         "NPXS2")  # the longest name that starts it
        self.assertEqual(_title_id("rnps-homeui", {"home": {"NPXS40002"}}), "")  # not at a word boundary

    def test_region_file_of_a_dump_keeps_its_address(self):
        self.write_dump([(0x20000, [200, ogg(), 200])])
        source = next(self.folder.glob("*.bin"))
        (row,) = self.rows(extract_files(source))
        self.assertEqual(row["address"], "0x200c8")
        self.assertEqual(row["note"], "Vorbis")


if __name__ == "__main__":
    unittest.main()
