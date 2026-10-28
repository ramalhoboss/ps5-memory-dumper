"""Offline tools on dumped files: literal concatenation, flat images and ELF export."""
import hashlib
import re
import shutil
import struct
from pathlib import Path

from .manifest import load_manifest
from .reader import MIB, PAGE, write_zeros
from .reporting import Reporter, check_cancel

MAX_MERGE_SPAN = 4096 * MIB  # refuse flat images larger than this unless the caller raises it
ELF_TYPES = dict(exec=2, core=4)  # ET_EXEC, ET_CORE
ELF_HEADER_SIZE, PHDR_SIZE = 64, 56
ELFOSABI_FREEBSD, EM_X86_64, PT_LOAD = 9, 62, 1
PF_X, PF_W, PF_R = 1, 2, 4


def natural_key(path):
    return tuple((0, int(part)) if part.isdigit() else (1, part.lower())
                 for part in re.split(r"(\d+)", Path(path).name))


def list_bin_files(folder):
    folder = Path(folder).expanduser().resolve()
    if not folder.is_dir():
        raise ValueError("The source folder does not exist")
    return sorted((p for p in folder.iterdir() if p.is_file() and p.suffix.lower() == ".bin"),
                  key=natural_key)


def _check_free_space(destination, needed):
    free = shutil.disk_usage(destination.parent).free
    if free < needed:
        raise OSError(f"Not enough space: {free / MIB:.0f} MiB free, {needed / MIB:.0f} MiB needed")


def _write_new(destination, write):
    """Creates `destination` (never overwrites) and removes it if `write` fails half-way."""
    if destination.exists():
        raise FileExistsError(f"The destination already exists: {destination}")
    try:
        with destination.open("xb") as output:
            return write(output)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def concatenate_files(files, destination, reporter=None, cancel=None):
    """Literal concatenation: does not restore memory ranges or gaps."""
    reporter = reporter or Reporter()
    files = [Path(p).expanduser().resolve() for p in files]
    destination = Path(destination).expanduser().resolve()
    if not files:
        raise ValueError("There are no .bin files to concatenate")
    if len(set(files)) != len(files):
        raise ValueError("The list contains repeated files")
    if destination in files:
        raise ValueError("The destination cannot be one of the source files")
    sizes = [p.stat().st_size for p in files]
    total = sum(sizes)
    _check_free_space(destination, total)
    reporter.log("Concatenation order:")
    for index, (source, size) in enumerate(zip(files, sizes), 1):
        reporter.log(f"  {index}. {source.name} ({size} bytes)")
    reporter.log("Literal join of the bytes; memory addresses and gaps are not rebuilt.")
    digest = hashlib.sha256()

    def write(output):
        written = 0
        for source, expected in zip(files, sizes):
            read = 0
            with source.open("rb") as stream:
                while data := stream.read(MIB):
                    check_cancel(cancel)
                    read += len(data)
                    if read > expected:
                        raise RuntimeError(f"The source changed while being read: {source}")
                    output.write(data)
                    digest.update(data)
                    written += len(data)
                    reporter.progress(written, total, 0)
            if read != expected:
                raise RuntimeError(f"The source changed while being read: {source}")
        return written

    written = _write_new(destination, write)
    reporter.log(f"Concatenated {len(files)} files: {written} bytes", "ok")
    reporter.log(f"Destination: {destination}", "ok")
    reporter.log(f"SHA-256: {digest.hexdigest()}", "ok")
    return dict(destination=str(destination), bytes=written, sha256=digest.hexdigest())


def _checked_regions(folder, document, regions):
    """Regions sorted by address whose files exist and whose file offsets equal address - start."""
    regions = sorted(regions, key=lambda r: int(r["start"], 16))
    if not regions:
        raise ValueError("Select at least one region")
    for previous, current in zip(regions, regions[1:]):
        if int(current["start"], 16) < int(previous["end"], 16):
            raise ValueError(f"Regions overlap at {current['start']}")
    for region in regions:
        if not region.get("file"):
            raise ValueError(f"Region {region['start']} has no file (nothing was read)")
        if region.get("gaps") and document.get("gap_fill") != "zeros":
            raise ValueError(f"Region {region['start']} has gaps that were not zero-filled, "
                             "so its file offsets do not match addresses")
        path = (folder / region["file"]).resolve()
        if path.parent != folder:
            raise ValueError(f"Invalid file path in the manifest: {region['file']}")
        if path.stat().st_size > int(region["end"], 16) - int(region["start"], 16):
            raise ValueError(f"{path.name} is larger than its region")
    return regions


def _copy_region(output, digest, folder, region, cancel, on_copied):
    """Copies a region file, checking it against the SHA-256 in the manifest; returns the bytes copied."""
    path = (folder / region["file"]).resolve()
    copied = 0
    actual = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(MIB):
            check_cancel(cancel)
            output.write(data)
            digest.update(data)
            actual.update(data)
            copied += len(data)
            on_copied(copied)
    if region.get("sha256") and actual.hexdigest() != region["sha256"]:
        raise ValueError(f"{path.name} does not match the SHA-256 in the manifest")
    return copied


def merge_regions(folder, regions, destination, max_span=MAX_MERGE_SPAN, reporter=None, cancel=None):
    """Writes one flat image of [first start, last end) from regions of a dump manifest.

    Each region lands at offset = address - first start, and everything that was not
    received (holes between regions, gaps, unread tails) is zero-filled, so the file
    can be loaded at the first start address in a disassembler. Files are checked
    against the SHA-256 in the manifest while they are copied.
    """
    reporter = reporter or Reporter()
    folder = Path(folder).expanduser().resolve()
    destination = Path(destination).expanduser().resolve()
    regions = _checked_regions(folder, load_manifest(folder), regions)
    base, end = int(regions[0]["start"], 16), int(regions[-1]["end"], 16)
    span = end - base
    if span > max_span:
        raise ValueError(f"The image would span {span / MIB:.0f} MiB (limit {max_span / MIB:.0f} MiB); "
                         "select regions that are closer together")
    _check_free_space(destination, span)
    reporter.log(f"Merging {len(regions)} region(s) into 0x{base:x}-0x{end:x} ({span / MIB:.2f} MiB)")
    digest = hashlib.sha256()

    def write(output):
        position = base
        for region in regions:
            start, stop = int(region["start"], 16), int(region["end"], 16)
            write_zeros(output, digest, start - position)
            copied = _copy_region(output, digest, folder, region, cancel,
                                  lambda n: reporter.progress(start - base + n, span, 0))
            write_zeros(output, digest, stop - start - copied)
            position = stop
        return position - base

    size = _write_new(destination, write)
    reporter.log(f"Flat image written: {destination} ({size} bytes, base 0x{base:x})", "ok")
    reporter.log(f"SHA-256: {digest.hexdigest()}", "ok")
    return dict(destination=str(destination), start=hex(base), end=hex(end), bytes=size,
                sha256=digest.hexdigest())


def _align(value, alignment=PAGE):
    return -(-value // alignment) * alignment


def _segment_flags(prot):
    """Region prot (r=1, w=2, x=4) to ELF p_flags (PF_X=1, PF_W=2, PF_R=4); unknown -> RW."""
    if prot is None:
        return PF_R | PF_W
    return (PF_R if prot & 1 else 0) | (PF_W if prot & 2 else 0) | (PF_X if prot & 4 else 0)


def export_elf(folder, regions, destination, elf_type="exec", reporter=None, cancel=None):
    """Writes an x86-64 ELF with one PT_LOAD segment per region at its real address.

    p_filesz is the data in the region file and p_memsz the region size, so loaders
    zero-fill unread tails; gaps inside files are already zeros. 'exec' (ET_EXEC, the
    default) opens as a program image in Ghidra and IDA; 'core' (ET_CORE) marks it as a
    memory snapshot. There are no section headers: region names stay in manifest.json.
    """
    reporter = reporter or Reporter()
    if elf_type not in ELF_TYPES:
        raise ValueError(f"The ELF type must be one of: {', '.join(ELF_TYPES)}")
    folder = Path(folder).expanduser().resolve()
    destination = Path(destination).expanduser().resolve()
    regions = _checked_regions(folder, load_manifest(folder), regions)
    if len(regions) >= 0xFFFF:
        raise ValueError("Too many regions for one ELF (65534 at most)")
    layout = []
    offset = _align(ELF_HEADER_SIZE + PHDR_SIZE * len(regions))
    for region in regions:
        size = (folder / region["file"]).stat().st_size
        layout.append((region, offset, size))
        offset = _align(offset + size)
    _check_free_space(destination, offset)
    total = sum(size for _, _, size in layout) or 1
    header = struct.pack("<4s5B7sHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, ELFOSABI_FREEBSD, 0, bytes(7),
                         ELF_TYPES[elf_type], EM_X86_64, 1, 0, ELF_HEADER_SIZE, 0, 0, ELF_HEADER_SIZE,
                         PHDR_SIZE, len(regions), 64, 0, 0)
    program_headers = b"".join(
        struct.pack("<IIQQQQQQ", PT_LOAD, _segment_flags(region.get("prot")), file_offset,
                    int(region["start"], 16), int(region["start"], 16), size,
                    int(region["end"], 16) - int(region["start"], 16), PAGE)
        for region, file_offset, size in layout)
    reporter.log(f"Exporting {len(regions)} region(s) as an ELF ({elf_type}), {offset / MIB:.2f} MiB")
    digest = hashlib.sha256()

    def write(output):
        output.write(header + program_headers)
        digest.update(header + program_headers)
        position = len(header) + len(program_headers)
        written = 0
        for region, file_offset, size in layout:
            write_zeros(output, digest, file_offset - position)
            _copy_region(output, digest, folder, region, cancel,
                         lambda n: reporter.progress(written + n, total, 0))
            written += size
            position = file_offset + size
        return position

    size = _write_new(destination, write)
    reporter.log(f"ELF written: {destination} ({size} bytes, {len(regions)} segments)", "ok")
    reporter.log(f"SHA-256: {digest.hexdigest()}", "ok")
    return dict(destination=str(destination), segments=len(regions), bytes=size, sha256=digest.hexdigest(),
                start=regions[0]["start"])
