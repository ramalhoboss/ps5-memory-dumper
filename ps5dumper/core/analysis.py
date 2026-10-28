"""Offline analysis of saved dumps: changed bytes between two dumps, and value scans.

Typical use: dump the game, change something in it (ammo, health...), dump again,
then compare the dumps or scan for the old value and keep the addresses whose value
changed the way you expect. Everything works on files; the console is not contacted.
"""
import bisect
import csv
import mmap
import re
import struct
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path

from .manifest import load_manifest
from .reader import MIB
from .reporting import Reporter, check_cancel

NUMBER_TYPES = {"int8": ("<b", "<B"), "int16": ("<h", "<H"), "int32": ("<i", "<I"), "int64": ("<q", "<Q"),
                "float": ("<f", None), "double": ("<d", None)}
VALUE_TYPES = (*NUMBER_TYPES, "string", "utf16", "bytes")
CONDITIONS = ("equals", "changed", "unchanged", "increased", "decreased")
SEARCH_LIMIT = 1_000_000
COMPARE_LIMIT = 200_000
PREVIEW = 16  # bytes shown before/after for each changed range
_CANCEL_EVERY = 65536


@dataclass
class Region:
    start: int
    end: int
    path: Path
    size: int  # bytes in the file; file offset = address - start
    item: dict
    gaps: list = field(default_factory=list)  # sorted [(start, end)]
    gap_starts: list = field(default_factory=list)


class DumpImage:
    """Read-only access to a dump by address.

    Only regions whose file offsets equal address - start are used (gaps zero-filled,
    or no gaps); the others are counted in `skipped`. Files are memory-mapped on demand.
    """

    def __init__(self, folder):
        self.folder = Path(folder).expanduser().resolve()
        self.document = load_manifest(self.folder)
        aligned = self.document.get("gap_fill") == "zeros"
        self.regions = []
        self.skipped = 0
        for item in self.document.get("regions", []):
            path = (self.folder / item["file"]).resolve() if item.get("file") else None
            if (path is None or path.parent != self.folder or not path.is_file()
                    or (item.get("gaps") and not aligned) or path.stat().st_size == 0):
                self.skipped += 1
                continue
            gaps = sorted((int(g["start"], 16), int(g["end"], 16)) for g in item.get("gaps") or ())
            self.regions.append(Region(int(item["start"], 16), int(item["end"], 16), path, path.stat().st_size,
                                       item, gaps, [g[0] for g in gaps]))
        self.regions.sort(key=lambda r: r.start)
        self._starts = [r.start for r in self.regions]
        self._open = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        for stream, mapped in self._open.values():
            mapped.close()
            stream.close()
        self._open.clear()

    def data(self, region):
        """The region file as a read-only memory map."""
        if region.path not in self._open:
            stream = region.path.open("rb")
            self._open[region.path] = (stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ))
        return self._open[region.path][1]

    def region_at(self, address):
        index = bisect.bisect_right(self._starts, address) - 1
        if index >= 0 and address < self.regions[index].start + self.regions[index].size:
            return self.regions[index]
        return None

    @staticmethod
    def in_gap(region, address, size=1):
        """Whether [address, address+size) touches an unreadable gap (zeros in the file, not real data)."""
        index = bisect.bisect_left(region.gap_starts, address + size)
        return index > 0 and region.gaps[index - 1][1] > address

    def read(self, address, size):
        """Bytes at `address`, or None when they were not captured."""
        region = self.region_at(address)
        if region is None or address + size > region.start + region.size or self.in_gap(region, address, size):
            return None
        offset = address - region.start
        return self.data(region)[offset:offset + size]


def parse_value(kind, text):
    """Returns (needle, size): bytes, or a compiled regex for byte patterns with ?? wildcards."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Enter a value")
    if kind in NUMBER_TYPES:
        signed, unsigned = NUMBER_TYPES[kind]
        if unsigned is None:
            return struct.pack(signed, float(text)), struct.calcsize(signed)
        value = int(text, 0)
        for fmt in (signed, unsigned):
            try:
                return struct.pack(fmt, value), struct.calcsize(fmt)
            except struct.error:
                continue
        raise ValueError(f"{text} does not fit in {kind}")
    if kind == "string":
        data = text.encode("utf-8")
    elif kind == "utf16":
        data = text.encode("utf-16-le")
    elif kind == "bytes":
        tokens = text.replace(",", " ").split()
        if any(t in ("?", "??") for t in tokens):
            parts = [b"." if t in ("?", "??") else re.escape(bytes.fromhex(t)) for t in tokens]
            size = sum(1 if t in ("?", "??") else len(bytes.fromhex(t)) for t in tokens)
            return re.compile(b"".join(parts), re.DOTALL), size
        data = bytes.fromhex("".join(tokens))
    else:
        raise ValueError(f"Unknown value type: {kind}")
    return data, len(data)


def decode(kind, raw):
    if raw is None:
        return None
    if kind in NUMBER_TYPES:
        return struct.unpack(NUMBER_TYPES[kind][0], raw)[0]
    if kind == "string":
        return raw.decode("utf-8", "replace")
    if kind == "utf16":
        return raw.decode("utf-16-le", "replace")
    return raw.hex(" ")


def _find_all(data, needle, cancel):
    if isinstance(needle, re.Pattern):
        for count, match in enumerate(needle.finditer(data)):
            if count % _CANCEL_EVERY == 0:
                check_cancel(cancel)
            yield match.start()
        return
    position, count = data.find(needle), 0
    while position >= 0:
        yield position
        count += 1
        if count % _CANCEL_EVERY == 0:
            check_cancel(cancel)
        position = data.find(needle, position + 1)


def search(folder, kind, text, aligned=True, writable_only=False, limit=SEARCH_LIMIT, reporter=None, cancel=None):
    """First scan: addresses in the dump where the value occurs (never inside unreadable gaps).

    Numbers are little-endian; `aligned` keeps only addresses that are multiples of
    their size, as the game normally stores them. Bytes accept ?? wildcards.
    """
    reporter = reporter or Reporter()
    needle, size = parse_value(kind, text)
    step = size if aligned and kind in NUMBER_TYPES else 1
    addresses = []
    truncated = False
    with DumpImage(folder) as image:
        regions = [r for r in image.regions if not writable_only or (r.item.get("prot") or 0) & 2]
        total = sum(r.size for r in regions) or 1
        done = 0
        for region in regions:
            check_cancel(cancel)
            for offset in _find_all(image.data(region), needle, cancel):
                address = region.start + offset
                if address % step or (region.gaps and image.in_gap(region, address, size)):
                    continue
                addresses.append(address)
                if len(addresses) >= limit:
                    truncated = True
                    break
            done += region.size
            reporter.progress(done, total, 0)
            if truncated:
                break
        skipped = image.skipped
    reporter.log(f"First scan for {kind} {text!r}: {len(addresses)} address(es)"
                 + (f" (stopped at {limit})" if truncated else ""), "ok")
    return dict(kind=kind, size=size, folder=str(Path(folder).resolve()), addresses=addresses,
                truncated=truncated, skipped=skipped)


def next_scan(scan, folder, condition, text=None, reporter=None, cancel=None):
    """Keeps the addresses of `scan` whose value in `folder` satisfies `condition`.

    `condition` compares with the dump of the previous scan (changed, unchanged,
    increased, decreased) or with `text` (equals). Returns a new scan.
    """
    reporter = reporter or Reporter()
    kind, size = scan["kind"], scan["size"]
    if condition not in CONDITIONS:
        raise ValueError(f"The condition must be one of: {', '.join(CONDITIONS)}")
    if condition in ("increased", "decreased") and kind not in NUMBER_TYPES:
        raise ValueError("Increased/decreased need a number type")
    target = None
    if condition == "equals":
        target, target_size = parse_value(kind, text)
        if target_size != size:
            raise ValueError("The new value must have the same length as the first scan")
    kept = []
    previous = scan["folder"]
    with DumpImage(previous) as before, DumpImage(folder) as after:
        addresses = scan["addresses"]
        for index, address in enumerate(addresses):
            if index % _CANCEL_EVERY == 0:
                check_cancel(cancel)
                reporter.progress(index, len(addresses), 0)
            new = after.read(address, size)
            if new is None:
                continue
            if condition == "equals":
                keep = target.fullmatch(new) is not None if isinstance(target, re.Pattern) else new == target
            else:
                old = before.read(address, size)
                if old is None:
                    continue
                if condition == "changed":
                    keep = new != old
                elif condition == "unchanged":
                    keep = new == old
                else:
                    a, b = decode(kind, old), decode(kind, new)
                    keep = b > a if condition == "increased" else b < a
            if keep:
                kept.append(address)
    reporter.progress(1, 1, 0)
    reporter.log(f"Next scan ({condition}): {len(kept)} of {len(scan['addresses'])} address(es) kept", "ok")
    return dict(scan, folder=str(Path(folder).resolve()), previous=str(Path(previous).resolve()),
                addresses=kept, truncated=False)


def scan_rows(scan, limit=None):
    """[(address, region name, previous value, current value)] for display or CSV."""
    rows = []
    kind, size = scan["kind"], scan["size"]
    with DumpImage(scan["folder"]) as now, \
            (DumpImage(scan["previous"]) if scan.get("previous") else nullcontext()) as before:
        for address in scan["addresses"][:limit]:
            region = now.region_at(address)
            rows.append((address, region.item.get("name", "") if region else "",
                         decode(kind, before.read(address, size)) if before is not None else None,
                         decode(kind, now.read(address, size))))
    return rows


def compare_dumps(folder_a, folder_b, merge_distance=8, limit=COMPARE_LIMIT, reporter=None, cancel=None):
    """Changed byte ranges between two dumps; regions are matched by identical start and end.

    Differences closer than `merge_distance` bytes form one range. Ranges touching an
    unreadable gap in either dump are ignored (zeros there are not real data).
    """
    reporter = reporter or Reporter()
    joiner = re.compile(rb"[^\x00](?:\x00{0,%d}[^\x00])*" % max(merge_distance - 1, 0))
    regions, ranges, truncated = [], [], False
    with DumpImage(folder_a) as a, DumpImage(folder_b) as b:
        by_key = {(r.start, r.end): r for r in b.regions}
        pairs = [(ra, by_key[(ra.start, ra.end)]) for ra in a.regions if (ra.start, ra.end) in by_key]
        total = sum(min(ra.size, rb.size) for ra, rb in pairs) or 1
        done = 0
        for ra, rb in pairs:
            da, db = a.data(ra), b.data(rb)
            compared = min(ra.size, rb.size)
            changed = count = 0
            current = None  # [start, end) of the range being extended

            def flush():
                nonlocal count, truncated
                start, end = current
                count += 1
                if len(ranges) >= limit:
                    truncated = True
                    return
                offset, preview = start - ra.start, min(PREVIEW, end - start)
                ranges.append(dict(address=start, size=end - start, region=ra.item.get("name", ""),
                                   before=da[offset:offset + preview].hex(" "),
                                   after=db[offset:offset + preview].hex(" ")))

            for position in range(0, compared, MIB):
                check_cancel(cancel)
                x, y = da[position:min(position + MIB, compared)], db[position:min(position + MIB, compared)]
                if x != y:
                    xor = (int.from_bytes(x, "little") ^ int.from_bytes(y, "little")).to_bytes(len(x), "little")
                    for match in joiner.finditer(xor):
                        start, end = ra.start + position + match.start(), ra.start + position + match.end()
                        if a.in_gap(ra, start, end - start) or b.in_gap(rb, start, end - start):
                            continue
                        changed += end - start - xor.count(0, match.start(), match.end())
                        if current is not None and start - current[1] < merge_distance:
                            current[1] = end
                            continue
                        if current is not None:
                            flush()
                        current = [start, end]
                done += len(x)
                reporter.progress(done, total, 0)
            if current is not None:
                flush()
            regions.append(dict(name=ra.item.get("name", ""), start=ra.start, end=ra.end, compared=compared,
                                changed_bytes=changed, ranges=count))
        result = dict(folder_a=str(a.folder), folder_b=str(b.folder), regions=regions, ranges=ranges,
                      truncated=truncated, changed_bytes=sum(r["changed_bytes"] for r in regions),
                      range_count=sum(r["ranges"] for r in regions),
                      unmatched_a=len(a.regions) - len(pairs), unmatched_b=len(b.regions) - len(pairs),
                      skipped=a.skipped + b.skipped)
    reporter.log(f"Compared {len(pairs)} region(s): {result['changed_bytes']} changed byte(s) "
                 f"in {result['range_count']} range(s)", "ok")
    return result


def write_csv(path, header, rows):
    """New CSV file (never overwrites)."""
    with Path(path).open("x", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)


def write_compare_csv(result, path):
    write_csv(path, ("address", "size", "region", "before", "after"),
              ((hex(r["address"]), r["size"], r["region"], r["before"], r["after"]) for r in result["ranges"]))


def write_scan_csv(scan, path):
    write_csv(path, ("address", "region", "previous", "current"),
              ((hex(address), region, "" if old is None else old, "" if new is None else new)
               for address, region, old, new in scan_rows(scan)))
