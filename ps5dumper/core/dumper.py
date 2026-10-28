"""Process dumps and explicit kernel ranges over ps5debug.

PID 0 uses kern_base/kern_read; it does not use process maps. A kernel memory
range is not automatically an ELF nor the full kernel. Dumps reconnect on their own
after a dropped connection and can be resumed from their manifest.
"""
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from ps5dbg.errors import ConnectionLost, ProtocolError

from .. import __version__
from .kernel_layout import detect_kernel_layout
from .manifest import FORMAT_VERSION, load_manifest, process_name, save_manifest
from .reader import BLOCK, MAX_UNREADABLE_BLOCKS, MIB, read_range
from .reporting import DumpCancelled, Reporter, check_cancel

KERNEL_LIMIT = 83 * MIB
KERNEL_BLOCK = 0x4000  # 16 KiB, matching kdump_ps5; never cross a PS5 page
MANIFEST_INTERVAL = 2.0  # seconds between manifest.json rewrites
MAX_U64 = (1 << 64) - 1
KERNEL_ADDRESS_MIN = 0xffff800000000000  # start of the upper virtual range
PROT_BITS = {"r": 1, "w": 2, "x": 4}
MAX_EMPTY_REGIONS = 3  # consecutive regions without data before switching to economy mode
DEFAULT_RETRIES = 5  # reconnections per request before a dump gives up
MAX_RECONNECT_DELAY = 30  # seconds
HYPERVISOR_WARNING = ("Kernel dumps require the hypervisor to be disabled on the PS5: run the hypervisor bypass "
                      "after the jailbreak and before loading ps5debug-NG. With the hypervisor active, kernel "
                      "code cannot be read and a kernel read can restart the console.")
GAP_NOTES = {
    "zeros": ("File offset = address - start. Unreadable gaps before received data are zero-filled; "
              "trailing unreadable bytes are omitted. Every gap [start, end) is listed in 'gaps'."),
    "none": ("In regions with 'gaps' the file holds only the bytes received, in address order and "
             "without padding; each gap [start, end) is missing from the file."),
}


class ResumeError(ValueError):
    """The dump cannot be resumed: the process is gone, the console restarted, or nothing is left."""


def _now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _header(kind, pid, info, gap_fill):
    return dict(format_version=FORMAT_VERSION, tool=f"ps5dumper {__version__}", type=kind, pid=pid,
                **(info or {}), started=_now(), finished=None, status="running", bytes=0,
                gap_fill=gap_fill)


def prot_string(prot):
    if prot is None:
        return "?"
    return "".join(letter if prot & bit else "-" for letter, bit in PROT_BITS.items())


def parse_prot(text):
    if not re.fullmatch(r"[rwx]*", text or ""):
        raise ValueError("Permissions accept only the letters r, w and x")
    return sum(PROT_BITS[c] for c in set(text or ""))


def readable_regions(maps):
    return [m for m in maps if m.prot & 1 and m.end > m.start]


def filter_regions(regions, required_prot=0, name=None, max_mib=None):
    """Applies the optional filters to the readable regions."""
    name = name.lower() if name else None
    return [m for m in regions
            if (m.prot & required_prot) == required_prot
            and (name is None or name in m.name.lower())
            and (max_mib is None or m.end - m.start <= max_mib * MIB)]


def safe_name(name, fallback="process"):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] or fallback


def default_dumps_dir():
    if getattr(sys, "frozen", False):  # packaged .exe: next to the executable
        return Path(sys.executable).resolve().parent / "dumps"
    return Path(__file__).resolve().parents[2] / "dumps"


def create_output_dir(name, output=None, required=0, root=None):
    """New folder `output`, or `root`/<name>_<timestamp>; never reuses an existing folder."""
    if output is not None:
        folder = Path(output).expanduser().resolve()
    else:
        root = Path(root or default_dumps_dir()).expanduser().resolve()
        folder = root / f"{name}_{datetime.now():%Y%m%d_%H%M%S_%f}"
    if required:
        base = next(p for p in (folder, *folder.parents) if p.exists())
        free = shutil.disk_usage(base).free
        if free < required:
            raise OSError(f"Not enough space in {base}: "
                          f"{free / MIB:.0f} MiB free, {required / MIB:.0f} MiB needed")
    folder.mkdir(parents=True, exist_ok=False)
    return folder


def resilient(read, ps5, retries, reporter, cancel, stats):
    """Wraps `read(address, n)`: on a dropped connection, reconnects and repeats the request.

    Waits 1, 2, 4... seconds (at most MAX_RECONNECT_DELAY) between attempts and gives up
    after `retries` reconnections for the same request. Reads have no side effects,
    so repeating one is safe. Counts received bytes and reconnections in `stats`.
    """
    def call(address, length):
        attempt = 0
        while True:
            try:
                data = read(address, length)
                stats["received"] += len(data)
                return data
            except (ConnectionLost, ProtocolError) as error:
                attempt += 1
                if attempt > retries:
                    raise
                delay = min(2 ** (attempt - 1), MAX_RECONNECT_DELAY)
                reporter.log(f"Connection problem at 0x{address:x} ({error}); reconnecting in {delay} s "
                             f"(attempt {attempt}/{retries})", "warn")
                if cancel is not None:
                    cancel.wait(delay)
                    check_cancel(cancel)
                else:
                    time.sleep(delay)
                ps5.close()
                try:
                    ps5.connect()
                except ConnectionLost as again:
                    reporter.log(f"Reconnection failed: {again}", "warn")
                    continue
                stats["reconnects"] += 1
                reporter.log("Reconnected; repeating the same request", "ok")
    return call


def _plan_entry(m):
    return dict(name=m.name, start=hex(m.start), end=hex(m.end), prot=m.prot)


def dump_process(ps5, pid, regions, folder, reporter=None, cancel=None, fill_gaps=True, info=None,
                 retries=DEFAULT_RETRIES):
    """Dumps the readable `regions` of `pid`: one .bin per region plus manifest.json.

    `info` adds descriptive fields to the manifest (process name, title id, console).
    The planned regions are stored in the manifest so an interrupted dump can be resumed.
    Returns the manifest document.
    """
    if pid == 0:
        raise ValueError("PID 0 needs dump_kernel(), not process maps")
    regions = readable_regions(regions)
    gap_fill = "zeros" if fill_gaps else "none"
    document = dict(_header("process", pid, info, gap_fill), note=GAP_NOTES[gap_fill],
                    plan=[_plan_entry(m) for m in regions], regions=[])
    return _run_process(ps5, document, folder, [(m, None) for m in regions], reporter or Reporter(),
                        cancel, retries)


def _region_done(folder, item, m, retry_gaps):
    """Whether a region from a previous run can be kept as it is."""
    if item.get("errors"):
        return False
    if item.get("gaps"):
        return not retry_gaps
    path = folder / item["file"] if item.get("file") else None
    return bool(item.get("complete") and path and path.is_file() and path.stat().st_size == m.end - m.start)


def _run_process(ps5, document, folder, work, reporter, cancel, retries, retry_gaps=False):
    """Reads `work` = [(VmMap or None, previous item or None)] in plan order.

    A previous item that is done is kept; one that stopped half-way is continued from
    the end of its file (or restarted when its gaps were not zero-filled). A None map
    means the region is no longer mapped: its previous item is kept as it is.
    """
    pid = document["pid"]
    fill_gaps = document.get("gap_fill") == "zeros"
    stats = dict(received=0, reconnects=0)
    read = resilient(lambda a, n: ps5.read(pid, a, n), ps5, retries, reporter, cancel, stats)
    items = [previous for _, previous in work]
    total = sum(m.end - m.start for m, _ in work if m is not None)
    done = 0
    started = time.perf_counter()
    previous_seconds = document.get("seconds") or 0
    previous_reconnects = document.get("reconnects") or 0
    last_write = float("-inf")
    empty_streak = 0
    status = "failed"

    def save():
        document["regions"] = [item for item in items if item is not None]
        document["bytes"] = sum(item["bytes"] for item in document["regions"])
        document["reconnects"] = previous_reconnects + stats["reconnects"]
        save_manifest(folder, document)

    def rate():
        return stats["received"] / max(time.perf_counter() - started, 1e-9)

    document.update(status="running", finished=None)
    try:
        for index, (m, previous) in enumerate(work):
            if m is None:
                continue
            size = m.end - m.start
            if previous is not None and _region_done(folder, previous, m, retry_gaps):
                done += size  # reported with the next region that is actually read
                continue
            name = f"{m.start:016x}-{m.end:016x}.bin"
            path = folder / name
            resume = (previous is not None and previous.get("file") == name and path.is_file()
                      and (fill_gaps or not previous.get("gaps")))
            if path.exists() and not resume:
                reporter.log(f"Restarting {m.name} at 0x{m.start:x}: its partial file cannot be continued", "warn")
                path.unlink()
            item = previous if previous is not None else dict(name=m.name, start=hex(m.start), end=hex(m.end),
                                                             prot=m.prot, bytes=0, complete=False, gaps=[])
            item.update(file=name, errors=[])
            items[index] = item
            reporter.region_started(index, len(work), item)

            def advance(n):
                nonlocal done
                done += n
                reporter.progress(done, total, rate())

            try:
                # With several consecutive regions without data (dead process, useless connection)
                # the first refused block abandons the region: 1 request instead of ~1000.
                read_range(read, m.start, size, path, item, BLOCK, recover=True,
                           economy=empty_streak >= MAX_EMPTY_REGIONS, fill_gaps=fill_gaps,
                           cancel=cancel, on_advance=advance, resume=resume, retry_gaps=retry_gaps)
                if item["gaps"]:
                    missing = sum(g["size"] for g in item["gaps"])
                    reporter.log(f"{m.name}: {len(item['gaps'])} gap(s), {missing} unreadable bytes", "warn")
            finally:
                if item["bytes"]:
                    if empty_streak >= MAX_EMPTY_REGIONS:
                        reporter.log("Economy mode ended: a region returned data")
                    empty_streak = 0
                else:
                    empty_streak += 1
                    if empty_streak == MAX_EMPTY_REGIONS:
                        reporter.log(f"{MAX_EMPTY_REGIONS} consecutive regions without data: economy mode "
                                     "(a region whose first block is refused is abandoned without bisection)",
                                     "warn")
                reporter.region_finished(index, len(work), item)
                now = time.monotonic()
                if now - last_write >= MANIFEST_INTERVAL:
                    save()
                    last_write = now
        listed = [item for item in items if item is not None]
        status = "complete" if len(listed) == len(work) and all(i["complete"] for i in listed) else "incomplete"
    except (DumpCancelled, KeyboardInterrupt):
        status = "cancelled"
        raise
    finally:
        document.update(status=status, finished=_now(),
                        seconds=round(previous_seconds + time.perf_counter() - started, 2))
        save()
    return document


def validate_kernel_range(start, size):
    if not isinstance(start, int) or isinstance(start, bool):
        raise ValueError("The address must be a 64-bit integer")
    if start < KERNEL_ADDRESS_MIN or start > MAX_U64:
        raise ValueError("The address is not in the upper 64-bit virtual range")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("The kernel size must be at least 1 byte")
    if start + size - 1 > MAX_U64:
        raise ValueError("The range goes past the 64-bit address limit")


def kernel_data_base(ps5):
    """CMD_KERN_BASE returns the kernel .data base, not the start of the ELF."""
    base = ps5.kern_base()
    validate_kernel_range(base, 1)
    return base


def dump_kernel(ps5, folder, size=None, start=None, reporter=None, cancel=None, info=None,
                recover=False, retries=DEFAULT_RETRIES):
    """With no size/start, detect text base and module size (supported firmware only).

    An explicit size reads a range from .data or the supplied start address.

    recover=True (experimental) bisects refused kernel blocks down to the page and zero-fills
    them, as for processes. It is off by default: whether a refused kern_read is always
    harmless depends on the payload, and a fault in kernel mode restarts the console.
    """
    reporter = reporter or Reporter()
    reporter.log(HYPERVISOR_WARNING, "warn")
    # Validate the explicit size/address before sending any command.
    automatic = size is None and start is None
    if automatic and recover:
        raise ValueError("Page recovery requires an explicit range; automatic full-kernel mode stops on errors")
    if size is None:
        size = KERNEL_LIMIT
    validate_kernel_range(KERNEL_ADDRESS_MIN if start is None else start, size)
    size = min(size, KERNEL_LIMIT)
    data_base = kernel_data_base(ps5)
    layout = detect_kernel_layout(ps5, data_base, KERNEL_LIMIT, reporter, cancel) if automatic else None
    if layout:
        address, size = layout["text_base"], layout["size"]
        recover = False  # stop on the first refused full-kernel block
    else:
        address = data_base if start is None else start
    validate_kernel_range(address, size)
    item = dict(name="kernel_data_region" if start is None else "kernel_explicit_region",
                start=hex(address), end=hex(address + size), prot=None,
                file=f"kernel_{address:016x}-{address + size:x}.bin",
                bytes=0, complete=False, errors=[], gaps=[])
    document = dict(_header("kernel", 0, info, "zeros" if recover else "none"), kernel_data_base=hex(data_base),
                    base_source="CMD_KERN_BASE: .data base, not the ELF start",
                    full_kernel=False, requested_size=size, block_size=KERNEL_BLOCK, recover=recover,
                    note="Requested range; permissions and the full map were not obtained. "
                         "Sequential capture, not atomic; requires the hypervisor disabled on the PS5."
                         + (" " + GAP_NOTES["zeros"] if recover else ""),
                    regions=[item])
    if layout:
        item["name"] = "kernel_image"
        document.update(full_kernel=True, kernel_text_base=hex(layout["text_base"]),
                        kernel_module_info=hex(layout["module_info"]),
                        kernel_firmware=layout["firmware"],
                        layout_source="kdump module-info size; ps5debug-NG SDK firmware offsets",
                        note="Detected text base and module size. Sequential capture, not atomic; "
                             "requires the hypervisor disabled on the PS5 (hypervisor bypass).")
    save_manifest(folder, document)
    reporter.log(f"Kernel .data base: 0x{data_base:x}", "ok")
    reporter.log(f"Range: 0x{address:x}-0x{address + size:x} ({size / MIB:.2f} MiB)")
    reporter.log("Kernel mode: CMD_KERN_READ, without CMD_PROC_MAPS."
                 + (" Gap recovery ON (experimental)." if recover else ""), "warn" if recover else "info")
    return _run_kernel(ps5, document, folder, item, reporter, cancel, retries)


def _run_kernel(ps5, document, folder, item, reporter, cancel, retries, resume=False, retry_gaps=False):
    address = int(item["start"], 16)
    size = int(item["end"], 16) - address
    recover = bool(document.get("recover"))
    stats = dict(received=0, reconnects=0)
    def read(address, length):
        # An unguarded kernel read may reboot the console. Never automatically
        # replay it after reconnecting: KASLR may have changed with the reboot.
        length = min(length, KERNEL_BLOCK - address % KERNEL_BLOCK)
        data = ps5.kern_read(address, length)
        stats["received"] += len(data)
        return data
    item["file"] = item.get("file") or f"kernel_{address:016x}-{address + size:x}.bin"
    reporter.region_started(0, 1, item)
    started = time.perf_counter()
    previous_seconds = document.get("seconds") or 0
    previous_reconnects = document.get("reconnects") or 0
    done = 0

    def advance(n):
        nonlocal done
        done += n
        reporter.progress(done, size, stats["received"] / max(time.perf_counter() - started, 1e-9))

    status = "failed"
    document.update(status="running", finished=None)
    try:
        read_range(read, address, size, folder / item["file"], item, KERNEL_BLOCK, recover=recover,
                   fill_gaps=recover, cancel=cancel, on_advance=advance, resume=resume, retry_gaps=retry_gaps,
                   abandon_after=None if recover else MAX_UNREADABLE_BLOCKS)
        status = "complete" if item["complete"] else "incomplete"
    except (DumpCancelled, KeyboardInterrupt):
        status = "cancelled"
        raise
    finally:
        document.update(bytes=item["bytes"], status=status, finished=_now(),
                        seconds=round(previous_seconds + time.perf_counter() - started, 2),
                        reconnects=previous_reconnects + stats["reconnects"])
        save_manifest(folder, document)
        reporter.region_finished(0, 1, item)
    return document


def resume_dump(ps5, folder, reporter=None, cancel=None, retry_gaps=False, retries=DEFAULT_RETRIES):
    """Continues a process or kernel dump from its manifest.

    Complete regions are kept; interrupted ones continue from the end of their file;
    regions never started are read. With retry_gaps=True unreadable gaps are read again.
    Refuses when the process is gone or the console restarted, because the addresses
    would then belong to something else.
    """
    folder = Path(folder).expanduser().resolve()
    reporter = reporter or Reporter()
    document = load_manifest(folder)
    if document.get("type") == "kernel":
        return _resume_kernel(ps5, folder, document, reporter, cancel, retry_gaps, retries)
    if document.get("type") != "process":
        raise ResumeError("Only process and kernel dumps can be resumed")
    if document.get("pid") == 0:
        raise ResumeError("PID 0 cannot be resumed as a process; start a new dump from the Kernel page")
    pid, expected = document["pid"], process_name(folder, document)
    running = {p.pid: p.name for p in ps5.procs()}
    if pid not in running:
        raise ResumeError(f"PID {pid} ({expected}) is no longer running, so its memory is gone; start a new dump")
    if expected and expected not in (running[pid], safe_name(running[pid])):
        raise ResumeError(f"PID {pid} now belongs to {running[pid]}, not {expected}; start a new dump")
    maps = {(m.start, m.end): m for m in readable_regions(ps5.maps(pid))}
    previous = {(int(r["start"], 16), int(r["end"], 16)): r for r in document["regions"]}
    plan = document.get("plan")
    if not plan:
        reporter.log("This manifest has no plan (older version): only the regions it lists are resumed", "warn")
        plan = [dict(name=r["name"], start=r["start"], end=r["end"], prot=r.get("prot")) for r in document["regions"]]
        document["plan"] = plan
    work = []
    for entry in plan:
        key = (int(entry["start"], 16), int(entry["end"], 16))
        item = previous.get(key)
        if key in maps:
            work.append((maps[key], item))
            continue
        if item is None:
            item = dict(entry, file=None, bytes=0, complete=False, gaps=[],
                        errors=[dict(address=entry["start"], type="NotMapped",
                                     message="the region was no longer mapped when the dump was resumed")])
        work.append((None, item))
    if all(m is None for m, _ in work):
        raise ResumeError("None of the planned regions is mapped any more: this is not the same process instance")
    pending = [m for m, item in work if m is not None and (item is None or not _region_done(folder, item, m, retry_gaps))]
    if not pending:
        hint = "; enable 'retry gaps' to read the unreadable pages again" if not retry_gaps else ""
        raise ResumeError("Nothing left to resume" + hint)
    unmapped = sum(m is None for m, _ in work)
    if unmapped:
        reporter.log(f"{unmapped} planned region(s) are no longer mapped and stay as they are", "warn")
    document["format_version"] = FORMAT_VERSION
    document.setdefault("resumed", []).append(_now())
    reporter.log(f"Resuming {expected} (PID {pid}): {len(pending)} of {len(work)} region(s) to read")
    return _run_process(ps5, document, folder, work, reporter, cancel, retries, retry_gaps)


def _resume_kernel(ps5, folder, document, reporter, cancel, retry_gaps, retries):
    reporter.log(HYPERVISOR_WARNING, "warn")
    base = kernel_data_base(ps5)
    if document.get("kernel_data_base") and int(document["kernel_data_base"], 16) != base:
        raise ResumeError("The kernel .data base changed: the console restarted, so the range must be dumped again")
    item = document["regions"][0]
    if not item.get("errors") and (item.get("complete") or not retry_gaps):
        raise ResumeError("Nothing left to resume" + ("" if item.get("complete") else
                                                      "; enable 'retry gaps' to read the unreadable pages again"))
    path = folder / item["file"] if item.get("file") else None
    resume = bool(path and path.is_file() and (document.get("gap_fill") == "zeros" or not item.get("gaps")))
    if path and path.exists() and not resume:
        path.unlink()
    document["format_version"] = FORMAT_VERSION
    document.setdefault("resumed", []).append(_now())
    reporter.log(f"Resuming kernel range {item['start']}-{item['end']}")
    return _run_kernel(ps5, document, folder, item, reporter, cancel, retries, resume=resume, retry_gaps=retry_gaps)


def summarize(document):
    regions = document.get("regions", [])
    gaps = [g for r in regions for g in r.get("gaps", ())]
    return dict(bytes=document.get("bytes", 0), regions=len(regions),
                incomplete=sum(not r.get("complete") for r in regions),
                gaps=len(gaps), gap_bytes=sum(g["size"] for g in gaps),
                seconds=document.get("seconds"))
