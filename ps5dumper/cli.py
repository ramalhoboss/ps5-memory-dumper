"""Process dumps and explicit kernel ranges via ps5debug (command line).

PID 0 uses kern_base/kern_read; it does not use process maps. With no size/start,
firmware 13.60 uses the kdump module-info method to detect full-kernel bounds
(requires console-side hypervisor bypass). Explicit ranges are not full kernels. Offline actions (--concat,
--export-elf, --compare, --search) work on saved dumps without the console.
"""
import argparse
import re
import time
from datetime import datetime
from pathlib import Path

from ps5dbg.errors import BadStatus

from . import AUTHOR, AUTHOR_URL
from .core.analysis import CONDITIONS, VALUE_TYPES, compare_dumps, next_scan, scan_rows, search
from .core.analysis import write_compare_csv, write_scan_csv
from .core.console import connect, discover_consoles, process_details
from .core.dumper import (DEFAULT_RETRIES, KERNEL_ADDRESS_MIN, KERNEL_LIMIT, create_output_dir, dump_kernel,
                          dump_process, filter_regions, parse_prot, readable_regions, resume_dump, safe_name,
                          summarize, validate_kernel_range)
from .core.files import ELF_TYPES, concatenate_files, export_elf, list_bin_files
from .core.manifest import MANIFEST_NAME, load_manifest
from .core.reader import MIB
from .core.reporting import Reporter

PROGRESS_INTERVAL = 8 * MIB
SHOWN = 30  # rows printed for compare/search; --report writes all of them


class ConsoleReporter(Reporter):
    PREFIX = {"info": "[*]", "ok": "[+]", "warn": "[-]", "error": "[-]"}

    def __init__(self):
        self.next_notice = PROGRESS_INTERVAL

    def log(self, message, level="info"):
        print(f"{self.PREFIX.get(level, '[*]')} {message}", flush=True)

    def region_started(self, index, count, item):
        print(f"[*] ({index + 1}/{count}) {item['name']}: {item['start']}-{item['end']}", flush=True)

    def progress(self, done, total, rate):
        if done < self.next_notice:
            return
        speed = f", {rate / MIB:.1f} MiB/s" if rate else ""
        print(f"[*] {done / MIB:.0f}/{total / MIB:.0f} MiB ({done / total:.0%}){speed}", flush=True)
        self.next_notice = (done // PROGRESS_INTERVAL + 1) * PROGRESS_INTERVAL


def concatenate_menu():
    try:
        entry = input("[?] Folder with the .bin files (Enter = cancel): ").strip().strip('"')
        if not entry:
            return
        folder = Path(entry).expanduser().resolve()
        files = list_bin_files(folder)
        if not files:
            print("[-] No .bin files were found in that folder.")
            return
        for index, source in enumerate(files, 1):
            print(f"  {index}. {source.name} ({source.stat().st_size} bytes)")
        order = input("[?] Order by number, separated by spaces (Enter = all in this order): ").strip()
        if order:
            indexes = [int(n) for n in order.split()]
            if len(set(indexes)) != len(indexes) or any(n < 1 or n > len(files) for n in indexes):
                raise ValueError("Choose valid numbers, without repetitions")
            files = [files[n - 1] for n in indexes]
        default = folder.parent / f"{folder.name}_concatenated.bin"
        name = input(f"[?] Output file [{default}]: ").strip().strip('"')
        concatenate_files(files, name or default, ConsoleReporter())
    except Exception as error:
        print(f"[-] Concatenation failed: {type(error).__name__}: {error}")


def discover_menu():
    print("[*] Looking for consoles on the local network...")
    found = discover_consoles()
    if not found:
        print("[-] No console answered. Check that the payload is running and the PC is on the same network.")
        return None
    for index, ip in enumerate(found, 1):
        print(f"  {index}. {ip}")
    if len(found) == 1:
        return found[0]
    choice = input("[?] Console number (Enter = cancel): ").strip()
    return found[int(choice) - 1] if choice.isdigit() and 1 <= int(choice) <= len(found) else None


def choose_process(ps5):
    """Refreshes the list on request; NEW means seen since the previous query.

    PID/name do not give the real creation time and can be reused.
    """
    previous = None
    refresh = True
    procs = []
    while True:
        if refresh:
            procs = list(ps5.procs())
            current = {(p.pid, p.name) for p in procs}
            new = current - previous if previous is not None else set()
            gone = previous - current if previous is not None else set()
            procs.sort(key=lambda p: ((p.pid, p.name) not in new, p.pid))
            print(f"\n[*] List refreshed at {datetime.now():%H:%M:%S}: {len(procs)} processes")
            if previous is not None:
                print(f"[*] {len(new)} new; {len(gone)} no longer listed")
            print("PID    | PROCESS")
            for p in procs:
                mark = " [NEW]" if (p.pid, p.name) in new else ""
                print(f"{p.pid:<6} | {p.name}{mark}")
            if not procs:
                print("[*] No process returned. Use R to try refreshing.")
            previous = current
            refresh = False
        entry = input("[?] PID (0 = kernel) | R = refresh | C = concatenate | quit: ").strip()
        if not entry or entry.lower() in ("quit", "q", "exit"):
            return None, procs
        if entry.lower() in ("c", "concatenate"):
            concatenate_menu()
            continue
        if entry.lower() in ("r", "refresh"):
            refresh = True
            continue
        try:
            pid = int(entry)
        except ValueError:
            print("[-] Enter a PID, R to refresh, C to concatenate or quit.")
            continue
        if pid < 0 or (pid != 0 and not any(p.pid == pid for p in procs)):
            print("[-] That PID is not in the list. Use R to refresh.")
            continue
        return pid, procs


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, epilog=f"Developed by {AUTHOR} - {AUTHOR_URL}")
    console = parser.add_argument_group("console")
    console.add_argument("--ip", help="PS5 IP; if omitted, it is asked before connecting")
    console.add_argument("--discover", action="store_true", help="find the console on the local network")
    console.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                         help=f"reconnections per request when the connection drops (default {DEFAULT_RETRIES}; 0 = off)")
    dump = parser.add_argument_group("dump")
    dump.add_argument("--kernel", action="store_true", help="read a kernel range, without PID/maps")
    dump.add_argument("--size-mib", type=int, default=None, help="explicit range size in MiB (max 83); omitted with no --start: detect full kernel on 13.60")
    dump.add_argument("--start", type=lambda s: int(s, 0), help="explicit address, for example 0xffff...")
    dump.add_argument("--kernel-recover", action="store_true",
                      help="EXPERIMENTAL: bisect refused kernel blocks and zero-fill them; a fault in kernel mode "
                           "restarts the console")
    dump.add_argument("--output", help="new destination folder; never replaces existing folders")
    dump.add_argument("--pid", type=int, help="PID to dump (0 = kernel); skips the interactive menu")
    dump.add_argument("--prot", help="only regions with all these permissions, for example x or rw "
                                     "(processes and --export-elf)")
    dump.add_argument("--name", help="only regions whose name contains this text, case-insensitive "
                                     "(processes and --export-elf)")
    dump.add_argument("--max-region-mib", type=int, help="skip regions larger than N MiB (processes only)")
    dump.add_argument("--no-fill-gaps", action="store_true",
                      help="do not zero-fill unreadable gaps (version 1 format: file offsets drift after a gap)")
    resume = parser.add_argument_group("resume")
    resume.add_argument("--resume", metavar="FOLDER", help="continue an interrupted or incomplete dump")
    resume.add_argument("--retry-gaps", action="store_true", help="with --resume, read unreadable gaps again")
    offline = parser.add_argument_group("offline (no console)")
    offline.add_argument("--concat", metavar="FOLDER", help="concatenate the .bin files in the folder")
    offline.add_argument("--concat-output", metavar="FILE", help="concatenation destination (new file)")
    offline.add_argument("--export-elf", metavar="FOLDER", help="export a dump as an x86-64 ELF for Ghidra/IDA")
    offline.add_argument("--elf-output", metavar="FILE", help="ELF destination (new file)")
    offline.add_argument("--elf-type", choices=tuple(ELF_TYPES), default="exec", help="ELF type (default exec)")
    offline.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"), help="changed bytes between two dumps")
    offline.add_argument("--search", metavar="FOLDER", help="first scan for --value of --type in a dump")
    offline.add_argument("--type", choices=VALUE_TYPES, default="int32", help="value type (default int32)")
    offline.add_argument("--value", help="value to search; bytes accept ?? wildcards, e.g. '48 8B ?? 05'")
    offline.add_argument("--unaligned", action="store_true", help="also match numbers at unaligned addresses")
    offline.add_argument("--writable-only", action="store_true", help="search only writable regions")
    offline.add_argument("--then", nargs="+", action="append", metavar="ARG",
                         help=f"next scan: FOLDER CONDITION [VALUE], condition one of {', '.join(CONDITIONS)}; "
                              "repeat for more scans")
    offline.add_argument("--report", metavar="FILE", help="write every result of --compare/--search to a new CSV")
    return parser


OFFLINE_ACTIONS = ("concat", "export_elf", "compare", "search")
OFFLINE_OPTIONS = dict(concat_output="concat", elf_output="export_elf", value="search", then="search")
OFFLINE_FLAGS = dict(unaligned="search", writable_only="search")


def validate(parser, args):
    offline = [name for name in OFFLINE_ACTIONS if getattr(args, name)]
    if len(offline) > 1:
        parser.error("choose only one of --concat, --export-elf, --compare and --search")
    for option, action in {**OFFLINE_OPTIONS, **OFFLINE_FLAGS}.items():
        if getattr(args, option) and not getattr(args, action):
            parser.error(f"--{option.replace('_', '-')} needs --{action.replace('_', '-')}")
    if args.report and not (args.compare or args.search):
        parser.error("--report needs --compare or --search")
    if args.retry_gaps and not args.resume:
        parser.error("--retry-gaps needs --resume")
    if args.retries < 0:
        parser.error("--retries cannot be negative")
    console_used = any((args.ip is not None, args.discover, args.kernel, args.pid is not None, args.start is not None,
                        args.size_mib is not None, args.output is not None, args.max_region_mib is not None,
                        args.no_fill_gaps, args.kernel_recover, args.resume))
    if offline:
        action = offline[0]
        if console_used:
            parser.error(f"--{action.replace('_', '-')} works offline and cannot be combined with console options")
        if (args.prot or args.name) and action != "export_elf":
            parser.error("--prot/--name apply to dumps and --export-elf")
        if action == "search" and not args.value:
            parser.error("--search needs --value")
        for then in args.then or []:
            if len(then) not in (2, 3) or then[1] not in CONDITIONS:
                parser.error(f"--then takes FOLDER CONDITION [VALUE], condition one of {', '.join(CONDITIONS)}")
            if then[1] == "equals" and len(then) != 3:
                parser.error("--then FOLDER equals needs a VALUE")
        return action
    if args.resume and any((args.kernel, args.pid is not None, args.start is not None, args.size_mib is not None,
                            args.output is not None, args.prot, args.name, args.max_region_mib is not None,
                            args.no_fill_gaps, args.kernel_recover)):
        parser.error("--resume continues a dump with its own settings; only --ip/--discover/--retries/--retry-gaps apply")
    if args.size_mib is not None and args.size_mib < 1:
        parser.error("--size-mib must be at least 1")
    if args.pid is not None and args.pid < 0:
        parser.error("--pid cannot be negative")
    if args.kernel and args.pid not in (None, 0):
        parser.error("--kernel is incompatible with a --pid other than 0")
    if args.prot is not None and not re.fullmatch(r"[rwx]+", args.prot):
        parser.error("--prot accepts only the letters r, w and x")
    if args.max_region_mib is not None and args.max_region_mib < 1:
        parser.error("--max-region-mib must be at least 1")
    return None


def run_offline(action, args):
    reporter = ConsoleReporter()
    try:
        if action == "concat":
            source = Path(args.concat).expanduser().resolve()
            destination = args.concat_output or source.parent / f"{source.name}_concatenated.bin"
            concatenate_files(list_bin_files(source), destination, reporter)
        elif action == "export_elf":
            folder = Path(args.export_elf).expanduser().resolve()
            required = parse_prot(args.prot)
            name = (args.name or "").lower()
            regions = [r for r in load_manifest(folder)["regions"] if r.get("file")
                       and ((r.get("prot") or 0) & required) == required and name in r.get("name", "").lower()]
            destination = args.elf_output or folder.parent / f"{folder.name}.elf"
            result = export_elf(folder, regions, destination, args.elf_type, reporter)
            print(f"[*] Open it in Ghidra/IDA as ELF x86-64; segments start at {result['start']}")
        elif action == "compare":
            result = compare_dumps(*args.compare, reporter=reporter)
            changed = sorted((r for r in result["regions"] if r["changed_bytes"]), key=lambda r: -r["changed_bytes"])
            print(f"[*] Regions compared: {len(result['regions'])}; only in BEFORE: {result['unmatched_a']}, "
                  f"only in AFTER: {result['unmatched_b']}, unusable: {result['skipped']}")
            for region in changed[:SHOWN]:
                print(f"    {region['name']:<28} 0x{region['start']:x}: {region['changed_bytes']} byte(s) "
                      f"in {region['ranges']} range(s)")
            for item in result["ranges"][:SHOWN]:
                print(f"    0x{item['address']:x} +{item['size']:<6} {item['before']}  ->  {item['after']}")
            if args.report:
                write_compare_csv(result, args.report)
                print(f"[+] Report: {Path(args.report).resolve()}")
        else:
            scan = search(args.search, args.type, args.value, aligned=not args.unaligned,
                          writable_only=args.writable_only, reporter=reporter)
            for then in args.then or []:
                scan = next_scan(scan, then[0], then[1], then[2] if len(then) == 3 else None, reporter)
            for address, region, old, new in scan_rows(scan, SHOWN):
                previous = f"{old} -> " if old is not None else ""
                print(f"    0x{address:x}  {region:<24} {previous}{new}")
            if len(scan["addresses"]) > SHOWN:
                print(f"[*] ... {len(scan['addresses']) - SHOWN} more" + ("; use --report for all" if not args.report else ""))
            if args.report:
                write_scan_csv(scan, args.report)
                print(f"[+] Report: {Path(args.report).resolve()}")
        return 0
    except KeyboardInterrupt:
        print("\n[-] Interrupted; a partial destination file was removed.")
        return 130
    except Exception as error:
        print(f"[-] {action.replace('_', ' ').capitalize()} failed: {type(error).__name__}: {error}")
        return 1


def ask_ip(args):
    """IP from --ip, --discover or the prompt (where C opens the concatenation menu)."""
    if args.ip is not None:
        ip = args.ip.strip()
        if not ip:
            raise ValueError("--ip cannot be empty")
        return ip
    if args.discover:
        return discover_menu()
    ip = None
    while not ip:
        ip = input("[?] PS5 IP (D = discover, C = concatenate files): ").strip()
        if ip.lower() in ("c", "concatenate"):
            concatenate_menu()
            ip = None
        elif ip.lower() in ("d", "discover"):
            ip = discover_menu()
        elif not ip:
            print("[-] Enter the PS5 IP to continue.")
    return ip


def print_summary(document, elapsed, kernel, resumed=False):
    summary = summarize(document)
    total = summary["bytes"]
    if resumed:
        print(f"[+] The dump now holds {total} bytes ({total / MIB:.2f} MiB); this run took {elapsed:.1f} s; "
              f"incomplete regions: {summary['incomplete']}")
    else:
        print(f"[+] Wrote {total} bytes ({total / MIB:.2f} MiB) in {elapsed:.1f} s "
              f"({total / MIB / elapsed:.1f} MiB/s); incomplete regions: {summary['incomplete']}")
    if document.get("reconnects"):
        print(f"[*] Reconnected {document['reconnects']} time(s) during the dump")
    if summary["gaps"]:
        print(f"[-] {summary['gaps']} gap(s), {summary['gap_bytes']} unreadable bytes; "
              f"see 'gaps' in {MANIFEST_NAME}")
    if kernel:
        print("[*] Detected full kernel image (raw memory, not ELF)" if document.get("full_kernel") else
              "[*] Kernel range dumped; it is not automatically the full kernel nor an ELF")
    return 0 if total and not summary["incomplete"] else 1


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    action = validate(parser, args)
    if action is not None:
        return run_offline(action, args)
    required_prot = parse_prot(args.prot)
    uses_filters = any(v is not None for v in (args.prot, args.name, args.max_region_mib))
    reporter = ConsoleReporter()
    folder = None
    operation = "connection"
    try:
        ip = ask_ip(args)
        if ip is None:
            return 1
        ps5 = connect(ip)
        with ps5:
            print(f"\n[+] Connected to the PS5 ({ip})")
            if args.resume:
                operation = "resume"
                folder = Path(args.resume).expanduser().resolve()
                start_time = time.perf_counter()
                document = resume_dump(ps5, folder, reporter, retry_gaps=args.retry_gaps, retries=args.retries)
                return print_summary(document, max(time.perf_counter() - start_time, 1e-9),
                                     document.get("type") == "kernel", resumed=True)
            kernel = args.kernel or args.pid == 0
            non_interactive = args.kernel or args.pid is not None
            if not kernel:
                operation = "process list"
                if args.pid is None:
                    pid, procs = choose_process(ps5)
                    if pid is None:
                        return 0
                    kernel = pid == 0
                else:
                    procs = sorted(ps5.procs(), key=lambda p: p.pid)
                    pid = args.pid
            if args.kernel_recover and not kernel:
                raise ValueError("--kernel-recover applies to kernel mode only")
            if kernel:
                if uses_filters:
                    raise ValueError("--prot/--name/--max-region-mib apply to processes only")
                operation = "kernel read"
                amount = args.size_mib
                automatic = amount is None and args.start is None
                if not automatic and amount is None:
                    amount = KERNEL_LIMIT // MIB
                size = None if automatic else min(amount * MIB, KERNEL_LIMIT)
                if size is not None:
                    validate_kernel_range(KERNEL_ADDRESS_MIN if args.start is None else args.start, size)
                operation = "creation of the destination folder"
                folder = create_output_dir("kernel_0", args.output, required=size or KERNEL_LIMIT)
                print(f"[*] Destination: {folder}", flush=True)
                operation = "kernel read"
                start_time = time.perf_counter()
                document = dump_kernel(ps5, folder, size, args.start, reporter, info=dict(console=ip),
                                       recover=args.kernel_recover, retries=args.retries)
            else:
                if args.start is not None or args.size_mib is not None:
                    raise ValueError("--start/--size-mib apply to kernel mode only")
                target = next((p for p in procs if p.pid == pid), None)
                if target is None:
                    raise ValueError("That PID is not in the process list")
                operation = f"maps of PID {pid}"
                maps = list(ps5.maps(pid))
                readable = readable_regions(maps)
                print(f"[*] {len(maps)} regions, {len(readable)} readable")
                if not readable:
                    print("[-] The server returned no readable region")
                    return 1
                selected = filter_regions(readable, required_prot, args.name, args.max_region_mib)
                if uses_filters:
                    print(f"[*] {len(selected)} regions after filters")
                    if not selected:
                        print("[-] No region matches the filters")
                        return 1
                to_read = sum(m.end - m.start for m in selected)
                print(f"[*] Reading {to_read / MIB:.2f} MiB in {len(selected)} regions")
                operation = "creation of the destination folder"
                folder = create_output_dir(f"{safe_name(target.name)}_{pid}", args.output, required=to_read)
                print(f"[*] Destination: {folder}", flush=True)
                operation = f"read of PID {pid}"
                info = dict(console=ip, process=target.name, **process_details(ps5, pid))
                start_time = time.perf_counter()
                document = dump_process(ps5, pid, selected, folder, reporter, fill_gaps=not args.no_fill_gaps,
                                        info=info, retries=args.retries)
            return print_summary(document, max(time.perf_counter() - start_time, 1e-9), kernel)
    except KeyboardInterrupt:
        print("\n[-] Interrupted; data already written is kept" + (f" (resume with --resume \"{folder}\")"
                                                                   if folder is not None else ""))
        return 130
    except BadStatus as e:
        print(f"[-] The payload answered but refused the operation ({operation}): {e}")
        print("[*] Check the command/range and the payload support; this does not mean the IP is wrong")
        return 1
    except Exception as e:
        print(f"[-] Failure in {operation}: {type(e).__name__}: {e}")
        return 1
    finally:
        if folder is not None:
            print(f"[*] Destination: {folder}; if reading started, see {MANIFEST_NAME}")


def interactive_dumper():
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
