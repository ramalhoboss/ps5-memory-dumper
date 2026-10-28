"""Bounded adaptation of earthonion/kdump_ps5's module-info size discovery.

Firmware offsets: Pharaoh2k/ps5debug-NG ps5-payload-sdk/crt/kernel.c.
Requires the console-side hypervisor bypass before accessing protected memory.
"""
import struct

from .reader import MIB
from .reporting import check_cancel

# Intentionally support only the firmware verified against the upstream SDK.
# Values are relative to CMD_KERN_BASE (the .data base), never absolute addresses.
OFFSETS = {1360: (0x0CC0000, 0x28C9E80)}  # text delta, allproc delta
SCAN_STEP = 0x1000
SCAN_LIMIT = 16 * MIB
RECORD_SIZE = 0x50


def detect_kernel_layout(ps5, data_base, maximum, reporter, cancel=None):
    firmware = ps5.fw_version()
    if firmware not in OFFSETS:
        raise ValueError(f"Automatic kernel bounds are not supported for firmware {firmware!r}; "
                         "use an explicit known range")
    text_delta, allproc_delta = OFFSETS[firmware]
    text_base = data_base - text_delta
    if text_base < 0xffff800000000000 or data_base > (1 << 64) - 1:
        raise ValueError("Invalid kernel base reported by the payload")
    allproc = data_base + allproc_delta
    address = (allproc + SCAN_STEP - 1) & ~(SCAN_STEP - 1)
    end = min(address + SCAN_LIMIT, text_base + maximum - RECORD_SIZE + 1)
    reporter.log("Detecting kernel module size (kdump method, firmware 13.60)")
    scanned = 0
    while address < end:
        check_cancel(cancel)
        # No retries, bisection or zero-fill here: metadata must be real bytes.
        record = ps5.kern_read(address, RECORD_SIZE)
        if not isinstance(record, (bytes, bytearray)) or len(record) != RECORD_SIZE:
            raise ValueError(f"Short or invalid kernel module record at 0x{address:x}")
        if record[8:15] == b"kernel\0" and record[0x18:0x23] == b"elf kernel\0":
            size = struct.unpack_from("<Q", record, 0x40)[0]
            if not text_delta < size <= maximum:
                raise ValueError(f"Invalid detected kernel size: 0x{size:x}; dump stopped")
            reporter.log(f"Detected kernel: 0x{text_base:x}-0x{text_base + size:x} "
                         f"({size / MIB:.2f} MiB)", "ok")
            return dict(firmware=firmware, text_base=text_base, size=size,
                        module_info=address, allproc=allproc)
        address += SCAN_STEP
        scanned += 1
        if scanned % 256 == 0:
            reporter.log(f"Kernel module search: {scanned} records checked")
    raise ValueError("Kernel module size was not found within the bounded search; "
                     "no fallback to a guessed 83 MiB range")
