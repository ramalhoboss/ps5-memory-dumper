"""Block reader with bisection recovery for ranges the payload partially refuses."""
import hashlib

from ps5dbg.errors import BadStatus

from .reporting import check_cancel

MIB = 1024 * 1024
# Each block is one full request to the payload (the server accepts up to 1 MiB).
BLOCK = MIB
PAGE = 4096  # smallest range bisection reaches
# Maximum recovery cost: a fully unreadable block costs ~2*BLOCK/PAGE requests.
MAX_UNREADABLE_BLOCKS = 2  # consecutive blocks without a readable byte before abandoning the rest of the region
NOT_ATTEMPTED = "NotAttempted"
_ZEROS = memoryview(bytes(BLOCK))


def validate_read(data, requested, address):
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > requested:
        raise RuntimeError(f"Invalid read at 0x{address:x}: expected 1..{requested} bytes")
    return data


def split_range(address, size):
    """Page-aligned halves, with the first one on top of the stack."""
    half = max(PAGE, size // 2 // PAGE * PAGE)
    return [(address + half, size - half), (address, half)]


def read_bisecting(reader, address, size, error, cancel=None):
    """Re-reads a range the server already refused (`error`), splitting it in half.

    Returns, in address order, tuples (address, size, data, error): `data` is
    None and `error` the BadStatus for ranges of up to PAGE bytes that stay
    unreadable. Only BadStatus is recoverable; any other failure propagates.
    """
    if size <= PAGE:
        return [(address, size, None, error)]
    chunks = []
    pending = split_range(address, size)
    while pending:
        check_cancel(cancel)
        a, n = pending.pop()
        try:
            data = validate_read(reader(a, n), n, a)
        except BadStatus as e:
            if n <= PAGE:
                chunks.append((a, n, None, e))
            else:
                pending.extend(split_range(a, n))
            continue
        chunks.append((a, len(data), data, None))
        if len(data) < n:  # short read: the rest is still unread
            pending.append((a + len(data), n - len(data)))
    return chunks


def record_gap(gaps, start, end, kind, message):
    """Appends [start, end); merges it with the previous gap if contiguous and from the same error."""
    if gaps:
        previous = gaps[-1]
        if (int(previous["end"], 16) == start and previous["type"] == kind
                and previous["message"] == message):
            previous["end"] = hex(end)
            previous["size"] = end - int(previous["start"], 16)
            return
    gaps.append(dict(start=hex(start), end=hex(end), size=end - start, type=kind, message=message))


def write_zeros(file, digest, count):
    while count > 0:
        chunk = _ZEROS[:min(count, BLOCK)]
        file.write(chunk)
        if digest is not None:
            digest.update(chunk)
        count -= len(chunk)


def read_chunks(reader, address, size, block, cancel=None):
    """Reads [address, address+size) in blocks, bisecting refused ones; same tuples as read_bisecting."""
    chunks = []
    end = address + size
    while address < end:
        check_cancel(cancel)
        request = min(block, end - address)
        try:
            data = validate_read(reader(address, request), request, address)
        except BadStatus as e:
            chunks += read_bisecting(reader, address, request, e, cancel)
            address += request
            continue
        chunks.append((address, len(data), data, None))
        address += len(data)
    return chunks


def gap_bytes_before(gaps, start, end):
    """Bytes of `gaps` that fall inside [start, end)."""
    return sum(max(0, min(int(g["end"], 16), end) - max(int(g["start"], 16), start)) for g in gaps)


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(BLOCK):
            digest.update(data)
    return digest.hexdigest()


def read_range(reader, start, size, destination, item, block, recover=False, economy=False,
               fill_gaps=False, cancel=None, on_advance=None, resume=False, retry_gaps=False,
               abandon_after=MAX_UNREADABLE_BLOCKS):
    """Writes only received bytes. A failure keeps the prefix and records the address.

    With recover=True a BadStatus does not abort: the block is halved down to a
    page (read_bisecting) and whatever stays unreadable goes to item["gaps"].
    With economy=True, if the first block is refused the whole region becomes a
    "NotAttempted" gap (1 request); if it is read, recovery continues normally.
    `abandon_after` consecutive blocks without a readable byte give up the rest of
    the region (None never gives up).
    With fill_gaps=True the gaps before received data are zero-filled, so the
    file offset always equals address - start; trailing unreadable bytes are omitted.
    With resume=True an existing file is continued: it must hold address-aligned data
    (zero-filled gaps, or no gaps). Its recorded gaps are kept or, with retry_gaps=True,
    read again and patched in place; then reading goes on from the end of the file.
    `on_advance(n)` is called after each block with the address bytes it handled.
    """
    end = start + size
    resuming = resume and destination.exists()
    if resuming:
        prefix = destination.stat().st_size
        if prefix > size:
            raise ValueError(f"{destination.name} is larger than its region")
        old_gaps = [g for g in item.get("gaps") or () if int(g["start"], 16) < start + prefix]
    digest = None if resuming else hashlib.sha256()
    created = False
    item.update(bytes=0, complete=False, errors=[], gaps=[])
    cursor = start  # next address not yet handled (as data or as a gap)
    written_end = start  # address that matches the current end of the file
    unreadable_streak = 0
    try:
        with destination.open("r+b" if resuming else "xb") as file:
            created = True
            if resuming:
                for gap in old_gaps:
                    a, b = int(gap["start"], 16), min(int(gap["end"], 16), start + prefix)
                    if not retry_gaps:
                        record_gap(item["gaps"], a, b, gap["type"], gap["message"])
                        continue
                    for address, n, data, error in read_chunks(reader, a, b - a, block, cancel):
                        if data is None:
                            record_gap(item["gaps"], address, address + n, type(error).__name__, str(error))
                        else:
                            file.seek(address - start)
                            file.write(data)
                file.seek(prefix)
                cursor = written_end = start + prefix
                if on_advance is not None:
                    on_advance(prefix)
            while cursor < end:
                check_cancel(cancel)
                before = cursor
                request = min(block, end - cursor)
                try:
                    data = validate_read(reader(cursor, request), request, cursor)
                    chunks = [(cursor, len(data), data, None)]
                except BadStatus as e:
                    if not recover:
                        raise
                    if economy and cursor == start:
                        record_gap(item["gaps"], start, end, NOT_ATTEMPTED,
                                   f"first block refused in economy mode: {e}")
                        cursor = end
                        chunks = []
                    else:
                        chunks = read_bisecting(reader, cursor, request, e, cancel)
                received = 0
                for address, n, data, error in chunks:
                    if data is None:
                        record_gap(item["gaps"], address, address + n, type(error).__name__, str(error))
                    else:
                        if fill_gaps:
                            write_zeros(file, digest, address - written_end)
                        file.write(data)
                        if digest is not None:
                            digest.update(data)
                        written_end = address + n
                        item["bytes"] += n
                        received += n
                    cursor = address + n
                unreadable_streak = 0 if received else unreadable_streak + 1
                if abandon_after and unreadable_streak >= abandon_after and cursor < end:
                    record_gap(item["gaps"], cursor, end, NOT_ATTEMPTED,
                               f"abandoned after {unreadable_streak} consecutive unreadable blocks")
                    cursor = end
                if on_advance is not None:
                    on_advance(cursor - before)
            item["complete"] = not item["gaps"]
    except BaseException as e:
        item["errors"].append(dict(address=hex(cursor), type=type(e).__name__, message=str(e)))
        raise
    finally:
        if created and destination.exists() and destination.stat().st_size == 0:
            destination.unlink()
            item["file"] = None
        if resuming and destination.exists():
            # Bytes were patched in place, so the hash and the count come from the final file.
            file_size = destination.stat().st_size
            item["sha256"] = file_sha256(destination)
            item["bytes"] = file_size - (gap_bytes_before(item["gaps"], start, start + file_size) if fill_gaps else 0)
        else:
            item["sha256"] = (digest or hashlib.sha256()).hexdigest()
