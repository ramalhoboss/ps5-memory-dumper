"""Segment a raw snapshot by long zero runs; preserves every byte via a manifest.
Nonzero data is NOT necessarily code. End offsets are exclusive.
"""
import argparse
import hashlib
import json
import mmap
import re
from pathlib import Path

CHUNK = 1024 * 1024


def digest_range(data, start, end):
    digest = hashlib.sha256()
    for pos in range(start, end, CHUNK):
        digest.update(data[pos:min(pos + CHUNK, end)])
    return digest.hexdigest()


def segment(source, output, minimum=65536, base=None):
    source, output = Path(source).resolve(), Path(output).resolve()
    if minimum < 1:
        raise ValueError('minimum must be positive')
    size = source.stat().st_size
    if base is not None and (base < 0 or base + size > 1 << 64):
        raise ValueError('address range exceeds 64 bits')
    output.mkdir(parents=True, exist_ok=False)
    document = dict(version=1, source=str(source), size=size,
                    min_zero_run=minimum, base=hex(base) if base is not None else None,
                    offset_end_exclusive=True, segments=[], complete=False)
    try:
        with source.open('rb') as stream:
            if size:
                with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                    document['sha256'] = digest_range(data, 0, size)
                    def emit(kind, start, end):
                        item = dict(kind=kind, offset=start, end=end, size=end-start)
                        if base is not None:
                            item['address'] = hex(base + start)
                        if kind == 'data':
                            name = f'data_{start:016x}_{end:016x}.bin'
                            digest = hashlib.sha256()
                            with (output / name).open('xb') as target:
                                for pos in range(start, end, CHUNK):
                                    block = data[pos:min(pos + CHUNK, end)]
                                    target.write(block)
                                    digest.update(block)
                            item.update(file=name, sha256=digest.hexdigest())
                        document['segments'].append(item)
                    cursor = 0
                    pattern = re.compile(b'\x00+')
                    for match in pattern.finditer(data):
                        start, end = match.span()
                        if end - start < minimum:
                            continue
                        if cursor < start:
                            emit('data', cursor, start)
                        emit('zero', start, end)
                        cursor = end
                    if cursor < size:
                        emit('data', cursor, size)
            else:
                document['sha256'] = hashlib.sha256(b'').hexdigest()
        document['stored_bytes'] = sum(s['size'] for s in document['segments'] if s['kind'] == 'data')
        document['omitted_zero_bytes'] = size - document['stored_bytes']
        document['complete'] = True
    finally:
        (output / 'segments.json').write_text(json.dumps(document, indent=2), encoding='utf-8')
    return document


def restore(manifest, destination):
    manifest, destination = Path(manifest).resolve(), Path(destination).resolve()
    doc = json.loads(manifest.read_text(encoding='utf-8'))
    if not doc.get('complete'):
        raise ValueError('incomplete segmentation')
    cursor = 0
    digest = hashlib.sha256()
    zeros = bytes(CHUNK)
    with destination.open('xb') as target:
        for item in doc['segments']:
            length = item['size']
            if item['offset'] != cursor or length <= 0 or item['end'] != cursor + length:
                raise ValueError('invalid segment coverage')
            if item['kind'] == 'zero':
                remaining = length
                while remaining:
                    block = zeros[:min(remaining, CHUNK)]
                    target.write(block)
                    digest.update(block)
                    remaining -= len(block)
            elif item['kind'] == 'data':
                path = (manifest.parent / item['file']).resolve()
                if path.parent != manifest.parent or path == destination:
                    raise ValueError('invalid segment path')
                actual = hashlib.sha256()
                received = 0
                with path.open('rb') as stream:
                    while block := stream.read(CHUNK):
                        received += len(block)
                        if received > length:
                            raise ValueError('oversized segment')
                        target.write(block)
                        actual.update(block)
                        digest.update(block)
                if received != length or actual.hexdigest() != item['sha256']:
                    raise ValueError('segment integrity mismatch')
            else:
                raise ValueError('unknown segment type')
            cursor += length
        if cursor != doc['size'] or digest.hexdigest() != doc['sha256']:
            raise ValueError('reconstructed image integrity mismatch')
    return cursor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    split = commands.add_parser('split')
    split.add_argument('source', type=Path)
    split.add_argument('output', type=Path, help='new directory')
    split.add_argument('--min-zero-run', type=int, default=65536, help='bytes; default 65536')
    split.add_argument('--base', type=lambda value: int(value, 0))
    rebuild = commands.add_parser('restore')
    rebuild.add_argument('manifest', type=Path)
    rebuild.add_argument('destination', type=Path, help='new file')
    args = parser.parse_args()
    if args.command == 'split':
        doc = segment(args.source, args.output, args.min_zero_run, args.base)
        print(f"Stored {doc['stored_bytes']} bytes; omitted {doc['omitted_zero_bytes']} zero bytes; {len(doc['segments'])} segments")
    else:
        print(f'Restored and verified {restore(args.manifest, args.destination)} bytes')


if __name__ == '__main__':
    main()
