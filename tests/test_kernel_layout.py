"""Regression checks for the bounded kdump module-info discovery."""
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from ps5dbg.errors import ConnectionLost
from ps5dumper.core.dumper import dump_kernel, KERNEL_LIMIT, KERNEL_BLOCK
from ps5dumper.core.kernel_layout import detect_kernel_layout, OFFSETS, RECORD_SIZE
from ps5dumper.core.reporting import Reporter, DumpCancelled

BASE = 0xffffffff81680000
TEXT = BASE - OFFSETS[1360][0]
FIRST_RECORD = (BASE + OFFSETS[1360][1] + 0xfff) & ~0xfff
SIZE = OFFSETS[1360][0] + 123


def record(size=SIZE):
    data = bytearray(RECORD_SIZE)
    data[8:15] = b"kernel\0"
    data[0x18:0x23] = b"elf kernel\0"
    struct.pack_into('<Q', data, 0x40, size)
    return bytes(data)


class KernelLayoutTests(unittest.TestCase):
    def client(self):
        ps5 = Mock()
        ps5.fw_version.return_value = 1360
        ps5.kern_base.return_value = BASE
        return ps5

    def test_full_image_uses_text_base_and_exact_detected_size(self):
        ps5 = self.client()
        def read(a, n):
            if a == FIRST_RECORD and n == RECORD_SIZE:
                return record()
            self.assertGreaterEqual(a, TEXT)
            self.assertLessEqual(a + n, TEXT + SIZE)
            self.assertLessEqual(n, KERNEL_BLOCK - a % KERNEL_BLOCK)
            return b'x' * n
        ps5.kern_read.side_effect = read
        with tempfile.TemporaryDirectory() as d:
            document = dump_kernel(ps5, Path(d))
            self.assertTrue(document['full_kernel'])
            self.assertEqual(document['kernel_firmware'], 1360)
            self.assertEqual(document['status'], 'complete')
            region = document['regions'][0]
            self.assertEqual(int(region['start'], 16), TEXT)
            self.assertEqual(int(region['end'], 16), TEXT + SIZE)
            self.assertEqual((Path(d) / region['file']).stat().st_size, SIZE)
        ps5.maps.assert_not_called()
        ps5.connect.assert_not_called()

    def test_search_advances_by_4k_until_both_names_match(self):
        ps5 = self.client()
        wrong = bytearray(record())
        wrong[0x18] = ord('X')
        ps5.kern_read.side_effect = [bytes(wrong), record()]
        result = detect_kernel_layout(ps5, BASE, KERNEL_LIMIT, Reporter())
        self.assertEqual(result['module_info'], FIRST_RECORD + 0x1000)
        self.assertEqual(ps5.kern_read.call_args_list[0].args, (FIRST_RECORD, RECORD_SIZE))

    def test_unsupported_firmware_never_reads_kernel_memory(self):
        ps5 = self.client()
        ps5.fw_version.return_value = 1342
        with self.assertRaisesRegex(ValueError, 'not supported'):
            detect_kernel_layout(ps5, BASE, KERNEL_LIMIT, Reporter())
        ps5.kern_read.assert_not_called()

    def test_invalid_sizes_are_rejected(self):
        for size in (0, OFFSETS[1360][0], KERNEL_LIMIT + 1, 2**64 - 1):
            with self.subTest(size=size):
                ps5 = self.client()
                ps5.kern_read.return_value = record(size)
                with self.assertRaisesRegex(ValueError, 'Invalid detected'):
                    detect_kernel_layout(ps5, BASE, KERNEL_LIMIT, Reporter())
                self.assertEqual(ps5.kern_read.call_count, 1)

    def test_search_is_bounded_and_never_guesses_size(self):
        ps5 = self.client()
        ps5.kern_read.return_value = bytes(RECORD_SIZE)
        with patch('ps5dumper.core.kernel_layout.SCAN_LIMIT', 0x2000):
            with self.assertRaisesRegex(ValueError, 'no fallback'):
                detect_kernel_layout(ps5, BASE, KERNEL_LIMIT, Reporter())
        self.assertEqual(ps5.kern_read.call_count, 2)

    def test_metadata_disconnect_aborts_without_image_or_retries(self):
        ps5 = self.client()
        ps5.kern_read.side_effect = ConnectionLost('disconnected')
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConnectionLost):
                dump_kernel(ps5, Path(d))
            self.assertEqual(list(Path(d).iterdir()), [])
        self.assertEqual(ps5.kern_read.call_count, 1)
        ps5.connect.assert_not_called()

    def test_cancel_prevents_metadata_reads(self):
        ps5 = self.client()
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(DumpCancelled):
            detect_kernel_layout(ps5, BASE, KERNEL_LIMIT, Reporter(), cancel)
        ps5.kern_read.assert_not_called()

    def test_short_metadata_is_not_zero_filled(self):
        ps5 = self.client()
        ps5.kern_read.return_value = b'x'
        with self.assertRaisesRegex(ValueError, 'Short or invalid'):
            detect_kernel_layout(ps5, BASE, KERNEL_LIMIT, Reporter())
        self.assertEqual(ps5.kern_read.call_count, 1)
