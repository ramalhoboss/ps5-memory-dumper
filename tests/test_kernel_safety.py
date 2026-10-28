"""Offline regression checks for PID 0 routing and bounded kernel requests."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from ps5dbg.errors import ConnectionLost
from ps5dumper.core.console import process_details
from ps5dumper.core.dumper import dump_kernel, resume_dump, ResumeError, KERNEL_BLOCK
from ps5dumper.core.manifest import save_manifest, load_manifest

BASE = 0xffffffff81680000

class KernelSafetyTests(unittest.TestCase):
    def test_kernel_requests_stay_within_pages_and_exact_range(self):
        ps5 = Mock()
        ps5.kern_base.return_value = BASE
        ps5.kern_read.side_effect = lambda a, n: bytes([a % 251]) * n
        with tempfile.TemporaryDirectory() as d:
            start, size = BASE + 123, KERNEL_BLOCK * 2 + 321
            result = dump_kernel(ps5, Path(d), size=size, start=start)
            cursor = start
            expected = bytearray()
            for call in ps5.kern_read.call_args_list:
                a, n = call.args
                self.assertEqual(a, cursor)
                self.assertGreater(n, 0)
                self.assertLessEqual(n, KERNEL_BLOCK - a % KERNEL_BLOCK)
                cursor += n
                expected.extend(bytes([a % 251]) * n)
            self.assertEqual(cursor, start + size)
            self.assertEqual(result['status'], 'complete')
            self.assertEqual((Path(d) / result['regions'][0]['file']).read_bytes(), expected)
        ps5.maps.assert_not_called()
        ps5.read.assert_not_called()

    def test_lost_kernel_connection_is_not_replayed(self):
        ps5 = Mock()
        ps5.kern_base.return_value = BASE
        ps5.kern_read.side_effect = [b'x' * KERNEL_BLOCK, ConnectionLost('disconnected')]
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConnectionLost):
                dump_kernel(ps5, Path(d), size=KERNEL_BLOCK * 3, retries=5)
            document = load_manifest(Path(d))
            self.assertEqual(document['status'], 'failed')
            self.assertEqual(document['bytes'], KERNEL_BLOCK)
            self.assertEqual(document['reconnects'], 0)
        self.assertEqual(ps5.kern_read.call_count, 2)
        ps5.connect.assert_not_called()

    def test_pid_zero_metadata_does_not_query_process(self):
        ps5 = Mock()
        self.assertEqual(process_details(ps5, 0), {})
        ps5.proc_info.assert_not_called()

    def test_legacy_pid_zero_process_dump_is_rejected_before_network(self):
        ps5 = Mock()
        with tempfile.TemporaryDirectory() as d:
            save_manifest(Path(d), dict(format_version=2, type='process', pid=0, regions=[]))
            with self.assertRaises(ResumeError):
                resume_dump(ps5, Path(d))
        self.assertEqual(ps5.mock_calls, [])

    def test_selecting_pid_zero_routes_to_kernel_without_maps(self):
        from types import SimpleNamespace
        from ps5dumper.gui.pages.processes import ProcessesPage
        ps5 = Mock()
        page = SimpleNamespace(
            session=SimpleNamespace(ps5=ps5, console=Mock()),
            current=(17, 'previous'), maps=[object()], regions=Mock(),
            region_title=Mock(), update_selection=Mock(), kernel_requested=Mock())
        ProcessesPage.load_regions(page, 0, 'kernel')
        self.assertIsNone(page.current)
        self.assertEqual(page.maps, [])
        page.regions.setRowCount.assert_called_once_with(0)
        page.update_selection.assert_called_once_with()
        page.kernel_requested.emit.assert_called_once_with()
        page.session.console.run.assert_not_called()
        ps5.maps.assert_not_called()

if __name__ == '__main__':
    unittest.main()
