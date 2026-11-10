"""Map refusal recovery, including a real TCP close by a simulated payload."""
import socket
import struct
import threading
import unittest
from unittest.mock import Mock
from ps5dbg import PS5Debug
from ps5dbg.constants import Status
from ps5dbg.errors import BadStatus, ConnectionLost
from ps5dumper.core.console import process_maps


class ProcessMapsTests(unittest.TestCase):
    def test_refused_maps_reconnect_once_without_replaying(self):
        ps5, reporter = Mock(), Mock()
        ps5.maps.side_effect = BadStatus(Status.ERROR, 'CMD_PROC_MAPS')
        self.assertIsNone(process_maps(ps5, 12, reporter))
        ps5.maps.assert_called_once_with(12)
        ps5.close.assert_called_once_with()
        ps5.connect.assert_called_once_with()

    def test_failed_reconnect_is_a_real_disconnect(self):
        ps5 = Mock()
        ps5.maps.side_effect = BadStatus(Status.ERROR, 'CMD_PROC_MAPS')
        ps5.connect.side_effect = ConnectionLost('offline')
        with self.assertRaises(ConnectionLost):
            process_maps(ps5, 12, Mock())

    def test_transport_failure_is_not_hidden(self):
        ps5 = Mock()
        ps5.maps.side_effect = ConnectionLost('offline')
        with self.assertRaises(ConnectionLost):
            process_maps(ps5, 12, Mock())
        ps5.connect.assert_not_called()

    def test_success_preserves_maps_without_reconnect(self):
        ps5 = Mock()
        ps5.maps.return_value = [object()]
        self.assertEqual(process_maps(ps5, 12, Mock()), ps5.maps.return_value)
        ps5.close.assert_not_called()
        ps5.connect.assert_not_called()

    def test_pid_zero_never_sends_process_maps(self):
        ps5 = Mock()
        with self.assertRaises(ValueError):
            process_maps(ps5, 0, Mock())
        ps5.maps.assert_not_called()

    def test_tcp_error_close_then_next_process_succeeds(self):
        requests, errors = [], []
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        listener.settimeout(5)
        def receive(conn, length):
            out = b''
            while len(out) < length:
                part = conn.recv(length - len(out))
                if not part:
                    raise RuntimeError('unexpected EOF')
                out += part
            return out
        def serve():
            try:
                for refused in (True, False):
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(5)
                        magic, cmd, size = struct.unpack('<III', receive(conn, 12))
                        pid, = struct.unpack('<I', receive(conn, size))
                        requests.append((cmd, pid))
                        if refused:
                            conn.sendall(struct.pack('<I', int(Status.ERROR)))
                        else:
                            conn.sendall(struct.pack('<II', int(Status.SUCCESS), 1))
                            conn.sendall(struct.pack('<32sQQQH', b'text', 0x400000, 0x401000, 0, 5))
            except Exception as error:
                errors.append(error)
        server = threading.Thread(target=serve, daemon=True)
        server.start()
        ps5 = PS5Debug('127.0.0.1', port=listener.getsockname()[1], timeout=2)
        try:
            ps5.connect()
            self.assertIsNone(process_maps(ps5, 12, Mock()))
            maps = process_maps(ps5, 34, Mock())
            self.assertEqual(len(maps), 1)
            self.assertEqual(maps[0].start, 0x400000)
            self.assertEqual(maps[0].name, 'text')
        finally:
            ps5.close()
            server.join(6)
            listener.close()
        self.assertFalse(server.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(requests, [(0xBDAA0004, 12), (0xBDAA0004, 34)])

    def test_gui_clears_old_regions_before_loading_a_new_pid(self):
        from types import SimpleNamespace
        from ps5dumper.gui.pages.processes import ProcessesPage
        runner = SimpleNamespace(busy=False)
        page = SimpleNamespace(
            session=SimpleNamespace(console=runner, ps5=Mock()), current=(8, 'old'),
            maps=[object()], regions=Mock(), region_title=Mock(), update_selection=Mock(),
            show_regions=Mock(), selected_process=lambda: (12, "restricted"))
        def run(task, done, failed):
            self.assertIsNone(page.current)
            self.assertEqual(page.maps, [])
            page.regions.setRowCount.assert_called_with(0)
            with __import__('unittest.mock', fromlist=['patch']).patch(
                    'ps5dumper.gui.pages.processes.process_maps', return_value=None):
                self.assertIsNone(task(Mock(), None))
            done(None)
            self.assertIsNone(page.current)
            page.show_regions.assert_not_called()
            self.assertIn('Connection reopened', page.region_title.setText.call_args.args[0])
            return False
        runner.run = run
        ProcessesPage.load_regions(page, 12, 'restricted')
