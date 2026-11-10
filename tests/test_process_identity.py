import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from ps5dbg.errors import BadStatus, ConnectionLost
from ps5dbg.constants import Status
from ps5dumper.core.console import process_details
from ps5dumper.gui.pages.processes import ProcessesPage

class ProcessIdentityTests(unittest.TestCase):
    def test_mismatched_selection_cannot_start_dump(self):
        page = SimpleNamespace(session=SimpleNamespace(console=SimpleNamespace(busy=False)),
            current=(55, 'orbis_audiod.elf'), selected_process=lambda: (60, 'SceHdmiEvent'),
            maps=[object()], regions=Mock(), region_title=Mock(), update_selection=Mock(),
            checked_maps=Mock())
        ProcessesPage.start_dump(page)
        self.assertIsNone(page.current)
        self.assertEqual(page.maps, [])
        page.checked_maps.assert_not_called()

    def test_late_map_result_is_discarded_after_selection_changes(self):
        page = SimpleNamespace(session=SimpleNamespace(console=SimpleNamespace(busy=False)),
            current=None, selected_process=lambda: (60, 'SceHdmiEvent'), maps=[],
            regions=Mock(), region_title=Mock(), update_selection=Mock(), show_regions=Mock())
        def run(task, done, failed):
            done([object()])
            return True
        page.session.console.run = run
        ProcessesPage.load_regions(page, 55, 'orbis_audiod.elf')
        self.assertIsNone(page.current)
        self.assertEqual(page.maps, [])
        page.show_regions.assert_not_called()

    def test_optional_metadata_error_reopens_socket_without_replay(self):
        for error in (BadStatus(Status.ERROR, 'CMD_PROC_INFO'), ConnectionLost('EOF')):
            with self.subTest(error=error):
                ps5=Mock()
                ps5.proc_info.side_effect=error
                self.assertEqual(process_details(ps5, 55, Mock()), {})
                ps5.proc_info.assert_called_once_with(55)
                ps5.close.assert_called_once_with()
                ps5.connect.assert_called_once_with()

    def test_optional_metadata_does_not_hide_failed_reconnection(self):
        ps5=Mock()
        ps5.proc_info.side_effect=ConnectionLost('EOF')
        ps5.connect.side_effect=ConnectionLost('offline')
        with self.assertRaises(ConnectionLost):
            process_details(ps5, 55, Mock())
