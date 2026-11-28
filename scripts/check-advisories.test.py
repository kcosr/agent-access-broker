import importlib.util
from datetime import date, datetime, timezone
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("advisories", Path(__file__).with_name("check-advisories.py"))
advisories = importlib.util.module_from_spec(spec)
spec.loader.exec_module(advisories)

CONFIG = '''[advisories]
ignore = [
    "RUSTSEC-2023-0071", # review-by: 2027-02-28
    "RUSTSEC-2026-0543", # review-by: 2027-02-28
]
'''


class ExceptionDates(unittest.TestCase):
    def test_review_deadline_is_inclusive_in_utc(self):
        for today in [date(2026, 11, 28), date(2027, 2, 28)]:
            advisories.check_exception_dates(CONFIG, today)
        with self.assertRaisesRegex(ValueError, "RUSTSEC-2023-0071.*expired"):
            advisories.check_exception_dates(CONFIG, date(2027, 3, 1))

    def test_each_exception_is_checked(self):
        text = CONFIG.replace('2027-02-28', '2028-02-28', 1)
        with self.assertRaisesRegex(ValueError, "RUSTSEC-2026-0543.*expired"):
            advisories.check_exception_dates(text, date(2027, 3, 1))

    def test_missing_malformed_and_impossible_dates_fail(self):
        for text in [CONFIG.replace(' # review-by: 2027-02-28', '', 1),
                     CONFIG.replace('2027-02-28', '2027-2-28', 1),
                     CONFIG.replace('2027-02-28', '2027-02-30', 1)]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                advisories.check_exception_dates(text, date(2026, 11, 28))

    def test_undated_added_exception_and_duplicates_fail(self):
        for text in [CONFIG.replace('\n]\n', '\n"RUSTSEC-2026-9999",\n]\n'),
                     CONFIG.replace('RUSTSEC-2026-0543', 'RUSTSEC-2023-0071')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                advisories.check_exception_dates(text, date(2026, 11, 28))

    def test_removed_exceptions_need_no_deadline(self):
        advisories.check_exception_dates('[advisories]\nignore = []\n', date(2099, 1, 1))

    def test_repository_exceptions_have_current_review_dates(self):
        advisories.check_exception_dates(
            (advisories.ROOT / '.cargo/audit.toml').read_text(),
            advisories.datetime.now(advisories.timezone.utc).date(),
        )

    def test_gate_rejects_expiry_before_cargo_and_propagates_audit_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '.cargo').mkdir()
            (root / '.cargo/audit.toml').write_text(CONFIG)
            with (patch.object(advisories, 'ROOT', root),
                  patch.object(advisories, 'datetime') as clock,
                  patch.object(advisories.subprocess, 'call', return_value=7) as audit,
                  patch.object(advisories.sys, 'argv', ['check-advisories.py', '--cargo', 'selected-cargo']),
                  patch.object(advisories.sys, 'stderr', io.StringIO())):
                clock.now.return_value = datetime(2027, 3, 1, tzinfo=timezone.utc)
                self.assertEqual(advisories.main(), 1)
                audit.assert_not_called()
                clock.now.return_value = datetime(2027, 2, 28, 23, 59, tzinfo=timezone.utc)
                self.assertEqual(advisories.main(), 7)
                audit.assert_called_once_with(['selected-cargo', 'audit', '--deny', 'warnings'], cwd=root)


if __name__ == "__main__":
    unittest.main()
