"""Native-uninstall transaction contract; no real OS registration is touched."""
import os
from pathlib import Path
import tempfile
import unittest

from installer_engine.engine import Engine, EngineError
from test_engine import PLATFORM, bundle

class UninstallTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='dim-uninstall-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.e = Engine(self.home / 'root', PLATFORM)
        self.pkg, self.pin = bundle(self.home, 'one', '1.5.7', {'app/main.bin': b'original'})
        self.e.stage(self.pkg, self.pin)
        self.e.activate(lambda: True)
        self.e.commit(lambda: True)
        self.data = self.e.root / 'data' / 'settings.secret'
        self.data.parent.mkdir()
        self.data.write_bytes(b'owner personal data, never remove')

    def test_prepare_and_cancel_native_unregistration_failure(self):
        self.e.prepare_uninstall(lambda: True)
        with self.assertRaisesRegex(EngineError, 'PENDING_REQUIRES'):
            self.e.verify()
        with self.assertRaisesRegex(EngineError, 'NATIVE_UNREGISTRATION_NOT_PROVEN'):
            self.e.finish_uninstall(lambda: False)
        self.assertEqual(self.e.abort_uninstall(lambda: True)['status'], 'PASS_UNINSTALL_ABORTED')
        self.assertEqual(self.e.verify()['version'], '1.5.7')
        self.assertEqual(self.data.read_bytes(), b'owner personal data, never remove')

    def test_scoped_complete_uninstall_then_new_clean_install(self):
        self.e.prepare_uninstall(lambda: True)
        result = self.e.finish_uninstall(lambda: True)
        self.assertEqual(result['status'], 'PASS_UNINSTALLED_CODE_ONLY')
        self.assertEqual(self.e.verify()['status'], 'EMPTY')
        self.assertFalse(self.e.current.exists())
        self.assertEqual(self.data.read_bytes(), b'owner personal data, never remove')
        self.e.stage(self.pkg, self.pin)
        self.e.activate(lambda: True)
        self.e.commit(lambda: True)
        self.assertEqual(self.e.verify()['version'], '1.5.7')

    def test_replay_native_uninstall_after_accepted_and_code_removed(self):
        self.e.prepare_uninstall(lambda: True)
        from installer_engine.engine import safe_remove_slot, atomic_json
        with self.e.locked():
            st = self.e._uninstall()
            atomic_json(self.e.uninstall_journal, {**st, 'phase':'accepted'})
            safe_remove_slot(self.e.previous, st['old']['manifest'])
        result = self.e.finish_uninstall(lambda: True)
        self.assertEqual(result['status'], 'PASS_UNINSTALLED_CODE_ONLY')
        self.assertEqual(self.e.verify()['status'], 'EMPTY')

    def test_replay_abort_after_rename(self):
        self.e.prepare_uninstall(lambda: True)
        with self.e.locked():
            os.rename(self.e.previous, self.e.current)
        self.e.abort_uninstall(lambda: True)
        self.assertEqual(self.e.verify()['version'], '1.5.7')

    def test_uninstall_does_not_delete_unknown_file(self):
        self.e.prepare_uninstall(lambda: True)
        unknown = self.e.previous / 'UNOWNED.txt'
        unknown.write_bytes(b'keep')
        with self.assertRaisesRegex(EngineError, 'FOREIGN_OR_MISSING_ACTIVE_FILES'):
            self.e.finish_uninstall(lambda: True)
        self.assertEqual(unknown.read_bytes(), b'keep')
        self.assertTrue(self.e.uninstall_journal.exists())

    def test_uninstall_refuses_mutual_transactions(self):
        self.e.prepare_uninstall(lambda: True)
        with self.assertRaisesRegex(EngineError, 'UNRECONCILED_PRIOR_TRANSACTION'):
            self.e.stage(self.pkg, self.pin)
        with self.assertRaisesRegex(EngineError, 'UNINSTALL_TRANSACTION_ACTIVE'):
            self.e.rollback(lambda: True)
        self.e.abort_uninstall(lambda: True)

    def test_uninstall_requires_quiescence(self):
        with self.assertRaisesRegex(EngineError, 'PRODUCT_NOT_QUIESCED'):
            self.e.prepare_uninstall(lambda: False)
        self.assertEqual(self.e.verify()['version'], '1.5.7')

if __name__ == "__main__":
    unittest.main(verbosity=2)
