#!/usr/bin/env python3
"""R771: user-owned special package file must fail closed without hanging Root.

The test only invokes pure source helpers with disposable FIFO/regular files
under this checkout. Each potentially blocking call runs in a bounded child.
No root privileges, real system services or network are involved.
"""
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/"linux/system/protected_upgrade_transaction.py"
CHILD=r'''
import importlib.util,sys
spec=importlib.util.spec_from_file_location("dim_r771_root",sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
name,path=sys.argv[2:]
try:
    if name=="no_symlink_regular":
        m.no_symlink_regular(path,owner=False)
    else:
        getattr(m,name)(path)
except RuntimeError as exc:
    if "FAIL_CLOSED_UNSAFE_FILE_TYPE_OR_SIZE" in str(exc):
        print("R771_REJECTED_NONREGULAR")
        sys.exit(0)
    print("R771_UNEXPECTED_ERROR",type(exc).__name__,str(exc))
    sys.exit(91)
except Exception as exc:
    print("R771_UNEXPECTED_EXCEPTION",type(exc).__name__,str(exc))
    sys.exit(92)
sys.exit(93)
'''

class R771SpecialFileNoHang(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="r771-user-fifo-",dir=str(ROOT))
        self.base=pathlib.Path(self.tmp.name)
        self.fifo=self.base/"untrusted-package-member"
        os.mkfifo(self.fifo,0o600)
        self.regular=self.base/"regular-payload"
        self.regular.write_bytes(b"PINNED_REGULAR_FILE")

    def tearDown(self):
        self.tmp.cleanup()

    def _must_reject_fifo(self,name):
        command=[sys.executable,"-B","-c",CHILD,str(SOURCE),name,str(self.fifo)]
        try:
            response=subprocess.run(command,capture_output=True,text=True,timeout=2.0)
        except subprocess.TimeoutExpired:
            self.fail("R771_FIFO_OPEN_BLOCKED_WAITING_FOR_NONEXISTENT_WRITER")
        self.assertEqual(response.returncode,0,(name,response.stdout,response.stderr))
        self.assertIn("R771_REJECTED_NONREGULAR",response.stdout)

    def test_01_guarded_source_bytes_reject_fifo_without_hang(self):
        self._must_reject_fifo("guarded_file_bytes")

    def test_02_regular_file_validation_reject_fifo_without_hang(self):
        self._must_reject_fifo("no_symlink_regular")

    def test_03_hash_file_reject_fifo_without_hang(self):
        self._must_reject_fifo("hash_file")

    def test_04_valid_regular_files_remain_readable(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location("dim_r771_inline",SOURCE)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        content=self.regular.read_bytes()
        self.assertEqual(module.guarded_file_bytes(self.regular),content)
        self.assertEqual(module.hash_file(self.regular),hashlib.sha256(content).hexdigest().upper())
        self.assertEqual(module.no_symlink_regular(self.regular,owner=False).st_size,len(content))

if __name__=="__main__":
    unittest.main(verbosity=2)
