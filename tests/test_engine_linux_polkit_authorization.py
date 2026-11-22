"""Vendor polkit OS credential authorization, not a production publisher grant."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from installer_engine.engine import EngineError
from installer_engine.linux_polkit_authorization import (
    STATUS, _subject_proc, observe_linux_polkit_authorization,
)

ACTION = "org.god13emad.directinternetmethod.install"


@unittest.skipUnless(sys.platform.startswith("linux") and
                     hasattr(socket, "SO_PEERCRED"),
                     "Linux kernel SO_PEERCRED required")
class ActualLinuxPolkitSubject(unittest.TestCase):
    def test_kernel_proc_identity_same_process(self):
        start, uid = _subject_proc(os.getpid())
        self.assertGreater(start, 0)
        self.assertEqual(uid, os.getuid())

    def test_os_kernel_peer_and_no_shell_using_vendor_pkcheck(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b, mock.patch(
            "installer_engine.linux_polkit_authorization.subprocess.run",
            return_value=SimpleNamespace(returncode=1)
        ) as runner:
            result = observe_linux_polkit_authorization(a, ACTION)
        args, kwargs = runner.call_args
        self.assertEqual(args[0][0], "/usr/bin/pkcheck")
        self.assertEqual(args[0][1:3], ["--action-id", ACTION])
        self.assertEqual(args[0][3], "--process")
        self.assertEqual(args[0][4].split(",")[0], str(os.getpid()))
        self.assertEqual(args[0][4].split(",")[-1], str(os.getuid()))
        self.assertNotIn("--allow-user-interaction", args[0])
        self.assertNotIn("shell", kwargs)
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(result["polkit_authorized"])
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["publisher_authenticated"])

    def test_actual_vendor_missing_policy_is_denied_not_installed(self):
        if not Path("/usr/bin/pkcheck").is_file():
            self.skipTest("vendor pkcheck missing: absent OS dependency not success")
        # Randomly named non-installed action; never authenticates a real broker.
        import secrets
        action = "org.god13emad.directinternetmethod.uninstalled-" + secrets.token_hex(8)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b:
            result = observe_linux_polkit_authorization(a, action)
        self.assertEqual(result["status"], STATUS)
        self.assertFalse(result["polkit_authorized"])
        self.assertFalse(result["native_installation_accepted"])

    def test_real_second_process_spoofed_identity_json_does_not_authorize(self):
        import tempfile
        import json
        with tempfile.TemporaryDirectory(prefix="dim-r939-peer-") as directory:
            endpoint = str(Path(directory) / "peer.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(endpoint)
                listener.listen(1)
                listener.settimeout(7)
                # This real child lies about being uid 0 and authorized.
                code = ("import socket,sys;"
                        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
                        "s.connect(sys.argv[1]);"
                        "s.sendall(b'{\\\"uid\\\":0,\\\"authorized\\\":true}');"
                        "s.recv(1);s.close()")
                child = subprocess.Popen([sys.executable, "-c", code, endpoint],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
                try:
                    with listener.accept()[0] as conn:
                        result = observe_linux_polkit_authorization(
                            conn, "org.god13emad.directinternetmethod.unknown-" +
                            str(child.pid))
                        raw = conn.recv(100)
                        conn.sendall(b"x")
                    _, stderr = child.communicate(timeout=5)
                    self.assertEqual(child.returncode, 0, stderr)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=3)
            self.assertEqual(json.loads(raw), {"uid": 0, "authorized": True})
            self.assertFalse(result["polkit_authorized"])
            self.assertFalse(result["native_installation_accepted"])
            if "kernel_peer_pid" in result:
                self.assertEqual(result["kernel_peer_pid"], child.pid)
                self.assertEqual(result["kernel_peer_uid"], os.getuid())

    def test_pin_never_promotes_polkit_to_product_acceptance(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b, mock.patch(
            "installer_engine.linux_polkit_authorization.subprocess.run",
            return_value=SimpleNamespace(returncode=0)
        ):
            result = observe_linux_polkit_authorization(a, ACTION)
        self.assertTrue(result["polkit_authorized"])  # MOCK ONLY, not native auth
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertFalse(result["privileged_broker_implemented"])

    def test_pid_start_or_uid_drift_denied_even_if_pkcheck_says_allowed(self):
        start, uid = _subject_proc(os.getpid())
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b, mock.patch(
            "installer_engine.linux_polkit_authorization._subject_proc",
            side_effect=[(start, uid), (start + 1, uid)]
        ), mock.patch(
            "installer_engine.linux_polkit_authorization.subprocess.run",
            return_value=SimpleNamespace(returncode=0)
        ):
            with self.assertRaisesRegex(EngineError, "SUBJECT_CHANGED"):
                observe_linux_polkit_authorization(a, ACTION)

    def test_kernel_uid_mismatch_denied_before_pkcheck(self):
        start, uid = _subject_proc(os.getpid())
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b, mock.patch(
            "installer_engine.linux_polkit_authorization._subject_proc",
            return_value=(start, uid + 1)
        ), mock.patch(
            "installer_engine.linux_polkit_authorization.subprocess.run"
        ) as runner:
            with self.assertRaisesRegex(EngineError, "PEER_UID_DRIFT"):
                observe_linux_polkit_authorization(a, ACTION)
        runner.assert_not_called()

    def test_no_auth_on_subprocess_failure_and_bad_action(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b:
            for bad in ("", "systemd1", "org.example;sh", "org.example/evil", "org.example_bad.id", 42):
                with self.subTest(bad=bad), self.assertRaisesRegex(
                    EngineError, "ACTION_ID_INVALID"):
                    observe_linux_polkit_authorization(a, bad)
            with mock.patch(
                "installer_engine.linux_polkit_authorization.subprocess.run",
                side_effect=FileNotFoundError
            ):
                result = observe_linux_polkit_authorization(a, ACTION)
        self.assertFalse(result["polkit_authorized"])
        self.assertEqual(result["reason"], "LINUX_POLKIT_NATIVE_CHECK_UNAVAILABLE")

    def test_bare_pid_not_taken_from_request(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with a, b:
            with self.assertRaisesRegex(EngineError, "UNIX_STREAM_REQUIRED"):
                observe_linux_polkit_authorization(a, ACTION)


class PortableLinuxPolkitSource(unittest.TestCase):
    def test_polkit_action_is_not_os_installed_authority(self):
        from installer_engine import linux_polkit_authorization
        p = Path(linux_polkit_authorization.__file__).read_text("utf8")
        self.assertIn("SO_PEERCRED", p)
        self.assertIn('"--process"', p)
        self.assertIn('f"{pid},{start},{uid}"', p)
        self.assertIn("native_installation_accepted\": False", p)
        self.assertNotIn("shell=True", p)
        self.assertNotIn("--enable-internal-agent", p)


if __name__ == "__main__":
    unittest.main()
