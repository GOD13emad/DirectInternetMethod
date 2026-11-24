"""Native Linux SO_PEERCRED observation across actual processes.

This test never authenticates polkit, deploys a service or mints a receipt.
A client-provided pid/uid in its bytes must not override kernel credentials.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from installer_engine.engine import EngineError
from installer_engine.linux_peer_credential import (
    STATUS, observe_linux_peer_credentials,
)


@unittest.skipUnless(sys.platform.startswith("linux") and
                     hasattr(socket, "SO_PEERCRED"),
                     "Linux kernel AF_UNIX credentials required")
class LinuxNativeKernelPeerTests(unittest.TestCase):
    def test_same_process_native_socketpair_not_a_polkit_grant(self):
        a,b=socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a,b:
            result=observe_linux_peer_credentials(
                a,expected_uid=os.getuid(), expected_pid=os.getpid())
        self.assertEqual(result["status"],STATUS)
        self.assertTrue(result["peer_credentials_native_kernel"])
        self.assertEqual(result["kernel_peer_uid"],os.getuid())
        self.assertEqual(result["kernel_peer_pid"],os.getpid())
        for key in ("polkit_authorized","system_bus_sender_authenticated",
                    "privileged_broker_implemented",
                    "protected_replay_writer_implemented",
                    "publisher_authenticated","native_installation_accepted"):
            self.assertFalse(result[key])

    def test_genuine_other_process_cannot_spoof_uid_via_request_json(self):
        with tempfile.TemporaryDirectory(prefix="dim-r936-peer-") as directory:
            path=str(Path(directory)/"peer.sock")
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(6)
                payload=json.dumps({"pid":1,"uid":0,"gid":0,
                                    "authorized":True}).encode()
                client_code=(
                    "import socket,sys;"
                    "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
                    "s.connect(sys.argv[1]);"
                    "s.sendall(bytes.fromhex(sys.argv[2]));"
                    "s.close()")
                child=subprocess.Popen([sys.executable,"-c",client_code,
                                        path,payload.hex()],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                try:
                    with listener.accept()[0] as connection:
                        peer=observe_linux_peer_credentials(
                            connection,expected_uid=os.getuid(),
                            expected_pid=child.pid)
                        raw=connection.recv(4096)
                    output,error=child.communicate(timeout=6)
                    self.assertEqual(child.returncode,0,error)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=3)
                self.assertEqual(raw,payload)
                self.assertEqual(peer["kernel_peer_pid"],child.pid)
                self.assertEqual(peer["kernel_peer_uid"],os.getuid())
                self.assertNotEqual(peer["kernel_peer_pid"],1)
                self.assertFalse(peer["polkit_authorized"])
                self.assertFalse(peer["native_installation_accepted"])

    def test_wrong_kernel_uid_is_fail_closed(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        with a,b:
            with self.assertRaisesRegex(EngineError,"LINUX_PEER_UID_MISMATCH"):
                observe_linux_peer_credentials(a,expected_uid=os.getuid()+1)

    def test_wrong_kernel_pid_is_fail_closed(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        with a,b:
            with self.assertRaisesRegex(EngineError,"LINUX_PEER_PID_MISMATCH"):
                observe_linux_peer_credentials(a,expected_pid=os.getpid()+1)

    def test_client_cannot_choose_invalid_expected_identity_types(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        with a,b:
            for expected in (True,-1,"1000"):
                with self.subTest(expected=expected):
                    with self.assertRaisesRegex(
                        EngineError,"LINUX_PEER_EXPECTED_UID_INVALID"):
                        observe_linux_peer_credentials(a,expected_uid=expected)

    def test_unrelated_socket_family_or_type_rejected(self):
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        with a,b:
            with self.assertRaisesRegex(
                EngineError,"LINUX_PEER_UNIX_STREAM_REQUIRED"):
                observe_linux_peer_credentials(a)


if __name__=="__main__":
    unittest.main()
