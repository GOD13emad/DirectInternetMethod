#!/usr/bin/env python3
"""R861: reject immediate policy-route drift BEFORE outgoing TLS or TCP relay.

Loopback + socketpair only; no external routing, DNS, privilege, VPN, browser,
installed files or system proxy mutation. Negative-first on R860 exact source.
"""
import importlib.util
import pathlib
import socket
import ssl
import struct
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/"linux/app/socket_fallback.py"
SPEC=importlib.util.spec_from_file_location("r861_under_test",SOURCE)
mod=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=mod
SPEC.loader.exec_module(mod)

def exact(s,n):
    data=b""
    while len(data)<n:
        b=s.recv(n-len(data))
        if not b:raise EOFError("EARLY_EOF")
        data+=b
    return data

def tls_client_hello():
    ctx=ssl.create_default_context()
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
    tls=ctx.wrap_bio(incoming,outgoing,server_hostname="www.youtube.com")
    try:tls.do_handshake()
    except ssl.SSLWantReadError:pass
    raw=outgoing.read()
    assert raw[0]==22 and raw[5]==1
    return raw

class ImmediateRouteDrift(unittest.TestCase):
    def setUp(self):
        self.physical=mod.PhysicalRoute("fake-physical","127.0.0.1")
        self.allowed=[True]
        self.checks=[]
        self.left,self.right=socket.socketpair()
        self.right.settimeout(2.5)
        def target(ip,route):
            self.checks.append((ip,route))
            return self.allowed[0]
        self.bridge=mod.LocalSocketFallback(
            route_getter=lambda:self.physical,
            resolver=lambda host:["142.251.151.4"],
            dialer=lambda ip,port,source_ip:self.left,
            destination_route_getter=target)
        self.port=self.bridge.start()
        self.client=socket.create_connection(("127.0.0.1",self.port),timeout=2.5)
        self.client.settimeout(2.5)
        self.addCleanup(self.right.close)
        self.addCleanup(self.bridge.stop)
        self.addCleanup(self.client.close)
        self.client.sendall(b"\x05\x01\x00")
        self.assertEqual(exact(self.client,2),b"\x05\x00")
        host=b"www.youtube.com"
        self.client.sendall(b"\x05\x01\x00\x03"+bytes([len(host)])+host+struct.pack("!H",443))
        self.assertEqual(exact(self.client,10)[1],0)

    def test_no_first_clienthello_after_route_drifts_post_dial(self):
        # Existing SOCKS handshake succeeded. Policy changes immediately,
        # before first ClientHello is sent; no periodic timer has elapsed.
        self.assertTrue(self.checks)
        self.allowed[0]=False
        self.client.sendall(tls_client_hello())
        self.assertEqual(self.right.recv(1),b"", "TLS_BYTES_LEAKED_AFTER_POST_DIAL_DRIFT")
        self.assertGreater(len(self.checks),1,"MISSING_PRE_TLS_ROUTE_RECHECK")

    def test_no_relay_bytes_during_fifteen_second_route_check_gap(self):
        rec=tls_client_hello()
        self.client.sendall(rec)
        self.assertEqual(exact(self.right,len(rec)),rec)
        self.right.sendall(b"CONTROL_OK")
        self.assertEqual(exact(self.client,10),b"CONTROL_OK")
        # The route changes before the 15-second periodic check. The next
        # outgoing application record must be denied before sendall.
        prior=len(self.checks)
        self.allowed[0]=False
        self.client.sendall(b"R861_EGRESS_MUST_BE_DENIED")
        self.assertEqual(self.right.recv(1),b"", "OUTBOUND_BYTES_LEAKED_IN_15_SECOND_WINDOW")
        self.assertGreater(len(self.checks),prior,"MISSING_EGRESS_ROUTE_RECHECK")

class SplitFragmentDrift(unittest.TestCase):
    def test_deny_second_tls_fragment_if_route_changes_between_writes(self):
        sent=[]
        allowed=[True]
        class ControlledSender:
            def sendall(self,data):
                sent.append(bytes(data))
                allowed[0]=False
        with self.assertRaisesRegex(ValueError,"SOCKET_ROUTE_CHANGED_BEFORE_TLS_SEND"):
            mod.send_initial_tls(ControlledSender(),tls_client_hello(),
                                 split=True,route_guard=lambda:allowed[0])
        self.assertEqual(sent,[b"\x16"],"SECOND_FRAGMENT_LEAKED_AFTER_ROUTE_DRIFT")

if __name__=="__main__":
    unittest.main(verbosity=2)
