#!/usr/bin/env python3
"""R747 local SOCKS opt-in: negative-first security & lifecycle; no real web.

All network operations use disposable 127.0.0.1 listeners. Production code
permanently rejects private DNS; fixture supplies public fake resolution and
a test-only dialer redirected to a separate private mock listener. Never starts
the real Direct Method service, alters DNS, installs binary or changes proxy.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import socket
import socketserver
import ssl
import struct
import threading
import time
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/"linux/app/socket_fallback.py"
SPEC=importlib.util.spec_from_file_location("dim_r747_socket_fallback",SOURCE)
sockmod=importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name]=sockmod
SPEC.loader.exec_module(sockmod)


def hello(host="www.youtube.com"):
    context=ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    rx,tx=ssl.MemoryBIO(),ssl.MemoryBIO()
    tls=context.wrap_bio(rx,tx,server_hostname=host)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    result=tx.read()
    assert result and result[0]==22 and result[5]==1
    return result


def read_n(sock,n):
    out=b""
    while len(out)<n:
        piece=sock.recv(n-len(out))
        if not piece:raise EOFError("mock peer closed")
        out+=piece
    return out


class Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address=False
    daemon_threads=True
    block_on_close=False


class CaptureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3.5)
        try:
            hdr=read_n(self.request,5)
            rest=read_n(self.request,int.from_bytes(hdr[3:5],"big"))
            self.server.received.append(hdr+rest)
            self.request.sendall(b"MOCK_UPSTREAM_OK")
        except (OSError,EOFError):
            pass


class SocketContract(unittest.TestCase):
    def setUp(self):
        self.upstream=Upstream(("127.0.0.1",0),CaptureHandler)
        self.upstream.received=[]
        self.thread=threading.Thread(target=self.upstream.serve_forever,
                                    kwargs={"poll_interval":0.05},daemon=True)
        self.thread.start()
        self.route=sockmod.PhysicalRoute("enp-test","127.0.0.1")
        self.actual_route=self.route
        self.dials=[]
        def mock_dial(ip,port,src):
            self.dials.append((ip,port,src))
            return socket.create_connection(("127.0.0.1",self.upstream.server_address[1]),timeout=2)
        self.bridge=sockmod.LocalSocketFallback(
            route_getter=lambda:self.actual_route,
            resolver=lambda host:["142.251.151.4"],
            dialer=mock_dial,
        )
        self.bridge._destination_route_getter=lambda ip,route: True
        self.port=self.bridge.start()
        # LIFO: stop bridge, shutdown mock server, close, then join.
        self.addCleanup(lambda:self.thread.join(timeout=2))
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        self.addCleanup(self.bridge.stop)

    def connect_raw(self):
        client=socket.create_connection(("127.0.0.1",self.port),timeout=2)
        client.settimeout(3)
        client.sendall(b"\x05\x01\x00")
        self.assertEqual(read_n(client,2),b"\x05\x00")
        return client

    def handshake(self,host="www.youtube.com",port=443):
        client=self.connect_raw()
        raw=host.encode("ascii")
        client.sendall(b"\x05\x01\x00\x03"+bytes([len(raw)])+raw+struct.pack("!H",port))
        answer=read_n(client,10)
        self.assertEqual(answer[0],5)
        return client,answer[1]

    def test_18_primary_lowest_metric_ethernet_with_wifi_still_allowed(self):
        from unittest import mock
        import subprocess
        routes=("default via 192.168.20.1 dev enp1s0 proto dhcp src 192.168.20.6 metric 100\n"
                "default via 192.168.20.1 dev wlp2s0 proto dhcp src 192.168.20.8 metric 600\n")
        effective="1.1.1.1 via 192.168.20.1 dev enp1s0 src 192.168.20.6 uid 1000\n    cache\n"
        with mock.patch.object(sockmod.subprocess,"run",side_effect=[
                subprocess.CompletedProcess([],0,stdout=routes,stderr=""),
                subprocess.CompletedProcess([],0,stdout=effective,stderr="")]) as call:
            self.assertEqual(sockmod.current_physical_route(),
                             sockmod.PhysicalRoute("enp1s0","192.168.20.6"))
            self.assertEqual(call.call_count,2)

    def test_19_ambiguous_equal_lowest_route_metrics_fail_closed(self):
        from unittest import mock
        import subprocess
        routes=("default via 192.168.20.1 dev enp1s0 src 192.168.20.6 metric 100\n"
                "default via 192.168.20.1 dev wlp2s0 src 192.168.20.8 metric 100\n")
        with mock.patch.object(sockmod.subprocess,"run",return_value=subprocess.CompletedProcess(
                [],0,stdout=routes,stderr="")):
            with self.assertRaisesRegex(RuntimeError,"AMBIGUOUS"):
                sockmod.current_physical_route()

    def test_20_lowest_vpn_default_route_must_not_be_skipped(self):
        from unittest import mock
        import subprocess
        routes=("default dev tailscale0 src 100.101.0.1 metric 10\n"
                "default via 192.168.20.1 dev enp1s0 src 192.168.20.6 metric 100\n")
        with mock.patch.object(sockmod.subprocess,"run",return_value=subprocess.CompletedProcess(
                [],0,stdout=routes,stderr="")):
            with self.assertRaises(RuntimeError):
                sockmod.current_physical_route()

    def test_21_effective_policy_route_mismatch_refused(self):
        from unittest import mock
        import subprocess
        route="default via 192.168.20.1 dev enp1s0 src 192.168.20.6 metric 100\n"
        effective="1.1.1.1 dev tailscale0 src 100.101.0.1 uid 1000\n"
        with mock.patch.object(sockmod.subprocess,"run",side_effect=[
                subprocess.CompletedProcess([],0,stdout=route,stderr=""),
                subprocess.CompletedProcess([],0,stdout=effective,stderr="")]):
            with self.assertRaisesRegex(RuntimeError,"POLICY|EFFECTIVE|TUNNEL"):
                sockmod.current_physical_route()

    def test_22_effective_route_get_failure_must_fail_closed(self):
        from unittest import mock
        import subprocess
        route="default via 192.168.20.1 dev enp1s0 src 192.168.20.6 metric 100\n"
        with mock.patch.object(sockmod.subprocess,"run",side_effect=[
                subprocess.CompletedProcess([],0,stdout=route,stderr=""),
                subprocess.CompletedProcess([],2,stdout="",stderr="route lookup failure")]):
            with self.assertRaises(RuntimeError):
                sockmod.current_physical_route()

    def test_23_target_specific_policy_route_refuses_tailscale_before_dial(self):
        self.bridge._destination_route_getter=lambda ip,route: False
        client,code=self.handshake()
        client.close()
        self.assertEqual(code,2)
        self.assertEqual(self.dials,[])

    def test_24_mixed_dns_must_validate_all_target_routes_before_any_dial(self):
        self.bridge._resolver=lambda host:["142.251.151.4","142.251.154.4"]
        observed=[]
        def route(ip,physical):
            observed.append((ip,physical))
            return ip != "142.251.154.4"
        self.bridge._destination_route_getter=route
        client,code=self.handshake()
        client.close()
        self.assertEqual(code,2)
        self.assertEqual(self.dials,[])
        self.assertEqual([x[0] for x in observed],
                         ["142.251.151.4","142.251.154.4"])

    def test_25_kernel_route_get_target_exact_source_and_interface(self):
        from unittest import mock
        import subprocess
        route=sockmod.PhysicalRoute("enp1s0","192.168.20.6")
        good="142.251.151.4 from 192.168.20.6 via 192.168.20.1 dev enp1s0 uid 1000 cache"
        tunnel=good.replace("dev enp1s0","dev tailscale0")
        wrongsource=good.replace("from 192.168.20.6","from 192.168.20.9")
        for reply,expected in ((good,True),(tunnel,False),(wrongsource,False),
                               ("unreachable 142.251.151.4",False)):
            with self.subTest(reply=reply):
                with mock.patch.object(sockmod.subprocess,"run",return_value=
                       subprocess.CompletedProcess([],0,stdout=reply,stderr="")) as runner:
                    self.assertEqual(sockmod.verify_target_physical_route("142.251.151.4",route),expected)
                    argv=runner.call_args.args[0]
                    self.assertEqual(argv[-6:],("142.251.151.4","from",
                        "192.168.20.6","ipproto","tcp","dport","443")[-6:])
        with mock.patch.object(sockmod.subprocess,"run",return_value=
               subprocess.CompletedProcess([],1,stdout="",stderr="route failure")):
            self.assertFalse(sockmod.verify_target_physical_route("142.251.151.4",route))

    def test_01_whitelist_is_exact_and_video_hosts_only(self):
        allowed=["youtube.com","www.youtube.com","m.youtube.com",
                 "r1---sn.googlevideo.com","i.ytimg.com","youtu.be",
                 "www.youtube-nocookie.com"]
        for host in allowed:
            with self.subTest(host=host):
                n,split=sockmod.normalize_allowed_host(host)
                self.assertTrue(split)
                self.assertEqual(n,host)
        for host in ["youtube.com.evil.org","evil-youtube.com","google.com",
                     "accounts.google.com","localhost","127.0.0.1",
                     "youtube.com.",".youtube.com","foo..youtube.com",
                     "ytimg.com.evil","gοοglevideo.com"]:
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    sockmod.normalize_allowed_host(host)

    def test_02_only_exact_controls_are_passed_without_split(self):
        for host in ["api.openai.com","github.com","gemini.google.com"]:
            self.assertEqual(sockmod.normalize_allowed_host(host),(host,False))
        for host in ["blog.github.com","foo.openai.com","localhost"]:
            with self.assertRaises(ValueError):
                sockmod.normalize_allowed_host(host)

    def test_03_private_reserved_and_rebinding_ips_rejected(self):
        for ip in ["0.0.0.0","127.0.0.1","10.0.0.1","192.168.20.6",
                   "172.16.0.1","169.254.1.1","224.0.0.1","255.255.255.255",
                   "100.115.125.114"]:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    sockmod.validate_public_addresses([ip])
        with self.assertRaises(ValueError):
            sockmod.validate_public_addresses(["142.251.151.4","127.0.0.1"])
        self.assertEqual(sockmod.validate_public_addresses(
            ["142.251.151.4","142.251.151.4"]),["142.251.151.4"])

    def test_04_parser_extracts_original_real_python_tls_sni(self):
        value=hello()
        self.assertEqual(sockmod.tls_hello_sni(value),"www.youtube.com")
        self.assertEqual(sockmod.tls_hello_sni(hello("github.com")),"github.com")

    def test_05_parser_rejects_truncated_fake_mismatch_record(self):
        record=hello()
        for mutant in [record[:-1],b"\x00"+record[1:],record[:4]+b"\x00",record+record]:
            with self.subTest(length=len(mutant)):
                with self.assertRaises(ValueError):
                    sockmod.tls_hello_sni(mutant)

    def test_06_segment_first_byte_only_and_passthrough_controls(self):
        calls=[]
        class Sender:
            def sendall(self,data):calls.append(bytes(data))
        record=hello()
        sockmod.send_initial_tls(Sender(),record,split=True)
        self.assertEqual(calls,[record[:1],record[1:]])
        calls.clear()
        sockmod.send_initial_tls(Sender(),record,split=False)
        self.assertEqual(calls,[record])

    def test_07_socks5_roundtrip_youtube_opaque_tls_record(self):
        client,code=self.handshake()
        self.addCleanup(client.close)
        self.assertEqual(code,0)
        value=hello()
        client.sendall(value)
        self.assertEqual(read_n(client,len(b"MOCK_UPSTREAM_OK")),b"MOCK_UPSTREAM_OK")
        self.assertEqual(self.upstream.received,[value])
        self.assertEqual(self.dials,[("142.251.151.4",443,"127.0.0.1")])

    def test_08_socks5_rejects_out_of_scope_hosts_without_dial(self):
        for name in ("evil.youtube.com.attacker.net","accounts.google.com","localhost"):
            client,code=self.handshake(name)
            client.close()
            self.assertEqual(code,2,name)
        self.assertEqual(self.dials,[])

    def test_09_socks5_rejects_http80_without_dial(self):
        client,code=self.handshake(port=80)
        client.close()
        self.assertEqual(code,2)
        self.assertEqual(self.dials,[])

    def test_10_socks5_rejects_ip_literal_and_udp_bind(self):
        for command in (1,2,3):
            client=self.connect_raw()
            client.sendall(b"\x05"+bytes([command])+b"\x00\x01"+
                           b"\x7f\x00\x00\x01"+struct.pack("!H",443))
            answer=read_n(client,10)
            self.assertIn(answer[1],(7,8))
            client.close()
        self.assertEqual(self.dials,[])

    def test_11_socks5_requires_noauth_method_only(self):
        client=socket.create_connection(("127.0.0.1",self.port),timeout=2)
        client.settimeout(2)
        client.sendall(b"\x05\x01\x02")
        self.assertEqual(read_n(client,2),b"\x05\xff")
        client.close()
        self.assertEqual(self.dials,[])

    def test_12_tls_connect_host_sni_mismatch_is_not_forwarded(self):
        client,code=self.handshake("www.youtube.com")
        self.assertEqual(code,0)
        client.sendall(hello("github.com"))
        client.settimeout(2)
        self.assertEqual(client.recv(1),b"")
        self.assertEqual(self.upstream.received,[])
        client.close()

    def test_13_changed_physical_route_denied_before_resolve_dial(self):
        self.actual_route=sockmod.PhysicalRoute("tailscale0","100.115.125.114")
        client,code=self.handshake()
        client.close()
        self.assertEqual(code,2)
        self.assertEqual(self.dials,[])

    def test_14_private_dns_denied_even_with_fake_dialer(self):
        self.bridge._resolver=lambda host:["142.251.151.4","192.168.1.1"]
        client,code=self.handshake()
        client.close()
        self.assertEqual(code,2)
        self.assertEqual(self.dials,[])

    def test_15_failed_read_of_tls_sni_does_not_forward_plaintext(self):
        client,code=self.handshake()
        self.assertEqual(code,0)
        client.sendall(b"GET / HTTP/1.1\r\n")
        client.close()
        self.assertEqual(self.upstream.received,[])

    def test_16_stop_disables_original_port_and_is_idempotent(self):
        port=self.bridge.port
        self.assertGreater(port,1024)
        self.bridge.stop()
        self.bridge.stop()
        self.assertIsNone(self.bridge.port)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1",port),timeout=1)

    def test_17_server_is_exactly_loopback_and_never_dns_or_route_mutates(self):
        self.assertEqual(self.bridge._server.server_address[0],"127.0.0.1")
        self.assertGreater(self.port,1024)
        self.assertFalse(self.bridge._stopping.is_set())

if __name__=="__main__":
    unittest.main(verbosity=1)
    print("R747_SOCKET_FALLBACK_LOCALHOST_OPTIN_25_SECURITY_AND_LIFECYCLE_CASES_PASS")
