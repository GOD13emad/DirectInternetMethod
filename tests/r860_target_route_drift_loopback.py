#!/usr/bin/env python3
"""R860 negative-first live loopback regression for destination-only policy-route drift.

No external network, privilege, installed files, DNS, proxy or VPN modifications.
The negative control was run on the unmodified installed module separately.
"""
import importlib.util
import pathlib
import socket
import ssl
import struct
import sys
import time

base=pathlib.Path(__file__).resolve().parents[1]
source=base/"linux/app/socket_fallback.py"
spec=importlib.util.spec_from_file_location("r860_module_under_test",source)
mod=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=mod
spec.loader.exec_module(mod)

def read_exact(conn,n):
    data=b""
    while len(data)<n:
        part=conn.recv(n-len(data))
        if not part:raise RuntimeError("UNEXPECTED_EOF")
        data+=part
    return data

def hello(host="www.youtube.com"):
    ctx=ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
    tls=ctx.wrap_bio(incoming,outgoing,server_hostname=host)
    try:tls.do_handshake()
    except ssl.SSLWantReadError:pass
    rec=outgoing.read()
    assert rec and rec[0]==22 and rec[5]==1
    return rec

physical=mod.PhysicalRoute("r860-fake","127.0.0.1")
left,right=socket.socketpair()
checks=[]
allowed=[True]
def target(ip,route):
    checks.append((ip,route))
    return allowed[0]
bridge=mod.LocalSocketFallback(
    route_getter=lambda:physical,
    resolver=lambda host:["142.251.151.4"],
    dialer=lambda ip,port,source_ip:left,
    destination_route_getter=target)
client=None
native=time.monotonic
try:
    port=bridge.start()
    client=socket.create_connection(("127.0.0.1",port),timeout=3)
    client.settimeout(4)
    client.sendall(b"\x05\x01\x00")
    assert read_exact(client,2)==b"\x05\x00"
    name=b"www.youtube.com"
    client.sendall(b"\x05\x01\x00\x03"+bytes([len(name)])+name+struct.pack("!H",443))
    assert read_exact(client,10)[1]==0
    record=hello()
    client.sendall(record)
    right.settimeout(4)
    assert read_exact(right,len(record))==record
    right.sendall(b"CONTROL_OK")
    assert read_exact(client,10)==b"CONTROL_OK"
    assert len(checks)>=3,("EXPECTED_PRE_TLS_EGRESS_CHECKS",len(checks))
    allowed[0]=False
    # Advance only the local synthetic timer; no OS clock or actual route.
    mod.time.monotonic=lambda:native()+20
    client.settimeout(2.5)
    try:
        chunk=client.recv(1)
    except socket.timeout:
        raise AssertionError("DANGEROUS_EXISTING_TUNNEL_IGNORED_TARGET_ROUTE_DRIFT")
    assert chunk==b"",("TUNNEL_RELAYED_AFTER_ROUTE_CHANGE",chunk)
    assert len(checks)>=2,("TARGET_NOT_REVALIDATED",len(checks))
    print("PASS_REJECTS_DESTINATION_ROUTE_DRIFT_WITHOUT_DEFAULT_ROUTE_CHANGE checks="+str(len(checks)))
finally:
    mod.time.monotonic=native
    if client:client.close()
    bridge.stop()
    right.close()
