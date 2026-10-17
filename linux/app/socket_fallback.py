#!/usr/bin/env python3
"""Opt-in, per-GUI-session, bounded localhost SOCKS5 fallback for selected sites.

R747: no third-party tpws binary, no Root, no transparent network interception,
no changes to system/browser proxies, DNS, routes or Tailscale. This is NOT
the normal Direct Method Start/Stop/Recovery backend and not global internet.

Only CONNECT/domain/443 to a small static public-site allowlist is allowed.
YouTube-family ClientHello is split in two write() calls after the first byte;
other allowed hosts are passed through intact. TLS is never decrypted;
the client MUST still validate the destination certificate.
"""
from __future__ import annotations

import ipaddress
import pathlib
import re
import select
import socket
import socketserver
import subprocess
import threading
import time
from dataclasses import dataclass

# Deliberately no wildcard goog(le).com or private/LAN traffic.
SEGMENT_SUFFIXES = (
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
    "youtube-nocookie.com",
)
CONTROL_HOSTS = frozenset(("github.com", "api.openai.com", "gemini.google.com"))
MAX_CLIENT_HELLO = 18432
MAX_SESSIONS = 12
MAX_IDLE_SECONDS = 300


@dataclass(frozen=True)
class PhysicalRoute:
    iface: str
    source_ip: str


def current_physical_route() -> PhysicalRoute:
    """Select a unique lowest-metric physical IPv4 route and verify OS policy.

    A connected Wi-Fi and Ethernet often create two default routes. This is
    normal, not an ownership conflict. A tied best metric, a tunnel winning,
    or an effective route different from the selected physical link is unsafe.
    No packets are sent by the ip route get lookup.
    """
    ip_cmd = ("/usr/sbin/ip" if pathlib.Path("/usr/sbin/ip").is_file()
              else "/usr/bin/ip")
    proc = subprocess.run(
        (ip_cmd, "-o", "-4", "route", "show", "default"),
        text=True, capture_output=True, timeout=3, check=False,
    )
    if proc.returncode:
        raise RuntimeError("SOCKET_ROUTE_LOOKUP_FAILED")
    candidates = []
    for line in proc.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        if (fields[0] != "default" or fields.count("dev") != 1 or
                fields.count("src") != 1 or fields.count("metric") > 1):
            raise RuntimeError("SOCKET_PHYSICAL_DEFAULT_ROUTE_UNVERIFIED")
        try:
            iface = fields[fields.index("dev") + 1]
            src = fields[fields.index("src") + 1]
            metric = (int(fields[fields.index("metric") + 1])
                      if "metric" in fields else 0)
            if metric < 0:
                raise ValueError("negative metric")
        except (IndexError, ValueError) as exc:
            raise RuntimeError("SOCKET_PHYSICAL_DEFAULT_ROUTE_UNVERIFIED") from exc
        candidates.append((metric, iface, src))
    if not candidates:
        raise RuntimeError("SOCKET_PHYSICAL_DEFAULT_ROUTE_UNAVAILABLE")
    best_metric = min(m for m, _, _ in candidates)
    winners = [(iface, src) for m, iface, src in candidates if m == best_metric]
    if len(winners) != 1:
        raise RuntimeError("SOCKET_PHYSICAL_DEFAULT_ROUTE_AMBIGUOUS")
    iface, src = winners[0]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", iface):
        raise RuntimeError("SOCKET_BAD_INTERFACE_NAME")
    if iface.startswith(("tailscale", "wg", "tun", "tap", "zt", "warp", "dim")):
        raise RuntimeError("SOCKET_VPN_OR_TUNNEL_AS_DEFAULT_ROUTE")
    try:
        ip = ipaddress.IPv4Address(src)
    except ValueError as exc:
        raise RuntimeError("SOCKET_BAD_PHYSICAL_SOURCE_IPV4") from exc
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise RuntimeError("SOCKET_INVALID_PHYSICAL_IP")

    # Main-table metrics alone are insufficient under policy routing/Tailscale
    # exit nodes. Check a public destination's actual unmarked kernel lookup.
    effective = subprocess.run(
        (ip_cmd, "-4", "route", "get", "1.1.1.1"),
        text=True, capture_output=True, timeout=3, check=False,
    )
    if effective.returncode:
        raise RuntimeError("SOCKET_EFFECTIVE_POLICY_ROUTE_UNAVAILABLE")
    actual = [row.split() for row in effective.stdout.splitlines()
              if "dev" in row.split()]
    if len(actual) != 1:
        raise RuntimeError("SOCKET_EFFECTIVE_POLICY_ROUTE_AMBIGUOUS")
    fields = actual[0]
    try:
        if (fields.count("dev") != 1 or fields.count("src") != 1 or
                fields[fields.index("dev") + 1] != iface or
                fields[fields.index("src") + 1] != str(ip)):
            raise RuntimeError("SOCKET_EFFECTIVE_POLICY_ROUTE_MISMATCH")
    except IndexError as exc:
        raise RuntimeError("SOCKET_EFFECTIVE_POLICY_ROUTE_UNVERIFIED") from exc
    return PhysicalRoute(iface, str(ip))



def verify_target_physical_route(ip: str, route: PhysicalRoute) -> bool:
    """Fail closed on policy routes that steer a specific destination away.

    Checking 1.1.1.1 alone cannot detect Tailscale/VPN split routes to the
    actual resolved target. ip route get DEST from SOURCE ipproto tcp dport
    443 is a read-only kernel lookup, not a mutation or packet transmission.
    """
    try:
        target = ipaddress.IPv4Address(ip)
        if not target.is_global or not isinstance(route, PhysicalRoute):
            return False
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", route.iface) or
                route.iface.startswith(("tailscale", "wg", "tun", "tap", "zt", "warp", "dim"))):
            return False
        source = ipaddress.IPv4Address(route.source_ip)
        if source.is_unspecified or source.is_multicast:
            return False
        command = ("/usr/sbin/ip" if pathlib.Path("/usr/sbin/ip").is_file()
                   else "/usr/bin/ip")
        check = subprocess.run(
            (command, "-o", "-4", "route", "get", str(target), "from",
             str(source), "ipproto", "tcp", "dport", "443"),
            text=True, capture_output=True, timeout=3, check=False,
        )
        if check.returncode != 0:
            return False
        # Linux emits an optional second "cache" row with no "dev".
        candidates = [line.split() for line in check.stdout.splitlines()
                      if "dev" in line.split()]
        if len(candidates) != 1:
            return False
        fields = candidates[0]
        if fields[0] != str(target) or fields.count("dev") != 1:
            return False
        if fields[fields.index("dev") + 1] != route.iface:
            return False
        # With from SOURCE iproute2 may print from SOURCE rather than src.
        sources = [fields[i + 1] for i, token in enumerate(fields[:-1])
                   if token in ("from", "src")]
        return bool(sources) and all(value == str(source) for value in sources)
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return False


def normalize_allowed_host(host: str) -> tuple[str, bool]:
    """(host, split) or fail-closed. A substring of an allowed host is NOT OK."""
    if not isinstance(host, str) or not 1 <= len(host) <= 253:
        raise ValueError("SOCKET_HOST_LENGTH_INVALID")
    try:
        host.encode("ascii", "strict")
    except UnicodeError as exc:
        raise ValueError("SOCKET_HOST_NON_ASCII") from exc
    lower = host.lower()
    if lower != host.strip().lower() or lower.endswith("."):
        raise ValueError("SOCKET_HOST_CANONICALIZATION_REJECTED")
    labels = lower.split(".")
    if (len(labels) < 2 or
            not all(1 <= len(x) <= 63 and
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", x)
                    for x in labels)):
        raise ValueError("SOCKET_HOST_LABELS_INVALID")
    is_video = any(lower == suffix or lower.endswith("." + suffix)
                   for suffix in SEGMENT_SUFFIXES)
    if not is_video and lower not in CONTROL_HOSTS:
        raise ValueError("SOCKET_HOST_NOT_IN_EXPLICIT_ALLOWLIST")
    return lower, is_video


def validate_public_addresses(addresses: list[str]) -> list[str]:
    """DNS rebinding/private-network hard stop, before attempting any TCP."""
    if not addresses or len(addresses) > 32:
        raise ValueError("SOCKET_DNS_NO_BOUNDED_IPV4_RESULTS")
    unique = []
    for raw in addresses:
        try:
            ip = ipaddress.IPv4Address(raw)
        except ValueError as exc:
            raise ValueError("SOCKET_DNS_INVALID_IPV4") from exc
        if (not ip.is_global or ip.is_multicast or ip.is_reserved or
                ip.is_unspecified or ip.is_link_local):
            raise ValueError("SOCKET_DNS_PRIVATE_OR_RESERVED_IPV4_REJECTED")
        if str(ip) not in unique:
            unique.append(str(ip))
    return unique


def resolve_public_ipv4(host: str) -> list[str]:
    answers = socket.getaddrinfo(host, 443, socket.AF_INET,
                                 socket.SOCK_STREAM, socket.IPPROTO_TCP)
    return validate_public_addresses([row[4][0] for row in answers])


def tls_hello_sni(record: bytes) -> str:
    """Parse exactly the initial complete TLS ClientHello record, not TLS keys."""
    if (len(record) < 52 or len(record) > MAX_CLIENT_HELLO or record[0] != 22 or
            record[1] != 3 or record[2] not in (0, 1, 2, 3, 4) or
            int.from_bytes(record[3:5], "big") != len(record) - 5):
        raise ValueError("SOCKET_TLS_RECORD_INVALID")
    body = memoryview(record)[5:]
    if body[0] != 1 or int.from_bytes(body[1:4], "big") > len(body) - 4:
        raise ValueError("SOCKET_TLS_CLIENTHELLO_INCOMPLETE_OR_INVALID")
    # Reject multi-handshake records and fragmented ClientHello instead of
    # altering an unknown stream or forwarding it without user-intended split.
    if int.from_bytes(body[1:4], "big") != len(body) - 4:
        raise ValueError("SOCKET_TLS_CLIENTHELLO_RECORD_NOT_EXCLUSIVE")
    p = 4 + 2 + 32
    def take(size: int) -> bytes:
        nonlocal p
        if size < 0 or p + size > len(body):
            raise ValueError("SOCKET_TLS_HELLO_TRUNCATED")
        raw = bytes(body[p:p + size])
        p += size
        return raw
    take(take(1)[0])
    take(int.from_bytes(take(2), "big"))  # cipher suites
    take(take(1)[0])                       # compression methods
    extensions_len = int.from_bytes(take(2), "big")
    end = p + extensions_len
    if end != len(body):
        raise ValueError("SOCKET_TLS_EXTENSION_LENGTH_INVALID")
    found = None
    while p < end:
        kind = int.from_bytes(take(2), "big")
        length = int.from_bytes(take(2), "big")
        value = take(length)
        if kind != 0:
            continue
        if found is not None or len(value) < 5:
            raise ValueError("SOCKET_TLS_DUPLICATE_OR_BAD_SNI")
        count = int.from_bytes(value[:2], "big")
        if count != len(value) - 2 or value[2] != 0:
            raise ValueError("SOCKET_TLS_SNI_LIST_INVALID")
        n = int.from_bytes(value[3:5], "big")
        if n == 0 or n != len(value) - 5:
            raise ValueError("SOCKET_TLS_SNI_NAME_LENGTH_INVALID")
        try:
            found = value[5:].decode("ascii", "strict")
        except UnicodeError as exc:
            raise ValueError("SOCKET_TLS_SNI_NON_ASCII") from exc
    if found is None:
        raise ValueError("SOCKET_TLS_SNI_REQUIRED")
    return normalize_allowed_host(found)[0]


def send_initial_tls(upstream, record: bytes, *, split: bool) -> None:
    """Only the first TLS record is intentionally segmented; no sleeps."""
    if not record or record[0] != 22:
        raise ValueError("SOCKET_INITIAL_TLS_RECORD_INVALID")
    if split:
        upstream.sendall(record[:1])
        upstream.sendall(record[1:])
    else:
        upstream.sendall(record)


def _read_exact(sock: socket.socket, count: int) -> bytes:
    if not 0 <= count <= MAX_CLIENT_HELLO:
        raise ValueError("SOCKET_FRAME_LENGTH_INVALID")
    output = bytearray()
    while len(output) < count:
        data = sock.recv(count - len(output))
        if not data:
            raise ConnectionError("SOCKET_UNEXPECTED_CLIENT_EOF")
        output.extend(data)
    return bytes(output)


def _reply(client: socket.socket, code: int) -> None:
    # RFC 1928, bind address/port = 0 (no misleading external IP disclosure).
    client.sendall(b"\x05" + bytes([code]) +
                   b"\x00\x01\x00\x00\x00\x00\x00\x00")


def dial_public_ipv4(ip: str, port: int, source_ip: str) -> socket.socket:
    """Connect to a previously validated public address using physical source."""
    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote.settimeout(4)
        remote.bind((source_ip, 0))
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote.connect((ip, port))
        return remote
    except BaseException:
        remote.close()
        raise


def _handle_request(bridge: "LocalSocketFallback", client: socket.socket) -> None:
    client.settimeout(8)
    header = _read_exact(client, 2)
    if header[0] != 5 or not 1 <= header[1] <= 8:
        return
    methods = _read_exact(client, header[1])
    if b"\x00" not in methods:
        client.sendall(b"\x05\xff")
        return
    client.sendall(b"\x05\x00")
    ver, operation, reserved, atyp = _read_exact(client, 4)
    if (ver, operation, reserved, atyp) != (5, 1, 0, 3):
        _reply(client, 7 if operation != 1 else 8)
        return
    hostname_length = _read_exact(client, 1)[0]
    if not 1 <= hostname_length <= 253:
        _reply(client, 8)
        return
    try:
        raw = _read_exact(client, hostname_length).decode("ascii", "strict")
        host, split = normalize_allowed_host(raw)
    except (ValueError, UnicodeError):
        _reply(client, 2)
        return
    port = int.from_bytes(_read_exact(client, 2), "big")
    if port != 443:
        _reply(client, 2)
        return
    try:
        # A new connection must not quietly migrate to another interface,
        # VPN default route or physical source after this GUI session started.
        if bridge._route_getter() != bridge.route:
            raise RuntimeError("SOCKET_PHYSICAL_ROUTE_CHANGED")
        addresses = validate_public_addresses(bridge._resolver(host))
        # Validate every DNS answer before dialing ANY destination. A single
        # VPN-specific route makes this session fail closed, not a fallback.
        if not all(bridge._destination_route_getter(ip, bridge.route) is True
                   for ip in addresses):
            raise RuntimeError("SOCKET_DESTINATION_POLICY_ROUTE_MISMATCH")
    except (OSError, ValueError, RuntimeError):
        _reply(client, 2)
        return
    remote = None
    for ip in addresses:
        if bridge._stopping.is_set():
            return
        try:
            remote = bridge._dialer(ip, port, bridge.route.source_ip)
            break
        except OSError:
            continue
    if remote is None:
        _reply(client, 4)
        return
    bridge._track(remote)
    try:
        _reply(client, 0)
        first = _read_exact(client, 5)
        length = int.from_bytes(first[3:5], "big")
        if length < 48 or length + 5 > MAX_CLIENT_HELLO:
            raise ValueError("SOCKET_TLS_FIRST_RECORD_LENGTH_UNSAFE")
        record = first + _read_exact(client, length)
        if tls_hello_sni(record) != host:
            raise ValueError("SOCKET_TLS_SNI_CONNECT_HOST_MISMATCH")
        send_initial_tls(remote, record, split=split)
        client.settimeout(15)
        remote.settimeout(15)
        last_activity = time.monotonic()
        next_route_check = last_activity + 15
        while not bridge._stopping.is_set():
            now = time.monotonic()
            if now - last_activity > MAX_IDLE_SECONDS:
                return
            if now >= next_route_check:
                if bridge._route_getter() != bridge.route:
                    return
                next_route_check = now + 15
            ready, _, _ = select.select((client, remote), (), (), 0.3)
            for source in ready:
                payload = source.recv(32768)
                if not payload:
                    return
                (remote if source is client else client).sendall(payload)
                last_activity = time.monotonic()
    finally:
        bridge._untrack(remote)
        try:
            remote.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        remote.close()


class _LoopbackServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = MAX_SESSIONS
    allow_reuse_address = False

    def verify_request(self, request, client_address):
        return client_address[0] == "127.0.0.1"


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        bridge = self.server.bridge
        if not bridge._slots.acquire(blocking=False):
            try:
                _reply(self.request, 1)
            except OSError:
                pass
            return
        bridge._track(self.request)
        try:
            _handle_request(bridge, self.request)
        except (OSError, ValueError, ConnectionError, TimeoutError):
            # Never log URL, hostname, DNS, private browsing data, or bytes.
            pass
        finally:
            bridge._untrack(self.request)
            bridge._slots.release()


class LocalSocketFallback:
    """Start only on explicit opt-in; stop on explicit button or GUI close."""
    def __init__(self, *, route_getter=current_physical_route,
                 resolver=resolve_public_ipv4, dialer=dial_public_ipv4,
                 destination_route_getter=verify_target_physical_route):
        self._route_getter = route_getter
        self._resolver = resolver
        self._dialer = dialer
        self._destination_route_getter = destination_route_getter
        self._slots = threading.BoundedSemaphore(MAX_SESSIONS)
        self._sockets: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._server = None
        self._thread = None
        self.route = None

    @property
    def port(self) -> int | None:
        return (self._server.server_address[1] if self._server else None)

    def start(self) -> int:
        if self._server:
            raise RuntimeError("SOCKET_SESSION_ALREADY_RUNNING")
        self.route = self._route_getter()
        if not isinstance(self.route, PhysicalRoute):
            raise RuntimeError("SOCKET_PHYSICAL_ROUTE_UNVERIFIED")
        self._stopping.clear()
        server = _LoopbackServer(("127.0.0.1", 0), _Handler,
                                 bind_and_activate=True)
        if server.server_address[0] != "127.0.0.1" or server.server_address[1] < 1024:
            server.server_close()
            raise RuntimeError("SOCKET_NOT_PRIVATE_DYNAMIC_LOOPBACK_PORT")
        server.bridge = self
        self._server = server
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.1},
                                  name="DIM-Local-Optin-SOCKS",
                                  daemon=True)
        self._thread = thread
        thread.start()
        return self.port

    def _track(self, sock: socket.socket) -> None:
        with self._lock:
            self._sockets.add(sock)

    def _untrack(self, sock: socket.socket) -> None:
        with self._lock:
            self._sockets.discard(sock)

    def stop(self) -> None:
        self._stopping.set()
        server, self._server = self._server, None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        with self._lock:
            sockets = tuple(self._sockets)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None
