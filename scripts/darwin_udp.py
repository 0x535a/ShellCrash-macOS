"""UDP handoff between PF, an Ethernet socket and Mihomo's SOCKS5 listener."""

from dataclasses import dataclass, field
import errno
import fcntl
import ipaddress
import selectors
import socket
import struct
import subprocess
import threading
import time
from typing import Optional

from darwin_pf import ANCHOR, PFCTL

DIOCNATLOOK = 0xC0544417
PF_OUT = 2
PF_EXTFILTER_APD = 1
MAX_FLOWS = 1024


def lookup(fd, peer, local, protocol):
    src, dst = (ipaddress.ip_address(value[0]) for value in (peer, local))
    family = socket.AF_INET if src.version == 4 else socket.AF_INET6
    query = bytearray(84)
    query[:len(src.packed)] = src.packed
    query[16:16 + len(dst.packed)] = dst.packed
    struct.pack_into("!H2xH", query, 64, peer[1], local[1])
    variant = PF_EXTFILTER_APD if protocol == socket.IPPROTO_UDP else 0
    struct.pack_into("4B", query, 80, family, protocol, variant, PF_OUT)
    fcntl.ioctl(fd, DIOCNATLOOK, query, True)
    restored = str(ipaddress.ip_address(bytes(query[48:48 + len(dst.packed)])))
    return restored, struct.unpack_from("!H", query, 76)[0]


def bind(address, kind):
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    sock = socket.socket(family, kind)
    sock.settimeout(2)
    try:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(address)
    except BaseException:
        sock.close()
        raise
    return sock


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("stream closed early")
        data.extend(chunk)
    return bytes(data)


def encode_address(address):
    host = ipaddress.ip_address(address[0])
    return bytes([1 if host.version == 4 else 4]) + host.packed + struct.pack("!H", address[1])


def decode_address(data):
    size = {1: 4, 4: 16}.get(data[0]) if data else None
    if size is None or len(data) < 3 + size:
        raise ValueError('invalid SOCKS5 UDP address')
    host = str(ipaddress.ip_address(data[1:1 + size]))
    return (host, struct.unpack_from("!H", data, 1 + size)[0]), 3 + size


def socks_authenticate(control, credentials):
    control.sendall(b'\x05\x02\x00\x02' if credentials else b'\x05\x01\x00')
    selection = read_exact(control, 2)
    if selection == b'\x05\x00':
        return
    if selection != b'\x05\x02' or not credentials:
        raise RuntimeError('SOCKS5 authentication method rejected')
    user, password = (field.encode('utf-8') for field in credentials)
    if not (1 <= len(user) <= 255 and 1 <= len(password) <= 255):
        raise ValueError('Invalid SOCKS5 credential length')
    control.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
    if read_exact(control, 2) != b'\x01\x00':
        raise RuntimeError('SOCKS5 credentials rejected')


class Association:
    def __init__(self, proxy, listener, peer, target, credentials=None):
        self.listener, self.peer, self.target = listener, peer, target
        self.activity = time.monotonic()
        self.socket = bind(("127.0.0.1", 0), socket.SOCK_DGRAM)
        try:
            self.control = socket.create_connection(proxy, timeout=2)
            try:
                socks_authenticate(self.control, credentials)
                self.control.sendall(b"\x05\x03\x00" + encode_address(self.socket.getsockname()))
                reply = read_exact(self.control, 4)
                if reply[:3] != b"\x05\x00\x00" or reply[3] != 1:
                    raise RuntimeError(f"SOCKS5 UDP ASSOCIATE failed: {reply.hex()}")
                relay, _ = decode_address(reply[3:] + read_exact(self.control, 6))
                if relay[0] == "0.0.0.0":
                    relay = proxy[0], relay[1]
                if not ipaddress.ip_address(relay[0]).is_loopback:
                    raise RuntimeError('SOCKS5 UDP relay must be on loopback')
                self.socket.connect(relay)
            except BaseException:
                self.control.close()
                raise
        except BaseException:
            self.socket.close()
            raise

    def send(self, data):
        self.socket.send(b"\x00\x00\x00" + encode_address(self.target) + data)
        self.activity = time.monotonic()

    def read(self):
        data = self.socket.recv(65535)
        if data[:3] != b"\x00\x00\x00":
            return None
        try:
            reply, size = decode_address(data[3:])
        except ValueError:
            return None
        if reply == self.target:
            self.activity = time.monotonic()
            return data[3 + size:]
        return None

    def receive(self):
        payload = self.read()
        if payload is not None:
            self.listener.sendto(payload, self.peer)
        return payload is not None

    def close(self):
        self.control.close()
        self.socket.close()


def udp_endpoints(frame):
    if (len(frame) >= 62 and frame[12:14] == b'\x86\xdd' and frame[14] >> 4 == 6
            and frame[20] == socket.IPPROTO_UDP):
        source = socket.inet_ntop(socket.AF_INET6, frame[22:38])
        target = socket.inet_ntop(socket.AF_INET6, frame[38:54])
        source_port, target_port = struct.unpack_from('!HH', frame, 54)
        return (source, source_port), (target, target_port)
    if (len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[14] >> 4 != 4
            or frame[23] != socket.IPPROTO_UDP):
        return None
    offset = 14 + (frame[14] & 15) * 4
    if offset < 34 or offset + 8 > len(frame) or struct.unpack_from('!H', frame, 20)[0] & 0x3fff:
        return None
    source, target = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
    source_port, target_port = struct.unpack_from('!HH', frame, offset)
    return (source, source_port), (target, target_port)


@dataclass
class Slot:
    listener: socket.socket
    target: Optional[tuple] = None
    activity: float = 0
    flows: dict = field(default_factory=dict)
    sessions: dict = field(default_factory=dict)

    @property
    def local(self):
        return self.listener.getsockname()


class Allocator:
    def __init__(self, channel, slots, proxy, fd, clients, targets, ports, intake, source_filter, base_rules,
                 credentials=None):
        self.channel = channel
        self.slots = slots
        self.family_slots = {
            version: [slot for slot in slots if slot.listener.family == family]
            for version, family in ((4, socket.AF_INET), (6, socket.AF_INET6))
        }
        self.proxy = proxy
        self.fd = fd
        self.clients = tuple(ipaddress.ip_network(item) for item in clients)
        self.targets = tuple(ipaddress.ip_network(item) for item in targets)
        self.ports = ports if isinstance(ports, dict) else {4: ports, 6: ports}
        self.credentials = credentials
        self.intake = intake
        self.sources = source_filter if isinstance(source_filter, dict) else {4: source_filter, 6: source_filter}
        self.base_rules = base_rules
        self.selector = selectors.DefaultSelector()
        self.selector.register(channel, selectors.EVENT_READ, self.capture)
        for slot in slots:
            self.selector.register(slot.listener, selectors.EVENT_READ, lambda selected=slot: self.from_client(selected))
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.stopping = threading.Event()
        self.error = None
        self.reuses = 0
        self.exhausted = 0
        self.stale = 0
        self.captured = self.reinjected = self.relayed = self.replied = 0
        self.disconnected = []

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stopping.set()
        self.thread.join(timeout=6)
        if self.thread.is_alive():
            raise RuntimeError('UDP allocator did not stop')

    def run(self):
        try:
            while not self.stopping.is_set():
                for event, _ in self.selector.select(timeout=0.1):
                    if event.fileobj.fileno() >= 0:
                        event.data()
                for slot, key, session in self.disconnected:
                    if slot.sessions.get(key) is session:
                        self.close_session(slot, key)
                self.disconnected.clear()
        except Exception as error:
            self.error = error
        finally:
            for slot in self.slots:
                self.clear_slot(slot)
            self.selector.close()

    def clear_slot(self, slot):
        for key in list(slot.sessions):
            self.close_session(slot, key)
        slot.flows.clear()
        # Keep the reserved socket, but never carry an old queued datagram into a new mapping.
        while True:
            try:
                slot.listener.recvfrom(65535)
            except BlockingIOError:
                break

    def close_session(self, slot, key):
        session = slot.sessions.pop(key)
        self.selector.unregister(session.socket)
        self.selector.unregister(session.control)
        session.close()

    def expired(self, slot):
        if time.monotonic() - slot.activity < 1:
            return False
        for peer in slot.flows:
            try:
                lookup(self.fd, peer, slot.local, socket.IPPROTO_UDP)
                return False
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
        return True

    def pf_target(self, slot, peer):
        try:
            return lookup(self.fd, peer, slot.local, socket.IPPROTO_UDP)
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
            return None

    def admits_flow(self, selected, peer):
        if peer in selected.flows or sum(len(slot.flows) for slot in self.slots) < MAX_FLOWS:
            return True

        cutoff = time.monotonic() - 1
        for slot in self.slots:
            for existing, seen in list(slot.flows.items()):
                if seen < cutoff and self.pf_target(slot, existing) is None:
                    if existing in slot.sessions:
                        self.close_session(slot, existing)
                    del slot.flows[existing]
        return sum(len(slot.flows) for slot in self.slots) < MAX_FLOWS

    def assign(self, target):
        candidates = self.family_slots[ipaddress.ip_address(target[0]).version]
        slot = next((item for item in candidates if item.target == target), None)
        if slot:
            return slot
        slot = next((item for item in candidates if not item.target), None)
        if not slot:
            slot = next((item for item in candidates if self.expired(item)), None)
        if not slot:
            return None
        old = slot.target
        self.clear_slot(slot)
        rules = []
        for item in self.slots:
            endpoint = target if item is slot else item.target
            if endpoint:
                address, port = endpoint
                listener, translated_port = item.local[:2]
                version = ipaddress.ip_address(address).version
                family = 'inet6' if version == 6 else 'inet'
                rules.append(f'rdr on {self.intake} {family} proto udp from {self.sources[version]} '
                             f'to {address} port {port} -> {listener} port {translated_port}')
        # Replace only the owned child ruleset in one PF transaction. Live translations keep
        # their PF states while a fresh target gets its own unprivileged listener port.
        subprocess.run([PFCTL, '-q', '-a', ANCHOR, '-f', '-'],
                       input='\n'.join(rules) + '\n' + self.base_rules, text=True,
                       check=True, capture_output=True, timeout=2)
        slot.target = target
        if old:
            self.reuses += 1
            print(f'RECYCLE {slot.local}: {old} -> {target}', flush=True)
        return slot

    def capture(self):
        size = struct.unpack('!I', read_exact(self.channel, 4))[0]
        if not 14 <= size <= 65536:
            raise ValueError(f'invalid isolated Ethernet frame length {size}')
        frame = read_exact(self.channel, size)
        endpoints = udp_endpoints(frame)
        if not endpoints:
            return
        peer, (address, port) = endpoints
        source_ip, target_ip = ipaddress.ip_address(peer[0]), ipaddress.ip_address(address)
        if (not any(source_ip in network for network in self.clients)
                or not any(target_ip in network for network in self.targets)
                or port not in self.ports.get(target_ip.version, ())):
            return
        self.captured += 1
        slot = self.assign((address, port))
        if not slot or not self.admits_flow(slot, peer):
            self.exhausted += 1
            return
        slot.activity = time.monotonic()
        slot.flows[peer] = slot.activity
        # Return the same IP packet on the feth peer, reversing only the Ethernet endpoints.
        self.channel.sendall(struct.pack('!I', size) + frame[6:12] + frame[:6] + frame[12:])
        self.reinjected += 1

    def from_client(self, slot):
        try:
            payload, peer = slot.listener.recvfrom(65535)
        except BlockingIOError:
            return
        peer = peer[:2]
        if peer not in slot.flows:
            return
        target = self.pf_target(slot, peer)
        if target is None:
            self.stale += 1
            return
        if target != slot.target:
            raise RuntimeError('PF original destination does not match the UDP listener allocation')
        key = peer
        if key not in slot.sessions:
            session = Association(self.proxy, slot.listener, peer, target, self.credentials)
            slot.sessions[key] = session
            self.selector.register(session.socket, selectors.EVENT_READ, lambda: self.reply(slot, session))
            self.selector.register(session.control, selectors.EVENT_READ, lambda: self.disconnected.append((slot, key, session)))
        slot.sessions[key].send(payload)
        self.relayed += 1

    def reply(self, slot, session):
        payload = session.read()
        if payload is None:
            return
        if self.pf_target(slot, session.peer) != session.target:
            # Never let an expired reply leave carrying the private listener address.
            self.stale += 1
            return
        session.listener.sendto(payload, session.peer)
        self.replied += 1
