"""Restore IPv6 PF TCP destinations and relay them to loopback Mihomo SOCKS5."""

from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import threading

from darwin_pf import managed_rules
from darwin_udp import bind, encode_address, lookup, read_exact, socks_authenticate


BUFFER_SIZE = 65536


def socks_connect(server, target, credentials):
    outbound = socket.create_connection(server, timeout=4)
    try:
        socks_authenticate(outbound, credentials)
        outbound.sendall(b'\x05\x01\x00' + encode_address(target))
        reply = read_exact(outbound, 4)
        if reply[:3] != b'\x05\x00\x00':
            raise RuntimeError(f'SOCKS5 CONNECT failed: {reply.hex()}')
        size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            size = read_exact(outbound, 1)[0]
        if size is None:
            raise RuntimeError('Invalid SOCKS5 CONNECT reply address')
        read_exact(outbound, size + 2)
        return outbound
    except BaseException:
        outbound.close()
        raise


def pump(left, right, stopping):
    peers = {left: right, right: left}
    buffers = {left: bytearray(), right: bytearray()}
    eof, shutdown = set(), set()
    for channel in peers:
        channel.setblocking(False)
    while not stopping.is_set() and (len(eof) != 2 or any(buffers.values())):
        readers = [channel for channel in peers if channel not in eof and len(buffers[peers[channel]]) < BUFFER_SIZE]
        writers = [channel for channel, pending in buffers.items() if pending]
        poll = select.poll()
        for channel in readers:
            poll.register(channel, select.POLLIN)
        for channel in writers:
            events = select.POLLOUT | (select.POLLIN if channel in readers else 0)
            poll.register(channel, events)
        ready = dict(poll.poll(200))
        for channel in readers:
            if not ready.get(channel.fileno(), 0) & (select.POLLIN | select.POLLHUP | select.POLLERR):
                continue
            pending = buffers[peers[channel]]
            try:
                data = channel.recv(BUFFER_SIZE - len(pending))
            except BlockingIOError:
                continue
            if data:
                pending.extend(data)
            else:
                eof.add(channel)
        for channel in writers:
            if not ready.get(channel.fileno(), 0) & (select.POLLOUT | select.POLLHUP | select.POLLERR):
                continue
            try:
                count = channel.send(buffers[channel])
            except BlockingIOError:
                continue
            del buffers[channel][:count]
        for channel in eof:
            other = peers[channel]
            if other not in shutdown and not buffers[other]:
                other.shutdown(socket.SHUT_WR)
                shutdown.add(other)


class Relay:
    def __init__(self, fd, plan, stopping):
        self.fd = fd
        self.stopping = stopping
        self.targets = tuple(ipaddress.IPv6Network(item) for item in plan['targets'])
        self.ports = set(plan['ports'])
        self.proxy = ('127.0.0.1', plan['proxy-port'])
        self.credentials = plan.get('credentials')
        self.capacity = threading.BoundedSemaphore(128)

    def accept(self, listener, sources):
        client, peer = listener.accept()
        if not any(ipaddress.IPv6Address(peer[0]) in network for network in sources) or not self.capacity.acquire(False):
            client.close()
            return
        worker = threading.Thread(target=self.handle, args=(client, peer), daemon=True)
        worker.start()

    def handle(self, client, peer):
        try:
            with client:
                target = lookup(self.fd, peer, client.getsockname(), socket.IPPROTO_TCP)
                address = ipaddress.IPv6Address(target[0])
                if not any(address in network for network in self.targets) or target[1] not in self.ports:
                    return
                with socks_connect(self.proxy, target, self.credentials) as upstream:
                    print(f'IPv6 TCP restored [{target[0]}]:{target[1]}', file=sys.stderr, flush=True)
                    pump(client, upstream, self.stopping)
        except (OSError, RuntimeError, ValueError) as error:
            if not self.stopping.is_set():
                print(f'IPv6 TCP relay: {error}', file=sys.stderr, flush=True)
        finally:
            self.capacity.release()


def listen_for_rules(plan, stack):
    rdr, routing, sources = [], [], {}
    service = '{ ' + ', '.join(plan['targets']) + ' } port { ' + ', '.join(map(str, plan['ports'])) + ' }'
    for selector in plan['selectors']:
        listener = stack.enter_context(bind((selector['listen'], 0), socket.SOCK_STREAM))
        listener.listen(128)
        sources[listener] = tuple(ipaddress.IPv6Network(item) for item in selector['clients'])
        source, interface = selector['source'], selector['interface']
        device = 'lo0' if selector['direction'] == 'out' else interface
        rdr.append(f'rdr pass on {device} inet6 proto tcp from {source} to {service} '
                   f'-> {listener.getsockname()[0]} port {listener.getsockname()[1]}')
        if selector['direction'] == 'out':
            routing.append(f'pass out quick on {interface} route-to (lo0 ::1) inet6 proto tcp '
                           f'from {source} to {service} user {selector["uid"]} no state')
    return sources, '\n'.join([*rdr, plan['ipv4-rules'].strip(), *routing, *plan.get('udp-rules', [])]) + '\n'


def main(mount, plan_path, core_pid, core_config):
    plan = json.loads(Path(plan_path).read_text())
    stopping = threading.Event()
    for name in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(name, lambda *_: stopping.set())
    with ExitStack() as stack:
        listeners, rules = listen_for_rules(plan, stack)
        fd = os.open('/dev/pf', os.O_RDONLY)
        stack.callback(os.close, fd)
        relay = Relay(fd, plan, stopping)
        rules_path = Path(plan_path).with_suffix('.pf')
        rules_path.write_text(rules)
        with managed_rules(mount, rules_path, core_pid, core_config) as worker:
            print('PASS project filter and rdr calls mounted. IPv6 TCP relay ready', flush=True)
            try:
                while not stopping.is_set():
                    ready, _, _ = select.select([sys.stdin, *listeners], [], [], 0.2)
                    if sys.stdin in ready:
                        break
                    if worker.poll() is not None:
                        raise RuntimeError('IPv6 TCP PF worker exited')
                    for listener in ready:
                        relay.accept(listener, listeners[listener])
            finally:
                stopping.set()


if __name__ == '__main__':
    try:
        if os.geteuid() != 0 or len(sys.argv) != 5:
            raise RuntimeError('IPv6 TCP relay requires root and the PF helper, plan and owned core identity')
        main(*sys.argv[1:])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'IPv6 TCP relay: {error}', file=sys.stderr)
        sys.exit(1)
