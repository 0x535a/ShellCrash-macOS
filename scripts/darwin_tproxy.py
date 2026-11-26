"""Own the Darwin PF UDP link and run the shared allocator under the PF lease."""

from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import subprocess
import sys
import threading
import time

from darwin_pf import ABSENT, managed_rules, report, run
from darwin_tcp import Relay, listen_for_rules
from darwin_udp import Allocator, Slot, bind


IFCONFIG = '/sbin/ifconfig'
ARP = '/usr/sbin/arp'
NDP = '/usr/sbin/ndp'
LINK_LOCAL = 'fe80::f0ce'


def interface_mac(name):
    output = run(IFCONFIG, name).stdout
    match = re.search(r'\bether ([0-9a-f:]+)', output)
    if not match:
        raise RuntimeError(f'missing Ethernet address on {name}')
    return match[1]


def destroy_link(name, mac):
    result = run(IFCONFIG, name, check=False)
    if result.returncode == 0 and f'ether {mac}' in result.stdout:
        run(IFCONFIG, name, 'destroy')


def create_link(stack):
    name = run(IFCONFIG, 'feth', 'create').stdout.strip()
    old_mac = interface_mac(name)
    stack.callback(destroy_link, name, old_mac)
    mac = '02:' + ':'.join(f'{byte:02x}' for byte in secrets.token_bytes(5))
    stack.callback(destroy_link, name, mac)
    run(IFCONFIG, name, 'ether', mac)
    return name, mac


def available(address):
    family = '-inet6' if ':' in address else '-inet'
    result = run('/sbin/route', '-n', 'get', family, address, check=False)
    flags = re.search(r'flags: <([^>]+)>', result.stdout)
    if result.returncode == 0 and (not flags or 'GATEWAY' not in flags[1].split(',')):
        raise RuntimeError(f'Tproxy infrastructure address {address} is already routed directly')


def link_owner(mount, plan_path):
    # This independent process owns all interface mutations and lives until its stdin closes.
    families = json.loads(Path(plan_path).read_text())['families']
    with ExitStack() as stack:
        intake, _ = create_link(stack)
        peer, peer_mac = create_link(stack)
        run(IFCONFIG, intake, 'peer', peer)
        run(IFCONFIG, intake, 'up')
        run(IFCONFIG, peer, 'up')
        gateways = {}
        if '4' in families:
            subnet = ipaddress.IPv4Network(families['4']['subnet'])
            alias = families['4']['alias']
            address, gateway = map(str, subnet.hosts())
            for candidate in (address, gateway, alias):
                available(candidate)
            run(IFCONFIG, intake, 'inet', address, 'netmask', str(subnet.netmask))
            run(IFCONFIG, intake, 'inet', alias, 'netmask', '255.255.255.255', 'alias')
            run(ARP, '-s', gateway, peer_mac, 'ifscope', intake)
            stack.callback(run, ARP, '-d', gateway, 'ifscope', intake, check=False)
            gateways['4'] = gateway
        if '6' in families:
            alias = families['6']['link-address']
            available(alias)
            run(IFCONFIG, intake, 'inet6', alias, 'prefixlen', '128', 'alias')
            deadline = time.monotonic() + 5
            while 'tentative' in run(IFCONFIG, intake).stdout:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Tproxy IPv6 link did not finish duplicate-address detection')
                time.sleep(0.2)
            scoped = f'{LINK_LOCAL}%{intake}'
            run(NDP, '-s', scoped, peer_mac)
            stack.callback(run, NDP, '-d', scoped, check=False)
            gateways['6'] = LINK_LOCAL
        print(json.dumps({'intake': intake, 'peer': peer, 'gateways': gateways}), flush=True)
        sys.stdin.buffer.read()

        # On a killed consumer, the PF watchdog is recovering independently from the same EOF.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if run(mount, 'main', 'status', check=False).stdout == ABSENT:
                break
            time.sleep(0.1)


def close_child(process, timeout=10):
    if process.stdin:
        try:
            process.stdin.close()
        except BrokenPipeError:
            pass
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.terminate()
        return process.wait(timeout=4)


def udp_rules(families, link):
    intake = link['intake']
    rules, sources = [], {}
    for version, plan in families.items():
        family = 'inet6' if version == '6' else 'inet'
        gateway = link['gateways'][version]
        source_filter = '{ ' + ', '.join(plan['clients']) + ' }'
        sources[int(version)] = source_filter
        service = '{ ' + ', '.join(plan['targets']) + ' } port { ' + ', '.join(map(str, plan['ports'])) + ' }'
        for selector in plan['selectors']:
            identity = f" user {selector['uid']}" if 'uid' in selector else ''
            rules.append(f"pass {selector['direction']} quick on {selector['interface']} route-to ({intake} {gateway}) "
                         f"{family} proto udp from {selector['source']} to {service}{identity} no state")
        rules.append(f"pass in quick on {intake} {family} proto udp from {source_filter} to {plan['alias']} keep state")
    return '\n'.join(rules) + '\n', sources


def supervise(mount, bridge, plan_path, core_pid, core_config):
    plan = json.loads(Path(plan_path).read_text())
    families = plan['families']
    stopping = threading.Event()
    for name in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(name, lambda *_: stopping.set())

    with ExitStack() as stack:
        owner = subprocess.Popen([sys.executable, '-B', __file__, '--link-owner', mount, plan_path],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, start_new_session=True)
        stack.callback(close_child, owner)
        stack.callback(owner.stdout.close)
        if not select.select([owner.stdout], [], [], 8)[0]:
            raise RuntimeError('Tproxy link owner did not report readiness')
        announcement = owner.stdout.readline()
        if not announcement:
            raise RuntimeError('Tproxy link owner exited during setup')
        link = json.loads(announcement)
        if stopping.is_set() or select.select([sys.stdin], [], [], 0)[0]:
            return

        listeners = {}
        tcp_rules = plan['ipv4-rules']
        if plan['tcp6']:
            listeners, tcp_rules = listen_for_rules(plan['tcp6'], stack)
        rules, sources = udp_rules(families, link)
        rules = tcp_rules + rules
        rules_path = Path(plan_path).with_suffix('.pf')
        rules_path.write_text(rules)
        sockets = []
        for family in families.values():
            for _ in range(family['slots']):
                listener = stack.enter_context(bind((family['alias'], 0), socket.SOCK_DGRAM))
                listener.setblocking(False)
                sockets.append(Slot(listener))
        child_socket, channel = socket.socketpair()
        stack.enter_context(channel)
        with child_socket:
            fd = child_socket.fileno()
            carrier = subprocess.Popen([bridge, link['peer'], str(fd)], pass_fds=(fd,), stdin=subprocess.DEVNULL)
        stack.callback(close_child, carrier)
        # Close our channel first so the Ethernet process exits on EOF.
        stack.callback(channel.close)
        channel.settimeout(2)
        pf_fd = os.open('/dev/pf', os.O_RDONLY)
        stack.callback(os.close, pf_fd)
        relay = Relay(pf_fd, plan['tcp6'], stopping) if listeners else None
        clients = [client for family in families.values() for client in family['clients']]
        targets = [target for family in families.values() for target in family['targets']]
        ports = {int(version): set(family['ports']) for version, family in families.items()}
        with managed_rules(mount, rules_path, core_pid, core_config) as worker:
            with Allocator(channel, sockets, ('127.0.0.1', plan['proxy-port']), pf_fd, clients, targets, ports,
                           link['intake'], sources, rules, plan['credentials']) as allocator:
                print(f'PASS project filter and rdr calls mounted. Tproxy UDP {link["intake"]} ready', flush=True)
                try:
                    while not stopping.is_set():
                        ready, _, _ = select.select([sys.stdin, *listeners], [], [], 0.1)
                        if sys.stdin in ready:
                            break
                        if allocator.error:
                            raise allocator.error
                        if not allocator.thread.is_alive() or any(child.poll() is not None for child in (carrier, worker, owner)):
                            raise RuntimeError('a Tproxy PF or Ethernet worker exited')
                        for listener in ready:
                            relay.accept(listener, listeners[listener])
                finally:
                    stopping.set()
        report(f'Tproxy UDP relayed={allocator.relayed}, replied={allocator.replied}, '
               f'exhausted={allocator.exhausted}, stale={allocator.stale}\n')


if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            raise RuntimeError('Tproxy requires root')
        if len(sys.argv) == 4 and sys.argv[1] == '--link-owner':
            link_owner(*sys.argv[2:])
        elif len(sys.argv) == 6:
            supervise(*sys.argv[1:])
        else:
            raise ValueError('Tproxy requires the PF helper, bridge, plan and owned core identity')
    except BrokenPipeError:
        sys.exit(1)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'Tproxy: {error}', file=sys.stderr)
        sys.exit(1)
