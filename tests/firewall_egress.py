"""Packet fixture for system_firewall.rs; disposable sandbox only."""
import os
import socket
import subprocess
import sys

assert os.environ.get("NEUTRON_TEST_SANDBOX") == "1"


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, (args, result.stderr)
    return result.stdout


peer_exec = ["nsenter", "--net=/run/netns/neutron-peer"]


server = None
try:
    run("ip", "netns", "add", "neutron-peer")
    run("ip", "link", "add", "phy-test", "type", "veth", "peer", "name", "peer-test")
    run("ip", "link", "set", "peer-test", "netns", "neutron-peer")
    run("ip", "addr", "add", "192.168.249.1/24", "dev", "phy-test")
    run(*peer_exec, "ip", "addr", "add", "192.168.249.2/24", "dev", "peer-test")
    run("ip", "link", "set", "phy-test", "up")
    run("ip", "link", "add", "wg-test", "type", "wireguard")
    run(*peer_exec, "ip", "link", "add", "wg-peer", "type", "wireguard")
    # IPv6 otherwise removes addresses on link-down, before the fixture can
    # move the same source addresses and established flows to physical egress.
    run("sysctl", "-w", "net.ipv6.conf.wg-test.keep_addr_on_down=1")
    run(*peer_exec, "sysctl", "-w", "net.ipv6.conf.wg-peer.keep_addr_on_down=1")
    keys = [run("wg", "genkey").strip() for _ in range(2)]
    public = []
    for key in keys:
        result = subprocess.run(["wg", "pubkey"], input=key, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        public.append(result.stdout.strip())
    for prefix, interface, key, peer_key, endpoint in [
        ([], "wg-test", keys[0], public[1], "192.168.249.2:51820"),
        (peer_exec, "wg-peer", keys[1], public[0], "192.168.249.1:51820"),
    ]:
        result = subprocess.run([
            *prefix, "wg", "set", interface, "private-key", "/dev/stdin",
            "listen-port", "51820", "peer", peer_key, "endpoint", endpoint,
            "allowed-ips", "198.18.0.0/24,2001:db8:18::/64",
        ], input=key, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    run("ip", "link", "set", "wg-test", "up")
    run(*peer_exec, "ip", "link", "set", "wg-peer", "up")
    run(*peer_exec, "ip", "link", "set", "lo", "up")
    run(*peer_exec, "ip", "link", "set", "peer-test", "up")
    for address, peer in [("198.18.0.1/24", "198.18.0.2/24"),
                          ("2001:db8:18::1/64", "2001:db8:18::2/64")]:
        run("ip", "addr", "add", address, "dev", "wg-test", "nodad")
        run(*peer_exec, "ip", "addr", "add", peer,
             "dev", "wg-peer", "nodad")
    # Both peers reply, making each UDP flow ESTABLISHED in conntrack.
    server = subprocess.Popen([*peer_exec, "python3", "-u", "-c", """
import selectors, socket
selector = selectors.DefaultSelector()
for family, address in [(socket.AF_INET, '198.18.0.2'), (socket.AF_INET6, '2001:db8:18::2')]:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((address, 51899))
    selector.register(sock, selectors.EVENT_READ)
print('ready', flush=True)
while True:
    for key, _ in selector.select():
        data, source = key.fileobj.recvfrom(1024)
        key.fileobj.sendto(data, source)
"""], stdout=subprocess.PIPE, text=True)
    assert server.stdout.readline().strip() == "ready"
    sockets = []
    for family, address in [(socket.AF_INET, "198.18.0.2"),
                            (socket.AF_INET6, "2001:db8:18::2")]:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.connect((address, 51899))
        sock.send(b"before")
        assert sock.recv(1024) == b"before"
        sockets.append(sock)
    print("ready", flush=True)
    assert sys.stdin.readline().strip() == "go"
    for sock in sockets:
        sock.send(b"allowed")
        assert sock.recv(1024) == b"allowed", "tunnel egress must remain permitted"
    # Preserve the routes, source IPs, sockets and conntrack entries, but make
    # egress no longer match the tunnel-interface allowance.
    run("ip", "link", "set", "wg-test", "down")
    run(*peer_exec, "ip", "link", "set", "wg-peer", "down")
    for address, peer in [("198.18.0.1/24", "198.18.0.2/24"),
                          ("2001:db8:18::1/64", "2001:db8:18::2/64")]:
        run("ip", "addr", "del", address, "dev", "wg-test")
        run(*peer_exec, "ip", "addr", "del", peer, "dev", "wg-peer")
        run("ip", "addr", "add", address, "dev", "phy-test", "nodad")
        run(*peer_exec, "ip", "addr", "add", peer, "dev", "peer-test", "nodad")
    for sock in sockets:
        try:
            sock.send(b"must-not-escape")
            sock.recv(1024)
        except (TimeoutError, PermissionError):
            pass
        else:
            raise AssertionError("established traffic escaped on physical egress")
    # Counters prove the packets reached Neutron's DROP, rather than timing out
    # because the fixture lost its route or neighbor entry.
    for tool in ["iptables", "ip6tables"]:
        # firewalld uses OUTPUT_direct on iptables, OUTPUT on nftables.
        rules = run(tool, "-t", "mangle", "-L", "-v", "-n", "-x")
        assert any("DROP" in line and "neutron-lockdown" in line and int(line.split()[0]) > 0
                   for line in rules.splitlines()), rules
finally:
    if server is not None:
        server.terminate()
        server.wait(timeout=5)
    for interface in ["wg-test", "phy-test"]:
        subprocess.run(["ip", "link", "del", interface], capture_output=True)
    subprocess.run(["ip", "netns", "del", "neutron-peer"], capture_output=True)
