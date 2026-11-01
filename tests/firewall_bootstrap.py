"""First hostname activation after reload, with a private physical-side DNS peer."""
import os
import select
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

assert os.environ.get("NEUTRON_TEST_SANDBOX") == "1"
binary = sys.argv[1]
namespace = "neutron-bootstrap-peer"
peer = ["nsenter", f"--net=/run/netns/{namespace}"]
name = f"nbt{os.getpid()}"
resolver = "203.0.113.53"
resolv_conf = Path("/etc/resolv.conf")
original_dns = resolv_conf.read_bytes()
server = None


def run(*args, env=None):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=90)
    if result.returncode != 0 and args[0] == binary and "connect" in args:
        print("Resolver file:", resolv_conf.read_text(), file=sys.stderr)
        for command in [("nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show", "--active"),
                        ("firewall-cmd", "--direct", "--get-all-rules"),
                        ("getent", "ahostsv4", "neutron-bootstrap.test")]:
            diagnostic = subprocess.run(command, capture_output=True, text=True, timeout=15)
            print(command, diagnostic.stdout, diagnostic.stderr, file=sys.stderr)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="neutron-bootstrap-") as scratch:
    root = Path(scratch)
    env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"))
    config = root / "config/neutron/config.toml"
    config.parent.mkdir(parents=True, mode=0o700)
    config.write_text(f'[general]\nverify_tunnel_on_connect = false\nauto_sync_profiles = false\nprofiles_dir = "{root}/profiles"\n')
    config.chmod(0o600)
    profile = root / f"{name}.conf"
    profile.write_text("""[Interface]
PrivateKey = OMHVnT2Gm0ZBb3xF2Cq0hZ0jVQ1z3T0lQ0Z0YQ0Z0X8=
Address = 10.251.1.2/32
DNS = 10.251.1.1
[Peer]
PublicKey = tGZ0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0k=
PresharedKey = OMHVnT2Gm0ZBb3xF2Cq0hZ0jVQ1z3T0lQ0Z0YQ0Z0X8=
AllowedIPs = 198.19.0.0/16
Endpoint = neutron-bootstrap.test:53
PersistentKeepalive = 0
""")
    profile.chmod(0o600)
    try:
        run("ip", "netns", "add", namespace)
        run("ip", "link", "add", "nb-physical", "type", "veth", "peer", "name", "nb-peer")
        run("ip", "link", "set", "nb-peer", "netns", namespace)
        run("ip", "addr", "add", "203.0.113.1/24", "dev", "nb-physical")
        run(*peer, "ip", "addr", "add", f"{resolver}/24", "dev", "nb-peer")
        run("ip", "link", "set", "nb-physical", "up")
        run(*peer, "ip", "link", "set", "nb-peer", "up")
        server = subprocess.Popen([*peer, sys.executable, "-u", "-c", """
import socket, struct
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('203.0.113.53', 53))
print('ready', flush=True)
while True:
    query, client = sock.recvfrom(4096)
    pos = 12
    while query[pos]:
        pos += query[pos] + 1
    end = pos + 5
    qtype = struct.unpack('!H', query[pos+1:pos+3])[0]
    answer = b''
    if qtype == 1:
        answer = struct.pack('!HHHIH', 0xc00c, 1, 1, 30, 4) + socket.inet_aton('198.18.251.1')
    header = query[:2] + struct.pack('!HHHHH', 0x8180, 1, bool(answer), 0, 0)
    sock.sendto(header + query[12:end] + answer, client)
"""], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert select.select([server.stdout], [], [], 10)[0], "DNS peer did not start"
        assert server.stdout.readline().strip() == "ready"
        resolv_conf.write_text(f"nameserver {resolver}\noptions timeout:1 attempts:1\n")
        run("nmcli", "connection", "import", "type", "wireguard", "file", str(profile))
        run("nmcli", "connection", "modify", name, "connection.autoconnect", "no")
        run("nmcli", "connection", "up", name)
        run(binary, "lockdown", "enable", env=env)
        run("nmcli", "connection", "down", name)
        run("firewall-cmd", "--reload")
        before = run("firewall-cmd", "--direct", "--get-all-rules")
        assert "--dport 53" in before and "-j DROP" in before
        # No tray daemon is running to repair the restored connected policy.
        resolv_conf.write_text(f"nameserver {resolver}\noptions timeout:1 attempts:1\n")
        run(binary, "connect", name, env=env)
        stored = run("nmcli", "--escape", "no", "-g", "wireguard.peers", "connection", "show", name)
        assert "neutron-bootstrap.test:53" in stored, "the canonical hostname must be restored"
        assert "OMHVnT2Gm0ZBb3xF2Cq0hZ0jVQ1z3T0lQ0Z0YQ0Z0X8=" in run("wg", "show", name, "preshared-keys"), "peer secrets must survive temporary pinning"
        assert "198.18.251.1:53" in run("wg", "show", name, "endpoints"), "the active device must retain its resolved endpoint"
        rules = run("firewall-cmd", "--direct", "--get-all-rules")
        assert any(f"-o {name} " in rule and "ACCEPT" in rule for rule in rules.splitlines()), rules
        assert any("198.18.251.1" in rule and "--dport 53" in rule and "ACCEPT" in rule for rule in rules.splitlines()), rules
        # Bootstrap DNS is closed again, including to the physical-side resolver.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(0.5)
        try:
            probe.sendto(bytes.fromhex("123401000001000000000000") + b"\x07example\x04test\x00\x00\x01\x00\x01", (resolver, 53))
            probe.recv(4096)
        except (TimeoutError, PermissionError):
            pass
        else:
            raise AssertionError("physical-side DNS remained open after activation")
        finally:
            probe.close()
    finally:
        subprocess.run([binary, "reset", "--yes"], env=env, capture_output=True, timeout=90)
        subprocess.run(["nmcli", "connection", "delete", name], capture_output=True, timeout=30)
        resolv_conf.write_bytes(original_dns)
        if server is not None:
            server.terminate()
            server.wait(timeout=5)
        subprocess.run(["ip", "link", "del", "nb-physical"], capture_output=True)
        subprocess.run(["ip", "netns", "del", namespace], capture_output=True)
