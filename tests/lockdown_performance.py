"""Disposable 21-profile lockdown benchmark; command counts are the regression gate."""
import json
import os
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

assert os.environ.get("NEUTRON_TEST_SANDBOX") == "1"
binary = sys.argv[1]


def run(*args, env=None):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="neutron-performance-") as scratch:
    root = Path(scratch)
    env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"))
    config = root / "config/neutron/config.toml"
    config.parent.mkdir(parents=True, mode=0o700)
    config.write_text(f'[general]\nverify_tunnel_on_connect = false\nauto_sync_profiles = false\nprofiles_dir = "{root}/profiles"\n')
    names = [f"np{i:02}{os.getpid()}" for i in range(21)]
    backups = []
    metrics = {}
    try:
        for i, name in enumerate(names):
            profile = root / f"{name}.conf"
            profile.write_text(f"""[Interface]
PrivateKey = OMHVnT2Gm0ZBb3xF2Cq0hZ0jVQ1z3T0lQ0Z0YQ0Z0X8=
Address = 10.253.60.{i+2}/32
[Peer]
PublicKey = tGZ0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0k=
AllowedIPs = 198.19.0.0/16
Endpoint = 192.0.2.{i+1}:51820
PersistentKeepalive = 0
""")
            run("nmcli", "connection", "import", "type", "wireguard", "file", str(profile))
            run("nmcli", "connection", "modify", name, "connection.autoconnect", "no")
        active = run("nmcli", "-t", "-f", "NAME", "connection", "show", "--active").splitlines()
        for name in names:
            if name in active:
                run("nmcli", "connection", "down", name)
        run(binary, "connect", names[0], env=env)
        # Wrappers live only in this container. Never instrument workstation tools.
        for tool in ["nmcli", "ip", "firewall-cmd"]:
            executable = Path(shutil.which(tool)).resolve()
            backup = executable.with_name(executable.name + ".neutron-performance-real")
            executable.rename(backup)
            backups.append((executable, backup))
            log = root / f"{tool}.log"
            executable.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\nexec {shlex.quote(str(backup))} \"$@\"\n")
            executable.chmod(0o755)

        def measure(label, command):
            for tool in ["nmcli", "ip", "firewall-cmd"]:
                (root / f"{tool}.log").write_text("")
            start = time.monotonic()
            run(*command, env=env)
            logs = {tool: (root / f"{tool}.log").read_text().splitlines() for tool in ["nmcli", "ip", "firewall-cmd"]}
            metrics[label] = {
                "seconds": round(time.monotonic() - start, 3),
                "nmcli": len(logs["nmcli"]),
                "profile_reads": sum("wireguard.peers" in line or "connection.interface-name" in line for line in logs["nmcli"]),
                "link_snapshots": sum("-json -details link show" in line for line in logs["ip"]),
                "firewall_cmd_writes": sum("--add-rule" in line or "--remove-rule" in line for line in logs["firewall-cmd"]),
            }

        measure("enable", [binary, "lockdown", "enable"])
        run("/usr/local/libexec/neutron-lockdown-helper")  # Warm outside the switch timing.
        for i in range(1, 4):
            measure(f"switch{i}", [binary, "switch", names[i]])
        measure("disable", [binary, "lockdown", "disable"])
        metrics["switch_median_seconds"] = statistics.median(metrics[f"switch{i}"]["seconds"] for i in range(1, 4))
        print(json.dumps(metrics), flush=True)
        if os.environ.get("NEUTRON_PERFORMANCE_ASSERT") == "1":
            for i in range(1, 4):
                assert metrics[f"switch{i}"]["profile_reads"] <= 4, metrics
                assert metrics[f"switch{i}"]["link_snapshots"] <= 8, metrics
            for label in ["enable", "disable", "switch1", "switch2", "switch3"]:
                assert metrics[label]["firewall_cmd_writes"] == 0, metrics
    finally:
        for executable, backup in reversed(backups):
            backup.replace(executable)
        subprocess.run([binary, "reset", "--yes"], env=env, capture_output=True, timeout=180)
        for name in names:
            subprocess.run(["nmcli", "connection", "delete", name], capture_output=True, timeout=30)
