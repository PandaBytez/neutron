#!/usr/bin/env bash
# Bring up D-Bus, NetworkManager and firewalld inside the sandbox, then run the
# given command.
#
# Neither daemon is usable the instant its process starts -- `nmcli` fails with
# "Could not create NMClient object" and `firewall-cmd` with "Failed to connect
# to bus" until each claims its D-Bus name. The waits below are what make the
# system tests deterministic instead of flaky on a loaded machine.
set -euo pipefail

readonly READY_TIMEOUT=30

fail() {
    echo "sandbox: $*" >&2
    exit 1
}

[[ "${NEUTRON_TEST_SANDBOX:-}" == "1" ]] ||
    fail "NEUTRON_TEST_SANDBOX is not set; refusing to start (is this the sandbox image?)"

# Wait for a daemon to become ready, failing with its log if it dies first.
# $1 = human name, $2 = pid, $3 = log path, $4... = readiness probe
wait_ready() {
    local name=$1 pid=$2 log=$3
    shift 3
    for _ in $(seq "$READY_TIMEOUT"); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        # A daemon that died is a setup failure, not a slow start; report it
        # with its log rather than timing out silently.
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "--- $name log ---" >&2
            cat "$log" >&2 || true
            fail "$name exited during startup"
        fi
        sleep 1
    done
    echo "--- $name log ---" >&2
    cat "$log" >&2 || true
    fail "$name did not become ready within ${READY_TIMEOUT}s"
}

# A stale socket or PID from a previous run in the same container would make
# daemons exit immediately.
rm -f /run/dbus/system_bus_socket /run/dbus/pid /run/firewalld/firewalld.pid /run/NetworkManager/NetworkManager.pid
mkdir -p /run/dbus /run/firewalld /var/log /etc/NetworkManager/system-connections

dbus-daemon --system --fork

# `--no-daemon`/`--nofork` keep both in the foreground so their lifetime is tied
# to this container; backgrounded here so the test command can run.
NetworkManager --no-daemon >/var/log/neutron-nm.log 2>&1 &
wait_ready NetworkManager $! /var/log/neutron-nm.log nmcli general status

firewalld --nofork --debug >/var/log/neutron-firewalld.log 2>&1 &
wait_ready firewalld $! /var/log/neutron-firewalld.log firewall-cmd --state

echo "sandbox: ready (NM $(nmcli -t -f STATE general status), firewalld $(firewall-cmd --state))" >&2

exec "$@"
