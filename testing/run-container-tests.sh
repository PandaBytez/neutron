#!/usr/bin/env bash
# Run Neutron's system tests inside a disposable sandbox container.
#
# `tests/system_nm.rs` and `tests/system_firewall.rs` drive real `nmcli` and
# `firewall-cmd`. Running them on a workstation would rewrite its network and
# firewall configuration, so they refuse to start unless NEUTRON_TEST_SANDBOX=1
# -- which only this harness sets.
#
#   ./testing/run-container-tests.sh             # NetworkManager + firewall tiers
#   ./testing/run-container-tests.sh --nm        # NetworkManager tier only
#   ./testing/run-container-tests.sh --firewall  # firewall tier only
#   ./testing/run-container-tests.sh --leaks     # the open leaks from BUGS.md
#   ./testing/run-container-tests.sh --rebuild   # force a fresh image
#   ./testing/run-container-tests.sh --shell     # interactive shell in the sandbox
#
# `--leaks` runs the `leak_*` tests, which assert the behaviour the open bugs in
# BUGS.md violate. They are EXPECTED TO FAIL until those bugs are fixed, and are
# excluded from the default run so an open leak does not turn CI permanently red.
set -euo pipefail

readonly IMAGE=neutron-sandbox
readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rebuild=0
shell=0
mode=all
for arg in "$@"; do
    case "$arg" in
        --rebuild)  rebuild=1 ;;
        --shell)    shell=1 ;;
        --nm)       mode=nm ;;
        --firewall) mode=firewall ;;
        --leaks)    mode=leaks ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

command -v podman >/dev/null ||
    { echo "podman is required (https://podman.io)" >&2; exit 1; }

if [[ $rebuild -eq 1 ]] || ! podman image exists "$IMAGE"; then
    echo "==> building $IMAGE"
    podman build -t "$IMAGE" -f "$REPO_ROOT/testing/Containerfile" "$REPO_ROOT"
fi

# --privileged: NetworkManager needs CAP_NET_ADMIN for WireGuard links and
# firewalld needs it for netfilter. Both are confined to the container's own
# network namespace -- netfilter tables and routes are per-netns, so the host's
# firewall and routing are untouched (verified; see testing/README.md).
#
# The source tree is mounted rather than copied so an edit-test cycle needs no
# image rebuild. `:z` relabels for SELinux. CARGO_TARGET_DIR is set in the image
# to keep build output off the mount.
podman_flags=(
    run --rm
    --privileged
    -v "$REPO_ROOT:/src:z"
    -w /src
)

if [ -t 0 ]; then
    podman_flags+=(-it)
else
    podman_flags+=(-i)
fi

podman_args=(
    "${podman_flags[@]}"
    "$IMAGE"
)

if [[ $shell -eq 1 ]]; then
    echo "==> interactive sandbox; NEUTRON_TEST_SANDBOX is set, so system tests will run here"
    exec podman "${podman_args[@]}" /bin/bash
fi

# `--test-threads=1` throughout: the tests share one NetworkManager and one
# firewalld, so parallel runs would interleave profile and rule changes and make
# failures irreproducible.
run_tier() {
    local name=$1
    shift
    echo "==> $name"
    podman "${podman_args[@]}" "$@"
}

case "$mode" in
    nm)
        run_tier "NetworkManager tier" \
            cargo test --test system_nm -- --ignored --test-threads=1
        ;;
    firewall)
        run_tier "firewall tier" \
            cargo test --test system_firewall -- --ignored --test-threads=1
        ;;
    leaks)
        echo "==> regression guards for fixed leaks (BUG-018, BUG-019, BUG-022)"
        run_tier "leak regression guards" \
            cargo test --test system_firewall -- --ignored --test-threads=1 leak_
        ;;
    all)
        run_tier "System tests (NetworkManager & firewalld)" \
            cargo test --test system_nm --test system_firewall -- --ignored --test-threads=1
        ;;
esac
