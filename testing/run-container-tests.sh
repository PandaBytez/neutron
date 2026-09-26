#!/usr/bin/env bash
# Run Neutron's system tests inside a disposable sandbox container.
#
# `tests/system_nm.rs`, `tests/system_firewall.rs` and `tests/system_uninstall.rs`
# drive real `nmcli`, `firewall-cmd` and `cargo install`. Running them on a
# workstation would rewrite its network and firewall configuration, so they
# refuse to start unless NEUTRON_TEST_SANDBOX=1 -- which only the sandbox sets.
#
#   ./testing/run-container-tests.sh             # NetworkManager + firewall + uninstall tiers
#   ./testing/run-container-tests.sh --nm        # NetworkManager tier only
#   ./testing/run-container-tests.sh --firewall  # firewall tier only
#   ./testing/run-container-tests.sh --uninstall  # uninstall tier only
#   ./testing/run-container-tests.sh --leaks     # leak regression checks
#   ./testing/run-container-tests.sh --rebuild   # force a fresh image
#   ./testing/run-container-tests.sh --shell     # interactive shell in the sandbox
#
# `--leaks` selects the `leak_*` regression tests, also included in the firewall tier.
#
# This is a wrapper, and deliberately so. The container invocation used to be
# assembled here as well as in the xtask, which meant the paths Neutron writes as
# root -- masked with container-local tmpfs, or a test that revokes lockdown
# deletes the developer's real refresh helper and polkit action -- were listed in
# two places. One list, in xtask, is the only safe number of copies. The flags
# below are therefore the same ones `cargo xtask` takes.
set -euo pipefail

case "${1:-}" in
    --leaks) exec cargo xtask test-leaks ;;
    --shell) exec cargo xtask shell ;;
    *)       exec cargo xtask test-system "$@" ;;
esac
