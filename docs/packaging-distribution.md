# Installation & Releases

Supported installation channels are Homebrew, Cargo, and static Linux binaries.
Static linking removes dynamic library dependencies, not the requirement for
NetworkManager, `nmcli`, and other system tools. Both the NetworkManager daemon
and `nmcli` must be 1.52+ and retain the selected `ipv4.routed-dns` /
`ipv6.routed-dns` values (`no` when kill-protected, otherwise `yes`). iproute2's
`ip` is required to verify protected resolver UDP/TCP egress after activation
and reapply; automatic routed-DNS processing alone is not a protection guarantee.
Lockdown additionally requires firewalld and polkit; desktop integration needs
the appropriate session services.

## Homebrew

```bash
brew tap pandabytez/tap && brew trust pandabytez/tap && brew install neutron
```

The formula is maintained in the sibling `homebrew-tap` repository by the release
script, not by copying a sample formula from this documentation.

## Cargo

Install the existing stable source tag:

```bash
cargo install --locked --git https://github.com/PandaBytez/neutron.git --tag v0.2.0
```

To install fixes newer than that tag, select an explicitly reviewed revision:

```bash
cargo install --locked --git https://github.com/PandaBytez/neutron.git --rev "<reviewed-commit-sha>"
```

These pages describe current source. The existence of `v0.2.0` does not mean
that tag includes later security fixes, nor that those fixes have been released
through Homebrew or binary assets. Check the selected revision and release notes.

## Static Binary

Download the x86_64 archive and matching SHA256SUMS from the
[release page](https://github.com/PandaBytez/neutron/releases), verify the archive
checksum, then extract and install `neutron` on your executable search path.
Use the asset names published for that release.

Alternatively, build from a reviewed checkout:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --locked --release --target x86_64-unknown-linux-musl
```

The binary is `target/x86_64-unknown-linux-musl/release/neutron`. A headless
installation does not bypass lockdown authentication: required helper refreshes
may prompt and fail closed when authorization is unavailable.

## Removal

`neutron uninstall` recognizes Homebrew and Cargo installations, withdraws
Neutron's policies and root-owned helper/action, and invokes the matching package
manager. Settings remain unless `--purge` is supplied. Unknown installation
shapes, including manually installed static binaries, are refused before changes.
For a static installation, run `neutron reset` to withdraw policies before
manually removing the binary; reset clears settings as well. See
[security recovery](security.md#uninstalling-revokes-everything-it-installed)
if the binary has already been removed.

## Release Contract

`./release.sh <tag> [notes-file]` is the only supported release entry point.
It requires a clean checkout on `main` with `HEAD == main`, a clean sibling
`homebrew-tap`, and the expected origin. It does not auto-commit dirty work;
it commits only its own version bump when needed. Existing local or remote tags
must peel to the release commit, and main, HEAD, and the tag are rechecked before
the atomic main-and-tag push.

The script accepts only a successful **main push** CI run whose source SHA
matches the release commit. It verifies the immutable commit source archive,
packages the CI-built static binary, publishes checksums, and updates the tap
using that verified archive's URL and SHA256. Reruns verify existing assets
instead of overwriting them. Do not publish releases or tap commits by hand.
