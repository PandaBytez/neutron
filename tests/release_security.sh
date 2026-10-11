#!/usr/bin/env bash
set -euo pipefail

# Every external release command is mocked. Only disposable files are changed;
# the real git/gh/cargo/curl commands are never called, even on the happy path.
if [ "${RELEASE_SECURITY_MOCK:-}" = 1 ]; then
    printf '%s %s\n' "${0##*/}" "$*" >> "$SCRATCH/commands"
    case "${0##*/}" in
        git)
            git_dir="$PWD"
            if [ "${1:-}" = -C ]; then git_dir="$2"; shift 2; fi
            if [ "$git_dir" = "$SCRATCH/homebrew-tap" ]; then
                case "$*" in
                    'symbolic-ref --quiet --short HEAD')
                        [ "$CASE" != tap-detached ] || exit 1
                        if [ "$CASE" = tap-branch ]; then printf 'feature\n'; else printf 'main\n'; fi
                        exit 0 ;;
                    'remote get-url origin')
                        if [ "$CASE" = tap-origin ]; then printf 'https://github.com/attacker/homebrew-tap.git\n'; else
                            printf '%s\n' "${TAP_ORIGIN:-https://github.com/PandaBytez/homebrew-tap.git}"
                        fi
                        exit 0 ;;
                    'status --porcelain')
                        [ "$CASE" != status-failed ] || exit 1
                        if ! cmp -s "$git_dir/Formula/neutron.rb" "$SCRATCH/tap-clean"; then printf ' M Formula/neutron.rb\n'; fi
                        exit 0 ;;
                    commit*)
                        cp "$git_dir/Formula/neutron.rb" "$SCRATCH/tap-clean"
                        exit 0 ;;
                    push*)
                        [ "$*" = 'push origin refs/heads/main:refs/heads/main' ] || exit 90
                        exit 0 ;;
                esac
            fi
            case "$*" in
                'symbolic-ref --quiet --short HEAD')
                    [ "$CASE" != detached ] || exit 1
                    if [ "$CASE" = prepush-branch ] && [ -f "$SCRATCH/tag" ]; then printf 'feature\n'; exit 0; fi
                    printf '%s\n' "${BRANCH:-main}" ;;
                'rev-parse HEAD') printf '%s\n' "$SHA" ;;
                'rev-parse refs/heads/main')
                    if [ "$CASE" = main-mismatch ]; then printf '%s\n' "$OTHER"; else printf '%s\n' "$SHA"; fi ;;
                'remote get-url origin') printf '%s\n' 'https://github.com/PandaBytez/neutron.git' ;;
                'status --porcelain')
                    [ "$CASE" != status-failed ] || exit 1
                    if [ "$CASE" = dirty ]; then printf '%s\n' ' M Cargo.toml'; fi ;;
                rev-parse*refs/tags/*)
                    if [ "$CASE" = prepush-tag ] && [ -f "$SCRATCH/tag" ]; then
                        printf '%s\n' "$OTHER"
                    elif [ "$CASE" = local-mismatch ]; then
                        if [[ "$*" = *'^{commit}'* ]]; then printf '%s\n' "$OTHER"; else printf '%s\n' "$SHA"; fi
                    elif [ -f "$SCRATCH/tag" ] || [ "$CASE" = bump-existing ]; then
                        printf '%s\n' "$SHA"
                    else exit 1; fi ;;
                ls-remote*)
                    [[ "$*" = *'https://github.com/PandaBytez/neutron.git'* ]] || exit 90
                    if [ "$CASE" = remote-mismatch ] || { [ "$CASE" = remote-moved ] && [ -f "$SCRATCH/pushed" ]; } ||
                       { [ "$CASE" = remote-moved-after-ci ] && [ -f "$SCRATCH/downloaded" ]; }; then
                        printf '%s\trefs/tags/v0.2.0\n%s\trefs/tags/v0.2.0^{}\n' "$SHA" "$OTHER"
                    elif [ -f "$SCRATCH/pushed" ]; then
                        printf '%s\trefs/tags/v0.2.0\n%s\trefs/tags/v0.2.0^{}\n' "$OTHER" "$SHA"
                    fi ;;
                'tag -a '*) touch "$SCRATCH/tag" ;;
                push*)
                    [[ "$*" != *--force* ]] || exit 90
                    touch "$SCRATCH/pushed" ;;
                add*|commit*) : ;;
                *) exit 90 ;;
            esac ;;
        gh)
            [[ "$*" = *'--repo PandaBytez/neutron'* ]] || exit 90
            case "$1 $2" in
                'run list')
                    [[ "$*" = *"--commit $SHA --workflow ci.yml --branch main --event push"* ]] || exit 90
                    if [ "$CASE" != no-ci ]; then printf '42\n'; fi ;;
                'run view')
                    [[ "$*" = *'--json status,conclusion,headSha,event,headBranch'* ]] || exit 90
                    head_sha="$SHA"; event=push; branch=main; conclusion=success
                    case "$CASE" in
                        ci-sha) head_sha="$OTHER" ;;
                        ci-event) event=pull_request ;;
                        ci-branch) branch=feature ;;
                        ci-failed) conclusion=failure ;;
                    esac
                    printf '{"headSha":"%s","event":"%s","headBranch":"%s","status":"completed","conclusion":"%s"}\n' "$head_sha" "$event" "$branch" "$conclusion" ;;
                'run download')
                    touch "$SCRATCH/downloaded"
                    destination="${!#}"
                    if [ "$CASE" != missing-binary ]; then printf 'mock static binary\n' > "$destination/neutron"; fi ;;
                'release view') [ -d "$SCRATCH/published" ] || [ "$CASE" = asset-mismatch ] ;;
                'release download')
                    destination="${!#}"
                    if [ "$CASE" = asset-mismatch ]; then
                        printf 'mismatch\n' > "$destination/neutron-v0.2.0-linux-x86_64.tar.gz"
                        printf 'mismatch\n' > "$destination/neutron-v0.2.0-SHA256SUMS"
                    else cp "$SCRATCH/published/"* "$destination/"; fi ;;
                'release create')
                    [[ "$*" = *"--verify-tag --target $SHA"* ]] || exit 90
                    mkdir "$SCRATCH/published"
                    for arg in "$@"; do
                        if [[ "$arg" = "$TMPDIR/"* ]]; then cp "$arg" "$SCRATCH/published/"; fi
                    done ;;
                *) exit 90 ;;
            esac ;;
        curl)
            [[ "$*" = *"https://github.com/PandaBytez/neutron/archive/$SHA.tar.gz"* ]] || exit 90
            destination="${!#}"
            [[ "$destination" = "$TMPDIR/"*/source.tar.gz ]] || exit 90
            [ "$(stat -c %a "${destination%/*}")" = 700 ] || exit 90
            if [ "$CASE" = download-failed ]; then exit 1; fi
            source_sha="$SHA"
            if [ "$CASE" = source-mismatch ]; then source_sha="$OTHER"; fi
            mkdir -p "$SCRATCH/source/neutron-$source_sha"
            printf 'source\n' > "$SCRATCH/source/neutron-$source_sha/Cargo.toml"
            tar -czf "$destination" -C "$SCRATCH/source" "neutron-$source_sha"
            printf 200 ;;
        cargo|sleep) : ;;
        *) exit 90 ;;
    esac
    exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
export SCRATCH
export SHA=1111111111111111111111111111111111111111
export OTHER=2222222222222222222222222222222222222222
mkdir -p "$SCRATCH/bin" "$SCRATCH/neutron" "$SCRATCH/homebrew-tap/Formula" "$SCRATCH/tmp"
cp "$ROOT/release.sh" "$SCRATCH/neutron/release.sh"
cp "${BASH_SOURCE[0]}" "$SCRATCH/bin/mock"
chmod +x "$SCRATCH/bin/mock"
for tool in git gh cargo curl sleep; do ln -s mock "$SCRATCH/bin/$tool"; done
export PATH="$SCRATCH/bin:$PATH" TMPDIR="$SCRATCH/tmp" RELEASE_SECURITY_MOCK=1

reset_case() {
    rm -rf "$SCRATCH/tag" "$SCRATCH/pushed" "$SCRATCH/published" "$SCRATCH/source" "$SCRATCH/downloaded"
    : > "$SCRATCH/commands"
    printf '[package]\nname = "neutron"\nversion = "0.2.0"\n' > "$SCRATCH/neutron/Cargo.toml"
    printf 'lockfile\n' > "$SCRATCH/neutron/Cargo.lock"
    printf 'url "https://github.com/PandaBytez/neutron/archive/refs/tags/v0.1.0.tar.gz"\nsha256 "old"\n' > "$SCRATCH/homebrew-tap/Formula/neutron.rb"
    cp "$SCRATCH/homebrew-tap/Formula/neutron.rb" "$SCRATCH/tap-clean"
}

reject() {
    if bash "$SCRATCH/neutron/release.sh" "$@" > "$SCRATCH/output" 2>&1; then
        printf 'FAIL: %s unexpectedly succeeded\n' "$CASE" >&2; exit 1
    fi
    if grep -q 'release create' "$SCRATCH/commands"; then
        printf 'FAIL: %s published a release\n' "$CASE" >&2; exit 1
    fi
    [ -z "$(ls -A "$TMPDIR")" ] || { printf 'FAIL: leaked assets\n' >&2; exit 1; }
    if grep -q 'old' "$SCRATCH/homebrew-tap/Formula/neutron.rb"; then :; else
        printf 'FAIL: %s modified the tap\n' "$CASE" >&2; exit 1
    fi
}

export CASE=invalid
for tag in '' v01.2.3 v1.02.3 v1.2.03 v1.2 v1.2.3-rc.1 v1.2.3+build \
    'v1.2.3/../../bad' 'v1.2.3";touch INJECTED' $'v1.2.3\nversion = "9"' '--help'; do
    reset_case
    reject "$tag"
    [ ! -s "$SCRATCH/commands" ] || { printf 'FAIL: invalid tag ran commands\n' >&2; exit 1; }
    grep -q 'version = "0.2.0"' "$SCRATCH/neutron/Cargo.toml"
done

for CASE in detached main-mismatch dirty status-failed local-mismatch remote-mismatch bump-existing; do
    export CASE
    reset_case
    tag=v0.2.0
    if [ "$CASE" = bump-existing ]; then tag=v0.3.0; fi
    reject "$tag"
    if grep -Eq '^git (add|commit|tag -a|push)|^cargo ' "$SCRATCH/commands"; then
        printf 'FAIL: %s mutated before preflight\n' "$CASE" >&2; exit 1
    fi
done
for CASE in tap-branch tap-detached tap-origin; do
    export CASE
    reset_case
    # A new version would trigger sed/cargo/commit if preflight did not reject it.
    reject v0.3.0
    grep -q 'version = "0.2.0"' "$SCRATCH/neutron/Cargo.toml"
    if grep -Eq '^git (add|commit|tag -a|push)|^cargo |^gh |^curl ' "$SCRATCH/commands"; then
        printf 'FAIL: %s mutated before tap preflight\n' "$CASE" >&2; exit 1
    fi
done
export CASE=branch BRANCH=feature
reset_case
reject v0.2.0
unset BRANCH

for CASE in prepush-tag prepush-branch remote-moved remote-moved-after-ci source-mismatch ci-sha ci-event ci-branch ci-failed no-ci download-failed missing-binary asset-mismatch; do
    export CASE
    reset_case
    reject v0.2.0
    if [[ "$CASE" = prepush-* ]] && grep -q '^git push' "$SCRATCH/commands"; then
        printf 'FAIL: changed refs were pushed\n' >&2; exit 1
    fi
done

export CASE=success
for tag in 0.2.0 v0.2.0 --v0.2.0 --0.2.0; do
    reset_case
    printf 'release notes\n' > "$SCRATCH/notes"
    bash "$SCRATCH/neutron/release.sh" "$tag" "$SCRATCH/notes" > "$SCRATCH/output" 2>&1
    grep -q "archive/$SHA.tar.gz" "$SCRATCH/homebrew-tap/Formula/neutron.rb"
    grep -q 'version "0.2.0"' "$SCRATCH/homebrew-tap/Formula/neutron.rb"
    grep -q -- "--notes-file $SCRATCH/notes" "$SCRATCH/commands"
    grep -q '^git push origin refs/heads/main:refs/heads/main$' "$SCRATCH/commands"
    [ -z "$(ls -A "$TMPDIR")" ]
    : > "$SCRATCH/commands"
    bash "$SCRATCH/neutron/release.sh" "$tag" > "$SCRATCH/output" 2>&1
    if grep -q 'release create' "$SCRATCH/commands"; then
        printf 'FAIL: rerun republished release\n' >&2; exit 1
    fi
    [ -z "$(ls -A "$TMPDIR")" ]
done
for TAP_ORIGIN in https://github.com/PandaBytez/homebrew-tap https://github.com/PandaBytez/homebrew-tap.git \
    git@github.com:PandaBytez/homebrew-tap.git ssh://git@github.com/PandaBytez/homebrew-tap.git; do
    export TAP_ORIGIN
    reset_case
    bash "$SCRATCH/neutron/release.sh" v0.2.0 > "$SCRATCH/output" 2>&1
done
printf 'Release security checks passed (scratch files and mock commands only).\n'
