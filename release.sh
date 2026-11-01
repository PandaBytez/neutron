#!/usr/bin/env bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAP_DIR="$(cd "$ROOT_DIR/../homebrew-tap" 2>/dev/null && pwd || true)"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo -e "${RED}Error:${NC} Version/tag argument required."
    echo "Usage: ./release.sh <tag> [notes-file] (e.g. ./release.sh v0.1.0 or ./release --v0.1.0)"
    echo "  With a notes file the release uses it verbatim; without one, GitHub generates notes."
    exit 1
fi

RAW_TAG="$1"
TAG="${RAW_TAG#--}"
if [[ ! "$TAG" =~ ^v ]]; then
    TAG="v$TAG"
fi
VERSION="${TAG#v}"
# Only stable SemVer releases are supported by the tap contract. Validate before
# any writes, including version substitution, temporary files, commits or tags.
if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "Error: expected a stable SemVer tag (vMAJOR.MINOR.PATCH, no leading zeroes)." >&2
    exit 1
fi
if [ -n "${2:-}" ] && [ ! -r "$2" ]; then
    echo "Error: notes file is not readable: $2" >&2
    exit 1
fi
REPO="PandaBytez/neutron"
for tool in gh jq git cargo curl tar sha256sum cmp mktemp; do
    command -v "$tool" >/dev/null || { echo "Error: $tool is required." >&2; exit 1; }
done

echo -e "${BLUE}==>${NC} Preparing release for ${GREEN}${TAG}${NC} (version: ${VERSION})"

# 1. Fail preflight before changing the checkout.
cd "$ROOT_DIR"
require_main() {
    local branch head main
    branch="$(git symbolic-ref --quiet --short HEAD)" || { echo "Error: release requires main, not detached HEAD." >&2; exit 1; }
    head="$(git rev-parse HEAD)"
    main="$(git rev-parse refs/heads/main)"
    if [ "$branch" != main ] || [ "$head" != "$main" ]; then
        echo "Error: release requires main checked out with HEAD == main." >&2
        exit 1
    fi
}
require_main
case "$(git remote get-url origin)" in
    "https://github.com/$REPO"|"https://github.com/$REPO.git"|"git@github.com:$REPO.git"|"ssh://git@github.com/$REPO.git") ;;
    *) echo "Error: origin must be $REPO." >&2; exit 1 ;;
esac
if [ ! -f "$TAP_DIR/Formula/neutron.rb" ]; then
    echo "Error: a clean sibling homebrew-tap with Formula/neutron.rb is required." >&2
    exit 1
fi
require_tap_main_origin() {
    local branch origin
    branch="$(git -C "$TAP_DIR" symbolic-ref --quiet --short HEAD)" || { echo "Error: tap requires main, not detached HEAD." >&2; exit 1; }
    if [ "$branch" != main ]; then
        echo "Error: homebrew-tap must have main checked out." >&2
        exit 1
    fi
    origin="$(git -C "$TAP_DIR" remote get-url origin)"
    case "$origin" in
        "https://github.com/PandaBytez/homebrew-tap"|"https://github.com/PandaBytez/homebrew-tap.git"|"git@github.com:PandaBytez/homebrew-tap.git"|"ssh://git@github.com/PandaBytez/homebrew-tap.git") ;;
        *) echo "Error: tap origin must be PandaBytez/homebrew-tap." >&2; exit 1 ;;
    esac
}
require_tap_main_origin
TAP_STATUS="$(git -C "$TAP_DIR" status --porcelain)"
CHECKOUT_STATUS="$(git status --porcelain)"
if [ -n "$TAP_STATUS" ]; then
    echo "Error: commit or stash tap changes before releasing." >&2
    exit 1
fi
if [ -n "$CHECKOUT_STATUS" ]; then
    echo "Error: commit or stash checkout changes before releasing." >&2
    exit 1
fi

COMMIT_SHA="$(git rev-parse HEAD)"
if [[ ! "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Error: expected a GitHub SHA-1 release commit." >&2
    exit 1
fi
LOCAL_TAG="$(git rev-parse --verify "refs/tags/$TAG^{commit}" 2>/dev/null || true)"
if git rev-parse --verify "refs/tags/$TAG" >/dev/null 2>&1 && [ "$LOCAL_TAG" != "$COMMIT_SHA" ]; then
    echo "Error: existing tag $TAG does not peel to HEAD." >&2
    exit 1
fi
remote_tag_commit() {
    git ls-remote "https://github.com/$REPO.git" "refs/tags/$TAG" "refs/tags/$TAG^{}" |
        awk '$2 ~ /\^\{\}$/ { peeled = $1 } $2 !~ /\^\{\}$/ { direct = $1 } END { print peeled ? peeled : direct }'
}
REMOTE_TAG="$(remote_tag_commit)"
if [ -n "$REMOTE_TAG" ] && [ "$REMOTE_TAG" != "$COMMIT_SHA" ]; then
    echo "Error: existing remote tag $TAG does not match HEAD." >&2
    exit 1
fi

# 2. Update Cargo.toml version if different
CURRENT_CARGO_VER=$(grep -m1 '^version =' Cargo.toml | cut -d '"' -f2)
if [ "$CURRENT_CARGO_VER" != "$VERSION" ]; then
    if [ -n "$LOCAL_TAG$REMOTE_TAG" ]; then
        echo "Error: existing tag cannot be reused for a version bump." >&2
        exit 1
    fi
    echo -e "${BLUE}==>${NC} Bumping Cargo.toml version from ${CURRENT_CARGO_VER} to ${VERSION}..."
    sed -i "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
    cargo check --quiet
    git add Cargo.toml Cargo.lock
    git commit -m "chore: bump version to $VERSION"
fi
COMMIT_SHA="$(git rev-parse HEAD)"
if [[ ! "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Error: expected a GitHub SHA-1 release commit." >&2
    exit 1
fi

# 3. Tag release locally
echo -e "${BLUE}==>${NC} Tagging ${TAG}..."
if git rev-parse --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "Reusing existing tag $TAG."
else
    git tag -a "$TAG" -m "Release $TAG"
fi

# 4. Push main branch AND tag together in a single network operation
require_main
CHECKOUT_STATUS="$(git status --porcelain)"
if [ "$(git rev-parse HEAD)" != "$COMMIT_SHA" ] ||
   [ "$(git rev-parse "refs/tags/$TAG^{commit}")" != "$COMMIT_SHA" ] ||
   [ -n "$CHECKOUT_STATUS" ]; then
    echo "Error: main, HEAD and the peeled tag must match the clean release commit." >&2
    exit 1
fi
echo -e "${BLUE}==>${NC} Pushing main branch and ${TAG} to origin..."
git push --atomic origin refs/heads/main:refs/heads/main "refs/tags/$TAG:refs/tags/$TAG"
require_remote_tag() {
    if [ "$(remote_tag_commit)" != "$COMMIT_SHA" ]; then
        echo "Error: remote tag $TAG no longer matches release commit $COMMIT_SHA." >&2
        exit 1
    fi
}
require_remote_tag

ASSET_DIR="$(mktemp -d)"
trap 'rm -rf "$ASSET_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 5. Calculate SHA256 of the release archive
# Pin the source to the same immutable commit as CI, not a movable tag URL.
TARBALL_URL="https://github.com/$REPO/archive/${COMMIT_SHA}.tar.gz"
echo -e "${BLUE}==>${NC} Fetching archive checksum for ${TARBALL_URL}..."

SHA256=""
EMPTY_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

for i in {1..12}; do
    SOURCE_TAR="$ASSET_DIR/source.tar.gz"
    HTTP_CODE=$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' -w "%{http_code}" "$TARBALL_URL" -o "$SOURCE_TAR" || true)

    if [ "$HTTP_CODE" = "200" ] && [ -s "$SOURCE_TAR" ]; then
        tar -tzf "$SOURCE_TAR" > "$ASSET_DIR/source-files"
        if ! awk -v root="neutron-$COMMIT_SHA/" 'index($0, root) != 1 { bad = 1 } END { exit bad || NR == 0 }' "$ASSET_DIR/source-files"; then
            echo "Error: source archive does not match the release commit." >&2
            exit 1
        fi
        CALC_SHA=$(sha256sum "$SOURCE_TAR" | awk '{print $1}')
        if [ "$CALC_SHA" != "$EMPTY_SHA" ]; then
            SHA256="$CALC_SHA"
            break
        fi
    fi
    rm -f "$SOURCE_TAR"
    echo "  Waiting for GitHub release archive generation... (attempt $i/12)"
    sleep 3
done

if [ -z "$SHA256" ]; then
    echo -e "${RED}Error:${NC} Could not download the GitHub archive; refusing to publish an unverified Homebrew checksum."
    exit 1
fi

echo -e "${GREEN}==>${NC} SHA256: ${YELLOW}${SHA256}${NC}"

# 6. Wait for the CI run on this commit and take its static binary
CI_RUN=""
for i in {1..90}; do
    CI_RUN=$(gh run list --repo "$REPO" --commit "$COMMIT_SHA" --workflow ci.yml --branch main --event push --json databaseId --limit 1 --jq '.[0].databaseId // empty' 2>/dev/null || true)
    if [ -n "$CI_RUN" ]; then
        RUN_METADATA=$(gh run view "$CI_RUN" --repo "$REPO" --json status,conclusion,headSha,event,headBranch)
        if ! jq -e --arg sha "$COMMIT_SHA" '.headSha == $sha and .event == "push" and .headBranch == "main"' <<< "$RUN_METADATA" >/dev/null; then
            echo "Error: CI metadata does not match the main push release commit." >&2
            exit 1
        fi
        RUN_STATUS=$(jq -r '.status' <<< "$RUN_METADATA")
        if [ "$RUN_STATUS" = "completed" ]; then
            break
        fi
    fi
    echo "  Waiting for CI on ${COMMIT_SHA}... (attempt $i/90)"
    sleep 20
done

if [ -z "$CI_RUN" ] || [ "${RUN_STATUS:-}" != "completed" ]; then
    echo -e "${RED}Error:${NC} No completed CI run for $COMMIT_SHA; refusing to ship an unbuilt binary."
    exit 1
fi

if [ "$(jq -r '.conclusion' <<< "$RUN_METADATA")" != "success" ]; then
    echo -e "${RED}Error:${NC} CI run $CI_RUN did not pass; refusing to publish its binary."
    exit 1
fi

echo -e "${BLUE}==>${NC} Downloading the static binary from CI run ${CI_RUN}..."
gh run download "$CI_RUN" --repo "$REPO" -n neutron-linux-x86_64 -D "$ASSET_DIR"
if [ ! -s "$ASSET_DIR/neutron" ] || [ -L "$ASSET_DIR/neutron" ]; then
    echo "Error: missing or unsafe CI binary." >&2
    exit 1
fi

BIN_TAR="neutron-${TAG}-linux-x86_64.tar.gz"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --mode=755 -czf "$ASSET_DIR/$BIN_TAR" -C "$ASSET_DIR" neutron
( cd "$ASSET_DIR" && sha256sum "$BIN_TAR" > "neutron-${TAG}-SHA256SUMS" )

# 7. Publish the release page, or leave an existing one untouched on a rerun
require_remote_tag
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    mkdir "$ASSET_DIR/existing"
    gh release download "$TAG" --repo "$REPO" -p "$BIN_TAR" -p "neutron-${TAG}-SHA256SUMS" -D "$ASSET_DIR/existing"
    if ! cmp "$ASSET_DIR/$BIN_TAR" "$ASSET_DIR/existing/$BIN_TAR" ||
       ! cmp "$ASSET_DIR/neutron-${TAG}-SHA256SUMS" "$ASSET_DIR/existing/neutron-${TAG}-SHA256SUMS"; then
        echo "Error: existing release assets do not match the verified CI binary." >&2
        exit 1
    fi
    echo -e "${YELLOW}Notice:${NC} Release $TAG already exists; leaving its notes and assets alone."
else
    echo -e "${BLUE}==>${NC} Publishing release ${TAG}..."
    if [ -n "${2:-}" ]; then
        gh release create "$TAG" --repo "$REPO" --verify-tag --target "$COMMIT_SHA" --title "Neutron $TAG" --notes-file "$2" \
            "$ASSET_DIR/$BIN_TAR" "$ASSET_DIR/neutron-${TAG}-SHA256SUMS"
    else
        gh release create "$TAG" --repo "$REPO" --verify-tag --target "$COMMIT_SHA" --title "Neutron $TAG" --generate-notes \
            "$ASSET_DIR/$BIN_TAR" "$ASSET_DIR/neutron-${TAG}-SHA256SUMS"
    fi
    echo -e "${GREEN}==>${NC} Release ${TAG} published with the static binary and its checksums."
fi

# 8. Update homebrew-tap if available
require_remote_tag
require_tap_main_origin
if [ -d "$TAP_DIR" ] && [ -f "$TAP_DIR/Formula/neutron.rb" ]; then
    echo -e "${BLUE}==>${NC} Updating Homebrew formula in ${TAP_DIR}..."
    cd "$TAP_DIR"

    # Update URL and SHA256 in Formula/neutron.rb
    sed -i "s|url \"https://github.com/PandaBytez/neutron/archive/.*\.tar\.gz\"|url \"${TARBALL_URL}\"|" Formula/neutron.rb
    sed -i "s|sha256 \".*\"|sha256 \"${SHA256}\"|" Formula/neutron.rb
    # Commit archive URLs do not let Homebrew infer the package version.
    if grep -q '^[[:space:]]*version "' Formula/neutron.rb; then
        sed -i "s|version \".*\"|version \"${VERSION}\"|" Formula/neutron.rb
    else
        sed -i "/^[[:space:]]*url /a\\  version \"${VERSION}\"" Formula/neutron.rb
    fi

    if [ -n "$(git status --porcelain)" ]; then
        git add Formula/neutron.rb
        git commit -m "chore(formula): bump neutron to ${TAG}"
        echo -e "${BLUE}==>${NC} Pushing homebrew-tap to origin main..."
        git push origin refs/heads/main:refs/heads/main
        echo -e "${GREEN}==>${NC} homebrew-tap successfully updated and pushed!"
    else
        echo "Homebrew formula was already up to date."
    fi
else
    echo -e "${RED}Error:${NC} homebrew-tap not found at $TAP_DIR"
    echo "Expected a sibling clone, otherwise the tap ships a version behind and nobody notices:"
    echo "  git clone https://github.com/PandaBytez/homebrew-tap $ROOT_DIR/../homebrew-tap"
    exit 1
fi

cd "$ROOT_DIR"
echo ""
echo -e "${GREEN}🎉 Release ${TAG} published successfully!${NC}"
echo -e "   - Release Tag: ${TAG}"
echo -e "   - Release URL:  https://github.com/PandaBytez/neutron/releases/tag/${TAG}"
echo -e "   - Archive URL:  ${TARBALL_URL}"
echo -e "   - SHA256:       ${SHA256}"
echo -e "   - Homebrew:     Updated in homebrew-tap"
