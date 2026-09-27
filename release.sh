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

if [ $# -lt 1 ]; then
    echo -e "${RED}Error:${NC} Version/tag argument required."
    echo "Usage: ./release.sh <tag> [notes-file] (e.g. ./release.sh v0.1.0 or ./release --v0.1.0)"
    echo "  With a notes file the release uses it verbatim; without one, GitHub generates notes."
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    echo -e "${RED}Error:${NC} gh is required (release page and CI artifact download)."
    exit 1
fi

RAW_TAG="$1"
TAG="${RAW_TAG#--}"
if [[ ! "$TAG" =~ ^v ]]; then
    TAG="v$TAG"
fi
VERSION="${TAG#v}"

echo -e "${BLUE}==>${NC} Preparing release for ${GREEN}${TAG}${NC} (version: ${VERSION})"

# 1. Verify working directory is clean
cd "$ROOT_DIR"
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}Warning:${NC} Working tree has uncommitted changes:"
    git status -s
    read -rp "Do you want to stage and commit these changes as a pre-release commit? [y/N] " confirm
    if [[ "$confirm" =~ ^[yY] ]]; then
        git add -A
        git commit -m "chore: prepare release ${TAG}"
    else
        echo -e "${RED}Aborting release.${NC} Please commit or stash changes first."
        exit 1
    fi
fi

# 2. Update Cargo.toml version if different
CURRENT_CARGO_VER=$(grep -m1 '^version =' Cargo.toml | cut -d '"' -f2)
if [ "$CURRENT_CARGO_VER" != "$VERSION" ]; then
    echo -e "${BLUE}==>${NC} Bumping Cargo.toml version from ${CURRENT_CARGO_VER} to ${VERSION}..."
    sed -i "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
    cargo check --quiet
    git add Cargo.toml Cargo.lock
    git commit -m "chore: bump version to $VERSION"
fi

# 3. Tag release locally
echo -e "${BLUE}==>${NC} Tagging ${TAG}..."
if git rev-parse --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "Reusing existing tag $TAG."
else
    git tag -a "$TAG" -m "Release $TAG"
fi

# 4. Push main branch AND tag together in a single network operation
echo -e "${BLUE}==>${NC} Pushing main branch and ${TAG} to origin..."
git push --atomic origin main "$TAG"

# 5. Calculate SHA256 of the release archive
TARBALL_URL="https://github.com/PandaBytez/neutron/archive/refs/tags/${TAG}.tar.gz"
echo -e "${BLUE}==>${NC} Fetching archive checksum for ${TARBALL_URL}..."

SHA256=""
EMPTY_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

for i in {1..12}; do
    TMP_TAR="/tmp/neutron-${TAG}.tar.gz"
    HTTP_CODE=$(curl -sL -w "%{http_code}" "$TARBALL_URL" -o "$TMP_TAR" || true)

    if [ "$HTTP_CODE" = "200" ] && [ -s "$TMP_TAR" ]; then
        CALC_SHA=$(sha256sum "$TMP_TAR" | awk '{print $1}')
        if [ "$CALC_SHA" != "$EMPTY_SHA" ]; then
            SHA256="$CALC_SHA"
            rm -f "$TMP_TAR"
            break
        fi
    fi
    rm -f "$TMP_TAR"
    echo "  Waiting for GitHub release archive generation... (attempt $i/12)"
    sleep 3
done

if [ -z "$SHA256" ]; then
    echo -e "${RED}Error:${NC} Could not download the GitHub archive; refusing to publish an unverified Homebrew checksum."
    exit 1
fi

echo -e "${GREEN}==>${NC} SHA256: ${YELLOW}${SHA256}${NC}"

# 6. Wait for the CI run on this commit and take its static binary
COMMIT_SHA="$(git rev-parse HEAD)"
CI_RUN=""
for i in {1..90}; do
    CI_RUN=$(gh run list --commit "$COMMIT_SHA" --workflow CI --json databaseId --limit 1 --jq '.[0].databaseId // empty' 2>/dev/null || true)
    if [ -n "$CI_RUN" ]; then
        RUN_STATUS=$(gh run view "$CI_RUN" --json status --jq '.status')
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

if [ "$(gh run view "$CI_RUN" --json conclusion --jq '.conclusion')" != "success" ]; then
    echo -e "${RED}Error:${NC} CI run $CI_RUN did not pass; refusing to publish its binary."
    exit 1
fi

echo -e "${BLUE}==>${NC} Downloading the static binary from CI run ${CI_RUN}..."
ASSET_DIR="$(mktemp -d)"
trap 'rm -rf "$ASSET_DIR"' EXIT
gh run download "$CI_RUN" -n neutron-linux-x86_64 -D "$ASSET_DIR"

BIN_TAR="neutron-${TAG}-linux-x86_64.tar.gz"
tar -czf "$ASSET_DIR/$BIN_TAR" -C "$ASSET_DIR" neutron
( cd "$ASSET_DIR" && sha256sum "$BIN_TAR" > "neutron-${TAG}-SHA256SUMS" )

# 7. Publish the release page, or leave an existing one untouched on a rerun
if gh release view "$TAG" >/dev/null 2>&1; then
    echo -e "${YELLOW}Notice:${NC} Release $TAG already exists; leaving its notes and assets alone."
else
    echo -e "${BLUE}==>${NC} Publishing release ${TAG}..."
    if [ -n "${2:-}" ]; then
        gh release create "$TAG" --title "Neutron $TAG" --notes-file "$2" \
            "$ASSET_DIR/$BIN_TAR" "$ASSET_DIR/neutron-${TAG}-SHA256SUMS"
    else
        gh release create "$TAG" --title "Neutron $TAG" --generate-notes \
            "$ASSET_DIR/$BIN_TAR" "$ASSET_DIR/neutron-${TAG}-SHA256SUMS"
    fi
    echo -e "${GREEN}==>${NC} Release ${TAG} published with the static binary and its checksums."
fi

# 8. Update homebrew-tap if available
if [ -d "$TAP_DIR" ] && [ -f "$TAP_DIR/Formula/neutron.rb" ]; then
    echo -e "${BLUE}==>${NC} Updating Homebrew formula in ${TAP_DIR}..."
    cd "$TAP_DIR"

    # Update URL and SHA256 in Formula/neutron.rb
    sed -i "s|url \"https://github.com/PandaBytez/neutron/archive/refs/tags/.*\.tar\.gz\"|url \"${TARBALL_URL}\"|" Formula/neutron.rb
    sed -i "s|sha256 \".*\"|sha256 \"${SHA256}\"|" Formula/neutron.rb

    if [ -n "$(git status --porcelain)" ]; then
        git add Formula/neutron.rb
        git commit -m "chore(formula): bump neutron to ${TAG}"
        echo -e "${BLUE}==>${NC} Pushing homebrew-tap to origin main..."
        git push origin main
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
