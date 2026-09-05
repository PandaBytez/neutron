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

# Enable in-memory credential caching for this session so credentials
# are entered at most once and shared across neutron and homebrew-tap pushes.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="credential.helper"
export GIT_CONFIG_VALUE_0="cache --timeout=900"

# Pre-seed credentials if GITHUB_TOKEN is available in the environment
if [ -n "${GITHUB_TOKEN:-}" ]; then
    printf "protocol=https\nhost=github.com\nusername=PandaBytez\npassword=%s\n\n" "$GITHUB_TOKEN" | git credential approve 2>/dev/null || true
fi

if [ $# -lt 1 ]; then
    echo -e "${RED}Error:${NC} Version/tag argument required."
    echo "Usage: ./release.sh <tag> (e.g. ./release.sh v0.1.0 or ./release --v0.1.0)"
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
git tag -fa "$TAG" -m "Release $TAG"

# 4. Push main branch AND tag together in a single network operation
echo -e "${BLUE}==>${NC} Pushing main branch and ${TAG} to origin..."
git push origin main "$TAG" --force

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
    echo -e "${YELLOW}Notice:${NC} Could not download public GitHub tarball directly (repo may be private or generating)."
    echo "Generating archive checksum from local git tree..."
    TMP_LOCAL="/tmp/neutron-local-${TAG}.tar.gz"
    git archive --format=tar.gz --prefix="neutron-${VERSION}/" "$TAG" -o "$TMP_LOCAL"
    SHA256=$(sha256sum "$TMP_LOCAL" | awk '{print $1}')
    rm -f "$TMP_LOCAL"
fi

echo -e "${GREEN}==>${NC} SHA256: ${YELLOW}${SHA256}${NC}"

# 6. Update homebrew-tap if available
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
    echo -e "${YELLOW}Notice:${NC} homebrew-tap repository not found at $TAP_DIR. Skipping tap update."
fi

cd "$ROOT_DIR"
echo ""
echo -e "${GREEN}🎉 Release ${TAG} published successfully!${NC}"
echo -e "   - Release Tag: ${TAG}"
echo -e "   - Archive URL: ${TARBALL_URL}"
echo -e "   - SHA256:      ${SHA256}"
echo -e "   - Homebrew:    Updated in homebrew-tap"
