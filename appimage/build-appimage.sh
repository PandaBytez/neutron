#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARCH="${ARCH:-$(uname -m)}"
APP_NAME="Neutron-VPN"
APP_ID="io.gitlab.neutron_vpn.neutron"
OUTPUT_APPIMAGE="${REPO_ROOT}/${APP_NAME}-${ARCH}.AppImage"
BUILD_DIR="${REPO_ROOT}/target/appimage"
APPDIR="${BUILD_DIR}/AppDir"

echo "==> Building ${APP_NAME} binary (release with gui feature)..."
if pkg-config --exists gtk4 libadwaita-1 2>/dev/null; then
    cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" --release --features gui
elif command -v flatpak >/dev/null 2>&1 && flatpak info org.gnome.Sdk//49 >/dev/null 2>&1; then
    echo "==> Host missing GTK4/Adwaita headers (immutable/atomic host). Building via GNOME SDK container..."
    flatpak run --filesystem=host --env=PATH=/usr/lib/sdk/rust-stable/bin:/usr/bin --command=sh org.gnome.Sdk//49 -c \
        "cargo build --manifest-path=\"${REPO_ROOT}/Cargo.toml\" --release --features gui"
else
    echo "==> Building with host toolchain..."
    cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" --release --features gui
fi

echo "==> Staging AppDir at ${APPDIR}..."
rm -rf "${APPDIR}"
mkdir -p \
    "${APPDIR}/usr/bin" \
    "${APPDIR}/usr/share/applications" \
    "${APPDIR}/usr/share/metainfo" \
    "${APPDIR}/usr/share/icons/hicolor/scalable/apps"

# Install main binary
cp "${REPO_ROOT}/target/release/neutron-vpn" "${APPDIR}/usr/bin/neutron-vpn"
chmod +x "${APPDIR}/usr/bin/neutron-vpn"

# Install desktop entry
cp "${REPO_ROOT}/resources/${APP_ID}.desktop" "${APPDIR}/${APP_ID}.desktop"
cp "${REPO_ROOT}/resources/${APP_ID}.desktop" "${APPDIR}/usr/share/applications/${APP_ID}.desktop"

# Install icon (SVG and standard PNG sizes)
cp "${REPO_ROOT}/resources/${APP_ID}.svg" "${APPDIR}/${APP_ID}.svg"
cp "${REPO_ROOT}/resources/${APP_ID}.svg" "${APPDIR}/usr/share/icons/hicolor/scalable/apps/${APP_ID}.svg"

echo "==> Staging PNG icon resolutions for desktop integration..."
for size in 16 24 32 48 64 128 256 512; do
    icon_dir="${APPDIR}/usr/share/icons/hicolor/${size}x${size}/apps"
    mkdir -p "${icon_dir}"
    cp "${REPO_ROOT}/resources/icons/${size}x${size}.png" "${icon_dir}/${APP_ID}.png"
done

# Tray status shields. Also installed into ~/.local/share at runtime, since the
# StatusNotifierItem protocol passes only an icon name for the shell to resolve.
for state in connected disconnected; do
    cp "${REPO_ROOT}/resources/status/neutron-vpn-${state}.svg" \
        "${APPDIR}/usr/share/icons/hicolor/scalable/apps/neutron-vpn-${state}.svg"
    for size in 16 24 32 48; do
        cp "${REPO_ROOT}/resources/status/${state}_${size}.png" \
            "${APPDIR}/usr/share/icons/hicolor/${size}x${size}/apps/neutron-vpn-${state}.png"
    done
done

# appimagetool takes the tray/file-manager thumbnail from .DirIcon, and AppImage
# integrators extract it as the launcher icon, so it must be a raster image they
# can load without relying on the file extension.
cp "${REPO_ROOT}/resources/icons/256x256.png" "${APPDIR}/.DirIcon"
cp "${REPO_ROOT}/resources/icons/512x512.png" "${APPDIR}/${APP_ID}.png"

# Install AppStream metadata
if [ -f "${REPO_ROOT}/resources/${APP_ID}.metainfo.xml" ]; then
    cp "${REPO_ROOT}/resources/${APP_ID}.metainfo.xml" "${APPDIR}/usr/share/metainfo/${APP_ID}.metainfo.xml"
fi

# Install AppRun script
cp "${SCRIPT_DIR}/AppRun" "${APPDIR}/AppRun"
chmod +x "${APPDIR}/AppRun"

# Locate or download appimagetool
APPIMAGETOOL=""
if command -v appimagetool >/dev/null 2>&1; then
    APPIMAGETOOL="$(command -v appimagetool)"
    echo "==> Using system appimagetool at ${APPIMAGETOOL}"
else
    TOOL_DIR="${BUILD_DIR}/tools"
    mkdir -p "${TOOL_DIR}"
    APPIMAGETOOL="${TOOL_DIR}/appimagetool-${ARCH}.AppImage"
    if [ ! -f "${APPIMAGETOOL}" ]; then
        echo "==> Downloading appimagetool for ${ARCH}..."
        TOOL_URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage"
        curl -fsSL "${TOOL_URL}" -o "${APPIMAGETOOL}"
        chmod +x "${APPIMAGETOOL}"
    fi
fi

echo "==> Generating AppImage: ${OUTPUT_APPIMAGE}..."
export ARCH="${ARCH}"
export APPIMAGE_EXTRACT_AND_RUN=1

NO_APPSTREAM_FLAG=""
if ! command -v appstreamcli >/dev/null 2>&1 && ! command -v appstream-util >/dev/null 2>&1; then
    NO_APPSTREAM_FLAG="--no-appstream"
fi

"${APPIMAGETOOL}" ${NO_APPSTREAM_FLAG} "${APPDIR}" "${OUTPUT_APPIMAGE}"

echo "==> AppImage created successfully: ${OUTPUT_APPIMAGE}"
