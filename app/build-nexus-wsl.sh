#!/bin/sh
# Project-local libnx keeps this build independent of the shared SDK version.
set -eu
app=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export DEVKITPRO=${DEVKITPRO:-/opt/devkitpro}
export DEVKITA64=${DEVKITA64:-$DEVKITPRO/devkitA64}
export LIBNX=${LIBNX:-$app/../dependencies/sdk/libnx}
export NEXUS_GRAPHICS=${NEXUS_GRAPHICS:-$app/../dependencies/sdk/graphics}
export PATH="$DEVKITA64/bin:$DEVKITPRO/tools/bin:$DEVKITPRO/portlibs/switch/bin:$PATH"
build=${NEXUS_BUILD_DIR:-$app/build/NexusPorts}
jobs=${NEXUS_BUILD_JOBS:-2}
if [ ! -f "$LIBNX/lib/libnx.a" ] || ! grep -q 'lang_data' "$LIBNX/include/switch/nacp.h"; then
  echo 'Compatible project-local libnx is missing. Run tools/setup-libnx.sh first.' >&2
  exit 1
fi
cmake -S "$app" -B "$build" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$app/cmake/NexusSwitch.cmake" \
  -Dnexus_deko_include="$NEXUS_GRAPHICS/include" \
  -Ddeko3d_lib="$NEXUS_GRAPHICS/lib/libdeko3d.a" \
  -DCMAKE_BUILD_TYPE=MinSizeRel -DLTO=OFF \
  -DFETCHCONTENT_UPDATES_DISCONNECTED=ON -DFETCHCONTENT_FULLY_DISCONNECTED="${NEXUS_OFFLINE:-ON}" \
  -DENABLE_LIBUSBHSFS=OFF -DENABLE_LIBUSBDVD=OFF -DENABLE_NTFS=OFF -DENABLE_EXT4=OFF \
  -DENABLE_LIBHAZE=OFF -DENABLE_FTPSRV=OFF \
  -DENABLE_DEVOPTAB_NFS=ON -DENABLE_DEVOPTAB_SMB2=ON -DENABLE_DEVOPTAB_SFTP=OFF \
  -DENABLE_DEVOPTAB_WEBDAV=OFF -DENABLE_DEVOPTAB_FTP=OFF -DENABLE_DEVOPTAB_HTTP=OFF \
  -DENABLE_AUDIO_MP3=OFF -DENABLE_AUDIO_OGG=OFF -DENABLE_AUDIO_WAV=OFF -DENABLE_AUDIO_FLAC=OFF \
  -DNEXUS_REPORT_CONFIG_DIR="${NEXUS_REPORT_CONFIG_DIR:-}" \
  -DNEXUS_BUNDLED_PROBE=OFF -DNEXUS_PRIVATE_KEY_INCLUDE_DIR= \
  -Dsphaira_VERSION_OVERRIDE="${NEXUS_VERSION:-0.2.28-smb.1}"
if [ "${1:-}" != '--configure-only' ]; then
  cmake --build "$build" --parallel "$jobs" --target sphaira_nro
fi
