#!/usr/bin/env bash
# Build mmtls_hide.so for Android ARM64
# Requires Android NDK or aarch64-linux-gnu cross toolchain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/mmtls_hide.so"
SRC="$SCRIPT_DIR/mmtls_hide.c"

# ── Find compiler ────────────────────────────────────────────────────────────
# Priority: NDK clang → aarch64-linux-android-clang → aarch64-linux-gnu-gcc

NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}/ndk}"
API=34

find_ndk_clang() {
    # NDK may be at $NDK_HOME/<version>/... or $NDK_HOME directly
    local candidates
    candidates=$(find "$NDK_HOME" -name "aarch64-linux-android${API}-clang" 2>/dev/null | head -1)
    if [ -z "$candidates" ]; then
        candidates=$(find "$NDK_HOME" -name "aarch64-linux-android*-clang" 2>/dev/null | sort -V | tail -1)
    fi
    echo "$candidates"
}

CC=""
LDFLAGS="-shared -fPIC -ldl"
CFLAGS="-O2 -fvisibility=default -fPIC"

NDK_CLANG=$(find_ndk_clang 2>/dev/null || true)
if [ -n "$NDK_CLANG" ]; then
    echo "[+] Using NDK: $NDK_CLANG"
    CC="$NDK_CLANG"
    CFLAGS="$CFLAGS --target=aarch64-linux-android${API}"
elif command -v aarch64-linux-android-clang &>/dev/null; then
    echo "[+] Using aarch64-linux-android-clang"
    CC="aarch64-linux-android-clang"
elif command -v aarch64-linux-gnu-gcc &>/dev/null; then
    echo "[+] Using aarch64-linux-gnu-gcc (glibc target — ok for AOSP)"
    CC="aarch64-linux-gnu-gcc"
    LDFLAGS="$LDFLAGS -Wl,--hash-style=sysv"
else
    echo "[!] No ARM64 cross compiler found."
    echo "    Install NDK: sdkmanager \"ndk;$(ls $NDK_HOME 2>/dev/null | tail -1 || echo '26.3.11579264')\""
    echo "    Or: apt install gcc-aarch64-linux-gnu"
    exit 1
fi

echo "[+] Building $OUT..."
$CC $CFLAGS -o "$OUT" "$SRC" $LDFLAGS
echo "[✓] Built: $OUT ($(file "$OUT" | grep -o 'ARM aarch64[^,]*'))"

echo ""
echo "Deploy:"
echo "  adb push $OUT /data/local/tmp/mmtls_hide.so"
echo "  adb shell chmod 755 /data/local/tmp/mmtls_hide.so"
echo "  adb shell setprop wrap.com.tencent.mm 'LD_PRELOAD=/data/local/tmp/mmtls_hide.so'"
echo "  # Force-stop and relaunch WeChat for the prop to take effect"
echo "  adb shell am force-stop com.tencent.mm"
