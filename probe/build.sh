#!/usr/bin/env bash
# Build mmtls_probe for Android ARM64
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/mmtls_probe"

NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}/ndk}"
API=34

NDK_CC=$(find "$NDK_HOME" -name "aarch64-linux-android${API}-clang" 2>/dev/null | sort -V | tail -1 || true)
if [ -z "$NDK_CC" ]; then
    NDK_CC=$(find "$NDK_HOME" -name "aarch64-linux-android-clang" 2>/dev/null | sort -V | tail -1 || true)
fi

if [ -n "$NDK_CC" ]; then
    echo "[+] NDK clang: $NDK_CC"
    "$NDK_CC" --target=aarch64-linux-android${API} -O2 -static -Wall -o "$OUT" "$SCRIPT_DIR/mmtls_probe.c"
elif command -v aarch64-linux-gnu-gcc &>/dev/null; then
    echo "[+] aarch64-linux-gnu-gcc"
    aarch64-linux-gnu-gcc -O2 -static -Wall -o "$OUT" "$SCRIPT_DIR/mmtls_probe.c"
else
    echo "[!] no ARM64 cross-compiler"; exit 1
fi

echo "[✓] $OUT  ($(file "$OUT" | grep -o 'ARM aarch64[^,]*'))"
echo ""
echo "Deploy:"
echo "  adb push $OUT /data/local/tmp/mmtls_probe"
echo "  adb shell chmod 755 /data/local/tmp/mmtls_probe"
echo ""
echo "Usage (on device as root):"
echo "  adb shell /data/local/tmp/mmtls_probe discover"
echo "  adb shell /data/local/tmp/mmtls_probe hook 0x<writer_pc>"
echo "  adb shell /data/local/tmp/mmtls_probe dump"
