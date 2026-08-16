#!/usr/bin/env bash
# Build libhook.so and mmtls_inject for Android ARM64
# Requires Android NDK; falls back to aarch64-linux-gnu toolchain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}/ndk}"
API=34

# ── Find NDK clang ──────────────────────────────────────────────────────────

find_ndk_clang() {
    local bin="${1}-clang"
    local c
    c=$(find "$NDK_HOME" -name "$bin" 2>/dev/null | sort -V | tail -1)
    echo "$c"
}

CC_LIB=""   # for libhook.so (needs -landroid -llog)
CC_BIN=""   # for mmtls_inject (static binary, no android libs)
SYSROOT=""

NDK_CC=$(find_ndk_clang "aarch64-linux-android${API}" 2>/dev/null || true)
if [ -z "$NDK_CC" ]; then
    NDK_CC=$(find_ndk_clang "aarch64-linux-android" 2>/dev/null || true)
fi

if [ -n "$NDK_CC" ]; then
    echo "[+] NDK clang: $NDK_CC"
    CC_LIB="$NDK_CC"
    CC_BIN="$NDK_CC"
elif command -v aarch64-linux-gnu-gcc &>/dev/null; then
    echo "[+] Fallback: aarch64-linux-gnu-gcc"
    CC_LIB="aarch64-linux-gnu-gcc"
    CC_BIN="aarch64-linux-gnu-gcc"
else
    echo "[!] No ARM64 cross-compiler found."
    echo "    apt install gcc-aarch64-linux-gnu"
    echo "    or install Android NDK via sdkmanager"
    exit 1
fi

# ── libhook.so ──────────────────────────────────────────────────────────────

OUT_LIB="$SCRIPT_DIR/libhook.so"
echo "[+] Building $OUT_LIB ..."

if [ -n "$NDK_CC" ]; then
    $CC_LIB \
        --target=aarch64-linux-android${API} \
        -O2 -fPIC -shared -fvisibility=default \
        -o "$OUT_LIB" \
        "$SCRIPT_DIR/libhook.c" \
        -llog
else
    # GNU toolchain — -landroid not available; stub out android/log.h
    $CC_LIB \
        -O2 -fPIC -shared -fvisibility=default \
        -Wl,--hash-style=sysv \
        -o "$OUT_LIB" \
        "$SCRIPT_DIR/libhook.c" \
        -Wl,--no-as-needed \
        -DANDROID_LOG_STUB
fi

echo "[✓] $OUT_LIB  ($(file "$OUT_LIB" | grep -o 'ARM aarch64[^,]*'))"

# ── mmtls_inject ────────────────────────────────────────────────────────────

OUT_BIN="$SCRIPT_DIR/mmtls_inject"
echo "[+] Building $OUT_BIN ..."

if [ -n "$NDK_CC" ]; then
    $CC_BIN \
        --target=aarch64-linux-android${API} \
        -O2 -static \
        -o "$OUT_BIN" \
        "$SCRIPT_DIR/mmtls_inject.c"
else
    $CC_BIN \
        -O2 -static \
        -Wl,--hash-style=sysv \
        -o "$OUT_BIN" \
        "$SCRIPT_DIR/mmtls_inject.c"
fi

echo "[✓] $OUT_BIN  ($(file "$OUT_BIN" | grep -o 'ARM aarch64[^,]*'))"

echo ""
echo "Deploy:"
echo "  adb push $OUT_LIB /data/local/tmp/libhook.so"
echo "  adb push $OUT_BIN /data/local/tmp/mmtls_inject"
echo "  adb shell chmod 755 /data/local/tmp/mmtls_inject"
echo ""
echo "Inject (WeChat must already be running with LD_PRELOAD=libhook.so):"
echo '  PID=$(adb shell pidof com.tencent.mm | tr -d "\r")'
echo '  adb shell /data/local/tmp/mmtls_inject $PID'
echo ""
echo "Key-only dump (no hooks installed):"
echo '  adb shell /data/local/tmp/mmtls_inject $PID --dump-key-only'
echo ""
echo "Monitor hook output:"
echo "  adb logcat -s mmhook"
