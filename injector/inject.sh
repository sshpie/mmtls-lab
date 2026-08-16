#!/usr/bin/env bash
# Deploy libhook.so + mmtls_inject and activate hooks in a running WeChat instance.
# Run AFTER launch.sh has started the emulator and WeChat is open.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

LIB="$SCRIPT_DIR/libhook.so"
INJ="$SCRIPT_DIR/mmtls_inject"

if [ ! -f "$LIB" ] || [ ! -f "$INJ" ]; then
    echo "[!] Binaries not found — run build.sh first."
    exit 1
fi

echo "[+] Pushing binaries..."
adb push "$LIB" /data/local/tmp/libhook.so
adb push "$INJ" /data/local/tmp/mmtls_inject
adb shell chmod 755 /data/local/tmp/mmtls_inject

# Ensure LD_PRELOAD prop is set so libhook.so loads on WeChat (re)start
adb shell setprop wrap.com.tencent.mm 'LD_PRELOAD=/data/local/tmp/libhook.so'
echo "[+] wrap.com.tencent.mm set."

# Check if WeChat is running
PID=$(adb shell "pidof com.tencent.mm 2>/dev/null || true" | tr -d '\r\n ')
if [ -z "$PID" ]; then
    echo "[!] WeChat not running."
    echo "    Start WeChat on the emulator, then re-run this script."
    echo "    (libhook.so will load automatically on next launch.)"
    exit 0
fi

echo "[+] WeChat PID=$PID"

# Verify libhook.so is in the process map
MAPPED=$(adb shell "grep libhook /proc/$PID/maps 2>/dev/null | head -1" | tr -d '\r')
if [ -z "$MAPPED" ]; then
    echo "[!] libhook.so not yet mapped in WeChat (force-stop and relaunch)."
    echo "    Force-stopping WeChat..."
    adb shell am force-stop com.tencent.mm
    sleep 2
    echo "[i] Relaunch WeChat from the emulator UI, then re-run inject.sh."
    exit 0
fi
echo "[+] libhook.so is mapped: $MAPPED"

# Run injector
echo "[+] Running mmtls_inject $PID ..."
adb shell /data/local/tmp/mmtls_inject "$PID"

echo ""
echo "[✓] Hooks active. Monitor with:"
echo "    adb logcat -s mmhook"
echo ""
echo "Key-only dump (no hooks installed, safe to run anytime):"
echo "    adb shell /data/local/tmp/mmtls_inject $PID --dump-key-only"
