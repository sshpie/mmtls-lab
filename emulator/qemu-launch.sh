#!/usr/bin/env bash
# Launch Android 14 ARM64 via the Google-patched QEMU binary directly
# (bypasses the emulator wrapper's cross-arch check)
set -euo pipefail

SDK="$HOME/Android/Sdk"
QEMU="$SDK/emulator/qemu/linux-x86_64/qemu-system-aarch64-patched"
IMG_DIR="$SDK/system-images/android-34/google_apis/arm64-v8a"
VMDIR="$(cd "$(dirname "$0")/../vm" && pwd)"

export LD_LIBRARY_PATH="$SDK/emulator/lib64:$SDK/emulator/lib64/qt/lib"

# Userdata must be writable; keep a working copy in VMDIR
if [ ! -f "$VMDIR/userdata.img" ] || [[ "${1:-}" == "--wipe" ]]; then
    echo "[+] (Re)initialising userdata..."
    cp "$IMG_DIR/userdata.img" "$VMDIR/userdata.img"
fi

# Clean up stale qcow2 overlays (emulator puts them in sysdir by default)
rm -f "$IMG_DIR"/*.qcow2 "$VMDIR"/*.qcow2 2>/dev/null || true

echo "[+] Launching Android 14 ARM64 (ARM64 emulation — slow boot, ~5-10 min)"
echo "    Once booted:  adb connect localhost:5554"
echo "    Or:           adb -s emulator-5554 shell"

exec "$QEMU" \
    -sysdir "$IMG_DIR" \
    -system "$IMG_DIR/system.img" \
    -vendor "$IMG_DIR/vendor.img" \
    -datadir "$VMDIR" \
    -data "$VMDIR/userdata.img" \
    -initdata "$IMG_DIR/userdata.img" \
    -kernel "$IMG_DIR/kernel-ranchu" \
    -ramdisk "$IMG_DIR/ramdisk.img" \
    -memory 4096 \
    -cores 4 \
    -no-window \
    -no-audio \
    -no-accel \
    -gpu off \
    -port 5554 \
    -no-metrics \
    -no-snapshot \
    -writable-system \
    -show-kernel \
    -feature -VirtioSndCard \
    -feature -AudioCapture \
    -feature -AudioPlayback \
    "$@"
