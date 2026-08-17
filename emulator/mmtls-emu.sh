#!/usr/bin/env bash
# mmtls-emu — Custom Android 14 ARM64 launcher
# Uses system QEMU (/usr/bin/qemu-system-aarch64) with virt machine type.
# Full control. No Google emulator frontend. Root via adb.
set -euo pipefail

QEMU=/usr/bin/qemu-system-aarch64
SDK="$HOME/Android/Sdk"
IMG_DIR="$SDK/system-images/android-34/google_apis/arm64-v8a"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VMDIR="$SCRIPT_DIR/../vm"

KERNEL="$SCRIPT_DIR/bin/kernel-ranchu-patched.gz"
SYSTEM="$IMG_DIR/system.img"
VENDOR="$SCRIPT_DIR/vendor-custom.img"   # patched fstab (a003c00→a000600)
USERDATA="$VMDIR/userdata.img"
ENCRYPTION="$IMG_DIR/encryptionkey.img"  # has "metadata" partition at slot 3
INITRD="$VMDIR/ramdisk-custom.img"       # stock ramdisk + our bootconfig

# Build the custom initrd if not present or stale
if [ ! -f "$INITRD" ] || [ "$SCRIPT_DIR/make-initrd.py" -nt "$INITRD" ]; then
    echo "[+] Generating ramdisk-custom.img..."
    python3 "$SCRIPT_DIR/make-initrd.py"
fi

# Fresh userdata copy
if [ ! -f "$USERDATA" ] || [[ "${1:-}" == "--wipe" ]]; then
    echo "[+] Initialising userdata..."
    cp "$IMG_DIR/userdata.img" "$USERDATA"
fi

echo "[+] mmtls-emu: Android 14 ARM64 on system QEMU (virt machine)"
echo "    CPU          : cortex-a76 (ARMv8.2, PSCI, all 4 cores)"
echo "    Serial       : telnet localhost 5556   (kernel + init output)"
echo "    QEMU monitor : telnet localhost 5557"
echo "    ADB          : adb connect localhost:5555"
echo ""
echo "    Once booted:"
echo "    adb -s localhost:5555 root"
echo "    adb -s localhost:5555 shell"

exec "$QEMU" \
    -machine  virt,gic-version=3 \
    -cpu      cortex-a76 \
    -smp      4 \
    -m        4096 \
    -kernel   "$KERNEL" \
    -initrd   "$INITRD" \
    -append   "console=ttyAMA0,38400 earlyprintk=ttyAMA0 keep_bootcon kvm-arm.mode=none kasan.mode=off no_timer_check loop.max_part=7 printk.devkmsg=on bootconfig" \
    \
    -drive    file="$SYSTEM",if=none,id=sys,format=raw,read-only=on \
    -device   virtio-blk-device,drive=sys \
    \
    -drive    file="$VENDOR",if=none,id=vnd,format=raw,read-only=on \
    -device   virtio-blk-device,drive=vnd \
    \
    -drive    file="$USERDATA",if=none,id=data,format=raw \
    -device   virtio-blk-device,drive=data \
    \
    -drive    file="$ENCRYPTION",if=none,id=enc,format=raw \
    -device   virtio-blk-device,drive=enc \
    \
    -device   virtio-net-device,netdev=net0 \
    -netdev   user,id=net0,hostfwd=tcp::5555-:5555 \
    \
    -serial   telnet:127.0.0.1:5556,server,nowait \
    -monitor  telnet:127.0.0.1:5557,server,nowait \
    -nographic \
    -nodefaults \
    "$@"
