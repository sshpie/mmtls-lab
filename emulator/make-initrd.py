#!/usr/bin/env python3
"""
Generates a custom ramdisk (initrd) with an appended bootconfig block
for the mmtls-emu custom QEMU launcher.

Output: vm/ramdisk-custom.img
"""
import struct, os, sys

RAMDISK_SRC = os.path.expanduser(
    "~/Android/Sdk/system-images/android-34/google_apis/arm64-v8a/ramdisk.img"
)
OUT_DIR = os.path.expanduser("~/mmtls-lab/vm")
OUT_FILE = os.path.join(OUT_DIR, "ramdisk-custom.img")
ADB_KEY_FILE = os.path.expanduser("~/.android/adbkey.pub")

with open(ADB_KEY_FILE) as f:
    adb_key = f.read().strip()

# Bootconfig text — key = value pairs, one per line
# androidboot.boot_devices must match slot 0 of the virt machine (a000000.virtio_mmio)
BOOTCONFIG = f"""\
androidboot.hardware = ranchu
androidboot.qemu = 1
androidboot.boot_devices = a000000.virtio_mmio
androidboot.serialno = EMULATOR1
androidboot.verifiedbootstate = orange
androidboot.logcat = *:V
androidboot.adb.pubkey = {adb_key}
androidboot.qemu.adb.pubkey = {adb_key}
androidboot.qemu.avd_name = mmtls
androidboot.qemu.virtiowifi = 0
androidboot.qemu.vsync = 60
androidboot.qemu.camera_hq_edge_processing = 0
androidboot.qemu.camera_protocol_ver = 1
androidboot.qemu.gltransport.name = pipe
androidboot.qemu.gltransport.drawFlushInterval = 800
androidboot.qemu.hwcodec.avcdec = 2
androidboot.qemu.hwcodec.hevcdec = 2
androidboot.qemu.hwcodec.vpxdec = 2
androidboot.qemu.settings.system.screen_off_timeout = 2147483647
androidboot.qemu.skin = HVGA
androidboot.dalvik.vm.heapsize = 576m
androidboot.debug.hwui.renderer = skiagl
androidboot.opengles.version = 196608
androidboot.vbmeta.hash_alg = sha256
androidboot.vbmeta.size = 6656
androidboot.vbmeta.digest = 7d083757a5e20cd0c568182e509f6d02da844505ce73ef80b2f1ada3f02ae18c
"""

text = BOOTCONFIG.encode()
size = len(text)
checksum = sum(text) & 0xFFFFFFFF
magic = b"#BOOTCONFIG\n"

footer = struct.pack("<II", size, checksum) + magic

with open(RAMDISK_SRC, "rb") as f:
    ramdisk = f.read()

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, "wb") as f:
    f.write(ramdisk)
    f.write(text)
    f.write(footer)

total = len(ramdisk) + len(text) + len(footer)
print(f"ramdisk: {len(ramdisk)} bytes")
print(f"bootconfig text: {size} bytes, checksum: 0x{checksum:08x}")
print(f"total initrd: {total} bytes → {OUT_FILE}")
