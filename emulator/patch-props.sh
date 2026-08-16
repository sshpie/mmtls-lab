#!/system/bin/sh
# Run on emulator via adb shell after boot — fakes real Pixel 4 identity
mount -o rw,remount /system 2>/dev/null || true

# Device identity
resetprop ro.product.manufacturer Google
resetprop ro.product.model "Pixel 4"
resetprop ro.product.name flame
resetprop ro.product.device flame
resetprop ro.product.board flame
resetprop ro.product.brand google

# Hardware — goldfish/ranchu are instant detection; qcom is realistic
resetprop ro.hardware qcom
resetprop ro.hardware.chipname SM8150

# Build — test-keys and userdebug are emulator tells
resetprop ro.build.fingerprint "google/flame/flame:12/SP2A.220505.002/8353555:user/release-keys"
resetprop ro.build.type user
resetprop ro.build.tags release-keys
resetprop ro.debuggable 0
resetprop ro.secure 1

# Telephony — 000000000000000 IMEI and "Android" operator are dead giveaways
# Hook via Frida instead of prop (IMEI not in props); but operator name is:
resetprop gsm.sim.operator.alpha "T-Mobile"
resetprop gsm.operator.alpha "T-Mobile"
resetprop gsm.operator.numeric "310260"
resetprop gsm.sim.operator.numeric "310260"

# Hide emulator-specific device nodes from app-level checks
# (native checks via open() need Frida hooks; these cover getprop-based checks)
resetprop ro.kernel.qemu 0
resetprop ro.kernel.qemu.gles 0
