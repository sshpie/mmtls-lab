#!/usr/bin/env bash
export ANDROID_SDK_ROOT="/home/cowboy/Android/Sdk"
export PATH="/home/cowboy/Android/Sdk/cmdline-tools/latest/bin:/home/cowboy/Android/Sdk/platform-tools:/home/cowboy/Android/Sdk/emulator:$PATH"

echo "[+] Starting wechat-mmtls-lab..."
emulator -avd "wechat-mmtls-lab" \
    -no-snapshot-save \
    -writable-system \
    -no-boot-anim \
    -wipe-data \
    -netdelay none \
    -netspeed full \
    -gpu swiftshader_indirect \
    -memory 4096 \
    &
EMULATOR_PID=$!

echo "[+] Waiting for boot (ARM64 emulation = slow, ~5 min)..."
adb wait-for-device
until adb shell getprop sys.boot_completed 2>/dev/null | grep -q "^1"; do
    sleep 5
done
echo "[+] Boot complete."

# Root setup
adb root || true
sleep 2
adb remount || true

# Apply prop patches
adb push "/home/cowboy/mmtls-lab/emulator/patch-props.sh" /data/local/tmp/
adb shell sh /data/local/tmp/patch-props.sh
echo "[+] Props patched."

# Remove emulator-specific device nodes that can't be hidden via props.
# Native code (open("/dev/qemu_pipe")) would bypass any property spoof.
# We have root + writable system — just delete them.
for node in /dev/qemu_pipe /dev/socket/qemud /dev/qemu_trace /sys/qemu_trace; do
    adb shell "rm -rf $node 2>/dev/null || true"
done
echo "[+] Emulator device nodes removed."

# SELinux enforcing mode blocks iptables NAT rules — must set permissive first
adb shell setenforce 0
echo "[+] SELinux → permissive."

# Prefer UID-based targeting so system traffic on port 80 is not intercepted.
# Fall back to port-based if WeChat is not yet installed.
WECHAT_UID=$(adb shell "dumpsys package com.tencent.mm 2>/dev/null | grep userId=" | head -1 | grep -o '[0-9]*' | head -1)
if [ -n "$WECHAT_UID" ]; then
    echo "[+] WeChat UID=$WECHAT_UID — using UID-targeted redirect."
    adb shell "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $WECHAT_UID -j REDIRECT --to-port 18080" || true
    adb shell "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner $WECHAT_UID --dport 443 -j REDIRECT --to-port 18443" || true
else
    echo "[!] WeChat not installed yet — falling back to port-based redirect (install WeChat then re-run iptables setup)."
    adb shell "iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 18080" || true
    adb shell "iptables -t nat -A OUTPUT -p tcp --dport 8080 -j REDIRECT --to-port 18080" || true
    adb shell "iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 18443" || true
fi

# Push evasion shim
if [ -f "/home/cowboy/mmtls-lab/evasion/mmtls_hide.so" ]; then
    adb push "/home/cowboy/mmtls-lab/evasion/mmtls_hide.so" /data/local/tmp/mmtls_hide.so
    adb shell chmod 755 /data/local/tmp/mmtls_hide.so
    adb shell setprop wrap.com.tencent.mm 'LD_PRELOAD=/data/local/tmp/mmtls_hide.so'
    echo "[+] Evasion shim deployed — WeChat will load it on next launch."
fi

# adb reverse: device port → host port (direction: emulator outbound → host tap)
# adb forward goes HOST→DEVICE (wrong direction for this use case)
adb reverse tcp:18080 tcp:18080
adb reverse tcp:18443 tcp:18443
echo "[+] Traffic redirect active. Start mmtls-tap on host."
echo "[+] Emulator PID: $EMULATOR_PID"
