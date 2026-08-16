#!/usr/bin/env bash
# mmtls-lab: Android ARM64 emulator setup
# Installs Google cmdline-tools, creates rooted ARM64 AVD, configures for WeChat RE
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SDK_DIR="$HOME/Android/Sdk"
CMDLINE_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
API=34
AVD_NAME="wechat-mmtls-lab"
SYSTEM_IMAGE="system-images;android-${API};google_apis;arm64-v8a"

mkdir -p "$SDK_DIR/cmdline-tools"

# ── 1. Download Android cmdline-tools ───────────────────────────────────────
if [ ! -f "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" ]; then
    echo "[+] Downloading Android cmdline-tools..."
    TMP=$(mktemp -d)
    curl -fL "$CMDLINE_URL" -o "$TMP/cmdline-tools.zip"
    unzip -q "$TMP/cmdline-tools.zip" -d "$TMP"
    mkdir -p "$SDK_DIR/cmdline-tools/latest"
    mv "$TMP/cmdline-tools/"* "$SDK_DIR/cmdline-tools/latest/"
    rm -rf "$TMP"
fi

export ANDROID_SDK_ROOT="$SDK_DIR"
export PATH="$SDK_DIR/cmdline-tools/latest/bin:$SDK_DIR/platform-tools:$SDK_DIR/emulator:$PATH"

# ── 2. Install required SDK packages ────────────────────────────────────────
echo "[+] Installing platform-tools, emulator, system image..."
yes | sdkmanager --licenses > /dev/null 2>&1 || true
sdkmanager "platform-tools" "emulator" "$SYSTEM_IMAGE"

# ── 3. Create AVD ───────────────────────────────────────────────────────────
if ! avdmanager list avd | grep -q "$AVD_NAME"; then
    echo "[+] Creating AVD: $AVD_NAME"
    echo "no" | avdmanager create avd \
        -n "$AVD_NAME" \
        -k "$SYSTEM_IMAGE" \
        --device "pixel_4" \
        --force
fi

# ── 4. Patch AVD config to look like a real Pixel 4 ─────────────────────────
AVD_DIR="$HOME/.android/avd/${AVD_NAME}.avd"
CONFIG="$AVD_DIR/config.ini"
echo "[+] Patching AVD config for emulator detection bypass..."
# Remove existing detection-relevant keys and set device-specific values
sed -i '/^hw\.device\.name\|^AvdId\|^PlayStore\|^tag\./!p' "$CONFIG" 2>/dev/null || true
cat >> "$CONFIG" << 'EOF'
hw.cpu.arch=arm64
hw.ramSize=4096
hw.gpu.mode=swiftshader_indirect
hw.keyboard=yes
EOF

# build.prop overrides go in a startup script (applied after boot)
cat > "$LAB_DIR/emulator/patch-props.sh" << 'PROPS'
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
PROPS
chmod +x "$LAB_DIR/emulator/patch-props.sh"

# ── 5. Write launch wrapper ──────────────────────────────────────────────────
cat > "$LAB_DIR/emulator/launch.sh" << LAUNCH
#!/usr/bin/env bash
export ANDROID_SDK_ROOT="$SDK_DIR"
export PATH="$SDK_DIR/cmdline-tools/latest/bin:$SDK_DIR/platform-tools:$SDK_DIR/emulator:\$PATH"

echo "[+] Starting $AVD_NAME..."
emulator -avd "$AVD_NAME" \\
    -no-snapshot-save \\
    -writable-system \\
    -no-boot-anim \\
    -wipe-data \\
    -netdelay none \\
    -netspeed full \\
    -gpu swiftshader_indirect \\
    -memory 4096 \\
    &
EMULATOR_PID=\$!

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
adb push "$LAB_DIR/emulator/patch-props.sh" /data/local/tmp/
adb shell sh /data/local/tmp/patch-props.sh
echo "[+] Props patched."

# Remove emulator-specific device nodes that can't be hidden via props.
# Native code (open("/dev/qemu_pipe")) would bypass any property spoof.
# We have root + writable system — just delete them.
for node in /dev/qemu_pipe /dev/socket/qemud /dev/qemu_trace /sys/qemu_trace; do
    adb shell "rm -rf \$node 2>/dev/null || true"
done
echo "[+] Emulator device nodes removed."

# SELinux enforcing mode blocks iptables NAT rules — must set permissive first
adb shell setenforce 0
echo "[+] SELinux → permissive."

# Prefer UID-based targeting so system traffic on port 80 is not intercepted.
# Fall back to port-based if WeChat is not yet installed.
WECHAT_UID=\$(adb shell "dumpsys package com.tencent.mm 2>/dev/null | grep userId=" | head -1 | grep -o '[0-9]*' | head -1)
if [ -n "\$WECHAT_UID" ]; then
    echo "[+] WeChat UID=\$WECHAT_UID — using UID-targeted redirect."
    adb shell "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner \$WECHAT_UID -j REDIRECT --to-port 18080" || true
    adb shell "iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner \$WECHAT_UID --dport 443 -j REDIRECT --to-port 18443" || true
else
    echo "[!] WeChat not installed yet — falling back to port-based redirect (install WeChat then re-run iptables setup)."
    adb shell "iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 18080" || true
    adb shell "iptables -t nat -A OUTPUT -p tcp --dport 8080 -j REDIRECT --to-port 18080" || true
    adb shell "iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 18443" || true
fi

# Push evasion shim
if [ -f "$LAB_DIR/evasion/mmtls_hide.so" ]; then
    adb push "$LAB_DIR/evasion/mmtls_hide.so" /data/local/tmp/mmtls_hide.so
    adb shell chmod 755 /data/local/tmp/mmtls_hide.so
    adb shell setprop wrap.com.tencent.mm 'LD_PRELOAD=/data/local/tmp/mmtls_hide.so'
    echo "[+] Evasion shim deployed — WeChat will load it on next launch."
fi

# adb reverse: device port → host port (direction: emulator outbound → host tap)
# adb forward goes HOST→DEVICE (wrong direction for this use case)
adb reverse tcp:18080 tcp:18080
adb reverse tcp:18443 tcp:18443
echo "[+] Traffic redirect active. Start mmtls-tap on host."
echo "[+] Emulator PID: \$EMULATOR_PID"
LAUNCH
chmod +x "$LAB_DIR/emulator/launch.sh"

echo ""
echo "[✓] Setup complete."
echo "    Run: $LAB_DIR/emulator/launch.sh"
echo ""
echo "    Install WeChat APK:"
echo "    adb install /media/cowboy/research/wechat-re/apk/wechat-arm64.apk"
echo ""
echo "    Start tap on host:"
echo "    python3 $LAB_DIR/tap/mmtls_tap.py"
