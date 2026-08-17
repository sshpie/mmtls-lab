#!/usr/bin/env bash
# post_boot.sh — Execute immediately after Android 14 ARM64 emulator boots
# Installs WeChat + pushes tools + prints ready-to-run commands
set -euo pipefail

ADB="adb -s emulator-5554"
APK="/media/cowboy/research/wechat-re/apk/wechat-arm64.apk"
INJECT="$HOME/mmtls-lab/injector/mmtls_inject"
LIBHOOK="$HOME/mmtls-lab/injector/libhook.so"
PROBE="$HOME/mmtls-lab/probe/mmtls_probe"

echo "[1] Rooting adb..."
adb root
sleep 2
adb connect localhost:5554
sleep 1

echo "[1b] Disabling SELinux enforcement (needed for cross-process ptrace)..."
$ADB shell setenforce 0
$ADB shell cat /proc/sys/kernel/yama/ptrace_scope || true
$ADB shell "echo 0 > /proc/sys/kernel/yama/ptrace_scope" 2>/dev/null || true

echo "[2] Pushing tools..."
$ADB push "$INJECT"  /data/local/tmp/mmtls_inject
$ADB push "$LIBHOOK" /data/local/tmp/libhook.so
$ADB push "$PROBE"   /data/local/tmp/mmtls_probe
$ADB shell chmod 755 /data/local/tmp/mmtls_inject /data/local/tmp/mmtls_probe

echo "[3] Installing WeChat..."
$ADB install -g "$APK"
echo "    WeChat install complete"

echo ""
echo "=== READY — run these in order ==="
echo ""
echo "# Terminal 1: discover mode (trigger a WeChat login after running)"
echo "$ADB shell /data/local/tmp/mmtls_probe discover"
echo ""
echo "# After discover outputs writer_pc, replace 0x<writer_pc> below:"
echo "$ADB shell /data/local/tmp/mmtls_probe hook 0x<writer_pc>"
echo ""
echo "# Launch WeChat:"
echo "$ADB shell am start -n com.tencent.mm/.ui.LauncherUI"
echo ""
echo "# Dump key one-shot (fallback if discover fails):"
echo "$ADB shell /data/local/tmp/mmtls_probe dump"
