# MMTLS Lab Session State

## Status: QEMU ARM64 BOOTING (2026-08-16)

The patched QEMU binary is successfully running Android 14 ARM64.
No more PCI device fatal errors. adb shows emulator-5554 offline (early boot stage).
ARM emulation without KVM: expect 10-30 min to full Android boot.

## Active Process
PID: varies per run — check `cat /tmp/claude-1000/-home-cowboy/aad6168a-50df-43b4-b454-548e970d4105/scratchpad/qemu.pid`
Log: `$SCRATCHPAD/qemu-boot12.log` (latest boot log)
ADB: `adb connect localhost:5554` then `adb -s emulator-5554 shell`

## Binary Patch Status
Patched binary: `~/Android/Sdk/emulator/qemu/linux-x86_64/qemu-system-aarch64-patched`
Patch manifest: `~/mmtls-lab/emulator/patches.md`
Launch script: `~/mmtls-lab/emulator/qemu-launch.sh` (uses patched binary)

All 11 patches applied. Boot reaches Android emulator GUI init + WiFi init stage.
PCI devices fixed:
- HDA audio (P1/P2/P3): function-level NOP
- virtio-serial-pci (P4/P4b): → virtio-serial-device
- virtio_input_multi_touch_pci_1..11 (P7): loop gate forced to skip
- virtio-wifi-pci (P8/P9): → virtio-wifi-device (string injected at 0x505600)
- virtio-vsock-pci (P10/P11): → virtio-vsock (string injected at 0x505640)

Additional PCI devices that MAY still appear on next boot:
- virtio-tablet-pci, virtio-keyboard-pci, virtio-mouse-pci (input - headless, not needed)
- virtio-gpu-pci (should be suppressed by -gpu off)
- virtio-rng-pci → virtio-rng-device (likely benign if hit)
- virtio-blk-pci → virtio-blk-device (storage - CRITICAL if hit)

String injection area: file 0x505600 (130k zero bytes in rodata)
- 0x505600: "virtio-wifi-device,netdev=virtio-wifi\0"
- 0x505640: "virtio-vsock,guest-cid=77\0"
- 0x505680+: FREE for next injection

## Next Steps (in order)
1. Wait for adb `emulator-5554` to come online (may take 20+ min from ARM boot start)
   - Check: `adb -s emulator-5554 shell getprop sys.boot_completed`
   - If new PCI errors appear in log: apply same patch methodology
2. `adb install /media/cowboy/research/wechat-re/apk/wechat-arm64.apk`
3. `adb push ~/mmtls-lab/inject/mmtls_inject /data/local/tmp/`
   `adb push ~/mmtls-lab/probe/mmtls_probe /data/local/tmp/`
4. Run mmtls_probe in discover mode to resolve writer_pc for gILinkKey
5. HKDF PSK binder: update mmtls_crafter.py with real HKDF-SHA384

## MMTLS Key Points
- gILinkKey: 72-byte session key at BSS VA 0x3d4648
- HKDF return site: 0x1ce290
- Key-insert orchestrator: 0x303fb0
- Record format: [type:u8][len:3B_BE][payload]

## Tools
- mmtls_inject: ~/mmtls-lab/inject/ (ptrace GOT patcher, ARM64 static)
- mmtls_probe: ~/mmtls-lab/probe/ (BRK #0 hook, ARM64 static)
- hijoy_trace: ~/hijoy-trace/ (JNI tracer, ARM64 static)
- ablation: handles HiJoy PTT RE via modules/hijoy_ptt_re.py
