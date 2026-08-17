# Emulator — ARM64 Android on x86_64 Host

## What We Did

Google's Android SDK ships `qemu-system-aarch64` (emulator 37.1.11.0) with a hardcoded guard that rejects ARM64 guests on x86_64 hosts. Calling the binary directly bypasses the wrapper arch check, but the QEMU frontend was built assuming an x86 guest environment — meaning it generates PCI bus device arguments (`virtio-XXX-pci`) for every device, while the ARM ranchu machine type uses VirtIO MMIO (no PCI bus). Every PCI device causes a fatal `No 'PCI' bus found` exit.

We applied 11 binary patches to `qemu-system-aarch64` to:
1. Suppress the HDA audio PCI device (ARM ranchu has no PCI bus for audio)
2. Replace `virtio-serial-pci` references with `virtio-serial-device` (MMIO)
3. Skip the multi-touch PCI device loop (11 `virtio_input_multi_touch_pci_N` devices)
4. Replace `virtio-wifi-pci` with `virtio-wifi-device` (MMIO WiFi)
5. Replace `virtio-vsock-pci` with `virtio-vsock` (MMIO vSock)

No recompile. No source. Pure binary patching of the x86_64 ELF.

## Files

```
emulator/
├── bin/
│   └── qemu-system-aarch64-patched   # patched binary (Git LFS, 32MB)
├── patches.md                         # full patch manifest with offsets + byte sequences
├── qemu-launch.sh                     # launch script (uses patched binary)
├── patch-props.sh                     # post-boot: fake Pixel 4 identity on device
└── README.md                          # this file
```

## Patching Methodology

ELF segment mapping for this binary:
- LOAD 0 (rodata): file offset = VA (first segment, base 0)
- LOAD 1 (text): VA = file_offset + 0x1000

**PCI device fix pattern:**
1. Find the PCI device string in rodata (e.g. `virtio-wifi-pci,netdev=virtio-wifi`)
2. Find its LEA xref in `.text` via RIP-relative displacement scan
3. Either: change the string in-place to the MMIO equivalent if it fits
4. Or: inject the MMIO string into zero-padded rodata at `0x505600+` and redirect the LEA displacement

**String injection area:** `file 0x505600` — 130k contiguous zero bytes in rodata, safe to overwrite.

**Loop/function-level suppression:** For cases like multi-touch (11-device loop gated by `androidHwConfig_isScreenMultiTouch`), change `je` → `jmp` to always take the skip branch.

Full patch details (byte sequences, file offsets, before/after): `emulator/patches.md`

## Launch

Requires Android SDK with `android-34/google_apis/arm64-v8a` system image installed:

```sh
bash emulator/qemu-launch.sh
```

ARM emulation without KVM (software): expect 15-30 min to full Android boot.

```sh
adb connect localhost:5554
# wait for online...
adb -s emulator-5554 shell getprop sys.boot_completed
# → 1 = booted
```

## Why

Running WeChat MMTLS protocol research requires a real ARM64 Android environment to run the ARM64 WeChat binary with our custom ptrace tools (`mmtls_inject`, `mmtls_probe`). x86 ABI translation would break the BRK #0 hook mechanism used by `mmtls_probe`.
