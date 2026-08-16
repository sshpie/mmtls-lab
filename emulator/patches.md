# qemu-system-aarch64-patched — Binary Patch Manifest

Binary: `~/Android/Sdk/emulator/qemu/linux-x86_64/qemu-system-aarch64-patched`
Base:   `~/Android/Sdk/emulator/qemu/linux-x86_64/qemu-system-aarch64` (emulator 37.1.11.0)

ELF segment mapping:
- LOAD 0 (ro-data): file 0x0 → VA 0x0 (covers .rodata at VA=file=0x34c000)
- LOAD 1 (text):    file 0xde7680 → VA 0xde8680, delta = +0x1000

## Applied Patches

### P1 — force-jmp past audio init branch
- File offset: 0x10FD35B
- Before: `0f 85 10 01 00 00` (jne 0x10FE471)
- After:  `e9 10 01 00 00 90` (jmp 0x10FE471 + nop)
- Effect: skips audio hardware init branch in ranchu machine init

### P2 — NOP pci_create_simple for intel-hda
- File offset: 0x10FD8BD
- Before: `e8 fe cf 05 00` (call 0x115B8C0)
- After:  `90 90 90 90 90`
- Effect: suppresses intel-hda PCI device creation call

### P3 — force-jmp past audio driver list (the real HDA fix)
- File offset: 0x10FFC11
- Before: `48 85 f6 0f 84 fb 00 00 00` (test rsi,rsi; je 0x1100D15)
- After:  `e9 ff 00 00 00 90 90 90 90` (jmp 0x1100D15 + nops)
- Effect: skips entire audio driver list iteration in function 0x1100BD0

### P4 — truncate virtio-serial-pci string → virtio-serial-device (rodata)
- File offset: 0x3B948B (string start)
- Before: b"virtio-serial-pci,ioeventfd=off\0"
- After:  b"virtio-serial-device\0" (21 bytes, rest unchanged)
- Effect: virtio-serial device uses MMIO bus type

### P4b — change virtio-serial,ioeventfd=off → virtio-serial-device (rodata)
- File offset: 0x3985B8 (second virtio-serial string)
- Before: b"virtio-serial,ioeventfd=off\0"
- After:  b"virtio-serial-device\0" (bytes 13..20 changed, null at +20)
- Effect: second virtio-serial device path uses MMIO bus

### P7 — force-skip multi-touch PCI device loop
- File offset: 0x1029E4C (VA 0x102AE4C)
- Before: `0f 84 96 fd ff ff` (je 0x102ABE8, if not multi-touch)
- After:  `e9 97 fd ff ff 90` (jmp 0x102ABE8 always + nop)
- Effect: bypasses 11-iteration loop that creates virtio_input_multi_touch_pci_{1..11}

### P8 — inject "virtio-wifi-device,netdev=virtio-wifi" into zero-padded rodata
- File offset: 0x505600
- Before: 38 zero bytes
- After:  b"virtio-wifi-device,netdev=virtio-wifi\0"
- Effect: provides MMIO device name for WiFi

### P9 — redirect LEA for virtio-wifi-pci string → injected MMIO string
- File offset: 0x1026E15 (VA 0x1027E15)
- Before: `48 8d 35 b2 ed 44 ff` (lea rsi,[0x476BCE] = "virtio-wifi-pci,netdev=virtio-wifi")
- After:  `48 8d 35 e4 d7 4d ff` (lea rsi,[0x505600] = "virtio-wifi-device,netdev=virtio-wifi")

### P10 — inject "virtio-vsock,guest-cid=77" into zero-padded rodata
- File offset: 0x505640
- Before: 26 zero bytes
- After:  b"virtio-vsock,guest-cid=77\0"
- Effect: provides MMIO vsock device name (correct name is "virtio-vsock", not "virtio-vsock-device")

### P11 — redirect LEA for virtio-vsock-pci string → injected MMIO string
- File offset: 0x1026EBB (VA 0x1027EBB)
- Before: `48 8d 35 52 93 45 ff` (lea rsi,[0x481214] = "virtio-vsock-pci,guest-cid=77")
- After:  `48 8d 35 7e d7 4d ff` (lea rsi,[0x505640] = "virtio-vsock,guest-cid=77")

## Remaining known PCI devices (may need patching if hit)

From string scan — present in binary but not yet hit as errors:
- `virtio-tablet-pci`, `virtio-keyboard-pci`, `virtio-mouse-pci`, `virtio-dual-mode-mouse-pci`
  - In function at VA 0x11E7xxx; only hit if those input features are enabled
- `virtio-gpu-pci` — likely skipped by `-gpu off`
- `virtio-rng-pci`, `virtio-blk-pci` — may be needed; MMIO forms: virtio-rng-device, virtio-blk-device
- `virtio-9p-pci` — host filesystem sharing, optional

## String injection area

Zero-padded rodata at file 0x505600 (130k zero bytes available):
- 0x505600: "virtio-wifi-device,netdev=virtio-wifi\0" (38 bytes)
- 0x505640: "virtio-vsock,guest-cid=77\0" (26 bytes)
- 0x505680+: free for additional injections
