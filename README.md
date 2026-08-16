# mmtls-lab

Custom ARM64 tooling for WeChat MMTLS research.
Tencent's TLS 1.3-variant protocol used by WeChat 8.x. 

## Architecture

```
mmtls-lab/
├── injector/          # PLT/GOT patcher — FULL_RELRO bypass via ptrace mprotect injection
│   ├── mmtls_inject.c # ARM64 static binary; patches libwechatnetwork.so GOT at runtime
│   ├── libhook.c      # Android hook library loaded via wrap.com.tencent.mm LD_PRELOAD
│   ├── build.sh       # NDK cross-compile
│   └── inject.sh      # adb deploy + attach script
├── probe/             # gILinkKey session key extractor
│   ├── mmtls_probe.c  # ARM64 static binary; three modes: discover / hook / dump
│   └── build.sh
├── crafter/
│   └── mmtls_crafter.py   # MMTLS record crafter (HKDF-SHA384 binders, PSK resumption)
├── tap/
│   └── mmtls_tap.py       # Transparent TCP interceptor — MMTLS record parser
├── evasion/
│   └── mmtls_hide.c       # Detection evasion shim
└── emulator/
    └── setup.sh           # AVD creation, WeChat APK install, baseline sanity checks
```

The Python integration layer lives in [ablation](https://github.com/zellkernel/ablation) at `modules/wechat_re.py` — `probe_discover()`, `probe_hook()`, `probe_dump()`, `injector_build()`, `injector_push()`.

## Protocol

MMTLS record format: `[type:u8][len:3B_BE][payload]`

WeChat 8.0.56 `libwechatnetwork.so` landmarks (ARM64 ELF VAs):
- `gILinkKey` (BSS): `0x3d4648` — 72-byte live session key
- HKDF call: `0x1ce28c` → BL `0x1dc424`; return site: `0x1ce290`
- Key-insert orchestrator: `0x303fb0` (fn@0x303fb0 / hlist splice at `0x304074`)

## Components

### mmtls_inject — PLT/GOT injector

Patches GOT entries in `libwechatnetwork.so` at runtime to redirect `connect`/`send`/`recv`/`sendto`/`recvfrom` through `libhook.so` globals. Bypasses Android FULL_RELRO (`.got.plt` is `PROT_READ` after link) by injecting `mprotect()` into the target process via ptrace register dance:

1. `PTRACE_ATTACH` + `waitpid`
2. `PTRACE_GETREGSET(NT_PRSTATUS)` — save `AArch64Regs`
3. Set `x0/x1/x2` = mprotect args, `LR` = orig PC, `PC` = mprotect addr in target libc
4. `PTRACE_SINGLESTEP` until `PC == LR` (ret returns here)
5. `PTRACE_POKEDATA` the GOT entry
6. Restore saved regs

R_AARCH64_JUMP_SLOT (type 1026) relocation entries are target.

### mmtls_probe — gILinkKey probe

Three modes:

```
mmtls_probe discover          # plant BRK@HKDF_RET, step until gILinkKey changes -> writer_pc
mmtls_probe hook 0x<addr>     # plant BRK at writer_pc, capture key on every write, emit JSON
mmtls_probe dump              # poll /proc/pid/mem at key_addr until non-zero+stable
```

AArch64 software breakpoint: `BRK #0` = `0xD4200000` (LE). PC does NOT auto-advance on exception — restore orig instruction + single-step + re-arm for persistent hooks.

Output JSON:
```json
{"mode":"hook","pid":1234,"count":1,"writer_pc":"0x1cad30","key":"aabbcc...","steps":412}
```

### mmtls_tap — TCP interceptor

Transparent MMTLS record parser. Taps the WeChat TCP stream (via iptables REDIRECT or tun device), reassembles MMTLS frames, and emits structured records.

### mmtls_crafter — record crafter

Crafts MMTLS ClientHello / PSK binder records for replay and fuzzing. Uses HKDF-SHA384 for binder computation.

## Build

### Prerequisites

- Android NDK r26+ (`ANDROID_NDK_HOME`)
- adb + rooted Android 12 ARM64 device or emulator (API 34)

### Injector

```sh
cd injector
bash build.sh          # builds libhook.so + mmtls_inject (ARM64 static)
```

### Probe

```sh
cd probe
bash build.sh          # builds mmtls_probe (ARM64 static)
```

### Deploy

```sh
# Injector
adb push injector/libhook.so /data/local/tmp/
adb push injector/mmtls_inject /data/local/tmp/
adb shell chmod 755 /data/local/tmp/mmtls_inject

# Probe
adb push probe/mmtls_probe /data/local/tmp/
adb shell chmod 755 /data/local/tmp/mmtls_probe
```

### Emulator setup

```sh
bash emulator/setup.sh    # creates AVD, installs WeChat, validates adb root
```

## Usage

### Discover gILinkKey write site

```sh
# On device as root — trigger a WeChat handshake first
adb shell su -c '/data/local/tmp/mmtls_probe discover'
# {"mode":"discover","pid":8842,"writer_pc":"0x1cad30","key":"a3f9...","steps":317}
```

### Continuous key capture

```sh
adb shell su -c '/data/local/tmp/mmtls_probe hook 0x1cad30'
# streams JSON lines, one per gILinkKey write event
```

### GOT patch + hook install

```sh
# wrap.com.tencent.mm LD_PRELOAD loads libhook.so into WeChat process
# mmtls_inject patches GOT entries to redirect through libhook globals
adb shell su -c '/data/local/tmp/mmtls_inject $(pidof com.tencent.mm)'
```

## Notes

- PAC (Pointer Authentication) is a no-op on QEMU/Android 12 emulator — hook pointers need no valid PAC signatures
- Android linker namespace isolation (Android 7+) blocks LD_PRELOAD from reaching `libwechatnetwork.so`'s libc symbols — ptrace GOT patching bypasses this entirely
- `process_vm_readv` does NOT bypass PROT_READ page protections — use `/proc/pid/mem` with `O_RDWR` or ptrace for writable access

## Target

WeChat `com.tencent.mm` 8.0.56 (arm64-v8a). `libwechatnetwork.so` SHA256 in `injector/build.sh`.

## Legal

Research against owned/controlled environments only. Do not deploy against production WeChat infrastructure.
