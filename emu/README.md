# arm64emu

ARM64 system emulator. No QEMU, no Unicorn. Written from scratch so the LLM that built it can also drive it — registers, memory, devices, instruction stream, all of it — over a Unix socket.

## Architecture

```
LLM (Claude) ←─ JSON/Unix socket ──→ ctrl server
                                          │
                                    EmuMachine
                                    ├── ARM64 interpreter (arm64.c)
                                    │   ├── 4× Cortex-A76 CPUs
                                    │   ├── ARMv8 MMU (stage-1)
                                    │   └── sysreg r/w
                                    ├── Physical memory + MMIO dispatch
                                    ├── GICv3 interrupt controller
                                    ├── PL011 UART
                                    ├── ARM generic timer
                                    └── virtio-blk (disk images)
```

## Build

```sh
make
```

Requires: gcc, zlib (for kernel decompression via zcat)

## Run

```sh
./emu64 \
    -kernel  path/to/kernel.gz \
    -initrd  path/to/ramdisk.img \
    -cmdline "console=ttyAMA0 earlycon kasan.mode=off" \
    -disk    system.img,ro \
    -disk    vendor.img,ro \
    -mem     2048 \
    -ctrl    /tmp/emu64-ctrl.sock
```

## LLM Control Protocol

Newline-delimited JSON over Unix socket `/tmp/emu64-ctrl.sock`.

### Memory

```json
{"cmd":"mem_read","addr":"0x40000000","len":16}
→ {"ok":true,"data":"deadbeef..."}

{"cmd":"mem_write","addr":"0x40001000","data":"aabbccdd"}
→ {"ok":true}
```

### Registers

```json
{"cmd":"reg_read","cpu":0,"reg":"x0"}
→ {"ok":true,"val":"0x0000000040000000"}

{"cmd":"reg_write","cpu":0,"reg":"pc","val":"0x40080000"}
→ {"ok":true}

{"cmd":"cpu_state","cpu":0}
→ {"ok":true,"pc":"0x...","pstate":"0x...","x":[...31 values...],"sp":"0x..."}
```

### System registers

```json
{"cmd":"sysreg_read","cpu":0,"reg":"sctlr_el1"}
→ {"ok":true,"val":"0x0000000000C50838"}

{"cmd":"sysreg_write","cpu":0,"reg":"vbar_el1","val":"0xffff800008000000"}
→ {"ok":true}
```

### Execution control

```json
{"cmd":"step","n":1,"cpu":0}
→ {"ok":true,"pc":"0x40080004","insns":1}

{"cmd":"run_until","pc":"0x40081000","max_insns":1000000}
→ {"ok":true,"pc":"0x40081000","insns":4200,"reason":"pc_match"}

{"cmd":"run"}
→ {"ok":true}

{"cmd":"pause"}
→ {"ok":true,"pc":"0x40082000"}

{"cmd":"status"}
→ {"ok":true,"running":true,"insns":12345,"cpus":4}
```

### Breakpoints

```json
{"cmd":"bp_set","addr":"0x1ce290"}
→ {"ok":true}

{"cmd":"bp_list"}
→ {"ok":true,"bps":["0x1ce290"]}

{"cmd":"bp_clear","addr":"0x1ce290"}
→ {"ok":true}
```

### Watchpoints

```json
{"cmd":"wp_set","cpu":0,"addr":"0x3d4648","len":72,"type":"w"}
→ {"ok":true}

{"cmd":"wp_clear","cpu":0,"addr":"0x3d4648"}
→ {"ok":true}
```

## Memory Map

| Base         | Size   | Device              |
|--------------|--------|---------------------|
| `0x00000000` | 128MB  | ROM / DTB           |
| `0x08000000` | 64KB   | GICv3 distributor   |
| `0x080A0000` | 128KB  | GICv3 redistributor |
| `0x09000000` | 4KB    | PL011 UART          |
| `0x0a000000` | 16KB   | virtio-mmio (32×)   |
| `0x40000000` | 2GB    | RAM                 |

## Design Principles

1. **LLM agency is native.** The control surface is designed alongside the emulator, not added after. Every internal state is reachable.
2. **From scratch.** No QEMU, no Unicorn, no external CPU emulation library. Every component written explicitly for auditability.
3. **Closed-loop.** LLM proposes → executes → observes failures → iterates. The control socket is the feedback channel.
4. **God mode.** Direct memory r/w, register manipulation, instruction inject, watchpoints on any address — at the hardware level, not OS level.
