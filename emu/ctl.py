#!/usr/bin/env python3
"""
ctl.py — LLM control client for arm64emu

Connects to the emu64 control socket and provides a Python API
for god-mode emulator control.

Usage:
    from ctl import Emu
    e = Emu("/tmp/emu64-ctrl.sock")
    print(e.status())
    e.bp_set(0x1ce290)
    e.run()
    # ... wait for stop notification (poll status)
    state = e.cpu_state(0)
    key = e.mem_read(0x3d4648, 72)
"""

import socket
import json
import time
import sys


class Emu:
    def __init__(self, sock_path: str = "/tmp/emu64-ctrl.sock", timeout: float = 5.0):
        self.sock_path = sock_path
        self.timeout   = timeout
        self._connect()

    def _connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.sock_path)
        self._buf = b""

    def _send(self, cmd: dict) -> dict:
        line = json.dumps(cmd) + "\n"
        self.sock.sendall(line.encode())
        # Read response line
        while b"\n" not in self._buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("emu64 closed connection")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        resp = json.loads(line)
        if not resp.get("ok"):
            raise RuntimeError(f"emu error: {resp.get('err', resp)}")
        return resp

    # ── Memory ────────────────────────────────────────────────────────────

    def mem_read(self, addr: int, length: int) -> bytes:
        r = self._send({"cmd": "mem_read", "addr": hex(addr), "len": length})
        return bytes.fromhex(r["data"])

    def mem_write(self, addr: int, data: bytes) -> None:
        self._send({"cmd": "mem_write", "addr": hex(addr), "data": data.hex()})

    def mem_read_u64(self, addr: int) -> int:
        import struct
        return struct.unpack_from("<Q", self.mem_read(addr, 8))[0]

    def mem_read_u32(self, addr: int) -> int:
        import struct
        return struct.unpack_from("<I", self.mem_read(addr, 4))[0]

    # ── Registers ─────────────────────────────────────────────────────────

    def reg_read(self, reg: str, cpu: int = 0) -> int:
        r = self._send({"cmd": "reg_read", "cpu": cpu, "reg": reg})
        return int(r["val"], 16)

    def reg_write(self, reg: str, val: int, cpu: int = 0) -> None:
        self._send({"cmd": "reg_write", "cpu": cpu, "reg": reg, "val": hex(val)})

    def cpu_state(self, cpu: int = 0) -> dict:
        r = self._send({"cmd": "cpu_state", "cpu": cpu})
        return r

    def sysreg_read(self, reg: str, cpu: int = 0) -> int:
        r = self._send({"cmd": "sysreg_read", "cpu": cpu, "reg": reg})
        return int(r["val"], 16)

    def sysreg_write(self, reg: str, val: int, cpu: int = 0) -> None:
        self._send({"cmd": "sysreg_write", "cpu": cpu, "reg": reg, "val": hex(val)})

    # ── Execution ─────────────────────────────────────────────────────────

    def step(self, n: int = 1, cpu: int = 0) -> dict:
        return self._send({"cmd": "step", "n": n, "cpu": cpu})

    def run_until(self, pc: int, max_insns: int = 10_000_000) -> dict:
        return self._send({"cmd": "run_until", "pc": hex(pc), "max_insns": max_insns})

    def run(self) -> None:
        self._send({"cmd": "run"})

    def pause(self) -> dict:
        return self._send({"cmd": "pause"})

    def status(self) -> dict:
        return self._send({"cmd": "status"})

    def halt(self) -> None:
        self._send({"cmd": "halt"})

    # ── Breakpoints ────────────────────────────────────────────────────────

    def bp_set(self, addr: int) -> None:
        self._send({"cmd": "bp_set", "addr": hex(addr)})

    def bp_clear(self, addr: int) -> None:
        self._send({"cmd": "bp_clear", "addr": hex(addr)})

    def bp_list(self) -> list:
        r = self._send({"cmd": "bp_list"})
        return [int(a, 16) for a in r.get("bps", [])]

    # ── Watchpoints ────────────────────────────────────────────────────────

    def wp_set(self, addr: int, length: int, type: str = "w", cpu: int = 0) -> None:
        self._send({"cmd": "wp_set", "cpu": cpu,
                    "addr": hex(addr), "len": length, "type": type})

    def wp_clear(self, addr: int, cpu: int = 0) -> None:
        self._send({"cmd": "wp_clear", "cpu": cpu, "addr": hex(addr)})

    # ── WeChat / MMTLS helpers ─────────────────────────────────────────────

    def wait_for_stop(self, poll_interval: float = 0.1, timeout: float = 300.0) -> dict:
        """Poll until emulator stops (breakpoint/watchpoint hit)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                st = self.status()
                if not st.get("running"):
                    return st
            except Exception:
                pass
            time.sleep(poll_interval)
        raise TimeoutError("emulator did not stop within timeout")

    def extract_gilinkkey(self, lib_base: int, key_bss_offset: int = 0x3d4648) -> bytes:
        """
        Read gILinkKey (72 bytes) from WeChat BSS.
        lib_base: load address of libwechatnetwork.so in guest
        key_bss_offset: VA offset of gILinkKey in the .so (default 0x3d4648)
        """
        key_va = lib_base + key_bss_offset
        return self.mem_read(key_va, 72)

    def hook_hkdf_return(self, lib_base: int, hkdf_ret_offset: int = 0x1ce290) -> None:
        """Plant breakpoint at HKDF return site to catch key writes."""
        self.bp_set(lib_base + hkdf_ret_offset)

    def watch_gilinkkey(self, lib_base: int, key_bss_offset: int = 0x3d4648) -> None:
        """Set write watchpoint on gILinkKey BSS address."""
        self.wp_set(lib_base + key_bss_offset, 72, "w")


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    import argparse, struct
    p = argparse.ArgumentParser(description="arm64emu control client")
    p.add_argument("--sock", default="/tmp/emu64-ctrl.sock")
    p.add_argument("cmd", nargs="?", default="status",
                   help="status|step|run|pause|halt|cpu|mem_read")
    p.add_argument("--addr", type=lambda x: int(x, 16))
    p.add_argument("--len",  type=int, default=16)
    p.add_argument("--cpu",  type=int, default=0)
    p.add_argument("--reg",  type=str)
    args = p.parse_args()

    e = Emu(args.sock)

    if args.cmd == "status":
        print(json.dumps(e.status(), indent=2))
    elif args.cmd == "step":
        print(json.dumps(e.step(), indent=2))
    elif args.cmd == "run":
        e.run(); print("running")
    elif args.cmd == "pause":
        print(json.dumps(e.pause(), indent=2))
    elif args.cmd == "halt":
        e.halt(); print("halted")
    elif args.cmd == "cpu":
        print(json.dumps(e.cpu_state(args.cpu), indent=2))
    elif args.cmd == "mem_read":
        if args.addr is None:
            print("--addr required"); sys.exit(1)
        data = e.mem_read(args.addr, args.len)
        # Hex dump
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {args.addr+i:016x}  {hex_part:<48}  {asc_part}")
    elif args.cmd == "gilinkkey":
        if args.addr is None:
            print("--addr = lib_base required"); sys.exit(1)
        key = e.extract_gilinkkey(args.addr)
        print(f"gILinkKey ({len(key)} bytes): {key.hex()}")
    else:
        print(f"Unknown command: {args.cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
