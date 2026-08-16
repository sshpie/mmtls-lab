#!/usr/bin/env python3
"""
mmtls-tap: transparent MMTLS TCP interceptor
Sits between WeChat (on the emulator) and Tencent servers.
WeChat's iptables REDIRECT sends its TCP streams to us; we proxy
them to the real servers while parsing every MMTLS record in both directions.

Architecture:
  WeChat → iptables REDIRECT → mmtls-tap:18080 → real Tencent longlink server
  Response path mirrors back.

Record parsing based on WeChat 8.0.56 static RE:
  [type:u8] [len_hi:u8] [len_mid:u8] [len_lo:u8] [payload:len bytes]
  Types: 0x14=change_cipher_spec, 0x15=alert, 0x16=handshake, 0x17=app_data, 0x19=heartbeat

Per WX-F13: alert [0x15] body = [level:u8] [type:u16_LE] ...
  type=0x74 = ALERT_FALLBACK_NO_MMTLS (downgrade trigger)
  type=0x73 = PSK_DELETE
"""

import asyncio
import struct
import sys
import time
import json
import os
import socket
import logging
from enum import IntEnum
from pathlib import Path
from typing import Optional

LOG_DIR = Path(__file__).parent.parent / "captures"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mmtls-tap")

# ── MMTLS constants (from static RE) ────────────────────────────────────────

class RecordType(IntEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT              = 0x15
    HANDSHAKE          = 0x16
    APPLICATION_DATA   = 0x17
    HEARTBEAT          = 0x19

ALERT_TYPES = {
    0x73: "PSK_DELETE",
    0x74: "ALERT_FALLBACK_NO_MMTLS",
}

HANDSHAKE_TYPES = {
    0x01: "client_hello",
    0x02: "server_hello",
    0x08: "encrypted_extensions",
    0x0b: "certificate",
    0x0f: "certificate_verify",
    0x14: "finished",
    0x18: "key_update",
    0x04: "new_session_ticket",
}

# Tencent longlink servers (from WX-F13 signed alert)
LONGLINK_SERVERS = [
    ("long.weixin.qq.com", 80),
    ("long.weixin.qq.com", 8080),
    ("longwechat.wechat.com", 80),
]

SHORTLINK_SERVERS = [
    ("short.weixin.qq.com", 8080),
]

# ── Record parser ────────────────────────────────────────────────────────────

class MMTLSRecord:
    __slots__ = ("rtype", "payload", "raw")

    def __init__(self, rtype: int, payload: bytes):
        self.rtype   = rtype
        self.payload = payload
        self.raw     = bytes([rtype]) + struct.pack(">I", len(payload))[1:] + payload

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["MMTLSRecord", bytes]:
        """Parse one record from buffer; return (record, remaining)."""
        if len(data) < 4:
            raise NeedMore(4 - len(data))
        rtype = data[0]
        length = (data[1] << 16) | (data[2] << 8) | data[3]
        total = 4 + length
        if len(data) < total:
            raise NeedMore(total - len(data))
        return cls(rtype, data[4:total]), data[total:]

    def describe(self) -> str:
        try:
            rt_name = RecordType(self.rtype).name
        except ValueError:
            rt_name = f"UNK_0x{self.rtype:02x}"

        detail = ""
        if self.rtype == RecordType.ALERT and len(self.payload) >= 3:
            level = self.payload[0]
            atype = struct.unpack_from("<H", self.payload, 1)[0]
            detail = f" level={level} type=0x{atype:02x}({ALERT_TYPES.get(atype,'?')})"
        elif self.rtype == RecordType.HANDSHAKE and len(self.payload) >= 1:
            ht = self.payload[0]
            detail = f" hs_type=0x{ht:02x}({HANDSHAKE_TYPES.get(ht,'?')})"
        return f"{rt_name} len={len(self.payload)}{detail}"


class NeedMore(Exception):
    def __init__(self, n): self.n = n


# ── Session capture ──────────────────────────────────────────────────────────

class Session:
    def __init__(self, caddr, dst_host, dst_port):
        self.id       = f"{caddr[0]}:{caddr[1]}-{dst_host}:{dst_port}-{int(time.time())}"
        self.caddr    = caddr
        self.dst      = (dst_host, dst_port)
        self.records  = []  # (ts, direction, record)
        self.log_path = LOG_DIR / f"{self.id}.jsonl"
        self._f       = open(self.log_path, "w")
        log.info(f"[{self.id}] session open → {dst_host}:{dst_port}")

    def record(self, direction: str, rec: MMTLSRecord):
        ts  = time.time()
        row = {
            "ts": ts, "dir": direction,
            "type": rec.rtype, "type_name": RecordType(rec.rtype).name if rec.rtype in RecordType._value2member_map_ else f"0x{rec.rtype:02x}",
            "len": len(rec.payload),
            "hex": rec.payload.hex(),
        }
        if rec.rtype == RecordType.ALERT and len(rec.payload) >= 3:
            row["alert_level"] = rec.payload[0]
            row["alert_type"]  = struct.unpack_from("<H", rec.payload, 1)[0]
        self._f.write(json.dumps(row) + "\n")
        self._f.flush()
        log.info(f"  [{direction}] {rec.describe()}")

    def close(self):
        self._f.close()
        log.info(f"[{self.id}] session closed — {len(self.records)} records → {self.log_path.name}")


# ── MMTLS stream parser ──────────────────────────────────────────────────────

class StreamParser:
    """Incremental MMTLS record parser for a byte stream."""

    def __init__(self, session: Session, direction: str, injector=None):
        self._buf      = b""
        self._session  = session
        self._dir      = direction
        self._injector = injector  # optional callable(record) → bytes | None

    def feed(self, data: bytes) -> bytes:
        """
        Feed raw bytes. Returns bytes to forward downstream
        (possibly modified if injector replaces a record).
        """
        self._buf += data
        out = b""
        while True:
            try:
                rec, self._buf = MMTLSRecord.from_bytes(self._buf)
            except NeedMore:
                break
            self._session.record(self._dir, rec)
            if self._injector:
                replacement = self._injector(rec)
                if replacement is not None:
                    out += replacement
                    continue
            out += rec.raw
        return out


# ── TCP proxy connection ─────────────────────────────────────────────────────

SOL_IP = 0
SO_ORIGINAL_DST = 80  # Linux-specific: recovers pre-REDIRECT destination

def get_original_dst(writer: asyncio.StreamWriter) -> tuple[str, int]:
    """
    Recover the original destination from an iptables-REDIRECTed connection.
    The kernel stores the pre-NAT dst in the socket; getsockopt(SO_ORIGINAL_DST)
    returns a sockaddr_in (16 bytes): [family:2][port:2_BE][addr:4][pad:8].
    Falls back to the local port heuristic if unavailable (direct connection).
    """
    sock = writer.get_extra_info("socket")
    try:
        raw = sock.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack(">H", raw[2:4])[0]
        ip   = socket.inet_ntoa(raw[4:8])
        return ip, port
    except OSError:
        # Not a REDIRECTed connection (e.g. crafter connecting directly)
        local_port = writer.get_extra_info("sockname")[1]
        return ("long.weixin.qq.com", 443 if local_port == 18443 else 80)


async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    inject_fn=None,
):
    caddr              = writer.get_extra_info("peername")
    dst_host, dst_port = get_original_dst(writer)

    session = Session(caddr, dst_host, dst_port)

    try:
        srv_reader, srv_writer = await asyncio.wait_for(
            asyncio.open_connection(dst_host, dst_port),
            timeout=10,
        )
    except Exception as e:
        log.error(f"upstream connect failed: {e}")
        writer.close()
        session.close()
        return

    c2s = StreamParser(session, "C→S", inject_fn)
    s2c = StreamParser(session, "S→C")

    async def forward_c2s():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                out = c2s.feed(data)
                srv_writer.write(out)
                await srv_writer.drain()
        except Exception:
            pass
        finally:
            # Half-close: client done writing → signal server with FIN on that direction
            try:
                srv_writer.write_eof()
            except Exception:
                pass

    async def forward_s2c():
        try:
            while True:
                data = await srv_reader.read(65536)
                if not data:
                    break
                out = s2c.feed(data)
                writer.write(out)
                await writer.drain()
        except Exception:
            pass
        finally:
            # Half-close: server done → signal client
            try:
                writer.write_eof()
            except Exception:
                pass

    await asyncio.gather(forward_c2s(), forward_s2c(), return_exceptions=True)
    session.close()


# ── Injection hooks (plug in crafted records here) ───────────────────────────

def make_injector(rules: list[dict]):
    """
    rules: list of {match_type: int, action: "log"|"drop"|"replace", payload: bytes}
    Returns a function(record) → bytes | None
    """
    def injector(rec: MMTLSRecord) -> Optional[bytes]:
        for rule in rules:
            if rec.rtype == rule.get("match_type"):
                action = rule.get("action", "log")
                if action == "drop":
                    log.warning(f"  [DROP] {rec.describe()}")
                    return b""
                elif action == "replace":
                    new_payload = rule["payload"]
                    new_rec = MMTLSRecord(rec.rtype, new_payload)
                    log.warning(f"  [REPLACE] {rec.describe()} → len={len(new_payload)}")
                    return new_rec.raw
        return None  # pass through
    return injector


# ── Main ─────────────────────────────────────────────────────────────────────

async def main(inject_rules=None):
    inject_fn = make_injector(inject_rules) if inject_rules else None

    servers = []
    for port in [18080, 18443]:
        srv = await asyncio.start_server(
            lambda r, w, f=inject_fn: handle_connection(r, w, f),
            host="127.0.0.1",
            port=port,
        )
        servers.append(srv)
        log.info(f"mmtls-tap listening on 127.0.0.1:{port}")

    log.info("Captures → " + str(LOG_DIR))
    log.info("Waiting for WeChat connections...")
    async with asyncio.TaskGroup() as tg:
        for srv in servers:
            tg.create_task(srv.serve_forever())


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="MMTLS transparent tap")
    ap.add_argument("--drop-alerts", action="store_true",
                    help="Drop all ALERT records (test server behavior)")
    ap.add_argument("--inject-downgrade", action="store_true",
                    help="Inject WX-F13 fallback alert to test HTTPS downgrade live")
    args = ap.parse_args()

    rules = []
    if args.drop_alerts:
        rules.append({"match_type": RecordType.ALERT, "action": "drop"})
    if args.inject_downgrade:
        # WX-F13: ALERT_FALLBACK_NO_MMTLS level=2 type=0x74 LE
        # Payload from static RE: [level=2][type=0x74 0x00][...sig bytes follow in real alert]
        # Minimal synthetic alert record for downgrade test:
        downgrade_payload = bytes([0x02, 0x74, 0x00])  # minimal; real sig required for auth
        rules.append({
            "match_type": RecordType.APPLICATION_DATA,
            "action": "replace",
            "payload": downgrade_payload,
        })
        log.warning("INJECT: downgrade alert will replace first APP_DATA record — "
                    "real ECDSA sig required for WeChat to accept")

    asyncio.run(main(rules if rules else None))
