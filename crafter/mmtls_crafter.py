#!/usr/bin/env python3
"""
mmtls-crafter: build and send crafted MMTLS records against Tencent servers.
Uses protocol knowledge from WeChat 8.0.56 static RE (WX-F1 through WX-F15).

Record wire format (from RE):
  [type:u8] [len:u24_BE] [payload...]

Can be used standalone (direct TCP to server) or fed through mmtls-tap's inject hooks.

Key protocol facts from RE:
  - Long-link port: 80 (TCP)
  - Short-link port: 8080 (TCP)
  - Cipher: AES-GCM-256 (H1) or SM4-GCM (H2, CN path)
  - Nonce: xorNonce(nonce[8:12], LE32(seq)) — WX-F13
  - PSK 0-RTT: HS_MODE_ZERO_RTT_PSK, ticket in mmtls/%08llx file
  - Server P-256 dual use: ECDH + ECDSA same key — WX-F14
  - HKDF: 7 labels, trafficKeyPair=56B — WX-F12
  - Alert level=2 type=0x74 = FALLBACK_NO_MMTLS downgrade
"""

import socket
import struct
import time
import os
import sys
import json
from enum import IntEnum
from typing import Optional
from pathlib import Path

CAPTURES = Path(__file__).parent.parent / "captures"
CAPTURES.mkdir(exist_ok=True)


class RecordType(IntEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT              = 0x15
    HANDSHAKE          = 0x16
    APPLICATION_DATA   = 0x17
    HEARTBEAT          = 0x19


class HSType(IntEnum):
    CLIENT_HELLO       = 0x01
    SERVER_HELLO       = 0x02
    ENCRYPTED_EXT      = 0x08
    CERTIFICATE        = 0x0b
    CERT_VERIFY        = 0x0f
    FINISHED           = 0x14
    NEW_SESSION_TICKET = 0x04
    KEY_UPDATE         = 0x18


# ── Record builder ───────────────────────────────────────────────────────────

def record(rtype: int, payload: bytes) -> bytes:
    hdr = struct.pack(">I", len(payload))[1:]  # 3-byte BE length
    return bytes([rtype]) + hdr + payload


def alert_record(level: int, alert_type: int) -> bytes:
    """
    level=1=warning, level=2=fatal
    alert_type=0x73=PSK_DELETE, 0x74=FALLBACK_NO_MMTLS
    """
    payload = bytes([level]) + struct.pack("<H", alert_type)
    return record(RecordType.ALERT, payload)


def handshake_record(hs_type: int, body: bytes) -> bytes:
    length = struct.pack(">I", len(body))[1:]
    payload = bytes([hs_type]) + length + body
    return record(RecordType.HANDSHAKE, payload)


def change_cipher_spec() -> bytes:
    return record(RecordType.CHANGE_CIPHER_SPEC, bytes([0x01]))


# ── ClientHello builder ──────────────────────────────────────────────────────
# Based on MMTLS protocol RE — TLS 1.3 style with WeChat extensions.
# We emit a minimal ClientHello to observe ServerHello and extract:
#   - server's ephemeral public key
#   - cipher suite selected
#   - session ticket issued (PSK material)

def client_hello_minimal(
    server_name: str = "long.weixin.qq.com",
    psk_identity: Optional[bytes] = None,
) -> bytes:
    """
    Minimal MMTLS ClientHello.
    Uses standard TLS 1.3 wire format since MMTLS is derived from TLS 1.3.
    Extensions: SNI, supported_versions(TLS1.3), supported_groups(P-256),
                key_share(P-256 ephemeral), signature_algorithms,
                optionally: pre_shared_key if psk_identity given.
    """
    import os
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, SECP256R1, ECDH
    )
    from cryptography.hazmat.backends import default_backend

    # Generate ephemeral P-256 key pair
    priv = generate_private_key(SECP256R1(), default_backend())
    pub  = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.X962,
        format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.UncompressedPoint,
    )  # 65 bytes (04 || x || y)

    client_random = os.urandom(32)
    session_id    = b""  # TLS 1.3: empty

    # Cipher suites (AES-GCM-256 + SM4-GCM WeChat extensions)
    cipher_suites = struct.pack(">HHH",
        0x1302,  # TLS_AES_256_GCM_SHA384
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x00FF,  # placeholder for SM4_GCM (WeChat custom, actual ID TBD)
    )

    # Extensions
    def ext(etype: int, data: bytes) -> bytes:
        return struct.pack(">HH", etype, len(data)) + data

    sni_host    = server_name.encode()
    sni_ext     = ext(0x0000, struct.pack(">HBH", len(sni_host)+3, 0, len(sni_host)) + sni_host)
    sv_ext      = ext(0x002b, b"\x02\x03\x04")  # supported_versions: TLS 1.3
    sg_ext      = ext(0x000a, b"\x00\x02\x00\x17")  # supported_groups: secp256r1
    ks_entry    = struct.pack(">HH", 0x0017, len(pub_bytes)) + pub_bytes  # secp256r1 key share
    ks_ext      = ext(0x0033, struct.pack(">H", len(ks_entry)) + ks_entry)
    sa_ext      = ext(0x000d, b"\x00\x04\x04\x03\x08\x04")  # ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256

    extensions = sni_ext + sv_ext + sg_ext + ks_ext + sa_ext

    if psk_identity is not None:
        # pre_shared_key extension (placeholder — real PSK needs ticket + binder)
        psk_id  = struct.pack(">H", len(psk_identity)) + psk_identity + struct.pack(">I", 0)
        binder  = b"\x20" + b"\x00" * 32  # dummy binder
        psk_ext = ext(0x0029, struct.pack(">H", len(psk_id)) + psk_id +
                                struct.pack(">H", len(binder)) + binder)
        extensions += psk_ext

    exts_wire = struct.pack(">H", len(extensions)) + extensions

    ch_body = (
        b"\x03\x03" +       # legacy_version TLS 1.2
        client_random +
        bytes([len(session_id)]) + session_id +
        struct.pack(">H", len(cipher_suites)) + cipher_suites +
        b"\x01\x00" +       # compression methods: null
        exts_wire
    )

    return handshake_record(HSType.CLIENT_HELLO, ch_body), priv


# ── Alert injection (WX-F13 downgrade test) ──────────────────────────────────

# Hardcoded 2020 Tencent-signed alert blob extracted from binary @ 0x42d3b
# Type=0x74 FALLBACK_NO_MMTLS, timestamp=1598803200
# NOTE: this is the canonical alert; replaying it tests if server/client accepts
# without live ECDSA re-signing (which would mean replay protection is absent).
# Full blob is XML + dual ECDSA sigs — minimal test: just the record header.

TENCENT_ALERT_TYPE    = 0x74
TENCENT_ALERT_LEVEL   = 0x02
MINIMAL_DOWNGRADE_ALERT = alert_record(TENCENT_ALERT_LEVEL, TENCENT_ALERT_TYPE)


# ── Connection ───────────────────────────────────────────────────────────────

class MMTLSConn:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host    = host
        self.port    = port
        self.sock    = socket.create_connection((host, port), timeout=timeout)
        self.buf     = b""
        self.seq     = 0
        self.session_id = f"{host}:{port}-{int(time.time())}"
        self._log    = []
        print(f"[+] connected → {host}:{port}")

    def send(self, raw: bytes, label: str = ""):
        self.sock.sendall(raw)
        length = (raw[1] << 16) | (raw[2] << 8) | raw[3] if len(raw) >= 4 else 0
        print(f"  → [{raw[0]:02x}] len={length} {label}")
        self._log.append({"dir": "send", "hex": raw.hex(), "ts": time.time()})

    def recv_record(self, timeout: float = 5.0) -> Optional[bytes]:
        """Read one complete MMTLS record from the server."""
        import select
        deadline = time.time() + timeout
        while True:
            if len(self.buf) >= 4:
                length = (self.buf[1] << 16) | (self.buf[2] << 8) | self.buf[3]
                total  = 4 + length
                if len(self.buf) >= total:
                    rec, self.buf = self.buf[:total], self.buf[total:]
                    rtype = rec[0]
                    print(f"  ← [{rtype:02x}] len={length}")
                    self._log.append({"dir": "recv", "hex": rec.hex(), "ts": time.time()})
                    return rec
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            r, _, _ = select.select([self.sock], [], [], min(remaining, 1.0))
            if r:
                chunk = self.sock.recv(65536)
                if not chunk:
                    return None
                self.buf += chunk

    def save(self):
        path = CAPTURES / f"{self.session_id}.jsonl"
        with open(path, "w") as f:
            for row in self._log:
                f.write(json.dumps(row) + "\n")
        print(f"[+] saved → {path}")

    def close(self):
        self.save()
        self.sock.close()


# ── Test scenarios ────────────────────────────────────────────────────────────

def scenario_observe_handshake(host="long.weixin.qq.com", port=80):
    """
    Send a minimal ClientHello and observe what the server returns.
    Goal: capture ServerHello, extract server's ephemeral pubkey + cipher suite.
    """
    print(f"\n=== SCENARIO: observe handshake @ {host}:{port} ===")
    conn = MMTLSConn(host, port)
    try:
        ch_record, priv_key = client_hello_minimal(server_name=host)
        conn.send(ch_record, "ClientHello")
        # Read up to 5 records or 5 seconds
        for _ in range(5):
            rec = conn.recv_record(timeout=5.0)
            if rec is None:
                break
    finally:
        conn.close()


def scenario_psk_probe(host="long.weixin.qq.com", port=80, psk_identity: Optional[bytes] = None):
    """
    Send ClientHello with PSK extension. If PSK is valid, server should respond
    with 0-RTT data. If invalid, server should send alert or regular ServerHello.
    Use to map PSK validation behavior.
    """
    print(f"\n=== SCENARIO: PSK probe @ {host}:{port} ===")
    conn = MMTLSConn(host, port)
    try:
        psk = psk_identity or os.urandom(32)  # random if none provided
        ch_record, priv_key = client_hello_minimal(server_name=host, psk_identity=psk)
        conn.send(ch_record, f"ClientHello+PSK(len={len(psk)})")
        for _ in range(5):
            rec = conn.recv_record(timeout=5.0)
            if rec is None:
                break
    finally:
        conn.close()


def scenario_inject_alert(host="long.weixin.qq.com", port=80):
    """
    Send the minimal FALLBACK_NO_MMTLS alert directly after connection.
    Tests whether the server processes it before handshake (should not).
    Maps server's handling of pre-handshake alerts.
    """
    print(f"\n=== SCENARIO: inject downgrade alert @ {host}:{port} ===")
    conn = MMTLSConn(host, port)
    try:
        # Send alert before any handshake
        conn.send(MINIMAL_DOWNGRADE_ALERT, "ALERT_FALLBACK_NO_MMTLS(level=2,type=0x74)")
        for _ in range(3):
            rec = conn.recv_record(timeout=3.0)
            if rec is None:
                break
    finally:
        conn.close()


def scenario_fuzz_record_type(host="long.weixin.qq.com", port=80):
    """
    Send records with unusual/unknown type bytes.
    Maps server's error handling and recovery behavior.
    """
    print(f"\n=== SCENARIO: fuzz record types @ {host}:{port} ===")
    for rtype in [0x13, 0x18, 0x1a, 0x20, 0xff]:
        conn = MMTLSConn(host, port)
        try:
            fuzz = record(rtype, b"\x00" * 8)
            conn.send(fuzz, f"FUZZ type=0x{rtype:02x}")
            rec = conn.recv_record(timeout=3.0)
        except Exception as e:
            print(f"  ! error: {e}")
        finally:
            conn.close()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="MMTLS crafter/probe tool")
    ap.add_argument("scenario", choices=[
        "handshake", "psk", "alert", "fuzz"
    ], help="Test scenario to run")
    ap.add_argument("--host", default="long.weixin.qq.com")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--psk", help="Hex-encoded PSK identity bytes for psk scenario")
    args = ap.parse_args()

    psk = bytes.fromhex(args.psk) if args.psk else None

    if args.scenario == "handshake":
        scenario_observe_handshake(args.host, args.port)
    elif args.scenario == "psk":
        scenario_psk_probe(args.host, args.port, psk)
    elif args.scenario == "alert":
        scenario_inject_alert(args.host, args.port)
    elif args.scenario == "fuzz":
        scenario_fuzz_record_type(args.host, args.port)
