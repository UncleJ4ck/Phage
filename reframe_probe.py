"""Attack-surface map: how does each H3 proxy re-frame a LEGITIMATE request body to its
H1 backend? Fire a well-formed POST (content-length:5, body 'HELLO') over real H3 and dump
the exact H1 the proxy emits (from the tap). The stack that emits transfer-encoding:chunked
(or BOTH content-length and transfer-encoding) is the chunked-desync target.

usage: python reframe_probe.py <udp_port> <tap_log>"""
import asyncio
import os
import ssl
import sys
import time

sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration

from phage.evo import genome as G
from phage.evo.driver import drive

PORT = int(sys.argv[1])
TAP = sys.argv[2]


def size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


async def _fire(genome):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", PORT, configuration=cfg) as client:
        http = H3Connection(client._quic)
        sid = client._quic.get_next_available_stream_id()
        await drive(http, client._quic, sid, genome, transmit=client.transmit, raw=False)
        await asyncio.sleep(0.3)


def fire(genome, label):
    off = size(TAP)
    try:
        asyncio.new_event_loop().run_until_complete(_fire(genome))
    except Exception:
        pass
    time.sleep(0.4)
    try:
        with open(TAP, "rb") as f:
            f.seek(off)
            fwd = f.read()
    except OSError:
        fwd = b""
    has_cl = b"content-length" in fwd.lower()
    has_te = b"transfer-encoding" in fwd.lower()
    print(f"\n[{label}] framing: CL={has_cl} TE-chunked={has_te} "
          f"{'  <<< BOTH (ambiguous!)' if has_cl and has_te else ''}")
    print(f"  H1 emitted:\n{fwd.decode('latin1')}")


if __name__ == "__main__":
    print(f"=== reframe probe: port {PORT} ===")
    fire([G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                     (b":authority", b"lab"), (b":path", b"/body"),
                     (b"content-length", b"5")), end_stream=False),
          G.Data(b"HELLO", end_stream=True)], "valid POST CL:5 body=HELLO")
    # No content-length: the proxy does not know the length upfront, so it must
    # choose how to delimit the body to the H1 backend (CL-after-buffer or chunked).
    fire([G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                     (b":authority", b"lab"), (b":path", b"/nocl")), end_stream=False),
          G.Data(b"HELLO", end_stream=True)], "POST no-CL streaming body=HELLO")
    # No-CL, multi-frame streaming body (harder to buffer, likelier to chunk).
    fire([G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                     (b":authority", b"lab"), (b":path", b"/stream")), end_stream=False),
          G.Data(b"AAAA", end_stream=False), G.Data(b"BBBB", end_stream=True)],
         "POST no-CL multi-frame body")
