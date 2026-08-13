"""0-RTT early-data flow against the H3 edge (allow-0rtt). Two-connection resumption:
conn 1 completes the handshake and captures the NewSessionTicket; conn 2 resumes with
that ticket, sends an H3 request as EARLY DATA before the handshake completes
(wait_connected=False). Proof of acceptance: HAProxy tags a 0-RTT-received request with
`Early-Data: 1` (RFC 8470) when it forwards to origin, so that header in the tap means
the request was processed as early data, not after the handshake. Also demonstrates the
0-RTT REPLAY property: the same early-data request, resent on a second resumption, reaches
the origin again."""
import asyncio, os, ssl, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration

TAP = "logs/tap_eo.jsonl"
PORT = 4434


class _NoStreamAdapter(QuicConnectionProtocol):
    def quic_event_received(self, event):
        pass


def _cfg(ticket=None):
    c = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    c.verify_mode = ssl.CERT_NONE
    if ticket is not None:
        c.session_ticket = ticket
    return c


async def prime():
    """Conn 1: full handshake, capture the session ticket for resumption."""
    box = {}
    cfg = _cfg()
    async with connect("127.0.0.1", PORT, configuration=cfg,
                       create_protocol=_NoStreamAdapter,
                       session_ticket_handler=lambda t: box.setdefault("t", t)) as client:
        await asyncio.wait_for(client.wait_connected(), 5)
        # the NewSessionTicket arrives shortly after handshake; pump the loop for it
        for _ in range(30):
            if "t" in box:
                break
            await asyncio.sleep(0.05)
    return box.get("t")


async def send_0rtt(ticket, path=b"/early", body=b"earlybody!"):
    """Conn 2: resume and send an H3 POST as 0-RTT early data (no wait_connected)."""
    cfg = _cfg(ticket)
    early = {"sent_before_handshake": None}
    async with connect("127.0.0.1", PORT, configuration=cfg,
                       create_protocol=_NoStreamAdapter, wait_connected=False) as client:
        q = client._quic
        http = H3Connection(q)
        sid = q.get_next_available_stream_id()
        early["sent_before_handshake"] = not q._handshake_complete
        http.send_headers(stream_id=sid, headers=[
            (b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab"),
            (b":path", path), (b"content-length", str(len(body)).encode())],
            end_stream=False)
        http.send_data(stream_id=sid, data=body, end_stream=True)
        client.transmit()            # flush -> aioquic emits 0-RTT packets
        await asyncio.sleep(1.5)
    return early["sent_before_handshake"]


def tap_delta(off):
    try:
        with open(TAP, "rb") as f:
            f.seek(off)
            return f.read()
    except OSError:
        return b""


def run(label, ticket):
    off = os.path.getsize(TAP) if os.path.exists(TAP) else 0
    before = asyncio.new_event_loop().run_until_complete(send_0rtt(ticket))
    time.sleep(0.4)
    fwd = tap_delta(off)
    reqline = fwd.split(b"\r\n", 1)[0]
    early_hdr = b"early-data: 1" in fwd.lower()
    reached = b"/early" in fwd
    print(f"\n### {label}")
    print(f"  sent before handshake complete : {before}")
    print(f"  request reached origin         : {reached}  ({reqline[:40]!r})")
    print(f"  HAProxy Early-Data: 1 tag      : {early_hdr}  <- proves 0-RTT acceptance")
    return reached and early_hdr


ticket = asyncio.new_event_loop().run_until_complete(prime())
print(f"session ticket captured: {ticket is not None}")
if ticket is None:
    print("no ticket issued; server may not support resumption. aborting.")
    sys.exit(1)

ok1 = run("0-RTT early-data request", ticket)
ok2 = run("0-RTT REPLAY (same ticket, resent)", ticket)
print("\n" + "=" * 50)
print("RESULT:", "0-RTT accepted + replayable" if (ok1 and ok2) else "0-RTT not confirmed")
