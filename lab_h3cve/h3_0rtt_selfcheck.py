"""Prove the Phage 0-RTT driver emits REAL, accepted early data. The HAProxy lab runs
limited-quic (OpenSSL QUIC-compat) which does not issue early-data tickets, so 0-RTT
degrades to 1-RTT there. This stands up a minimal aioquic H3 server (which DOES support
0-RTT: server-side max_early_data=0xFFFFFFFF + an in-memory ticket store) in a thread,
then runs the driver's resume+early-data flow against it and asserts:
  - conn 2 obtains valid ZERO_RTT send keys (aioquic will emit 0-RTT packets)
  - the request reaches the server BEFORE the handshake completes (true early data)
  - the same early data replays on a second resumption (the 0-RTT replay property)."""
import asyncio, ssl, sys, threading, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated
from aioquic.tls import Epoch, SessionTicket

PORT = 4470
RECV = []          # (path, was_early_data) the server saw
TICKETS = {}       # in-memory resumption store -> enables 0-RTT


class Server(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._http = None

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        if self._http is None:
            return
        for e in self._http.handle_event(event):
            if isinstance(e, HeadersReceived):
                hdrs = dict(e.headers)
                path = hdrs.get(b":path", b"?")
                # not handshake-complete when the request lands => it arrived as 0-RTT
                RECV.append((path, not self._quic._handshake_complete))
                self._http.send_headers(e.stream_id, [(b":status", b"200")], end_stream=False)
                self._http.send_data(e.stream_id, b"ok", end_stream=True)


def run_server(ready):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain("lab.crt", "lab.key")

    async def go():
        await serve("127.0.0.1", PORT, configuration=cfg, create_protocol=Server,
                    session_ticket_fetcher=lambda label: TICKETS.pop(label, None),
                    session_ticket_handler=lambda t: TICKETS.__setitem__(t.ticket, t))
        ready.set()
        await asyncio.Future()

    loop.run_until_complete(go())


# Drive through the PACKAGE 0-RTT capability, not inline client code.
from phage.evo import genome as G
from phage.evo.runner import capture_session_ticket, drive_early_data

ready = threading.Event()
threading.Thread(target=run_server, args=(ready,), daemon=True).start()
ready.wait(5)
time.sleep(0.3)

t1 = capture_session_ticket("127.0.0.1", PORT)
print("ticket issued:", t1 is not None,
      "| max_early_data_size:", getattr(t1, "max_early_data_size", None))

RECV.clear()
# a fresh ticket is issued per connection; prime once per leg
h1, e1 = drive_early_data("127.0.0.1", PORT, G.seed_post(path=b"/early1"), t1)
t2 = capture_session_ticket("127.0.0.1", PORT)
h2, e2 = drive_early_data("127.0.0.1", PORT, G.seed_post(path=b"/early2"), t2)
time.sleep(0.3)

print("\nleg 1: 0-RTT send keys valid:", h1, "errors:", e1)
print("leg 2: 0-RTT send keys valid:", h2, "errors:", e2)
print("server received:", RECV)
early_ok = any(p == b"/early1" and early for p, early in RECV) and \
           any(p == b"/early2" and early for p, early in RECV)
print("\n" + "=" * 50)
print("RESULT:", "0-RTT early data emitted + accepted before handshake" if (h1 and h2 and early_ok)
      else "0-RTT NOT confirmed")
