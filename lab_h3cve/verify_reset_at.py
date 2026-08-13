"""Wire proof for RESET_STREAM_AT injection. A minimal aioquic server is taught to
parse frame 0x24 (aioquic has no native support); the client uses
phage.evo.quic_ext.enable_reliable_reset to emit it after a request body. The server
records the (stream_id, error_code, final_size, reliable_size) it decodes. If they match
what the client sent, Phage emits a byte-valid RESET_STREAM_AT on the wire, one layer
below where every other H3 tool stops."""
import asyncio, ssl, sys, threading, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
from phage.evo.quic_ext import enable_reliable_reset, encode_reset_stream_at

PORT = 4480
RECV = []  # (stream_id, error_code, final_size, reliable_size) the server decoded from 0x24


class Server(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        handlers = self._quic._QuicConnection__frame_handlers
        epochs = handlers[0x04][1]  # RESET_STREAM's allowed epochs (ONE_RTT etc.)
        handlers[0x24] = (self._on_reset_at, epochs)
        self._http = None

    def _on_reset_at(self, context, frame_type, buf):
        RECV.append((buf.pull_uint_var(), buf.pull_uint_var(),
                     buf.pull_uint_var(), buf.pull_uint_var()))

    def quic_event_received(self, event):
        pass


def run_server(ready):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain("lab.crt", "lab.key")

    async def go():
        await serve("127.0.0.1", PORT, configuration=cfg, create_protocol=Server)
        ready.set()
        await asyncio.Future()

    loop.run_until_complete(go())


async def client(sid_hint, ec, final, reliable):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", PORT, configuration=cfg) as c:
        q = c._quic
        await asyncio.wait_for(c.wait_connected(), 5)
        enable_reliable_reset(q)
        http = H3Connection(q)
        sid = q.get_next_available_stream_id()
        http.send_headers(stream_id=sid, headers=[
            (b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", b"lab"), (b":path", b"/x"),
            (b"content-length", b"100")], end_stream=False)
        http.send_data(stream_id=sid, data=b"A" * 50, end_stream=False)
        c.transmit()
        await asyncio.sleep(0.2)
        q.send_reset_stream_at(sid, ec, final, reliable)  # retroactive: shrink to `reliable`
        c.transmit()
        await asyncio.sleep(0.5)
        return sid


ready = threading.Event()
threading.Thread(target=run_server, args=(ready,), daemon=True).start()
ready.wait(5)
time.sleep(0.3)

RECV.clear()
EC, FINAL, RELIABLE = 0x10C, 60, 5
sid = asyncio.new_event_loop().run_until_complete(client(0, EC, FINAL, RELIABLE))
time.sleep(0.3)

print("expected fields:", (sid, EC, FINAL, RELIABLE))
print("server decoded  :", RECV)
ok = any(r == (sid, EC, FINAL, RELIABLE) for r in RECV)
print("frame bytes     :", encode_reset_stream_at(sid, EC, FINAL, RELIABLE).hex())
print("\n" + "=" * 50)
print("RESULT:", "RESET_STREAM_AT emitted and parsed byte-valid on the wire" if ok
      else "NOT confirmed")
