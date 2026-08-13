"""End-to-end gene proof: drive a real _mut_reliable_reset GENOME through the package
driver.drive(), and confirm the patched aioquic server receives the RESET_STREAM_AT
frame(s) the gene declared. Proves genome -> driver -> quic_ext -> wire."""
import asyncio, random, ssl, sys, threading, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
from phage.evo import genome as G
from phage.evo.driver import drive
from phage.evo.quic_ext import enable_reliable_reset

PORT = 4481
RECV = []


class Server(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        h = self._quic._QuicConnection__frame_handlers
        h[0x24] = (self._on, h[0x04][1])

    def _on(self, context, frame_type, buf):
        RECV.append((buf.pull_uint_var(), buf.pull_uint_var(),
                     buf.pull_uint_var(), buf.pull_uint_var()))

    def quic_event_received(self, event):
        pass


def run_server(ready):
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain("lab.crt", "lab.key")

    async def go():
        await serve("127.0.0.1", PORT, configuration=cfg, create_protocol=Server)
        ready.set(); await asyncio.Future()

    loop.run_until_complete(go())


async def fire(genome):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN); cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", PORT, configuration=cfg) as c:
        await asyncio.wait_for(c.wait_connected(), 5)
        enable_reliable_reset(c._quic)
        http = H3Connection(c._quic)
        sid = c._quic.get_next_available_stream_id()
        errs = await drive(http, c._quic, sid, genome, transmit=c.transmit)
        await asyncio.sleep(0.6)
        return sid, errs


ready = threading.Event()
threading.Thread(target=run_server, args=(ready,), daemon=True).start()
ready.wait(5); time.sleep(0.3)

genome = G._mut_reliable_reset(G.seed_post(), random.Random(1))
rats = [(o.error_code, o.final_size, o.reliable_size) for o in genome if isinstance(o, G.ResetStreamAt)]
RECV.clear()
sid, errs = asyncio.new_event_loop().run_until_complete(fire(genome))
time.sleep(0.3)

print("gene ops        :", [type(o).__name__ for o in genome])
print("gene declared   :", rats)
print("driver errors   :", [(i, type(e).__name__) for i, e in errs])
print("server received :", RECV)
want = [(sid, ec, fs, rs) for (ec, fs, rs) in rats]
ok = errs == [] and RECV == want
print("\n" + "=" * 50)
print("RESULT:", "gene emits RESET_STREAM_AT end-to-end" if ok else "NOT confirmed")
